//! `ContentIndex` (PRD §5.3): the global index of what spans namespaces
//! (holders, GC holds, the blocklist), sharded by object id over
//! [`Partition::ContentShard`] partitions. It is a layer over any
//! [`NamespaceStore`], not a backend trait: every per-object update is one
//! [`Batch`] in the object's shard, which gives any backend the PRD's
//! "atomic per-object updates".
//!
//! Each object has a state row (`c`, [`ObjectState`]): a change sequence,
//! the time of the last change and the holder count. Every mutation
//! rewrites it in the same batch, guarded by `Equals` on the value it read,
//! so a GC delete guarded by the value [`ContentIndex::collectable`]
//! returns fails if anything changed since (WP-5.3b).
//!
//! Holder rows are provisional: WP-4.10a moves them to sub-shards by
//! (object, hash(holder)) and keeps the count here. Callers must not rely on
//! scanning every holder of an object in one partition; the count is what
//! GC reads.

use mkit_core::hash::Hash;

use super::codec;
use super::error::StoreError;
use super::keys::{self, ParsedKey};
use super::kv::{Batch, BatchOutcome, Cursor, Key, NamespaceStore, Precondition, Value, Write};
use super::partition::Partition;
use crate::repo::{NamespaceKey, RepoName};

/// Object-id prefix fan-out of the content shards (and repo index shards):
/// a fixed deployment constant, never resharded (PRD §5.3, D34).
pub const INDEX_FANOUT: u16 = 4096;
const _: () = assert!(INDEX_FANOUT == 1 << 12);

/// Longest [`BlockEntry::reason`], in bytes.
pub const MAX_BLOCK_REASON_BYTES: usize = 256;

/// Optimistic re-plans (normative rule 3) before a contended mutation
/// fails with a retryable [`StoreError::Unavailable`].
const MAX_ATTEMPTS: usize = 8;
/// Page size of the hold scan in [`ContentIndex::collectable`].
const HOLD_SCAN_PAGE: u32 = 100;

/// The content shard of `object`: its top 12 bits.
#[must_use]
pub fn content_shard(object: &Hash) -> Partition {
    Partition::ContentShard(u16::from_be_bytes([object[0], object[1]]) >> 4)
}

/// Every content shard, by construction (the `Partition` enumeration
/// rule 5).
pub fn content_shards() -> impl Iterator<Item = Partition> {
    (0..INDEX_FANOUT).map(Partition::ContentShard)
}

/// A repository that holds an object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Holder {
    /// Namespace.
    pub ns: NamespaceKey,
    /// Repository.
    pub repo: RepoName,
}

/// One page of [`ContentIndex::holders`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HolderPage {
    /// Holders in key order.
    pub holders: Vec<Holder>,
    /// Resume point, if more holders may follow.
    pub next: Option<Cursor>,
}

/// A blocklist entry (PRD §6.7 takedown).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    /// Reason code, at most [`MAX_BLOCK_REASON_BYTES`].
    pub reason: String,
    /// When the object was blocked, Unix ms.
    pub blocked_at_ms: u64,
}

/// An object's state row. Absent means never indexed: no holders, no holds,
/// last change at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ObjectState {
    /// Change sequence; every mutation increments it.
    pub seq: u64,
    /// Time of the last change, Unix ms (never moves backwards).
    pub changed_at_ms: u64,
    /// Number of holder rows.
    pub holders: u64,
}

/// The `ContentIndex` layer over a store's content shards. The store must
/// accept every key class and atomic multi-key batches; otherwise every
/// mutation fails with [`StoreError::Unsupported`].
#[derive(Debug, Clone)]
pub struct ContentIndex<S> {
    store: S,
}

impl<S: NamespaceStore> ContentIndex<S> {
    /// Wrap `store`.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// The underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Record GC hold `hold_id` on `object` until `expires_at_ms`
    /// (re-adding extends it). Taken **before** the ref-shard apply that
    /// makes the object reachable (PRD §5.3). The hold's TTL must exceed
    /// `MAX_APPLY_WINDOW` plus the relay-lag bound (00-plan P-21, P-23), so
    /// it outlives every write that could still commit and be relayed.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if `expires_at_ms <= now_ms`.
    pub async fn add_hold(
        &self,
        object: &Hash,
        hold_id: &Hash,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if expires_at_ms <= now_ms {
            return Err(StoreError::Invalid("hold already expired".into()));
        }
        let (key, value) = (
            keys::hold(object, hold_id),
            codec::encode_hold(expires_at_ms),
        );
        self.mutate(object, now_ms, None, |_, _| {
            vec![Write::Put(key.clone(), value.clone())]
        })
        .await
    }

    /// Release hold `hold_id`. Normally the relay step that records the
    /// holder row releases it in the same batch (see [`Self::add_holder`],
    /// WP-4.10, R-75); this standalone form is for abandoned uploads.
    pub async fn release_hold(
        &self,
        object: &Hash,
        hold_id: &Hash,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let key = keys::hold(object, hold_id);
        self.mutate(object, now_ms, None, |_, _| {
            vec![Write::Delete(key.clone())]
        })
        .await
    }

    /// Record that `holder` holds `object` (idempotent), releasing hold
    /// `releases` in the same batch: a dedup hold is released only when its
    /// holder row is recorded (PRD §6.7).
    pub async fn add_holder(
        &self,
        object: &Hash,
        holder: &Holder,
        releases: Option<&Hash>,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let key = keys::holder(object, &holder.ns, &holder.repo)?;
        let release = releases.map(|id| keys::hold(object, id));
        self.mutate(object, now_ms, Some(&key), |present, state| {
            if !present {
                state.holders += 1;
            }
            let mut writes = vec![Write::Put(key.clone(), Value::default())];
            writes.extend(release.clone().map(Write::Delete));
            writes
        })
        .await
    }

    /// Remove `holder` of `object`; removing an absent holder is not an
    /// error.
    pub async fn remove_holder(
        &self,
        object: &Hash,
        holder: &Holder,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let key = keys::holder(object, &holder.ns, &holder.repo)?;
        self.mutate(object, now_ms, Some(&key), |present, state| {
            if present {
                state.holders = state.holders.saturating_sub(1);
            }
            vec![Write::Delete(key.clone())]
        })
        .await
    }

    /// Up to `limit` holders of `object` after `after`.
    pub async fn holders(
        &self,
        object: &Hash,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<HolderPage, StoreError> {
        let (start, end) = keys::holders_of(object);
        let page = self
            .store
            .scan(&content_shard(object), &start, &end, after, limit)
            .await?;
        let holders = page
            .entries
            .iter()
            .map(|(key, _)| match keys::parse(key) {
                Some(ParsedKey::Holder { ns, repo, .. }) => Ok(Holder { ns, repo }),
                _ => Err(StoreError::Corrupt("malformed holder key".into())),
            })
            .collect::<Result<_, _>>()?;
        Ok(HolderPage {
            holders,
            next: page.next,
        })
    }

    /// Put `object` on the global blocklist (replacing any entry).
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if the reason exceeds
    /// [`MAX_BLOCK_REASON_BYTES`].
    pub async fn block(
        &self,
        object: &Hash,
        entry: &BlockEntry,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        if entry.reason.len() > MAX_BLOCK_REASON_BYTES {
            return Err(StoreError::Invalid("block reason too long".into()));
        }
        let (key, value) = (keys::block(object), codec::encode_block_entry(entry));
        self.mutate(object, now_ms, None, |_, _| {
            vec![Write::Put(key.clone(), value.clone())]
        })
        .await
    }

    /// Take `object` off the blocklist.
    pub async fn unblock(&self, object: &Hash, now_ms: u64) -> Result<(), StoreError> {
        let key = keys::block(object);
        self.mutate(object, now_ms, None, |_, _| {
            vec![Write::Delete(key.clone())]
        })
        .await
    }

    /// The blocklist entry of `object`, if blocked.
    pub async fn blocked(&self, object: &Hash) -> Result<Option<BlockEntry>, StoreError> {
        let value = self
            .store
            .get(&content_shard(object), &keys::block(object))
            .await?;
        value.as_ref().map(codec::decode_block_entry).transpose()
    }

    /// The state row of `object`, if it was ever indexed.
    pub async fn state(&self, object: &Hash) -> Result<Option<ObjectState>, StoreError> {
        let value = self
            .store
            .get(&content_shard(object), &keys::object_state(object))
            .await?;
        value.as_ref().map(codec::decode_object_state).transpose()
    }

    /// Whether GC may delete `object` at `now_ms`: zero holders, zero
    /// unexpired holds (a hold is live while `now_ms < expires_at_ms`), and
    /// `now_ms - last change >= grace_ms`. If so,
    /// returns the precondition (on the state row) that the delete batch
    /// must carry, so it fails if anything changed after this check.
    pub async fn collectable(
        &self,
        object: &Hash,
        now_ms: u64,
        grace_ms: u64,
    ) -> Result<Option<Precondition>, StoreError> {
        let p = content_shard(object);
        let state_key = keys::object_state(object);
        let raw = self.store.get(&p, &state_key).await?;
        let state = raw
            .as_ref()
            .map(codec::decode_object_state)
            .transpose()?
            .unwrap_or_default();
        if state.holders > 0 || now_ms.saturating_sub(state.changed_at_ms) < grace_ms {
            return Ok(None);
        }
        let (start, end) = keys::holds_of(object);
        let mut after = None;
        loop {
            let page = self
                .store
                .scan(&p, &start, &end, after.as_ref(), HOLD_SCAN_PAGE)
                .await?;
            for (_, value) in &page.entries {
                if codec::decode_hold(value)? > now_ms {
                    return Ok(None);
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(Some(match raw {
            Some(value) => Precondition::Equals(state_key, value),
            None => Precondition::Absent(state_key),
        }))
    }

    /// Apply one per-object mutation: read the layout version, the state
    /// row and `probe`; let `plan` update the state (it gets whether
    /// `probe` is present) and return its writes; commit them with the new
    /// state row, guarded on everything read. Re-plans on a lost race.
    async fn mutate(
        &self,
        object: &Hash,
        now_ms: u64,
        probe: Option<&Key>,
        plan: impl Fn(bool, &mut ObjectState) -> Vec<Write>,
    ) -> Result<(), StoreError> {
        let p = content_shard(object);
        let state_key = keys::object_state(object);
        let mut read = vec![keys::layout_version(), state_key.clone()];
        read.extend(probe.cloned());
        for _ in 0..MAX_ATTEMPTS {
            let values = self.store.get_many(&p, &read).await?;
            let mut batch = Batch::new();
            batch = match values.first().and_then(Option::as_ref) {
                None => batch
                    .require(Precondition::Absent(read[0].clone()))
                    .put(read[0].clone(), codec::encode_u32(keys::LAYOUT_VERSION)),
                Some(v) if codec::decode_u32(v)? > keys::LAYOUT_VERSION => {
                    return Err(StoreError::Unsupported(
                        "content shard has a newer layout version".into(),
                    ));
                }
                Some(v) => batch.require(Precondition::Equals(read[0].clone(), v.clone())),
            };
            let old = values.get(1).cloned().flatten();
            let mut state = old
                .as_ref()
                .map(codec::decode_object_state)
                .transpose()?
                .unwrap_or_default();
            batch = batch.require(match &old {
                Some(v) => Precondition::Equals(state_key.clone(), v.clone()),
                None => Precondition::Absent(state_key.clone()),
            });
            let present = values.get(2).is_some_and(Option::is_some);
            batch.writes.extend(plan(present, &mut state));
            state.seq = state.seq.wrapping_add(1);
            state.changed_at_ms = state.changed_at_ms.max(now_ms);
            batch = batch.put(state_key.clone(), codec::encode_object_state(&state));
            match self.store.apply(&p, batch).await? {
                BatchOutcome::Committed => return Ok(()),
                BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. } => {}
            }
        }
        Err(StoreError::unavailable("content index update contended"))
    }
}

#[cfg(test)]
mod tests {
    use futures_executor::block_on;

    use super::*;
    use crate::memory::MemoryKv;

    const GRACE: u64 = 1_000;

    fn holder(repo: &str) -> Holder {
        Holder {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new(repo).unwrap(),
        }
    }

    fn state(idx: &ContentIndex<MemoryKv>, object: &Hash) -> ObjectState {
        block_on(idx.state(object)).unwrap().unwrap()
    }

    fn collectable(idx: &ContentIndex<MemoryKv>, object: &Hash, now: u64) -> bool {
        block_on(idx.collectable(object, now, GRACE))
            .unwrap()
            .is_some()
    }

    #[test]
    fn content_shard_is_the_top_twelve_bits() {
        assert_eq!(content_shard(&[0; 32]), Partition::ContentShard(0));
        let mut id = [0xff; 32];
        assert_eq!(content_shard(&id), Partition::ContentShard(4095));
        id[..2].copy_from_slice(&[0x12, 0x3f]);
        assert_eq!(content_shard(&id), Partition::ContentShard(0x123));
        assert_eq!(content_shards().count(), usize::from(INDEX_FANOUT));
    }

    #[test]
    fn content_index_collectable_rules() {
        let idx = ContentIndex::new(MemoryKv::default());
        let obj = [7; 32];
        // Never indexed: nothing holds it, its last change counts as 0, and
        // its guard is `Absent`.
        assert!(!collectable(&idx, &obj, GRACE - 1));
        assert_eq!(
            block_on(idx.collectable(&obj, GRACE, GRACE)).unwrap(),
            Some(Precondition::Absent(keys::object_state(&obj)))
        );
        block_on(idx.add_holder(&obj, &holder("a"), None, 10)).unwrap();
        assert!(!collectable(&idx, &obj, 10 + GRACE * 10), "held");
        block_on(idx.remove_holder(&obj, &holder("a"), 20)).unwrap();
        assert!(!collectable(&idx, &obj, 20 + GRACE - 1), "within grace");
        assert!(collectable(&idx, &obj, 20 + GRACE));
        // An unexpired hold blocks collection; an expired one does not.
        block_on(idx.add_hold(&obj, &[1; 32], 5_000, 30)).unwrap();
        assert!(!collectable(&idx, &obj, 30 + GRACE));
        assert!(!collectable(&idx, &obj, 4_999));
        assert!(collectable(&idx, &obj, 5_000), "a hold ends at its expiry");
        // The returned guard fails once anything changes.
        let guard = block_on(idx.collectable(&obj, 5_001, GRACE))
            .unwrap()
            .unwrap();
        block_on(idx.release_hold(&obj, &[1; 32], 5_002)).unwrap();
        let outcome = block_on(
            idx.store()
                .apply(&content_shard(&obj), Batch::new().require(guard)),
        )
        .unwrap();
        assert!(matches!(outcome, BatchOutcome::PreconditionFailed { .. }));
        // A blocklist entry is not a hold.
        block_on(idx.block(
            &obj,
            &BlockEntry {
                reason: "dmca".into(),
                blocked_at_ms: 9,
            },
            6_000,
        ))
        .unwrap();
        assert!(collectable(&idx, &obj, 6_000 + GRACE));
    }

    #[test]
    fn content_index_holder_add_idempotent() {
        let idx = ContentIndex::new(MemoryKv::default());
        let obj = [8; 32];
        for _ in 0..3 {
            block_on(idx.add_holder(&obj, &holder("a"), None, 1)).unwrap();
        }
        block_on(idx.add_holder(&obj, &holder("b"), None, 1)).unwrap();
        assert_eq!(state(&idx, &obj).holders, 2);
        let page = block_on(idx.holders(&obj, None, 1)).unwrap();
        assert_eq!(page.holders, vec![holder("a")]);
        let rest = block_on(idx.holders(&obj, page.next.as_ref(), 10)).unwrap();
        assert_eq!((rest.holders, rest.next), (vec![holder("b")], None));
        for _ in 0..2 {
            block_on(idx.remove_holder(&obj, &holder("a"), 2)).unwrap();
        }
        assert_eq!(state(&idx, &obj).holders, 1);
        // Recording a holder releases its dedup hold in the same batch.
        block_on(idx.add_hold(&obj, &[2; 32], 100, 3)).unwrap();
        let before = state(&idx, &obj).seq;
        block_on(idx.add_holder(&obj, &holder("c"), Some(&[2; 32]), 4)).unwrap();
        assert_eq!(state(&idx, &obj).seq, before + 1);
        assert_eq!(state(&idx, &obj).holders, 2);
        let hold = block_on(
            idx.store()
                .get(&content_shard(&obj), &keys::hold(&obj, &[2; 32])),
        );
        assert_eq!(hold.unwrap(), None);
    }

    #[test]
    fn content_index_every_mutation_bumps_last_change() {
        let idx = ContentIndex::new(MemoryKv::default());
        let obj = [9; 32];
        let entry = BlockEntry {
            reason: "r".into(),
            blocked_at_ms: 1,
        };
        let mut last = ObjectState::default();
        for (i, now) in (1_u64..).zip([10, 20, 15, 30, 40, 50, 60, 70]) {
            match i {
                1 => block_on(idx.add_hold(&obj, &[1; 32], 99, now)),
                2 | 3 => block_on(idx.add_holder(&obj, &holder("a"), None, now)),
                4 | 5 => block_on(idx.remove_holder(&obj, &holder("a"), now)),
                6 => block_on(idx.block(&obj, &entry, now)),
                7 => block_on(idx.unblock(&obj, now)),
                _ => block_on(idx.release_hold(&obj, &[1; 32], now)),
            }
            .unwrap();
            let s = state(&idx, &obj);
            assert_eq!(s.seq, i, "mutation {i} bumps the sequence");
            // The change time never moves backwards (the 15 after 20).
            assert_eq!(s.changed_at_ms, now.max(last.changed_at_ms));
            last = s;
        }
        let v = block_on(
            idx.store()
                .get(&content_shard(&obj), &keys::layout_version()),
        );
        assert_eq!(v.unwrap(), Some(codec::encode_u32(keys::LAYOUT_VERSION)));
        assert!(matches!(
            block_on(idx.add_hold(&obj, &[1; 32], 5, 5)),
            Err(StoreError::Invalid(_))
        ));
        let long = BlockEntry {
            reason: "x".repeat(MAX_BLOCK_REASON_BYTES + 1),
            blocked_at_ms: 0,
        };
        assert!(matches!(
            block_on(idx.block(&obj, &long, 1)),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(state(&idx, &obj), last, "rejected calls write nothing");
    }

    #[test]
    fn content_index_objects_in_different_shards_isolated() {
        let idx = ContentIndex::new(MemoryKv::default());
        let (a, mut b) = ([0x10; 32], [0x10; 32]);
        b[0] = 0x20;
        assert_ne!(content_shard(&a), content_shard(&b));
        block_on(idx.add_holder(&a, &holder("x"), None, 1)).unwrap();
        block_on(idx.add_hold(&a, &[1; 32], 99, 1)).unwrap();
        let entry = BlockEntry {
            reason: "r".into(),
            blocked_at_ms: 1,
        };
        block_on(idx.block(&a, &entry, 1)).unwrap();
        assert_eq!(block_on(idx.state(&b)).unwrap(), None);
        assert_eq!(block_on(idx.blocked(&b)).unwrap(), None);
        assert_eq!(block_on(idx.blocked(&a)).unwrap(), Some(entry));
        assert!(
            block_on(idx.holders(&b, None, 10))
                .unwrap()
                .holders
                .is_empty()
        );
        let stats = block_on(idx.store().stats(&content_shard(&b))).unwrap();
        assert_eq!(stats.keys, Some(0), "b's shard was never written");
        // Same shard, different object: rows stay apart too.
        let mut c = a;
        c[31] = 0;
        assert_eq!(content_shard(&a), content_shard(&c));
        assert!(
            block_on(idx.holders(&c, None, 10))
                .unwrap()
                .holders
                .is_empty()
        );
        assert!(collectable(&idx, &c, GRACE));
        assert!(!collectable(&idx, &a, GRACE * 10), "a is held");
    }

    #[test]
    fn content_index_refuses_newer_layout_version() {
        let idx = ContentIndex::new(MemoryKv::default());
        let obj = [3; 32];
        let newer = Batch::new().put(
            keys::layout_version(),
            codec::encode_u32(keys::LAYOUT_VERSION + 1),
        );
        block_on(idx.store().apply(&content_shard(&obj), newer)).unwrap();
        assert!(matches!(
            block_on(idx.add_holder(&obj, &holder("a"), None, 1)),
            Err(StoreError::Unsupported(_))
        ));
    }
}
