//! `ContentIndex` (PRD §5.3): the global index of what spans namespaces
//! (holders, GC holds, the blocklist), sharded by object id over
//! [`Partition::ContentShard`] partitions. It is a layer over any
//! [`NamespaceStore`], not a backend trait: every per-object update is one
//! [`Batch`] in the object's shard, which gives any backend the PRD's
//! "atomic per-object updates".
//!
//! Each object has a state row (`c`, [`ObjectState`]): a change sequence,
//! the time of the last change, the holder count and the GC `deleting`
//! mark. Every mutation rewrites it in the same batch, guarded by `Equals`
//! on the value it read, and prunes the expired hold rows it saw.
//!
//! **GC ordering (R-64).** GC deletes an object's bytes only through this
//! sequence:
//! 1. [`ContentIndex::collectable`] checks zero holders, zero live holds
//!    and the grace period, and returns a [`GcPlan`]: one batch guarded on
//!    the state row that prunes the expired holds and sets `deleting`.
//! 2. [`ContentIndex::commit_collect`] applies it. It fails if anything
//!    changed since step 1. Once it commits, [`ContentIndex::add_hold`] and
//!    [`ContentIndex::add_holder`] answer a retryable
//!    [`StoreError::Unavailable`], so no upload can dedup against bytes that
//!    are about to go; the client retries and re-uploads.
//! 3. GC deletes the blob (idempotent), only after step 2 committed.
//! 4. [`ContentIndex::finish_collect`] clears `deleting`. A GC that stops
//!    between 2 and 4 finds `deleting` set in [`ContentIndex::state`] and
//!    resumes at step 3.
//!
//! **Holder rows (R-131).** A holder row is a [`HolderRecord`]: the object's
//! post-bump change sequence and the id of the operation (the consuming
//! ticket) that recorded it. Every holder write, including a re-record of
//! the same holder, advances the object's sequence, and a removal is
//! conditional on the sequence the caller read
//! ([`ContentIndex::remove_holder`]), so a removal never undoes a holder
//! that was re-recorded after the read (SPEC-SERVER §13.3). The count on the
//! state row is what GC reads. The rows stay in the object's content shard.
//!
//! **Deadlines.** Hold and holder batches carry a `NotAfter` deadline of
//! `now_ms + `[`CONTENT_APPLY_WINDOW_MS`]: a batch that reaches the store
//! after its plan-time blocklist and `deleting` reads went stale writes
//! nothing and answers a retryable [`StoreError::Unavailable`] (§14.2).

use mkit_core::hash::Hash;

use super::codec;
use super::error::StoreError;
use super::keys::{self, ParsedKey};
use super::kv::{Batch, BatchOutcome, Cursor, Key, NamespaceStore, Precondition, Value, Write};
use super::partition::Partition;
use crate::repo::{NamespaceKey, RepoName};

/// Object-id prefix fan-out of the global content shards: a fixed deployment
/// constant, never resharded (PRD §5.3, D34).
pub const INDEX_FANOUT: u16 = 4096;
const _: () = assert!(INDEX_FANOUT == 1 << 12);

/// Object-id prefix fan-out of each repository's index shards: the top four
/// bits of the id. A fixed deployment constant, never resharded. It is small
/// on purpose: the shards are per repository, so a repository's rows spread
/// over few partitions and a whole-repository copy or sweep touches at most
/// sixteen of them.
pub const REPO_INDEX_FANOUT: u16 = 16;
const _: () = assert!(REPO_INDEX_FANOUT == 1 << 4);

/// Ref-name hash fan-out: a fixed deployment constant, never resharded
/// (PRD §5.3, D34).
pub const REF_INDEX_FANOUT: u16 = 16;

/// Longest [`BlockEntry::reason`], in bytes.
pub const MAX_BLOCK_REASON_BYTES: usize = 256;

/// Longest hold, from `now_ms` to its expiry: 24 hours. A hold must
/// outlive `MAX_APPLY_WINDOW` plus the relay-lag bound (00-plan P-21,
/// P-23); the cap stops a caller from pinning an object indefinitely.
pub const MAX_HOLD_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// How long a hold or holder batch may take to reach the store, from the
/// `now_ms` its plan was made at (`NotAfter`, SPEC-WRITE-GRANTS §5.5). The
/// same bound as `MAX_APPLY_WINDOW`.
pub const CONTENT_APPLY_WINDOW_MS: u64 = 10_000;

/// Optimistic re-plans (normative rule 3) before a contended mutation
/// fails with a retryable [`StoreError::Unavailable`].
const MAX_ATTEMPTS: usize = 8;
/// Page size of the hold scan in [`ContentIndex::collectable`].
const HOLD_SCAN_PAGE: u32 = 100;
/// Hold rows a mutation reads to prune the expired ones.
const PRUNE_SCAN: u32 = 32;
/// Most expired holds one GC plan deletes (the batch stays under
/// `MAX_BATCH_OPS`); later mutations prune the rest.
const GC_PRUNE_MAX: usize = 90;

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
#[non_exhaustive]
pub struct Holder {
    /// Namespace.
    pub ns: NamespaceKey,
    /// Repository.
    pub repo: RepoName,
}

impl Holder {
    /// A holder.
    #[must_use]
    pub fn new(ns: NamespaceKey, repo: RepoName) -> Self {
        Self { ns, repo }
    }
}

/// One page of [`ContentIndex::holders`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct HolderPage {
    /// Holders in key order.
    pub holders: Vec<Holder>,
    /// Resume point, if more holders may follow.
    pub next: Option<Cursor>,
}

/// A holder row's value (R-131).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HolderRecord {
    /// The object's change sequence when the row was written (post-bump), so
    /// the row is replaced, and a stale removal refused, by every later
    /// write.
    pub seq: u64,
    /// The operation that recorded it: the consuming ticket id. Orphan
    /// reconciliation (WP-5.3a) checks the ticket's liveness through it.
    pub op_id: Hash,
}

impl HolderRecord {
    /// A holder record.
    #[must_use]
    pub fn new(seq: u64, op_id: Hash) -> Self {
        Self { seq, op_id }
    }
}

/// A blocklist entry (PRD §6.7 takedown).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockEntry {
    /// Reason code, at most [`MAX_BLOCK_REASON_BYTES`].
    pub reason: String,
    /// When the object was blocked, Unix ms.
    pub blocked_at_ms: u64,
}

impl BlockEntry {
    /// A blocklist entry.
    #[must_use]
    pub fn new(reason: impl Into<String>, blocked_at_ms: u64) -> Self {
        Self {
            reason: reason.into(),
            blocked_at_ms,
        }
    }
}

/// An object's state row. Absent means never indexed: no holders, no holds,
/// last change at 0, not deleting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ObjectState {
    /// Change sequence; every mutation increments it.
    pub seq: u64,
    /// Time of the last change, Unix ms (never moves backwards).
    pub changed_at_ms: u64,
    /// Number of holder rows.
    pub holders: u64,
    /// GC committed to deleting the object's bytes (see the module docs).
    pub deleting: bool,
}

impl ObjectState {
    /// A state row.
    #[must_use]
    pub fn new(seq: u64, changed_at_ms: u64, holders: u64, deleting: bool) -> Self {
        Self {
            seq,
            changed_at_ms,
            holders,
            deleting,
        }
    }
}

/// The result of [`ContentIndex::add_hold`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum HoldOutcome {
    /// The hold is recorded.
    Held,
    /// The object is on the blocklist: nothing was written, and the upload
    /// must be rejected.
    Blocked(BlockEntry),
}

/// The result of [`ContentIndex::add_holder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HolderOutcome {
    /// The holder row was not there before.
    pub newly_added: bool,
    /// The object had no holder before this write.
    pub first_holder: bool,
    /// What the holder row now says.
    pub record: HolderRecord,
    /// The object's blocklist entry, if blocked: the relay then takes the
    /// object down in the holding repo (R-75). The row is recorded either
    /// way, so a takedown finds the holder.
    pub blocked: Option<BlockEntry>,
}

/// A GC delete plan from [`ContentIndex::collectable`]: one batch in the
/// object's shard, guarded on the state row it checked, that prunes the
/// expired holds and sets `deleting`. Apply it with
/// [`ContentIndex::commit_collect`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GcPlan {
    /// The object's shard.
    pub partition: Partition,
    /// The guarded batch.
    pub batch: Batch,
}

/// What a mutation saw, for its plan.
struct Seen {
    probe: Option<Value>,
    /// The auxiliary row a mutation named (the hold a holder releases).
    aux: Option<Value>,
    blocked: Option<BlockEntry>,
}

/// A mutation's plan: commit writes, or stop without writing.
enum Step<T> {
    Commit(Vec<Write>, T),
    Stop(T),
    CommitBatch(Batch, T),
}

fn refuse_while_deleting(state: &ObjectState) -> Result<(), StoreError> {
    if state.deleting {
        return Err(StoreError::unavailable(
            "object is being garbage-collected; retry",
        ));
    }
    Ok(())
}

/// Guard the layout version `v` read: `Absent` plus a put of this binary's
/// version, or `Equals`; refuse any other version.
fn guard_layout(batch: Batch, v: Option<&Value>) -> Result<Batch, StoreError> {
    let key = keys::layout_version();
    Ok(match v {
        None => batch
            .require(Precondition::Absent(key.clone()))
            .put(key, codec::encode_u32(keys::LAYOUT_VERSION)),
        Some(v) if codec::decode_u32(v)? != keys::LAYOUT_VERSION => {
            return Err(StoreError::Unsupported(
                "content shard has a different layout version".into(),
            ));
        }
        Some(v) => batch.require(Precondition::Equals(key, v.clone())),
    })
}

/// Guard the state row read at `key`: `Equals` its value or `Absent`.
fn guard_state(key: &Key, old: Option<&Value>) -> Precondition {
    match old {
        Some(v) => Precondition::Equals(key.clone(), v.clone()),
        None => Precondition::Absent(key.clone()),
    }
}

/// The `c` row after a change at `now_ms`.
fn bumped(mut state: ObjectState, now_ms: u64) -> ObjectState {
    state.seq = state.seq.wrapping_add(1);
    state.changed_at_ms = state.changed_at_ms.max(now_ms);
    state
}

/// A store borrowed for one call, without cloning a Worker adapter or
/// changing its partition routing: the relay's target, and the store a
/// [`ContentIndex`] runs over during extraction.
pub(crate) struct BorrowedStore<'a, S>(pub(crate) &'a S);

impl<S: NamespaceStore> NamespaceStore for BorrowedStore<'_, S> {
    fn capabilities(&self) -> super::kv::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, k).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.0.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<super::kv::ScanPage, StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<super::kv::PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
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

    /// Record GC hold `hold_id` on `object` until `expires_at_ms`.
    /// Re-adding keeps the later of the two expiries. Taken **before** the
    /// ref-shard apply that makes the object reachable (PRD §5.3). The TTL
    /// must exceed `MAX_APPLY_WINDOW` plus the relay-lag bound (00-plan
    /// P-21, P-23) and is capped at [`MAX_HOLD_TTL_MS`].
    ///
    /// # Errors
    /// [`StoreError::Invalid`] if the hold is already expired or longer
    /// than [`MAX_HOLD_TTL_MS`]; a retryable [`StoreError::Unavailable`]
    /// while GC is deleting the object.
    pub async fn add_hold(
        &self,
        object: &Hash,
        hold_id: &Hash,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<HoldOutcome, StoreError> {
        if expires_at_ms <= now_ms {
            return Err(StoreError::Invalid("hold already expired".into()));
        }
        if expires_at_ms - now_ms > MAX_HOLD_TTL_MS {
            return Err(StoreError::Invalid("hold exceeds MAX_HOLD_TTL_MS".into()));
        }
        let key = keys::hold(object, hold_id);
        self.mutate(object, now_ms, Some(&key), None, true, |seen, state| {
            if let Some(entry) = &seen.blocked {
                return Ok(Step::Stop(HoldOutcome::Blocked(entry.clone())));
            }
            refuse_while_deleting(state)?;
            let old = seen.probe.as_ref().map(codec::decode_hold).transpose()?;
            let expiry = old.map_or(expires_at_ms, |old| old.max(expires_at_ms));
            let put = Write::Put(key.clone(), codec::encode_hold(expiry));
            Ok(Step::Commit(vec![put], HoldOutcome::Held))
        })
        .await
    }

    /// Extend hold `hold_id` on `object` to `expires_at_ms`, only if it is
    /// still recorded and live at `now_ms`. A hold that is gone or expired
    /// may already have been passed by GC, so it is not brought back: the
    /// caller redoes from the `head` check.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] as for [`Self::add_hold`]; a retryable
    /// [`StoreError::Unavailable`] while GC is deleting the object or when
    /// the hold is no longer live.
    pub async fn extend_hold(
        &self,
        object: &Hash,
        hold_id: &Hash,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<HoldOutcome, StoreError> {
        if expires_at_ms <= now_ms {
            return Err(StoreError::Invalid("hold already expired".into()));
        }
        if expires_at_ms - now_ms > MAX_HOLD_TTL_MS {
            return Err(StoreError::Invalid("hold exceeds MAX_HOLD_TTL_MS".into()));
        }
        let key = keys::hold(object, hold_id);
        self.mutate(object, now_ms, Some(&key), None, true, |seen, state| {
            if let Some(entry) = &seen.blocked {
                return Ok(Step::Stop(HoldOutcome::Blocked(entry.clone())));
            }
            refuse_while_deleting(state)?;
            let old = seen.probe.as_ref().map(codec::decode_hold).transpose()?;
            let Some(old) = old.filter(|old| *old > now_ms) else {
                return Err(StoreError::unavailable("hold no longer live; retry"));
            };
            let put = Write::Put(key.clone(), codec::encode_hold(old.max(expires_at_ms)));
            Ok(Step::Commit(vec![put], HoldOutcome::Held))
        })
        .await
    }

    /// Establish durable queued-holder ownership before creating a source
    /// relay intent. Identical retries do not bump `c`; a different owner
    /// cannot replace it. No expiration or unguarded removal is supported.
    /// The value binds repository, source, verification job and intent.
    pub async fn protect_pending_holder(
        &self,
        object: &Hash,
        hold_id: &Hash,
        identity: &super::PendingHolderV1,
        now_ms: u64,
    ) -> Result<HoldOutcome, StoreError> {
        if identity.object != *object || identity.hold_id != *hold_id {
            return Err(StoreError::Corrupt("pending holder key mismatch".into()));
        }
        let identity = identity.encode()?;
        let key = keys::pending_holder(object, hold_id);
        self.mutate(object, now_ms, Some(&key), None, true, |seen, state| {
            if let Some(entry) = &seen.blocked {
                return Ok(Step::Stop(HoldOutcome::Blocked(entry.clone())));
            }
            refuse_while_deleting(state)?;
            if let Some(prior) = &seen.probe {
                if prior != &identity {
                    return Err(StoreError::Corrupt(
                        "pending-holder identity changed".into(),
                    ));
                }
                return Ok(Step::Stop(HoldOutcome::Held));
            }
            Ok(Step::Commit(
                vec![Write::Put(key.clone(), identity.clone())],
                HoldOutcome::Held,
            ))
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
        self.mutate(object, now_ms, None, None, true, |_, _| {
            Ok(Step::Commit(vec![Write::Delete(key.clone())], ()))
        })
        .await
    }

    /// Record that `holder` holds `object` (idempotent), releasing hold
    /// `releases` in the same batch: a dedup hold is released only when its
    /// holder row is recorded (PRD §6.7). `op_id` is the consuming ticket.
    /// Every call advances the object's sequence and rewrites the row, also
    /// when the holder was already recorded (SPEC-SERVER §13.3), so the
    /// count changes only for a new holder. A blocked object is still
    /// recorded, and reported in the outcome.
    ///
    /// # Errors
    /// A retryable [`StoreError::Unavailable`] while GC is deleting the
    /// object, or when the batch missed its `NotAfter` deadline.
    pub async fn add_holder(
        &self,
        object: &Hash,
        holder: &Holder,
        op_id: &Hash,
        releases: Option<&Hash>,
        now_ms: u64,
    ) -> Result<HolderOutcome, StoreError> {
        self.holder_write(object, holder, op_id, releases, now_ms, false)
            .await
    }

    /// Like [`Self::add_holder`], but a blocked object is not recorded: the
    /// hold `releases` is deleted in the same guarded batch and the outcome
    /// carries the block entry, so the caller fails the upload and the bytes
    /// fall to ordinary GC (SPEC-SERVER §14.2). Used by extraction; the relay
    /// still records blocked holders (R-75).
    ///
    /// # Errors
    /// As [`Self::add_holder`].
    pub async fn add_holder_unless_blocked(
        &self,
        object: &Hash,
        holder: &Holder,
        op_id: &Hash,
        releases: Option<&Hash>,
        now_ms: u64,
    ) -> Result<HolderOutcome, StoreError> {
        self.holder_write(object, holder, op_id, releases, now_ms, true)
            .await
    }

    async fn holder_write(
        &self,
        object: &Hash,
        holder: &Holder,
        op_id: &Hash,
        releases: Option<&Hash>,
        now_ms: u64,
        refuse_blocked: bool,
    ) -> Result<HolderOutcome, StoreError> {
        let key = keys::holder(object, &holder.ns, &holder.repo)?;
        let release = releases.map(|id| keys::hold(object, id));
        self.mutate(
            object,
            now_ms,
            Some(&key),
            release.as_ref(),
            true,
            |seen, state| {
                refuse_while_deleting(state)?;
                if refuse_blocked && let Some(entry) = &seen.blocked {
                    let record = HolderRecord::new(bumped(*state, now_ms).seq, *op_id);
                    let writes = release.clone().map(Write::Delete).into_iter().collect();
                    return Ok(Step::Commit(
                        writes,
                        HolderOutcome {
                            newly_added: false,
                            first_holder: false,
                            record,
                            blocked: Some(entry.clone()),
                        },
                    ));
                }
                // A hold that is gone or expired no longer protects the bytes the
                // caller relied on: GC may have passed. Retry from the `head`.
                if release.is_some()
                    && !seen.aux.as_ref().is_some_and(|hold| {
                        codec::decode_hold(hold).is_ok_and(|expires| expires > now_ms)
                    })
                {
                    return Err(StoreError::unavailable("hold no longer live; retry"));
                }
                let newly_added = seen.probe.is_none();
                let first_holder = state.holders == 0;
                if newly_added {
                    state.holders += 1;
                }
                // The sequence this write stores: `mutate` bumps it once more.
                let record = HolderRecord::new(bumped(*state, now_ms).seq, *op_id);
                let mut writes = vec![Write::Put(key.clone(), codec::encode_holder(&record))];
                writes.extend(release.clone().map(Write::Delete));
                let outcome = HolderOutcome {
                    newly_added,
                    first_holder,
                    record,
                    blocked: seen.blocked.clone(),
                };
                Ok(Step::Commit(writes, outcome))
            },
        )
        .await
    }

    /// The record of `holder` of `object`, if recorded.
    pub async fn holder_record(
        &self,
        object: &Hash,
        holder: &Holder,
    ) -> Result<Option<HolderRecord>, StoreError> {
        let key = keys::holder(object, &holder.ns, &holder.repo)?;
        let value = self.store.get(&content_shard(object), &key).await?;
        value.as_ref().map(codec::decode_holder).transpose()
    }

    /// Remove `holder` of `object`, only if its row still carries
    /// `expected_seq` (the sequence of the record the caller read). `true`
    /// if it was removed; `false` (a no-op) when the holder is absent or was
    /// written again since (SPEC-SERVER §13.3 step 4).
    pub async fn remove_holder(
        &self,
        object: &Hash,
        holder: &Holder,
        expected_seq: u64,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let key = keys::holder(object, &holder.ns, &holder.repo)?;
        self.mutate(object, now_ms, Some(&key), None, true, |seen, state| {
            let current = seen.probe.as_ref().map(codec::decode_holder).transpose()?;
            if current.is_none_or(|record| record.seq != expected_seq) {
                return Ok(Step::Stop(false));
            }
            state.holders = state.holders.saturating_sub(1);
            Ok(Step::Commit(vec![Write::Delete(key.clone())], true))
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
        crate::takedown::directory::reserve(&self.store, object, now_ms).await?;
        let (key, value) = (keys::block(object), codec::encode_block_entry(entry));
        self.mutate(object, now_ms, None, None, false, |_, _| {
            Ok(Step::Commit(
                vec![
                    Write::Put(key.clone(), value.clone()),
                    Write::Put(
                        crate::takedown::denial::legacy_descriptor_key(object),
                        value.clone(),
                    ),
                ],
                (),
            ))
        })
        .await
    }

    /// Install an independent V2 action without replacing any current V1 denial.
    pub async fn install_block_action(
        &self,
        object: &Hash,
        action: &crate::takedown::denial::BlockAction,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let staged =
            crate::takedown::denial::stage_action(&self.store, object, action, now_ms).await?;
        self.install_stored_block_action(object, &staged, now_ms)
            .await
    }

    /// Activate already verified immutable metadata without reading source bytes.
    pub async fn install_stored_block_action(
        &self,
        object: &Hash,
        staged: &crate::takedown::denial::StoredAction,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        self.install_stored_block_action_with_batch(object, staged, now_ms, Batch::new())
            .await
    }

    /// Commit source-local safety effects atomically with a new denial action.
    pub(crate) async fn install_stored_block_action_with_batch(
        &self,
        object: &Hash,
        staged: &crate::takedown::denial::StoredAction,
        now_ms: u64,
        effects: Batch,
    ) -> Result<(), StoreError> {
        use crate::takedown::denial::{action_key, decode_actions, encode_actions};
        crate::takedown::directory::reserve(&self.store, object, now_ms).await?;
        let key = action_key(object);
        self.mutate(object, now_ms, Some(&key), None, false, |seen, _| {
            let mut actions = decode_actions(seen.probe.as_ref())?;
            match actions.binary_search_by_key(&staged.action.id, |a| a.action.id) {
                Ok(i) if actions[i] == *staged => return Ok(Step::Stop(())),
                Ok(_) => return Err(StoreError::Invalid("denial action identity reused".into())),
                Err(i) => actions.insert(i, staged.clone()),
            }
            let value = encode_actions(actions)?;
            let mut batch = effects.clone();
            batch.writes.extend([
                Write::Put(key.clone(), value.clone()),
                Write::Put(crate::takedown::denial::descriptor_key(object), value),
            ]);
            Ok(Step::CommitBatch(batch, ()))
        })
        .await
    }

    /// Take `object` off the blocklist.
    pub async fn unblock(&self, object: &Hash, now_ms: u64) -> Result<(), StoreError> {
        let key = keys::block(object);
        self.mutate(object, now_ms, None, None, false, |_, _| {
            Ok(Step::Commit(
                vec![
                    Write::Delete(key.clone()),
                    Write::Delete(crate::takedown::denial::legacy_descriptor_key(object)),
                ],
                (),
            ))
        })
        .await
    }

    /// The blocklist entry of `object`, if blocked.
    pub async fn blocked(&self, object: &Hash) -> Result<Option<BlockEntry>, StoreError> {
        let rows = self
            .store
            .get_many(
                &content_shard(object),
                &[
                    keys::block(object),
                    crate::takedown::denial::action_key(object),
                ],
            )
            .await?;
        if rows.len() != 2 {
            return Err(StoreError::Corrupt("short denial read".into()));
        }
        let legacy = rows[0]
            .as_ref()
            .map(codec::decode_block_entry)
            .transpose()?;
        let independent = crate::takedown::denial::representative(rows[1].as_ref())?;
        Ok(legacy.or(independent))
    }

    /// The state row of `object`, if it was ever indexed.
    pub async fn state(&self, object: &Hash) -> Result<Option<ObjectState>, StoreError> {
        let value = self
            .store
            .get(&content_shard(object), &keys::object_state(object))
            .await?;
        value.as_ref().map(codec::decode_object_state).transpose()
    }

    /// Step 1 of the GC ordering (module docs). Whether GC may delete
    /// `object` at `now_ms`: not already `deleting`, zero holders, zero
    /// live holds (a hold is live while `now_ms < expires_at_ms`), and
    /// `now_ms - last change >= grace_ms`. If so, the [`GcPlan`] that
    /// commits the decision.
    pub async fn collectable(
        &self,
        object: &Hash,
        now_ms: u64,
        grace_ms: u64,
    ) -> Result<Option<GcPlan>, StoreError> {
        let p = content_shard(object);
        let state_key = keys::object_state(object);
        let read = [keys::layout_version(), state_key.clone()];
        let values = self.store.get_many(&p, &read).await?;
        let (v, raw) = (values[0].as_ref(), values[1].as_ref());
        let state = raw
            .map(codec::decode_object_state)
            .transpose()?
            .unwrap_or_default();
        if state.deleting
            || state.holders > 0
            || now_ms.saturating_sub(state.changed_at_ms) < grace_ms
        {
            return Ok(None);
        }
        // Pending holder intents remain applicable beyond ticket/hold expiry.
        // Even unknown/corrupt rows block deletion; reconciliation must prove
        // that no durable source intent can still deliver before removing one.
        let (start, end) = keys::pending_holders_of(object);
        if !self
            .store
            .scan(&p, &start, &end, None, 1)
            .await?
            .entries
            .is_empty()
        {
            return Ok(None);
        }
        let mut expired = Vec::new();
        let (start, end) = keys::holds_of(object);
        let mut after = None;
        loop {
            let page = self
                .store
                .scan(&p, &start, &end, after.as_ref(), HOLD_SCAN_PAGE)
                .await?;
            for (key, value) in page.entries {
                if codec::decode_hold(&value)? > now_ms {
                    return Ok(None);
                }
                if expired.len() < GC_PRUNE_MAX {
                    expired.push(Write::Delete(key));
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let mut batch = guard_layout(Batch::new(), v)?.require(guard_state(&state_key, raw));
        batch.writes.extend(expired);
        let mut next = bumped(state, now_ms);
        next.deleting = true;
        let batch = batch.put(state_key, codec::encode_object_state(&next));
        Ok(Some(GcPlan {
            partition: p,
            batch,
        }))
    }

    /// Step 2 of the GC ordering: apply `plan`. `true` if it committed and
    /// the object is now `deleting`, so GC may delete its bytes; `false` if
    /// anything changed since the plan was made.
    pub async fn commit_collect(&self, plan: GcPlan) -> Result<bool, StoreError> {
        let outcome = self.store.apply(&plan.partition, plan.batch).await?;
        Ok(outcome == BatchOutcome::Committed)
    }

    /// Step 4 of the GC ordering: after the bytes are deleted, clear
    /// `deleting` so the object can be uploaded again. A no-op if it is not
    /// set.
    pub async fn finish_collect(&self, object: &Hash, now_ms: u64) -> Result<(), StoreError> {
        self.mutate(object, now_ms, None, None, false, |_, state| {
            if !state.deleting {
                return Ok(Step::Stop(()));
            }
            state.deleting = false;
            Ok(Step::Commit(Vec::new(), ()))
        })
        .await
    }

    /// Apply one per-object mutation. Read the layout version, the state
    /// row, the blocklist entry and `probe`, plus a page of holds; `plan`
    /// sees them and updates the state, then either stops (nothing is
    /// written) or returns its writes. They commit after deletes of the
    /// expired holds read and before the new state row, guarded on the
    /// layout version and the state row (every change to the object's rows
    /// rewrites it). Re-plans on a lost race. With `deadline`, the batch also
    /// requires `NotAfter(now_ms + CONTENT_APPLY_WINDOW_MS)`, and a batch
    /// that misses it is a retryable [`StoreError::Unavailable`] (a re-plan
    /// would reuse the same stale `now_ms`).
    async fn mutate<T>(
        &self,
        object: &Hash,
        now_ms: u64,
        probe: Option<&Key>,
        aux: Option<&Key>,
        deadline: bool,
        plan: impl Fn(&Seen, &mut ObjectState) -> Result<Step<T>, StoreError>,
    ) -> Result<T, StoreError> {
        let p = content_shard(object);
        let state_key = keys::object_state(object);
        let mut read = vec![
            keys::layout_version(),
            state_key.clone(),
            keys::block(object),
            crate::takedown::denial::action_key(object),
        ];
        read.extend(probe.cloned());
        read.extend(aux.cloned());
        let (hold_start, hold_end) = keys::holds_of(object);
        for _ in 0..MAX_ATTEMPTS {
            let values = self.store.get_many(&p, &read).await?;
            if values.len() != read.len() {
                return Err(StoreError::Corrupt("short content read".into()));
            }
            let mut values = values.into_iter();
            let (v, old, blocked) = (values.next(), values.next(), values.next());
            let (v, old, blocked) = (v.flatten(), old.flatten(), blocked.flatten());
            let independent =
                crate::takedown::denial::representative(values.next().flatten().as_ref())?;
            // The optional rows follow the fixed ones, in this order.
            let probed = probe.and_then(|_| values.next().flatten());
            let auxiliary = aux.and_then(|_| values.next().flatten());
            let seen = Seen {
                probe: probed,
                aux: auxiliary,
                blocked: blocked
                    .as_ref()
                    .map(codec::decode_block_entry)
                    .transpose()?
                    .or(independent),
            };
            let holds = self
                .store
                .scan(&p, &hold_start, &hold_end, None, PRUNE_SCAN)
                .await?;
            let mut state = old
                .as_ref()
                .map(codec::decode_object_state)
                .transpose()?
                .unwrap_or_default();
            let (mut batch, out) = match plan(&seen, &mut state)? {
                Step::Stop(out) => return Ok(out),
                Step::Commit(writes, out) => (
                    Batch {
                        preconditions: Vec::new(),
                        writes,
                    },
                    out,
                ),
                Step::CommitBatch(batch, out) => (batch, out),
            };
            let writes = std::mem::take(&mut batch.writes);
            if deadline {
                let by = now_ms.saturating_add(CONTENT_APPLY_WINDOW_MS);
                batch = batch.require(Precondition::NotAfter(by));
            }
            let mut batch =
                guard_layout(batch, v.as_ref())?.require(guard_state(&state_key, old.as_ref()));
            for (key, value) in holds.entries {
                if codec::decode_hold(&value)? <= now_ms {
                    batch = batch.delete(key);
                }
            }
            batch.writes.extend(writes);
            let batch = batch.put(
                state_key.clone(),
                codec::encode_object_state(&bumped(state, now_ms)),
            );
            match self.store.apply(&p, batch).await? {
                BatchOutcome::Committed => return Ok(out),
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(StoreError::unavailable(
                        "content index deadline passed; retry",
                    ));
                }
                BatchOutcome::PreconditionFailed { .. } => {}
            }
        }
        Err(StoreError::unavailable("content index update contended"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use futures_executor::block_on;

    use super::*;
    use crate::ManualClock;
    use crate::memory::MemoryKv;

    const GRACE: u64 = 1_000;
    /// The consuming ticket every test holder is recorded under.
    const OP: Hash = [0x0f; 32];

    /// A store whose `NotAfter` clock never reaches a test's small times.
    fn kv() -> MemoryKv {
        MemoryKv::with_clock(Arc::new(ManualClock::new(0)))
    }

    fn holder(repo: &str) -> Holder {
        Holder::new(
            NamespaceKey::deployment_default(),
            RepoName::new(repo).unwrap(),
        )
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
    fn expired_hold_readded_keeps_its_fresh_expiry_after_pruning() {
        let idx = ContentIndex::new(kv());
        let object = [0x53; 32];
        let hold = [0x35; 32];
        held(block_on(idx.add_hold(&object, &hold, 5, 0)));
        held(block_on(idx.add_hold(&object, &hold, 10_000, 6)));
        let key = keys::hold(&object, &hold);
        assert_eq!(
            block_on(idx.store().get(&content_shard(&object), &key)).unwrap(),
            Some(codec::encode_hold(10_000)),
            "pruning the expired snapshot must precede the fresh hold write"
        );
        assert!(!collectable(&idx, &object, GRACE + 10));
        held(block_on(idx.extend_hold(&object, &hold, 12_000, 7)));
        assert_eq!(
            block_on(idx.store().get(&content_shard(&object), &key)).unwrap(),
            Some(codec::encode_hold(12_000))
        );
        assert_eq!(state(&idx, &object).seq, 3);
    }

    #[test]
    fn pending_holder_insert_invalidates_gc_and_retries_do_not_bump() {
        let idx = ContentIndex::new(kv());
        let object = [0x47; 32];
        let hold = [0x74; 32];
        let prior = block_on(idx.collectable(&object, GRACE, GRACE))
            .unwrap()
            .unwrap();
        let owner = super::super::PendingHolderV1::new(
            holder("repo"),
            Partition::Namespace(NamespaceKey::deployment_default()),
            OP,
            object,
            hold,
            [0x55; 32],
        )
        .unwrap();
        held(block_on(
            idx.protect_pending_holder(&object, &hold, &owner, GRACE),
        ));
        assert!(!block_on(idx.commit_collect(prior)).unwrap());
        let recorded = state(&idx, &object);
        held(block_on(idx.protect_pending_holder(
            &object,
            &hold,
            &owner,
            GRACE + 1,
        )));
        assert_eq!(state(&idx, &object), recorded);
        assert!(!collectable(&idx, &object, u64::MAX));
        let mut replacement = owner.clone();
        replacement.intent = [0x56; 32];
        assert!(matches!(
            block_on(idx.protect_pending_holder(&object, &hold, &replacement, GRACE + 1)),
            Err(StoreError::Corrupt(_))
        ));
        let raw = owner.encode().unwrap();
        assert_eq!(super::super::PendingHolderV1::decode(&raw).unwrap(), owner);
        let mut trailing = raw.as_bytes().to_vec();
        trailing.push(0);
        assert!(super::super::PendingHolderV1::decode(&Value::new(trailing)).is_err());
        assert_eq!(
            keys::parse(&keys::pending_holder(&object, &hold)),
            Some(ParsedKey::PendingHolder {
                object,
                hold_id: hold
            })
        );
    }

    #[test]
    fn pending_holder_protection_survives_expired_hold() {
        let store = kv();
        let idx = ContentIndex::new(store);
        let object = [0x42; 32];
        let hold = [0x24; 32];
        held(block_on(idx.add_hold(&object, &hold, 5_000, 0)));
        let key = keys::pending_holder(&object, &hold);
        block_on(idx.store().apply(
            &content_shard(&object),
            Batch::new().put(key, Value::new(vec![1])),
        ))
        .unwrap();
        assert!(
            !collectable(&idx, &object, MAX_HOLD_TTL_MS + GRACE),
            "queued holder work protects bytes after the TTL expires"
        );
    }

    /// Remove `repo`'s holder at the sequence its row carries now.
    fn remove(idx: &ContentIndex<MemoryKv>, object: &Hash, repo: &str, now: u64) -> bool {
        let Some(record) = block_on(idx.holder_record(object, &holder(repo))).unwrap() else {
            return block_on(idx.remove_holder(object, &holder(repo), 0, now)).unwrap();
        };
        block_on(idx.remove_holder(object, &holder(repo), record.seq, now)).unwrap()
    }

    fn hold_row(idx: &ContentIndex<MemoryKv>, object: &Hash, id: &Hash) -> Option<u64> {
        let v = block_on(
            idx.store()
                .get(&content_shard(object), &keys::hold(object, id)),
        );
        v.unwrap().map(|v| codec::decode_hold(&v).unwrap())
    }

    fn held(outcome: Result<HoldOutcome, StoreError>) {
        assert_eq!(outcome.unwrap(), HoldOutcome::Held);
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
        let idx = ContentIndex::new(kv());
        let obj = [7; 32];
        // Never indexed: nothing holds it, its last change counts as 0, and
        // the plan is guarded on the absent state row.
        assert!(!collectable(&idx, &obj, GRACE - 1));
        let plan = block_on(idx.collectable(&obj, GRACE, GRACE))
            .unwrap()
            .unwrap();
        assert!(
            plan.batch
                .preconditions
                .contains(&Precondition::Absent(keys::object_state(&obj)))
        );
        block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 10)).unwrap();
        assert!(!collectable(&idx, &obj, 10 + GRACE * 10), "held");
        remove(&idx, &obj, "a", 20);
        assert!(!collectable(&idx, &obj, 20 + GRACE - 1), "within grace");
        assert!(collectable(&idx, &obj, 20 + GRACE));
        // A live hold blocks collection; an expired one does not.
        held(block_on(idx.add_hold(&obj, &[1; 32], 5_000, 30)));
        assert!(!collectable(&idx, &obj, 30 + GRACE));
        assert!(!collectable(&idx, &obj, 4_999));
        assert!(collectable(&idx, &obj, 5_000), "a hold ends at its expiry");
        // A plan fails once anything changes after it was made.
        let stale = block_on(idx.collectable(&obj, 5_001, GRACE))
            .unwrap()
            .unwrap();
        let entry = BlockEntry::new("dmca", 9);
        block_on(idx.block(&obj, &entry, 5_002)).unwrap();
        assert!(!block_on(idx.commit_collect(stale)).unwrap());
        assert!(!state(&idx, &obj).deleting);
        // A blocklist entry is not a hold. The plan prunes the expired hold
        // and marks the object deleting.
        let plan = block_on(idx.collectable(&obj, 5_002 + GRACE, GRACE))
            .unwrap()
            .unwrap();
        assert!(block_on(idx.commit_collect(plan)).unwrap());
        assert!(state(&idx, &obj).deleting);
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), None);
        assert!(!collectable(&idx, &obj, u64::MAX), "already deleting");
    }

    #[test]
    fn content_index_gc_commit_beats_a_racing_upload() {
        let idx = ContentIndex::new(kv());
        let obj = [6; 32];
        block_on(idx.release_hold(&obj, &[0; 32], 1)).unwrap();
        let plan = block_on(idx.collectable(&obj, 1 + GRACE, GRACE))
            .unwrap()
            .unwrap();
        // GC commits first: the upload's hold must fail retryably rather
        // than let the upload dedup against bytes GC is about to delete.
        assert!(block_on(idx.commit_collect(plan)).unwrap());
        let now = 2 + GRACE;
        assert!(matches!(
            block_on(idx.add_hold(&obj, &[1; 32], now + 100, now)),
            Err(StoreError::Unavailable(_))
        ));
        assert!(matches!(
            block_on(idx.add_holder(&obj, &holder("a"), &OP, None, now)),
            Err(StoreError::Unavailable(_))
        ));
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), None);
        // After the blob delete, GC clears the mark and uploads resume.
        block_on(idx.finish_collect(&obj, now)).unwrap();
        let s = state(&idx, &obj);
        block_on(idx.finish_collect(&obj, now)).unwrap();
        assert_eq!(state(&idx, &obj), s, "finishing twice is a no-op");
        held(block_on(idx.add_hold(&obj, &[1; 32], now + 100, now)));
        // The other order: a hold taken first makes the plan fail.
        let plan = block_on(idx.collectable(&obj, now + 100 + GRACE, GRACE))
            .unwrap()
            .unwrap();
        held(block_on(idx.add_hold(
            &obj,
            &[2; 32],
            now + 200 + GRACE,
            now + 100 + GRACE,
        )));
        assert!(!block_on(idx.commit_collect(plan)).unwrap());
    }

    #[test]
    fn content_index_blocklist_on_add_paths() {
        let idx = ContentIndex::new(kv());
        let obj = [5; 32];
        let entry = BlockEntry::new("csam", 1);
        block_on(idx.block(&obj, &entry, 1)).unwrap();
        let before = state(&idx, &obj);
        assert_eq!(
            block_on(idx.add_hold(&obj, &[1; 32], 100, 2)).unwrap(),
            HoldOutcome::Blocked(entry.clone())
        );
        assert_eq!(state(&idx, &obj), before, "a refused hold writes nothing");
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), None);
        let outcome = block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 3)).unwrap();
        assert_eq!((outcome.newly_added, outcome.blocked), (true, Some(entry)));
        block_on(idx.unblock(&obj, 4)).unwrap();
        held(block_on(idx.add_hold(&obj, &[1; 32], 100, 5)));
        let outcome = block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 6)).unwrap();
        assert_eq!((outcome.newly_added, outcome.blocked), (false, None));
    }

    #[test]
    fn content_index_holds_extend_prune_and_cap() {
        let idx = ContentIndex::new(kv());
        let obj = [4; 32];
        held(block_on(idx.add_hold(&obj, &[1; 32], 500, 1)));
        held(block_on(idx.add_hold(&obj, &[1; 32], 300, 2)));
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), Some(500), "never shortened");
        held(block_on(idx.add_hold(&obj, &[1; 32], 700, 3)));
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), Some(700));
        held(block_on(idx.add_hold(&obj, &[2; 32], 50, 4)));
        // A later mutation deletes the expired hold rows it reads.
        block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 600)).unwrap();
        assert_eq!(hold_row(&idx, &obj, &[2; 32]), None);
        assert_eq!(hold_row(&idx, &obj, &[1; 32]), Some(700));
        assert!(matches!(
            block_on(idx.add_hold(&obj, &[3; 32], 10 + MAX_HOLD_TTL_MS + 1, 10)),
            Err(StoreError::Invalid(_))
        ));
        held(block_on(idx.add_hold(
            &obj,
            &[3; 32],
            10 + MAX_HOLD_TTL_MS,
            10,
        )));
    }

    #[test]
    fn content_index_holder_add_idempotent() {
        let idx = ContentIndex::new(kv());
        let obj = [8; 32];
        for i in 0..3 {
            let outcome = block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 1)).unwrap();
            assert_eq!(outcome.newly_added, i == 0);
        }
        block_on(idx.add_holder(&obj, &holder("b"), &OP, None, 1)).unwrap();
        assert_eq!(state(&idx, &obj).holders, 2);
        let page = block_on(idx.holders(&obj, None, 1)).unwrap();
        assert_eq!(page.holders, vec![holder("a")]);
        let rest = block_on(idx.holders(&obj, page.next.as_ref(), 10)).unwrap();
        assert_eq!((rest.holders, rest.next), (vec![holder("b")], None));
        for _ in 0..2 {
            remove(&idx, &obj, "a", 2);
        }
        assert_eq!(state(&idx, &obj).holders, 1);
        // Recording a holder releases its dedup hold in the same batch.
        held(block_on(idx.add_hold(&obj, &[2; 32], 100, 3)));
        let before = state(&idx, &obj).seq;
        block_on(idx.add_holder(&obj, &holder("c"), &OP, Some(&[2; 32]), 4)).unwrap();
        assert_eq!(state(&idx, &obj).seq, before + 1);
        assert_eq!(state(&idx, &obj).holders, 2);
        assert_eq!(hold_row(&idx, &obj, &[2; 32]), None);
    }

    #[test]
    fn content_index_every_mutation_bumps_last_change() {
        let idx = ContentIndex::new(kv());
        let obj = [9; 32];
        let entry = BlockEntry::new("r", 1);
        let mut last = ObjectState::default();
        for (i, now) in (1_u64..).zip([10, 20, 15, 30, 40, 50, 60, 70]) {
            let last_seq = last.seq;
            match i {
                1 => block_on(idx.add_hold(&obj, &[1; 32], 99, now)).map(drop),
                2 | 3 => block_on(idx.add_holder(&obj, &holder("a"), &OP, None, now)).map(drop),
                4 => block_on(idx.remove_holder(&obj, &holder("a"), last_seq, now)).map(drop),
                5 => block_on(idx.release_hold(&obj, &[9; 32], now)),
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
        let long = BlockEntry::new("x".repeat(MAX_BLOCK_REASON_BYTES + 1), 0);
        assert!(matches!(
            block_on(idx.block(&obj, &long, 1)),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(state(&idx, &obj), last, "rejected calls write nothing");
    }

    #[test]
    fn content_index_objects_in_different_shards_isolated() {
        let idx = ContentIndex::new(kv());
        let (a, mut b) = ([0x10; 32], [0x10; 32]);
        b[0] = 0x20;
        assert_ne!(content_shard(&a), content_shard(&b));
        block_on(idx.add_holder(&a, &holder("x"), &OP, None, 1)).unwrap();
        held(block_on(idx.add_hold(&a, &[1; 32], 99, 1)));
        let entry = BlockEntry::new("r", 1);
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
    fn content_index_refuses_other_layout_versions() {
        for version in [keys::LAYOUT_VERSION - 1, keys::LAYOUT_VERSION + 1] {
            refuses_layout_version(version);
        }
    }

    fn refuses_layout_version(version: u32) {
        let idx = ContentIndex::new(kv());
        let obj = [3; 32];
        let newer = Batch::new().put(keys::layout_version(), codec::encode_u32(version));
        block_on(idx.store().apply(&content_shard(&obj), newer)).unwrap();
        assert!(matches!(
            block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 1)),
            Err(StoreError::Unsupported(_))
        ));
        assert!(matches!(
            block_on(idx.collectable(&obj, GRACE, GRACE)),
            Err(StoreError::Unsupported(_))
        ));
    }

    #[test]
    fn content_index_holder_records_advance_seq_and_guard_removal() {
        let idx = ContentIndex::new(kv());
        let obj = [0x31; 32];
        let (a, b) = ([1; 32], [2; 32]);
        let first = block_on(idx.add_holder(&obj, &holder("a"), &a, None, 1)).unwrap();
        assert!(first.newly_added && first.first_holder);
        assert_eq!(first.record, HolderRecord::new(1, a));
        let second = block_on(idx.add_holder(&obj, &holder("b"), &a, None, 2)).unwrap();
        assert!(second.newly_added && !second.first_holder);
        // A re-record advances the sequence and rewrites the row, and the
        // count does not change.
        let again = block_on(idx.add_holder(&obj, &holder("a"), &b, None, 3)).unwrap();
        assert!(!again.newly_added && !again.first_holder);
        assert_eq!(again.record, HolderRecord::new(3, b));
        let stored = block_on(idx.holder_record(&obj, &holder("a"))).unwrap();
        assert_eq!(stored, Some(again.record));
        assert_eq!(state(&idx, &obj).holders, 2);
        assert_eq!(state(&idx, &obj).seq, 3);
        // A removal that read the first record is stale: a no-op that
        // writes nothing, not even a sequence bump.
        assert!(!block_on(idx.remove_holder(&obj, &holder("a"), 1, 4)).unwrap());
        assert_eq!(state(&idx, &obj).seq, 3);
        assert!(!block_on(idx.remove_holder(&obj, &holder("never"), 3, 4)).unwrap());
        assert_eq!(state(&idx, &obj).holders, 2);
        assert!(block_on(idx.remove_holder(&obj, &holder("a"), 3, 5)).unwrap());
        let last = block_on(idx.add_holder(&obj, &holder("b"), &a, None, 6)).unwrap();
        assert!(!last.first_holder);
        assert!(block_on(idx.remove_holder(&obj, &holder("b"), last.record.seq, 7)).unwrap());
        assert_eq!(state(&idx, &obj).holders, 0);
        let refill = block_on(idx.add_holder(&obj, &holder("a"), &a, None, 8)).unwrap();
        assert!(refill.first_holder, "no holder was left");
    }

    /// A store that commits a blocklist entry for `armed` between a
    /// mutation's reads and its batch.
    struct Racing {
        kv: MemoryKv,
        armed: std::sync::Mutex<Option<(Hash, BlockEntry)>>,
    }

    impl NamespaceStore for Racing {
        fn capabilities(&self) -> crate::store::StoreCapabilities {
            self.kv.capabilities()
        }

        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.kv.get(p, key).await
        }

        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<crate::store::ScanPage, StoreError> {
            self.kv.scan(p, start, end, after, limit).await
        }

        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            let race = self.armed.lock().unwrap().take();
            if let Some((object, entry)) = race {
                let raced = Batch::new()
                    .put(keys::block(&object), codec::encode_block_entry(&entry))
                    .put(
                        keys::object_state(&object),
                        codec::encode_object_state(&ObjectState::new(1, 0, 0, false)),
                    );
                self.kv.apply(&content_shard(&object), raced).await?;
            }
            self.kv.apply(p, batch).await
        }

        async fn stats(&self, p: &Partition) -> Result<crate::store::PartitionStats, StoreError> {
            self.kv.stats(p).await
        }

        async fn probe(&self) -> Result<(), StoreError> {
            self.kv.probe().await
        }
    }

    #[test]
    fn content_index_holds_and_holders_racing_block_see_the_block() {
        let entry = BlockEntry::new("dmca", 1);
        let racing = |object: Hash| {
            ContentIndex::new(Racing {
                kv: kv(),
                armed: std::sync::Mutex::new(Some((object, entry.clone()))),
            })
        };
        // The hold's guarded batch loses to the block; its re-plan refuses.
        let obj = [0x41; 32];
        let idx = racing(obj);
        let hold = block_on(idx.add_hold(&obj, &[1; 32], 100, 2)).unwrap();
        assert_eq!(hold, HoldOutcome::Blocked(entry.clone()));
        assert_eq!(hold_row_in(&idx, &obj, &[1; 32]), None);
        // The holder is recorded anyway (a takedown must find it) and
        // reports the block.
        let obj = [0x42; 32];
        let idx = racing(obj);
        let outcome = block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 2)).unwrap();
        assert_eq!(outcome.blocked, Some(entry.clone()));
        assert!(outcome.newly_added);
    }

    fn hold_row_in(idx: &ContentIndex<Racing>, object: &Hash, id: &Hash) -> Option<u64> {
        let key = keys::hold(object, id);
        let v = block_on(idx.store().get(&content_shard(object), &key)).unwrap();
        v.map(|v| codec::decode_hold(&v).unwrap())
    }

    #[test]
    fn content_index_hold_and_holder_batches_carry_a_deadline() {
        let clock = Arc::new(ManualClock::new(0));
        let idx = ContentIndex::new(MemoryKv::with_clock(clock.clone()));
        let obj = [0x51; 32];
        held(block_on(idx.add_hold(&obj, &[1; 32], 100, 10)));
        // The store's clock is past the plan's `now + window`: nothing is
        // written, and the failure is the retryable kind.
        clock.set(i64::try_from(10 + CONTENT_APPLY_WINDOW_MS + 1).unwrap());
        let before = state(&idx, &obj);
        let hold = block_on(idx.add_hold(&obj, &[2; 32], 200, 10));
        assert!(matches!(hold, Err(StoreError::Unavailable(_))));
        let holder_added = block_on(idx.add_holder(&obj, &holder("a"), &OP, None, 10));
        assert!(matches!(holder_added, Err(StoreError::Unavailable(_))));
        let removed = block_on(idx.remove_holder(&obj, &holder("a"), 1, 10));
        assert!(
            !removed.unwrap(),
            "an absent holder is a no-op, before any write"
        );
        assert_eq!(state(&idx, &obj), before);
        assert_eq!(hold_row(&idx, &obj, &[2; 32]), None);
        assert_eq!(
            block_on(idx.holder_record(&obj, &holder("a"))).unwrap(),
            None
        );
        // A fresh plan time succeeds.
        let now = 10 + CONTENT_APPLY_WINDOW_MS + 1;
        assert!(block_on(idx.add_holder(&obj, &holder("a"), &OP, None, now)).is_ok());
    }

    #[test]
    fn content_index_holder_releases_only_a_live_hold() {
        let idx = ContentIndex::new(kv());
        let obj = [0x61; 32];
        // No hold at all, then an expired one: the holder batch refuses and
        // writes nothing.
        let none = block_on(idx.add_holder(&obj, &holder("a"), &OP, Some(&[1; 32]), 1));
        assert!(matches!(none, Err(StoreError::Unavailable(_))));
        held(block_on(idx.add_hold(&obj, &[1; 32], 50, 2)));
        let before = state(&idx, &obj);
        let late = block_on(idx.add_holder(&obj, &holder("a"), &OP, Some(&[1; 32]), 60));
        assert!(matches!(late, Err(StoreError::Unavailable(_))));
        assert_eq!(state(&idx, &obj).holders, before.holders);
        assert_eq!(
            block_on(idx.holder_record(&obj, &holder("a"))).unwrap(),
            None
        );
        // A live hold is released with the holder.
        held(block_on(idx.add_hold(&obj, &[2; 32], 500, 70)));
        block_on(idx.add_holder(&obj, &holder("a"), &OP, Some(&[2; 32]), 80)).unwrap();
        assert_eq!(hold_row(&idx, &obj, &[2; 32]), None);
        assert!(
            block_on(idx.holder_record(&obj, &holder("a")))
                .unwrap()
                .is_some()
        );
    }
}
