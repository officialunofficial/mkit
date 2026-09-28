//! Repository-scoped, write-once object index rows. A row becomes visible
//! only when its pack's repository membership row exists. Production writers
//! are installed by WP-4.7 and WP-4.8.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::Hash;

use super::codec::{self, RelayV1};
use super::keys::{self, ParsedKey};
use super::outbox::MAX_RELAY_PUTS;
use super::{
    BlobKey, Key, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES, MAX_VALUE_BYTES, NamespaceStore,
    Partition, StoreError, Value,
};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;

/// Maximum object ids accepted by one lookup, matching the takedown named-id cap.
pub const MAX_LOOKUP_IDS: usize = 256;
/// Maximum index candidates read in one call. A truncated miss fails closed;
/// no missing result is inferred from a truncated scan.
pub const MAX_LOOKUP_ROWS: usize = 4096;
/// Maximum scan calls in one lookup, including legal empty continuation pages.
pub const MAX_LOOKUP_PAGES: usize = 8192;
const SCAN_PAGE_ROWS: u32 = 128;

/// The immutable location and decoded metadata of one pack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexValue {
    /// Offset of the complete frame in the pack.
    pub frame_offset: u64,
    /// Length of the complete frame on the wire.
    pub frame_length: u64,
    /// SPEC-PACKFILE entry type: raw, delta, zstd raw, or zstd delta.
    pub wire_type: u8,
    /// Reconstructed object size in bytes.
    pub decoded_size: u64,
    /// Delta depth of the entry, with a raw entry at zero.
    pub chain_depth: u32,
    /// Base id for delta entry types only.
    pub delta_base: Option<Hash>,
}

impl IndexValue {
    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        if self.frame_length == 0
            || self.frame_offset.checked_add(self.frame_length).is_none()
            || self.decoded_size == 0
        {
            return Err(StoreError::Invalid("invalid object index lengths".into()));
        }
        match (self.wire_type, self.delta_base, self.chain_depth) {
            (0x00 | 0x03, None, 0) | (0x02 | 0x04, Some(_), 1..) => Ok(()),
            _ => Err(StoreError::Invalid(
                "invalid object index entry type".into(),
            )),
        }
    }
}

/// One verified pack entry in pack order. Repeated object ids in a pack
/// retain the first location and value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry {
    /// Object id.
    pub object: Hash,
    /// Immutable location metadata.
    pub value: IndexValue,
}

/// A direct batch of index upserts to the source partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectIndexBatch {
    /// The source/target partition.
    pub target: Partition,
    /// Key/value upserts in key order.
    pub puts: Vec<(Key, Value)>,
}

/// Pure, deterministic plan. The caller commits each direct batch and
/// enqueues each relay row separately from the advance batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexPlan {
    /// Upserts whose target is the source partition.
    pub direct: Vec<DirectIndexBatch>,
    /// Upserts for other partitions, already bounded for relay delivery.
    pub relay: Vec<RelayV1>,
}

/// Plan one pack's index rows, sorted by partition and key. The first
/// occurrence of an object in `entries` wins. A relay row has at most
/// [`MAX_RELAY_PUTS`] upserts and fits both value and target-batch limits.
pub fn plan_index_rows(
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    pack: &Hash,
    entries: &[IndexEntry],
    at_ms: u64,
) -> Result<IndexPlan, StoreError> {
    let mut grouped: BTreeMap<Partition, BTreeMap<Key, Value>> = BTreeMap::new();
    for entry in entries {
        let target = shards.object_index(repo, &entry.object);
        let key = keys::object_index(&repo.name, &entry.object, pack);
        let group = grouped.entry(target).or_default();
        if let std::collections::btree_map::Entry::Vacant(slot) = group.entry(key) {
            slot.insert(codec::encode_object_index(&entry.value)?);
        }
    }
    let mut plan = IndexPlan::default();
    for (target, rows) in grouped {
        if &target == source {
            let mut puts = Vec::new();
            let mut bytes = 0;
            for (key, value) in rows {
                let size = key.as_bytes().len() + value.as_bytes().len();
                if size > MAX_BATCH_BYTES || key.as_bytes().len() > MAX_KEY_BYTES {
                    return Err(StoreError::Invalid("object index row too large".into()));
                }
                if puts.len() == MAX_BATCH_OPS || bytes + size > MAX_BATCH_BYTES {
                    plan.direct.push(DirectIndexBatch {
                        target: target.clone(),
                        puts: std::mem::take(&mut puts),
                    });
                    bytes = 0;
                }
                bytes += size;
                puts.push((key, value));
            }
            if !puts.is_empty() {
                plan.direct.push(DirectIndexBatch { target, puts });
            }
        } else {
            let mut row = RelayV1 {
                at_ms,
                target,
                puts: Vec::new(),
            };
            let mut bytes = 0;
            for (key, value) in rows {
                let size = key.as_bytes().len() + value.as_bytes().len();
                if key.as_bytes().len() > MAX_KEY_BYTES || value.as_bytes().len() > MAX_VALUE_BYTES
                {
                    return Err(StoreError::Invalid("object index row too large".into()));
                }
                row.puts.push((key, value));
                let encoded = codec::encode_relay(&row);
                if row.puts.len() > MAX_RELAY_PUTS
                    || encoded.is_err()
                    || bytes + size + 2 * (MAX_KEY_BYTES + 8) > MAX_BATCH_BYTES
                {
                    let Some(last) = row.puts.pop() else {
                        return Err(StoreError::Invalid("empty object index relay row".into()));
                    };
                    if row.puts.is_empty() {
                        return Err(StoreError::Invalid(
                            "object index relay row too large".into(),
                        ));
                    }
                    plan.relay.push(row.clone());
                    row.puts.clear();
                    row.puts.push(last);
                    codec::encode_relay(&row)?;
                    bytes = 0;
                }
                bytes += size;
            }
            if !row.puts.is_empty() {
                plan.relay.push(row);
            }
        }
    }
    Ok(plan)
}

/// A member pack and the object's immutable entry location within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatedObject {
    /// Pack whose membership makes the row visible.
    pub pack: Hash,
    /// Entry location and metadata.
    pub value: IndexValue,
}

#[derive(Debug, thiserror::Error)]
#[error("object index lookup budget exceeded")]
struct LookupBudgetExceeded;

fn budget_exceeded() -> StoreError {
    StoreError::unavailable(LookupBudgetExceeded)
}

/// Locate the first member pack, in pack-id order, for each requested id.
/// Each object scan and the call as a whole are bounded. Membership keys are
/// deduplicated, then read once per membership partition (the store's
/// `get_many` is partition-scoped). A truncated miss fails closed.
pub async fn locate_many<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<Vec<Option<LocatedObject>>, StoreError> {
    if ids.len() > MAX_LOOKUP_IDS {
        return Err(StoreError::Invalid("too many object ids".into()));
    }
    let mut candidates: BTreeMap<Hash, Vec<(Hash, Value)>> = BTreeMap::new();
    let mut truncated = BTreeSet::new();
    let mut total = 0;
    let mut pages = 0;
    for id in ids {
        if candidates.contains_key(id) {
            continue;
        }
        let partition = shards.object_index(repo, id);
        let (start, end) = keys::object_index_range(&repo.name, id);
        let mut after = None;
        let mut rows = Vec::new();
        loop {
            if total == MAX_LOOKUP_ROWS || pages == MAX_LOOKUP_PAGES {
                if rows.is_empty() {
                    return Err(budget_exceeded());
                }
                truncated.insert(*id);
                break;
            }
            let limit = SCAN_PAGE_ROWS
                .min(u32::try_from(MAX_LOOKUP_ROWS - total).map_err(|_| budget_exceeded())?);
            let page = store
                .scan(&partition, &start, &end, after.as_ref(), limit)
                .await?;
            pages += 1;
            if page.entries.len() > limit as usize {
                return Err(StoreError::Corrupt(
                    "object index scan exceeded limit".into(),
                ));
            }
            total += page.entries.len();
            for (key, value) in page.entries {
                match keys::parse(&key) {
                    Some(ParsedKey::ObjectIndex {
                        repo: found,
                        object,
                        pack_id,
                    }) if found == repo.name && object == *id => rows.push((pack_id, value)),
                    _ => return Err(StoreError::Corrupt("malformed object index key".into())),
                }
            }
            match page.next {
                Some(cursor) => after = Some(cursor),
                None => break,
            }
        }
        candidates.insert(*id, rows);
    }
    let mut packs: BTreeMap<Partition, BTreeSet<Hash>> = BTreeMap::new();
    for rows in candidates.values() {
        for (pack, _) in rows {
            packs
                .entry(shards.membership(repo, &BlobKey::pack(*pack)))
                .or_default()
                .insert(*pack);
        }
    }
    let mut members = BTreeSet::new();
    for (partition, ids) in packs {
        let ids: Vec<_> = ids.into_iter().collect();
        let keys: Vec<_> = ids
            .iter()
            .map(|pack| keys::membership(&repo.name, pack))
            .collect();
        let values = store.get_many(&partition, &keys).await?;
        if values.len() != ids.len() {
            return Err(StoreError::Corrupt("short membership get_many".into()));
        }
        for (pack, value) in ids.into_iter().zip(values) {
            if value.is_some() {
                members.insert(pack);
            }
        }
    }
    ids.iter()
        .map(|id| {
            let found = candidates[id]
                .iter()
                .find(|(pack, _)| members.contains(pack))
                .map(|(pack, value)| {
                    Ok::<LocatedObject, StoreError>(LocatedObject {
                        pack: *pack,
                        value: codec::decode_object_index(value)?,
                    })
                })
                .transpose()?;
            if found.is_none() && truncated.contains(id) {
                Err(budget_exceeded())
            } else {
                Ok(found)
            }
        })
        .collect()
}

/// Whether each object has any pack member of this repository.
pub async fn contains_many<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<Vec<bool>, StoreError> {
    Ok(locate_many(store, shards, repo, ids)
        .await?
        .into_iter()
        .map(|location| location.is_some())
        .collect())
}

/// Whether this repository holds any named id, for the takedown sweep.
pub async fn holds_any<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<bool, StoreError> {
    Ok(contains_many(store, shards, repo, ids)
        .await?
        .into_iter()
        .any(|yes| yes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::pipeline::{D34Shards, SinglePartition};
    use crate::repo::{NamespaceKey, RepoName};
    use crate::{
        Batch, BatchOutcome, Cursor, MemoryKv, PartitionStats, ScanPage, StoreCapabilities,
    };

    #[derive(Debug)]
    struct EmptyPageOnce {
        inner: MemoryKv,
        empty_once: AtomicBool,
        get_many_calls: AtomicUsize,
    }

    impl NamespaceStore for EmptyPageOnce {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, k).await
        }
        async fn get_many(
            &self,
            p: &Partition,
            keys: &[Key],
        ) -> Result<Vec<Option<Value>>, StoreError> {
            self.get_many_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get_many(p, keys).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            if self.empty_once.swap(false, Ordering::SeqCst) {
                let first = self.inner.scan(p, start, end, after, 1).await?;
                return Ok(ScanPage {
                    entries: Vec::new(),
                    next: first.next,
                });
            }
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.inner.probe().await
        }
    }

    fn repo(name: &str) -> RepoId {
        RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(name).unwrap(),
        }
    }

    fn raw(offset: u64) -> IndexValue {
        IndexValue {
            frame_offset: offset,
            frame_length: 17,
            wire_type: 0,
            decoded_size: 42,
            chain_depth: 0,
            delta_base: None,
        }
    }

    fn source() -> Partition {
        Partition::Ref {
            ns: NamespaceKey::deployment_default(),
            repo: RepoName::new("a").unwrap(),
            shard_ref: "refs/heads/main".into(),
        }
    }

    #[test]
    fn binary_value_golden_and_validation() {
        let row = IndexValue {
            frame_offset: 0x0102_0304_0506_0708,
            frame_length: 17,
            wire_type: 2,
            decoded_size: 42,
            chain_depth: 3,
            delta_base: Some([0x33; 32]),
        };
        let value = codec::encode_object_index(&row).unwrap();
        let golden = [
            &b"\x01\x01\x02\x03\x04\x05\x06\x07\x08"[..],
            &17_u64.to_be_bytes(),
            &[2],
            &42_u64.to_be_bytes(),
            &3_u32.to_be_bytes(),
            &[1],
            &[0x33; 32],
        ]
        .concat();
        assert_eq!(value.as_bytes(), golden);
        assert_eq!(codec::decode_object_index(&value).unwrap(), row);
        let raw_value = codec::encode_object_index(&raw(0)).unwrap();
        assert_eq!(raw_value.as_bytes().len(), 31);
        assert_eq!(codec::decode_object_index(&raw_value).unwrap(), raw(0));
        for bad in [
            Value::new(vec![]),
            Value::new([&[2], &golden[1..]].concat()),
            Value::new(golden[..62].to_vec()),
            Value::new([&golden[..30], &[0], &golden[31..]].concat()),
        ] {
            assert!(matches!(
                codec::decode_object_index(&bad),
                Err(StoreError::Corrupt(_))
            ));
        }
        assert!(
            codec::encode_object_index(&IndexValue {
                wire_type: 1,
                ..raw(0)
            })
            .is_err()
        );
        assert!(
            codec::encode_object_index(&IndexValue {
                frame_length: 0,
                ..raw(0)
            })
            .is_err()
        );
        let deep = IndexValue {
            chain_depth: 300,
            ..row
        };
        assert_eq!(
            codec::decode_object_index(&codec::encode_object_index(&deep).unwrap()).unwrap(),
            deep
        );
    }

    #[test]
    fn planner_chunks_deduplicates_and_is_deterministic() {
        let r = repo("a");
        let pack = [9; 32];
        let entries: Vec<_> = (0..220)
            .map(|i| {
                let mut object = [0; 32];
                object[30..].copy_from_slice(&u16::try_from(i).unwrap().to_be_bytes());
                IndexEntry {
                    object,
                    value: raw(i),
                }
            })
            .collect();
        let mut duplicate = entries.clone();
        duplicate.push(IndexEntry {
            object: entries[0].object,
            value: raw(999),
        });
        let p = Partition::Namespace(r.namespace.clone());
        let plan = plan_index_rows(&SinglePartition, &r, &p, &pack, &duplicate, 7).unwrap();
        assert_eq!(
            plan,
            plan_index_rows(&SinglePartition, &r, &p, &pack, &duplicate, 7).unwrap()
        );
        assert!(plan.relay.is_empty());
        assert_eq!(
            plan.direct
                .iter()
                .map(|batch| batch.puts.len())
                .collect::<Vec<_>>(),
            [100, 100, 20]
        );
        assert_eq!(
            plan.direct[0].puts[0].1,
            codec::encode_object_index(&raw(0)).unwrap()
        );
        for batch in &plan.direct {
            let bytes: usize = batch
                .puts
                .iter()
                .map(|(k, v)| k.as_bytes().len() + v.as_bytes().len())
                .sum();
            assert!(bytes <= MAX_BATCH_BYTES);
        }
        let relay = plan_index_rows(&D34Shards, &r, &source(), &pack, &duplicate, 7).unwrap();
        assert!(relay.direct.is_empty());
        assert_eq!(relay.relay.len(), 3);
        assert_eq!(
            relay
                .relay
                .iter()
                .map(|row| row.puts.len())
                .collect::<Vec<_>>(),
            [96, 96, 28]
        );
        for row in relay.relay {
            assert!(codec::encode_relay(&row).unwrap().as_bytes().len() <= MAX_VALUE_BYTES);
        }
    }

    #[test]
    fn planner_spans_every_prefix() {
        let r = repo("a");
        let entries: Vec<_> = (0..4096_u16)
            .map(|prefix| {
                let mut object = [0; 32];
                object[0] = u8::try_from(prefix >> 4).unwrap();
                object[1] = u8::try_from((prefix & 0x0f) << 4).unwrap();
                IndexEntry {
                    object,
                    value: raw(u64::from(prefix)),
                }
            })
            .collect();
        let plan = plan_index_rows(&D34Shards, &r, &source(), &[8; 32], &entries, 7).unwrap();
        assert_eq!(plan.relay.len(), 4096);
        assert!(plan.relay.iter().all(|row| row.puts.len() == 1));
        assert_eq!(
            plan,
            plan_index_rows(&D34Shards, &r, &source(), &[8; 32], &entries, 7).unwrap()
        );
        assert_eq!(
            plan.relay
                .iter()
                .map(|row| &row.target)
                .collect::<BTreeSet<_>>()
                .len(),
            4096
        );
    }

    async fn membership_gate(shards: &dyn ShardMap) {
        let store = MemoryKv::default();
        let a = repo("a");
        let b = repo("b");
        let id = [0x12; 32];
        let pack = [0x34; 32];
        let row = codec::encode_object_index(&raw(5)).unwrap();
        let key = keys::object_index(&a.name, &id, &pack);
        let target = shards.object_index(&a, &id);
        assert_eq!(
            store
                .apply(&target, Batch::new().put(key, row))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let other_target = shards.object_index(&b, &id);
        assert_eq!(
            store
                .apply(
                    &other_target,
                    Batch::new().put(
                        keys::object_index(&b.name, &id, &pack),
                        codec::encode_object_index(&raw(5)).unwrap(),
                    ),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            contains_many(&store, shards, &a, &[id, id]).await.unwrap(),
            [false, false]
        );
        assert_eq!(
            contains_many(&store, shards, &b, &[id]).await.unwrap(),
            [false]
        );
        let member = keys::membership(&a.name, &pack);
        let partition = shards.membership(&a, &BlobKey::pack(pack));
        assert_eq!(
            store
                .apply(&partition, Batch::new().put(member, Value::default()))
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            locate_many(&store, shards, &a, &[id]).await.unwrap(),
            [Some(LocatedObject {
                pack,
                value: raw(5)
            })]
        );
        assert!(holds_any(&store, shards, &a, &[id]).await.unwrap());
        assert!(!holds_any(&store, shards, &b, &[id]).await.unwrap());
    }

    #[tokio::test]
    async fn membership_gate_single() {
        membership_gate(&SinglePartition).await;
    }

    #[tokio::test]
    async fn membership_gate_d34() {
        membership_gate(&D34Shards).await;
    }

    #[tokio::test]
    async fn lookup_pages_past_nonmember_packs() {
        let store = MemoryKv::default();
        let r = repo("a");
        let id = [0x12; 32];
        let target = D34Shards.object_index(&r, &id);
        for chunk in (0..130_u16).collect::<Vec<_>>().chunks(100) {
            let mut batch = Batch::new();
            for i in chunk {
                let mut pack = [0; 32];
                pack[30..].copy_from_slice(&i.to_be_bytes());
                batch = batch.put(
                    keys::object_index(&r.name, &id, &pack),
                    codec::encode_object_index(&raw(u64::from(*i))).unwrap(),
                );
            }
            assert_eq!(
                store.apply(&target, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
        let mut last = [0; 32];
        last[30..].copy_from_slice(&129_u16.to_be_bytes());
        let membership = D34Shards.membership(&r, &BlobKey::pack(last));
        assert_eq!(
            store
                .apply(
                    &membership,
                    Batch::new().put(keys::membership(&r.name, &last), Value::default())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[id]).await.unwrap(),
            [Some(LocatedObject {
                pack: last,
                value: raw(129)
            })]
        );
    }

    #[tokio::test]
    async fn lookup_accepts_empty_continuation_page() {
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            get_many_calls: AtomicUsize::new(0),
        };
        let r = repo("a");
        let id = [0x12; 32];
        let target = D34Shards.object_index(&r, &id);
        let mut member = [0; 32];
        member[31] = 1;
        for pack in [[0; 32], member] {
            assert_eq!(
                store
                    .apply(
                        &target,
                        Batch::new().put(
                            keys::object_index(&r.name, &id, &pack),
                            codec::encode_object_index(&raw(5)).unwrap()
                        )
                    )
                    .await
                    .unwrap(),
                BatchOutcome::Committed
            );
        }
        assert_eq!(
            store
                .apply(
                    &D34Shards.membership(&r, &BlobKey::pack(member)),
                    Batch::new().put(keys::membership(&r.name, &member), Value::default())
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        store.empty_once.store(true, Ordering::SeqCst);
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[id]).await.unwrap(),
            [Some(LocatedObject {
                pack: member,
                value: raw(5)
            })]
        );
        assert_eq!(store.get_many_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn lookup_budget_fails_closed() {
        let store = MemoryKv::default();
        let r = repo("a");
        let id = [0x12; 32];
        let target = D34Shards.object_index(&r, &id);
        for chunk in (0..=MAX_LOOKUP_ROWS).collect::<Vec<_>>().chunks(100) {
            let mut batch = Batch::new();
            for i in chunk {
                let mut pack = [0; 32];
                pack[28..].copy_from_slice(&u32::try_from(*i).unwrap().to_be_bytes());
                batch = batch.put(
                    keys::object_index(&r.name, &id, &pack),
                    codec::encode_object_index(&raw(5)).unwrap(),
                );
            }
            assert_eq!(
                store.apply(&target, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
        assert!(matches!(
            locate_many(&store, &D34Shards, &r, &[id]).await,
            Err(StoreError::Unavailable(_))
        ));
        let first = [0; 32];
        assert_eq!(
            store
                .apply(
                    &D34Shards.membership(&r, &BlobKey::pack(first)),
                    Batch::new().put(keys::membership(&r.name, &first), Value::default()),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[id]).await.unwrap(),
            [Some(LocatedObject {
                pack: first,
                value: raw(5)
            })]
        );
    }
}
