//! Repository-scoped, write-once object index rows. A row becomes visible
//! only when its pack's repository membership row exists. Production writers
//! are installed by WP-4.7 and WP-4.8.

use std::collections::{BTreeMap, BTreeSet};

use mkit_core::hash::Hash;
use mkit_core::store::MAX_RAW_OBJECT_SIZE;

use super::codec::{self, RelayV1};
use super::keys::{self, ParsedKey};
use super::outbox::MAX_RELAY_PUTS;
use super::{
    BlobKey, Key, MAX_BATCH_BYTES, MAX_KEY_BYTES, MAX_VALUE_BYTES, NamespaceStore, Partition,
    RangeScan, ScanPage, StoreError, Value,
};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;

/// Maximum object ids accepted by one lookup, matching the takedown named-id cap.
pub const MAX_LOOKUP_IDS: usize = 256;
/// Maximum index candidates read for one object id. An id that reaches this
/// many rows with more remaining, and has no member among them, gets
/// [`LookupError::TooManyRows`].
pub const MAX_LOOKUP_ROWS: usize = 4096;
/// Maximum partition-scoped scan calls in one lookup. Each call may serve a
/// prefix of up to 256 ranges, including legal empty continuation pages.
pub const MAX_LOOKUP_PAGES: usize = 512;
/// At most 487 partition-scoped membership reads accompany 512 scan pages:
/// the whole call uses at most 999 Worker subrequests.
pub const MAX_LOOKUP_MEMBERSHIP_READS: usize = 487;
// A 4 MiB admission budget includes payloads and a conservative 512-byte
// charge per candidate for Vec capacity and membership BTree nodes. Together
// with <=1,000 transient scan rows, <=256 scan states and 128-key membership
// RPCs, a lookup retains less than 16 MiB of index state, leaving headroom in
// the Worker's 128 MB isolate for decoding, runtime and JS transport copies.
const CANDIDATE_BYTES: usize = 4 * 1024 * 1024;
const CANDIDATE_OVERHEAD: usize = 512;
const MEMBERSHIP_CHUNK: usize = 128;
const SCAN_PAGE_ROWS: u32 = 128;
const SCAN_CALL_ROWS: u32 = 1_000;
const _: () = assert!(MAX_LOOKUP_PAGES + MAX_LOOKUP_MEMBERSHIP_READS < 1000);

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
    /// In-pack delta hops to the first non-in-pack-delta entry: zero for a
    /// full object, one for an external base, otherwise one plus the base's
    /// in-pack depth. Verification follows external bases for total depth.
    pub chain_depth: u32,
    /// Base id for delta entry types only.
    pub delta_base: Option<Hash>,
}

impl IndexValue {
    pub(crate) fn validate(&self, object: &Hash) -> Result<(), StoreError> {
        if self.frame_length == 0
            || self.frame_length > u64::from(u32::MAX) + 5
            || self.frame_offset.checked_add(self.frame_length).is_none()
            || self.decoded_size == 0
            || self.decoded_size > MAX_RAW_OBJECT_SIZE as u64
            || self.chain_depth > u32::from(u16::MAX)
            || self.delta_base == Some(*object)
        {
            return Err(StoreError::Invalid("invalid object index metadata".into()));
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
    plan_index_rows_inner(shards, repo, source, pack, entries, at_ms, false)
}

/// Plan direct idempotent upserts for every target partition. Native indexed
/// verification uses this before committing membership; no per-object write
/// enters the advance batch.
pub fn plan_index_rows_direct(
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    pack: &Hash,
    entries: &[IndexEntry],
    at_ms: u64,
) -> Result<IndexPlan, StoreError> {
    plan_index_rows_inner(shards, repo, source, pack, entries, at_ms, true)
}

fn plan_index_rows_inner(
    shards: &dyn ShardMap,
    repo: &RepoId,
    source: &Partition,
    pack: &Hash,
    entries: &[IndexEntry],
    at_ms: u64,
    direct_all: bool,
) -> Result<IndexPlan, StoreError> {
    let mut grouped: BTreeMap<Partition, BTreeMap<Key, Value>> = BTreeMap::new();
    for entry in entries {
        let target = shards.object_index(repo, &entry.object);
        let key = keys::object_index(&repo.name, &entry.object, pack);
        let group = grouped.entry(target).or_default();
        if let std::collections::btree_map::Entry::Vacant(slot) = group.entry(key) {
            slot.insert(codec::encode_object_index(&entry.object, &entry.value)?);
        }
    }
    let mut plan = IndexPlan::default();
    for (target, rows) in grouped {
        if direct_all || &target == source {
            let mut puts = Vec::new();
            let mut bytes = 0;
            for (key, value) in rows {
                let size = key.as_bytes().len() + value.as_bytes().len();
                if size > MAX_BATCH_BYTES
                    || key.as_bytes().len() > MAX_KEY_BYTES
                    || value.as_bytes().len() > MAX_VALUE_BYTES
                {
                    return Err(StoreError::Invalid("object index row too large".into()));
                }
                if puts.len() == MAX_RELAY_PUTS || bytes + size > MAX_BATCH_BYTES {
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
                target: target.clone(),
                puts: Vec::new(),
                deletes: Vec::new(),
            };
            let base_bytes = codec::encode_relay(&row)?.as_bytes().len();
            let mut encoded_bytes = base_bytes;
            for (key, value) in rows {
                // Relay JSON renders key and value as hex strings.
                let addition = 7 + 2 * (key.as_bytes().len() + value.as_bytes().len());
                if key.as_bytes().len() > MAX_KEY_BYTES
                    || value.as_bytes().len() > MAX_VALUE_BYTES
                    || base_bytes + addition > MAX_VALUE_BYTES
                    || base_bytes + addition + 2 * (MAX_KEY_BYTES + 8) > MAX_BATCH_BYTES
                {
                    return Err(StoreError::Invalid("object index row too large".into()));
                }
                let comma = usize::from(!row.puts.is_empty());
                if row.puts.len() == MAX_RELAY_PUTS
                    || encoded_bytes + addition + comma > MAX_VALUE_BYTES
                    || encoded_bytes + addition + comma + 2 * (MAX_KEY_BYTES + 8) > MAX_BATCH_BYTES
                {
                    // Validation only: the enqueuer encodes the row itself.
                    codec::encode_relay(&row)?;
                    plan.relay.push(row);
                    row = RelayV1 {
                        at_ms,
                        target: target.clone(),
                        puts: Vec::new(),
                        deletes: Vec::new(),
                    };
                    encoded_bytes = base_bytes;
                }
                encoded_bytes += addition + usize::from(!row.puts.is_empty());
                row.puts.push((key, value));
            }
            if !row.puts.is_empty() {
                codec::encode_relay(&row)?;
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

/// A bounded lookup that could not prove membership or absence for one id.
/// Every variant fails closed for that id only; retryability differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    /// At least [`MAX_LOOKUP_ROWS`] rows for this object, with more
    /// remaining, and none of those read belongs to a member pack. **Not
    /// retryable**: it persists while the object has that many index rows in
    /// this repository. Rows of packs that never became members are removed by
    /// §13 GC (WP-5.3a); rows of member packs are not.
    #[error("object index row cap exceeded")]
    TooManyRows,
    /// The call used all [`MAX_LOOKUP_PAGES`] scan pages before this id's
    /// scan finished. **Retryable** in a call with fewer ids.
    #[error("object index page cap exceeded")]
    TooManyPages,
    /// The call's membership-read budget ran out before a member was found in
    /// this id's candidates. **Retryable** in a call with fewer ids, unless the
    /// id's own candidates span more than [`MAX_LOOKUP_MEMBERSHIP_READS`]
    /// membership partitions before its first member.
    #[error("object index membership-read cap exceeded")]
    TooManyMembershipReads,
}

/// One object's result. Backend failures still fail the whole call.
pub type ObjectLookup = Result<Option<LocatedObject>, LookupError>;
/// One object's membership answer.
pub type PresenceLookup = Result<bool, LookupError>;

struct IdScan {
    partition: Partition,
    start: Key,
    end: Key,
    after: Option<super::Cursor>,
    rows: Vec<(Hash, Value)>,
    done: bool,
    reason: Option<LookupError>,
}

fn validate_scan_reply(
    repo: &RepoId,
    ids: &[Hash],
    ranges: &[RangeScan],
    pages: &[ScanPage],
) -> Result<(), StoreError> {
    if pages.is_empty() || pages.len() > ranges.len() {
        return Err(StoreError::Corrupt(
            "invalid scan_many served prefix".into(),
        ));
    }
    for ((id, range), page) in ids.iter().zip(ranges).zip(pages) {
        if page.entries.len() > range.limit as usize {
            return Err(StoreError::Corrupt(
                "object index scan exceeded limit".into(),
            ));
        }
        if page.entries.iter().any(|(key, _)| !matches!(keys::parse(key),
            Some(ParsedKey::ObjectIndex { repo: found, object, .. }) if found == repo.name && object == *id)) {
            return Err(StoreError::Corrupt("malformed object index key".into()));
        }
    }
    Ok(())
}

/// Scan candidates in rounds, with one batched call per distinct partition
/// per round. The served-prefix cursor rotates within a partition across
/// rounds, so a hot first id cannot indefinitely hide later ids.
#[allow(clippy::too_many_lines)] // Keep the bounded scan state machine together.
async fn scan_all<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<BTreeMap<Hash, IdScan>, StoreError> {
    let mut scans: BTreeMap<Hash, IdScan> = BTreeMap::new();
    let mut order = Vec::new();
    for id in ids {
        if scans.contains_key(id) {
            continue;
        }
        let (start, end) = keys::object_index_range(&repo.name, id);
        scans.insert(
            *id,
            IdScan {
                partition: shards.object_index(repo, id),
                start,
                end,
                after: None,
                rows: Vec::new(),
                done: false,
                reason: None,
            },
        );
        order.push(*id);
    }
    let mut calls = 0;
    let mut retained_bytes = 0;
    let mut rotations: BTreeMap<Partition, usize> = BTreeMap::new();
    loop {
        let mut groups: BTreeMap<Partition, Vec<Hash>> = BTreeMap::new();
        for id in &order {
            let Some(scan) = scans.get_mut(id) else {
                continue;
            };
            if scan.done {
                continue;
            }
            if scan.rows.len() >= MAX_LOOKUP_ROWS {
                scan.done = true;
                scan.reason = Some(LookupError::TooManyRows);
                continue;
            }
            groups.entry(scan.partition.clone()).or_default().push(*id);
        }
        if groups.is_empty() {
            return Ok(scans);
        }
        let mut jobs = Vec::new();
        for (partition, mut ids) in groups {
            if calls == MAX_LOOKUP_PAGES {
                for id in ids {
                    if let Some(scan) = scans.get_mut(&id) {
                        scan.done = true;
                        scan.reason = Some(LookupError::TooManyPages);
                    }
                }
                continue;
            }
            let n = ids.len();
            ids.rotate_left(rotations.get(&partition).copied().unwrap_or(0) % n);
            let mut remaining_rows = SCAN_CALL_ROWS;
            let ranges: Vec<_> = ids
                .iter()
                .scan(&mut remaining_rows, |remaining, id| {
                    if **remaining == 0 {
                        return None;
                    }
                    let scan = &scans[id];
                    let limit = SCAN_PAGE_ROWS
                        .min(**remaining)
                        .min(u32::try_from(MAX_LOOKUP_ROWS - scan.rows.len()).unwrap_or(u32::MAX));
                    **remaining -= limit;
                    Some(RangeScan {
                        start: scan.start.clone(),
                        end: scan.end.clone(),
                        after: scan.after.clone(),
                        limit,
                    })
                })
                .collect();
            calls += 1; // Reserve page allowance before any scan is dispatched.
            jobs.push((partition, ids, ranges));
        }
        let mut served = false;
        let mut pending = jobs.into_iter().peekable();
        while pending.peek().is_some() {
            let mut wave = Vec::new();
            let mut rows = 0;
            while let Some((_, _, ranges)) = pending.peek() {
                let requested = ranges.iter().map(|r| r.limit).sum::<u32>();
                if !wave.is_empty()
                    && (wave.len() == super::read_io::parallelism()
                        || rows + requested > SCAN_CALL_ROWS)
                {
                    break;
                }
                rows += requested;
                wave.push(
                    pending
                        .next()
                        .ok_or_else(|| StoreError::Corrupt("missing scan plan".into()))?,
                );
            }
            // Both page count and the whole transient row/byte allowance are
            // reserved above; failed waves drain every dispatched reply.
            let reservation = if store.reader_admission() {
                store.reserve_read_calls(u32::try_from(wave.len()).unwrap_or(u32::MAX))?
            } else {
                None
            };
            let replies = super::ReadReservation::scope(
                &[reservation],
                futures::future::join_all(wave.iter().map(|(p, _, r)| store.scan_many(p, r))),
            )
            .await;
            // All dispatched errors belong to this call, even when an earlier
            // reply exhausts candidate retention during deterministic processing.
            let replies = replies.into_iter().collect::<Result<Vec<_>, _>>()?;
            for ((_, ids, ranges), pages) in wave.iter().zip(&replies) {
                validate_scan_reply(repo, ids, ranges, pages)?;
            }
            for ((partition, ids, _), pages) in wave.into_iter().zip(replies) {
                *rotations.entry(partition).or_default() += pages.len();
                served = true;
                for (id, page) in ids.iter().zip(pages) {
                    let Some(scan) = scans.get_mut(id) else {
                        return Err(StoreError::Corrupt("missing object index scan".into()));
                    };
                    for (key, value) in page.entries {
                        match keys::parse(&key) {
                            Some(ParsedKey::ObjectIndex {
                                repo: found,
                                object,
                                pack_id,
                            }) if found == repo.name && object == *id => {
                                let size =
                                    CANDIDATE_OVERHEAD.saturating_add(value.as_bytes().len());
                                if size > CANDIDATE_BYTES - retained_bytes {
                                    // Keep only the proven pack-order prefix. The
                                    // existing page cap asks callers for smaller batches.
                                    for scan in scans.values_mut().filter(|s| !s.done) {
                                        scan.done = true;
                                        scan.reason = Some(LookupError::TooManyPages);
                                    }
                                    return Ok(scans);
                                }
                                retained_bytes += size;
                                scan.rows.push((pack_id, value));
                            }
                            _ => {
                                return Err(StoreError::Corrupt(
                                    "malformed object index key".into(),
                                ));
                            }
                        }
                    }
                    match page.next {
                        Some(cursor) => scan.after = Some(cursor),
                        None => scan.done = true,
                    }
                }
            }
        }
        if !served {
            return Ok(scans);
        }
    }
}

/// Locate the first member pack, in pack-id order, for each requested id.
/// Each object has its own row cap; scan pages and membership reads have
/// call-wide caps. A capped miss affects only its id. Each id's candidates are
/// admitted to the membership reads as a pack-id-order prefix that fits the
/// remaining budget, so a member early in pack order is always found.
/// Candidate retention has a call-wide 4 MiB admission budget; reaching it
/// uses the existing smaller-batch page-cap error. Membership keys are
/// deduplicated and joined in 128-key chunks. Every chunk counts against the
/// membership-read cap, including multiple chunks of one partition.
pub async fn locate_many<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<Vec<ObjectLookup>, StoreError> {
    if ids.len() > MAX_LOOKUP_IDS {
        return Err(StoreError::Invalid("too many object ids".into()));
    }
    let scans = scan_all(store, shards, repo, ids).await?;
    let mut truncated: BTreeMap<Hash, LookupError> = scans
        .iter()
        .filter_map(|(id, scan)| scan.reason.map(|reason| (*id, reason)))
        .collect();
    // Admit smaller candidate sets first, so one hot id cannot consume the
    // membership budget needed to answer an ordinary id in the same call.
    let mut order: Vec<_> = scans.keys().copied().collect();
    order.sort_by_key(|id| (scans[id].rows.len(), *id));
    let mut packs: BTreeMap<Partition, BTreeSet<Hash>> = BTreeMap::new();
    let mut admitted: BTreeMap<Hash, usize> = BTreeMap::new();
    let mut membership_reads = 0;
    for id in order {
        let rows = &scans[&id].rows;
        let mut count = 0;
        for (pack, _) in rows {
            let partition = shards.membership(repo, &BlobKey::pack(*pack));
            let group = packs.get(&partition);
            let new_chunk =
                group.is_none_or(|g| !g.contains(pack) && g.len() % MEMBERSHIP_CHUNK == 0);
            if new_chunk {
                if membership_reads == MAX_LOOKUP_MEMBERSHIP_READS {
                    break;
                }
                membership_reads += 1;
            }
            packs.entry(partition).or_default().insert(*pack);
            count += 1;
        }
        if count < rows.len() {
            truncated
                .entry(id)
                .or_insert(LookupError::TooManyMembershipReads);
        }
        admitted.insert(id, count);
    }
    let mut jobs = Vec::new();
    for (partition, ids) in packs {
        let ids: Vec<_> = ids.into_iter().collect();
        for chunk in ids.chunks(MEMBERSHIP_CHUNK) {
            let keys: Vec<_> = chunk
                .iter()
                .map(|pack| keys::membership(&repo.name, pack))
                .collect();
            jobs.push((partition.clone(), chunk.to_vec(), keys));
        }
    }
    let mut members = BTreeSet::new();
    for wave in jobs.chunks(super::read_io::parallelism()) {
        // <=768 keys per wave, within the scanner's shared 1,000-row allowance.
        let reservation = if store.reader_admission() {
            store.reserve_read_calls(u32::try_from(wave.len()).unwrap_or(u32::MAX))?
        } else {
            None
        };
        let replies = super::ReadReservation::scope(
            &[reservation],
            futures::future::join_all(wave.iter().map(|(p, _, keys)| store.get_many(p, keys))),
        )
        .await;
        for ((_, ids, _), reply) in wave.iter().zip(replies) {
            let values = reply?;
            if values.len() != ids.len() {
                return Err(StoreError::Corrupt("short membership get_many".into()));
            }
            for (pack, value) in ids.iter().zip(values) {
                if value.is_some() {
                    members.insert(*pack);
                }
            }
        }
    }
    ids.iter()
        .map(|id| {
            let rows = &scans[id].rows;
            let prefix = &rows[..admitted.get(id).copied().unwrap_or(0).min(rows.len())];
            // Rows are in pack-id order and every earlier row was checked, so
            // the first member in the admitted prefix is the first overall.
            let found = prefix
                .iter()
                .find(|(pack, _)| members.contains(pack))
                .map(|(pack, value)| {
                    Ok::<LocatedObject, StoreError>(LocatedObject {
                        pack: *pack,
                        value: codec::decode_object_index(id, value)?,
                    })
                })
                .transpose()?;
            if found.is_none()
                && let Some(reason) = truncated.get(id)
            {
                Ok(Err(*reason))
            } else {
                Ok(Ok(found))
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
) -> Result<Vec<PresenceLookup>, StoreError> {
    Ok(locate_many(store, shards, repo, ids)
        .await?
        .into_iter()
        .map(|location| location.map(|location| location.is_some()))
        .collect())
}

/// Whether this repository holds any named id, for the takedown sweep. This
/// is a repository-index membership probe, not a `ContentIndex` hold or holder
/// (`store/content_index.rs`), which is the global GC protection of an
/// extracted object; the names collide. This
/// first round performs exactly one read per distinct index partition,
/// satisfying §14.3/R-133 when all requested ranges are served and each id
/// fits one page. A served prefix or an id with more than one page needs
/// further rounds; WP-5.6 accounts for that. A capped miss fails closed: with no hit, the first
/// id's [`LookupError`] is returned so the caller can tell a data-dependent cap
/// from a backend failure.
pub async fn holds_any<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
    ids: &[Hash],
) -> Result<PresenceLookup, StoreError> {
    let answers = contains_many(store, shards, repo, ids).await?;
    if answers.iter().any(|answer| matches!(answer, Ok(true))) {
        return Ok(Ok(true));
    }
    if let Some(reason) = answers.into_iter().find_map(Result::err) {
        return Ok(Err(reason));
    }
    Ok(Ok(false))
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
        max_ranges: Option<usize>,
        fail_partition: Option<Partition>,
        get_many_calls: AtomicUsize,
        scan_many_calls: AtomicUsize,
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
        async fn scan_many(
            &self,
            p: &Partition,
            ranges: &[RangeScan],
        ) -> Result<Vec<ScanPage>, StoreError> {
            self.scan_many_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_partition.as_ref() == Some(p) {
                return Err(StoreError::unavailable("completed wave fault"));
            }
            let mut pages = Vec::with_capacity(ranges.len());
            for range in ranges.iter().take(self.max_ranges.unwrap_or(ranges.len())) {
                pages.push(
                    self.scan(
                        p,
                        &range.start,
                        &range.end,
                        range.after.as_ref(),
                        range.limit,
                    )
                    .await?,
                );
            }
            Ok(pages)
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
        let object = [0x12; 32];
        let row = IndexValue {
            frame_offset: 0x0102_0304_0506_0708,
            frame_length: 17,
            wire_type: 2,
            decoded_size: 42,
            chain_depth: 3,
            delta_base: Some([0x33; 32]),
        };
        let value = codec::encode_object_index(&object, &row).unwrap();
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
        assert_eq!(codec::decode_object_index(&object, &value).unwrap(), row);
        let raw_value = codec::encode_object_index(&object, &raw(0)).unwrap();
        assert_eq!(raw_value.as_bytes().len(), 31);
        assert_eq!(
            codec::decode_object_index(&object, &raw_value).unwrap(),
            raw(0)
        );
        for bad in [
            Value::new(vec![]),
            Value::new([&[2], &golden[1..]].concat()),
            Value::new(golden[..62].to_vec()),
            Value::new([&golden[..30], &[0], &golden[31..]].concat()),
        ] {
            assert!(matches!(
                codec::decode_object_index(&object, &bad),
                Err(StoreError::Corrupt(_))
            ));
        }
        assert!(
            codec::encode_object_index(
                &object,
                &IndexValue {
                    wire_type: 1,
                    ..raw(0)
                }
            )
            .is_err()
        );
        assert!(
            codec::encode_object_index(
                &object,
                &IndexValue {
                    frame_length: 0,
                    ..raw(0)
                }
            )
            .is_err()
        );
        let deep = IndexValue {
            chain_depth: 300,
            ..row
        };
        assert_eq!(
            codec::decode_object_index(
                &object,
                &codec::encode_object_index(&object, &deep).unwrap()
            )
            .unwrap(),
            deep
        );
        for invalid in [
            IndexValue {
                decoded_size: MAX_RAW_OBJECT_SIZE as u64 + 1,
                ..raw(0)
            },
            IndexValue {
                frame_length: u64::from(u32::MAX) + 6,
                ..raw(0)
            },
            IndexValue {
                chain_depth: u32::from(u16::MAX) + 1,
                ..deep
            },
            IndexValue {
                delta_base: Some(object),
                ..row
            },
        ] {
            assert!(codec::encode_object_index(&object, &invalid).is_err());
        }
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
            [96, 96, 28]
        );
        assert_eq!(
            plan.direct[0].puts[0].1,
            codec::encode_object_index(&entries[0].object, &raw(0)).unwrap()
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

    #[tokio::test]
    // The planner takes no store, so this only pins that its output ignores
    // repository state; deriving `chain_depth` from pack bytes is WP-4.8's test.
    async fn planner_bytes_do_not_depend_on_repository_state() {
        let r = repo("a");
        let object = [0x12; 32];
        let pack = [0x34; 32];
        let entry = IndexEntry {
            object,
            value: IndexValue {
                frame_offset: 10,
                frame_length: 20,
                wire_type: 2,
                decoded_size: 42,
                chain_depth: 1,
                delta_base: Some([0x56; 32]),
            },
        };
        let source = source();
        let empty = MemoryKv::default();
        let member = MemoryKv::default();
        let index_target = D34Shards.object_index(&r, &object);
        let index_key = keys::object_index(&r.name, &object, &pack);
        let index_value = codec::encode_object_index(&object, &entry.value).unwrap();
        for store in [&empty, &member] {
            store
                .apply(
                    &index_target,
                    Batch::new().put(index_key.clone(), index_value.clone()),
                )
                .await
                .unwrap();
        }
        member
            .apply(
                &D34Shards.membership(&r, &BlobKey::pack(pack)),
                Batch::new().put(keys::membership(&r.name, &pack), Value::default()),
            )
            .await
            .unwrap();
        assert_ne!(
            contains_many(&empty, &D34Shards, &r, &[object])
                .await
                .unwrap(),
            contains_many(&member, &D34Shards, &r, &[object])
                .await
                .unwrap()
        );
        let first = plan_index_rows(&D34Shards, &r, &source, &pack, &[entry], 7).unwrap();
        let second = plan_index_rows(&D34Shards, &r, &source, &pack, &[entry], 7).unwrap();
        assert_eq!(first, second);
    }

    async fn membership_gate(shards: &dyn ShardMap) {
        let store = MemoryKv::default();
        let a = repo("a");
        let b = repo("b");
        let id = [0x12; 32];
        let pack = [0x34; 32];
        let row = codec::encode_object_index(&id, &raw(5)).unwrap();
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
                        codec::encode_object_index(&id, &raw(5)).unwrap(),
                    ),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            contains_many(&store, shards, &a, &[id, id]).await.unwrap(),
            [Ok(false), Ok(false)]
        );
        assert_eq!(
            contains_many(&store, shards, &b, &[id]).await.unwrap(),
            [Ok(false)]
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
            [Ok(Some(LocatedObject {
                pack,
                value: raw(5)
            }))]
        );
        assert_eq!(
            holds_any(&store, shards, &a, &[id]).await.unwrap(),
            Ok(true)
        );
        assert_eq!(
            holds_any(&store, shards, &b, &[id]).await.unwrap(),
            Ok(false)
        );
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
    async fn holds_any_reads_each_distinct_index_partition_once_in_first_round() {
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            max_ranges: None,
            fail_partition: None,
            get_many_calls: AtomicUsize::new(0),
            scan_many_calls: AtomicUsize::new(0),
        };
        let r = repo("a");
        let mut first = [0x12; 32];
        let mut second = first;
        second[31] = 0x34;
        let third = [0x34; 32];
        first[31] = 0x56;
        assert_eq!(
            holds_any(&store, &D34Shards, &r, &[first, second, third])
                .await
                .unwrap(),
            Ok(false)
        );
        assert_eq!(store.scan_many_calls.load(Ordering::SeqCst), 2);
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
                    codec::encode_object_index(&id, &raw(u64::from(*i))).unwrap(),
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
            [Ok(Some(LocatedObject {
                pack: last,
                value: raw(129)
            }))]
        );
    }

    #[tokio::test]
    async fn lookup_accepts_empty_continuation_page() {
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            max_ranges: None,
            fail_partition: None,
            get_many_calls: AtomicUsize::new(0),
            scan_many_calls: AtomicUsize::new(0),
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
                            codec::encode_object_index(&id, &raw(5)).unwrap()
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
            [Ok(Some(LocatedObject {
                pack: member,
                value: raw(5)
            }))]
        );
        assert_eq!(store.get_many_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn hot_object_cap_does_not_hide_another_id() {
        let store = MemoryKv::default();
        let r = repo("a");
        let hot = [0x12; 32];
        let normal = [0x13; 32];
        let normal_pack = [0x55; 32];
        let target = D34Shards.object_index(&r, &hot);
        for chunk in (0..=MAX_LOOKUP_ROWS).collect::<Vec<_>>().chunks(100) {
            let mut batch = Batch::new();
            for i in chunk {
                let mut pack = [0; 32];
                pack[28..].copy_from_slice(&u32::try_from(*i).unwrap().to_be_bytes());
                batch = batch.put(
                    keys::object_index(&r.name, &hot, &pack),
                    codec::encode_object_index(&hot, &raw(5)).unwrap(),
                );
            }
            assert_eq!(
                store.apply(&target, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
        assert_eq!(
            store
                .apply(
                    &D34Shards.object_index(&r, &normal),
                    Batch::new().put(
                        keys::object_index(&r.name, &normal, &normal_pack),
                        codec::encode_object_index(&normal, &raw(7)).unwrap(),
                    ),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        assert_eq!(
            store
                .apply(
                    &D34Shards.membership(&r, &BlobKey::pack(normal_pack)),
                    Batch::new().put(keys::membership(&r.name, &normal_pack), Value::default(),),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
        let normal_location = Some(LocatedObject {
            pack: normal_pack,
            value: raw(7),
        });
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[hot, normal])
                .await
                .unwrap(),
            [Err(LookupError::TooManyRows), Ok(normal_location)]
        );
        assert_eq!(
            contains_many(&store, &D34Shards, &r, &[hot, normal])
                .await
                .unwrap(),
            [Err(LookupError::TooManyRows), Ok(true)]
        );
        assert_eq!(
            holds_any(&store, &D34Shards, &r, &[hot, normal])
                .await
                .unwrap(),
            Ok(true)
        );
        assert_eq!(
            holds_any(&store, &D34Shards, &r, &[hot]).await.unwrap(),
            Err(LookupError::TooManyRows)
        );
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
            locate_many(&store, &D34Shards, &r, &[hot, normal])
                .await
                .unwrap(),
            [
                Ok(Some(LocatedObject {
                    pack: first,
                    value: raw(5)
                })),
                Ok(normal_location)
            ]
        );
    }

    async fn put_rows(store: &MemoryKv, r: &RepoId, object: &Hash, packs: &[Hash]) {
        let target = D34Shards.object_index(r, object);
        for chunk in packs.chunks(100) {
            let mut batch = Batch::new();
            for pack in chunk {
                batch = batch.put(
                    keys::object_index(&r.name, object, pack),
                    codec::encode_object_index(object, &raw(5)).unwrap(),
                );
            }
            assert_eq!(
                store.apply(&target, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
    }

    async fn make_member(store: &MemoryKv, r: &RepoId, pack: &Hash) {
        assert_eq!(
            store
                .apply(
                    &D34Shards.membership(r, &BlobKey::pack(*pack)),
                    Batch::new().put(keys::membership(&r.name, pack), Value::default()),
                )
                .await
                .unwrap(),
            BatchOutcome::Committed
        );
    }

    #[tokio::test]
    async fn capped_scan_prefix_rotates_cursors_and_preserves_first_member_order() {
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            max_ranges: Some(1),
            fail_partition: None,
            get_many_calls: AtomicUsize::new(0),
            scan_many_calls: AtomicUsize::new(0),
        };
        let r = repo("prefix");
        let hot = [0x12; 32];
        let mut sibling = hot;
        sibling[31] += 1;
        let other = [0x34; 32];
        let packs: Vec<Hash> = (0..130u16)
            .map(|n| {
                let mut pack = [0; 32];
                pack[30..].copy_from_slice(&n.to_be_bytes());
                pack
            })
            .collect();
        put_rows(&store.inner, &r, &hot, &packs).await;
        for id in [sibling, other] {
            put_rows(&store.inner, &r, &id, &packs[128..]).await;
        }
        for pack in &packs[128..] {
            make_member(&store.inner, &r, pack).await;
        }
        let calls = crate::indexed::budget::SliceBudget::new(32);
        let io = super::super::read_io::ReadIo::new();
        let bounded = crate::indexed::budget::Budgeted::new(&store, &calls).with_io(&io);
        let ids = [sibling, hot, other, hot];
        let answers = locate_many(&bounded, &D34Shards, &r, &ids).await.unwrap();
        assert_eq!(
            answers,
            vec![
                Ok(Some(LocatedObject {
                    pack: packs[128],
                    value: raw(5)
                }));
                ids.len()
            ]
        );
        assert!(
            store.scan_many_calls.load(Ordering::SeqCst) >= 4,
            "both the served prefix and the hot object's continuation are exercised"
        );
        assert!(calls.used() <= 32);
    }

    #[tokio::test]
    async fn public_view_returns_one_prepaid_scan_prefix_without_hidden_dispatch() {
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            max_ranges: Some(1),
            fail_partition: None,
            get_many_calls: AtomicUsize::new(0),
            scan_many_calls: AtomicUsize::new(0),
        };
        let r = repo("view-prefix");
        let calls = crate::indexed::budget::SliceBudget::new(1);
        let io = super::super::read_io::ReadIo::new();
        let bounded = crate::indexed::budget::Budgeted::new(&store, &calls).with_io(&io);
        let view = crate::store::view::ViewStore {
            store: &bounded,
            repo: &r,
            writer: false,
            policy: None,
        };
        let p = D34Shards.object_index(&r, &[0x12; 32]);
        let ranges = vec![
            RangeScan {
                start: Key::new(b"a".to_vec()),
                end: Key::new(b"b".to_vec()),
                after: None,
                limit: 1
            };
            2
        ];
        let reservation = view.reserve_read_calls(1).unwrap();
        let pages =
            super::super::ReadReservation::scope(&[reservation], view.scan_many(&p, &ranges))
                .await
                .unwrap();
        assert_eq!(pages.len(), 1);
        assert_eq!(store.scan_many_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.used(), 1);
        assert!(view.reserve_read_calls(1).is_err());
        assert_eq!(store.scan_many_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn candidate_retention_cap_does_not_hide_later_wave_failure() {
        let r = repo("wave-errors");
        let ids = [[0x12; 32], [0x34; 32]];
        let mut partitions = ids.map(|id| (D34Shards.object_index(&r, &id), id));
        partitions.sort_by(|a, b| a.0.cmp(&b.0));
        let store = EmptyPageOnce {
            inner: MemoryKv::default(),
            empty_once: AtomicBool::new(false),
            max_ranges: None,
            fail_partition: Some(partitions[1].0.clone()),
            get_many_calls: AtomicUsize::new(0),
            scan_many_calls: AtomicUsize::new(0),
        };
        // The earlier reply exceeds retention before the later error is processed.
        for n in 0..10u8 {
            store
                .inner
                .apply(
                    &partitions[0].0,
                    Batch::new().put(
                        keys::object_index(&r.name, &partitions[0].1, &[n; 32]),
                        Value::new(vec![0; crate::store::MAX_VALUE_BYTES]),
                    ),
                )
                .await
                .unwrap();
        }
        assert!(matches!(
            scan_all(&store, &D34Shards, &r, &ids).await,
            Err(StoreError::Unavailable(_))
        ));
        assert_eq!(store.scan_many_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn index_wave_preflight_is_scoped_to_reader_admission() {
        for admitted in [false, true] {
            let store = EmptyPageOnce {
                inner: MemoryKv::default(),
                empty_once: AtomicBool::new(false),
                max_ranges: None,
                fail_partition: None,
                get_many_calls: AtomicUsize::new(0),
                scan_many_calls: AtomicUsize::new(0),
            };
            let inherited = crate::indexed::budget::SliceBudget::new(5);
            let inner = crate::indexed::budget::Budgeted::new(&store, &inherited);
            let budget = crate::indexed::budget::SliceBudget::new(100);
            let io = super::super::read_io::ReadIo::new();
            let mut facade = crate::indexed::budget::Budgeted::new(&inner, &budget);
            if admitted {
                facade = facade.with_io(&io);
            }
            let facade = std::sync::Arc::new(facade);
            let r = repo("admission");
            let view = crate::store::view::ViewStore {
                store: &facade,
                repo: &r,
                writer: false,
                policy: None,
            };
            let ids: Vec<_> = (0..6u8).map(|n| [n * 16; 32]).collect();
            assert!(locate_many(&view, &D34Shards, &r, &ids).await.is_err());
            assert_eq!(
                store.scan_many_calls.load(Ordering::SeqCst),
                if admitted { 0 } else { 5 }
            );
        }
    }

    /// Candidate packs spread over more membership partitions than the call
    /// budget: the first member in pack-id order is still found, and only a
    /// miss inside the admitted prefix reports the cap.
    #[tokio::test]
    async fn spread_candidates_admit_a_pack_order_prefix() {
        let store = MemoryKv::default();
        let r = repo("a");
        let object = [0x21; 32];
        let mut packs: Vec<Hash> = (0u32..600)
            .map(|i| mkit_core::hash::hash(&i.to_be_bytes()))
            .collect();
        packs.sort_unstable();
        let partitions: BTreeSet<_> = packs
            .iter()
            .map(|pack| D34Shards.membership(&r, &BlobKey::pack(*pack)))
            .collect();
        assert!(partitions.len() > MAX_LOOKUP_MEMBERSHIP_READS);
        put_rows(&store, &r, &object, &packs).await;
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[object])
                .await
                .unwrap(),
            [Err(LookupError::TooManyMembershipReads)]
        );
        make_member(&store, &r, &packs[3]).await;
        assert_eq!(
            locate_many(&store, &D34Shards, &r, &[object])
                .await
                .unwrap(),
            [Ok(Some(LocatedObject {
                pack: packs[3],
                value: raw(5)
            }))]
        );
    }

    /// Hot ids early in a request cannot spend the page budget before a later
    /// ordinary id gets its first page.
    #[tokio::test]
    async fn page_budget_round_robins_across_ids() {
        let store = MemoryKv::default();
        let r = repo("a");
        let mut hot = Vec::new();
        for h in 0u8..16 {
            let object = [h; 32];
            let packs: Vec<Hash> = (0u32..=u32::try_from(MAX_LOOKUP_ROWS).unwrap())
                .map(|i| {
                    let mut pack = [0; 32];
                    pack[28..].copy_from_slice(&i.to_be_bytes());
                    pack
                })
                .collect();
            put_rows(&store, &r, &object, &packs).await;
            hot.push(object);
        }
        let normal = [0x77; 32];
        let normal_pack = [0x99; 32];
        put_rows(&store, &r, &normal, &[normal_pack]).await;
        make_member(&store, &r, &normal_pack).await;
        let mut ids = hot.clone();
        ids.push(normal);
        let answers = locate_many(&store, &D34Shards, &r, &ids).await.unwrap();
        assert_eq!(
            answers[16],
            Ok(Some(LocatedObject {
                pack: normal_pack,
                value: raw(5)
            }))
        );
        assert!(answers[..16].iter().all(Result::is_err));
    }
}
