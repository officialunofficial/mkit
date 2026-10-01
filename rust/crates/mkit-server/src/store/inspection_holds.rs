//! Inspection holds in the advance's ref partition. A single advance-level
//! pending marker can be folded into the caller's guarded apply; kind-14 work
//! later materializes per-content rows. Reads are not atomic snapshots.

use std::collections::BTreeSet;

use mkit_core::hash::Hash;

use crate::pipeline::ShardMap;
use crate::repo::RepoId;

use super::{
    Batch, MAX_BATCH_OPS, MAX_SCAN_RANGES, NamespaceStore, Partition, Precondition, StoreError,
    Value, keys,
};

/// Forward-row writes per content id, on install and release.
pub const HOLD_OPS_PER_ID: usize = 1;
/// One manifest CAS and one manifest write, shared by a plan.
pub const HOLD_SHARED_OPS: usize = 2;
/// One advance-level hold marker: one absence guard and one put.
pub const ADVANCE_HOLD_MARKER_OPS: usize = 2;
const PENDING_HOLD_MARKER: u8 = 0;
/// Most input ids for an install plan, before deduplication.
pub const MAX_HOLD_BATCH_IDS: usize = MAX_BATCH_OPS - HOLD_SHARED_OPS;
/// Most distinct ids held by one advance. The manifest is at most 320,002
/// bytes; its guard and replacement fit the one MiB limit together.
/// This bounds storage resources, not the inspected set: callers can hold
/// whole added packs and record flagged object ids in the separate registry.
pub const MAX_HOLD_IDS_PER_ADVANCE: usize = 10_000;

/// Per-advance holds, routed beside the advance via the existing shard map.
#[derive(Debug)]
pub struct InspectionHolds<'a, S> {
    store: &'a S,
    repo: &'a RepoId,
    partition: Partition,
    reserved_ops: usize,
}

impl<'a, S: NamespaceStore> InspectionHolds<'a, S> {
    /// Resolve the advance's ref partition once; never infer a partition.
    #[must_use]
    pub fn new(store: &'a S, shards: &dyn ShardMap, repo: &'a RepoId, ref_name: &str) -> Self {
        Self {
            store,
            repo,
            partition: shards.ref_shard(repo, ref_name),
            reserved_ops: 0,
        }
    }

    /// Reserve operations for the caller's advance guards and state writes.
    /// This is additional to the backend's reserved operations.
    #[must_use]
    pub const fn with_reserved_ops(mut self, ops: usize) -> Self {
        self.reserved_ops = ops;
        self
    }

    /// The partition in which the caller applies every returned effect.
    #[must_use]
    pub fn partition(&self) -> &Partition {
        &self.partition
    }

    /// Plan the constant-cost hold record to include in the advance apply.
    /// Per-content hold rows are materialized later by inspection work.
    /// Repeated calls are idempotent and guard the existing record.
    ///
    /// # Errors
    /// Storage failures propagate; corrupt records and unsupported batches fail closed.
    pub async fn plan_advance_hold(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if let Some(value) = &prior {
            decode_manifest(Some(value))?;
        } else {
            batch = batch.put(key, encode_pending_hold());
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Plan one bounded kind-14 materialization page. The manifest CAS
    /// serializes additions and releases for this advance; while materializing,
    /// the manifest remains pending until `plan_complete` commits. Existing
    /// ids need no forward-row write. Re-plan after any CAS loss.
    ///
    /// # Errors
    /// Invalid for an oversized input, manifest, or batch; corrupt for an
    /// invalid stored manifest. Storage read failures propagate.
    pub async fn plan_holds(&self, advance: &Hash, ids: &[Hash]) -> Result<Batch, StoreError> {
        if ids.len() > self.batch_limit()? {
            return Err(StoreError::Invalid(
                "inspection hold batch is too large".into(),
            ));
        }
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let manifest = decode_manifest(prior.as_ref())?;
        let (mut held, materializing) = match manifest {
            HoldManifest::Materializing(ids) => (ids, true),
            HoldManifest::Materialized(ids) => (ids, false),
        };
        let mut added = Vec::new();
        for id in ids {
            if held.insert(*id) {
                added.push(*id);
            }
        }
        if held.len() > MAX_HOLD_IDS_PER_ADVANCE {
            return Err(StoreError::Invalid(
                "advance has too many inspection holds".into(),
            ));
        }
        if added.is_empty() {
            let batch = Batch::new().require(manifest_guard(key, prior.as_ref()));
            batch.validate(&self.store.capabilities())?;
            return Ok(batch);
        }
        let mut batch = Batch::new()
            .require(manifest_guard(key.clone(), prior.as_ref()))
            .put(
                key,
                if materializing {
                    encode_materializing(&held)
                } else {
                    encode_manifest(&held)
                },
            );
        for id in added {
            batch = batch.put(
                keys::inspection_hold(&self.repo.name, &id, advance),
                Value::default(),
            );
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Complete kind-14 materialization after every content page is committed.
    /// Until this transition, serving must treat content belonging to this
    /// advance as held, including content not yet present in a forward row.
    /// Completing an empty materialization is valid and removes that fallback.
    pub async fn plan_complete(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let manifest = decode_manifest(prior.as_ref())?;
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if prior.is_some()
            && let HoldManifest::Materializing(ids) = manifest
        {
            batch = batch.put(key, encode_manifest(&ids));
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Plan a bounded release page belonging only to this advance, after the
    /// advance obligation has ended. The caller must atomically guard the
    /// terminal advance transition on the first page so no later kind-14 page
    /// can apply. Repeat after each committed page until a plan with no writes
    /// is returned. A partial page rewrites the manifest with remaining ids;
    /// re-plan after CAS loss.
    ///
    /// # Errors
    /// Invalid for unusable backend limits; corrupt for a bad manifest;
    /// storage failures propagate. No writes happen while planning.
    pub async fn plan_release(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let limit = self.batch_limit()?;
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let mut held = match decode_manifest(prior.as_ref())? {
            HoldManifest::Materializing(ids) | HoldManifest::Materialized(ids) => ids,
        };
        if held.is_empty() {
            let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
            if prior.is_some() {
                batch = batch.delete(key);
            }
            batch.validate(&self.store.capabilities())?;
            return Ok(batch);
        }
        let released: Vec<_> = held.iter().take(limit).copied().collect();
        for id in &released {
            held.remove(id);
        }
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        batch = if held.is_empty() {
            batch.delete(key)
        } else {
            batch.put(key, encode_manifest(&held))
        };
        for id in released {
            batch = batch.delete(keys::inspection_hold(&self.repo.name, &id, advance));
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Return the subset with materialized per-content rows in sorted,
    /// deduplicated order. During a pending advance marker, serving must also
    /// check whether the requested content belongs to that held advance while
    /// the manifest is still materializing.
    /// Every materialized id needs one prefix probe with limit one. The
    /// probes are sequential and are not a snapshot.
    ///
    /// # Errors
    /// Invalid for more than 256 inputs, corrupt for malformed hold rows;
    /// storage failures propagate.
    pub async fn is_held(&self, ids: &[Hash]) -> Result<Vec<Hash>, StoreError> {
        if ids.len() > MAX_SCAN_RANGES {
            return Err(StoreError::Invalid(
                "too many inspection hold probes".into(),
            ));
        }
        let mut held = Vec::new();
        for id in ids.iter().copied().collect::<BTreeSet<_>>() {
            let (start, end) = keys::inspection_hold_range(&self.repo.name, &id);
            let page = self
                .store
                .scan(&self.partition, &start, &end, None, 1)
                .await?;
            if let Some((key, value)) = page.entries.first() {
                if key.as_bytes().len() != start.as_bytes().len() + 32
                    || !key.as_bytes().starts_with(start.as_bytes())
                    || !value.as_bytes().is_empty()
                {
                    return Err(StoreError::Corrupt("invalid inspection hold row".into()));
                }
                held.push(id);
            }
        }
        Ok(held)
    }

    fn batch_limit(&self) -> Result<usize, StoreError> {
        MAX_BATCH_OPS
            .saturating_sub(self.store.capabilities().reserved_batch_ops)
            .saturating_sub(self.reserved_ops)
            .checked_sub(HOLD_SHARED_OPS)
            .filter(|limit| *limit > 0)
            .ok_or_else(|| StoreError::Invalid("backend has no inspection hold budget".into()))
    }
}

fn manifest_guard(key: super::Key, prior: Option<&Value>) -> Precondition {
    match prior {
        Some(value) => Precondition::Equals(key, value.clone()),
        None => Precondition::Absent(key),
    }
}

#[derive(Debug)]
enum HoldManifest {
    Materializing(BTreeSet<Hash>),
    Materialized(BTreeSet<Hash>),
}

fn encode_pending_hold() -> Value {
    Value::new(vec![PENDING_HOLD_MARKER])
}

fn encode_materializing(ids: &BTreeSet<Hash>) -> Value {
    let mut bytes = Vec::with_capacity(2 + ids.len() * 32);
    bytes.extend_from_slice(&[2, PENDING_HOLD_MARKER]);
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Value::new(bytes)
}

fn encode_manifest(ids: &BTreeSet<Hash>) -> Value {
    let mut bytes = Vec::with_capacity(1 + ids.len() * 32);
    bytes.push(1);
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Value::new(bytes)
}

pub(crate) fn validate_manifest(value: &Value) -> Result<(), StoreError> {
    decode_manifest(Some(value)).map(|_| ())
}

fn decode_manifest(value: Option<&Value>) -> Result<HoldManifest, StoreError> {
    let Some(value) = value else {
        return Ok(HoldManifest::Materializing(BTreeSet::new()));
    };
    let bytes = value.as_bytes();
    if bytes == [PENDING_HOLD_MARKER] {
        return Ok(HoldManifest::Materializing(BTreeSet::new()));
    }
    if bytes == [1] {
        return Ok(HoldManifest::Materialized(BTreeSet::new()));
    }
    let (version, encoded_ids) = match bytes.first() {
        Some(1) => (1, &bytes[1..]),
        Some(2) if bytes.get(1) == Some(&PENDING_HOLD_MARKER) => (2, &bytes[2..]),
        _ => {
            return Err(StoreError::Corrupt(
                "invalid inspection hold manifest".into(),
            ));
        }
    };
    if !encoded_ids.len().is_multiple_of(32) || encoded_ids.len() / 32 > MAX_HOLD_IDS_PER_ADVANCE {
        return Err(StoreError::Corrupt(
            "invalid inspection hold manifest".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut last = None;
    for chunk in encoded_ids.chunks_exact(32) {
        let mut id = [0; 32];
        id.copy_from_slice(chunk);
        if last.is_some_and(|last| last >= id) {
            return Err(StoreError::Corrupt(
                "unsorted inspection hold manifest".into(),
            ));
        }
        ids.insert(id);
        last = Some(id);
    }
    Ok(if version == 2 {
        HoldManifest::Materializing(ids)
    } else {
        HoldManifest::Materialized(ids)
    })
}

#[cfg(test)]
#[path = "inspection_holds_tests.rs"]
mod tests;
