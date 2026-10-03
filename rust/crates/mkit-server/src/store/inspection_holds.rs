//! Repository-wide inspection holds; kind-14 work writes content rows after advance commit.
//!
//! Unintegrated groundwork for future async inspection: no pipeline or adapter path creates holds.

use std::collections::BTreeSet;

use mkit_core::hash::Hash;

use crate::pipeline::ShardMap;
use crate::repo::RepoId;

use super::{
    Batch, MAX_BATCH_OPS, MAX_SCAN_RANGES, NamespaceStore, Partition, Precondition, StoreError,
    Value, keys,
};

/// Forward-row writes per content id, on install and release.
pub(crate) const HOLD_OPS_PER_ID: usize = 1;
/// Shared manifest CAS and write cost per plan.
pub(crate) const HOLD_SHARED_OPS: usize = 2;
/// Advance-level marker cost: one absence guard and one put.
pub(crate) const ADVANCE_HOLD_MARKER_OPS: usize = 2;
const PENDING_HOLD_MARKER: u8 = 0;
/// Most input ids for an install plan, before deduplication.
pub(crate) const MAX_HOLD_BATCH_IDS: usize = MAX_BATCH_OPS - HOLD_SHARED_OPS;
/// Maximum distinct ids per advance; the 320,001-byte manifest fits twice under the one MiB limit.
pub(crate) const MAX_HOLD_IDS_PER_ADVANCE: usize = 10_000;

/// Content holds and release manifests share the flag registry partition; advance records stay in ref shards.
/// Callers use repository-unique advance ids, binding the ref identity and advance sequence.
#[derive(Debug)]
pub(crate) struct InspectionHolds<'a, S> {
    store: &'a S,
    repo: &'a RepoId,
    partition: Partition,
    advance_partition: Partition,
    reserved_ops: usize,
}

impl<'a, S: NamespaceStore> InspectionHolds<'a, S> {
    /// Resolve repository hold storage and the separate advance ref partition.
    #[must_use]
    pub(crate) fn new(
        store: &'a S,
        shards: &dyn ShardMap,
        repo: &'a RepoId,
        ref_name: &str,
    ) -> Self {
        Self {
            store,
            repo,
            partition: shards.object_index(repo, &[0; 32]),
            advance_partition: shards.ref_shard(repo, ref_name),
            reserved_ops: 0,
        }
    }

    /// Reserve operations for caller guards and state writes, in addition to backend reservations.
    #[must_use]
    pub(crate) const fn with_reserved_ops(mut self, ops: usize) -> Self {
        self.reserved_ops = ops;
        self
    }

    /// Apply content installation and release plans in this repository partition.
    #[must_use]
    pub(crate) fn partition(&self) -> &Partition {
        &self.partition
    }

    /// Apply advance hold, completion, and final removal plans in this ref partition.
    #[must_use]
    pub(crate) fn advance_partition(&self) -> &Partition {
        &self.advance_partition
    }

    /// Plan the constant-cost advance hold record; kind-14 work later materializes per-content rows.
    /// Repeated calls guard the existing record.
    /// # Errors Storage failures propagate; corrupt records and unsupported batches fail closed.
    pub(crate) async fn plan_advance_hold(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.advance_partition, &key).await?;
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if let Some(value) = &prior {
            validate_advance_hold(value)?;
        } else {
            batch = batch.put(key, Value::new(vec![PENDING_HOLD_MARKER]));
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Plan one repository-wide kind-14 page after advance commit; the manifest CAS serializes updates.
    /// Existing ids need no forward-row write; re-plan after CAS loss.
    /// # Errors Invalid for oversized input/batch; corrupt for invalid manifests; storage errors propagate.
    pub(crate) async fn plan_holds(
        &self,
        advance: &Hash,
        ids: &[Hash],
    ) -> Result<Batch, StoreError> {
        if ids.len() > self.batch_limit()? {
            return Err(StoreError::Invalid(
                "inspection hold batch is too large".into(),
            ));
        }
        let key = keys::inspection_hold_manifest(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let manifest = decode_manifest(prior.as_ref())?;
        if manifest.released {
            return Err(StoreError::Invalid(
                "advance inspection holds are released".into(),
            ));
        }
        let mut held = manifest.ids;
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
            .put(key, encode_manifest(&held));
        for id in added {
            batch = batch.put(
                keys::inspection_hold(&self.repo.name, &id, advance),
                Value::default(),
            );
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Complete kind-14 in the ref shard after every repository page commits.
    /// The caller serializes completion with its kind-14 progress/advance state.
    /// Until this commits, serving treats all content of the advance as held.
    /// # Errors Returns storage, corrupt marker, or missing/released advance errors.
    pub(crate) async fn plan_complete(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let manifest_key = keys::inspection_hold_manifest(&self.repo.name, advance);
        let manifest = self.store.get(&self.partition, &manifest_key).await?;
        if decode_manifest(manifest.as_ref())?.released {
            return Err(StoreError::Invalid(
                "advance inspection holds are released".into(),
            ));
        }
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.advance_partition, &key).await?;
        let value = prior
            .as_ref()
            .ok_or_else(|| StoreError::Invalid("missing advance hold".into()))?;
        validate_advance_hold(value)?;
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if value.as_bytes() == [PENDING_HOLD_MARKER] {
            batch = batch.put(key, Value::new(vec![1]));
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Release one repository page after the caller durably ends the obligation in the ref shard.
    /// The manifest becomes permanently released on the first page, fencing late kind-14 writes.
    /// Re-plan after CAS loss; repeat until no writes, then remove the ref-level advance record.
    /// # Errors Returns invalid bounds, corrupt manifests, or storage failures.
    pub(crate) async fn plan_release(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let limit = self.batch_limit()?;
        let key = keys::inspection_hold_manifest(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let manifest = decode_manifest(prior.as_ref())?;
        let mut held = manifest.ids;
        let released: Vec<_> = held.iter().take(limit).copied().collect();
        for id in &released {
            held.remove(id);
        }
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if !manifest.released || !released.is_empty() {
            batch = batch.put(key, encode_released(&held));
        }
        for id in released {
            batch = batch.delete(keys::inspection_hold(&self.repo.name, &id, advance));
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Remove the ref-level hold after repository release finishes; retain the repository tombstone.
    /// Released manifests cannot gain new ids, so the completed release observation remains valid.
    /// The caller guards its terminal advance state in this ref-shard apply.
    /// # Errors Returns storage, corruption, or unfinished release errors.
    pub(crate) async fn plan_release_advance(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let manifest_key = keys::inspection_hold_manifest(&self.repo.name, advance);
        let manifest = self.store.get(&self.partition, &manifest_key).await?;
        let manifest = decode_manifest(manifest.as_ref())?;
        if !manifest.released || !manifest.ids.is_empty() {
            return Err(StoreError::Invalid(
                "repository hold release is incomplete".into(),
            ));
        }
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.advance_partition, &key).await?;
        let mut batch = Batch::new().require(manifest_guard(key.clone(), prior.as_ref()));
        if let Some(value) = prior.as_ref() {
            validate_advance_hold(value)?;
            batch = batch.delete(key);
        }
        batch.validate(&self.store.capabilities())?;
        Ok(batch)
    }

    /// Return sorted, deduplicated ids with forward rows; serving also checks pending advances.
    /// Each id probes the canonical repository partition with limit one, across all ref advances.
    /// Reads are sequential, not a snapshot; pending ref-level advance records are checked by serving.
    /// # Errors Invalid above 256 ids; corrupt for malformed rows; storage failures propagate.
    pub(crate) async fn is_held(&self, ids: &[Hash]) -> Result<Vec<Hash>, StoreError> {
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
struct HoldManifest {
    released: bool,
    ids: BTreeSet<Hash>,
}

fn encode_manifest(ids: &BTreeSet<Hash>) -> Value {
    encode_manifest_state(ids, false)
}

fn encode_released(ids: &BTreeSet<Hash>) -> Value {
    encode_manifest_state(ids, true)
}

fn encode_manifest_state(ids: &BTreeSet<Hash>, released: bool) -> Value {
    let mut bytes = Vec::with_capacity(1 + ids.len() * 32);
    bytes.push(if released { 2 } else { 1 });
    for id in ids {
        bytes.extend_from_slice(id);
    }
    Value::new(bytes)
}

pub(crate) fn validate_advance_hold(value: &Value) -> Result<(), StoreError> {
    if matches!(value.as_bytes(), [0 | 1]) {
        Ok(())
    } else {
        Err(StoreError::Corrupt(
            "invalid advance inspection hold".into(),
        ))
    }
}

pub(crate) fn validate_manifest(value: &Value) -> Result<(), StoreError> {
    decode_manifest(Some(value)).map(|_| ())
}

fn decode_manifest(value: Option<&Value>) -> Result<HoldManifest, StoreError> {
    let Some(value) = value else {
        return Ok(HoldManifest {
            released: false,
            ids: BTreeSet::new(),
        });
    };
    let Some((&state, encoded_ids)) = value.as_bytes().split_first() else {
        return Err(StoreError::Corrupt(
            "invalid inspection hold manifest".into(),
        ));
    };
    if !matches!(state, 1 | 2)
        || !encoded_ids.len().is_multiple_of(32)
        || encoded_ids.len() / 32 > MAX_HOLD_IDS_PER_ADVANCE
    {
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
    Ok(HoldManifest {
        released: state == 2,
        ids,
    })
}

#[cfg(test)]
#[path = "inspection_holds_tests.rs"]
mod tests;
