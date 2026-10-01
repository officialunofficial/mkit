//! Inspection holds in the advance's ref partition. Plans must be folded
//! into the caller's guarded advance apply; reads are not atomic snapshots.

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
/// Most input ids for an install plan, before deduplication.
pub const MAX_HOLD_BATCH_IDS: usize = MAX_BATCH_OPS - HOLD_SHARED_OPS;
/// Most distinct ids held by one advance. The manifest is at most 320,001
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

    /// Plan idempotent additions. The manifest CAS serializes additions and
    /// releases for this advance; existing ids need no forward-row write.
    /// The caller also guards its advance state in the combined apply and
    /// re-plans after any CAS loss. Seven new ids cost nine operations.
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
        let mut held = decode_manifest(prior.as_ref())?;
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

    /// Plan a bounded release page belonging only to this advance. Repeat
    /// after each committed page until a plan with no writes is returned. A partial
    /// page rewrites the manifest with the remaining ids. Re-plan on CAS
    /// loss, and guard the caller's advance transition in the combined apply.
    ///
    /// # Errors
    /// Invalid for unusable backend limits; corrupt for a bad manifest;
    /// storage failures propagate. No writes happen while planning.
    pub async fn plan_release(&self, advance: &Hash) -> Result<Batch, StoreError> {
        let limit = self.batch_limit()?;
        let key = keys::inspection_hold_index(&self.repo.name, advance);
        let prior = self.store.get(&self.partition, &key).await?;
        let mut held = decode_manifest(prior.as_ref())?;
        if held.is_empty() {
            let batch = Batch::new().require(manifest_guard(key, prior.as_ref()));
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

    /// Return the held subset in sorted, deduplicated order. Every content
    /// id needs only a prefix probe with limit one, regardless of how many
    /// advances hold it. The probes are sequential and are not a snapshot.
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

fn decode_manifest(value: Option<&Value>) -> Result<BTreeSet<Hash>, StoreError> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let bytes = value.as_bytes();
    if bytes.first() != Some(&1)
        || bytes.len() <= 1
        || !(bytes.len() - 1).is_multiple_of(32)
        || (bytes.len() - 1) / 32 > MAX_HOLD_IDS_PER_ADVANCE
    {
        return Err(StoreError::Corrupt(
            "invalid inspection hold manifest".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut last = None;
    for chunk in bytes[1..].chunks_exact(32) {
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
    Ok(ids)
}

#[cfg(test)]
#[path = "inspection_holds_tests.rs"]
mod tests;
