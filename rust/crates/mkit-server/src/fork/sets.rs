//! Binary id sets in the destination coordinator (`fo` rows): sorted,
//! concatenated 32-byte ids, bounded by [`super::MAX_SET_IDS`].

use super::{ForkError, MAX_SET_IDS};
use crate::repo::RepoName;
use crate::store::{Batch, NamespaceStore, Partition, StoreError, Value, keys};
use mkit_core::hash::Hash;
use std::collections::BTreeSet;

/// A set read from its row. Writers add no guard of their own: every set
/// write rides in the batch of the job row's guarded update, which serializes
/// drivers (and spares the batch a second copy of every set in its guards).
pub(crate) struct Set {
    pub ids: BTreeSet<Hash>,
    changed: bool,
}

impl Set {
    pub(crate) fn insert(&mut self, id: Hash) -> bool {
        let added = self.ids.insert(id);
        self.changed |= added;
        added
    }
    pub(crate) fn pop(&mut self) -> Option<Hash> {
        let id = self.ids.pop_first();
        self.changed |= id.is_some();
        id
    }
    /// Add the put of a changed set to `batch`; at most `max` ids.
    pub(crate) fn write(
        &self,
        batch: Batch,
        repo: &RepoName,
        set: u8,
        max: usize,
    ) -> Result<Batch, ForkError> {
        if !self.changed {
            return Ok(batch);
        }
        if self.ids.len() > max {
            return Err(ForkError::TooLarge);
        }
        let key = keys::fork_set(repo, set);
        let mut bytes = Vec::with_capacity(self.ids.len() * 32);
        for id in &self.ids {
            bytes.extend_from_slice(id);
        }
        Ok(batch.put(key, Value::new(bytes)))
    }
}

/// Decode a set row.
pub(crate) fn decode(value: &Value) -> Result<BTreeSet<Hash>, StoreError> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(32) || bytes.len() / 32 > MAX_SET_IDS {
        return Err(StoreError::Corrupt("invalid fork set".into()));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut id = [0; 32];
            id.copy_from_slice(chunk);
            id
        })
        .collect())
}

/// Read several sets of one repository in a single call.
pub(crate) async fn read<S: NamespaceStore, const N: usize>(
    store: &S,
    p: &Partition,
    repo: &RepoName,
    which: [u8; N],
) -> Result<[Set; N], ForkError> {
    let wanted: Vec<_> = which.iter().map(|set| keys::fork_set(repo, *set)).collect();
    let rows = store.get_many(p, &wanted).await?;
    if rows.len() != N {
        return Err(StoreError::Corrupt("short fork set read".into()).into());
    }
    let mut out = Vec::with_capacity(N);
    for row in rows {
        out.push(Set {
            ids: row.as_ref().map(decode).transpose()?.unwrap_or_default(),
            changed: false,
        });
    }
    out.try_into()
        .map_err(|_| ForkError::Unavailable("fork set read"))
}

/// Delete working or cleared sets. A delete of an absent row is a no-op, so
/// the batch needs no guard and a replay is harmless.
pub(crate) fn discard(mut batch: Batch, repo: &RepoName, which: &[u8]) -> Batch {
    for set in which {
        batch = batch.delete(keys::fork_set(repo, *set));
    }
    batch
}
