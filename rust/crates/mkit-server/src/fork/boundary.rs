//! The publication boundary a completed fork leaves in its destination.
//!
//! The packmap head the fork inherited carries a boundary flag in its
//! membership witness. A publication walk that reads the flag while walking
//! the packmap chain loads the cleared set and skips any commit or tree in it
//! (a skipped tree skips its whole subtree). Repositories that were never
//! forked read no extra row: the flag arrives with the witness the chain walk
//! reads anyway.
//!
//! What a skip waives is only the structural re-walk of an object the source
//! already proved and the fork already copied. Nothing else is waived:
//! the skipped objects' packs stay in the advance's dependencies (the chain
//! is still walked, so the flagged head must be in it), and the advance-time
//! denial proof covers every dependency pack and every external base, among
//! them the inherited external-base packs recorded here.

use super::{set, sets};
use crate::pipeline::ShardMap;
use crate::repo::RepoId;
use crate::store::{NamespaceStore, StoreError, keys};
use mkit_core::hash::Hash;
use std::collections::BTreeSet;

/// The loaded boundary of one destination.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cleared {
    /// Inherited commits and trees that need no structural re-walk.
    pub ids: BTreeSet<Hash>,
    /// Inherited packs that only supply external delta bases.
    pub bases: BTreeSet<Hash>,
}

/// Load the cleared set and the inherited base packs: one coordinator read.
///
/// # Errors
/// Storage failures and corrupt rows.
pub(crate) async fn load<S: NamespaceStore>(
    store: &S,
    shards: &dyn ShardMap,
    repo: &RepoId,
) -> Result<Cleared, StoreError> {
    let p = shards.coordinator(&repo.namespace);
    let rows = store
        .get_many(
            &p,
            &[
                keys::fork_set(&repo.name, set::CLEARED),
                keys::fork_set(&repo.name, set::BASES),
            ],
        )
        .await?;
    let [ids, bases]: [_; 2] = rows
        .try_into()
        .map_err(|_| StoreError::Corrupt("short fork boundary read".into()))?;
    Ok(Cleared {
        ids: ids
            .as_ref()
            .map(sets::decode)
            .transpose()?
            .unwrap_or_default(),
        bases: bases
            .as_ref()
            .map(sets::decode)
            .transpose()?
            .unwrap_or_default(),
    })
}
