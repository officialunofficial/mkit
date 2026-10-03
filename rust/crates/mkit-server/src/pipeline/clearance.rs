//! Trusted inspection preparation and immediate serving-stop seam for post-launch WP-5.5c.
use crate::ServerError;
use crate::op::Operation;
use crate::repo::RepoId;
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::publication::{Advance, Clearance, Pair};
use mkit_core::hash::Hash;

/// Trusted inspection obligations and immediate serving-stop policy.
/// The pipeline verifies the entire resulting pair and derives dependencies,
/// including on head-only and packmap-only `UpdateRef`; policy cannot omit them.
/// This does not confer authorization; the pipeline has already authorized.
pub trait PublicationPolicy: MaybeSend + MaybeSync {
    /// Prepare the stable advance record from a verified resulting pair.
    /// Sequence, generation and operation correlation are set by the pipeline.
    fn prepare<'a>(
        &'a self,
        op: &'a Operation,
        value: &'a Pair,
    ) -> BoxFuture<'a, Result<Advance, ServerError>>;
    /// Immediate serving stop, including containing packs and external delta sources.
    /// A configured inspector must install a coherent gate before applying a hold.
    fn pack_available(&self, repo: &RepoId, pack: &Hash) -> bool;
}

pub(crate) struct Immediate;
impl PublicationPolicy for Immediate {
    fn prepare<'a>(
        &'a self,
        _: &'a Operation,
        value: &'a Pair,
    ) -> BoxFuture<'a, Result<Advance, ServerError>> {
        Box::pin(async move { Ok(immediate(value.clone(), [0; 32], Vec::new())) })
    }
    fn pack_available(&self, _: &RepoId, _: &Hash) -> bool {
        true
    }
}

/// Planner context is present on all atomic stores, even without an inspector.
#[derive(Clone)]
pub(crate) struct PublicationWrite<'a> {
    pub repo: &'a RepoId,
    pub source: &'a crate::Partition,
    pub shards: &'a dyn super::ShardMap,
    pub prepared: Option<&'a Advance>,
    /// The publication row `prepared` was computed against. Request-local:
    /// never stored, and required whenever `prepared` is present.
    pub bound: Option<PreparedAt>,
}

/// Identity of the publication row a proof was computed against. The proof's
/// verdict (membership generation, dependency visibility, boundary) is only
/// meaningful for this row; a replanned write must refuse or re-prepare rather
/// than transplant it onto a newer row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `published` and `value` are deliberately excluded: only the recheck timer and
// `append` move them, and `append` re-derives publication from the fresh row,
// so including them would refuse proofs that remain valid.
pub(crate) struct PreparedAt {
    pub generation: u64,
    pub sequence: u64,
    pub boundary: u64,
}

impl PreparedAt {
    pub(crate) fn of(row: &crate::store::publication::Publication) -> Self {
        Self {
            generation: row.generation,
            sequence: row.sequence,
            boundary: row.boundary,
        }
    }
}

pub(crate) fn resulting_pair(
    repo: &crate::RepoName,
    refs: &[super::RefUpdate],
    snap: &super::Snapshot,
) -> Result<Pair, ServerError> {
    let Some(update) = refs.first() else {
        return Ok(Pair::default());
    };
    let name = crate::store::publication::sequence_ref(&update.name);
    let target = |name: &str| -> Result<Option<Hash>, ServerError> {
        if let Some(update) = refs.iter().find(|u| u.name == name) {
            return Ok(update.new);
        }
        snap.get(&crate::store::keys::ref_key(repo, name))
            .map(crate::store::codec::decode_ref_id)
            .transpose()
            .map_err(super::meta_error)
    };
    Ok(Pair {
        head: target(&name)?,
        packmap: mkit_attest::grant::head_packmap(&name)
            .map(|name| target(&name))
            .transpose()?
            .flatten(),
    })
}

pub(crate) fn immediate(value: Pair, operation: Hash, additions: Vec<Hash>) -> Advance {
    Advance {
        sequence: 1,
        generation: 0,
        value,
        operation,
        additions,
        dependencies: Vec::new(),
        external_bases: Vec::new(),
        obligations: Vec::new(),
        state: Clearance::Cleared,
    }
}
