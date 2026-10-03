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
    pub proof: Option<&'a crate::indexed::publication::incremental::Proof>,
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

#[derive(Debug)]
pub(crate) struct Prepared {
    pub advance: Advance,
    pub proof: crate::indexed::publication::incremental::Proof,
}
impl std::ops::Deref for Prepared {
    type Target = Advance;
    fn deref(&self) -> &Advance {
        &self.advance
    }
}
