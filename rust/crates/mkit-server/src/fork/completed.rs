//! Evidence that a signed request replays a fork that already accepted its terminal result.
//!
//! The answer is a witness, not a result: the result of a fork always comes
//! from [`crate::pipeline::Pipeline::fork_repo`]. The witness only lets an
//! embedder's own pre-dispatch policy stand aside for a replay, so it checks
//! the stored job against the request field by field and fails closed.

use super::{ForkJobV1, ForkSpec, Phase, binding};
use crate::repo::{NamespaceKey, RepoId, RepoName};

/// A request that replays a fork which finished, with consistent job
/// evidence: the replay record is committed for this very request and the
/// destination's job retains acceptance and agrees with the request on its source,
/// branch, tip, destination, binding, packmap and source sequence.
///
/// It carries no [`super::ForkResult`]; ask the pipeline for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedFork {
    source: RepoId,
    destination: RepoId,
}

impl CompletedFork {
    /// The repository that was forked.
    #[must_use]
    pub fn source(&self) -> &RepoId {
        &self.source
    }

    /// The repository the fork created.
    #[must_use]
    pub fn destination(&self) -> &RepoId {
        &self.destination
    }

    /// The witness for `job` against `spec`, or `None` when any field of the
    /// stored evidence disagrees with the request.
    pub(crate) fn check(job: &ForkJobV1, spec: &ForkSpec) -> Option<Self> {
        let result = job.accepted.as_ref()?;
        let source = RepoId {
            namespace: NamespaceKey::from_stored(job.source_ns.clone()),
            name: RepoName::new(job.source_repo.clone()).ok()?,
        };
        let destination = RepoId {
            namespace: NamespaceKey::from_stored(job.dest_ns.clone()),
            name: RepoName::new(job.dest_repo.clone()).ok()?,
        };
        let phase_consistent = match job.phase {
            Phase::Publish => job.result.is_none(),
            Phase::Done => job.result.as_ref() == Some(result),
            _ => false,
        };
        let consistent = phase_consistent
            && job.failure.is_none()
            && job.binding == binding(spec)
            && destination == spec.dest
            && source == spec.source
            && job.source_ref == spec.source_ref
            && job.tip == spec.expected_tip
            && result.source
                == crate::store::repo_storage::identity(&source.namespace, &source.name)
            && result.source_ref == spec.source_ref
            && result.tip == spec.expected_tip
            && result.packmap == job.packmap
            && result.source_sequence == job.source_sequence;
        consistent.then_some(Self {
            source,
            destination,
        })
    }
}
