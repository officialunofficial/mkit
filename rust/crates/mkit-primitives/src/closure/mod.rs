//! Repository-view closure contracts, independent of storage and acquisition.
//!
//! Closure consumes an in-pack view and batched repository membership facts.
//! Missing facts and lost pages never become authoritative absence.

use crate::{
    error::Failure,
    evidence::{MemberFact, RepositoryId, Revision, RulesetBinding},
    pack_verify::{Acquisition, EvidenceSequence, RequestId},
};
use mkit_core::{hash::Hash, object::ObjectType};

// One definition for the walker's exact requested sequence and evidence export.
pub(crate) fn heads_root(heads: impl ExactSizeIterator<Item = Hash>) -> Result<Hash, Failure> {
    let mut digest = mkit_core::hash::Hasher::new();
    let domain = b"mkit-closure-heads:v1";
    let resource = || Failure {
        code: crate::error::FailureCode::ResourceLimit,
        location: crate::error::Location::default(),
        detail: crate::error::BoundedDetail::None,
    };
    digest
        .update(
            &u16::try_from(domain.len())
                .map_err(|_| resource())?
                .to_le_bytes(),
        )
        .update(domain)
        .update(
            &u64::try_from(heads.len())
                .map_err(|_| resource())?
                .to_le_bytes(),
        );
    for head in heads {
        digest.update(&head);
    }
    Ok(digest.finalize())
}

/// Required closure coverage; direct-child coverage never implies resulting-pair coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Coverage {
    /// All direct references from all new objects and all requested heads.
    DirectChildren,
    /// Complete resulting head and packmap pair coverage.
    ResultingPair,
}
/// Edge role and occurrence preserve distinct obligations for repeated IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Tree entry.
    TreeEntry,
    /// Commit or remix tree.
    Tree,
    /// Commit or remix parent; ancestry follows these only.
    Parent,
    /// Chunk occurrence in reconstructed order.
    Chunk,
    /// Tag target.
    TagTarget,
}
/// One direct reference; no new kind refusal is implied by recording an obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectEdge {
    /// Target object identity.
    pub target: Hash,
    /// Semantic edge role.
    pub kind: EdgeKind,
    /// Occurrence ordinal in the source object.
    pub ordinal: u64,
    /// Expected kind where applicable under the selected ruleset.
    pub expected_kind: Option<ObjectType>,
    /// Expected canonical or reconstructed length where applicable.
    pub expected_len: Option<u64>,
}
/// In-pack object metadata without a forged verification artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InPackObject {
    /// Canonical object identity.
    pub object: Hash,
    /// Canonical kind.
    pub kind: ObjectType,
    /// Canonical byte length.
    pub canonical_len: u64,
}
/// Canonical manifest summary authenticated by the supplied verified-object view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkedBlobSummary {
    /// Exact required sum of ordered chunk payload lengths.
    pub total_size: u64,
    /// Exact number of chunk occurrences, including duplicates.
    pub chunks: u64,
}
/// Pure view of already available in-pack records, useful for independent tests.
///
/// Methods only inspect supplied immutable data. Implementations must not perform
/// I/O. The walker still bounds pages, edges, and work. This trait cannot create
/// a `VerifiedPack`; acceptance must bind the view root to a sealed artifact.
pub trait InPackObjectView {
    /// Commitment binding this view to its full supplied object set.
    fn object_set_root(&self) -> Hash;
    /// Bytes retained by this supplied view, including inline metadata and all
    /// owned or borrowed retained buffers. A paged view reports resident pages,
    /// not the size of the host's external storage. This is a trusted host fact.
    fn retained_bytes(&self) -> u64;
    /// Exact number of distinct objects.
    fn object_count(&self) -> u64;
    /// Bounded metadata lookup. Missing retained data is an error, not absence.
    ///
    /// # Errors
    /// Returns acquisition, authentication, or resource failure.
    fn object(&self, id: &Hash) -> Result<Option<InPackObject>, Failure>;
    /// Enumerate one bounded edge page without allocating the full edge set.
    ///
    /// # Errors
    /// Returns acquisition, authentication, or resource failure. `None` means
    /// the exact ordinal is beyond the complete authenticated edge sequence.
    fn edge(&self, id: &Hash, ordinal: u64) -> Result<Option<ObjectEdge>, Failure>;
    /// Canonical manifest totals, derived from already verified canonical bytes.
    /// This is metadata, not an assertion that the referenced chunks are present.
    ///
    /// # Errors
    /// Returns acquisition, authentication, or resource failure. Non-manifests
    /// return `None`; missing manifest metadata must fail closed.
    fn chunked_blob(&self, _id: &Hash) -> Result<Option<ChunkedBlobSummary>, Failure> {
        Ok(None)
    }
    /// Enumerate every distinct object, including surplus entries.
    ///
    /// # Errors
    /// Returns acquisition, authentication, or resource failure.
    fn object_at(&self, ordinal: u64) -> Result<Option<InPackObject>, Failure>;
}
/// Batched membership acquisition, bounded by the caller's configured batch cap.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct MembershipRequest {
    /// Run-bound acquisition identity.
    pub request: RequestId,
    /// Required repository.
    pub repository: RepositoryId,
    /// Exact observed repository incarnation/view.
    pub view: Revision,
    /// Ordered object IDs; replies preserve the exact order and count.
    pub objects: Vec<Hash>,
}
/// One bound answer. An unavailable reply cannot prove absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipAnswer {
    /// Exact requested object ID.
    pub object: Hash,
    /// Authoritative present/absent or explicit acquisition failure.
    pub value: Acquisition<MemberFact>,
}
/// Batched answer; unsolicited, duplicate, stale, and mismatched entries refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct MembershipResponse {
    /// Exact run-bound request identity.
    pub request: RequestId,
    /// Exact requested repository.
    pub repository: RepositoryId,
    /// Exact requested repository view.
    pub view: Revision,
    /// Ordered answers for every requested ID.
    pub answers: Vec<MembershipAnswer>,
}
/// Sealed closure evidence. Only the closure module can construct it.
///
/// ```compile_fail
/// use mkit_primitives::{closure::*, evidence::*, pack_verify::EvidenceSequence};
/// fn forge(repository: RepositoryId, view: Revision, ruleset: RulesetBinding,
///          coverage: Coverage, external_witnesses: EvidenceSequence) -> ClosureProof {
///     ClosureProof { repository, view, ruleset, coverage,
///         object_set_root: [0; 32], heads_root: [0; 32], external_witnesses,
///         witness_page: None }
/// }
/// ```
#[derive(Debug)]
#[must_use]
pub struct ClosureProof {
    repository: RepositoryId,
    view: Revision,
    ruleset: RulesetBinding,
    coverage: Coverage,
    object_set_root: Hash,
    heads_root: Hash,
    external_witnesses: EvidenceSequence,
    witness_page: Option<crate::evidence::PageCommitment>,
}
impl ClosureProof {
    /// Repository whose verified members terminate external edges.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }
    /// Exact repository view; continued validity needs acceptance guards.
    #[must_use]
    pub const fn view(&self) -> Revision {
        self.view
    }
    /// Established closure ruleset.
    #[must_use]
    pub const fn ruleset(&self) -> RulesetBinding {
        self.ruleset
    }
    /// Explicit coverage scope.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }
    /// Bound complete supplied object set.
    #[must_use]
    pub const fn object_set_root(&self) -> Hash {
        self.object_set_root
    }
    /// Bound requested head set.
    #[must_use]
    pub const fn heads_root(&self) -> Hash {
        self.heads_root
    }
    /// First relied-on membership page, exposing each exact supplier pack through
    /// `output::decode_witness`. Every page remains part of the proof lifetime.
    #[must_use]
    pub const fn relied_on_members(&self) -> Option<crate::evidence::PageCommitment> {
        self.witness_page
    }
    /// Exact mutable membership and supplier dependencies to guard.
    #[must_use]
    pub const fn external_witnesses(&self) -> EvidenceSequence {
        self.external_witnesses
    }
}

pub mod edges;
mod journal;
pub mod limits;
pub mod output;
pub mod pair;
mod walker;
pub use walker::{
    CanonicalSource, ClosureCheck, ClosureDiagnostics, ClosureFailureContext, ClosurePage,
    ClosureRequest, ClosureResponse, ClosureStep, ClosureWalker,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod semantic_fixture;
