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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InPackObject {
    /// Canonical object identity.
    pub object: Hash,
    /// Canonical kind.
    pub kind: ObjectType,
    /// Canonical byte length.
    pub canonical_len: u64,
}
/// Pure view of already available in-pack records, useful for independent tests.
///
/// Methods only inspect supplied immutable data. Implementations must not perform
/// I/O. The walker still bounds pages, edges, and work. This trait cannot create
/// a `VerifiedPack`; acceptance must bind the view root to a sealed artifact.
pub trait InPackObjectView {
    /// Commitment binding this view to its full supplied object set.
    fn object_set_root(&self) -> Hash;
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
///         object_set_root: [0; 32], heads_root: [0; 32], external_witnesses }
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
    /// Exact mutable membership and supplier dependencies to guard.
    #[must_use]
    pub const fn external_witnesses(&self) -> EvidenceSequence {
        self.external_witnesses
    }
}
