//! Pull protocol and opaque all-entry verification result.
//!
//! The framing driver establishes source integrity and framing. All-entry
//! verification owns sealed pack evidence. A request authorizes no publication;
//! unavailable input differs from authoritative absence.

mod integrity;
mod resources;
pub use resources::ResourceUsage;
pub mod framing;
pub mod verify;

use crate::{
    evidence::{
        MemberFact, PackSource, PageCommitment, ProofReference, RepositoryId, RulesetBinding,
        SourceBinding,
    },
    limits::{IndexedProfile, VerifyLimits},
};
use mkit_core::{hash::Hash, object::ObjectType};

/// Acquisition identity bound to a run and monotonically assigned sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestId {
    /// Run generation; stale replies cannot cross restarts.
    pub generation: u64,
    /// Sequence within the run.
    pub sequence: u64,
}
/// Exact byte range with checked end arithmetic required by the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// Starting offset.
    pub offset: u64,
    /// Requested length.
    pub len: u64,
}
/// Immutable byte source, with no storage address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ByteSource {
    /// Frozen pack bytes.
    Pack(PackSource),
    /// Previously authenticated canonical bytes.
    Canonical {
        /// Type-dependent object ID.
        object: Hash,
        /// Exact canonical length.
        len: u64,
        /// Immutable version.
        binding: SourceBinding,
    },
}
/// Purpose of an external fact request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectPurpose {
    /// Resolve a delta; membership must be in the requested repository.
    DeltaBase,
    /// Check a referenced object's kind or canonical length.
    Reference,
}
/// One bounded host request. Acquisition requests remain singular; compute
/// requests use the separately configured bounded caller capacity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum Request {
    /// Execute immutable library-created work with caller-owned scheduling.
    Compute {
        /// Exact job identity, operation, commitments, and reserved permits.
        job: verify::ComputeRequest,
    },
    /// Read exactly this range from this immutable source.
    Bytes {
        /// Request identity.
        request: RequestId,
        /// Bound source.
        source: ByteSource,
        /// Exact range.
        range: ByteRange,
    },
    /// Acquire a repository-scoped verified-member fact.
    ExternalObject {
        /// Request identity.
        request: RequestId,
        /// Required repository.
        repository: RepositoryId,
        /// Required object.
        object: Hash,
        /// Required use.
        purpose: ObjectPurpose,
    },
    /// Restore an authenticated retained page; absence never proves nonmembership.
    EvidencePage {
        /// Request identity.
        request: RequestId,
        /// Expected commitment.
        page: PageCommitment,
    },
}
/// Explicit acquisition outcome. Lack of a response is never absence.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum Acquisition<T> {
    /// Exact requested value.
    Present(T),
    /// Authoritative absence, only meaningful for a requested fact.
    Absent,
    /// Acquisition could not complete; retry or restart.
    Unavailable,
}
/// A complete reply, including the exact acquisition bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum Response<'a> {
    /// Exact byte-range response; short, oversized, and wrong-source replies refuse.
    Bytes {
        /// Request identity.
        request: RequestId,
        /// Echoed source.
        source: ByteSource,
        /// Echoed range.
        range: ByteRange,
        /// Exact requested bytes or explicit acquisition failure.
        value: Acquisition<&'a [u8]>,
    },
    /// Verified member and immutable canonical-byte source.
    ExternalObject {
        /// Request identity.
        request: RequestId,
        /// Fact, scoped to the requested repository.
        value: Acquisition<MemberFact>,
    },
    /// Encoded retained page; the machine authenticates it before use.
    EvidencePage {
        /// Request identity.
        request: RequestId,
        /// Expected page identity.
        page: PageCommitment,
        /// Page bytes; loss cannot produce successful lookup or absence.
        value: Acquisition<&'a [u8]>,
    },
}
/// Provisional canonical fragment; completion is required before publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectFragment<'a> {
    /// Wire-order entry ordinal.
    pub ordinal: u64,
    /// Canonical offset.
    pub offset: u64,
    /// Bounded bytes, charged until released by the consumer.
    pub bytes: &'a [u8],
}
/// Retained-page event. Acknowledgment is mandatory before dependent progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct EvidencePage<'a> {
    /// Exact commitment to retain and acknowledge.
    pub commitment: PageCommitment,
    /// Immutable encoded bytes.
    pub bytes: &'a [u8],
}
/// One cooperative pull-machine outcome.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
// Keep the fixed-size sealed summary inline; boxing adds an ownership allocation
// that the verifier would have to charge at completion.
#[allow(clippy::large_enum_variant)]
pub enum Step<'a> {
    /// Caller must acquire input.
    Request(Request),
    /// Privately retain or reproduce canonical bytes until completion.
    ProvisionalObject(ObjectFragment<'a>),
    /// Backpressure until this evidence page is retained and acknowledged.
    RetainEvidence(EvidencePage<'a>),
    /// Bounded internal progress; call again.
    Progress,
    /// Every required check succeeded; this alone grants no membership.
    Complete(VerifiedPack),
}
/// Immutable head candidate facts authenticated by all-entry verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeadFact {
    /// Object identity.
    pub object: Hash,
    /// Verified kind; closure decides whether it is an allowed head.
    pub kind: ObjectType,
    /// Authenticated object record lookup.
    pub evidence: ProofReference,
}
/// Finite artifact counts; object and occurrence counts differ for duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackCounts {
    /// All wire entries, including duplicates.
    pub entries: u64,
    /// Distinct canonical objects.
    pub objects: u64,
    /// Wire entries decoded through a delta; never exceeds `entries`.
    pub delta_entries: u64,
    /// Summed wire payload lengths.
    pub wire_payload_bytes: u64,
    /// Summed canonical decode lengths.
    pub decoded_bytes: u64,
}
/// Committed paged sequence, never an object-count-sized resident vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceSequence {
    /// Authenticated root.
    pub root: Hash,
    /// Exact committed record count.
    pub count: u64,
}
/// Sealed all-entry indexed verification. Construction belongs to this module.
///
/// Retained pages are part of its evidence lifetime. Page loss requires recovery
/// or re-verification, never fabricated lookup success. This is not a remote
/// attestation and grants neither repository membership nor read permission.
///
/// ```compile_fail
/// use mkit_primitives::{pack_verify::*, evidence::*, limits::*};
/// fn forge(source: PackSource, counts: PackCounts, ruleset: RulesetBinding,
///          profile: IndexedProfile, limits: VerifyLimits,
///          sequence: EvidenceSequence) -> VerifiedPack {
///     VerifiedPack { source, counts, version: 1, trailer: [0; 32],
///         ruleset, profile, limits,
///         object_set_root: [0; 32], occurrences: sequence,
///         dependencies: sequence, ordinals: sequence, heads: sequence }
/// }
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct VerifiedPack {
    source: PackSource,
    counts: PackCounts,
    version: u32,
    trailer: Hash,
    ruleset: RulesetBinding,
    profile: IndexedProfile,
    limits: VerifyLimits,
    object_set_root: Hash,
    occurrences: EvidenceSequence,
    dependencies: EvidenceSequence,
    ordinals: EvidenceSequence,
    heads: EvidenceSequence,
}
impl VerifiedPack {
    /// Seals a completed run. Only the verify driver may construct this; all
    /// arguments are already authenticated at this point.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seal(
        source: PackSource,
        counts: PackCounts,
        version: u32,
        trailer: Hash,
        ruleset: RulesetBinding,
        profile: IndexedProfile,
        limits: VerifyLimits,
        object_set_root: Hash,
        occurrences: EvidenceSequence,
        dependencies: EvidenceSequence,
        ordinals: EvidenceSequence,
        heads: EvidenceSequence,
    ) -> Self {
        Self {
            source,
            counts,
            version,
            trailer,
            ruleset,
            profile,
            limits,
            object_set_root,
            occurrences,
            dependencies,
            ordinals,
            heads,
        }
    }
    /// Requested and computed whole-pack identity; equality is established at sealing.
    #[must_use]
    pub const fn pack_id(&self) -> Hash {
        self.source.id
    }
    /// Exact complete pack length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.source.len
    }
    /// Whether the complete source has zero bytes (valid packs are never empty).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.source.len == 0
    }
    /// Immutable source binding.
    #[must_use]
    pub const fn source(&self) -> PackSource {
        self.source
    }
    /// Object and occurrence accounting.
    #[must_use]
    pub const fn counts(&self) -> PackCounts {
        self.counts
    }
    /// Verified pack format version from the validated header.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
    /// Verified trailer digest from the integrity pass.
    #[must_use]
    pub const fn trailer(&self) -> Hash {
        self.trailer
    }
    /// Established ruleset and semantic profile.
    #[must_use]
    pub const fn ruleset(&self) -> RulesetBinding {
        self.ruleset
    }
    /// Effective indexed content ceilings.
    #[must_use]
    pub const fn profile(&self) -> IndexedProfile {
        self.profile
    }
    /// Effective caller execution limits.
    #[must_use]
    pub const fn limits(&self) -> VerifyLimits {
        self.limits
    }
    /// Authenticated root of every distinct object.
    #[must_use]
    pub const fn object_set_root(&self) -> Hash {
        self.object_set_root
    }
    /// Ordered occurrence evidence, preserving duplicates.
    #[must_use]
    pub const fn occurrences(&self) -> EvidenceSequence {
        self.occurrences
    }
    /// Dependency evidence: per-object graph-edge records followed by
    /// repository-scoped external base facts, not repository closure.
    /// Occurrence records carry the start/count spans into this sequence.
    #[must_use]
    pub const fn dependencies(&self) -> EvidenceSequence {
        self.dependencies
    }
    /// Distinct objects enumerated in first-occurrence order for positional
    /// lookup; sequence position is the first-occurrence rank.
    #[must_use]
    pub const fn ordinals(&self) -> EvidenceSequence {
        self.ordinals
    }
    /// Authenticated head-fact sequence.
    #[must_use]
    pub const fn head_facts(&self) -> EvidenceSequence {
        self.heads
    }
}
