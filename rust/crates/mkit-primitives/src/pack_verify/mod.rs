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
///
/// The driver hands a page to the host when its cache evicts it, at a
/// checkpoint, and at completion of a durable run. Pages are scoped to the run
/// and are reproduced by re-verifying the pack; they are not an archive.
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
// Keep the fixed-size sealed summary inline; boxing adds an ownership allocation
// that the verifier would have to charge at completion.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum Step<'a> {
    /// Caller must acquire input.
    Request(Request),
    /// Privately retain or reproduce canonical bytes until completion.
    ProvisionalObject(ObjectFragment<'a>),
    /// Backpressure until this evidence page is retained and acknowledged.
    RetainEvidence(EvidencePage<'a>),
    /// A page the host retained is no longer reachable from the driver's roots
    /// or from its latest checkpoint; the host may drop it. No reply is needed,
    /// and the run never asks for it again. Completion ends the obligation:
    /// the host may discard every page of the run, released or not.
    ReleasePage(PageCommitment),
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
/// Order-independent commitment to every external delta-base fact a verification
/// received, re-requests included: their count and the 256-bit wrapping sum of
/// their domain-separated hashes.
///
/// The host that supplied the facts can recompute it from its own list, so an
/// omitted, extra or altered base is detectable without any retained page.
///
/// It protects against accidental host omission, not an adversarial host: the
/// count and sum are not collision-resistant against a list the host chooses,
/// and a host that can lie about the list can skip the decision anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalBases {
    /// Number of facts received.
    pub count: u64,
    /// Wrapping little-endian 256-bit sum of the facts' domain-separated hashes.
    pub sum: Hash,
}
impl ExternalBases {
    /// The commitment of no external base.
    pub const EMPTY: Self = Self {
        count: 0,
        sum: [0; 32],
    };
    /// Add one received fact.
    ///
    /// # Errors
    /// `ResourceLimit` if the count would overflow.
    pub fn add(&mut self, fact: &crate::evidence::MemberFact) -> Result<(), crate::error::Failure> {
        let record = verify::records::DependencyRecord::External {
            consumed_ordinal: 0,
            child: [0; 32],
            fact: fact.clone(),
        }
        .to_bytes();
        let digest = mkit_core::hash::domain_digest(b"mkit-external-base:v1", &record);
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| crate::error::Failure {
                code: crate::error::FailureCode::ResourceLimit,
                location: crate::error::Location::default(),
                detail: crate::error::BoundedDetail::None,
            })?;
        let mut carry = 0u16;
        for (sum, add) in self.sum.iter_mut().zip(digest) {
            let total = u16::from(*sum) + u16::from(add) + carry;
            *sum = total.to_le_bytes()[0];
            carry = total >> 8;
        }
        Ok(())
    }
    /// Commitment of a list, in any order.
    ///
    /// # Errors
    /// `ResourceLimit` if the count would overflow.
    pub fn of<'a>(
        facts: impl IntoIterator<Item = &'a crate::evidence::MemberFact>,
    ) -> Result<Self, crate::error::Failure> {
        let mut commitment = Self::EMPTY;
        for fact in facts {
            commitment.add(fact)?;
        }
        Ok(commitment)
    }
}
/// Sealed all-entry indexed verification. Construction belongs to this module.
///
/// It carries root digests and counts, not the evidence pages. Pages are scoped
/// to the run that produced them, and re-verifying the pack reproduces them
/// exactly. The producing driver needs no page after `Step::Complete`. The host
/// must keep pages needed by downstream retained occurrence views, closure
/// witnesses, [`crate::decision::AcceptanceBasis::from_verified`], or evidence
/// export until every consumer finishes or its needed data is materialized.
/// Complete verification, consume the retained view or build the closure, then
/// construct the basis or export evidence before disposing of their input pages.
/// Choose ephemeral retention only if later consumers need no retained pages or
/// their needed data has been materialized; it does not flush the live cache at
/// completion. Page loss while a consumer still needs evidence requires recovery
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
    external_bases: ExternalBases,
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
        external_bases: ExternalBases,
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
            external_bases,
        }
    }
    /// A pack that no verification produced, for tests of consumers only.
    ///
    /// Only the `synthetic-artifacts` feature (or this crate's own tests) exposes it.
    /// It fabricates a sealed artifact; production code must never enable it.
    #[cfg(any(test, feature = "synthetic-artifacts"))]
    #[doc(hidden)]
    pub fn synthetic_for_tests(object_set_root: Hash, ruleset: RulesetBinding) -> Self {
        Self::synthetic_with_external_bases(object_set_root, ruleset, ExternalBases::EMPTY)
    }
    /// [`Self::synthetic_for_tests`] with an external-base commitment.
    #[cfg(any(test, feature = "synthetic-artifacts"))]
    #[doc(hidden)]
    pub fn synthetic_with_external_bases(
        object_set_root: Hash,
        ruleset: RulesetBinding,
        external_bases: ExternalBases,
    ) -> Self {
        let sequence = EvidenceSequence {
            root: [0; 32],
            count: 0,
        };
        Self::seal(
            PackSource {
                id: [0; 32],
                len: 0,
                binding: crate::evidence::SourceBinding([0; 32]),
            },
            PackCounts {
                entries: 0,
                objects: 0,
                delta_entries: 0,
                wire_payload_bytes: 0,
                decoded_bytes: 0,
            },
            1,
            [0; 32],
            ruleset,
            IndexedProfile {
                pack_bytes: 1 << 30,
                decoded_bytes: 4 << 30,
                delta_depth: 50,
            },
            VerifyLimits::indexed(),
            object_set_root,
            sequence,
            sequence,
            sequence,
            sequence,
            external_bases,
        )
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
    /// Commitment to every external delta-base fact the verification received.
    #[must_use]
    pub const fn external_bases(&self) -> ExternalBases {
        self.external_bases
    }
    /// Authenticated head-fact sequence.
    #[must_use]
    pub const fn head_facts(&self) -> EvidenceSequence {
        self.heads
    }
}
