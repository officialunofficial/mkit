//! Stable refusal codes and bounded diagnostics.

/// Stable refusal category. Display text is diagnostic; match the code instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FailureCode {
    // pack_verify
    /// Pack magic mismatch.
    #[error("InvalidMagic")]
    InvalidMagic,
    /// Unsupported pack format.
    #[error("UnsupportedPackVersion")]
    UnsupportedPackVersion,
    /// Truncated input.
    #[error("UnexpectedEof")]
    UnexpectedEof,
    /// Unknown frame tag.
    #[error("InvalidEntryType")]
    InvalidEntryType,
    /// Protocol entry ceiling exceeded.
    #[error("TooManyObjects")]
    TooManyObjects,
    /// Protocol wire-byte ceiling exceeded.
    #[error("PackfileTooLarge")]
    PackfileTooLarge,
    /// Pack integrity mismatch.
    #[error("PackfileCorrupted")]
    PackfileCorrupted,
    /// Compressed-entry header truncated.
    #[error("ZstdEntryTruncated")]
    ZstdEntryTruncated,
    /// Delta base prefix truncated.
    #[error("DeltaEntryTruncated")]
    DeltaEntryTruncated,
    /// Nonstorable delta object used as a canonical object.
    #[error("NonStorableObject")]
    NonStorableObject,
    /// Data follows the declared entry sequence.
    #[error("TrailingData")]
    TrailingData,
    /// Invalid compressed stream.
    #[error("DecompressionFailed")]
    DecompressionFailed,
    /// Compressed output length mismatch.
    #[error("DecompressedSizeMismatch")]
    DecompressedSizeMismatch,
    /// Compressed output exceeds its ceiling.
    #[error("DecompressionLimitExceeded")]
    DecompressionLimitExceeded,
    /// Invalid delta instructions.
    #[error("InvalidDelta")]
    InvalidDelta,
    /// Delta base identity mismatch.
    #[error("DeltaBaseMismatch")]
    DeltaBaseMismatch,
    /// Delta target length mismatch.
    #[error("DeltaSizeMismatch")]
    DeltaSizeMismatch,
    /// Noncanonical object encoding.
    #[error("NonCanonicalObject")]
    NonCanonicalObject,
    /// Type-dependent object identity mismatch.
    #[error("ObjectHashMismatch")]
    ObjectHashMismatch,
    /// Invalid individual signature.
    #[error("BadSignature")]
    BadSignature,
    /// The delta chain inside the pack alone exceeds the profile depth. A
    /// property of the submitted bytes, so permanent.
    #[error("DeltaChainTooDeep")]
    DeltaChainTooDeep,
    /// The chain fits the profile inside the pack but passes it once an
    /// external base's recorded depth is added. That depth belongs to
    /// repository state, so the refusal is never permanent.
    #[error("ExternalDeltaChainTooDeep")]
    ExternalDeltaChainTooDeep,
    /// Authoritative repository base absence.
    #[error("ExternalBaseAbsent")]
    ExternalBaseAbsent,
    /// Source is shorter than the pack header and trailer.
    #[error("PackfileTooShort")]
    PackfileTooShort,
    // closure
    /// Required child absence.
    #[error("MissingClosure")]
    MissingClosure,
    /// Required object kind mismatch.
    #[error("WrongKind")]
    WrongKind,
    /// A packmap chain node repeated an earlier node.
    #[error("PackmapCycle")]
    PackmapCycle,
    // infrastructure
    /// Caller execution budget exhausted.
    #[error("ResourceLimit")]
    ResourceLimit,
    /// Input acquisition unavailable.
    #[error("UnavailableInput")]
    UnavailableInput,
    /// Reply violates the request contract.
    #[error("InvalidResponse")]
    InvalidResponse,
    /// Invalid or unsupported resume state.
    #[error("InvalidCheckpoint")]
    InvalidCheckpoint,
    /// Immutable source binding changed.
    #[error("SourceChanged")]
    SourceChanged,
    /// Build lacks the required decoder.
    #[error("UnsupportedCapability")]
    UnsupportedCapability,
    /// The machine has not reached a checkpoint-safe boundary.
    #[error("CheckpointNotReady")]
    CheckpointNotReady,
    // decision
    /// Ref operation grammar, names, pairing, or deletion shape is invalid.
    #[error("InvalidRefRequest")]
    InvalidRefRequest,
    // fork
    /// Uniform source absence at the final fork proof.
    #[error("ForkSourceNotFound")]
    ForkSourceNotFound,
    /// Foreign or visible destination state prevents acceptance.
    #[error("ForkDestinationNotEmpty")]
    ForkDestinationNotEmpty,
    /// Fork authorization or authority facts no longer match.
    #[error("ForkPermissionDenied")]
    ForkPermissionDenied,
    /// Declared and requested destination visibility differ.
    #[error("ForkVisibilityMismatch")]
    ForkVisibilityMismatch,
    /// Fork reservation is no longer pending.
    #[error("ForkReservationSettled")]
    ForkReservationSettled,
    /// Fork durable protection expired.
    #[error("ForkExpired")]
    ForkExpired,
    /// Fork admission debit or applicable quota does not match.
    #[error("ForkQuotaExceeded")]
    ForkQuotaExceeded,
    /// Fork job or replay belongs to another binding.
    #[error("ForkBindingMismatch")]
    ForkBindingMismatch,
    /// Destination lifecycle currently withholds accepted fork clearance.
    #[error("ForkLifecycleUnavailable")]
    ForkLifecycleUnavailable,
    // auth
    /// Malformed, mismatched, expired, or incorrectly signed auth envelope.
    #[error("InvalidEnvelope")]
    InvalidEnvelope,
    /// Host-authenticated upload claims do not bind to the request.
    #[error("ClaimsBindingMismatch")]
    ClaimsBindingMismatch,
    // replay
    // evidence
    /// Unsupported evidence format version.
    #[error("UnsupportedEvidenceVersion")]
    UnsupportedEvidenceVersion,
    /// Evidence ruleset or profile does not match the writer configuration.
    #[error("EvidenceProfileMismatch")]
    EvidenceProfileMismatch,
    /// Noncanonical evidence framing, order, tags, or facts.
    #[error("NonCanonicalEvidence")]
    NonCanonicalEvidence,
    /// Evidence does not match the frozen pack and operation.
    #[error("EvidenceBindingMismatch")]
    EvidenceBindingMismatch,
    /// Head kind or signer metadata does not match the evidence.
    #[error("EvidenceHeadMismatch")]
    EvidenceHeadMismatch,
    /// Unsupported normative verification ruleset.
    #[error("UnsupportedRuleset")]
    UnsupportedRuleset,

    /// Malformed or noncanonical evidence encoding.
    #[error("InvalidEvidence")]
    InvalidEvidence,

    /// Evidence does not authenticate under the expected commitment.
    #[error("EvidenceMismatch")]
    EvidenceMismatch,
}
impl FailureCode {
    /// Stable machine-readable string. Diagnostic Display text is not a parser API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMagic => "InvalidMagic",
            Self::UnsupportedPackVersion => "UnsupportedPackVersion",
            Self::UnexpectedEof => "UnexpectedEof",
            Self::InvalidEntryType => "InvalidEntryType",
            Self::TooManyObjects => "TooManyObjects",
            Self::PackfileTooLarge => "PackfileTooLarge",
            Self::PackfileCorrupted => "PackfileCorrupted",
            Self::ZstdEntryTruncated => "ZstdEntryTruncated",
            Self::DeltaEntryTruncated => "DeltaEntryTruncated",
            Self::NonStorableObject => "NonStorableObject",
            Self::TrailingData => "TrailingData",
            Self::DecompressionFailed => "DecompressionFailed",
            Self::DecompressedSizeMismatch => "DecompressedSizeMismatch",
            Self::DecompressionLimitExceeded => "DecompressionLimitExceeded",
            Self::InvalidDelta => "InvalidDelta",
            Self::DeltaBaseMismatch => "DeltaBaseMismatch",
            Self::DeltaSizeMismatch => "DeltaSizeMismatch",
            Self::NonCanonicalObject => "NonCanonicalObject",
            Self::ObjectHashMismatch => "ObjectHashMismatch",
            Self::BadSignature => "BadSignature",
            Self::DeltaChainTooDeep => "DeltaChainTooDeep",
            Self::ExternalDeltaChainTooDeep => "ExternalDeltaChainTooDeep",
            Self::ExternalBaseAbsent => "ExternalBaseAbsent",
            Self::PackfileTooShort => "PackfileTooShort",
            Self::MissingClosure => "MissingClosure",
            Self::WrongKind => "WrongKind",
            Self::PackmapCycle => "PackmapCycle",
            Self::ResourceLimit => "ResourceLimit",
            Self::UnavailableInput => "UnavailableInput",
            Self::InvalidResponse => "InvalidResponse",
            Self::InvalidCheckpoint => "InvalidCheckpoint",
            Self::CheckpointNotReady => "CheckpointNotReady",
            Self::SourceChanged => "SourceChanged",
            Self::UnsupportedCapability => "UnsupportedCapability",
            // decision
            Self::InvalidRefRequest => "InvalidRefRequest",
            // fork
            Self::ForkSourceNotFound => "ForkSourceNotFound",
            Self::ForkDestinationNotEmpty => "ForkDestinationNotEmpty",
            Self::ForkPermissionDenied => "ForkPermissionDenied",
            Self::ForkVisibilityMismatch => "ForkVisibilityMismatch",
            Self::ForkReservationSettled => "ForkReservationSettled",
            Self::ForkExpired => "ForkExpired",
            Self::ForkQuotaExceeded => "ForkQuotaExceeded",
            Self::ForkBindingMismatch => "ForkBindingMismatch",
            Self::ForkLifecycleUnavailable => "ForkLifecycleUnavailable",
            // auth
            Self::InvalidEnvelope => "InvalidEnvelope",
            Self::ClaimsBindingMismatch => "ClaimsBindingMismatch",
            // evidence
            Self::UnsupportedEvidenceVersion => "UnsupportedEvidenceVersion",
            Self::EvidenceProfileMismatch => "EvidenceProfileMismatch",
            Self::NonCanonicalEvidence => "NonCanonicalEvidence",
            Self::EvidenceBindingMismatch => "EvidenceBindingMismatch",
            Self::EvidenceHeadMismatch => "EvidenceHeadMismatch",
            Self::UnsupportedRuleset => "UnsupportedRuleset",
            Self::InvalidEvidence => "InvalidEvidence",
            Self::EvidenceMismatch => "EvidenceMismatch",
        }
    }
}
/// Whether an embedder may record a refusal so a retry of the same input gets
/// it back unchanged. Derived from the code alone; no embedder state is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Persistence {
    /// A property of the submitted bytes: the same bytes always draw the same
    /// refusal, so it may be recorded and replayed.
    Content,
    /// Depends on repository state, time, a deployment limit or resources.
    /// Re-run the operation instead of replaying it.
    Transient,
}
impl FailureCode {
    /// How an embedder may treat a refusal with this code (SPEC-PACKFILE 6.2).
    /// Unlisted codes are [`Persistence::Transient`], so a new code is never
    /// recorded by accident.
    #[must_use]
    pub const fn persistence(self) -> Persistence {
        match self {
            Self::InvalidMagic
            | Self::UnsupportedPackVersion
            | Self::UnexpectedEof
            | Self::InvalidEntryType
            | Self::TooManyObjects
            | Self::PackfileCorrupted
            | Self::ZstdEntryTruncated
            | Self::DeltaEntryTruncated
            | Self::NonStorableObject
            | Self::TrailingData
            | Self::DecompressionFailed
            | Self::DecompressedSizeMismatch
            | Self::DecompressionLimitExceeded
            | Self::InvalidDelta
            | Self::DeltaBaseMismatch
            | Self::DeltaSizeMismatch
            | Self::NonCanonicalObject
            | Self::ObjectHashMismatch
            | Self::BadSignature
            | Self::DeltaChainTooDeep
            | Self::PackfileTooShort => Persistence::Content,
            _ => Persistence::Transient,
        }
    }
}
impl Failure {
    /// How an embedder may treat this refusal; see [`FailureCode::persistence`].
    #[must_use]
    pub const fn persistence(&self) -> Persistence {
        self.code.persistence()
    }
}

/// What a repository-membership miss means at a given age.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MembershipMiss {
    /// Inside the visibility lag window: the object may still become visible.
    /// Retry; this is never a content verdict.
    Retryable,
    /// After the window: an authenticated absence, a content verdict.
    Absent,
}

/// Classify a membership miss for an input first seen `age` ago (same unit as
/// `bound`). The miss is retryable while `age < bound`.
///
/// ```
/// use mkit_primitives::error::{classify_membership_miss, MembershipMiss};
/// assert_eq!(classify_membership_miss(9, 10), MembershipMiss::Retryable);
/// assert_eq!(classify_membership_miss(10, 10), MembershipMiss::Absent);
/// ```
#[must_use]
pub const fn classify_membership_miss(age: u64, bound: u64) -> MembershipMiss {
    if age < bound {
        MembershipMiss::Retryable
    } else {
        MembershipMiss::Absent
    }
}

/// Bounded failure attribution, with no object bytes or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Location {
    /// Frame ordinal when known.
    pub ordinal: Option<u64>,
    /// Pack byte offset when known.
    pub offset: Option<u64>,
}
/// Fixed-size diagnostic context; no caller-controlled strings are retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundedDetail {
    /// No additional context.
    None,
    /// Expected and actual numeric bounds.
    Bounds {
        /// Expected bound or value.
        expected: u64,
        /// Observed value.
        actual: u64,
    },
}
/// A refusal with stable code and bounded attribution.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code} at {location:?}: {detail:?}")]
pub struct Failure {
    /// Stable classification.
    pub code: FailureCode,
    /// Frame and offset attribution.
    pub location: Location,
    /// Bounded diagnostic values.
    pub detail: BoundedDetail,
}

#[cfg(test)]
mod tests {
    use super::FailureCode;
    #[test]
    fn stable_codes_are_unique() {
        let codes = [
            FailureCode::InvalidMagic.as_str(),
            FailureCode::UnsupportedPackVersion.as_str(),
            FailureCode::UnexpectedEof.as_str(),
            FailureCode::InvalidEntryType.as_str(),
            FailureCode::TooManyObjects.as_str(),
            FailureCode::PackfileTooLarge.as_str(),
            FailureCode::PackfileCorrupted.as_str(),
            FailureCode::ZstdEntryTruncated.as_str(),
            FailureCode::DeltaEntryTruncated.as_str(),
            FailureCode::NonStorableObject.as_str(),
            FailureCode::TrailingData.as_str(),
            FailureCode::DecompressionFailed.as_str(),
            FailureCode::DecompressedSizeMismatch.as_str(),
            FailureCode::DecompressionLimitExceeded.as_str(),
            FailureCode::InvalidDelta.as_str(),
            FailureCode::DeltaBaseMismatch.as_str(),
            FailureCode::DeltaSizeMismatch.as_str(),
            FailureCode::NonCanonicalObject.as_str(),
            FailureCode::ObjectHashMismatch.as_str(),
            FailureCode::BadSignature.as_str(),
            FailureCode::DeltaChainTooDeep.as_str(),
            FailureCode::ExternalDeltaChainTooDeep.as_str(),
            FailureCode::ExternalBaseAbsent.as_str(),
            FailureCode::PackfileTooShort.as_str(),
            FailureCode::MissingClosure.as_str(),
            FailureCode::WrongKind.as_str(),
            FailureCode::PackmapCycle.as_str(),
            FailureCode::ResourceLimit.as_str(),
            FailureCode::UnavailableInput.as_str(),
            FailureCode::InvalidResponse.as_str(),
            FailureCode::InvalidCheckpoint.as_str(),
            FailureCode::SourceChanged.as_str(),
            FailureCode::UnsupportedCapability.as_str(),
            // decision
            FailureCode::InvalidRefRequest.as_str(),
            FailureCode::CheckpointNotReady.as_str(),
            FailureCode::ForkSourceNotFound.as_str(),
            FailureCode::ForkDestinationNotEmpty.as_str(),
            FailureCode::ForkPermissionDenied.as_str(),
            FailureCode::ForkVisibilityMismatch.as_str(),
            FailureCode::ForkReservationSettled.as_str(),
            FailureCode::ForkExpired.as_str(),
            FailureCode::ForkQuotaExceeded.as_str(),
            FailureCode::ForkBindingMismatch.as_str(),
            FailureCode::ForkLifecycleUnavailable.as_str(),
            // auth
            FailureCode::InvalidEnvelope.as_str(),
            FailureCode::ClaimsBindingMismatch.as_str(),
            FailureCode::UnsupportedEvidenceVersion.as_str(),
            FailureCode::EvidenceProfileMismatch.as_str(),
            FailureCode::NonCanonicalEvidence.as_str(),
            FailureCode::EvidenceBindingMismatch.as_str(),
            FailureCode::EvidenceHeadMismatch.as_str(),
            FailureCode::UnsupportedRuleset.as_str(),
            FailureCode::InvalidEvidence.as_str(),
            FailureCode::EvidenceMismatch.as_str(),
        ];
        let unique: std::collections::BTreeSet<_> = codes.into_iter().collect();
        assert_eq!(unique.len(), codes.len());
        let registered: std::collections::BTreeSet<_> =
            include_str!("../fixtures/error/failure-codes.txt")
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect();
        assert_eq!(
            unique, registered,
            "stable code registry must match the API"
        );
    }
}
