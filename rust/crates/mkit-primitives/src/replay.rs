//! Pure replay classification (SPEC-TRANSPORT-CONNECT §7.1).
//!
//! Authenticate destination, signature, and current envelope time before lookup.
//! A record's pruning timestamp never extends authorization validity. Reads
//! bypass the ledger. Hosts guard observed records and atomically commit replay
//! transitions with their effects; this module neither reads nor writes storage.

use mkit_core::hash::Hash;

/// An authoritative replay observation, supplied by the host after authentication.
/// `R` is the host's terminal result representation; transient refusals and
/// admission challenges must never be supplied as committed results.
#[derive(Debug, Clone)]
pub struct ReplayObservation<'a, R> {
    /// Digest of the complete authenticated operation.
    pub fingerprint: Hash,
    /// Observed durable state.
    pub state: ReplayStateView<'a, R>,
}

/// Observed replay state; results are borrowed and returned exactly.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ReplayStateView<'a, R> {
    /// Incomplete write; only the supported unticketed upload can resume.
    InFlight {
        /// Whether this operation supports resuming the same reservation.
        resumable: bool,
    },
    /// Terminal result already committed with its effects.
    Committed(RecordedResult<'a, R>),
}

/// A host's exact terminal payload with an explicit final classification.
/// Successful payloads are supplied only after the host observes durable
/// success. Rejections can be constructed only through the permanent allowlist;
/// challenges and transient refusals have no representation here.
#[derive(Debug, Clone)]
#[must_use]
pub struct RecordedResult<'a, R> {
    result: &'a R,
    rejection: Option<PermanentCode>,
}

impl<'a, R> RecordedResult<'a, R> {
    /// Supply an authoritatively observed successful result. This is a host
    /// observation, not verification evidence: callers must not label errors
    /// or pending operations as successful payloads.
    pub const fn success(result: &'a R) -> Self {
        Self {
            result,
            rejection: None,
        }
    }

    /// Supply a permanent refusal. `has_details` excludes admission challenges
    /// and other detailed transient errors, as in the reference storage path.
    /// Returns `None` for every code outside the permanent allowlist.
    #[must_use]
    pub const fn rejection(result: &'a R, code: &str, has_details: bool) -> Option<Self> {
        match storable_rejection(code, has_details) {
            Some(code) => Some(Self {
                result,
                rejection: Some(code),
            }),
            None => None,
        }
    }

    /// Permanent refusal code, or `None` for a successful result.
    #[must_use]
    pub const fn rejection_code(&self) -> Option<&PermanentCode> {
        self.rejection.as_ref()
    }
}

/// Classification without expiry pruning or mutable effects.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum ReplayDecision<'a, R> {
    /// Fresh; the host needs an absence guard to reserve or commit it.
    Fresh,
    /// Same operation completed; return this exact saved result.
    Recorded(&'a R),
    /// Same operation can resume its in-flight upload.
    Resume,
    /// Same operation is in flight; retryable `aborted`.
    InFlight,
    /// Same scope identifies a different operation; `invalid_argument`.
    Conflict,
}

/// Classify the supplied observation. Fingerprint mismatch takes precedence
/// over all stored states. This function deliberately accepts no clock: record
/// expiry is a pruning concern, while current envelope validity is checked first.
///
/// # Examples
/// ```
/// use mkit_primitives::replay::{classify_replay, ReplayDecision};
/// assert_eq!(classify_replay::<()>(None, &[0; 32]), ReplayDecision::Fresh);
/// ```
pub fn classify_replay<'a, R>(
    existing: Option<ReplayObservation<'a, R>>,
    fingerprint: &Hash,
) -> ReplayDecision<'a, R> {
    match existing {
        None => ReplayDecision::Fresh,
        Some(record) if record.fingerprint != *fingerprint => ReplayDecision::Conflict,
        Some(record) => match record.state {
            ReplayStateView::Committed(result) => ReplayDecision::Recorded(result.result),
            ReplayStateView::InFlight { resumable: true } => ReplayDecision::Resume,
            ReplayStateView::InFlight { resumable: false } => ReplayDecision::InFlight,
        },
    }
}

/// Shared permanent rejection codes. Replay adds only allowlist mapping;
/// the skeleton's terminal result model owns the code type.
pub use crate::decision::PermanentCode;

impl PermanentCode {
    /// Parse only the explicit permanent-code allowlist. In particular,
    /// membership lag, pending verification and unavailable inspection all use
    /// `unavailable` and are never storable. Unknown/future codes are refused.
    #[must_use]
    pub const fn from_code(code: &str) -> Option<Self> {
        Some(match code.as_bytes() {
            b"invalid_argument" => Self::InvalidArgument,
            b"not_found" => Self::NotFound,
            b"already_exists" => Self::AlreadyExists,
            b"permission_denied" => Self::PermissionDenied,
            b"failed_precondition" => Self::FailedPrecondition,
            b"out_of_range" => Self::OutOfRange,
            b"unimplemented" => Self::Unimplemented,
            _ => return None,
        })
    }

    /// Canonical Connect code for host mapping.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::PermissionDenied => "permission_denied",
            Self::FailedPrecondition => "failed_precondition",
            Self::OutOfRange => "out_of_range",
            Self::Unimplemented => "unimplemented",
        }
    }
}

/// Apply the permanent-code allowlist with the admission-challenge exclusion.
/// Hosts retain their own terminal payloads; no error details or token encoding
/// are standardized here. Other retryable outcomes have no permanent code.
#[must_use]
pub const fn storable_rejection(code: &str, admission_challenge: bool) -> Option<PermanentCode> {
    if admission_challenge {
        None
    } else {
        PermanentCode::from_code(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn fixture_classifier_matrix_returns_exact_recorded_result() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../fixtures/replay/classifier.json")).unwrap();
        assert_eq!(cases.len(), 10);
        let result = ("saved public result", [42; 32]);
        for case in cases {
            let state = match case["state"].as_str().unwrap() {
                "absent" => None,
                "committed" => Some(ReplayStateView::Committed(RecordedResult::success(&result))),
                "rejected" => Some(ReplayStateView::Committed(
                    RecordedResult::rejection(&result, "not_found", false).unwrap(),
                )),
                "resumable" => Some(ReplayStateView::InFlight { resumable: true }),
                "in_flight" => Some(ReplayStateView::InFlight { resumable: false }),
                _ => panic!("unknown fixture state"),
            };
            let fact = state.map(|state| ReplayObservation {
                fingerprint: [7; 32],
                state,
            });
            let fingerprint = if case["same_fingerprint"].as_bool().unwrap() {
                [7; 32]
            } else {
                [8; 32]
            };
            let decision = classify_replay(fact, &fingerprint);
            let actual = match decision {
                ReplayDecision::Fresh => "fresh",
                ReplayDecision::Recorded(saved) => {
                    assert!(std::ptr::eq(saved, &raw const result));
                    "recorded"
                }
                ReplayDecision::Resume => "resume",
                ReplayDecision::InFlight => "in_flight",
                ReplayDecision::Conflict => "conflict",
            };
            assert_eq!(actual, case["expected"].as_str().unwrap(), "{case}");
        }
    }

    #[test]
    fn fixture_code_allowlist_and_transient_exclusions() {
        let cases: Vec<Value> =
            serde_json::from_str(include_str!("../fixtures/replay/codes.json")).unwrap();
        assert_eq!(cases.len(), 17);
        for case in cases {
            let code = case["code"].as_str().unwrap();
            let permanent = storable_rejection(code, false);
            let recorded = RecordedResult::rejection(&case, code, false);
            assert_eq!(recorded.is_some(), permanent.is_some());
            assert!(RecordedResult::rejection(&case, code, true).is_none());
            if let Some(recorded) = recorded {
                assert_eq!(recorded.rejection_code(), permanent.as_ref());
            }
            assert_eq!(
                permanent.is_some(),
                case["storable"].as_bool().unwrap(),
                "{code}"
            );
            if let Some(permanent) = permanent {
                assert_eq!(permanent.as_str(), code);
            }
            assert_eq!(storable_rejection(code, true), None, "challenge: {code}");
        }
        for reason in [
            "membership lag",
            "pending verification",
            "unavailable inspection",
        ] {
            assert_eq!(storable_rejection("unavailable", false), None, "{reason}");
        }
    }
}
