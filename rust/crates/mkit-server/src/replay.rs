//! The replay-ledger state model (PRD §5.4 stages 0 and 4).
//!
//! One record per signed write, keyed by its auth v2 scope. Stage 0 looks
//! the record up and [`classify`]s it; stage 4 reserves it `in_flight`; the
//! apply that commits the write stores its [`StoredResult`]. Admission
//! challenges and `pending_verification` are never stored: no
//! [`StoredResult`] can represent them.

use mkit_core::hash::Hash;
use mkit_core::protocol::AdvanceOutcome;

use crate::error::Code;

/// The replay key: auth v2 `Authorized.scope`,
/// `BLAKE3(audience \n repository \n pubkey \n nonce)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReplayKey(pub Hash);

/// A replay-ledger record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    /// Digest of every signed field; a retry must match it.
    pub fingerprint: Hash,
    /// When the record may be pruned: the envelope's expiry, Unix ms.
    pub expires_at_ms: i64,
    /// Where the operation stands.
    pub state: ReplayState,
}

/// Where a recorded operation stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayState {
    /// Reserved, not yet committed. `resumable`: a retry may resume it
    /// (`UploadPack` only, overview Q5); otherwise a retry is told to wait.
    InFlight {
        /// Whether a retry resumes the operation.
        resumable: bool,
    },
    /// Committed; a retry gets this result back.
    Committed(StoredResult),
}

/// A final result a retry gets back. There is deliberately no variant for
/// an admission challenge or `pending_verification`, and a
/// [`StoredRejection`] holds only final codes and no error detail, so
/// neither can ever be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredResult {
    /// `UpdateRef`.
    UpdateRef(UpdateRefResult),
    /// `AdvanceRefs`.
    AdvanceRefs(AdvanceOutcome),
    /// `UploadPack` succeeded.
    UploadPack,
    /// A final rejection after the reservation, e.g. a policy denial.
    Rejected(StoredRejection),
}

/// The result of an `UpdateRef` compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRefResult {
    /// The ref moved.
    Committed,
    /// The expectation did not hold; `current` is what the ref held.
    Conflict {
        /// The ref's value at commit, if any.
        current: Option<Hash>,
    },
}

/// A storable rejection: a final code and its public message, with no
/// error detail (so never an admission challenge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRejection {
    code: Code,
    message: String,
}

impl StoredRejection {
    /// Whether a retry of the same nonce may get `code` back forever: only
    /// outcomes that re-running cannot change. Retryable codes
    /// (`unavailable`, which covers `pending_verification`, `aborted`,
    /// `resource_exhausted`), transient or server-side ones (`canceled`,
    /// `deadline_exceeded`, `internal`, `unknown`, `data_loss`) and
    /// `unauthenticated` are re-run instead.
    #[must_use]
    pub const fn is_storable(code: Code) -> bool {
        matches!(
            code,
            Code::InvalidArgument
                | Code::NotFound
                | Code::AlreadyExists
                | Code::PermissionDenied
                | Code::FailedPrecondition
                | Code::OutOfRange
                | Code::Unimplemented
        )
    }

    /// A rejection a retry of the same nonce gets back forever; `None`
    /// unless [`Self::is_storable`].
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Option<Self> {
        Self::is_storable(code).then(|| Self {
            code,
            message: message.into(),
        })
    }

    /// The error code.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// The public message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What stage 0 does with a request, given its record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayDecision {
    /// No record: a new operation, which continues to authorization.
    New,
    /// Committed: return the stored result without running any hook.
    Return(StoredResult),
    /// In flight and resumable (`UploadPack`).
    Resume,
    /// In flight: retryable `aborted`, before admission.
    RetryLater,
    /// The nonce was used for a different operation: `invalid_argument`.
    FingerprintMismatch,
}

/// Classify a request with `fingerprint` against its record, if any.
#[must_use]
pub fn classify(existing: Option<&ReplayRecord>, fingerprint: &Hash) -> ReplayDecision {
    match existing {
        None => ReplayDecision::New,
        Some(record) if record.fingerprint != *fingerprint => ReplayDecision::FingerprintMismatch,
        Some(record) => match &record.state {
            ReplayState::Committed(result) => ReplayDecision::Return(result.clone()),
            ReplayState::InFlight { resumable: true } => ReplayDecision::Resume,
            ReplayState::InFlight { resumable: false } => ReplayDecision::RetryLater,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: Hash = [7; 32];

    fn record(state: ReplayState) -> ReplayRecord {
        ReplayRecord {
            fingerprint: FP,
            expires_at_ms: 1_000,
            state,
        }
    }

    #[test]
    fn classify_none_is_new() {
        assert_eq!(classify(None, &FP), ReplayDecision::New);
    }

    #[test]
    fn classify_other_fingerprint_is_mismatch() {
        for state in [
            ReplayState::InFlight { resumable: true },
            ReplayState::Committed(StoredResult::UploadPack),
        ] {
            assert_eq!(
                classify(Some(&record(state)), &[8; 32]),
                ReplayDecision::FingerprintMismatch
            );
        }
    }

    #[test]
    fn classify_committed_returns_stored_result() {
        let result = StoredResult::UpdateRef(UpdateRefResult::Conflict {
            current: Some([1; 32]),
        });
        let rec = record(ReplayState::Committed(result.clone()));
        assert_eq!(classify(Some(&rec), &FP), ReplayDecision::Return(result));
    }

    #[test]
    fn classify_inflight_resumable_is_resume() {
        let rec = record(ReplayState::InFlight { resumable: true });
        assert_eq!(classify(Some(&rec), &FP), ReplayDecision::Resume);
    }

    #[test]
    fn classify_inflight_not_resumable_is_retry_later() {
        let rec = record(ReplayState::InFlight { resumable: false });
        assert_eq!(classify(Some(&rec), &FP), ReplayDecision::RetryLater);
    }

    #[test]
    fn no_stored_result_variant_for_challenge() {
        // Exhaustive on purpose: a new variant must be checked against the
        // "never store a challenge or pending_verification" rule.
        fn is_final(result: &StoredResult) -> bool {
            match result {
                StoredResult::UpdateRef(_)
                | StoredResult::AdvanceRefs(_)
                | StoredResult::UploadPack => true,
                StoredResult::Rejected(r) => StoredRejection::is_storable(r.code()),
            }
        }
        // A challenge is `permission_denied` with HTTP 402 and a typed
        // detail; a stored rejection holds neither. `pending_verification`
        // is `unavailable`, which is refused.
        let denied = StoredRejection::new(Code::PermissionDenied, "denied").unwrap();
        assert_eq!(
            (denied.code(), denied.message()),
            (Code::PermissionDenied, "denied")
        );
        assert!(is_final(&StoredResult::Rejected(denied)));
    }

    #[test]
    fn stored_rejection_admits_only_final_codes() {
        let final_codes = [
            Code::InvalidArgument,
            Code::NotFound,
            Code::AlreadyExists,
            Code::PermissionDenied,
            Code::FailedPrecondition,
            Code::OutOfRange,
            Code::Unimplemented,
        ];
        for code in final_codes {
            assert!(StoredRejection::new(code, "m").is_some(), "{code:?}");
        }
        let refused = [
            // Retryable: re-run, never replay (covers pending_verification).
            Code::Unavailable,
            Code::Aborted,
            Code::ResourceExhausted,
            // Transient or client-side cancellation.
            Code::Canceled,
            Code::DeadlineExceeded,
            // Server-side faults.
            Code::Internal,
            Code::Unknown,
            Code::DataLoss,
            // Credentials: a retry may present valid ones.
            Code::Unauthenticated,
        ];
        for code in refused {
            assert_eq!(StoredRejection::new(code, "m"), None, "{code:?}");
        }
        assert_eq!(
            final_codes.len() + refused.len(),
            16,
            "every Code is classified"
        );
    }
}
