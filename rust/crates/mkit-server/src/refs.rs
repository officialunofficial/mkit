//! Ref compare-and-swap and ref-name helpers (SPEC-TRANSPORT-CONNECT §3,
//! SPEC-REFS §3 and §4).
//!
//! The canonical copy of logic that today lives in `apps/vcs-worker/src/refs.rs`,
//! `mkit-transport-connect`'s `refs_convert.rs` and `hashutil.rs`, and
//! `mkit serve`'s `pack_key_from_id`/`decode_update_ref`. The old copies go
//! when their consumers switch: `mkit serve` in WP-M0-13,
//! `mkit-transport-connect` in WP-M0-15 and `vcs-worker` in WP-M0-17.
//! `apps/repo-worker` keeps its own copy (planner decision Q11).

use mkit_core::hash::Hash;
use mkit_core::refs::RefWriteCondition;
pub use mkit_core::refs::{validate_ref_name, validate_ref_prefix};

use crate::error::ServerError;

/// A CAS expectation as its wire number, aligned with
/// `mkit.transport.v1.RefExpectation`. The numbers are load-bearing and match
/// `mkit.rpc.v1.ssh.RefExpectation` and `mkit.repo.v1.RefExpectation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefExpectationWire {
    /// `REF_EXPECTATION_UNSPECIFIED` (0): a protocol error.
    Unspecified = 0,
    /// `REF_EXPECTATION_ANY` (1): last writer wins.
    Any = 1,
    /// `REF_EXPECTATION_MISSING` (2): create only.
    Missing = 2,
    /// `REF_EXPECTATION_MATCH` (3): the current value must equal the expected id.
    Match = 3,
}

impl RefExpectationWire {
    /// Map a raw enum wire number. Unknown numbers collapse to
    /// [`Self::Unspecified`], which is rejected downstream.
    #[must_use]
    pub const fn from_wire(n: i32) -> Self {
        match n {
            1 => Self::Any,
            2 => Self::Missing,
            3 => Self::Match,
            _ => Self::Unspecified,
        }
    }
}

/// Why a CAS update could not commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// `MISSING`, but the ref exists.
    Exists,
    /// `MATCH`, but the ref is absent.
    Missing,
    /// `MATCH`, but the current value differs from the expected id.
    Mismatch,
}

/// The outcome of [`evaluate_cas`]. `Invalid` is a malformed request
/// (`invalid_argument`); `Conflict` is a precondition failure the client can
/// rebase and retry (`failed_precondition`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasDecision {
    /// The write may commit.
    Committed,
    /// The precondition does not hold.
    Conflict(ConflictReason),
    /// The request is malformed; the message is client-safe.
    Invalid(&'static str),
}

/// Decide a CAS write. `current` is the ref's value (`None` when absent) and
/// `expected` the `MATCH` target, which must be `None` for `ANY` and
/// `MISSING`. Ids are compared as opaque bytes.
///
/// - `ANY` always commits.
/// - `MISSING` commits only when `current` is `None`.
/// - `MATCH` commits only when `current` equals `expected`.
#[must_use]
pub fn evaluate_cas(
    current: Option<&[u8]>,
    expectation: RefExpectationWire,
    expected: Option<&[u8]>,
) -> CasDecision {
    match expectation {
        RefExpectationWire::Any => {
            if expected.is_some() {
                return CasDecision::Invalid("expected_id must be empty for ANY");
            }
            CasDecision::Committed
        }
        RefExpectationWire::Missing => {
            if expected.is_some() {
                return CasDecision::Invalid("expected_id must be empty for MISSING");
            }
            match current {
                None => CasDecision::Committed,
                Some(_) => CasDecision::Conflict(ConflictReason::Exists),
            }
        }
        RefExpectationWire::Match => {
            let Some(expected) = expected else {
                return CasDecision::Invalid("expected_id required for MATCH");
            };
            match current {
                None => CasDecision::Conflict(ConflictReason::Missing),
                Some(cur) if cur != expected => CasDecision::Conflict(ConflictReason::Mismatch),
                Some(_) => CasDecision::Committed,
            }
        }
        RefExpectationWire::Unspecified => {
            CasDecision::Invalid("expectation is UNSPECIFIED (protocol error)")
        }
    }
}

/// Convert a wire `(expectation, expected_id)` pair into a
/// [`RefWriteCondition`]. An absent `expected_id` is passed as empty.
///
/// # Errors
/// [`crate::Code::InvalidArgument`] when the expectation is unspecified or
/// unknown (SPEC-TRANSPORT-CONNECT §3), when `ANY` or `MISSING` carries a
/// non-empty `expected_id`, or when `MATCH`'s `expected_id` is not 32 bytes.
pub fn condition_from_wire(
    expectation: i32,
    expected_id: &[u8],
) -> Result<RefWriteCondition, ServerError> {
    match RefExpectationWire::from_wire(expectation) {
        RefExpectationWire::Any if expected_id.is_empty() => Ok(RefWriteCondition::Any),
        RefExpectationWire::Any => Err(ServerError::invalid_argument(
            "REF_EXPECTATION_ANY MUST carry an empty expected_id",
        )),
        RefExpectationWire::Missing if expected_id.is_empty() => Ok(RefWriteCondition::Missing),
        RefExpectationWire::Missing => Err(ServerError::invalid_argument(
            "REF_EXPECTATION_MISSING MUST carry an empty expected_id",
        )),
        RefExpectationWire::Match => Ok(RefWriteCondition::Match(hash_from_slice(expected_id)?)),
        RefExpectationWire::Unspecified => Err(ServerError::invalid_argument(
            "expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED",
        )),
    }
}

/// Parse a 32-byte digest from a wire `bytes` field.
///
/// # Errors
/// [`crate::Code::InvalidArgument`] unless `bytes` is exactly 32 bytes long.
pub fn hash_from_slice(bytes: &[u8]) -> Result<Hash, ServerError> {
    Hash::try_from(bytes).map_err(|_| {
        ServerError::invalid_argument(format!(
            "expected a 32-byte digest, got {} bytes",
            bytes.len()
        ))
    })
}

/// The name `ListRefs` returns for a stored ref: `full` with `prefix`
/// stripped when it starts with it, otherwise `full` unchanged.
///
/// `Transport::list_refs` promises that returned names have the prefix
/// stripped (SPEC-REFS §4), and every native transport honors it. The CLI's
/// fetch, pull and clone path relies on it to derive each branch's packmap
/// ref (`refs/mkit/packmap/<bare-branch>`) from the listed name. Returning
/// the full path there breaks that lookup (`packmap_ref("refs/heads/main")`
/// is not `refs/mkit/packmap/main`), which surfaces as "no pack map to
/// reconstruct it" on `mkit clone`, not as an auth or wire error.
#[must_use]
pub fn strip_listed_prefix<'a>(full: &'a str, prefix: &str) -> &'a str {
    full.strip_prefix(prefix).unwrap_or(full)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Code;

    const ID_A: &[u8] = &[0xaa; 32];
    const ID_B: &[u8] = &[0xbb; 32];

    // Ported from apps/vcs-worker/src/refs.rs `any_clobbers`.
    #[test]
    fn any_clobbers() {
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectationWire::Any, None),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(None, RefExpectationWire::Any, None),
            CasDecision::Committed
        );
        assert!(matches!(
            evaluate_cas(Some(ID_A), RefExpectationWire::Any, Some(ID_A)),
            CasDecision::Invalid(_)
        ));
    }

    // Ported from apps/vcs-worker/src/refs.rs `missing_create_only`.
    #[test]
    fn missing_create_only() {
        assert_eq!(
            evaluate_cas(None, RefExpectationWire::Missing, None),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectationWire::Missing, None),
            CasDecision::Conflict(ConflictReason::Exists)
        );
        assert!(matches!(
            evaluate_cas(None, RefExpectationWire::Missing, Some(ID_A)),
            CasDecision::Invalid(_)
        ));
    }

    // Ported from apps/vcs-worker/src/refs.rs `match_cas`.
    #[test]
    fn match_cas() {
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectationWire::Match, Some(ID_A)),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(Some(ID_B), RefExpectationWire::Match, Some(ID_A)),
            CasDecision::Conflict(ConflictReason::Mismatch)
        );
        assert_eq!(
            evaluate_cas(None, RefExpectationWire::Match, Some(ID_A)),
            CasDecision::Conflict(ConflictReason::Missing)
        );
        assert!(matches!(
            evaluate_cas(Some(ID_A), RefExpectationWire::Match, None),
            CasDecision::Invalid(_)
        ));
    }

    // Ported from apps/vcs-worker/src/refs.rs `unspecified_is_protocol_error`.
    #[test]
    fn unspecified_is_protocol_error() {
        assert!(matches!(
            evaluate_cas(None, RefExpectationWire::Unspecified, None),
            CasDecision::Invalid(_)
        ));
    }

    // Ported from apps/vcs-worker/src/refs.rs `from_wire_numbers_match_proto`.
    #[test]
    fn from_wire_numbers_match_proto() {
        assert_eq!(RefExpectationWire::from_wire(1), RefExpectationWire::Any);
        assert_eq!(
            RefExpectationWire::from_wire(2),
            RefExpectationWire::Missing
        );
        assert_eq!(RefExpectationWire::from_wire(3), RefExpectationWire::Match);
        assert_eq!(
            RefExpectationWire::from_wire(0),
            RefExpectationWire::Unspecified
        );
        assert_eq!(
            RefExpectationWire::from_wire(99),
            RefExpectationWire::Unspecified
        );
    }

    // Ported from apps/vcs-worker/src/refs.rs `digest_length` (`is_valid_digest`),
    // with the message of mkit-transport-connect/src/hashutil.rs.
    #[test]
    fn digest_length() {
        assert_eq!(hash_from_slice(&[7; 32]).unwrap(), [7; 32]);
        for len in [0, 31, 33] {
            let err = hash_from_slice(&vec![0; len]).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(
                err.public_message(),
                format!("expected a 32-byte digest, got {len} bytes")
            );
        }
    }

    fn rejected(expectation: i32, expected_id: &[u8]) -> String {
        let err = condition_from_wire(expectation, expected_id).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        err.public_message().to_owned()
    }

    // Messages from mkit-transport-connect/src/refs_convert.rs.
    #[test]
    fn condition_from_wire_unspecified_and_unknown() {
        for expectation in [0, 99, -1] {
            assert_eq!(
                rejected(expectation, &[]),
                "expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED"
            );
        }
    }

    #[test]
    fn condition_from_wire_any_or_missing_with_an_id() {
        assert_eq!(
            rejected(1, ID_A),
            "REF_EXPECTATION_ANY MUST carry an empty expected_id"
        );
        assert_eq!(
            rejected(2, ID_A),
            "REF_EXPECTATION_MISSING MUST carry an empty expected_id"
        );
    }

    #[test]
    fn condition_from_wire_match_needs_32_bytes() {
        assert_eq!(
            rejected(3, &[0; 31]),
            "expected a 32-byte digest, got 31 bytes"
        );
        assert_eq!(rejected(3, &[]), "expected a 32-byte digest, got 0 bytes");
    }

    #[test]
    fn condition_from_wire_ok() {
        assert_eq!(condition_from_wire(1, &[]).unwrap(), RefWriteCondition::Any);
        assert_eq!(
            condition_from_wire(2, &[]).unwrap(),
            RefWriteCondition::Missing
        );
        assert_eq!(
            condition_from_wire(3, ID_B).unwrap(),
            RefWriteCondition::Match([0xbb; 32])
        );
    }

    #[test]
    fn strip_listed_prefix_strips_only_a_matching_prefix() {
        assert_eq!(
            strip_listed_prefix("refs/heads/main", "refs/heads/"),
            "main"
        );
        assert_eq!(
            strip_listed_prefix("refs/heads/main", ""),
            "refs/heads/main"
        );
        assert_eq!(
            strip_listed_prefix("refs/tags/v1", "refs/heads/"),
            "refs/tags/v1"
        );
        assert_eq!(
            strip_listed_prefix("refs/heads/main", "refs/heads/main"),
            ""
        );
    }

    #[test]
    fn ref_name_validation_is_mkit_core() {
        assert!(validate_ref_name("refs/heads/main"));
        assert!(!validate_ref_name("refs/heads/../main"));
        assert!(validate_ref_prefix(""));
        assert!(validate_ref_prefix("refs/heads/"));
        assert!(!validate_ref_prefix("/"));
    }
}
