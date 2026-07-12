// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Ref-name/pack-id validation and the CAS decision state machine for
// UpdateRef / AdvanceRefs. Adapted from apps/repo-worker/src/refs.rs: this
// service has no "room" concept (one Worker deployment = one mkit
// repository, per SPEC-TRANSPORT-CONNECT §7.1), so the room allow-list is
// dropped; everything else (ref-name grammar delegation, the pure CAS state
// machine) is unchanged.

/// Validate a ref name against the mkit SPEC-REFS §3 grammar. Delegates to
/// the canonical [`mkit_core::refs::validate_ref_name`] so the worker and the
/// core crate can never desync on the grammar.
#[must_use]
pub fn is_valid_ref_name(name: &str) -> bool {
    mkit_core::refs::validate_ref_name(name)
}

/// A ListRefs prefix is empty, or a valid ref name (optionally trailing '/').
/// Delegates to the canonical [`mkit_core::refs::validate_ref_prefix`].
#[must_use]
pub fn is_valid_ref_prefix(prefix: &str) -> bool {
    mkit_core::refs::validate_ref_prefix(prefix)
}

/// CAS expectation, proto-aligned with `mkit.transport.v1.RefExpectation`.
/// Wire numbers are load-bearing (ANY=1, MISSING=2, MATCH=3; UNSPECIFIED=0) —
/// pinned byte-for-byte against `mkit.rpc.v1.ssh.RefExpectation` /
/// `mkit.repo.v1.RefExpectation` (see transport.proto's header comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefExpectation {
    Unspecified = 0,
    Any = 1,
    Missing = 2,
    Match = 3,
}

impl RefExpectation {
    /// Map a raw proto enum wire number to the CAS expectation. Unknown
    /// numbers collapse to `Unspecified` (a protocol error downstream).
    #[must_use]
    pub fn from_wire(n: i32) -> Self {
        match n {
            1 => Self::Any,
            2 => Self::Missing,
            3 => Self::Match,
            _ => Self::Unspecified,
        }
    }
}

/// The reason a CAS update could not commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// MISSING expectation but the ref already exists.
    Exists,
    /// MATCH expectation but the ref is absent.
    Missing,
    /// MATCH expectation but the current value differs from `expected`.
    Mismatch,
}

/// Outcome of evaluating a CAS update — a pure decision. `Invalid` is a
/// malformed request (protocol error, SPEC-TRANSPORT-CONNECT §3: a
/// conforming server MUST reject `REF_EXPECTATION_UNSPECIFIED` with
/// `invalid_argument`); `Conflict` is a precondition failure the client can
/// rebase + retry (`failed_precondition`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasDecision {
    Committed,
    Conflict(ConflictReason),
    Invalid(&'static str),
}

/// Pure CAS decision. `current` is the ref's present value (None = absent);
/// `expected` is the MATCH target (must be None for ANY/MISSING). Ids are
/// compared as opaque byte slices.
///
///   ANY      -> always commit (clobber); expected MUST be empty.
///   MISSING  -> commit iff current is None (else conflict Exists); expected MUST be empty.
///   MATCH    -> commit iff current == expected (else Missing/Mismatch); expected REQUIRED.
#[must_use]
pub fn evaluate_cas(
    current: Option<&[u8]>,
    expectation: RefExpectation,
    expected: Option<&[u8]>,
) -> CasDecision {
    match expectation {
        RefExpectation::Any => {
            if expected.is_some() {
                return CasDecision::Invalid("expected_id must be empty for ANY");
            }
            CasDecision::Committed
        }
        RefExpectation::Missing => {
            if expected.is_some() {
                return CasDecision::Invalid("expected_id must be empty for MISSING");
            }
            match current {
                None => CasDecision::Committed,
                Some(_) => CasDecision::Conflict(ConflictReason::Exists),
            }
        }
        RefExpectation::Match => {
            let Some(expected) = expected else {
                return CasDecision::Invalid("expected_id required for MATCH");
            };
            match current {
                None => CasDecision::Conflict(ConflictReason::Missing),
                Some(cur) if cur != expected => CasDecision::Conflict(ConflictReason::Mismatch),
                Some(_) => CasDecision::Committed,
            }
        }
        RefExpectation::Unspecified => {
            CasDecision::Invalid("expectation is UNSPECIFIED (protocol error)")
        }
    }
}

/// A raw 32-byte BLAKE3 pack digest (proto wire form for `pack_id` /
/// `object_id` / `new_id` / `expected_id` fields carrying a MATCH target).
#[must_use]
pub fn is_valid_digest(bytes: &[u8]) -> bool {
    bytes.len() == 32
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &[u8] = &[0xaa; 32];
    const ID_B: &[u8] = &[0xbb; 32];

    #[test]
    fn any_clobbers() {
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectation::Any, None),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(None, RefExpectation::Any, None),
            CasDecision::Committed
        );
        assert!(matches!(
            evaluate_cas(Some(ID_A), RefExpectation::Any, Some(ID_A)),
            CasDecision::Invalid(_)
        ));
    }

    #[test]
    fn missing_create_only() {
        assert_eq!(
            evaluate_cas(None, RefExpectation::Missing, None),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectation::Missing, None),
            CasDecision::Conflict(ConflictReason::Exists)
        );
        assert!(matches!(
            evaluate_cas(None, RefExpectation::Missing, Some(ID_A)),
            CasDecision::Invalid(_)
        ));
    }

    #[test]
    fn match_cas() {
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectation::Match, Some(ID_A)),
            CasDecision::Committed
        );
        assert_eq!(
            evaluate_cas(Some(ID_B), RefExpectation::Match, Some(ID_A)),
            CasDecision::Conflict(ConflictReason::Mismatch)
        );
        assert_eq!(
            evaluate_cas(None, RefExpectation::Match, Some(ID_A)),
            CasDecision::Conflict(ConflictReason::Missing)
        );
        assert!(matches!(
            evaluate_cas(Some(ID_A), RefExpectation::Match, None),
            CasDecision::Invalid(_)
        ));
    }

    #[test]
    fn unspecified_is_protocol_error() {
        assert!(matches!(
            evaluate_cas(None, RefExpectation::Unspecified, None),
            CasDecision::Invalid(_)
        ));
    }

    #[test]
    fn from_wire_numbers_match_proto() {
        assert_eq!(RefExpectation::from_wire(1), RefExpectation::Any);
        assert_eq!(RefExpectation::from_wire(2), RefExpectation::Missing);
        assert_eq!(RefExpectation::from_wire(3), RefExpectation::Match);
        assert_eq!(RefExpectation::from_wire(0), RefExpectation::Unspecified);
        assert_eq!(RefExpectation::from_wire(99), RefExpectation::Unspecified);
    }

    #[test]
    fn digest_length() {
        assert!(is_valid_digest(&[0u8; 32]));
        assert!(!is_valid_digest(&[0u8; 31]));
        assert!(!is_valid_digest(&[]));
    }
}
