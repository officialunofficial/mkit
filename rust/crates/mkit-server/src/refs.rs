//! Ref compare-and-swap and ref-name helpers (SPEC-TRANSPORT-CONNECT §3,
//! SPEC-TRANSPORT §4.2.1, SPEC-REFS §3 and §4).
//!
//! The canonical copy of logic that lived in `mkit serve`'s
//! `pack_key_from_id`/`decode_update_ref` (removed in WP-M0-13), vcs-worker's
//! former `refs.rs` (removed in WP-M0-17), and `mkit-transport-connect` 0.4's
//! `refs_convert.rs` and `hashutil.rs` (removed in WP-M0-15).
//! `apps/repo-worker` keeps its own copy (planner decision Q11).

use std::borrow::Cow;

use mkit_core::hash::Hash;
use mkit_core::refs::RefWriteCondition;
pub use mkit_core::refs::validate_ref_prefix;

use crate::error::{Code, ServerError};

/// Longest ref name, in bytes: SPEC-REFS §3's bound,
/// [`mkit_core::refs::MAX_REF_NAME_BYTES`]. It bounds every ref key
/// (`store::keys`) below `MAX_KEY_BYTES`, with room for the longest repo
/// name; `store::keys` asserts that at compile time. Clients check the
/// same bound (`mkit_rpc::MAX_REF_NAME`) before sending.
pub const MAX_REF_NAME_BYTES: usize = mkit_core::refs::MAX_REF_NAME_BYTES;

/// The public message for a ref name or `ListRefs` prefix over
/// [`MAX_REF_NAME_BYTES`]; `mkit serve` sends it as-is.
pub const REF_NAME_TOO_LONG: &str = "ref name too long";

/// The prefix of every ref name the pipeline serves: refs live under
/// `refs/` (SPEC-REFS §2: `refs/heads/`, `refs/tags/`, and mkit's own
/// `refs/mkit/packmap/`).
pub const SERVED_REFS_PREFIX: &str = "refs/";

/// The public message for a ref name outside [`SERVED_REFS_PREFIX`]
/// (SPEC-REFS §2), on every binding; `mkit serve` sends it as-is. It
/// points an operator whose repo holds such refs, written by an older
/// `mkit serve`, to the migration notes (docs/CLI.md, "Refs outside
/// `refs/`"); it names no server path.
pub const REF_NAME_OUTSIDE_REFS: &str = "ref name must start with refs/ (refs outside refs/ \
     written by older servers are no longer served; see the migration notes)";

/// Whether the pipeline serves `name`: a valid ref name
/// ([`validate_ref_name`]) under [`SERVED_REFS_PREFIX`].
///
/// SPEC-REFS §3's grammar also admits names such as `main`, and the old
/// `mkit serve` wrote them to `<root>/main` (so `packs/<hex>` could
/// overwrite a pack). SPEC-REFS §2 requires a transport server to refuse
/// them on every read and write, by name, with
/// [`REF_NAME_OUTSIDE_REFS`] (reconciliation R-86). Listing prefixes are not restricted: a prefix
/// outside `refs/` simply lists nothing.
#[must_use]
pub fn is_served_ref_name(name: &str) -> bool {
    name.starts_with(SERVED_REFS_PREFIX) && validate_ref_name(name)
}

/// Validate a ref name: the SPEC-REFS §3 grammar and at most
/// [`MAX_REF_NAME_BYTES`] bytes ([`mkit_core::refs::validate_ref_name`]).
#[must_use]
pub fn validate_ref_name(name: &str) -> bool {
    mkit_core::refs::validate_ref_name(name)
}

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
#[non_exhaustive]
pub enum ConflictReason {
    /// `MISSING`, but the ref exists.
    Exists,
    /// `MATCH`, but the ref is absent.
    Missing,
    /// `MATCH`, but the current value differs from the expected id.
    Mismatch,
}

/// The outcome of [`evaluate_cas`] or [`evaluate_condition`]. `Invalid` is a
/// malformed request (`invalid_argument`); `Conflict` is a precondition
/// failure the client can rebase and retry (`failed_precondition`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CasDecision {
    /// The write may commit.
    Committed,
    /// The precondition does not hold.
    Conflict(ConflictReason),
    /// The request is malformed; the message is client-safe.
    Invalid(&'static str),
}

/// Decide a CAS write from its wire form. `current` is the ref's value
/// (`None` when absent) and `expected` the `MATCH` target, which must be
/// `None` for `ANY` and `MISSING`. Ids are compared as opaque bytes.
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

/// Decide a CAS write from a decoded [`RefWriteCondition`], the check every
/// storage backend shares. Same rules as [`evaluate_cas`]; a decoded
/// condition is never `Invalid`.
#[must_use]
pub fn evaluate_condition(current: Option<&Hash>, condition: &RefWriteCondition) -> CasDecision {
    match (condition, current) {
        (RefWriteCondition::Missing, Some(_)) => CasDecision::Conflict(ConflictReason::Exists),
        (RefWriteCondition::Match(_), None) => CasDecision::Conflict(ConflictReason::Missing),
        (RefWriteCondition::Match(want), Some(cur)) if cur != want => {
            CasDecision::Conflict(ConflictReason::Mismatch)
        }
        (RefWriteCondition::Any | RefWriteCondition::Missing | RefWriteCondition::Match(_), _) => {
            CasDecision::Committed
        }
    }
}

/// The wire field a digest came from; the ssh wire names it in its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestField {
    /// `pack_id` of `PackExists` or `DownloadPack`.
    PackId,
    /// `new_id` of `UpdateRef` or `AdvanceRefs`.
    NewId,
    /// `expected_id` of a `MATCH` write.
    ExpectedId,
}

/// How a binding treats an `expected_id` sent with `ANY` or `MISSING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnusedExpectedId {
    /// Reject it, as SPEC-TRANSPORT-CONNECT §3 requires: the Connect servers.
    Reject,
    /// Ignore it, as SPEC-TRANSPORT §4.2.1 requires: the ssh and enc wires.
    /// The result is what an empty `expected_id` would give.
    Ignore,
}

/// A malformed ref or digest field. Every variant is
/// [`Code::InvalidArgument`]; the two message methods keep today's text for
/// each wire family, as [`crate::upload::UploadError`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefWireError {
    /// The expectation is unspecified or an unknown number.
    Unspecified,
    /// `ANY` or `MISSING` (the payload) carried a non-empty `expected_id`.
    IdNotEmpty(RefExpectationWire),
    /// A digest field that is absent (`len: None`) or not 32 bytes long.
    BadDigest {
        /// The field.
        field: DigestField,
        /// Its length, or `None` when absent.
        len: Option<usize>,
    },
}

impl RefWireError {
    /// Always [`Code::InvalidArgument`].
    #[must_use]
    pub const fn code(self) -> Code {
        Code::InvalidArgument
    }

    /// `mkit serve`'s message, verbatim. The ssh wire ignores a non-empty
    /// `expected_id` for `ANY`/`MISSING`, so `IdNotEmpty` never reaches it and
    /// borrows `vcs-worker`'s text.
    #[must_use]
    pub const fn ssh_message(self) -> &'static str {
        match self {
            Self::Unspecified => "UpdateRef.expectation is required",
            Self::IdNotEmpty(RefExpectationWire::Missing) => {
                "expected_id must be empty for MISSING"
            }
            Self::IdNotEmpty(_) => "expected_id must be empty for ANY",
            Self::BadDigest {
                field: DigestField::PackId,
                len: None,
            } => "pack_id missing",
            Self::BadDigest {
                field: DigestField::PackId,
                len: Some(_),
            } => "pack_id must be 32 bytes",
            Self::BadDigest {
                field: DigestField::NewId,
                ..
            } => "new_id must be 32 bytes",
            Self::BadDigest {
                field: DigestField::ExpectedId,
                ..
            } => "MATCH expectation requires a 32-byte expected_id",
        }
    }

    /// `mkit-transport-connect`'s message, verbatim.
    #[must_use]
    pub fn connect_message(self) -> Cow<'static, str> {
        match self {
            Self::Unspecified => "expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED".into(),
            Self::IdNotEmpty(RefExpectationWire::Missing) => {
                "REF_EXPECTATION_MISSING MUST carry an empty expected_id".into()
            }
            Self::IdNotEmpty(_) => "REF_EXPECTATION_ANY MUST carry an empty expected_id".into(),
            Self::BadDigest { len, .. } => format!(
                "expected a 32-byte digest, got {} bytes",
                len.unwrap_or_default()
            )
            .into(),
        }
    }
}

impl From<RefWireError> for ServerError {
    /// The Connect code and message.
    fn from(err: RefWireError) -> Self {
        Self::new(err.code(), err.connect_message())
    }
}

/// Convert a wire `(expectation, expected_id)` pair into a
/// [`RefWriteCondition`]. An absent `expected_id` is passed as empty.
/// `unused` says what an `expected_id` sent with `ANY` or `MISSING` means.
///
/// # Errors
/// [`RefWireError::Unspecified`] for an unspecified or unknown expectation
/// (SPEC-TRANSPORT-CONNECT §3), [`RefWireError::IdNotEmpty`] under
/// [`UnusedExpectedId::Reject`], or [`RefWireError::BadDigest`] when
/// `MATCH`'s `expected_id` is not 32 bytes.
pub fn condition_from_wire(
    expectation: i32,
    expected_id: &[u8],
    unused: UnusedExpectedId,
) -> Result<RefWriteCondition, RefWireError> {
    let expectation = RefExpectationWire::from_wire(expectation);
    let reject_id = unused == UnusedExpectedId::Reject && !expected_id.is_empty();
    match expectation {
        RefExpectationWire::Any | RefExpectationWire::Missing if reject_id => {
            Err(RefWireError::IdNotEmpty(expectation))
        }
        RefExpectationWire::Any => Ok(RefWriteCondition::Any),
        RefExpectationWire::Missing => Ok(RefWriteCondition::Missing),
        RefExpectationWire::Match => Ok(RefWriteCondition::Match(hash_from_slice(
            DigestField::ExpectedId,
            Some(expected_id),
        )?)),
        RefExpectationWire::Unspecified => Err(RefWireError::Unspecified),
    }
}

/// Parse a 32-byte digest from a wire `bytes` field (`None` when absent).
///
/// # Errors
/// [`RefWireError::BadDigest`] unless `bytes` is present and exactly 32
/// bytes long.
pub fn hash_from_slice(field: DigestField, bytes: Option<&[u8]>) -> Result<Hash, RefWireError> {
    let bytes = bytes.ok_or(RefWireError::BadDigest { field, len: None })?;
    Hash::try_from(bytes).map_err(|_| RefWireError::BadDigest {
        field,
        len: Some(bytes.len()),
    })
}

/// The scan prefix of a validated `ListRefs` prefix (SPEC-REFS §4): empty
/// for an empty prefix, otherwise the prefix with its trailing `/`s
/// replaced by exactly one. A listing covers the refs whose full name
/// starts with it, so a prefix matches only at a path-component boundary:
/// `refs/heads`, `refs/heads/` and `refs//` all scan `refs/heads/` (and
/// `refs/`), `refs/heads/ma` scans `refs/heads/ma/` and does not match
/// `refs/heads/main`, and a ref named exactly the prefix is never listed.
#[must_use]
pub fn list_scan_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

/// The name `ListRefs` returns for a stored ref `full` under `prefix`:
/// `full` with [`list_scan_prefix`]`(prefix)` stripped, or `None` when it
/// does not extend the prefix at a component boundary (SPEC-REFS §4).
///
/// `Transport::list_refs` promises that returned names have the prefix
/// stripped, and every native transport honors it. The CLI's fetch, pull
/// and clone path relies on it to derive each branch's packmap ref
/// (`refs/mkit/packmap/<bare-branch>`) from the listed name. Returning the
/// full path there breaks that lookup (`packmap_ref("refs/heads/main")` is
/// not `refs/mkit/packmap/main`), which surfaces as "no pack map to
/// reconstruct it" on `mkit clone`, not as an auth or wire error.
#[must_use]
pub fn strip_listed_prefix<'a>(full: &'a str, prefix: &str) -> Option<&'a str> {
    full.strip_prefix(list_scan_prefix(prefix).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn evaluate_condition_matches_evaluate_cas() {
        let (a, b) = ([0xaa; 32], [0xbb; 32]);
        for current in [None, Some(&a), Some(&b)] {
            for condition in [
                RefWriteCondition::Any,
                RefWriteCondition::Missing,
                RefWriteCondition::Match(a),
                RefWriteCondition::Match(b),
            ] {
                let (expectation, expected) = match &condition {
                    RefWriteCondition::Any => (RefExpectationWire::Any, None),
                    RefWriteCondition::Missing => (RefExpectationWire::Missing, None),
                    RefWriteCondition::Match(h) => (RefExpectationWire::Match, Some(&h[..])),
                };
                assert_eq!(
                    evaluate_condition(current, &condition),
                    evaluate_cas(current.map(|h| &h[..]), expectation, expected),
                    "{current:?} {condition:?}"
                );
            }
        }
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
    // with the Connect message of mkit-transport-connect/src/hashutil.rs
    // (0.4, removed in WP-M0-15).
    #[test]
    fn digest_length() {
        let new_id = |b: &[u8]| hash_from_slice(DigestField::NewId, Some(b));
        assert_eq!(new_id(&[7; 32]).unwrap(), [7; 32]);
        for len in [0, 31, 33] {
            let err = new_id(&vec![0; len]).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(
                err.connect_message(),
                format!("expected a 32-byte digest, got {len} bytes")
            );
            assert_eq!(err.ssh_message(), "new_id must be 32 bytes");
        }
    }

    // Ported from mkit-cli/src/commands/serve/tests.rs
    // `pack_key_from_id_rejects_bad_length_as_invalid_request`, asserting the
    // ssh text of `pack_key_from_id`.
    #[test]
    fn pack_key_from_id_rejects_bad_length_as_invalid_request() {
        let pack_id = |b: Option<&[u8]>| hash_from_slice(DigestField::PackId, b);
        let err = pack_id(Some(&[0; 16])).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(err.ssh_message(), "pack_id must be 32 bytes");
        assert_eq!(pack_id(None).unwrap_err().ssh_message(), "pack_id missing");
        assert_eq!(pack_id(Some(&[7; 32])).unwrap(), [7; 32]);
    }

    fn rejected(expectation: i32, expected_id: &[u8]) -> RefWireError {
        condition_from_wire(expectation, expected_id, UnusedExpectedId::Reject).unwrap_err()
    }

    // Connect messages from mkit-transport-connect/src/refs_convert.rs
    // (0.4, removed in WP-M0-15); ssh
    // messages from mkit serve's `decode_update_ref`.
    #[test]
    fn condition_from_wire_unspecified_and_unknown() {
        for expectation in [0, 99, -1] {
            let err = rejected(expectation, &[]);
            assert_eq!(err, RefWireError::Unspecified);
            assert_eq!(
                err.connect_message(),
                "expectation MUST NOT be REF_EXPECTATION_UNSPECIFIED"
            );
            assert_eq!(err.ssh_message(), "UpdateRef.expectation is required");
        }
    }

    #[test]
    fn condition_from_wire_any_or_missing_with_an_id() {
        assert_eq!(
            rejected(1, ID_A).connect_message(),
            "REF_EXPECTATION_ANY MUST carry an empty expected_id"
        );
        assert_eq!(
            rejected(2, ID_A).connect_message(),
            "REF_EXPECTATION_MISSING MUST carry an empty expected_id"
        );
        let err: ServerError = rejected(1, ID_A).into();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn condition_from_ssh_wire_ignores_an_unused_id() {
        let ssh = |e, id| condition_from_wire(e, id, UnusedExpectedId::Ignore);
        assert_eq!(ssh(1, ID_A), Ok(RefWriteCondition::Any));
        assert_eq!(ssh(2, &[1, 2, 3]), Ok(RefWriteCondition::Missing));
        assert_eq!(ssh(0, &[]), Err(RefWireError::Unspecified));
        assert_eq!(
            ssh(3, &[0; 31]).unwrap_err().ssh_message(),
            "MATCH expectation requires a 32-byte expected_id"
        );
    }

    #[test]
    fn condition_from_wire_match_needs_32_bytes() {
        assert_eq!(
            rejected(3, &[0; 31]).connect_message(),
            "expected a 32-byte digest, got 31 bytes"
        );
        assert_eq!(
            rejected(3, &[]).connect_message(),
            "expected a 32-byte digest, got 0 bytes"
        );
    }

    #[test]
    fn condition_from_wire_ok() {
        let connect = |e, id| condition_from_wire(e, id, UnusedExpectedId::Reject);
        assert_eq!(connect(1, &[]), Ok(RefWriteCondition::Any));
        assert_eq!(connect(2, &[]), Ok(RefWriteCondition::Missing));
        assert_eq!(connect(3, ID_B), Ok(RefWriteCondition::Match([0xbb; 32])));
    }

    /// SPEC-REFS §4: component-boundary matching, as `FileTransport`'s
    /// directory walk does it.
    #[test]
    fn strip_listed_prefix_matches_at_component_boundaries() {
        let strip = strip_listed_prefix;
        for p in ["refs/heads", "refs/heads/", "refs/heads//"] {
            assert_eq!(strip("refs/heads/main", p), Some("main"), "{p}");
            assert_eq!(strip("refs/heads/feat/x", p), Some("feat/x"), "{p}");
            assert_eq!(strip("refs/tags/v1", p), None, "{p}");
        }
        assert_eq!(strip("refs/heads/main", ""), Some("refs/heads/main"));
        assert_eq!(strip("refs/heads/main", "refs//"), Some("heads/main"));
        assert_eq!(strip("refs/heads/main", "refs"), Some("heads/main"));
        // A bare string prefix is no match, so names never start with `/`
        // and `feat/x` and `featx` never both strip to `x`.
        assert_eq!(strip("refs/heads/main", "refs/heads/ma"), None);
        assert_eq!(strip("refs/heads/featx", "refs/heads/feat"), None);
        assert_eq!(strip("refs/heads/feat/x", "refs/heads/feat"), Some("x"));
        // A ref named exactly the prefix is not listed.
        assert_eq!(strip("refs/heads/main", "refs/heads/main"), None);
        assert_eq!(list_scan_prefix(""), "");
        assert_eq!(list_scan_prefix("refs//"), "refs/");
        assert_eq!(list_scan_prefix("refs/heads/main"), "refs/heads/main/");
    }

    #[test]
    fn ref_name_validation_is_mkit_core() {
        assert!(validate_ref_name("refs/heads/main"));
        assert!(!validate_ref_name("refs/heads/../main"));
        let longest = format!("refs/heads/{}", "a".repeat(MAX_REF_NAME_BYTES - 11));
        assert!(validate_ref_name(&longest));
        assert!(!validate_ref_name(&format!("{longest}a")));
        assert!(validate_ref_prefix(""));
        assert!(validate_ref_prefix("refs/heads/"));
        assert!(!validate_ref_prefix("/"));
    }
}
