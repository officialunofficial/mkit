// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Worker-specific ref helpers: the `room` allow-list plus thin wrappers over
// the canonical SPEC-REFS §3 validators in `mkit_core::refs`, and the CAS state
// machine for UpdateRef. The CAS unit tests below are the conformance suite
// for this state machine.

/// Validate a ref name against the mkit SPEC-REFS §3 grammar. Delegates to the
/// canonical [`mkit_core::refs::validate_ref_name`] so the worker and the core
/// crate can never desync on the grammar.
#[must_use]
pub fn is_valid_ref_name(name: &str) -> bool {
    mkit_core::refs::validate_ref_name(name)
}

/// Validate a `room` identifier. Strict: 1..=64 chars from `[A-Za-z0-9._-]`,
/// no slashes, non-empty. The room is used unescaped as an R2 key prefix and
/// as a DO instance name, so a tight allow-list keeps both namespaces clean.
#[must_use]
pub fn is_valid_room(room: &str) -> bool {
    if room.is_empty() || room.len() > 64 {
        return false;
    }
    room.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// A ListRefs prefix is empty, or a valid ref name (optionally trailing '/').
/// Delegates to the canonical [`mkit_core::refs::validate_ref_prefix`].
#[must_use]
pub fn is_valid_ref_prefix(prefix: &str) -> bool {
    mkit_core::refs::validate_ref_prefix(prefix)
}

/// Validate the length of an `UpdateRef` CAS `expected_id`. Empty is valid —
/// ANY/MISSING expectations carry no `expected_id` (see [`evaluate_cas`]
/// below) — but a non-empty value must be exactly 32 bytes (a BLAKE3 object
/// id). Enforced at the RPC boundary in `worker_impl::service::update_ref`,
/// mirroring [`is_valid_room`] / [`is_valid_ref_name`] above, so a malformed
/// length is rejected with `invalid_argument` before it ever reaches
/// [`evaluate_cas`], where comparing mismatched-length byte slices can never
/// be equal and would otherwise silently resolve to `Conflict(Mismatch)`.
#[must_use]
pub fn is_valid_expected_id_len(expected_id: &[u8]) -> bool {
    expected_id.is_empty() || expected_id.len() == 32
}

/// The smallest string strictly greater than every string having `prefix` as
/// a prefix — the exclusive upper bound of a `ListRefs` prefix range scan
/// (`refstore::list_refs`). Clone the bytes, drop trailing `0xFF`, and
/// increment the last remaining byte. Returns `None` when `prefix` is empty
/// or all-`0xFF` (no finite successor), or when the increment would break
/// UTF-8 — callers then fall back to a lower-bound-only scan (still correct,
/// just not upper-bounded).
///
/// Pure string logic with no `worker`/DO dependency, so — like the rest of
/// this module — it lives here rather than in `worker_impl::refstore` (which
/// is `#[cfg(target_arch = "wasm32")]`-gated wholesale and so can't run its
/// own `#[cfg(test)]`s under plain `cargo test`).
#[must_use]
pub fn prefix_successor(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(&last) = bytes.last() {
        if last == 0xFF {
            bytes.pop();
        } else {
            let n = bytes.len();
            bytes[n - 1] = last + 1;
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

/// The lower bound of a `ListRefs` prefix range scan, given an optional
/// keyset cursor. Returns `(bound, strict)`:
///   - `start_after` empty (first page) -> `(prefix, false)`, i.e. `path >= prefix`.
///   - `start_after` non-empty (a later page) -> `(start_after, true)`, i.e.
///     `path > start_after` — strict, so the cursor row itself isn't repeated.
///
/// Rejects a `start_after` that doesn't extend `prefix`: a cross-prefix
/// cursor would let a caller page outside the range its `prefix` claims to
/// scope, silently returning refs the caller didn't ask to see.
pub fn list_refs_lower_bound(
    prefix: &str,
    start_after: &str,
) -> Result<(String, bool), &'static str> {
    if start_after.is_empty() {
        return Ok((prefix.to_string(), false));
    }
    if !start_after.starts_with(prefix) {
        return Err("start_after must start with prefix");
    }
    Ok((start_after.to_string(), true))
}

/// Resolves a `ListRefs` wire `page_size` into either `None` — the
/// pre-pagination "legacy" unbounded scan (`page_size == 0`: no LIMIT,
/// `next_cursor` always empty) — or `Some(cap)`, the effective page cap
/// clamped to `[1, 1000]` (`refstore::list_refs` then queries `cap + 1` rows
/// to detect a following page without a second round-trip).
///
/// Pure so it's directly unit-testable: `worker_impl::refstore` is
/// `#[cfg(target_arch = "wasm32")]`-gated wholesale (like the rest of this
/// module's callers — see the doc comment above) and so can't run its own
/// `#[cfg(test)]`s under plain `cargo test`.
#[must_use]
pub fn resolve_page_cap(page_size: u32) -> Option<u32> {
    if page_size == 0 {
        None
    } else {
        Some(page_size.clamp(1, 1000))
    }
}

/// CAS expectation, proto-aligned with `mkit.repo.v1.RefExpectation`.
/// Wire numbers are load-bearing (ANY=1, MISSING=2, MATCH=3; UNSPECIFIED=0).
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

/// Outcome of evaluating a CAS update — a pure decision, mirroring the TS
/// `CasDecision`. `Invalid` is a malformed request (protocol error);
/// `Conflict` is a precondition failure the client can rebase + retry.
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

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &[u8] = &[0xaa; 32];
    const ID_B: &[u8] = &[0xbb; 32];

    // --- evaluate_cas conformance vectors ------------------------------------
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

    // Ref-name / prefix grammar is validated by the canonical
    // `mkit_core::refs` conformance tests; the worker only re-exports them.

    #[test]
    fn room_rules() {
        for r in ["demo", "room-1", "a.b_c", "A1", &"x".repeat(64)] {
            assert!(is_valid_room(r), "should accept {r:?}");
        }
        for r in [
            "",
            "a/b",
            "a b",
            "a\\b",
            "a@b",
            &"x".repeat(65),
            "refs/heads",
        ] {
            assert!(!is_valid_room(r), "should reject {r:?}");
        }
    }

    #[test]
    fn from_wire_numbers_match_proto() {
        assert_eq!(RefExpectation::from_wire(1), RefExpectation::Any);
        assert_eq!(RefExpectation::from_wire(2), RefExpectation::Missing);
        assert_eq!(RefExpectation::from_wire(3), RefExpectation::Match);
        assert_eq!(RefExpectation::from_wire(0), RefExpectation::Unspecified);
        assert_eq!(RefExpectation::from_wire(99), RefExpectation::Unspecified);
    }

    // --- is_valid_expected_id_len (issue #682) -------------------------
    //
    // Regression for the `update_ref` RPC-boundary guard: a MATCH request
    // with a non-empty, wrong-length `expected_id` must be caught here
    // (service.rs returns `invalid_argument`) instead of falling through to
    // `evaluate_cas`, where comparing mismatched-length byte slices can
    // never be equal and would deterministically — but misleadingly —
    // resolve to `Conflict(Mismatch)`.
    #[test]
    fn expected_id_len_rejects_non_empty_wrong_lengths() {
        for len in [1, 16, 31, 33, 64] {
            assert!(
                !is_valid_expected_id_len(&vec![0xaa; len]),
                "length {len} must be rejected"
            );
        }
    }

    #[test]
    fn expected_id_len_accepts_empty_for_any_missing() {
        assert!(is_valid_expected_id_len(&[]));
    }

    #[test]
    fn expected_id_len_accepts_32_bytes_for_match() {
        assert!(is_valid_expected_id_len(ID_A));
    }

    // Confirms the exact failure mode this guard prevents: without the
    // length check, a malformed `expected_id` reaches `evaluate_cas` and
    // resolves to a misleading `Conflict(Mismatch)` rather than a protocol
    // error, because mismatched-length slices are never `==`.
    #[test]
    fn without_the_guard_evaluate_cas_would_mask_the_malformed_request() {
        let malformed_expected: &[u8] = &[0xaa; 16]; // not 32 bytes
        assert!(!is_valid_expected_id_len(malformed_expected));
        assert_eq!(
            evaluate_cas(Some(ID_A), RefExpectation::Match, Some(malformed_expected)),
            CasDecision::Conflict(ConflictReason::Mismatch)
        );
    }

    // --- prefix_successor vectors (ListRefs pagination upper bound) --------

    #[test]
    fn prefix_successor_increments_last_byte() {
        assert_eq!(
            prefix_successor("refs/heads/").as_deref(),
            Some("refs/heads0")
        );
        assert_eq!(prefix_successor("a").as_deref(), Some("b"));
    }

    #[test]
    fn prefix_successor_has_no_finite_bound_for_empty_prefix() {
        assert_eq!(prefix_successor(""), None);
    }

    // --- list_refs_lower_bound conformance vectors (ListRefs pagination) ---

    #[test]
    fn empty_start_after_uses_prefix_inclusive() {
        assert_eq!(
            list_refs_lower_bound("refs/heads/", ""),
            Ok(("refs/heads/".to_string(), false))
        );
        assert_eq!(list_refs_lower_bound("", ""), Ok((String::new(), false)));
    }

    #[test]
    fn start_after_extending_prefix_is_strict() {
        assert_eq!(
            list_refs_lower_bound("refs/heads/", "refs/heads/main"),
            Ok(("refs/heads/main".to_string(), true))
        );
        // An empty prefix is extended by anything.
        assert_eq!(
            list_refs_lower_bound("", "refs/heads/main"),
            Ok(("refs/heads/main".to_string(), true))
        );
        // Equal to the prefix itself still counts as "extending" it.
        assert_eq!(
            list_refs_lower_bound("refs/heads/", "refs/heads/"),
            Ok(("refs/heads/".to_string(), true))
        );
    }

    #[test]
    fn start_after_outside_prefix_is_rejected() {
        assert!(list_refs_lower_bound("refs/heads/", "refs/tags/v1").is_err());
        assert!(list_refs_lower_bound("refs/heads/", "other").is_err());
        // Shorter than the prefix, so it can't start with it either.
        assert!(list_refs_lower_bound("refs/heads/", "refs/").is_err());
    }

    // An empty prefix (list every ref in the room, no filter) still produces a
    // correct half-open range: no upper bound (`prefix_successor("")` is
    // `None`) and an inclusive lower bound of the empty string, which every
    // ref name is `>=` (SQLite TEXT ordering).
    #[test]
    fn empty_prefix_has_no_upper_bound_and_an_inclusive_empty_lower_bound() {
        assert_eq!(prefix_successor(""), None);
        assert_eq!(list_refs_lower_bound("", ""), Ok((String::new(), false)));
    }

    // A cursor round-trip: `start_after` set to the LAST name returned by the
    // previous page must exclude that row from the next page (strict `>`), not
    // re-include it — otherwise a client walking pages sees the boundary ref
    // twice.
    #[test]
    fn start_after_equal_to_previous_pages_last_row_excludes_it() {
        let last_row_of_page_one = "refs/heads/m";
        assert_eq!(
            list_refs_lower_bound("refs/heads/", last_row_of_page_one),
            Ok((last_row_of_page_one.to_string(), true))
        );
        // Same, with no prefix filter (the unfiltered "all refs" listing).
        assert_eq!(
            list_refs_lower_bound("", last_row_of_page_one),
            Ok((last_row_of_page_one.to_string(), true))
        );
    }

    // --- resolve_page_cap vectors (ListRefs page_size resolution) ----------

    #[test]
    fn page_size_zero_is_the_legacy_unbounded_scan() {
        assert_eq!(resolve_page_cap(0), None);
    }

    #[test]
    fn page_size_within_range_passes_through_unclamped() {
        assert_eq!(resolve_page_cap(1), Some(1));
        assert_eq!(resolve_page_cap(200), Some(200));
        assert_eq!(resolve_page_cap(1000), Some(1000));
    }

    #[test]
    fn page_size_above_the_cap_is_clamped_to_1000() {
        assert_eq!(resolve_page_cap(1001), Some(1000));
        assert_eq!(resolve_page_cap(u32::MAX), Some(1000));
    }
}
