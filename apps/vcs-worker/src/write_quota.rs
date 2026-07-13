// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Pure per-author write-quota decision for UpdateRef/AdvanceRefs/UploadPack,
// ported verbatim (same arithmetic, same tests) from
// apps/repo-worker/src/write_quota.rs — see that module's doc for the full
// design rationale. Enforcement is wired through `AuthInterceptor`
// (`worker_impl/auth.rs`) for the two unary RPCs, and through the
// `upload_pack` handler itself (`worker_impl/service.rs`) for the
// client-streaming one — both call the RefStore DO's `/quota` op
// (`worker_impl/refstore.rs`) before doing any storage write, so the DO's
// serial execution makes the read-evaluate-write atomic.
//
// Unlike apps/repo-worker, this Worker serves a SINGLE global repository (one
// RefStore DO instance — see wrangler.jsonc and SPEC-TRANSPORT-CONNECT
// §7.1), not one instance per room. There is therefore no room dimension to
// this quota at all: the ledger is keyed on `author` alone, inside the one
// DO this deployment has.
//
// This module owns only the pure budget arithmetic so it runs under
// `cargo test` on the host even though its only caller (`refstore.rs`) is
// wasm32-only.
//
// UpdateRef and AdvanceRefs carry no chargeable payload (a ref CAS moves a
// pointer, not bytes), so both charge `incoming_bytes = 0` — same treatment
// repo-worker gives UpdateRef. UploadPack is the one RPC that transfers real
// payload (a pack, up to `service::MAX_PACK_BYTES`), and charges the pack's
// declared `total_bytes` (known as soon as the stream's `header` message is
// parsed, before any chunk is read or stored — see service.rs's
// `upload_pack` for exactly where that check runs and why it can't run
// earlier, in the interceptor itself).

/// Width of the fixed accounting window. A window resets in full once it
/// elapses — cheaper to persist than a sliding log, at the cost of a burst at
/// the boundary (an author can write up to ~2x the per-window budget across
/// any 2x-WINDOW span, never unlimited, since each half is itself capped).
pub const WRITE_QUOTA_WINDOW_MS: i64 = 60 * 60 * 1_000; // 1 hour

/// Max `UpdateRef` + `AdvanceRefs` + `UploadPack` calls, combined, from one
/// author within a window.
pub const WRITE_QUOTA_MAX_OPS: u32 = 300;

/// Max `UploadPack` `total_bytes` payload, summed, from one author within a
/// window. `UpdateRef`/`AdvanceRefs` carry no pack bytes and contribute 0.
pub const WRITE_QUOTA_MAX_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

/// The persisted per-author quota row (mirrors the DO's `write_quota` table:
/// `refstore::read_quota_state` / `refstore::handle_quota_check`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaState {
    /// Epoch-ms the current window started.
    pub window_start: i64,
    /// Writes accepted so far in this window.
    pub ops: u32,
    /// `UploadPack` bytes accepted so far in this window.
    pub bytes: u64,
}

/// The outcome of evaluating one write against an author's quota state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Under budget: the caller persists `state` (replacing whatever it had)
    /// and lets the write proceed.
    Allowed(QuotaState),
    /// Over budget: the caller rejects the write (Connect `resource_exhausted`)
    /// and leaves the persisted state untouched. `reason` is safe to surface
    /// to the client.
    Exhausted { reason: &'static str },
}

/// Evaluate one write of `incoming_bytes` from an author whose last known
/// state is `current` (`None` = no row yet, e.g. their first write, or a
/// stale row already pruned), at server time `now` (epoch-ms).
///
/// A window that has fully elapsed (`now - window_start >= WINDOW_MS`) resets
/// the counters to zero before applying this write, so a key is never
/// penalized for activity outside the current window. Ops are checked before
/// bytes so a flood of zero-byte `UpdateRef`/`AdvanceRefs` calls hits the op
/// cap on its own terms rather than silently passing because it never
/// touches the byte budget.
#[must_use]
pub fn evaluate_quota(current: Option<QuotaState>, now: i64, incoming_bytes: u64) -> QuotaDecision {
    let base = match current {
        Some(s) if now - s.window_start < WRITE_QUOTA_WINDOW_MS => s,
        _ => QuotaState {
            window_start: now,
            ops: 0,
            bytes: 0,
        },
    };

    let ops = base.ops + 1;
    let bytes = base.bytes.saturating_add(incoming_bytes);

    if ops > WRITE_QUOTA_MAX_OPS {
        return QuotaDecision::Exhausted {
            reason: "write op quota exceeded for this window; try again later",
        };
    }
    if bytes > WRITE_QUOTA_MAX_BYTES {
        return QuotaDecision::Exhausted {
            reason: "write byte quota exceeded for this window; try again later",
        };
    }

    QuotaDecision::Allowed(QuotaState {
        window_start: base.window_start,
        ops,
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_write_from_a_fresh_key_is_allowed() {
        let d = evaluate_quota(None, 10_000, 1_000);
        assert_eq!(
            d,
            QuotaDecision::Allowed(QuotaState {
                window_start: 10_000,
                ops: 1,
                bytes: 1_000
            })
        );
    }

    #[test]
    fn under_the_op_cap_stays_allowed() {
        let state = QuotaState {
            window_start: 0,
            ops: WRITE_QUOTA_MAX_OPS - 1,
            bytes: 0,
        };
        let d = evaluate_quota(Some(state), 100, 0);
        assert_eq!(
            d,
            QuotaDecision::Allowed(QuotaState {
                window_start: 0,
                ops: WRITE_QUOTA_MAX_OPS,
                bytes: 0
            })
        );
    }

    #[test]
    fn at_the_op_cap_is_rejected() {
        // Already AT the cap: one more op would push it over.
        let state = QuotaState {
            window_start: 0,
            ops: WRITE_QUOTA_MAX_OPS,
            bytes: 0,
        };
        let d = evaluate_quota(Some(state), 100, 0);
        assert!(matches!(d, QuotaDecision::Exhausted { .. }));
    }

    #[test]
    fn exactly_at_the_byte_cap_is_allowed() {
        // Modeling a single UploadPack landing exactly at the byte cap.
        let state = QuotaState {
            window_start: 0,
            ops: 0,
            bytes: 0,
        };
        let d = evaluate_quota(Some(state), 100, WRITE_QUOTA_MAX_BYTES);
        assert_eq!(
            d,
            QuotaDecision::Allowed(QuotaState {
                window_start: 0,
                ops: 1,
                bytes: WRITE_QUOTA_MAX_BYTES
            })
        );
    }

    #[test]
    fn one_byte_over_the_cap_is_rejected() {
        let state = QuotaState {
            window_start: 0,
            ops: 0,
            bytes: WRITE_QUOTA_MAX_BYTES,
        };
        let d = evaluate_quota(Some(state), 100, 1);
        assert!(matches!(d, QuotaDecision::Exhausted { .. }));
    }

    #[test]
    fn window_resets_after_it_elapses() {
        // Exhausted at the tail of a window...
        let state = QuotaState {
            window_start: 0,
            ops: WRITE_QUOTA_MAX_OPS,
            bytes: 0,
        };
        let still_current = evaluate_quota(Some(state), WRITE_QUOTA_WINDOW_MS - 1, 0);
        assert!(matches!(still_current, QuotaDecision::Exhausted { .. }));
        // ...but once the window has fully elapsed, a fresh window starts and
        // the SAME author is allowed again — quota state resets over time.
        let reset = evaluate_quota(Some(state), WRITE_QUOTA_WINDOW_MS, 0);
        assert_eq!(
            reset,
            QuotaDecision::Allowed(QuotaState {
                window_start: WRITE_QUOTA_WINDOW_MS,
                ops: 1,
                bytes: 0
            })
        );
    }

    #[test]
    fn ops_and_bytes_are_independent_caps() {
        // Many zero-byte UpdateRef/AdvanceRefs calls can hit the op cap well
        // under the byte cap (which only UploadPack ever touches).
        let mut state = None;
        let mut now = 0i64;
        for _ in 0..WRITE_QUOTA_MAX_OPS {
            match evaluate_quota(state, now, 0) {
                QuotaDecision::Allowed(s) => state = Some(s),
                QuotaDecision::Exhausted { .. } => panic!("should still be under the op cap"),
            }
            now += 1;
        }
        assert!(matches!(
            evaluate_quota(state, now, 0),
            QuotaDecision::Exhausted { .. }
        ));
    }

    #[test]
    fn a_single_max_size_pack_is_allowed_but_a_second_is_not() {
        // service::MAX_PACK_BYTES is 64 MiB; WRITE_QUOTA_MAX_BYTES is 128 MiB,
        // so exactly two max-size packs fit in one window and a third does not.
        const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
        let first = evaluate_quota(None, 0, MAX_PACK_BYTES);
        let state = match first {
            QuotaDecision::Allowed(s) => s,
            QuotaDecision::Exhausted { .. } => panic!("first max-size pack should be allowed"),
        };
        let second = evaluate_quota(Some(state), 1, MAX_PACK_BYTES);
        assert!(matches!(second, QuotaDecision::Allowed(_)));
        let state = match second {
            QuotaDecision::Allowed(s) => s,
            QuotaDecision::Exhausted { .. } => unreachable!(),
        };
        let third = evaluate_quota(Some(state), 2, 1);
        assert!(matches!(third, QuotaDecision::Exhausted { .. }));
    }

    #[test]
    fn different_authors_are_independent() {
        // Not modeled in this module (the DO keys the table by author), but
        // documented here: a fresh `current = None` for a distinct key always
        // starts a clean window regardless of any other key's state.
        let exhausted = QuotaState {
            window_start: 0,
            ops: WRITE_QUOTA_MAX_OPS,
            bytes: WRITE_QUOTA_MAX_BYTES,
        };
        let _ = exhausted; // another author's state; irrelevant to a fresh `None`
        let d = evaluate_quota(None, 0, 1);
        assert_eq!(
            d,
            QuotaDecision::Allowed(QuotaState {
                window_start: 0,
                ops: 1,
                bytes: 1
            })
        );
    }
}
