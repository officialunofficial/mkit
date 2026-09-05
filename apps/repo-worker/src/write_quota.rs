// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Pure per-author write-quota arithmetic. RefStore evaluates this inside the
// transaction that reserves a signed nonce and applies mutable effects.
// Object publication reserves its budget before R2 access; retries reuse the
// reservation and never charge twice.
//
// This module owns only the pure budget arithmetic — mirroring `chat.rs`'s
// `is_rate_limited` — so it runs under `cargo test` on the host even though
// its only caller (`refstore.rs`) is wasm32-only.
//
// Unlike chat/react's plain "minimum interval since the last op" floor,
// PutObject bodies vary in size up to the 8 MiB cap, so a single timestamp
// isn't enough: the quota tracks a rolling (window, ops, bytes) triple per
// author, scoped to a room implicitly (each room's DO instance holds its own
// `write_quota` table row per author — see `refstore::ensure_write_quota_table`).

/// Width of the fixed accounting window. A window resets in full once it
/// elapses — cheaper to persist than a sliding log, at the cost of a burst at
/// the boundary (an author can write up to ~2x the per-window budget across
/// any 2x-WINDOW span, never unlimited, since each half is itself capped).
pub const WRITE_QUOTA_WINDOW_MS: i64 = 60 * 60 * 1_000; // 1 hour

/// Max `PutObject` + `UpdateRef` calls, combined, from one author in one room
/// within a window.
pub const WRITE_QUOTA_MAX_OPS: u32 = 300;

/// Max `PutObject` `bytes` payload, summed, from one author in one room
/// within a window. `UpdateRef` carries no object bytes and contributes 0.
pub const WRITE_QUOTA_MAX_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB

/// The persisted per-author quota row (mirrors the DO's `write_quota` table:
/// `refstore::read_quota_state` / `refstore::charge_quota`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaState {
    /// Epoch-ms the current window started.
    pub window_start: i64,
    /// Writes accepted so far in this window.
    pub ops: u32,
    /// `PutObject` bytes accepted so far in this window.
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
/// state is `current` (`None` = no row yet, e.g. their first write in this
/// room, or a stale row already pruned), at server time `now` (epoch-ms).
///
/// A window that has fully elapsed (`now - window_start >= WINDOW_MS`) resets
/// the counters to zero before applying this write, so a key is never
/// penalized for activity outside the current window. Ops are checked before
/// bytes so a flood of zero-byte `UpdateRef`s hits the op cap on its own
/// terms rather than silently passing because it never touches the byte
/// budget.
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
        // Many tiny writes can hit the op cap well under the byte cap.
        let mut state = None;
        let mut now = 0i64;
        for _ in 0..WRITE_QUOTA_MAX_OPS {
            match evaluate_quota(state, now, 1) {
                QuotaDecision::Allowed(s) => state = Some(s),
                QuotaDecision::Exhausted { .. } => panic!("should still be under the op cap"),
            }
            now += 1;
        }
        assert!(matches!(
            evaluate_quota(state, now, 1),
            QuotaDecision::Exhausted { .. }
        ));
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
