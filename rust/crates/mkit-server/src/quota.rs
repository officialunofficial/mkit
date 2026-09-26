//! Write quotas: the value types, the default limits and the fixed-window
//! evaluation.
//!
//! [`evaluate_quota`] is the canonical copy of
//! `apps/vcs-worker/src/write_quota.rs`, which goes when `vcs-worker`
//! switches in WP-M0-17. `apps/repo-worker` keeps its own copy (planner
//! decision Q11).

use mkit_core::hash::to_hex;

use crate::repo::NamespaceKey;

/// Limits for one fixed quota window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaLimits {
    /// Window length in milliseconds.
    pub window_ms: i64,
    /// Most write operations allowed per window.
    pub max_ops: u32,
    /// Most bytes allowed per window.
    pub max_bytes: u64,
}

/// Usage recorded in the current window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaState {
    /// Window start, Unix epoch milliseconds.
    pub window_start: i64,
    /// Operations counted so far.
    pub ops: u32,
    /// Bytes counted so far.
    pub bytes: u64,
}

/// The key a quota is counted under. In M0 that is one signer within one
/// namespace (planner default Q14); the per-namespace aggregate lands in M1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuotaScope(String);

impl QuotaScope {
    /// The scope for `signer` in `ns`: `"<namespace>\n<signer hex>"`.
    #[must_use]
    pub fn for_signer(ns: &NamespaceKey, signer: &[u8; 32]) -> Self {
        Self(format!("{}\n{}", ns.as_str(), to_hex(signer)))
    }

    /// The scope key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One charge an Admission decision asks the write's batch to apply: one
/// operation and `bytes` against `scope`'s current window under `limits`.
/// The planner evaluates it with [`evaluate_quota`] on the value it read
/// and guards that read, so the charge is exact within one partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaCharge {
    /// The counter charged.
    pub scope: QuotaScope,
    /// Bytes charged: 0 for ref writes, the declared size for `UploadPack`.
    pub bytes: u64,
    /// The window and caps.
    pub limits: QuotaLimits,
}

/// Today's per-signer write quota (planner decision Q14): 300 writes and
/// 128 MiB of `UploadPack` bytes per one-hour window.
pub const DEFAULT_WRITE_QUOTA: QuotaLimits = QuotaLimits {
    window_ms: 3_600_000,
    max_ops: 300,
    max_bytes: 128 * 1024 * 1024,
};

/// The outcome of charging one write against a quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Under budget: persist this state in place of the old one and let the
    /// write proceed.
    Allowed(QuotaState),
    /// Over budget: reject the write with `resource_exhausted` and leave the
    /// stored state untouched.
    Exhausted {
        /// Client-safe reason.
        reason: &'static str,
    },
}

/// Charge one write of `incoming_bytes` at server time `now` (Unix epoch
/// milliseconds) against `current`, the stored state (`None` for a first
/// write or a pruned row).
///
/// A window that has fully elapsed (`now - window_start >= window_ms`)
/// resets the counters before this write is applied, so a signer is never
/// charged for activity outside the current window. That permits a burst of
/// up to twice the budget across a window boundary, never more. Ops are
/// checked before bytes, so a flood of zero-byte ref writes hits the op cap
/// on its own. Ref writes charge 0 bytes; `UploadPack` charges its declared
/// `total_bytes`.
#[must_use]
pub fn evaluate_quota(
    current: Option<QuotaState>,
    now: i64,
    incoming_bytes: u64,
    limits: &QuotaLimits,
) -> QuotaDecision {
    let base = match current {
        Some(s) if now.saturating_sub(s.window_start) < limits.window_ms => s,
        _ => QuotaState {
            window_start: now,
            ops: 0,
            bytes: 0,
        },
    };
    let ops = base.ops.saturating_add(1);
    let bytes = base.bytes.saturating_add(incoming_bytes);
    if ops > limits.max_ops {
        return QuotaDecision::Exhausted {
            reason: "write op quota exceeded for this window; try again later",
        };
    }
    if bytes > limits.max_bytes {
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

    // The quota tests below are ported verbatim from
    // apps/vcs-worker/src/write_quota.rs, reading its constants from
    // DEFAULT_WRITE_QUOTA.
    const WRITE_QUOTA_WINDOW_MS: i64 = DEFAULT_WRITE_QUOTA.window_ms;
    const WRITE_QUOTA_MAX_OPS: u32 = DEFAULT_WRITE_QUOTA.max_ops;
    const WRITE_QUOTA_MAX_BYTES: u64 = DEFAULT_WRITE_QUOTA.max_bytes;

    fn evaluate(current: Option<QuotaState>, now: i64, incoming_bytes: u64) -> QuotaDecision {
        evaluate_quota(current, now, incoming_bytes, &DEFAULT_WRITE_QUOTA)
    }

    #[test]
    fn default_quota_is_todays_vcs_worker_limits() {
        assert_eq!(WRITE_QUOTA_WINDOW_MS, 60 * 60 * 1_000);
        assert_eq!(WRITE_QUOTA_MAX_OPS, 300);
        assert_eq!(WRITE_QUOTA_MAX_BYTES, 128 * 1024 * 1024);
    }

    #[test]
    fn exhausted_reasons_are_verbatim() {
        let full_ops = QuotaState {
            window_start: 0,
            ops: WRITE_QUOTA_MAX_OPS,
            bytes: 0,
        };
        assert_eq!(
            evaluate(Some(full_ops), 1, 0),
            QuotaDecision::Exhausted {
                reason: "write op quota exceeded for this window; try again later"
            }
        );
        assert_eq!(
            evaluate(None, 1, WRITE_QUOTA_MAX_BYTES + 1),
            QuotaDecision::Exhausted {
                reason: "write byte quota exceeded for this window; try again later"
            }
        );
    }

    #[test]
    fn first_write_from_a_fresh_key_is_allowed() {
        let d = evaluate(None, 10_000, 1_000);
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
        let d = evaluate(Some(state), 100, 0);
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
        let d = evaluate(Some(state), 100, 0);
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
        let d = evaluate(Some(state), 100, WRITE_QUOTA_MAX_BYTES);
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
        let d = evaluate(Some(state), 100, 1);
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
        let still_current = evaluate(Some(state), WRITE_QUOTA_WINDOW_MS - 1, 0);
        assert!(matches!(still_current, QuotaDecision::Exhausted { .. }));
        // ...but once the window has fully elapsed, a fresh window starts and
        // the SAME author is allowed again — quota state resets over time.
        let reset = evaluate(Some(state), WRITE_QUOTA_WINDOW_MS, 0);
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
            match evaluate(state, now, 0) {
                QuotaDecision::Allowed(s) => state = Some(s),
                QuotaDecision::Exhausted { .. } => panic!("should still be under the op cap"),
            }
            now += 1;
        }
        assert!(matches!(
            evaluate(state, now, 0),
            QuotaDecision::Exhausted { .. }
        ));
    }

    #[test]
    fn a_single_max_size_pack_is_allowed_but_a_second_is_not() {
        // service::MAX_PACK_BYTES is 64 MiB; WRITE_QUOTA_MAX_BYTES is 128 MiB,
        // so exactly two max-size packs fit in one window and a third does not.
        const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
        let first = evaluate(None, 0, MAX_PACK_BYTES);
        let state = match first {
            QuotaDecision::Allowed(s) => s,
            QuotaDecision::Exhausted { .. } => panic!("first max-size pack should be allowed"),
        };
        let second = evaluate(Some(state), 1, MAX_PACK_BYTES);
        assert!(matches!(second, QuotaDecision::Allowed(_)));
        let state = match second {
            QuotaDecision::Allowed(s) => s,
            QuotaDecision::Exhausted { .. } => unreachable!(),
        };
        let third = evaluate(Some(state), 2, 1);
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
        let d = evaluate(None, 0, 1);
        assert_eq!(
            d,
            QuotaDecision::Allowed(QuotaState {
                window_start: 0,
                ops: 1,
                bytes: 1
            })
        );
    }

    #[test]
    fn signer_scope_is_namespace_newline_hex() {
        let ns = NamespaceKey::deployment_default();
        let scope = QuotaScope::for_signer(&ns, &[0xab; 32]);
        assert_eq!(scope.as_str(), format!("root\n{}", "ab".repeat(32)));
        assert_ne!(scope, QuotaScope::for_signer(&ns, &[0xac; 32]));
    }
}
