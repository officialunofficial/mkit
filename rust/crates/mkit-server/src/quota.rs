//! Write quotas: the value types, the default limits and the fixed-window
//! evaluation.
//!
//! [`evaluate_quota`] is the canonical copy of vcs-worker's former
//! `write_quota.rs` (removed when vcs-worker moved onto this crate in
//! WP-M0-17). `apps/repo-worker` keeps its own copy (planner decision Q11).

use mkit_core::hash::to_hex;

use crate::error::ServerError;
use crate::repo::NamespaceKey;
use crate::store::{Key, Precondition, Value, Write, codec, keys};
use crate::timers::registry::kinds;

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
/// namespace (planner default Q14). Namespace totals use separate `qs`/`qt`
/// rows and leave this per-signer scope unchanged.
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

/// How often an active ref shard reconciles its fixed-window usage.
pub const QUOTA_ROLLUP_MS: u64 = 60_000;

// plan_namespace asserts that ticketed advances have no namespace charge.
// An admitted write may add a qs guard/put, timer, and initial view seed.
const _: () = assert!(crate::store::outbox::ADVANCE_SHARED_OPS + 4 <= crate::store::MAX_BATCH_OPS);

/// A fixed-window namespace counter. `u64` also holds sums across shards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespaceUsage {
    /// Admitted writes.
    pub ops: u64,
    /// Admitted upload bytes.
    pub bytes: u64,
}

impl NamespaceUsage {
    /// Add a nondecreasing cumulative counter's delta.
    #[must_use]
    pub fn delta_from(self, older: Self) -> Option<Self> {
        Some(Self {
            ops: self.ops.checked_sub(older.ops)?,
            bytes: self.bytes.checked_sub(older.bytes)?,
        })
    }

    /// Add two counters, failing closed on overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            ops: self.ops.checked_add(other.ops)?,
            bytes: self.bytes.checked_add(other.bytes)?,
        })
    }
}

/// A ref shard's unguarded copy of the namespace aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceView {
    /// Coordinator total at `observed_at_ms`.
    pub total: NamespaceUsage,
    /// This shard's contribution already included in `total`.
    pub pushed: NamespaceUsage,
    /// Time of the coordinator read, for stale-view metrics.
    pub observed_at_ms: u64,
}

/// One default-admission namespace charge, prepared for the write planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceCharge {
    /// The fixed window and caps.
    pub limits: QuotaLimits,
    /// Window selected by the request's one read-ahead.
    pub window: u64,
    /// Bytes from the admission charge.
    pub bytes: u64,
    /// Ref shards roll up; coordinator and Single partitions are exact.
    pub rollup: bool,
}

/// Freshness of the unguarded local view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewStatus {
    /// An aggregate was read within two rollup periods.
    Fresh,
    /// No view has been installed for this window.
    Missing,
    /// The last coordinator read is older than two periods.
    Stale,
}

/// The namespace quota's pure admission result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceDecision {
    /// Charge this exact local counter in the write batch.
    Allowed {
        /// New local cumulative usage.
        usage: NamespaceUsage,
        /// Whether the view was usable.
        view: ViewStatus,
    },
    /// Neither the write nor any quota state is allocated.
    Exhausted,
}

/// The fixed window number, with floor division at the epoch.
#[must_use]
pub fn namespace_window(now_ms: i64, window_ms: i64) -> u64 {
    let window = window_ms.max(1);
    u64::try_from(now_ms.div_euclid(window)).unwrap_or(0)
}

/// Test local exact usage first, then the most recent coordinator estimate.
/// Missing or stale views admit under the local cap and are metered by the
/// caller. A view contains this shard's last pushed count, so its estimate
/// never double-counts that contribution.
#[must_use]
pub fn evaluate_namespace(
    current: NamespaceUsage,
    view: Option<NamespaceView>,
    now_ms: i64,
    charge: NamespaceCharge,
) -> NamespaceDecision {
    let Some(usage) = current.checked_add(NamespaceUsage {
        ops: 1,
        bytes: charge.bytes,
    }) else {
        return NamespaceDecision::Exhausted;
    };
    let cap = NamespaceUsage {
        ops: u64::from(charge.limits.max_ops),
        bytes: charge.limits.max_bytes,
    };
    if usage.ops > cap.ops || usage.bytes > cap.bytes {
        return NamespaceDecision::Exhausted;
    }
    if !charge.rollup {
        return NamespaceDecision::Allowed {
            usage,
            view: ViewStatus::Fresh,
        };
    }
    let status = match view {
        None => ViewStatus::Missing,
        Some(v)
            if u64::try_from(now_ms)
                .unwrap_or(0)
                .saturating_sub(v.observed_at_ms)
                > 2 * QUOTA_ROLLUP_MS =>
        {
            ViewStatus::Stale
        }
        Some(_) => ViewStatus::Fresh,
    };
    if let (ViewStatus::Fresh, Some(view)) = (status, view) {
        let Some(other) = view.total.delta_from(view.pushed) else {
            return NamespaceDecision::Exhausted;
        };
        let Some(estimate) = other.checked_add(usage) else {
            return NamespaceDecision::Exhausted;
        };
        if estimate.ops > cap.ops || estimate.bytes > cap.bytes {
            return NamespaceDecision::Exhausted;
        }
    }
    NamespaceDecision::Allowed {
        usage,
        view: status,
    }
}

/// Decode a snapshot observation and apply the pure check. Corrupt quota
/// values fail closed like a failed quota read.
pub(crate) fn check_namespace(
    current: Option<&Value>,
    view: Option<&Value>,
    now_ms: i64,
    charge: NamespaceCharge,
) -> Result<NamespaceDecision, ServerError> {
    let current = current
        .map(codec::decode_namespace_usage)
        .transpose()
        .map_err(|e| ServerError::internal("namespace quota read failed", e.to_string()))?
        .unwrap_or_default();
    let view = if charge.rollup {
        view.map(codec::decode_namespace_view)
            .transpose()
            .map_err(|e| ServerError::internal("namespace quota read failed", e.to_string()))?
    } else {
        None
    };
    Ok(evaluate_namespace(current, view, now_ms, charge))
}

/// The key of this charge's exact local counter.
#[must_use]
pub(crate) fn counter_key(charge: NamespaceCharge, window: u64) -> Key {
    if charge.rollup {
        keys::quota_shard(window)
    } else {
        keys::quota_total(window)
    }
}

/// Append the namespace charge to the same batch as the write. The qv read
/// has no guard: timer refreshes cannot force a hot write to re-plan.
pub(crate) fn plan_namespace_charge(
    charge: NamespaceCharge,
    current: Option<&Value>,
    view: Option<&Value>,
    now_ms: i64,
    server_now_ms: u64,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(), ServerError> {
    let window = charge.window;
    let key = counter_key(charge, window);
    let decision = check_namespace(current, view, now_ms, charge)?;
    let NamespaceDecision::Allowed { usage, .. } = decision else {
        return Err(ServerError::resource_exhausted(
            "namespace write op/byte quota exceeded for this window; try again later",
        ));
    };
    pre.push(match current {
        Some(value) => Precondition::Equals(key.clone(), value.clone()),
        None => Precondition::Absent(key.clone()),
    });
    puts.push(Write::Put(key, codec::encode_namespace_usage(usage)));
    if current.is_none() {
        let window_ms = u64::try_from(charge.limits.window_ms.max(1)).unwrap_or(1);
        let due = if charge.rollup {
            server_now_ms.saturating_add(QUOTA_ROLLUP_MS)
        } else {
            window
                .saturating_add(1)
                .saturating_mul(window_ms)
                .saturating_add(mkit_core::write_auth::MAX_CLOCK_LEAD_MS.unsigned_abs())
        };
        puts.push(Write::Put(
            keys::timer(due, kinds::QUOTA_ROLLUP.get(), &window.to_be_bytes()),
            codec::encode_u64(window_ms),
        ));
    }
    Ok(())
}

/// Plan the post-admission charge. A changed window or a quota race after a
/// lease grant asks the client to retry instead of denying after allocation.
pub(crate) fn plan_namespace_after_admission(
    charge: NamespaceCharge,
    current: Option<&Value>,
    view: Option<&Value>,
    now_ms: i64,
    server_now_ms: u64,
    lease_committed: bool,
    pre: &mut Vec<Precondition>,
    puts: &mut Vec<Write>,
) -> Result<(), ServerError> {
    if namespace_window(now_ms, charge.limits.window_ms) != charge.window {
        return Err(ServerError::aborted_retryable(
            "namespace quota window advanced; retry",
        ));
    }
    plan_namespace_charge(charge, current, view, now_ms, server_now_ms, pre, puts).map_err(
        |error| {
            if lease_committed && error.code() == crate::Code::ResourceExhausted {
                ServerError::aborted_retryable("namespace quota changed; retry")
            } else {
                error
            }
        },
    )
}

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

    // The quota tests below are ported verbatim from vcs-worker's former
    // write_quota.rs, reading its constants from DEFAULT_WRITE_QUOTA.
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

    #[test]
    fn namespace_local_exhaustion_is_exact_even_without_a_view() {
        let charge = NamespaceCharge {
            limits: QuotaLimits {
                window_ms: 1_000,
                max_ops: 2,
                max_bytes: 5,
            },
            window: 0,
            bytes: 2,
            rollup: true,
        };
        let first = evaluate_namespace(NamespaceUsage::default(), None, 0, charge);
        assert_eq!(
            first,
            NamespaceDecision::Allowed {
                usage: NamespaceUsage { ops: 1, bytes: 2 },
                view: ViewStatus::Missing,
            }
        );
        let second = evaluate_namespace(NamespaceUsage { ops: 1, bytes: 2 }, None, 1, charge);
        assert!(matches!(second, NamespaceDecision::Allowed { .. }));
        assert_eq!(
            evaluate_namespace(NamespaceUsage { ops: 2, bytes: 4 }, None, 2, charge),
            NamespaceDecision::Exhausted
        );
        let too_many_bytes = NamespaceCharge { bytes: 6, ..charge };
        assert_eq!(
            evaluate_namespace(NamespaceUsage::default(), None, 0, too_many_bytes),
            NamespaceDecision::Exhausted
        );
    }

    #[test]
    fn namespace_fixed_window_rolls_over_without_reusing_the_old_counter() {
        let limits = QuotaLimits {
            window_ms: 600_000,
            max_ops: 1,
            max_bytes: 0,
        };
        let old = namespace_window(599_999, limits.window_ms);
        let new = namespace_window(600_000, limits.window_ms);
        assert_eq!((old, new), (0, 1));
        assert_ne!(keys::quota_shard(old), keys::quota_shard(new));
        let charge = NamespaceCharge {
            limits,
            window: new,
            bytes: 0,
            rollup: true,
        };
        assert!(matches!(
            evaluate_namespace(NamespaceUsage::default(), None, 600_000, charge),
            NamespaceDecision::Allowed { .. }
        ));
    }

    #[test]
    fn namespace_view_subtracts_own_pushed_count_and_expires() {
        let charge = NamespaceCharge {
            limits: QuotaLimits {
                window_ms: 1_000_000,
                max_ops: 5,
                max_bytes: 10,
            },
            window: 0,
            bytes: 0,
            rollup: true,
        };
        let local = NamespaceUsage { ops: 2, bytes: 0 };
        let view = NamespaceView {
            total: NamespaceUsage { ops: 4, bytes: 0 },
            pushed: local,
            observed_at_ms: 0,
        };
        assert!(matches!(
            evaluate_namespace(local, Some(view), 1, charge),
            NamespaceDecision::Allowed {
                usage: NamespaceUsage { ops: 3, .. },
                view: ViewStatus::Fresh
            }
        ));
        assert_eq!(
            evaluate_namespace(NamespaceUsage { ops: 3, bytes: 0 }, Some(view), 1, charge),
            NamespaceDecision::Exhausted
        );
        assert!(matches!(
            evaluate_namespace(
                NamespaceUsage { ops: 3, bytes: 0 },
                Some(view),
                (2 * QUOTA_ROLLUP_MS + 1).cast_signed(),
                charge
            ),
            NamespaceDecision::Allowed {
                view: ViewStatus::Stale,
                ..
            }
        ));
        let exact = NamespaceCharge {
            rollup: false,
            ..charge
        };
        assert_eq!(
            evaluate_namespace(NamespaceUsage { ops: 5, bytes: 0 }, None, 0, exact),
            NamespaceDecision::Exhausted
        );
    }

    #[test]
    fn simulated_overshoot_is_bounded_by_other_shards_last_three_periods() {
        const SHARDS: usize = 5;
        const CAP: u32 = 80;
        let charge = NamespaceCharge {
            limits: QuotaLimits {
                window_ms: 1_000_000,
                max_ops: CAP,
                max_bytes: 0,
            },
            window: 0,
            bytes: 0,
            rollup: true,
        };
        let mut local = [NamespaceUsage::default(); SHARDS];
        let mut views = [None; SHARDS];
        let mut writes: Vec<(u64, usize)> = Vec::new();
        for second in 0..180_u64 {
            let now = second * 1_000;
            if second > 0 && now.is_multiple_of(QUOTA_ROLLUP_MS) {
                let total = NamespaceUsage {
                    ops: writes.len() as u64,
                    bytes: 0,
                };
                for shard in 0..SHARDS {
                    views[shard] = Some(NamespaceView {
                        total,
                        pushed: local[shard],
                        observed_at_ms: now,
                    });
                }
            }
            for shard in 0..SHARDS {
                if let NamespaceDecision::Allowed { usage, .. } =
                    evaluate_namespace(local[shard], views[shard], now.cast_signed(), charge)
                {
                    local[shard] = usage;
                    writes.push((now, shard));
                    let overshoot = writes.len().saturating_sub(CAP as usize);
                    let other_recent = writes
                        .iter()
                        .filter(|(at, source)| {
                            *source != shard && now.saturating_sub(*at) <= 3 * QUOTA_ROLLUP_MS
                        })
                        .count();
                    assert!(
                        overshoot <= other_recent,
                        "t={now} shard={shard}: {overshoot} > {other_recent}"
                    );
                }
            }
        }
        assert!(
            writes.len() > CAP as usize,
            "simulation must exercise overshoot"
        );
    }

    #[test]
    fn rollup_timer_uses_server_time_even_with_business_clock_skew() {
        let business_now_ms = 180_000;
        let server_now_ms = 1_000;
        let charge = NamespaceCharge {
            limits: QuotaLimits {
                window_ms: 60_000,
                max_ops: 2,
                max_bytes: 0,
            },
            window: namespace_window(business_now_ms, 60_000),
            bytes: 0,
            rollup: true,
        };
        let (mut pre, mut writes) = (Vec::new(), Vec::new());
        plan_namespace_charge(
            charge,
            None,
            None,
            business_now_ms,
            server_now_ms,
            &mut pre,
            &mut writes,
        )
        .unwrap();
        assert!(writes.iter().any(|write| matches!(write,
            Write::Put(key, _) if matches!(keys::parse(key), Some(keys::ParsedKey::Timer { due_at_ms: 61_000, kind: 5, .. }))
        )));
    }

    #[cfg(feature = "memory")]
    #[test]
    fn single_and_coordinator_exact_paths_commit_the_total() {
        use crate::store::{Batch, BatchOutcome, NamespaceStore, Partition};
        use crate::{MemoryKv, NamespaceKey};
        use futures_executor::block_on;

        let store = MemoryKv::default();
        let charge = NamespaceCharge {
            limits: QuotaLimits {
                window_ms: 60_000,
                max_ops: 2,
                max_bytes: 4,
            },
            window: 0,
            bytes: 2,
            rollup: false,
        };
        for partition in [
            Partition::Namespace(NamespaceKey::deployment_default()),
            Partition::Coordinator(NamespaceKey::deployment_default()),
        ] {
            let key = keys::quota_total(0);
            for _ in 0..2 {
                let current = block_on(store.get(&partition, &key)).unwrap();
                let (mut pre, mut writes) = (Vec::new(), Vec::new());
                plan_namespace_charge(charge, current.as_ref(), None, 0, 0, &mut pre, &mut writes)
                    .unwrap();
                assert_eq!(
                    block_on(store.apply(
                        &partition,
                        Batch {
                            preconditions: pre,
                            writes
                        }
                    ))
                    .unwrap(),
                    BatchOutcome::Committed
                );
            }
            let current = block_on(store.get(&partition, &key)).unwrap();
            let (mut pre, mut writes) = (Vec::new(), Vec::new());
            assert_eq!(
                plan_namespace_charge(charge, current.as_ref(), None, 0, 0, &mut pre, &mut writes)
                    .unwrap_err()
                    .code(),
                crate::Code::ResourceExhausted
            );
            assert!(pre.is_empty() && writes.is_empty());
            assert_eq!(
                codec::decode_namespace_usage(current.as_ref().unwrap()).unwrap(),
                NamespaceUsage { ops: 2, bytes: 4 }
            );
            assert!(
                block_on(store.get(&partition, &keys::quota_shard(0)))
                    .unwrap()
                    .is_none()
            );
        }
    }
}
