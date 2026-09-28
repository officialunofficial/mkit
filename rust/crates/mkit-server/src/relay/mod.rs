//! Source-side, at-least-once outbox delivery. Target watermarks make
//! redelivery idempotent, including a crash before source cleanup.
//!
//! Each source persists one relay scan cycle in `rs`: the `os` snapshot at
//! cycle start, the last inspected sequence, and up to 32 blocked targets.
//! During an active cycle (`cursor < cycle_end`), every undelivered row with
//! `seq <= cursor` has its target in `blocked`. A completed marker
//! (`cursor == cycle_end`) is exempt: the next fire resets the cursor and
//! blocked set before scanning from the head. Target batches apply each
//! target's rows in ascending sequence. If an older row is behind the active
//! cursor, its target is blocked; if it lies ahead, ascending scanning reaches
//! it first. Thus no later row for a target is applied while an older one is
//! undelivered. The cycle end excludes new rows until the next cycle.
//! Only delivery failures block targets; reaching the target budget pauses
//! the cursor before the next target. Blocked targets are retried at each
//! cycle start. While fewer than `MAX_BLOCKED_TARGETS` distinct failing
//! targets precede it, every healthy target is eventually delivered: a fire
//! that sees a deliverable row delivers at least one, delivered rows are
//! deleted in the same guarded checkpoint, and fires without delivery back
//! off. No closed-form fire bound is claimed; the throughput regressions in
//! `tests.rs` pin fire counts for representative schedules. A mid-cycle
//! append first waits for the next cycle. This can exceed
//! `RELAY_LAG_BOUND_MS` in time; WP-1.23c's `namespace_relay_watermark`
//! must tolerate that lag.

mod deliver;
mod hook;

pub use deliver::RelayHandler;
pub use hook::{NoHook, RelayHook};

use crate::store::{NamespaceStore, Partition, StoreError, codec, keys};

/// P-15: consumers allow a 60-second relay lag window.
pub const RELAY_LAG_BOUND_MS: u64 = 60_000;

/// Source work per fire. Targets are processed sequentially.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RelayBudget {
    /// Base row budget (default 256). A fire inspects at most four times this
    /// many rows; selected targets may receive every row in that scan window.
    pub max_rows: u32,
    /// Maximum distinct targets attempted (default 16). Later targets pause
    /// the scan without joining the failed-target blocked set.
    pub max_targets: u32,
    /// Optional maximum target store calls per target per fire, clamped to
    /// at least two. Workers use two (one watermark get and one apply), and
    /// total calls per fire are bounded by this times `max_targets`; native
    /// defaults to no cap.
    pub max_target_calls: Option<u32>,
}
impl Default for RelayBudget {
    fn default() -> Self {
        Self {
            max_rows: 256,
            max_targets: 16,
            max_target_calls: None,
        }
    }
}

/// A commit-time lower bound for this source's undelivered outbox: every
/// undelivered row committed at or after the returned time (+1).
///
/// Rows are in commit order (the `os` guard), but `at_ms` is the writer's
/// plan-time reading and is **not** monotonic in seq: a writer may read its
/// clock before retrying on `os`. The first row's `at_ms` still bounds every
/// later row's commit time from below, because later rows commit after it.
/// So the value is a valid lower bound, but it can move **backwards** as
/// rows are delivered. A consumer (WP-1.23c's coordinator) keeps the running
/// maximum it has seen, which stays safe for the same reason. The bound
/// assumes the writer's clock is not ahead of the committing store's clock
/// by more than the lease margin. Saturates at zero; an empty source
/// reports `now_ms`.
pub async fn relay_watermark<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    now_ms: u64,
) -> Result<u64, StoreError> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let page = store.scan(p, &start, &end, None, 1).await?;
    match page.entries.first() {
        Some((_, value)) => Ok(codec::decode_relay(value)?.at_ms.saturating_sub(1)),
        None => Ok(now_ms),
    }
}

#[cfg(all(test, feature = "memory"))]
mod tests;
