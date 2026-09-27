//! Source-side, at-least-once outbox delivery. Target watermarks make
//! redelivery idempotent, including a crash before source cleanup.

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
    /// Maximum queue rows delivered (default 256); up to four times as many
    /// are inspected to find work behind blocked targets.
    pub max_rows: u32,
    /// Maximum distinct targets visited (default 16).
    pub max_targets: u32,
    /// Optional maximum target store calls per target per fire. Workers use
    /// two (one watermark get and one apply); native defaults to no cap.
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
