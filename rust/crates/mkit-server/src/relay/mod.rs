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
    /// Maximum queue rows inspected (default 256).
    pub max_rows: u32,
    /// Maximum distinct targets visited (default 16).
    pub max_targets: u32,
}
impl Default for RelayBudget {
    fn default() -> Self {
        Self {
            max_rows: 256,
            max_targets: 16,
        }
    }
}

/// Commit-time lower bound through which this source has delivered its outbox.
/// The first row is oldest because writers append in commit order. Saturates
/// at zero for a writer timestamp of zero; an empty source is current at now.
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
