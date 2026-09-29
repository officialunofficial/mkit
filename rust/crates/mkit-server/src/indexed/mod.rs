//! Indexed ingestion shared by native inline verification and future Worker
//! scheduling. Verification extracts large objects into the global object
//! store before a pack's `Verified` state is written (WP-4.10).

pub mod classify;
pub mod entries;
mod extract;
pub mod resolve;
pub mod state;
pub mod verify;

#[cfg(all(test, feature = "memory"))]
mod extract_tests;
#[cfg(all(test, feature = "memory"))]
mod tests;

use crate::{ErrorDetail, ServerError};

/// The canonical pending response: one protobuf detail, HTTP 503 and
/// `Retry-After` rounded up to whole seconds.
#[must_use]
pub fn pending(retry_after_ms: u64) -> ServerError {
    let retry_after_ms = retry_after_ms.max(1_000);
    let mut value = vec![0x08];
    let mut n = retry_after_ms;
    while n >= 0x80 {
        value.push(u8::try_from(n & 0x7f).unwrap_or(0) | 0x80);
        n >>= 7;
    }
    value.push(u8::try_from(n).unwrap_or(0));
    ServerError::unavailable("pack verification pending")
        .with_detail(ErrorDetail {
            type_name: "mkit.transport.v1.PendingVerification".into(),
            value: value.into(),
        })
        .with_http_status(503)
        .with_header("Retry-After", retry_after_ms.div_ceil(1_000).to_string())
}

/// Limits for opt-in indexed mode. A deployment cannot switch an existing
/// opaque repository to indexed mode: its member packs have no `i` rows.
/// Programmatic only; not exposed by adapters until Stage 2 (R-154):
/// SPEC-SERVER §12.1 requires per-ref storage leases in indexed deployments.
/// `test-faults` builds expose flags for the wire case only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IndexedConfig {
    /// Maximum total delta chain depth across in-pack and member bases.
    pub max_delta_chain_depth: u32,
    /// Repository membership lag window in milliseconds.
    pub relay_lag_bound_ms: u64,
    /// Largest accepted indexed pack.
    pub max_pack_bytes: u64,
    /// Whole-pack decoding budget; at least `max_pack_bytes`.
    pub decode_budget: u64,
    /// Least Blob size extracted into the global object store, at least 1.
    /// Never advertised (SPEC-SERVER §9.6).
    pub extract_min_bytes: u64,
    /// Most content bytes one advance may reassemble into the object store,
    /// and most member bytes it may resolve to do so. A small manifest over
    /// many member chunks amplifies into a large reassembly; exceeding this
    /// is `pack exceeds indexed decode budget`. `None` derives
    /// `4 * max_pack_bytes` when the pipeline is built; a set value must be
    /// at least `max_pack_bytes`.
    pub max_extract_bytes: Option<u64>,
    /// Most member commits one fast-forward check may read (WP-4.17), at
    /// least 1. Beyond it the check is unproven and the write is denied.
    pub max_ancestry_commits: u32,
}

impl IndexedConfig {
    /// [`Self::max_extract_bytes`], or `4 * max_pack_bytes` when unset.
    #[must_use]
    pub fn effective_max_extract_bytes(&self) -> u64 {
        self.max_extract_bytes
            .unwrap_or_else(|| self.max_pack_bytes.saturating_mul(4))
    }
}

/// The default [`IndexedConfig::max_ancestry_commits`].
pub const DEFAULT_MAX_ANCESTRY_COMMITS: u32 = 256;

/// The default [`IndexedConfig::extract_min_bytes`]: 64 KiB.
pub const DEFAULT_EXTRACT_MIN_BYTES: u64 = 64 * 1024;

impl Default for IndexedConfig {
    fn default() -> Self {
        Self {
            max_delta_chain_depth: 50,
            relay_lag_bound_ms: crate::relay::RELAY_LAG_BOUND_MS,
            max_pack_bytes: 2 << 30,
            decode_budget: 2 << 30,
            extract_min_bytes: DEFAULT_EXTRACT_MIN_BYTES,
            max_extract_bytes: None,
            max_ancestry_commits: DEFAULT_MAX_ANCESTRY_COMMITS,
        }
    }
}
