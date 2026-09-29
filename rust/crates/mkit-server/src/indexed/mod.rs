//! Indexed ingestion shared by native inline verification and future Worker
//! scheduling. The verified object list is the extraction seam for WP-4.10.

pub mod classify;
pub mod entries;
pub mod resolve;
pub mod state;
pub mod verify;

#[cfg(all(test, feature = "memory"))]
mod tests;

use crate::{ErrorDetail, ServerError};

/// The canonical pending response: one protobuf detail, HTTP 503 and
/// `Retry-After` rounded up to whole seconds.
pub fn pending(retry_after_ms: u64) -> ServerError {
    let retry_after_ms = retry_after_ms.max(1_000);
    let mut value = vec![0x08];
    let mut n = retry_after_ms;
    while n >= 0x80 {
        value.push((n as u8 & 0x7f) | 0x80);
        n >>= 7;
    }
    value.push(n as u8);
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
}

impl Default for IndexedConfig {
    fn default() -> Self {
        Self {
            max_delta_chain_depth: 50,
            relay_lag_bound_ms: crate::relay::RELAY_LAG_BOUND_MS,
            max_pack_bytes: 2 << 30,
            decode_budget: 2 << 30,
        }
    }
}
