//! Indexed ingestion shared by native inline verification and future Worker
//! scheduling. Verification extracts large objects into the global object
//! store before a pack's `Verified` state is written (WP-4.10).

pub mod budget;
pub mod checkpoint;
pub mod classify;
pub mod entries;
mod extract;
pub mod job;
pub mod publication;
pub mod resolve;
pub mod scheduled;
pub mod state;
pub mod verify;

#[cfg(all(test, feature = "memory"))]
mod extract_tests;
#[cfg(all(test, feature = "memory"))]
mod job_tests;
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
    /// Where verification runs: inline in the advance, or in checkpointed
    /// alarm slices (WP-4.8). Programmatic only.
    pub verification: VerificationMode,
    /// Most member commits and uncached delta bases one fast-forward check
    /// may resolve (WP-4.17), from 1 to [`MAX_ANCESTRY_COMMITS_LIMIT`].
    /// Beyond it the check is unproven and
    /// the write is denied.
    pub max_ancestry_commits: u32,
}

/// Where a ticketed pack is verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum VerificationMode {
    /// In the advance, whole-pack and in memory (native).
    #[default]
    Inline,
    /// By kind-7 slices; an advance only checks their result and answers
    /// `PendingVerification` until they finish (Workers).
    Scheduled,
}

impl IndexedConfig {
    /// Scheduled verification (WP-4.8) for packs up to `max_pack_bytes`, every
    /// other limit at its default; the decode budget is raised to cover the
    /// pack cap when that is larger.
    #[must_use]
    pub fn scheduled(max_pack_bytes: u64) -> Self {
        let defaults = Self::default();
        Self {
            verification: VerificationMode::Scheduled,
            max_pack_bytes,
            decode_budget: defaults.decode_budget.max(max_pack_bytes),
            max_ancestry_commits: SCHEDULED_MAX_ANCESTRY_COMMITS,
            ..defaults
        }
    }

    /// [`Self::max_extract_bytes`], or `4 * max_pack_bytes` when unset.
    #[must_use]
    pub fn effective_max_extract_bytes(&self) -> u64 {
        self.max_extract_bytes
            .unwrap_or_else(|| self.max_pack_bytes.saturating_mul(4))
    }
}

/// The largest accepted [`IndexedConfig::max_ancestry_commits`].
pub const MAX_ANCESTRY_COMMITS_LIMIT: u32 = 65_536;

/// [`IndexedConfig::max_ancestry_commits`] under scheduled verification: a
/// Worker alarm cannot walk more (WP-4.17's Worker cap, R-171).
pub const SCHEDULED_MAX_ANCESTRY_COMMITS: u32 = 64;

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
            verification: VerificationMode::Inline,
            max_ancestry_commits: DEFAULT_MAX_ANCESTRY_COMMITS,
        }
    }
}
