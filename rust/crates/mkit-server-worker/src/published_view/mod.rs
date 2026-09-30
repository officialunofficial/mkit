//! Stage 2 published ref snapshots. Nothing is constructed by Stage 1 entrypoints.
mod codec;
mod fence;
pub use fence::fenced_reader;
#[cfg(target_arch = "wasm32")]
mod runtime;
mod timer;
pub use codec::{Envelope, cache_key, object_key};
use core::future::Future;

use mkit_server::pipeline::published::PublishedSource;
use mkit_server::{BoxFuture, MaybeSend, MaybeSync, Partition, RepoId, StoreError};
#[cfg(target_arch = "wasm32")]
pub use runtime::{WorkerCache, WorkerSnapshotBucket};
use std::sync::Arc;
pub use timer::{AlarmLimited, SnapshotAlarm, SnapshotHandler, extend_relay, state_key};

/// Hard row cap, including empty snapshots.
pub const MAX_ROWS: usize = 64;
/// Hard encoded body cap; 16 bodies retain at most 512 KiB.
pub const MAX_BYTES: usize = 32 * 1024;
/// `Cache` residence, independently checked as well as sent to the `Cache` API.
pub const CACHE_TTL_MS: u64 = 1000;
/// Finite freshness window; expiry falls back to the published index.
pub const VALIDITY_MS: u64 = 60_000;
/// Quiet public and private buckets are revisited before expiry.
pub const REFRESH_MS: u64 = 30_000;
/// Publication debounce and minimum replacement interval.
pub const DEBOUNCE_MS: u64 = 1000;
/// Dedicated private R2 binding, never a pack/backup bucket.
pub const SNAPSHOTS_BINDING: &str = "PUBLISHED_SNAPSHOTS";

/// Programmatic configuration only: no environment parser enables this feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedViewConfig {
    /// Unique deployment identity; changing deployments must change this value.
    pub deployment: String,
    /// Records inspection activation. Snapshots and fallback both use published inputs.
    pub inspection_configured: bool,
    /// Unsigned `ReadRef` opt-in; signed reads always bypass snapshots.
    pub unsigned_read_ref: bool,
}
impl PublishedViewConfig {
    /// Validate a deployment identity. All resource caps and TTLs are fixed.
    pub fn new(deployment: impl Into<String>) -> Result<Self, StoreError> {
        let deployment = deployment.into();
        if deployment.is_empty()
            || deployment.len() > 128
            || !deployment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        {
            return Err(StoreError::Invalid(
                "invalid published-view deployment identity".into(),
            ));
        }
        Ok(Self {
            deployment,
            inspection_configured: false,
            unsigned_read_ref: false,
        })
    }
}

/// Bounded `GET` result. Implementations reject oversize objects before retaining bodies.
#[derive(Debug, Clone)]
pub struct SnapshotObject {
    /// Opaque conditional replacement token.
    pub etag: String,
    /// Storage replacement time; enforces the interval even after a crash.
    pub stored_at_ms: u64,
    /// Complete bounded envelope.
    pub bytes: Vec<u8>,
}
/// Mutable snapshots need compare-and-replace, separate from immutable pack puts.
pub trait SnapshotBucket: Clone + MaybeSend + MaybeSync + 'static {
    /// One bounded lookup; oversize or failed objects return an error, without retries.
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<SnapshotObject>, StoreError>> + MaybeSend;
    /// `None` requires absence; `Some` requires the observed `ETag`. False is a conflict.
    fn replace(
        &self,
        key: &str,
        etag: Option<&str>,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend;
    /// Remove obsolete public data after observing a private repository.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}
/// Ref data only. No visibility or authorization is stored in the cache.
pub trait SnapshotCache: MaybeSend + MaybeSync {
    /// A bounded body with its insertion time, or a miss.
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<(u64, Vec<u8>)>, StoreError>> + MaybeSend;
    /// One best-effort fill, max-age=1 second.
    fn put(
        &self,
        key: &str,
        at_ms: u64,
        bytes: Vec<u8>,
    ) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}
/// The published-source adapter; only invoked after authoritative authorization.
pub struct SnapshotReader<B, C> {
    /// Dedicated private bucket.
    pub bucket: B,
    /// Internal deployment-scoped cache.
    pub cache: C,
    /// Explicit Stage 2 settings.
    pub config: PublishedViewConfig,
    /// Refresh time after storage awaits so a slow lookup cannot serve expired data.
    pub clock: Arc<dyn mkit_server::Clock>,
}
impl<B, C> core::fmt::Debug for SnapshotReader<B, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotReader")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}
impl<B, C> SnapshotReader<B, C> {
    fn now(&self, floor: u64) -> u64 {
        u64::try_from(self.clock.now_ms()).unwrap_or(0).max(floor)
    }
}
impl<B: SnapshotBucket, C: SnapshotCache> PublishedSource for SnapshotReader<B, C> {
    fn inspection_configured(&self) -> bool {
        self.config.inspection_configured
    }
    fn uses_published_values(&self) -> bool {
        true
    }
    fn read_ref_enabled(&self) -> bool {
        self.config.unsigned_read_ref
    }
    fn bucket<'a>(
        &'a self,
        repo: &'a RepoId,
        partition: &'a Partition,
        now_ms: u64,
    ) -> BoxFuture<'a, mkit_server::pipeline::published::PublishedBucket> {
        Box::pin(async move {
            let key = object_key(partition)?;
            let cache = cache_key(&self.config.deployment, partition)?;
            if let Ok(Some((at, bytes))) = self.cache.get(&cache).await
                && at <= self.now(now_ms)
                && self.now(now_ms) - at < CACHE_TTL_MS
                && let Ok(envelope) = Envelope::decode(&bytes, partition, self.now(now_ms))
            {
                return Ok(Some(envelope.rows));
            }
            if let Ok(Some(object)) = self.bucket.get(&key).await
                && let Ok(envelope) = Envelope::decode(&object.bytes, partition, self.now(now_ms))
            {
                // The third operation is either this fill or the caller's live scan.
                let _ = self.cache.put(&cache, self.now(now_ms), object.bytes).await;
                if self.now(now_ms) >= envelope.valid_until_ms {
                    return Err(StoreError::unavailable(
                        "snapshot expired during cache fill",
                    ));
                }
                return Ok(Some(envelope.rows));
            }
            let _ = repo; // Envelope identity is the entire routed partition.
            Ok(None)
        })
    }
}
/// Share a source without caching authorization.
pub fn shared_reader<B: SnapshotBucket, C: SnapshotCache + 'static>(
    bucket: B,
    cache: C,
    config: PublishedViewConfig,
    clock: Arc<dyn mkit_server::Clock>,
) -> Arc<dyn PublishedSource> {
    Arc::new(SnapshotReader {
        bucket,
        cache,
        config,
        clock,
    })
}
#[cfg(test)]
mod tests;
