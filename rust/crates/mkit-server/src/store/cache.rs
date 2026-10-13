//! Optional positive caching over the storage contract.
//!
//! Cache entries are data, never authority. All current metadata families are
//! live. Only complete, hash-verified pack bytes qualify; physical presence is
//! checked again before a cached pack is returned.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt as _;
use mkit_core::upload_parts::PartPlan;

use super::*;
use crate::{Clock, MaybeSend, MaybeSync, Sleep, with_timeout};

/// Whether a present value can survive across operations in an immutable cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cacheability {
    /// Verified writes cannot change the bytes associated with this key.
    Immutable,
    /// Bytes or presence can change, carry policy, or lack an immutable proof.
    Live,
}

/// Classification of metadata reads. Unknown and future families remain live.
///
/// Even object-index rows can be replaced by supported merge imports and public
/// index planners. No existing metadata family has an unconditional proof.
#[must_use]
pub const fn cacheability(_key: &Key) -> Cacheability {
    Cacheability::Live
}

/// Classification of scan results, including their membership and continuation.
/// New index rows can appear even when existing row bytes do not change.
#[must_use]
pub const fn scan_cacheability(_start: &Key, _end: &Key) -> Cacheability {
    Cacheability::Live
}

/// Classification of blob reads. Upload-marker presence is policy; extracted
/// object keys accept caller-supplied roots rather than binding bytes to the id.
#[must_use]
pub const fn blob_cacheability(key: &BlobKey) -> Cacheability {
    match key.namespace() {
        BlobNamespace::Pack => Cacheability::Immutable,
        _ => Cacheability::Live,
    }
}

/// An embedder's byte cache. Errors and elapsed deadlines are cache misses.
///
/// Implementations MUST bound response allocation and retention, and permit
/// cancellation. A completed put may survive cancellation. Store no negative
/// entries; cache bytes never replace live authorization or presence checks.
pub trait ImmutableCache: MaybeSend + MaybeSync {
    /// Present cached bytes, or a miss.
    fn get(
        &self,
        key: &[u8],
    ) -> impl Future<Output = Result<Option<Bytes>, StoreError>> + MaybeSend;
    /// Retain present bytes under an opaque, deployment-scoped stable key.
    fn put(
        &self,
        key: Bytes,
        value: Bytes,
    ) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}

impl<C: ImmutableCache + ?Sized> ImmutableCache for Arc<C> {
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, StoreError> {
        (**self).get(key).await
    }
    async fn put(&self, key: Bytes, value: Bytes) -> Result<(), StoreError> {
        (**self).put(key, value).await
    }
}

/// Maximum bytes the wrapper buffers or accepts in one cache entry.
pub const MAX_IMMUTABLE_CACHE_ENTRY_BYTES: usize = MAX_BLOB_PIECE_BYTES;

/// Explicit deployment identity and deadline for optional cache I/O.
#[derive(Clone)]
pub struct CacheConfig {
    deployment: Bytes,
    sleep: Arc<dyn Sleep>,
    timeout: Duration,
}

impl core::fmt::Debug for CacheConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CacheConfig")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl CacheConfig {
    /// Configure a distinct deployment/storage identity. Rotate this identity
    /// after restoring or resetting authoritative storage. Each cache call has
    /// a nonzero deadline of at most 100 ms, independent of store deadlines.
    pub fn new(
        deployment: &str,
        sleep: Arc<dyn Sleep>,
        timeout: Duration,
    ) -> Result<Self, StoreError> {
        if deployment.is_empty()
            || deployment.len() > 256
            || timeout.is_zero()
            || timeout > Duration::from_millis(100)
        {
            return Err(StoreError::Invalid(
                "invalid immutable cache configuration".into(),
            ));
        }
        Ok(Self {
            deployment: Bytes::copy_from_slice(deployment.as_bytes()),
            sleep,
            timeout,
        })
    }

    fn key(&self, kind: &[u8], partition: &[u8], key: &[u8]) -> Bytes {
        let mut hash = blake3::Hasher::new();
        hash.update(b"mkit.immutable-cache.v1\0");
        for component in [self.deployment.as_ref(), kind, partition, key] {
            hash.update(&(component.len() as u64).to_be_bytes());
            hash.update(component);
        }
        Bytes::copy_from_slice(hash.finalize().as_bytes())
    }

    async fn get<C: ImmutableCache>(&self, cache: &C, key: &[u8]) -> Option<Bytes> {
        with_timeout(&self.sleep, self.timeout, cache.get(key))
            .await
            .ok()?
            .ok()?
            .filter(|bytes| bytes.len() <= MAX_IMMUTABLE_CACHE_ENTRY_BYTES)
    }

    async fn put<C: ImmutableCache>(&self, cache: &C, key: Bytes, bytes: Bytes) {
        if bytes.len() <= MAX_IMMUTABLE_CACHE_ENTRY_BYTES {
            let _ = with_timeout(&self.sleep, self.timeout, cache.put(key, bytes)).await;
        }
    }
}

/// A bounded in-memory LRU with a fixed TTL measured from insertion.
/// Clones share entries. Hits do not extend retention.
#[derive(Clone)]
pub struct MemoryImmutableCache {
    state: Arc<Mutex<MemoryState>>,
    max_bytes: usize,
    ttl: Duration,
    clock: Arc<dyn Clock>,
}

#[derive(Default)]
struct MemoryState {
    entries: BTreeMap<Bytes, (Bytes, i64)>,
    order: VecDeque<Bytes>,
    bytes: usize,
}

impl core::fmt::Debug for MemoryImmutableCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryImmutableCache")
            .field("max_bytes", &self.max_bytes)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl MemoryState {
    fn remove(&mut self, key: &[u8]) {
        if let Some((bytes, _)) = self.entries.remove(key) {
            self.bytes -= key.len() + bytes.len() + 128;
            self.order.retain(|entry| entry.as_ref() != key);
        }
    }
    fn evict_expired(&mut self, now: i64, ttl: Duration) {
        let mut removed = 0;
        self.entries.retain(|key, (bytes, inserted)| {
            let age = now
                .checked_sub(*inserted)
                .and_then(|age| u128::try_from(age).ok());
            let keep = now >= 0 && age.is_some_and(|age| age < ttl.as_millis());
            if !keep {
                removed += key.len() + bytes.len() + 128;
            }
            keep
        });
        self.bytes -= removed;
        self.order.retain(|key| self.entries.contains_key(key));
    }
}

impl MemoryImmutableCache {
    /// Bound retained key/value bytes plus 128 bytes of accounting overhead per
    /// entry. A zero capacity or TTL disables retention. Invalid clocks miss.
    #[must_use]
    pub fn new(max_bytes: usize, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryState::default())),
            max_bytes,
            ttl,
            clock,
        }
    }
}

impl MemoryImmutableCache {
    /// Remove expired copies physically. Lookup and insertion also sweep expiry;
    /// an idle host must schedule this method (or drop the backend) to satisfy
    /// a physical-retention SLA. TTL plus sweep interval must fit that SLA.
    pub fn evict_expired(&self) {
        let now = self.clock.now_ms();
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .evict_expired(now, self.ttl);
    }
}

impl ImmutableCache for MemoryImmutableCache {
    async fn get(&self, key: &[u8]) -> Result<Option<Bytes>, StoreError> {
        let now = self.clock.now_ms();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.evict_expired(now, self.ttl);
        let Some((bytes, inserted)) = state.entries.get(key) else {
            return Ok(None);
        };
        let age = now
            .checked_sub(*inserted)
            .and_then(|age| u128::try_from(age).ok());
        if now < 0 || age.is_none_or(|age| age >= self.ttl.as_millis()) {
            state.remove(key);
            return Ok(None);
        }
        let bytes = bytes.clone();
        state.order.retain(|entry| entry.as_ref() != key);
        state.order.push_back(Bytes::copy_from_slice(key));
        Ok(Some(bytes))
    }

    async fn put(&self, key: Bytes, value: Bytes) -> Result<(), StoreError> {
        let now = self.clock.now_ms();
        let Some(size) = key
            .len()
            .checked_add(value.len())
            .and_then(|n| n.checked_add(128))
        else {
            return Ok(());
        };
        if now < 0 || self.ttl.is_zero() || size > self.max_bytes {
            return Ok(());
        }
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.evict_expired(now, self.ttl);
        state.remove(&key);
        while state.bytes > self.max_bytes - size {
            let Some(oldest) = state.order.front().cloned() else {
                break;
            };
            state.remove(&oldest);
        }
        // Detach slices from potentially much larger backing allocations.
        let key = Bytes::copy_from_slice(&key);
        let value = Bytes::copy_from_slice(&value);
        state.bytes += size;
        state.order.push_back(key.clone());
        state.entries.insert(key, (value, now));
        Ok(())
    }
}

/// Metadata facade carrying an embedder's cache configuration. All current
/// metadata and scan classifications are Live, so every operation delegates
/// directly, including guarded batches and their precondition observations.
#[derive(Debug, Clone)]
pub struct CachingNamespaceStore<S, C> {
    inner: S,
    cache: C,
    config: CacheConfig,
}

impl<S, C> CachingNamespaceStore<S, C> {
    /// Opt in with the same deployment identity as the blob facade.
    #[must_use]
    pub fn new(inner: S, cache: C, config: CacheConfig) -> Self {
        Self {
            inner,
            cache,
            config,
        }
    }
    /// The authoritative store, for maintenance and adapter-specific hooks.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }
    /// The supplied cache backend.
    #[must_use]
    pub const fn cache(&self) -> &C {
        &self.cache
    }
    /// The explicit cache configuration.
    #[must_use]
    pub const fn config(&self) -> &CacheConfig {
        &self.config
    }
}

impl<S: NamespaceStore, C: ImmutableCache> NamespaceStore for CachingNamespaceStore<S, C> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn reader_admission(&self) -> bool {
        self.inner.reader_admission()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_calls(calls)
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        if cacheability(key) == Cacheability::Live {
            return self.inner.get(p, key).await;
        }
        let partition = p.encode()?;
        let cache_key = self.config.key(b"namespace", &partition, key.as_bytes());
        if let Some(bytes) = self.config.get(&self.cache, &cache_key).await
            && bytes.len() <= MAX_VALUE_BYTES
        {
            return Ok(Some(Value::new(bytes)));
        }
        let value = self.inner.get(p, key).await?;
        if let Some(value) = &value {
            self.config
                .put(&self.cache, cache_key, value.clone().into_bytes())
                .await;
        }
        Ok(value)
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.inner.has(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        // Bound optional work even for a caller with an unbounded key list.
        // Current classifications take this direct path without cache I/O.
        if !keys
            .iter()
            .take(16)
            .any(|key| cacheability(key) == Cacheability::Immutable)
        {
            return self.inner.get_many(p, keys).await;
        }
        let partition = p.encode()?;
        let mut values = vec![None; keys.len()];
        let mut missing = Vec::new();
        let mut positions = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            if index < 16 && cacheability(key) == Cacheability::Immutable {
                let cache_key = self.config.key(b"namespace", &partition, key.as_bytes());
                if let Some(bytes) = self.config.get(&self.cache, &cache_key).await
                    && bytes.len() <= MAX_VALUE_BYTES
                {
                    values[index] = Some(Value::new(bytes));
                    continue;
                }
            }
            missing.push(key.clone());
            positions.push(index);
        }
        if !missing.is_empty() {
            let fetched = self.inner.get_many(p, &missing).await?;
            if fetched.len() != missing.len() {
                return Err(StoreError::unavailable("invalid store read cardinality"));
            }
            for ((index, key), value) in positions.into_iter().zip(missing).zip(fetched) {
                if index < 16
                    && cacheability(&key) == Cacheability::Immutable
                    && let Some(value) = &value
                {
                    let cache_key = self.config.key(b"namespace", &partition, key.as_bytes());
                    self.config
                        .put(&self.cache, cache_key, value.clone().into_bytes())
                        .await;
                }
                values[index] = value;
            }
        }
        Ok(values)
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.inner.scan_many(p, ranges).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// Cache complete verified packs of at most one MiB. Ranges can use a previously
/// cached full pack; range misses and larger bodies remain ordinary store reads.
/// Every hit checks physical presence live. Writes never touch the cache.
#[derive(Debug, Clone)]
pub struct CachingBlobStore<B, C> {
    inner: B,
    cache: C,
    config: CacheConfig,
}

impl<B, C> CachingBlobStore<B, C> {
    /// Opt in for an explicit deployment/storage identity.
    #[must_use]
    pub fn new(inner: B, cache: C, config: CacheConfig) -> Self {
        Self {
            inner,
            cache,
            config,
        }
    }
    /// The authoritative blob store.
    #[must_use]
    pub const fn inner(&self) -> &B {
        &self.inner
    }
}

impl<B: BlobStore, C: ImmutableCache> BlobStore for CachingBlobStore<B, C> {
    type Sink = B::Sink;
    fn read_call_allowance(&self) -> Option<u32> {
        self.inner.read_call_allowance()
    }
    fn read_byte_allowance(&self) -> Option<u64> {
        self.inner.read_byte_allowance()
    }
    fn reserve_read_calls(&self, calls: u32) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_calls(calls)
    }
    fn reserve_read_bytes(&self, bytes: u64) -> Result<Option<ReadReservation>, StoreError> {
        self.inner.reserve_read_bytes(bytes)
    }
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        if blob_cacheability(key) == Cacheability::Live
            || range.is_some_and(|r| r.start > r.end_inclusive)
        {
            return self.inner.get(key, range).await;
        }
        let cache_key = self.config.key(b"blob:pack", b"", key.hash());
        if let Some(bytes) = self.config.get(&self.cache, &cache_key).await
            && blake3::hash(&bytes).as_bytes() == key.hash()
        {
            let present = self.inner.head(key).await?;
            let Some(meta) = present else {
                return Ok(None);
            };
            if meta.len == bytes.len() as u64 {
                let bytes = if let Some(range) = range {
                    let range = range.resolve(meta.len)?;
                    bytes.slice(range.start as usize..range.end as usize)
                } else {
                    bytes
                };
                return Ok(Some(BlobBody::Bytes(bytes)));
            }
        }
        let body = self.inner.get(key, range).await?;
        if range.is_some() {
            return Ok(body);
        }
        let bytes = match body {
            Some(BlobBody::Bytes(bytes)) if bytes.len() <= MAX_IMMUTABLE_CACHE_ENTRY_BYTES => bytes,
            Some(BlobBody::Stream { len, mut stream })
                if len <= MAX_IMMUTABLE_CACHE_ENTRY_BYTES as u64 =>
            {
                let mut bytes = Vec::with_capacity(len as usize);
                while let Some(piece) = stream.next().await {
                    let piece = piece?;
                    if piece.len() > MAX_BLOB_PIECE_BYTES
                        || bytes.len() + piece.len() > len as usize
                    {
                        return Err(StoreError::Invalid(
                            "blob stream exceeds declared length".into(),
                        ));
                    }
                    bytes.extend_from_slice(&piece);
                }
                if bytes.len() as u64 != len {
                    return Err(StoreError::Invalid("short blob stream".into()));
                }
                Bytes::from(bytes)
            }
            other => return Ok(other),
        };
        if blake3::hash(&bytes).as_bytes() == key.hash() {
            self.config.put(&self.cache, cache_key, bytes.clone()).await;
        }
        Ok(Some(BlobBody::Bytes(bytes)))
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

impl<B: MultipartBlobStore, C: ImmutableCache> MultipartBlobStore for CachingBlobStore<B, C> {
    type PartSink = B::PartSink;
    const MAX_PARTS: u32 = B::MAX_PARTS;
    fn supports_multipart(&self) -> bool {
        self.inner.supports_multipart()
    }
    fn single_put_limit(&self) -> Option<u64> {
        self.inner.single_put_limit()
    }
    async fn begin_multipart(
        &self,
        key: BlobKey,
        len: u64,
        size: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.inner.begin_multipart(key, len, size).await
    }
    async fn begin_multipart_for_ticket(
        &self,
        key: BlobKey,
        len: u64,
        size: u64,
        id: [u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        self.inner
            .begin_multipart_for_ticket(key, len, size, id)
            .await
    }
    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        cv: [u8; 32],
    ) -> Result<Self::PartSink, StoreError> {
        self.inner.begin_part(key, session, plan, index, cv).await
    }
    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        self.inner.complete(key, session, plan, parts).await
    }
    async fn complete_with_root(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
        root: mkit_core::hash::Hash,
    ) -> Result<CommitOutcome, StoreError> {
        self.inner
            .complete_with_root(key, session, plan, parts, root)
            .await
    }
    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        self.inner.abort(key, session).await
    }
}

#[cfg(test)]
#[path = "cache_tests.rs"]
mod tests;
