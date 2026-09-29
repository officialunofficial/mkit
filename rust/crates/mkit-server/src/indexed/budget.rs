//! Per-slice subrequest accounting and pack window reads (WP-4.8).
//!
//! A Workers alarm allows 1,000 subrequests and its clock does not advance
//! during CPU work, so a slice is bounded in fixed units: every call that
//! leaves the Durable Object (an R2 range, an index or membership shard call)
//! is charged one unit, and the slice stops before it passes its share.

use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Cursor, Key, NamespaceStore, Partition,
    RangeScan, ScanPage, StoreCapabilities, StoreError, Value,
};
use crate::{Batch, BatchOutcome, BoxFuture, MaybeSend, MaybeSync, PartitionStats};
use futures::StreamExt as _;
use mkit_core::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

/// A shared call counter with a fixed limit.
#[derive(Debug, Clone)]
pub struct SliceBudget {
    used: Arc<AtomicU32>,
    limit: u32,
}

impl SliceBudget {
    /// A budget of `limit` calls.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            used: Arc::new(AtomicU32::new(0)),
            limit,
        }
    }

    /// Calls charged so far.
    #[must_use]
    pub fn used(&self) -> u32 {
        self.used.load(Ordering::SeqCst)
    }

    /// Calls left.
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.limit.saturating_sub(self.used())
    }

    /// Charge one call, failing once the limit is spent. The failing call is
    /// not counted, so an exhausted budget stays exhausted.
    ///
    /// # Errors
    /// `StoreError::Unavailable`: a spent budget is not a CAS race.
    pub fn charge(&self) -> Result<(), StoreError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                (used < self.limit).then(|| used + 1)
            })
            .map(|_| ())
            .map_err(|_| {
                StoreError::Unavailable("verification slice subrequest budget exhausted".into())
            })
    }
}

/// Whether `error` is [`SliceBudget`] running out.
#[must_use]
pub fn is_exhausted(error: &StoreError) -> bool {
    matches!(error, StoreError::Unavailable(reason) if reason.to_string().contains("subrequest budget"))
}

/// A store whose every call is one charged unit, batched reads included (one
/// round trip however many keys), as the rollup's budgeted store charges.
#[derive(Debug)]
pub struct Budgeted<'a, S> {
    inner: &'a S,
    budget: &'a SliceBudget,
}

impl<'a, S> Budgeted<'a, S> {
    /// `inner` charging `budget`.
    #[must_use]
    pub fn new(inner: &'a S, budget: &'a SliceBudget) -> Self {
        Self { inner, budget }
    }
}

impl<S: NamespaceStore> NamespaceStore for Budgeted<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.budget.charge()?;
        self.inner.get(p, key).await
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.budget.charge()?;
        self.inner.has(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.budget.charge()?;
        self.inner.get_many(p, keys).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.budget.charge()?;
        self.inner.scan_many(p, ranges).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.budget.charge()?;
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.budget.charge()?;
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.budget.charge()?;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.budget.charge()?;
        self.inner.probe().await
    }
}

/// Blob reads use the same counter as namespace calls.
impl<B: BlobStore> BlobStore for Budgeted<'_, B> {
    type Sink = B::Sink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.budget.charge()?;
        self.inner.get(key, range).await
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.budget.charge()?;
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

/// A window read that could not be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The object no longer has the etag the job recorded: restart the job.
    EtagChanged,
    /// The pack is not in storage.
    Missing,
    /// The store failed or returned a short range.
    Unavailable,
}

/// Bytes of one range and the etag of the object they came from.
#[derive(Debug)]
pub struct Window {
    /// Exactly the bytes asked for.
    pub bytes: Vec<u8>,
    /// The object's etag.
    pub etag: String,
}

/// Range reads of a stored pack, bound to one etag (SPEC-PACKFILE §11: keeping
/// the source immutable across resumes is the caller's job).
pub trait PackWindows: MaybeSend + MaybeSync {
    /// Read `len` bytes at `offset`. With `etag`, an object that no longer has
    /// it answers [`WindowError::EtagChanged`], never other bytes.
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>>;
}

/// Windows over any [`BlobStore`]. Packs are content-addressed and immutable,
/// so the etag is the pack id; the reader binds the bytes to it as well.
#[derive(Debug)]
pub struct BlobWindows<'a, B>(pub &'a B);

impl<B: BlobStore> PackWindows for BlobWindows<'_, B> {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            let tag = mkit_core::hash::to_hex(pack);
            if etag.is_some_and(|expected| expected != tag) {
                return Err(WindowError::EtagChanged);
            }
            let end = offset
                .checked_add(len.saturating_sub(1))
                .ok_or(WindowError::Unavailable)?;
            let body = self
                .0
                .get(
                    &BlobKey::pack(*pack),
                    Some(ByteRange {
                        start: offset,
                        end_inclusive: end,
                    }),
                )
                .await
                .map_err(|_| WindowError::Unavailable)?
                .ok_or(WindowError::Missing)?;
            let mut bytes = Vec::new();
            match body {
                BlobBody::Bytes(chunk) => bytes.extend_from_slice(&chunk),
                BlobBody::Stream { mut stream, .. } => {
                    while let Some(chunk) = stream.next().await {
                        bytes.extend_from_slice(&chunk.map_err(|_| WindowError::Unavailable)?);
                        if bytes.len() as u64 > len {
                            return Err(WindowError::Unavailable);
                        }
                    }
                }
            }
            if bytes.len() as u64 != len {
                return Err(WindowError::Unavailable);
            }
            Ok(Window { bytes, etag: tag })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_counts_calls_and_stays_exhausted() {
        let budget = SliceBudget::new(2);
        assert!(budget.charge().is_ok() && budget.charge().is_ok());
        let error = budget.charge().unwrap_err();
        assert!(is_exhausted(&error));
        assert_eq!((budget.used(), budget.remaining()), (2, 0));
        assert!(budget.charge().is_err());
        assert!(!is_exhausted(&StoreError::Unavailable("x".into())));
    }
}
