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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub use crate::budget::{SliceBudget, is_exhausted};

/// Encoded pack-range bytes reserved by one object-reader session.
#[derive(Debug)]
pub(crate) struct EncodedBudget {
    limit: u64,
    pub(crate) used: AtomicU64,
}

#[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
impl EncodedBudget {
    pub(crate) fn new(limit: u64) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
        }
    }

    pub(crate) fn charge(&self, bytes: u64) -> Result<(), StoreError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map(|_| ())
            .map_err(|_| StoreError::unavailable("object reader encoded budget exhausted"))
    }
}

/// A store whose every call is one charged unit, batched reads included (one
/// round trip however many keys), as the rollup's budgeted store charges.
///
/// Object readers additionally compose a second (session) budget, an encoded
/// byte budget for ranged blob reads, and a flag recording that a cap was hit
/// before lower layers redact the error.
#[derive(Debug)]
pub struct Budgeted<'a, S> {
    inner: &'a S,
    budget: Option<&'a SliceBudget>,
    session: Option<&'a SliceBudget>,
    encoded: Option<&'a EncodedBudget>,
    hit: Option<&'a AtomicBool>,
    io: Option<&'a crate::store::read_io::ReadIo>,
    credits: crate::store::ReadCredits,
}

impl<'a, S> Budgeted<'a, S> {
    /// `inner` charging `budget`.
    #[must_use]
    pub fn new(inner: &'a S, budget: &'a SliceBudget) -> Self {
        Self {
            inner,
            budget: Some(budget),
            session: None,
            encoded: None,
            hit: None,
            io: None,
            credits: crate::store::ReadCredits::default(),
        }
    }

    /// `inner` charging nothing, but recording an inherited cap.
    pub(crate) fn capture(inner: &'a S, hit: &'a AtomicBool) -> Self {
        Self {
            inner,
            budget: None,
            session: None,
            encoded: None,
            hit: Some(hit),
            io: None,
            credits: crate::store::ReadCredits::default(),
        }
    }

    /// Record in `hit` whenever a charge or the inner store reports a spent cap.
    #[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
    pub(crate) fn flagging(mut self, hit: &'a AtomicBool) -> Self {
        self.hit = Some(hit);
        self
    }

    /// Also charge every call to a shared session budget, after `budget`.
    #[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
    pub(crate) fn with_session(mut self, session: &'a SliceBudget) -> Self {
        self.session = Some(session);
        self
    }

    /// Reserve ranged blob reads against `encoded` before the read.
    #[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
    pub(crate) fn with_encoded(mut self, encoded: &'a EncodedBudget) -> Self {
        self.encoded = Some(encoded);
        self
    }

    #[cfg_attr(not(feature = "http-objects"), allow(dead_code))]
    pub(crate) fn with_io(mut self, io: &'a crate::store::read_io::ReadIo) -> Self {
        self.io = Some(io);
        self
    }
    async fn admit(
        &self,
        rows: usize,
        bytes: u64,
    ) -> Result<Option<crate::store::read_io::ReadLease>, StoreError> {
        match self.io {
            Some(io) => io.acquire(rows, bytes).await.map(Some),
            None => Ok(None),
        }
    }
    fn note<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if let Some(hit) = self.hit
            && result.as_ref().is_err_and(is_exhausted)
        {
            hit.store(true, Ordering::SeqCst);
        }
        result
    }

    fn reserve(
        &self,
        count: u32,
        inherited: Result<Option<crate::store::ReadReservation>, StoreError>,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        let inherited = self.note(inherited)?;
        self.note(
            self.budget
                .map_or(Ok(()), |b| b.charge_many(count))
                .and_then(|()| self.session.map_or(Ok(()), |b| b.charge_many(count))),
        )?;
        let local = self
            .io
            .map_or_else(|| self.credits.prepay(count), |io| io.prepay(count));
        Ok(Some(local.with_inherited(inherited)))
    }
    pub(crate) fn charge(&self) -> Result<(), StoreError> {
        if self.io.is_some_and(crate::store::read_io::ReadIo::paid) || self.credits.paid() {
            return Ok(());
        }
        let result = self
            .budget
            .map_or(Ok(()), SliceBudget::charge)
            .and_then(|()| self.session.map_or(Ok(()), SliceBudget::charge));
        self.note(result)
    }
}

impl<S: NamespaceStore> NamespaceStore for Budgeted<'_, S> {
    fn reader_admission(&self) -> bool {
        self.io.is_some() || self.inner.reader_admission()
    }
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn reserve_read_calls(
        &self,
        count: u32,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        self.reserve(count, self.inner.reserve_read_calls(count))
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.charge()?;
        let _lease = self
            .admit(
                1,
                (crate::store::MAX_KEY_BYTES + crate::store::MAX_VALUE_BYTES) as u64,
            )
            .await?;
        self.note(self.inner.get(p, key).await)
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.charge()?;
        let _lease = self
            .admit(
                1,
                (crate::store::MAX_KEY_BYTES + crate::store::MAX_VALUE_BYTES) as u64,
            )
            .await?;
        self.note(self.inner.has(p, key).await)
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.charge()?;
        let _lease = self
            .admit(
                keys.len(),
                keys.len()
                    .saturating_mul(crate::store::MAX_KEY_BYTES + crate::store::MAX_VALUE_BYTES)
                    as u64,
            )
            .await?;
        self.note(self.inner.get_many(p, keys).await)
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.charge()?;
        let rows = ranges.iter().map(|r| r.limit as usize).sum::<usize>();
        let _lease = self
            .admit(
                rows,
                rows.saturating_mul(crate::store::MAX_KEY_BYTES + crate::store::MAX_VALUE_BYTES)
                    as u64,
            )
            .await?;
        self.note(self.inner.scan_many(p, ranges).await)
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.charge()?;
        let _lease = self
            .admit(
                limit as usize,
                (limit as usize)
                    .saturating_mul(crate::store::MAX_KEY_BYTES + crate::store::MAX_VALUE_BYTES)
                    as u64,
            )
            .await?;
        self.note(self.inner.scan(p, start, end, after, limit).await)
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.charge()?;
        self.note(self.inner.apply(p, batch).await)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.charge()?;
        self.note(self.inner.stats(p).await)
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.charge()?;
        self.note(self.inner.probe().await)
    }
}

/// Blob reads use the same counter as namespace calls.
impl<B: BlobStore> BlobStore for Budgeted<'_, B> {
    type Sink = B::Sink;

    fn reserve_read_calls(
        &self,
        count: u32,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        self.reserve(count, self.inner.reserve_read_calls(count))
    }
    fn reserve_read_bytes(
        &self,
        bytes: u64,
    ) -> Result<Option<crate::store::ReadReservation>, StoreError> {
        let inherited = self.note(self.inner.reserve_read_bytes(bytes))?;
        let Some(io) = self.io else {
            return Ok(inherited);
        };
        if let Some(encoded) = self.encoded {
            self.note(encoded.charge(bytes))?;
        }
        self.note(io.prepay_bytes(bytes))
            .map(|local| Some(local.with_inherited(inherited)))
    }
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.charge()?;
        // R2's ranged BlobStore read checks metadata before fetching bytes.
        // Reserve both backend requests even for stores that need only one.
        if let Some(range) = range {
            self.charge()?;
            if let Some(encoded) = self.encoded {
                let bytes = range
                    .end_inclusive
                    .saturating_sub(range.start)
                    .saturating_add(1);
                let result = if self.io.is_some_and(|io| io.paid_bytes(bytes)) {
                    Ok(())
                } else {
                    encoded.charge(bytes)
                };
                if result.is_err()
                    && let Some(hit) = self.hit
                {
                    hit.store(true, Ordering::SeqCst);
                }
                result?;
            }
        } else if self.encoded.is_some() {
            // An unranged read cannot be reserved before it happens.
            return Err(StoreError::unavailable(
                "object reader blob reads must be ranged",
            ));
        }
        let bytes = range.map_or(0, |r| {
            r.end_inclusive.saturating_sub(r.start).saturating_add(1)
        });
        let lease = self.admit(0, bytes).await?;
        let body = self.note(self.inner.get(key, range).await)?;
        Ok(match (body, lease) {
            (Some(body), Some(lease)) => Some(lease.hold(body)),
            (body, _) => body,
        })
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.charge()?;
        let _lease = self.admit(0, 0).await?;
        self.note(self.inner.head(key).await)
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

    #[test]
    fn child_spends_its_parent_and_rolls_back_a_refused_charge() {
        let parent = SliceBudget::new(3);
        let child = parent.child(2);
        child.charge().unwrap();
        child.charge().unwrap();
        // The child's own limit refuses first; the parent is untouched by it.
        assert!(child.charge().is_err());
        assert!(child.refused() && !parent.refused());
        assert_eq!((child.used(), parent.used()), (2, 2));
        let sibling = parent.child(5);
        sibling.charge().unwrap();
        // The parent refuses a charge its child would grant: no partial charge.
        assert!(sibling.charge().is_err());
        assert_eq!((sibling.used(), parent.used()), (1, 3));
        assert!(parent.refused() && sibling.ancestor_refused());
        assert_eq!(sibling.remaining(), 0);
        assert!(parent.charge_many(2).is_err());
        assert_eq!(parent.used(), 3);
    }

    #[test]
    fn a_failed_dispatch_stays_charged() {
        struct Failing;
        impl NamespaceStore for Failing {
            fn capabilities(&self) -> StoreCapabilities {
                StoreCapabilities::full()
            }
            async fn get(&self, _: &Partition, _: &Key) -> Result<Option<Value>, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn has(&self, _: &Partition, _: &Key) -> Result<bool, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn get_many(
                &self,
                _: &Partition,
                _: &[Key],
            ) -> Result<Vec<Option<Value>>, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn scan(
                &self,
                _: &Partition,
                _: &Key,
                _: &Key,
                _: Option<&Cursor>,
                _: u32,
            ) -> Result<ScanPage, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
                Err(StoreError::unavailable("injected"))
            }
            async fn probe(&self) -> Result<(), StoreError> {
                Err(StoreError::unavailable("injected"))
            }
        }
        let budget = SliceBudget::new(2);
        let store = Budgeted::new(&Failing, &budget);
        let p = Partition::Namespace(crate::NamespaceKey::deployment_default());
        let key = Key::new(b"k".to_vec());
        for _ in 0..2 {
            let error = futures_executor::block_on(store.get(&p, &key)).unwrap_err();
            assert!(!is_exhausted(&error), "the dispatch failed, not the budget");
        }
        assert_eq!(budget.used(), 2, "failed dispatches are never refunded");
        let error = futures_executor::block_on(store.get(&p, &key)).unwrap_err();
        assert!(is_exhausted(&error) && budget.refused());
    }
}

#[cfg(all(test, feature = "memory"))]
mod read_stream_tests {
    use super::*;
    use futures::FutureExt as _;
    use std::sync::atomic::AtomicUsize;

    struct Streams {
        calls: AtomicUsize,
    }
    impl BlobStore for Streams {
        type Sink = crate::MemoryPackSink;
        async fn begin(&self, _: BlobKey, _: u64) -> Result<Self::Sink, StoreError> {
            unreachable!()
        }
        async fn get(
            &self,
            _: &BlobKey,
            range: Option<ByteRange>,
        ) -> Result<Option<BlobBody>, StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let range = range.expect("test reads always request a range");
            Ok(Some(BlobBody::Stream {
                len: range.end_inclusive - range.start + 1,
                stream: Box::pin(futures::stream::pending()),
            }))
        }
        async fn head(&self, _: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
            unreachable!()
        }
        async fn probe(&self) -> Result<(), StoreError> {
            Ok(())
        }
        async fn delete(&self, _: &BlobKey) -> Result<bool, StoreError> {
            unreachable!()
        }
    }

    #[test]
    fn streaming_bodies_hold_call_permits_and_cancellation_releases_them() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let backend = Streams {
                calls: AtomicUsize::new(0),
            };
            let io = crate::store::read_io::ReadIo::new();
            let budget = SliceBudget::new(100);
            let store = Budgeted::new(&backend, &budget).with_io(&io);
            let key = BlobKey::pack([1; 32]);
            let range = Some(ByteRange {
                start: 0,
                end_inclusive: 7,
            });
            let mut bodies = Vec::new();
            for _ in 0..6 {
                bodies.push(store.get(&key, range).await.unwrap().unwrap());
            }
            assert!(store.get(&key, range).now_or_never().is_none());
            assert_eq!(backend.calls.load(Ordering::SeqCst), 6);
            drop(bodies.pop());
            let body = store
                .get(&key, range)
                .now_or_never()
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(backend.calls.load(Ordering::SeqCst), 7);
            drop(body);
            drop(bodies);
            assert_eq!(budget.used(), 16, "cancelled admission stays charged");
            let body = store.get(&key, range).await.unwrap().unwrap();
            drop(body);
        });
    }
}
