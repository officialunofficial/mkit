//! Accounting shared by additive object-reader sessions.
use super::object_reader::OBJECT_READER_CALLS;
use crate::http_objects::resolve::Budget;
use crate::indexed::budget::SliceBudget;
use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Cursor, Key, NamespaceStore, Partition,
    RangeScan, ScanPage, StoreCapabilities, StoreError, Value,
};
use crate::{Batch, BatchOutcome, PartitionStats};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Aggregate allowances for calls sharing one [`ReaderSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadLimits {
    /// Storage and authorization call units; ranged blob reads cost two units.
    pub storage_calls: u32,
    /// Canonical bytes decoded, including proof ancestors and delta bases.
    pub decoded_bytes: u64,
    /// Encoded pack-range bytes reserved before I/O, including repeated reads.
    pub encoded_bytes: u64,
    /// Canonical output bytes; duplicate outputs count individually.
    pub output_bytes: u64,
}
impl ReadLimits {
    /// Construct explicit aggregate allowances. Zero allows no work in that dimension.
    #[must_use]
    pub const fn new(
        storage_calls: u32,
        decoded_bytes: u64,
        encoded_bytes: u64,
        output_bytes: u64,
    ) -> Self {
        Self {
            storage_calls,
            decoded_bytes,
            encoded_bytes,
            output_bytes,
        }
    }
}
impl Default for ReadLimits {
    fn default() -> Self {
        Self::new(OBJECT_READER_CALLS, 256 << 20, u64::MAX, 256 << 20)
    }
}
/// A ledger for sequential reader calls, retained even after a failed call.
/// Metadata calls charge proof work but emit no canonical output bytes.
/// Existing per-call HTTP allowances and embedder-supplied `SliceBudget`s
/// still apply. Create a new session to start a new allowance.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReaderSession {
    pub(crate) io: IoLedger,
    limits: ReadLimits,
    decoded: u64,
    output: OutputBudget,
}
impl ReaderSession {
    /// Start an empty ledger with explicit limits.
    #[must_use]
    pub fn new(limits: ReadLimits) -> Self {
        Self {
            io: IoLedger {
                calls: SliceBudget::new(limits.storage_calls),
                encoded: EncodedBudget::new(limits.encoded_bytes),
            },
            limits,
            decoded: 0,
            output: OutputBudget {
                used: 0,
                limit: limits.output_bytes,
            },
        }
    }
    /// Snapshot consumed allowances; encoded reservations include failed I/O.
    #[must_use]
    pub fn used(&self) -> ReadLimits {
        ReadLimits::new(
            self.io.calls.used(),
            self.decoded,
            self.io.encoded.used.load(Ordering::SeqCst),
            self.output.used,
        )
    }
    pub(crate) fn split(
        &mut self,
        per_call: u64,
    ) -> (&IoLedger, DecodeCharge<'_>, &mut OutputBudget) {
        let initial = per_call.min(self.limits.decoded_bytes.saturating_sub(self.decoded));
        (
            &self.io,
            DecodeCharge {
                budget: Budget(initial),
                initial,
                used: &mut self.decoded,
            },
            &mut self.output,
        )
    }
}
impl Default for ReaderSession {
    fn default() -> Self {
        Self::new(ReadLimits::default())
    }
}
#[derive(Debug)]
pub(crate) struct IoLedger {
    pub calls: SliceBudget,
    encoded: EncodedBudget,
}
#[derive(Debug)]
pub(crate) struct OutputBudget {
    pub used: u64,
    limit: u64,
}
impl OutputBudget {
    pub(crate) fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }
}
// Settles decoded work on failure and cancellation as well as success.
pub(crate) struct DecodeCharge<'a> {
    pub budget: Budget,
    initial: u64,
    used: &'a mut u64,
}
impl Drop for DecodeCharge<'_> {
    fn drop(&mut self) {
        *self.used += self.initial.saturating_sub(self.budget.0);
    }
}
#[derive(Debug)]
pub(crate) struct EncodedBudget {
    limit: u64,
    used: AtomicU64,
}
impl EncodedBudget {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            used: AtomicU64::new(0),
        }
    }
    fn charge(&self, bytes: u64) -> Result<(), StoreError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map(|_| ())
            .map_err(|_| StoreError::unavailable("object reader encoded budget exhausted"))
    }
}
// Reader-local failure marker: avoids mistaking a backend outage at an exactly
// spent call allowance for exhaustion after lower layers redact storage errors.
pub(crate) struct ReaderStore<'a, S> {
    inner: &'a S,
    calls: Option<&'a SliceBudget>,
    session_calls: Option<&'a SliceBudget>,
    encoded: Option<&'a EncodedBudget>,
    exhausted: &'a AtomicBool,
}
impl<'a, S> ReaderStore<'a, S> {
    pub(super) fn new(
        inner: &'a S,
        calls: &'a SliceBudget,
        session: Option<&'a IoLedger>,
        exhausted: &'a AtomicBool,
    ) -> Self {
        Self {
            inner,
            calls: Some(calls),
            session_calls: session.map(|s| &s.calls),
            encoded: session.map(|s| &s.encoded),
            exhausted,
        }
    }
    // Authorization retains its existing two call reservations. Capture an
    // inherited invocation cap before HTTP authorization erases store errors.
    pub(super) fn capture(inner: &'a S, exhausted: &'a AtomicBool) -> Self {
        Self {
            inner,
            calls: None,
            session_calls: None,
            encoded: None,
            exhausted,
        }
    }
    pub(super) fn charge(&self) -> Result<(), StoreError> {
        let result = self
            .calls
            .map_or(Ok(()), SliceBudget::charge)
            .and_then(|()| self.session_calls.map_or(Ok(()), SliceBudget::charge));
        if result.is_err() {
            self.exhausted.store(true, Ordering::SeqCst);
        }
        result
    }
    fn observe<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if result
            .as_ref()
            .is_err_and(crate::indexed::budget::is_exhausted)
        {
            self.exhausted.store(true, Ordering::SeqCst);
        }
        result
    }
    fn charge_bytes(&self, bytes: u64) -> Result<(), StoreError> {
        let result = self.encoded.map_or(Ok(()), |budget| budget.charge(bytes));
        if result.is_err() {
            self.exhausted.store(true, Ordering::SeqCst);
        }
        result
    }
}
impl<S: NamespaceStore> NamespaceStore for ReaderStore<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.charge()?;
        self.observe(self.inner.get(p, key).await)
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.charge()?;
        self.observe(self.inner.has(p, key).await)
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.charge()?;
        self.observe(self.inner.get_many(p, keys).await)
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.charge()?;
        self.observe(self.inner.scan_many(p, ranges).await)
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
        self.observe(self.inner.scan(p, start, end, after, limit).await)
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.charge()?;
        self.observe(self.inner.apply(p, batch).await)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.charge()?;
        self.observe(self.inner.stats(p).await)
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.charge()?;
        self.observe(self.inner.probe().await)
    }
}

impl<B: BlobStore> BlobStore for ReaderStore<'_, B> {
    type Sink = B::Sink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.charge()?;
        if let Some(range) = range {
            self.charge()?;
            self.charge_bytes(
                range
                    .end_inclusive
                    .saturating_sub(range.start)
                    .saturating_add(1),
            )?;
        }
        let body = self.observe(self.inner.get(key, range).await)?;
        if range.is_none()
            && let Some(body) = &body
        {
            self.charge_bytes(match body {
                BlobBody::Bytes(b) => b.len() as u64,
                BlobBody::Stream { len, .. } => *len,
            })?;
        }
        Ok(body)
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.charge()?;
        self.inner.head(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.charge()?;
        self.inner.probe().await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}
