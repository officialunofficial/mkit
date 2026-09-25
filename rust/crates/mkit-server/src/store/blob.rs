//! The blob contract (PRD §5.3): content-addressed, immutable bytes.
//!
//! Every concrete store is built for one keyspace: `packs` (today's
//! `packs/<hex>`, where `BLAKE3(bytes) == key`) by default. M4 builds a
//! second instance for the global object store (D32), so a new keyspace
//! needs no trait change. Resumable multipart uploads are a sub-trait
//! (`MultipartBlobStore`, WP-1.11).

use core::fmt;
use core::future::Future;

use bytes::Bytes;

use super::error::StoreError;
use crate::rt::{BoxStream, MaybeSend, MaybeSync};

/// A blob's key.
pub type BlobKey = mkit_core::protocol::PackKey;

/// An inclusive byte range, as in HTTP `Range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte.
    pub start: u64,
    /// Last byte; clamped to the blob's last byte.
    pub end_inclusive: u64,
}

impl ByteRange {
    /// The `start..end` slice this range selects in a blob of `len` bytes.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] when `start > end_inclusive` (malformed);
    /// [`StoreError::RangeNotSatisfiable`] when `start >= len`.
    pub fn resolve(self, len: u64) -> Result<core::ops::Range<u64>, StoreError> {
        if self.start > self.end_inclusive {
            return Err(StoreError::Invalid("byte range start after its end".into()));
        }
        if self.start >= len {
            return Err(StoreError::RangeNotSatisfiable { len });
        }
        Ok(self.start..self.end_inclusive.min(len - 1) + 1)
    }
}

/// A blob's metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobMeta {
    /// Length in bytes.
    pub len: u64,
}

/// A blob's bytes, whole or streamed.
pub enum BlobBody {
    /// All bytes in one buffer.
    Bytes(Bytes),
    /// A stream of chunks totaling `len` bytes.
    Stream {
        /// Total length.
        len: u64,
        /// The chunks, in order.
        stream: BoxStream<'static, Result<Bytes, StoreError>>,
    },
}

impl fmt::Debug for BlobBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            Self::Stream { len, .. } => f.debug_struct("Stream").field("len", len).finish(),
        }
    }
}

/// How a [`PackSink::commit`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The blob is new.
    Created,
    /// The blob was already there (identical bytes, by construction).
    /// Advisory: a concurrent writer of the same key may see `Created` too,
    /// and a backend that cannot tell cheaply may report `Created`. Nothing
    /// may depend on it for correctness or accounting.
    AlreadyPresent,
}

/// A content-addressed, immutable blob store. Writes are put-if-absent;
/// rewriting a present key with identical bytes is `AlreadyPresent`.
pub trait BlobStore: MaybeSend + MaybeSync {
    /// The upload handle [`Self::begin`] returns.
    type Sink: PackSink;

    /// Start writing blob `key` of `len` bytes.
    fn begin(
        &self,
        key: BlobKey,
        len: u64,
    ) -> impl Future<Output = Result<Self::Sink, StoreError>> + MaybeSend;

    /// The blob's bytes, or `range` of them. Backends SHOULD stream
    /// anything larger than one chunk and never buffer a whole pack. A
    /// range starting at or past the end is
    /// [`StoreError::RangeNotSatisfiable`].
    fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> impl Future<Output = Result<Option<BlobBody>, StoreError>> + MaybeSend;

    /// The blob's metadata, if present.
    fn head(
        &self,
        key: &BlobKey,
    ) -> impl Future<Output = Result<Option<BlobMeta>, StoreError>> + MaybeSend;

    /// A cheap health check.
    fn probe(&self) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;

    /// Remove a blob; returns whether it existed. Never called by the M0
    /// pipeline: reserved for GC and takedown (WP-5.3b, WP-5.6).
    fn delete(&self, key: &BlobKey) -> impl Future<Output = Result<bool, StoreError>> + MaybeSend;
}

/// An in-progress blob upload.
///
/// Memory is bounded by a backend constant (one part, e.g. an R2 multipart
/// part or a write buffer), never by the blob. Dropping a sink without
/// `commit` or `abort` leaves nothing visible; its staged bytes may leak
/// until the backend reclaims them (a temp-file sweep natively, R2's
/// abort-incomplete-multipart-upload lifecycle rule).
pub trait PackSink: MaybeSend {
    /// Append a chunk. Writing past the declared length is
    /// [`StoreError::Invalid`].
    fn write(&mut self, chunk: Bytes) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;

    /// Make the blob visible, only if `BLAKE3(bytes) == key` and the total
    /// equals the declared length; otherwise [`StoreError::Invalid`] and
    /// nothing is visible (a streaming backend withholds its final part
    /// until the hash verifies).
    fn commit(self) -> impl Future<Output = Result<CommitOutcome, StoreError>> + MaybeSend;

    /// Discard the upload; nothing becomes visible.
    fn abort(self) -> impl Future<Output = ()> + MaybeSend;
}
