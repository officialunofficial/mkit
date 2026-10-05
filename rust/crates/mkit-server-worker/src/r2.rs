//! [`R2BlobStore`]: the content-addressed [`BlobStore`] over R2, streaming
//! both ways (reconciliation R-25). No code path holds a whole blob.
//!
//! **Put.** [`BlobStore::begin`] opens a conditional put
//! (`If-None-Match: *`, as vcs-worker's `put_addressed`) of exactly the
//! declared length, fed by a depth-1 channel, and **spawns** it
//! ([`ObjectBucket::spawn_put`]; `spawn_local` on Workers). workers-rs
//! builds the JS put inside an `async fn`, so an unspawned put would not
//! start until awaited, and a sink writing into a full channel before then
//! would deadlock (review 01, R-67). Each [`PackSink::write`] hashes its
//! chunk and forwards it, except that the blob's **last byte is withheld**
//! until the BLAKE3 of every byte equals the key and the length matches.
//! A fixed-length R2 body that ends short fails the put, so an abort, a
//! mismatch or a dropped sink never makes anything visible: only verified
//! bytes are ever published under a key. [`PackSink::commit`] releases the
//! last byte, closes the body and awaits the put. A failed condition means
//! the key exists: [`CommitOutcome::AlreadyPresent`].
//!
//! **Memory** per upload is a few chunks, never the blob: the caller's
//! chunk, the one in the channel, the `Vec<u8>` workers-rs copies it into
//! and the `Uint8Array` it copies that into, plus whatever the
//! fixed-length `TransformStream` queues (about 3 to 4 chunks in all).
//!
//! **Early answers.** R2 may answer a put before reading its whole body
//! (a failed condition, a 429). Every send races the put's answer: once the
//! put has ended, the sink stops forwarding, keeps hashing the remaining
//! chunks and discards them, and [`PackSink::commit`] still verifies before
//! it reports the answer.
//!
//! **Limits.** R2 allows about one write per second per key; a concurrent
//! writer of the same key can make a put fail (HTTP 429). Because a key only
//! ever holds verified bytes, a failed put of verified bytes whose key is
//! then present is `AlreadyPresent`; otherwise it is `Unavailable`, and the
//! client retries.
//! `max_bytes` (64 MiB by default) caps the single-part `UploadPack` put's
//! declared length. Ticketed multipart bypasses that cap and uses verified
//! 8–32 MiB CV-keyed part objects, then rehashes the complete pack through
//! a conditional put. A bucket lifecycle rule removes leftover staging
//! objects after eight days.
//!
//! **Get.** A body is always a [`BlobBody::Stream`] over the R2 object
//! body, re-chunked to pieces of at most [`MAX_BLOB_PIECE_BYTES`] and
//! checked against the expected length. A range reads R2's range; the blob
//! length it is resolved against comes from a `head` first.
//!
//! The store serves the bytes it verified and nothing else: it never
//! decodes or re-encodes pack contents (serving pushed zstd frames is
//! decided above it, WP-4.7/4.8).

use core::future::Future;
use core::ops::Range;
use core::pin::Pin;
use core::task::{Context, Poll};
#[cfg(feature = "__test-faults")]
use std::sync::Arc;
#[cfg(feature = "__test-faults")]
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::future::{self, Either};
use futures::{SinkExt as _, Stream, StreamExt as _};
use mkit_core::hash::{Hash, Hasher};
use mkit_core::upload_parts::{PartHasher, PartPlan};
use mkit_server::storage_error::StorageOp;
use mkit_server::store::MAX_BLOB_PIECE_BYTES;
use mkit_server::{
    BlobBody, BlobKey, BlobMeta, BlobStore, BoxStream, ByteRange, CommitOutcome, MaybeSend,
    MaybeSync, PackSink, StoreError,
};

use crate::backend_error;

/// The R2 bucket binding vcs-worker uses.
pub const STORAGE_BINDING: &str = "STORAGE";
/// The pack keyspace: objects are `packs/<hex>`.
pub const PACKS_KEYSPACE: &str = "packs";
/// The default cap on one put's declared length (M1 stopgap).
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

mod multipart;
mod object_multipart;
pub use multipart::R2PartSink;
pub use object_multipart::{VerifiedObjectPart, VerifiedObjectPartRef};

/// Sent into a put body to fail it before its declared length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyAborted;

/// The body of a spawned put: chunks, in order.
pub type PutBody = mpsc::Receiver<Result<Bytes, BodyAborted>>;

/// How a put ended: `Ok(true)` created, `Ok(false)` not written because the
/// key existed, `Err` with the backend's detail (for the server log only).
pub type PutResult = Result<bool, String>;

/// An object body as the backend delivers it.
pub type ObjectStream = BoxStream<'static, Result<Bytes, String>>;

/// A bounded page of object names and an opaque continuation cursor.
#[derive(Debug)]
pub struct ObjectPage {
    pub keys: Vec<String>,
    pub cursor: Option<String>,
}

/// The answer of [`ObjectBucket::get_range_etag`].
#[derive(Debug, PartialEq, Eq)]
pub enum RangeRead {
    /// No such object.
    Absent,
    /// The object no longer has the etag the caller required.
    EtagChanged,
    /// The requested range, and the etag of the object it came from.
    Bytes {
        /// Exactly the requested range.
        bytes: Vec<u8>,
        /// The object's etag.
        etag: String,
    },
}

/// The object-store operations [`R2BlobStore`] needs: R2 on Workers
/// (`EnvBucket`, wasm32), a simulation in tests. Errors carry the backend's
/// detail, which the store logs and never returns.
pub trait ObjectBucket: MaybeSend + MaybeSync + Clone + 'static {
    /// Reserve backend calls before a bounded read wave.
    #[doc(hidden)]
    fn reserve_read_calls(
        &self,
        _calls: u32,
    ) -> Result<Option<mkit_server::store::ReadReservation>, StoreError> {
        Ok(None)
    }
    /// Start, now, a put of `key` that writes only if the key is absent,
    /// with a body of exactly `len` bytes read from `body`. The put must
    /// make progress while the caller is still writing into `body` (it is
    /// spawned, not returned as a future), and must fail, writing nothing,
    /// if `body` ends before `len` bytes or yields [`BodyAborted`].
    fn spawn_put(&self, key: String, len: u64, body: PutBody) -> oneshot::Receiver<PutResult>;

    /// The object's size, if present.
    fn head(&self, key: &str) -> impl Future<Output = Result<Option<u64>, String>> + MaybeSend;

    /// The object's full size and its body, or `range` of it.
    fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> impl Future<Output = Result<Option<(u64, ObjectStream)>, String>> + MaybeSend;

    /// `range` of the object, only while it still has `etag` (when given),
    /// and the etag it has. Scheduled verification reads a pack in windows
    /// across alarms and binds every read to the etag of the first
    /// (SPEC-PACKFILE §11); a backend without conditional reads fails.
    fn get_range_etag(
        &self,
        _key: &str,
        _range: Range<u64>,
        _etag: Option<&str>,
    ) -> impl Future<Output = Result<RangeRead, String>> + MaybeSend {
        async { Err("conditional range reads are not supported".to_owned()) }
    }

    /// Remove the object; absent is not an error.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), String>> + MaybeSend;

    /// Return at most 1,000 keys with the given prefix.
    fn list(
        &self,
        prefix: &str,
        cursor: Option<&str>,
    ) -> impl Future<Output = Result<ObjectPage, String>> + MaybeSend;

    /// Remove at most 1,000 objects. Absent keys are harmless.
    fn delete_many(
        &self,
        keys: Vec<String>,
    ) -> impl Future<Output = Result<(), String>> + MaybeSend;

    /// Create a private backend multipart session for `key`. Unsupported by
    /// default; only the verified object protocol may use this primitive.
    fn create_object_upload(
        &self,
        _key: &str,
    ) -> impl Future<Output = Result<String, String>> + MaybeSend {
        async { Err("backend multipart unsupported".into()) }
    }

    /// Spawn one fixed-length private part body. Success returns its opaque
    /// backend `ETag`; it is NOT a content-integrity proof.
    fn spawn_object_part(
        &self,
        _key: String,
        _upload: String,
        _number: u16,
        _len: u64,
        _body: PutBody,
    ) -> oneshot::Receiver<Result<String, String>> {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err("backend multipart unsupported".into()));
        rx
    }

    /// Publish exactly the listed backend parts. No conditional publication
    /// is available; callers must establish deterministic verified bytes.
    fn complete_object_upload(
        &self,
        _key: &str,
        _upload: &str,
        _parts: Vec<(u16, String)>,
    ) -> impl Future<Output = Result<(), String>> + MaybeSend {
        async { Err("backend multipart unsupported".into()) }
    }

    /// Abort the private backend session. A gone session is harmless.
    fn abort_object_upload(
        &self,
        _key: &str,
        _upload: &str,
    ) -> impl Future<Output = Result<(), String>> + MaybeSend {
        async { Err("backend multipart unsupported".into()) }
    }

    /// A cheap reachability check.
    fn probe(&self) -> impl Future<Output = Result<(), String>> + MaybeSend;
}

/// A content-addressed [`BlobStore`] for one keyspace of an
/// [`ObjectBucket`] (see the module docs).
#[derive(Debug, Clone)]
pub struct R2BlobStore<B> {
    bucket: B,
    keyspace: &'static str,
    max_bytes: u64,
    defer_abort: bool,
    #[cfg(feature = "__test-faults")]
    fail_final: Arc<AtomicBool>,
}

impl<B: ObjectBucket> R2BlobStore<B> {
    /// A store for `keyspace` ([`PACKS_KEYSPACE`] for pack uploads), capped
    /// at [`DEFAULT_MAX_BYTES`] per blob.
    ///
    /// # Panics
    /// If `keyspace` would alias a sibling namespace (`objects`,
    /// `object-offsets`, `upload-markers`).
    #[must_use]
    pub fn new(bucket: B, keyspace: &'static str) -> Self {
        assert!(
            !mkit_server::is_reserved_pack_keyspace(keyspace),
            "a keyspace must not alias a sibling namespace: {keyspace:?}"
        );
        Self {
            bucket,
            keyspace,
            max_bytes: DEFAULT_MAX_BYTES,
            defer_abort: false,
            #[cfg(feature = "__test-faults")]
            fail_final: Arc::default(),
        }
    }

    /// Cap one blob at `max_bytes` instead.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Leave expiry session cleanup to the bucket lifecycle when its alarm has no R2 budget.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn with_deferred_abort(mut self, defer: bool) -> Self {
        self.defer_abort = defer;
        self
    }

    /// The object key of `key`: `<keyspace>/<hex>` for packs, or the sibling
    /// `upload-markers/v1/<hex>` namespace for upload markers.
    ///
    /// # Errors
    /// [`StoreError::Invalid`] for an unsupported blob namespace.
    pub fn object_key(&self, key: &BlobKey) -> Result<String, StoreError> {
        key.relative_path(self.keyspace)
    }

    /// Fail the next commit at its withheld final byte, after the hash
    /// verified: the put fails and nothing becomes visible (`__test-faults`).
    #[cfg(feature = "__test-faults")]
    pub fn fail_final_chunk_once(&self) {
        self.fail_final.store(true, Ordering::SeqCst);
    }
}

/// The hashing, length-checking core of an upload: every chunk is hashed
/// and forwarded except the blob's last byte, which [`Self::finish`]
/// releases only if the bytes verify.
#[derive(Debug)]
struct Withheld {
    expected: ExpectedHash,
    len: u64,
    received: u64,
    last: Option<Bytes>,
}

#[derive(Debug)]
enum ExpectedHash {
    Root { key: BlobKey, hasher: Hasher },
    Part { cv: [u8; 32], hasher: PartHasher },
}

impl Withheld {
    fn new(key: BlobKey, len: u64) -> Self {
        Self {
            expected: ExpectedHash::Root {
                key,
                hasher: Hasher::new(),
            },
            len,
            received: 0,
            last: None,
        }
    }

    fn part(cv: [u8; 32], plan: &PartPlan, index: u32) -> Result<Self, StoreError> {
        let len = plan
            .expected_len(index)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let hasher =
            PartHasher::new(plan, index).map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        Ok(Self {
            expected: ExpectedHash::Part { cv, hasher },
            len,
            received: 0,
            last: None,
        })
    }

    /// Hash `chunk`; the part to forward now. The chunk that completes the
    /// declared length keeps its last byte back.
    fn push(&mut self, mut chunk: Bytes) -> Result<Bytes, StoreError> {
        let total = self.received.saturating_add(chunk.len() as u64);
        if total > self.len {
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        }
        match &mut self.expected {
            ExpectedHash::Root { hasher, .. } => {
                hasher.update(&chunk);
            }
            ExpectedHash::Part { hasher, .. } => hasher
                .update(&chunk)
                .map_err(|e| StoreError::Invalid(e.to_string().into()))?,
        }
        self.received = total;
        if total == self.len && !chunk.is_empty() {
            self.last = Some(chunk.split_off(chunk.len() - 1));
        }
        Ok(chunk)
    }

    /// The withheld byte, if every byte arrived and hashes to the key (or to
    /// `root`, for an object key).
    fn finish(&mut self, root: Option<Hash>) -> Result<Option<Bytes>, StoreError> {
        if self.received != self.len {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        match &mut self.expected {
            ExpectedHash::Root { key, hasher } => {
                if hasher.finalize() != key.expected_root(root)? {
                    return Err(StoreError::Invalid(
                        "blob hash does not match its key".into(),
                    ));
                }
            }
            ExpectedHash::Part { cv, hasher } => {
                let actual = hasher
                    .clone()
                    .finalize()
                    .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
                if actual != *cv {
                    return Err(StoreError::PartSubtreeMismatch);
                }
            }
        }
        Ok(self.last.take())
    }
}

/// The spawned put behind a sink, and its answer once it has one.
#[derive(Debug)]
struct Running<T = bool> {
    tx: Option<mpsc::Sender<Result<Bytes, BodyAborted>>>,
    /// `None` once the answer is in.
    done: Option<oneshot::Receiver<Result<T, String>>>,
    answer: Option<Result<T, String>>,
}

impl Running<bool> {
    fn spawn<B: ObjectBucket>(bucket: &B, object: String, len: u64) -> Self {
        // Buffer 0 plus one slot per sender: depth 1.
        let (tx, rx) = mpsc::channel(0);
        Self {
            tx: Some(tx),
            done: Some(bucket.spawn_put(object, len, rx)),
            answer: None,
        }
    }
}

impl<T> Running<T> {
    /// Keep the put's answer; stop feeding its body.
    fn record(&mut self, answer: Result<Result<T, String>, oneshot::Canceled>) {
        self.answer = Some(answer.unwrap_or_else(|_| Err("put task dropped".into())));
        self.done = None;
        self.tx = None;
    }

    /// Wait for the answer, if it is not in yet.
    async fn settle(&mut self) {
        if let Some(done) = self.done.take() {
            let answer = done.await;
            self.record(answer);
        }
    }

    /// Forward `chunk`, unless the put has answered. The send races the
    /// answer: a put that ends without reading its whole body (a failed
    /// condition, a 429) never leaves the sender waiting on a full channel.
    async fn send(&mut self, chunk: Bytes) {
        let (Some(tx), Some(done)) = (self.tx.as_mut(), self.done.as_mut()) else {
            return;
        };
        let ended = match future::select(tx.send(Ok(chunk)), done).await {
            Either::Left((Ok(()), _)) => return,
            // The body's reader is gone: the put ended.
            Either::Left((Err(_), _)) => None,
            Either::Right((answer, _)) => Some(answer),
        };
        match ended {
            Some(answer) => self.record(answer),
            None => self.settle().await,
        }
    }

    /// Close the body (every declared byte is in it) and return the answer.
    async fn finish(&mut self) -> Result<T, String> {
        self.tx = None;
        self.settle().await;
        self.answer
            .take()
            .unwrap_or_else(|| Err("no answer".into()))
    }

    /// Fail the body and wait for the put to end, so nothing it wrote can
    /// appear after this returns.
    async fn fail(mut self) {
        if let Some(mut tx) = self.tx.take() {
            // A full channel is fine: closing it short fails the put too.
            let _ = tx.try_send(Err(BodyAborted));
        }
        self.settle().await;
    }
}

/// The upload handle of [`R2BlobStore`].
#[derive(Debug)]
pub struct R2PackSink<B> {
    bucket: B,
    store: R2BlobStore<B>,
    object: String,
    core: Withheld,
    /// `None` for an empty blob, whose put starts only at commit.
    put: Option<Running>,
    failed: bool,
    #[cfg(feature = "__test-faults")]
    fail_final: Arc<AtomicBool>,
}

impl<B: ObjectBucket> R2PackSink<B> {
    /// Forward a chunk; after an early answer it is only hashed (by the
    /// caller) and dropped.
    async fn send(&mut self, chunk: Bytes) {
        if let Some(put) = self.put.as_mut().filter(|_| !chunk.is_empty()) {
            put.send(chunk).await;
        }
    }

    async fn fail(&mut self) {
        if let Some(put) = self.put.take() {
            put.fail().await;
        }
    }
}

impl<B: ObjectBucket> BlobStore for R2BlobStore<B> {
    type Sink = R2PackSink<B>;
    fn reserve_read_calls(
        &self,
        calls: u32,
    ) -> Result<Option<mkit_server::store::ReadReservation>, StoreError> {
        self.bucket.reserve_read_calls(calls)
    }

    async fn begin(&self, key: BlobKey, len: u64) -> Result<R2PackSink<B>, StoreError> {
        mkit_server::store::ReadReservation::scope(&[], async {
            if len > self.max_bytes {
                return Err(StoreError::Invalid(
                    "blob exceeds the store's size cap".into(),
                ));
            }
            Ok(self.sink(self.object_key(&key)?, Withheld::new(key, len)))
        })
        .await
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let object = self.object_key(key)?;
        let span = match range {
            None => None,
            Some(range) => {
                let Some(len) = self.head_len(&object).await? else {
                    return Ok(None);
                };
                Some(range.resolve(len)?)
            }
        };
        let got = self
            .bucket
            .get(&object, span.clone())
            .await
            .map_err(|e| backend_error(StorageOp::BlobGet, e))?;
        let Some((size, stream)) = got else {
            return Ok(None);
        };
        let len = span.map_or(size, |s| s.end - s.start);
        Ok(Some(BlobBody::Stream {
            len,
            stream: Box::pin(Pieces::new(stream, len)),
        }))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        Ok(self
            .head_len(&self.object_key(key)?)
            .await?
            .map(|len| BlobMeta { len }))
    }

    async fn probe(&self) -> Result<(), StoreError> {
        mkit_server::store::ReadReservation::scope(&[], async {
            self.bucket
                .probe()
                .await
                .map_err(|e| backend_error(StorageOp::BlobHead, e))
        })
        .await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        // The existence probe belongs to mutation, not an admitted read wave.
        mkit_server::store::ReadReservation::scope(&[], async {
            let object = self.object_key(key)?;
            if self.head_len(&object).await?.is_none() {
                return Ok(false);
            }
            self.bucket
                .delete(&object)
                .await
                .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
            Ok(true)
        })
        .await
    }
}

impl<B: ObjectBucket> R2BlobStore<B> {
    fn sink(&self, object: String, core: Withheld) -> R2PackSink<B> {
        let put = (core.len > 0).then(|| Running::spawn(&self.bucket, object.clone(), core.len));
        R2PackSink {
            bucket: self.bucket.clone(),
            store: self.clone(),
            object,
            core,
            put,
            failed: false,
            #[cfg(feature = "__test-faults")]
            fail_final: self.fail_final.clone(),
        }
    }

    async fn head_len(&self, object: &str) -> Result<Option<u64>, StoreError> {
        self.bucket
            .head(object)
            .await
            .map_err(|e| backend_error(StorageOp::BlobHead, e))
    }
}

impl<B: ObjectBucket> PackSink for R2PackSink<B> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        mkit_server::store::ReadReservation::scope(&[], async {
            if self.failed {
                return Err(StoreError::Invalid("write after a failed write".into()));
            }
            match self.core.push(chunk) {
                Ok(forward) => {
                    self.send(forward).await;
                    Ok(())
                }
                Err(e) => {
                    self.failed = true;
                    self.fail().await;
                    Err(e)
                }
            }
        })
        .await
    }

    async fn commit(self) -> Result<CommitOutcome, StoreError> {
        self.finish(None).await
    }

    async fn commit_with_root(self, content_root: Hash) -> Result<CommitOutcome, StoreError> {
        self.finish(Some(content_root)).await
    }

    async fn abort(mut self) {
        mkit_server::store::ReadReservation::scope(&[], async {
            self.fail().await;
        })
        .await;
    }
}

impl<B: ObjectBucket> R2PackSink<B> {
    /// Verify against `root` (the key's hash for `None`), then release the
    /// withheld byte.
    async fn finish(mut self, root: Option<Hash>) -> Result<CommitOutcome, StoreError> {
        mkit_server::store::ReadReservation::scope(&[], async {
        if self.failed {
            self.fail().await;
            return Err(StoreError::Invalid("commit after a failed write".into()));
        }
        let last = match self.core.finish(root) {
            Ok(last) => last,
            Err(e) => {
                self.fail().await;
                return Err(e);
            }
        };
        if let Some(root) = root
            && let Err(error) = self
                .store
                .pin_object_root(&self.object, root, self.core.len)
                .await
        {
            self.fail().await;
            return Err(error);
        }
        #[cfg(feature = "__test-faults")]
        if self.fail_final.swap(false, Ordering::SeqCst) {
            self.fail().await;
            return Err(StoreError::unavailable(
                "injected fault at the withheld final chunk",
            ));
        }
        if self.put.is_none() {
            // An empty blob: verified above, so start its put now.
            self.put = Some(Running::spawn(&self.bucket, self.object.clone(), 0));
        }
        if let Some(last) = last {
            self.send(last).await;
        }
        let Some(mut put) = self.put.take() else {
            return Err(backend_error(StorageOp::BlobPut, "no put"));
        };
        // The bytes verified above, so any answer, early or not, stands.
        match put.finish().await {
            Ok(true) => Ok(CommitOutcome::Created),
            Ok(false) => Ok(CommitOutcome::AlreadyPresent),
            Err(detail) => {
                // A key holds only verified bytes: if it is present now (a
                // concurrent writer, R2's per-key write rate), ours are too.
                if matches!(self.bucket.head(&self.object).await, Ok(Some(n)) if n == self.core.len)
                {
                    return Ok(CommitOutcome::AlreadyPresent);
                }
                Err(backend_error(StorageOp::BlobPut, detail))
            }
        }
        })
        .await
    }
}

/// An object body re-chunked to pieces of at most
/// [`MAX_BLOB_PIECE_BYTES`], failing if it is not exactly `len` bytes.
struct Pieces {
    inner: ObjectStream,
    remaining: u64,
    rest: Bytes,
    done: bool,
}

impl Pieces {
    fn new(inner: ObjectStream, len: u64) -> Self {
        Self {
            inner,
            remaining: len,
            rest: Bytes::new(),
            done: false,
        }
    }

    fn fail(&mut self, detail: impl core::fmt::Display) -> Poll<Option<Result<Bytes, StoreError>>> {
        self.done = true;
        Poll::Ready(Some(Err(backend_error(StorageOp::BlobRead, detail))))
    }
}

impl Stream for Pieces {
    type Item = Result<Bytes, StoreError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if !this.rest.is_empty() {
                let n = this.rest.len().min(MAX_BLOB_PIECE_BYTES);
                return Poll::Ready(Some(Ok(this.rest.split_to(n))));
            }
            match this.inner.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(detail))) => return this.fail(detail),
                Poll::Ready(Some(Ok(piece))) => {
                    let n = piece.len() as u64;
                    if n > this.remaining {
                        return this.fail("object body longer than its length");
                    }
                    this.remaining -= n;
                    this.rest = piece;
                }
                Poll::Ready(None) if this.remaining > 0 => {
                    return this.fail("object body shorter than its length");
                }
                Poll::Ready(None) => this.done = true,
            }
        }
    }
}

/// R2 through a `worker::Env` bucket binding.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct EnvBucket {
    env: worker::Env,
    binding: &'static str,
    request_budget: Option<mkit_server::indexed::budget::SliceBudget>,
    read_credits: std::sync::Arc<mkit_server::store::ReadCredits>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
}

#[cfg(target_arch = "wasm32")]
impl EnvBucket {
    /// The bucket bound as `binding` ([`STORAGE_BINDING`]).
    #[must_use]
    pub fn new(env: worker::Env, binding: &'static str) -> Self {
        Self {
            env,
            binding,
            request_budget: None,
            read_credits: std::sync::Arc::default(),
            alarm_budget: None,
        }
    }

    /// Share the incoming request's allowance across R2 calls and upload clones.
    #[must_use]
    pub fn with_budget(mut self, budget: mkit_server::indexed::budget::SliceBudget) -> Self {
        self.request_budget = Some(budget);
        self.read_credits = std::sync::Arc::default();
        self
    }

    /// Share the existing alarm allowance; each R2 operation charges at dispatch.
    #[must_use]
    pub fn with_alarm_budget(mut self, budget: mkit_server::purge::SliceBudget) -> Self {
        self.alarm_budget = Some(budget);
        self.read_credits = std::sync::Arc::default();
        self
    }

    fn bucket(&self, prepaid_read: bool) -> Result<worker::Bucket, String> {
        if !prepaid_read || !self.read_credits.paid() {
            crate::ns_client::charge_request(self.request_budget.as_ref())
                .map_err(|e| e.to_string())?;
            crate::ns_client::charge_alarm(self.alarm_budget.as_ref())
                .map_err(|e| e.to_string())?;
        }
        self.env.bucket(self.binding).map_err(|e| e.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl crate::backup::BackupBucket for EnvBucket {
    async fn put(&self, key: &str, bytes: Vec<u8>, partition_hex: &str) -> Result<(), String> {
        let metadata =
            std::collections::HashMap::from([("partition".to_owned(), partition_hex.to_owned())]);
        self.bucket(false)?
            .put(key, bytes)
            .custom_metadata(metadata)
            .only_if(worker::Conditional {
                etag_does_not_match: Some("*".to_owned()),
                ..Default::default()
            })
            .execute()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

/// The Workers blob store: packs in the `STORAGE` bucket.
#[cfg(target_arch = "wasm32")]
pub type WorkerBlobStore = R2BlobStore<EnvBucket>;

#[cfg(target_arch = "wasm32")]
impl ObjectBucket for EnvBucket {
    fn reserve_read_calls(
        &self,
        calls: u32,
    ) -> Result<Option<mkit_server::store::ReadReservation>, StoreError> {
        crate::ns_client::reserve_calls(
            self.request_budget.as_ref(),
            self.alarm_budget.as_ref(),
            calls,
        )?;
        Ok(Some(self.read_credits.prepay(calls)))
    }
    fn spawn_put(&self, key: String, len: u64, body: PutBody) -> oneshot::Receiver<PutResult> {
        let (tx, rx) = oneshot::channel();
        let bucket = self.bucket(false);
        worker::wasm_bindgen_futures::spawn_local(async move {
            let result = async move {
                let body = body.map(|item| {
                    item.map(Vec::from)
                        .map_err(|_| worker::Error::RustError("upload aborted".into()))
                });
                let put = bucket?
                    .put(key, worker::FixedLengthStream::wrap(body, len))
                    .only_if(worker::Conditional {
                        etag_does_not_match: Some("*".to_owned()),
                        ..Default::default()
                    })
                    .execute()
                    .await
                    .map_err(|e| e.to_string())?;
                // `None`: the condition failed, the key exists.
                Ok(put.is_some())
            }
            .await;
            let _ = tx.send(result);
        });
        rx
    }

    async fn head(&self, key: &str) -> Result<Option<u64>, String> {
        let object = self
            .bucket(true)?
            .head(key)
            .await
            .map_err(|e| e.to_string())?;
        Ok(object.map(|o| o.size()))
    }

    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
        let bucket = self.bucket(true)?;
        let mut get = bucket.get(key);
        if let Some(r) = range {
            get = get.range(worker::Range::OffsetWithLength {
                offset: r.start,
                length: r.end - r.start,
            });
        }
        let Some(object) = get.execute().await.map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let body = object.body().ok_or("object has no body")?;
        let stream = body.stream().map_err(|e| e.to_string())?;
        let stream = stream.map(|piece| piece.map(Bytes::from).map_err(|e| e.to_string()));
        Ok(Some((object.size(), Box::pin(stream))))
    }

    async fn get_range_etag(
        &self,
        key: &str,
        range: Range<u64>,
        etag: Option<&str>,
    ) -> Result<RangeRead, String> {
        let bucket = self.bucket(true)?;
        let mut get = bucket.get(key).range(worker::Range::OffsetWithLength {
            offset: range.start,
            length: range.end - range.start,
        });
        if let Some(etag) = etag {
            get = get.only_if(worker::Conditional {
                etag_matches: Some(etag.to_owned()),
                ..Default::default()
            });
        }
        let Some(object) = get.execute().await.map_err(|e| e.to_string())? else {
            return Ok(RangeRead::Absent);
        };
        // A failed condition answers the object's metadata without a body.
        let Some(body) = object.body() else {
            return Ok(RangeRead::EtagChanged);
        };
        Ok(RangeRead::Bytes {
            bytes: body.bytes().await.map_err(|e| e.to_string())?,
            etag: object.etag(),
        })
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.bucket(false)?
            .delete(key)
            .await
            .map_err(|e| e.to_string())
    }

    async fn list(&self, prefix: &str, cursor: Option<&str>) -> Result<ObjectPage, String> {
        let bucket = self.bucket(false)?;
        let mut listing = bucket.list().prefix(prefix).limit(1000);
        if let Some(cursor) = cursor {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await.map_err(|e| e.to_string())?;
        Ok(ObjectPage {
            keys: page.objects().iter().map(worker::Object::key).collect(),
            cursor: page.cursor(),
        })
    }

    async fn delete_many(&self, keys: Vec<String>) -> Result<(), String> {
        self.bucket(false)?
            .delete_multiple(keys)
            .await
            .map_err(|e| e.to_string())
    }

    async fn create_object_upload(&self, key: &str) -> Result<String, String> {
        let upload = self
            .bucket(false)?
            .create_multipart_upload(key)
            .execute()
            .await
            .map_err(|e| e.to_string())?;
        Ok(upload.upload_id().await)
    }

    fn spawn_object_part(
        &self,
        key: String,
        upload: String,
        number: u16,
        len: u64,
        body: PutBody,
    ) -> oneshot::Receiver<Result<String, String>> {
        let (tx, rx) = oneshot::channel();
        let bucket = self.bucket(false);
        worker::wasm_bindgen_futures::spawn_local(async move {
            let result = async move {
                let body = body.map(|item| {
                    item.map(Vec::from)
                        .map_err(|_| worker::Error::RustError("upload aborted".into()))
                });
                let upload = bucket?
                    .resume_multipart_upload(key, upload)
                    .map_err(|e| e.to_string())?;
                let part = upload
                    .upload_part(number, worker::FixedLengthStream::wrap(body, len))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(part.etag())
            }
            .await;
            let _ = tx.send(result);
        });
        rx
    }

    async fn complete_object_upload(
        &self,
        key: &str,
        upload: &str,
        parts: Vec<(u16, String)>,
    ) -> Result<(), String> {
        self.bucket(false)?
            .resume_multipart_upload(key, upload)
            .map_err(|e| e.to_string())?
            .complete(
                parts
                    .into_iter()
                    .map(|(number, etag)| worker::UploadedPart::new(number, etag)),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn abort_object_upload(&self, key: &str, upload: &str) -> Result<(), String> {
        self.bucket(false)?
            .resume_multipart_upload(key, upload)
            .map_err(|e| e.to_string())?
            .abort()
            .await
            .map_err(|e| e.to_string())
    }

    async fn probe(&self) -> Result<(), String> {
        crate::ns_client::charge_request(self.request_budget.as_ref())
            .map_err(|e| e.to_string())?;
        if mkit_worker_common::health::r2_head_probe(&self.env, self.binding).await {
            Ok(())
        } else {
            Err("r2 head probe failed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::executor::block_on;
    use futures::future::BoxFuture;
    use mkit_core::hash::hash;

    use super::*;

    fn key_of(bytes: &[u8]) -> BlobKey {
        BlobKey::pack(hash(bytes))
    }

    #[test]
    fn withheld_final_chunk_logic() {
        let data: Vec<u8> = (0..=255_u8).cycle().take(10_000).collect();
        let chunks: Vec<Bytes> = data.chunks(1000).map(Bytes::copy_from_slice).collect();
        // Right key: every byte but the last forwards as it arrives, and
        // no forwarded piece is larger than the chunk that carried it.
        let mut w = Withheld::new(key_of(&data), data.len() as u64);
        let mut forwarded = Vec::new();
        for chunk in &chunks {
            let out = w.push(chunk.clone()).unwrap();
            assert!(out.len() <= chunk.len());
            assert!(w.last.as_ref().is_none_or(|b| b.len() == 1));
            forwarded.extend_from_slice(&out);
        }
        assert_eq!(forwarded, data[..data.len() - 1]);
        assert_eq!(w.finish(None).unwrap().unwrap(), data[data.len() - 1..]);
        // Wrong key: the same bytes forward, the last byte never does.
        let mut w = Withheld::new(key_of(b"other"), data.len() as u64);
        let mut forwarded = 0;
        for chunk in &chunks {
            forwarded += w.push(chunk.clone()).unwrap().len();
        }
        assert_eq!(forwarded, data.len() - 1);
        assert!(matches!(w.finish(None), Err(StoreError::Invalid(_))));
        // Short and long bodies.
        let mut w = Withheld::new(key_of(&data), data.len() as u64 + 1);
        for chunk in &chunks {
            w.push(chunk.clone()).unwrap();
        }
        assert!(w.last.is_none(), "nothing is withheld before the end");
        assert!(matches!(w.finish(None), Err(StoreError::Invalid(_))));
        let mut w = Withheld::new(key_of(b"ab"), 1);
        assert!(matches!(
            w.push(Bytes::from_static(b"ab")),
            Err(StoreError::Invalid(_))
        ));
        // The empty blob withholds nothing and verifies against BLAKE3("").
        let mut w = Withheld::new(key_of(b""), 0);
        assert!(w.push(Bytes::new()).unwrap().is_empty());
        assert_eq!(w.finish(None).unwrap(), None);
    }

    /// A bucket whose put consumer runs on its own thread (`spawn`), or
    /// is parked unpolled (the deadlock R-67 guards against).
    #[derive(Clone)]
    struct ModelBucket {
        spawn: bool,
        parked: Arc<Mutex<Vec<BoxFuture<'static, ()>>>>,
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl ModelBucket {
        fn new(spawn: bool) -> Self {
            Self {
                spawn,
                parked: Arc::default(),
                received: Arc::default(),
            }
        }
    }

    impl ObjectBucket for ModelBucket {
        fn spawn_put(
            &self,
            _key: String,
            len: u64,
            mut body: PutBody,
        ) -> oneshot::Receiver<PutResult> {
            let (tx, rx) = oneshot::channel();
            let received = self.received.clone();
            let consume = async move {
                let mut n = 0;
                while let Some(Ok(chunk)) = body.next().await {
                    n += chunk.len() as u64;
                    received.lock().unwrap().extend_from_slice(&chunk);
                }
                let _ = tx.send(if n == len {
                    Ok(true)
                } else {
                    Err("short".into())
                });
            };
            if self.spawn {
                std::thread::spawn(move || block_on(consume));
            } else {
                self.parked.lock().unwrap().push(Box::pin(consume));
            }
            rx
        }

        async fn head(&self, _key: &str) -> Result<Option<u64>, String> {
            Ok(None)
        }

        async fn get(
            &self,
            _key: &str,
            _range: Option<Range<u64>>,
        ) -> Result<Option<(u64, ObjectStream)>, String> {
            Ok(None)
        }

        async fn delete(&self, _key: &str) -> Result<(), String> {
            Ok(())
        }

        async fn list(&self, _prefix: &str, _cursor: Option<&str>) -> Result<ObjectPage, String> {
            Ok(ObjectPage {
                keys: Vec::new(),
                cursor: None,
            })
        }

        async fn delete_many(&self, _keys: Vec<String>) -> Result<(), String> {
            Ok(())
        }

        async fn probe(&self) -> Result<(), String> {
            Ok(())
        }
    }

    /// Upload 8 chunks (the channel holds 1) on a thread; whether it
    /// finished within `wait`.
    fn upload_finishes(bucket: &ModelBucket, wait: Duration) -> bool {
        let data: Vec<u8> = (0..8 * 4096_u32).map(|i| i.to_le_bytes()[0]).collect();
        let store = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = block_on(async {
                let mut sink = store.begin(key_of(&data), data.len() as u64).await?;
                for chunk in data.chunks(4096) {
                    sink.write(Bytes::copy_from_slice(chunk)).await?;
                }
                sink.commit().await
            });
            let _ = done_tx.send((result.map_err(|e| e.to_string()), data));
        });
        match done_rx.recv_timeout(wait) {
            Ok((result, data)) => {
                assert_eq!(result.unwrap(), CommitOutcome::Created);
                assert_eq!(*bucket.received.lock().unwrap(), data);
                true
            }
            Err(_) => false,
        }
    }

    #[test]
    fn put_is_driven_while_writing() {
        assert!(upload_finishes(
            &ModelBucket::new(true),
            Duration::from_mins(1)
        ));
        // Unspawned, the put would only start at commit: the second chunk
        // blocks on the full channel forever.
        let parked = ModelBucket::new(false);
        assert!(!upload_finishes(&parked, Duration::from_millis(300)));
        assert_eq!(parked.parked.lock().unwrap().len(), 1);
    }

    #[test]
    fn pieces_rechunk_and_check_length() {
        let big = Bytes::from(vec![7_u8; MAX_BLOB_PIECE_BYTES * 2 + 3]);
        let read = |pieces: Vec<Result<Bytes, String>>, len| {
            let stream: ObjectStream = Box::pin(futures::stream::iter(pieces));
            block_on(Pieces::new(stream, len).collect::<Vec<_>>())
        };
        let out = read(vec![Ok(big.clone())], big.len() as u64);
        let sizes: Vec<usize> = out.iter().map(|p| p.as_ref().unwrap().len()).collect();
        assert_eq!(sizes, [MAX_BLOB_PIECE_BYTES, MAX_BLOB_PIECE_BYTES, 3]);
        for (pieces, len) in [
            (vec![Ok(big.clone())], big.len() as u64 + 1),
            (vec![Ok(big.clone())], big.len() as u64 - 1),
            (vec![Err("reset".to_owned())], 1),
        ] {
            let out = read(pieces, len);
            assert!(matches!(out.last(), Some(Err(StoreError::Unavailable(_)))));
        }
        assert!(read(vec![], 0).is_empty());
    }
}
