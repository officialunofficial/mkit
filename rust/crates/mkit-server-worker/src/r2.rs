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
//! the key exists: [`CommitOutcome::AlreadyPresent`]. Memory per upload is
//! the chunk in flight plus one in the channel.
//!
//! **Limits.** R2 allows about one write per second per key; a concurrent
//! writer of the same key can make a put fail (HTTP 429). Because a key only
//! ever holds verified bytes, a failed put whose key is then present is
//! `AlreadyPresent`; otherwise it is `Unavailable`, and the client retries.
//! `max_bytes` (64 MiB by default) caps one put's declared length: a
//! **documented M1 stopgap** (PRD §8 M0), a counter and not a buffer. M1
//! replaces it with resumable multipart parts (WP-1.11), which carry R2's
//! own rules: every part but the last at least 5 MiB and all the same size,
//! incomplete uploads aborted by a 7-day lifecycle rule, and the upload
//! completed only after verification (PRD §5.3).
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
#[cfg(feature = "test-faults")]
use std::sync::Arc;
#[cfg(feature = "test-faults")]
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use futures::channel::{mpsc, oneshot};
use futures::{SinkExt as _, Stream, StreamExt as _};
use mkit_core::hash::Hasher;
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

/// The object-store operations [`R2BlobStore`] needs: R2 on Workers
/// (`EnvBucket`, wasm32), a simulation in tests. Errors carry the backend's
/// detail, which the store logs and never returns.
pub trait ObjectBucket: MaybeSend + MaybeSync + Clone + 'static {
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

    /// Remove the object; absent is not an error.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), String>> + MaybeSend;

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
    #[cfg(feature = "test-faults")]
    fail_final: Arc<AtomicBool>,
}

impl<B: ObjectBucket> R2BlobStore<B> {
    /// A store for `keyspace` ([`PACKS_KEYSPACE`] for pack uploads), capped
    /// at [`DEFAULT_MAX_BYTES`] per blob.
    #[must_use]
    pub fn new(bucket: B, keyspace: &'static str) -> Self {
        Self {
            bucket,
            keyspace,
            max_bytes: DEFAULT_MAX_BYTES,
            #[cfg(feature = "test-faults")]
            fail_final: Arc::default(),
        }
    }

    /// Cap one blob at `max_bytes` instead.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// The object key of `key`: `<keyspace>/<hex>`.
    #[must_use]
    pub fn object_key(&self, key: &BlobKey) -> String {
        format!("{}/{}", self.keyspace, key.to_hex())
    }

    /// Fail the next commit at its withheld final byte, after the hash
    /// verified: the put fails and nothing becomes visible (`test-faults`).
    #[cfg(feature = "test-faults")]
    pub fn fail_final_chunk_once(&self) {
        self.fail_final.store(true, Ordering::SeqCst);
    }
}

/// The hashing, length-checking core of an upload: every chunk is hashed
/// and forwarded except the blob's last byte, which [`Self::finish`]
/// releases only if the bytes verify.
#[derive(Debug)]
struct Withheld {
    key: BlobKey,
    len: u64,
    received: u64,
    hasher: Hasher,
    last: Option<Bytes>,
}

impl Withheld {
    fn new(key: BlobKey, len: u64) -> Self {
        Self {
            key,
            len,
            received: 0,
            hasher: Hasher::new(),
            last: None,
        }
    }

    /// Hash `chunk`; the part to forward now. The chunk that completes the
    /// declared length keeps its last byte back.
    fn push(&mut self, mut chunk: Bytes) -> Result<Bytes, StoreError> {
        let total = self.received.saturating_add(chunk.len() as u64);
        if total > self.len {
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        }
        self.hasher.update(&chunk);
        self.received = total;
        if total == self.len && !chunk.is_empty() {
            self.last = Some(chunk.split_off(chunk.len() - 1));
        }
        Ok(chunk)
    }

    /// The withheld byte, if every byte arrived and hashes to the key.
    fn finish(&mut self) -> Result<Option<Bytes>, StoreError> {
        if self.received != self.len {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        if self.hasher.finalize() != self.key.0 {
            return Err(StoreError::Invalid(
                "blob hash does not match its key".into(),
            ));
        }
        Ok(self.last.take())
    }
}

/// The spawned put behind a sink.
#[derive(Debug)]
struct Running {
    tx: Option<mpsc::Sender<Result<Bytes, BodyAborted>>>,
    done: oneshot::Receiver<PutResult>,
}

impl Running {
    fn spawn<B: ObjectBucket>(bucket: &B, object: String, len: u64) -> Self {
        // Buffer 0 plus one slot per sender: depth 1.
        let (tx, rx) = mpsc::channel(0);
        Self {
            tx: Some(tx),
            done: bucket.spawn_put(object, len, rx),
        }
    }

    /// Fail the body and wait for the put to end, so nothing it wrote can
    /// appear after this returns.
    async fn fail(mut self) {
        if let Some(mut tx) = self.tx.take() {
            // A full channel is fine: closing it short fails the put too.
            let _ = tx.try_send(Err(BodyAborted));
        }
        let _ = self.done.await;
    }
}

/// The upload handle of [`R2BlobStore`].
#[derive(Debug)]
pub struct R2PackSink<B> {
    bucket: B,
    object: String,
    core: Withheld,
    /// `None` for an empty blob, whose put starts only at commit.
    put: Option<Running>,
    failed: bool,
    #[cfg(feature = "test-faults")]
    fail_final: Arc<AtomicBool>,
}

impl<B: ObjectBucket> R2PackSink<B> {
    async fn send(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if chunk.is_empty() {
            return Ok(());
        }
        let Some(tx) = self.put.as_mut().and_then(|p| p.tx.as_mut()) else {
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        };
        if tx.send(Ok(chunk)).await.is_ok() {
            return Ok(());
        }
        // The put ended early; its outcome says why.
        self.failed = true;
        let detail = match self.put.take() {
            Some(p) => match p.done.await {
                Ok(Err(detail)) => detail,
                Ok(Ok(_)) => "put finished before its body".into(),
                Err(_) => "put task dropped".into(),
            },
            None => "no put".into(),
        };
        Err(backend_error(StorageOp::BlobPut, detail))
    }

    async fn fail(&mut self) {
        if let Some(put) = self.put.take() {
            put.fail().await;
        }
    }
}

impl<B: ObjectBucket> BlobStore for R2BlobStore<B> {
    type Sink = R2PackSink<B>;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<R2PackSink<B>, StoreError> {
        if len > self.max_bytes {
            return Err(StoreError::Invalid(
                "blob exceeds the store's size cap".into(),
            ));
        }
        let object = self.object_key(&key);
        let put = (len > 0).then(|| Running::spawn(&self.bucket, object.clone(), len));
        Ok(R2PackSink {
            bucket: self.bucket.clone(),
            object,
            core: Withheld::new(key, len),
            put,
            failed: false,
            #[cfg(feature = "test-faults")]
            fail_final: self.fail_final.clone(),
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let object = self.object_key(key);
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
            .head_len(&self.object_key(key))
            .await?
            .map(|len| BlobMeta { len }))
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.bucket
            .probe()
            .await
            .map_err(|e| backend_error(StorageOp::BlobHead, e))
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        let object = self.object_key(key);
        if self.head_len(&object).await?.is_none() {
            return Ok(false);
        }
        self.bucket
            .delete(&object)
            .await
            .map_err(|e| backend_error(StorageOp::BlobPut, e))?;
        Ok(true)
    }
}

impl<B: ObjectBucket> R2BlobStore<B> {
    async fn head_len(&self, object: &str) -> Result<Option<u64>, StoreError> {
        self.bucket
            .head(object)
            .await
            .map_err(|e| backend_error(StorageOp::BlobHead, e))
    }
}

impl<B: ObjectBucket> PackSink for R2PackSink<B> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("write after a failed write".into()));
        }
        match self.core.push(chunk) {
            Ok(forward) => self.send(forward).await,
            Err(e) => {
                self.failed = true;
                self.fail().await;
                Err(e)
            }
        }
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        if self.failed {
            self.fail().await;
            return Err(StoreError::Invalid("commit after a failed write".into()));
        }
        let last = match self.core.finish() {
            Ok(last) => last,
            Err(e) => {
                self.fail().await;
                return Err(e);
            }
        };
        #[cfg(feature = "test-faults")]
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
            self.send(last).await?;
        }
        let Some(mut put) = self.put.take() else {
            return Err(backend_error(StorageOp::BlobPut, "no put"));
        };
        // Close the body: every declared byte is in it.
        drop(put.tx.take());
        match put.done.await {
            Ok(Ok(true)) => Ok(CommitOutcome::Created),
            Ok(Ok(false)) => Ok(CommitOutcome::AlreadyPresent),
            Ok(Err(detail)) => {
                // A key holds only verified bytes: if it is present now (a
                // concurrent writer, R2's per-key write rate), ours are too.
                if matches!(self.bucket.head(&self.object).await, Ok(Some(n)) if n == self.core.len)
                {
                    return Ok(CommitOutcome::AlreadyPresent);
                }
                Err(backend_error(StorageOp::BlobPut, detail))
            }
            Err(_) => Err(backend_error(StorageOp::BlobPut, "put task dropped")),
        }
    }

    async fn abort(mut self) {
        self.fail().await;
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
}

#[cfg(target_arch = "wasm32")]
impl EnvBucket {
    /// The bucket bound as `binding` ([`STORAGE_BINDING`]).
    #[must_use]
    pub fn new(env: worker::Env, binding: &'static str) -> Self {
        Self { env, binding }
    }

    fn bucket(&self) -> Result<worker::Bucket, String> {
        self.env.bucket(self.binding).map_err(|e| e.to_string())
    }
}

/// The Workers blob store: packs in the `STORAGE` bucket.
#[cfg(target_arch = "wasm32")]
pub type WorkerBlobStore = R2BlobStore<EnvBucket>;

#[cfg(target_arch = "wasm32")]
impl ObjectBucket for EnvBucket {
    fn spawn_put(&self, key: String, len: u64, body: PutBody) -> oneshot::Receiver<PutResult> {
        let (tx, rx) = oneshot::channel();
        let bucket = self.bucket();
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
        let object = self.bucket()?.head(key).await.map_err(|e| e.to_string())?;
        Ok(object.map(|o| o.size()))
    }

    async fn get(
        &self,
        key: &str,
        range: Option<Range<u64>>,
    ) -> Result<Option<(u64, ObjectStream)>, String> {
        let bucket = self.bucket()?;
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

    async fn delete(&self, key: &str) -> Result<(), String> {
        self.bucket()?.delete(key).await.map_err(|e| e.to_string())
    }

    async fn probe(&self) -> Result<(), String> {
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
        BlobKey::new(hash(bytes))
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
        assert_eq!(w.finish().unwrap().unwrap(), data[data.len() - 1..]);
        // Wrong key: the same bytes forward, the last byte never does.
        let mut w = Withheld::new(key_of(b"other"), data.len() as u64);
        let mut forwarded = 0;
        for chunk in &chunks {
            forwarded += w.push(chunk.clone()).unwrap().len();
        }
        assert_eq!(forwarded, data.len() - 1);
        assert!(matches!(w.finish(), Err(StoreError::Invalid(_))));
        // Short and long bodies.
        let mut w = Withheld::new(key_of(&data), data.len() as u64 + 1);
        for chunk in &chunks {
            w.push(chunk.clone()).unwrap();
        }
        assert!(w.last.is_none(), "nothing is withheld before the end");
        assert!(matches!(w.finish(), Err(StoreError::Invalid(_))));
        let mut w = Withheld::new(key_of(b"ab"), 1);
        assert!(matches!(
            w.push(Bytes::from_static(b"ab")),
            Err(StoreError::Invalid(_))
        ));
        // The empty blob withholds nothing and verifies against BLAKE3("").
        let mut w = Withheld::new(key_of(b""), 0);
        assert!(w.push(Bytes::new()).unwrap().is_empty());
        assert_eq!(w.finish().unwrap(), None);
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
