//! `Blocking<S>`: run a store whose bodies are synchronous on tokio's
//! blocking pool.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_executor::block_on;
use futures_util::StreamExt as _;
use mkit_server::store::MAX_BLOB_PIECE_BYTES;
use mkit_server::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, BoxStream, ByteRange,
    CommitOutcome, Cursor, Key, NamespaceStore, PackSink, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, StoreMaintenance, Value,
};

/// How long a probe result answers later probes (see [`Blocking`]).
pub const PROBE_CACHE_TTL: Duration = Duration::from_secs(1);

/// The last probe: when it ran and whether it passed.
type ProbeCache = tokio::sync::Mutex<Option<(Instant, bool)>>;

/// Runs every call of the wrapped store on `tokio::task::spawn_blocking`,
/// so its synchronous I/O (a `SQLite` transaction, a file write) never
/// stalls an async worker thread. It adapts both store contracts:
/// [`NamespaceStore`] (with [`StoreMaintenance`]) and [`BlobStore`], whose
/// upload sink and streamed bodies run on the blocking pool too.
///
/// Cancellation-safe (normative rule 4): the blocking task runs to
/// completion even if the awaiting future is dropped, so a dropped `apply`
/// commits fully or not at all, possibly after the drop. A panic in the
/// store is reported as [`StoreError::Unavailable`], and the store stays
/// usable if its own locks survive panics.
///
/// `probe` is unauthenticated work (`grpc.health.v1.Health`), so it is
/// coalesced and cached: concurrent probes share one call, and a result
/// answers every probe for [`PROBE_CACHE_TTL`]. A flood of health checks
/// costs at most one store probe per second.
///
/// The calls must run inside a tokio runtime.
pub struct Blocking<S> {
    inner: Arc<S>,
    probe: Arc<ProbeCache>,
}

impl<S> Blocking<S> {
    /// Wrap `store`.
    #[must_use]
    pub fn new(store: S) -> Self {
        Self {
            inner: Arc::new(store),
            probe: Arc::default(),
        }
    }

    /// The wrapped store, for synchronous callers.
    #[must_use]
    pub fn inner(&self) -> &Arc<S> {
        &self.inner
    }
}

impl<S> Clone for Blocking<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            probe: Arc::clone(&self.probe),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for Blocking<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Blocking").field(&self.inner).finish()
    }
}

/// Run `f` on a blocking thread; a panic or cancellation is `Unavailable`.
pub(crate) async fn on_pool<T, F>(f: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => Err(StoreError::unavailable("store call panicked")),
        Err(_) => Err(StoreError::unavailable("store call cancelled")),
    }
}

impl<S: Send + Sync + 'static> Blocking<S> {
    /// Run `f` on the store on a blocking thread.
    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&S) -> Result<T, StoreError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        on_pool(move || f(&inner)).await
    }

    /// The cached probe: `probe` runs at most once per
    /// [`PROBE_CACHE_TTL`], and concurrent callers wait for one run.
    async fn cached_probe<F>(&self, probe: F) -> Result<(), StoreError>
    where
        F: FnOnce(&S) -> Result<(), StoreError> + Send + 'static,
    {
        let mut last = self.probe.lock().await;
        let ok = match *last {
            Some((at, ok)) if at.elapsed() < PROBE_CACHE_TTL => ok,
            _ => {
                let result = self.run(probe).await;
                if let Err(e) = &result {
                    tracing::warn!(error = %e, "store probe failed");
                }
                *last = Some((Instant::now(), result.is_ok()));
                return result;
            }
        };
        if ok {
            Ok(())
        } else {
            Err(StoreError::unavailable("store probe failed (cached)"))
        }
    }
}

impl<S: NamespaceStore + Send + Sync + 'static> NamespaceStore for Blocking<S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let (p, key) = (p.clone(), key.clone());
        self.run(move |s| block_on(s.get(&p, &key))).await
    }

    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        let (p, key) = (p.clone(), key.clone());
        self.run(move |s| block_on(s.has(&p, &key))).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        let (p, keys) = (p.clone(), keys.to_vec());
        self.run(move |s| block_on(s.get_many(&p, &keys))).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let (p, start, end, after) = (p.clone(), start.clone(), end.clone(), after.cloned());
        self.run(move |s| block_on(s.scan(&p, &start, &end, after.as_ref(), limit)))
            .await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let p = p.clone();
        self.run(move |s| block_on(s.apply(&p, batch))).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        let p = p.clone();
        self.run(move |s| block_on(s.stats(&p))).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.cached_probe(|s| block_on(NamespaceStore::probe(s)))
            .await
    }
}

impl<S: StoreMaintenance + Send + Sync + 'static> StoreMaintenance for Blocking<S> {
    fn layout_version(&self) -> u32 {
        self.inner.layout_version()
    }

    async fn migrate(&self) -> Result<u32, StoreError> {
        self.run(|s| block_on(s.migrate())).await
    }

    async fn backup_to(&self, dest: &str) -> Result<(), StoreError> {
        let dest = dest.to_owned();
        self.run(move |s| block_on(s.backup_to(&dest))).await
    }
}

/// The upload sink of a [`Blocking`] blob store: each call moves the inner
/// sink onto a blocking thread and back. If the awaiting future is dropped
/// mid-call, the inner sink is dropped on that thread, which leaves nothing
/// visible (the [`PackSink`] contract), and later calls fail
/// `Unavailable`.
pub struct BlockingSink<K> {
    inner: Option<K>,
}

impl<K> fmt::Debug for BlockingSink<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingSink")
            .field("open", &self.inner.is_some())
            .finish()
    }
}

fn sink_gone() -> StoreError {
    StoreError::unavailable("upload sink lost to a cancelled call")
}

impl<K: PackSink + 'static> PackSink for BlockingSink<K> {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        let mut sink = self.inner.take().ok_or_else(sink_gone)?;
        let (sink, result) = on_pool(move || {
            let result = block_on(sink.write(chunk));
            Ok((sink, result))
        })
        .await?;
        self.inner = Some(sink);
        result
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        let sink = self.inner.take().ok_or_else(sink_gone)?;
        on_pool(move || block_on(sink.commit())).await
    }

    async fn abort(mut self) {
        if let Some(sink) = self.inner.take() {
            // Nothing to report: an abort that fails leaves nothing visible
            // either.
            let _ = on_pool(move || {
                block_on(sink.abort());
                Ok(())
            })
            .await;
        }
    }
}

/// `stream`, each piece read on a blocking thread.
fn stream_on_pool(
    stream: BoxStream<'static, Result<Bytes, StoreError>>,
) -> BoxStream<'static, Result<Bytes, StoreError>> {
    let pieces = futures_util::stream::unfold(Some(stream), |state| async move {
        let mut stream = state?;
        match on_pool(move || Ok(block_on(async { (stream.next().await, stream) }))).await {
            Ok((Some(piece), stream)) => Some((piece, Some(stream))),
            Ok((None, _)) => None,
            // The read thread panicked: end the body with the error.
            Err(e) => Some((Err(e), None)),
        }
    });
    Box::pin(pieces)
}

impl<S: BlobStore + Send + Sync + 'static> BlobStore for Blocking<S>
where
    S::Sink: 'static,
{
    type Sink = BlockingSink<S::Sink>;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        let sink = self.run(move |s| block_on(s.begin(key, len))).await?;
        Ok(BlockingSink { inner: Some(sink) })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let key = *key;
        let body = self.run(move |s| block_on(s.get(&key, range))).await?;
        Ok(body.map(|body| match body {
            // A body over `MAX_BLOB_PIECE_BYTES` is always a stream.
            BlobBody::Bytes(bytes) => {
                debug_assert!(bytes.len() <= MAX_BLOB_PIECE_BYTES);
                BlobBody::Bytes(bytes)
            }
            BlobBody::Stream { len, stream } => BlobBody::Stream {
                len,
                stream: stream_on_pool(stream),
            },
        }))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        let key = *key;
        self.run(move |s| block_on(s.head(&key))).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.cached_probe(|s| block_on(BlobStore::probe(s))).await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        let key = *key;
        self.run(move |s| block_on(s.delete(&key))).await
    }
}
