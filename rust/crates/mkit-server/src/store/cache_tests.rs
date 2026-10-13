//! Positive-cache conformance, including untrusted and unavailable backends.
#![allow(clippy::unwrap_used)] // Invalid fixtures must fail immediately.
use super::*;
use crate::memory::{MemoryBlobStore, MemoryKv, MemoryPackSink};
use crate::{ManualClock, ManualSleep};
use futures::executor::block_on;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
enum Reply {
    Miss,
    Garbage,
    Error,
    Pending,
}

struct AdversarialCache {
    reply: Reply,
    gets: AtomicUsize,
    puts: AtomicUsize,
}

impl AdversarialCache {
    fn new(reply: Reply) -> Self {
        Self {
            reply,
            gets: AtomicUsize::new(0),
            puts: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> (usize, usize) {
        (
            self.gets.load(Ordering::SeqCst),
            self.puts.load(Ordering::SeqCst),
        )
    }
}

impl ImmutableCache for AdversarialCache {
    async fn get(&self, _: &[u8]) -> Result<Option<Bytes>, StoreError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        match self.reply {
            Reply::Miss => Ok(None),
            Reply::Garbage => Ok(Some(Bytes::from_static(b"stale garbage"))),
            Reply::Error => Err(StoreError::unavailable("cache unavailable")),
            Reply::Pending => futures::future::pending().await,
        }
    }
    async fn put(&self, _: Bytes, _: Bytes) -> Result<(), StoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        match self.reply {
            Reply::Error => Err(StoreError::unavailable("cache unavailable")),
            Reply::Pending => futures::future::pending().await,
            _ => Ok(()),
        }
    }
}

fn config() -> CacheConfig {
    CacheConfig::new(
        "test-deployment",
        Arc::new(ManualSleep::new()),
        Duration::from_millis(10),
    )
    .unwrap()
}

fn memory(clock: Arc<ManualClock>) -> MemoryImmutableCache {
    MemoryImmutableCache::new(
        4 * MAX_IMMUTABLE_CACHE_ENTRY_BYTES,
        Duration::from_secs(60),
        clock,
    )
}

struct SpyBlobs {
    inner: MemoryBlobStore,
    gets: AtomicUsize,
    heads: AtomicUsize,
    stream: bool,
}

impl SpyBlobs {
    fn new(stream: bool) -> Self {
        Self {
            inner: MemoryBlobStore::default(),
            gets: AtomicUsize::new(0),
            heads: AtomicUsize::new(0),
            stream,
        }
    }
    fn calls(&self) -> (usize, usize) {
        (
            self.gets.load(Ordering::SeqCst),
            self.heads.load(Ordering::SeqCst),
        )
    }
}

impl BlobStore for SpyBlobs {
    type Sink = MemoryPackSink;
    async fn begin(&self, key: BlobKey, len: u64) -> Result<Self::Sink, StoreError> {
        self.inner.begin(key, len).await
    }
    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        let body = self.inner.get(key, range).await?;
        if self.stream {
            if let Some(BlobBody::Bytes(bytes)) = body {
                let len = bytes.len() as u64;
                let split = bytes.len() / 2;
                let pieces = vec![Ok(bytes.slice(..split)), Ok(bytes.slice(split..))];
                return Ok(Some(BlobBody::Stream {
                    len,
                    stream: Box::pin(futures::stream::iter(pieces)),
                }));
            }
        }
        Ok(body)
    }
    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.heads.fetch_add(1, Ordering::SeqCst);
        self.inner.head(key).await
    }
    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

async fn upload<B: BlobStore>(store: &B, bytes: Bytes) -> BlobKey {
    let key = BlobKey::pack(*blake3::hash(&bytes).as_bytes());
    let mut sink = store.begin(key, bytes.len() as u64).await.unwrap();
    for piece in bytes.chunks(MAX_BLOB_PIECE_BYTES) {
        sink.write(Bytes::copy_from_slice(piece)).await.unwrap();
    }
    sink.commit().await.unwrap();
    key
}

async fn bytes(body: Option<BlobBody>) -> Bytes {
    match body.unwrap() {
        BlobBody::Bytes(bytes) => bytes,
        BlobBody::Stream { mut stream, .. } => {
            let mut bytes = Vec::new();
            while let Some(piece) = stream.next().await {
                bytes.extend_from_slice(&piece.unwrap());
            }
            Bytes::from(bytes)
        }
    }
}

async fn namespace_contract<C: ImmutableCache>(cache: C) {
    let clock = Arc::new(ManualClock::new(0));
    let store = CachingNamespaceStore::new(MemoryKv::with_clock(clock), cache, config());
    let p = Partition::ContentShard(0);
    let key = Key::new("ob/entry");
    let absent = Key::new("ob/missing");
    let old = Value::new("old");
    let new = Value::new("new");
    assert_eq!(
        store
            .apply(&p, Batch::new().put(key.clone(), old.clone()))
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(store.get(&p, &key).await.unwrap(), Some(old.clone()));
    assert_eq!(store.get(&p, &absent).await.unwrap(), None);
    store
        .inner()
        .apply(&p, Batch::new().put(key.clone(), new.clone()))
        .await
        .unwrap();
    assert_eq!(
        store
            .get_many(&p, &[key.clone(), absent.clone()])
            .await
            .unwrap(),
        vec![Some(new.clone()), None]
    );
    let range = RangeScan::new(Key::new("ob/"), Key::new("ob0"), None, 10);
    assert_eq!(
        store
            .scan(&p, &range.start, &range.end, None, 10)
            .await
            .unwrap()
            .entries,
        vec![(key.clone(), new.clone())]
    );
    assert_eq!(
        store.scan_many(&p, &[range]).await.unwrap()[0].entries,
        vec![(key.clone(), new.clone())]
    );
    assert_eq!(
        store
            .apply(
                &p,
                Batch::new()
                    .require(Precondition::Equals(key.clone(), old))
                    .delete(key.clone())
            )
            .await
            .unwrap(),
        BatchOutcome::PreconditionFailed {
            index: 0,
            observed: Some(new.clone())
        }
    );
    assert_eq!(
        store
            .apply(
                &p,
                Batch::new()
                    .require(Precondition::Absent(key.clone()))
                    .put(absent.clone(), new.clone())
            )
            .await
            .unwrap(),
        BatchOutcome::PreconditionFailed {
            index: 0,
            observed: Some(new.clone())
        }
    );
    assert_eq!(
        store
            .apply(
                &p,
                Batch::new()
                    .require(Precondition::Equals(key.clone(), new))
                    .delete(key.clone())
            )
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    assert!(!store.has(&p, &key).await.unwrap());
    assert_eq!(
        store.get_many(&p, &[key, absent]).await.unwrap(),
        vec![None, None]
    );
}

#[test]
fn namespace_live_reads_and_guarded_batches_bypass_every_cache() {
    block_on(async {
        namespace_contract(memory(Arc::new(ManualClock::new(0)))).await;
        for reply in [Reply::Garbage, Reply::Error, Reply::Pending] {
            let cache = Arc::new(AdversarialCache::new(reply));
            namespace_contract(cache.clone()).await;
            assert_eq!(cache.calls(), (0, 0));
        }
    });
}

#[test]
fn memory_pack_hits_ranges_and_physical_deletion() {
    block_on(async {
        for stream in [false, true] {
            let store = CachingBlobStore::new(
                SpyBlobs::new(stream),
                memory(Arc::new(ManualClock::new(0))),
                config(),
            );
            let expected = Bytes::from_static(b"verified pack contents");
            let key = upload(&store, expected.clone()).await;
            assert_eq!(bytes(store.get(&key, None).await.unwrap()).await, expected);
            assert_eq!(bytes(store.get(&key, None).await.unwrap()).await, expected);
            assert_eq!(store.inner().calls(), (1, 1));
            let range = ByteRange {
                start: 2,
                end_inclusive: 6,
            };
            assert_eq!(
                bytes(store.get(&key, Some(range)).await.unwrap()).await,
                expected.slice(2..7)
            );
            assert_eq!(store.inner().calls(), (1, 2));
            assert!(
                store
                    .get(
                        &key,
                        Some(ByteRange {
                            start: 99,
                            end_inclusive: 100
                        })
                    )
                    .await
                    .is_err()
            );
            assert!(store.delete(&key).await.unwrap());
            assert!(store.get(&key, None).await.unwrap().is_none());
            assert_eq!(store.inner().calls(), (1, 4));
        }
    });
}

#[test]
fn absent_blobs_and_live_namespaces_never_populate_cache() {
    block_on(async {
        let cache = Arc::new(AdversarialCache::new(Reply::Miss));
        let store = CachingBlobStore::new(SpyBlobs::new(false), cache.clone(), config());
        let hash = *blake3::hash(b"missing").as_bytes();
        for key in [
            BlobKey::pack(hash),
            BlobKey::upload_marker(hash),
            BlobKey::object(hash),
            BlobKey::object_offsets(hash),
        ] {
            assert!(store.get(&key, None).await.unwrap().is_none());
            assert!(store.get(&key, None).await.unwrap().is_none());
        }
        assert_eq!(cache.calls(), (2, 0));
        assert_eq!(store.inner().calls(), (8, 0));
    });
}

#[test]
fn garbage_hits_and_cache_errors_fall_back_to_authoritative_packs() {
    block_on(async {
        for reply in [Reply::Garbage, Reply::Error] {
            let cache = Arc::new(AdversarialCache::new(reply));
            let store = CachingBlobStore::new(SpyBlobs::new(false), cache.clone(), config());
            let expected = Bytes::from_static(b"authentic");
            let key = upload(&store, expected.clone()).await;
            assert_eq!(cache.calls(), (0, 0));
            for _ in 0..2 {
                assert_eq!(bytes(store.get(&key, None).await.unwrap()).await, expected);
            }
            assert_eq!(store.inner().calls(), (2, 0));
            assert_eq!(cache.calls(), (2, 2));
            store.head(&key).await.unwrap();
            store.delete(&key).await.unwrap();
            store.probe().await.unwrap();
            assert_eq!(cache.calls(), (2, 2));
        }
    });
}

struct ImmediateSleep;
impl Sleep for ImmediateSleep {
    fn sleep(&self, _: Duration) -> crate::rt::BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

#[test]
fn stalled_cache_get_and_put_have_bounded_deadlines() {
    block_on(async {
        let cache = Arc::new(AdversarialCache::new(Reply::Pending));
        let config = CacheConfig::new(
            "timeouts",
            Arc::new(ImmediateSleep),
            Duration::from_millis(10),
        )
        .unwrap();
        let store = CachingBlobStore::new(SpyBlobs::new(false), cache.clone(), config);
        let expected = Bytes::from_static(b"deadline pack");
        let key = upload(&store, expected.clone()).await;
        assert_eq!(bytes(store.get(&key, None).await.unwrap()).await, expected);
        assert_eq!(cache.calls(), (1, 1));
        assert_eq!(store.inner().calls(), (1, 0));
    });
}

#[test]
fn range_misses_and_large_streams_do_not_populate_cache() {
    block_on(async {
        let cache = Arc::new(AdversarialCache::new(Reply::Miss));
        let store = CachingBlobStore::new(SpyBlobs::new(false), cache.clone(), config());
        let expected = Bytes::from(vec![7; MAX_IMMUTABLE_CACHE_ENTRY_BYTES + 1]);
        let key = upload(&store, expected.clone()).await;
        let range = ByteRange {
            start: 1,
            end_inclusive: 3,
        };
        assert_eq!(
            bytes(store.get(&key, Some(range)).await.unwrap()).await,
            expected.slice(1..4)
        );
        assert_eq!(bytes(store.get(&key, None).await.unwrap()).await, expected);
        assert_eq!(cache.calls(), (2, 0));
    });
}

#[test]
fn cache_keys_separate_deployments_partitions_kinds_and_component_boundaries() {
    let a = config();
    let b = CacheConfig::new(
        "other-deployment",
        Arc::new(ManualSleep::new()),
        Duration::from_millis(10),
    )
    .unwrap();
    let key = a.key(b"namespace", b"partition-a", b"ob/key");
    assert_eq!(key, a.key(b"namespace", b"partition-a", b"ob/key"));
    assert_ne!(key, b.key(b"namespace", b"partition-a", b"ob/key"));
    assert_ne!(key, a.key(b"namespace", b"partition-b", b"ob/key"));
    assert_ne!(key, a.key(b"blob:pack", b"partition-a", b"ob/key"));
    assert_ne!(
        a.key(b"namespace", b"a", b"bc"),
        a.key(b"namespace", b"ab", b"c")
    );
}

#[test]
fn memory_lru_accounts_overhead_and_does_not_extend_ttl_on_hits() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let cache = MemoryImmutableCache::new(260, Duration::from_millis(10), clock.clone());
        for key in [b"a", b"b"] {
            cache
                .put(Bytes::copy_from_slice(key), Bytes::from_static(b"v"))
                .await
                .unwrap();
        }
        assert!(cache.get(b"a").await.unwrap().is_some());
        cache
            .put(Bytes::from_static(b"c"), Bytes::from_static(b"v"))
            .await
            .unwrap();
        assert!(cache.get(b"b").await.unwrap().is_none());
        assert!(cache.get(b"a").await.unwrap().is_some());
        clock.set(9);
        assert!(cache.get(b"a").await.unwrap().is_some());
        clock.set(10);
        assert!(cache.get(b"a").await.unwrap().is_none());
        cache
            .put(Bytes::from_static(b"oversize"), Bytes::from(vec![0; 260]))
            .await
            .unwrap();
        assert!(cache.get(b"oversize").await.unwrap().is_none());
    });
}

#[test]
fn memory_cache_disabled_capacity_ttl_and_invalid_clocks_miss() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(10));
        for (capacity, ttl) in [(0, Duration::from_secs(1)), (1024, Duration::ZERO)] {
            let cache = MemoryImmutableCache::new(capacity, ttl, clock.clone());
            cache
                .put(Bytes::from_static(b"k"), Bytes::from_static(b"v"))
                .await
                .unwrap();
            assert!(cache.get(b"k").await.unwrap().is_none());
        }
        let cache = memory(clock.clone());
        cache
            .put(Bytes::from_static(b"k"), Bytes::from_static(b"v"))
            .await
            .unwrap();
        clock.set(9);
        assert!(cache.get(b"k").await.unwrap().is_none());
        clock.set(-1);
        cache
            .put(Bytes::from_static(b"k"), Bytes::from_static(b"v"))
            .await
            .unwrap();
        assert!(cache.get(b"k").await.unwrap().is_none());
    });
}

struct StreamFixture {
    len: u64,
    pieces: Vec<Bytes>,
}

impl BlobStore for StreamFixture {
    type Sink = MemoryPackSink;
    async fn begin(&self, _: BlobKey, _: u64) -> Result<Self::Sink, StoreError> {
        Err(StoreError::Unsupported("read-only fixture".into()))
    }
    async fn get(&self, _: &BlobKey, _: Option<ByteRange>) -> Result<Option<BlobBody>, StoreError> {
        Ok(Some(BlobBody::Stream {
            len: self.len,
            stream: Box::pin(futures::stream::iter(
                self.pieces.clone().into_iter().map(Ok),
            )),
        }))
    }
    async fn head(&self, _: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        unreachable!("a miss cannot consult head")
    }
    async fn delete(&self, _: &BlobKey) -> Result<bool, StoreError> {
        Ok(false)
    }
    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[test]
fn bounded_stream_buffering_rejects_short_and_excess_bodies() {
    block_on(async {
        for (len, pieces) in [
            (3, vec![Bytes::from_static(b"ab")]),
            (1, vec![Bytes::from_static(b"ab")]),
            (0, vec![Bytes::from(vec![0; MAX_BLOB_PIECE_BYTES + 1])]),
        ] {
            let cache = Arc::new(AdversarialCache::new(Reply::Miss));
            let store =
                CachingBlobStore::new(StreamFixture { len, pieces }, cache.clone(), config());
            assert!(matches!(
                store.get(&BlobKey::pack([0; 32]), None).await,
                Err(StoreError::Invalid(_))
            ));
            assert_eq!(cache.calls(), (1, 0));
        }
    });
}

#[test]
fn unverified_store_bytes_are_returned_without_cache_publication() {
    block_on(async {
        let cache = Arc::new(AdversarialCache::new(Reply::Miss));
        let store = CachingBlobStore::new(
            StreamFixture {
                len: 3,
                pieces: vec![Bytes::from_static(b"abc")],
            },
            cache.clone(),
            config(),
        );
        assert_eq!(
            bytes(store.get(&BlobKey::pack([0; 32]), None).await.unwrap()).await,
            Bytes::from_static(b"abc")
        );
        assert_eq!(cache.calls(), (1, 0));
    });
}

#[test]
fn memory_cache_copies_slices_to_bound_retained_backing_allocations() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let cache = MemoryImmutableCache::new(130, Duration::from_secs(1), clock);
        let key_backing = Bytes::from(vec![b'k'; MAX_IMMUTABLE_CACHE_ENTRY_BYTES]);
        let value_backing = Bytes::from(vec![b'v'; MAX_IMMUTABLE_CACHE_ENTRY_BYTES]);
        let key = key_backing.slice(..1);
        let value = value_backing.slice(..1);
        cache.put(key.clone(), value.clone()).await.unwrap();
        let retained = cache.get(&key).await.unwrap().unwrap();
        assert_eq!(retained, value);
        // The caller keeps both backing buffers alive, so a distinct pointer
        // proves the backend did not retain their large allocations by cloning.
        assert_ne!(retained.as_ptr(), value.as_ptr());
        let state = cache.state.lock().unwrap();
        let retained_key = state.entries.keys().next().unwrap();
        assert_ne!(retained_key.as_ptr(), key.as_ptr());
        assert_eq!(state.bytes, 130);
    });
}

#[test]
fn memory_expiry_sweeps_physically_release_idle_entries() {
    block_on(async {
        let clock = Arc::new(ManualClock::new(0));
        let cache = MemoryImmutableCache::new(1024, Duration::from_millis(10), clock.clone());
        cache
            .put(Bytes::from_static(b"k"), Bytes::from_static(b"v"))
            .await
            .unwrap();
        clock.set(10);
        {
            let state = cache.state.lock().unwrap();
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.order.len(), 1);
            assert_eq!(state.bytes, 1 + 1 + 128);
        }
        cache.evict_expired();
        let state = cache.state.lock().unwrap();
        assert!(state.entries.is_empty());
        assert!(state.order.is_empty());
        assert_eq!(state.bytes, 0);
    });
}

#[test]
fn memory_access_and_insertion_sweep_unrelated_expired_entries() {
    block_on(async {
        for insertion in [false, true] {
            let clock = Arc::new(ManualClock::new(0));
            let cache = MemoryImmutableCache::new(1024, Duration::from_millis(10), clock.clone());
            cache
                .put(Bytes::from_static(b"old"), Bytes::from_static(b"payload"))
                .await
                .unwrap();
            clock.set(10);
            if insertion {
                cache
                    .put(Bytes::from_static(b"new"), Bytes::from_static(b"value"))
                    .await
                    .unwrap();
            } else {
                assert!(cache.get(b"unrelated miss").await.unwrap().is_none());
            }
            let state = cache.state.lock().unwrap();
            assert!(!state.entries.contains_key(b"old".as_slice()));
            assert_eq!(state.entries.len(), usize::from(insertion));
            assert_eq!(state.order.len(), usize::from(insertion));
            assert_eq!(state.bytes, if insertion { 3 + 5 + 128 } else { 0 });
        }
    });
}

#[test]
fn malformed_and_unsatisfiable_ranges_match_uncached_reads() {
    block_on(async {
        let store = CachingBlobStore::new(
            SpyBlobs::new(false),
            memory(Arc::new(ManualClock::new(0))),
            config(),
        );
        let key = upload(&store, Bytes::from_static(b"pack bytes")).await;
        assert!(store.get(&key, None).await.unwrap().is_some());
        let malformed = ByteRange {
            start: 5,
            end_inclusive: 2,
        };
        assert!(matches!(
            store.inner().get(&key, Some(malformed)).await,
            Err(StoreError::Invalid(_))
        ));
        assert!(matches!(
            store.get(&key, Some(malformed)).await,
            Err(StoreError::Invalid(_))
        ));
        let unsatisfiable = ByteRange {
            start: 10,
            end_inclusive: 10,
        };
        assert!(matches!(
            store.inner().get(&key, Some(unsatisfiable)).await,
            Err(StoreError::RangeNotSatisfiable { len: 10 })
        ));
        assert!(matches!(
            store.get(&key, Some(unsatisfiable)).await,
            Err(StoreError::RangeNotSatisfiable { len: 10 })
        ));
        store.delete(&key).await.unwrap();
        assert!(
            store
                .inner()
                .get(&key, Some(malformed))
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.get(&key, Some(malformed)).await.unwrap().is_none());
    });
}
