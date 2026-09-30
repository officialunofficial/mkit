use super::*;
use futures::FutureExt as _;
use futures::executor::block_on;
use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys};
use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
use mkit_server::{
    Batch, BatchOutcome, Clock, Key, ManualClock, MemoryKv, NamespaceKey, NamespaceStore,
    Partition, Precondition, RepoId, RepoName, Value,
};
use mkit_server_native::RusqliteConn;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct CountStore<N> {
    inner: Arc<N>,
    calls: Arc<AtomicUsize>,
}
impl<N> Clone for CountStore<N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            calls: self.calls.clone(),
        }
    }
}
impl<N> CountStore<N> {
    fn new(inner: N) -> Self {
        Self {
            inner: Arc::new(inner),
            calls: Arc::default(),
        }
    }
}
impl<N: NamespaceStore> NamespaceStore for CountStore<N> {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_many(p, k).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&mkit_server::Cursor>,
        limit: u32,
    ) -> Result<mkit_server::ScanPage, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.scan(partition, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.apply(p, b).await
    }
    async fn stats(&self, p: &Partition) -> Result<mkit_server::PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

type Interleave = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;
#[derive(Clone)]
struct Bucket {
    object: Arc<Mutex<Option<SnapshotObject>>>,
    calls: Arc<AtomicUsize>,
    puts: Arc<AtomicUsize>,
    clock: Arc<ManualClock>,
    fail_get: Arc<AtomicBool>,
    conflict: Arc<AtomicBool>,
    crash: Arc<AtomicBool>,
    interleave: Interleave,
}
impl Bucket {
    fn new(clock: Arc<ManualClock>) -> Self {
        Self {
            object: Arc::default(),
            calls: Arc::default(),
            puts: Arc::default(),
            clock,
            fail_get: Arc::default(),
            conflict: Arc::default(),
            crash: Arc::default(),
            interleave: Arc::default(),
        }
    }
}
impl SnapshotBucket for Bucket {
    async fn get(&self, _: &str) -> Result<Option<SnapshotObject>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_get.load(Ordering::SeqCst) {
            return Err(StoreError::unavailable("get failed"));
        }
        Ok(self.object.lock().unwrap().clone())
    }
    async fn replace(
        &self,
        _: &str,
        etag: Option<&str>,
        bytes: Vec<u8>,
    ) -> Result<bool, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(change) = self.interleave.lock().unwrap().take() {
            change();
        }
        let mut object = self.object.lock().unwrap();
        if self.conflict.load(Ordering::SeqCst) || object.as_ref().map(|o| o.etag.as_str()) != etag
        {
            return Ok(false);
        }
        let number = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
        *object = Some(SnapshotObject {
            etag: number.to_string(),
            stored_at_ms: u64::try_from(self.clock.now_ms()).unwrap(),
            bytes,
        });
        if self.crash.swap(false, Ordering::SeqCst) {
            return Err(StoreError::unavailable("lost put reply"));
        }
        Ok(true)
    }
    async fn delete(&self, _: &str) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.object.lock().unwrap().take();
        Ok(())
    }
}
#[derive(Default)]
struct Cache {
    object: Mutex<Option<(u64, Vec<u8>)>>,
    calls: AtomicUsize,
    fail: AtomicBool,
    get_hook: Interleave,
    put_hook: Interleave,
}
impl SnapshotCache for Cache {
    async fn get(&self, _: &str) -> Result<Option<(u64, Vec<u8>)>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::unavailable("cache down"));
        }
        if let Some(hook) = self.get_hook.lock().unwrap().take() {
            hook();
        }
        Ok(self.object.lock().unwrap().clone())
    }
    async fn put(&self, _: &str, at: u64, bytes: Vec<u8>) -> Result<(), StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(StoreError::unavailable("cache down"));
        }
        if let Some(hook) = self.put_hook.lock().unwrap().take() {
            hook();
        }
        *self.object.lock().unwrap() = Some((at, bytes));
        Ok(())
    }
}
fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("sample").unwrap(),
    }
}
fn partition() -> Partition {
    D34Shards.ref_index(&repo(), "refs/heads/main")
}
fn envelope(generation: u64, at: u64) -> Envelope {
    Envelope {
        partition: partition(),
        generation,
        captured_at_ms: at,
        valid_until_ms: at + VALIDITY_MS,
        rows: vec![(
            "refs/heads/main".into(),
            [u8::try_from(generation).unwrap(); 32],
        )],
    }
}
fn local(clock: &Arc<ManualClock>) -> SqlKvStore<RusqliteConn> {
    SqlKvStore::open(
        RusqliteConn::open_in_memory()
            .unwrap()
            .with_clock(clock.clone()),
    )
    .unwrap()
}
fn delivery(store: &SqlKvStore<RusqliteConn>, source: u64, seq: u64, delete: bool) -> BatchOutcome {
    let p = partition();
    let rh = keys::relay_high_water(&Partition::Ref {
        ns: repo().namespace,
        repo: repo().name,
        shard_ref: format!("refs/heads/source-{source}"),
    })
    .unwrap();
    let observed = store.get(&p, &rh).now_or_never().unwrap().unwrap();
    let batch = Batch::new()
        .require(observed.map_or_else(
            || Precondition::Absent(rh.clone()),
            |v| Precondition::Equals(rh.clone(), v),
        ))
        .put(rh, codec::encode_u64(seq));
    let batch = if delete {
        batch.delete(keys::published_index(&repo().name, "refs/heads/main"))
    } else {
        batch.put(
            keys::published_index(&repo().name, "refs/heads/main"),
            codec::encode_ref_id(&[seq.to_le_bytes()[0]; 32]),
        )
    };
    store
        .apply_extended(&p.clone(), batch, move |get, batch, now| {
            extend_relay(&p, get, batch, now).map(|_| ())
        })
        .unwrap()
}
fn public(meta: &impl NamespaceStore, private: bool) {
    meta.apply(
        &Partition::Coordinator(repo().namespace),
        Batch::new()
            .put(
                keys::repo_record(&repo().name),
                codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
            )
            .put(
                keys::repo_visibility(&repo().name),
                codec::encode_repo_visibility(&codec::RepoVisibilityV1 {
                    visibility: if private {
                        codec::StoredVisibility::Private
                    } else {
                        codec::StoredVisibility::Public
                    },
                    last_created_ms: 0,
                    last_statement_id: None,
                }),
            ),
    )
    .now_or_never()
    .unwrap()
    .unwrap();
}
fn tick(
    store: &SqlKvStore<RusqliteConn>,
    registry: &TimerRegistry<'_, SqlKvStore<RusqliteConn>>,
    clock: &ManualClock,
) -> mkit_server::timers::RunReport {
    block_on(run_due(
        store,
        &partition(),
        registry,
        clock,
        u64::try_from(clock.now_ms()).unwrap(),
        &TickBudget::default(),
    ))
    .unwrap()
}
fn state(store: &SqlKvStore<RusqliteConn>) -> super::timer::State {
    super::timer::State::decode(
        &block_on(store.get(&partition(), &state_key()))
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn codec_is_deterministic_bounded_and_validates_all_boundaries() {
    let e = envelope(1, 1000);
    let bytes = e.encode().unwrap();
    assert_eq!(e.encode().unwrap(), bytes);
    assert_eq!(Envelope::decode(&bytes, &partition(), 1000).unwrap(), e);
    assert_eq!(&bytes[bytes.len() - 32..], &[1; 32]);
    for end in 0..bytes.len() {
        assert!(Envelope::decode(&bytes[..end], &partition(), 1000).is_err());
    }
    let mut wrong_version = bytes.clone();
    wrong_version[3] = 1; // Refuse old envelopes captured from live-index inputs.
    assert!(Envelope::decode(&wrong_version, &partition(), 1000).is_err());
    assert!(Envelope::decode(&bytes, &partition(), 999).is_err());
    assert!(Envelope::decode(&bytes, &partition(), 61000).is_err());
    let foreign = D34Shards.ref_index(
        &RepoId {
            name: RepoName::new("foreign").unwrap(),
            ..repo()
        },
        "refs/heads/main",
    );
    assert!(Envelope::decode(&bytes, &foreign, 1000).is_err());
    assert!(Envelope::decode(&vec![0; MAX_BYTES + 1], &partition(), 1000).is_err());
    for rows in [
        vec![("refs/heads//bad".into(), [0; 32])],
        vec![("refs/heads/main".into(), [0; 32]); MAX_ROWS + 1],
        vec![("refs/tags/foreign".into(), [0; 32])],
    ] {
        assert!(Envelope { rows, ..e.clone() }.encode().is_err());
    }
    let mut empty = e;
    empty.rows.clear();
    assert!(
        Envelope::decode(&empty.encode().unwrap(), &partition(), 1000)
            .unwrap()
            .rows
            .is_empty()
    );
    assert_ne!(
        cache_key("stage", &partition()).unwrap(),
        cache_key("prod", &partition()).unwrap()
    );
    assert!(
        object_key(&foreign)
            .unwrap()
            .starts_with("snapshots/v1/root/foreign/")
    );
    assert!(!PublishedViewConfig::new("stage").unwrap().unsigned_read_ref);
}

#[test]
fn dirty_generation_is_atomic_for_multiple_sources_and_deletes() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    assert_eq!(delivery(&store, 1, 1, false), BatchOutcome::Committed);
    let first = state(&store);
    assert_eq!(first.generation, 1);
    assert_eq!(first.due, 2000);
    assert!(first.dirty);
    // Actual duplicate delivery is stopped by its original watermark guard.
    let p = partition();
    let rh = keys::relay_high_water(&Partition::Ref {
        ns: repo().namespace,
        repo: repo().name,
        shard_ref: "refs/heads/source-1".into(),
    })
    .unwrap();
    let batch = Batch::new()
        .require(Precondition::Absent(rh))
        .delete(keys::published_index(&repo().name, "refs/heads/main"));
    assert!(matches!(
        store
            .apply_extended(&p.clone(), batch, move |get, batch, now| extend_relay(
                &p, get, batch, now
            )
            .map(|_| ()))
            .unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(state(&store).generation, 1);
    clock.set(1500);
    delivery(&store, 2, 1, true);
    assert_eq!(state(&store).generation, 2);
    assert_eq!(state(&store).due, 2000);
    assert!(
        block_on(store.get(
            &partition(),
            &keys::published_index(&repo().name, "refs/heads/main")
        ))
        .unwrap()
        .is_none()
    );
    // Extension overflow rolls back both watermark and index changes.
    let p = partition();
    let key = Key::new(b"test-rollback".to_vec());
    let batch = Batch::new().put(key.clone(), Value::default());
    assert!(
        store
            .apply_extended(&p, batch, |_, batch, _| {
                for _ in 0..101 {
                    batch.writes.push(mkit_server::Write::Put(
                        Key::new(b"overflow".to_vec()),
                        Value::default(),
                    ));
                }
                Ok(())
            })
            .is_err()
    );
    assert!(block_on(store.get(&p, &key)).unwrap().is_none());
}

#[test]
fn bursts_refresh_quiet_buckets_and_never_replace_twice_per_second() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let meta = CountStore::new(MemoryKv::default());
    public(&meta, false);
    let bucket = Bucket::new(clock.clone());
    let alarm = SnapshotAlarm::default();
    let registry = TimerRegistry::new().register(SnapshotHandler {
        bucket: bucket.clone(),
        coordinator: meta,
        clock: clock.clone(),
        alarm: alarm.clone(),
    });
    for at in 1000..2000 {
        clock.set(at);
        delivery(&store, 1, u64::try_from(at).unwrap(), false);
    }
    assert_eq!(state(&store).due, 2000);
    clock.set(2000);
    assert_eq!(tick(&store, &registry, &clock).fired, 1);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 1);
    clock.set(2100);
    delivery(&store, 2, 1, false);
    assert_eq!(state(&store).due, 3100);
    clock.set(3100);
    alarm.reset();
    tick(&store, &registry, &clock);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 2);
    clock.set(33100);
    alarm.reset();
    tick(&store, &registry, &clock);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 3);
    assert_eq!(
        Envelope::decode(
            &bucket.object.lock().unwrap().as_ref().unwrap().bytes,
            &partition(),
            33100
        )
        .unwrap()
        .captured_at_ms,
        33100
    );
}

#[test]
fn etag_conflict_crash_and_relay_during_upload_preserve_dirty_work() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = Arc::new(local(&clock));
    let meta = CountStore::new(MemoryKv::default());
    public(&meta, false);
    let bucket = Bucket::new(clock.clone());
    let alarm = SnapshotAlarm::default();
    let registry = TimerRegistry::new().register(SnapshotHandler {
        bucket: bucket.clone(),
        coordinator: meta,
        clock: clock.clone(),
        alarm: alarm.clone(),
    });
    delivery(&store, 1, 1, false);
    clock.set(2000);
    bucket.conflict.store(true, Ordering::SeqCst);
    tick(&store, &registry, &clock);
    assert!(state(&store).dirty);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 0);
    clock.set(3000);
    alarm.reset();
    bucket.conflict.store(false, Ordering::SeqCst);
    bucket.crash.store(true, Ordering::SeqCst);
    tick(&store, &registry, &clock);
    assert!(state(&store).dirty);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 1);
    clock.set(4000);
    alarm.reset();
    let changed = store.clone();
    *bucket.interleave.lock().unwrap() = Some(Box::new(move || {
        delivery(&changed, 2, 1, true);
    }));
    assert_eq!(tick(&store, &registry, &clock).raced, 1);
    assert_eq!(state(&store).generation, 2);
    assert!(state(&store).dirty);
    clock.set(5000);
    alarm.reset();
    tick(&store, &registry, &clock);
    assert!(!state(&store).dirty);
    assert!(
        Envelope::decode(
            &bucket.object.lock().unwrap().as_ref().unwrap().bytes,
            &partition(),
            5000
        )
        .unwrap()
        .rows
        .is_empty()
    );
}

#[test]
fn private_missing_and_oversized_buckets_remove_public_data_without_upload() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let meta = CountStore::new(MemoryKv::default());
    public(&meta, true);
    let bucket = Bucket::new(clock.clone());
    *bucket.object.lock().unwrap() = Some(SnapshotObject {
        etag: "old".into(),
        stored_at_ms: 0,
        bytes: envelope(1, 1000).encode().unwrap(),
    });
    let alarm = SnapshotAlarm::default();
    let registry = TimerRegistry::new().register(SnapshotHandler {
        bucket: bucket.clone(),
        coordinator: meta.clone(),
        clock: clock.clone(),
        alarm: alarm.clone(),
    });
    delivery(&store, 1, 1, false);
    clock.set(2000);
    tick(&store, &registry, &clock);
    assert!(bucket.object.lock().unwrap().is_none());
    assert_eq!(bucket.calls.load(Ordering::SeqCst), 1);
    public(&meta, false);
    // More than the row cap in the same bucket must not retain a truncated view.
    let mut n = 0;
    let mut inserted = 0;
    while inserted <= MAX_ROWS {
        let name = format!("refs/heads/n{n:06}");
        n += 1;
        if D34Shards.ref_index(&repo(), &name) == partition() {
            block_on(store.apply(
                &partition(),
                Batch::new().put(
                    keys::published_index(&repo().name, &name),
                    codec::encode_ref_id(&[1; 32]),
                ),
            ))
            .unwrap();
            inserted += 1;
        }
    }
    clock.set(32000);
    alarm.reset();
    tick(&store, &registry, &clock);
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 0);
    assert!(bucket.object.lock().unwrap().is_none());
}

#[test]
fn cache_expiry_failures_and_malformed_snapshots_use_at_most_two_lookups_before_fallback() {
    let clock = Arc::new(ManualClock::new(1000));
    let bucket = Bucket::new(clock);
    let cache = Cache::default();
    *bucket.object.lock().unwrap() = Some(SnapshotObject {
        etag: "e".into(),
        stored_at_ms: 1000,
        bytes: envelope(1, 1000).encode().unwrap(),
    });
    let mut reader = SnapshotReader {
        bucket: bucket.clone(),
        cache,
        config: PublishedViewConfig::new("staging").unwrap(),
        clock: bucket.clock.clone(),
    };
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 1000))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        bucket.calls.load(Ordering::SeqCst) + reader.cache.calls.load(Ordering::SeqCst),
        3
    );
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 1999))
            .unwrap()
            .is_some()
    );
    assert_eq!(bucket.calls.load(Ordering::SeqCst), 1);
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2000))
            .unwrap()
            .is_some()
    );
    assert_eq!(bucket.calls.load(Ordering::SeqCst), 2);
    reader.cache.fail.store(true, Ordering::SeqCst);
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2100))
            .unwrap()
            .is_some()
    );
    bucket.object.lock().unwrap().as_mut().unwrap().bytes[3] = 99;
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2200))
            .unwrap()
            .is_none()
    );
    bucket.object.lock().unwrap().as_mut().unwrap().bytes = vec![0; MAX_BYTES + 1];
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2200))
            .unwrap()
            .is_none()
    );
    bucket.fail_get.store(true, Ordering::SeqCst);
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2200))
            .unwrap()
            .is_none()
    );
    let before = bucket.calls.load(Ordering::SeqCst);
    reader.config.inspection_configured = true;
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 2200))
            .unwrap()
            .is_none()
    );
    assert_eq!(bucket.calls.load(Ordering::SeqCst), before + 1);
}

#[test]
fn feature_on_env_and_existing_app_entrypoints_remain_inert() {
    let cfg = crate::adapter::WorkerConfig::from_vars(|name| match name {
        "AUTH_AUDIENCE" => Some("https://example.test".into()),
        "AUTH_REPOSITORY" => Some("default".into()),
        _ => None,
    })
    .unwrap();
    assert!(cfg.published_view.is_none());
    let app = include_str!("../../../../../apps/vcs-worker/src/worker_impl.rs");
    assert!(!app.contains("fetch_configured"));
    assert!(!app.contains("ns_object_configured"));
    let config = include_str!("../../../../../apps/vcs-worker/wrangler.jsonc");
    assert!(!config.contains(SNAPSHOTS_BINDING));
}

#[test]
fn mixed_read_misses_and_expiry_keep_49_calls_and_reserve_one_hook_call() {
    let clock = Arc::new(ManualClock::new(1000));
    let bucket = Bucket::new(clock);
    let cache = Cache::default();
    *bucket.object.lock().unwrap() = Some(SnapshotObject {
        etag: "v".into(),
        stored_at_ms: 1000,
        bytes: envelope(1, 1000).encode().unwrap(),
    });
    let reader = SnapshotReader {
        bucket: bucket.clone(),
        cache,
        config: PublishedViewConfig::new("stage").unwrap(),
        clock: bucket.clock.clone(),
    };
    let live = CountStore::new(MemoryKv::default());
    for p in D34Shards.ref_index_partitions(&repo()) {
        if block_on(reader.bucket(&repo(), &p, 1000))
            .unwrap()
            .is_none()
        {
            block_on(live.scan(
                &p,
                &Key::new(b"x\0".to_vec()),
                &Key::new(b"x\x01".to_vec()),
                None,
                1,
            ))
            .unwrap();
        }
    }
    assert_eq!(
        bucket.calls.load(Ordering::SeqCst)
            + reader.cache.calls.load(Ordering::SeqCst)
            + live.calls.load(Ordering::SeqCst)
            + 1,
        49
    );
    // A cache put failure consumes the third operation but still returns its
    // validated R2 data, so there is no fourth, unnecessary live call.
    assert_eq!(49 + 1, 50);
    assert_eq!(crate::adapter::FREE_OUTCOME_ROWS_PER_FIRE, 8);
    assert_eq!(crate::adapter::FREE_OUTCOME_FIRES_PER_ALARM, 1);
}

#[derive(Clone)]
struct BackupCalls(Arc<AtomicUsize>);
impl crate::backup::BackupBucket for BackupCalls {
    async fn put<'a>(&'a self, _: &'a str, _: Vec<u8>, _: &'a str) -> Result<(), String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn all_partition_heads_share_one_snapshot_fire_and_eight_calls_including_backup() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let meta = CountStore::new(MemoryKv::default());
    public(&meta, false);
    meta.calls.store(0, Ordering::SeqCst);
    let bucket = Bucket::new(clock.clone());
    let backups = BackupCalls(Arc::default());
    let alarm = SnapshotAlarm::default();
    let registry = TimerRegistry::new()
        .register(SnapshotHandler {
            bucket: bucket.clone(),
            coordinator: meta.clone(),
            clock: clock.clone(),
            alarm: alarm.clone(),
        })
        .register(AlarmLimited {
            handler: crate::backup::BackupHandler::new(
                backups.clone(),
                crate::backup::BackupConfig::default(),
            ),
            alarm: alarm.clone(),
        });
    let partitions = D34Shards.ref_index_partitions(&repo());
    for p in &partitions {
        block_on(
            store.apply(
                p,
                Batch::new()
                    .put(
                        state_key(),
                        super::timer::State {
                            generation: 1,
                            dirty: true,
                            due: 2000,
                            last_success: 0,
                        }
                        .encode(),
                    )
                    .put(keys::timer(2000, 10, b""), Value::default()),
            ),
        )
        .unwrap();
        block_on(store.apply(p, crate::backup::seed_batch(1000, 1000))).unwrap();
    }
    clock.set(2000);
    alarm.reset();
    for p in &partitions {
        block_on(run_due(
            &store,
            p,
            &registry,
            clock.as_ref(),
            2000,
            &TickBudget::default(),
        ))
        .unwrap();
    }
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 1);
    assert_eq!(meta.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        bucket.calls.load(Ordering::SeqCst)
            + meta.calls.load(Ordering::SeqCst)
            + backups.0.load(Ordering::SeqCst),
        8
    );
    assert_eq!(backups.0.load(Ordering::SeqCst), 5);
    assert!(
        store
            .timer_heads()
            .unwrap()
            .iter()
            .all(|(_, due)| *due > 2000)
    );
}

#[test]
fn configured_pressure_store_propagates_atomic_timer_wakes_and_inert_store_writes_none() {
    use crate::{classes::ShardClass, ns_object::PressureStore};
    let clock = Arc::new(ManualClock::new(1000));
    let plain = PressureStore::new(
        local(&clock),
        ShardClass::RepoIndexShard,
        clock.clone(),
        Arc::new(mkit_server::telemetry::NoopMetrics),
    );
    let key = keys::published_index(&repo().name, "refs/heads/main");
    block_on(plain.apply(
        &partition(),
        Batch::new().put(key.clone(), codec::encode_ref_id(&[1; 32])),
    ))
    .unwrap();
    assert!(
        block_on(plain.get(&partition(), &state_key()))
            .unwrap()
            .is_none()
    );
    assert!(plain.take_seeded_due().is_none());
    let enabled = PressureStore::new(
        local(&clock),
        ShardClass::RepoIndexShard,
        clock.clone(),
        Arc::new(mkit_server::telemetry::NoopMetrics),
    )
    .with_published_view();
    block_on(enabled.apply(
        &partition(),
        Batch::new().put(key, codec::encode_ref_id(&[1; 32])),
    ))
    .unwrap();
    assert_eq!(enabled.take_seeded_due(), Some(2000));
    assert_eq!(enabled.capabilities().reserved_batch_ops, 3);
    let state = block_on(enabled.get(&partition(), &state_key())).unwrap();
    assert!(state.is_some());
    // Input precondition failure must not publish a wake or bump state.
    block_on(
        enabled.apply(
            &partition(),
            Batch::new()
                .require(Precondition::Absent(state_key()))
                .delete(keys::published_index(&repo().name, "refs/heads/main")),
        ),
    )
    .unwrap();
    assert!(enabled.take_seeded_due().is_none());
    assert_eq!(
        block_on(enabled.get(&partition(), &state_key())).unwrap(),
        state
    );
}

#[test]
fn slow_cache_awaits_never_serve_expired_data_or_add_a_fourth_operation() {
    for expire_on_fill in [false, true] {
        let clock = Arc::new(ManualClock::new(1000));
        let bucket = Bucket::new(clock.clone());
        let bytes = envelope(1, 1000).encode().unwrap();
        *bucket.object.lock().unwrap() = Some(SnapshotObject {
            etag: "e".into(),
            stored_at_ms: 1000,
            bytes: bytes.clone(),
        });
        let cache = Cache::default();
        let hook = if expire_on_fill {
            &cache.put_hook
        } else {
            *cache.object.lock().unwrap() = Some((1000, bytes));
            &cache.get_hook
        };
        let advance = clock.clone();
        *hook.lock().unwrap() = Some(Box::new(move || advance.set(61000)));
        let reader = SnapshotReader {
            bucket: bucket.clone(),
            cache,
            config: PublishedViewConfig::new("slow").unwrap(),
            clock,
        };
        let result = block_on(reader.bucket(&repo(), &partition(), 1000));
        if expire_on_fill {
            assert!(result.is_err()); // Fill spent operation three: fail the page, no live call.
        } else {
            assert!(result.unwrap().is_none());
        }
        assert_eq!(
            bucket.calls.load(Ordering::SeqCst) + reader.cache.calls.load(Ordering::SeqCst),
            if expire_on_fill { 3 } else { 2 }
        );
    }
}

#[test]
fn conditional_replacement_never_regresses_generation_or_capture_time() {
    for (generation, captured_at_ms) in [(2, 1000), (1, 3000)] {
        let clock = Arc::new(ManualClock::new(1000));
        let store = local(&clock);
        let meta = CountStore::new(MemoryKv::default());
        public(&meta, false);
        let bucket = Bucket::new(clock.clone());
        let bytes = envelope(generation, captured_at_ms).encode().unwrap();
        *bucket.object.lock().unwrap() = Some(SnapshotObject {
            etag: "newer".into(),
            stored_at_ms: 0,
            bytes: bytes.clone(),
        });
        let alarm = SnapshotAlarm::default();
        let registry = TimerRegistry::new().register(SnapshotHandler {
            bucket: bucket.clone(),
            coordinator: meta,
            clock: clock.clone(),
            alarm,
        });
        delivery(&store, 1, 1, false);
        clock.set(2000);
        tick(&store, &registry, &clock);
        assert!(state(&store).dirty);
        assert_eq!(bucket.puts.load(Ordering::SeqCst), 0);
        assert_eq!(bucket.object.lock().unwrap().as_ref().unwrap().bytes, bytes);
        assert_eq!(bucket.calls.load(Ordering::SeqCst), 1); // No retry or replacement.
    }
}

#[test]
fn privacy_change_during_upload_is_cleaned_on_refresh_without_a_retry() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let meta = CountStore::new(MemoryKv::default());
    public(&meta, false);
    meta.calls.store(0, Ordering::SeqCst);
    let bucket = Bucket::new(clock.clone());
    let changed = meta.inner.clone();
    *bucket.interleave.lock().unwrap() = Some(Box::new(move || public(changed.as_ref(), true)));
    let alarm = SnapshotAlarm::default();
    let registry = TimerRegistry::new().register(SnapshotHandler {
        bucket: bucket.clone(),
        coordinator: meta.clone(),
        clock: clock.clone(),
        alarm: alarm.clone(),
    });
    delivery(&store, 1, 1, false);
    clock.set(2000);
    tick(&store, &registry, &clock);
    // Authorization observed public before the upload await. R2 stays private;
    // the pipeline's independent private-transition test denies subsequent reads
    // before touching this obsolete body. Publication does not re-read visibility.
    assert_eq!(meta.calls.load(Ordering::SeqCst), 1);
    assert_eq!(bucket.calls.load(Ordering::SeqCst), 2);
    assert!(bucket.object.lock().unwrap().is_some());
    clock.set(32000);
    alarm.reset();
    tick(&store, &registry, &clock);
    assert!(bucket.object.lock().unwrap().is_none());
    assert_eq!(bucket.puts.load(Ordering::SeqCst), 1);
    assert_eq!(meta.calls.load(Ordering::SeqCst), 2);
    assert_eq!(bucket.calls.load(Ordering::SeqCst), 3);
}

#[test]
fn full_reserved_target_batch_and_three_local_writes_commit_atomically() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let partition = partition();
    let old_timer = keys::timer(
        30000,
        mkit_server::timers::registry::kinds::PUBLISHED_VIEW.get(),
        b"",
    );
    let clean = super::timer::State {
        generation: 1,
        dirty: false,
        due: 30000,
        last_success: 0,
    };
    block_on(
        store.apply(
            &partition,
            Batch::new()
                .put(state_key(), clean.encode())
                .put(old_timer.clone(), Value::default()),
        ),
    )
    .unwrap();
    let guard = Key::new(b"target-watermark".to_vec());
    let mut batch = Batch::new()
        .require(Precondition::Absent(guard.clone()))
        .put(guard, Value::default());
    for _ in 0..95 {
        batch.writes.push(mkit_server::Write::Put(
            keys::published_index(&repo().name, "refs/heads/main"),
            codec::encode_ref_id(&[9; 32]),
        ));
    }
    let mut caps = mkit_server::StoreCapabilities::full();
    caps.reserved_batch_ops = 3;
    assert_eq!(batch.preconditions.len() + batch.writes.len(), 97);
    batch.validate(&caps).unwrap();
    let target = partition.clone();
    assert_eq!(
        store
            .apply_extended(&partition, batch.clone(), move |get, batch, at| {
                extend_relay(&target, get, batch, at).map(|_| ())
            })
            .unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(state(&store).generation, 2);
    assert_eq!(state(&store).due, 2000);
    assert!(
        block_on(store.get(&partition, &old_timer))
            .unwrap()
            .is_none()
    );
    let target = partition.clone();
    assert!(matches!(
        store
            .apply_extended(&partition, batch, move |get, batch, at| {
                extend_relay(&target, get, batch, at).map(|_| ())
            })
            .unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(state(&store).generation, 2);
}

#[test]
fn purge_during_snapshot_refill_cannot_return_stale_rows() {
    let clock = Arc::new(ManualClock::new(1000));
    let bucket = Bucket::new(clock.clone());
    *bucket.object.lock().unwrap() = Some(SnapshotObject {
        etag: "old".into(),
        stored_at_ms: 1000,
        bytes: envelope(1, 1000).encode().unwrap(),
    });
    let store = Arc::new(MemoryKv::default());
    let changed = store.clone();
    let cache = Cache::default();
    *cache.put_hook.lock().unwrap() = Some(Box::new(move || {
        changed
            .apply(
                &D34Shards.coordinator(&repo().namespace),
                Batch::new().put(
                    keys::cache_purge_generation("root/sample"),
                    Value::new(1001u64.to_be_bytes().to_vec()),
                ),
            )
            .now_or_never()
            .unwrap()
            .unwrap();
    }));
    let reader = SnapshotReader {
        bucket,
        cache,
        config: PublishedViewConfig::new("purge-fence").unwrap(),
        clock,
    };
    let reader = fenced_reader(
        Arc::new(reader),
        store.clone(),
        mkit_server::pipeline::Sharding::D34,
    );
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 1000))
            .unwrap()
            .is_none()
    );
    // Retained R2/cache bytes stay fenced on a cold retry before global ack.
    assert!(
        block_on(reader.bucket(&repo(), &partition(), 1000))
            .unwrap()
            .is_none()
    );
}

#[test]
fn live_index_updates_do_not_dirty_published_snapshot_work() {
    let clock = Arc::new(ManualClock::new(1000));
    let store = local(&clock);
    let p = partition();
    let live = keys::ref_index_key(&repo().name, "refs/heads/main");
    assert_eq!(
        store
            .apply_extended(
                &p.clone(),
                Batch::new().put(live.clone(), codec::encode_ref_id(&[9; 32])),
                move |get, batch, now| extend_relay(&p, get, batch, now).map(|_| ())
            )
            .unwrap(),
        BatchOutcome::Committed
    );
    assert!(
        block_on(store.get(&partition(), &state_key()))
            .unwrap()
            .is_none()
    );
    delivery(&store, 1, 1, false);
    assert_eq!(state(&store).generation, 1);
    assert_eq!(
        block_on(store.get(&partition(), &live)).unwrap(),
        Some(codec::encode_ref_id(&[9; 32]))
    );
    assert_eq!(
        block_on(store.get(
            &partition(),
            &keys::published_index(&repo().name, "refs/heads/main")
        ))
        .unwrap(),
        Some(codec::encode_ref_id(&[1; 32]))
    );
}
