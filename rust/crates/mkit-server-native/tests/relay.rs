//! Relay delivery through the running native driver and server registration.
#![allow(clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{codec, keys, outbox::OutboxBuilder, tickets::plan_membership};
use mkit_server::timers::{TickBudget, TimerRegistry, registry::kinds, run_due};
use mkit_server::{
    Batch, BatchOutcome, BlobKey, Clock, Cursor, Key, ManualClock, NamespaceKey, NamespaceStore,
    Partition, PartitionStats, RepoId, RepoName, ScanPage, StoreCapabilities, StoreError,
    SystemClock, Value, Write,
};
use mkit_server_native::timers::{TimerDriver, TimerNotifying, TimerStore};
use mkit_server_native::{Blocking, RusqliteConn, Shutdown, server};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("relay").unwrap(),
    }
}

async fn enqueue<S: NamespaceStore>(store: &S, pack: [u8; 32]) -> (Partition, Partition, u64) {
    let repo = repo();
    let source = D34Shards.ref_shard(&repo, "refs/heads/main");
    let target = D34Shards.membership(&repo, &BlobKey::pack(pack));
    let due = u64::try_from(SystemClock.now_ms()).unwrap();
    let mut outbox = OutboxBuilder::new(None, None).unwrap();
    outbox.relay_at(due);
    let mut batch = Batch::new();
    plan_membership(
        &repo.name,
        &[pack],
        &source,
        &D34Shards,
        &repo,
        &mut outbox,
        &mut batch.writes,
    );
    outbox
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert!(batch.writes.iter().any(|write| {
        matches!(write, mkit_server::Write::Put(key, value)
            if *key == keys::timer(due, kinds::RELAY.get(), b"")
                && *value == Value::default())
    }));
    assert_eq!(
        store.apply(&source, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    (source, target, due)
}

// Yield through the store reads and scheduler, with a single bounded wait.
// No sleep loop is needed to drive timer progress.
async fn wait_watermark<S: NamespaceStore>(store: &S, source: &Partition, target: &Partition) {
    let key = keys::relay_high_water(source).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(value) = store.get(target, &key).await.unwrap() {
                assert_eq!(codec::decode_u64(&value).unwrap(), 1);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("running driver did not deliver relay timer");
}

async fn assert_delivered<S: NamespaceStore>(
    store: &S,
    source: &Partition,
    target: &Partition,
    pack: [u8; 32],
    due: u64,
) {
    assert_eq!(
        store
            .get(target, &keys::membership(&repo().name, &pack))
            .await
            .unwrap(),
        Some(Value::default())
    );
    assert_eq!(store.get(source, &keys::relay(1)).await.unwrap(), None);
    assert_eq!(
        store
            .get(source, &keys::timer(due, kinds::RELAY.get(), b""))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbox_timer_notifies_running_driver_and_delivers_without_sleep_loop() {
    let dir = tempfile::tempdir().unwrap();
    let store: TimerStore = Blocking::new(TimerNotifying::new(
        SqlKvStore::open(RusqliteConn::open(dir.path().join("relay.sqlite3")).unwrap()).unwrap(),
    ));
    let registry = TimerRegistry::new().register(RelayHandler {
        target: store.clone(),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    let shutdown = Shutdown::new();
    let task = TimerDriver::new(store.clone(), registry, Arc::new(SystemClock))
        .start(shutdown.clone())
        .await
        .unwrap();
    let pack = [0x11; 32];
    let (source, target, due) = enqueue(&store, pack).await;
    wait_watermark(&store, &source, &target).await;
    shutdown.trigger();
    task.await.unwrap();
    assert_delivered(&store, &source, &target, pack, due).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_open_registers_relay_handler_without_test_faults() {
    let root = common::repo_root();
    let database = root.path().join("meta.sqlite3");
    let meta = format!("sqlite:{}", common::s(&database));
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--sharding",
            "d34",
            "--unsafe-allow-any-peer",
        ],
        &[],
    )
    .unwrap();
    let mut opened = server::open(&cfg).unwrap();
    let raw = Blocking::new(SqlKvStore::open(RusqliteConn::open(&database).unwrap()).unwrap());
    let pack = [0x22; 32];
    let (source, target, due) = enqueue(&raw, pack).await;
    let shutdown = Shutdown::new();
    let task = opened
        .timers
        .take()
        .expect("SQLite server timer driver")
        .start(shutdown.clone())
        .await
        .unwrap();
    wait_watermark(&raw, &source, &target).await;
    shutdown.trigger();
    task.await.unwrap();
    assert_delivered(&raw, &source, &target, pack, due).await;
}

/// Real `SQLite` batches with failures at the two relay commit boundaries.
#[derive(Clone)]
struct FaultSql {
    inner: Arc<SqlKvStore<RusqliteConn>>,
    fail_deletes: Arc<AtomicUsize>,
    reject_target: Option<Partition>,
    committed: Arc<Mutex<Vec<Batch>>>,
}

impl FaultSql {
    fn new(reject_target: Option<Partition>) -> Self {
        Self {
            inner: Arc::new(SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap()),
            fail_deletes: Arc::new(AtomicUsize::new(0)),
            reject_target,
            committed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn batches(&self) -> Vec<Batch> {
        self.committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn clear_batches(&self) {
        self.committed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl NamespaceStore for FaultSql {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, key).await
    }

    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.inner.has(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.inner.get_many(p, keys).await
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

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let deleting_relay = batch.writes.iter().any(|write| {
            matches!(write, Write::Delete(key)
                if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))))
        });
        if self.reject_target.as_ref() == Some(p)
            || (deleting_relay
                && self
                    .fail_deletes
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok())
        {
            return Err(StoreError::Unavailable(
                "injected relay boundary failure".into(),
            ));
        }
        let result = self.inner.apply(p, batch.clone()).await?;
        if result == BatchOutcome::Committed {
            self.committed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(batch);
        }
        Ok(result)
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

type RelayPuts = Vec<(Partition, Vec<(Key, Value)>)>;

async fn queue(source: &FaultSql, partition: &Partition, relays: RelayPuts) {
    let prior = source
        .get(partition, &keys::outbox_sequence())
        .await
        .unwrap();
    let mut builder = OutboxBuilder::new(prior.as_ref(), None).unwrap();
    builder.relay_at(100);
    for (target, puts) in relays {
        builder.relay(&target, puts);
    }
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        source.apply(partition, batch).await.unwrap(),
        BatchOutcome::Committed
    );
}

fn sql_registry(target: FaultSql) -> TimerRegistry<FaultSql> {
    TimerRegistry::new().register(RelayHandler {
        target,
        hook: NoHook,
        budget: RelayBudget::default(),
    })
}

async fn pending(source: &FaultSql, partition: &Partition) -> Vec<(Key, Value)> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    source
        .scan(partition, &start, &end, None, 256)
        .await
        .unwrap()
        .entries
}

#[tokio::test]
async fn sqlite_crash_after_target_commit_retries_without_another_target_apply() {
    let source = FaultSql::new(None);
    let target = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let destination = D34Shards.membership(&repo(), &BlobKey::pack([1; 32]));
    let key = keys::membership(&repo().name, &[1; 32]);
    queue(
        &source,
        &partition,
        vec![(destination.clone(), vec![(key.clone(), Value::default())])],
    )
    .await;
    source.fail_deletes.store(1, Ordering::SeqCst);
    let registry = sql_registry(target.clone());
    let clock = ManualClock::new(100);
    let first = run_due(
        &source,
        &partition,
        &registry,
        &clock,
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(first.failed, 1);
    assert_eq!(pending(&source, &partition).await.len(), 1);
    assert_eq!(
        target.get(&destination, &key).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(target.batches().len(), 1);
    assert_eq!(
        target
            .get(&destination, &keys::relay_high_water(&partition).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );

    let second = run_due(
        &source,
        &partition,
        &registry,
        &clock,
        101,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(second.fired, 1);
    assert!(pending(&source, &partition).await.is_empty());
    assert_eq!(
        target.batches().len(),
        1,
        "duplicate was read, never applied"
    );
}

#[tokio::test]
async fn sqlite_failing_target_keeps_its_later_rows_and_allows_other_targets() {
    let source = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let failing = D34Shards.membership(&repo(), &BlobKey::pack([1; 32]));
    let healthy = D34Shards.membership(&repo(), &BlobKey::pack([2; 32]));
    let target = FaultSql::new(Some(failing.clone()));
    let failed_key = Key::new(&b"r\0failing"[..]);
    let healthy_key = Key::new(&b"r\0healthy"[..]);
    queue(
        &source,
        &partition,
        vec![
            (
                failing.clone(),
                vec![(failed_key.clone(), Value::new(&b"first"[..]))],
            ),
            (
                healthy.clone(),
                vec![(healthy_key.clone(), Value::default())],
            ),
        ],
    )
    .await;
    queue(
        &source,
        &partition,
        vec![(
            failing.clone(),
            vec![(failed_key.clone(), Value::new(&b"later"[..]))],
        )],
    )
    .await;
    let registry = sql_registry(target.clone());
    let report = run_due(
        &source,
        &partition,
        &registry,
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert_eq!(
        report.next_wake_ms,
        Some(100 + mkit_server::timers::RETRY_BACKOFF_MS)
    );
    let remaining = pending(&source, &partition).await;
    assert_eq!(remaining.len(), 2);
    assert!(
        remaining
            .iter()
            .all(|(_, v)| codec::decode_relay(v).unwrap().target == failing)
    );
    assert_eq!(target.get(&failing, &failed_key).await.unwrap(), None);
    assert_eq!(
        target.get(&healthy, &healthy_key).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(target.batches().len(), 1);
}

#[tokio::test]
async fn sqlite_chunks_target_operations_and_source_cleanup_bytes() {
    let source = FaultSql::new(None);
    let target = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let destination = D34Shards.membership(&repo(), &BlobKey::pack([1; 32]));
    let puts: Vec<_> = (0..192u32)
        .map(|i| {
            (
                Key::new([&b"r\0"[..], &i.to_be_bytes()].concat()),
                Value::new(vec![0; 1024]),
            )
        })
        .collect();
    queue(
        &source,
        &partition,
        vec![(destination.clone(), puts.clone())],
    )
    .await;
    assert_eq!(pending(&source, &partition).await.len(), 2);
    let registry = sql_registry(target.clone());
    let report = run_due(
        &source,
        &partition,
        &registry,
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert_eq!(
        target.batches().len(),
        2,
        "each 96-put row needs its own target batch"
    );
    assert!(pending(&source, &partition).await.is_empty());
    for (key, value) in puts {
        assert_eq!(target.get(&destination, &key).await.unwrap(), Some(value));
    }
    for batch in target.batches() {
        batch.validate(&StoreCapabilities::full()).unwrap();
    }

    let large_partition = D34Shards.ref_shard(&repo(), "refs/heads/large");
    for i in 0..11u32 {
        queue(
            &source,
            &large_partition,
            vec![(
                destination.clone(),
                vec![(
                    Key::new([&b"r\0large"[..], &i.to_be_bytes()].concat()),
                    Value::new(vec![1; 100 * 1024]),
                )],
            )],
        )
        .await;
    }
    assert_eq!(pending(&source, &large_partition).await.len(), 11);
    source.clear_batches();
    target.clear_batches();
    let report = run_due(
        &source,
        &large_partition,
        &registry,
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(pending(&source, &large_partition).await.is_empty());
    assert_eq!(
        target.batches().len(),
        2,
        "raw target puts exceed one batch's byte limit"
    );
    let deletes = source.batches().into_iter().filter(|batch| batch.writes.iter().any(|write| {
        matches!(write, Write::Delete(key) if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))))
    })).collect::<Vec<_>>();
    assert_eq!(
        deletes.len(),
        3,
        "encoded-row Equals guards require byte-limited cleanup batches"
    );
    for batch in deletes {
        batch.validate(&StoreCapabilities::full()).unwrap();
        assert!(
            batch
                .writes
                .iter()
                .all(|write| matches!(write, Write::Delete(_)))
        );
    }
}
