//! Relay delivery through the running native driver and server registration.
#![allow(clippy::unwrap_used)]

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use mkit_server::pipeline::{D34Shards, ShardMap};
use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
use mkit_server::sql::{Capacity, SqlKvStore};
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
    reject_targets: Vec<Partition>,
    reject_dynamic: Arc<Mutex<BTreeSet<Partition>>>,
    scan_conflict: Arc<std::sync::atomic::AtomicBool>,
    committed: Arc<Mutex<Vec<Batch>>>,
}

impl FaultSql {
    fn new(reject_target: Option<Partition>) -> Self {
        Self::with_store(
            SqlKvStore::open(RusqliteConn::open_in_memory().unwrap()).unwrap(),
            reject_target,
        )
    }

    fn with_store(inner: SqlKvStore<RusqliteConn>, reject_target: Option<Partition>) -> Self {
        Self {
            inner: Arc::new(inner),
            fail_deletes: Arc::new(AtomicUsize::new(0)),
            reject_target,
            reject_targets: Vec::new(),
            reject_dynamic: Arc::default(),
            scan_conflict: Arc::default(),
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
            || self.reject_targets.contains(p)
            || self.reject_dynamic.lock().unwrap().contains(p)
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
        let scan_key = keys::relay_scan();
        if self.scan_conflict.load(Ordering::SeqCst)
            && let Some(index) = batch.preconditions.iter().position(|pre| {
                matches!(pre, mkit_server::Precondition::Absent(k)
                    | mkit_server::Precondition::Equals(k, _) if k == &scan_key)
            })
        {
            self.scan_conflict.store(false, Ordering::SeqCst);
            return Ok(BatchOutcome::PreconditionFailed {
                index,
                observed: None,
            });
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

fn sql_budget(rows: u32, targets: u32, calls: Option<u32>) -> RelayBudget {
    let mut budget = RelayBudget::default();
    budget.max_rows = rows;
    budget.max_targets = targets;
    budget.max_target_calls = calls;
    budget
}

fn sql_registry(target: FaultSql) -> TimerRegistry<'static, FaultSql> {
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
    let remaining = pending(&source, &partition).await;
    assert!(
        remaining.is_empty(),
        "second tick left {:?}; state {:?}",
        remaining
            .iter()
            .map(|(k, _)| keys::parse(k))
            .collect::<Vec<_>>(),
        source
            .get(&partition, &keys::relay_scan())
            .await
            .unwrap()
            .map(|v| codec::decode_relay_scan(&v).unwrap())
    );
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
    assert_eq!(report.next_wake_ms, Some(101));
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
                .all(|write| matches!(write, Write::Delete(_))
                    || matches!(write, Write::Put(key, _) if *key == keys::relay_scan()))
        );
    }
}

#[tokio::test]
async fn sqlite_failing_backlog_does_not_fill_the_delivery_window() {
    let source = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let failing = Partition::ContentShard(0);
    let healthy = Partition::ContentShard(1);
    let target = FaultSql::new(Some(failing.clone()));
    for _ in 0..3 {
        queue(
            &source,
            &partition,
            vec![(
                failing.clone(),
                vec![(Key::new(b"r\0failed".to_vec()), Value::default())],
            )],
        )
        .await;
    }
    let key = Key::new(b"r\0healthy".to_vec());
    queue(
        &source,
        &partition,
        vec![(healthy.clone(), vec![(key.clone(), Value::default())])],
    )
    .await;
    let registry = TimerRegistry::new().register(RelayHandler {
        target: target.clone(),
        hook: NoHook,
        budget: sql_budget(2, 2, None),
    });
    run_due(
        &source,
        &partition,
        &registry,
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        target.get(&healthy, &key).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(pending(&source, &partition).await.len(), 3);
}

#[tokio::test]
async fn sqlite_full_failing_target_budget_resumes_at_next_target() {
    let source = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let mut target = FaultSql::new(None);
    target.reject_targets = vec![Partition::ContentShard(0), Partition::ContentShard(1)];
    let key = Key::new(b"r\0healthy".to_vec());
    for i in 0..3u16 {
        queue(
            &source,
            &partition,
            vec![(
                Partition::ContentShard(i),
                vec![(key.clone(), Value::default())],
            )],
        )
        .await;
    }
    let registry = TimerRegistry::new().register(RelayHandler {
        target: target.clone(),
        hook: NoHook,
        budget: sql_budget(2, 2, None),
    });
    for now in [100, 100 + mkit_server::timers::RETRY_BACKOFF_MS] {
        run_due(
            &source,
            &partition,
            &registry,
            &ManualClock::new(i64::try_from(now).unwrap()),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        target.get(&Partition::ContentShard(2), &key).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(pending(&source, &partition).await.len(), 2);
}

#[tokio::test]
async fn sqlite_target_sequence_order_survives_target_pause() {
    let source = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let target = FaultSql::new(None);
    let key = Key::new(b"r\0ordered".to_vec());
    for seq in 1..=5u8 {
        queue(
            &source,
            &partition,
            vec![(
                Partition::ContentShard(u16::from(seq % 2)),
                vec![(key.clone(), Value::new(vec![seq]))],
            )],
        )
        .await;
    }
    let registry = TimerRegistry::new().register(RelayHandler {
        target: target.clone(),
        hook: NoHook,
        budget: sql_budget(1, 1, Some(2)),
    });
    for now in 100..105 {
        run_due(
            &source,
            &partition,
            &registry,
            &ManualClock::new(i64::try_from(now).unwrap()),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }
    assert!(pending(&source, &partition).await.is_empty());
    let applied: Vec<_> = target
        .batches()
        .iter()
        .flat_map(|batch| batch.writes.iter())
        .filter_map(|write| match write {
            Write::Put(k, value) if k == &key => Some(value.as_bytes()[0]),
            _ => None,
        })
        .collect();
    assert_eq!(
        applied
            .iter()
            .copied()
            .filter(|seq| seq % 2 == 1)
            .collect::<Vec<_>>(),
        vec![1, 3, 5],
        "odd rows must commit in order within their target"
    );
    assert_eq!(
        applied
            .iter()
            .copied()
            .filter(|seq| seq % 2 == 0)
            .collect::<Vec<_>>(),
        vec![2, 4],
        "even rows must commit in order within their target"
    );
    assert_eq!(
        target.get(&Partition::ContentShard(1), &key).await.unwrap(),
        Some(Value::new(vec![5]))
    );
    assert_eq!(
        target.get(&Partition::ContentShard(0), &key).await.unwrap(),
        Some(Value::new(vec![4]))
    );
}

#[tokio::test]
async fn sqlite_corrupt_row_delivers_decodable_prefix_then_stops() {
    let source = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let target = FaultSql::new(None);
    let destination = Partition::ContentShard(0);
    let key = Key::new(b"r\0healthy".to_vec());
    queue(
        &source,
        &partition,
        vec![(destination.clone(), vec![(key.clone(), Value::default())])],
    )
    .await;
    source
        .apply(
            &partition,
            Batch::new()
                .put(keys::relay(2), Value::new(b"bad".to_vec()))
                .put(keys::outbox_sequence(), codec::encode_u64(2)),
        )
        .await
        .unwrap();
    let report = run_due(
        &source,
        &partition,
        &sql_registry(target.clone()),
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.failed, 1);
    assert_eq!(pending(&source, &partition).await.len(), 1);
    assert_eq!(
        target.get(&destination, &key).await.unwrap(),
        Some(Value::default())
    );
    assert!(
        source
            .get(&partition, &keys::relay(2))
            .await
            .unwrap()
            .is_some()
    );
}

async fn plant_sql_schedule(source: &FaultSql, partition: &Partition, schedule: &[u16]) {
    for (chunk_index, chunk) in schedule.chunks(90).enumerate() {
        let mut batch = Batch::new();
        for (offset, destination) in chunk.iter().enumerate() {
            let seq = u64::try_from(chunk_index * 90 + offset + 1).unwrap();
            let row = codec::RelayV1 {
                at_ms: 100,
                target: Partition::ContentShard(*destination),
                puts: vec![(
                    Key::new([b"delivered/".as_slice(), &seq.to_be_bytes()].concat()),
                    codec::encode_u64(seq),
                )],
                deletes: Vec::new(),
            };
            batch = batch.put(keys::relay(seq), codec::encode_relay(&row).unwrap());
        }
        assert_eq!(
            source.apply(partition, batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
    assert_eq!(
        source
            .apply(
                partition,
                Batch::new()
                    .put(
                        keys::outbox_sequence(),
                        codec::encode_u64(schedule.len() as u64)
                    )
                    .put(keys::timer(100, kinds::RELAY.get(), b""), Value::default())
            )
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
}

fn sql_order_key(seq: u64) -> Key {
    Key::new([b"delivered/".as_slice(), &seq.to_be_bytes()].concat())
}

async fn one_sql_relay_tick(
    source: &FaultSql,
    partition: &Partition,
    target: FaultSql,
    now: u64,
) -> mkit_server::timers::RunReport {
    let registry = TimerRegistry::new().register(RelayHandler {
        target,
        hook: NoHook,
        budget: sql_budget(128, 8, Some(2)),
    });
    run_due(
        source,
        partition,
        &registry,
        &ManualClock::new(i64::try_from(now).unwrap()),
        now,
        &TickBudget::new(1, 1, 512, 60_000),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn sqlite_durable_scan_crosses_600_row_backlog_and_recovers_after_restart() {
    let source = FaultSql::new(None);
    let target = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let a = Partition::ContentShard(0);
    let b = Partition::ContentShard(1);
    target.reject_dynamic.lock().unwrap().insert(a.clone());
    let mut schedule = vec![0; 599];
    schedule.push(1);
    plant_sql_schedule(&source, &partition, &schedule).await;
    let mut now = 100;
    for _ in 0..3 {
        let report = one_sql_relay_tick(&source, &partition, target.clone(), now).await;
        now = report.next_wake_ms.unwrap_or(now + 1).max(now + 1);
    }
    assert_eq!(
        target.get(&b, &sql_order_key(600)).await.unwrap(),
        Some(codec::encode_u64(600))
    );
    assert!(
        source
            .get(&partition, &keys::relay(1))
            .await
            .unwrap()
            .is_some()
    );
    let scan = source
        .get(&partition, &keys::relay_scan())
        .await
        .unwrap()
        .unwrap();
    assert!(
        codec::decode_relay_scan(&scan).is_ok(),
        "SQLite checkpoint did not survive handler restart"
    );
    target.reject_dynamic.lock().unwrap().clear();
    for _ in 0..12 {
        let report = one_sql_relay_tick(&source, &partition, target.clone(), now).await;
        now = report.next_wake_ms.unwrap_or(now + 1).max(now + 1);
        if source
            .get(&partition, &keys::relay(1))
            .await
            .unwrap()
            .is_none()
            && source
                .get(&partition, &keys::relay(599))
                .await
                .unwrap()
                .is_none()
        {
            break;
        }
    }
    assert!(pending(&source, &partition).await.is_empty());
    assert_eq!(
        target.get(&a, &sql_order_key(1)).await.unwrap(),
        Some(codec::encode_u64(1))
    );
    assert_eq!(
        target.get(&a, &sql_order_key(599)).await.unwrap(),
        Some(codec::encode_u64(599))
    );
    let delivered: Vec<_> = target
        .batches()
        .iter()
        .flat_map(|batch| batch.writes.iter())
        .filter_map(|write| match write {
            Write::Put(k, v) if k.as_bytes().starts_with(b"delivered/") => {
                Some(codec::decode_u64(v).unwrap())
            }
            _ => None,
        })
        .collect();
    let a_delivered: Vec<_> = delivered.into_iter().filter(|seq| *seq <= 599).collect();
    assert_eq!(a_delivered, (1..=599).collect::<Vec<_>>());
}

#[tokio::test]
async fn sqlite_scan_state_guard_conflict_retries_without_deleting_rows() {
    let source = FaultSql::new(None);
    let target = FaultSql::new(None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    plant_sql_schedule(&source, &partition, &[0, 1, 0]).await;
    source.scan_conflict.store(true, Ordering::SeqCst);
    let first = one_sql_relay_tick(&source, &partition, target.clone(), 100).await;
    assert_eq!(first.failed, 1);
    assert_eq!(pending(&source, &partition).await.len(), 3);
    assert!(
        source
            .get(&partition, &keys::relay_scan())
            .await
            .unwrap()
            .is_none()
    );
    let now = first.next_wake_ms.unwrap();
    let second = one_sql_relay_tick(&source, &partition, target.clone(), now).await;
    assert_eq!(second.fired, 1);
    let mut now = second.next_wake_ms.unwrap_or(now + 1);
    for _ in 0..4 {
        if pending(&source, &partition).await.is_empty() {
            break;
        }
        let report = one_sql_relay_tick(&source, &partition, target.clone(), now).await;
        now = report.next_wake_ms.unwrap_or(now + 1).max(now + 1);
    }
    assert!(pending(&source, &partition).await.is_empty());
    assert_eq!(
        target
            .get(&Partition::ContentShard(0), &sql_order_key(1))
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
    assert_eq!(
        target
            .get(&Partition::ContentShard(0), &sql_order_key(3))
            .await
            .unwrap(),
        Some(codec::encode_u64(3))
    );
}

#[tokio::test]
async fn sqlite_full_source_relay_timer_reschedules_immediately_after_progress() {
    let conn = RusqliteConn::open_in_memory().unwrap();
    let source = FaultSql::with_store(SqlKvStore::open(conn.clone()).unwrap(), None);
    let partition = D34Shards.ref_shard(&repo(), "refs/heads/main");
    let a = Partition::ContentShard(0);
    let b = Partition::ContentShard(1);
    let a_key = Key::new(b"failed".to_vec());
    let b_key = Key::new(b"healthy".to_vec());
    queue(
        &source,
        &partition,
        vec![
            (a.clone(), vec![(a_key, Value::default())]),
            (b.clone(), vec![(b_key.clone(), Value::default())]),
        ],
    )
    .await;
    drop(source);
    // Soft limit zero forbids ordinary puts. The timer-move reserve keeps a
    // successful relay fire on its immediate schedule after an earlier retry.
    let source = FaultSql::with_store(
        SqlKvStore::open_with_capacity(conn, Capacity::new(1 << 20).with_reserve(1 << 20)).unwrap(),
        None,
    );
    let target = FaultSql::new(Some(a.clone()));
    let mut now = 100;
    for _ in 0..8 {
        let registry = TimerRegistry::new().register(RelayHandler {
            target: target.clone(),
            hook: NoHook,
            budget: sql_budget(2, 1, None),
        });
        let report = run_due(
            &source,
            &partition,
            &registry,
            &ManualClock::new(i64::try_from(now).unwrap()),
            now,
            &TickBudget::new(1, 1, 64, 10_000),
        )
        .await
        .unwrap();
        if target.get(&b, &b_key).await.unwrap().is_some() {
            assert_eq!(
                report.next_wake_ms,
                Some(now + 1),
                "full-shard timer move must preserve the immediate next fire"
            );
            break;
        }
        now = report.next_wake_ms.unwrap_or(now + 5_000).max(now + 1);
    }
    assert_eq!(
        target.get(&b, &b_key).await.unwrap(),
        Some(Value::default()),
        "a zero-soft-limit source kept the relay timer on failing A and starved B"
    );
    assert!(
        source
            .get(&partition, &keys::relay(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        source
            .get(&partition, &keys::relay(2))
            .await
            .unwrap()
            .is_none()
    );
}
