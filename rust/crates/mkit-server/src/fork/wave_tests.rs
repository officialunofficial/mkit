//! Operation counts, ordered failures, and replay guards for fork waves.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::indexed::budget::Budgeted;
use crate::pipeline::D34Shards;
use crate::store::{
    Batch, BatchOutcome, BorrowedStore, ContentIndex, Cursor, Holder, Key, NamespaceStore,
    Partition, PartitionStats, RangeScan, ScanPage, StoreCapabilities, StoreError, Value, codec,
    content_shard, keys,
};
use crate::{ManualClock, MemoryKv};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

struct Probe {
    inner: MemoryKv,
    calls: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    scan_nonempty: Option<u16>,
    partition_failures: Vec<u16>,
    partition_exhausted: Option<u16>,
    key_failure: Option<Key>,
    lost_reply: AtomicBool,
    stats_keys: Option<u64>,
    stats_failures: Vec<u16>,
    opaque_allowance: bool,
    retry_object: Option<Hash>,
    retry_attempts: AtomicUsize,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            inner: MemoryKv::with_clock(std::sync::Arc::new(ManualClock::new(0))),
            calls: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            scan_nonempty: None,
            partition_failures: Vec::new(),
            partition_exhausted: None,
            key_failure: None,
            lost_reply: AtomicBool::new(false),
            stats_keys: None,
            stats_failures: Vec::new(),
            opaque_allowance: false,
            retry_object: None,
            retry_attempts: AtomicUsize::new(0),
        }
    }
}

impl Probe {
    async fn delay(&self) {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        // Later calls finish sooner, so completion order cannot choose errors.
        tokio::time::sleep(Duration::from_millis(4 - u64::try_from(call % 4).unwrap())).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
    fn partition_error(&self, p: &Partition) -> Result<(), StoreError> {
        let number = match p {
            Partition::RefIndex { bucket, .. } => *bucket,
            Partition::RepoIndex { prefix, .. } => *prefix,
            _ => return Ok(()),
        };
        if self.partition_exhausted == Some(number) {
            return Err(StoreError::unavailable(crate::budget::BudgetExhausted));
        }
        if self.partition_failures.contains(&number) {
            return Err(StoreError::unavailable(format!(
                "injected partition {number}"
            )));
        }
        Ok(())
    }
    fn key_error(&self, keys: &[Key]) -> Result<(), StoreError> {
        if self
            .key_failure
            .as_ref()
            .is_some_and(|key| keys.contains(key))
        {
            return Err(StoreError::unavailable("injected key"));
        }
        Ok(())
    }
}

impl NamespaceStore for Probe {
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        (!self.opaque_allowance).then_some(u32::MAX)
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.delay().await;
        self.key_error(std::slice::from_ref(key))?;
        self.inner.get(p, key).await
    }
    async fn has(&self, p: &Partition, key: &Key) -> Result<bool, StoreError> {
        self.delay().await;
        self.key_error(std::slice::from_ref(key))?;
        self.inner.has(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.delay().await;
        self.key_error(keys)?;
        self.inner.get_many(p, keys).await
    }
    async fn scan_many(
        &self,
        p: &Partition,
        ranges: &[RangeScan],
    ) -> Result<Vec<ScanPage>, StoreError> {
        self.delay().await;
        self.partition_error(p)?;
        self.inner.scan_many(p, ranges).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.delay().await;
        self.partition_error(p)?;
        if matches!(p, Partition::RefIndex { bucket, .. } if Some(*bucket) == self.scan_nonempty) {
            return Ok(ScanPage {
                entries: vec![(start.clone(), Value::default())],
                next: None,
            });
        }
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.delay().await;
        if let Some(object) = self.retry_object
            && *p == content_shard(&object)
        {
            let attempt = self.retry_attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < 7 {
                if attempt == 6 {
                    self.inner
                        .apply(
                            p,
                            Batch::new().put(
                                keys::block(&object),
                                codec::encode_block_entry(&crate::store::BlockEntry::new(
                                    "blocked", 0,
                                )),
                            ),
                        )
                        .await?;
                }
                return Ok(BatchOutcome::PreconditionFailed {
                    index: 2,
                    observed: None,
                });
            }
        }
        let outcome = self.inner.apply(p, batch).await?;
        if self.lost_reply.swap(false, Ordering::SeqCst) {
            return Err(StoreError::unavailable("lost apply reply"));
        }
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.delay().await;
        self.partition_error(p)?;
        if matches!(p, Partition::RepoIndex { prefix, .. } if self.stats_failures.contains(prefix))
        {
            return Err(StoreError::unavailable("injected stats"));
        }
        if let Some(keys) = self.stats_keys {
            return Ok(PartitionStats {
                keys: Some(keys),
                bytes: 0,
            });
        }
        self.inner.stats(p).await
    }
}

fn repo(name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(name).unwrap(),
    }
}

fn env<'a>(store: &'a Probe, clock: &'a ManualClock) -> ForkEnv<'a, Probe> {
    ForkEnv {
        store,
        shards: &D34Shards,
        clock,
        takedown_denial: true,
        extract_min_bytes: Some(1),
        limits: ForkLimits::default(),
    }
}

fn job() -> ForkJobV1 {
    let source = repo("source");
    let dest = repo("destination");
    ForkJobV1 {
        binding: [9; 32],
        dest_ns: dest.namespace.as_str().into(),
        dest_repo: dest.name.as_str().into(),
        source_ns: source.namespace.as_str().into(),
        source_repo: source.name.as_str().into(),
        source_ref: "refs/heads/main".into(),
        tip: [1; 32],
        packmap: [2; 32],
        source_sequence: 1,
        source_generation: 0,
        visibility: "private".into(),
        created_ms: 0,
        expires_ms: JOB_TTL_MS,
        phase: Phase::Copy,
        packs: Vec::new(),
        cursor: 0,
        deps: Vec::new(),
        part: 0,
        after: None,
        scanned: 0,
        copied: 0,
        failure: None,
        settle: None,
        fence: None,
        result: None,
    }
}

#[tokio::test(start_paused = true)]
async fn empty_waves_keep_successful_scan_counts() {
    for (members, expected) in [(true, 32), (false, 16)] {
        let store = Probe::default();
        let clock = ManualClock::new(0);
        job::require_empty(&env(&store, &clock), &repo("destination"), members)
            .await
            .unwrap();
        assert_eq!(store.calls.load(Ordering::SeqCst), expected);
        assert!(store.peak.load(Ordering::SeqCst) > 1);
        assert!(store.peak.load(Ordering::SeqCst) <= 6);
    }
}

#[tokio::test(start_paused = true)]
async fn empty_waves_keep_not_empty_before_later_failure() {
    let store = Probe {
        scan_nonempty: Some(1),
        partition_failures: vec![2],
        ..Probe::default()
    };
    let clock = ManualClock::new(0);
    let error = job::require_empty(&env(&store, &clock), &repo("destination"), true)
        .await
        .unwrap_err();
    assert!(matches!(error, ForkError::NotEmpty));
    assert!(store.calls.load(Ordering::SeqCst) <= 6);
}

#[tokio::test(start_paused = true)]
async fn scannable_waves_charge_sixteen_stats_and_keep_error_order() {
    let clock = ManualClock::new(0);
    let store = Probe::default();
    let budget = crate::budget::SliceBudget::new(100);
    copy::require_scannable(&env(&store, &clock), &job(), &budget)
        .await
        .unwrap();
    assert_eq!(store.calls.load(Ordering::SeqCst), 16);
    assert_eq!(budget.used(), 16);
    assert!(store.peak.load(Ordering::SeqCst) > 1);
    assert!(store.peak.load(Ordering::SeqCst) <= 6);
    let store = Probe {
        partition_exhausted: Some(1),
        partition_failures: vec![2],
        ..Probe::default()
    };
    let error = copy::require_scannable(
        &env(&store, &clock),
        &job(),
        &crate::budget::SliceBudget::new(100),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, ForkError::Slice), "{error:?}");
}

async fn source_holders(store: &MemoryKv, objects: &[Hash]) {
    let source = repo("source");
    let holder = Holder::new(source.namespace, source.name);
    let index = ContentIndex::new(BorrowedStore(store));
    for object in objects {
        index
            .add_holder(object, &holder, &[8; 32], None, 0)
            .await
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn holder_waves_count_reads_and_writes_and_reenter_idempotently() {
    let store = Probe::default();
    // Distinct rows in one content partition still need no CAS retry.
    let mut objects = [[0x10; 32]; 4];
    for (n, object) in objects.iter_mut().enumerate() {
        object[31] = u8::try_from(n).unwrap();
    }
    source_holders(&store.inner, &objects[..3]).await;
    let clock = ManualClock::new(0);
    let job = job();
    for _ in 0..2 {
        let before = store.calls.load(Ordering::SeqCst);
        let budget = crate::budget::SliceBudget::new(400);
        copy::copy_holders(
            &env(&store, &clock),
            &Budgeted::new(&store, &budget),
            &budget,
            &job,
            &job.source().unwrap(),
            &job.dest().unwrap(),
            &objects,
        )
        .await
        .unwrap();
        assert_eq!(store.calls.load(Ordering::SeqCst) - before, 13);
        assert_eq!(budget.used(), 13);
    }
    let dest = job.dest().unwrap();
    let holder = Holder::new(dest.namespace, dest.name);
    let index = ContentIndex::new(BorrowedStore(&store.inner));
    for object in &objects[..3] {
        let record = index.holder_record(object, &holder).await.unwrap().unwrap();
        assert_eq!(record.op_id, job.binding);
        let raw = store
            .inner
            .get(&content_shard(object), &keys::object_state(object))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(codec::decode_object_state(&raw).unwrap().holders, 2);
    }
    assert!(
        index
            .holder_record(&objects[3], &holder)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.peak.load(Ordering::SeqCst) > 1);
    assert!(store.peak.load(Ordering::SeqCst) <= 4);
}

#[tokio::test(start_paused = true)]
async fn holder_waves_keep_blocked_before_later_io_error() {
    let objects = [[0x10; 32], [0x20; 32], [0x30; 32]];
    let source = repo("source");
    let holder = Holder::new(source.namespace, source.name);
    let store = Probe {
        key_failure: Some(keys::holder(&objects[2], &holder.ns, &holder.repo).unwrap()),
        ..Probe::default()
    };
    source_holders(&store.inner, &objects).await;
    store
        .inner
        .apply(
            &content_shard(&objects[1]),
            Batch::new().put(
                keys::block(&objects[1]),
                codec::encode_block_entry(&crate::store::BlockEntry::new("blocked", 0)),
            ),
        )
        .await
        .unwrap();
    let clock = ManualClock::new(0);
    let job = job();
    for calls in [400, 8] {
        let budget = crate::budget::SliceBudget::new(calls);
        let error = copy::copy_holders(
            &env(&store, &clock),
            &Budgeted::new(&store, &budget),
            &budget,
            &job,
            &job.source().unwrap(),
            &job.dest().unwrap(),
            &objects,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ForkError::NotFound), "{error:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn holder_waves_replay_a_committed_write_with_lost_reply_and_duplicates() {
    let store = Probe::default();
    let object = [0x10; 32];
    source_holders(&store.inner, &[object]).await;
    let clock = ManualClock::new(0);
    let job = job();
    store.lost_reply.store(true, Ordering::SeqCst);
    let budget = crate::budget::SliceBudget::new(100);
    assert!(
        copy::copy_holders(
            &env(&store, &clock),
            &Budgeted::new(&store, &budget),
            &budget,
            &job,
            &job.source().unwrap(),
            &job.dest().unwrap(),
            &[object]
        )
        .await
        .is_err()
    );
    let before = store.calls.load(Ordering::SeqCst);
    let budget = crate::budget::SliceBudget::new(100);
    copy::copy_holders(
        &env(&store, &clock),
        &Budgeted::new(&store, &budget),
        &budget,
        &job,
        &job.source().unwrap(),
        &job.dest().unwrap(),
        &[object, object],
    )
    .await
    .unwrap();
    assert_eq!(store.calls.load(Ordering::SeqCst) - before, 8);
    assert_eq!(budget.used(), 8);
    let raw = store
        .inner
        .get(&content_shard(&object), &keys::object_state(&object))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_object_state(&raw).unwrap().holders, 2);
}

#[tokio::test(start_paused = true)]
async fn scannable_waves_sum_every_partition_before_refusing() {
    let store = Probe {
        stats_keys: Some(MAX_SCANNED_ROWS / 16 + 1),
        ..Probe::default()
    };
    let budget = crate::budget::SliceBudget::new(16);
    let clock = ManualClock::new(0);
    assert!(matches!(
        copy::require_scannable(&env(&store, &clock), &job(), &budget).await,
        Err(ForkError::TooLarge)
    ));
    assert_eq!(store.calls.load(Ordering::SeqCst), 16);
    assert_eq!(budget.used(), 16);
}

#[tokio::test(start_paused = true)]
async fn empty_waves_preserve_budgeted_error_order_and_charges() {
    let store = Probe {
        scan_nonempty: Some(1),
        partition_failures: vec![2],
        ..Probe::default()
    };
    let budget = crate::budget::SliceBudget::new(3);
    let clock = ManualClock::new(0);
    let remote = Budgeted::new(&store, &budget);
    let env = ForkEnv {
        store: &remote,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: None,
        limits: ForkLimits::default(),
    };
    assert!(matches!(
        job::require_empty(&env, &repo("destination"), true).await,
        Err(ForkError::NotEmpty)
    ));
    assert_eq!(budget.used(), 3);
    assert_eq!(store.calls.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn scannable_tight_budget_observes_earlier_error_before_reserving_later_calls() {
    let store = Probe {
        partition_failures: vec![1, 2],
        ..Probe::default()
    };
    let budget = crate::budget::SliceBudget::new(2);
    let clock = ManualClock::new(0);
    assert!(matches!(
        copy::require_scannable(&env(&store, &clock), &job(), &budget).await,
        Err(ForkError::Unavailable(_))
    ));
    assert_eq!(budget.used(), 2);
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn holder_waves_keep_blocked_precedence_under_an_opaque_inherited_cap() {
    let objects = [[0x10; 32], [0x20; 32], [0x30; 32]];
    let source = repo("source");
    let from = Holder::new(source.namespace, source.name);
    let store = Probe {
        opaque_allowance: true,
        key_failure: Some(keys::holder(&objects[2], &from.ns, &from.repo).unwrap()),
        ..Probe::default()
    };
    source_holders(&store.inner, &objects).await;
    store
        .inner
        .apply(
            &content_shard(&objects[1]),
            Batch::new().put(
                keys::block(&objects[1]),
                codec::encode_block_entry(&crate::store::BlockEntry::new("blocked", 0)),
            ),
        )
        .await
        .unwrap();
    let clock = ManualClock::new(0);
    let parent_calls = crate::budget::SliceBudget::new(8);
    let parent = Budgeted::new(&store, &parent_calls);
    let local_calls = crate::budget::SliceBudget::new(100);
    let remote = Budgeted::new(&parent, &local_calls);
    let env = ForkEnv {
        store: &parent,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: Some(1),
        limits: ForkLimits::default(),
    };
    let job = job();
    assert!(matches!(
        copy::copy_holders(
            &env,
            &remote,
            &local_calls,
            &job,
            &job.source().unwrap(),
            &job.dest().unwrap(),
            &objects
        )
        .await,
        Err(ForkError::NotFound)
    ));
    assert_eq!(local_calls.used(), 8);
    assert_eq!(parent_calls.used(), 8);
    assert_eq!(store.calls.load(Ordering::SeqCst), 8);
    assert!(!parent_calls.refused());
    assert_eq!(store.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn holder_waves_keep_a_retrying_block_before_an_aliased_cap() {
    let objects = [[0x10; 32], [0x20; 32]];
    let store = Probe {
        retry_object: Some(objects[0]),
        ..Probe::default()
    };
    source_holders(&store.inner, &objects).await;
    let shared_calls = crate::budget::SliceBudget::new(50);
    let inner = Budgeted::new(&store, &shared_calls);
    let outer = Budgeted::new(&inner, &shared_calls);
    let local_calls = crate::budget::SliceBudget::new(600);
    let remote = Budgeted::new(&outer, &local_calls);
    let clock = ManualClock::new(0);
    let env = ForkEnv {
        store: &outer,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: Some(1),
        limits: ForkLimits::default(),
    };
    let job = job();
    let error = copy::copy_holders(
        &env,
        &remote,
        &local_calls,
        &job,
        &job.source().unwrap(),
        &job.dest().unwrap(),
        &objects,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, ForkError::NotFound), "{error:?}");
    assert_eq!(store.retry_attempts.load(Ordering::SeqCst), 8);
    assert_eq!(store.calls.load(Ordering::SeqCst), 25);
    assert_eq!(local_calls.used(), 25);
    assert_eq!(shared_calls.used(), 50);
    assert!(!shared_calls.refused());
    assert_eq!(store.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn register_stats_keep_first_error_with_shared_parent_budget() {
    let store = Probe {
        stats_failures: vec![0, 1],
        ..Probe::default()
    };
    let mut job = job();
    job.phase = Phase::Register;
    let dest = job.dest().unwrap();
    store
        .inner
        .apply(
            &D34Shards.coordinator(&dest.namespace),
            Batch::new().put(keys::fork_job(&dest.name), super::encode_job(&job).unwrap()),
        )
        .await
        .unwrap();
    let parent = crate::budget::SliceBudget::new(41);
    let local = parent.child(41);
    let wrapped = Budgeted::new(&store, &parent);
    let clock = ManualClock::new(0);
    let env = ForkEnv {
        store: &wrapped,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: Some(1),
        limits: ForkLimits::default(),
    };
    // Registration leaves six shared calls. Eagerly debiting six local stats
    // would refuse the first backend call and hide its earlier I/O error.
    let error = step(&env, &dest, &local).await.unwrap_err();
    assert!(matches!(error, ForkError::Unavailable(_)), "{error:?}");
    assert_eq!(store.calls.load(Ordering::SeqCst), 35);
    assert_eq!(parent.used(), 37);
    assert_eq!(local.used(), 2);
    assert!(!parent.refused());
    assert!(!local.refused());
}
