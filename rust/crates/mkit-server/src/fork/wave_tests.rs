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
    scan_repo_failures: Vec<u16>,
    partition_failures: Vec<u16>,
    partition_exhausted: Option<u16>,
    scan_exhausted: std::sync::atomic::AtomicI32,
    apply_failures: Vec<u16>,
    apply_deadlines: Vec<u16>,
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
            scan_repo_failures: Vec::new(),
            partition_failures: Vec::new(),
            partition_exhausted: None,
            scan_exhausted: std::sync::atomic::AtomicI32::new(-1),
            apply_failures: Vec::new(),
            apply_deadlines: Vec::new(),
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
        if matches!(p, Partition::RepoIndex { prefix, .. }
            if i32::from(*prefix) == self.scan_exhausted.load(Ordering::SeqCst))
        {
            return Err(StoreError::unavailable(crate::budget::BudgetExhausted));
        }
        if matches!(p, Partition::RepoIndex { prefix, .. } if self.scan_repo_failures.contains(prefix))
        {
            return Err(StoreError::unavailable("injected repo scan"));
        }
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
        if matches!(p, Partition::RepoIndex { prefix, .. } if self.apply_failures.contains(prefix))
        {
            return Err(StoreError::unavailable("injected apply"));
        }
        if matches!(p, Partition::RepoIndex { prefix, .. } if self.apply_deadlines.contains(prefix))
        {
            return Ok(BatchOutcome::DeadlinePassed {
                backend_now: 10_001,
            });
        }
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
        lanes: Vec::new(),
        after: None,
        scanned: 0,
        copied: 0,
        failure: None,
        settle: None,
        fence: None,
        fence_rows: crate::fork::FenceRowsV1::default(),
        source_access: crate::fork::SourceAccessV1::default(),
        accepted: None,
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
    assert_eq!(budget.used(), 2);
    assert_eq!(store.calls.load(Ordering::SeqCst), 2);
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

#[tokio::test(start_paused = true)]
async fn register_scans_keep_first_error_with_aliased_parent_budget() {
    let store = Probe {
        scan_repo_failures: vec![2, 3],
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
    let first = Budgeted::new(&store, &parent);
    let wrapped = Budgeted::new(&first, &parent);
    let clock = ManualClock::new(0);
    let env = ForkEnv {
        store: &wrapped,
        shards: &D34Shards,
        clock: &clock,
        takedown_denial: true,
        extract_min_bytes: Some(1),
        limits: ForkLimits::default(),
    };
    // Two inherited layers debit the same parent. A later sibling refusal
    // must not hide the earlier scan error at global partition position 18.
    let error = step(&env, &dest, &local).await.unwrap_err();
    assert!(matches!(error, ForkError::Unavailable(_)), "{error:?}");
    assert_eq!(store.calls.load(Ordering::SeqCst), 20);
    assert_eq!(parent.used(), 41);
    assert_eq!(local.used(), 1);
    assert!(!parent.refused());
    assert!(!local.refused());
}

fn object_of(lane: usize, n: usize) -> Hash {
    let mut object = [0; 32];
    object[0] = u8::try_from(lane).unwrap() << 4;
    object[1..3].copy_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
    object
}

const PACK: Hash = [5; 32];

/// `per_lane[i]` index rows of the pack in source partition `i`, each of
/// `size` decoded bytes.
async fn seed(store: &MemoryKv, per_lane: &[usize], size: u64) {
    let source = repo("source");
    for (lane, &count) in per_lane.iter().enumerate() {
        let partition = D34Shards.object_index_partitions(&source)[lane].clone();
        for chunk in (0..count).collect::<Vec<_>>().chunks(50) {
            let mut batch = Batch::new();
            for &n in chunk {
                let object = object_of(lane, n);
                let value = codec::encode_object_index(
                    &object,
                    &crate::store::index::IndexValue {
                        frame_offset: 0,
                        frame_length: 10,
                        wire_type: 0,
                        decoded_size: size,
                        chain_depth: 0,
                        delta_base: None,
                    },
                )
                .unwrap();
                batch = batch.put(keys::object_index(&source.name, &object, &PACK), value);
            }
            store.apply(&partition, batch).await.unwrap();
        }
    }
}

fn copy_job(expected: u64) -> ForkJobV1 {
    let mut job = job();
    job.packs = vec![PackRow {
        id: PACK,
        len: 1,
        objects: expected,
        node: false,
        base: false,
    }];
    job
}

fn env_with<'a>(
    store: &'a Probe,
    clock: &'a ManualClock,
    extract_min_bytes: Option<u64>,
) -> ForkEnv<'a, Probe> {
    ForkEnv {
        extract_min_bytes,
        ..env(store, clock)
    }
}

/// Index rows now in the destination.
async fn copied_rows(store: &MemoryKv) -> usize {
    let dest = repo("destination");
    let (start, end) = keys::object_index_repo_range(&dest.name);
    let mut total = 0;
    for partition in D34Shards.object_index_partitions(&dest) {
        let mut after = None;
        loop {
            let page = store
                .scan(&partition, &start, &end, after.as_ref(), 500)
                .await
                .unwrap();
            total += page.entries.len();
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
    }
    total
}

async fn finish_copy(env: &ForkEnv<'_, Probe>, job: &mut ForkJobV1, calls: u32) -> u32 {
    for slices in 1..300 {
        let budget = crate::budget::SliceBudget::new(calls);
        if copy::copy(env, job, &budget).await.unwrap() {
            return slices;
        }
    }
    panic!("copy did not finish");
}

#[tokio::test(start_paused = true)]
async fn copy_waves_read_partitions_together_and_a_page_needs_no_holder_budget() {
    // Few candidates: 300 rows per partition fit one 500-row page, so each of
    // the sixteen partitions costs a scan and four writes, in waves of six.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[300; 16], 1).await;
    let mut job = copy_job(4_800);
    let slices = finish_copy(&env_with(&store, &clock, None), &mut job, 600).await;
    assert_eq!(slices, 1);
    assert_eq!((job.scanned, job.copied), (4_800, 4_800));
    assert_eq!(copied_rows(&store.inner).await, 4_800);
    assert_eq!(store.calls.load(Ordering::SeqCst), 16 * 5);
    assert!(
        job.lanes
            .iter()
            .all(|lane| lane.done && lane.held.is_none())
    );
    assert!(store.peak.load(Ordering::SeqCst) > 1);
    assert!(store.peak.load(Ordering::SeqCst) <= 6);
}

#[tokio::test(start_paused = true)]
async fn extraction_pages_of_few_candidates_are_256_rows() {
    // 300 rows of 1 byte under a 1 MiB threshold: no candidate, two pages
    // each, and still one slice.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[300; 16], 1).await;
    let mut job = copy_job(4_800);
    let env = env_with(&store, &clock, Some(1 << 20));
    assert_eq!(finish_copy(&env, &mut job, 600).await, 1);
    assert_eq!(copied_rows(&store.inner).await, 4_800);
    // The manifest set read, then per partition: two scans and 3 + 1 writes.
    assert_eq!(store.calls.load(Ordering::SeqCst), 1 + 16 * 6);
}

#[tokio::test(start_paused = true)]
async fn a_page_of_many_holder_candidates_resumes_inside_the_page() {
    // 200 rows that are all candidates exceed the 64 one wave may copy.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[200], 10).await;
    let objects: Vec<Hash> = (0..200).map(|n| object_of(0, n)).collect();
    source_holders(&store.inner, &objects).await;
    let mut job = copy_job(200);
    let env = env_with(&store, &clock, Some(1));
    // 200 holders at up to six calls each outgrow one slice, so the page
    // spans slices without losing its place.
    assert!(finish_copy(&env, &mut job, 600).await > 1);
    assert_eq!((job.scanned, job.copied), (200, 200));
    let dest = job.dest().unwrap();
    let to = Holder::new(dest.namespace.clone(), dest.name.clone());
    let index = ContentIndex::new(BorrowedStore(&store.inner));
    for object in &objects {
        assert!(index.holder_record(object, &to).await.unwrap().is_some());
    }
    assert_eq!(copied_rows(&store.inner).await, 200);

    // The same page under a slice that ends inside it keeps its place and
    // finishes on later slices.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[200], 10).await;
    source_holders(&store.inner, &objects).await;
    let mut job = copy_job(200);
    let env = env_with(&store, &clock, Some(1));
    let budget = crate::budget::SliceBudget::new(200);
    assert!(!copy::copy(&env, &mut job, &budget).await.unwrap());
    let held = job.lanes[0].held.clone();
    assert!(held.is_some(), "the cut left the page");
    assert!(!job.lanes[0].done);
    assert_eq!((job.scanned, job.copied), (0, 0));
    // The mark survives the job row's own encoding between slices.
    let mut job = decode_job(&encode_job(&job).unwrap()).unwrap();
    assert_eq!(job.lanes[0].held, held);
    assert!(finish_copy(&env, &mut job, 200).await > 1);
    assert_eq!((job.scanned, job.copied), (200, 200));
    for object in &objects {
        assert!(index.holder_record(object, &to).await.unwrap().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn a_slice_spent_mid_wave_keeps_nothing_of_the_wave_and_resumes() {
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[20; 16], 1).await;
    let mut job = copy_job(320);
    let env = env_with(&store, &clock, None);
    // The second partition of the first wave runs out of calls.
    store.scan_exhausted.store(1, Ordering::SeqCst);
    let budget = crate::budget::SliceBudget::new(500);
    assert!(!copy::copy(&env, &mut job, &budget).await.unwrap());
    assert!(job.lanes.iter().all(|lane| *lane == CopyLane::default()));
    assert_eq!((job.scanned, job.copied), (0, 0));
    // The next slice repeats the wave and finishes the copy.
    store.scan_exhausted.store(-1, Ordering::SeqCst);
    assert_eq!(finish_copy(&env, &mut job, 500).await, 1);
    assert_eq!((job.scanned, job.copied), (320, 320));
    assert_eq!(copied_rows(&store.inner).await, 320);
}

#[tokio::test(start_paused = true)]
async fn any_slice_size_copies_the_same_rows() {
    for calls in [10, 14, 25, 90] {
        let (store, clock) = (Probe::default(), ManualClock::new(0));
        seed(&store.inner, &[30; 16], 1).await;
        let mut job = copy_job(480);
        finish_copy(&env_with(&store, &clock, None), &mut job, calls).await;
        assert_eq!((job.scanned, job.copied), (480, 480), "{calls} calls");
        assert_eq!(copied_rows(&store.inner).await, 480);
    }
}

#[tokio::test(start_paused = true)]
async fn copy_waves_report_the_first_failure_in_partition_order() {
    // Partition 0 holds more rows than the inventories count; partition 1's
    // scan fails. Partition 0 is first.
    let clock = ManualClock::new(0);
    let store = Probe {
        scan_repo_failures: vec![1],
        ..Probe::default()
    };
    seed(&store.inner, &[3, 3, 3], 1).await;
    let mut job = copy_job(2);
    let error = copy::copy(
        &env_with(&store, &clock, None),
        &mut job,
        &crate::budget::SliceBudget::new(500),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ForkError::NotFound);

    // Reversed: partition 0's scan fails and partition 1 holds the excess.
    let store = Probe {
        scan_repo_failures: vec![0],
        ..Probe::default()
    };
    seed(&store.inner, &[3, 3, 3], 1).await;
    let mut job = copy_job(2);
    let error = copy::copy(
        &env_with(&store, &clock, None),
        &mut job,
        &crate::budget::SliceBudget::new(500),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ForkError::Unavailable("fork storage unavailable"));

    // Neither failure: the counts disagree only in total.
    let store = Probe::default();
    seed(&store.inner, &[3, 3, 3], 1).await;
    let mut job = copy_job(10);
    let error = copy::copy(
        &env_with(&store, &clock, None),
        &mut job,
        &crate::budget::SliceBudget::new(500),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ForkError::NotFound);
}

#[tokio::test(start_paused = true)]
async fn an_unknown_read_allowance_copies_one_partition_at_a_time() {
    let (clock, store) = (
        ManualClock::new(0),
        Probe {
            opaque_allowance: true,
            ..Probe::default()
        },
    );
    seed(&store.inner, &[10; 16], 1).await;
    let mut job = copy_job(160);
    assert_eq!(
        finish_copy(&env_with(&store, &clock, None), &mut job, 600).await,
        1
    );
    assert_eq!(store.peak.load(Ordering::SeqCst), 1);
    assert_eq!(copied_rows(&store.inner).await, 160);
}

#[tokio::test(start_paused = true)]
async fn a_lane_the_wave_has_no_holder_room_for_is_not_written_twice() {
    // Two partitions of 100 candidates each; the slice pays for few holders,
    // so the first partition takes them all and the second gets none.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    seed(&store.inner, &[100, 100], 10).await;
    let objects: Vec<Hash> = (0..2)
        .flat_map(|lane| (0..100).map(move |n| object_of(lane, n)))
        .collect();
    source_holders(&store.inner, &objects).await;
    let mut job = copy_job(200);
    let env = env_with(&store, &clock, Some(1));
    assert!(
        !copy::copy(&env, &mut job, &crate::budget::SliceBudget::new(120))
            .await
            .unwrap()
    );
    assert!(
        job.lanes[0]
            .held
            .as_ref()
            .is_some_and(|mark| !mark.is_empty())
    );
    assert_eq!(job.lanes[1].held, Some(Vec::new()));
    assert_eq!(copied_rows(&store.inner).await, 200);
    let before = store.calls.load(Ordering::SeqCst);
    // Neither partition rewrites its rows now: writes stay at their count.
    assert!(finish_copy(&env, &mut job, 600).await >= 1);
    assert_eq!((job.scanned, job.copied), (200, 200));
    assert!(store.calls.load(Ordering::SeqCst) > before);
    let dest = job.dest().unwrap();
    let to = Holder::new(dest.namespace.clone(), dest.name.clone());
    let index = ContentIndex::new(BorrowedStore(&store.inner));
    for object in &objects {
        assert!(index.holder_record(object, &to).await.unwrap().is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn a_write_failure_in_one_partition_ends_the_wave_after_the_ones_before_it() {
    // Partition 1's write fails; partition 2 holds the excess rows. The
    // earlier partition decides: the write error, not the count.
    let clock = ManualClock::new(0);
    let store = Probe {
        apply_failures: vec![1],
        ..Probe::default()
    };
    seed(&store.inner, &[3, 3, 3], 1).await;
    let mut job = copy_job(7);
    let error = copy::copy(
        &env_with(&store, &clock, None),
        &mut job,
        &crate::budget::SliceBudget::new(500),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ForkError::Unavailable("fork storage unavailable"));
    assert_eq!(job.lanes, vec![CopyLane::default(); 16]);

    // A blocked holder of partition 0 is reported before partition 1's
    // write failure, as in the serial walk.
    let store = Probe {
        apply_failures: vec![1],
        ..Probe::default()
    };
    seed(&store.inner, &[3, 3], 10).await;
    let objects: Vec<Hash> = (0..3).map(|n| object_of(0, n)).collect();
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
    let mut job = copy_job(6);
    let error = copy::copy(
        &env_with(&store, &clock, Some(1)),
        &mut job,
        &crate::budget::SliceBudget::new(500),
    )
    .await
    .unwrap_err();
    assert_eq!(error, ForkError::NotFound);
}

#[tokio::test(start_paused = true)]
async fn a_wave_narrows_to_the_writes_the_slice_can_pay_for() {
    // Under a map that spreads one source partition over many destination
    // partitions, a page needs a write per row. Six such pages outgrow a fresh
    // slice, so the wave keeps only the lanes that fit and the copy finishes.
    let (store, clock) = (Probe::default(), ManualClock::new(0));
    let source = repo("source");
    let wide = Spread;
    let partitions = wide.object_index_partitions(&source);
    assert_eq!(partitions.len(), 16);
    for (lane, partition) in partitions.iter().enumerate().take(6) {
        let mut batch = Batch::new();
        for n in 0..100 {
            let object = object_of(lane, n);
            let value = codec::encode_object_index(
                &object,
                &crate::store::index::IndexValue {
                    frame_offset: 0,
                    frame_length: 10,
                    wire_type: 0,
                    decoded_size: 1,
                    chain_depth: 0,
                    delta_base: None,
                },
            )
            .unwrap();
            batch = batch.put(keys::object_index(&source.name, &object, &PACK), value);
        }
        store.inner.apply(partition, batch).await.unwrap();
    }
    let mut job = copy_job(600);
    let env = ForkEnv {
        shards: &wide,
        ..env_with(&store, &clock, None)
    };
    for slices in 1..20 {
        let budget = crate::budget::SliceBudget::new(600);
        if copy::copy(&env, &mut job, &budget).await.unwrap() {
            assert!(slices > 1, "six pages of 100 writes cannot share one slice");
            break;
        }
    }
    assert_eq!((job.scanned, job.copied), (600, 600));
}

/// Sixteen listed index partitions whose rows are routed over 4,096 by their
/// second and third bytes, so one source page writes to a partition per row.
struct Spread;

impl ShardMap for Spread {
    fn ref_shard(&self, repo: &RepoId, ref_name: &str) -> Partition {
        D34Shards.ref_shard(repo, ref_name)
    }
    fn coordinator(&self, ns: &NamespaceKey) -> Partition {
        D34Shards.coordinator(ns)
    }
    fn ref_index(&self, repo: &RepoId, ref_name: &str) -> Partition {
        D34Shards.ref_index(repo, ref_name)
    }
    fn ref_index_partitions(&self, repo: &RepoId) -> Vec<Partition> {
        D34Shards.ref_index_partitions(repo)
    }
    fn membership(&self, repo: &RepoId, pack: &crate::BlobKey) -> Partition {
        D34Shards.membership(repo, pack)
    }
    fn object_index(&self, repo: &RepoId, object: &Hash) -> Partition {
        Partition::RepoIndex {
            ns: repo.namespace.clone(),
            repo: repo.name.clone(),
            prefix: u16::from_be_bytes([object[1], object[2]]) % 4096,
        }
    }
    fn object_index_partitions(&self, repo: &RepoId) -> Vec<Partition> {
        D34Shards.object_index_partitions(repo)
    }
}

fn planned() -> job::ForkPlan {
    job::ForkPlan {
        packmap: [2; 32],
        generation: 3,
        packs: vec![PackRow {
            id: [2; 32],
            len: 10,
            objects: 1,
            node: true,
            base: false,
        }],
    }
}

fn view(packmap: Hash, generation: u64) -> plan::SourceView {
    plan::SourceView {
        packmap,
        sequence: 1,
        generation,
    }
}

#[test]
fn a_carried_plan_is_refused_unless_the_pair_is_the_one_it_was_computed_from() {
    // A moved packmap head or membership generation, same tip: not the set
    // that was planned and admitted.
    for (packmap, generation) in [([9; 32], 3), ([2; 32], 4)] {
        let mut job = job();
        job.phase = Phase::Plan;
        assert_eq!(
            planned()
                .carry(&view(packmap, generation), &mut job)
                .unwrap_err(),
            ForkError::TipChanged
        );
        assert_eq!(job.phase, Phase::Plan);
        assert!(job.packs.is_empty());
    }
    let mut job = job();
    job.phase = Phase::Plan;
    planned().carry(&view([2; 32], 3), &mut job).unwrap();
    assert_eq!(
        (job.phase, job.cursor, job.packs.len()),
        (Phase::Trees, 0, 1)
    );
    assert!(job.deps.is_empty());
}

#[test]
fn a_carried_plan_larger_than_the_admitted_bytes_is_refused_before_the_job_exists() {
    let mut job = job();
    job.phase = Phase::Plan;
    job.settle = Some(SettleV1 {
        rid: String::new(),
        pending: Vec::new(),
        repository: String::new(),
        replay: None,
        charges: Vec::new(),
        namespace_cap: None,
        declared_bytes: 9,
    });
    assert_eq!(
        planned().carry(&view([2; 32], 3), &mut job).unwrap_err(),
        ForkError::Quota(OVER_ADMITTED)
    );
    job.settle.as_mut().unwrap().declared_bytes = 10;
    planned().carry(&view([2; 32], 3), &mut job).unwrap();
    assert_eq!(job.phase, Phase::Trees);
}

#[test]
fn wave_width_is_one_without_a_known_allowance_and_bounded_by_the_slice() {
    let known = Probe::default();
    let unknown = Probe {
        opaque_allowance: true,
        ..Probe::default()
    };
    let whole = crate::budget::SliceBudget::new(SLICE_CALLS);
    assert_eq!(wave_width(&known, &whole, 8), WAVE_WIDTH);
    assert_eq!(wave_width(&unknown, &whole, 8), 1);
    let tight = crate::budget::SliceBudget::new(24);
    assert_eq!(wave_width(&known, &tight, 8), 3);
    let spent = crate::budget::SliceBudget::new(7);
    assert_eq!(wave_width(&known, &spent, 8), 1);
}

#[tokio::test(start_paused = true)]
async fn copy_wave_deadline_keeps_input_order_against_a_blocked_holder() {
    for deadline_first in [true, false] {
        let clock = ManualClock::new(0);
        let store = Probe {
            apply_deadlines: vec![u16::from(!deadline_first)],
            ..Probe::default()
        };
        seed(&store.inner, &[3, 3], 10).await;
        let object = object_of(usize::from(deadline_first), 1);
        source_holders(&store.inner, &[object]).await;
        store
            .inner
            .apply(
                &content_shard(&object),
                Batch::new().put(
                    keys::block(&object),
                    codec::encode_block_entry(&crate::store::BlockEntry::new("blocked", 0)),
                ),
            )
            .await
            .unwrap();
        let mut job = copy_job(6);
        let error = copy::copy(
            &env_with(&store, &clock, Some(1)),
            &mut job,
            &crate::budget::SliceBudget::new(500),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error,
            if deadline_first {
                ForkError::Unavailable("fork copy deadline")
            } else {
                ForkError::NotFound
            }
        );
        assert_eq!(job.lanes, vec![CopyLane::default(); 16]);
    }
}
