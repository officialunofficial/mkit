#![allow(clippy::unwrap_used)]

use super::*;
use crate::pipeline::{D34Shards, ShardMap, SinglePartition};
use crate::store::{
    Key,
    codec::{self, RelayV1},
    outbox::{MAX_RELAY_PUTS, OutboxBuilder},
    tickets,
};
use crate::timers::{
    DueTimer, Fired, TickBudget, TimerCtx, TimerHandler, TimerRegistry, registry::kinds, run_due,
};
use crate::{
    Batch, BatchOutcome, BoxFuture, Cursor, ManualClock, MemoryKv, NamespaceKey, PartitionStats,
    Precondition, RepoId, RepoName, ScanPage, StoreCapabilities, Value, Write,
};
use std::collections::BTreeSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

fn source() -> Partition {
    Partition::Ref {
        ns: NamespaceKey::deployment_default(),
        repo: RepoName::new("a").unwrap(),
        shard_ref: "refs/heads/main".into(),
    }
}
fn target(i: u16) -> Partition {
    Partition::ContentShard(i)
}
fn key() -> Key {
    Key::new(b"index-key".to_vec())
}
fn memory() -> MemoryKv {
    MemoryKv::with_clock(Arc::new(ManualClock::new(100)))
}
fn handler<T>(target: T) -> RelayHandler<T> {
    RelayHandler {
        target,
        hook: NoHook,
        budget: RelayBudget::default(),
    }
}

async fn append<S: NamespaceStore>(
    store: &S,
    target: &Partition,
    puts: Vec<(Key, Value)>,
    now: u64,
) -> Batch {
    let os = store
        .get(&source(), &keys::outbox_sequence())
        .await
        .unwrap();
    let mut builder = OutboxBuilder::new(os.as_ref(), None).unwrap();
    builder.relay_at(now);
    builder.relay(target, puts);
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        store.apply(&source(), batch.clone()).await.unwrap(),
        BatchOutcome::Committed
    );
    batch
}

async fn append_delete<S: NamespaceStore>(store: &S, target: &Partition, key: Key) {
    let os = store
        .get(&source(), &keys::outbox_sequence())
        .await
        .unwrap();
    let mut builder = OutboxBuilder::new(os.as_ref(), None).unwrap();
    builder.relay_at(50);
    builder.relay_delete(target, vec![key]);
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        store.apply(&source(), batch).await.unwrap(),
        BatchOutcome::Committed
    );
}

#[tokio::test]
async fn relay_delete_orders_after_put_and_redelivery_is_idempotent() {
    let source_store = memory();
    let h = handler(memory());
    let target = target(0);
    let key = key();
    append(
        &source_store,
        &target,
        vec![(key.clone(), Value::new(b"old".as_slice()))],
        50,
    )
    .await;
    append_delete(&source_store, &target, key.clone()).await;
    fire(&h, &source_store).await.unwrap();
    assert_eq!(h.target.get(&target, &key).await.unwrap(), None);
    assert_eq!(
        h.target
            .get(&target, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(2))
    );
    fire(&h, &source_store).await.unwrap();
    assert_eq!(h.target.get(&target, &key).await.unwrap(), None);

    append(
        &source_store,
        &target,
        vec![(key.clone(), Value::new(b"new".as_slice()))],
        50,
    )
    .await;
    append(
        &source_store,
        &target,
        vec![(key.clone(), Value::new(b"newer".as_slice()))],
        50,
    )
    .await;
    fire(&h, &source_store).await.unwrap();
    assert_eq!(
        h.target.get(&target, &key).await.unwrap(),
        Some(Value::new(b"newer".as_slice()))
    );
}
async fn queued<S: NamespaceStore>(store: &S) -> Vec<(Key, Value)> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    let mut rows = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .scan(&source(), &start, &end, cursor.as_ref(), 1000)
            .await
            .unwrap();
        rows.extend(page.entries);
        match page.next {
            Some(next) => cursor = Some(next),
            None => return rows,
        }
    }
}
async fn fire<S: NamespaceStore, T: NamespaceStore, H: RelayHook>(
    h: &RelayHandler<T, H>,
    store: &S,
) -> Result<Fired, StoreError> {
    h.fire(
        &TimerCtx {
            store,
            partition: &source(),
            now_ms: 100,
        },
        &DueTimer {
            due_at_ms: 100,
            kind: kinds::RELAY,
            reference: bytes::Bytes::default(),
            value: Value::default(),
        },
    )
    .await
}

struct Instrumented {
    inner: MemoryKv,
    fail_target: Option<Partition>,
    fail_targets: Vec<Partition>,
    calls: Arc<AtomicUsize>,
    scanned: AtomicUsize,
    fail_delete: AtomicBool,
    race_watermark: AtomicBool,
    append_on_drain: Mutex<Option<Batch>>,
    applies: Arc<Mutex<Vec<(Partition, Batch)>>>,
    short_pages: bool,
    fail_watermark_after_apply: bool,
    reject: Mutex<BTreeSet<Partition>>,
    fail_first: Mutex<BTreeSet<Partition>>,
    successful: Mutex<Vec<(Partition, Batch)>>,
    scan_conflict: AtomicBool,
}
impl Instrumented {
    fn new() -> Self {
        Self {
            inner: memory(),
            fail_target: None,
            fail_targets: Vec::new(),
            calls: Arc::new(AtomicUsize::new(0)),
            scanned: AtomicUsize::new(0),
            fail_delete: AtomicBool::new(false),
            race_watermark: AtomicBool::new(false),
            append_on_drain: Mutex::new(None),
            applies: Arc::new(Mutex::new(Vec::new())),
            short_pages: false,
            fail_watermark_after_apply: false,
            reject: Mutex::default(),
            fail_first: Mutex::default(),
            successful: Mutex::default(),
            scan_conflict: AtomicBool::new(false),
        }
    }
}
impl NamespaceStore for Instrumented {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_watermark_after_apply
            && matches!(keys::parse(k), Some(keys::ParsedKey::RelayHighWater(_)))
            && !self.applies.lock().unwrap().is_empty()
        {
            return Err(StoreError::unavailable(std::io::Error::other(
                "watermark read interrupted",
            )));
        }
        self.inner.get(p, k).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let page = self
            .inner
            .scan(
                partition,
                start,
                end,
                after,
                if self.short_pages {
                    limit.min(1)
                } else {
                    limit
                },
            )
            .await?;
        self.scanned.fetch_add(page.entries.len(), Ordering::SeqCst);
        if start == &keys::class_range(keys::TAG_RELAY).0 && page.entries.is_empty() {
            let writer = self.append_on_drain.lock().unwrap().take();
            if let Some(batch) = writer {
                assert_eq!(
                    self.inner.apply(partition, batch).await?,
                    BatchOutcome::Committed
                );
            }
        }
        Ok(page)
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.applies.lock().unwrap().push((p.clone(), b.clone()));
        if self.fail_target.as_ref() == Some(p)
            || self.fail_targets.contains(p)
            || self.reject.lock().unwrap().contains(p)
            || self.fail_first.lock().unwrap().remove(p)
        {
            return Err(StoreError::Full);
        }
        if b.writes.iter().any(|w| matches!(w,Write::Delete(k) if matches!(keys::parse(k),Some(keys::ParsedKey::Relay(_))))) && self.fail_delete.swap(false,Ordering::SeqCst) { return Err(StoreError::Full); }
        if self.race_watermark.swap(false, Ordering::SeqCst) {
            // A concurrent deliverer applies exactly the first row before our stale guard.
            let rh = keys::relay_high_water(&source())?;
            self.inner
                .apply(
                    p,
                    Batch::new()
                        .put(key(), Value::new(b"concurrent".to_vec()))
                        .put(rh, codec::encode_u64(1)),
                )
                .await?;
        }
        let scan_key = keys::relay_scan();
        if p == &source()
            && self.scan_conflict.load(Ordering::SeqCst)
            && let Some(index) = b.preconditions.iter().position(|pre| {
                matches!(pre, Precondition::Absent(k) | Precondition::Equals(k, _) if k == &scan_key)
            })
        {
            self.scan_conflict.store(false, Ordering::SeqCst);
            return Ok(BatchOutcome::PreconditionFailed { index, observed: None });
        }
        let result = self.inner.apply(p, b.clone()).await?;
        if result == BatchOutcome::Committed {
            self.successful.lock().unwrap().push((p.clone(), b));
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

/// Forces overlapping fires to yield around every store call. The number
/// of yields varies with the property seed and the concurrent call order.
struct Yielding<'a, S> {
    inner: &'a S,
    seed: u64,
    calls: AtomicUsize,
}

impl<'a, S> Yielding<'a, S> {
    fn new(inner: &'a S, seed: u64) -> Self {
        Self {
            inner,
            seed,
            calls: AtomicUsize::new(0),
        }
    }

    async fn jitter(&self) {
        let n = u64::try_from(self.calls.fetch_add(1, Ordering::SeqCst)).unwrap();
        let mut bits = n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ self.seed;
        bits ^= bits >> 30;
        bits = bits.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        for _ in 0..=bits % 3 {
            tokio::task::yield_now().await;
        }
    }
}

impl<S: NamespaceStore> NamespaceStore for Yielding<'_, S> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.jitter().await;
        let result = self.inner.get(p, key).await;
        self.jitter().await;
        result
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.jitter().await;
        let result = self.inner.scan(p, start, end, after, limit).await;
        self.jitter().await;
        result
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.jitter().await;
        let result = self.inner.apply(p, batch).await;
        self.jitter().await;
        result
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.jitter().await;
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.jitter().await;
        self.inner.probe().await
    }
}

#[tokio::test]
async fn delivery_sequence_order_and_watermark_dedup_preserve_newer_values() {
    let s = memory();
    let t = Instrumented::new();
    append(
        &s,
        &target(0),
        vec![(key(), Value::new(b"first".to_vec()))],
        50,
    )
    .await;
    // Sequence allocation is shared with outcomes and need not be contiguous.
    s.apply(
        &source(),
        Batch::new().put(keys::outbox_sequence(), codec::encode_u64(7)),
    )
    .await
    .unwrap();
    append(
        &s,
        &target(0),
        vec![(key(), Value::new(b"last".to_vec()))],
        60,
    )
    .await;
    let saved = queued(&s).await;
    let h = handler(t);
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Done(_)));
    assert!(queued(&s).await.is_empty());
    assert_eq!(
        h.target.get(&target(0), &key()).await.unwrap(),
        Some(Value::new(b"last".to_vec()))
    );
    assert_eq!(
        h.target
            .get(&target(0), &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(8))
    );
    {
        let batches = h.target.applies.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(
            batches[0].1.writes[0],
            Write::Put(key(), Value::new(b"first".to_vec()))
        );
        assert_eq!(
            batches[0].1.writes[1],
            Write::Put(key(), Value::new(b"last".to_vec()))
        );
    }
    h.target
        .inner
        .apply(
            &target(0),
            Batch::new().put(key(), Value::new(b"newer".to_vec())),
        )
        .await
        .unwrap();
    let mut restore = Batch::new();
    for (k, v) in saved {
        restore = restore.put(k, v);
    }
    s.apply(&source(), restore).await.unwrap();
    fire(&h, &s).await.unwrap();
    assert!(queued(&s).await.is_empty());
    assert_eq!(
        h.target.applies.lock().unwrap().len(),
        1,
        "duplicate delivery must not apply any target batch"
    );
    assert_eq!(
        h.target.get(&target(0), &key()).await.unwrap(),
        Some(Value::new(b"newer".to_vec()))
    );
}

#[tokio::test]
async fn crash_after_target_apply_retries_cleanup_without_reapplying() {
    let s = Instrumented::new();
    let h = handler(Instrumented::new());
    append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    s.fail_delete.store(true, Ordering::SeqCst);
    assert!(fire(&h, &s).await.is_err());
    assert_eq!(queued(&s).await.len(), 1);
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Done(_)));
    assert!(queued(&s).await.is_empty());
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn identical_index_rows_from_two_sources_survive_redelivery() {
    let s = Instrumented::new();
    let h = handler(Instrumented::new());
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("a").unwrap(),
    };
    let object = [0x12; 32];
    let pack = [0x34; 32];
    let target = D34Shards.object_index(&repo, &object);
    let index_key = keys::object_index(&repo.name, &object, &pack);
    let value = codec::encode_object_index(
        &object,
        &crate::store::index::IndexValue {
            frame_offset: 7,
            frame_length: 19,
            wire_type: 0,
            decoded_size: 24,
            chain_depth: 0,
            delta_base: None,
        },
    )
    .unwrap();
    append(&s, &target, vec![(index_key.clone(), value.clone())], 50).await;
    let second = Partition::Ref {
        ns: repo.namespace.clone(),
        repo: repo.name.clone(),
        shard_ref: "refs/heads/second".into(),
    };
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.relay_at(50);
    builder.relay(&target, vec![(index_key.clone(), value.clone())]);
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        s.apply(&second, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    s.fail_delete.store(true, Ordering::SeqCst);
    assert!(fire(&h, &s).await.is_err());
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
    s.fail_delete.store(false, Ordering::SeqCst);
    fire(&h, &s).await.unwrap();
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
    h.fire(
        &TimerCtx {
            store: &s,
            partition: &second,
            now_ms: 100,
        },
        &DueTimer {
            due_at_ms: 100,
            kind: kinds::RELAY,
            reference: bytes::Bytes::default(),
            value: Value::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(h.target.applies.lock().unwrap().len(), 2);
    assert_eq!(
        h.target.get(&target, &index_key).await.unwrap(),
        Some(value)
    );
    assert_eq!(
        h.target
            .get(&target, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
    assert_eq!(
        h.target
            .get(&target, &keys::relay_high_water(&second).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
}

#[tokio::test]
async fn failed_target_retains_its_later_rows_while_other_targets_commit() {
    let s = memory();
    let mut t = Instrumented::new();
    t.fail_target = Some(target(0));
    let h = handler(t);
    for p in [target(0), target(1), target(0)] {
        append(&s, &p, vec![(key(), Value::default())], 50).await;
    }
    assert!(matches!(
        fire(&h, &s).await.unwrap(),
        Fired::Reschedule { due_at_ms: 101, .. }
    ));
    let remaining = queued(&s).await;
    assert_eq!(remaining.len(), 2);
    assert!(
        remaining
            .iter()
            .all(|(_, v)| codec::decode_relay(v).unwrap().target == target(0))
    );
    assert_eq!(
        h.target
            .get(&target(1), &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(2))
    );
    assert_eq!(
        h.target
            .applies
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == &target(0))
            .count(),
        1
    );
}

#[tokio::test]
async fn retried_relay_progress_reschedules_after_its_physical_wake() {
    let s = memory();
    let t = memory();
    for destination in [target(0), target(1)] {
        append(&s, &destination, vec![(key(), Value::default())], 100).await;
    }
    let retry = keys::timer_retry(5100, kinds::RELAY.get(), b"", 100, 1);
    s.apply(
        &source(),
        Batch::new()
            .delete(keys::timer(100, kinds::RELAY.get(), b""))
            .put(retry.clone(), Value::default()),
    )
    .await
    .unwrap();
    let mut h = handler(t);
    h.budget.max_targets = 1;
    let registry = TimerRegistry::new().register(h);
    let clock = ManualClock::new(5100);
    let report = run_due(
        &s,
        &source(),
        &registry,
        &clock,
        5100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!((report.fired, report.failed), (1, 0));
    assert_eq!(report.next_wake_ms, Some(5101));
    assert_eq!(queued(&s).await.len(), 1);
    assert_eq!(s.get(&source(), &retry).await.unwrap(), None);
    assert_eq!(
        s.get(&source(), &keys::timer(5101, kinds::RELAY.get(), b""))
            .await
            .unwrap(),
        Some(Value::default())
    );
    clock.set(5101);
    let report = run_due(
        &s,
        &source(),
        &registry,
        &clock,
        5101,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        (report.fired, report.failed, report.next_wake_ms),
        (1, 0, None)
    );
    assert!(queued(&s).await.is_empty());
}

#[tokio::test]
async fn same_millisecond_writer_during_fire_cannot_lose_wakeup() {
    let s = Instrumented::new();
    let t = memory();
    append(
        &s,
        &target(0),
        vec![(key(), Value::new(b"old".to_vec()))],
        100,
    )
    .await;
    let os = s.get(&source(), &keys::outbox_sequence()).await.unwrap();
    let mut b = OutboxBuilder::new(os.as_ref(), None).unwrap();
    b.relay_at(100);
    b.relay(&target(0), vec![(key(), Value::new(b"new".to_vec()))]);
    let mut writer = Batch::new();
    b.try_finish(&mut writer.preconditions, &mut writer.writes)
        .unwrap();
    // Barrier at the final scan's return: the empty snapshot is already read,
    // then a writer commits its rows and identical timer before fire returns Done.
    *s.append_on_drain.lock().unwrap() = Some(writer);
    let registry = TimerRegistry::new().register(handler(t));
    let clock = ManualClock::new(100);
    let report = run_due(
        &s,
        &source(),
        &registry,
        &clock,
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.raced, 1);
    assert_eq!(queued(&s).await.len(), 1);
    let retry = keys::timer_retry(5100, 3, b"", 100, 1);
    assert_eq!(report.next_wake_ms, Some(5100));
    assert_eq!(
        s.get(&source(), &retry).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(
        s.get(&source(), &keys::timer(100, 3, b"")).await.unwrap(),
        None
    );
    let early = run_due(
        &s,
        &source(),
        &registry,
        &clock,
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(early.fired, 0);
    assert_eq!(queued(&s).await.len(), 1);
    assert_eq!(
        s.get(&source(), &retry).await.unwrap(),
        Some(Value::default())
    );
    clock.set(5100);
    let report = run_due(
        &s,
        &source(),
        &registry,
        &clock,
        5100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(queued(&s).await.is_empty());
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    assert!(
        s.scan(&source(), &start, &end, None, 1)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}

#[tokio::test]
async fn budgets_reschedule_and_short_pages_are_followed() {
    for budget in [
        RelayBudget {
            max_rows: 2,
            max_targets: 16,
            max_target_calls: None,
        },
        RelayBudget {
            max_rows: 256,
            max_targets: 1,
            max_target_calls: None,
        },
    ] {
        let mut s = Instrumented::new();
        s.short_pages = true;
        for i in 0..3 {
            append(&s, &target(i), vec![(key(), Value::default())], 50).await;
        }
        let h = RelayHandler {
            budget,
            ..handler(memory())
        };
        let outcome = fire(&h, &s).await.unwrap();
        if budget.max_targets == 1 {
            assert!(matches!(outcome, Fired::Reschedule { due_at_ms: 101, .. }));
        } else {
            assert!(matches!(outcome, Fired::Done(_)));
        }
        assert_eq!(
            queued(&s.inner).await.len(),
            if budget.max_targets == 1 { 2 } else { 0 }
        );
    }
}

#[tokio::test]
async fn corrupt_row_delivers_decodable_prefix_then_stops() {
    let s = memory();
    let h = handler(Instrumented::new());
    append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    s.apply(
        &source(),
        Batch::new()
            .put(keys::relay(2), Value::new(b"bad".to_vec()))
            .put(keys::outbox_sequence(), codec::encode_u64(2)),
    )
    .await
    .unwrap();
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Retry));
    assert_eq!(queued(&s).await.len(), 1);
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
}

struct Hook {
    fail: Option<Partition>,
    condition_fails: bool,
}
impl RelayHook for Hook {
    fn before_apply<'a>(
        &'a self,
        p: &'a Partition,
        rows: &'a [(u64, RelayV1)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            assert!(!rows.is_empty());
            if self.fail.as_ref() == Some(p) {
                return Err(StoreError::Full);
            }
            if self.condition_fails {
                pre.push(Precondition::Present(Key::new(b"missing".to_vec())));
            }
            writes.push(Write::Put(
                Key::new(b"hook".to_vec()),
                codec::encode_u64(rows.last().unwrap().0),
            ));
            Ok(())
        })
    }
}
#[tokio::test]
async fn hook_effects_are_atomic_and_errors_isolate_targets() {
    let s = memory();
    let h = RelayHandler {
        target: memory(),
        hook: Hook {
            fail: Some(target(0)),
            condition_fails: false,
        },
        budget: RelayBudget::default(),
    };
    for p in [target(0), target(1)] {
        append(&s, &p, vec![(key(), Value::default())], 50).await;
    }
    fire(&h, &s).await.unwrap();
    assert_eq!(queued(&s).await.len(), 1);
    assert_eq!(
        h.target
            .get(&target(1), &Key::new(b"hook".to_vec()))
            .await
            .unwrap(),
        Some(codec::encode_u64(2))
    );
    assert!(h.target.get(&target(0), &key()).await.unwrap().is_none());
    let h = RelayHandler {
        target: memory(),
        hook: Hook {
            fail: None,
            condition_fails: true,
        },
        budget: RelayBudget::default(),
    };
    fire(&h, &s).await.unwrap();
    for k in [
        key(),
        Key::new(b"hook".to_vec()),
        keys::relay_high_water(&source()).unwrap(),
    ] {
        assert!(h.target.get(&target(0), &k).await.unwrap().is_none());
    }
    assert_eq!(queued(&s).await.len(), 1);
}

#[tokio::test]
async fn concurrent_watermark_advance_is_reread_and_retried_once() {
    let s = memory();
    let t = Instrumented::new();
    t.race_watermark.store(true, Ordering::SeqCst);
    for v in [b"first", b"later"] {
        append(&s, &target(0), vec![(key(), Value::new(v.to_vec()))], 50).await;
    }
    let h = handler(t);
    fire(&h, &s).await.unwrap();
    assert!(queued(&s).await.is_empty());
    assert_eq!(h.target.applies.lock().unwrap().len(), 2);
    assert_eq!(
        h.target.get(&target(0), &key()).await.unwrap(),
        Some(Value::new(b"later".to_vec()))
    );
    assert_eq!(
        h.target.applies.lock().unwrap()[1].1.writes.len(),
        2,
        "retry drops concurrently committed first row"
    );
}

#[tokio::test]
async fn multirow_target_batches_and_source_deletes_respect_operation_limits() {
    let s = Instrumented::new();
    let h = handler(Instrumented::new());
    for i in 0..55 {
        append(
            &s,
            &target(0),
            vec![
                (Key::new(vec![i, 0]), Value::default()),
                (Key::new(vec![i, 1]), Value::default()),
            ],
            50,
        )
        .await;
    }
    // Two puts per row require multiple target batches; >50 rows require multiple deletes.
    fire(&h, &s).await.unwrap();
    assert!(queued(&s).await.is_empty());
    assert_eq!(h.target.applies.lock().unwrap().len(), 2);
    assert_eq!(
        s.applies
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, b)| b.writes.iter().any(|w| matches!(w, Write::Delete(_))))
            .count(),
        2
    );
    for (_, b) in s.applies.lock().unwrap().iter() {
        b.validate(&StoreCapabilities::full()).unwrap();
    }
}

#[tokio::test]
async fn local_watermark_and_membership_planner_in_both_shard_modes() {
    let s = memory();
    assert_eq!(relay_watermark(&s, &source(), 100).await.unwrap(), 100);
    append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    append(&s, &target(1), vec![(key(), Value::default())], 60).await;
    assert_eq!(relay_watermark(&s, &source(), 100).await.unwrap(), 49);
    fire(&handler(memory()), &s).await.unwrap();
    assert_eq!(relay_watermark(&s, &source(), 101).await.unwrap(), 101);
    for shards in [
        &SinglePartition as &dyn ShardMap,
        &D34Shards as &dyn ShardMap,
    ] {
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("a").unwrap(),
        };
        let p = shards.ref_shard(&repo, "refs/heads/main");
        let s = memory();
        let t = memory();
        let mut builder = OutboxBuilder::new(None, None).unwrap();
        builder.relay_at(50);
        let mut batch = Batch::new();
        tickets::plan_membership(
            &repo.name,
            &[[1; 32]],
            &p,
            shards,
            &repo,
            &mut builder,
            &mut batch.writes,
        );
        builder
            .try_finish(&mut batch.preconditions, &mut batch.writes)
            .unwrap();
        s.apply(&p, batch).await.unwrap();
        assert!(
            s.get(&p, &keys::membership(&repo.name, &[1; 32]))
                .await
                .unwrap()
                .is_some()
        );
        if p == source() {
            fire(&handler(t), &s).await.unwrap();
            assert!(queued(&s).await.is_empty());
        } else {
            assert!(s.get(&p, &keys::outbox_sequence()).await.unwrap().is_none());
            assert!(s.get(&p, &keys::timer(50, 3, b"")).await.unwrap().is_none());
        }
    }
}

#[test]
fn maximal_chunk_fits_target_and_more_puts_split_in_seq_order() {
    let p = Partition::Ref {
        ns: NamespaceKey::from_stored(format!("ed25519-{}", "a".repeat(64))),
        repo: RepoName::new("r".repeat(255)).unwrap(),
        shard_ref: format!("refs/heads/{}", "b".repeat(501)),
    };
    let rh = keys::relay_high_water(&p).unwrap();
    assert_eq!(rh.as_bytes().len(), 846);
    assert_eq!(keys::parse(&rh), Some(keys::ParsedKey::RelayHighWater(p)));
    let mut builder = OutboxBuilder::new(None, None).unwrap();
    builder.relay_at(12);
    let mut puts: Vec<_> = (0..=MAX_RELAY_PUTS)
        .map(|i| {
            (
                Key::new(vec![u8::try_from(i).unwrap(); 1024]),
                Value::new(vec![0; 1600]),
            )
        })
        .collect();
    let encoded_size = codec::encode_relay(&RelayV1 {
        at_ms: 12,
        target: target(0),
        puts: puts[..MAX_RELAY_PUTS].to_vec(),
        deletes: Vec::new(),
    })
    .unwrap()
    .as_bytes()
    .len();
    let padding = (crate::MAX_VALUE_BYTES - encoded_size) / 2;
    puts[MAX_RELAY_PUTS - 1].1 = Value::new(vec![0; 1600 + padding]);
    builder.relay(&target(0), puts);
    let mut batch = Batch::new();
    builder
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    let rows = batch
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::Put(k, v) if matches!(keys::parse(k), Some(keys::ParsedKey::Relay(_))) => {
                Some((k, codec::decode_relay(v).unwrap()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1.puts.len(), MAX_RELAY_PUTS);
    assert!(
        codec::encode_relay(&rows[0].1).unwrap().as_bytes().len() >= crate::MAX_VALUE_BYTES - 1
    );
    assert_eq!(rows[1].1.puts.len(), 1);
    let mut target_batch = Batch::new()
        .require(Precondition::Equals(rh.clone(), codec::encode_u64(0)))
        .put(rh, codec::encode_u64(1));
    target_batch.writes.extend(
        rows[0]
            .1
            .puts
            .iter()
            .cloned()
            .map(|(k, v)| Write::Put(k, v)),
    );
    target_batch.preconditions.push(Precondition::NotAfter(100));
    target_batch
        .writes
        .push(Write::Put(Key::new(b"hook".to_vec()), Value::default()));
    assert_eq!(
        target_batch.preconditions.len() + target_batch.writes.len(),
        crate::MAX_BATCH_OPS
    );
    target_batch.validate(&StoreCapabilities::full()).unwrap();
    assert!(rows.iter().all(|(_, r)| r.at_ms == 12));
}

#[test]
fn byte_chunking_and_missing_stamp_fail_without_mutating_outputs() {
    let mut b = OutboxBuilder::new(None, None).unwrap();
    b.relay(&target(0), vec![(key(), Value::default())]);
    let mut batch = Batch::new().require(Precondition::NotAfter(500));
    let saved = batch.clone();
    assert!(
        matches!(b.try_finish(&mut batch.preconditions,&mut batch.writes),Err(StoreError::Invalid(message)) if message=="relay rows need relay_at")
    );
    assert_eq!(batch, saved);
    let mut b = OutboxBuilder::new(None, None).unwrap();
    b.relay_at(5);
    b.relay(
        &target(0),
        (0..3)
            .map(|i| (Key::new(vec![i]), Value::new(vec![i; 100_000])))
            .collect(),
    );
    b.try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    let rows = batch
        .writes
        .iter()
        .filter_map(|w| match w {
            Write::Put(k, v) if matches!(keys::parse(k), Some(keys::ParsedKey::Relay(_))) => {
                Some(codec::decode_relay(v).unwrap())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].puts.len(), 2);
    assert_eq!(rows[1].puts.len(), 1);
    let mut b = OutboxBuilder::new(None, None).unwrap();
    b.relay_at(5);
    b.relay(
        &target(0),
        vec![(key(), Value::new(vec![0; crate::store::MAX_VALUE_BYTES]))],
    );
    let saved = batch.clone();
    assert!(
        b.try_finish(&mut batch.preconditions, &mut batch.writes)
            .is_err()
    );
    assert_eq!(batch, saved);
}

#[tokio::test]
async fn encoded_byte_budget_bounds_large_queue_reads_and_reschedules() {
    let s = memory();
    let h = handler(memory());
    for i in 0..12 {
        append(
            &s,
            &target(0),
            vec![(Key::new(vec![i]), Value::new(vec![i; 200_000]))],
            50,
        )
        .await;
    }
    assert!(matches!(
        fire(&h, &s).await.unwrap(),
        Fired::Reschedule { .. }
    ));
    assert_eq!(
        queued(&s).await.len(),
        2,
        "4 MiB fire budget leaves the last two rows queued"
    );
    fire(&h, &s).await.unwrap();
    assert!(queued(&s).await.is_empty());
}

struct LargeHook;
impl RelayHook for LargeHook {
    fn before_apply<'a>(
        &'a self,
        _p: &'a Partition,
        _rows: &'a [(u64, RelayV1)],
        _pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            writes.push(Write::Put(
                Key::new(b"hook-large".to_vec()),
                Value::new(vec![9; 500_000]),
            ));
            Ok(())
        })
    }
}
#[tokio::test]
async fn hook_additions_shrink_combined_batches_to_make_progress() {
    let s = memory();
    let h = RelayHandler {
        target: Instrumented::new(),
        hook: LargeHook,
        budget: RelayBudget::default(),
    };
    for i in 0..4 {
        append(
            &s,
            &target(0),
            vec![(Key::new(vec![i]), Value::new(vec![i; 200_000]))],
            50,
        )
        .await;
    }
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Done(_)));
    assert!(queued(&s).await.is_empty());
    {
        let batches = h.target.applies.lock().unwrap();
        assert_eq!(batches.len(), 2);
        for (_, batch) in batches.iter() {
            batch.validate(&StoreCapabilities::full()).unwrap();
        }
    }
    assert_eq!(
        h.target
            .get(&target(0), &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(4))
    );
}

#[tokio::test]
async fn later_watermark_read_failure_preserves_committed_chunk_cleanup() {
    let s = memory();
    let mut t = Instrumented::new();
    t.fail_watermark_after_apply = true;
    let h = handler(t);
    for i in 0..55 {
        append(
            &s,
            &target(0),
            vec![
                (Key::new(vec![i, 0]), Value::default()),
                (Key::new(vec![i, 1]), Value::default()),
            ],
            50,
        )
        .await;
    }
    assert!(matches!(
        fire(&h, &s).await.unwrap(),
        Fired::Reschedule { .. }
    ));
    assert_eq!(
        queued(&s).await.len(),
        7,
        "48 delivered rows were cleaned even though next chunk failed its read"
    );
    assert_eq!(h.target.applies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn drained_sources_guard_observed_or_absent_sequence() {
    let s = memory();
    let h = handler(memory());
    let Fired::Done(batch) = fire(&h, &s).await.unwrap() else {
        panic!("empty source not done")
    };
    // A first-ever relay row committed during the fire moves `os` from
    // absent, so `Done` must race rather than drop the kick.
    assert_eq!(
        batch.preconditions,
        vec![Precondition::Absent(keys::outbox_sequence())]
    );
    s.apply(
        &source(),
        Batch::new().put(keys::outbox_sequence(), codec::encode_u64(7)),
    )
    .await
    .unwrap();
    let Fired::Done(batch) = fire(&h, &s).await.unwrap() else {
        panic!("drained source not done")
    };
    assert_eq!(
        batch.preconditions,
        vec![Precondition::Equals(
            keys::outbox_sequence(),
            codec::encode_u64(7)
        )]
    );
}

#[tokio::test]
async fn zero_row_or_target_budget_is_clamped_to_one_and_delivers() {
    for budget in [
        RelayBudget {
            max_rows: 0,
            max_targets: 16,
            max_target_calls: None,
        },
        RelayBudget {
            max_rows: 256,
            max_targets: 0,
            max_target_calls: None,
        },
    ] {
        let source = memory();
        let relay = RelayHandler {
            budget,
            ..handler(Instrumented::new())
        };
        append(&source, &target(0), vec![(key(), Value::default())], 50).await;
        // A zero budget would reschedule at `now` forever; it is clamped to 1.
        assert!(matches!(
            fire(&relay, &source).await.unwrap(),
            Fired::Done(_)
        ));
        assert!(queued(&source).await.is_empty());
        assert_eq!(relay.target.applies.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn failing_target_backlog_does_not_fill_the_delivery_window() {
    let s = memory();
    let mut target_store = Instrumented::new();
    target_store.fail_target = Some(target(0));
    let h = RelayHandler {
        budget: RelayBudget {
            max_rows: 2,
            max_targets: 2,
            max_target_calls: None,
        },
        ..handler(target_store)
    };
    for _ in 0..3 {
        append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    }
    append(&s, &target(1), vec![(key(), Value::default())], 50).await;
    fire(&h, &s).await.unwrap();
    assert_eq!(
        h.target.get(&target(1), &key()).await.unwrap(),
        Some(Value::default())
    );
    assert_eq!(queued(&s).await.len(), 3);
}

#[tokio::test]
async fn full_failing_target_budget_pauses_before_the_next_target() {
    let s = memory();
    let mut target_store = Instrumented::new();
    target_store.fail_targets = vec![target(0), target(1)];
    let h = RelayHandler {
        budget: RelayBudget {
            max_rows: 2,
            max_targets: 2,
            max_target_calls: None,
        },
        ..handler(target_store)
    };
    append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    append(&s, &target(1), vec![(key(), Value::default())], 50).await;
    append(&s, &target(2), vec![(key(), Value::default())], 50).await;
    let registry = TimerRegistry::new().register(h);
    for now in [50, 50 + crate::timers::RETRY_BACKOFF_MS] {
        run_due(
            &s,
            &source(),
            &registry,
            &ManualClock::new(i64::try_from(now).unwrap()),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        queued(&s).await.len(),
        2,
        "healthy target must drain despite the full failing target budget"
    );
}

#[tokio::test]
async fn target_sequence_order_survives_target_pauses_across_fires() {
    let s = memory();
    let target_store = Instrumented::new();
    let applies = target_store.applies.clone();
    for seq in 1..=5u8 {
        append(
            &s,
            &target(u16::from(seq % 2)),
            vec![(key(), Value::new(vec![seq]))],
            50,
        )
        .await;
    }
    let registry = TimerRegistry::new().register(RelayHandler {
        budget: RelayBudget {
            max_rows: 1,
            max_targets: 1,
            max_target_calls: Some(2),
        },
        ..handler(target_store)
    });
    for now in 50..55 {
        run_due(
            &s,
            &source(),
            &registry,
            &ManualClock::new(i64::try_from(now).unwrap()),
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }
    assert!(queued(&s).await.is_empty());
    let applies = applies.lock().unwrap();
    for (p, expected) in [(target(1), vec![1u8, 3, 5]), (target(0), vec![2u8, 4])] {
        let seen: Vec<_> = applies
            .iter()
            .filter(|(target, _)| target == &p)
            .flat_map(|(_, batch)| batch.writes.iter())
            .filter_map(|write| match write {
                Write::Put(k, v) if k == &key() => Some(v.as_bytes()[0]),
                _ => None,
            })
            .collect();
        assert_eq!(seen, expected);
    }
}

#[tokio::test]
async fn target_call_cap_defers_chunks_without_losing_completed_prefix() {
    let s = memory();
    let h = RelayHandler {
        budget: RelayBudget {
            max_rows: 128,
            max_targets: 8,
            max_target_calls: Some(2),
        },
        ..handler(Instrumented::new())
    };
    let puts = (0..192u16)
        .map(|i| (Key::new(i.to_be_bytes().to_vec()), Value::default()))
        .collect();
    append(&s, &target(0), puts, 50).await;
    assert_eq!(queued(&s).await.len(), 2);
    assert!(matches!(
        fire(&h, &s).await.unwrap(),
        Fired::Reschedule { due_at_ms: 101, .. }
    ));
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    assert_eq!(queued(&s).await.len(), 1);
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Done(_)));
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 4);
    assert!(queued(&s).await.is_empty());
}

#[tokio::test]
async fn target_call_cap_defers_watermark_race_without_exceeding_calls() {
    let s = memory();
    let h = RelayHandler {
        budget: RelayBudget {
            max_rows: 128,
            max_targets: 8,
            max_target_calls: Some(2),
        },
        ..handler(Instrumented::new())
    };
    h.target.race_watermark.store(true, Ordering::SeqCst);
    append(
        &s,
        &target(0),
        vec![(key(), Value::new(b"first".to_vec()))],
        50,
    )
    .await;
    append(
        &s,
        &target(0),
        vec![(key(), Value::new(b"second".to_vec()))],
        50,
    )
    .await;
    fire(&h, &s).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    assert_eq!(queued(&s).await.len(), 2);
    fire(&h, &s).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 4);
    assert!(queued(&s).await.is_empty());
}

#[tokio::test]
async fn blocked_prefix_scans_at_most_four_times_rows_plus_backlog_head() {
    let s = Instrumented::new();
    let mut target_store = Instrumented::new();
    target_store.fail_target = Some(target(0));
    for _ in 0..9 {
        append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    }
    let h = RelayHandler {
        budget: RelayBudget {
            max_rows: 2,
            max_targets: 2,
            max_target_calls: None,
        },
        ..handler(target_store)
    };
    fire(&h, &s).await.unwrap();
    assert_eq!(s.scanned.load(Ordering::SeqCst), 9);
}

#[tokio::test]
async fn malformed_queue_key_before_first_sequence_blocks_later_delivery() {
    for corrupt_key in [keys::relay(0), Key::new(b"or\0".to_vec())] {
        let s = memory();
        let h = handler(Instrumented::new());
        let valid = RelayV1 {
            at_ms: 50,
            target: target(0),
            puts: vec![(order_key(2), codec::encode_u64(2))],
            deletes: Vec::new(),
        };
        s.apply(
            &source(),
            Batch::new()
                .put(corrupt_key.clone(), Value::new(b"bad".to_vec()))
                .put(keys::relay(2), codec::encode_relay(&valid).unwrap())
                .put(keys::outbox_sequence(), codec::encode_u64(2)),
        )
        .await
        .unwrap();
        assert!(
            matches!(fire(&h, &s).await.unwrap(), Fired::Retry),
            "malformed key {corrupt_key:?} was skipped"
        );
        assert!(s.get(&source(), &corrupt_key).await.unwrap().is_some());
        assert!(s.get(&source(), &keys::relay(2)).await.unwrap().is_some());
        assert!(
            h.target
                .get(&target(0), &order_key(2))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            h.target
                .get(&target(0), &keys::relay_high_water(&source()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn malformed_suffix_between_cursor_and_next_sequence_blocks_delivery() {
    let s = memory();
    let h = handler(Instrumented::new());
    let malformed = Key::new([keys::relay(1).as_bytes(), b"\xff"].concat());
    assert!(keys::relay(1) < malformed && malformed < keys::relay(2));
    let valid = RelayV1 {
        at_ms: 50,
        target: target(0),
        puts: vec![(order_key(2), codec::encode_u64(2))],
        deletes: Vec::new(),
    };
    let scan = codec::RelayScanV1 {
        cycle_end: 2,
        cursor: 1,
        blocked: vec![],
    };
    s.apply(
        &source(),
        Batch::new()
            .put(malformed.clone(), Value::new(b"bad".to_vec()))
            .put(keys::relay(2), codec::encode_relay(&valid).unwrap())
            .put(keys::outbox_sequence(), codec::encode_u64(2))
            .put(keys::relay_scan(), codec::encode_relay_scan(&scan).unwrap()),
    )
    .await
    .unwrap();
    assert!(
        matches!(fire(&h, &s).await.unwrap(), Fired::Retry),
        "malformed suffix after cursor was skipped"
    );
    assert!(s.get(&source(), &malformed).await.unwrap().is_some());
    assert!(
        h.target
            .get(&target(0), &order_key(2))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        h.target
            .get(&target(0), &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap()
            .is_none()
    );
}

fn order_key(seq: u64) -> Key {
    Key::new([b"delivered/".as_slice(), &seq.to_be_bytes()].concat())
}

async fn plant_schedule<S: NamespaceStore>(store: &S, schedule: &[u16]) {
    for (offset, chunk) in schedule.chunks(90).enumerate() {
        let mut batch = Batch::new();
        for (index, destination) in chunk.iter().enumerate() {
            let seq = u64::try_from(offset * 90 + index + 1).unwrap();
            let row = RelayV1 {
                at_ms: 50,
                target: target(*destination),
                puts: vec![(order_key(seq), codec::encode_u64(seq))],
                deletes: Vec::new(),
            };
            batch = batch.put(keys::relay(seq), codec::encode_relay(&row).unwrap());
        }
        assert_eq!(
            store.apply(&source(), batch).await.unwrap(),
            BatchOutcome::Committed
        );
    }
    store
        .apply(
            &source(),
            Batch::new().put(
                keys::outbox_sequence(),
                codec::encode_u64(schedule.len() as u64),
            ),
        )
        .await
        .unwrap();
}

fn scan_budget(rows: u32, targets: u32) -> RelayBudget {
    RelayBudget {
        max_rows: rows,
        max_targets: targets,
        max_target_calls: Some(WORKER_RELAY_CALLS_PER_TARGET),
    }
}

#[tokio::test]
async fn durable_scan_reaches_healthy_row_after_512_failed_rows_and_retries_next_cycle() {
    let mut timer_value = Value::default();
    let source_store = Instrumented::new();
    let t = Instrumented::new();
    t.reject.lock().unwrap().insert(target(0));
    let mut h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    let mut schedule = vec![0; 512];
    schedule.push(1);
    plant_schedule(&source_store, &schedule).await;
    for _ in 0..3 {
        let inspected_before = source_store.scanned.load(Ordering::SeqCst);
        fire_with_value(&h, &source_store, &mut timer_value)
            .await
            .unwrap();
        // The relay reads at most 512 delivery candidates plus one source
        // head row for the backlog gauge.
        assert!(source_store.scanned.load(Ordering::SeqCst) - inspected_before <= 513);
        // Simulate an isolate/process being recreated between every fire.
        h = RelayHandler {
            target: h.target,
            hook: NoHook,
            budget: scan_budget(128, 8),
        };
    }
    assert!(
        h.target
            .get(&target(1), &order_key(513))
            .await
            .unwrap()
            .is_some(),
        "bounded durable scan never reached the healthy row beyond its first window"
    );
    assert_eq!(queued(&source_store).await.len(), 512);
    assert!(
        h.target
            .applies
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == &target(0))
            .count()
            >= 2,
        "blocked A was not retried after a completed scan cycle"
    );
    h.target.reject.lock().unwrap().clear();
    for _ in 0..12 {
        fire_with_value(&h, &source_store, &mut timer_value)
            .await
            .unwrap();
        if queued(&source_store).await.is_empty() {
            break;
        }
    }
    assert!(
        queued(&source_store).await.is_empty(),
        "blocked target was not retried after cycle reset"
    );
    assert!(
        h.target
            .get(&target(0), &order_key(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        h.target
            .get(&target(0), &order_key(512))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn durable_scan_keeps_seq_600_behind_failed_seq_1_until_head_restart() {
    let mut timer_value = Value::default();
    let s = memory();
    let t = Instrumented::new();
    t.fail_first.lock().unwrap().insert(target(0));
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    let mut schedule = vec![1; 600];
    schedule[0] = 0;
    schedule[599] = 0;
    plant_schedule(&s, &schedule).await;
    for _ in 0..20 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        let delivered_old = h
            .target
            .get(&target(0), &order_key(1))
            .await
            .unwrap()
            .is_some();
        let delivered_new = h
            .target
            .get(&target(0), &order_key(600))
            .await
            .unwrap()
            .is_some();
        assert!(
            !delivered_new || delivered_old,
            "watermark skipped an older undelivered target row"
        );
        if queued(&s).await.is_empty() {
            break;
        }
    }
    assert!(queued(&s).await.is_empty());
    assert!(
        h.target
            .get(&target(0), &order_key(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        h.target
            .get(&target(0), &order_key(600))
            .await
            .unwrap()
            .is_some()
    );
    let seen = committed_sequences(&h.target, &target(0));
    assert_eq!(seen, vec![1, 600]);
}

fn committed_sequences(store: &Instrumented, destination: &Partition) -> Vec<u64> {
    store
        .successful
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, _)| p == destination)
        .flat_map(|(_, batch)| batch.writes.iter())
        .filter_map(|write| match write {
            Write::Put(k, v) if k.as_bytes().starts_with(b"delivered/") => {
                Some(codec::decode_u64(v).unwrap())
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn durable_scan_overflow_33_failures_restarts_safely_and_recovers_all_rows() {
    let mut timer_value = Value::default();
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = (0..33).map(target).collect();
    let h = RelayHandler {
        budget: scan_budget(4, 8),
        ..handler(t)
    };
    let mut schedule: Vec<_> = (0..33).collect();
    schedule.extend(0..34);
    plant_schedule(&s, &schedule).await;
    let mut first_overflow_attempts = None;
    let mut retried_after_overflow = false;
    for _ in 0..80 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        let attempts = h
            .target
            .applies
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == &target(0))
            .count();
        if let Some(first) = first_overflow_attempts {
            retried_after_overflow |= attempts > first;
        }
        let state = s
            .get(&source(), &keys::relay_scan())
            .await
            .unwrap()
            .unwrap();
        let state = codec::decode_relay_scan(&state).unwrap();
        if state.cursor == state.cycle_end && state.blocked.len() == codec::MAX_BLOCKED_TARGETS {
            first_overflow_attempts.get_or_insert(attempts);
        }
    }
    assert!(
        first_overflow_attempts.is_some(),
        "33rd failed target did not end the cycle"
    );
    assert!(
        retried_after_overflow,
        "first failed target was not retried after cycle reset"
    );
    assert!(
        s.get(&source(), &keys::relay(33)).await.unwrap().is_some(),
        "overflow lost the 33rd target's row"
    );
    assert!(
        h.target
            .get(&target(33), &order_key(67))
            .await
            .unwrap()
            .is_none(),
        "healthy target beyond 33 failed targets was visited before recovery"
    );
    for destination in 0..33 {
        assert!(committed_sequences(&h.target, &target(destination)).is_empty());
    }
    h.target.reject.lock().unwrap().clear();
    for _ in 0..80 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if queued(&s).await.is_empty() {
            break;
        }
    }
    assert!(queued(&s).await.is_empty());
    for destination in 0..34 {
        let actual = committed_sequences(&h.target, &target(destination));
        let expected: Vec<_> = schedule
            .iter()
            .enumerate()
            .filter(|(_, p)| **p == destination)
            .map(|(i, _)| i as u64 + 1)
            .collect();
        assert_eq!(actual, expected, "overflow reordered target {destination}");
    }
}

#[tokio::test]
async fn grouped_row_past_overflow_is_cleaned_in_the_same_checkpoint() {
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = (1..=33).map(target).collect();
    let h = RelayHandler {
        budget: scan_budget(64, 64),
        ..handler(t)
    };
    let mut schedule = vec![0];
    schedule.extend(1..=33);
    schedule.push(0);
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    fire_with_value(&h, &s, &mut timer_value).await.unwrap();
    assert!(
        h.target
            .get(&target(0), &order_key(1))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        h.target
            .get(&target(0), &order_key(35))
            .await
            .unwrap()
            .is_some(),
        "selected target receives all of its rows, even past the source checkpoint"
    );
    assert_eq!(
        h.target
            .get(&target(0), &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(35))
    );
    assert!(s.get(&source(), &keys::relay(35)).await.unwrap().is_none());
    let state = s
        .get(&source(), &keys::relay_scan())
        .await
        .unwrap()
        .unwrap();
    let state = codec::decode_relay_scan(&state).unwrap();
    assert_eq!(state.cursor, 35);
    assert_eq!(state.blocked.len(), 32);
    h.target.reject.lock().unwrap().clear();
    for _ in 0..16 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if queued(&s).await.is_empty() {
            break;
        }
    }
    assert!(queued(&s).await.is_empty());
    assert_eq!(committed_sequences(&h.target, &target(0)), vec![1, 35]);
}

#[tokio::test]
async fn durable_scan_guard_conflict_keeps_cleanup_and_state_atomic() {
    let mut timer_value = Value::default();
    let s = Instrumented::new();
    let h = handler(Instrumented::new());
    plant_schedule(&s, &[0, 1, 0]).await;
    s.scan_conflict.store(true, Ordering::SeqCst);
    let result = fire_with_value(&h, &s, &mut timer_value).await.unwrap();
    assert!(
        matches!(result, Fired::Retry),
        "source scan-state race must retry"
    );
    assert_eq!(
        queued(&s).await.len(),
        3,
        "failed scan guard deleted source rows"
    );
    assert!(
        s.get(&source(), &keys::relay_scan())
            .await
            .unwrap()
            .is_none()
    );
    for _ in 0..4 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if queued(&s).await.is_empty() {
            break;
        }
    }
    assert!(queued(&s).await.is_empty());
    assert_eq!(committed_sequences(&h.target, &target(0)), vec![1, 3]);
    assert_eq!(committed_sequences(&h.target, &target(1)), vec![2]);
}

#[tokio::test]
async fn one_target_slot_eventually_visits_healthy_b_after_a_fails() {
    let s = memory();
    let t = Instrumented::new();
    t.reject.lock().unwrap().insert(target(0));
    let h = RelayHandler {
        budget: scan_budget(2, 1),
        ..handler(t)
    };
    plant_schedule(&s, &[0, 1]).await;
    let mut timer_value = Value::default();
    for _ in 0..5 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if h.target
            .get(&target(1), &order_key(2))
            .await
            .unwrap()
            .is_some()
        {
            break;
        }
    }
    assert!(
        h.target
            .get(&target(1), &order_key(2))
            .await
            .unwrap()
            .is_some()
    );
    assert!(s.get(&source(), &keys::relay(1)).await.unwrap().is_some());
}

#[tokio::test]
async fn two_failing_targets_cannot_starve_a_healthy_target_with_one_target_slot() {
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = [target(0), target(1)].into();
    let h = RelayHandler {
        budget: scan_budget(1, 1),
        ..handler(t)
    };
    plant_schedule(&s, &[0, 0, 2, 2, 1]).await;
    let mut timer_value = Value::default();
    for _ in 0..20 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if committed_sequences(&h.target, &target(2)) == [3, 4] {
            break;
        }
    }
    assert_eq!(committed_sequences(&h.target, &target(2)), vec![3, 4]);
    assert!(s.get(&source(), &keys::relay(1)).await.unwrap().is_some());
    assert!(s.get(&source(), &keys::relay(5)).await.unwrap().is_some());
}

#[tokio::test]
async fn worker_budget_drains_512_distinct_healthy_targets_without_idle_fires() {
    let s = memory();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(Instrumented::new())
    };
    plant_schedule(&s, &(0..512).collect::<Vec<_>>()).await;
    let mut timer_value = Value::default();
    for fire_number in 1..=68 {
        let before = queued(&s).await.len();
        if before == 0 {
            break;
        }
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        let after = queued(&s).await.len();
        assert!(
            after < before,
            "fire {fire_number} made no delivery progress"
        );
    }
    assert!(queued(&s).await.is_empty(), "512 targets exceeded 68 fires");
}

#[tokio::test]
async fn worker_paid_and_free_budgets_drain_4096_targets_within_alarm_call_caps() {
    for (targets_per_fire, fires_per_alarm) in [
        (WORKER_PAID_RELAY_TARGETS, WORKER_PAID_RELAY_FIRES),
        (WORKER_FREE_RELAY_TARGETS, WORKER_FREE_RELAY_FIRES),
    ] {
        let calls_per_alarm = targets_per_fire * fires_per_alarm * WORKER_RELAY_CALLS_PER_TARGET;
        let max_alarms = 4096_u32.div_ceil(targets_per_fire * fires_per_alarm) + 64;
        let source_store = memory();
        plant_schedule(&source_store, &(0..4096).collect::<Vec<_>>()).await;
        let h = RelayHandler {
            budget: scan_budget(128, targets_per_fire),
            ..handler(Instrumented::new())
        };
        let mut timer_value = Value::default();
        let mut alarms = 0;
        while !relay_delivered_through(&source_store, &source(), 4096)
            .await
            .unwrap()
        {
            alarms += 1;
            assert!(
                alarms <= max_alarms,
                "relay did not drain within {max_alarms} alarms"
            );
            let before = h.target.calls.load(Ordering::SeqCst);
            for _ in 0..fires_per_alarm {
                fire_with_value(&h, &source_store, &mut timer_value)
                    .await
                    .unwrap();
            }
            let calls = h.target.calls.load(Ordering::SeqCst) - before;
            assert!(
                calls <= calls_per_alarm as usize,
                "alarm used {calls} target calls"
            );
        }
    }
}

#[tokio::test]
async fn worker_budget_reaches_healthy_target_after_31_failures_and_480_more() {
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = (0..31).map(target).collect();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    let schedule: Vec<_> = (0..512).collect();
    // B is target 31, immediately after the 31 failing targets.
    assert_eq!(schedule[31], 31);
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    let mut b_fire = None;
    for fire_number in 1..=70 {
        let delivered_before = h.target.successful.lock().unwrap().len();
        let outcome = fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        let delivered_after = h.target.successful.lock().unwrap().len();
        if delivered_after == delivered_before
            && let Fired::Reschedule { due_at_ms, .. } = outcome
        {
            assert!(
                due_at_ms >= 100 + crate::timers::RETRY_BACKOFF_MS,
                "zero-delivery fire rescheduled immediately"
            );
        }
        if b_fire.is_none()
            && h.target
                .get(&target(31), &order_key(32))
                .await
                .unwrap()
                .is_some()
        {
            b_fire = Some(fire_number);
        }
        if h.target.successful.lock().unwrap().len() >= 481 {
            break;
        }
    }
    assert!(
        b_fire.is_some_and(|fire| fire <= 6),
        "B exceeded its fire bound"
    );
    for destination in 31..512 {
        assert_eq!(
            committed_sequences(&h.target, &target(destination)),
            vec![u64::from(destination) + 1],
            "healthy target {destination} was not delivered"
        );
    }
}

async fn round_robin_reaches_b(targets: u16, rounds: usize, budget: RelayBudget, bound: usize) {
    let s = memory();
    let h = RelayHandler {
        budget,
        ..handler(Instrumented::new())
    };
    let mut schedule: Vec<_> = (0..rounds).flat_map(|_| 0..targets).collect();
    schedule.push(targets);
    let b_seq = u64::try_from(schedule.len()).unwrap();
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    for fire_number in 1..=bound {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if h.target
            .get(&target(targets), &order_key(b_seq))
            .await
            .unwrap()
            .is_some()
        {
            assert!(queued(&s).await.is_empty(), "delivered rows stayed queued");
            return;
        }
        assert!(fire_number < bound, "B missed the {bound}-fire bound");
    }
}

#[tokio::test]
async fn round_robin_targets_reach_b_without_duplicate_group_slot_collapse() {
    round_robin_reaches_b(9, 32, scan_budget(128, 8), 4).await;
    round_robin_reaches_b(16, 32, scan_budget(128, 8), 5).await;
    round_robin_reaches_b(64, 8, scan_budget(128, 8), 11).await;
    round_robin_reaches_b(32, 32, RelayBudget::default(), 5).await;
}

#[tokio::test]
async fn duplicate_only_groups_use_reads_but_no_target_slots() {
    let s = memory();
    let t = Instrumented::new();
    let rh = keys::relay_high_water(&source()).unwrap();
    for destination in 0..8 {
        let seq = u64::from(destination) + 1;
        t.apply(
            &target(destination),
            Batch::new()
                .put(rh.clone(), codec::encode_u64(seq))
                .put(order_key(seq), codec::encode_u64(seq)),
        )
        .await
        .unwrap();
    }
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    plant_schedule(&s, &(0..9).collect::<Vec<_>>()).await;
    let calls_before = h.target.calls.load(Ordering::SeqCst);
    let mut timer_value = Value::default();
    fire_with_value(&h, &s, &mut timer_value).await.unwrap();
    let calls = h.target.calls.load(Ordering::SeqCst) - calls_before;
    assert!(
        calls <= 16,
        "duplicate reads exceeded the Worker call budget"
    );
    assert!(queued(&s).await.is_empty());
    assert!(
        h.target
            .get(&target(8), &order_key(9))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn thousand_row_healthy_target_does_not_hide_b() {
    let s = memory();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(Instrumented::new())
    };
    let mut schedule = vec![0; 1_000];
    schedule.push(1);
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    for fire_number in 1..=16 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if h.target
            .get(&target(1), &order_key(1_001))
            .await
            .unwrap()
            .is_some()
        {
            assert!(
                fire_number <= 15,
                "B exceeded the single-target backlog bound"
            );
            assert!(queued(&s).await.is_empty());
            return;
        }
    }
    panic!("B stayed hidden behind a healthy 1,000-row backlog");
}

#[tokio::test]
async fn appended_b_waits_for_next_cycle_then_passes_31_failures_and_992_rows() {
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = (0..31).map(target).collect();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    let mut schedule: Vec<_> = (0..31).collect();
    schedule.extend(vec![31; 992]);
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    fire_with_value(&h, &s, &mut timer_value).await.unwrap();
    let b_seq = u64::try_from(schedule.len() + 1).unwrap();
    append(
        &s,
        &target(32),
        vec![(order_key(b_seq), codec::encode_u64(b_seq))],
        100,
    )
    .await;
    let mut fires_in_b_cycle = 0;
    for _ in 0..80 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        let state = codec::decode_relay_scan(
            &s.get(&source(), &keys::relay_scan())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        if state.cycle_end < b_seq {
            assert!(
                h.target
                    .get(&target(32), &order_key(b_seq))
                    .await
                    .unwrap()
                    .is_none()
            );
            continue;
        }
        fires_in_b_cycle += 1;
        if h.target
            .get(&target(32), &order_key(b_seq))
            .await
            .unwrap()
            .is_some()
        {
            assert!(
                fires_in_b_cycle <= 18,
                "B exceeded the amended backlog bound"
            );
            assert_eq!(queued(&s).await.len(), 31);
            return;
        }
    }
    panic!("B remained hidden after its cycle started");
}

#[tokio::test]
async fn tiny_target_call_caps_are_clamped_to_two() {
    for cap in [0, 1] {
        let s = memory();
        let h = RelayHandler {
            budget: RelayBudget {
                max_target_calls: Some(cap),
                ..scan_budget(128, 8)
            },
            ..handler(Instrumented::new())
        };
        plant_schedule(&s, &[0]).await;
        let mut timer_value = Value::default();
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        assert!(queued(&s).await.is_empty(), "cap {cap} stalled delivery");
    }
}

#[tokio::test]
async fn nine_failed_targets_do_not_hide_the_tenth_with_empty_kicks() {
    let s = memory();
    let t = Instrumented::new();
    *t.reject.lock().unwrap() = (0..9).map(target).collect();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    plant_schedule(&s, &(0..10).collect::<Vec<_>>()).await;
    let mut timer_value = Value::default();
    for _ in 0..4 {
        let outcome = fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if let Fired::Reschedule { value, .. } = outcome {
            assert!(value.as_bytes().is_empty(), "relay kick carried scan state");
        }
        if h.target
            .get(&target(9), &order_key(10))
            .await
            .unwrap()
            .is_some()
        {
            break;
        }
    }
    assert!(
        h.target
            .get(&target(9), &order_key(10))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn alternating_400_healthy_rows_drain_within_eight_fires() {
    let s = memory();
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(Instrumented::new())
    };
    let schedule: Vec<_> = (0..400).map(|n| n % 2).collect();
    plant_schedule(&s, &schedule).await;
    let mut timer_value = Value::default();
    for _ in 0..8 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if queued(&s).await.is_empty() {
            break;
        }
    }
    assert!(queued(&s).await.is_empty());
    for destination in 0..2 {
        assert_eq!(
            committed_sequences(&h.target, &target(destination)),
            schedule
                .iter()
                .enumerate()
                .filter(|(_, p)| **p == destination)
                .map(|(i, _)| i as u64 + 1)
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn alternating_failed_a_and_200_healthy_b_rows_drain_b_in_four_fires() {
    let s = memory();
    let t = Instrumented::new();
    t.reject.lock().unwrap().insert(target(0));
    let h = RelayHandler {
        budget: scan_budget(128, 8),
        ..handler(t)
    };
    plant_schedule(&s, &(0..400).map(|n| n % 2).collect::<Vec<_>>()).await;
    let mut timer_value = Value::default();
    for _ in 0..4 {
        fire_with_value(&h, &s, &mut timer_value).await.unwrap();
        if committed_sequences(&h.target, &target(1)).len() == 200 {
            break;
        }
    }
    assert_eq!(committed_sequences(&h.target, &target(1)).len(), 200);
    assert_eq!(queued(&s).await.len(), 200);
}

#[tokio::test]
async fn corrupt_scan_state_restarts_under_its_observed_value_guard() {
    let s = Instrumented::new();
    let h = handler(Instrumented::new());
    plant_schedule(&s, &[0, 1]).await;
    let corrupt = Value::new(b"bad relay scan".to_vec());
    s.apply(
        &source(),
        Batch::new().put(keys::relay_scan(), corrupt.clone()),
    )
    .await
    .unwrap();
    let mut timer_value = Value::default();
    fire_with_value(&h, &s, &mut timer_value).await.unwrap();
    assert!(queued(&s).await.is_empty());
    let guarded_replacement = s.successful.lock().unwrap().iter().any(|(p, batch)| {
        p == &source()
            && batch.preconditions.iter().any(|pre| {
                matches!(pre, Precondition::Equals(key, value)
                    if key == &keys::relay_scan() && value == &corrupt)
            })
    });
    assert!(guarded_replacement);
    assert!(
        codec::decode_relay_scan(
            &s.get(&source(), &keys::relay_scan())
                .await
                .unwrap()
                .unwrap()
        )
        .is_ok()
    );
}

async fn fire_with_value<S: NamespaceStore, T: NamespaceStore, H: RelayHook>(
    h: &RelayHandler<T, H>,
    store: &S,
    timer_value: &mut Value,
) -> Result<Fired, StoreError> {
    let outcome = h
        .fire(
            &TimerCtx {
                store,
                partition: &source(),
                now_ms: 100,
            },
            &DueTimer {
                due_at_ms: 100,
                kind: kinds::RELAY,
                reference: bytes::Bytes::default(),
                value: timer_value.clone(),
            },
        )
        .await?;
    match &outcome {
        Fired::Done(batch) => {
            assert_eq!(
                store.apply(&source(), batch.clone()).await?,
                BatchOutcome::Committed
            );
        }
        Fired::Reschedule { value, batch, .. } => {
            assert_eq!(
                store.apply(&source(), batch.clone()).await?,
                BatchOutcome::Committed
            );
            *timer_value = value.clone();
        }
        Fired::Retry => {}
    }
    Ok(outcome)
}

async fn assert_pending_watermarks<S: NamespaceStore, T: NamespaceStore>(
    source_store: &S,
    target_store: &T,
) {
    for (key, value) in queued(source_store).await {
        let Some(keys::ParsedKey::Relay(seq)) = keys::parse(&key) else {
            panic!("bad fixture key");
        };
        let destination = codec::decode_relay(&value).unwrap().target;
        let watermark = target_store
            .get(&destination, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap()
            .map_or(0, |v| codec::decode_u64(&v).unwrap());
        if watermark >= seq {
            assert!(
                target_store
                    .get(&destination, &order_key(seq))
                    .await
                    .unwrap()
                    .is_some(),
                "target watermark passed an undelivered older row"
            );
        }
    }
}

proptest::proptest! {
    #![proptest_config({
        let mut cfg = proptest::prelude::ProptestConfig::with_cases(96);
        cfg.failure_persistence = None;
        cfg
    })]
    #[test]
    fn random_relay_schedules_preserve_order_and_healthy_liveness(
        schedule in proptest::collection::vec(0u16..48, 65..181),
        initially_failing in 0u16..40,
        rows in 1u32..17,
        targets in 1u32..9,
        appended in proptest::collection::vec(0u16..48, 1..5),
        guard_conflict in proptest::bool::ANY,
        concurrent_fires in proptest::bool::ANY,
        yield_seed in proptest::num::u64::ANY,
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let s = Instrumented::new();
            let t = Instrumented::new();
            *t.reject.lock().unwrap() = (0..initially_failing).map(target).collect();
            let source_store = Yielding::new(&s, yield_seed);
            let target_store = Yielding::new(&t, yield_seed.rotate_left(17));
            let h = RelayHandler { budget: scan_budget(rows, targets), ..handler(target_store) };
            plant_schedule(&s, &schedule).await;
            let mut timer_value = Value::default();
            fire_with_value(&h, &source_store, &mut timer_value).await.unwrap();
            let original_end = schedule.len() as u64;
            let state = codec::decode_relay_scan(
                &s.get(&source(), &keys::relay_scan()).await.unwrap().unwrap()
            ).unwrap();
            assert_eq!(state.cycle_end, original_end);
            assert!(state.cursor < state.cycle_end);
            for (offset, destination) in appended.iter().enumerate() {
                let seq = original_end + offset as u64 + 1;
                append(&s, &target(*destination),
                    vec![(order_key(seq), codec::encode_u64(seq))], 100).await;
            }
            let mut expected_schedule = schedule.clone();
            expected_schedule.extend(appended);
            fire_with_value(&h, &source_store, &mut timer_value).await.unwrap();
            let state = codec::decode_relay_scan(
                &s.get(&source(), &keys::relay_scan()).await.unwrap().unwrap()
            ).unwrap();
            assert_eq!(state.cycle_end, original_end);
            for seq in original_end + 1..=expected_schedule.len() as u64 {
                let destination = target(expected_schedule[usize::try_from(seq).unwrap() - 1]);
                assert!(h.target.get(&destination, &order_key(seq)).await.unwrap().is_none(),
                    "row appended beyond cycle_end was delivered inside the old cycle");
            }
            if guard_conflict {
                s.scan_conflict.store(true, Ordering::SeqCst);
            }
            if concurrent_fires {
                let (left, right) = tokio::join!(fire(&h, &source_store), fire(&h, &source_store));
                assert!(left.is_ok() && right.is_ok());
            }
            let healthy_complete = || (initially_failing..48).all(|destination| {
                let expected: Vec<_> = expected_schedule.iter().enumerate()
                    .filter(|(_, p)| **p == destination)
                    .map(|(i, _)| i as u64 + 1).collect();
                committed_sequences(&t, &target(destination)) == expected
            });
            for fire_number in 0..256 {
                // A timer kick has no scan state, including after a guard race.
                timer_value = Value::default();
                fire_with_value(&h, &source_store, &mut timer_value).await.unwrap();
                assert!(timer_value.as_bytes().is_empty());
                assert_pending_watermarks(&s, &t).await;
                if healthy_complete() || (initially_failing >= 32 && fire_number == 31) { break; }
            }
            if initially_failing < u16::try_from(codec::MAX_BLOCKED_TARGETS).unwrap() {
                assert!(healthy_complete(), "healthy targets stalled while failures persisted");
            }
            t.reject.lock().unwrap().clear();
            for _ in 0..1000 {
                fire_with_value(&h, &source_store, &mut timer_value).await.unwrap();
                assert_pending_watermarks(&s, &t).await;
                if queued(&s).await.is_empty() { break; }
            }
            assert!(queued(&s).await.is_empty(), "healthy targets did not drain");
            for destination in 0..48 {
                let expected: Vec<_> = expected_schedule.iter().enumerate()
                    .filter(|(_, p)| **p == destination)
                    .map(|(i, _)| i as u64 + 1).collect();
                let actual = committed_sequences(&t, &target(destination));
                assert_eq!(actual, expected, "target {destination} starved or reordered");
            }
        });
    }
}

struct DeclaredSnapshotHook;
impl RelayHook for DeclaredSnapshotHook {
    fn read_keys(&self, _: &Partition, _: &[(u64, RelayV1)]) -> Result<Vec<Key>, StoreError> {
        Ok(vec![Key::new(b"hook-state".to_vec())])
    }
    fn before_apply<'a>(
        &'a self,
        _: &'a Partition,
        _: &'a [(u64, RelayV1)],
        _: &'a mut Vec<Precondition>,
        _: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { panic!("declared hook must receive its snapshot") })
    }
    fn before_apply_observed<'a>(
        &'a self,
        _: &'a Partition,
        _: &'a [(u64, RelayV1)],
        observed: &'a [(Key, Option<Value>)],
        pre: &'a mut Vec<Precondition>,
        writes: &'a mut Vec<Write>,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let key = Key::new(b"hook-state".to_vec());
            let raw = observed.iter().find(|(k, _)| k == &key).unwrap().1.as_ref();
            pre.push(match raw {
                Some(raw) => Precondition::Equals(key.clone(), raw.clone()),
                None => Precondition::Absent(key.clone()),
            });
            writes.push(Write::Put(key, codec::encode_u64(1)));
            Ok(())
        })
    }
}
struct RoutedMethods {
    inner: MemoryKv,
    calls: AtomicUsize,
    lost_reply: AtomicBool,
}
impl NamespaceStore for RoutedMethods {
    fn capabilities(&self) -> StoreCapabilities {
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
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        panic!("no target scan")
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = self.inner.apply(p, b).await?;
        if result == BatchOutcome::Committed && self.lost_reply.swap(false, Ordering::SeqCst) {
            return Err(StoreError::Unavailable("lost target reply".into()));
        }
        Ok(result)
    }
    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        panic!("no target stats")
    }
    async fn probe(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
#[tokio::test]
async fn declared_hook_snapshot_and_watermark_use_two_routed_methods() {
    let local = memory();
    let remote = RoutedMethods {
        inner: memory(),
        calls: AtomicUsize::new(0),
        lost_reply: AtomicBool::new(false),
    };
    let p = target(0);
    append(
        &local,
        &p,
        vec![(key(), Value::new(b"payload".as_slice()))],
        50,
    )
    .await;
    let h = RelayHandler {
        target: remote,
        hook: DeclaredSnapshotHook,
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    fire(&h, &local).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        h.target
            .inner
            .get(&p, &Key::new(b"hook-state".to_vec()))
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
    assert_eq!(
        h.target
            .inner
            .get(&p, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
    assert!(queued(&local).await.is_empty());
}

#[tokio::test]
async fn current_generic_96_effect_rows_fit_with_the_holder_hook() {
    let local = memory();
    let remote = RoutedMethods {
        inner: memory(),
        calls: AtomicUsize::new(0),
        lost_reply: AtomicBool::new(false),
    };
    let destination = target(0);
    let puts = (0..96_u8)
        .map(|n| (Key::new(vec![b'x', n]), Value::new(vec![n])))
        .collect();
    append(&local, &destination, puts, 50).await;
    let h = RelayHandler {
        target: remote,
        hook: HolderRelayHook {
            clock: Arc::new(ManualClock::new(100)),
        },
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    fire(&h, &local).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    for n in 0..96_u8 {
        assert_eq!(
            h.target
                .inner
                .get(&destination, &Key::new(vec![b'x', n]))
                .await
                .unwrap(),
            Some(Value::new(vec![n]))
        );
    }
    assert!(queued(&local).await.is_empty());
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One atomic delivery scenario includes setup and state assertions.
async fn holder_re_records_bump_once_and_duplicate_intents_fold() {
    let local = memory();
    let remote = RoutedMethods {
        inner: memory(),
        calls: AtomicUsize::new(0),
        lost_reply: AtomicBool::new(false),
    };
    let object = [0x72; 32];
    let destination = crate::store::content_shard(&object);
    let h = RelayHandler {
        target: remote,
        hook: HolderRelayHook {
            clock: Arc::new(ManualClock::new(100)),
        },
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    for generation in 0..2_u8 {
        let hold = [0x73 + generation; 32];
        let identity = crate::store::PendingHolderV1::new(
            crate::store::Holder::new(
                NamespaceKey::deployment_default(),
                RepoName::new("a").unwrap(),
            ),
            source(),
            [0x75; 32],
            object,
            hold,
            [0x76 + generation; 32],
        )
        .unwrap();
        let idx = crate::store::ContentIndex::new(crate::store::BorrowedStore(&h.target.inner));
        assert_eq!(
            idx.add_hold(&object, &hold, 10_000, 100).await.unwrap(),
            crate::store::HoldOutcome::Held
        );
        assert_eq!(
            idx.protect_pending_holder(&object, &hold, &identity, 100)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        let before = codec::decode_object_state(
            &h.target
                .inner
                .get(&destination, &keys::object_state(&object))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        // Two different relay sequences can carry the same durable intent.
        for _ in 0..2 {
            append(
                &local,
                &destination,
                vec![(
                    keys::pending_holder(&object, &hold),
                    identity.encode().unwrap(),
                )],
                50,
            )
            .await;
        }
        let calls = h.target.calls.load(Ordering::SeqCst);
        fire(&h, &local).await.unwrap();
        assert_eq!(h.target.calls.load(Ordering::SeqCst) - calls, 2);
        assert!(queued(&local).await.is_empty());
        let after = codec::decode_object_state(
            &h.target
                .inner
                .get(&destination, &keys::object_state(&object))
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            after.holders, 1,
            "the same holder keeps one conservative count"
        );
        assert_eq!(
            after.seq,
            before.seq + 1,
            "a distinct re-record bumps once; duplicate intents do not"
        );
        assert!(
            h.target
                .inner
                .get(&destination, &keys::pending_holder(&object, &hold))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            h.target
                .inner
                .get(&destination, &keys::hold(&object, &hold))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn duplicate_holder_intent_drains_across_bounded_target_applies() {
    let local = memory();
    let remote = memory();
    let a = [0x72; 32];
    let mut b = a;
    b[31] = 0x73;
    let destination = crate::store::content_shard(&a);
    assert_eq!(crate::store::content_shard(&b), destination);
    let idx = crate::store::ContentIndex::new(crate::store::BorrowedStore(&remote));
    let mut identities = Vec::new();
    for object in [a, b] {
        let identity = crate::store::PendingHolderV1::new(
            crate::store::Holder::new(
                NamespaceKey::deployment_default(),
                RepoName::new("a").unwrap(),
            ),
            source(),
            [0x75; 32],
            object,
            object,
            [0x76; 32],
        )
        .unwrap();
        assert_eq!(
            idx.add_hold(&object, &object, 10_000, 100).await.unwrap(),
            crate::store::HoldOutcome::Held
        );
        assert_eq!(
            idx.protect_pending_holder(&object, &object, &identity, 100)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        identities.push(identity);
    }
    for identity in [&identities[0], &identities[1], &identities[0]] {
        append(
            &local,
            &destination,
            vec![(
                keys::pending_holder(&identity.object, &identity.hold_id),
                identity.encode().unwrap(),
            )],
            50,
        )
        .await;
    }
    let h = RelayHandler {
        target: remote,
        hook: HolderRelayHook {
            clock: Arc::new(ManualClock::new(100)),
        },
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    for _ in 0..6 {
        fire(&h, &local).await.unwrap();
    }
    let state = codec::decode_object_state(
        &h.target
            .get(&destination, &keys::object_state(&a))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(state.holders, 1);
    assert_eq!(state.seq, 3, "duplicate intent must not bump again");
    assert!(
        queued(&local).await.is_empty(),
        "duplicate intent must drain after gp release"
    );
    assert_eq!(
        h.target
            .get(&destination, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(3))
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the lost-reply boundary and all atomic effects together.
async fn holder_delivery_lost_reply_is_atomic_and_never_double_bumps() {
    let local = memory();
    let object = [0x42; 32];
    let hold = [0x43; 32];
    let p = crate::store::content_shard(&object);
    let remote = RoutedMethods {
        inner: memory(),
        calls: AtomicUsize::new(0),
        lost_reply: AtomicBool::new(true),
    };
    let idx = crate::store::ContentIndex::new(crate::store::BorrowedStore(&remote.inner));
    let identity = crate::store::PendingHolderV1::new(
        crate::store::Holder::new(
            NamespaceKey::deployment_default(),
            RepoName::new("a").unwrap(),
        ),
        source(),
        [0x44; 32],
        object,
        hold,
        [0x45; 32],
    )
    .unwrap();
    assert_eq!(
        idx.add_hold(&object, &hold, 10_000, 100).await.unwrap(),
        crate::store::HoldOutcome::Held
    );
    assert_eq!(
        idx.protect_pending_holder(&object, &hold, &identity, 100)
            .await
            .unwrap(),
        crate::store::HoldOutcome::Held
    );
    append(
        &local,
        &p,
        vec![(
            keys::pending_holder(&object, &hold),
            identity.encode().unwrap(),
        )],
        50,
    )
    .await;
    let h = RelayHandler {
        target: remote,
        hook: HolderRelayHook {
            clock: Arc::new(ManualClock::new(100)),
        },
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    fire(&h, &local).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    assert!(
        !queued(&local).await.is_empty(),
        "lost reply keeps source intent queued"
    );
    let state = h
        .target
        .inner
        .get(&p, &keys::object_state(&object))
        .await
        .unwrap()
        .unwrap();
    let value = codec::decode_object_state(&state).unwrap();
    assert_eq!(value.holders, 1);
    assert!(
        h.target
            .inner
            .get(&p, &keys::pending_holder(&object, &hold))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        h.target
            .inner
            .get(&p, &keys::hold(&object, &hold))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        h.target
            .inner
            .get(&p, &keys::relay_high_water(&source()).unwrap())
            .await
            .unwrap(),
        Some(codec::encode_u64(1))
    );
    fire(&h, &local).await.unwrap();
    assert!(queued(&local).await.is_empty());
    assert_eq!(
        h.target.calls.load(Ordering::SeqCst),
        3,
        "duplicate watermark needs only one routed snapshot"
    );
    assert_eq!(
        h.target
            .inner
            .get(&p, &keys::object_state(&object))
            .await
            .unwrap(),
        Some(state)
    );
}

#[tokio::test]
async fn late_v2_blocked_holder_after_ttl_retains_real_takedown_handoff() {
    late_blocked_holder_handoff(true).await;
}

#[tokio::test]
async fn late_blocked_holder_after_ttl_retains_real_takedown_handoff() {
    late_blocked_holder_handoff(false).await;
}

#[allow(clippy::too_many_lines)] // The durable handoff is checked through materialization and protection release.
async fn late_blocked_holder_handoff(v2: bool) {
    let local = memory();
    let object = [0x46; 32];
    let hold = [0x47; 32];
    let p = crate::store::content_shard(&object);
    let remote = RoutedMethods {
        inner: memory(),
        calls: AtomicUsize::new(0),
        lost_reply: AtomicBool::new(false),
    };
    let idx = crate::store::ContentIndex::new(crate::store::BorrowedStore(&remote.inner));
    let identity = crate::store::PendingHolderV1::new(
        crate::store::Holder::new(
            NamespaceKey::deployment_default(),
            RepoName::new("a").unwrap(),
        ),
        source(),
        [0x48; 32],
        object,
        hold,
        [0x49; 32],
    )
    .unwrap();
    assert_eq!(
        idx.add_hold(&object, &hold, 10_000, 100).await.unwrap(),
        crate::store::HoldOutcome::Held
    );
    assert_eq!(
        idx.protect_pending_holder(&object, &hold, &identity, 100)
            .await
            .unwrap(),
        crate::store::HoldOutcome::Held
    );
    let blocked = crate::store::BlockEntry::new("late", 101);
    if v2 {
        idx.install_block_action(
            &object,
            &crate::takedown::denial::BlockAction {
                id: [0x4a; 32],
                takedown_id: [0x4b; 32],
                reason: "late".into(),
                blocked_at_ms: 101,
                chunk_ids: vec![],
            },
            101,
        )
        .await
        .unwrap();
    } else {
        idx.block(&object, &blocked, 101).await.unwrap();
    }
    append(
        &local,
        &p,
        vec![(
            keys::pending_holder(&object, &hold),
            identity.encode().unwrap(),
        )],
        50,
    )
    .await;
    let now = crate::store::MAX_HOLD_TTL_MS + 1_000;
    assert!(idx.collectable(&object, now, 0).await.unwrap().is_none());
    let h = RelayHandler {
        target: remote,
        hook: HolderRelayHook {
            clock: Arc::new(ManualClock::new(i64::try_from(now).unwrap())),
        },
        budget: RelayBudget {
            max_target_calls: Some(2),
            ..RelayBudget::default()
        },
    };
    fire(&h, &local).await.unwrap();
    assert_eq!(h.target.calls.load(Ordering::SeqCst), 2);
    assert!(queued(&local).await.is_empty());
    let key = keys::content_takedown(&object, &identity.intent);
    let raw = h.target.inner.get(&p, &key).await.unwrap().unwrap();
    let request = ContentTakedownV1::decode(&raw).unwrap();
    assert_eq!(request.identity, identity);
    assert_eq!(request.blocked, blocked);
    assert!(request.ready_at_ms.is_none());
    assert_eq!(
        keys::parse(&key),
        Some(keys::ParsedKey::ContentTakedown {
            object,
            intent: identity.intent
        })
    );
    let reference = bytes::Bytes::from([object.as_slice(), identity.intent.as_slice()].concat());
    let fired = TakedownRequestTimer
        .fire(
            &TimerCtx {
                store: &h.target.inner,
                partition: &p,
                now_ms: now,
            },
            &DueTimer {
                due_at_ms: now,
                kind: kinds::CONTENT_TAKEDOWN_REQUEST,
                reference,
                value: Value::default(),
            },
        )
        .await
        .unwrap();
    let Fired::Reschedule { batch, .. } = fired else {
        panic!("handoff must stay durably pending for5.6a")
    };
    assert_eq!(
        h.target.inner.apply(&p, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    let ready =
        ContentTakedownV1::decode(&h.target.inner.get(&p, &key).await.unwrap().unwrap()).unwrap();
    assert_eq!(ready.ready_at_ms, Some(now));
    assert_eq!(ready.blocked, blocked);
    assert!(
        h.target
            .inner
            .get(&p, &keys::pending_holder(&object, &hold))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        h.target
            .inner
            .get(&p, &keys::hold(&object, &hold))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        codec::decode_object_state(
            &h.target
                .inner
                .get(&p, &keys::object_state(&object))
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .holders,
        1
    );
    let mut bad = ready.encode().unwrap().as_bytes().to_vec();
    bad.push(0);
    assert!(ContentTakedownV1::decode(&Value::new(bad)).is_err());
}

fn duplicate_proof_identity() -> crate::store::PendingHolderV1 {
    crate::store::PendingHolderV1::new(
        crate::store::Holder::new(
            NamespaceKey::deployment_default(),
            RepoName::new("a").unwrap(),
        ),
        source(),
        [0x75; 32],
        [0x72; 32],
        [0x73; 32],
        [0x76; 32],
    )
    .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Check both a new block and an already-retained late-block request.
async fn duplicate_holder_intent_after_block_has_only_watermark_effects() {
    for initially_blocked in [false, true] {
        let local = memory();
        let h = RelayHandler {
            target: Instrumented::new(),
            hook: HolderRelayHook {
                clock: Arc::new(ManualClock::new(100)),
            },
            budget: RelayBudget {
                max_target_calls: Some(2),
                ..RelayBudget::default()
            },
        };
        let identity = duplicate_proof_identity();
        let object = identity.object;
        let destination = crate::store::content_shard(&object);
        let gp = keys::pending_holder(&object, &identity.hold_id);
        let holder = keys::holder(&object, &identity.holder.ns, &identity.holder.repo).unwrap();
        let c = keys::object_state(&object);
        let ct = keys::content_takedown(&object, &identity.intent);
        let idx = crate::store::ContentIndex::new(crate::store::BorrowedStore(&h.target.inner));
        assert_eq!(
            idx.add_hold(&object, &identity.hold_id, 10_000, 100)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        assert_eq!(
            idx.protect_pending_holder(&object, &identity.hold_id, &identity, 100)
                .await
                .unwrap(),
            crate::store::HoldOutcome::Held
        );
        if initially_blocked {
            idx.block(&object, &crate::store::BlockEntry::new("initial", 100), 100)
                .await
                .unwrap();
        }
        append(
            &local,
            &destination,
            vec![(gp.clone(), identity.encode().unwrap())],
            50,
        )
        .await;
        fire(&h, &local).await.unwrap();
        assert!(queued(&local).await.is_empty());
        idx.block(
            &object,
            &crate::store::BlockEntry::new("after delivery", 100),
            100,
        )
        .await
        .unwrap();
        let prior_c = h.target.inner.get(&destination, &c).await.unwrap().unwrap();
        let prior_h = h
            .target
            .inner
            .get(&destination, &holder)
            .await
            .unwrap()
            .unwrap();
        let prior_ct = h.target.inner.get(&destination, &ct).await.unwrap();
        assert_eq!(prior_ct.is_some(), initially_blocked);
        append(
            &local,
            &destination,
            vec![(gp.clone(), identity.encode().unwrap())],
            50,
        )
        .await;
        fire(&h, &local).await.unwrap();
        assert!(
            queued(&local).await.is_empty(),
            "matching protected duplicate must drain after a block"
        );
        assert_eq!(
            h.target.inner.get(&destination, &c).await.unwrap(),
            Some(prior_c.clone())
        );
        assert_eq!(
            h.target.inner.get(&destination, &holder).await.unwrap(),
            Some(prior_h.clone())
        );
        assert_eq!(
            h.target.inner.get(&destination, &ct).await.unwrap(),
            prior_ct
        );
        let batches = h.target.applies.lock().unwrap();
        let batch = &batches.last().unwrap().1;
        batch.validate(&StoreCapabilities::full()).unwrap();
        assert_eq!(
            batch.writes,
            vec![Write::Put(
                keys::relay_high_water(&source()).unwrap(),
                codec::encode_u64(2)
            )]
        );
        assert!(batch.preconditions.contains(&Precondition::Absent(gp)));
        assert!(
            batch
                .preconditions
                .contains(&Precondition::Equals(holder, prior_h))
        );
        assert!(
            batch
                .preconditions
                .contains(&Precondition::Equals(c, prior_c))
        );
    }
}

#[tokio::test]
async fn absent_pending_marker_without_matching_live_holder_stays_queued_with_diagnostic() {
    let identity = duplicate_proof_identity();
    for (ticket, state_present, deleting) in [
        (None, true, false),
        (Some([0x77; 32]), true, false),
        (Some(identity.ticket), true, true),
        (Some(identity.ticket), false, false),
    ] {
        let local = memory();
        let h = RelayHandler {
            target: Instrumented::new(),
            hook: HolderRelayHook {
                clock: Arc::new(ManualClock::new(100)),
            },
            budget: RelayBudget::default(),
        };
        let destination = crate::store::content_shard(&identity.object);
        let gp = keys::pending_holder(&identity.object, &identity.hold_id);
        let mut fixture = Batch::new();
        if let Some(ticket) = ticket {
            fixture = fixture.put(
                keys::holder(&identity.object, &identity.holder.ns, &identity.holder.repo).unwrap(),
                codec::encode_holder(&crate::store::HolderRecord::new(7, ticket)),
            );
        }
        if state_present {
            fixture = fixture.put(
                keys::object_state(&identity.object),
                codec::encode_object_state(&crate::store::ObjectState::new(
                    7,
                    100,
                    u64::from(ticket.is_some()),
                    deleting,
                )),
            );
        }
        h.target.inner.apply(&destination, fixture).await.unwrap();
        append(
            &local,
            &destination,
            vec![(gp.clone(), identity.encode().unwrap())],
            50,
        )
        .await;
        fire(&h, &local).await.unwrap();
        assert_eq!(queued(&local).await.len(), 1);
        assert!(h.target.applies.lock().unwrap().is_empty());
        assert!(
            h.target
                .inner
                .get(&destination, &keys::relay_high_water(&source()).unwrap())
                .await
                .unwrap()
                .is_none()
        );
        let row = codec::decode_relay(&queued(&local).await[0].1).unwrap();
        let rows = [(1, row)];
        let mut wanted = h.hook.read_keys(&destination, &rows).unwrap();
        wanted.push(keys::relay_high_water(&source()).unwrap());
        let values = h
            .target
            .inner
            .get_many(&destination, &wanted)
            .await
            .unwrap();
        let seen: Vec<_> = wanted.into_iter().zip(values).collect();
        let error = h
            .hook
            .before_apply_observed(&destination, &rows, &seen, &mut Vec::new(), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::Unavailable(message)
            if message.to_string() == "pending holder marker absent without matching live holder; retry"));
    }
}

#[tokio::test]
async fn absent_pending_marker_proof_rejects_concurrent_holder_state_or_marker_changes() {
    let identity = duplicate_proof_identity();
    let destination = crate::store::content_shard(&identity.object);
    let gp = keys::pending_holder(&identity.object, &identity.hold_id);
    let holder =
        keys::holder(&identity.object, &identity.holder.ns, &identity.holder.repo).unwrap();
    let c = keys::object_state(&identity.object);
    let rh = keys::relay_high_water(&source()).unwrap();
    let hook = HolderRelayHook {
        clock: Arc::new(ManualClock::new(100)),
    };
    let rows = [(
        1,
        RelayV1 {
            at_ms: 50,
            target: destination.clone(),
            puts: vec![(gp.clone(), identity.encode().unwrap())],
            deletes: Vec::new(),
        },
    )];
    for changed in [holder.clone(), c.clone(), gp.clone()] {
        let remote = memory();
        remote
            .apply(
                &destination,
                Batch::new()
                    .put(
                        holder.clone(),
                        codec::encode_holder(&crate::store::HolderRecord::new(7, identity.ticket)),
                    )
                    .put(
                        c.clone(),
                        codec::encode_object_state(&crate::store::ObjectState::new(
                            7, 100, 1, false,
                        )),
                    ),
            )
            .await
            .unwrap();
        let mut wanted = hook.read_keys(&destination, &rows).unwrap();
        wanted.push(rh.clone());
        let values = remote.get_many(&destination, &wanted).await.unwrap();
        let seen: Vec<_> = wanted.into_iter().zip(values).collect();
        let mut batch = Batch::new()
            .require(Precondition::Absent(rh.clone()))
            .put(gp.clone(), identity.encode().unwrap())
            .put(rh.clone(), codec::encode_u64(1));
        hook.before_apply_observed(
            &destination,
            &rows,
            &seen,
            &mut batch.preconditions,
            &mut batch.writes,
        )
        .await
        .unwrap();
        assert_eq!(
            batch.writes,
            vec![Write::Put(rh.clone(), codec::encode_u64(1))]
        );
        remote
            .apply(
                &destination,
                Batch::new().put(changed.clone(), Value::new(vec![255])),
            )
            .await
            .unwrap();
        let expected = batch
            .preconditions
            .iter()
            .position(|pre| match pre {
                Precondition::Absent(key) | Precondition::Equals(key, _) => key == &changed,
                _ => false,
            })
            .unwrap();
        assert!(
            matches!(remote.apply(&destination, batch).await.unwrap(), BatchOutcome::PreconditionFailed { index, .. } if index == expected)
        );
        assert!(remote.get(&destination, &rh).await.unwrap().is_none());
    }
}
