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
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
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
async fn queued<S: NamespaceStore>(store: &S) -> Vec<(Key, Value)> {
    let (start, end) = keys::class_range(keys::TAG_RELAY);
    store
        .scan(&source(), &start, &end, None, 1000)
        .await
        .unwrap()
        .entries
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
    fail_delete: AtomicBool,
    race_watermark: AtomicBool,
    append_on_drain: Mutex<Option<Batch>>,
    applies: Mutex<Vec<(Partition, Batch)>>,
    short_pages: bool,
    fail_watermark_after_apply: bool,
}
impl Instrumented {
    fn new() -> Self {
        Self {
            inner: memory(),
            fail_target: None,
            fail_delete: AtomicBool::new(false),
            race_watermark: AtomicBool::new(false),
            append_on_drain: Mutex::new(None),
            applies: Mutex::new(Vec::new()),
            short_pages: false,
            fail_watermark_after_apply: false,
        }
    }
}
impl NamespaceStore for Instrumented {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
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
        self.applies.lock().unwrap().push((p.clone(), b.clone()));
        if self.fail_target.as_ref() == Some(p) {
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
        self.inner.apply(p, b).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
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
        Fired::Reschedule {
            due_at_ms: 5100,
            ..
        }
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
    assert!(
        s.get(&source(), &keys::timer(100, 3, b""))
            .await
            .unwrap()
            .is_some()
    );
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
    assert_eq!(report.fired, 1);
    assert!(queued(&s).await.is_empty());
    assert!(
        s.get(&source(), &keys::timer(100, 3, b""))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn budgets_reschedule_and_short_pages_are_followed() {
    for budget in [
        RelayBudget {
            max_rows: 2,
            max_targets: 16,
        },
        RelayBudget {
            max_rows: 256,
            max_targets: 1,
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
        assert!(matches!(
            fire(&h, &s).await.unwrap(),
            Fired::Reschedule { due_at_ms: 101, .. }
        ));
        assert_eq!(
            queued(&s.inner).await.len(),
            if budget.max_targets == 1 { 2 } else { 1 }
        );
    }
}

#[tokio::test]
async fn corrupt_row_stops_tick_without_skipping_or_deleting() {
    let s = memory();
    let h = handler(Instrumented::new());
    append(&s, &target(0), vec![(key(), Value::default())], 50).await;
    s.apply(
        &source(),
        Batch::new().put(keys::relay(2), Value::new(b"bad".to_vec())),
    )
    .await
    .unwrap();
    assert!(matches!(fire(&h, &s).await.unwrap(), Fired::Retry));
    assert_eq!(queued(&s).await.len(), 2);
    assert!(h.target.applies.lock().unwrap().is_empty());
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
async fn drained_sources_guard_observed_sequence_and_absent_sequence_needs_no_guard() {
    let s = memory();
    let h = handler(memory());
    let Fired::Done(batch) = fire(&h, &s).await.unwrap() else {
        panic!("empty source not done")
    };
    assert_eq!(batch, Batch::new());
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
async fn zero_row_or_target_budget_delivers_nothing_and_keeps_the_kick() {
    for budget in [
        RelayBudget {
            max_rows: 0,
            max_targets: 16,
        },
        RelayBudget {
            max_rows: 256,
            max_targets: 0,
        },
    ] {
        let source = memory();
        let relay = RelayHandler {
            budget,
            ..handler(Instrumented::new())
        };
        append(&source, &target(0), vec![(key(), Value::default())], 50).await;
        assert!(matches!(
            fire(&relay, &source).await.unwrap(),
            Fired::Reschedule { .. }
        ));
        assert_eq!(queued(&source).await.len(), 1);
        assert!(relay.target.applies.lock().unwrap().is_empty());
    }
}
