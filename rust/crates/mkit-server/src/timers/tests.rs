use super::*;
use crate::{
    BoxFuture, Cursor, ManualClock, MemoryKv, NamespaceKey, PartitionStats, ScanPage,
    StoreCapabilities,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn memory() -> MemoryKv {
    MemoryKv::with_clock(Arc::new(ManualClock::new(100)))
}

#[test]
fn takedown_work_timer_key_golden() {
    // R-190: the new allocation retains the existing generic timer wire shape.
    let kind = registry::kinds::TAKEDOWN_WORK.get();
    assert_eq!(kind, 15);
    let key = keys::timer(100, kind, b"action-1");
    assert_eq!(
        key.as_bytes(),
        b"w\0\0\0\0\0\0\0\0\x64\x0f\0\0\0\0\0\0\0\0\x64action-1"
    );
    assert!(matches!(keys::parse(&key), Some(keys::ParsedKey::Timer {
        due_at_ms: 100, kind: 15, reference
    }) if reference.as_ref() == b"action-1"));
}

#[cfg(feature = "__test-faults")]
#[tokio::test]
async fn test_timer_d34_deletes_ref_and_enqueues_index_delete_without_lease() {
    use crate::pipeline::{D34Shards, ShardMap};
    use crate::repo::{RepoId, RepoName};
    use crate::store::codec;
    let store = memory();
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("a").unwrap(),
    };
    let name = "refs/heads/main";
    let source = D34Shards.ref_shard(&repo, name);
    store
        .apply(
            &source,
            Batch::new()
                .put(keys::outbox_sequence(), codec::encode_u64(5))
                .put(
                    keys::ref_key(&repo.name, name),
                    codec::encode_ref_id(&[1; 32]),
                ),
        )
        .await
        .unwrap();
    let reference = [repo.name.as_str().as_bytes(), b"\0", name.as_bytes()].concat();
    let due = DueTimer {
        due_at_ms: 100,
        kind: registry::kinds::TEST,
        reference: reference.into(),
        value: Value::default(),
    };
    let fired = test_kind::TestTimer
        .fire(
            &TimerCtx {
                store: &store,
                partition: &source,
                now_ms: 100,
            },
            &due,
        )
        .await
        .unwrap();
    let Fired::Done(batch) = fired else {
        panic!("test timer must commit")
    };
    assert!(batch.preconditions.contains(&Precondition::Equals(
        keys::outbox_sequence(),
        codec::encode_u64(5)
    )));
    assert!(
        !batch
            .preconditions
            .iter()
            .any(|pre| matches!(pre, Precondition::Equals(key, _) if *key == keys::epoch_lease()))
    );
    assert!(
        batch
            .writes
            .contains(&Write::Delete(keys::ref_key(&repo.name, name)))
    );
    assert!(batch.writes.iter().any(|write| matches!(write, Write::Put(key, _) if *key == keys::timer(100, registry::kinds::RELAY.get(), b""))));
    let row = batch
        .writes
        .iter()
        .find_map(|write| match write {
            Write::Put(key, value)
                if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_))) =>
            {
                Some(codec::decode_relay(value).unwrap())
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(row.target, D34Shards.ref_index(&repo, name));
    assert_eq!(
        row.deletes,
        vec![
            keys::published_index(&repo.name, name),
            keys::ref_index_key(&repo.name, name)
        ]
    );
}

fn partition() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}
fn timer(due: u64, kind: u8, id: u32) -> Key {
    keys::timer(due, kind, &id.to_be_bytes())
}
async fn put<S: NamespaceStore>(store: &S, key: Key) {
    assert_eq!(
        store
            .apply(&partition(), Batch::new().put(key, Value::default()))
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
}
fn effect() -> Key {
    Key::new(b"effect".to_vec())
}
#[derive(Clone)]
enum Action {
    Done,
    Effect,
    LargeEffect,
    BadCondition,
    Deadline,
    Retry,
    Error,
    Reschedule(u64),
    PutTimer(u64),
    Advance(Arc<ManualClock>),
}
struct Handler(u8, Action, Option<u32>);
impl<S: NamespaceStore> TimerHandler<S> for Handler {
    fn kind(&self) -> TimerKind {
        TimerKind::new(self.0)
    }
    fn max_per_tick(&self) -> Option<u32> {
        self.2
    }
    fn fire<'a>(
        &'a self,
        _ctx: &'a TimerCtx<'a, S>,
        _timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            Ok(match &self.1 {
                Action::Done => Fired::Done(Batch::new()),
                Action::Effect => {
                    Fired::Done(Batch::new().put(effect(), Value::new(b"yes".to_vec())))
                }
                Action::LargeEffect => {
                    Fired::Done(Batch::new().put(effect(), Value::new(vec![0; 32])))
                }
                Action::BadCondition => Fired::Done(
                    Batch::new()
                        .require(Precondition::Present(effect()))
                        .put(effect(), Value::default()),
                ),
                Action::Deadline => Fired::Done(Batch::new().require(Precondition::NotAfter(99))),
                Action::Retry => Fired::Retry,
                Action::Error => return Err(StoreError::Full),
                Action::Reschedule(due) => Fired::Reschedule {
                    due_at_ms: *due,
                    value: Value::new(b"new".to_vec()),
                    batch: Batch::new(),
                },
                Action::PutTimer(due) => {
                    Fired::Done(Batch::new().put(timer(*due, 2, 1), Value::default()))
                }
                Action::Advance(clock) => {
                    clock.advance(10);
                    Fired::Done(Batch::new())
                }
            })
        })
    }
}
async fn tick<S: NamespaceStore>(
    store: &S,
    registry: &TimerRegistry<'static, S>,
    clock: &ManualClock,
    budget: &TickBudget,
) -> RunReport {
    run_due(store, &partition(), registry, clock, 100, budget)
        .await
        .unwrap()
}
#[tokio::test]
async fn due_future_and_second_delivery() {
    let store = memory();
    let clock = ManualClock::new(100);
    let registry = TimerRegistry::new().register(Handler(1, Action::Done, None));
    put(&store, timer(99, 1, 1)).await;
    put(&store, timer(101, 1, 2)).await;
    let report = tick(&store, &registry, &clock, &TickBudget::default()).await;
    assert_eq!((report.fired, report.next_wake_ms), (1, Some(101)));
    assert_eq!(
        tick(&store, &registry, &clock, &TickBudget::default())
            .await
            .fired,
        0
    );
    let report = run_due(
        &store,
        &partition(),
        &registry,
        &clock,
        101,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!((report.fired, report.next_wake_ms), (1, None));
}
#[tokio::test]
async fn effects_are_atomic_and_failed_handler_condition_is_raced() {
    for action in [Action::Effect, Action::BadCondition] {
        let store = memory();
        let key = timer(1, 1, 1);
        put(&store, key.clone()).await;
        let registry = TimerRegistry::new().register(Handler(1, action.clone(), None));
        let report = tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default(),
        )
        .await;
        let bad = matches!(action, Action::BadCondition);
        assert_eq!(
            (report.fired, report.raced),
            (u32::from(!bad), u32::from(bad))
        );
        assert!(store.get(&partition(), &key).await.unwrap().is_none());
        assert_eq!(
            store
                .get(
                    &partition(),
                    &keys::timer_retry(5100, 1, &1_u32.to_be_bytes(), 1, 1)
                )
                .await
                .unwrap()
                .is_some(),
            bad
        );
        assert_eq!(
            store.get(&partition(), &effect()).await.unwrap().is_some(),
            !bad
        );
        // Unchanged work after a failed condition gets a durable backoff wake.
        let wake = if bad {
            Some(100 + RETRY_BACKOFF_MS)
        } else {
            None
        };
        assert_eq!(report.next_wake_ms, wake);
    }
}
#[tokio::test]
async fn per_kind_fairness_and_repeated_drain() {
    let store = memory();
    let clock = ManualClock::new(100);
    for id in 0..100 {
        put(&store, timer(1, 1, id)).await;
    }
    for id in 0..5 {
        put(&store, timer(2, 2, id)).await;
    }
    let registry = TimerRegistry::new()
        .register(Handler(1, Action::Done, None))
        .register(Handler(2, Action::Done, None));
    let budget = TickBudget::new(128, 10, 512, 10_000);
    let report = tick(&store, &registry, &clock, &budget).await;
    assert_eq!(
        (report.fired, report.deferred, report.next_wake_ms),
        (15, 90, Some(100))
    );
    let mut total = report.fired;
    for _ in 0..9 {
        total += tick(&store, &registry, &clock, &budget).await.fired;
    }
    assert_eq!(total, 105);
    assert_eq!(
        tick(&store, &registry, &clock, &budget).await.next_wake_ms,
        None
    );
}
#[tokio::test]
async fn global_budgets_and_kind_override() {
    for (budget, action, want_fired) in [
        (TickBudget::new(1, 32, 512, 10_000), Action::Done, 1),
        (TickBudget::new(128, 32, 1, 10_000), Action::Done, 0),
        (
            TickBudget::new(128, 32, 512, 10),
            Action::Advance(Arc::new(ManualClock::new(100))),
            1,
        ),
    ] {
        let store = memory();
        for id in 0..3 {
            put(&store, timer(1, 1, id)).await;
        }
        let clock = match &action {
            Action::Advance(clock) => clock.clone(),
            _ => Arc::new(ManualClock::new(100)),
        };
        let registry = TimerRegistry::new().register(Handler(1, action, None));
        let report = tick(&store, &registry, &clock, &budget).await;
        assert!(report.stopped_on_budget);
        assert_eq!(report.fired, want_fired);
        assert_eq!(
            report.next_wake_ms,
            Some(if want_fired == 0 { 5100 } else { 100 })
        );
    }
    let store = memory();
    for id in 0..3 {
        put(&store, timer(1, 1, id)).await;
    }
    let registry = TimerRegistry::new().register(Handler(1, Action::Done, Some(1)));
    assert_eq!(
        tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default()
        )
        .await
        .deferred,
        2
    );
    let budget = TickBudget::new(0, 0, 0, 0);
    assert_eq!(
        (
            budget.max_fired,
            budget.max_per_kind,
            budget.max_scanned,
            budget.max_elapsed_ms
        ),
        (1, 1, 1, 1)
    );
}
#[tokio::test]
async fn unknown_rows_are_retained_with_backoff() {
    let store = memory();
    for id in 0..600 {
        put(&store, timer(1, 0, id)).await;
    }
    let report = tick(
        &store,
        &TimerRegistry::new(),
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!(
        (
            report.fired,
            report.scanned,
            report.unknown,
            report.next_wake_ms
        ),
        (0, 128, 128, Some(100))
    );
    assert!(report.stopped_on_budget);
    assert_eq!(store.stats(&partition()).await.unwrap().keys, Some(600));
}
#[tokio::test]
async fn handler_failures_remain_and_backoff_is_capped_by_future() {
    for action in [Action::Retry, Action::Error] {
        let store = memory();
        put(&store, timer(1, 1, 1)).await;
        let registry = TimerRegistry::new().register(Handler(1, action, None));
        let report = tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default(),
        )
        .await;
        assert_eq!((report.failed, report.next_wake_ms), (1, Some(5100)));
        assert!(
            store
                .get(
                    &partition(),
                    &keys::timer_retry(5100, 1, &1_u32.to_be_bytes(), 1, 1)
                )
                .await
                .unwrap()
                .is_some()
        );
        put(&store, timer(200, 1, 2)).await;
        assert_eq!(
            tick(
                &store,
                &registry,
                &ManualClock::new(100),
                &TickBudget::default()
            )
            .await
            .next_wake_ms,
            Some(200)
        );
    }
}
#[tokio::test]
async fn reschedule_and_same_key_rejection() {
    for due in [1, 150] {
        let store = memory();
        put(&store, timer(1, 1, 1)).await;
        let registry = TimerRegistry::new().register(Handler(1, Action::Reschedule(due), None));
        let report = tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default(),
        )
        .await;
        if due == 1 {
            assert_eq!((report.failed, report.fired), (1, 0));
        } else {
            assert_eq!((report.fired, report.next_wake_ms), (1, Some(150)));
            assert_eq!(
                store.get(&partition(), &timer(due, 1, 1)).await.unwrap(),
                Some(Value::new(b"new".to_vec()))
            );
            assert!(
                store
                    .get(&partition(), &timer(1, 1, 1))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
#[tokio::test]
async fn committed_put_lowers_wake_and_clamps_to_now() {
    for due in [50, 150] {
        let store = memory();
        put(&store, timer(1, 1, 1)).await;
        put(&store, timer(300, 1, 2)).await;
        let registry = TimerRegistry::new().register(Handler(1, Action::PutTimer(due), None));
        let report = tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default(),
        )
        .await;
        assert_eq!(report.next_wake_ms, Some(due.max(100)));
    }
}
struct Racing {
    inner: MemoryKv,
    changed: AtomicBool,
}
impl NamespaceStore for Racing {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, part: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(part, key).await
    }
    async fn scan(
        &self,
        part: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(part, start, end, after, limit).await
    }
    async fn apply(&self, part: &Partition, budget: Batch) -> Result<BatchOutcome, StoreError> {
        if !budget.preconditions.is_empty() && !self.changed.swap(true, Ordering::SeqCst) {
            self.inner
                .apply(
                    part,
                    Batch::new().put(timer(1, 1, 1), Value::new(b"changed".to_vec())),
                )
                .await?;
        }
        self.inner.apply(part, budget).await
    }
    async fn stats(&self, part: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(part).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}
#[tokio::test]
async fn changed_timer_row_loses_guard_and_does_not_apply_effects() {
    let store = Racing {
        inner: memory(),
        changed: AtomicBool::new(false),
    };
    put(&store, timer(1, 1, 1)).await;
    let registry = TimerRegistry::new().register(Handler(1, Action::Effect, None));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!((report.raced, report.fired), (1, 0));
    assert_eq!(report.next_wake_ms, Some(100 + RETRY_BACKOFF_MS));
    assert!(store.get(&partition(), &effect()).await.unwrap().is_none());
    assert_eq!(
        store.get(&partition(), &timer(1, 1, 1)).await.unwrap(),
        Some(Value::new(b"changed".to_vec()))
    );
}
#[test]
#[should_panic(expected = "zero")]
fn registry_rejects_zero() {
    let _: TimerRegistry<'static, MemoryKv> =
        TimerRegistry::new().register(Handler(0, Action::Done, None));
}
#[test]
#[should_panic(expected = "already")]
fn registry_rejects_duplicate() {
    let _: TimerRegistry<'static, MemoryKv> = TimerRegistry::new()
        .register(Handler(1, Action::Done, None))
        .register(Handler(1, Action::Done, None));
}

#[tokio::test]
async fn apply_full_and_deadline_are_failed_without_effects() {
    for (store, action) in [
        (memory().with_capacity_limit(24), Action::LargeEffect),
        (memory(), Action::Deadline),
    ] {
        let key = timer(1, 1, 1);
        put(&store, key.clone()).await;
        let registry = TimerRegistry::new().register(Handler(1, action, None));
        let report = tick(
            &store,
            &registry,
            &ManualClock::new(100),
            &TickBudget::default(),
        )
        .await;
        assert_eq!(
            (report.failed, report.fired, report.next_wake_ms),
            (1, 0, Some(5100))
        );
        assert!(store.get(&partition(), &key).await.unwrap().is_none());
        assert!(
            store
                .get(
                    &partition(),
                    &keys::timer_retry(5100, 1, &1_u32.to_be_bytes(), 1, 1)
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(store.get(&partition(), &effect()).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn zero_kind_cap_still_fires_one_per_tick() {
    let store = memory();
    put(&store, timer(1, 1, 1)).await;
    let registry = TimerRegistry::new().register(Handler(1, Action::Effect, Some(0)));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!((report.fired, report.deferred), (1, 0));
    assert!(store.get(&partition(), &effect()).await.unwrap().is_some());
}

#[tokio::test]
async fn raced_with_deferred_and_nothing_fired_backs_off() {
    let store = Racing {
        inner: memory(),
        changed: AtomicBool::new(false),
    };
    put(&store, timer(1, 1, 1)).await;
    put(&store, timer(2, 1, 2)).await;
    let registry = TimerRegistry::new().register(Handler(1, Action::Effect, Some(1)));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!((report.fired, report.raced, report.deferred), (0, 1, 1));
    assert_eq!(report.next_wake_ms, Some(100 + RETRY_BACKOFF_MS));
}

#[tokio::test]
async fn failed_timer_is_physically_redated_without_losing_payload() {
    let store = memory();
    let old = timer(1, 1, 1);
    let payload = Value::new(b"retained-work".to_vec());
    store
        .apply(&partition(), Batch::new().put(old.clone(), payload.clone()))
        .await
        .unwrap();
    let registry = TimerRegistry::new().register(Handler(1, Action::Retry, None));
    tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert!(
        store.get(&partition(), &old).await.unwrap().is_none(),
        "failed timer pins the physical head"
    );
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let page = store
        .scan(&partition(), &start, &end, None, 10)
        .await
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].1, payload);
    assert!(matches!(
        keys::parse(&page.entries[0].0),
        Some(keys::ParsedKey::Timer {
            due_at_ms: 5100,
            ..
        })
    ));
}

#[tokio::test]
async fn retry_backoff_survives_restart_and_caps_without_waiving_rows() {
    let store = memory();
    let payload = Value::new(b"opaque".to_vec());
    store
        .apply(
            &partition(),
            Batch::new().put(timer(1, 1, 1), payload.clone()),
        )
        .await
        .unwrap();
    let mut now = 100;
    for attempt in 1_u8..=12 {
        // A fresh registry, clock and tick state model a cold restart.
        let clock = ManualClock::new(i64::try_from(now).unwrap());
        let registry = TimerRegistry::new().register(Handler(1, Action::Retry, None));
        let report = run_due(
            &store,
            &partition(),
            &registry,
            &clock,
            now,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        assert_eq!((report.failed, report.fired), (1, 0));
        let delay = (RETRY_BACKOFF_MS * (1_u64 << (attempt.min(8) - 1))).min(MAX_RETRY_BACKOFF_MS);
        assert_eq!(report.next_wake_ms, Some(now + delay));
        let (start, end) = keys::class_range(keys::TAG_TIMER);
        let page = store
            .scan(&partition(), &start, &end, None, 2)
            .await
            .unwrap();
        assert_eq!(
            page.entries.len(),
            1,
            "backoff must neither duplicate nor delete work"
        );
        assert_eq!(page.entries[0].1, payload);
        assert_eq!(
            keys::timer_retry_state(&page.entries[0].0),
            Some((1, attempt.min(8)))
        );
        now += delay;
    }
    // A newly available handler still executes retained work after the cap.
    let registry = TimerRegistry::new().register(Handler(1, Action::Done, None));
    let report = run_due(
        &store,
        &partition(),
        &registry,
        &ManualClock::new(i64::try_from(now).unwrap()),
        now,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!((report.fired, report.failed), (1, 0));
    assert_eq!(store.stats(&partition()).await.unwrap().keys, Some(0));
}

#[tokio::test]
async fn backoff_guard_cannot_overwrite_concurrent_payload_or_destination() {
    let store = Racing {
        inner: memory(),
        changed: AtomicBool::new(false),
    };
    put(&store, timer(1, 1, 1)).await;
    let registry = TimerRegistry::new().register(Handler(1, Action::Retry, None));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!(report.raced, 1);
    assert_eq!(
        store.get(&partition(), &timer(1, 1, 1)).await.unwrap(),
        Some(Value::new(b"changed".to_vec()))
    );
    assert_eq!(store.stats(&partition()).await.unwrap().keys, Some(1));

    let store = memory();
    let old = timer(1, 1, 1);
    let destination = keys::timer_retry(5100, 1, &1_u32.to_be_bytes(), 1, 1);
    store
        .apply(
            &partition(),
            Batch::new()
                .put(old.clone(), Value::new(b"original".to_vec()))
                .put(destination.clone(), Value::new(b"other".to_vec())),
        )
        .await
        .unwrap();
    let registry = TimerRegistry::new().register(Handler(1, Action::Retry, None));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!(report.raced, 1);
    assert_eq!(
        store.get(&partition(), &old).await.unwrap(),
        Some(Value::new(b"original".to_vec()))
    );
    assert_eq!(
        store.get(&partition(), &destination).await.unwrap(),
        Some(Value::new(b"other".to_vec()))
    );
}

struct OriginalDue;
impl<S: NamespaceStore> TimerHandler<S> for OriginalDue {
    fn kind(&self) -> TimerKind {
        TimerKind::new(1)
    }
    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            assert_eq!(timer.due_at_ms, 1);
            assert_eq!(timer.value.as_bytes(), b"payload");
            if ctx.now_ms == 100 {
                Ok(Fired::Retry)
            } else {
                Ok(Fired::Reschedule {
                    due_at_ms: ctx.now_ms + 100,
                    value: timer.value.clone(),
                    batch: Batch::new(),
                })
            }
        })
    }
}

#[tokio::test]
async fn retry_preserves_handler_due_and_success_resets_retry_metadata() {
    let store = memory();
    store
        .apply(
            &partition(),
            Batch::new().put(timer(1, 1, 1), Value::new(b"payload".to_vec())),
        )
        .await
        .unwrap();
    let registry = TimerRegistry::new().register(OriginalDue);
    let first = run_due(
        &store,
        &partition(),
        &registry,
        &ManualClock::new(100),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(first.failed, 1);
    let second = run_due(
        &store,
        &partition(),
        &registry,
        &ManualClock::new(5100),
        5100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!((second.fired, second.next_wake_ms), (1, Some(5200)));
    let key = timer(5200, 1, 1);
    assert_eq!(keys::timer_retry_state(&key), Some((5200, 0)));
    assert_eq!(
        store.get(&partition(), &key).await.unwrap(),
        Some(Value::new(b"payload".to_vec()))
    );
}

#[tokio::test]
async fn exact_commit_boundary_keeps_unexamined_future_timers_awake() {
    let store = memory();
    for id in 0..2 {
        put(&store, timer(1, 1, id)).await;
    }
    put(&store, timer(300, 1, 9)).await;
    let registry = TimerRegistry::new().register(Handler(1, Action::Done, None));
    let report = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::new(2, 32, 512, 10_000),
    )
    .await;
    assert_eq!(report.fired, 2);
    assert!(report.stopped_on_budget);
    assert_eq!(report.next_wake_ms, Some(100));
    let resumed = tick(
        &store,
        &registry,
        &ManualClock::new(100),
        &TickBudget::default(),
    )
    .await;
    assert_eq!(resumed.next_wake_ms, Some(300));
    assert!(
        store
            .get(&partition(), &timer(300, 1, 9))
            .await
            .unwrap()
            .is_some()
    );
}
