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
    registry: &TimerRegistry<S>,
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
        assert_eq!(store.get(&partition(), &key).await.unwrap().is_some(), bad);
        assert_eq!(
            store.get(&partition(), &effect()).await.unwrap().is_some(),
            !bad
        );
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
        (TickBudget::new(128, 32, 1, 10_000), Action::Done, 1),
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
        assert_eq!(report.next_wake_ms, Some(100));
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
        (0, 512, 512, Some(5100))
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
                .get(&partition(), &timer(1, 1, 1))
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
    assert!(store.get(&partition(), &effect()).await.unwrap().is_none());
    assert_eq!(
        store.get(&partition(), &timer(1, 1, 1)).await.unwrap(),
        Some(Value::new(b"changed".to_vec()))
    );
}
#[test]
#[should_panic(expected = "zero")]
fn registry_rejects_zero() {
    let _: TimerRegistry<MemoryKv> = TimerRegistry::new().register(Handler(0, Action::Done, None));
}
#[test]
#[should_panic(expected = "already")]
fn registry_rejects_duplicate() {
    let _: TimerRegistry<MemoryKv> = TimerRegistry::new()
        .register(Handler(1, Action::Done, None))
        .register(Handler(1, Action::Done, None));
}

#[tokio::test]
async fn apply_full_and_deadline_are_failed_without_effects() {
    for (store, action) in [
        (memory().with_capacity_limit(15), Action::LargeEffect),
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
        assert!(store.get(&partition(), &key).await.unwrap().is_some());
        assert!(store.get(&partition(), &effect()).await.unwrap().is_none());
    }
}
