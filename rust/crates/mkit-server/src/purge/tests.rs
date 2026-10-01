use super::*;
use crate::{BatchOutcome, NamespaceKey, NamespaceStore, Partition, memory::MemoryKv};
fn request() -> Request {
    Request {
        purge_id: "test-purge".into(),
        audience: "https://server.example".into(),
        repository: "root/repo".into(),
        namespace: String::new(),
        trigger: Trigger::Manual,
        url_paths: vec!["/object/path".into()],
        object_ids: Vec::new(),
        refs: Vec::new(),
    }
}
#[tokio::test]
async fn durable_enqueue_guards_refill_generation_and_combined_backlog() {
    let store = MemoryKv::default();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let request = request();
    assert_eq!(
        store
            .apply(&p, plan_enqueue(&request, 10, None, None).unwrap())
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    assert!(matches!(
        store
            .apply(&p, plan_enqueue(&request, 10, None, None).unwrap())
            .await
            .unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    let row = store
        .get(&p, &keys::cache_purge_generation(request.scope()))
        .await
        .unwrap();
    assert_eq!(generation(row.as_ref()).unwrap(), 10);
    assert_eq!(
        read_request(&store, &p, &request.purge_id).await.unwrap(),
        Some(request)
    );
}
#[test]
fn selectors_include_proof_and_snapshot_and_budget_is_shared() {
    let request = request();
    let tags = request.tags();
    assert_eq!(tags.len(), 3);
    assert!(tags.iter().any(|t| t.starts_with("mkit-proof-")));
    assert!(tags.iter().any(|t| t.starts_with("mkit-snapshot-")));
    let budget = SliceBudget::new(2);
    let other = budget.clone();
    assert!(budget.charge(1));
    assert!(other.charge(1));
    assert!(!budget.charge(1));
    assert_eq!(budget.used(), 2);
}

#[test]
fn all_selector_variants_are_audience_and_scope_bound() {
    let mut request = request();
    request.object_ids = vec![STANDARD.encode([7; 32])];
    request.refs = vec!["refs/heads/main".into()];
    request.validate().unwrap();
    let tags = request.tags();
    for kind in ["path", "object", "ref", "proof", "snapshot"] {
        assert!(
            tags.iter()
                .any(|tag| tag.starts_with(&format!("mkit-{kind}-")))
        );
    }
    request.url_paths.clear();
    request.object_ids.clear();
    request.refs.clear();
    let repository = request.tags();
    assert_eq!(
        repository,
        [cache_tag(&request.audience, "repository", "root/repo")]
    );
    request.repository.clear();
    request.namespace = "root".into();
    request.validate().unwrap();
    assert_eq!(
        request.tags(),
        [cache_tag(&request.audience, "namespace", "root")]
    );
    request.audience = "https://other.example".into();
    assert_ne!(request.tags()[0], repository[0]);
}

struct EnumeratedLocal(std::sync::Arc<std::sync::Mutex<Vec<u32>>>);
impl LocalInvalidation for EnumeratedLocal {
    fn invalidate<'a>(
        &'a self,
        _: &'a Request,
        mut cursor: u32,
        budget: &'a SliceBudget,
    ) -> crate::BoxFuture<'a, Result<Option<u32>, StoreError>> {
        Box::pin(async move {
            while cursor < 2 {
                // Enumeration and deletion must share the delivery allowance.
                if !budget.charge(2) {
                    return Ok(Some(cursor));
                }
                self.0.lock().unwrap().push(cursor);
                cursor += 1;
            }
            Ok(None)
        })
    }
}

#[tokio::test]
async fn cold_slices_resume_local_cursor_and_reserve_budget_before_global_delivery() {
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::{Arc, Mutex};
    let store = MemoryKv::default();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let request = request();
    store
        .apply(&p, plan_enqueue(&request, 10, None, None).unwrap())
        .await
        .unwrap();
    let deleted = Arc::new(Mutex::new(Vec::new()));
    // This fixture has already failed once, so the next actual delivery succeeds.
    let attempts = Arc::new(Mutex::new(vec![request.clone()]));
    let clock = crate::ManualClock::new(10);
    for now in 10..=12 {
        clock.set(now);
        let budget = SliceBudget::new(2);
        let registry = TimerRegistry::new().register(PurgeDelivery::new(
            Arc::new(EnumeratedLocal(deleted.clone())),
            Some(Arc::new(RetrySink(attempts.clone()))),
            budget.clone(),
        ));
        let report = run_due(
            &store,
            &p,
            &registry,
            &clock,
            u64::try_from(now).unwrap(),
            &TickBudget::new(2, 2, 32, 1000),
        )
        .await
        .unwrap();
        assert_eq!(
            (report.fired, report.unknown, report.scanned),
            if now == 10 { (1, 1, 2) } else { (1, 0, 1) }
        );
        assert_eq!(budget.used(), if now < 12 { 2 } else { 1 });
        if now < 12 {
            assert_eq!(
                attempts.lock().unwrap().len(),
                1,
                "no sink call without allowance"
            );
            assert!(
                read_request(&store, &p, &request.purge_id)
                    .await
                    .unwrap()
                    .is_some()
            );
        }
    }
    assert_eq!(*deleted.lock().unwrap(), [0, 1]);
    assert_eq!(attempts.lock().unwrap().len(), 2);
    assert!(
        read_request(&store, &p, &request.purge_id)
            .await
            .unwrap()
            .is_none()
    );
}

struct RetrySink(std::sync::Arc<std::sync::Mutex<Vec<Request>>>);
impl PurgeSink for RetrySink {
    fn deliver<'a>(&'a self, request: &'a Request) -> crate::BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut attempts = self.0.lock().unwrap();
            attempts.push(request.clone());
            if attempts.len() == 1 {
                Err(StoreError::unavailable("sink offline"))
            } else {
                Ok(())
            }
        })
    }
}
#[tokio::test]
async fn failed_global_delivery_remains_durable_and_restarts_with_identical_request() {
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::{Arc, Mutex};
    let clock = crate::ManualClock::new(10);
    let store = MemoryKv::default();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let request = request();
    store
        .apply(&p, plan_enqueue(&request, 10, None, None).unwrap())
        .await
        .unwrap();
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let registry = TimerRegistry::new().register(PurgeDelivery::new(
        Arc::new(NoLocalCache),
        Some(Arc::new(RetrySink(attempts.clone()))),
        SliceBudget::new(2),
    ));
    let first_tick = run_due(
        &store,
        &p,
        &registry,
        &clock,
        10,
        &TickBudget::new(2, 2, 32, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        (first_tick.fired, first_tick.unknown, first_tick.scanned),
        (1, 1, 2)
    );
    assert_eq!(
        attempts.lock().unwrap().as_slice(),
        std::slice::from_ref(&request)
    );
    assert_eq!(
        read_request(&store, &p, &request.purge_id).await.unwrap(),
        Some(request.clone())
    );
    let backlog = store
        .get(&p, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
    // Cold registry resumes the persisted progress; it cannot acknowledge the
    // failed remote attempt merely because local invalidation completed.
    let registry = TimerRegistry::new().register(PurgeDelivery::new(
        Arc::new(NoLocalCache),
        Some(Arc::new(RetrySink(attempts.clone()))),
        SliceBudget::new(2),
    ));
    clock.set(2010);
    let retry_tick = run_due(
        &store,
        &p,
        &registry,
        &clock,
        2010,
        &TickBudget::new(2, 2, 32, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        (retry_tick.fired, retry_tick.unknown, retry_tick.scanned),
        (1, 0, 1)
    );
    assert_eq!(
        read_request(&store, &p, &request.purge_id).await.unwrap(),
        None
    );
    assert_eq!(
        codec::decode_backlog(
            &store
                .get(&p, &keys::outcome_backlog())
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        codec::Backlog::default()
    );
    let remaining = timer_rows(&store, &p).await;
    assert_eq!(remaining.len(), 1);
    assert!(matches!(
        keys::parse(&remaining[0].0),
        Some(keys::ParsedKey::Timer { kind: 8, .. })
    ));
    assert_eq!(*attempts.lock().unwrap(), [request.clone(), request]);
    assert_eq!(
        generation(
            store
                .get(&p, &keys::cache_purge_generation("root/repo"))
                .await
                .unwrap()
                .as_ref()
        )
        .unwrap(),
        10
    );
}

#[derive(Default)]
struct OutcomeCapture(std::sync::Mutex<Vec<crate::pipeline::Outcome>>);
impl crate::pipeline::OutcomeSink for OutcomeCapture {
    async fn deliver(
        &self,
        outcome: &crate::pipeline::Outcome,
    ) -> Result<(), crate::pipeline::DeliveryError> {
        self.0.lock().unwrap().push(outcome.clone());
        Ok(())
    }
}

async fn purge_first_paid_terminal() -> (MemoryKv, Partition, Request, crate::ManualClock) {
    use crate::store::codec::{PendingOp, ReservationV1};
    use crate::store::outbox::{OutboxBuilder, Terminal};
    let clock = crate::ManualClock::new(10);
    let store = MemoryKv::default();
    // Visibility purge and paid HTTP read both use the namespace coordinator.
    let ns = NamespaceKey::from_stored("0x1111111111111111111111111111111111111111".into());
    let repository = format!("{}/repo", ns.as_str());
    let p = Partition::Coordinator(ns);
    let mut purge = request();
    purge.repository.clone_from(&repository);
    store
        .apply(&p, plan_enqueue(&purge, 10, None, None).unwrap())
        .await
        .unwrap();
    let prior = codec::encode_reservation(&ReservationV1::Pending {
        repository: repository.clone(),
        created_at_ms: 10,
        reconcile_at_ms: 60010,
        op: PendingOp::Read,
    });
    let mut batch = Batch::new();
    let mut pending = OutboxBuilder::new(
        None,
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    pending.pending(
        "paid-read",
        None,
        &codec::decode_reservation(&prior).unwrap(),
    );
    pending
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    store.apply(&p, batch).await.unwrap();
    let mut terminal = OutboxBuilder::new(
        None,
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    terminal.outcome(
        "paid-read",
        &prior,
        Terminal::new(ReservationV1::ReadServed {
            repository: repository.clone(),
            occurred_at_ms: 20,
            object: [7; 32],
            bytes_served: 123,
        })
        .unwrap(),
    );
    let mut batch = Batch::new();
    terminal
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    batch.validate(&store.capabilities()).unwrap();
    store.apply(&p, batch).await.unwrap();
    (store, p, purge, clock)
}

#[tokio::test]
async fn purge_first_outcome_survives_purge_completion_reconcile_and_restart() {
    use crate::store::codec::ReservationV1;
    use crate::timers::{TickBudget, TimerRegistry, run_due};
    use std::sync::{Arc, Mutex};
    let (store, p, purge, clock) = purge_first_paid_terminal().await;
    let attempts = Arc::new(Mutex::new(Vec::new()));
    for now in [20, 2020, 60010] {
        clock.set(now);
        // No outcome driver is alive before the final cold registry restart.
        let registry = TimerRegistry::new()
            .register(PurgeDelivery::new(
                Arc::new(NoLocalCache),
                Some(Arc::new(RetrySink(attempts.clone()))),
                SliceBudget::new(16),
            ))
            .register(crate::timers::reservation_reconcile::ReservationReconcile);
        run_due(
            &store,
            &p,
            &registry,
            &clock,
            u64::try_from(now).unwrap(),
            &TickBudget::new(32, 32, 128, 1000),
        )
        .await
        .unwrap();
    }
    assert!(
        read_request(&store, &p, &purge.purge_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        codec::decode_backlog(
            &store
                .get(&p, &keys::outcome_backlog())
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .rows,
        1
    );
    assert!(matches!(
        codec::decode_reservation(
            &store
                .get(&p, &keys::reservation("paid-read").unwrap())
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        ReservationV1::ReadServed {
            bytes_served: 123,
            ..
        }
    ));
    let timers = store
        .scan(
            &p,
            &crate::Key::new(b"w\0".to_vec()),
            &crate::Key::new(b"w\x01".to_vec()),
            None,
            100,
        )
        .await
        .unwrap();
    assert!(
        !timers
            .entries
            .iter()
            .any(|(k, _)| matches!(keys::parse(k), Some(keys::ParsedKey::Timer { kind: 9, .. })))
    );
    let sink = Arc::new(OutcomeCapture::default());
    let registry = TimerRegistry::new().register(delivery(sink.clone()));
    clock.set(70010);
    run_due(
        &store,
        &p,
        &registry,
        &clock,
        70010,
        &TickBudget::new(32, 32, 128, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        sink.0.lock().unwrap().len(),
        1,
        "purge-first backlog must not strand the paid terminal outcome after restart"
    );
    assert_eq!(sink.0.lock().unwrap()[0].reservation_id, "paid-read");
    assert!(
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none(),
        "acknowledging the last outcome deletes the zero backlog row"
    );
}

#[test]
fn zero_to_positive_purge_adds_one_outcome_kick_within_batch_budget() {
    let first = plan_enqueue(&request(), 10, None, None).unwrap();
    first.validate(&crate::StoreCapabilities::full()).unwrap();
    let count = |batch: &Batch, kind| {
        batch.writes.iter().filter(|w| matches!(w, crate::Write::Put(k, _) if matches!(keys::parse(k), Some(keys::ParsedKey::Timer { kind:k, .. }) if k == kind))).count()
    };
    assert_eq!(count(&first, 11), 1);
    assert_eq!(
        count(&first, 8),
        1,
        "purge owns the shared zero-to-positive delivery wake"
    );
    assert_eq!(first.preconditions.len() + first.writes.len(), 8);
    let backlog = codec::encode_backlog(&codec::Backlog {
        rows: 1,
        bytes: 512,
    });
    let next = plan_enqueue(&request(), 11, Some(&backlog), None).unwrap();
    assert_eq!(
        count(&next, 8),
        0,
        "a positive backlog retains its existing kick"
    );
}

async fn timer_rows(store: &MemoryKv, p: &Partition) -> Vec<(crate::Key, crate::Value)> {
    store
        .scan(
            p,
            &crate::Key::new(b"w\0".to_vec()),
            &crate::Key::new(b"w\x01".to_vec()),
            None,
            100,
        )
        .await
        .unwrap()
        .entries
}
fn delivery(
    sink: std::sync::Arc<OutcomeCapture>,
) -> crate::timers::outcome_delivery::OutcomeDelivery<std::sync::Arc<OutcomeCapture>> {
    crate::timers::outcome_delivery::OutcomeDelivery::new(
        sink,
        "https://server.example".into(),
        std::sync::Arc::new(crate::NoopMetrics),
        std::sync::Arc::new(crate::rt::ManualSleep::new()),
    )
}
fn purge_and_outcomes(
    sink: std::sync::Arc<OutcomeCapture>,
) -> crate::timers::TimerRegistry<'static, MemoryKv> {
    crate::timers::TimerRegistry::new()
        .register(delivery(sink))
        .register(PurgeDelivery::new(
            std::sync::Arc::new(NoLocalCache),
            None,
            SliceBudget::new(16),
        ))
}
async fn single_tick(
    store: &MemoryKv,
    p: &Partition,
    registry: &crate::timers::TimerRegistry<'_, MemoryKv>,
    now: u64,
) -> crate::timers::RunReport {
    crate::timers::run_due(
        store,
        p,
        registry,
        &crate::ManualClock::new(i64::try_from(now).unwrap()),
        now,
        &crate::timers::TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap()
}
#[tokio::test]
async fn repeated_purge_cycles_reuse_one_delayed_outcome_wake() {
    let store = MemoryKv::default();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let sink = std::sync::Arc::new(OutcomeCapture::default());
    let registry = purge_and_outcomes(sink.clone());
    let mut request = request();
    store
        .apply(&p, plan_enqueue(&request, 10, None, None).unwrap())
        .await
        .unwrap();
    let report = single_tick(&store, &p, &registry, 10).await;
    assert_eq!((report.fired, report.unknown, report.scanned), (1, 0, 1));
    let wake = timer_rows(&store, &p)
        .await
        .into_iter()
        .find(|(key, _)| {
            matches!(
                keys::parse(key),
                Some(keys::ParsedKey::Timer { kind: 8, .. })
            )
        })
        .unwrap();
    let Some(keys::ParsedKey::Timer {
        due_at_ms: wake_at, ..
    }) = keys::parse(&wake.0)
    else {
        panic!("wake")
    };
    assert!(wake_at > 25);
    for now in 20..=25 {
        let report = single_tick(&store, &p, &registry, u64::try_from(now).unwrap()).await;
        assert_eq!((report.fired, report.unknown, report.scanned), (1, 0, 1));
        let oc = store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            codec::decode_backlog(&oc).unwrap(),
            codec::Backlog::default()
        );
        assert_eq!(
            timer_rows(&store, &p).await.as_slice(),
            std::slice::from_ref(&wake)
        );
        if now < 25 {
            request.purge_id = format!("cycle-{now}");
            let generation = store
                .get(&p, &keys::cache_purge_generation(request.scope()))
                .await
                .unwrap();
            let batch = plan_enqueue(
                &request,
                u64::try_from(now + 1).unwrap(),
                Some(&oc),
                generation.as_ref(),
            )
            .unwrap();
            batch.validate(&store.capabilities()).unwrap();
            assert_eq!(batch.preconditions.len() + batch.writes.len(), 7);
            store.apply(&p, batch).await.unwrap();
            assert_eq!(
                timer_rows(&store, &p)
                    .await
                    .iter()
                    .filter(|(key, _)| matches!(
                        keys::parse(key),
                        Some(keys::ParsedKey::Timer { kind: 8, .. })
                    ))
                    .count(),
                1
            );
        }
    }
    let report = single_tick(&store, &p, &registry, wake_at).await;
    assert_eq!(report.fired, 1);
    assert!(timer_rows(&store, &p).await.is_empty());
    assert!(
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
    assert!(sink.0.lock().unwrap().is_empty());
}
#[tokio::test]
async fn stale_zero_backlog_drain_cannot_delete_new_outcome_or_its_wake() {
    use crate::store::outbox::{OutboxBuilder, Terminal};
    use crate::timers::{DueTimer, Fired, TimerCtx, TimerHandler};
    let store = MemoryKv::default();
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let key = keys::timer(10, 8, b"");
    let zero = codec::encode_backlog(&codec::Backlog::default());
    store
        .apply(
            &p,
            Batch::new()
                .put(key.clone(), Value::default())
                .put(keys::outcome_backlog(), zero.clone()),
        )
        .await
        .unwrap();
    let sink = std::sync::Arc::new(OutcomeCapture::default());
    let handler = delivery(sink.clone());
    let timer = DueTimer {
        due_at_ms: 10,
        kind: crate::timers::registry::kinds::OUTCOME_DELIVERY,
        reference: b"".as_slice().into(),
        value: Value::default(),
    };
    let Fired::Done(mut stale) = handler
        .fire(
            &TimerCtx {
                store: &store,
                partition: &p,
                now_ms: 10,
            },
            &timer,
        )
        .await
        .unwrap()
    else {
        panic!("zero drain")
    };
    stale
        .preconditions
        .push(crate::Precondition::Equals(key.clone(), Value::default()));
    stale.writes.push(crate::Write::Delete(key.clone()));
    let mut outbox = OutboxBuilder::new(None, Some(&zero)).unwrap();
    outbox.abort_direct(
        "new-outcome",
        Terminal::new(codec::ReservationV1::Aborted {
            repository: "0x1111111111111111111111111111111111111111/repo".into(),
            occurred_at_ms: 20,
            reason: codec::AbortReason::Unspecified,
            detail: String::new(),
        })
        .unwrap(),
    );
    let mut append = Batch::new();
    outbox
        .try_finish(&mut append.preconditions, &mut append.writes)
        .unwrap();
    assert!(!append.writes.iter().any(|write| matches!(write, crate::Write::Put(k, _) if matches!(keys::parse(k), Some(keys::ParsedKey::Timer {kind: 8, ..})))));
    store.apply(&p, append).await.unwrap();
    stale.validate(&store.capabilities()).unwrap();
    assert!(matches!(
        store.apply(&p, stale).await.unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    assert_eq!(timer_rows(&store, &p).await.len(), 1);
    let registry = purge_and_outcomes(sink.clone());
    let report = crate::timers::run_due(
        &store,
        &p,
        &registry,
        &crate::ManualClock::new(20),
        20,
        &crate::timers::TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    assert!(timer_rows(&store, &p).await.is_empty());
    assert!(
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn immediate_budget_is_shared_across_actions_and_reserves_parent_before_effects() {
    let parent = crate::indexed::budget::SliceBudget::new(5);
    let immediate = SliceBudget::with_parent(64, parent.clone());
    let mut effects = 0;
    for _action in 0..256 {
        if immediate.clone().charge(2) {
            effects += 1;
        }
    }
    assert_eq!(effects, 2);
    assert_eq!(parent.used(), 4);
    assert_eq!(parent.remaining(), 1);
    assert!(parent.charge_many(2).is_err());
    assert_eq!(
        parent.used(),
        4,
        "failed reservation cannot consume part of a call group"
    );
}

#[tokio::test]
async fn automatic_audit_uses_the_callers_charged_source_snapshot() {
    use std::sync::Arc;
    let source = MemoryKv::with_clock(Arc::new(crate::ManualClock::new(10)));
    let captured = Arc::new(MemoryKv::default());
    let repo = crate::RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: crate::RepoName::new("repo").unwrap(),
    };
    let p = Partition::Namespace(repo.namespace.clone());
    source
        .apply(
            &p,
            Batch::new().put(keys::outbox_sequence(), codec::encode_u64(41)),
        )
        .await
        .unwrap();
    captured
        .apply(
            &p,
            Batch::new().put(keys::outbox_sequence(), codec::encode_u64(999)),
        )
        .await
        .unwrap();
    let config = PurgeConfig::new("https://server.example".into(), false, false).with_audit(
        Arc::new(crate::admin::SystemAudit::new(captured.clone(), p.clone())),
    );
    let budget = crate::indexed::budget::SliceBudget::new(2);
    let bounded = crate::indexed::budget::Budgeted::new(&source, &budget);
    let batch = super::automatic::plan_repository(
        Some(&config),
        &bounded,
        &p,
        &repo,
        Trigger::Takedown,
        "snapshot",
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        budget.used(),
        2,
        "request lookup and one combined source snapshot"
    );
    batch.validate(&source.capabilities()).unwrap();
    assert_eq!(
        source.apply(&p, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    assert_eq!(
        codec::decode_u64(
            source
                .get(&p, &keys::outbox_sequence())
                .await
                .unwrap()
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        42
    );
    assert_eq!(
        codec::decode_u64(
            captured
                .get(&p, &keys::outbox_sequence())
                .await
                .unwrap()
                .as_ref()
                .unwrap()
        )
        .unwrap(),
        999
    );
    let exhausted = crate::indexed::budget::SliceBudget::new(1);
    let bounded = crate::indexed::budget::Budgeted::new(&source, &exhausted);
    assert!(
        super::automatic::plan_repository(
            Some(&config),
            &bounded,
            &p,
            &repo,
            Trigger::Takedown,
            "next",
            11
        )
        .await
        .is_err()
    );
    assert_eq!(exhausted.used(), 1);
}
