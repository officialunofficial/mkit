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
    run_due(
        &store,
        &p,
        &registry,
        &clock,
        10,
        &TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
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
    run_due(
        &store,
        &p,
        &registry,
        &clock,
        2010,
        &TickBudget::new(1, 1, 16, 1000),
    )
    .await
    .unwrap();
    assert_eq!(
        read_request(&store, &p, &request.purge_id).await.unwrap(),
        None
    );
    assert!(
        store
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
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
