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
        run_due(
            &store,
            &p,
            &registry,
            &clock,
            now as u64,
            &TickBudget::new(1, 1, 16, 1000),
        )
        .await
        .unwrap();
        assert!(budget.used() <= 2);
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
