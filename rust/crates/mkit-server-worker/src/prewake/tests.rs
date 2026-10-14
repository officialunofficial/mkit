use super::*;
use crate::naming::DoTarget;
use crate::wire::{NsCall, NsRequest};
use futures::executor::block_on;
use mkit_server::{Key, NamespaceKey, RepoName, StoreError};
use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Default)]
struct Transport {
    active: Arc<AtomicU32>,
    peak: Arc<AtomicU32>,
    targets: Arc<Mutex<Vec<String>>>,
    fail: bool,
    hang: bool,
}
struct Active(Arc<AtomicU32>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl NsTransport for Transport {
    async fn call(
        &self,
        target: &DoTarget,
        op: &'static str,
        body: String,
    ) -> Result<String, StoreError> {
        let request: NsRequest = serde_json::from_str(&body).unwrap();
        if op != "ping" {
            return Ok(r#"{"reply":"value","value":null}"#.into());
        }
        assert_eq!(request.call, NsCall::Ping);
        self.targets.lock().unwrap().push(target.name.clone());
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        let _active = Active(self.active.clone());
        let mut pending = true;
        futures::future::poll_fn(|cx| {
            if self.hang {
                std::task::Poll::Pending
            } else if pending {
                pending = false;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        if self.fail {
            Err(StoreError::unavailable("injected ping failure"))
        } else {
            Ok(serde_json::to_string(&crate::wire::NsReply::Ok).unwrap())
        }
    }
}
fn repo(name: &str) -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(name).unwrap(),
    }
}
fn store(transport: Transport, budget: u32) -> DoNamespaceStore<Transport> {
    DoNamespaceStore::new(
        transport,
        Partition::Coordinator(NamespaceKey::deployment_default()),
    )
    .with_budget(SliceBudget::new(budget))
}
fn hint(recent: Recent) -> Prewake {
    Prewake {
        ttl_ms: 90_000,
        recent,
        allowance: SliceBudget::new(CALLS),
    }
}

#[test]
fn wave_is_width_sixteen_joined_and_recent_across_requests() {
    let transport = Transport::default();
    let store = store(transport.clone(), 9000);
    let recent = Recent::default();
    let first = hint(recent.clone());
    let second = hint(recent.clone());
    block_on(futures::future::join(
        first.run(&store, &repo("wave")),
        second.run(&store, &repo("wave")),
    ));
    assert_eq!(transport.active.load(Ordering::SeqCst), 0);
    assert_eq!(transport.peak.load(Ordering::SeqCst), CALLS);
    let targets = transport.targets.lock().unwrap();
    assert_eq!(targets.len(), CALLS as usize);
    assert_eq!(
        targets
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        CALLS as usize
    );
    assert_eq!(first.allowance.used() + second.allowance.used(), CALLS);
    assert_eq!(store.read_call_allowance(), Some(8984));
    drop(targets);
    block_on(hint(recent).run(&store, &repo("wave")));
    assert_eq!(transport.targets.lock().unwrap().len(), CALLS as usize);
}

#[test]
fn tight_budget_and_exhausted_allowance_skip_without_charging() {
    let transport = Transport::default();
    let store = store(transport.clone(), 15);
    let prewake = hint(Recent::default());
    block_on(prewake.run(&store, &repo("tight")));
    assert_eq!(prewake.allowance.used(), 0);
    assert_eq!(store.read_call_allowance(), Some(15));
    assert!(prewake.recent.lock().unwrap().is_empty());
    assert!(transport.targets.lock().unwrap().is_empty());
    let p = Partition::Coordinator(NamespaceKey::deployment_default());
    // The same ordinary read succeeds after the skipped wave.
    assert!(
        block_on(store.get(&p, &Key::new(b"key".to_vec())))
            .unwrap()
            .is_none()
    );
    let exhausted = hint(Recent::default());
    exhausted.allowance.charge_many(CALLS).unwrap();
    assert!(!exhausted.claim(&repo("allowance"), 0, None));
}

#[test]
fn failures_are_suppressed_and_retries_are_rate_bounded() {
    let transport = Transport {
        fail: true,
        ..Transport::default()
    };
    let store = store(transport.clone(), 9000);
    let recent = Recent::default();
    block_on(hint(recent.clone()).run(&store, &repo("failure")));
    block_on(hint(recent).run(&store, &repo("failure")));
    assert_eq!(transport.targets.lock().unwrap().len(), CALLS as usize);
    assert_eq!(transport.active.load(Ordering::SeqCst), 0);
    assert_eq!(store.read_call_allowance(), Some(8984));
    let p = Partition::Coordinator(NamespaceKey::deployment_default());
    assert!(
        block_on(store.get(&p, &Key::new(b"key".to_vec())))
            .unwrap()
            .is_none()
    );
}

#[test]
fn ttl_expiry_capacity_and_cancellation_claims_are_bounded() {
    let recent = Recent::default();
    assert!(hint(recent.clone()).claim(&repo("expiry"), 100, None));
    assert!(!hint(recent.clone()).claim(&repo("expiry"), 90_099, None));
    assert!(hint(recent.clone()).claim(&repo("expiry"), 90_100, None));
    // Full live caches skip new keys without evicting existing claims.
    for i in 1..MAX_REPOSITORIES {
        recent
            .lock()
            .unwrap()
            .insert(repo(&format!("r{i}")), 180_100);
    }
    assert!(!hint(recent.clone()).claim(&repo("full"), 90_101, None));
    assert!(!hint(recent.clone()).claim(&repo("expiry"), 90_101, None));
    assert!(hint(recent).claim(&repo("full"), 180_100, None));
}

#[test]
fn configuration_defaults_off_and_bounds_ttl() {
    assert_eq!(parse(&|_| None).unwrap(), None);
    assert_eq!(
        parse(&|key| (key == "REPO_INDEX_PREWAKE").then(|| "true".into())).unwrap(),
        Some(90_000)
    );
    for bad in ["0", "121", "-1", "invalid"] {
        assert!(
            parse(&|key| (key == "REPO_INDEX_PREWAKE_TTL_SECONDS").then(|| bad.into())).is_err()
        );
    }
}

#[test]
fn cancelled_wave_is_not_detached_and_retains_its_claim() {
    use std::future::Future as _;
    let transport = Transport::default();
    let store = store(transport.clone(), 9000);
    let recent = Recent::default();
    let prewake = hint(recent.clone());
    let repository = repo("cancel");
    let mut wave = Box::pin(prewake.run(&store, &repository));
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    assert!(wave.as_mut().poll(&mut cx).is_pending());
    assert_eq!(transport.active.load(Ordering::SeqCst), CALLS);
    drop(wave);
    assert_eq!(transport.active.load(Ordering::SeqCst), 0);
    block_on(hint(recent).run(&store, &repository));
    assert_eq!(transport.targets.lock().unwrap().len(), CALLS as usize);
    assert_eq!(store.read_call_allowance(), Some(8984));
}

struct NoData;
impl NamespaceStore for NoData {
    fn capabilities(&self) -> mkit_server::StoreCapabilities {
        panic!("ping does not probe capabilities")
    }
    async fn get(&self, _: &Partition, _: &Key) -> Result<Option<mkit_server::Value>, StoreError> {
        panic!("ping does not read rows")
    }
    async fn scan(
        &self,
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&mkit_server::Cursor>,
        _: u32,
    ) -> Result<mkit_server::ScanPage, StoreError> {
        panic!("ping does not scan rows")
    }
    async fn apply(
        &self,
        _: &Partition,
        _: mkit_server::Batch,
    ) -> Result<mkit_server::BatchOutcome, StoreError> {
        panic!("ping does not mutate rows")
    }
    async fn stats(&self, _: &Partition) -> Result<mkit_server::PartitionStats, StoreError> {
        panic!("ping does not read stats")
    }
    async fn probe(&self) -> Result<(), StoreError> {
        panic!("ping does not probe data")
    }
}
#[test]
fn ping_dispatch_uses_no_application_data_and_validates_partition_class() {
    let p = Partition::RepoIndex {
        ns: NamespaceKey::deployment_default(),
        repo: RepoName::new("ping").unwrap(),
        prefix: 0,
    };
    let body = serde_json::to_string(&NsRequest::new(&p, NsCall::Ping).unwrap()).unwrap();
    let good: crate::wire::NsReply = serde_json::from_str(&block_on(crate::ns_object::serve(
        &NoData,
        &body,
        crate::classes::ShardClass::RepoIndexShard,
    )))
    .unwrap();
    assert_eq!(good, crate::wire::NsReply::Ok);
    let bad: crate::wire::NsReply = serde_json::from_str(&block_on(crate::ns_object::serve(
        &NoData,
        &body,
        crate::classes::ShardClass::ContentIndexShard,
    )))
    .unwrap();
    assert!(matches!(bad, crate::wire::NsReply::Err { .. }));
}

#[test]
fn timed_out_wave_is_suppressed_cancels_calls_and_retains_claim() {
    use std::future::Future as _;
    let transport = Transport {
        hang: true,
        ..Transport::default()
    };
    let store = store(transport.clone(), 9000);
    let recent = Recent::default();
    let prewake = hint(recent.clone());
    let repository = repo("timeout");
    let sleep = mkit_server::ManualSleep::new();
    let mut wave = Box::pin(finish_wave(&sleep, prewake.run(&store, &repository)));
    let mut cx = std::task::Context::from_waker(futures::task::noop_waker_ref());
    assert!(wave.as_mut().poll(&mut cx).is_pending());
    assert_eq!(transport.active.load(Ordering::SeqCst), CALLS);
    assert_eq!(sleep.requested(), vec![std::time::Duration::from_secs(1)]);
    sleep.fire();
    block_on(wave);
    assert_eq!(transport.active.load(Ordering::SeqCst), 0);
    block_on(hint(recent).run(&store, &repository));
    assert_eq!(transport.targets.lock().unwrap().len(), CALLS as usize);
    assert_eq!(store.read_call_allowance(), Some(8984));
    let p = Partition::Coordinator(NamespaceKey::deployment_default());
    assert!(
        block_on(store.get(&p, &Key::new(b"key".to_vec())))
            .unwrap()
            .is_none()
    );
}

#[test]
fn configured_store_hook_shares_recent_claims_and_off_is_noop() {
    let transport = Transport::default();
    let repository = repo("configured-cache");
    let first = store(transport.clone(), 9000).with_index_prewake(Some(90_000));
    block_on(first.prepare_repo_read(&repository));
    let second = store(transport.clone(), 9000).with_index_prewake(Some(90_000));
    block_on(second.prepare_repo_read(&repository));
    let off = store(transport.clone(), 9000).with_index_prewake(None);
    block_on(off.prepare_repo_read(&repo("configured-off")));
    assert_eq!(transport.targets.lock().unwrap().len(), CALLS as usize);
    assert_eq!(first.read_call_allowance(), Some(8984));
    assert_eq!(second.read_call_allowance(), Some(9000));
    assert_eq!(off.read_call_allowance(), Some(9000));
}
