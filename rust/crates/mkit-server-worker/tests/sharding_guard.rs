//! Deployment marker checks through the real Worker wire and simulated DOs.
mod common;

use std::sync::{Arc, Mutex};

use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::Sharding;
use mkit_server::store::keys;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, NamespaceKey, NamespaceStore, Partition, PartitionStats,
    ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_worker::naming::do_target;
use mkit_server_worker::ns_client::DoNamespaceStore;
use mkit_server_worker::sharding_guard::DeploymentGuard;

fn root() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}
fn mode(value: &str) -> Value {
    Value::new(value.as_bytes().to_vec())
}
fn store(dir: &tempfile::TempDir) -> DoNamespaceStore<Loopback> {
    Loopback::store(dir.path().to_path_buf(), DoConfig::default())
}

#[test]
fn empty_d34_root_records_mode_and_later_single_isolate_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let first = DeploymentGuard::default();
    block_on(first.check(store.clone(), Sharding::D34, None)).unwrap();
    assert_eq!(store.transport().calls(), 3);
    block_on(first.check(store.clone(), Sharding::D34, None)).unwrap();
    assert_eq!(
        store.transport().calls(),
        3,
        "cached success costs no calls"
    );
    assert_eq!(
        block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
        Some(mode("d34"))
    );
    let later = DeploymentGuard::default();
    let before = store.transport().calls();
    let error = block_on(later.check(store.clone(), Sharding::Single, None)).unwrap_err();
    assert!(error.0.contains("configured=single stored=d34"));
    block_on(later.check(store.clone(), Sharding::Single, None)).unwrap_err();
    assert_eq!(
        store.transport().calls() - before,
        1,
        "cached refusal costs no calls"
    );
}

#[test]
fn unmarked_single_ref_data_refuses_d34_and_records_single() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let repo = mkit_server::RepoName::new("default").unwrap();
    block_on(store.apply(
        &root(),
        Batch::new().put(
            keys::ref_key(&repo, "refs/heads/main"),
            Value::new(vec![1; 32]),
        ),
    ))
    .unwrap();
    let before = store.transport().calls();
    let error =
        block_on(DeploymentGuard::default().check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert!(error.0.contains("configured=d34 stored=single"));
    assert_eq!(store.transport().calls() - before, 2);
    assert_eq!(
        block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
        None
    );
    let before = store.transport().calls();
    block_on(DeploymentGuard::default().check(store.clone(), Sharding::Single, None)).unwrap();
    assert_eq!(store.transport().calls() - before, 3);
    assert_eq!(
        block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
        Some(mode("single"))
    );
}

#[test]
fn empty_single_root_records_single() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    block_on(DeploymentGuard::default().check(store.clone(), Sharding::Single, None)).unwrap();
    assert_eq!(store.transport().calls(), 3);
    assert_eq!(
        block_on(store.get(&root(), &keys::sharding_marker())).unwrap(),
        Some(mode("single"))
    );
}

#[test]
fn overlapping_requests_share_the_in_flight_check() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    let (a, b) = block_on(futures::future::join(
        guard.check(store.clone(), Sharding::D34, None),
        guard.check(store.clone(), Sharding::D34, None),
    ));
    a.unwrap();
    b.unwrap();
    assert_eq!(store.transport().calls(), 3);
}

/// Two isolates overlap between the loser's scan and conditional apply. The
/// winning isolate's real guard writes the marker. After the failed check we
/// mutate it directly in the simulated database to prove the loser compares the
/// apply observation, rather than re-reading a later value.
#[derive(Clone)]
struct Racing {
    store: DoNamespaceStore<Loopback>,
    winner: Sharding,
    corrupt_observation: bool,
    winner_at_scan: bool,
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl Racing {
    fn record(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
}

impl NamespaceStore for Racing {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.record("get");
        self.store.get(p, key).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.record("scan");
        if self.winner_at_scan {
            DeploymentGuard::default()
                .check(self.store.clone(), self.winner, None)
                .await
                .unwrap();
        }
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.record("apply");
        DeploymentGuard::default()
            .check(self.store.clone(), self.winner, None)
            .await
            .unwrap();
        let outcome = self.store.apply(p, batch).await?;
        assert!(matches!(
            outcome,
            BatchOutcome::PreconditionFailed {
                index: 0,
                observed: Some(_)
            }
        ));
        let later = if self.winner == Sharding::D34 {
            "single"
        } else {
            "d34"
        };
        self.store
            .transport()
            .raw_apply(
                &do_target(p)?,
                p,
                Batch::new().put(keys::sharding_marker(), mode(later)),
            )
            .await;
        if self.corrupt_observation {
            Ok(BatchOutcome::PreconditionFailed {
                index: 0,
                observed: None,
            })
        } else {
            Ok(outcome)
        }
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.record("stats");
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.record("probe");
        self.store.probe().await
    }
}

#[test]
fn absent_race_uses_atomic_observation_in_exactly_three_calls() {
    for winner in [Sharding::D34, Sharding::Single] {
        let dir = tempfile::tempdir().unwrap();
        let racing = Racing {
            store: store(&dir),
            winner,
            corrupt_observation: false,
            winner_at_scan: false,
            calls: Arc::default(),
        };
        let guard = DeploymentGuard::default();
        let result = block_on(guard.check(racing.clone(), Sharding::D34, None));
        assert_eq!(result.is_ok(), winner == Sharding::D34);
        assert_eq!(*racing.calls.lock().unwrap(), ["get", "scan", "apply"]);
        assert_eq!(
            racing.store.transport().calls(),
            6,
            "three DO calls per isolate, including the winner"
        );
        let _ = block_on(guard.check(racing.clone(), Sharding::D34, None));
        assert_eq!(racing.calls.lock().unwrap().len(), 3);
    }
}

#[test]
fn failed_absent_without_observed_value_refuses_as_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let racing = Racing {
        store: store(&dir),
        winner: Sharding::D34,
        corrupt_observation: true,
        winner_at_scan: false,
        calls: Arc::default(),
    };
    let error = block_on(DeploymentGuard::default().check(racing.clone(), Sharding::D34, None))
        .unwrap_err();
    assert!(error.0.contains("corrupt reply"));
    assert!(error.0.contains("failed Absent has no observed value"));
    assert_eq!(*racing.calls.lock().unwrap(), ["get", "scan", "apply"]);
    assert_eq!(racing.store.transport().calls(), 6);
}

#[test]
fn full_range_detects_a_key_at_the_maximum_valid_byte_value() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    block_on(store.apply(
        &root(),
        Batch::new().put(
            Key::new(vec![0xff; mkit_server::MAX_KEY_BYTES]),
            mode("data"),
        ),
    ))
    .unwrap();
    block_on(DeploymentGuard::default().check(store, Sharding::D34, None)).unwrap_err();
}

#[test]
fn marker_installed_between_get_and_scan_is_compared_as_a_marker() {
    let dir = tempfile::tempdir().unwrap();
    let racing = Racing {
        store: store(&dir),
        winner: Sharding::D34,
        corrupt_observation: false,
        winner_at_scan: true,
        calls: Arc::default(),
    };
    block_on(DeploymentGuard::default().check(racing.clone(), Sharding::D34, None)).unwrap();
    assert_eq!(*racing.calls.lock().unwrap(), ["get", "scan"]);
    assert_eq!(
        racing.store.transport().calls(),
        5,
        "winner uses three calls; loser uses two"
    );
}

#[test]
fn reused_isolate_refuses_changed_mode_after_completed_check() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    block_on(guard.check(store.clone(), Sharding::Single, None)).unwrap();
    let error = block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert!(error.0.contains("configured=d34 isolate=single"));
    assert_eq!(store.transport().calls(), 3);
}

#[test]
fn reused_isolate_refuses_changed_mode_during_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    let initial = guard.check(store.clone(), Sharding::Single, None);
    block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert_eq!(store.transport().calls(), 0);
    block_on(initial).unwrap();
    assert_eq!(store.transport().calls(), 3);
}

#[test]
fn reused_isolate_refuses_jurisdiction_changes_without_another_store_call() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    block_on(guard.check(store.clone(), Sharding::D34, Some("eu".into()))).unwrap();
    block_on(guard.check(store.clone(), Sharding::D34, Some("us".into()))).unwrap_err();
    block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert_eq!(store.transport().calls(), 3);
}
