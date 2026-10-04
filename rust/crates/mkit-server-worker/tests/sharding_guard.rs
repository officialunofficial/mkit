//! Deployment marker checks through the real Worker wire and simulated DOs.
mod common;

use std::sync::{Arc, Mutex};

use common::{DoConfig, Loopback};
use futures::executor::block_on;
use mkit_server::pipeline::Sharding;
use mkit_server::store::adapter_spi::keys;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, NamespaceKey, NamespaceStore, Partition, PartitionStats,
    ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_worker::naming::do_target;
use mkit_server_worker::ns_client::DoNamespaceStore;
use mkit_server_worker::sharding_guard::{
    GuardError, Outcome, Settled, check_addressing, check_mode,
};

// Same cache operations as the adapter; each returned future belongs to its
// caller and the RefCell holds only the settled data defined by the library.
#[derive(Default)]
struct DeploymentGuard(std::cell::RefCell<Option<Settled>>);
impl DeploymentGuard {
    /// The sharding check only, keyed like the adapter's guarded step.
    async fn check<S: NamespaceStore>(
        &self,
        store: S,
        mode: Sharding,
        jurisdiction: Option<&str>,
    ) -> Result<(), GuardError> {
        if let Some(outcome) = Settled::cached(&self.0, mode, false, jurisdiction) {
            return outcome.into_result();
        }
        let result = check_mode(&store, mode).await;
        Settled::finish(&self.0, mode, false, jurisdiction, result)
    }

    /// The adapter's whole guarded step: sharding then addressing.
    async fn check_all<S: NamespaceStore>(
        &self,
        store: S,
        mode: Sharding,
        multi: bool,
    ) -> Result<(), GuardError> {
        if let Some(outcome) = Settled::cached(&self.0, mode, multi, None) {
            return outcome.into_result();
        }
        let result = match check_mode(&store, mode).await {
            Ok(Outcome::Ok) => check_addressing(&store, multi).await,
            settled => settled,
        };
        Settled::finish(&self.0, mode, multi, None, result)
    }
}

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
    assert!(error.to_string().contains("configured=single stored=d34"));
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
    assert!(error.to_string().contains("configured=d34 stored=single"));
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

/// Yield after each observation so both request handles see an empty root
/// before either conditional write. No synchronization future is shared.
#[derive(Clone)]
struct Interleaved {
    store: DoNamespaceStore<Loopback>,
    committed: Arc<std::sync::atomic::AtomicUsize>,
    observed: Arc<std::sync::atomic::AtomicUsize>,
    fail_get: Arc<std::sync::atomic::AtomicBool>,
}
impl Interleaved {
    fn new(store: DoNamespaceStore<Loopback>) -> Self {
        Self {
            store,
            committed: Arc::default(),
            observed: Arc::default(),
            fail_get: Arc::default(),
        }
    }
}
async fn yield_once() {
    let mut yielded = false;
    futures::future::poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}
impl NamespaceStore for Interleaved {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        if self
            .fail_get
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::unavailable(std::io::Error::other(
                "temporary outage",
            )));
        }
        let result = self.store.get(p, key).await;
        yield_once().await;
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
        let result = self.store.scan(p, start, end, after, limit).await;
        yield_once().await;
        result
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let result = self.store.apply(p, batch).await?;
        match &result {
            BatchOutcome::Committed => {
                self.committed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            BatchOutcome::PreconditionFailed {
                observed: Some(value),
                ..
            } => {
                assert!(value == &mode("d34") || value == &mode("single"));
                self.observed
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        Ok(result)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}
#[test]
fn overlapping_requests_own_their_checks_and_compare_atomic_observed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interleaved::new(store(&dir));
    let guard = DeploymentGuard::default();
    let (a, b) = block_on(futures::future::join(
        guard.check(store.clone(), Sharding::D34, None),
        guard.check(store.clone(), Sharding::D34, None),
    ));
    a.unwrap();
    b.unwrap();
    assert_eq!(
        store.store.transport().calls(),
        6,
        "each request owns get, scan, apply"
    );
    assert_eq!(store.committed.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(store.observed.load(std::sync::atomic::Ordering::SeqCst), 1);
    block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap();
    assert_eq!(
        store.store.transport().calls(),
        6,
        "settled success costs zero calls"
    );
}
#[test]
fn transient_storage_error_is_not_cached() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interleaved::new(store(&dir));
    store
        .fail_get
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let guard = DeploymentGuard::default();
    let error = block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert_eq!(error.public_message(), "deployment storage unavailable");
    assert!(
        guard.0.borrow().is_none(),
        "storage errors never settle the cache"
    );
    block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap();
    assert_eq!(store.store.transport().calls(), 3);
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
        self.calls.lock().expect("call trace lock").push(name);
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
            assert_eq!(
                check_mode(&self.store, self.winner)
                    .await
                    .expect("winning isolate initializes its marker"),
                Outcome::Ok
            );
        }
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.record("apply");
        assert_eq!(
            check_mode(&self.store, self.winner)
                .await
                .expect("winning isolate initializes its marker"),
            Outcome::Ok
        );
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
            "three DO calls per request, including the winner"
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
    assert_eq!(error.public_message(), "deployment sharding marker corrupt");
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
fn reused_isolate_rechecks_changed_mode_after_completed_check() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    block_on(guard.check(store.clone(), Sharding::Single, None)).unwrap();
    let error = block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert!(error.to_string().contains("configured=d34 stored=single"));
    assert_eq!(
        store.transport().calls(),
        4,
        "changed config reads the marker again"
    );
}

#[test]
fn reused_isolate_checks_each_config_while_requests_are_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interleaved::new(store(&dir));
    let guard = DeploymentGuard::default();
    let (single, d34) = block_on(futures::future::join(
        guard.check(store.clone(), Sharding::Single, None),
        guard.check(store.clone(), Sharding::D34, None),
    ));
    single.unwrap();
    assert_eq!(
        d34.unwrap_err().public_message(),
        "deployment sharding mismatch"
    );
    assert_eq!(store.store.transport().calls(), 6);
    block_on(guard.check(store.clone(), Sharding::D34, None)).unwrap_err();
    assert_eq!(
        store.store.transport().calls(),
        7,
        "old config's settled value is dropped"
    );
}

#[test]
fn reused_isolate_rechecks_jurisdiction_with_the_new_store_handle() {
    let eu = tempfile::tempdir().unwrap();
    let us = tempfile::tempdir().unwrap();
    let eu = store(&eu);
    let us = store(&us);
    let guard = DeploymentGuard::default();
    block_on(guard.check(eu.clone(), Sharding::D34, Some("eu"))).unwrap();
    block_on(guard.check(us.clone(), Sharding::Single, Some("us"))).unwrap();
    assert_eq!(
        us.transport().calls(),
        3,
        "new jurisdiction maps to empty objects"
    );
    block_on(guard.check(eu.clone(), Sharding::Single, Some("eu"))).unwrap_err();
    assert_eq!(
        eu.transport().calls(),
        4,
        "original jurisdiction's marker is authoritative"
    );
}

#[test]
fn every_definitive_outcome_is_cached_and_has_its_public_message() {
    for (bytes, sharding, expected) in [
        (b"d34".to_vec(), Sharding::D34, None),
        (
            b"single".to_vec(),
            Sharding::D34,
            Some("deployment sharding mismatch"),
        ),
        (
            vec![0xff],
            Sharding::Single,
            Some("deployment sharding marker corrupt"),
        ),
        (
            b"unknown".to_vec(),
            Sharding::D34,
            Some("deployment sharding marker corrupt"),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        block_on(store.apply(
            &root(),
            Batch::new().put(keys::sharding_marker(), Value::new(bytes)),
        ))
        .unwrap();
        let before = store.transport().calls();
        let guard = DeploymentGuard::default();
        for _ in 0..2 {
            let result = block_on(guard.check(store.clone(), sharding, None));
            assert_eq!(result.err().map(|error| error.public_message()), expected);
        }
        assert_eq!(store.transport().calls() - before, 1);
    }
    assert_eq!(
        Outcome::Corrupt.into_result().unwrap_err().public_message(),
        "deployment sharding marker corrupt"
    );
}

#[test]
fn old_config_completion_does_not_replace_newer_settled_config() {
    let eu = tempfile::tempdir().unwrap();
    let us = tempfile::tempdir().unwrap();
    let eu = Interleaved::new(store(&eu));
    let us = store(&us);
    let guard = DeploymentGuard::default();
    block_on(async {
        let old = guard.check(eu.clone(), Sharding::D34, Some("eu"));
        futures::pin_mut!(old);
        assert!(futures::poll!(&mut old).is_pending());
        guard
            .check(us.clone(), Sharding::Single, Some("us"))
            .await
            .unwrap();
        old.await.unwrap();
        guard
            .check(us.clone(), Sharding::Single, Some("us"))
            .await
            .unwrap();
    });
    assert_eq!(
        us.transport().calls(),
        3,
        "new config remains settled after old completion"
    );
    assert_eq!(eu.store.transport().calls(), 3);
}

#[test]
fn fresh_roots_record_the_configured_addressing() {
    for (multi, expected) in [(false, "single"), (true, "multi")] {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        assert_eq!(
            block_on(check_addressing(&store, multi)).unwrap(),
            Outcome::Ok
        );
        assert_eq!(
            block_on(store.get(&root(), &keys::addressing_marker())).unwrap(),
            Some(mode(expected))
        );
    }
}

#[test]
fn housekeeping_rows_are_not_unmarked_data() {
    // The object writes `bk`, `w` and `sm` before or without a commit;
    // they do not establish addressing on a fresh store.
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    block_on(
        store.apply(
            &root(),
            Batch::new()
                .put(keys::backup_state(), Value::new(vec![1]))
                .put(keys::timer(1, 1, b"x"), Value::default())
                .put(keys::sharding_marker(), mode("single")),
        ),
    )
    .unwrap();
    assert_eq!(
        block_on(check_addressing(&store, true)).unwrap(),
        Outcome::Ok
    );
    assert_eq!(
        block_on(store.get(&root(), &keys::addressing_marker())).unwrap(),
        Some(mode("multi"))
    );
}

#[test]
fn stored_addressing_refuses_the_other_mode() {
    for (stored, multi) in [(false, true), (true, false)] {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        block_on(check_addressing(&store, stored)).unwrap();
        let before = store.transport().calls();
        let error =
            block_on(DeploymentGuard::default().check_all(store.clone(), Sharding::Single, multi))
                .unwrap_err();
        assert_eq!(error.public_message(), "deployment addressing mismatch");
        let (configured, stored) = if multi {
            ("multi", "single")
        } else {
            ("single", "multi")
        };
        assert!(
            error
                .to_string()
                .contains(&format!("configured={configured} stored={stored}"))
        );
        assert_eq!(
            store.transport().calls() - before,
            4,
            "fresh sharding check (3 calls) then the addressing get"
        );
    }
}

#[test]
fn populated_root_without_addressing_marker_refuses_both_modes() {
    for multi in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        let repo = mkit_server::RepoName::new("default").unwrap();
        block_on(
            store.apply(
                &root(),
                Batch::new()
                    .put(
                        keys::ref_key(&repo, "refs/heads/main"),
                        Value::new(vec![1; 32]),
                    )
                    .put(keys::layout_version(), Value::default()),
            ),
        )
        .unwrap();
        assert_eq!(
            block_on(check_addressing(&store, multi)).unwrap(),
            Outcome::AddressingCorrupt
        );
        assert_eq!(
            block_on(store.get(&root(), &keys::addressing_marker())).unwrap(),
            None
        );
    }
}

#[test]
fn corrupt_addressing_marker_refuses() {
    for bytes in [vec![0xff], b"unknown".to_vec()] {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir);
        block_on(store.apply(
            &root(),
            Batch::new().put(keys::addressing_marker(), Value::new(bytes)),
        ))
        .unwrap();
        let error = block_on(DeploymentGuard::default().check_all(store, Sharding::Single, false))
            .unwrap_err();
        assert_eq!(
            error.public_message(),
            "deployment addressing marker corrupt"
        );
    }
}

#[test]
fn settled_cache_is_keyed_by_addressing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir);
    let guard = DeploymentGuard::default();
    block_on(guard.check_all(store.clone(), Sharding::Single, false)).unwrap();
    let before = store.transport().calls();
    block_on(guard.check_all(store.clone(), Sharding::Single, false)).unwrap();
    assert_eq!(
        store.transport().calls() - before,
        0,
        "same addressing settles"
    );
    let error = block_on(guard.check_all(store.clone(), Sharding::Single, true)).unwrap_err();
    assert_eq!(
        error.public_message(),
        "deployment addressing mismatch",
        "a changed addressing re-runs and refuses"
    );
}

#[test]
fn canceled_cold_request_leaves_no_cached_request_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Interleaved::new(store(&dir));
    let guard = DeploymentGuard::default();
    block_on(async {
        {
            let canceled = guard.check(store.clone(), Sharding::D34, None);
            futures::pin_mut!(canceled);
            assert!(futures::poll!(&mut canceled).is_pending());
        }
        assert!(guard.0.borrow().is_none());
        guard
            .check(store.clone(), Sharding::D34, None)
            .await
            .unwrap();
    });
    assert_eq!(
        store.store.transport().calls(),
        4,
        "one canceled get and three new request calls"
    );
}

/// A root acquires a layout row after the addressing read and before its apply.
struct LayoutRace {
    store: mkit_server::MemoryKv,
    layout: Value,
}
impl NamespaceStore for LayoutRace {
    fn capabilities(&self) -> StoreCapabilities {
        self.store.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
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
        self.store.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.store
            .apply(
                p,
                Batch::new().put(keys::layout_version(), self.layout.clone()),
            )
            .await?;
        self.store.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.store.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.store.probe().await
    }
}

#[test]
fn addressing_bootstrap_refuses_a_racing_layout_row_even_with_marker_like_bytes() {
    for multi in [false, true] {
        for layout in [
            Value::new(1u32.to_be_bytes().to_vec()),
            mode("single"),
            mode("multi"),
        ] {
            let store = LayoutRace {
                store: mkit_server::MemoryKv::default(),
                layout,
            };
            assert_eq!(
                block_on(check_addressing(&store, multi)).unwrap(),
                Outcome::AddressingCorrupt
            );
            assert_eq!(
                block_on(store.get(&root(), &keys::addressing_marker())).unwrap(),
                None
            );
        }
    }
}
