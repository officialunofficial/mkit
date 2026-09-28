//! D34 epoch leases over both atomic metadata backends, including paused writes.
#![cfg(all(feature = "sqlite", feature = "test-faults"))]
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use mkit_core::hash::{hash, to_hex};
use mkit_core::protocol::RefWriteCondition;
use mkit_core::repo_identity::Namespace;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authenticated, Authorizer, D34Shards,
    FaultHooks, FaultPoint, Hooks, Pipeline, PipelineConfig, RequestMeta, RevokeBudget,
    RevokeProgress, ShardMap, Sharding, TestDirectives,
};
use mkit_server::policy::{NamespacePolicy, WritePolicy};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, Cursor, Key, Partition, PartitionStats, Precondition, ScanPage,
    StoreCapabilities, StoreError, Value, Write, codec, keys,
};
use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::{
    Addressing, AuthzFacts, Code, ManualClock, MemoryBlobStore, MemoryKv, MultiAddressing,
    NamespaceStore, NoopMetrics, Operation, Procedure, RefUpdate, ServerError, UpdateRefResult,
};
use mkit_server_conformance::wire::sign::{Signer, body_commitment};
use mkit_server_native::{Blocking, RusqliteConn};
use tokio::sync::Notify;

const REF: &str = "refs/heads/a";
const AUDIENCE: &str = "http://localhost:9876";
const BODY: &[u8] = b"lease test";

fn identity() -> String {
    format!(
        "ed25519-{}/leases",
        Signer::new([1; 32], AUDIENCE, "unused").public_key_hex()
    )
}

#[derive(Clone, Debug)]
enum Call {
    Many(Partition, Vec<Key>),
    Apply(Partition, Batch, BatchOutcome),
    Other,
}

#[derive(Default)]
struct Gate {
    enabled: AtomicBool,
    entered: Notify,
    release: Notify,
}
impl Gate {
    fn arm(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    async fn pause(&self) {
        if self.enabled.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
    async fn entered(&self) {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified())
            .await
            .unwrap();
    }
    fn resume(&self) {
        self.release.notify_one();
    }
}

#[derive(Default)]
struct Controls {
    calls: Mutex<Vec<Call>>,
    push: Gate,
    ack: Gate,
    scan_clock: Mutex<Option<Arc<ManualClock>>>,
}
struct Store<N> {
    inner: Arc<N>,
    controls: Arc<Controls>,
}
impl<N> Clone for Store<N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            controls: self.controls.clone(),
        }
    }
}
impl<N> Store<N> {
    fn new(inner: N) -> Self {
        Self {
            inner: Arc::new(inner),
            controls: Arc::new(Controls::default()),
        }
    }
    fn record(&self, call: Call) {
        self.controls.calls.lock().unwrap().push(call);
    }
    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.controls.calls.lock().unwrap())
    }
}
impl<N: NamespaceStore> NamespaceStore for Store<N> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.record(Call::Other);
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, ks: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.record(Call::Many(p.clone(), ks.to_vec()));
        self.inner.get_many(p, ks).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.record(Call::Other);
        if start == &keys::class_range(keys::TAG_LEASED_SHARD).0
            && let Some(clock) = self.controls.scan_clock.lock().unwrap().as_ref()
        {
            clock.advance(10);
        }
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        if matches!(p, Partition::Ref { .. })
            && batch
                .writes
                .iter()
                .all(|w| matches!(w, Write::Put(k, _) if *k == keys::epoch_lease()))
        {
            self.controls.push.pause().await;
        }
        if matches!(p, Partition::Coordinator(_))
            && batch.writes.len() == 1
            && matches!(&batch.writes[0], Write::Put(k, _) if k.as_bytes().starts_with(b"ls\0"))
        {
            self.controls.ack.pause().await;
        }
        let outcome = self.inner.apply(p, batch.clone()).await?;
        self.record(Call::Apply(p.clone(), batch, outcome.clone()));
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.record(Call::Other);
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.record(Call::Other);
        self.inner.probe().await
    }
}

#[derive(Default)]
struct Faults {
    a: Gate,
    b: Gate,
    epochs: Mutex<Vec<Option<u64>>>,
}
struct FaultControl(Arc<Faults>);
impl FaultHooks for FaultControl {
    async fn at(
        &self,
        point: FaultPoint,
        op: &Operation,
        d: &TestDirectives,
    ) -> Result<(), ServerError> {
        if point == FaultPoint::BeforeFinalApply && d.fault.as_deref() == Some("a") {
            self.0.epochs.lock().unwrap().push(op.leased_epoch);
            self.0.a.pause().await;
        }
        if point == FaultPoint::AfterLeaseGrant && d.fault.as_deref() == Some("b") {
            self.0.b.pause().await;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Reject {
    Allow,
    Challenge,
    Deny,
}
struct Policy(Reject);
impl Authorizer for Policy {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(self.0, Reject::Deny) {
            Err(ServerError::permission_denied("test denial"))
        } else {
            Ok(AuthzFacts::default())
        }
    }
}
impl Admission for Policy {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        if matches!(self.0, Reject::Challenge) {
            Ok(AdmissionDecision::Challenge {
                challenges: vec![],
                description: "test challenge".into(),
            })
        } else {
            Ok(AdmissionDecision::allow(vec![]))
        }
    }
}
type Pipe<N> = Pipeline<MemoryBlobStore, Store<N>, Hooks<Policy, Policy>>;
fn pipeline<N: NamespaceStore>(
    store: Store<N>,
    clock: Arc<ManualClock>,
    faults: Arc<Faults>,
    rejection: Reject,
) -> Arc<Pipe<N>> {
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: Policy(rejection),
        admission: Policy(rejection),
        pre_receive: defaults.pre_receive,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let mut cfg = PipelineConfig::new(
        Addressing::Multi(MultiAddressing::new().with_namespace_policy(
            NamespacePolicy::Allowlist(
                [Namespace::parse(identity().split_once('/').unwrap().0).unwrap()].into(),
            ),
        )),
        AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, "").unwrap()),
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    );
    cfg.sharding = Sharding::D34;
    cfg.write_policy = WritePolicy::Owner;
    cfg.write_quota = None;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap());
    Arc::new(
        Pipeline::new(
            MemoryBlobStore::default(),
            store,
            hooks,
            cfg,
            clock,
            Arc::new(NoopMetrics),
        )
        .unwrap()
        .with_faults(FaultControl(faults)),
    )
}
fn auth<N: NamespaceStore>(pipe: &Pipe<N>, token: Option<&str>) -> Authenticated {
    let signer = Signer::new([1; 32], AUDIENCE, &identity());
    loop {
        let mut envelope =
            signer.envelope(Procedure::UpdateRef.connect_path(), body_commitment(BODY));
        // The scenarios use controlled clocks from 0 through 135000 ms. This
        // fixed validity window stays valid while leases and store clocks move.
        envelope.created_at = 0;
        envelope.expires_at = 240_000;
        envelope.digest = Some(to_hex(&hash(BODY)));
        let carriage = signer.sign(&envelope);
        let authenticated = pipe
            .authenticate(&RequestMeta {
                procedure: Procedure::UpdateRef,
                header: &|h| match h {
                    "x-mkit-test-fault" => token.map(str::to_owned),
                    "x-mkit-test-clock-skew-ms" if token == Some("skew") => Some("100000".into()),
                    _ => carriage
                        .headers
                        .iter()
                        .find(|(name, _)| name == h)
                        .map(|(_, value)| value.clone()),
                },
                unary_body: Some(BODY),
                transport_principal: None,
            })
            .unwrap();
        // Exclude opportunistic replay pruning from exact call-count checks.
        if !authenticated.auth.as_ref().unwrap().replay_scope[0].is_multiple_of(8) {
            return authenticated;
        }
    }
}

fn update(name: &str, byte: u8) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Any,
        new: [byte; 32],
    }
}
fn shard(a: &Authenticated, name: &str) -> Partition {
    D34Shards.ref_shard(&a.repo().repo, name)
}
fn coordinator(a: &Authenticated) -> Partition {
    D34Shards.coordinator(&a.repo().repo.namespace)
}
fn ls_key(a: &Authenticated, name: &str) -> Key {
    let Partition::Ref { shard_ref, .. } = shard(a, name) else {
        unreachable!()
    };
    keys::leased_shard(&a.repo().repo.name, &shard_ref)
}
async fn el<N: NamespaceStore>(
    store: &Store<N>,
    a: &Authenticated,
    name: &str,
) -> codec::EpochLease {
    codec::decode_epoch_lease(
        &store
            .inner
            .get(&shard(a, name), &keys::epoch_lease())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}
async fn ls<N: NamespaceStore>(
    store: &Store<N>,
    a: &Authenticated,
    name: &str,
) -> codec::LeasedShard {
    codec::decode_leased_shard(
        &store
            .inner
            .get(&coordinator(a), &ls_key(a, name))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}
async fn committed<N: NamespaceStore>(pipe: &Pipe<N>, a: &Authenticated, name: &str, byte: u8) {
    // Each logical operation has its own signed replay scope. Reusing a's
    // envelope here would turn subsequent lifecycle writes into replays.
    let fresh = auth(pipe, a.test_directives().fault.as_deref());
    assert_eq!(
        pipe.update_ref(&fresh, update(name, byte)).await.unwrap(),
        UpdateRefResult::Committed
    );
}
fn assert_cost(calls: &[Call], expected: usize) {
    assert_eq!(calls.len(), expected, "{calls:?}");
    assert!(
        matches!(&calls[0], Call::Many(Partition::Ref { .. }, ks) if ks.contains(&keys::epoch_lease()) && !ks.contains(&keys::grant_epoch()))
    );
    if expected == 5 {
        assert!(
            matches!(&calls[1], Call::Other),
            "renewal adds exactly one source watermark scan"
        );
        assert!(
            matches!(&calls[2], Call::Many(Partition::Coordinator(_), ks) if ks.len() == 5 && ks.contains(&keys::grant_epoch()) && ks.contains(&keys::lease_recovery()))
        );
        assert!(
            matches!(&calls[3], Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed) if !b.preconditions.iter().any(|p| matches!(p, Precondition::NotAfter(_))))
        );
    }
    assert!(matches!(
        calls.last(),
        Some(Call::Apply(
            Partition::Ref { .. },
            _,
            BatchOutcome::Committed
        ))
    ));
}
fn deadline(calls: &[Call]) -> u64 {
    calls
        .iter()
        .find_map(|c| match c {
            Call::Apply(Partition::Ref { .. }, b, _) => match b.preconditions.first() {
                Some(Precondition::NotAfter(d)) => Some(*d),
                _ => None,
            },
            _ => None,
        })
        .unwrap()
}
async fn lifecycle<N: NamespaceStore>(
    backend: N,
    pipeline_clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        pipeline_clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let calls = store.take();
    assert_cost(&calls, 5);
    assert_eq!(deadline(&calls), 10_000);
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 30_000);
    committed(&pipe, &a, REF, 2).await;
    assert_cost(&store.take(), 2);
    // Replay cap wins at the start; the lease cap wins late in the lease.
    pipeline_clock.set(20_000);
    store_clock.set(20_000);
    committed(&pipe, &a, REF, 3).await;
    let calls = store.take();
    assert_cost(&calls, 2);
    assert_eq!(deadline(&calls), 25_000);
    // 999 ms is insufficient for a new plan, even though the lease is live.
    pipeline_clock.set(24_001);
    store_clock.set(24_001);
    committed(&pipe, &a, REF, 4).await;
    assert_cost(&store.take(), 5);
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 54_001);
    pipeline_clock.set(54_001);
    store_clock.set(54_001);
    committed(&pipe, &a, REF, 5).await;
    assert_cost(&store.take(), 5);
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 84_001);
}

async fn rejected_existing_repo<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let original_el = el(&store, &a, REF).await;
    let original_ls = ls(&store, &a, REF).await;
    clock.set(30_000);
    store_clock.set(30_000);
    // Exercise both an unleased shard and an expired, unswept lease.
    for rejection in [Reject::Challenge, Reject::Deny] {
        let rejected = pipeline(store.clone(), clock.clone(), faults.clone(), rejection);
        for name in ["refs/heads/new", REF] {
            store.take();
            assert_eq!(
                rejected
                    .update_ref(&auth(&rejected, None), update(name, 2))
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
            let calls = store.take();
            assert_eq!(calls.len(), 3, "{calls:?}");
            assert!(matches!(
                calls.as_slice(),
                [Call::Many(..), Call::Other, Call::Many(..)]
            ));
            assert!(
                store
                    .inner
                    .get(&shard(&a, "refs/heads/new"), &keys::epoch_lease())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .inner
                    .get(&coordinator(&a), &ls_key(&a, "refs/heads/new"))
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(el(&store, &a, REF).await, original_el);
            assert_eq!(ls(&store, &a, REF).await, original_ls);
        }
    }
}

fn old_batch(old_el: codec::EpochLease) -> Batch {
    Batch::new()
        .require(Precondition::NotAfter(old_el.expires_at_ms - 5_000))
        .require(Precondition::Equals(
            keys::epoch_lease(),
            codec::encode_epoch_lease(&old_el),
        ))
        .put(Key::new(b"old-epoch-write".to_vec()), Value::default())
}
async fn renewal_counterexample<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
    cancel_b: bool,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let initial = auth(&pipe, None);
    committed(&pipe, &initial, REF, 1).await;
    let old = el(&store, &initial, REF).await;
    clock.set(23_999);
    store_clock.set(23_999);
    faults.a.arm();
    let a_auth = auth(&pipe, Some("a"));
    let a_pipe = pipe.clone();
    let a = tokio::spawn(async move { a_pipe.update_ref(&a_auth, update(REF, 2)).await });
    faults.a.entered().await;
    pipe.bump_epoch(&initial.repo().repo.namespace, 1)
        .await
        .unwrap();
    clock.set(24_501);
    store_clock.set(24_501);
    faults.b.arm();
    let b_auth = auth(&pipe, Some("b"));
    let b_pipe = pipe.clone();
    let b = tokio::spawn(async move { b_pipe.update_ref(&b_auth, update(REF, 3)).await });
    faults.b.entered().await;
    let renewed = ls(&store, &initial, REF).await;
    assert_eq!(renewed.epoch, 1);
    assert_eq!(
        renewed.acked_epoch, 0,
        "renewal cannot acknowledge an uninstalled epoch"
    );
    assert_eq!(el(&store, &initial, REF).await, old);
    if cancel_b {
        b.abort();
    }
    store.controls.push.arm();
    let revoke_pipe = pipe.clone();
    let ns = initial.repo().repo.namespace.clone();
    let revoke = tokio::spawn(async move {
        revoke_pipe
            .revoke_step(&ns, &RevokeBudget::new(10_000))
            .await
    });
    store.controls.push.entered().await;
    assert!(
        !revoke.is_finished(),
        "completion must wait for the shard installation"
    );
    assert_eq!(ls(&store, &initial, REF).await.acked_epoch, 0);
    assert_eq!(el(&store, &initial, REF).await.epoch, 0);
    store.controls.push.resume();
    assert_eq!(revoke.await.unwrap().unwrap(), RevokeProgress::Complete);
    assert_eq!(ls(&store, &initial, REF).await.acked_epoch, 1);
    assert!(matches!(
        store
            .inner
            .apply(&shard(&initial, REF), old_batch(old))
            .await
            .unwrap(),
        BatchOutcome::PreconditionFailed { .. }
    ));
    faults.a.resume();
    assert_eq!(a.await.unwrap().unwrap(), UpdateRefResult::Committed);
    assert_eq!(*faults.epochs.lock().unwrap(), vec![Some(0), Some(1)]);
    let a_key = keys::ref_key(&initial.repo().repo.name, REF);
    let calls = store.take();
    let attempts: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::Apply(Partition::Ref { .. }, batch, outcome)
                if batch
                    .writes
                    .contains(&Write::Put(a_key.clone(), Value::new(vec![2; 32]))) =>
            {
                Some(outcome)
            }
            _ => None,
        })
        .collect();
    assert!(
        matches!(
            attempts.first(),
            Some(BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. })
        ),
        "the actual old A batch must fail: {calls:?}"
    );
    assert_eq!(attempts.last(), Some(&&BatchOutcome::Committed));
    if !cancel_b {
        faults.b.resume();
        assert_eq!(b.await.unwrap().unwrap(), UpdateRefResult::Committed);
    }
    assert_eq!(el(&store, &initial, REF).await.epoch, 1);
}
async fn renewal_paused<N: NamespaceStore + 'static>(
    backend: N,
    c: Arc<ManualClock>,
    s: Arc<ManualClock>,
) {
    renewal_counterexample(backend, c, s, false).await;
}
async fn renewal_cancelled<N: NamespaceStore + 'static>(
    backend: N,
    c: Arc<ManualClock>,
    s: Arc<ManualClock>,
) {
    renewal_counterexample(backend, c, s, true).await;
}

async fn recovered_table<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    // A namespace's old creation timestamp cannot establish a recovery fence.
    store
        .inner
        .apply(
            &coordinator(&a),
            Batch::new().put(
                keys::namespace_record(),
                codec::encode_namespace_record(&codec::NamespaceRecord {
                    created_at_ms: 0,
                    config_version: 1,
                }),
            ),
        )
        .await
        .unwrap();
    clock.set(100_000);
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(1_000))
            .await
            .unwrap(),
        RevokeProgress::Complete
    );
    pipe.mark_lease_table_recovered(&a.repo().repo.namespace)
        .await
        .unwrap();
    let marker = store
        .inner
        .get(&coordinator(&a), &keys::lease_recovery())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        codec::decode_lease_recovery(&marker).unwrap().resumed_at_ms,
        100_000
    );
    for now in [100_000, 134_999] {
        clock.set(now);
        assert!(matches!(
            pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(1_000))
                .await
                .unwrap(),
            RevokeProgress::Pending { .. }
        ));
    }
    clock.set(135_000);
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(1_000))
            .await
            .unwrap(),
        RevokeProgress::Complete
    );
    assert_eq!(
        store
            .inner
            .get(&coordinator(&a), &keys::lease_recovery())
            .await
            .unwrap(),
        Some(marker)
    );
}

async fn expired_row_renewal<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let old = el(&store, &a, REF).await;
    pipe.bump_epoch(&a.repo().repo.namespace, 1).await.unwrap();
    clock.set(30_000);
    store_clock.set(30_000);
    faults.b.arm();
    let b_auth = auth(&pipe, Some("b"));
    let b_pipe = pipe.clone();
    let b = tokio::spawn(async move { b_pipe.update_ref(&b_auth, update(REF, 2)).await });
    faults.b.entered().await;
    assert_eq!(el(&store, &a, REF).await, old);
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 1);
    assert_eq!(
        store
            .inner
            .apply(&shard(&a, REF), old_batch(old))
            .await
            .unwrap(),
        BatchOutcome::DeadlinePassed {
            backend_now: 30_000
        }
    );
    faults.b.resume();
    b.await.unwrap().unwrap();
    assert_eq!(el(&store, &a, REF).await.epoch, 1);
}

async fn push_race<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    pipe.bump_epoch(&a.repo().repo.namespace, 1).await.unwrap();
    clock.set(24_501);
    store_clock.set(24_501);
    store.take();
    store.controls.push.arm();
    let p = pipe.clone();
    let ns = a.repo().repo.namespace.clone();
    let revoke = tokio::spawn(async move { p.revoke_step(&ns, &RevokeBudget::new(10_000)).await });
    store.controls.push.entered().await;
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 0);
    committed(&pipe, &a, REF, 2).await;
    assert_eq!(el(&store, &a, REF).await.epoch, 1);
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 0);
    store.controls.push.resume();
    assert_eq!(revoke.await.unwrap().unwrap(), RevokeProgress::Complete);
    let calls = store.take();
    let pushes: Vec<_> = calls
        .iter()
        .filter_map(|call| match call {
            Call::Apply(Partition::Ref { .. }, batch, outcome)
                if batch
                    .writes
                    .iter()
                    .all(|w| matches!(w, Write::Put(k, _) if *k == keys::epoch_lease())) =>
            {
                Some(outcome)
            }
            _ => None,
        })
        .collect();
    assert!(
        matches!(
            pushes.first(),
            Some(BatchOutcome::PreconditionFailed { .. })
        ),
        "{calls:?}"
    );
    assert!(
        pushes.contains(&&BatchOutcome::Committed),
        "push retry must commit before ack: {calls:?}"
    );
    let committed_push_index = calls
        .iter()
        .position(|c| {
            matches!(c,
        Call::Apply(Partition::Ref { .. }, b, BatchOutcome::Committed)
        if b.writes.iter().all(|w| matches!(w, Write::Put(k, _) if *k == keys::epoch_lease())))
        })
        .unwrap();
    let ack_index = calls
        .iter()
        .position(|c| {
            matches!(c,
        Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed)
        if b.writes.iter().any(|w| matches!(w, Write::Put(k, v)
            if *k == ls_key(&a, REF) && codec::decode_leased_shard(v).unwrap().acked_epoch == 1)))
        })
        .unwrap();
    assert!(
        committed_push_index < ack_index,
        "ack cannot precede a committed push"
    );
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 1);
    assert_eq!(
        el(&store, &a, REF).await.expires_at_ms,
        ls(&store, &a, REF).await.expires_at_ms
    );
}

async fn absent_el_and_budget<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    let names: Vec<_> = (0..6).map(|i| format!("refs/heads/{i}")).collect();
    for name in &names {
        committed(&pipe, &a, name, 1).await;
    }
    // A cancelled first write may leave a coordinator grant with no shard copy.
    store
        .inner
        .apply(
            &shard(&a, &names[0]),
            Batch::new().delete(keys::epoch_lease()),
        )
        .await
        .unwrap();
    // Mark that row unacknowledged so a bump must install even an absent el.
    pipe.bump_epoch(&a.repo().repo.namespace, 1).await.unwrap();
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(10_000))
            .await
            .unwrap(),
        RevokeProgress::Pending { remaining: 2 }
    );
    assert_eq!(el(&store, &a, &names[0]).await.epoch, 1);
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(10_000))
            .await
            .unwrap(),
        RevokeProgress::Complete
    );
    for name in &names {
        assert_eq!(ls(&store, &a, name).await.acked_epoch, 1);
    }
    pipe.bump_epoch(&a.repo().repo.namespace, 2).await.unwrap();
    clock.set(30_000);
    store_clock.set(30_000);
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(10_000))
            .await
            .unwrap(),
        RevokeProgress::Complete
    );
    for invalid in [2, 1, 1_027] {
        assert_eq!(
            pipe.bump_epoch(&a.repo().repo.namespace, invalid)
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
}

async fn sweep<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    use mkit_server::timers::{lease_sweep::LeaseSweep, registry::kinds};
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let reference = [
        a.repo().repo.name.as_str().as_bytes(),
        b"\0",
        REF.as_bytes(),
    ]
    .concat();
    let old_timer = keys::timer(30_000, kinds::LEASE_SWEEP.get(), &reference);
    assert!(
        store
            .inner
            .get(&coordinator(&a), &old_timer)
            .await
            .unwrap()
            .is_some()
    );
    let mut prior = ls(&store, &a, REF).await;
    prior.relay_watermark_ms = 60_000;
    store
        .apply(
            &coordinator(&a),
            Batch::new().put(ls_key(&a, REF), codec::encode_leased_shard(&prior)),
        )
        .await
        .unwrap();
    clock.set(24_501);
    store_clock.set(24_501);
    store.take();
    committed(&pipe, &a, REF, 2).await;
    assert_eq!(
        ls(&store, &a, REF).await.relay_watermark_ms,
        60_000,
        "a lower renewal report cannot lower the running maximum"
    );
    let new_timer = keys::timer(54_501, kinds::LEASE_SWEEP.get(), &reference);
    let calls = store.take();
    let moved = calls.iter().any(|c| matches!(c, Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed)
        if b.writes.contains(&Write::Delete(old_timer.clone())) && b.writes.iter().any(|w| matches!(w, Write::Put(k, _) if *k == new_timer))));
    assert!(moved, "timer move must share the lease grant batch");
    assert!(calls.iter().any(|c| matches!(c, Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed)
        if b.writes.contains(&Write::Delete(old_timer.clone())) && b.writes.len() == 3 && b.preconditions.len() == 4)),
        "renewal still uses four guards and three writes");
    let renewal_ref_ops = calls
        .iter()
        .find_map(|c| match c {
            Call::Apply(Partition::Ref { .. }, b, BatchOutcome::Committed) => {
                Some((b.preconditions.len(), b.writes.len()))
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        renewal_ref_ops,
        (4, 4),
        "the ref batch keeps its lease installation and three other writes"
    );
    assert!(
        store
            .inner
            .get(&coordinator(&a), &old_timer)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(&coordinator(&a), &new_timer)
            .await
            .unwrap()
            .is_some()
    );
    clock.set(54_501);
    store_clock.set(54_501);
    let report = run_due(
        &store,
        &coordinator(&a),
        &TimerRegistry::new().register(LeaseSweep::new(store.clone())),
        clock.as_ref(),
        54_501,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(
        store
            .inner
            .get(&coordinator(&a), &ls_key(&a, REF))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(&coordinator(&a), &new_timer)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn expired_lease_is_kept_until_source_outbox_drains() {
    use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
    use mkit_server::timers::{
        lease_sweep::{LeaseSweep, lease_reference},
        registry::kinds,
    };

    let clock = Arc::new(ManualClock::new(100));
    let store = Store::new(MemoryKv::with_clock(clock.clone()));
    let ns = mkit_server::NamespaceKey::deployment_default();
    let repo = mkit_server::RepoName::new("kept").unwrap();
    let shard_ref = "refs/heads/main";
    let source = Partition::Ref {
        ns: ns.clone(),
        repo: repo.clone(),
        shard_ref: shard_ref.into(),
    };
    let coordinator = Partition::Coordinator(ns);
    let ls_key = keys::leased_shard(&repo, shard_ref);
    let timer100 = keys::timer(
        100,
        kinds::LEASE_SWEEP.get(),
        &lease_reference(&repo, shard_ref),
    );
    let timer10100 = keys::timer(
        10_100,
        kinds::LEASE_SWEEP.get(),
        &lease_reference(&repo, shard_ref),
    );
    let lease = codec::LeasedShard {
        epoch: 1,
        expires_at_ms: 100,
        acked_epoch: 1,
        relay_watermark_ms: 0,
        sweep_due_ms: 100,
    };
    let relay = codec::RelayV1 {
        at_ms: 90,
        target: coordinator.clone(),
        puts: vec![(Key::new(&b"x\0"[..]), Value::default())],
    };
    store
        .apply(
            &source,
            Batch::new()
                .put(keys::relay(1), codec::encode_relay(&relay).unwrap())
                .put(keys::outbox_sequence(), codec::encode_u64(1))
                .put(keys::timer(100, kinds::RELAY.get(), b""), Value::default())
                .put(Key::new(&b"tdr\0"[..]), codec::encode_u64(10_100)),
        )
        .await
        .unwrap();
    store
        .apply(
            &coordinator,
            Batch::new()
                .put(ls_key.clone(), codec::encode_leased_shard(&lease))
                .put(timer100, Value::default()),
        )
        .await
        .unwrap();
    let relay_registry = TimerRegistry::new().register(RelayHandler {
        target: store.clone(),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    let delayed = run_due(
        &store,
        &source,
        &relay_registry,
        clock.as_ref(),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(delayed.fired, 1);
    assert!(
        store.get(&source, &keys::relay(1)).await.unwrap().is_some(),
        "relay-delay fault must retain the outbox"
    );
    let registry = TimerRegistry::new().register(LeaseSweep::new(store.clone()));
    let report = run_due(
        &store,
        &coordinator,
        &registry,
        clock.as_ref(),
        100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    let kept =
        codec::decode_leased_shard(&store.get(&coordinator, &ls_key).await.unwrap().unwrap())
            .unwrap();
    assert_eq!(kept.relay_watermark_ms, 89);
    assert_eq!(kept.sweep_due_ms, 10_100);
    assert!(
        store
            .get(&coordinator, &timer10100)
            .await
            .unwrap()
            .is_some()
    );
    clock.set(10_100);
    let drained = run_due(
        &store,
        &source,
        &relay_registry,
        clock.as_ref(),
        10_100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(drained.fired, 1);
    assert!(store.get(&source, &keys::relay(1)).await.unwrap().is_none());
    let report = run_due(
        &store,
        &coordinator,
        &registry,
        clock.as_ref(),
        10_100,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(store.get(&coordinator, &ls_key).await.unwrap().is_none());
}

#[tokio::test]
async fn revocation_completes_with_expired_kept_row() {
    use mkit_server::timers::lease_sweep::LeaseSweep;

    let clock = Arc::new(ManualClock::new(0));
    let store_clock = Arc::new(ManualClock::new(0));
    let store = Store::new(MemoryKv::with_clock(store_clock.clone()));
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let source = shard(&a, REF);
    let relay = codec::RelayV1 {
        at_ms: 1,
        target: coordinator(&a),
        puts: vec![(Key::new(&b"x\0"[..]), Value::default())],
    };
    store
        .apply(
            &source,
            Batch::new().put(keys::relay(1), codec::encode_relay(&relay).unwrap()),
        )
        .await
        .unwrap();
    clock.set(30_000);
    store_clock.set(30_000);
    let report = run_due(
        &store,
        &coordinator(&a),
        &TimerRegistry::new().register(LeaseSweep::new(store.clone())),
        clock.as_ref(),
        30_000,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(
        store
            .get(&coordinator(&a), &ls_key(&a, REF))
            .await
            .unwrap()
            .is_some()
    );
    pipe.bump_epoch(&a.repo().repo.namespace, 1).await.unwrap();
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::default())
            .await
            .unwrap(),
        RevokeProgress::Complete
    );
    clock.set(30_001);
    store_clock.set(30_001);
    committed(&pipe, &a, REF, 2).await;
    let (start, end) = keys::class_range(keys::TAG_TIMER);
    let timers = store
        .scan(&coordinator(&a), &start, &end, None, 20)
        .await
        .unwrap();
    let sweeps = timers.entries.iter().filter(|(key, _)| matches!(keys::parse(key), Some(keys::ParsedKey::Timer { kind, .. }) if kind == mkit_server::timers::registry::kinds::LEASE_SWEEP.get())).count();
    assert_eq!(
        sweeps, 1,
        "renewal must remove the kept row's prior sweep timer"
    );
}

async fn clocks_are_separate<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let skewed = auth(&pipe, Some("skew"));
    committed(&pipe, &skewed, REF, 1).await;
    assert_eq!(deadline(&store.take()), 10_000);
    assert_eq!(el(&store, &skewed, REF).await.expires_at_ms, 30_000);
    clock.set(1_000);
    faults.a.arm();
    let a_auth = auth(&pipe, Some("a"));
    let a_pipe = pipe.clone();
    let a = tokio::spawn(async move { a_pipe.update_ref(&a_auth, update(REF, 2)).await });
    faults.a.entered().await;
    // Only the backend clock advances past the planned deadline. A retry
    // gets one further attempt; a still-stale pipeline clock cannot commit it.
    store_clock.set(11_001);
    store.take();
    faults.a.resume();
    assert_eq!(a.await.unwrap().unwrap_err().code(), Code::Unavailable);
    let misses = store
        .take()
        .iter()
        .filter(|c| {
            matches!(
                c,
                Call::Apply(
                    _,
                    _,
                    BatchOutcome::DeadlinePassed {
                        backend_now: 11_001
                    }
                )
            )
        })
        .count();
    assert_eq!(misses, 2);
}

async fn elapsed_budget_makes_progress<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    let names: Vec<_> = (0..9).map(|i| format!("refs/heads/{i:02}")).collect();
    for name in &names {
        committed(&pipe, &a, name, 1).await;
    }
    pipe.bump_epoch(&a.repo().repo.namespace, 1).await.unwrap();
    // Simulate the already-committed push+ack prefix. Only the suffix needs
    // work; restarting every slice at the prefix would starve it forever.
    for name in &names[..8] {
        let mut installed = el(&store, &a, name).await;
        installed.epoch = 1;
        store
            .inner
            .apply(
                &shard(&a, name),
                Batch::new().put(keys::epoch_lease(), codec::encode_epoch_lease(&installed)),
            )
            .await
            .unwrap();
        let mut acknowledged = ls(&store, &a, name).await;
        acknowledged.acked_epoch = 1;
        store
            .inner
            .apply(
                &coordinator(&a),
                Batch::new().put(ls_key(&a, name), codec::encode_leased_shard(&acknowledged)),
            )
            .await
            .unwrap();
    }
    *store.controls.scan_clock.lock().unwrap() = Some(clock.clone());
    let mut complete = false;
    for _ in 0..10 {
        if pipe
            .revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(15))
            .await
            .unwrap()
            == RevokeProgress::Complete
        {
            complete = true;
            break;
        }
    }
    assert!(
        complete,
        "bounded slices must eventually reach the unacknowledged suffix"
    );
    assert_eq!(ls(&store, &a, &names[8]).await.acked_epoch, 1);
    assert_eq!(el(&store, &a, &names[8]).await.epoch, 1);
}

macro_rules! backends {
    ($memory:ident, $sqlite:ident, $scenario:ident) => {
        #[tokio::test]
        async fn $memory() {
            let pipeline_clock = Arc::new(ManualClock::new(0));
            let store_clock = Arc::new(ManualClock::new(0));
            $scenario(
                MemoryKv::with_clock(store_clock.clone()),
                pipeline_clock,
                store_clock,
            )
            .await;
        }
        #[tokio::test]
        async fn $sqlite() {
            let pipeline_clock = Arc::new(ManualClock::new(0));
            let store_clock = Arc::new(ManualClock::new(0));
            let dir = tempfile::tempdir().unwrap();
            let conn = RusqliteConn::open(dir.path().join("meta.sqlite3"))
                .unwrap()
                .with_clock(store_clock.clone());
            $scenario(
                Blocking::new(SqlKvStore::open(conn).unwrap()),
                pipeline_clock,
                store_clock,
            )
            .await;
        }
    };
}
backends!(lifecycle_memory, lifecycle_sqlite, lifecycle);
backends!(
    rejected_existing_memory,
    rejected_existing_sqlite,
    rejected_existing_repo
);
backends!(renewal_paused_memory, renewal_paused_sqlite, renewal_paused);
backends!(
    renewal_cancelled_memory,
    renewal_cancelled_sqlite,
    renewal_cancelled
);
backends!(
    recovered_table_memory,
    recovered_table_sqlite,
    recovered_table
);
backends!(expired_row_memory, expired_row_sqlite, expired_row_renewal);
backends!(push_race_memory, push_race_sqlite, push_race);
backends!(
    absent_el_and_budget_memory,
    absent_el_and_budget_sqlite,
    absent_el_and_budget
);
backends!(sweep_memory, sweep_sqlite, sweep);

backends!(
    clocks_are_separate_memory,
    clocks_are_separate_sqlite,
    clocks_are_separate
);

backends!(
    elapsed_budget_progress_memory,
    elapsed_budget_progress_sqlite,
    elapsed_budget_makes_progress
);

/// Renewal must make a previously planned coordinator ack fail its exact ls
/// guard, preserving the extended lease for the next epoch's revocation.
async fn renewal_between_push_and_ack<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let ns = a.repo().repo.namespace.clone();
    pipe.bump_epoch(&ns, 1).await.unwrap();
    clock.set(24_500);
    store_clock.set(24_500);
    store.controls.ack.arm();
    let p = pipe.clone();
    let revoke_ns = ns.clone();
    let revoke =
        tokio::spawn(async move { p.revoke_step(&revoke_ns, &RevokeBudget::new(10_000)).await });
    store.controls.ack.entered().await;
    assert_eq!(el(&store, &a, REF).await.epoch, 1);
    committed(&pipe, &a, REF, 2).await;
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 54_500);
    store.controls.ack.resume();
    assert_eq!(revoke.await.unwrap().unwrap(), RevokeProgress::Complete);
    let row = ls(&store, &a, REF).await;
    let copy = el(&store, &a, REF).await;
    assert_eq!(
        row.expires_at_ms, 54_500,
        "a stale ack must not restore the earlier expiry"
    );
    assert_eq!(row.acked_epoch, 1);
    pipe.bump_epoch(&ns, 2).await.unwrap();
    clock.set(30_000);
    store_clock.set(30_000);
    let mut done = false;
    for _ in 0..5 {
        let progress = pipe
            .revoke_step(&ns, &RevokeBudget::new(10_000))
            .await
            .unwrap();
        if progress == RevokeProgress::Complete {
            assert_eq!(
                el(&store, &a, REF).await.epoch,
                2,
                "cannot complete while a usable epoch-1 lease remains"
            );
            done = true;
            break;
        }
    }
    assert!(done);
    let outcome = store
        .inner
        .apply(&shard(&a, REF), old_batch(copy))
        .await
        .unwrap();
    assert!(
        matches!(
            outcome,
            BatchOutcome::PreconditionFailed { .. } | BatchOutcome::DeadlinePassed { .. }
        ),
        "epoch-1 write committed after epoch-2 Complete: ls={row:?} el={copy:?} {outcome:?}"
    );
}
backends!(
    renewal_between_push_ack_memory,
    renewal_between_push_ack_sqlite,
    renewal_between_push_and_ack
);

/// Sweep on its own clock, then renew on a pipeline clock lagging behind it.
async fn swept_lease_renewal<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
    renewal_now_ms: i64,
) {
    use mkit_server::timers::lease_sweep::LeaseSweep;
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let old = el(&store, &a, REF).await;
    assert_eq!(old.expires_at_ms, 30_000);

    clock.set(renewal_now_ms);
    store_clock.set(30_000);
    let sweep_clock = ManualClock::new(30_000);
    let report = run_due(
        &store,
        &coordinator(&a),
        &TimerRegistry::new().register(LeaseSweep::new(store.clone())),
        &sweep_clock,
        30_000,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(
        store
            .inner
            .get(&coordinator(&a), &ls_key(&a, REF))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(el(&store, &a, REF).await, old);
    assert_eq!(
        store
            .inner
            .apply(&shard(&a, REF), old_batch(old))
            .await
            .unwrap(),
        BatchOutcome::DeadlinePassed {
            backend_now: 30_000
        }
    );
    committed(&pipe, &a, REF, 2).await;
    let expected_expiry = u64::try_from(renewal_now_ms).unwrap() + 30_000;
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, expected_expiry);
    assert_eq!(ls(&store, &a, REF).await.expires_at_ms, expected_expiry);
}

/// One millisecond of skew is below the configured 5000 margin. Renewal must
/// commit to expiry 59999 even though the old raw expiry is ahead of its clock.
async fn normal_sweep_clock_skew<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    swept_lease_renewal(backend, clock, store_clock, 29_999).await;
}
backends!(
    normal_sweep_clock_skew_memory,
    normal_sweep_clock_skew_sqlite,
    normal_sweep_clock_skew
);

#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(
    expected = "an observed el outlives every ls it could have been granted under, beyond the skew margin"
)]
async fn excessive_sweep_clock_skew_panics_memory() {
    let pipeline_clock = Arc::new(ManualClock::new(0));
    let store_clock = Arc::new(ManualClock::new(0));
    // Sweep/backend 30000 minus pipeline 24999 exceeds margin5000 by one.
    swept_lease_renewal(
        MemoryKv::with_clock(store_clock.clone()),
        pipeline_clock,
        store_clock,
        24_999,
    )
    .await;
}

#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(
    expected = "an observed el outlives every ls it could have been granted under, beyond the skew margin"
)]
async fn excessive_sweep_clock_skew_panics_sqlite() {
    let pipeline_clock = Arc::new(ManualClock::new(0));
    let store_clock = Arc::new(ManualClock::new(0));
    let dir = tempfile::tempdir().unwrap();
    let conn = RusqliteConn::open(dir.path().join("meta.sqlite3"))
        .unwrap()
        .with_clock(store_clock.clone());
    swept_lease_renewal(
        Blocking::new(SqlKvStore::open(conn).unwrap()),
        pipeline_clock,
        store_clock,
        24_999,
    )
    .await;
}

/// Declared table loss can leave a live shard copy ahead of missing ls rows.
/// The recovery hold-off fences completion while renewal installs a new copy.
async fn recovered_loss_then_renew<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 30_000);
    assert_eq!(
        store
            .inner
            .apply(&coordinator(&a), Batch::new().delete(ls_key(&a, REF)))
            .await
            .unwrap(),
        BatchOutcome::Committed,
    );
    pipe.mark_lease_table_recovered(&a.repo().repo.namespace)
        .await
        .unwrap();
    clock.set(24_500);
    store_clock.set(24_500);
    store.take();
    committed(&pipe, &a, REF, 2).await;
    let calls = store.take();
    assert_eq!(calls.len(), 5, "{calls:?}");
    assert_eq!(el(&store, &a, REF).await.expires_at_ms, 54_500);
    assert_eq!(ls(&store, &a, REF).await.expires_at_ms, 54_500);
    assert_eq!(
        pipe.revoke_step(&a.repo().repo.namespace, &RevokeBudget::new(10_000))
            .await
            .unwrap(),
        RevokeProgress::Pending { remaining: 1 },
    );
}
backends!(
    recovered_loss_renewal_memory,
    recovered_loss_renewal_sqlite,
    recovered_loss_then_renew
);
