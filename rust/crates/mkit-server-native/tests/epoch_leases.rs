//! D34 epoch leases over both atomic metadata backends, including paused writes.
#![cfg(all(feature = "sqlite", feature = "test-faults"))]
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use mkit_attest::grant::{
    AcceptedSchemes, Capabilities, EpochStatement, Grant, OwnerScheme, RefScopes, RepoScope,
    RepositoryIdentity, SignedHeader,
};
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
    Addressing, AuthzFacts, Code, GrantConfig, ManualClock, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceStore, NoopMetrics, Operation, Procedure, RefUpdate, ServerError,
    UpdateRefResult,
};
use mkit_server_conformance::wire::sign::{Signer, body_commitment};
use mkit_server_native::{Blocking, RusqliteConn};
use proptest::prelude::*;
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
    fail_push_once: AtomicBool,
    push_conflict: AtomicBool,
    epoch_race_once: Mutex<Option<u64>>,
    epoch_after_cas_once: Mutex<Option<u64>>,
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
        if matches!(p, Partition::Coordinator(_))
            && batch
                .writes
                .iter()
                .any(|write| matches!(write, Write::Put(key, _) if *key == keys::grant_epoch()))
        {
            let raced = self.controls.epoch_race_once.lock().unwrap().take();
            if let Some(epoch) = raced {
                self.inner
                    .apply(
                        p,
                        Batch::new().put(keys::grant_epoch(), codec::encode_u64(epoch)),
                    )
                    .await?;
            }
        }
        if matches!(p, Partition::Ref { .. })
            && batch
                .writes
                .iter()
                .all(|w| matches!(w, Write::Put(k, _) if *k == keys::epoch_lease()))
        {
            if self.controls.push_conflict.load(Ordering::SeqCst) {
                let outcome = BatchOutcome::PreconditionFailed {
                    index: 0,
                    observed: None,
                };
                self.record(Call::Apply(p.clone(), batch, outcome.clone()));
                return Ok(outcome);
            }
            if self.controls.fail_push_once.swap(false, Ordering::SeqCst) {
                return Err(StoreError::unavailable(std::io::Error::other(
                    "injected epoch push failure",
                )));
            }
            self.controls.push.pause().await;
        }
        if matches!(p, Partition::Coordinator(_))
            && batch.writes.len() == 1
            && matches!(&batch.writes[0], Write::Put(k, _) if k.as_bytes().starts_with(b"ls\0"))
        {
            self.controls.ack.pause().await;
        }
        let outcome = self.inner.apply(p, batch.clone()).await?;
        if matches!(p, Partition::Coordinator(_))
            && outcome == BatchOutcome::Committed
            && batch
                .writes
                .iter()
                .any(|write| matches!(write, Write::Put(key, _) if *key == keys::grant_epoch()))
        {
            let raced = self.controls.epoch_after_cas_once.lock().unwrap().take();
            if let Some(epoch) = raced {
                self.inner
                    .apply(
                        p,
                        Batch::new().put(keys::grant_epoch(), codec::encode_u64(epoch)),
                    )
                    .await?;
            }
        }
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
    c: Gate,
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
        if point == FaultPoint::AfterAuthorize && d.fault.as_deref() == Some("c") {
            self.0.c.pause().await;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Reject {
    Allow,
    Reserved,
    Challenge,
    Deny,
    Authority(Option<u64>),
    UnfencedAuthority(Option<u64>),
}
struct Policy(Reject);
impl Authorizer for Policy {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        if matches!(self.0, Reject::Deny) {
            Err(ServerError::permission_denied("test denial"))
        } else {
            let mut facts = AuthzFacts::default();
            facts.authority_generation = match self.0 {
                Reject::Authority(generation) | Reject::UnfencedAuthority(generation) => generation,
                _ => None,
            };
            Ok(facts)
        }
    }
}
impl Admission for Policy {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        if matches!(self.0, Reject::Challenge) {
            Ok(AdmissionDecision::challenge(
                vec![mkit_server::pipeline::Challenge {
                    scheme: "mpp".into(),
                    value: "pay".into(),
                }],
                "test challenge",
            ))
        } else {
            let allowed = AdmissionDecision::allow(vec![]);
            Ok(if matches!(self.0, Reject::Authority(_)) {
                allowed.with_reservation(input.idempotency_key.unwrap())
            } else if matches!(self.0, Reject::Reserved) {
                allowed.with_reservation("epoch-race")
            } else {
                allowed
            })
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
    pipeline_with_uploads(
        store,
        clock,
        faults,
        rejection,
        MemoryBlobStore::default(),
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    )
}
fn pipeline_with_uploads<N: NamespaceStore>(
    store: Store<N>,
    clock: Arc<ManualClock>,
    faults: Arc<Faults>,
    rejection: Reject,
    blobs: MemoryBlobStore,
    limits: UploadLimits,
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
        limits,
    );
    cfg.sharding = Sharding::D34;
    cfg.write_policy = WritePolicy::Owner;
    cfg.grants = Some(
        GrantConfig::new_allowing_loopback(
            AUDIENCE,
            AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
            vec![],
        )
        .unwrap(),
    );
    if matches!(
        rejection,
        Reject::Authority(_) | Reject::UnfencedAuthority(_)
    ) {
        cfg.authorizer_role = mkit_server::policy::AuthorizerRole::Authority;
    }
    if matches!(rejection, Reject::Authority(_)) {
        cfg.authority_fence = Some(
            mkit_server::authority::AuthorityFence::parse(&format!(
                "deployment {} {}",
                Signer::new([7; 32], AUDIENCE, "unused").public_key_hex(),
                identity().split_once('/').unwrap().0
            ))
            .unwrap(),
        );
    }
    cfg.write_quota = None;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap());
    Arc::new(
        Pipeline::new(blobs, store, hooks, cfg, clock, Arc::new(NoopMetrics))
            .unwrap()
            .with_faults(FaultControl(faults)),
    )
}
fn auth<N: NamespaceStore>(pipe: &Pipe<N>, token: Option<&str>) -> Authenticated {
    auth_as(pipe, token, [1; 32], None)
}

fn auth_as<N: NamespaceStore>(
    pipe: &Pipe<N>,
    token: Option<&str>,
    seed: [u8; 32],
    grant: Option<&str>,
) -> Authenticated {
    auth_for(pipe, token, seed, grant, Procedure::UpdateRef)
}

fn auth_for<N: NamespaceStore>(
    pipe: &Pipe<N>,
    token: Option<&str>,
    seed: [u8; 32],
    grant: Option<&str>,
    procedure: Procedure,
) -> Authenticated {
    let signer = Signer::new(seed, AUDIENCE, &identity());
    loop {
        let mut envelope = signer.envelope(procedure.connect_path(), body_commitment(BODY));
        // The scenarios use controlled clocks from 0 through 135000 ms. This
        // fixed validity window stays valid while leases and store clocks move.
        envelope.created_at = 0;
        envelope.expires_at = 240_000;
        envelope.digest = Some(to_hex(&hash(BODY)));
        let carriage = signer.sign(&envelope);
        let authenticated = pipe
            .authenticate(&RequestMeta {
                procedure,
                header: &|h| match h {
                    "x-mkit-test-fault" => token.map(str::to_owned),
                    "x-mkit-test-clock-skew-ms" if token == Some("skew") => Some("100000".into()),
                    "x-write-grant" => grant.map(str::to_owned),
                    _ => carriage
                        .headers
                        .iter()
                        .find(|(name, _)| name == h)
                        .map(|(_, value)| value.clone()),
                },
                header_values: None,
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

fn owner() -> Signer {
    Signer::new([1; 32], AUDIENCE, &identity())
}

fn signed_grant(epoch: u64) -> String {
    let statement = Grant {
        namespace: Namespace::parse(identity().split_once('/').unwrap().0).unwrap(),
        scope: RepoScope::Repository(RepositoryIdentity::parse(&identity()).unwrap()),
        grantee: mkit_core::hash::from_hex(
            &Signer::new([2; 32], AUDIENCE, &identity()).public_key_hex(),
        )
        .unwrap(),
        capabilities: Capabilities::Write,
        audiences: vec![AUDIENCE.into()],
        ref_scopes: Some(RefScopes::parse("refs/heads/*=cufd").unwrap()),
        epoch,
        created_ms: 0,
        expiry_ms: 240_000,
        nonce: hash(format!("grant-{epoch}").as_bytes()),
    }
    .encode()
    .unwrap();
    SignedHeader {
        statement: statement.clone(),
        scheme: OwnerScheme::Ed25519,
        blob: owner().sign_grant_statement(&statement).to_vec(),
    }
    .encode()
    .unwrap()
}

fn signed_epoch(new_epoch: u64) -> String {
    let statement = EpochStatement {
        namespace: Namespace::parse(identity().split_once('/').unwrap().0).unwrap(),
        new_epoch,
        audiences: vec![AUDIENCE.into()],
        created_ms: 0,
        expiry_ms: 240_000,
        nonce: hash(format!("epoch-{new_epoch}").as_bytes()),
    }
    .encode()
    .unwrap();
    SignedHeader {
        statement: statement.clone(),
        scheme: OwnerScheme::Ed25519,
        blob: owner().sign_grant_statement(&statement).to_vec(),
    }
    .encode()
    .unwrap()
}

fn granted_auth<N: NamespaceStore>(
    pipe: &Pipe<N>,
    token: Option<&str>,
    epoch: u64,
) -> Authenticated {
    let grant = signed_grant(epoch);
    auth_as(pipe, token, [2; 32], Some(&grant))
}

fn update(name: &str, byte: u8) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Any,
        new: Some([byte; 32]),
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

async fn finish_bounded_revoke<N: NamespaceStore + 'static>(
    pipe: &Pipe<N>,
    ns: &mkit_server::NamespaceKey,
) {
    for _ in 0..4 {
        if pipe
            .revoke_step(ns, &RevokeBudget::new(10_000))
            .await
            .unwrap()
            == RevokeProgress::Complete
        {
            return;
        }
    }
    panic!("revocation did not complete within four additional bounded slices");
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
    assert_eq!(
        revoke.await.unwrap().unwrap(),
        RevokeProgress::Pending { remaining: 1 }
    );
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 0);
    finish_bounded_revoke(&pipe, &a.repo().repo.namespace).await;
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

fn assert_renewal_ops(calls: &[Call], old_timer: &Key, new_timer: &Key) {
    let moved = calls.iter().any(|c| matches!(c, Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed)
        if b.writes.contains(&Write::Delete((*old_timer).clone())) && b.writes.iter().any(|w| matches!(w, Write::Put(k, _) if k == new_timer))));
    assert!(moved, "timer move must share the lease grant batch");
    assert!(calls.iter().any(|c| matches!(c, Call::Apply(Partition::Coordinator(_), b, BatchOutcome::Committed)
        if b.writes.contains(&Write::Delete((*old_timer).clone())) && b.writes.len() == 3 && b.preconditions.len() == 5
            && b.preconditions.contains(&Precondition::Absent(keys::lease_recovery())))),
        "renewal uses five guards including raw recovery mode and three writes");
    assert!(calls.iter().any(|c| matches!(c,
        Call::Many(Partition::Coordinator(_), keys) if keys.len() == 5 && keys.contains(&keys::lease_recovery())
    )), "renewal preserves the five-row coordinator read");
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
        (5, 7),
        "the ref batch keeps its lease installation and adds the index relay"
    );
}

#[allow(clippy::too_many_lines)] // One lease lifecycle across write, renewal, relay drain and sweep.
async fn sweep<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
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
    assert_renewal_ops(&calls, &old_timer, &new_timer);
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
    // The two D34 writes left index rows. Drain them so this sweep tests
    // renewal and expiry rather than the outbox hold-off.
    let source = shard(&a, REF);
    let relay_registry = TimerRegistry::new().register(RelayHandler {
        target: store.clone(),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    for _ in 0..3 {
        if store
            .inner
            .get(&source, &keys::relay(1))
            .await
            .unwrap()
            .is_none()
            && store
                .inner
                .get(&source, &keys::relay(2))
                .await
                .unwrap()
                .is_none()
        {
            break;
        }
        run_due(
            &store,
            &source,
            &relay_registry,
            clock.as_ref(),
            24_501,
            &TickBudget::default(),
        )
        .await
        .unwrap();
    }
    assert!(
        store
            .inner
            .get(&source, &keys::relay(1))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(&source, &keys::relay(2))
            .await
            .unwrap()
            .is_none()
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
async fn corrupt_relay_row_does_not_block_lease_renewal() {
    let clock = Arc::new(ManualClock::new(1_000));
    let store = Store::new(MemoryKv::with_clock(clock.clone()));
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Allow,
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    assert_eq!(ls(&store, &a, REF).await.relay_watermark_ms, 1_000);

    clock.set(1_100);
    store
        .apply(
            &shard(&a, REF),
            Batch::new().put(keys::relay(1), Value::new(&b"corrupt relay"[..])),
        )
        .await
        .unwrap();
    clock.set(26_000);
    committed(&pipe, &a, REF, 2).await;
    assert_eq!(ls(&store, &a, REF).await.relay_watermark_ms, 1_000);
    let watermark =
        mkit_server::store::watermark::namespace_relay_watermark(&store, &coordinator(&a), 26_000)
            .await
            .unwrap();
    assert!(watermark < 1_100, "corrupt undelivered row is held");
}

const MODEL_REFS: [&str; 3] = ["refs/heads/a", "refs/heads/b", "refs/heads/c"];

async fn append_model_relay(
    store: &Store<MemoryKv>,
    a: &Authenticated,
    name: &str,
    seq: u64,
    at_ms: u64,
    commit_ms: u64,
) {
    use mkit_server::timers::registry::kinds;

    let source = shard(a, name);
    let lease_value = store
        .get(&source, &keys::epoch_lease())
        .await
        .unwrap()
        .unwrap();
    let lease = codec::decode_epoch_lease(&lease_value).unwrap();
    let row = codec::RelayV1 {
        at_ms,
        target: coordinator(a),
        puts: vec![(Key::new(&b"x\0"[..]), codec::encode_u64(seq))],
        deletes: Vec::new(),
    };
    let batch = Batch::new()
        .require(Precondition::Equals(keys::epoch_lease(), lease_value))
        .require(Precondition::NotAfter(lease.expires_at_ms - 5_000))
        .put(keys::relay(seq), codec::encode_relay(&row).unwrap())
        .put(keys::outbox_sequence(), codec::encode_u64(seq))
        .put(
            keys::timer(commit_ms, kinds::RELAY.get(), b""),
            Value::default(),
        );
    assert_eq!(
        store.apply(&source, batch).await.unwrap(),
        BatchOutcome::Committed
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn real_relay_lease_interleavings_bound_undelivered_commits(
        actions in prop::collection::vec((0u8..5, 0u8..3, 1u8..8), 25..70)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
            use mkit_server::store::watermark::namespace_relay_watermark;
            use mkit_server::timers::lease_sweep::LeaseSweep;

            let clock = Arc::new(ManualClock::new(100));
            let store = Store::new(MemoryKv::with_clock(clock.clone()));
            let pipe = pipeline(store.clone(), clock.clone(), Arc::new(Faults::default()), Reject::Allow);
            let a = auth(&pipe, None);
            let mut now = 101u64;
            let mut next_seq = [0u64; 3];
            let mut undelivered = Vec::<(usize, u64, u64)>::new();

            // Invariant: every undelivered relay row committed after report r
            // has commit time >= r. A later row may carry a stale at_ms.
            committed(&pipe, &a, MODEL_REFS[0], 1).await;
            let r = ls(&store, &a, MODEL_REFS[0]).await.relay_watermark_ms;
            prop_assert_eq!(r, 100);
            clock.set(101);
            next_seq[0] = 1;
            append_model_relay(&store, &a, MODEL_REFS[0], 1, 50, now).await;
            undelivered.push((0, 1, now));
            prop_assert!(now >= r, "commit time must follow the prior report");
            now = ls(&store, &a, MODEL_REFS[0]).await.expires_at_ms + 1;
            clock.set(i64::try_from(now).unwrap());
            let sweep = TimerRegistry::new().register(LeaseSweep::new(store.clone()));
            let swept = run_due(&store, &coordinator(&a), &sweep, clock.as_ref(), now, &TickBudget::default()).await.unwrap();
            prop_assert!(swept.fired > 0, "the real lease sweep must fire on an undelivered row");
            committed(&pipe, &a, MODEL_REFS[0], 2).await;
            prop_assert_eq!(ls(&store, &a, MODEL_REFS[0]).await.relay_watermark_ms, r,
                "a stale lower source report cannot erase the running maximum");

            for (index, (action, shard_index, step)) in actions.into_iter().enumerate() {
                now += u64::from(step);
                clock.set(i64::try_from(now).unwrap());
                let n = usize::from(shard_index);
                let name = MODEL_REFS[n];
                let source = shard(&a, name);
                let key = ls_key(&a, name);
                let before = store.get(&coordinator(&a), &key).await.unwrap()
                    .map(|v| codec::decode_leased_shard(&v).unwrap());
                match action {
                    0 => {
                        committed(&pipe, &a, name, u8::try_from(index % 250 + 3).unwrap()).await;
                        next_seq[n] += 1;
                        let seq = next_seq[n];
                        append_model_relay(&store, &a, name, seq, now.saturating_sub(u64::from(step) + 1), now).await;
                        undelivered.push((n, seq, now));
                    }
                    1 if now < 180_000 => {
                        if let Some(old) = before {
                            now = now.max(old.expires_at_ms.saturating_sub(5_000).saturating_add(1));
                            clock.set(i64::try_from(now).unwrap());
                        }
                        committed(&pipe, &a, name, u8::try_from(index % 250 + 3).unwrap()).await;
                    }
                    2 => {
                        let registry = TimerRegistry::new().register(RelayHandler {
                            target: store.clone(), hook: NoHook, budget: RelayBudget::default(),
                        });
                        run_due(&store, &source, &registry, clock.as_ref(), now, &TickBudget::default()).await.unwrap();
                    }
                    3 => {
                        let registry = TimerRegistry::new().register(LeaseSweep::new(store.clone()));
                        run_due(&store, &coordinator(&a), &registry, clock.as_ref(), now, &TickBudget::default()).await.unwrap();
                    }
                    _ => {}
                }
                let after = store.get(&coordinator(&a), &key).await.unwrap()
                    .map(|v| codec::decode_leased_shard(&v).unwrap());
                if let (Some(old), Some(new)) = (before, after) {
                    prop_assert!(new.relay_watermark_ms >= old.relay_watermark_ms,
                        "shard {n} maximum fell from {} to {}", old.relay_watermark_ms, new.relay_watermark_ms);
                }
                let watermark = namespace_relay_watermark(&store, &coordinator(&a), now).await.unwrap();
                let mut remaining = Vec::new();
                for (shard_id, seq, committed_at) in undelivered {
                    if store.get(&shard(&a, MODEL_REFS[shard_id]), &keys::relay(seq)).await.unwrap().is_some() {
                        prop_assert!(watermark <= committed_at,
                            "watermark {watermark} passed undelivered commit {committed_at}");
                        remaining.push((shard_id, seq, committed_at));
                    }
                }
                undelivered = remaining;
            }
            Ok(())
        })?;
    }
}

async fn plant_delayed_relay_and_expired_lease(
    store: &Store<MemoryKv>,
    source: &Partition,
    coordinator: &Partition,
    repo: &mkit_server::RepoName,
    shard_ref: &str,
) {
    use mkit_server::timers::{lease_sweep::lease_reference, registry::kinds};

    let lease = codec::LeasedShard {
        authority_generation: None,
        acked_authority_generation: None,
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
        deletes: Vec::new(),
    };
    store
        .apply(
            source,
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
            coordinator,
            Batch::new()
                .put(
                    keys::leased_shard(repo, shard_ref),
                    codec::encode_leased_shard(&lease),
                )
                .put(
                    keys::timer(
                        100,
                        kinds::LEASE_SWEEP.get(),
                        &lease_reference(repo, shard_ref),
                    ),
                    Value::default(),
                ),
        )
        .await
        .unwrap();
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
    let timer10100 = keys::timer(
        10_100,
        kinds::LEASE_SWEEP.get(),
        &lease_reference(&repo, shard_ref),
    );
    plant_delayed_relay_and_expired_lease(&store, &source, &coordinator, &repo, shard_ref).await;
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
    assert!(
        store
            .get(&source, &Key::new(&b"tdr\0"[..]))
            .await
            .unwrap()
            .is_none(),
        "the delay marker is consumed when delivery resumes"
    );
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
        deletes: Vec::new(),
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
    assert_eq!(
        revoke.await.unwrap().unwrap(),
        RevokeProgress::Pending { remaining: 1 }
    );
    assert_eq!(ls(&store, &a, REF).await.acked_epoch, 0);
    finish_bounded_revoke(&pipe, &ns).await;
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
    use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
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

    // The ref write now leaves an index relay row. Drain it so this case
    // isolates lease clock skew rather than the sweep's outbox hold-off.
    let relay_report = run_due(
        &store,
        &shard(&a, REF),
        &TimerRegistry::new().register(RelayHandler {
            target: store.clone(),
            hook: NoHook,
            budget: RelayBudget::default(),
        }),
        clock.as_ref(),
        0,
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(relay_report.fired, 1);

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
    Box::pin(swept_lease_renewal(
        Blocking::new(SqlKvStore::open(conn).unwrap()),
        pipeline_clock,
        store_clock,
        24_999,
    ))
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

async fn assert_grant_write_uncommitted<N: NamespaceStore>(
    store: &Store<N>,
    a: &Authenticated,
    ref_name: &str,
) {
    let partition = shard(a, ref_name);
    let replay = keys::replay(&a.auth.as_ref().unwrap().replay_scope);
    assert!(
        store
            .inner
            .get(&partition, &replay)
            .await
            .unwrap()
            .is_none()
    );
    let (first, end) = keys::class_range(keys::TAG_QUOTA);
    assert!(
        store
            .inner
            .scan(&partition, &first, &end, None, 10)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
}

async fn revoke_during_authorize<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock, faults.clone(), Reject::Allow);
    let owner_auth = auth(&pipe, None);
    committed(&pipe, &owner_auth, REF, 1).await;
    let granted = granted_auth(&pipe, Some("c"), 0);
    faults.c.arm();
    let task = {
        let pipe = pipe.clone();
        let granted = granted.clone();
        tokio::spawn(async move { pipe.update_ref(&granted, update(REF, 2)).await })
    };
    faults.c.entered().await;
    assert_eq!(pipe.set_grant_epoch(&signed_epoch(1)).await.unwrap(), 1);
    faults.c.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(
        store
            .inner
            .get(
                &shard(&owner_auth, REF),
                &keys::ref_key(&owner_auth.repo().repo.name, REF)
            )
            .await
            .unwrap(),
        Some(codec::encode_ref_id(&[1; 32]))
    );
    assert_grant_write_uncommitted(&store, &granted, REF).await;
}
backends!(
    revoke_during_authorize_memory,
    revoke_during_authorize_sqlite,
    revoke_during_authorize
);

async fn failed_push_then_expired_lease<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let owner_auth = auth(&pipe, None);
    committed(&pipe, &owner_auth, REF, 1).await;
    clock.set(23_999);
    store_clock.set(23_999);
    let granted = granted_auth(&pipe, Some("a"), 0);
    faults.a.arm();
    let task = {
        let pipe = pipe.clone();
        let granted = granted.clone();
        tokio::spawn(async move { pipe.update_ref(&granted, update(REF, 2)).await })
    };
    faults.a.entered().await;
    store.controls.fail_push_once.store(true, Ordering::SeqCst);
    assert!(pipe.set_grant_epoch(&signed_epoch(1)).await.is_err());
    clock.set(31_000);
    store_clock.set(31_000);
    assert_eq!(pipe.set_grant_epoch(&signed_epoch(1)).await.unwrap(), 1);
    faults.a.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_eq!(
        store
            .inner
            .get(
                &shard(&owner_auth, REF),
                &keys::ref_key(&owner_auth.repo().repo.name, REF)
            )
            .await
            .unwrap(),
        Some(codec::encode_ref_id(&[1; 32]))
    );
    assert_grant_write_uncommitted(&store, &granted, REF).await;
    assert!(store.take().iter().any(|call| matches!(
        call,
        Call::Apply(
            Partition::Ref { .. },
            _,
            BatchOutcome::DeadlinePassed { .. }
        )
    )));
}
backends!(
    failed_push_then_expired_lease_memory,
    failed_push_then_expired_lease_sqlite,
    failed_push_then_expired_lease
);

async fn idle_shard_rejects_old_grant<N: NamespaceStore + 'static>(
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
    let owner_auth = auth(&pipe, None);
    committed(&pipe, &owner_auth, REF, 1).await;
    clock.set(31_000);
    store_clock.set(31_000);
    assert_eq!(pipe.set_grant_epoch(&signed_epoch(1)).await.unwrap(), 1);
    let idle = "refs/heads/idle";
    let granted = granted_auth(&pipe, None, 0);
    assert_eq!(
        pipe.update_ref(&granted, update(idle, 2))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        store
            .inner
            .get(
                &shard(&granted, idle),
                &keys::ref_key(&granted.repo().repo.name, idle)
            )
            .await
            .unwrap()
            .is_none()
    );
    assert_grant_write_uncommitted(&store, &granted, idle).await;
}
backends!(
    idle_shard_rejects_old_grant_memory,
    idle_shard_rejects_old_grant_sqlite,
    idle_shard_rejects_old_grant
);

async fn expiry_races_ack<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(store.clone(), clock.clone(), faults, Reject::Allow);
    let owner_auth = auth(&pipe, None);
    committed(&pipe, &owner_auth, REF, 1).await;
    store.controls.ack.arm();
    let task = {
        let pipe = pipe.clone();
        tokio::spawn(async move { pipe.set_grant_epoch(&signed_epoch(1)).await })
    };
    store.controls.ack.entered().await;
    clock.set(31_000);
    store_clock.set(31_000);
    store.controls.ack.resume();
    assert_eq!(task.await.unwrap().unwrap(), 1);
    let granted = granted_auth(&pipe, None, 0);
    assert_eq!(
        pipe.update_ref(&granted, update(REF, 2))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_grant_write_uncommitted(&store, &granted, REF).await;
}
backends!(
    expiry_races_ack_memory,
    expiry_races_ack_sqlite,
    expiry_races_ack
);

async fn pending_retry_completes<N: NamespaceStore + 'static>(
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
    let owner_auth = auth(&pipe, None);
    committed(&pipe, &owner_auth, REF, 1).await;
    pipe.mark_lease_table_recovered(&owner_auth.repo().repo.namespace)
        .await
        .unwrap();
    let statement = signed_epoch(1);
    let error = pipe.set_grant_epoch(&statement).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert!(
        error
            .headers()
            .iter()
            .any(|(name, value)| name == "Retry-After" && value == "1")
    );
    clock.set(36_000);
    store_clock.set(36_000);
    assert_eq!(pipe.set_grant_epoch(&statement).await.unwrap(), 1);
    let granted = granted_auth(&pipe, None, 0);
    assert_eq!(
        pipe.update_ref(&granted, update(REF, 2))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_grant_write_uncommitted(&store, &granted, REF).await;
}
backends!(
    pending_retry_completes_memory,
    pending_retry_completes_sqlite,
    pending_retry_completes
);

async fn reserved_begin_epoch_mismatch<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let owner_pipe = pipeline(store.clone(), clock.clone(), faults.clone(), Reject::Allow);
    let owner_auth = auth(&owner_pipe, None);
    committed(&owner_pipe, &owner_auth, REF, 1).await;
    let reserved = pipeline(store.clone(), clock, faults.clone(), Reject::Reserved);
    let grant = signed_grant(0);
    let granted = auth_for(
        &reserved,
        Some("a"),
        [2; 32],
        Some(&grant),
        Procedure::BeginUpload,
    );
    faults.a.arm();
    let task = {
        let reserved = reserved.clone();
        let granted = granted.clone();
        tokio::spawn(async move { reserved.begin_upload(&granted, REF, &[2; 32], 10).await })
    };
    faults.a.entered().await;
    assert_eq!(
        owner_pipe.set_grant_epoch(&signed_epoch(1)).await.unwrap(),
        1
    );
    faults.a.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_grant_write_uncommitted(&store, &granted, REF).await;
    assert_eq!(
        store
            .inner
            .get(
                &shard(&owner_auth, REF),
                &keys::ref_key(&owner_auth.repo().repo.name, REF)
            )
            .await
            .unwrap(),
        Some(codec::encode_ref_id(&[1; 32]))
    );
    let (first, end) = keys::class_range(keys::TAG_TICKET);
    assert!(
        store
            .inner
            .scan(&shard(&granted, REF), &first, &end, None, 10)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    let outcome = store
        .inner
        .get(
            &shard(&granted, REF),
            &keys::reservation("epoch-race").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&outcome).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::EpochMismatch,
            ..
        }
    ));
}
backends!(
    reserved_begin_epoch_mismatch_memory,
    reserved_begin_epoch_mismatch_sqlite,
    reserved_begin_epoch_mismatch
);

async fn epoch_rpc_rules<N: NamespaceStore + 'static>(
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
    assert_eq!(
        pipe.get_grant_epoch("ED25519-bad")
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert!(
        store.take().is_empty(),
        "bad grammar must not reach storage"
    );
    assert_eq!(
        pipe.get_grant_epoch(
            "ed25519-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .await
        .unwrap(),
        0
    );
    assert!(
        store.take().is_empty(),
        "unserved namespace must not reach storage"
    );
    assert_eq!(
        pipe.set_grant_epoch(&"x".repeat(8_193))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert!(
        store.take().is_empty(),
        "oversize statement must not reach storage"
    );
    assert_eq!(
        pipe.get_grant_epoch(identity().split_once('/').unwrap().0)
            .await
            .unwrap(),
        0
    );
    // The business clock, not wall time, controls the statement's expiry.
    clock.set(240_000);
    assert_eq!(
        pipe.set_grant_epoch(&signed_epoch(1))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    clock.set(0);
    // Another request wins the CAS with the same value: reclassify as Retry.
    *store.controls.epoch_race_once.lock().unwrap() = Some(1);
    assert_eq!(pipe.set_grant_epoch(&signed_epoch(1)).await.unwrap(), 1);
    assert_eq!(
        pipe.get_grant_epoch(identity().split_once('/').unwrap().0)
            .await
            .unwrap(),
        1
    );
    // A concurrent higher epoch turns a proposed lower epoch into Reject.
    *store.controls.epoch_race_once.lock().unwrap() = Some(3);
    assert_eq!(
        pipe.set_grant_epoch(&signed_epoch(2))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        pipe.get_grant_epoch(identity().split_once('/').unwrap().0)
            .await
            .unwrap(),
        3
    );
    // A second owner statement advances after our CAS but before our
    // completion scan. The response must report the fenced stored epoch.
    *store.controls.epoch_after_cas_once.lock().unwrap() = Some(5);
    assert_eq!(pipe.set_grant_epoch(&signed_epoch(4)).await.unwrap(), 5);
    assert_eq!(
        pipe.get_grant_epoch(identity().split_once('/').unwrap().0)
            .await
            .unwrap(),
        5
    );
    assert_no_epoch_accounting_rows(&store, &pipe).await;
}

async fn assert_no_epoch_accounting_rows<N: NamespaceStore>(store: &Store<N>, pipe: &Pipe<N>) {
    let coordinator = coordinator(&auth(pipe, None));
    for tag in [keys::TAG_REPLAY, keys::TAG_QUOTA] {
        let (first, end) = keys::class_range(tag);
        assert!(
            store
                .inner
                .scan(&coordinator, &first, &end, None, 10)
                .await
                .unwrap()
                .entries
                .is_empty(),
            "epoch RPC created an accounting row in {tag}"
        );
    }
}
backends!(
    epoch_rpc_rules_memory,
    epoch_rpc_rules_sqlite,
    epoch_rpc_rules
);

fn signed_authority(generation: u64) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::Signer as _;
    let text = format!(
        "mkit-authority-generation:v1\ndeployment\n{}\n{generation}\n{AUDIENCE}\n0\n240000\n{}",
        identity().split_once('/').unwrap().0,
        to_hex(&hash(b"authority-nonce"))
    );
    let signature = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).sign(&hash(text.as_bytes()));
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(text),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

#[allow(clippy::too_many_lines)] // One paused-write regression also proves fresh authorization and committed replay after revocation.
async fn authority_paused<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(0)),
    );
    let initial = auth(&pipe, None);
    committed(&pipe, &initial, REF, 1).await;
    // R-63: an already authorized delegate is paused at the final atomic apply.
    let delegate = auth_as(&pipe, Some("a"), [2; 32], None);
    faults.a.arm();
    let task = {
        let pipe = pipe.clone();
        let delegate = delegate.clone();
        tokio::spawn(async move { pipe.update_ref(&delegate, update(REF, 2)).await })
    };
    faults.a.entered().await;
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(1))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(1))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ls(&store, &initial, REF).await.acked_authority_generation,
        Some(1)
    );
    assert_eq!(
        el(&store, &initial, REF).await.authority_generation,
        Some(1)
    );
    faults.a.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    assert_grant_write_uncommitted(&store, &delegate, REF).await;
    let aborted = store
        .inner
        .get(
            &shard(&delegate, REF),
            &keys::reservation(&delegate.auth.as_ref().unwrap().nonce).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&aborted).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::EpochMismatch,
            ..
        }
    ));
    assert_eq!(
        pipe.get_grant_epoch(identity().split_once('/').unwrap().0)
            .await
            .unwrap(),
        0
    );
    // A stale reply must not gain a fresh generation by renewing its lease.
    clock.set(31_000);
    store_clock.set(31_000);
    let stale = auth_as(&pipe, None, [2; 32], None);
    assert_eq!(
        pipe.update_ref(&stale, update(REF, 3))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let fresh = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(1)),
    );
    let current = auth_as(&fresh, None, [2; 32], None);
    assert_eq!(
        fresh.update_ref(&current, update(REF, 4)).await.unwrap(),
        UpdateRefResult::Committed
    );
    // Replay of a committed result after a newer barrier is not new acceptance.
    assert_eq!(
        fresh
            .set_authority_generation(&signed_authority(2))
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        fresh.update_ref(&current, update(REF, 4)).await.unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        fresh
            .set_authority_generation(&signed_authority(1))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
}
backends!(
    authority_paused_memory,
    authority_paused_sqlite,
    authority_paused
);

async fn authority_missing_and_recovery<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let missing = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(None),
    );
    let a = auth_as(&missing, None, [2; 32], None);
    assert_eq!(
        missing
            .update_ref(&a, update(REF, 1))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        faults,
        Reject::Authority(Some(0)),
    );
    let a = auth_as(&pipe, None, [2; 32], None);
    committed(&pipe, &a, REF, 1).await;
    let old = el(&store, &a, REF).await;
    // R-151: failed push cannot acknowledge; expiration plus backend NotAfter fences delayed writes.
    store.controls.fail_push_once.store(true, Ordering::SeqCst);
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(1))
            .await
            .unwrap_err()
            .code(),
        Code::Internal
    );
    assert_eq!(
        ls(&store, &a, REF).await.acked_authority_generation,
        Some(0)
    );
    clock.set(31_000);
    store_clock.set(31_000);
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(1))
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        store
            .inner
            .apply(&shard(&a, REF), old_batch(old))
            .await
            .unwrap(),
        BatchOutcome::DeadlinePassed { .. }
    ));
    pipe.mark_lease_table_recovered(&a.repo().repo.namespace)
        .await
        .unwrap();
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(2))
            .await
            .unwrap_err()
            .code(),
        Code::Unavailable
    );
    clock.set(66_000);
    store_clock.set(66_000);
    assert_eq!(
        pipe.set_authority_generation(&signed_authority(2))
            .await
            .unwrap(),
        2
    );
}
backends!(
    authority_missing_recovery_memory,
    authority_missing_recovery_sqlite,
    authority_missing_and_recovery
);

async fn authority_during_authorize_and_begin<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(0)),
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let stale = auth_as(&pipe, Some("c"), [2; 32], None);
    faults.c.arm();
    let task = {
        let pipe = pipe.clone();
        tokio::spawn(async move { pipe.update_ref(&stale, update(REF, 2)).await })
    };
    faults.c.entered().await;
    pipe.set_authority_generation(&signed_authority(1))
        .await
        .unwrap();
    faults.c.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    let fresh = pipeline(
        store.clone(),
        clock,
        faults.clone(),
        Reject::Authority(Some(1)),
    );
    let a = auth_for(&fresh, Some("a"), [2; 32], None, Procedure::BeginUpload);
    faults.a.arm();
    let task = {
        let fresh = fresh.clone();
        let a = a.clone();
        tokio::spawn(async move { fresh.begin_upload(&a, REF, &[2; 32], 10).await })
    };
    faults.a.entered().await;
    fresh
        .set_authority_generation(&signed_authority(2))
        .await
        .unwrap();
    faults.a.resume();
    assert_eq!(
        task.await.unwrap().unwrap_err().code(),
        Code::PermissionDenied
    );
    let (first, end) = keys::class_range(keys::TAG_TICKET);
    assert!(
        store
            .inner
            .scan(&shard(&a, REF), &first, &end, None, 10)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    let reservation = store
        .inner
        .get(
            &shard(&a, REF),
            &keys::reservation(&a.auth.as_ref().unwrap().nonce).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&reservation).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::EpochMismatch,
            ..
        }
    ));
}
backends!(
    authority_authorize_begin_memory,
    authority_authorize_begin_sqlite,
    authority_during_authorize_and_begin
);

async fn authority_visibility<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    use mkit_attest::grant::Visibility;
    use mkit_server::pipeline::VisibilityRequest;
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(0)),
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    let delegate = auth_for(&pipe, None, [2; 32], None, Procedure::SetRepoVisibility);
    pipe.set_repo_visibility(&delegate, VisibilityRequest::Envelope(Visibility::Public))
        .await
        .unwrap();
    pipe.set_authority_generation(&signed_authority(1))
        .await
        .unwrap();
    let stale = auth_for(&pipe, None, [2; 32], None, Procedure::SetRepoVisibility);
    assert_eq!(
        pipe.set_repo_visibility(&stale, VisibilityRequest::Envelope(Visibility::Private))
            .await
            .unwrap_err()
            .code(),
        Code::PermissionDenied
    );
    let fresh = pipeline(store, clock, faults, Reject::Authority(Some(1)));
    let current = auth_for(&fresh, None, [2; 32], None, Procedure::SetRepoVisibility);
    fresh
        .set_repo_visibility(&current, VisibilityRequest::Envelope(Visibility::Private))
        .await
        .unwrap();
}
backends!(
    authority_visibility_memory,
    authority_visibility_sqlite,
    authority_visibility
);

async fn authority_renewal_between_push_and_ack<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    store_clock: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(0)),
    );
    let a = auth(&pipe, None);
    committed(&pipe, &a, REF, 1).await;
    store.controls.ack.arm();
    let task = {
        let pipe = pipe.clone();
        tokio::spawn(async move { pipe.set_authority_generation(&signed_authority(1)).await })
    };
    store.controls.ack.entered().await;
    assert_eq!(el(&store, &a, REF).await.authority_generation, Some(1));
    clock.set(24_500);
    store_clock.set(24_500);
    let fresh = pipeline(store.clone(), clock, faults, Reject::Authority(Some(1)));
    let delegate = auth_as(&fresh, None, [2; 32], None);
    assert_eq!(
        fresh.update_ref(&delegate, update(REF, 2)).await.unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        ls(&store, &a, REF).await.acked_authority_generation,
        Some(0)
    );
    store.controls.ack.resume();
    // Advancing the manual clock exhausted the original bounded call; retry resumes its barrier.
    let pending = task.await.unwrap().unwrap_err();
    assert_eq!(pending.code(), Code::Unavailable);
    assert_eq!(
        fresh
            .set_authority_generation(&signed_authority(1))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        ls(&store, &a, REF).await.acked_authority_generation,
        Some(1)
    );
    assert_eq!(el(&store, &a, REF).await.authority_generation, Some(1));
    assert_eq!(el(&store, &a, REF).await.epoch, 0);
}
backends!(
    authority_renew_ack_memory,
    authority_renew_ack_sqlite,
    authority_renewal_between_push_and_ack
);

#[tokio::test]
async fn authority_setter_has_a_fixed_scan_bound_with_a_frozen_clock() {
    use mkit_server::{Clock, NamespaceKey, RepoName};
    let clock = Arc::new(ManualClock::new(100));
    let store = Store::new(MemoryKv::with_clock(clock.clone()));
    let ns = NamespaceKey::from_namespace(
        &Namespace::parse(identity().split_once('/').unwrap().0).unwrap(),
    );
    let coordinator = Partition::Coordinator(ns);
    for index in 0..1536 {
        let row = codec::LeasedShard {
            authority_generation: Some(0),
            acked_authority_generation: Some(u64::from(index >= 4)),
            epoch: 0,
            acked_epoch: 0,
            expires_at_ms: if index >= 4 && index % 2 == 0 {
                99
            } else {
                100_000
            },
            relay_watermark_ms: 0,
            sweep_due_ms: 100_000,
        };
        store
            .inner
            .apply(
                &coordinator,
                Batch::new().put(
                    keys::leased_shard(&RepoName::new(format!("scan-{index:04}")).unwrap(), REF),
                    codec::encode_leased_shard(&row),
                ),
            )
            .await
            .unwrap();
    }
    let pipe = pipeline(
        store.clone(),
        clock.clone(),
        Arc::new(Faults::default()),
        Reject::Authority(Some(1)),
    );
    store.take();
    store.controls.push_conflict.store(true, Ordering::SeqCst);
    let result = pipe.set_authority_generation(&signed_authority(1)).await;
    let calls = store.take();
    let mut max_calls = calls.len();
    assert!(
        calls.len() <= 50,
        "one setter scanned {} calls at frozen time",
        calls.len()
    );
    assert_eq!(result.unwrap_err().code(), Code::Unavailable);
    store.controls.push_conflict.store(false, Ordering::SeqCst);
    let mut complete = false;
    for _ in 0..60 {
        // Each slice runs in a fresh pipeline, as separate cold Worker calls do.
        let pipe = pipeline(
            store.clone(),
            clock.clone(),
            Arc::new(Faults::default()),
            Reject::Authority(Some(1)),
        );
        let result = pipe.set_authority_generation(&signed_authority(1)).await;
        let count = store.take().len();
        max_calls = max_calls.max(count);
        assert!(
            count <= 50,
            "setter exceeded general Worker budget: {count}"
        );
        if result.is_ok() {
            complete = true;
            break;
        }
        assert_eq!(result.unwrap_err().code(), Code::Unavailable);
    }
    assert!(
        complete,
        "durable confirmed prefix must advance across bounded retries"
    );
    eprintln!(
        "maximum setter metadata calls including activation, collision and completion: {max_calls}"
    );
    assert_eq!(clock.now_ms(), 100);
}

async fn disabled_executor_refuses_persisted_authority<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    _: Arc<ManualClock>,
) {
    let store = Store::new(backend);
    let faults = Arc::new(Faults::default());
    let enabled = pipeline(
        store.clone(),
        clock.clone(),
        faults.clone(),
        Reject::Authority(Some(0)),
    );
    let initial = auth(&enabled, None);
    committed(&enabled, &initial, REF, 1).await;
    let begin = auth_for(&enabled, None, [1; 32], None, Procedure::BeginUpload);
    let mkit_server::BeginUploadResult::Ticket { token, .. } = enabled
        .begin_upload(&begin, REF, &[3; 32], 10)
        .await
        .unwrap()
    else {
        panic!("expected ticket")
    };
    for generation in [0, 1] {
        if generation == 1 {
            enabled
                .set_authority_generation(&signed_authority(1))
                .await
                .unwrap();
        }
        for rejection in [Reject::UnfencedAuthority(Some(0)), Reject::Allow] {
            let disabled = pipeline(store.clone(), clock.clone(), faults.clone(), rejection);
            let old = auth_as(&disabled, None, [1; 32], None);
            assert!(
                disabled.update_ref(&old, update(REF, 2)).await.is_err(),
                "disabled usable lease accepted generation {generation}"
            );
            let visibility = auth_for(&disabled, None, [1; 32], None, Procedure::SetRepoVisibility);
            assert!(
                disabled
                    .set_repo_visibility(
                        &visibility,
                        mkit_server::pipeline::VisibilityRequest::Envelope(
                            mkit_attest::grant::Visibility::Public
                        )
                    )
                    .await
                    .is_err()
            );
            let complete = auth_for(&disabled, None, [1; 32], None, Procedure::CompleteUpload);
            assert_eq!(
                disabled
                    .complete_upload(&complete, &token, &[])
                    .await
                    .unwrap_err()
                    .code(),
                Code::Unavailable
            );
            let fresh = auth_as(&disabled, None, [1; 32], None);
            assert!(
                disabled
                    .update_ref(&fresh, update("refs/heads/fresh", 3))
                    .await
                    .is_err(),
                "disabled fresh shard accepted generation {generation}"
            );
        }
    }
    clock.advance(30_000);
    let disabled = pipeline(store, clock, faults, Reject::UnfencedAuthority(Some(0)));
    let expired = auth_as(&disabled, None, [1; 32], None);
    assert!(
        disabled.update_ref(&expired, update(REF, 4)).await.is_err(),
        "disabled expired renewal accepted"
    );
}
backends!(
    disabled_executor_refuses_persisted_authority_memory,
    disabled_executor_refuses_persisted_authority_sqlite,
    disabled_executor_refuses_persisted_authority
);

#[tokio::test]
async fn authority_activation_before_business_creation_preserves_recovery_and_watermarks() {
    use mkit_server::store::watermark::{check_recovery, mark_lease_table_reconciled};
    use mkit_server::{NamespaceKey, RepoName};
    let clock = Arc::new(ManualClock::new(100));
    let store = Store::new(MemoryKv::with_clock(clock.clone()));
    let pipe = pipeline(
        store.clone(),
        clock,
        Arc::new(Faults::default()),
        Reject::Authority(Some(0)),
    );
    let ns = NamespaceKey::from_namespace(
        &Namespace::parse(identity().split_once('/').unwrap().0).unwrap(),
    );
    let coordinator = Partition::Coordinator(ns.clone());
    pipe.set_authority_generation(&signed_authority(0))
        .await
        .unwrap();
    assert!(
        store
            .inner
            .get(&coordinator, &keys::namespace_record())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(
                &coordinator,
                &keys::repo_record(&RepoName::new("leases").unwrap())
            )
            .await
            .unwrap()
            .is_none()
    );
    let raw = store
        .inner
        .get(&coordinator, &keys::lease_recovery())
        .await
        .unwrap()
        .unwrap();
    let mode = codec::decode_lease_recovery(&raw).unwrap();
    assert_eq!(mode.authority_fence, Some(true));
    assert_eq!(mode.authority_ready, Some(true));
    assert_eq!(mode.recovery_time(), None);
    assert!(check_recovery(&store, &coordinator, None).await.is_ok());
    assert!(
        mark_lease_table_reconciled(&store, &coordinator, 100)
            .await
            .is_err()
    );
    pipe.mark_lease_table_recovered(&ns).await.unwrap();
    let raw = store
        .inner
        .get(&coordinator, &keys::lease_recovery())
        .await
        .unwrap()
        .unwrap();
    let mode = codec::decode_lease_recovery(&raw).unwrap();
    assert_eq!(mode.authority_fence, Some(true));
    assert_eq!(mode.authority_ready, Some(true));
    assert_eq!(mode.recovery_time(), Some(100));
    assert!(check_recovery(&store, &coordinator, None).await.is_err());
    mark_lease_table_reconciled(&store, &coordinator, 101)
        .await
        .unwrap();
    assert!(check_recovery(&store, &coordinator, None).await.is_ok());
}

fn stream_auth<N: NamespaceStore>(
    pipe: &Pipe<N>,
    procedure: Procedure,
    commitment: String,
) -> Authenticated {
    let signer = owner();
    let mut envelope = signer.envelope(procedure.connect_path(), commitment);
    envelope.created_at = 0;
    envelope.expires_at = 240_000;
    let carriage = signer.sign(&envelope);
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &|name| {
            carriage
                .headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        },
        header_values: None,
        unary_body: None,
        transport_principal: None,
    })
    .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Same valid bytes exercise both ticket protocols and every framing.
async fn authority_stream_metadata_work_is_independent_of_framing() {
    use bytes::Bytes;
    use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
    use mkit_server::store::{BlobKey, MultipartBlobStore};
    use mkit_server::upload::token::TicketClaims;
    use mkit_server_conformance::wire::sign::pack_commitment;
    let data = vec![17; 8193];
    for enabled in [false, true] {
        for multipart in [false, true] {
            let store = Store::new(MemoryKv::default());
            let clock = Arc::new(ManualClock::new(100));
            let blobs = MemoryBlobStore::default();
            let pipe = pipeline_with_uploads(
                store.clone(),
                clock,
                Arc::new(Faults::default()),
                if enabled {
                    Reject::Authority(Some(0))
                } else {
                    Reject::Allow
                },
                blobs.clone(),
                UploadLimits {
                    max_total_bytes: 64 * 1024 * 1024,
                    max_chunks: u32::MAX,
                },
            );
            if enabled {
                pipe.set_authority_generation(&signed_authority(0))
                    .await
                    .unwrap();
            }
            let first = vec![5; usize::try_from(MIN_PART_SIZE).unwrap()];
            let pack = if multipart {
                [first.as_slice(), data.as_slice()].concat()
            } else {
                data.clone()
            };
            let pack_id = hash(&pack);
            let session = if multipart {
                blobs
                    .begin_multipart(BlobKey::pack(pack_id), pack.len() as u64, MIN_PART_SIZE)
                    .await
                    .unwrap()
            } else {
                Vec::new()
            };
            let claims = TicketClaims {
                authority_generation: enabled.then_some(0),
                ticket_id: [19; 32],
                audience: AUDIENCE.into(),
                repository: identity(),
                signer: mkit_core::hash::from_hex(&owner().public_key_hex()).unwrap(),
                pack_id,
                bytes: pack.len() as u64,
                part_size: MIN_PART_SIZE,
                expires_at_ms: 240_000,
                upload_session: session,
            };
            let token = TicketKeys::new(vec![("test".into(), [9; 32])])
                .unwrap()
                .mint(&claims);
            let plan =
                PartPlan::new(MIN_PART_SIZE + data.len() as u64, MIN_PART_SIZE, 10_000).unwrap();
            let index = u32::from(multipart);
            let cv = if multipart {
                part_subtree_cv(&plan, index, &data).unwrap()
            } else {
                [0; 32]
            };
            let mut receipts = Vec::new();
            if multipart {
                store.take();
                let first_cv = part_subtree_cv(&plan, 0, &first).unwrap();
                let a = stream_auth(
                    &pipe,
                    Procedure::UploadPart,
                    format!(
                        "part:{}:0:{}:{}",
                        to_hex(&claims.ticket_id),
                        to_hex(&first_cv),
                        MIN_PART_SIZE
                    ),
                );
                let mut part = pipe.open_part(&a, &token, 0).await.unwrap();
                part.push(Bytes::copy_from_slice(&first)).await.unwrap();
                receipts.push(part.finish().await.unwrap());
                let calls = store.take().len();
                assert_eq!(calls, 68);
                eprintln!("full8MiB part metadata calls: enabled={enabled} calls={calls}");
            }
            let mut baseline = None;
            for framing in [64 * 1024, 4 * 1024, 1] {
                for replay in [false, true] {
                    store.take();
                    if multipart {
                        let a = stream_auth(
                            &pipe,
                            Procedure::UploadPart,
                            format!(
                                "part:{}:{index}:{}:{}",
                                to_hex(&claims.ticket_id),
                                to_hex(&cv),
                                data.len()
                            ),
                        );
                        let mut part = pipe.open_part(&a, &token, index).await.unwrap();
                        for chunk in data.chunks(framing) {
                            part.push(Bytes::copy_from_slice(chunk)).await.unwrap();
                        }
                        let receipt = part.finish().await.unwrap();
                        receipts.truncate(1);
                        receipts.push(receipt);
                    } else {
                        let a = stream_auth(
                            &pipe,
                            Procedure::UploadPack,
                            pack_commitment(&pack_id, claims.bytes),
                        );
                        let mut upload = pipe
                            .open_ticketed_upload(&a, Some(&pack_id), Some(claims.bytes), &token)
                            .await
                            .unwrap();
                        let mut offset = 0;
                        for chunk in data.chunks(framing) {
                            let end = offset + chunk.len();
                            upload
                                .push(
                                    Some(&pack_id),
                                    Some(offset as u64),
                                    Bytes::copy_from_slice(chunk),
                                    end == data.len(),
                                )
                                .await
                                .unwrap();
                            offset = end;
                        }
                        upload.finish().await.unwrap();
                    }
                    let calls = store.take().len();
                    let expected = *baseline.get_or_insert(calls);
                    assert_eq!(
                        calls, expected,
                        "enabled={enabled} multipart={multipart} framing={framing} replay={replay}"
                    );
                    assert!(calls <= 50, "whole request metadata calls={calls}");
                    eprintln!(
                        "stream calls: enabled={enabled} multipart={multipart} framing={framing} replay={replay} calls={calls}"
                    );
                }
            }
            if !multipart {
                let large = Bytes::from(vec![23; 64 * 1024 * 1024]);
                let mut full = claims.clone();
                full.ticket_id = [20; 32];
                full.pack_id = hash(&large);
                full.bytes = large.len() as u64;
                let token = TicketKeys::new(vec![("test".into(), [9; 32])])
                    .unwrap()
                    .mint(&full);
                let a = stream_auth(
                    &pipe,
                    Procedure::UploadPack,
                    pack_commitment(&full.pack_id, full.bytes),
                );
                store.take();
                let mut upload = pipe
                    .open_ticketed_upload(&a, Some(&full.pack_id), Some(full.bytes), &token)
                    .await
                    .unwrap();
                for offset in (0..large.len()).step_by(64 * 1024) {
                    let end = (offset + 64 * 1024).min(large.len());
                    upload
                        .push(
                            Some(&full.pack_id),
                            Some(offset as u64),
                            large.slice(offset..end),
                            end == large.len(),
                        )
                        .await
                        .unwrap();
                }
                upload.finish().await.unwrap();
                let calls = store.take().len();
                assert_eq!(calls, 517);
                eprintln!("full64MiB single metadata calls: enabled={enabled} calls={calls}");
            }
            let mut stale_part = None;
            if enabled && multipart {
                let a = stream_auth(
                    &pipe,
                    Procedure::UploadPart,
                    format!(
                        "part:{}:{index}:{}:{}",
                        to_hex(&claims.ticket_id),
                        to_hex(&cv),
                        data.len()
                    ),
                );
                let mut part = pipe.open_part(&a, &token, index).await.unwrap();
                part.push(Bytes::copy_from_slice(&data)).await.unwrap();
                stale_part = Some(part);
            }
            if multipart {
                for replay in [false, true] {
                    store.take();
                    let a = auth_for(&pipe, None, [1; 32], None, Procedure::CompleteUpload);
                    pipe.complete_upload(&a, &token, &receipts).await.unwrap();
                    let calls = store.take().len();
                    assert!(calls <= 50);
                    eprintln!("completion calls: enabled={enabled} replay={replay} calls={calls}");
                }
            }
            if enabled {
                if let Some(part) = stale_part {
                    pipe.set_authority_generation(&signed_authority(1))
                        .await
                        .unwrap();
                    assert_eq!(
                        part.finish().await.unwrap_err().code(),
                        Code::PermissionDenied
                    );
                } else {
                    let a = stream_auth(
                        &pipe,
                        Procedure::UploadPack,
                        pack_commitment(&pack_id, claims.bytes),
                    );
                    let mut upload = pipe
                        .open_ticketed_upload(&a, Some(&pack_id), Some(claims.bytes), &token)
                        .await
                        .unwrap();
                    upload
                        .push(Some(&pack_id), Some(0), Bytes::copy_from_slice(&data), true)
                        .await
                        .unwrap();
                    pipe.set_authority_generation(&signed_authority(1))
                        .await
                        .unwrap();
                    assert_eq!(
                        upload.finish().await.unwrap_err().code(),
                        Code::PermissionDenied
                    );
                }
            }
        }
    }
}
