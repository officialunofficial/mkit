//! `BeginUpload` admission, durable replay, caps and write races on both backends.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

#[cfg(feature = "test-faults")]
use std::sync::atomic::AtomicBool;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use mkit_core::hash::{hash, to_hex};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::protocol::{PackKey, RefWriteCondition};
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::fs::FsBlobStore;
use mkit_server::indexed::{IndexedConfig, state};
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authenticated, Authorizer, D34Shards,
    DefaultAdmission, Hooks, Pipeline, PipelineConfig, RequestMeta, ShardMap, Sharding,
    SinglePartition,
};
#[cfg(feature = "test-faults")]
use mkit_server::pipeline::{FaultHooks, FaultPoint, TestDirectives};
use mkit_server::policy::{AuthorizerRole, NamespacePolicy};
use mkit_server::quota::QuotaScope;
use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, BlobKey, BlobStore, Cursor, Key, MultipartBlobStore, PackSink, Partition,
    PartitionStats, Precondition, ScanPage, StoreCapabilities, StoreError, Value, Write, codec,
    keys,
};
use mkit_server::timers::{TickBudget, TimerRegistry, registry::kinds, run_due};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::{
    Addressing, AuthzFacts, BeginUploadResult, Code, ManualClock, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceKey, NamespaceStore, NoopMetrics, Operation, Principal, Procedure,
    RefUpdate, ReplayState, RepoId, RepoName, ServerError, StoredResult,
};
use mkit_server_conformance::wire::sign::{Signer, body_commitment, pack_commitment};
use mkit_server_native::{Blocking, RusqliteConn};
use tokio::sync::Barrier;
#[cfg(feature = "test-faults")]
use tokio::sync::Notify;

const AUDIENCE: &str = "http://localhost:9876";
const BODY: &[u8] = b"begin upload request";
const REF: &str = "refs/heads/main";
const PACK: [u8; 32] = [9; 32];
const BYTES: u64 = 32;
const TTL: u64 = 60_000;
const CAP_MESSAGE: &str = "too many open upload tickets";
const KEY_TEXT: &str = "dev 0101010101010101010101010101010101010101010101010101010101010101";

#[derive(Clone, Copy, Debug)]
struct Mode {
    multi: bool,
    sharding: Sharding,
}
const MODES: [Mode; 4] = [
    Mode {
        multi: false,
        sharding: Sharding::Single,
    },
    Mode {
        multi: false,
        sharding: Sharding::D34,
    },
    Mode {
        multi: true,
        sharding: Sharding::Single,
    },
    Mode {
        multi: true,
        sharding: Sharding::D34,
    },
];
impl Mode {
    fn identity(self) -> String {
        if self.multi {
            format!(
                "ed25519-{}/tickets",
                Signer::new([1; 32], AUDIENCE, "unused").public_key_hex()
            )
        } else {
            "tickets".into()
        }
    }
    fn partition(self, a: &Authenticated, name: &str) -> Partition {
        if self.sharding == Sharding::D34 {
            D34Shards.ref_shard(&a.repo().repo, name)
        } else {
            SinglePartition.ref_shard(&a.repo().repo, name)
        }
    }
}

#[derive(Debug, Clone)]
enum Call {
    Many(Vec<Key>),
    Apply(Partition, Batch, BatchOutcome),
}
#[derive(Default)]
struct Controls {
    calls: Mutex<Vec<Call>>,
    barrier: Mutex<Option<Arc<Barrier>>>,
    barrier_reads: AtomicUsize,
    #[cfg(feature = "test-faults")]
    abort_pause: Mutex<Option<Arc<AdvancePause>>>,
    #[cfg(feature = "test-faults")]
    abort_deadline: AtomicBool,
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
    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.controls.calls.lock().unwrap())
    }
    fn arm_race(&self) {
        self.controls.barrier_reads.store(0, Ordering::SeqCst);
        *self.controls.barrier.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    }
    #[cfg(feature = "test-faults")]
    fn arm_abort(&self, pause: Arc<AdvancePause>) {
        *self.controls.abort_pause.lock().unwrap() = Some(pause);
    }
}
impl<N: NamespaceStore> NamespaceStore for Store<N> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, ks: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.controls
            .calls
            .lock()
            .unwrap()
            .push(Call::Many(ks.to_vec()));
        let values = self.inner.get_many(p, ks).await?;
        if ks.iter().any(|k| k.as_bytes().starts_with(b"ti\0")) {
            let barrier = self.controls.barrier.lock().unwrap().clone();
            if let Some(barrier) = barrier
                && self.controls.barrier_reads.fetch_add(1, Ordering::SeqCst) < 2
            {
                // Both requests observe the pre-admission state before either can apply.
                tokio::time::timeout(Duration::from_secs(5), barrier.wait())
                    .await
                    .unwrap();
            }
        }
        Ok(values)
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.inner.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        #[cfg(feature = "test-faults")]
        if batch.writes.iter().any(|w| match w {
            Write::Put(k, v) if k.as_bytes().starts_with(b"o\0") => matches!(
                codec::decode_reservation(v),
                Ok(codec::ReservationV1::Aborted { .. })
            ),
            _ => false,
        }) {
            let pause = self.controls.abort_pause.lock().unwrap().take();
            if let Some(pause) = pause {
                pause.entered.notify_one();
                pause.release.notified().await;
            }
            if self.controls.abort_deadline.swap(false, Ordering::SeqCst) {
                let outcome = BatchOutcome::DeadlinePassed { backend_now: 1 };
                self.controls.calls.lock().unwrap().push(Call::Apply(
                    p.clone(),
                    batch,
                    outcome.clone(),
                ));
                return Ok(outcome);
            }
        }
        let outcome = self.inner.apply(p, batch.clone()).await?;
        self.controls
            .calls
            .lock()
            .unwrap()
            .push(Call::Apply(p.clone(), batch, outcome.clone()));
        Ok(outcome)
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[derive(Default)]
struct Spy {
    admissions: AtomicUsize,
    rejection: AtomicUsize,
    reservation: AtomicUsize,
}
#[derive(Clone)]
struct Policy(Arc<Spy>);
impl Authorizer for Policy {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        if self.0.rejection.load(Ordering::SeqCst) == 1 {
            Err(ServerError::permission_denied("test policy denial"))
        } else {
            Ok(AuthzFacts::default())
        }
    }
}
impl Admission for Policy {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let sequence = self.0.admissions.fetch_add(1, Ordering::SeqCst);
        if input.op.procedure() == Procedure::BeginUpload {
            assert!(input.declared_bytes >= BYTES);
            assert!(input.pack_id.is_some());
            assert_eq!(input.new_to_repo_bytes, Some(input.declared_bytes));
        }
        match self.0.rejection.load(Ordering::SeqCst) {
            2 => Ok(AdmissionDecision::challenge(
                vec![mkit_server::pipeline::Challenge {
                    scheme: "mpp".into(),
                    value: "pay".into(),
                }],
                "test challenge",
            )),
            3 => Ok(AdmissionDecision::Deny(ServerError::permission_denied(
                "test admission denial",
            ))),
            _ => {
                let allowed = DefaultAdmission.admit(input).await?;
                if self.0.reservation.load(Ordering::SeqCst) == 1 {
                    Ok(allowed.with_reservation(format!("admission-{sequence}")))
                } else {
                    Ok(allowed)
                }
            }
        }
    }
}
type Pipe<N> = Pipeline<MemoryBlobStore, Store<N>, Hooks<Policy, Policy>>;
fn config(mode: Mode) -> PipelineConfig {
    let addressing = if mode.multi {
        Addressing::Multi(
            MultiAddressing::new().with_namespace_policy(NamespacePolicy::Allowlist(
                [Namespace::parse(mode.identity().split_once('/').unwrap().0).unwrap()].into(),
            )),
        )
    } else {
        Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("tickets").unwrap(),
            },
        }
    };
    let mut cfg = PipelineConfig::new(
        addressing,
        AuthMode::AuthV2(
            AuthV2Config::new(AUDIENCE, if mode.multi { "" } else { "tickets" }).unwrap(),
        ),
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    );
    cfg.sharding = mode.sharding;
    cfg.authorizer_role = AuthorizerRole::Authority;
    cfg.ticket_keys = Some(TicketKeys::parse(KEY_TEXT).unwrap());
    cfg.ticket_ttl_ms = TTL;
    cfg
}
fn pipeline<N: NamespaceStore>(
    store: Store<N>,
    blobs: MemoryBlobStore,
    spy: Arc<Spy>,
    cfg: PipelineConfig,
    clock: Arc<ManualClock>,
) -> Arc<Pipe<N>> {
    let defaults = Hooks::new();
    Arc::new(
        Pipeline::new(
            blobs,
            store,
            Hooks {
                authorizer: Policy(spy.clone()),
                admission: Policy(spy),
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            },
            cfg,
            clock,
            Arc::new(NoopMetrics),
        )
        .unwrap(),
    )
}
fn auth<B: MultipartBlobStore, N: NamespaceStore, H: mkit_server::pipeline::HookSet>(
    pipe: &Pipeline<B, Store<N>, H>,
    mode: Mode,
    seed: u8,
    procedure: Procedure,
) -> Authenticated {
    let signer = Signer::new([seed; 32], AUDIENCE, &mode.identity());
    loop {
        let mut envelope = signer.envelope(procedure.connect_path(), body_commitment(BODY));
        envelope.created_at = 0;
        envelope.expires_at = 240_000;
        envelope.digest = Some(to_hex(&hash(BODY)));
        let carriage = signer.sign(&envelope);
        let a = pipe
            .authenticate(&RequestMeta {
                procedure,
                header: &|h| {
                    carriage
                        .headers
                        .iter()
                        .find(|(name, _)| name == h)
                        .map(|(_, v)| v.clone())
                },
                header_values: None,
                unary_body: Some(BODY),
                transport_principal: None,
            })
            .unwrap();
        // Keep opportunistic pruning out of snapshot and write assertions.
        if !a.auth.as_ref().unwrap().replay_scope[0].is_multiple_of(8) {
            return a;
        }
    }
}
fn auth_other_repo<N: NamespaceStore>(
    pipe: &Pipe<N>,
    mode: Mode,
    procedure: Procedure,
) -> Authenticated {
    let identity = mode.identity().replace("/tickets", "/other");
    let signer = Signer::new([1; 32], AUDIENCE, &identity);
    let mut envelope = signer.envelope(procedure.connect_path(), body_commitment(BODY));
    envelope.created_at = 0;
    envelope.expires_at = 240_000;
    envelope.digest = Some(to_hex(&hash(BODY)));
    let carriage = signer.sign(&envelope);
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &|h| {
            carriage
                .headers
                .iter()
                .find(|(name, _)| name == h)
                .map(|(_, v)| v.clone())
        },
        header_values: None,
        unary_body: Some(BODY),
        transport_principal: None,
    })
    .unwrap()
}
fn ticket_id(result: &BeginUploadResult) -> [u8; 32] {
    match result {
        BeginUploadResult::Ticket { id, .. } => *id,
        BeginUploadResult::AlreadyPresent => panic!("expected ticket, got {result:?}"),
    }
}
fn upd(name: &str, condition: RefWriteCondition, new: [u8; 32]) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        condition,
        new: Some(new),
    }
}
fn no_writes(calls: &[Call]) {
    assert!(
        calls.iter().all(|c| !matches!(c, Call::Apply(..))),
        "unexpected write: {calls:?}"
    );
}
async fn replay<N: NamespaceStore>(
    store: &Store<N>,
    mode: Mode,
    a: &Authenticated,
) -> Option<StoredResult> {
    store
        .inner
        .get(
            &mode.partition(a, REF),
            &keys::replay(&a.auth.as_ref().unwrap().replay_scope),
        )
        .await
        .unwrap()
        .map(|v| match codec::decode_replay_record(&v).unwrap().state {
            ReplayState::Committed(result) => result,
            other @ ReplayState::InFlight { .. } => panic!("not committed: {other:?}"),
        })
}
async fn warm<N: NamespaceStore>(pipe: &Pipe<N>, mode: Mode) {
    let a = auth(pipe, mode, 1, Procedure::UpdateRef);
    pipe.update_ref(
        &a,
        RefUpdate {
            name: REF.into(),
            condition: RefWriteCondition::Any,
            new: Some([1; 32]),
        },
    )
    .await
    .unwrap();
}

#[allow(clippy::too_many_lines)] // One lifecycle scenario verifies all four layout combinations.
async fn lifecycle<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let cfg = config(mode);
    let keys = cfg.ticket_keys.clone().unwrap();
    let part_size = cfg.part_size;
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        cfg,
        clock,
    );
    let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let first = pipe.begin_upload(&a, REF, &PACK, BYTES).await.unwrap();
    let id = ticket_id(&first);
    let BeginUploadResult::Ticket {
        part_size: actual_size,
        expires_at_ms,
        token,
        ..
    } = &first
    else {
        unreachable!()
    };
    assert_eq!(*actual_size, part_size);
    assert_eq!(*expires_at_ms, TTL);
    let claims = keys.verify(token, 0).unwrap();
    assert_eq!(claims.ticket_id, id);
    assert_eq!(claims.repository, mode.identity());
    assert_eq!(claims.audience, AUDIENCE);
    assert_eq!(claims.signer, a.auth.as_ref().unwrap().signer);
    assert_eq!(claims.pack_id, PACK);
    assert_eq!(claims.bytes, BYTES);
    assert!(claims.upload_session.is_empty());
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 1);
    assert_eq!(
        replay(&store, mode, &a).await,
        Some(StoredResult::BeginUpload(first.clone()))
    );
    let calls = store.take();
    let p = mode.partition(&a, REF);
    let first_snapshot = calls
        .iter()
        .find_map(|c| match c {
            Call::Many(ks) => Some(ks),
            Call::Apply(..) => None,
        })
        .unwrap();
    for prefix in [b"ti\0".as_slice(), b"tc\0", b"tu\0", b"m\0"] {
        assert!(
            first_snapshot
                .iter()
                .any(|k| k.as_bytes().starts_with(prefix)),
            "missing folded read {prefix:?}: {calls:?}"
        );
    }
    let batch = calls
        .iter()
        .find_map(|c| match c {
            Call::Apply(partition, b, BatchOutcome::Committed)
                if partition == &p
                    && b.writes
                        .iter()
                        .any(|w| matches!(w, Write::Put(k, _) if *k == keys::ticket(&id))) =>
            {
                Some(b)
            }
            _ => None,
        })
        .unwrap();
    assert!(
        batch
            .writes
            .iter()
            .any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(b"o\0")))
    );
    assert!(
        batch
            .writes
            .iter()
            .any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(b"q\0")))
    );
    if mode.sharding == Sharding::D34 {
        assert!(
            batch
                .preconditions
                .iter()
                .any(|p| matches!(p, Precondition::Absent(k) | Precondition::Equals(k, _) if *k == keys::epoch_lease()))
        );
        assert!(
            batch
                .preconditions
                .iter()
                .any(|p| matches!(p, Precondition::NotAfter(deadline) if *deadline <= 25_000))
        );
    }
    // Membership never supersedes an authorized live ticket, even if admission would challenge.
    store
        .inner
        .apply(
            &p,
            Batch::new().put(
                keys::membership(&a.repo().repo.name, &PACK),
                Value::default(),
            ),
        )
        .await
        .unwrap();
    spy.admissions.store(0, Ordering::SeqCst);
    spy.rejection.store(2, Ordering::SeqCst);
    let repeated = auth(&pipe, mode, 1, Procedure::BeginUpload);
    assert_eq!(
        pipe.begin_upload(&repeated, REF, &PACK, BYTES)
            .await
            .unwrap(),
        first
    );
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(
        replay(&store, mode, &repeated).await,
        Some(StoredResult::BeginUpload(first.clone()))
    );
    let different_bytes = auth(&pipe, mode, 1, Procedure::BeginUpload);
    assert_eq!(
        pipe.begin_upload(&different_bytes, REF, &PACK, BYTES + 1)
            .await
            .unwrap(),
        first
    );
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(
        replay(&store, mode, &different_bytes).await,
        Some(StoredResult::BeginUpload(first.clone()))
    );
    let repeated_calls = store.take();
    assert!(repeated_calls.iter().all(|c| match c {
        Call::Apply(_, b, _) => !b.writes.iter().any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(b"t\0") || k.as_bytes().starts_with(b"o\0"))), Call::Many(_) => true,
    }));
    store
        .inner
        .apply(
            &p,
            Batch::new().delete(keys::membership(&a.repo().repo.name, &PACK)),
        )
        .await
        .unwrap();
    spy.rejection.store(0, Ordering::SeqCst);
    let other = auth(&pipe, mode, 2, Procedure::BeginUpload);
    let second = pipe.begin_upload(&other, REF, &PACK, BYTES).await.unwrap();
    assert_ne!(ticket_id(&second), id);
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 1);
    // Replay keeps the exact token after consumption has removed the ticket row.
    store
        .inner
        .apply(&p, Batch::new().delete(keys::ticket(&id)))
        .await
        .unwrap();
    spy.admissions.store(0, Ordering::SeqCst);
    store.take();
    assert_eq!(
        pipe.begin_upload(&a, REF, &PACK, BYTES).await.unwrap(),
        first
    );
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    no_writes(&store.take());
}

async fn present<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        spy.clone(),
        config(mode),
        clock.clone(),
    );
    let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let pack = mkit_core::hash::hash(b"present pack");
    if mode.multi {
        store
            .inner
            .apply(
                &mode.partition(&a, REF),
                Batch::new().put(
                    keys::membership(&a.repo().repo.name, &pack),
                    Value::default(),
                ),
            )
            .await
            .unwrap();
    } else {
        let mut sink = blobs
            .begin(PackKey::from_hash(pack).into(), 12)
            .await
            .unwrap();
        sink.write(Bytes::from_static(b"present pack"))
            .await
            .unwrap();
        sink.commit().await.unwrap();
    }
    spy.rejection.store(2, Ordering::SeqCst);
    assert_eq!(
        pipe.begin_upload(&a, REF, &pack, BYTES).await.unwrap(),
        BeginUploadResult::AlreadyPresent
    );
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    assert_eq!(
        replay(&store, mode, &a).await,
        Some(StoredResult::BeginUpload(BeginUploadResult::AlreadyPresent))
    );
    assert!(store.take().iter().all(|c| match c { Call::Apply(_, b, _) => !b.writes.iter().any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(b"t\0") || k.as_bytes().starts_with(b"o\0") || k.as_bytes().starts_with(b"q\0"))), Call::Many(_) => true }));
}

async fn caps<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        config(mode),
        clock,
    );
    for per_ref in [true, false] {
        let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
        let p = mode.partition(&a, REF);
        let counter = if per_ref {
            keys::tickets_per_ref(&a.repo().repo.name, REF).unwrap()
        } else {
            keys::tickets_per_signer(&a.repo().repo.name, REF, &a.auth.as_ref().unwrap().signer)
                .unwrap()
        };
        let cap = if per_ref { 1024 } else { 64 };
        store
            .inner
            .apply(
                &p,
                Batch::new().put(counter.clone(), codec::encode_u64(cap)),
            )
            .await
            .unwrap();
        store.take();
        let err = pipe.begin_upload(&a, REF, &PACK, BYTES).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.public_message(), CAP_MESSAGE);
        assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
        no_writes(&store.take());
        assert_eq!(replay(&store, mode, &a).await, None);
        store
            .inner
            .apply(&p, Batch::new().delete(counter))
            .await
            .unwrap();
    }
}

async fn expired_ticket_keeps_cap_slot<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let mut cfg = config(mode);
    cfg.ticket_caps.per_ref = 1;
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        cfg,
        clock.clone(),
    );
    let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
    assert!(matches!(
        pipe.begin_upload(&a, REF, &PACK, BYTES).await.unwrap(),
        BeginUploadResult::Ticket { .. }
    ));
    clock.set(i64::try_from(TTL).unwrap());
    store.take();
    spy.admissions.store(0, Ordering::SeqCst);
    let next = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let error = pipe
        .begin_upload(&next, REF, &[8; 32], BYTES)
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::FailedPrecondition);
    assert_eq!(error.public_message(), CAP_MESSAGE);
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    no_writes(&store.take());
    assert_eq!(replay(&store, mode, &next).await, None);
}

async fn rejected<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        config(mode),
        clock,
    );
    // Cold and already-created repositories both allocate nothing on denial/challenge.
    for existing in [false, true] {
        if existing {
            spy.rejection.store(0, Ordering::SeqCst);
            warm(&pipe, mode).await;
        }
        for rejection in [1, 2, 3] {
            spy.rejection.store(rejection, Ordering::SeqCst);
            let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
            store.take();
            assert_eq!(
                pipe.begin_upload(&a, "refs/heads/rejected", &PACK, BYTES)
                    .await
                    .unwrap_err()
                    .code(),
                Code::PermissionDenied
            );
            no_writes(&store.take());
            let p = mode.partition(&a, "refs/heads/rejected");
            assert!(
                store
                    .inner
                    .get(&p, &keys::replay(&a.auth.as_ref().unwrap().replay_scope))
                    .await
                    .unwrap()
                    .is_none()
            );
            if mode.sharding == Sharding::D34 {
                assert!(
                    store
                        .inner
                        .get(&p, &keys::epoch_lease())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
}

async fn validation<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        config(mode),
        clock.clone(),
    );
    let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
    for (name, pack, bytes) in [
        ("refs/mkit/packmap/main", PACK.as_slice(), BYTES),
        ("not-a-ref", PACK.as_slice(), BYTES),
        (REF, &[1; 31], BYTES),
        (REF, PACK.as_slice(), 0),
        (REF, PACK.as_slice(), 1025),
    ] {
        assert_eq!(
            pipe.begin_upload(&a, name, pack, bytes)
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
    if mode.sharding == Sharding::D34 {
        assert_eq!(
            pipe.begin_upload(&a, "refs/tags/tag", &PACK, BYTES)
                .await
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
    }
    assert!(
        store.take().is_empty(),
        "validation must precede metadata reads"
    );
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 0);
    let mut cfg = config(mode);
    cfg.ticket_keys = None;
    let defaults = Hooks::new();
    let disabled = Pipeline::new(
        MemoryBlobStore::default(),
        store.clone(),
        Hooks {
            authorizer: Policy(spy.clone()),
            admission: Policy(spy),
            pre_receive: defaults.pre_receive,
            receipts: defaults.receipts,
            outcomes: defaults.outcomes,
        },
        cfg,
        clock,
        Arc::new(NoopMetrics),
    );
    let error = disabled.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.public_message(),
        "admission requires auth v2 and upload ticket keys"
    );
    assert!(store.take().is_empty());
    // Under multi addressing a keyless auth v2 deployment is refused at
    // startup, so "upload tickets are not configured" exists only for
    // single ones.
    if !mode.multi {
        let mut cfg = config(mode);
        cfg.ticket_keys = None;
        cfg.authorizer_role = AuthorizerRole::Check;
        let disabled = Pipeline::new(
            MemoryBlobStore::default(),
            store.clone(),
            Hooks::new(),
            cfg,
            Arc::new(ManualClock::new(0)),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let a = auth(&disabled, mode, 1, Procedure::BeginUpload);
        let error = disabled
            .begin_upload(&a, REF, &PACK, BYTES)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unimplemented);
        assert_eq!(error.public_message(), "upload tickets are not configured");
        assert!(store.take().is_empty());
    }
}

async fn race<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
    reserved: bool,
    cap: bool,
    same_nonce: bool,
) {
    let _ = race_with_bytes(backend, clock, mode, reserved, cap, same_nonce, BYTES).await;
}

#[allow(clippy::too_many_lines)] // The barrier and both race outcomes form one scenario.
async fn race_with_bytes<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
    reserved: bool,
    cap: bool,
    same_nonce: bool,
    bytes: u64,
) -> bool {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    let mut cfg = config(mode);
    if cap {
        cfg.ticket_caps.per_ref = 1;
    }
    cfg.upload_limits.max_total_bytes = bytes;
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(store.clone(), blobs.clone(), spy.clone(), cfg, clock);
    warm(&pipe, mode).await;
    spy.reservation
        .store(usize::from(reserved), Ordering::SeqCst);
    spy.admissions.store(0, Ordering::SeqCst);
    store.take();
    store.arm_race();
    let a = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let b = if same_nonce {
        a.clone()
    } else {
        auth(&pipe, mode, 1, Procedure::BeginUpload)
    };
    let first_pipe = pipe.clone();
    let second_pipe = pipe.clone();
    let a_copy = a.clone();
    let b_copy = b.clone();
    let second_pack = if cap { [8; 32] } else { PACK };
    let one =
        tokio::spawn(async move { first_pipe.begin_upload(&a_copy, REF, &PACK, bytes).await });
    let two = tokio::spawn(async move {
        second_pipe
            .begin_upload(&b_copy, REF, &second_pack, bytes)
            .await
    });
    let (one, two) = tokio::time::timeout(Duration::from_secs(10), async {
        (one.await.unwrap(), two.await.unwrap())
    })
    .await
    .unwrap();
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 2);
    let (winner, loser, loser_auth) = match one {
        Ok(winner) => (winner, two, &b),
        Err(error) => (two.unwrap(), Err(error), &a),
    };
    if same_nonce && reserved {
        assert_eq!(loser.unwrap_err().code(), Code::Aborted);
        assert_eq!(
            replay(&store, mode, &a).await,
            Some(StoredResult::BeginUpload(winner))
        );
    } else if same_nonce {
        assert_eq!(loser.unwrap(), winner);
        assert_eq!(
            replay(&store, mode, &a).await,
            Some(StoredResult::BeginUpload(winner))
        );
    } else if reserved && cap {
        let error = loser.unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.public_message(), CAP_MESSAGE);
        assert_eq!(replay(&store, mode, loser_auth).await, None);
    } else if reserved {
        let error = loser.unwrap_err();
        assert_eq!(error.code(), Code::Aborted);
        assert_eq!(error.public_message(), "upload ticket race");
        assert!(error.code().is_retryable());
        assert_eq!(replay(&store, mode, loser_auth).await, None);
    } else if cap {
        let error = loser.unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
        assert_eq!(error.public_message(), CAP_MESSAGE);
        assert!(matches!(
            replay(&store, mode, loser_auth).await,
            Some(StoredResult::Rejected(_))
        ));
    } else {
        assert_eq!(loser.unwrap(), winner);
    }
    let p = mode.partition(&a, REF);
    if reserved {
        let (start, end) = keys::class_range(keys::TAG_RESERVATION);
        let rows = store
            .inner
            .scan(&p, &start, &end, None, 100)
            .await
            .unwrap()
            .entries;
        let aborts: Vec<_> = rows
            .iter()
            .filter_map(|(_, raw)| match codec::decode_reservation(raw).unwrap() {
                codec::ReservationV1::Aborted { reason, .. } => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(aborts.len(), 1);
        assert_eq!(
            aborts[0],
            if cap {
                codec::AbortReason::Unspecified
            } else {
                codec::AbortReason::ReplayRace
            }
        );
    }
    assert_eq!(
        codec::decode_u64(
            &store
                .inner
                .get(
                    &p,
                    &keys::tickets_per_ref(&a.repo().repo.name, REF).unwrap()
                )
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        1
    );
    let scope = QuotaScope::for_signer(&a.repo().repo.namespace, &a.auth.as_ref().unwrap().signer);
    let quota = codec::decode_quota_state(
        &store
            .inner
            .get(&p, &keys::quota(&scope))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    // The warm-up costs one op; synthetic races charge both admitted writes.
    assert_eq!(quota.ops, if reserved || same_nonce { 2 } else { 3 });
    assert_eq!(
        quota.bytes,
        if reserved || same_nonce {
            bytes
        } else {
            bytes * 2
        }
    );
    let calls = store.take();
    if !same_nonce {
        assert!(
            calls.iter().any(|c| matches!(
                c,
                Call::Apply(_, _, BatchOutcome::PreconditionFailed { .. })
            )),
            "barrier did not force a write race"
        );
    }
    let ticket_batches = calls.iter().filter(|c| matches!(c, Call::Apply(_, b, BatchOutcome::Committed) if b.writes.iter().any(|w| matches!(w, Write::Put(k, _) if k.as_bytes().starts_with(b"t\0"))))).count();
    assert_eq!(ticket_batches, 1);
    if bytes <= MIN_PART_SIZE {
        return true;
    }
    let plan = PartPlan::new(bytes, MIN_PART_SIZE, u32::MAX).unwrap();
    let mut active = 0;
    for id in [0_u64, 1] {
        match blobs
            .begin_part(BlobKey::pack(PACK), &id.to_be_bytes(), &plan, 0, [0; 32])
            .await
        {
            Ok(_) => active += 1,
            Err(StoreError::SessionGone) => {}
            Err(err) => panic!("unexpected part-session probe error: {err}"),
        }
    }
    active == 1
}
#[tokio::test]
async fn multipart_existing_race_aborts_losing_session() {
    let clock = Arc::new(ManualClock::new(0));
    let losing_session_was_aborted = Box::pin(race_with_bytes(
        MemoryKv::with_clock(clock.clone()),
        clock,
        MODES[0],
        true,
        false,
        false,
        MIN_PART_SIZE + 1,
    ))
    .await;
    assert!(losing_session_was_aborted);
}

/// The first `BeginUpload` pauses before its final apply (it will win); the
/// second fails there at once, so its cleanup runs while the winner's ticket
/// is not yet committed.
#[cfg(feature = "test-faults")]
struct FailFirstBegin {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

#[cfg(feature = "test-faults")]
struct FailFirstBeginHook(Arc<FailFirstBegin>);

#[cfg(feature = "test-faults")]
impl FaultHooks for FailFirstBeginHook {
    async fn at(
        &self,
        point: FaultPoint,
        op: &Operation,
        _: &TestDirectives,
    ) -> Result<(), ServerError> {
        if point == FaultPoint::BeforeFinalApply && op.procedure() == Procedure::BeginUpload {
            match self.0.calls.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    self.0.entered.notify_one();
                    self.0.release.notified().await;
                }
                1 => return Err(ServerError::aborted_retryable("test losing begin")),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(feature = "test-faults")]
#[tokio::test]
async fn fs_begin_race_loser_preserves_winning_session() {
    let dir = tempfile::tempdir().unwrap();
    let blobs = FsBlobStore::new(dir.path());
    let clock = Arc::new(ManualClock::new(0));
    let mode = MODES[0];
    let defaults = Hooks::new();
    let spy = Arc::new(Spy::default());
    let mut cfg = config(mode);
    cfg.upload_limits.max_total_bytes = MIN_PART_SIZE + 1;
    let fault = Arc::new(FailFirstBegin {
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let pipe = Arc::new(
        Pipeline::new(
            blobs.clone(),
            Store::new(MemoryKv::with_clock(clock.clone())),
            Hooks {
                authorizer: Policy(spy.clone()),
                admission: Policy(spy),
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            },
            cfg,
            clock,
            Arc::new(NoopMetrics),
        )
        .unwrap()
        .with_faults(FailFirstBeginHook(fault.clone())),
    );
    let authenticated = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let first = {
        let pipe = pipe.clone();
        let authenticated = authenticated.clone();
        tokio::spawn(async move {
            pipe.begin_upload(&authenticated, REF, &PACK, MIN_PART_SIZE + 1)
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), fault.entered.notified())
        .await
        .unwrap();
    // The loser fails and cleans up while the winner's ticket is uncommitted.
    let loser = pipe
        .begin_upload(&authenticated, REF, &PACK, MIN_PART_SIZE + 1)
        .await
        .unwrap_err();
    assert_eq!(loser.code(), Code::Aborted);
    fault.release.notify_one();
    let winner = first.await.unwrap().unwrap();
    let plan = PartPlan::new(MIN_PART_SIZE + 1, MIN_PART_SIZE, u32::MAX).unwrap();
    let id = ticket_id(&winner);
    blobs
        .begin_part(BlobKey::pack(PACK), &id, &plan, 0, [0; 32])
        .await
        .unwrap();
}
macro_rules! backends {
    ($memory:ident, $sqlite:ident, $scenario:ident $(, $arg:expr)*) => {
        #[tokio::test]
        async fn $memory() {
            for mode in MODES {
                let clock = Arc::new(ManualClock::new(0));
                $scenario(MemoryKv::with_clock(clock.clone()), clock, mode $(, $arg)*).await;
            }
        }
        #[tokio::test]
        async fn $sqlite() {
            for mode in MODES {
                let clock = Arc::new(ManualClock::new(0));
                let dir = tempfile::tempdir().unwrap();
                let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap().with_clock(clock.clone());
                $scenario(Blocking::new(SqlKvStore::open(conn).unwrap()), clock, mode $(, $arg)*).await;
            }
        }
    };
}
backends!(lifecycle_memory, lifecycle_sqlite, lifecycle);

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn indexed_sqlite_verified_pack_reuse_rechecks_current_closure() {
    let mode = Mode {
        multi: true,
        sharding: Sharding::Single,
    };
    let clock = Arc::new(ManualClock::new(0));
    let conn = RusqliteConn::open_in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let store = Store::new(Blocking::new(SqlKvStore::open(conn).unwrap()));
    let mut cfg = config(mode);
    cfg.ticket_ttl_ms = 120_000;
    cfg.indexed = Some(IndexedConfig::default());
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        Arc::new(Spy::default()),
        cfg,
        clock.clone(),
    );

    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut first = PackWriter::new_raw_only();
    first.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    let mut second = PackWriter::new_raw_only();
    second
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    let packs = [first.finish().unwrap(), second.finish().unwrap()];

    let mut tickets = Vec::new();
    for pack in &packs {
        let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
        let BeginUploadResult::Ticket { id, token, .. } = pipe
            .begin_upload(&begin, REF, &hash(pack), pack.len() as u64)
            .await
            .unwrap()
        else {
            panic!("expected ticket");
        };
        Box::pin(upload_ticket(&pipe, mode, pack, &token)).await;
        tickets.push(id);
    }
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let partition = mode.partition(&advance, REF);
    let repo = advance.repo().repo.clone();
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Match([0x5a; 32]), head),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                hash(&packs[1])
            ),
            tickets.clone(),
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::HeadConflict
    );
    for pack in &packs {
        let raw = store
            .inner
            .get(&partition, &keys::verification(&repo.name, &hash(pack)))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            state::decode(&raw).unwrap(),
            state::VerificationV1::Verified { .. }
        ));
    }
    assert!(
        store
            .inner
            .get(&partition, &keys::ref_key(&repo.name, REF))
            .await
            .unwrap()
            .is_none()
    );

    clock.advance(i64::try_from(IndexedConfig::default().relay_lag_bound_ms).unwrap());
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let error = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, head),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                hash(&packs[0]),
            ),
            vec![tickets[0]],
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(error.public_message(), "open closure");
    for key in [
        keys::ref_key(&repo.name, REF),
        keys::ref_key(&repo.name, "refs/mkit/packmap/main"),
        keys::membership(&repo.name, &hash(&packs[0])),
        keys::membership(&repo.name, &hash(&packs[1])),
    ] {
        assert!(store.inner.get(&partition, &key).await.unwrap().is_none());
    }

    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, head),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                hash(&packs[1])
            ),
            tickets,
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    assert!(
        store
            .inner
            .get(&partition, &keys::ref_key(&repo.name, REF))
            .await
            .unwrap()
            .is_some()
    );
}

/// An indexed push of a 1.2 MiB file lands in the global object store at
/// `objects/<id>` with the file's exact length, and only after the pack
/// verified (WP-4.10, SPEC-SERVER §9.6).
#[tokio::test]
#[allow(clippy::too_many_lines)] // One push checks the file, the pack and the namespaces.
async fn indexed_push_extracts_a_large_file_to_the_object_store() {
    let mode = Mode {
        multi: true,
        sharding: Sharding::Single,
    };
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(0));
    let conn = RusqliteConn::open_in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let store = Store::new(Blocking::new(SqlKvStore::open(conn).unwrap()));
    let mut cfg = config(mode);
    cfg.ticket_ttl_ms = 120_000;
    cfg.upload_limits.max_total_bytes = 4 << 20;
    cfg.indexed = Some(IndexedConfig::default());
    let spy = Arc::new(Spy::default());
    let defaults = Hooks::new();
    let pipe = Arc::new(
        Pipeline::new(
            FsBlobStore::new(dir.path()),
            store.clone(),
            Hooks {
                authorizer: Policy(spy.clone()),
                admission: Policy(spy),
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            },
            cfg,
            clock.clone(),
            Arc::new(NoopMetrics),
        )
        .unwrap(),
    );

    let file: Vec<u8> = (0..(1_u32 << 20)).map(|i| (i % 251) as u8).collect();
    let blob = Object::Blob(mkit_core::object::Blob { data: file.clone() });
    let blob_id = blob.id().unwrap();
    let tree = Object::Tree(Tree {
        entries: vec![mkit_core::object::TreeEntry {
            name: b"big.bin".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: blob_id,
        }],
    });
    let tree_id = tree.id().unwrap();
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"large file".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer).unwrap().0;
    let commit = Object::Commit(commit);
    let head = commit.id().unwrap();
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(blob_id, &serialize(&blob).unwrap())
        .unwrap();
    writer
        .push_raw(tree_id, &serialize(&tree).unwrap())
        .unwrap();
    writer.push_raw(head, &serialize(&commit).unwrap()).unwrap();
    let pack = writer.finish().unwrap();

    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let BeginUploadResult::Ticket { id, token, .. } = pipe
        .begin_upload(&begin, REF, &hash(&pack), pack.len() as u64)
        .await
        .unwrap()
    else {
        panic!("expected ticket");
    };
    Box::pin(upload_ticket(&pipe, mode, &pack, &token)).await;
    let object_path = dir.path().join("objects").join(to_hex(&blob_id));
    assert!(
        !object_path.exists(),
        "nothing is extracted before the advance"
    );
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let outcome = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, head),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                hash(&pack),
            ),
            vec![id],
        )
        .await
        .unwrap();
    assert_eq!(outcome, mkit_core::protocol::AdvanceOutcome::Committed);
    assert_eq!(std::fs::read(&object_path).unwrap(), file);
    // Only the file is extracted; the pack stays a pack and is not served
    // from the object namespace.
    let extracted: Vec<_> = std::fs::read_dir(dir.path().join("objects"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(extracted, [std::ffi::OsString::from(to_hex(&blob_id))]);
    assert!(dir.path().join("packs").join(to_hex(&hash(&pack))).exists());
    assert!(!dir.path().join("packs").join(to_hex(&blob_id)).exists());
}

fn upload_auth<B: MultipartBlobStore, N: NamespaceStore>(
    pipe: &Pipeline<B, Store<N>, Hooks<Policy, Policy>>,
    mode: Mode,
    pack: &[u8],
) -> Authenticated {
    let signer = Signer::new([1; 32], AUDIENCE, &mode.identity());
    let mut envelope = signer.envelope(
        Procedure::UploadPack.connect_path(),
        pack_commitment(&hash(pack), pack.len() as u64),
    );
    envelope.created_at = 0;
    envelope.expires_at = 240_000;
    let carriage = signer.sign(&envelope);
    pipe.authenticate(&RequestMeta {
        procedure: Procedure::UploadPack,
        header: &|h| {
            carriage
                .headers
                .iter()
                .find(|(name, _)| name == h)
                .map(|(_, v)| v.clone())
        },
        header_values: None,
        unary_body: None,
        transport_principal: None,
    })
    .unwrap()
}

async fn upload_ticket<B: MultipartBlobStore, N: NamespaceStore>(
    pipe: &Pipeline<B, Store<N>, Hooks<Policy, Policy>>,
    mode: Mode,
    pack: &[u8],
    token: &[u8],
) {
    let id = hash(pack);
    let a = upload_auth(pipe, mode, pack);
    let mut session = pipe
        .open_ticketed_upload(&a, Some(&id), Some(pack.len() as u64), token)
        .await
        .unwrap();
    session
        .push(Some(&id), Some(0), Bytes::copy_from_slice(pack), true)
        .await
        .unwrap();
    session.finish().await.unwrap();
}

#[allow(clippy::too_many_lines)] // One lifecycle checks outcomes, counters, relay and repo isolation.
async fn advance_flow<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const PACK_A: &[u8; 32] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PACK_B: &[u8; 32] = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"; // opaque MKPL node
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let spy = Arc::new(Spy::default());
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        spy.clone(),
        config(mode),
        clock.clone(),
    );
    let mut ids = Vec::new();
    let mut reservations = Vec::new();
    for (index, pack) in [PACK_A.as_slice(), PACK_B.as_slice()]
        .into_iter()
        .enumerate()
    {
        // Exercise both synthetic `s:` and admission-supplied reservations.
        spy.reservation.store(index, Ordering::SeqCst);
        let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
        let result = pipe
            .begin_upload(&begin, REF, &hash(pack), pack.len() as u64)
            .await
            .unwrap();
        let id = ticket_id(&result);
        let raw = store
            .inner
            .get(&mode.partition(&begin, REF), &keys::ticket(&id))
            .await
            .unwrap()
            .unwrap();
        reservations.push(codec::decode_ticket(&raw).unwrap().reservation_id);
        let BeginUploadResult::Ticket { token, .. } = result else {
            panic!("expected ticket")
        };
        Box::pin(upload_ticket(&pipe, mode, pack, &token)).await;
        ids.push(id);
    }
    spy.reservation.store(0, Ordering::SeqCst);
    assert!(reservations[0].starts_with("s:"));
    assert!(reservations[1].starts_with("admission-"));
    let admissions = spy.admissions.load(Ordering::SeqCst);
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let result = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            ids.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result, mkit_core::protocol::AdvanceOutcome::Committed);
    assert_eq!(spy.admissions.load(Ordering::SeqCst), admissions);
    let partition = mode.partition(&advance, REF);
    for (id, rid) in ids.iter().zip(&reservations) {
        assert!(
            store
                .inner
                .get(&partition, &keys::ticket(id))
                .await
                .unwrap()
                .is_none()
        );
        let row = store
            .inner
            .get(&partition, &keys::reservation(rid).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            codec::decode_reservation(&row).unwrap(),
            codec::ReservationV1::Committed {
                bytes_stored: 32,
                ..
            }
        ));
        assert!(
            store
                .inner
                .get(
                    &partition,
                    &keys::ticket_index(
                        &advance.repo().repo.name,
                        REF,
                        &hash(if id == &ids[0] {
                            PACK_A.as_slice()
                        } else {
                            PACK_B.as_slice()
                        }),
                        &advance.auth.as_ref().unwrap().signer
                    )
                    .unwrap()
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .inner
                .get(
                    &partition,
                    &keys::timer(TTL, kinds::TICKET_EXPIRY.get(), id)
                )
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .inner
                .get(
                    &partition,
                    &keys::membership(
                        &advance.repo().repo.name,
                        &hash(if id == &ids[0] {
                            PACK_A.as_slice()
                        } else {
                            PACK_B.as_slice()
                        })
                    )
                )
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        store
            .inner
            .get(
                &partition,
                &keys::tickets_per_ref(&advance.repo().repo.name, REF).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    let backlog = store
        .inner
        .get(&partition, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 2);
    for (i, rid) in reservations.iter().enumerate() {
        assert!(
            store
                .inner
                .get(
                    &partition,
                    &keys::outcome_pending((i + 1) as u64, rid).unwrap()
                )
                .await
                .unwrap()
                .is_some()
        );
    }
    assert!(
        store
            .inner
            .get(
                &partition,
                &keys::tickets_per_signer(
                    &advance.repo().repo.name,
                    REF,
                    &advance.auth.as_ref().unwrap().signer
                )
                .unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    if mode.multi {
        let other_begin = auth_other_repo(&pipe, mode, Procedure::BeginUpload);
        pipe.begin_upload(&other_begin, REF, &hash(b"other repo seed"), 32)
            .await
            .unwrap();
        let other_exists = auth_other_repo(&pipe, mode, Procedure::PackExists);
        assert!(
            !pipe
                .pack_exists(&other_exists, PackKey::new(hash(PACK_A)))
                .await
                .unwrap()
        );
        let other_download = auth_other_repo(&pipe, mode, Procedure::DownloadPack);
        assert_eq!(
            pipe.download(&other_download, PackKey::new(hash(PACK_A)))
                .await
                .unwrap_err()
                .code(),
            Code::NotFound
        );
    }
    if mode.sharding == Sharding::D34 {
        let registry = TimerRegistry::new().register(RelayHandler {
            target: store.clone(),
            hook: NoHook,
            budget: RelayBudget::default(),
        });
        run_due(
            &store,
            &partition,
            &registry,
            clock.as_ref(),
            0,
            &TickBudget::default(),
        )
        .await
        .unwrap();
        for pack in [PACK_A.as_slice(), PACK_B.as_slice()] {
            let id = hash(pack);
            let target =
                D34Shards.membership(&advance.repo().repo, &mkit_server::store::BlobKey::pack(id));
            assert!(
                store
                    .inner
                    .get(&target, &keys::membership(&advance.repo().repo.name, &id))
                    .await
                    .unwrap()
                    .is_some()
            );
            assert!(
                mkit_server::store::read::is_member(
                    &store,
                    &D34Shards,
                    &advance.repo().repo,
                    &id,
                    None
                )
                .await
                .unwrap()
            );
            assert!(
                mkit_server::store::read::is_member(
                    &store,
                    &D34Shards,
                    &advance.repo().repo,
                    &id,
                    Some(REF)
                )
                .await
                .unwrap()
            );
        }
    }
    let later = auth(&pipe, mode, 1, Procedure::BeginUpload);
    assert!(matches!(
        pipe.begin_upload(&later, REF, &hash(PACK_A), 32)
            .await
            .unwrap(),
        BeginUploadResult::AlreadyPresent
    ));
}

backends!(advance_flow_memory, advance_flow_sqlite, advance_flow);

async fn missing_pack_aborts<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    const PACK: &[u8; 32] = b"cccccccccccccccccccccccccccccccc";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let result = pipe
        .begin_upload(&begin, REF, &hash(PACK), 32)
        .await
        .unwrap();
    let id = ticket_id(&result);
    let raw = store
        .inner
        .get(&mode.partition(&begin, REF), &keys::ticket(&id))
        .await
        .unwrap()
        .unwrap();
    let rid = codec::decode_ticket(&raw).unwrap().reservation_id;
    let BeginUploadResult::Ticket { token, .. } = result else {
        panic!("expected ticket")
    };
    Box::pin(upload_ticket(&pipe, mode, PACK, &token)).await;
    assert!(
        blobs
            .delete(&mkit_server::store::BlobKey::pack(hash(PACK)))
            .await
            .unwrap()
    );
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![id],
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "upload not complete for ticket");
    let partition = mode.partition(&advance, REF);
    assert!(
        store
            .inner
            .get(&partition, &keys::ticket(&id))
            .await
            .unwrap()
            .is_none()
    );
    let row = store
        .inner
        .get(&partition, &keys::reservation(&rid).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&row).unwrap(),
        codec::ReservationV1::Aborted {
            reason: codec::AbortReason::PackMissing,
            ..
        }
    ));
    let abort_batch = store.take().into_iter().find_map(|call| match call {
        Call::Apply(_, batch, BatchOutcome::Committed)
            if batch.writes.iter().any(|w| matches!(w,
                Write::Put(k, v) if *k == keys::reservation(&rid).unwrap()
                    && matches!(codec::decode_reservation(v), Ok(codec::ReservationV1::Aborted { .. }))
            )) => Some(batch),
        _ => None,
    }).expect("separate abort batch");
    assert_eq!(abort_batch.preconditions[0], Precondition::NotAfter(10_000));
    let fresh = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let next = pipe
        .begin_upload(&fresh, REF, &hash(PACK), 32)
        .await
        .unwrap();
    assert_ne!(ticket_id(&next), id);
}

backends!(
    missing_pack_aborts_memory,
    missing_pack_aborts_sqlite,
    missing_pack_aborts
);

async fn mixed_incomplete<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    const LOST: &[u8; 32] = b"dddddddddddddddddddddddddddddddd";
    const NOT_UPLOADED: &[u8; 32] = b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let first = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let not_uploaded = pipe
        .begin_upload(&first, REF, &hash(NOT_UPLOADED), 32)
        .await
        .unwrap();
    let not_uploaded_id = ticket_id(&not_uploaded);
    let second = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let lost = pipe
        .begin_upload(&second, REF, &hash(LOST), 32)
        .await
        .unwrap();
    let lost_id = ticket_id(&lost);
    let BeginUploadResult::Ticket { token, .. } = lost else {
        panic!("expected ticket")
    };
    Box::pin(upload_ticket(&pipe, mode, LOST, &token)).await;
    blobs
        .delete(&mkit_server::store::BlobKey::pack(hash(LOST)))
        .await
        .unwrap();
    let first_advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let first_err = pipe
        .advance_refs_with_tickets(
            &first_advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![not_uploaded_id, lost_id],
        )
        .await
        .unwrap_err();
    assert_eq!(first_err.public_message(), "upload not complete for ticket");
    let p = mode.partition(&first_advance, REF);
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&lost_id))
            .await
            .unwrap()
            .is_some()
    );
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![lost_id, not_uploaded_id],
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "upload not complete for ticket");
    let p = mode.partition(&advance, REF);
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&not_uploaded_id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&lost_id))
            .await
            .unwrap()
            .is_none()
    );
}

backends!(
    mixed_incomplete_memory,
    mixed_incomplete_sqlite,
    mixed_incomplete
);

async fn marker_missing_precedes_expired<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let first = pipe
        .begin_upload(&begin, REF, &hash(b"first"), 32)
        .await
        .unwrap();
    let second_begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let second = pipe
        .begin_upload(&second_begin, REF, &hash(b"second"), 32)
        .await
        .unwrap();
    let ids = [ticket_id(&first), ticket_id(&second)];
    let p = mode.partition(&begin, REF);
    let key = keys::ticket(&ids[1]);
    let mut expired =
        codec::decode_ticket(&store.inner.get(&p, &key).await.unwrap().unwrap()).unwrap();
    expired.expires_at_ms = 0;
    assert_eq!(
        store
            .inner
            .apply(&p, Batch::new().put(key, codec::encode_ticket(&expired)))
            .await
            .unwrap(),
        BatchOutcome::Committed
    );
    // A D34 BeginUpload installed a lease. Remove it to prove this failure
    // never installs another one before the ticket decision.
    if mode.sharding == Sharding::D34 {
        store
            .inner
            .apply(&p, Batch::new().delete(keys::epoch_lease()))
            .await
            .unwrap();
    }
    store.take();
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            ids.to_vec(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "upload not complete for ticket");
    assert!(
        store
            .take()
            .iter()
            .all(|call| !matches!(call, Call::Apply(..)))
    );
    assert!(
        store
            .inner
            .get(
                &p,
                &keys::replay(&advance.auth.as_ref().unwrap().replay_scope)
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(&p, &keys::epoch_lease())
            .await
            .unwrap()
            .is_none()
    );
}

backends!(
    marker_missing_precedes_expired_memory,
    marker_missing_precedes_expired_sqlite,
    marker_missing_precedes_expired
);

async fn lost_pack_precedes_bad_row<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let lost = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let lost_id = ticket_id(&lost);
    let BeginUploadResult::Ticket { token, .. } = lost else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    blobs.delete(&BlobKey::pack(hash(DATA))).await.unwrap();
    let second_begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let bad = pipe
        .begin_upload(&second_begin, REF, &hash(b"bad row"), 32)
        .await
        .unwrap();
    let bad_id = ticket_id(&bad);
    let p = mode.partition(&begin, REF);
    let raw = store
        .inner
        .get(&p, &keys::ticket(&bad_id))
        .await
        .unwrap()
        .unwrap();
    let mut row = codec::decode_ticket(&raw).unwrap();
    row.expires_at_ms = 0;
    store
        .inner
        .apply(
            &p,
            Batch::new().put(keys::ticket(&bad_id), codec::encode_ticket(&row)),
        )
        .await
        .unwrap();
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![lost_id, bad_id],
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(err.public_message(), "upload not complete for ticket");
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&lost_id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&bad_id))
            .await
            .unwrap()
            .is_some()
    );
    let bad_outcome = store
        .inner
        .get(&p, &keys::reservation(&row.reservation_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&bad_outcome).unwrap(),
        codec::ReservationV1::Ticketed { .. }
    ));
    let backlog = store
        .inner
        .get(&p, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
}

backends!(
    lost_pack_precedes_bad_row_memory,
    lost_pack_precedes_bad_row_sqlite,
    lost_pack_precedes_bad_row
);

#[cfg(feature = "test-faults")]
async fn abort_deadline_is_unavailable<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(
        store.clone(),
        blobs.clone(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let opened = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&opened);
    let BeginUploadResult::Ticket { token, .. } = opened else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    blobs.delete(&BlobKey::pack(hash(DATA))).await.unwrap();
    store.controls.abort_deadline.store(true, Ordering::SeqCst);
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![id],
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(err.public_message(), "commit deadline passed; retry");
    let p = mode.partition(&advance, REF);
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&id))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .inner
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .is_none()
    );
}

#[cfg(feature = "test-faults")]
backends!(
    abort_deadline_is_unavailable_memory,
    abort_deadline_is_unavailable_sqlite,
    abort_deadline_is_unavailable
);

async fn direct_ref_reservations_fail_closed<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    let store = Store::new(backend);
    let spy = Arc::new(Spy::default());
    spy.reservation.store(1, Ordering::SeqCst);
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        spy.clone(),
        config(mode),
        clock,
    );
    let update = auth(&pipe, mode, 1, Procedure::UpdateRef);
    let result = pipe
        .update_ref(&update, upd(REF, RefWriteCondition::Missing, [3; 32]))
        .await
        .unwrap();
    assert!(matches!(result, mkit_server::UpdateRefResult::Committed));
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let result = pipe
        .advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32],
            ),
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(result, mkit_core::protocol::AdvanceOutcome::HeadConflict);
    assert_eq!(spy.admissions.load(Ordering::SeqCst), 2);
    let p = mode.partition(&advance, REF);
    assert!(
        store
            .inner
            .get(&p, &keys::ref_key(&advance.repo().repo.name, REF))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .inner
            .get(
                &p,
                &keys::ref_key(&advance.repo().repo.name, "refs/mkit/packmap/main")
            )
            .await
            .unwrap()
            .is_none()
    );
    for (rid, committed) in [("admission-0", true), ("admission-1", false)] {
        let row = codec::decode_reservation(
            &store
                .inner
                .get(&p, &keys::reservation(rid).unwrap())
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(if committed {
            matches!(row, codec::ReservationV1::Committed { .. })
        } else {
            matches!(
                row,
                codec::ReservationV1::Aborted {
                    reason: codec::AbortReason::RefConflict,
                    ..
                }
            )
        });
    }
    for a in [&update, &advance] {
        assert!(
            store
                .inner
                .get(&p, &keys::replay(&a.auth.as_ref().unwrap().replay_scope))
                .await
                .unwrap()
                .is_some()
        );
    }
}

backends!(
    direct_ref_reservations_fail_closed_memory,
    direct_ref_reservations_fail_closed_sqlite,
    direct_ref_reservations_fail_closed
);

async fn noncanonical_ticket_pair_is_invalid<N: NamespaceStore>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let a = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let err = pipe
        .advance_refs_with_tickets(
            &a,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd("refs/heads/other", RefWriteCondition::Missing, [4; 32]),
            vec![[1; 32]],
        )
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "ticketed advance requires a branch head and its packmap"
    );
    assert!(store.take().is_empty());
}

backends!(
    noncanonical_ticket_pair_memory,
    noncanonical_ticket_pair_sqlite,
    noncanonical_ticket_pair_is_invalid
);

#[cfg(feature = "test-faults")]
#[derive(Default)]
struct AdvancePause {
    armed: AtomicBool,
    pause_begin: AtomicBool,
    entered: Notify,
    release: Notify,
}

#[cfg(feature = "test-faults")]
struct PauseHook(Arc<AdvancePause>);

#[cfg(feature = "test-faults")]
impl FaultHooks for PauseHook {
    async fn at(
        &self,
        point: FaultPoint,
        op: &Operation,
        _: &TestDirectives,
    ) -> Result<(), ServerError> {
        if point == FaultPoint::BeforeFinalApply
            && (op.procedure() == Procedure::AdvanceRefs
                || (op.procedure() == Procedure::BeginUpload
                    && self.0.pause_begin.load(Ordering::SeqCst)))
            && self.0.armed.swap(false, Ordering::SeqCst)
        {
            self.0.entered.notify_one();
            self.0.release.notified().await;
        }
        Ok(())
    }
}

#[cfg(feature = "test-faults")]
fn paused_pipeline<N: NamespaceStore>(
    store: Store<N>,
    blobs: MemoryBlobStore,
    clock: Arc<ManualClock>,
    mode: Mode,
    pause: Arc<AdvancePause>,
) -> Arc<Pipe<N>> {
    let defaults = Hooks::new();
    let spy = Arc::new(Spy::default());
    Arc::new(
        Pipeline::new(
            blobs,
            store,
            Hooks {
                authorizer: Policy(spy.clone()),
                admission: Policy(spy),
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            },
            config(mode),
            clock,
            Arc::new(NoopMetrics),
        )
        .unwrap()
        .with_faults(PauseHook(pause)),
    )
}

#[cfg(feature = "test-faults")]
#[allow(clippy::too_many_lines)] // The paused and winning advances share a full setup and row assertions.
async fn consume_race<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
    same_nonce: bool,
) {
    const DATA: &[u8; 32] = b"ffffffffffffffffffffffffffffffff";
    let store = Store::new(backend);
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        clock,
        mode,
        pause.clone(),
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let ticket = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&ticket);
    let rid = codec::decode_ticket(
        &store
            .inner
            .get(&mode.partition(&begin, REF), &keys::ticket(&id))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .reservation_id;
    let BeginUploadResult::Ticket { token, .. } = ticket else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    let first_auth = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let second_auth = if same_nonce {
        first_auth.clone()
    } else {
        auth(&pipe, mode, 1, Procedure::AdvanceRefs)
    };
    pause.armed.store(true, Ordering::SeqCst);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move {
            pipe.advance_refs_with_tickets(
                &first_auth,
                upd(REF, RefWriteCondition::Missing, [3; 32]),
                upd(
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    [4; 32],
                ),
                vec![id],
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &second_auth,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32]
            ),
            vec![id],
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    pause.release.notify_one();
    let losing = blocked.await.unwrap();
    if same_nonce {
        assert_eq!(
            losing.unwrap(),
            mkit_core::protocol::AdvanceOutcome::Committed
        );
    } else {
        assert_eq!(losing.unwrap_err().code(), Code::FailedPrecondition);
    }
    let p = mode.partition(&second_auth, REF);
    assert!(matches!(
        codec::decode_reservation(
            &store
                .inner
                .get(&p, &keys::reservation(&rid).unwrap())
                .await
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        codec::ReservationV1::Committed { .. }
    ));
    let backlog = store
        .inner
        .get(&p, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
}

#[cfg(feature = "test-faults")]
backends!(
    consume_same_nonce_memory,
    consume_same_nonce_sqlite,
    consume_race,
    true
);
#[cfg(feature = "test-faults")]
backends!(
    consume_different_nonce_memory,
    consume_different_nonce_sqlite,
    consume_race,
    false
);

#[cfg(feature = "test-faults")]
async fn live_begin_races_consume<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii";
    let store = Store::new(backend);
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        clock,
        mode,
        pause.clone(),
    );
    let initial = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let ticket = pipe
        .begin_upload(&initial, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&ticket);
    let BeginUploadResult::Ticket { token, .. } = ticket else {
        unreachable!()
    };
    pause.pause_begin.store(true, Ordering::SeqCst);
    pause.armed.store(true, Ordering::SeqCst);
    let returning = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move { pipe.begin_upload(&returning, REF, &hash(DATA), 32).await })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32]
            ),
            vec![id],
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    pause.release.notify_one();
    let error = blocked.await.unwrap().unwrap_err();
    assert_eq!(error.code(), Code::Aborted);
    assert_eq!(error.public_message(), "upload ticket race");
}

#[cfg(feature = "test-faults")]
backends!(
    live_begin_races_consume_memory,
    live_begin_races_consume_sqlite,
    live_begin_races_consume
);

#[cfg(feature = "test-faults")]
async fn existing_begin_races_consume<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj";
    let store = Store::new(backend);
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        clock,
        mode,
        pause.clone(),
    );
    pause.pause_begin.store(true, Ordering::SeqCst);
    pause.armed.store(true, Ordering::SeqCst);
    let first_auth = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move { pipe.begin_upload(&first_auth, REF, &hash(DATA), 32).await })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    let second_auth = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let opened = pipe
        .begin_upload(&second_auth, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&opened);
    let BeginUploadResult::Ticket { token, .. } = opened else {
        unreachable!()
    };
    // The paused opener loses its first apply, then plans Existing on the
    // winner's row and pauses at its second BeforeFinalApply.
    pause.armed.store(true, Ordering::SeqCst);
    pause.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32]
            ),
            vec![id],
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    pause.release.notify_one();
    match blocked.await.unwrap() {
        Ok(BeginUploadResult::Ticket { id: answer, .. }) => assert_ne!(answer, id),
        Ok(BeginUploadResult::AlreadyPresent) => {}
        Err(error) => assert_eq!(error.code(), Code::Aborted),
    }
}

#[cfg(feature = "test-faults")]
backends!(
    existing_begin_races_consume_memory,
    existing_begin_races_consume_sqlite,
    existing_begin_races_consume
);

#[cfg(feature = "test-faults")]
async fn abort_races_consume<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"gggggggggggggggggggggggggggggggg";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(store.clone(), blobs.clone(), clock, mode, pause.clone());
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let ticket = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&ticket);
    let rid = codec::decode_ticket(
        &store
            .inner
            .get(&mode.partition(&begin, REF), &keys::ticket(&id))
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .reservation_id;
    let BeginUploadResult::Ticket { token, .. } = ticket else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    blobs
        .delete(&mkit_server::store::BlobKey::pack(hash(DATA)))
        .await
        .unwrap();
    store.arm_abort(pause.clone());
    let first_auth = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move {
            pipe.advance_refs_with_tickets(
                &first_auth,
                upd(REF, RefWriteCondition::Missing, [3; 32]),
                upd(
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    [4; 32],
                ),
                vec![id],
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    let consume = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &consume,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32]
            ),
            vec![id],
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    pause.release.notify_one();
    assert_eq!(
        blocked.await.unwrap().unwrap_err().code(),
        Code::FailedPrecondition
    );
    let p = mode.partition(&consume, REF);
    let row = store
        .inner
        .get(&p, &keys::reservation(&rid).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&row).unwrap(),
        codec::ReservationV1::Committed { .. }
    ));
    let backlog = store
        .inner
        .get(&p, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
}

#[cfg(feature = "test-faults")]
backends!(
    abort_races_consume_memory,
    abort_races_consume_sqlite,
    abort_races_consume
);

#[cfg(feature = "test-faults")]
async fn abort_race_replans_into_commit<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii";
    let store = Store::new(backend);
    let blobs = MemoryBlobStore::default();
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(store.clone(), blobs.clone(), clock, mode, pause.clone());
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let opened = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&opened);
    let BeginUploadResult::Ticket { token, .. } = opened else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    blobs.delete(&BlobKey::pack(hash(DATA))).await.unwrap();
    store.arm_abort(pause.clone());
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move {
            pipe.advance_refs_with_tickets(
                &advance,
                upd(REF, RefWriteCondition::Missing, [3; 32]),
                upd(
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    [4; 32],
                ),
                vec![id],
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    let p = mode.partition(&begin, REF);
    let key = keys::ticket(&id);
    let mut row = codec::decode_ticket(&store.inner.get(&p, &key).await.unwrap().unwrap()).unwrap();
    row.expires_at_ms += 1_000;
    store
        .inner
        .apply(&p, Batch::new().put(key, codec::encode_ticket(&row)))
        .await
        .unwrap();
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    pause.release.notify_one();
    assert_eq!(
        blocked.await.unwrap().unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    assert!(
        store
            .inner
            .get(&p, &keys::ticket(&id))
            .await
            .unwrap()
            .is_none()
    );
    let calls = store.take();
    assert!(calls.iter().any(|c| matches!(
        c,
        Call::Apply(_, _, BatchOutcome::PreconditionFailed { .. })
    )));
}

#[cfg(feature = "test-faults")]
backends!(
    abort_race_replans_into_commit_memory,
    abort_race_replans_into_commit_sqlite,
    abort_race_replans_into_commit
);

#[cfg(feature = "test-faults")]
#[allow(clippy::too_many_lines)] // Simulates the future expiry handler's guarded terminal batch.
async fn expired_close_races_consume<N: NamespaceStore + 'static>(
    backend: N,
    clock: Arc<ManualClock>,
    mode: Mode,
) {
    const DATA: &[u8; 32] = b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh";
    let store = Store::new(backend);
    let pause = Arc::new(AdvancePause::default());
    let pipe = paused_pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        clock.clone(),
        mode,
        pause.clone(),
    );
    let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
    let ticket = pipe
        .begin_upload(&begin, REF, &hash(DATA), 32)
        .await
        .unwrap();
    let id = ticket_id(&ticket);
    let BeginUploadResult::Ticket { token, .. } = ticket else {
        unreachable!()
    };
    Box::pin(upload_ticket(&pipe, mode, DATA, &token)).await;
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    let p = mode.partition(&advance, REF);
    let ticket_key = keys::ticket(&id);
    let raw = store.inner.get(&p, &ticket_key).await.unwrap().unwrap();
    let ticket = codec::decode_ticket(&raw).unwrap();
    pause.armed.store(true, Ordering::SeqCst);
    let blocked = {
        let pipe = pipe.clone();
        tokio::spawn(async move {
            pipe.advance_refs_with_tickets(
                &advance,
                upd(REF, RefWriteCondition::Missing, [3; 32]),
                upd(
                    "refs/mkit/packmap/main",
                    RefWriteCondition::Missing,
                    [4; 32],
                ),
                vec![id],
            )
            .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    clock.advance(i64::try_from(TTL).unwrap());
    let index = keys::ticket_index(
        &ticket.repo,
        &ticket.ref_name,
        &ticket.pack_id,
        &ticket.signer,
    )
    .unwrap();
    let tc = keys::tickets_per_ref(&ticket.repo, &ticket.ref_name).unwrap();
    let tu = keys::tickets_per_signer(&ticket.repo, &ticket.ref_name, &ticket.signer).unwrap();
    let mut batch = Batch::new();
    mkit_server::store::tickets::plan_ticket_close(
        &id,
        &ticket,
        &raw,
        store.inner.get(&p, &index).await.unwrap().as_ref(),
        store.inner.get(&p, &tc).await.unwrap().as_ref(),
        store.inner.get(&p, &tu).await.unwrap().as_ref(),
        mkit_server::store::tickets::CloseReason::Expired,
        &mut batch.preconditions,
        &mut batch.writes,
    )
    .unwrap();
    let reservation_key = keys::reservation(&ticket.reservation_id).unwrap();
    let prior = store
        .inner
        .get(&p, &reservation_key)
        .await
        .unwrap()
        .unwrap();
    let mut outbox = mkit_server::store::outbox::OutboxBuilder::new(
        store
            .inner
            .get(&p, &keys::outbox_sequence())
            .await
            .unwrap()
            .as_ref(),
        store
            .inner
            .get(&p, &keys::outcome_backlog())
            .await
            .unwrap()
            .as_ref(),
    )
    .unwrap();
    outbox.outcome(
        &ticket.reservation_id,
        &prior,
        mkit_server::store::outbox::Terminal::new(codec::ReservationV1::Expired {
            repository: mode.identity(),
            occurred_at_ms: TTL,
        })
        .unwrap(),
    );
    outbox
        .try_finish(&mut batch.preconditions, &mut batch.writes)
        .unwrap();
    assert_eq!(
        store.inner.apply(&p, batch).await.unwrap(),
        BatchOutcome::Committed
    );
    pause.release.notify_one();
    assert_eq!(
        blocked.await.unwrap().unwrap_err().code(),
        Code::FailedPrecondition
    );
    let row = store
        .inner
        .get(&p, &reservation_key)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        codec::decode_reservation(&row).unwrap(),
        codec::ReservationV1::Expired { .. }
    ));
    let backlog = store
        .inner
        .get(&p, &keys::outcome_backlog())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_backlog(&backlog).unwrap().rows, 1);
}

#[cfg(feature = "test-faults")]
backends!(
    expired_close_races_consume_memory,
    expired_close_races_consume_sqlite,
    expired_close_races_consume
);

async fn seven_tickets_commit<N: NamespaceStore>(backend: N, clock: Arc<ManualClock>, mode: Mode) {
    let store = Store::new(backend);
    let pipe = pipeline(
        store.clone(),
        MemoryBlobStore::default(),
        Arc::new(Spy::default()),
        config(mode),
        clock,
    );
    let mut ids = Vec::new();
    for n in 0_u8..7 {
        let data = [n + 20; 32];
        let begin = auth(&pipe, mode, 1, Procedure::BeginUpload);
        let ticket = pipe
            .begin_upload(&begin, REF, &hash(&data), 32)
            .await
            .unwrap();
        ids.push(ticket_id(&ticket));
        let BeginUploadResult::Ticket { token, .. } = ticket else {
            unreachable!()
        };
        Box::pin(upload_ticket(&pipe, mode, &data, &token)).await;
    }
    store.take();
    let advance = auth(&pipe, mode, 1, Procedure::AdvanceRefs);
    assert_eq!(
        pipe.advance_refs_with_tickets(
            &advance,
            upd(REF, RefWriteCondition::Missing, [3; 32]),
            upd(
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                [4; 32]
            ),
            ids,
        )
        .await
        .unwrap(),
        mkit_core::protocol::AdvanceOutcome::Committed
    );
    let calls = store.take();
    let batch = calls
        .iter()
        .find_map(|call| match call {
            Call::Apply(_, batch, BatchOutcome::Committed)
                if batch
                    .writes
                    .iter()
                    .filter(|w| matches!(w, Write::Delete(k) if k.as_bytes().starts_with(b"t\0")))
                    .count()
                    == 7 =>
            {
                Some(batch)
            }
            _ => None,
        })
        .expect("seven-ticket commit batch");
    batch.validate(&store.capabilities()).unwrap();
    assert!(batch.preconditions.len() + batch.writes.len() <= mkit_server::store::MAX_BATCH_OPS);
}

backends!(
    seven_tickets_commit_memory,
    seven_tickets_commit_sqlite,
    seven_tickets_commit
);

backends!(already_present_memory, already_present_sqlite, present);
backends!(caps_memory, caps_sqlite, caps);
backends!(
    expired_cap_slot_memory,
    expired_cap_slot_sqlite,
    expired_ticket_keeps_cap_slot
);
backends!(rejected_memory, rejected_sqlite, rejected);
backends!(validation_memory, validation_sqlite, validation);
backends!(
    race_synthetic_existing_memory,
    race_synthetic_existing_sqlite,
    race,
    false,
    false,
    false
);
backends!(
    race_reserved_existing_memory,
    race_reserved_existing_sqlite,
    race,
    true,
    false,
    false
);
backends!(
    race_synthetic_cap_memory,
    race_synthetic_cap_sqlite,
    race,
    false,
    true,
    false
);
backends!(
    race_reserved_cap_memory,
    race_reserved_cap_sqlite,
    race,
    true,
    true,
    false
);
backends!(
    race_same_nonce_memory,
    race_same_nonce_sqlite,
    race,
    false,
    false,
    true
);
backends!(
    race_same_nonce_reserved_memory,
    race_same_nonce_reserved_sqlite,
    race,
    true,
    false,
    true
);

#[tokio::test]
async fn unsupported_auth_modes_have_no_metadata_effects() {
    let mode = MODES[0];
    for auth_mode in [
        AuthMode::Open,
        AuthMode::Bearer {
            token: mkit_server::Redacted::new("test"),
        },
        AuthMode::TransportIdentity,
    ] {
        let store = Store::new(MemoryKv::default());
        let mut cfg = config(mode);
        cfg.auth = auth_mode;
        cfg.write_quota = None;
        cfg.authorizer_role = AuthorizerRole::Check;
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            store.clone(),
            Hooks::new(),
            cfg,
            Arc::new(ManualClock::new(0)),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let a = pipe
            .authenticate(&RequestMeta {
                procedure: Procedure::BeginUpload,
                header: &|h| (h == "authorization").then(|| "Bearer test".into()),
                header_values: None,
                unary_body: Some(BODY),
                transport_principal: Some(Principal::TransportPeer { ed25519: [1; 32] }),
            })
            .unwrap();
        let error = pipe.begin_upload(&a, REF, &PACK, BYTES).await.unwrap_err();
        assert_eq!(error.code(), Code::Unimplemented);
        assert_eq!(error.public_message(), "BeginUpload requires auth v2");
        assert!(store.take().is_empty());
    }
}

#[test]
fn invalid_ticket_limits_are_rejected_at_startup() {
    for mutation in 0..4 {
        let mut cfg = config(MODES[0]);
        match mutation {
            0 => cfg.ticket_ttl_ms = 0,
            1 => cfg.ticket_ttl_ms = 604_800_000,
            2 => cfg.ticket_caps.per_ref = 0,
            _ => cfg.ticket_caps.per_signer = 0,
        }
        let defaults = Hooks::new();
        let spy = Arc::new(Spy::default());
        let result = Pipeline::new(
            MemoryBlobStore::default(),
            Store::new(MemoryKv::default()),
            Hooks {
                authorizer: Policy(spy.clone()),
                admission: Policy(spy),
                pre_receive: defaults.pre_receive,
                receipts: defaults.receipts,
                outcomes: defaults.outcomes,
            },
            cfg,
            Arc::new(ManualClock::new(0)),
            Arc::new(NoopMetrics),
        );
        assert_eq!(
            result.unwrap_err().code(),
            Code::InvalidArgument,
            "mutation {mutation}"
        );
    }
}
