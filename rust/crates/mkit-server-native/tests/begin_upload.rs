//! `BeginUpload` admission, durable replay, caps and write races on both backends.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use mkit_core::hash::{hash, to_hex};
use mkit_core::protocol::{PackKey, RefWriteCondition};
use mkit_core::repo_identity::Namespace;
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authenticated, Authorizer, D34Shards,
    DefaultAdmission, Hooks, Pipeline, PipelineConfig, RequestMeta, ShardMap, Sharding,
    SinglePartition,
};
use mkit_server::policy::{AuthorizerRole, NamespacePolicy};
use mkit_server::quota::QuotaScope;
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, BlobKey, BlobStore, Cursor, Key, MultipartBlobStore, PackSink, Partition,
    PartitionStats, Precondition, ScanPage, StoreCapabilities, StoreError, Value, Write, codec,
    keys,
};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::{
    Addressing, AuthzFacts, BeginUploadResult, Code, ManualClock, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceKey, NamespaceStore, NoopMetrics, Operation, Principal, Procedure,
    RefUpdate, ReplayState, RepoId, RepoName, ServerError, StoredResult,
};
use mkit_server_conformance::wire::sign::{Signer, body_commitment};
use mkit_server_native::{Blocking, RusqliteConn};
use tokio::sync::Barrier;

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
            2 => Ok(AdmissionDecision::Challenge {
                challenges: vec![],
                description: "test challenge".into(),
            }),
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
fn auth<N: NamespaceStore, H: mkit_server::pipeline::HookSet>(
    pipe: &Pipeline<MemoryBlobStore, Store<N>, H>,
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
fn ticket_id(result: &BeginUploadResult) -> [u8; 32] {
    match result {
        BeginUploadResult::Ticket { id, .. } => *id,
        BeginUploadResult::AlreadyPresent => panic!("expected ticket, got {result:?}"),
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
            new: [1; 32],
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
        clock,
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
    spy.reservation
        .store(usize::from(reserved), Ordering::SeqCst);
    let mut cfg = config(mode);
    if cap {
        cfg.ticket_caps.per_ref = 1;
    }
    cfg.upload_limits.max_total_bytes = bytes;
    let blobs = MemoryBlobStore::default();
    let pipe = pipeline(store.clone(), blobs.clone(), spy.clone(), cfg, clock);
    warm(&pipe, mode).await;
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
    if same_nonce {
        assert_eq!(loser.unwrap(), winner);
        assert_eq!(
            replay(&store, mode, &a).await,
            Some(StoredResult::BeginUpload(winner))
        );
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
    let losing_session_was_aborted = race_with_bytes(
        MemoryKv::with_clock(clock.clone()),
        clock,
        MODES[0],
        true,
        false,
        false,
        MIN_PART_SIZE + 1,
    )
    .await;
    assert!(losing_session_was_aborted);
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
