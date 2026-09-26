//! Pipeline tests over the memory stores and a `ManualClock`.

use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ed25519_dalek::{Signer, SigningKey};
use futures_executor::block_on;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::refs::RefWriteCondition::{self, Any, Match, Missing};
use mkit_core::write_auth::{Context as AuthContext, Operation as SignedOp};
use proptest::prelude::*;

use super::plan::*;
use super::*;
use crate::auth_v2::AuthV2Config;
use crate::error::Code;
use crate::memory::{MemoryBlobStore, MemoryFault, MemoryKv};
use crate::op::VerifiedAuth;
use crate::principal::Principal;
use crate::quota::{QuotaScope, QuotaState};
use crate::replay::{ReplayKey, ReplayRecord, ReplayState};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::store::keys::LAYOUT_VERSION;
use crate::store::{
    Batch, Key, PartitionStats, Precondition, ScanPage, StoreCapabilities, Value, Write, codec,
    keys,
};

const AUDIENCE: &str = "https://api.example.test";
const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;
const WINDOW: u64 = 10_000;
const HEAD: &str = "refs/heads/main";
const PACKMAP: &str = "refs/mkit/packmap/main";
const A: Hash = [0xaa; 32];
const B: Hash = [0xbb; 32];
const C: Hash = [0xcc; 32];

// ---------------------------------------------------------------- helpers

/// Run a future that never waits (memory stores) to completion.
fn now<F: Future>(fut: F) -> F::Output {
    match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("memory store future pending"),
    }
}

/// Pending once, then ready: makes every store call a real await point.
#[derive(Default)]
struct YieldOnce(bool);

impl Future for YieldOnce {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            return Poll::Ready(());
        }
        self.0 = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

type ApplyHook = Box<dyn Fn(&MemoryKv, &Partition, &Batch) + Send + Sync>;

/// A `MemoryKv` that records every key it sees and batch it applies, can
/// run a hook before each apply and can yield at every call.
struct Spy {
    inner: MemoryKv,
    hook: Option<ApplyHook>,
    yields: bool,
    seen: Mutex<Vec<Key>>,
    batches: Mutex<Vec<Batch>>,
    calls: AtomicU32,
}

impl Spy {
    fn new(inner: MemoryKv) -> Self {
        Self {
            inner,
            hook: None,
            yields: false,
            seen: Mutex::default(),
            batches: Mutex::default(),
            calls: AtomicU32::new(0),
        }
    }

    fn hook(
        mut self,
        hook: impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync + 'static,
    ) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }

    /// Backend round trips so far.
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }

    async fn pause(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.yields {
            YieldOnce::default().await;
        }
    }

    fn saw(&self, key: &Key) {
        self.seen.lock().unwrap().push(key.clone());
    }
}

impl NamespaceStore for Spy {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.pause().await;
        self.saw(key);
        self.inner.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.pause().await;
        for k in keys {
            self.saw(k);
        }
        self.inner.get_many(p, keys).await
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&crate::store::Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.pause().await;
        self.saw(start);
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.pause().await;
        for pre in &batch.preconditions {
            if let Precondition::Absent(k) | Precondition::Present(k) | Precondition::Equals(k, _) =
                pre
            {
                self.saw(k);
            }
        }
        for write in &batch.writes {
            let (Write::Put(k, _) | Write::Delete(k)) = write;
            self.saw(k);
        }
        self.batches.lock().unwrap().push(batch.clone());
        if let Some(hook) = &self.hook {
            hook(&self.inner, p, &batch);
        }
        self.inner.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

type Labels = Vec<(String, String)>;

#[derive(Default)]
struct SpyMetrics(Mutex<Vec<(&'static str, Labels)>>);

impl Metrics for SpyMetrics {
    fn incr(&self, name: &'static str, labels: &[(&'static str, &str)], _by: u64) {
        let labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()));
        self.0.lock().unwrap().push((name, labels.collect()));
    }
    fn observe_ms(&self, _: &'static str, _: &[(&'static str, &str)], _: f64) {}
}

impl SpyMetrics {
    fn count(&self, name: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, _)| *n == name)
            .count()
    }
}

struct Env<H = Hooks> {
    pipe: Pipeline<MemoryBlobStore, Spy, H>,
    clock: Arc<ManualClock>,
    metrics: Arc<SpyMetrics>,
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    }
}

fn ns() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

fn authv2() -> AuthMode {
    AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap())
}

fn cfg(auth: AuthMode) -> PipelineConfig {
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    PipelineConfig::new(Addressing::Single { repo: repo() }, auth, limits)
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(T0))
}

fn store(clock: &Arc<ManualClock>) -> MemoryKv {
    MemoryKv::with_clock(clock.clone())
}

fn build<H: HookSet>(cfg: PipelineConfig, meta: Spy, hooks: H, clock: Arc<ManualClock>) -> Env<H> {
    let metrics = Arc::new(SpyMetrics::default());
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta,
        hooks,
        cfg,
        clock.clone(),
        metrics.clone(),
    )
    .unwrap();
    Env {
        pipe,
        clock,
        metrics,
    }
}

fn env(auth: AuthMode) -> Env {
    let clock = clock();
    build(cfg(auth), Spy::new(store(&clock)), Hooks::new(), clock)
}

fn upd(name: &str, condition: RefWriteCondition, new: Hash) -> RefUpdate {
    RefUpdate {
        name: name.to_owned(),
        condition,
        new,
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn nonce(n: u32) -> String {
    format!("{n:064x}")
}

/// A request as a binding would present it.
#[derive(Clone)]
struct Req {
    procedure: Procedure,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
    principal: Option<Principal>,
}

impl Req {
    fn unsigned(procedure: Procedure) -> Self {
        Self {
            procedure,
            body: Vec::new(),
            headers: Vec::new(),
            principal: None,
        }
    }

    fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.retain(|(n, _)| *n != name);
        self.headers.push((name, value.to_owned()));
        self
    }

    /// Signed with auth v2 at `created`, valid for 300 s.
    fn signed(
        key: &SigningKey,
        procedure: Procedure,
        body: &[u8],
        nonce: &str,
        created: i64,
    ) -> Self {
        let digest = to_hex(&hash(body));
        let commitment = format!("body:{digest}");
        let expires = created + 300_000;
        let op = SignedOp {
            context: AuthContext {
                audience: AUDIENCE,
                repository: REPO,
            },
            procedure: procedure.connect_path(),
            commitment: &commitment,
            created_at: created,
            expires_at: expires,
            nonce,
        };
        let signature = key.sign(&op.digest().unwrap());
        let headers = vec![
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", AUDIENCE.to_owned()),
            ("x-repository", REPO.to_owned()),
            ("x-public-key", to_hex(key.verifying_key().as_bytes())),
            ("x-signature", to_hex_bytes(&signature.to_bytes())),
            ("x-digest", digest),
            ("x-content-commitment", commitment),
            ("x-created-at", created.to_string()),
            ("x-expires-at", expires.to_string()),
            ("idempotency-key", nonce.to_owned()),
        ];
        Self {
            procedure,
            body: body.to_vec(),
            headers,
            principal: None,
        }
    }

    /// A signed `UpdateRef` whose body stands for `u`.
    fn update(key: &SigningKey, n: u32, u: &RefUpdate, created: i64) -> Self {
        let body = format!("{u:?}");
        Self::signed(
            key,
            Procedure::UpdateRef,
            body.as_bytes(),
            &nonce(n),
            created,
        )
    }
}

impl<H: HookSet> Env<H> {
    fn auth(&self, req: &Req) -> Result<Authenticated, ServerError> {
        let lookup = |name: &str| {
            req.headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
        };
        self.pipe.authenticate(&RequestMeta {
            procedure: req.procedure,
            header: &lookup,
            unary_body: Some(&req.body),
            transport_principal: req.principal.clone(),
        })
    }

    fn update(&self, req: &Req, u: &RefUpdate) -> Result<UpdateRefResult, ServerError> {
        block_on(self.pipe.update_ref(&self.auth(req)?, u.clone()))
    }

    fn advance(
        &self,
        req: &Req,
        head: &RefUpdate,
        pm: &RefUpdate,
    ) -> Result<AdvanceOutcome, ServerError> {
        block_on(
            self.pipe
                .advance_refs(&self.auth(req)?, head.clone(), pm.clone()),
        )
    }

    fn open_update(&self, u: &RefUpdate) -> Result<UpdateRefResult, ServerError> {
        self.update(&Req::unsigned(Procedure::UpdateRef), u)
    }

    fn read(&self, name: &str) -> Option<Hash> {
        let a = self.auth(&Req::unsigned(Procedure::ReadRef)).unwrap();
        block_on(self.pipe.read_ref(&a, name)).unwrap()
    }

    fn rows(&self) -> Vec<(Key, Value)> {
        let (start, end) = (Key::new(vec![0]), Key::new(vec![0xff]));
        now(self
            .pipe
            .meta
            .inner
            .scan(&ns(), &start, &end, None, 100_000))
        .unwrap()
        .entries
    }

    fn count(&self, tag: &str) -> usize {
        let prefix = format!("{tag}\0");
        let rows = self.rows();
        rows.iter()
            .filter(|(k, _)| k.as_bytes().starts_with(prefix.as_bytes()))
            .count()
    }

    fn batches(&self) -> Vec<Batch> {
        self.pipe.meta.batches.lock().unwrap().clone()
    }
}

/// Seed refs through the store directly, one batch each.
fn seed(kv: &MemoryKv, refs: &[(&str, Hash)]) {
    let name = RepoName::new(REPO).unwrap();
    for (n, id) in refs {
        let batch = Batch::new().put(keys::ref_key(&name, n), codec::encode_ref_id(id));
        assert_eq!(
            now(kv.apply(&ns(), batch)).unwrap(),
            BatchOutcome::Committed
        );
    }
}

fn with_admission<Ad: Admission>(admission: Ad) -> Hooks<OpenAuthorizer, Ad> {
    Hooks {
        authorizer: OpenAuthorizer,
        admission,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    }
}

fn replay_row(env: &Env, req: &Req) -> Option<crate::replay::ReplayRecord> {
    let scope = env.auth(req).unwrap().auth.unwrap().replay_scope;
    now(read::replay_lookup(
        &env.pipe.meta.inner,
        &ns(),
        &ReplayKey(scope),
    ))
    .unwrap()
}

/// The first nonce from `from` whose replay scope is (or is not) sampled
/// for pruning.
fn nonce_where<H: HookSet>(env: &Env<H>, k: &SigningKey, sampled: bool, from: u32) -> u32 {
    let u = upd(HEAD, Missing, A);
    (from..from + 1_000)
        .find(|n| {
            let scope = env
                .auth(&Req::update(k, *n, &u, T0))
                .unwrap()
                .auth
                .unwrap()
                .replay_scope;
            scope[0].is_multiple_of(plan::PRUNE_SAMPLE) == sampled
        })
        .unwrap()
}

fn code<T: core::fmt::Debug>(r: Result<T, ServerError>) -> Code {
    r.unwrap_err().code()
}

// ------------------------------------------------------------- auth v2

#[test]
fn authv2_update_ref_happy_path_then_replay_returns_same_after_ref_moved() {
    let env = env(authv2());
    let k = key(7);
    let create = upd(HEAD, Missing, A);
    let first = Req::update(&k, 1, &create, T0);
    assert_eq!(
        env.update(&first, &create).unwrap(),
        UpdateRefResult::Committed
    );
    let moved = upd(HEAD, Match(A), B);
    let second = Req::update(&k, 2, &moved, T0);
    assert_eq!(
        env.update(&second, &moved).unwrap(),
        UpdateRefResult::Committed
    );
    env.clock.advance(1_000);
    // The replay returns the saved result and repeats nothing.
    assert_eq!(
        env.update(&first, &create).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(env.read(HEAD), Some(B));
    // A conflict is stored too, and replayed as the same conflict.
    let stale = upd(HEAD, Match(A), C);
    let third = Req::update(&k, 3, &stale, T0);
    let conflict = UpdateRefResult::Conflict { current: Some(B) };
    assert_eq!(env.update(&third, &stale).unwrap(), conflict);
    let again = upd(HEAD, Match(B), C);
    assert_eq!(
        env.update(&Req::update(&k, 4, &again, T0), &again).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(env.update(&third, &stale).unwrap(), conflict);
    assert_eq!(env.read(HEAD), Some(C));
}

#[test]
fn authv2_nonce_reuse_different_op_is_invalid_argument() {
    let env = env(authv2());
    let k = key(7);
    let one = upd(HEAD, Missing, A);
    env.update(&Req::update(&k, 1, &one, T0), &one).unwrap();
    let other = upd(HEAD, Any, B);
    let err = env
        .update(&Req::update(&k, 1, &other, T0), &other)
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        err.public_message(),
        "nonce reused for a different operation"
    );
    assert_eq!(env.read(HEAD), Some(A));
}

#[test]
fn authv2_missing_headers_is_unauthenticated() {
    let env = env(authv2());
    for procedure in [
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::UploadPack,
    ] {
        assert_eq!(
            code(env.auth(&Req::unsigned(procedure))),
            Code::Unauthenticated
        );
    }
    let u = upd(HEAD, Missing, A);
    let signed = Req::update(&key(7), 1, &u, T0).header("x-signature", "");
    assert_eq!(code(env.update(&signed, &u)), Code::Unauthenticated);
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_wrong_audience_unauthenticated() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0).header("x-audience", "https://other.example.test");
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(
        err.public_message(),
        "request audience or repository mismatch"
    );
}

#[test]
fn authv2_expired_unauthenticated() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    env.clock.set(T0 + 300_001);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(err.public_message(), "expired or future authorization");
    assert!(env.rows().is_empty());
}

#[test]
fn authv2_reads_need_no_signature() {
    let env = env(authv2());
    seed(&env.pipe.meta.inner, &[(HEAD, A)]);
    let list = env.auth(&Req::unsigned(Procedure::ListRefs)).unwrap();
    assert_eq!(
        (&list.principal, &list.auth),
        (&Principal::Anonymous, &None)
    );
    let refs = block_on(env.pipe.list_refs(&list, "refs/heads/")).unwrap();
    assert_eq!(
        refs,
        vec![RefEntry {
            name: "main".into(),
            id: A
        }]
    );
    assert_eq!(env.read(HEAD), Some(A));
    let exists = env.auth(&Req::unsigned(Procedure::PackExists)).unwrap();
    assert!(!block_on(env.pipe.pack_exists(&exists, PackKey::new(C))).unwrap());
    // Credentials are bound to their procedure.
    assert_eq!(
        code(block_on(env.pipe.read_ref(&list, HEAD))),
        Code::Unauthenticated
    );
}

#[test]
fn quota_exhaustion_is_resource_exhausted_and_allocates_no_replay_record() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 2,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let k = key(7);
    let reqs: Vec<_> = (1..=3)
        .map(|i| {
            let u = upd(&format!("refs/heads/b{i}"), Missing, A);
            (Req::update(&k, i, &u, T0), u)
        })
        .collect();
    env.update(&reqs[0].0, &reqs[0].1).unwrap();
    env.update(&reqs[1].0, &reqs[1].1).unwrap();
    let rows = env.rows();
    let err = env.update(&reqs[2].0, &reqs[2].1).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(
        err.public_message(),
        "write op quota exceeded for this window; try again later"
    );
    assert_eq!(replay_row(&env, &reqs[2].0), None);
    assert_eq!(env.rows(), rows, "nothing allocated");
}

#[test]
fn retry_after_quota_exhaustion_still_returns_stored_result() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 1,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let k = key(7);
    let first = upd(HEAD, Missing, A);
    let req = Req::update(&k, 1, &first, T0);
    env.update(&req, &first).unwrap();
    let next = upd(HEAD, Any, B);
    assert_eq!(
        code(env.update(&Req::update(&k, 2, &next, T0), &next)),
        Code::ResourceExhausted
    );
    // The saved reply is checked before admission.
    assert_eq!(
        env.update(&req, &first).unwrap(),
        UpdateRefResult::Committed
    );
}

// --------------------------------------------------------- advance refs

#[test]
fn advance_refs_atomic_store_conflict_leaves_both_untouched() {
    for auth in [AuthMode::Open, authv2()] {
        let env = env(auth);
        assert!(env.pipe.capabilities().atomic_advance);
        seed(&env.pipe.meta.inner, &[(HEAD, A), (PACKMAP, A)]);
        let req = |n| {
            let r = Req::signed(
                &key(7),
                Procedure::AdvanceRefs,
                &nonce(n).into_bytes(),
                &nonce(n),
                T0,
            );
            if matches!(env.pipe.cfg.auth, AuthMode::Open) {
                Req::unsigned(Procedure::AdvanceRefs)
            } else {
                r
            }
        };
        let cases = [
            (
                upd(HEAD, Match(A), B),
                upd(PACKMAP, Match(C), B),
                AdvanceOutcome::PackmapConflict,
            ),
            (
                upd(HEAD, Match(C), B),
                upd(PACKMAP, Match(A), B),
                AdvanceOutcome::HeadConflict,
            ),
            // Both conflict: the packmap takes precedence.
            (
                upd(HEAD, Missing, B),
                upd(PACKMAP, Missing, B),
                AdvanceOutcome::PackmapConflict,
            ),
        ];
        for (n, (head, pm, outcome)) in (1..).zip(cases) {
            assert_eq!(env.advance(&req(n), &head, &pm).unwrap(), outcome);
            assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(A)));
        }
        let (head, pm) = (upd(HEAD, Match(A), B), upd(PACKMAP, Match(A), C));
        assert_eq!(
            env.advance(&req(9), &head, &pm).unwrap(),
            AdvanceOutcome::Committed
        );
        assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(B), Some(C)));
    }
}

#[test]
fn advance_refs_nonatomic_store_matches_trait_default_order() {
    let clock = clock();
    let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
    let env = build(cfg(AuthMode::Open), Spy::new(kv), Hooks::new(), clock);
    assert!(!env.pipe.capabilities().atomic_advance);
    seed(&env.pipe.meta.inner, &[(HEAD, A), (PACKMAP, A)]);
    let req = Req::unsigned(Procedure::AdvanceRefs);
    // Head conflict: the packmap is already written (protocol.rs order).
    let (head, pm) = (upd(HEAD, Match(C), B), upd(PACKMAP, Match(A), B));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::HeadConflict
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(B)));
    // Packmap conflict: the head is never attempted.
    let (head, pm) = (upd(HEAD, Match(A), C), upd(PACKMAP, Match(A), C));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::PackmapConflict
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(A), Some(B)));
    let (head, pm) = (upd(HEAD, Match(A), C), upd(PACKMAP, Match(B), C));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!((env.read(HEAD), env.read(PACKMAP)), (Some(C), Some(C)));
    // Two sequential single-key batches, each with its own deadline.
    let last: Vec<_> = env.batches().into_iter().rev().take(2).collect();
    for batch in last {
        assert!(matches!(batch.preconditions[0], Precondition::NotAfter(_)));
        assert_eq!(batch.writes.len(), 1);
    }
}

// ---------------------------------------------------------- other modes

#[test]
fn bearer_mode_rejects_missing_or_wrong_token_on_reads_and_writes() {
    let env = env(AuthMode::Bearer {
        token: crate::error::Redacted::new("s3cr3t"),
    });
    let all = [
        Procedure::ListRefs,
        Procedure::ReadRef,
        Procedure::UpdateRef,
        Procedure::AdvanceRefs,
        Procedure::PackExists,
        Procedure::UploadPack,
        Procedure::DownloadPack,
    ];
    for procedure in all {
        let bare = Req::unsigned(procedure);
        for req in [
            bare.clone(),
            bare.clone().header("authorization", "Bearer wrong!"),
            bare.clone().header("authorization", "s3cr3t"),
            bare.clone().header("authorization", "Bearer s3cr3tt"),
        ] {
            let err = env.auth(&req).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated);
            assert!(!format!("{err} {err:?}").contains("s3cr3t"));
        }
        let ok = env
            .auth(&bare.header("authorization", "Bearer s3cr3t"))
            .unwrap();
        assert_eq!(ok.principal, Principal::BearerHolder);
    }
    let req = Req::unsigned(Procedure::UpdateRef).header("authorization", "Bearer s3cr3t");
    env.update(&req, &upd(HEAD, Missing, A)).unwrap();
    assert_eq!(env.count("p") + env.count("q"), 0, "no replay or quota");
}

#[test]
fn open_mode_allows_everything_without_replay() {
    let env = env(AuthMode::Open);
    assert_eq!(
        env.open_update(&upd(HEAD, Missing, A)).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.open_update(&upd(HEAD, Missing, B)).unwrap(),
        UpdateRefResult::Conflict { current: Some(A) }
    );
    let req = Req::unsigned(Procedure::AdvanceRefs);
    let (head, pm) = (upd(HEAD, Match(A), B), upd(PACKMAP, Missing, B));
    assert_eq!(
        env.advance(&req, &head, &pm).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(env.read(HEAD), Some(B));
    for tag in ["p", "px", "q", "qx"] {
        assert_eq!(env.count(tag), 0, "{tag}");
    }
    // An unsigned conflict needs no write at all.
    let writes = env.batches().len();
    env.open_update(&upd(HEAD, Match(C), A)).unwrap();
    assert_eq!(env.batches().len(), writes);
}

#[test]
fn transport_identity_mode_uses_binding_principal() {
    let env = env(AuthMode::TransportIdentity);
    let ssh = Principal::SshForcedCommand { key: None };
    let mut req = Req::unsigned(Procedure::UpdateRef);
    assert_eq!(code(env.auth(&req)), Code::Unauthenticated);
    req.principal = Some(ssh.clone());
    let a = env.auth(&req).unwrap();
    assert_eq!((a.principal, a.auth), (ssh, None));
    env.update(&req, &upd(HEAD, Missing, A)).unwrap();
    assert_eq!(env.count("p"), 0);
}

struct Fixed(AdmissionDecision);

impl Admission for Fixed {
    async fn admit(&self, _: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Ok(self.0.clone())
    }
}

#[test]
fn admission_challenge_maps_to_permission_denied_and_writes_nothing() {
    let challenge = AdmissionDecision::Challenge {
        challenges: vec![Challenge {
            scheme: "Payment".into(),
            value: "id=1".into(),
        }],
        description: "pay".into(),
    };
    let denied = AdmissionDecision::Deny(ServerError::permission_denied("no"));
    for (decision, message) in [(challenge, "admission required"), (denied, "no")] {
        let clock = clock();
        let hooks = with_admission(Fixed(decision));
        let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
        let u = upd(HEAD, Missing, A);
        let req = Req::update(&key(7), 1, &u, T0);
        let err = env.update(&req, &u).unwrap_err();
        assert_eq!(
            (err.code(), err.public_message()),
            (Code::PermissionDenied, message)
        );
        assert!(err.details().is_empty() && err.http_status().is_none());
        assert!(env.batches().is_empty() && env.rows().is_empty());
    }
}

#[test]
fn pipeline_new_rejects_authv2_over_refs_only_store() {
    let clock = clock();
    let blobs = MemoryBlobStore::default();
    let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
    let metrics: Arc<dyn Metrics> = Arc::new(crate::NoopMetrics);
    let err = Pipeline::new(blobs, kv, Hooks::new(), cfg(authv2()), clock, metrics).unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[test]
fn refs_only_store_never_sees_layout_version_key() {
    for auth in [AuthMode::Open, AuthMode::TransportIdentity] {
        let clock = clock();
        let kv = store(&clock).with_capabilities(StoreCapabilities::refs_only());
        let env = build(cfg(auth), Spy::new(kv), Hooks::new(), clock);
        let principal = Some(Principal::SshForcedCommand { key: None });
        let req = |p| Req {
            principal: principal.clone(),
            ..Req::unsigned(p)
        };
        env.update(&req(Procedure::UpdateRef), &upd(HEAD, Missing, A))
            .unwrap();
        let (head, pm) = (upd(HEAD, Any, B), upd(PACKMAP, Missing, B));
        env.advance(&req(Procedure::AdvanceRefs), &head, &pm)
            .unwrap();
        let a = env.auth(&req(Procedure::ListRefs)).unwrap();
        assert_eq!(block_on(env.pipe.list_refs(&a, "")).unwrap().len(), 2);
        let seen = env.pipe.meta.seen.lock().unwrap().clone();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(keys::is_ref_key), "{seen:?}");
    }
}

// ------------------------------------------------------ pure planners

fn repo_name() -> RepoName {
    RepoName::new(REPO).unwrap()
}

fn clock_at(plan_time_ms: u64, deadline_cap: Option<u64>) -> PlanClock {
    PlanClock {
        plan_time_ms,
        business_now_ms: i64::try_from(plan_time_ms).unwrap(),
        max_apply_window_ms: WINDOW,
        deadline_cap,
    }
}

fn snapshot(req: &WriteRequest<'_>, values: &[(Key, Value)]) -> Snapshot {
    let mut snap = Snapshot::default();
    for key in req.read_keys() {
        let value = values
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone());
        snap.insert(key, value);
    }
    snap
}

fn ref_value(name: &str, id: Hash) -> (Key, Value) {
    (keys::ref_key(&repo_name(), name), codec::encode_ref_id(&id))
}

#[test]
fn plan_cas_any_missing_match_on_snapshot() {
    let name = repo_name();
    let cases = [
        (Any, None, true),
        (Any, Some(A), true),
        (Missing, None, true),
        (Missing, Some(A), false),
        (Match(A), Some(A), true),
        (Match(A), Some(B), false),
        (Match(A), None, false),
    ];
    for (condition, current, commits) in cases {
        let refs = [upd(HEAD, condition, C)];
        let req = WriteRequest {
            repo: &name,
            kind: WriteKind::UpdateRef,
            refs: &refs,
            replay: None,
            charges: &[],
            grant: None,
            layout_version: false,
        };
        let values: Vec<_> = current.map(|id| ref_value(HEAD, id)).into_iter().collect();
        let planned = plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap();
        match planned {
            Planned::Apply(plan) => {
                assert!(commits, "{condition:?} {current:?}");
                assert_eq!(
                    plan.on_commit,
                    StoredResult::UpdateRef(UpdateRefResult::Committed)
                );
                assert_eq!(
                    plan.batch.writes,
                    vec![Write::Put(ref_value(HEAD, C).0, ref_value(HEAD, C).1)]
                );
                let guarded = plan.batch.preconditions.len() == 2;
                assert_eq!(guarded, condition != Any, "Any is never guarded");
            }
            Planned::Done(result) => {
                assert!(!commits, "{condition:?} {current:?}");
                assert_eq!(
                    result,
                    StoredResult::UpdateRef(UpdateRefResult::Conflict { current })
                );
            }
        }
    }
}

fn replay() -> ReplayGuard {
    ReplayGuard {
        scope: [1; 32],
        fingerprint: [2; 32],
        expires_at_ms: T0,
    }
}

#[test]
fn plan_conflict_writes_only_the_replay_record() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Match(A), C), upd(HEAD, Match(A), C)];
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        replay: Some(replay()),
        charges: &[],
        grant: None,
        layout_version: false,
    };
    let values = [ref_value(PACKMAP, A), ref_value(HEAD, B)];
    let Planned::Apply(plan) =
        plan_write(&req, &snapshot(&req, &values), &clock_at(5, None)).unwrap()
    else {
        panic!("a signed conflict is stored");
    };
    assert_eq!(
        plan.on_commit,
        StoredResult::AdvanceRefs(AdvanceOutcome::HeadConflict)
    );
    let written: Vec<_> = plan
        .batch
        .writes
        .iter()
        .map(|w| match w {
            Write::Put(k, _) | Write::Delete(k) => keys::parse(k),
        })
        .collect();
    assert!(matches!(
        written[..],
        [
            Some(keys::ParsedKey::Replay(_)),
            Some(keys::ParsedKey::ReplayExpiry { .. })
        ]
    ));
    // Both refs that decided the conflict are guarded with what was read.
    assert_eq!(
        plan.batch.preconditions[1..],
        [
            Precondition::Equals(values[0].0.clone(), values[0].1.clone()),
            Precondition::Equals(values[1].0.clone(), values[1].1.clone()),
            Precondition::Absent(keys::replay(&[1; 32])),
        ]
    );
    assert_eq!(plan.replay_index, Some(3));
}

fn charge(max_ops: u32) -> QuotaCharge {
    QuotaCharge {
        scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[3; 32]),
        bytes: 0,
        limits: QuotaLimits {
            window_ms: 60_000,
            max_ops,
            max_bytes: 0,
        },
    }
}

#[test]
fn plan_quota_exhaustion_yields_no_batch() {
    let name = repo_name();
    let refs = [upd(HEAD, Any, C)];
    let charges = [charge(1)];
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        replay: Some(replay()),
        charges: &charges,
        grant: None,
        layout_version: true,
    };
    let used = QuotaState {
        window_start: T0,
        ops: 1,
        bytes: 0,
    };
    let values = [(
        keys::quota(&charges[0].scope),
        codec::encode_quota_state(&used),
    )];
    let err = plan_write(&req, &snapshot(&req, &values), &clock_at(ms(T0) + 1, None)).unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
}

fn condition() -> impl Strategy<Value = RefWriteCondition> {
    prop_oneof![Just(Any), Just(Missing), Just(Match(A)), Just(Match(B))]
}

fn maybe_id() -> impl Strategy<Value = Option<Hash>> {
    prop_oneof![Just(None), Just(Some(A)), Just(Some(B))]
}

proptest! {
    #[test]
    fn plan_guards_every_read_and_starts_with_not_after(
        advance in any::<bool>(),
        conditions in (condition(), condition()),
        currents in (maybe_id(), maybe_id()),
        signed in any::<bool>(),
        quota in prop::option::of(0u32..3),
        layout in prop_oneof![Just(None), Just(Some(false)), Just(Some(true))],
        plan_time in 0u64..1_000_000,
        cap in prop::option::of(0u64..1_100_000),
    ) {
        let name = repo_name();
        let refs = [upd(PACKMAP, conditions.0, C), upd(HEAD, conditions.1, C)];
        let refs = if advance { &refs[..] } else { &refs[1..] };
        let charges: Vec<_> = quota.map(|_| charge(2)).into_iter().collect();
        let req = WriteRequest {
            repo: &name,
            kind: if advance { WriteKind::AdvanceRefs } else { WriteKind::UpdateRef },
            refs,
            replay: signed.then(replay),
            charges: &charges,
            grant: None,
            layout_version: layout.is_some(),
        };
        let mut values = Vec::new();
        for (name, current) in [(PACKMAP, currents.0), (HEAD, currents.1)] {
            values.extend(current.map(|id| ref_value(name, id)));
        }
        if let Some(ops) = quota.filter(|ops| *ops > 0) {
            let state = QuotaState { window_start: 0, ops, bytes: 0 };
            values.push((keys::quota(&charges[0].scope), codec::encode_quota_state(&state)));
        }
        if layout == Some(true) {
            values.push((keys::layout_version(), codec::encode_u32(LAYOUT_VERSION)));
        }
        let snap = snapshot(&req, &values);
        let clock = clock_at(plan_time, cap);
        let planned = plan_write(&req, &snap, &clock);
        let plan = match planned {
            Err(e) => { prop_assert_eq!(e.code(), Code::ResourceExhausted); return Ok(()); }
            Ok(Planned::Done(_)) => { prop_assert!(!signed && charges.is_empty()); return Ok(()); }
            Ok(Planned::Apply(plan)) => plan,
        };
        let expected = cap.map_or(plan_time + WINDOW, |c| c.min(plan_time + WINDOW));
        prop_assert_eq!(&plan.batch.preconditions[0], &Precondition::NotAfter(expected));
        prop_assert_eq!(plan.batch.preconditions.iter().filter(|p| matches!(p, Precondition::NotAfter(_))).count(), 1);
        let replay_key = keys::replay(&[1; 32]);
        for pre in &plan.batch.preconditions[1..] {
            match pre {
                Precondition::Equals(k, v) => prop_assert_eq!(snap.get(k), Some(v)),
                Precondition::Absent(k) if *k == replay_key => {}
                Precondition::Absent(k) => prop_assert_eq!(snap.get(k), None),
                other => prop_assert!(false, "unexpected {:?}", other),
            }
        }
        let guarded = |k: &Key| plan.batch.preconditions.iter().any(|p| matches!(p,
            Precondition::Equals(g, _) | Precondition::Absent(g) if g == k));
        for k in req.read_keys().iter().filter(|k| !keys::is_ref_key(k)) {
            prop_assert!(guarded(k), "{:?} unguarded", k);
        }
        for update in refs.iter().filter(|u| u.condition != Any) {
            let k = keys::ref_key(&name, &update.name);
            let decided = plan.batch.writes.iter().any(|w| matches!(w, Write::Put(p, _) if *p == k));
            prop_assert!(!decided || guarded(&k), "{} written unguarded", update.name);
        }
        prop_assert!(plan.batch.validate(&StoreCapabilities::full()).is_ok());
    }
}

fn verified(expires_at: i64) -> VerifiedAuth {
    let authorized = mkit_core::write_auth::Authorized {
        scope: "11".repeat(32),
        public_key: "22".repeat(32),
        nonce: "ab".repeat(32),
        fingerprint: "33".repeat(32),
        commitment: format!("body:{}", "cd".repeat(32)),
        expires_at,
    };
    VerifiedAuth::try_from(&authorized).unwrap()
}

fn charges_for(input: &AdmissionInput<'_>) -> Vec<QuotaCharge> {
    match block_on(DefaultAdmission.admit(input)).unwrap() {
        AdmissionDecision::Allow { charges, .. } => charges,
        other => panic!("{other:?}"),
    }
}

#[test]
fn default_admission_charges_signed_writes_only() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let auth = verified(T0);
    let op = |kind, auth: Option<VerifiedAuth>| {
        let principal = auth
            .as_ref()
            .map_or(Principal::Anonymous, |a| Principal::Signer {
                ed25519: a.signer,
            });
        crate::op::Operation::new(repo.clone(), principal, auth, kind)
    };
    let write = crate::op::OpKind::UpdateRef(upd(HEAD, Missing, A));
    let signed = op(write.clone(), Some(auth.clone()));
    let mut input = AdmissionInput::new(&signed);
    assert_eq!(input.idempotency_key, Some(auth.nonce.as_str()));
    assert_eq!((input.declared_bytes, input.pack_id), (0, None));
    assert!(charges_for(&input).is_empty(), "no configured quota");
    input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
    let scope = QuotaScope::for_signer(&repo.namespace, &auth.signer);
    let expected = QuotaCharge {
        scope,
        bytes: 0,
        limits: crate::quota::DEFAULT_WRITE_QUOTA,
    };
    assert_eq!(charges_for(&input), vec![expected]);
    let read = crate::op::OpKind::ReadRef { name: HEAD.into() };
    for other in [op(write, None), op(read, Some(auth))] {
        let mut input = AdmissionInput::new(&other);
        input.write_quota = Some(crate::quota::DEFAULT_WRITE_QUOTA);
        assert!(charges_for(&input).is_empty());
    }
}

#[test]
fn single_partition_maps_everything_to_the_namespace() {
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: repo_name(),
    };
    let expected = Partition::Namespace(NamespaceKey::deployment_default());
    let shards = SinglePartition;
    assert_eq!(shards.ref_shard(&repo, HEAD), expected);
    assert_eq!(shards.ref_shard(&repo, PACKMAP), expected);
    assert_eq!(shards.coordinator(&repo.namespace), expected);
    assert_eq!(shards.ref_index(&repo), expected);
    assert_eq!(shards.membership(&repo, &PackKey::new(A)), expected);
}

// ----------------------------------------------- deadline and re-plans

/// Move the store clock past the deadline before the first `n` applies.
fn late(
    clock: &Arc<ManualClock>,
    n: u32,
) -> impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync + use<> {
    let (clock, left) = (clock.clone(), AtomicU32::new(n));
    move |_, _, _| {
        if left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
            .is_ok()
        {
            clock.advance(i64::try_from(WINDOW).unwrap() + 1);
        }
    }
}

#[test]
fn late_batch_fails_not_after_and_replans() {
    for auth in [authv2(), AuthMode::Open] {
        for (late_applies, ok) in [(1, true), (2, false)] {
            let clock = clock();
            let spy = Spy::new(store(&clock)).hook(late(&clock, late_applies));
            let env = build(cfg(auth.clone()), spy, Hooks::new(), clock);
            let u = upd(HEAD, Missing, A);
            let req = match env.pipe.cfg.auth {
                AuthMode::Open => Req::unsigned(Procedure::UpdateRef),
                _ => Req::update(&key(7), 1, &u, T0),
            };
            let result = env.update(&req, &u);
            if ok {
                assert_eq!(result.unwrap(), UpdateRefResult::Committed);
                assert_eq!(env.batches().len(), 2);
            } else {
                // Re-planned once, then `unavailable`, never `aborted`.
                let err = result.unwrap_err();
                assert_eq!(err.code(), Code::Unavailable);
                assert!(env.rows().is_empty(), "a late batch never commits");
            }
        }
    }
}

#[test]
fn not_after_ignores_test_clock_skew() {
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let mut a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
    a.business_skew_ms = 3_600_000;
    block_on(env.pipe.update_ref(&a, u)).unwrap();
    let batch = &env.batches()[0];
    assert_eq!(
        batch.preconditions[0],
        Precondition::NotAfter(ms(T0) + WINDOW)
    );
    // Business time (the quota window) does move.
    let rows = env.rows();
    let (_, quota) = rows
        .iter()
        .find(|(k, _)| k.as_bytes().starts_with(b"q\0"))
        .unwrap();
    let state = codec::decode_quota_state(quota).unwrap();
    assert_eq!(state.window_start, T0 + 3_600_000);
}

/// Toggle the layout version key before the first `n` applies: a
/// concurrent writer that breaks one of the plan's guards.
fn interfere(n: u32) -> impl Fn(&MemoryKv, &Partition, &Batch) + Send + Sync {
    let left = AtomicU32::new(n);
    move |kv, p, _| {
        if left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |l| l.checked_sub(1))
            .is_ok()
        {
            let v = keys::layout_version();
            let batch = if now(kv.get(p, &v)).unwrap().is_some() {
                Batch::new().delete(v)
            } else {
                Batch::new().put(v, codec::encode_u32(LAYOUT_VERSION))
            };
            now(kv.apply(p, batch)).unwrap();
        }
    }
}

#[test]
fn replan_after_concurrent_writer_then_succeeds() {
    let clock = clock();
    let spy = Spy::new(store(&clock)).hook(interfere(MAX_REPLAN));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    assert_eq!(
        env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(
        env.batches().len(),
        usize::try_from(MAX_REPLAN).unwrap() + 1
    );
}

#[test]
fn replan_exhaustion_is_aborted_retryable() {
    let clock = clock();
    let spy = Spy::new(store(&clock)).hook(interfere(MAX_REPLAN + 1));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Aborted);
    assert!(err.code().is_retryable());
    assert_eq!(env.read(HEAD), None);
    // The retry with the same nonce commits.
    assert_eq!(env.update(&req, &u).unwrap(), UpdateRefResult::Committed);
}

#[test]
fn concurrent_duplicate_returns_the_winners_result() {
    // Another request with the same nonce commits between plan and apply:
    // the loser's replay guard fails and it answers with the winner's result.
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    let auth = env(authv2()).auth(&req).unwrap().auth.unwrap();
    let won = StoredResult::UpdateRef(UpdateRefResult::Conflict { current: Some(C) });
    let record = ReplayRecord {
        fingerprint: auth.fingerprint,
        expires_at_ms: auth.expires_at_ms,
        state: ReplayState::Committed(won),
    };
    let fired = std::sync::atomic::AtomicBool::new(false);
    let hook = move |kv: &MemoryKv, p: &Partition, _: &Batch| {
        if !fired.swap(true, Ordering::SeqCst) {
            let key = keys::replay(&auth.replay_scope);
            let batch = Batch::new().put(key, codec::encode_replay_record(&record));
            now(kv.apply(p, batch)).unwrap();
        }
    };
    let clock = clock();
    let env = build(
        cfg(authv2()),
        Spy::new(store(&clock)).hook(hook),
        Hooks::new(),
        clock,
    );
    let result = env.update(&req, &u).unwrap();
    assert_eq!(result, UpdateRefResult::Conflict { current: Some(C) });
    assert_eq!(env.read(HEAD), None);
}

#[test]
fn store_full_maps_to_unavailable() {
    let clock = clock();
    // Two expired replay entries the write's prune deletes.
    let expired = || {
        [[5u8; 32], [6; 32]].iter().fold(Batch::new(), |b, scope| {
            b.put(keys::replay_expiry(1, scope), Value::default())
                .put(keys::replay(scope), Value::new(vec![1]))
        })
    };
    let probe = store(&clock);
    now(probe.apply(&ns(), expired())).unwrap();
    let used = now(probe.stats(&ns())).unwrap().bytes;
    // The same rows under a cap they almost fill.
    let kv = store(&clock).with_capacity_limit(used + 8);
    now(kv.apply(&ns(), expired())).unwrap();
    let env = build(cfg(authv2()), Spy::new(kv), Hooks::new(), clock);
    let u = upd(HEAD, Missing, A);
    let n = nonce_where(&env, &key(7), true, 1);
    let err = env
        .update(&Req::update(&key(7), n, &u, T0), &u)
        .unwrap_err();
    assert_eq!(
        (err.code(), err.public_message()),
        (Code::Unavailable, "storage partition full")
    );
    assert_eq!(env.metrics.count(METRIC_PARTITION_FULL), 1);
    // The prune ran as a delete-only batch; nothing else was written.
    assert!(env.rows().is_empty(), "{:?}", env.rows());
}

#[test]
fn dropped_request_future_leaves_no_partial_state() {
    let u = upd(HEAD, Missing, A);
    let (pre, post) = {
        let env = env(authv2());
        let before = env.rows();
        env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap();
        (before, env.rows())
    };
    for polls in 0.. {
        let clock = clock();
        let mut spy = Spy::new(store(&clock));
        spy.yields = true;
        let env = build(cfg(authv2()), spy, Hooks::new(), clock);
        let a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
        let mut fut = Box::pin(env.pipe.update_ref(&a, u.clone()));
        let mut done = false;
        for _ in 0..polls {
            if fut
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                done = true;
                break;
            }
        }
        drop(fut);
        let rows = env.rows();
        assert!(rows == pre || rows == post, "after {polls} polls");
        if done {
            assert_eq!(rows, post);
            break;
        }
    }
}

#[test]
fn list_refs_strips_prefix_and_paginates() {
    let clock = clock();
    let mut cfg = cfg(AuthMode::Open);
    cfg.list_page_limit = 2;
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let names = ["a", "b", "c", "d", "e"].map(|n| format!("refs/heads/{n}"));
    let mut refs: Vec<_> = names.iter().map(|n| (n.as_str(), A)).collect();
    refs.push(("refs/tags/v1", B));
    seed(&env.pipe.meta.inner, &refs);
    let a = env.auth(&Req::unsigned(Procedure::ListRefs)).unwrap();
    let listed = block_on(env.pipe.list_refs(&a, "refs/heads/")).unwrap();
    let got: Vec<_> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(got, ["a", "b", "c", "d", "e"]);
    assert_eq!(block_on(env.pipe.list_refs(&a, "")).unwrap().len(), 6);
    assert_eq!(
        code(block_on(env.pipe.list_refs(&a, "/"))),
        Code::InvalidArgument
    );
    // Five refs at two per page is three scans.
    let scans = env.pipe.meta.seen.lock().unwrap().len();
    assert_eq!(scans, 3 + 3);
}

#[test]
fn store_error_is_redacted() {
    let clock = clock();
    let kv = store(&clock).with_fault(MemoryFault::ApplyBefore);
    let env = build(cfg(AuthMode::Open), Spy::new(kv), Hooks::new(), clock);
    let err = env.open_update(&upd(HEAD, Missing, A)).unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.public_message(), "ref store request failed");
    for shown in [format!("{err}"), format!("{err:?}")] {
        assert!(!shown.contains("injected"), "{shown}");
    }
    assert!(err.log_detail().unwrap().contains("injected"));
}

type AdmissionSeen = (Option<String>, u64, Option<QuotaLimits>);

#[derive(Default)]
struct SpyAdmission(Mutex<Vec<AdmissionSeen>>);

impl Admission for SpyAdmission {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        let seen = (
            input.idempotency_key.map(str::to_owned),
            input.declared_bytes,
            input.write_quota,
        );
        self.0.lock().unwrap().push(seen);
        DefaultAdmission.admit(input).await
    }
}

#[test]
fn admission_input_carries_nonce_and_declared_bytes() {
    let clock = clock();
    let hooks = with_admission(SpyAdmission::default());
    let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 9, &u, T0);
    env.update(&req, &u).unwrap();
    env.update(&req, &u).unwrap(); // a replay never reaches admission
    let seen = env.pipe.hooks.admission.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![(Some(nonce(9)), 0, Some(crate::quota::DEFAULT_WRITE_QUOTA))]
    );
}

#[test]
fn replay_and_quota_rows_shrink_after_load() {
    let clock = clock();
    let mut cfg = cfg(authv2());
    cfg.write_quota = Some(QuotaLimits {
        window_ms: 60_000,
        max_ops: 1_000,
        max_bytes: 0,
    });
    let env = build(cfg, Spy::new(store(&clock)), Hooks::new(), clock);
    let write = |signer: u8, n: u32| {
        let u = upd(&format!("refs/heads/s{signer}-{n}"), Missing, A);
        let created = env.clock.now_ms();
        env.update(&Req::update(&key(signer), n, &u, created), &u)
            .unwrap();
    };
    for n in 0..500 {
        write(u8::try_from(n % 50).unwrap(), n);
    }
    let counts = |env: &Env| ["p", "px", "q", "qx"].map(|t| env.count(t));
    let baseline = counts(&env);
    assert_eq!(baseline, [500, 500, 50, 50]);
    // Past the envelope window plus the prune grace, and two quota windows.
    env.clock.advance(300_000 + 60_000 + 120_000 + 1);
    // One write in eight runs the prune, of up to PRUNE_LIMIT rows each.
    for n in 500..580 {
        write(200, n);
    }
    let after = counts(&env);
    for (a, b) in after.iter().zip(baseline) {
        assert!(*a <= b, "{after:?} vs {baseline:?}");
    }
    assert_eq!(after[2..], [1, 1], "every stale quota window pruned");
}

// ------------------------------------------------- telemetry and misc

#[test]
fn metrics_count_requests_by_code_and_dropped_headers() {
    let env = env(AuthMode::Open);
    env.open_update(&upd(HEAD, Missing, A)).unwrap();
    let _ = env.open_update(&upd("refs/heads/..", Missing, A));
    let requests: Vec<_> = env
        .metrics
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|(n, _)| *n == METRIC_REQUESTS)
        .map(|(_, labels)| labels.clone())
        .collect();
    let label = |code: &str| {
        vec![
            ("procedure".to_owned(), "UpdateRef".to_owned()),
            ("code".to_owned(), code.to_owned()),
        ]
    };
    assert_eq!(requests, vec![label("ok"), label("invalid_argument")]);
    let err = env
        .pipe
        .with_header(ServerError::unavailable("x"), "Retry-After", "1");
    let err = env.pipe.with_header(err, "Bad Name", "v");
    assert_eq!(err.headers().len(), 1);
    assert_eq!(env.metrics.count(METRIC_HEADER_DROPPED), 1);
}

#[test]
fn health_probes_both_stores() {
    let env = env(AuthMode::Open);
    assert!(block_on(env.pipe.health()).is_healthy());
}

#[test]
fn entry_futures_are_send() {
    fn send<T: Send>(_: &T) {}
    let env = env(authv2());
    let u = upd(HEAD, Missing, A);
    let a = env.auth(&Req::update(&key(7), 1, &u, T0)).unwrap();
    send(&env.pipe.update_ref(&a, u));
    send(&env.pipe.list_refs(&a, ""));
}

fn ms(t: i64) -> u64 {
    u64::try_from(t).unwrap()
}

#[test]
fn plan_signed_conflict_still_charges_quota() {
    let name = repo_name();
    let refs = [upd(HEAD, Missing, C)];
    let charges = [charge(5)];
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        replay: Some(replay()),
        charges: &charges,
        grant: None,
        layout_version: false,
    };
    let values = [ref_value(HEAD, A)];
    let clock = clock_at(ms(T0), None);
    let Planned::Apply(plan) = plan_write(&req, &snapshot(&req, &values), &clock).unwrap() else {
        panic!("a signed conflict is stored");
    };
    let conflict = UpdateRefResult::Conflict { current: Some(A) };
    assert_eq!(plan.on_commit, StoredResult::UpdateRef(conflict));
    let quota = keys::quota(&charges[0].scope);
    let after = plan.batch.writes.iter().find_map(|w| match w {
        Write::Put(k, v) if *k == quota => Some(codec::decode_quota_state(v).unwrap()),
        _ => None,
    });
    let one = QuotaState {
        window_start: T0,
        ops: 1,
        bytes: 0,
    };
    assert_eq!(after, Some(one));
    assert!(
        plan.batch
            .preconditions
            .contains(&Precondition::Absent(quota))
    );
    let ref_key = keys::ref_key(&name, HEAD);
    let moved = plan
        .batch
        .writes
        .iter()
        .any(|w| matches!(w, Write::Put(k, _) if *k == ref_key));
    assert!(!moved, "the ref stays");
}

#[test]
fn plan_prune_fits_the_batch_op_cap() {
    let name = repo_name();
    let refs = [upd(PACKMAP, Any, C), upd(HEAD, Any, C)];
    let charges: Vec<_> = (0u8..4)
        .map(|i| QuotaCharge {
            scope: QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[i; 32]),
            ..charge(5)
        })
        .collect();
    let req = WriteRequest {
        repo: &name,
        kind: WriteKind::AdvanceRefs,
        refs: &refs,
        replay: Some(replay()),
        charges: &charges,
        grant: None,
        layout_version: true,
    };
    let mut snap = snapshot(&req, &[]);
    let limit = usize::try_from(PRUNE_LIMIT).unwrap();
    for i in 0..limit {
        let old = [u8::try_from(100 + i).unwrap(); 32];
        snap.expired_replays
            .push((keys::replay_expiry(1, &old), keys::replay(&old)));
        let scope = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &old);
        let state = QuotaState {
            window_start: 5,
            ops: 1,
            bytes: 0,
        };
        let quota = keys::quota(&scope);
        snap.insert(quota.clone(), Some(codec::encode_quota_state(&state)));
        snap.stale_quotas
            .push((keys::quota_window(5, &scope), quota));
    }
    let Planned::Apply(plan) = plan_write(&req, &snap, &clock_at(ms(T0), None)).unwrap() else {
        panic!("a write");
    };
    let ops = plan.batch.preconditions.len() + plan.batch.writes.len();
    assert!(ops <= crate::store::MAX_BATCH_OPS, "{ops}");
    assert!(plan.batch.validate(&StoreCapabilities::full()).is_ok());
    let prune = plan.prune.unwrap();
    assert!(prune.writes.len() >= 2 * limit, "every replay pair fits");
    // Prune guards come last, from `prune_from` on.
    let guards = &plan.batch.preconditions[plan.prune_from..];
    assert_eq!(guards, &prune.preconditions[1..]);
    assert!(guards.iter().all(|p| matches!(p, Precondition::Equals(..))));
}

#[test]
fn prune_sampling_is_deterministic_one_in_eight() {
    let name = repo_name();
    let refs = [upd(HEAD, Any, C)];
    let request = |replay: Option<ReplayGuard>| WriteRequest {
        repo: &name,
        kind: WriteKind::UpdateRef,
        refs: &refs,
        replay,
        charges: &[],
        grant: None,
        layout_version: false,
    };
    let sampled = (0u8..=255)
        .filter(|b| {
            let scoped = ReplayGuard {
                scope: [*b; 32],
                ..replay()
            };
            prune_sampled(&request(Some(scoped)), 3)
        })
        .count();
    assert_eq!(sampled, 256 / 8);
    assert!(!prune_sampled(&request(None), 8), "nothing to prune");
}

#[test]
fn admission_allow_constructor() {
    let decision = AdmissionDecision::allow(vec![charge(1)]).with_reservation("r-1");
    let AdmissionDecision::Allow {
        charges,
        reservation,
    } = decision
    else {
        panic!("allow");
    };
    assert_eq!(
        (charges, reservation),
        (vec![charge(1)], Some("r-1".into()))
    );
    let deny = AdmissionDecision::Deny(crate::ServerError::permission_denied("no"));
    assert!(matches!(
        deny.with_reservation("x"),
        AdmissionDecision::Deny(_)
    ));
}

// ---------------------------------------------- review: round trips etc.

#[test]
fn signed_write_costs_two_backend_calls_in_steady_state() {
    let env = env(authv2());
    let k = key(7);
    let mut measured = Vec::new();
    let mut n = 0;
    for (i, sampled) in [false, false, true, false].into_iter().enumerate() {
        n = nonce_where(&env, &k, sampled, n + 1);
        let u = upd(&format!("refs/heads/b{i}"), Missing, A);
        let before = env.pipe.meta.calls();
        env.update(&Req::update(&k, n, &u, T0), &u).unwrap();
        measured.push((sampled, env.pipe.meta.calls() - before));
    }
    // One get_many and one apply; a sampled write adds its two prune scans.
    assert_eq!(measured, [(false, 2), (false, 2), (true, 4), (false, 2)]);
    // A replay is one read and no apply.
    let u = upd("refs/heads/b0", Missing, A);
    let first = nonce_where(&env, &k, false, 1);
    let before = env.pipe.meta.calls();
    env.update(&Req::update(&k, first, &u, T0), &u).unwrap();
    assert_eq!(env.pipe.meta.calls() - before, 1);
}

#[test]
fn signed_deadline_is_capped_by_the_envelope() {
    // A long apply window: the envelope cap binds.
    let first = clock();
    let mut long = cfg(authv2());
    long.max_apply_window = Duration::from_mins(2);
    let env = build(long, Spy::new(store(&first)), Hooks::new(), first);
    let u = upd(HEAD, Missing, A);
    let req = Req::update(&key(7), 1, &u, T0);
    env.clock.set(T0 + 290_000);
    env.update(&req, &u).unwrap();
    let expires = ms(T0) + 300_000;
    let cap = expires + MAX_CLOCK_LEAD_MS.unsigned_abs();
    assert_eq!(
        env.batches()[0].preconditions[0],
        Precondition::NotAfter(cap)
    );

    // A late batch whose envelope expired meanwhile is not re-planned.
    let clock = clock();
    clock.set(T0 + 295_000);
    let spy = Spy::new(store(&clock)).hook(late(&clock, 1));
    let env = build(cfg(authv2()), spy, Hooks::new(), clock);
    let err = env.update(&req, &u).unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert_eq!(env.batches().len(), 1);
    assert!(env.rows().is_empty());
}

#[test]
fn deny_with_402_but_no_challenge_detail_is_403() {
    let paid = ServerError::permission_denied("pay").with_http_status(402);
    let challenge = ServerError::admission_challenge(bytes::Bytes::from_static(b"c"));
    for (denial, status) in [(paid, 403), (challenge, 402)] {
        let clock = clock();
        let hooks = with_admission(Fixed(AdmissionDecision::Deny(denial)));
        let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
        let u = upd(HEAD, Missing, A);
        let err = env
            .update(&Req::update(&key(7), 1, &u, T0), &u)
            .unwrap_err();
        assert_eq!(
            (err.code(), err.http_status()),
            (Code::PermissionDenied, Some(status))
        );
        assert!(env.rows().is_empty());
    }
}

struct Granting;

impl Authorizer for Granting {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        Ok(AuthzFacts {
            owner: true,
            grant: Some(crate::op::GrantRef {
                id: [9; 32],
                epoch: 0,
            }),
        })
    }
}

#[derive(Default)]
struct SeesAuthz(Mutex<Option<AuthzFacts>>);

impl Admission for SeesAuthz {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        *self.0.lock().unwrap() = Some(input.op.authz.clone());
        Ok(AdmissionDecision::allow(Vec::new()))
    }
}

#[test]
fn authorizer_facts_reach_admission_and_apply() {
    let clock = clock();
    let hooks = Hooks {
        authorizer: Granting,
        admission: SeesAuthz::default(),
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: NoOutcomes,
    };
    let env = build(cfg(authv2()), Spy::new(store(&clock)), hooks, clock);
    let u = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), 1, &u, T0), &u).unwrap();
    let seen = env.pipe.hooks.admission.0.lock().unwrap().clone().unwrap();
    assert!(seen.owner);
    assert_eq!(seen.grant.map(|g| g.epoch), Some(0));
    // The grant's epoch is required at apply: absent means epoch 0.
    let guard = Precondition::Absent(keys::grant_epoch());
    assert!(env.batches()[0].preconditions.contains(&guard));
}

#[test]
fn lost_prune_race_retries_without_prune_uncounted() {
    let clock = clock();
    let other = QuotaScope::for_signer(&NamespaceKey::deployment_default(), &[42; 32]);
    let quota = keys::quota(&other);
    let stale = QuotaState {
        window_start: 1,
        ops: 1,
        bytes: 0,
    };
    let kv = store(&clock);
    let seed_batch = Batch::new()
        .put(quota.clone(), codec::encode_quota_state(&stale))
        .put(keys::quota_window(1, &other), Value::default());
    now(kv.apply(&ns(), seed_batch)).unwrap();
    // Apply 0: another writer moves the stale quota row (the prune guard
    // fails). Applies 1..=MAX_REPLAN: a real guard breaks each time.
    let (applies, layout) = (AtomicU32::new(0), interfere(MAX_REPLAN));
    let race = quota.clone();
    let hook = move |kv: &MemoryKv, p: &Partition, batch: &Batch| {
        if applies.fetch_add(1, Ordering::SeqCst) == 0 {
            let moved = QuotaState { ops: 2, ..stale };
            let bump = Batch::new().put(race.clone(), codec::encode_quota_state(&moved));
            now(kv.apply(p, bump)).unwrap();
        } else {
            layout(kv, p, batch);
        }
    };
    let env = build(cfg(authv2()), Spy::new(kv).hook(hook), Hooks::new(), clock);
    let n = nonce_where(&env, &key(7), true, 1);
    let u = upd(HEAD, Missing, A);
    env.update(&Req::update(&key(7), n, &u, T0), &u).unwrap();
    let batches = env.batches();
    assert_eq!(batches.len(), usize::try_from(MAX_REPLAN).unwrap() + 2);
    let deletes = |b: &Batch| b.writes.iter().any(|w| matches!(w, Write::Delete(_)));
    assert!(deletes(&batches[0]), "the first attempt prunes");
    assert!(!batches[1..].iter().any(deletes), "the retries do not");
    let kept = now(env.pipe.meta.inner.get(&ns(), &quota)).unwrap();
    assert!(kept.is_some(), "the raced row is not pruned");
}
