//! Coordinator creation, ordering and round-trip costs on both metadata backends.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use mkit_core::protocol::RefWriteCondition;
use mkit_core::repo_identity::Namespace;
use mkit_server::Clock;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authenticated, Authorizer, D34Shards,
    Hooks, Pipeline, PipelineConfig, PreReceive, RequestMeta, ShardMap, Sharding, SinglePartition,
};
use mkit_server::policy::NamespacePolicy;
use mkit_server::relay::{NoHook, RelayBudget, RelayHandler};
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, BlobKey, Cursor, Key, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value, Write, codec, keys,
};
use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::{
    Addressing, Code, MemoryBlobStore, MemoryKv, MultiAddressing, NamespaceStore, NoopMetrics,
    Procedure, RefUpdate, ServerError, SystemClock, UpdateRefResult,
};
use mkit_server::{AuthzFacts, Creation, Operation};
use mkit_server_conformance::wire::sign::Signer;
use mkit_server_native::{Blocking, RusqliteConn};
use proptest::prelude::*;
use tokio::sync::Barrier;

const AUDIENCE: &str = "http://localhost:9876";
const BODY: &[u8] = b"coordinator creation request";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Get(Partition, Key),
    Many(Partition, Vec<Key>),
    Scan(Partition),
    Apply(Partition),
    Stats,
    Probe,
}

#[derive(Default)]
struct Controls {
    calls: Mutex<Vec<Call>>,
    race: Mutex<Option<Arc<Barrier>>>,
    race_reads: AtomicUsize,
    fail_refs: AtomicBool,
    fail_index_scan: AtomicBool,
    fail_grants: AtomicUsize,
}

struct TestStore<N> {
    inner: Arc<N>,
    controls: Arc<Controls>,
}

impl<N> Clone for TestStore<N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            controls: self.controls.clone(),
        }
    }
}

impl<N> TestStore<N> {
    fn new(inner: N) -> Self {
        Self {
            inner: Arc::new(inner),
            controls: Arc::new(Controls::default()),
        }
    }

    fn record(&self, call: Call) {
        self.controls.calls.lock().unwrap().push(call);
    }

    fn take_calls(&self) -> Vec<Call> {
        std::mem::take(&mut *self.controls.calls.lock().unwrap())
    }
}

impl<N: NamespaceStore> NamespaceStore for TestStore<N> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.record(Call::Get(p.clone(), key.clone()));
        self.inner.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        names: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.record(Call::Many(p.clone(), names.to_vec()));
        let values = self.inner.get_many(p, names).await?;
        // Single reads nr/rr; D34 folds creation into the nr/rr/e/ls/lr
        // lease snapshot. Both coordinator reads pause after observation.
        if names.first() == Some(&keys::namespace_record()) {
            assert!(names.len() == 2 || names.len() == 5);
            if names.len() == 5 {
                assert_eq!(names[2], keys::grant_epoch());
                assert!(names[3].as_bytes().starts_with(b"ls\0"));
                assert_eq!(names[4], keys::lease_recovery());
            }
            let barrier = self.controls.race.lock().unwrap().clone();
            if let Some(barrier) = barrier
                && self.controls.race_reads.fetch_add(1, Ordering::SeqCst) < 2
            {
                assert!(values.iter().all(Option::is_none));
                barrier.wait().await;
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
        self.record(Call::Scan(p.clone()));
        if matches!(p, Partition::RefIndex { .. })
            && self.controls.fail_index_scan.load(Ordering::SeqCst)
        {
            return Err(StoreError::Unsupported(
                "injected index scan failure".into(),
            ));
        }
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.record(Call::Apply(p.clone()));
        let writes_lease = batch.writes.iter().any(
            |write| matches!(write, Write::Put(key, _) if key.as_bytes().starts_with(b"ls\0")),
        );
        if writes_lease
            && self
                .controls
                .fail_grants
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Ok(BatchOutcome::PreconditionFailed {
                index: 3,
                observed: None,
            });
        }
        let writes_ref = batch
            .writes
            .iter()
            .any(|write| matches!(write, Write::Put(key, _) if keys::is_ref_key(key)));
        if writes_ref && self.controls.fail_refs.load(Ordering::SeqCst) {
            return Err(StoreError::Unsupported("injected ref apply failure".into()));
        }
        self.inner.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.record(Call::Stats);
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.record(Call::Probe);
        self.inner.probe().await
    }
}

#[derive(Default)]
struct Observations {
    admitted: Mutex<Vec<Creation>>,
    created: Mutex<Vec<Creation>>,
}

#[derive(Clone)]
struct Observe {
    observations: Arc<Observations>,
    challenge: bool,
}

impl Admission for Observe {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        assert_eq!(input.creates_namespace, input.op.creation.namespace);
        assert_eq!(input.creates_repo, input.op.creation.repo);
        self.observations
            .admitted
            .lock()
            .unwrap()
            .push(input.op.creation);
        if self.challenge {
            Ok(AdmissionDecision::challenge(
                vec![mkit_server::pipeline::Challenge {
                    scheme: "mpp".into(),
                    value: "pay".into(),
                }],
                "test admission challenge",
            ))
        } else {
            Ok(AdmissionDecision::allow(Vec::new()))
        }
    }
}

impl PreReceive for Observe {
    async fn check(&self, op: &Operation, _: Option<&BlobKey>) -> Result<(), ServerError> {
        self.observations.created.lock().unwrap().push(op.created);
        Ok(())
    }
}

struct Policy {
    deny: bool,
}

impl Authorizer for Policy {
    async fn authorize(&self, _: &Operation) -> Result<AuthzFacts, ServerError> {
        if self.deny {
            Err(ServerError::permission_denied("test authorization denial"))
        } else {
            Ok(AuthzFacts::default())
        }
    }
}

type TestPipeline<N> = Pipeline<MemoryBlobStore, TestStore<N>, Hooks<Policy, Observe, Observe>>;

fn pipeline<N: NamespaceStore>(
    store: TestStore<N>,
    sharding: Sharding,
    addressing: Addressing,
    challenge: bool,
    deny: bool,
) -> (TestPipeline<N>, Arc<Observations>) {
    pipeline_with_page_limit(store, sharding, addressing, challenge, deny, 1000)
}

fn pipeline_with_page_limit<N: NamespaceStore>(
    store: TestStore<N>,
    sharding: Sharding,
    addressing: Addressing,
    challenge: bool,
    deny: bool,
    page_limit: u32,
) -> (TestPipeline<N>, Arc<Observations>) {
    let observations = Arc::new(Observations::default());
    let observer = Observe {
        observations: observations.clone(),
        challenge,
    };
    let defaults = Hooks::new();
    let hooks = Hooks {
        authorizer: Policy { deny },
        admission: observer.clone(),
        pre_receive: observer,
        receipts: defaults.receipts,
        outcomes: defaults.outcomes,
    };
    let auth = AuthMode::AuthV2(
        AuthV2Config::new(
            AUDIENCE,
            match &addressing {
                Addressing::Single { repo } => repo.name.as_str(),
                _ => "",
            },
        )
        .unwrap(),
    );
    let mut cfg = PipelineConfig::new(
        addressing,
        auth,
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    );
    cfg.sharding = sharding;
    cfg.list_page_limit = page_limit;
    cfg.write_quota = None;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap());
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        store,
        hooks,
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    (pipe, observations)
}

async fn real_index_listing<N: NamespaceStore>(backend: N, names: &[String]) {
    let store = TestStore::new(backend);
    let (pipe, _) =
        pipeline_with_page_limit(store.clone(), Sharding::D34, multi(), false, false, 3);
    let identities = [identity("index-a"), identity("index-b")];
    for repository in &identities {
        let auth = signed(&pipe, repository);
        pipe.update_ref(&auth, update("refs/heads/bootstrap", 1))
            .await
            .unwrap();
        for name in names {
            let target = D34Shards.ref_index(&auth.repo().repo, name);
            let value = if repository == &identities[0] {
                [1; 32]
            } else {
                [2; 32]
            };
            store
                .inner
                .apply(
                    &target,
                    Batch::new().put(
                        keys::ref_index_key(&auth.repo().repo.name, name),
                        codec::encode_ref_id(&value),
                    ),
                )
                .await
                .unwrap();
        }
    }
    for (repository, id) in identities.iter().zip([[1; 32], [2; 32]]) {
        let reader = read(&pipe, Procedure::ListRefs, repository);
        let got = pipe.list_refs(&reader, "refs/heads/").await.unwrap();
        let expected = names
            .iter()
            .map(|name| name.strip_prefix("refs/heads/").unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            got.iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(got.iter().all(|entry| entry.id == id));
        let narrow = pipe.list_refs(&reader, "refs/heads/feat/").await.unwrap();
        assert_eq!(
            narrow
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            names
                .iter()
                .filter_map(|name| name.strip_prefix("refs/heads/feat/"))
                .collect::<Vec<_>>()
        );
    }
}

async fn index_corruption_unavailable<N: NamespaceStore>(backend: N) {
    let store = TestStore::new(backend);
    let (pipe, _) = pipeline(store.clone(), Sharding::D34, multi(), false, false);
    let identity = identity("index-corrupt");
    let auth = signed(&pipe, &identity);
    pipe.update_ref(&auth, update("refs/heads/main", 1))
        .await
        .unwrap();
    let reader = read(&pipe, Procedure::ListRefs, &identity);
    store.controls.fail_index_scan.store(true, Ordering::SeqCst);
    assert_eq!(
        pipe.list_refs(&reader, "").await.unwrap_err().code(),
        Code::Unavailable
    );
    store
        .controls
        .fail_index_scan
        .store(false, Ordering::SeqCst);
    let name = "refs/heads/wrong";
    let correct = D34Shards.ref_index(&auth.repo().repo, name);
    let wrong = D34Shards
        .ref_index_partitions(&auth.repo().repo)
        .into_iter()
        .find(|p| p != &correct)
        .unwrap();
    store
        .inner
        .apply(
            &wrong,
            Batch::new().put(
                keys::ref_index_key(&auth.repo().repo.name, name),
                codec::encode_ref_id(&[9; 32]),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        pipe.list_refs(&reader, "").await.unwrap_err().code(),
        Code::Unavailable
    );
}

async fn relay_ref_index_lag<N: NamespaceStore + 'static>(backend: N) {
    let store = TestStore::new(backend);
    let (pipe, _) = pipeline(store.clone(), Sharding::D34, multi(), false, false);
    let identity = identity("index-lag");
    let name = "refs/heads/main";
    let auth = signed(&pipe, &identity);
    pipe.update_ref(&auth, update(name, 1)).await.unwrap();
    let reader = read(&pipe, Procedure::ListRefs, &identity);
    let ref_reader = read(&pipe, Procedure::ReadRef, &identity);
    assert_eq!(
        pipe.read_ref(&ref_reader, name).await.unwrap(),
        Some([1; 32])
    );
    assert!(
        pipe.list_refs(&reader, "refs/heads/")
            .await
            .unwrap()
            .is_empty()
    );
    let source = D34Shards.ref_shard(&auth.repo().repo, name);
    let registry = TimerRegistry::new().register(RelayHandler {
        target: store.clone(),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    let budget = TickBudget::default();
    let clock = SystemClock;
    let tick = || {
        run_due(
            &store,
            &source,
            &registry,
            &clock,
            u64::try_from(clock.now_ms()).unwrap(),
            &budget,
        )
    };
    assert!(tick().await.unwrap().fired > 0);
    assert_eq!(
        pipe.list_refs(&reader, "refs/heads/")
            .await
            .unwrap()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        vec!["main"]
    );
    let mut delete = update(name, 0);
    delete.condition = RefWriteCondition::Match([1; 32]);
    delete.new = None;
    pipe.update_ref(&signed(&pipe, &identity), delete)
        .await
        .unwrap();
    assert_eq!(pipe.read_ref(&ref_reader, name).await.unwrap(), None);
    assert_eq!(
        pipe.list_refs(&reader, "refs/heads/").await.unwrap().len(),
        1
    );
    assert!(tick().await.unwrap().fired > 0);
    assert!(
        pipe.list_refs(&reader, "refs/heads/")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn ref_index_lag_memory() {
    Box::pin(relay_ref_index_lag(MemoryKv::default())).await;
}

#[tokio::test]
async fn ref_index_lag_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
    Box::pin(relay_ref_index_lag(Blocking::new(
        SqlKvStore::open(conn).unwrap(),
    )))
    .await;
}

#[cfg(feature = "test-faults")]
#[tokio::test]
async fn advance_ref_relay_delay_holds_both_index_rows() {
    use mkit_server::pipeline::RELAY_DELAY_MS_HEADER;

    let store = TestStore::new(MemoryKv::default());
    let (pipe, _) = pipeline(store.clone(), Sharding::D34, multi(), false, false);
    let identity = identity("advance-delay");
    let envelope = Signer::new([1; 32], AUDIENCE, &identity)
        .sign_body(Procedure::AdvanceRefs.connect_path(), BODY);
    let mut headers = envelope.headers;
    headers.push((RELAY_DELAY_MS_HEADER.into(), "600000".into()));
    let auth = authenticate(&pipe, Procedure::AdvanceRefs, &headers);
    let head = "refs/heads/main";
    let packmap = "refs/mkit/packmap/main";
    pipe.advance_refs(&auth, update(head, 1), update(packmap, 2))
        .await
        .unwrap();

    let source = D34Shards.ref_shard(&auth.repo().repo, head);
    assert!(store.get(&source, &keys::relay(1)).await.unwrap().is_some());
    let clock = SystemClock;
    let registry = TimerRegistry::new().register(RelayHandler {
        target: store.clone(),
        hook: NoHook,
        budget: RelayBudget::default(),
    });
    let report = run_due(
        &store,
        &source,
        &registry,
        &clock,
        u64::try_from(clock.now_ms()).unwrap(),
        &TickBudget::default(),
    )
    .await
    .unwrap();
    assert_eq!(report.fired, 1);
    assert!(store.get(&source, &keys::relay(1)).await.unwrap().is_some());
    for name in [head, packmap] {
        let bucket = D34Shards.ref_index(&auth.repo().repo, name);
        assert!(
            store
                .get(&bucket, &keys::ref_index_key(&auth.repo().repo.name, name))
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn index_failures_are_unavailable_memory() {
    index_corruption_unavailable(MemoryKv::default()).await;
}

#[tokio::test]
async fn index_failures_are_unavailable_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
    index_corruption_unavailable(Blocking::new(SqlKvStore::open(conn).unwrap())).await;
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(12))]
    #[test]
    fn real_memory_and_sqlite_d34_pages_match_sorted_refs(ids in proptest::collection::vec(0u16..100, 0..30)) {
        let mut names = ids.into_iter().map(|id| format!("refs/heads/feat/n{id:03}")).collect::<Vec<_>>();
        names.extend(["refs/heads/featx".to_owned(), "refs/heads/main".to_owned()]);
        names.sort(); names.dedup();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            real_index_listing(MemoryKv::default(), &names).await;
            let dir = tempfile::tempdir().unwrap();
            let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
            real_index_listing(Blocking::new(SqlKvStore::open(conn).unwrap()), &names).await;
        });
    }
}

fn multi() -> Addressing {
    Addressing::Multi(
        MultiAddressing::new().with_namespace_policy(NamespacePolicy::Allowlist(
            [Namespace::parse(identity("unused").split_once('/').unwrap().0).unwrap()].into(),
        )),
    )
}

fn identity(repo: &str) -> String {
    format!(
        "ed25519-{}/{repo}",
        Signer::new([1; 32], AUDIENCE, "unused").public_key_hex()
    )
}

fn signed<N: NamespaceStore>(pipe: &TestPipeline<N>, identity: &str) -> Authenticated {
    let signer = Signer::new([1; 32], AUDIENCE, identity);
    // Replay pruning is sampled by scope. Select a scope outside that
    // maintenance path so the operation's call-count assertions are stable.
    loop {
        let envelope = signer.sign_body(Procedure::UpdateRef.connect_path(), BODY);
        let authenticated = authenticate(pipe, Procedure::UpdateRef, &envelope.headers);
        if !authenticated.auth.as_ref().unwrap().replay_scope[0].is_multiple_of(8) {
            return authenticated;
        }
    }
}

fn authenticate<N: NamespaceStore>(
    pipe: &TestPipeline<N>,
    procedure: Procedure,
    headers: &[(String, String)],
) -> Authenticated {
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &lookup,
        header_values: None,
        unary_body: Some(BODY),
        transport_principal: None,
    })
    .unwrap()
}

fn read<N: NamespaceStore>(
    pipe: &TestPipeline<N>,
    procedure: Procedure,
    identity: &str,
) -> Authenticated {
    authenticate(pipe, procedure, &[("x-repository".into(), identity.into())])
}

fn update(name: &str, value: u8) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Any,
        new: Some([value; 32]),
    }
}

fn facts(namespace: bool, repo: bool) -> Creation {
    let mut creation = Creation::default();
    creation.namespace = namespace;
    creation.repo = repo;
    creation
}

fn coordinator(sharding: Sharding, auth: &Authenticated) -> Partition {
    match sharding {
        Sharding::Single => SinglePartition.coordinator(&auth.repo().repo.namespace),
        Sharding::D34 => D34Shards.coordinator(&auth.repo().repo.namespace),
        _ => unreachable!(),
    }
}

fn ref_shard(sharding: Sharding, auth: &Authenticated, name: &str) -> Partition {
    match sharding {
        Sharding::Single => SinglePartition.ref_shard(&auth.repo().repo, name),
        Sharding::D34 => D34Shards.ref_shard(&auth.repo().repo, name),
        _ => unreachable!(),
    }
}

async fn registered<N: NamespaceStore>(
    store: &TestStore<N>,
    sharding: Sharding,
    auth: &Authenticated,
) {
    let p = coordinator(sharding, auth);
    let namespace = store
        .inner
        .get(&p, &keys::namespace_record())
        .await
        .unwrap()
        .unwrap();
    let repo = store
        .inner
        .get(&p, &keys::repo_record(&auth.repo().repo.name))
        .await
        .unwrap()
        .unwrap();
    let namespace = codec::decode_namespace_record(&namespace).unwrap();
    let repo = codec::decode_repo_record(&repo).unwrap();
    assert_eq!(namespace.config_version, 1);
    assert!(namespace.created_at_ms > 0);
    assert!(repo.created_at_ms > 0);
}

fn assert_fresh_shard_calls(calls: &[Call], sharding: Sharding) {
    assert_eq!(
        calls.len(),
        if sharding == Sharding::D34 { 5 } else { 3 },
        "{sharding:?}: {calls:?}"
    );
    if sharding == Sharding::D34 {
        assert!(matches!(
            calls,
            [
                Call::Many(..),
                Call::Scan(Partition::Ref { .. }),
                Call::Many(..),
                Call::Apply(..),
                Call::Apply(..)
            ]
        ));
    } else {
        assert!(matches!(
            calls,
            [Call::Many(..), Call::Many(..), Call::Apply(..)]
        ));
    }
}

async fn creation_and_cost<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    let (pipe, observed) = pipeline(store.clone(), sharding, multi(), false, false);
    let first = signed(&pipe, &identity("first"));
    assert_eq!(
        pipe.update_ref(&first, update("refs/heads/a", 1))
            .await
            .unwrap(),
        UpdateRefResult::Committed
    );
    let calls = store.take_calls();
    assert_eq!(
        calls.len(),
        if sharding == Sharding::D34 { 5 } else { 4 },
        "{sharding:?}: {calls:?}"
    );
    assert!(if sharding == Sharding::D34 {
        matches!(
            calls.as_slice(),
            [
                Call::Many(..),
                Call::Scan(Partition::Ref { .. }),
                Call::Many(..),
                Call::Apply(..),
                Call::Apply(..)
            ]
        )
    } else {
        matches!(
            calls.as_slice(),
            [
                Call::Many(..),
                Call::Many(..),
                Call::Apply(..),
                Call::Apply(..)
            ]
        )
    });
    registered(&store, sharding, &first).await;

    let steady = signed(&pipe, &identity("first"));
    pipe.update_ref(&steady, update("refs/heads/a", 2))
        .await
        .unwrap();
    let calls = store.take_calls();
    assert_eq!(calls.len(), 2, "{sharding:?}: {calls:?}");
    assert!(matches!(
        calls.as_slice(),
        [Call::Many(..), Call::Apply(..)]
    ));

    // Single has one ref partition, so remove its local hint to model a
    // fresh shard of an already registered repo without changing registry rows.
    if sharding == Sharding::Single {
        store
            .inner
            .apply(
                &ref_shard(sharding, &first, "refs/heads/b"),
                Batch::new().delete(keys::repo_known(&first.repo().repo.name)),
            )
            .await
            .unwrap();
    }
    let fresh = signed(&pipe, &identity("first"));
    pipe.update_ref(&fresh, update("refs/heads/b", 3))
        .await
        .unwrap();
    let calls = store.take_calls();
    assert_fresh_shard_calls(&calls, sharding);

    let second = signed(&pipe, &identity("second"));
    pipe.update_ref(&second, update("refs/heads/a", 4))
        .await
        .unwrap();
    assert_eq!(
        store.take_calls().len(),
        if sharding == Sharding::D34 { 5 } else { 4 }
    );
    registered(&store, sharding, &second).await;
    let expected = vec![
        facts(true, true),
        facts(false, false),
        facts(false, false),
        facts(false, true),
    ];
    assert_eq!(*observed.admitted.lock().unwrap(), expected);
    assert_eq!(*observed.created.lock().unwrap(), expected);
}

async fn creation_race<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    *store.controls.race.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    let (pipe, observed) = pipeline(store.clone(), sharding, multi(), false, false);
    let a = signed(&pipe, &identity("racing"));
    let b = signed(&pipe, &identity("racing"));
    let writes = async {
        tokio::join!(
            pipe.update_ref(&a, update("refs/heads/a", 1)),
            pipe.update_ref(&b, update("refs/heads/b", 2)),
        )
    };
    let (a_result, b_result) = tokio::time::timeout(std::time::Duration::from_secs(10), writes)
        .await
        .unwrap();
    assert_eq!(a_result.unwrap(), UpdateRefResult::Committed);
    assert_eq!(b_result.unwrap(), UpdateRefResult::Committed);
    assert_eq!(
        *observed.admitted.lock().unwrap(),
        vec![facts(true, true); 2]
    );
    let created = observed.created.lock().unwrap().clone();
    assert_eq!(created.len(), 2);
    assert_eq!(created.iter().filter(|c| c.namespace).count(), 1);
    assert_eq!(created.iter().filter(|c| c.repo).count(), 1);
    registered(&store, sharding, &a).await;
    let reader = read(&pipe, Procedure::ReadRef, &identity("racing"));
    for (name, value) in [("refs/heads/a", 1), ("refs/heads/b", 2)] {
        assert_eq!(
            pipe.read_ref(&reader, name).await.unwrap(),
            Some([value; 32])
        );
    }
}

async fn lease_grant_retries_contention<N: NamespaceStore>(backend: N) {
    let store = TestStore::new(backend);
    store.controls.fail_grants.store(4, Ordering::SeqCst);
    let (pipe, _) = pipeline(store.clone(), Sharding::D34, multi(), false, false);
    let auth = signed(&pipe, &identity("grant-race"));
    assert_eq!(
        pipe.update_ref(&auth, update("refs/heads/a", 1))
            .await
            .unwrap(),
        UpdateRefResult::Committed
    );
    assert_eq!(store.controls.fail_grants.load(Ordering::SeqCst), 0);
    let coordinator = coordinator(Sharding::D34, &auth);
    assert_eq!(
        store
            .take_calls()
            .iter()
            .filter(|call| matches!(call, Call::Apply(p) if p == &coordinator))
            .count(),
        5
    );
}

/// Two first writes to different repos of a new namespace: both observe
/// `{true, true}`, one creates the namespace, and each registers its own
/// repo (the loser of `nr` retries with only its `rr`).
async fn creation_race_two_repos<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    *store.controls.race.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    let (pipe, observed) = pipeline(store.clone(), sharding, multi(), false, false);
    let a = signed(&pipe, &identity("repo-x"));
    let b = signed(&pipe, &identity("repo-y"));
    let writes = async {
        tokio::join!(
            pipe.update_ref(&a, update("refs/heads/a", 1)),
            pipe.update_ref(&b, update("refs/heads/b", 2)),
        )
    };
    let (a_result, b_result) = tokio::time::timeout(std::time::Duration::from_secs(10), writes)
        .await
        .unwrap();
    assert_eq!(a_result.unwrap(), UpdateRefResult::Committed);
    assert_eq!(b_result.unwrap(), UpdateRefResult::Committed);
    assert_eq!(
        *observed.admitted.lock().unwrap(),
        vec![facts(true, true); 2]
    );
    let created = observed.created.lock().unwrap().clone();
    assert_eq!(created.len(), 2);
    assert_eq!(created.iter().filter(|c| c.namespace).count(), 1);
    assert_eq!(created.iter().filter(|c| c.repo).count(), 2);
    registered(&store, sharding, &a).await;
    registered(&store, sharding, &b).await;
}

async fn no_state_on_rejection<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    for (repo, challenge, deny) in [("challenged", true, false), ("denied", false, true)] {
        let (pipe, observed) = pipeline(store.clone(), sharding, multi(), challenge, deny);
        let auth = signed(&pipe, &identity(repo));
        assert_eq!(
            pipe.update_ref(&auth, update("refs/heads/a", 1))
                .await
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
        let calls = store.take_calls();
        assert_eq!(calls.len(), if sharding == Sharding::D34 { 3 } else { 2 });
        assert!(
            calls
                .iter()
                .all(|call| matches!(call, Call::Many(..) | Call::Scan(..)))
        );
        let p = coordinator(sharding, &auth);
        for key in [
            keys::namespace_record(),
            keys::repo_record(&auth.repo().repo.name),
        ] {
            assert!(store.inner.get(&p, &key).await.unwrap().is_none());
        }
        let shard = ref_shard(sharding, &auth, "refs/heads/a");
        assert_eq!(store.inner.stats(&shard).await.unwrap().keys, Some(0));
        assert!(observed.created.lock().unwrap().is_empty());
    }
}

async fn replay_skips_coordinator<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    let (pipe, observed) = pipeline(store.clone(), sharding, multi(), false, false);
    let auth = signed(&pipe, &identity("replay"));
    let request = update("refs/heads/a", 1);
    pipe.update_ref(&auth, request.clone()).await.unwrap();
    store
        .inner
        .apply(
            &ref_shard(sharding, &auth, "refs/heads/a"),
            Batch::new().delete(keys::repo_known(&auth.repo().repo.name)),
        )
        .await
        .unwrap();
    store.take_calls();
    assert_eq!(
        pipe.update_ref(&auth, request).await.unwrap(),
        UpdateRefResult::Committed
    );
    let calls = store.take_calls();
    assert_eq!(calls.len(), 1, "{sharding:?}: {calls:?}");
    assert!(
        matches!(calls.first(), Some(Call::Many(_, names)) if names.first() != Some(&keys::namespace_record()))
    );
    assert_eq!(observed.admitted.lock().unwrap().len(), 1);
    assert_eq!(observed.created.lock().unwrap().len(), 1);
}

async fn registered_before_refs<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    let (pipe, _) = pipeline(store.clone(), sharding, multi(), false, false);
    let identity = identity("empty");
    let reader = read(&pipe, Procedure::ReadRef, &identity);
    assert_eq!(
        pipe.read_ref(&reader, "refs/heads/a")
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    let auth = signed(&pipe, &identity);
    store.controls.fail_refs.store(true, Ordering::SeqCst);
    assert!(
        pipe.update_ref(&auth, update("refs/heads/a", 1))
            .await
            .is_err()
    );
    registered(&store, sharding, &auth).await;
    let shard = ref_shard(sharding, &auth, "refs/heads/a");
    let marker = keys::repo_known(&auth.repo().repo.name);
    assert!(store.inner.get(&shard, &marker).await.unwrap().is_none());
    assert_eq!(pipe.read_ref(&reader, "refs/heads/a").await.unwrap(), None);
    let listed = pipe
        .list_refs(&read(&pipe, Procedure::ListRefs, &identity), "refs")
        .await;
    assert!(listed.unwrap().is_empty());
    store.controls.fail_refs.store(false, Ordering::SeqCst);
    pipe.update_ref(&auth, update("refs/heads/a", 1))
        .await
        .unwrap();
    assert_eq!(
        store.inner.get(&shard, &marker).await.unwrap(),
        Some(Value::new(Vec::new()))
    );
    assert_eq!(
        pipe.read_ref(&reader, "refs/heads/a").await.unwrap(),
        Some([1; 32])
    );
}

async fn single_addressing<N: NamespaceStore>(backend: N, sharding: Sharding) {
    let store = TestStore::new(backend);
    let addressing = Addressing::Single {
        repo: mkit_server::RepoId {
            namespace: mkit_server::NamespaceKey::deployment_default(),
            name: mkit_server::RepoName::new("configured").unwrap(),
        },
    };
    let (pipe, observed) = pipeline(store.clone(), sharding, addressing, false, false);
    let reader = read(&pipe, Procedure::ReadRef, "configured");
    assert_eq!(pipe.read_ref(&reader, "refs/heads/a").await.unwrap(), None);
    assert_eq!(store.take_calls().len(), 1);
    let auth = signed(&pipe, "configured");
    pipe.update_ref(&auth, update("refs/heads/a", 1))
        .await
        .unwrap();
    assert_eq!(
        store.take_calls().len(),
        if sharding == Sharding::D34 { 5 } else { 2 }
    );
    assert_eq!(
        *observed.admitted.lock().unwrap(),
        vec![Creation::default()]
    );
    assert_eq!(*observed.created.lock().unwrap(), vec![Creation::default()]);
    let p = coordinator(sharding, &auth);
    // D34 needs nr/rr even with Single addressing: lease grants guard the
    // registry rows and carry nr.config_version into el. Creation facts stay
    // false because the configured repository already exists to the caller.
    for key in [
        keys::namespace_record(),
        keys::repo_record(&auth.repo().repo.name),
    ] {
        assert_eq!(
            store.inner.get(&p, &key).await.unwrap().is_some(),
            sharding == Sharding::D34
        );
    }
    if sharding == Sharding::D34 {
        store.take_calls();
        let fresh = signed(&pipe, "configured");
        pipe.update_ref(&fresh, update("refs/heads/a", 2))
            .await
            .unwrap();
        let calls = store.take_calls();
        assert_eq!(calls.len(), 2, "steady D34 ref write: {calls:?}");
        assert!(matches!(
            calls.as_slice(),
            [Call::Many(..), Call::Apply(..)]
        ));
        let reader = read(&pipe, Procedure::ListRefs, "configured");
        let _ = pipe.list_refs(&reader, "refs/heads/").await.unwrap();
        let calls = store.take_calls();
        assert!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Scan(Partition::RefIndex { .. })))
                .count()
                <= 16
        );
    }
}

macro_rules! backends {
    ($memory:ident, $sqlite:ident, $scenario:ident) => {
        #[tokio::test]
        async fn $memory() {
            for sharding in [Sharding::Single, Sharding::D34] {
                $scenario(MemoryKv::default(), sharding).await;
            }
        }
        #[tokio::test]
        async fn $sqlite() {
            for sharding in [Sharding::Single, Sharding::D34] {
                let dir = tempfile::tempdir().unwrap();
                let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
                $scenario(Blocking::new(SqlKvStore::open(conn).unwrap()), sharding).await;
            }
        }
    };
}

backends!(
    creation_cost_memory,
    creation_cost_sqlite,
    creation_and_cost
);
backends!(creation_race_memory, creation_race_sqlite, creation_race);

#[tokio::test]
async fn lease_grant_retries_contention_memory() {
    lease_grant_retries_contention(MemoryKv::default()).await;
}

#[tokio::test]
async fn lease_grant_retries_contention_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
    lease_grant_retries_contention(Blocking::new(SqlKvStore::open(conn).unwrap())).await;
}

backends!(
    creation_race_two_repos_memory,
    creation_race_two_repos_sqlite,
    creation_race_two_repos
);
backends!(rejection_memory, rejection_sqlite, no_state_on_rejection);
backends!(replay_memory, replay_sqlite, replay_skips_coordinator);
backends!(
    empty_registered_memory,
    empty_registered_sqlite,
    registered_before_refs
);
backends!(
    single_addressing_memory,
    single_addressing_sqlite,
    single_addressing
);
