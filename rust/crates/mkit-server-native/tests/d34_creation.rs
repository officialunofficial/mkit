//! Coordinator creation, ordering and round-trip costs on both metadata backends.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use mkit_core::protocol::RefWriteCondition;
use mkit_core::repo_identity::Namespace;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authenticated, Authorizer, D34Shards,
    Hooks, Pipeline, PipelineConfig, PreReceive, RequestMeta, ShardMap, Sharding, SinglePartition,
};
use mkit_server::policy::NamespacePolicy;
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, BlobKey, Cursor, Key, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value, Write, codec, keys,
};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Code, MemoryBlobStore, MemoryKv, MultiAddressing, NamespaceStore, NoopMetrics,
    Procedure, RefUpdate, ServerError, SystemClock, UpdateRefResult,
};
use mkit_server::{AuthzFacts, Creation, Operation};
use mkit_server_conformance::wire::sign::Signer;
use mkit_server_native::{Blocking, RusqliteConn};
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
        self.inner.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.record(Call::Apply(p.clone()));
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
            Ok(AdmissionDecision::Challenge {
                challenges: Vec::new(),
                description: "test admission challenge".into(),
            })
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
    cfg.write_quota = None;
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
        new: [value; 32],
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
    assert_eq!(calls.len(), 4, "{sharding:?}: {calls:?}");
    assert!(matches!(
        calls.as_slice(),
        [
            Call::Many(..),
            Call::Many(..),
            Call::Apply(..),
            Call::Apply(..)
        ]
    ));
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
    let expected_calls = if sharding == Sharding::D34 { 4 } else { 3 };
    assert_eq!(calls.len(), expected_calls, "{sharding:?}: {calls:?}");
    if sharding == Sharding::D34 {
        assert!(matches!(
            calls.as_slice(),
            [
                Call::Many(..),
                Call::Many(..),
                Call::Apply(..),
                Call::Apply(..)
            ]
        ));
    } else {
        assert!(matches!(
            calls.as_slice(),
            [Call::Many(..), Call::Many(..), Call::Apply(..)]
        ));
    }

    let second = signed(&pipe, &identity("second"));
    pipe.update_ref(&second, update("refs/heads/a", 4))
        .await
        .unwrap();
    assert_eq!(store.take_calls().len(), 4);
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
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|call| matches!(call, Call::Many(..))));
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
    if sharding == Sharding::Single {
        assert!(listed.unwrap().is_empty());
    } else {
        assert_eq!(listed.unwrap_err().code(), Code::Unimplemented);
    }
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
        if sharding == Sharding::D34 { 4 } else { 2 }
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
