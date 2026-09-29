use mkit_server_worker::adapter;
use mkit_server_worker::classes::ShardClass;
use mkit_server_worker::ns_object::NsObject;
use worker::{
    Context, DurableObject, Env, Request, Response, Result, State, durable_object, event,
    wasm_bindgen,
};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if req.path() == "/seed" {
        return seed(env).await;
    }
    adapter::fetch_configured(req, env, config()).await
}

/// The deployment-default namespace's partition: one SQLite key-value
/// store, capped for the `WORKERS_PLAN` var.
#[durable_object]
pub struct RefStore {
    object: NsObject,
}

impl DurableObject for RefStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object_configured(state, &env, ShardClass::RefStore, config()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `NsCoordinator` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct NsCoordinator {
    object: NsObject,
}

impl DurableObject for NsCoordinator {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object_configured(state, &env, ShardClass::NsCoordinator, config()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `RefShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct RefShard {
    object: NsObject,
}

impl DurableObject for RefShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object_configured(state, &env, ShardClass::RefShard, config()),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `RepoIndexShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct RepoIndexShard {
    object: NsObject,
}

impl DurableObject for RepoIndexShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object_configured(
                state,
                &env,
                ShardClass::RepoIndexShard,
                config(),
            ),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `ContentIndexShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct ContentIndexShard {
    object: NsObject,
}

impl DurableObject for ContentIndexShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object_configured(
                state,
                &env,
                ShardClass::ContentIndexShard,
                config(),
            ),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

fn config() -> mkit_server_worker::published_view::PublishedViewConfig {
    mkit_server_worker::published_view::PublishedViewConfig::new("local-cpu-probe").unwrap()
}
const NS: &str = "ed25519-1111111111111111111111111111111111111111111111111111111111111111";
async fn seed(env: Env) -> Result<Response> {
    use mkit_server::pipeline::{D34Shards, ShardMap};
    use mkit_server::store::{codec, keys};
    use mkit_server::{Batch, NamespaceKey, NamespaceStore, Partition, RepoId, RepoName};
    use mkit_server_worker::published_view::{
        Envelope, SnapshotBucket, VALIDITY_MS, WorkerSnapshotBucket, object_key,
    };
    let ns = mkit_core::repo_identity::Namespace::parse(NS).unwrap();
    let repo = RepoId {
        namespace: NamespaceKey::from_namespace(&ns),
        name: RepoName::new("cpu").unwrap(),
    };
    let meta = mkit_server_worker::ns_client::DoNamespaceStore::new(
        mkit_server_worker::ns_client::StubTransport::new(env.clone(), Default::default()),
        Partition::Namespace(NamespaceKey::deployment_default()),
    );
    meta.apply(
        &Partition::Coordinator(repo.namespace.clone()),
        Batch::new().put(
            keys::repo_record(&repo.name),
            codec::encode_repo_record(&codec::RepoRecord { created_at_ms: 1 }),
        ),
    )
    .await
    .unwrap();
    let mut buckets = vec![Vec::new(); 16];
    let mut i = 0;
    while buckets.iter().any(|rows| rows.len() < 58) {
        let name = format!("refs/heads/{i:08}{}", "a".repeat(480));
        i += 1;
        let Partition::RefIndex { bucket, .. } = D34Shards.ref_index(&repo, &name) else {
            unreachable!()
        };
        if buckets[usize::from(bucket)].len() < 58 {
            buckets[usize::from(bucket)].push((name, [1; 32]));
        }
    }
    let at = worker::Date::now().as_millis();
    let bucket = WorkerSnapshotBucket(env);
    let mut total = 0;
    for (partition, rows) in D34Shards
        .ref_index_partitions(&repo)
        .into_iter()
        .zip(buckets)
    {
        let bytes = Envelope {
            partition: partition.clone(),
            generation: 1,
            captured_at_ms: at,
            valid_until_ms: at + VALIDITY_MS,
            rows,
        }
        .encode()
        .unwrap();
        total += bytes.len();
        let key = object_key(&partition).unwrap();
        bucket.delete(&key).await.unwrap();
        assert!(bucket.replace(&key, None, bytes).await.unwrap());
    }
    Response::ok(format!("seeded 928 refs, {total} encoded bytes"))
}
