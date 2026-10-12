//! Shared fixtures for the local-server tests: an in-process `mkit-server`
//! pipeline on a loopback port, a signer, and a publisher that pushes through
//! `mkit-client`.
#![allow(dead_code, unreachable_pub, clippy::unwrap_used)] // each test file uses a subset

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, mpsc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use connectrpc::server::Server;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_client::{
    Client, Clock, Destination, Entry, Limits, Outcome, PackmapMode, Plan, Push, Signer, Visibility,
};
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::refs::RefWriteCondition;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::authority::AuthorityFence;
use mkit_server::namespace::NamespaceMode;
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, AuthMode, Authorizer, Hooks, Pipeline,
    PipelineConfig,
};
use mkit_server::policy::{AuthorizerRole, NamespacePolicy};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::url_token::{UrlTokenConfig, UrlTokenKeys};
use mkit_server::{
    Addressing, AuthzFacts, CallerView, MemoryBlobStore, MemoryKv, MultiAddressing, Operation,
    Principal, ServerError, SystemClock,
};
use mkit_sync::{Executor as _, NativeClock, NativeHttp};

/// The authority-mode namespace the authority tests address (SPEC-SERVER
/// §6.2.2 opaque grammar).
pub const NS: &str = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
/// The hook's writer: pushes and flips visibility.
pub const WRITER_SEED: u8 = 0x11;
/// The hook's reader: may read private repositories.
pub const READER_SEED: u8 = 0x22;
/// A signer the hook denies.
pub const STRANGER_SEED: u8 = 0x33;
/// The deployment key that fences the namespace's authority generation.
const DEPLOY_SEED: [u8; 32] = [0x44; 32];

pub fn public_key(seed: u8) -> [u8; 32] {
    KeyPair::from_seed([seed; 32]).public.0
}

/// An Ed25519 signer over a one-byte seed.
pub struct Dalek(SigningKey);

impl Dalek {
    pub fn new(seed: u8) -> Self {
        Self(SigningKey::from_bytes(&[seed; 32]))
    }
}

impl Signer for Dalek {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        Ok(self.0.sign(digest).to_bytes())
    }
}

pub fn destination(origin: &str, repository: &str) -> Destination {
    Destination::new(origin.to_owned(), repository.to_owned()).unwrap()
}

/// Objects and the tip of one signed commit carrying `files`.
pub fn build_commit(
    seed: u8,
    parent: Option<Hash>,
    files: &[(&str, &[u8])],
    stamp: u64,
) -> (Vec<Object>, Hash) {
    let key = KeyPair::from_seed([seed; 32]);
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    for (name, data) in files {
        let blob = Object::Blob(Blob {
            data: data.to_vec(),
        });
        entries.push(TreeEntry {
            name: name.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob.id().unwrap(),
        });
        objects.push(blob);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let tree = Object::Tree(Tree { entries });
    let tree_hash = tree.id().unwrap();
    objects.push(tree);
    let mut commit = Commit::new_unannotated(
        tree_hash,
        parent.into_iter().collect(),
        Identity::ed25519(key.public.0),
        key.public.0,
        format!("commit at {stamp}").into_bytes(),
        stamp,
        [0u8; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let tip = commit.id().unwrap();
    objects.push(commit);
    (objects, tip)
}

/// Push one commit on `main` of `repository` as `seed`. `parent` is the
/// branch's current tip (`None` creates it).
pub fn push_commit(
    http: &NativeHttp,
    origin: &str,
    repository: &str,
    seed: u8,
    parent: Option<Hash>,
    files: &[(&str, &[u8])],
) -> Hash {
    let (objects, tip) = build_commit(
        seed,
        parent,
        files,
        1_700_000_000 + u64::from(parent.is_some()),
    );
    let signer = Dalek::new(seed);
    let clock = NativeClock;
    let anonymous = Client::anonymous(http, destination(origin, repository));
    let info = http.block_on(anonymous.server_info()).unwrap();
    let limits = Limits::from_server_info(&info, 1 << 20, 64 << 20).unwrap();
    let entries = objects.iter().map(|object| Entry::Raw {
        id: object.id().unwrap(),
        bytes: mkit_core::serialize::serialize(object).unwrap(),
    });
    let plan = Plan::prepare(entries, limits).unwrap();
    let condition = parent.map_or(RefWriteCondition::Missing, RefWriteCondition::Match);
    let push = Push::new(
        destination(origin, repository),
        "main",
        condition,
        tip,
        PackmapMode::Append {
            self_contained: parent.is_none(),
        },
        plan,
        clock.now_ms() + 120_000,
    )
    .unwrap();
    let outcome = http.block_on(push.run(http, &signer, &clock)).unwrap();
    assert_eq!(outcome, Outcome::Committed);
    tip
}

/// Make `repository` private, signed as `seed`.
pub fn make_private(http: &NativeHttp, origin: &str, repository: &str, seed: u8) {
    let signer = Dalek::new(seed);
    let clock = NativeClock;
    let dest = destination(origin, repository);
    let client = Client::signed(http, dest, &signer, &clock);
    http.block_on(client.set_repo_visibility(Visibility::Private, None))
        .unwrap();
}

/// What the Authority hook observed.
pub type HookCalls = Arc<Mutex<Vec<(Principal, AuthzFacts)>>>;

/// The authority-mode hook: writer view for the writer key, reader view for
/// the reader key, defaults for anonymous, a refusal for any other signer.
#[derive(Debug, Clone, Default)]
pub struct Authority(pub HookCalls);

impl Authorizer for Authority {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        self.0
            .lock()
            .unwrap()
            .push((op.principal.clone(), op.authz.clone()));
        match &op.principal {
            Principal::Anonymous => Ok(AuthzFacts::default()),
            p if p.ed25519() == Some(&public_key(WRITER_SEED)) => {
                let mut facts = AuthzFacts::default();
                facts.caller_view = CallerView::Writer;
                facts.authority_generation = Some(0);
                Ok(facts)
            }
            p if p.ed25519() == Some(&public_key(READER_SEED)) => {
                let mut facts = AuthzFacts::default();
                facts.caller_view = CallerView::Reader;
                Ok(facts)
            }
            _ => Err(ServerError::permission_denied("hook denied")),
        }
    }
}

/// Admits every write.
#[derive(Debug, Clone, Default)]
pub struct Admit;

impl Admission for Admit {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        Ok(AdmissionDecision::allow(vec![])
            .with_reservation(format!("r:{}", input.idempotency_key.unwrap_or("unsigned"))))
    }
}

type TestHooks = Hooks<Authority, Admit>;
type TestPipeline = Pipeline<MemoryBlobStore, Arc<MemoryKv>, TestHooks>;

/// An in-process mkit-server on a loopback port; stops when dropped.
pub struct Live {
    pub origin: String,
    pub calls: HookCalls,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Live {
    /// An authority-mode deployment (SPEC-SERVER §6.2.2) with `NS` registered
    /// at generation 0 before it serves.
    pub fn authority() -> Self {
        let (origin_tx, origin_rx) = mpsc::channel();
        let (calls_tx, calls_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                let origin = format!("http://{}", bound.local_addr().unwrap());
                let mut cfg = PipelineConfig::new(
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(
                        NamespacePolicy::Any {
                            unsafe_without_admission: false,
                        },
                    )),
                    AuthMode::AuthV2(AuthV2Config::new(&origin, "").unwrap()),
                    UploadLimits::new(4 << 20, 64),
                );
                cfg.namespace_mode = NamespaceMode::Authority;
                cfg.authorizer_role = AuthorizerRole::Authority;
                cfg.list_repos_authority_full = true;
                cfg.write_quota = None;
                cfg.ticket_keys = Some(TicketKeys::new(vec![("tickets".into(), [9; 32])]).unwrap());
                cfg.url_tokens = Some(UrlTokenConfig::new(
                    UrlTokenKeys::parse_key_file(&format!("active {}", to_hex(&[11; 32]))).unwrap(),
                ));
                cfg.authority_fence = Some(
                    AuthorityFence::parse_with_mode(
                        &format!(
                            "deployment {} *",
                            to_hex(
                                SigningKey::from_bytes(&DEPLOY_SEED)
                                    .verifying_key()
                                    .as_bytes()
                            )
                        ),
                        NamespaceMode::Authority,
                    )
                    .unwrap(),
                );
                let authorizer = Authority::default();
                let defaults = Hooks::new();
                let hooks = Hooks {
                    authorizer: authorizer.clone(),
                    admission: Admit,
                    pre_receive: defaults.pre_receive,
                    receipts: defaults.receipts,
                    outcomes: defaults.outcomes,
                };
                let clock = Arc::new(SystemClock);
                let pipeline: TestPipeline = Pipeline::new(
                    MemoryBlobStore::default(),
                    Arc::new(MemoryKv::with_clock(clock.clone())),
                    hooks,
                    cfg,
                    clock,
                    Arc::new(mkit_server::NoopMetrics),
                )
                .unwrap();
                assert_eq!(
                    pipeline
                        .set_authority_generation(&generation(&origin, NS, 0))
                        .await
                        .unwrap(),
                    0
                );
                origin_tx.send(origin).unwrap();
                calls_tx.send(authorizer.0.clone()).unwrap();
                bound
                    .serve_with_service_and_shutdown(
                        mkit_server::connect::service(Arc::new(pipeline)),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .unwrap();
            });
        });
        Self {
            origin: origin_rx.recv().unwrap(),
            calls: calls_rx.recv().unwrap(),
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }

    /// The default (self-certifying) deployment: `ed25519-…` namespaces owned
    /// by their key, here the writer's.
    pub fn self_certifying() -> Self {
        let owner = mkit_attest::grant::Namespace::parse(&self_certifying_namespace()).unwrap();
        let (origin_tx, origin_rx) = mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let bound = Server::bind("127.0.0.1:0").await.unwrap();
                let origin = format!("http://{}", bound.local_addr().unwrap());
                origin_tx.send(origin.clone()).unwrap();
                let mut cfg = PipelineConfig::new(
                    Addressing::Multi(MultiAddressing::new().with_namespace_policy(
                        NamespacePolicy::Allowlist(BTreeSet::from([owner])),
                    )),
                    AuthMode::AuthV2(AuthV2Config::new(&origin, "").unwrap()),
                    UploadLimits::new(4 << 20, 64),
                );
                cfg.ticket_keys = Some(
                    TicketKeys::parse(
                        "dev 1111111111111111111111111111111111111111111111111111111111111111",
                    )
                    .unwrap(),
                );
                let clock = Arc::new(SystemClock);
                let pipeline = Pipeline::new(
                    MemoryBlobStore::default(),
                    MemoryKv::with_clock(clock.clone()),
                    Hooks::new(),
                    cfg,
                    clock,
                    Arc::new(mkit_server::NoopMetrics),
                )
                .unwrap();
                bound
                    .serve_with_service_and_shutdown(
                        mkit_server::connect::service(Arc::new(pipeline)),
                        async {
                            let _ = shutdown_rx.await;
                        },
                    )
                    .await
                    .unwrap();
            });
        });
        Self {
            origin: origin_rx.recv().unwrap(),
            calls: HookCalls::default(),
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }
}

/// The self-certifying namespace of the writer key.
pub fn self_certifying_namespace() -> String {
    format!("ed25519-{}", to_hex(&public_key(WRITER_SEED)))
}

impl Drop for Live {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A `mkit-authority-generation:v1` statement the deployment fence accepts.
fn generation(audience: &str, namespace: &str, n: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap())
        .unwrap();
    let text = format!(
        "mkit-authority-generation:v1\ndeployment\n{namespace}\n{n}\n{audience}\n{now}\n{}\n{}",
        now + 60_000,
        to_hex(&hash(namespace.as_bytes()))
    );
    let sig = SigningKey::from_bytes(&DEPLOY_SEED).sign(&hash(text.as_bytes()));
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(text),
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}
