//! The Worker's embedded dispatch entry: the same deployment guard as the
//! fetch path, behind authentication and ahead of every pipeline read.
#![cfg(not(target_arch = "wasm32"))]
#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::many_single_char_names
)]
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use futures::executor::block_on;
use mkit_attest::grant::Visibility;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::write_auth::{Context, Operation as SignedOp};
use mkit_server::Clock as _;
use mkit_server::fork::ForkRequest;
use mkit_server::indexed::IndexedConfig;
use mkit_server::pipeline::{Authenticated, EmbeddedGate, Hooks, Pipeline, Sharding};
use mkit_server::store::adapter_spi::keys;
use mkit_server::{
    Batch, BatchOutcome, BoxFuture, Code, Cursor, Key, ManualClock, MemoryBlobStore, MemoryKv,
    NamespaceKey, NamespaceStore, Partition, PartitionStats, Procedure, RangeScan, RepoId,
    RepoName, ScanPage, ServerError, StoreCapabilities, StoreError, Value,
};
use mkit_server_worker::embedded::EmbeddedDispatch;
use mkit_server_worker::sharding_guard::DeploymentGuard;

const AUDIENCE: &str = "https://embedded.example";

/// A store that counts every call it serves.
#[derive(Clone, Default)]
struct Counting {
    inner: Arc<MemoryKv>,
    calls: Arc<AtomicU64>,
}

impl NamespaceStore for Counting {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_many(p, k).await
    }
    async fn scan_many(&self, p: &Partition, r: &[RangeScan]) -> Result<Vec<ScanPage>, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.scan_many(p, r).await
    }
    async fn scan(
        &self,
        p: &Partition,
        s: &Key,
        e: &Key,
        a: Option<&Cursor>,
        l: u32,
    ) -> Result<ScanPage, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.scan(p, s, e, a, l).await
    }
    async fn apply(&self, p: &Partition, b: Batch) -> Result<BatchOutcome, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.apply(p, b).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[derive(Default)]
struct Policy(AtomicU32);
impl EmbeddedGate<ForkRequest> for Policy {
    fn policy<'a>(
        &'a self,
        _: &'a Authenticated,
        _: &'a ForkRequest,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

struct Fixture {
    dispatch: EmbeddedDispatch<MemoryBlobStore, Counting, Hooks>,
    store: Counting,
    clock: Arc<ManualClock>,
    identity: String,
    request: ForkRequest,
}

fn fixture(guard: DeploymentGuard) -> Fixture {
    let owner = SigningKey::from_bytes(&[7; 32]);
    let namespace = mkit_core::repo_identity::Namespace::Ed25519(*owner.verifying_key().as_bytes());
    let mut cfg = mkit_server::pipeline::PipelineConfig::new(
        mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new().with_namespace_policy(
            mkit_server::policy::NamespacePolicy::Allowlist([namespace].into()),
        )),
        mkit_server::pipeline::AuthMode::AuthV2(
            mkit_server::auth_v2::AuthV2Config::new(AUDIENCE, "embedded-test").unwrap(),
        ),
        mkit_server::upload::UploadLimits::new(1 << 30, 64),
    );
    cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
    cfg.sharding = Sharding::D34;
    cfg.indexed = Some(IndexedConfig::scheduled(1 << 30));
    cfg.ticket_keys =
        Some(mkit_server::upload::token::TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    let clock = Arc::new(ManualClock::new(1_700_000_000_000));
    let store = Counting::default();
    let pipeline = Pipeline::new(
        MemoryBlobStore::default(),
        store.clone(),
        Hooks::new(),
        cfg,
        clock.clone(),
        Arc::new(mkit_server::telemetry::NoopMetrics),
    )
    .unwrap();
    let source = RepoId {
        namespace: NamespaceKey::from_namespace(&namespace),
        name: RepoName::new("source").unwrap(),
    };
    Fixture {
        dispatch: EmbeddedDispatch::new(pipeline, store.clone(), guard),
        store,
        clock,
        identity: format!("{namespace}/forked"),
        request: ForkRequest {
            source,
            source_ref: "refs/heads/main".into(),
            expected_tip: [3; 32],
            dest_visibility: Visibility::Public,
        },
    }
}

impl Fixture {
    /// The auth v2 headers of a fork of this fixture's request, signed over
    /// `signed_body`.
    fn headers(&self, nonce: u32, signed_body: &[u8]) -> Vec<(String, String)> {
        let owner = SigningKey::from_bytes(&[7; 32]);
        let digest = to_hex(&hash(signed_body));
        let commitment = format!("body:{digest}");
        let nonce = format!("{nonce:064x}");
        let now = self.clock.now_ms();
        let expires = now + 300_000;
        let envelope = SignedOp {
            context: Context {
                audience: AUDIENCE,
                repository: &self.identity,
            },
            procedure: Procedure::Fork.connect_path(),
            commitment: &commitment,
            created_at: now,
            expires_at: expires,
            nonce: &nonce,
        };
        let signature = owner.sign(&envelope.digest().unwrap());
        [
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", AUDIENCE.to_owned()),
            ("x-repository", self.identity.clone()),
            ("x-public-key", to_hex(owner.verifying_key().as_bytes())),
            ("x-signature", to_hex_bytes(&signature.to_bytes())),
            ("x-content-commitment", commitment),
            ("x-digest", digest),
            ("x-created-at", now.to_string()),
            ("x-expires-at", expires.to_string()),
            ("idempotency-key", nonce),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
    }

    fn fork(&self, signed_body: &[u8], policy: &Policy) -> Result<(), ServerError> {
        fn assert_send<T: Send>(value: T) -> T {
            value
        }
        let headers = self.headers(1, signed_body);
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        block_on(assert_send(self.dispatch.dispatch_fork(
            &header,
            &self.request.canonical_body(),
            policy,
        )))
        .map(|_| ())
    }
}

fn write_marker(store: &Counting, mode: &str) {
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let batch = Batch::new().put(
        keys::sharding_marker(),
        Value::new(mode.as_bytes().to_vec()),
    );
    block_on(store.inner.apply(&root, batch)).unwrap();
}

#[test]
fn an_incompatible_stored_layout_refuses_the_entry_as_the_fetch_path_does() {
    let f = fixture(DeploymentGuard::new(Sharding::D34, true, None));
    write_marker(&f.store, "single");
    let policy = Policy::default();
    let error = f.fork(&f.request.canonical_body(), &policy).unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    // The text fetch answers with for the same refusal.
    assert_eq!(
        error.public_message(),
        mkit_server_worker::sharding_guard::MISMATCH_MESSAGE
    );
    assert_eq!(policy.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_mis_signed_request_is_refused_before_the_guard_reads_storage() {
    let f = fixture(DeploymentGuard::new(Sharding::D34, true, None));
    write_marker(&f.store, "single");
    let before = f.store.calls.load(Ordering::SeqCst);
    let policy = Policy::default();
    // A signature over another body.
    let error = f.fork(b"another body", &policy).unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated);
    assert_eq!(f.store.calls.load(Ordering::SeqCst), before);
    assert_eq!(policy.0.load(Ordering::SeqCst), 0);
}

#[test]
fn a_compatible_layout_reaches_the_policy_and_then_the_pipeline() {
    let f = fixture(DeploymentGuard::new(Sharding::D34, true, None));
    let policy = Policy::default();
    // The guard records its markers, the policy runs, and the pipeline then
    // gives its own uniform answer for the absent source.
    let error = f.fork(&f.request.canonical_body(), &policy).unwrap_err();
    assert_eq!(error.code(), Code::NotFound);
    assert_eq!(error.public_message(), "source not found");
    assert_eq!(policy.0.load(Ordering::SeqCst), 1);
}
