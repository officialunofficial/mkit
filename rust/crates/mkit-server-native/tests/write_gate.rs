//! Regression for the pipeline's write gate (`Pipeline::with_write_gate`):
//! parallel auth v2 writes by one signer share its quota-window row, so on
//! a store whose commit takes time they race each other through re-plans.
//! Without the gate some exhaust the re-plan bound and fail `aborted`
//! (the ignored, timing-dependent test shows it); with it, every write
//! commits. The wire case that first showed it,
//! `list.large_response_within_limit` (8 writes in flight per signer),
//! drives both servers.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::sync::Arc;
use std::time::Duration;

use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BatchOutcome, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceKey,
    NamespaceStore, NoopMetrics, Partition, PartitionStats, RepoId, RepoName, ScanPage,
    StoreCapabilities, StoreError, SystemClock, Value,
};
use mkit_server_conformance::wire::{Profile, Verdict, WireAuth, WireTarget, run};
use mkit_server_native::{RouterOptions, Shutdown, build_router};

const CASE: &str = "list.large_response_within_limit";

/// [`MemoryKv`] whose commit takes a few milliseconds, like an fsync'd
/// `SQLite` commit: plans that read the same row meanwhile go stale.
#[derive(Clone, Default)]
struct SlowCommit(Arc<MemoryKv>);

impl NamespaceStore for SlowCommit {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.0.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        tokio::time::sleep(Duration::from_millis(3)).await;
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

/// Run the case against an auth v2 pipeline (default quota), gated or not.
async fn verdict(gated: bool) -> Verdict {
    let (listener, origin) = common::listener().await;
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("default").unwrap(),
    };
    let auth = AuthMode::AuthV2(AuthV2Config::new(origin.clone(), "default").unwrap());
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    let cfg = PipelineConfig::new(Addressing::Single { repo }, auth, limits);
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        SlowCommit::default(),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let pipe = if gated { pipe.with_write_gate() } else { pipe };
    let router = build_router(Arc::new(pipe), &RouterOptions::default());
    let shutdown = Shutdown::new();
    common::spawn_serve(listener, router, &shutdown);

    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: "default".to_owned(),
        seed: [0x3c; 32],
    });
    profile.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    profile.fresh_target = true;
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, Some(CASE)).await;
    shutdown.trigger();
    eprintln!("gated={gated}\n{}", report.tap());
    report.verdict(CASE).unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_signer_parallel_writes_commit_with_the_gate() {
    let gated = verdict(true).await;
    assert!(matches!(gated, Verdict::Pass(_)), "{gated:?}");
}

/// [`MemoryKv`] that counts the commits in flight at once.
#[derive(Clone, Default)]
struct CountingCommit {
    kv: Arc<MemoryKv>,
    now: Arc<std::sync::atomic::AtomicUsize>,
    max: Arc<std::sync::atomic::AtomicUsize>,
}

impl NamespaceStore for CountingCommit {
    fn capabilities(&self) -> StoreCapabilities {
        self.kv.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.kv.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.kv.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.kv.scan(p, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        use std::sync::atomic::Ordering::SeqCst;
        let now = self.now.fetch_add(1, SeqCst) + 1;
        self.max.fetch_max(now, SeqCst);
        tokio::time::sleep(Duration::from_millis(2)).await;
        let outcome = self.kv.apply(p, batch).await;
        self.now.fetch_sub(1, SeqCst);
        outcome
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.kv.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.kv.probe().await
    }
}

/// `Pipeline::with_auth`, as `mkit-server` runs the enc listener beside the
/// HTTP one: the sibling sees the same stores, and writes through either
/// pipeline pass the one write gate, so no two commit at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_auth_sibling_shares_stores_and_the_write_gate() {
    use mkit_core::protocol::RefWriteCondition;
    use mkit_server::pipeline::RequestMeta;
    use mkit_server::{Principal, Procedure, RefUpdate};

    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("default").unwrap(),
    };
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    let store = CountingCommit::default();
    let cfg = PipelineConfig::new(Addressing::Single { repo }, AuthMode::Open, limits);
    let http = Pipeline::new(
        MemoryBlobStore::default(),
        store.clone(),
        Hooks::new(),
        cfg,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap()
    .with_write_gate();
    let enc = http.with_auth(AuthMode::TransportIdentity).unwrap();
    let (http, enc) = (Arc::new(http), Arc::new(enc));

    let mut writes = Vec::new();
    for i in 0..32u8 {
        let (pipe, principal) = if i % 2 == 0 {
            (Arc::clone(&http), None)
        } else {
            let peer = Principal::TransportPeer { ed25519: [i; 32] };
            (Arc::clone(&enc), Some(peer))
        };
        writes.push(tokio::spawn(async move {
            let no_headers = |_: &str| -> Option<String> { None };
            let a = pipe
                .authenticate(&RequestMeta {
                    procedure: Procedure::UpdateRef,
                    header: &no_headers,
                    unary_body: None,
                    transport_principal: principal,
                })
                .unwrap();
            let update = RefUpdate {
                name: format!("refs/heads/b{i}"),
                condition: RefWriteCondition::Missing,
                new: [i; 32],
            };
            pipe.update_ref(&a, update).await.unwrap();
        }));
    }
    for w in writes {
        w.await.unwrap();
    }
    assert_eq!(store.max.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Each pipeline reads what the other wrote.
    let no_headers = |_: &str| -> Option<String> { None };
    let meta = |principal| RequestMeta {
        procedure: Procedure::ListRefs,
        header: &no_headers,
        unary_body: None,
        transport_principal: principal,
    };
    let a = http.authenticate(&meta(None)).unwrap();
    assert_eq!(http.list_refs(&a, "refs/heads").await.unwrap().len(), 32);
    let peer = Principal::TransportPeer { ed25519: [0; 32] };
    let a = enc.authenticate(&meta(Some(peer))).unwrap();
    assert_eq!(enc.list_refs(&a, "refs/heads").await.unwrap().len(), 32);
    // The sibling authenticates its own way: no transport identity, no
    // request.
    assert!(enc.authenticate(&meta(None)).is_err());
}

/// The race the gate removes. It depends on timing (the writes must
/// interleave inside the slow commit), so it is not part of the gate run;
/// run it with `--ignored` to see the failure mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing-dependent demonstration of the race the gate removes"]
async fn same_signer_parallel_writes_abort_without_the_gate() {
    let ungated = verdict(false).await;
    assert!(
        matches!(&ungated, Verdict::Fail(why) if why.contains("aborted")),
        "without the gate the writes should exhaust their re-plans: {ungated:?}"
    );
}
