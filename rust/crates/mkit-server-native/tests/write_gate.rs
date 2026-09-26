//! Regression for the pipeline's write gate (`Pipeline::with_write_gate`):
//! parallel auth v2 writes by one signer share its quota-window row, so on
//! a store whose commit takes time they race each other through re-plans.
//! Without the gate some exhaust the re-plan bound and fail `aborted`;
//! with it, every write commits. The wire case that first showed it,
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
async fn same_signer_parallel_writes_need_the_gate() {
    let ungated = verdict(false).await;
    assert!(
        matches!(&ungated, Verdict::Fail(why) if why.contains("aborted")),
        "without the gate the writes should exhaust their re-plans: {ungated:?}"
    );
    let gated = verdict(true).await;
    assert!(matches!(gated, Verdict::Pass(_)), "{gated:?}");
}
