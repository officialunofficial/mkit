//! Baseline: the wire suite against the pipeline's Connect binding
//! (`mkit_server::connect::service`) over the memory stores, served by
//! `axum` on a loopback port, in three auth profiles: `none`, `bearer`, and
//! `auth-v2` with a tiny quota. The memory store commits batches
//! atomically, so every profile declares `atomic-advance`. With this
//! crate's `test-faults` feature a fourth profile adds the clock-skew
//! directive and `GET /__mkit_test/stats`.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::sync::Arc;

use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::quota::QuotaLimits as ServerQuota;
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BatchOutcome, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceKey,
    NamespaceStore, Partition, PartitionStats, Redacted, RepoId, RepoName, ScanPage,
    StoreCapabilities, StoreError, SystemClock, Value,
};
use mkit_server_conformance::wire::{Profile, QuotaLimits, WireAuth, WireTarget, run};

const REPOSITORY: &str = "default";
const TOKEN: &str = "conformance-bearer-token";
const MAX_PACK: u64 = 4 << 20;
const QUOTA: ServerQuota = ServerQuota {
    window_ms: 3_600_000,
    max_ops: 6,
    max_bytes: 2 << 20,
};

/// Cases the pipeline fails today, each with the reason: fixed in flight,
/// never an accepted behavior. An entry that starts passing fails the
/// baseline until it is removed.
const PIPELINE_DIVERGENCES: &[(&str, &str)] = &[(
    "refs.list_prefix_component_boundary",
    "ListRefs matches the prefix as a bare string (`.../feat` lists `.../featx` as `x` \
     and `.../feat/x` as `/x`), against SPEC-REFS §4's `/` boundary; the fix is in \
     flight (mkit#1120). The assertion is the spec's.",
)];

/// A memory store shared with the test, for the stats endpoint.
#[derive(Clone)]
struct Shared(Arc<MemoryKv>);

impl NamespaceStore for Shared {
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
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

/// Serve a pipeline in `auth` mode with `quota`; returns its origin and the
/// metadata store.
async fn serve(
    auth: impl FnOnce(&str) -> AuthMode,
    quota: Option<ServerQuota>,
) -> (String, Shared) {
    let (listener, origin) = common::listener().await;
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPOSITORY).unwrap(),
    };
    let limits = UploadLimits {
        max_total_bytes: MAX_PACK,
        max_chunks: 64,
    };
    let mut cfg = PipelineConfig::new(Addressing::Single { repo }, auth(&origin), limits);
    cfg.write_quota = quota;
    let clock = Arc::new(SystemClock);
    let meta = Shared(Arc::new(MemoryKv::with_clock(clock.clone())));
    let pipe = Pipeline::new(
        MemoryBlobStore::default(),
        meta.clone(),
        Hooks::new(),
        cfg,
        clock,
        Arc::new(mkit_server::NoopMetrics),
    )
    .unwrap();
    let app = axum::Router::new().fallback_service(mkit_server::connect::service(Arc::new(pipe)));
    #[cfg(feature = "test-faults")]
    let app = app.route(
        mkit_server_conformance::wire::STATS_PATH,
        axum::routing::get({
            let meta = meta.clone();
            move || stats(meta.clone())
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    (origin, meta)
}

/// `GET /__mkit_test/stats`: the single partition's stats.
#[cfg(feature = "test-faults")]
async fn stats(meta: Shared) -> axum::Json<serde_json::Value> {
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let s = meta.stats(&p).await.unwrap();
    axum::Json(serde_json::json!({ "bytes": s.bytes, "keys": s.keys }))
}

fn profile(auth: WireAuth) -> Profile {
    let mut p = Profile::new(auth);
    p.atomic_advance = true;
    p.max_pack_bytes = MAX_PACK;
    p.list_refs = 200;
    p.derive_features();
    p
}

fn authv2(origin: &str) -> AuthMode {
    AuthMode::AuthV2(AuthV2Config::new(origin, REPOSITORY).unwrap())
}

fn v2_profile(origin: &str) -> Profile {
    let mut p = profile(WireAuth::AuthV2 {
        audience: origin.to_owned(),
        repository: REPOSITORY.to_owned(),
        seed: [0x5e; 32],
    });
    p.quota = Some(QuotaLimits {
        max_ops: QUOTA.max_ops,
        max_bytes: QUOTA.max_bytes,
        window_ms: QUOTA.window_ms,
    });
    p.derive_features();
    p
}

async fn check(origin: String, profile: Profile) {
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    common::judge(&run(&target, None).await, PIPELINE_DIVERGENCES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_open() {
    let (origin, _) = serve(|_| AuthMode::Open, None).await;
    check(origin, profile(WireAuth::None)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_bearer() {
    let auth = |_: &str| AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    };
    let (origin, _) = serve(auth, None).await;
    let token = TOKEN.to_owned();
    check(origin, profile(WireAuth::Bearer { token })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_auth_v2_quota_atomic() {
    let (origin, _) = serve(authv2, Some(QUOTA)).await;
    let profile = v2_profile(&origin);
    check(origin, profile).await;
}

/// The `test-faults` cases: the clock-skew directive and the stats
/// endpoint, on an auth v2 server whose quota window is short enough for
/// the growth case to wait out (it prunes on the real clock: about 70 s).
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_auth_v2_test_faults() {
    use mkit_server_conformance::wire::Feature;
    let quota = ServerQuota {
        window_ms: 5_000,
        ..QUOTA
    };
    let (origin, _) = serve(authv2, Some(quota)).await;
    let mut profile = v2_profile(&origin);
    profile.quota = profile.quota.map(|q| QuotaLimits {
        window_ms: quota.window_ms,
        ..q
    });
    profile.features.insert(Feature::TestFaults);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    // The rest of the suite ran on this profile above.
    for case in [
        "replay.expired_retry_rejected",
        "growth.replay_and_quota_pruned",
    ] {
        let report = run(&target, Some(case)).await;
        common::judge(&report, PIPELINE_DIVERGENCES);
        assert_eq!(report.passes(), [case], "{case} did not run and pass");
    }
}
