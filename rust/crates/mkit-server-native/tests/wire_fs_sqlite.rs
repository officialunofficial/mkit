//! The M0 exit gate for FS + `SQLite`: the whole wire suite against the
//! `mkit-server serve` wiring (`config::resolve`, then `server::open`: FS
//! blobs under the root, `SQLite` metadata, auth v2) served in-process on a
//! loopback port. Profile: auth v2, atomic advance, a tiny quota (swapped
//! in for the default so the `quota.*` cases can exhaust it), health, and
//! strict gzip auth.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server::quota::QuotaLimits as ServerQuota;
use mkit_server_conformance::wire::{Feature, Profile, QuotaLimits, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};

const REPOSITORY: &str = "default";
const MAX_PACK: u64 = 4 << 20;
const QUOTA: ServerQuota = ServerQuota {
    window_ms: 3_600_000,
    max_ops: 6,
    max_bytes: 2 << 20,
};

/// Cases the native server fails, each with the reason. Target: none.
const DIVERGENCES: &[(&str, &str)] = &[];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_suite_fs_sqlite_auth_v2() {
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let (listener, origin) = common::listener().await;
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&db));
    let mut cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--auth",
            "auth-v2",
            "--audience",
            &origin,
            "--repository",
            REPOSITORY,
            "--max-pack-bytes",
            &max_pack,
        ],
        &[],
    )
    .unwrap();
    cfg.pipeline.write_quota = Some(QUOTA);
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: REPOSITORY.to_owned(),
        seed: [0x5e; 32],
    });
    profile.atomic_advance = true;
    profile.max_pack_bytes = MAX_PACK;
    profile.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    profile.fresh_target = true;
    profile.quota = Some(QuotaLimits {
        max_ops: QUOTA.max_ops,
        max_bytes: QUOTA.max_bytes,
        window_ms: QUOTA.window_ms,
    });
    profile.derive_features();
    profile.features.insert(Feature::Health);
    // The pipeline rejects a signature over gzip bytes (fails closed).
    profile.features.insert(Feature::StrictGzipAuth);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, None).await;
    common::judge(&report, DIVERGENCES);
    // Fault injection and Multi mode are unavailable in the native wiring.
    for skipped in report.skips() {
        assert!(
            skipped == "advance.nonatomic_packmap_first"
                || matches!(
                    skipped,
                    "replay.expired_retry_rejected" | "growth.replay_and_quota_pruned"
                )
                || skipped.starts_with("auth.bearer")
                || mkit_server_conformance::wire::CASES
                    .iter()
                    .any(|c| c.name == skipped && c.requires.contains(&Feature::MultiRepo)),
            "unexpected skip {skipped}"
        );
    }

    shutdown.trigger();
    served.await.unwrap().unwrap();
    // The refs live in SQLite, and the root is marked for it.
    assert!(db.exists());
    assert!(root.path().join(".mkit/server-meta").exists());
    assert!(!root.path().join("refs").exists());
    drop(opened);
}
