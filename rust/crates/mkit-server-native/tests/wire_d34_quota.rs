//! D34 quota conformance on the native wiring (WP-1.26b): `--meta sqlite`
//! shards per (repository, ref) by default, so the write quota is counted per
//! (signer, branch), and a Multi deployment's namespace cap spans branches
//! after a ref shard's rollup. The pipeline registry's kind-5 handler runs
//! the rollup when the case skews the clock and names the shard.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server::quota::QuotaLimits as ServerQuota;
use mkit_server_conformance::wire::{
    Feature, Milestone, Profile, QuotaLimits, WireAuth, WireTarget, multi_allowlist_text, run,
};
use mkit_server_native::{Shutdown, server};

const REPOSITORY: &str = "default";
const MAX_PACK: u64 = 4 << 20;
const QUOTA: ServerQuota = ServerQuota {
    window_ms: 3_600_000,
    max_ops: 6,
    max_bytes: 2 << 20,
};

const DIVERGENCES: &[(&str, &str)] = &[];

fn quota_profile(origin: &str, repository: &str) -> Profile {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.to_owned(),
        repository: repository.to_owned(),
        seed: [0x5e; 32],
    });
    profile.milestone = Milestone::M1;
    profile.atomic_advance = true;
    profile.max_pack_bytes = MAX_PACK;
    profile.fresh_target = true;
    profile.quota = Some(QuotaLimits {
        max_ops: QUOTA.max_ops,
        max_bytes: QUOTA.max_bytes,
        window_ms: QUOTA.window_ms,
    });
    profile.sharding_d34 = true;
    profile.derive_features();
    profile
}

/// Single addressing: the four `quota.*` cases spend one branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_cases_run_per_branch_under_the_d34_default() {
    let root = common::repo_root();
    let ticket_file = root.path().join("ticket.keys");
    common::secret_file(
        &ticket_file,
        b"dev 1111111111111111111111111111111111111111111111111111111111111111\n",
    );
    let (listener, origin) = common::listener().await;
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
    // No `--sharding`: the default for SQLite metadata is D34.
    let mut cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--ticket-key-file",
            common::s(&ticket_file),
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
    assert_eq!(cfg.pipeline.sharding, mkit_server::pipeline::Sharding::D34);
    cfg.pipeline.write_quota = Some(QUOTA);
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile: quota_profile(&origin, REPOSITORY),
    };
    let report = run(&target, Some("quota.")).await;
    common::judge(&report, DIVERGENCES);
    for case in [
        "quota.ops_exhaustion_resource_exhausted",
        "quota.bytes_exhaustion_resource_exhausted",
        "quota.exhaustion_allocates_no_replay",
        "quota.replay_not_charged",
    ] {
        assert!(report.passes().contains(&case), "{case} did not pass");
    }
    shutdown.trigger();
    served.await.unwrap().unwrap();
    drop(opened);
}

/// Multi: the namespace cap across branches after a forced rollup.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn namespace_cap_spans_branches_after_a_forced_rollup() {
    let root = common::repo_root();
    let ticket_file = root.path().join("ticket.keys");
    common::secret_file(
        &ticket_file,
        b"dev 1111111111111111111111111111111111111111111111111111111111111111\n",
    );
    let (listener, origin) = common::listener().await;
    let mut profile = quota_profile(&origin, "ignored-in-multi-mode");
    profile.run_id = "wire-d34-quota".to_owned();
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::NamespacePolicy);
    profile.features.insert(Feature::TestFaults);
    let allowlist = root.path().join("namespaces");
    std::fs::write(&allowlist, multi_allowlist_text(&profile)).unwrap();
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
    let mut cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--addressing",
            "multi",
            "--namespace-allowlist",
            common::s(&allowlist),
            "--meta",
            &meta,
            "--ticket-key-file",
            common::s(&ticket_file),
            "--auth",
            "auth-v2",
            "--audience",
            &origin,
            "--max-pack-bytes",
            &max_pack,
        ],
        &[],
    )
    .unwrap();
    assert_eq!(cfg.pipeline.sharding, mkit_server::pipeline::Sharding::D34);
    cfg.pipeline.write_quota = Some(QUOTA);
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let case = "quota.namespace_cap_after_rollup";
    let report = run(&target, Some(case)).await;
    common::judge(&report, DIVERGENCES);
    assert_eq!(report.passes(), [case], "{case} did not run and pass");
    shutdown.trigger();
    served.await.unwrap().unwrap();
    drop(opened);
}
