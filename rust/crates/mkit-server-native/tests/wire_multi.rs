//! The Multi exit gate (WP-1.30): the `repo.*`, `repository.*`, `policy.*`,
//! `tickets.advance_other_repository` and `info.*` wire cases against the
//! `mkit-server serve` wiring (`config::resolve`, then `server::open`)
//! started with `--addressing multi`: FS blobs under the root, `SQLite`
//! metadata, auth v2, and the namespace allowlist this profile derives.
//! The membership cases seed their fixture through a real ticketed push;
//! only `membership_read_your_writes` still skips (it needs D34's held
//! undelivered index).

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server_conformance::wire::{
    Feature, Milestone, Profile, Verdict, WireAuth, WireTarget, multi_allowlist_text, run,
};
use mkit_server_native::{Shutdown, server};

const MAX_PACK: u64 = 4 << 20;

/// Cases the native server fails, each with the reason. Target: none.
const DIVERGENCES: &[(&str, &str)] = &[];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_suite_multi_sqlite_auth_v2() {
    let root = common::repo_root();
    let ticket_file = root.path().join("ticket.keys");
    common::secret_file(
        &ticket_file,
        b"dev 1111111111111111111111111111111111111111111111111111111111111111\n",
    );
    let db = root.path().join("meta.sqlite3");
    let (listener, origin) = common::listener().await;
    // A fixed run id makes the allowlist derivation deterministic.
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: "ignored-in-multi-mode".to_owned(),
        seed: [0x5e; 32],
    });
    profile.run_id = "wire-multi".to_owned();
    profile.milestone = Milestone::M1;
    profile.atomic_advance = true;
    profile.max_pack_bytes = MAX_PACK;
    profile.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    profile.fresh_target = true;
    profile.derive_features();
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::NamespacePolicy);
    profile.features.insert(Feature::Tickets);
    profile.ticket_per_signer = 4;
    // The allowlist the deployment starts with, one namespace per line.
    let allowlist = root.path().join("namespaces");
    std::fs::write(&allowlist, multi_allowlist_text(&profile)).unwrap();
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&db));
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
    cfg.pipeline.ticket_caps.per_signer = 4;
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    // M0 cases exercise headerless reads and packs; the Multi cases carry
    // repository identities and exercise repository-scoped membership.
    for filter in [
        "repo.",
        "repository.",
        "policy.",
        "tickets.advance_other_repository",
        "info.",
    ] {
        let report = run(&target, Some(filter)).await;
        common::judge(&report, DIVERGENCES);
        for case in mkit_server_conformance::wire::CASES.iter().filter(|case| {
            case.name.contains(filter) && case.requires.contains(&Feature::MultiRepo)
        }) {
            match case.name {
                // The read-your-writes case keeps its D34 skip; the other
                // membership cases seed over the wire and run.
                "repo.membership_read_your_writes" => assert!(
                    matches!(report.verdict(case.name), Some(Verdict::Skip(reason))
                        if reason == "requires separate membership and ref shards (D34)"),
                    "{} did not skip with its D34 reason",
                    case.name
                ),
                _ => assert!(
                    matches!(report.verdict(case.name), Some(Verdict::Pass(_))),
                    "{} did not run and pass",
                    case.name
                ),
            }
        }
    }

    shutdown.trigger();
    served.await.unwrap().unwrap();
    assert!(db.exists());
    drop(opened);
}
