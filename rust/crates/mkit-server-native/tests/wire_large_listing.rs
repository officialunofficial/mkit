//! The over-32 MiB listing (WP-1.27): about 75,000 refs with near-512-byte
//! names make one repository's listing pass 32 MiB, so the D34 merge that
//! pages the ref index must keep its 2 MiB page bound over hundreds of
//! pages. Only a native deployment creates that many refs in reasonable
//! time (R-134 keeps the Worker at 1,000); the in-crate proof is
//! `listing_over_32_mib_obeys_two_mib_pages`.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server_conformance::wire::{Milestone, Profile, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};

const REFS: u32 = 75_000;
const MAX_PACK: u64 = 4 << 20;
const CASE: &str = "list.merge_paging_over_32_mib";

async fn merge_paging(sharding: &str) {
    let root = common::repo_root();
    let ticket_file = root.path().join("ticket.keys");
    common::secret_file(
        &ticket_file,
        b"dev 1111111111111111111111111111111111111111111111111111111111111111\n",
    );
    let (listener, origin) = common::listener().await;
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--sharding",
            sharding,
            "--ticket-key-file",
            common::s(&ticket_file),
            "--auth",
            "auth-v2",
            "--audience",
            &origin,
            "--repository",
            "default",
            "--max-pack-bytes",
            &max_pack,
        ],
        &[],
    )
    .unwrap();
    let mut opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    // The relay driver delivers D34's ref-name index.
    let timers = opened
        .timers
        .take()
        .map(|driver| tokio::spawn(driver.start(shutdown.clone())));
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: "default".to_owned(),
        seed: [0x5e; 32],
    });
    profile.milestone = Milestone::M1;
    profile.atomic_advance = true;
    profile.max_pack_bytes = MAX_PACK;
    profile.fresh_target = true;
    profile.sharding_d34 = sharding == "d34";
    profile.merge_paging_refs = REFS;
    profile.derive_features();
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, Some(CASE)).await;
    common::judge(&report, &[]);
    assert_eq!(report.passes(), [CASE], "{CASE} did not run and pass");
    shutdown.trigger();
    served.await.unwrap().unwrap();
    if let Some(timers) = timers {
        timers.await.unwrap().unwrap().await.unwrap();
    }
    drop(opened);
}

/// 75,000 HTTP writes and the relay backlog take a few minutes, so the
/// ignored-only CI lane (`--profile ignored-lane`) runs this, not every
/// default `nextest` run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "75,000 refs over HTTP: run by the ignored-lane profile"]
async fn listing_over_32_mib_pages_under_d34() {
    merge_paging("d34").await;
}
