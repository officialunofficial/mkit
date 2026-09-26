//! FS + fs-layout with a bearer token: the `mkit-server serve` wiring that
//! replaced `mkit serve --http`. The wire suite runs against it (profile
//! bearer, non-atomic advance), and every case passes.
//!
//! Until WP-M0-15 removed `mkit serve --http`, this test also ran the suite
//! against that legacy server (`mkit_transport_connect::serve` over
//! `FileTransport`, profile `none`) and required every case the legacy server
//! passed to pass here too. That comparison held with no native divergence.
//! The legacy server's one known failure, fixed by the pipeline, was
//! `refs.invalid_ref_name_invalid_argument`: `AdvanceRefs` with an invalid
//! head name answered `invalid_argument`, but only after it had written the
//! packmap, since `mkit serve --http` ran the `Transport::advance_refs`
//! default (write the packmap, then validate and write the head). The
//! pipeline validates both names before any write. The legacy server also
//! had no 512-ref cap on `ListRefs`.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::collections::BTreeSet;

use mkit_server_conformance::wire::{Feature, Profile, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};

const TOKEN: &str = "native-bearer-token";

/// Cases the native server fails, each with the reason. Target: none.
const DIVERGENCES: &[(&str, &str)] = &[];

fn profile(auth: WireAuth) -> Profile {
    let mut p = Profile::new(auth);
    p.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    p.fresh_target = true;
    p.features.insert(Feature::Health);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_layout_bearer_passes_the_wire_suite() {
    // The native server: token from the environment, fs-layout by default.
    let root = common::repo_root();
    let (listener, origin) = common::listener().await;
    let cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
        ],
        &[("MKIT_API_TOKEN", TOKEN)],
    )
    .unwrap();
    assert_eq!(cfg.meta, mkit_server_native::config::MetaChoice::FsLayout);
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile: profile(WireAuth::Bearer {
            token: TOKEN.to_owned(),
        }),
    };
    let native = run(&target, None).await;
    common::judge(&native, DIVERGENCES);

    // The bearer cases, and the case the legacy server failed, ran and
    // passed.
    let native_passes: BTreeSet<_> = native.passes().into_iter().collect();
    for case in [
        "auth.bearer_missing_unauthenticated",
        "auth.bearer_wrong_unauthenticated",
        "auth.bearer_applies_to_streaming",
        "refs.invalid_ref_name_invalid_argument",
    ] {
        assert!(native_passes.contains(case), "{case}");
    }

    shutdown.trigger();
    served.await.unwrap().unwrap();
    // The refs are FileTransport's files under the root.
    assert!(root.path().join("refs/heads/conformance").is_dir());
    drop(opened);
}
