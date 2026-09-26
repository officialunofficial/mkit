//! FS + fs-layout with a bearer token: the `mkit-server serve` wiring that
//! replaces `mkit serve --http`. The wire suite runs against it (profile
//! bearer, non-atomic advance) and against the legacy server
//! (`mkit_transport_connect` over `FileTransport`, the M0-07 baseline, in
//! its `none` profile), and every case the legacy server passes must pass
//! here too.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use mkit_server_conformance::wire::{Feature, Profile, WireAuth, WireTarget, run};
use mkit_server_native::{Shutdown, server};
use mkit_transport_file::FileTransport;

const TOKEN: &str = "native-bearer-token";

/// Cases the native server fails, each with the reason. Target: none.
const DIVERGENCES: &[(&str, &str)] = &[];

/// The legacy server's known failure (see mkit-server-conformance's
/// `baseline_legacy_connect.rs`), which the pipeline fixes.
const LEGACY_DIVERGENCES: &[(&str, &str)] = &[(
    "refs.invalid_ref_name_invalid_argument",
    "`mkit serve --http` writes the packmap before it validates the head name",
)];

fn profile(auth: WireAuth) -> Profile {
    let mut p = Profile::new(auth);
    p.list_refs = 200;
    p.features.insert(Feature::Health);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fs_layout_bearer_matches_legacy_baseline() {
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

    // The legacy `mkit serve --http` on another root.
    let legacy_root = common::repo_root();
    let (listener, legacy_origin) = common::listener().await;
    tokio::spawn(mkit_transport_connect::serve(
        listener,
        Arc::new(FileTransport::new(legacy_root.path())),
        std::future::pending(),
    ));
    let target = WireTarget {
        base_url: legacy_origin.parse().unwrap(),
        profile: profile(WireAuth::None),
    };
    let legacy = run(&target, None).await;
    common::judge(&legacy, LEGACY_DIVERGENCES);

    // Case for case: everything the legacy server passes passes here.
    let native_passes: BTreeSet<_> = native.passes().into_iter().collect();
    let missing: Vec<_> = legacy
        .passes()
        .into_iter()
        .filter(|c| !native_passes.contains(c))
        .collect();
    assert!(
        missing.is_empty(),
        "legacy passes these, native does not: {missing:?}"
    );
    // And the bearer cases ran and passed.
    for case in [
        "auth.bearer_missing_unauthenticated",
        "auth.bearer_wrong_unauthenticated",
        "auth.bearer_applies_to_streaming",
    ] {
        assert!(native_passes.contains(case), "{case}");
    }

    shutdown.trigger();
    served.await.unwrap().unwrap();
    // The refs are FileTransport's files under the root.
    assert!(root.path().join("refs/heads/conformance").is_dir());
    drop(opened);
}
