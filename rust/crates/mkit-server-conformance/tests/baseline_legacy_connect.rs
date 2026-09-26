//! Baseline: the wire suite against today's `mkit serve --http`, which is
//! `mkit_transport_connect::router` over `FileTransport`
//! (`mkit-cli/src/commands/serve/http.rs`), served by `axum` on a loopback
//! port. Profile `none`, non-atomic advance, the 4 GiB pack cap.
//!
//! WP-M0-15 deletes this test when it removes `mkit-transport-connect`'s
//! `server` feature: `mkit serve --http` then runs on the pipeline, which
//! `baseline_pipeline_memory.rs` covers.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::sync::Arc;

use mkit_server_conformance::wire::{Feature, Profile, WireAuth, WireTarget, run};
use mkit_transport_file::FileTransport;

/// Cases the legacy server fails, each with the reason. The pipeline passes
/// all of them; `mkit serve --http` moves onto it in WP-M0-15.
const LEGACY_DIVERGENCES: &[(&str, &str)] = &[
    (
        "refs.invalid_ref_name_invalid_argument",
        "AdvanceRefs with an invalid head name is `invalid_argument`, but only after the \
         packmap was written: the `Transport::advance_refs` default writes the packmap, then \
         validates and writes the head. The pipeline validates both names before any write.",
    ),
    (
        "refs.name_over_512_bytes_invalid_argument",
        "FileTransport has no ref-name length cap (only SPEC-REFS §3's grammar); the \
         512-byte cap arrives with the pipeline (mkit_server::refs::MAX_REF_NAME_BYTES).",
    ),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_mkit_serve_http() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(FileTransport::new(dir.path()));
    let (listener, origin) = common::listener().await;
    tokio::spawn(mkit_transport_connect::serve(
        listener,
        transport,
        std::future::pending(),
    ));

    let mut profile = Profile::new(WireAuth::None);
    profile.list_refs = 200;
    // `mkit serve --http` mounts `grpc.health.v1.Health` (mkit#796).
    profile.features.insert(Feature::Health);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, None).await;
    common::judge(&report, LEGACY_DIVERGENCES);
}
