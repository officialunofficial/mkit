// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stage the ConnectRPC TransportService + grpc.health.v1.Health server stubs
// + buffa message modules into $OUT_DIR for `connectrpc::include_generated!()`.
//
// Default path: copy the pre-generated sources committed under generated/ into
// $OUT_DIR — NO protoc required. Cloudflare Workers Builds (and CI) ship no
// protoc new enough for the `edition = "2023"` proto, so vendoring keeps the
// Worker building with zero system dependencies. Mirrors apps/repo-worker.
//
// Regeneration path: set MKIT_TRANSPORT_CODEGEN=1 to run connectrpc-build
// against the CANONICAL repo-root protos (proto/mkit/transport/v1/transport.proto
// and proto/grpc/health/v1/health.proto — mkit#796) instead (requires protoc
// >= 27 on PATH or via PROTOC). After editing either proto, run
// scripts/regen-transport-proto.sh from the repo root to refresh generated/
// for this crate, then commit.
//
// grpc.health.v1.health.proto is compiled here (not via the
// `connectrpc-health` crate) because that crate's Cargo.toml unconditionally
// depends on `connectrpc` with `features = ["server"]`, which pulls in
// `tokio/net` + `hyper-util/server` + `dep:libc` — none of which build for
// wasm32-unknown-unknown. Vendoring the standard proto and hand-writing the
// `Health` trait impl (see src/worker_impl/service.rs) keeps this Worker's
// dependency graph wasm-clean while staying wire-compatible with
// `grpc_health_probe` / kubelet gRPC probes / service meshes.

use std::path::{Path, PathBuf};

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=generated");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=MKIT_TRANSPORT_CODEGEN");

    let marker = out_dir.join(".mkit-transport-codegen");

    if std::env::var_os("MKIT_TRANSPORT_CODEGEN").is_some() {
        // Single source of truth: the repo-root canonical proto module, two
        // hops up from this crate (apps/vcs-worker -> repo root).
        let canonical_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../proto")
            .canonicalize()
            .expect("canonical proto root not found: expected proto/ at repo root");
        let proto = canonical_root.join("mkit/transport/v1/transport.proto");
        let health_proto = canonical_root.join("grpc/health/v1/health.proto");
        println!("cargo:rerun-if-changed={}", proto.display());
        println!("cargo:rerun-if-changed={}", health_proto.display());

        connectrpc_build::Config::new()
            .files(&[
                proto.to_str().expect("proto path is valid UTF-8"),
                health_proto.to_str().expect("proto path is valid UTF-8"),
            ])
            .includes(&[canonical_root.to_str().expect("proto root is valid UTF-8")])
            .include_file("_connectrpc.rs")
            .compile()
            .expect("connectrpc-build codegen failed for canonical transport.proto");
        std::fs::write(&marker, b"").expect("write codegen marker");
        return;
    }

    let _ = std::fs::remove_file(&marker);

    let vendored = Path::new("generated");
    let mut staged = 0usize;
    for entry in std::fs::read_dir(vendored).expect("read generated/") {
        let path = entry.expect("read generated/ entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            std::fs::copy(&path, out_dir.join(path.file_name().expect("file name")))
                .expect("stage generated module");
            staged += 1;
        }
    }
    assert!(
        staged > 0,
        "generated/ contains no .rs modules — run scripts/regen-transport-proto.sh"
    );
}
