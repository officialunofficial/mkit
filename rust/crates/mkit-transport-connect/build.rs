// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stage the `mkit.transport.v1.TransportService` ConnectRPC server stubs +
// buffa message modules into $OUT_DIR for `connectrpc::include_generated!()`.
//
// Default path: copy the pre-generated sources committed under `generated/`
// into $OUT_DIR — NO protoc required. Mirrors `apps/repo-worker/build.rs` /
// `rust/crates/mkit-repo-client/build.rs`: CI and docs.rs ship no protoc new
// enough for the `edition = "2023"` proto, so vendoring keeps this crate
// building with zero system dependencies.
//
// Regeneration path: set MKIT_TRANSPORT_CODEGEN=1 to run `connectrpc-build`
// against the CANONICAL proto (repo-root `proto/mkit/transport/v1/transport.proto`)
// instead — requires protoc >= 27 on PATH (or via PROTOC). After editing
// transport.proto, run scripts/regen-transport-proto.sh from the repo root to
// refresh generated/, then commit the result.

use std::path::{Path, PathBuf};

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=generated");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=MKIT_TRANSPORT_CODEGEN");

    // Marker distinguishing REAL codegen output from staged copies of
    // generated/ (both fill OUT_DIR with the same file set), so
    // scripts/regen-transport-proto.sh can find the right dir.
    let marker = out_dir.join(".mkit-transport-codegen");

    if std::env::var_os("MKIT_TRANSPORT_CODEGEN").is_some() {
        // Single source of truth: the repo-root canonical proto, two hops up
        // from this crate (rust/crates/mkit-transport-connect -> repo root).
        let canonical_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../proto")
            .canonicalize()
            .expect("canonical proto root not found: expected <repo root>/proto");
        let proto = canonical_root.join("mkit/transport/v1/transport.proto");
        println!("cargo:rerun-if-changed={}", proto.display());

        connectrpc_build::Config::new()
            .files(&[proto.to_str().expect("proto path is valid UTF-8")])
            .includes(&[canonical_root.to_str().expect("proto root is valid UTF-8")])
            .include_file("_connectrpc.rs")
            .compile()
            .expect("connectrpc-build codegen failed for canonical transport.proto");
        std::fs::write(&marker, b"").expect("write codegen marker");
        return;
    }

    // A prior codegen-mode run may have used this same OUT_DIR; drop its
    // marker so the regen script never copies staged files.
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
