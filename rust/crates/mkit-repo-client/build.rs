//! Code-generate the `mkit.repo.v1.RepoService` ConnectRPC client + message
//! types from the CANONICAL proto.
//!
//! Single source of truth: `apps/repo-worker/proto/mkit/repo/v1/repo.proto`.
//! This crate compiles that file directly (via a workspace-relative path) so the
//! client and the worker can never drift — there is no second copy to keep in
//! sync. The include dir is the canonical `proto/` root, so the proto's
//! `package mkit.repo.v1` / file path resolve exactly as they do server-side.

use std::path::Path;

fn main() {
    // `apps/repo-worker/proto` relative to this crate
    // (rust/crates/mkit-repo-client) — five hops up to the repo root.
    let canonical_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../apps/repo-worker/proto")
        .canonicalize()
        .expect(
            "canonical proto root not found: \
             expected apps/repo-worker/proto relative to mkit-repo-client; \
             this crate is part of the mkit monorepo and compiles the worker's \
             canonical repo.proto directly",
        );
    let proto = canonical_root.join("mkit/repo/v1/repo.proto");

    // Re-run codegen whenever the canonical proto changes.
    println!("cargo:rerun-if-changed={}", proto.display());

    connectrpc_build::Config::new()
        .files(&[proto.to_str().expect("proto path is valid UTF-8")])
        .includes(&[canonical_root.to_str().expect("proto root is valid UTF-8")])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("failed to compile canonical apps/repo-worker/proto/mkit/repo/v1/repo.proto");
}
