// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stage the ConnectRPC RepoService server stubs + buffa message modules into
// $OUT_DIR for `connectrpc::include_generated!()`.
//
// Default path: copy the pre-generated sources committed under generated/ into
// $OUT_DIR — NO protoc required. Cloudflare Workers Builds (and CI) ship no
// protoc new enough for the `edition = "2023"` proto, so vendoring keeps the
// Worker building with zero system dependencies. Mirrors rust/crates/mkit-rpc.
//
// Regeneration path: set MKIT_REPO_CODEGEN=1 to run connectrpc-build against
// proto/ instead (requires protoc >= 27 on PATH or via PROTOC). After editing
// repo.proto, run scripts/regen-repo-proto.sh from the repo root to refresh
// generated/ for this crate AND rust/crates/mkit-repo-client, then commit.

use std::path::{Path, PathBuf};

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=generated");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=MKIT_REPO_CODEGEN");

    let marker = out_dir.join(".mkit-repo-codegen");

    if std::env::var_os("MKIT_REPO_CODEGEN").is_some() {
        println!("cargo:rerun-if-changed=proto/mkit/repo/v1/repo.proto");
        // Shared ref types (mkit.common.v1.RefExpectation / RefEntry), two
        // repo-root hops up from apps/repo-worker — see
        // mkit/common/v1/refs.proto's header comment. Also used by
        // rust/crates/mkit-rpc's ssh.proto.
        println!("cargo:rerun-if-changed=../../proto/mkit/common/v1/refs.proto");
        connectrpc_build::Config::new()
            .files(&[
                "proto/mkit/repo/v1/repo.proto",
                "../../proto/mkit/common/v1/refs.proto",
            ])
            .includes(&["proto/", "../../proto/"])
            .include_file("_connectrpc.rs")
            .compile()
            .expect("connectrpc-build codegen failed for repo.proto");
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
        "generated/ contains no .rs modules — run scripts/regen-repo-proto.sh"
    );
}
