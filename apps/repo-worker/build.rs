// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Codegen: run connectrpc-build (buffa messages + ConnectRPC RepoService
// server stubs) over the canonical contract into $OUT_DIR/_connectrpc.rs.
// The crate root pulls it in with `connectrpc::include_generated!()`.
//
// Requires `protoc` on PATH (libprotoc 34.1 here, which supports
// `edition = "2023"` as declared in repo.proto).

fn main() {
    connectrpc_build::Config::new()
        .files(&["proto/mkit/repo/v1/repo.proto"])
        .includes(&["proto/"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("connectrpc-build codegen failed for repo.proto");
}
