// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Stage the `mkit.transport.v1.TransportService` and `grpc.health.v1.Health`
// ConnectRPC server stubs and buffa message modules into $OUT_DIR for
// `connectrpc::include_generated!()` (the `connect` feature only; without it
// and without `remote-hooks` this script does nothing).
//
// Default path: copy the pre-generated sources committed under generated/
// into $OUT_DIR. NO protoc required: Cloudflare Workers Builds, CI and
// docs.rs ship no protoc new enough for the `edition = "2023"` proto.
//
// Regeneration path: set MKIT_TRANSPORT_CODEGEN=1 to run connectrpc-build
// against the CANONICAL repo-root protos (proto/mkit/transport/v1/
// transport.proto and proto/grpc/health/v1/health.proto) instead; requires
// protoc >= 27 on PATH or via PROTOC. After editing either proto, run
// scripts/regen-transport-proto.sh from the repo root and commit generated/.
//
// grpc.health.v1 is compiled here, not taken from the `connectrpc-health`
// crate: that crate depends on `connectrpc` with `features = ["server"]`
// (tokio/net, hyper-util server, libc), which does not build for
// wasm32-unknown-unknown.
//
// The `remote-hooks` feature does the same for the `mkit.server.hooks.v1`
// messages, with buffa alone (no ConnectRPC stubs: nothing here serves or
// calls a generated client). Sources live under generated/hooks/ and stage
// into $OUT_DIR/hooks/. Regenerate with MKIT_HOOKS_CODEGEN=1 (protoc >= 27),
// i.e. scripts/regen-hooks-proto.sh from the repo root.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "connect")]
    connect::stage();
    #[cfg(feature = "remote-hooks")]
    hooks::stage();
}

#[cfg(feature = "remote-hooks")]
mod hooks {
    use std::path::{Path, PathBuf};

    /// Written next to real codegen output so the regen script can tell it
    /// from a staged copy of `generated/hooks/`.
    const MARKER: &str = ".mkit-server-hooks-codegen";

    pub(crate) fn stage() {
        let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("hooks");
        std::fs::create_dir_all(&out_dir).expect("create hooks OUT_DIR");
        println!("cargo:rerun-if-changed=generated/hooks");
        println!("cargo:rerun-if-env-changed=PROTOC");
        println!("cargo:rerun-if-env-changed=MKIT_HOOKS_CODEGEN");
        let marker = out_dir.join(MARKER);

        if std::env::var_os("MKIT_HOOKS_CODEGEN").is_some() {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../proto")
                .canonicalize()
                .expect("canonical proto root not found: expected proto/ at repo root");
            let hooks = root.join("mkit/server/hooks/v1/hooks.proto");
            println!("cargo:rerun-if-changed={}", hooks.display());
            buffa_build::Config::new()
                .files(&[hooks.to_str().expect("proto path is valid UTF-8")])
                .includes(&[root.to_str().expect("proto root is valid UTF-8")])
                .out_dir(&out_dir)
                .generate_views(false)
                .generate_json(true)
                .include_file("_hooks.rs")
                .compile()
                .expect("buffa codegen failed for the canonical hooks proto");
            std::fs::write(&marker, b"").expect("write codegen marker");
            return;
        }

        let _ = std::fs::remove_file(&marker);
        let mut staged = 0usize;
        for entry in std::fs::read_dir(Path::new("generated/hooks")).expect("read generated/hooks/")
        {
            let path = entry.expect("read generated/hooks/ entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path.file_name().expect("file name");
                std::fs::copy(&path, out_dir.join(name)).expect("stage generated module");
                staged += 1;
            }
        }
        assert!(
            staged > 0,
            "generated/hooks/ contains no .rs modules: run scripts/regen-hooks-proto.sh"
        );
    }
}

#[cfg(feature = "connect")]
mod connect {
    use std::path::{Path, PathBuf};

    /// Written next to real codegen output, so the regen script can tell it
    /// from a staged copy of `generated/` (both fill `OUT_DIR` with the same
    /// file set).
    const MARKER: &str = ".mkit-server-transport-codegen";

    pub(crate) fn stage() {
        let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
        println!("cargo:rerun-if-changed=generated");
        println!("cargo:rerun-if-env-changed=PROTOC");
        println!("cargo:rerun-if-env-changed=MKIT_TRANSPORT_CODEGEN");
        let marker = out_dir.join(MARKER);

        if std::env::var_os("MKIT_TRANSPORT_CODEGEN").is_some() {
            // The repo-root canonical proto module, three hops up
            // (rust/crates/mkit-server -> repo root).
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../proto")
                .canonicalize()
                .expect("canonical proto root not found: expected proto/ at repo root");
            let transport = root.join("mkit/transport/v1/transport.proto");
            let health = root.join("grpc/health/v1/health.proto");
            println!("cargo:rerun-if-changed={}", transport.display());
            println!("cargo:rerun-if-changed={}", health.display());
            connectrpc_build::Config::new()
                .files(&[
                    transport.to_str().expect("proto path is valid UTF-8"),
                    health.to_str().expect("proto path is valid UTF-8"),
                ])
                .includes(&[root.to_str().expect("proto root is valid UTF-8")])
                .include_file("_connectrpc.rs")
                .compile()
                .expect("connectrpc-build codegen failed for the canonical protos");
            std::fs::write(&marker, b"").expect("write codegen marker");
            return;
        }

        let _ = std::fs::remove_file(&marker);
        let mut staged = 0usize;
        for entry in std::fs::read_dir(Path::new("generated")).expect("read generated/") {
            let path = entry.expect("read generated/ entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                let name = path.file_name().expect("file name");
                std::fs::copy(&path, out_dir.join(name)).expect("stage generated module");
                staged += 1;
            }
        }
        assert!(
            staged > 0,
            "generated/ contains no .rs modules: run scripts/regen-transport-proto.sh"
        );
    }
}
