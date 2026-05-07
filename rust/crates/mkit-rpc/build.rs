// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Compiles the .proto schemas in proto/ into Rust modules under
// $OUT_DIR via buffa-build. Requires `protoc` on PATH (or PROTOC
// env var). CI installs protobuf-compiler; local dev needs it via
// `brew install protobuf` (macOS) or the distro package.

fn main() {
    let proto_dir = std::path::PathBuf::from("proto");

    let files = [
        proto_dir.join("common.proto"),
        proto_dir.join("signer.proto"),
        proto_dir.join("ssh.proto"),
    ];

    // Re-run only when a .proto changes. Without these, cargo
    // re-runs build.rs on every recompile.
    println!("cargo:rerun-if-changed=build.rs");
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    println!("cargo:rerun-if-env-changed=PROTOC");

    buffa_build::Config::new()
        .files(&files)
        .includes(&[&proto_dir])
        .include_file("_includes.rs")
        .compile()
        .expect("buffa codegen");
}
