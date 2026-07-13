// Stages the buffa-generated Rust modules for the .proto schemas in
// proto/ into $OUT_DIR.
//
// Default path: copy the pre-generated sources committed under
// generated/ — no protoc required. This keeps docs.rs (whose build
// image ships protoc 3.21, too old for the `edition = "2023"` protos)
// and stock-distro users building, with zero system dependencies.
//
// Regeneration path: set MKIT_RPC_CODEGEN=1 to run buffa-build against
// proto/ instead (requires protoc >= 27 on PATH or via PROTOC). After
// changing a .proto, run scripts/regen-rpc-proto.sh from the repo root
// to refresh generated/ and commit the result.

use std::path::PathBuf;

fn main() {
    let proto_dir = PathBuf::from("proto");
    // Shared ref types (mkit.common.v1.RefExpectation / RefEntry), one repo
    // root up from rust/crates/mkit-rpc — see mkit/common/v1/refs.proto's
    // header comment. Also used by apps/repo-worker's repo.proto.
    let common_dir = PathBuf::from("../../../proto");
    let common_refs_proto = common_dir.join("mkit/common/v1/refs.proto");

    let files = [
        proto_dir.join("mkit/rpc/v1/common.proto"),
        proto_dir.join("mkit/rpc/v1/signer/signer.proto"),
        proto_dir.join("mkit/rpc/v1/ssh/ssh.proto"),
        proto_dir.join("mkit/rpc/v1/verify/verify.proto"),
        common_refs_proto.clone(),
    ];

    // Re-run when a .proto, the vendored output, or the mode changes.
    // Without these, cargo re-runs build.rs on every recompile.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=generated");
    for f in &files {
        println!("cargo:rerun-if-changed={}", f.display());
    }
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=MKIT_RPC_CODEGEN");

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    // Marker distinguishing real codegen output from staged copies of
    // generated/ — both fill OUT_DIR with the same .rs file set, so
    // scripts/regen-rpc-proto.sh needs this to find the right dir.
    let marker = out_dir.join(".mkit-rpc-codegen");

    if std::env::var_os("MKIT_RPC_CODEGEN").is_some() {
        buffa_build::Config::new()
            .files(&files)
            .includes(&[&proto_dir, &common_dir])
            .include_file("_includes.rs")
            // Emits `arbitrary::Arbitrary` derives gated behind the
            // crate's opt-in `arbitrary` feature — used by the fuzz
            // harness (rust/fuzz) for decode/roundtrip targets.
            .generate_arbitrary(true)
            .compile()
            .expect("buffa codegen");
        std::fs::write(&marker, b"").expect("write codegen marker");
        return;
    }
    // A previous codegen-mode run may have used this same OUT_DIR;
    // drop its marker so the regen script never copies staged files.
    let _ = std::fs::remove_file(&marker);
    let vendored = PathBuf::from("generated");
    let mut staged = 0usize;
    for entry in std::fs::read_dir(&vendored).expect("read generated/") {
        let entry = entry.expect("read generated/ entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "rs") {
            std::fs::copy(&path, out_dir.join(entry.file_name())).expect("stage generated module");
            staged += 1;
        }
    }
    assert!(
        staged > 0,
        "generated/ contains no .rs modules — run scripts/regen-rpc-proto.sh"
    );
}
