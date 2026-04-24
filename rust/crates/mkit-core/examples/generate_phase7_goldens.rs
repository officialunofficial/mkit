//! Generator for the Phase 7a golden vectors (SSH frame wire format).
//!
//! Run with `cargo run -p mkit-core --example generate_phase7_goldens
//! -- <out-dir>` (defaults to `rust/tests/golden/phase7`). Idempotent:
//! every input is a fixed constant; re-running emits byte-identical
//! files.
//!
//! This generator is the source of truth for the Phase 7a vectors;
//! the SSH transport's emitter is cross-checked against these bytes by
//! the transport test suite.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use mkit_core::hash;
use mkit_core::protocol::{
    OP_HELLO, OP_UPLOAD_PACK, SSH_BINARY_NAME, SSH_PROTO_VERSION, encode_frame,
    encode_hello_payload,
};

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args
        .get(1)
        .map_or_else(|| PathBuf::from("rust/tests/golden/phase7"), PathBuf::from);
    fs::create_dir_all(&out_dir)?;

    // 1. frame_hello.bin — the mandatory first frame on every SSH
    //    connection. SPEC-TRANSPORT §7.4:
    //      proto_version = 0x01
    //      binary_name   = "mkit"
    //      client_version = "mkit 0.1.0"
    //    wrapped in a standard [opcode][u32 LE len][payload] frame.
    let hello_payload =
        encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "mkit 0.1.0").unwrap();
    let hello_frame = encode_frame(OP_HELLO, &hello_payload).unwrap();
    write_vector(&out_dir, "frame_hello", &hello_frame)?;

    // 2. frame_upload_pack.bin — a sample OP_UPLOAD_PACK frame. Payload
    //    is `[32 digest][pack bytes]` per SPEC-TRANSPORT §7.2. We use a
    //    deterministic digest (BLAKE3 of the string "phase7-pack") and
    //    a short 16-byte filler so the frame fits in a single line of
    //    hex when inspected.
    let pack_digest = hash::hash(b"phase7-pack");
    let pack_body: [u8; 16] = [
        0x4D, 0x4B, 0x49, 0x54, // "MKIT" magic (so a reader can sanity-check)
        0x00, 0x00, 0x00, 0x01, // placeholder version=1
        0x00, 0x00, 0x00, 0x00, // placeholder entry_count=0
        0xDE, 0xAD, 0xBE, 0xEF, // sentinel
    ];
    let mut upload_payload = Vec::with_capacity(32 + pack_body.len());
    upload_payload.extend_from_slice(&pack_digest);
    upload_payload.extend_from_slice(&pack_body);
    let upload_frame = encode_frame(OP_UPLOAD_PACK, &upload_payload).unwrap();
    write_vector(&out_dir, "frame_upload_pack", &upload_frame)?;

    // Manifest for the integration tests.
    let mut manifest = String::new();
    manifest.push_str("# Phase 7a golden vectors (deterministic)\n");
    manifest.push_str("# Produced by examples/generate_phase7_goldens.rs\n");
    manifest.push_str("# Format: <name> <blake3-hex-of-bin-bytes>\n");
    for name in ["frame_hello", "frame_upload_pack"] {
        let bytes = fs::read(out_dir.join(format!("{name}.bin")))?;
        let h = hash::hash(&bytes);
        writeln!(manifest, "{name} {}", hash::to_hex(&h)).expect("write to String never fails");
    }
    fs::write(out_dir.join("MANIFEST.txt"), manifest)?;

    println!("phase7 goldens written to {}", out_dir.display());
    Ok(())
}

fn write_vector(out: &std::path::Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let bin_path = out.join(format!("{name}.bin"));
    let json_path = out.join(format!("{name}.json"));
    fs::write(&bin_path, bytes)?;
    let digest = hash::to_hex(&hash::hash(bytes));
    let json = format!(
        "{{\n  \"name\": \"{name}\",\n  \"bin\": \"{name}.bin\",\n  \"size\": {},\n  \"blake3\": \"{digest}\"\n}}\n",
        bytes.len()
    );
    fs::write(&json_path, json)?;
    Ok(())
}
