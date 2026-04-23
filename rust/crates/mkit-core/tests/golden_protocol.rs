//! Phase 7a golden-vector integration tests.
//!
//! Pins the on-wire bytes emitted by `encode_frame` +
//! `encode_hello_payload` so the SSH transport (Phase 7e) can depend on
//! them. The bytes are regenerated via
//! `cargo run -p mkit-core --example generate_phase7_goldens`.
//!
//! Matching Phase 4's test style — read the `.bin`, re-emit from the
//! library, compare byte-for-byte.

use std::fs;
use std::path::PathBuf;

use mkit_core::hash;
use mkit_core::protocol::{
    FRAME_HEADER_LEN, OP_HELLO, OP_UPLOAD_PACK, SSH_BINARY_NAME, SSH_PROTO_VERSION, decode_frame,
    encode_frame, encode_hello_payload,
};

fn golden_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR points at rust/crates/mkit-core; the goldens
    // live two levels up under rust/tests/golden/phase7/.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("phase7")
}

fn read_golden(name: &str) -> Vec<u8> {
    let path = golden_dir().join(format!("{name}.bin"));
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn read_manifest_digest(name: &str) -> String {
    let manifest = fs::read_to_string(golden_dir().join("MANIFEST.txt"))
        .expect("MANIFEST.txt must exist — run examples/generate_phase7_goldens.rs");
    for line in manifest.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let n = parts.next().unwrap_or("").trim();
        let d = parts.next().unwrap_or("").trim();
        if n == name {
            return d.to_string();
        }
    }
    panic!("vector {name} missing from MANIFEST.txt");
}

#[test]
fn frame_hello_matches_golden() {
    let payload = encode_hello_payload(SSH_PROTO_VERSION, SSH_BINARY_NAME, "mkit 0.2.1").unwrap();
    let frame = encode_frame(OP_HELLO, &payload).unwrap();
    let golden = read_golden("frame_hello");
    assert_eq!(
        frame, golden,
        "frame_hello bytes diverged from golden — update generator + manifest if intentional"
    );

    // Spot-check the on-disk layout so a future editor sees the shape.
    // [opcode=0x00][u32 LE len=17][proto=0x01][name_len=4]"mkit"[ver_len=10]"mkit 0.2.1"
    assert_eq!(frame[0], OP_HELLO);
    assert_eq!(&frame[1..5], 17u32.to_le_bytes().as_slice());
    assert_eq!(frame[5], SSH_PROTO_VERSION);
    assert_eq!(frame[6], 4);
    assert_eq!(&frame[7..11], b"mkit");
    assert_eq!(frame[11], 10);
    assert_eq!(&frame[12..], b"mkit 0.2.1");
}

#[test]
fn frame_hello_decodes() {
    let frame = read_golden("frame_hello");
    let (op, payload) = decode_frame(&frame).unwrap();
    assert_eq!(op, OP_HELLO);
    assert_eq!(payload.len(), frame.len() - FRAME_HEADER_LEN);
}

#[test]
fn frame_upload_pack_matches_golden() {
    let pack_digest = hash::hash(b"phase7-pack");
    let pack_body: [u8; 16] = [
        0x4D, 0x4B, 0x49, 0x54, // "MKIT"
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let mut payload = Vec::with_capacity(32 + pack_body.len());
    payload.extend_from_slice(&pack_digest);
    payload.extend_from_slice(&pack_body);
    let frame = encode_frame(OP_UPLOAD_PACK, &payload).unwrap();

    let golden = read_golden("frame_upload_pack");
    assert_eq!(
        frame, golden,
        "frame_upload_pack bytes diverged from golden"
    );
}

#[test]
fn manifest_digests_match_bin_contents() {
    for name in ["frame_hello", "frame_upload_pack"] {
        let bytes = read_golden(name);
        let expected = read_manifest_digest(name);
        let got = hash::to_hex(&hash::hash(&bytes));
        assert_eq!(
            got, expected,
            "MANIFEST.txt BLAKE3 for {name} does not match {name}.bin"
        );
    }
}
