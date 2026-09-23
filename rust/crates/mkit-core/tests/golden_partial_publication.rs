//! Independently encoded request-fingerprint preimage, committed as bytes.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use mkit_core::hash::{hash, to_hex};
use serde_json::{Value, json};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/partial_publication")
}

fn independent_preimage() -> Vec<u8> {
    let mut bytes = b"mkit.scoped-publication-request.v1\0".to_vec();
    for field in ["mkit+file:///tmp/recipient", "repo", "refs/heads/main"] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[2; 32]);
    bytes.extend_from_slice(&[3; 32]);
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&[4; 32]);
    bytes
}

#[test]
fn write_fingerprint_golden_if_requested() {
    if std::env::var_os("MKIT_WRITE_GOLDEN").is_none() {
        return;
    }
    let dir = golden_dir();
    fs::create_dir_all(&dir).unwrap();
    let bytes = independent_preimage();
    let digest = to_hex(&hash(&bytes));
    fs::write(dir.join("request_v1.bin"), &bytes).unwrap();
    fs::write(
        dir.join("request_v1.json"),
        format!("{}\n", serde_json::to_string_pretty(&json!({
        "name": "request_v1",
        "description": "Domain-separated, length-prefixed scoped publication request preimage",
        "preimage_blake3": digest,
        "endpoint": "mkit+file:///tmp/recipient",
        "repository": "repo",
        "exact_ref": "refs/heads/main",
        "base_id": "01".repeat(32),
        "candidate_id": "02".repeat(32),
        "update_digest": "03".repeat(32),
        "update_length": 7,
        "operation_id": "04".repeat(32),
        "fingerprint": digest,
    })).unwrap()),
    )
    .unwrap();
    fs::write(
        dir.join("MANIFEST.txt"),
        format!("# name blake3\nrequest_v1 {digest}\n"),
    )
    .unwrap();
}

#[test]
fn committed_fingerprint_preimage_matches_grammar_and_digest() {
    if std::env::var_os("MKIT_WRITE_GOLDEN").is_some() {
        return;
    }
    let dir = golden_dir();
    let bytes = fs::read(dir.join("request_v1.bin")).unwrap();
    let sidecar: Value =
        serde_json::from_slice(&fs::read(dir.join("request_v1.json")).unwrap()).unwrap();
    let manifest = fs::read_to_string(dir.join("MANIFEST.txt")).unwrap();
    assert_eq!(bytes, independent_preimage());
    assert_eq!(sidecar["fingerprint"], to_hex(&hash(&bytes)));
    assert!(manifest.contains(&format!(
        "request_v1 {}",
        sidecar["fingerprint"].as_str().unwrap()
    )));
}
