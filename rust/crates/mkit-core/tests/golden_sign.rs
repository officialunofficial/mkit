//! Phase 6 (signing) goldens.
//!
//! For every fixture we:
//!
//! 1. Load the matching commit/remix object bytes from the Phase 1
//!    fixtures (`commit_0parent.bin`, `remix_2sources.bin`).
//! 2. Deserialize via `mkit_core::serialize::deserialize`.
//! 3. Re-derive the signing bytes via `commit_signing_bytes` /
//!    `remix_signing_bytes`.
//! 4. Compare byte-for-byte against the pinned `_signing_bytes.bin`
//!    fixture.
//! 5. Re-derive `BLAKE3(domain || signing_bytes)` and assert it matches
//!    the recorded MANIFEST digest of the same domain-prefixed input.

use std::fs;
use std::path::PathBuf;

use mkit_core::deserialize;
use mkit_core::hash::{hash, to_hex};
use mkit_core::object::Object;
use mkit_core::sign::{commit_signing_bytes, remix_signing_bytes};

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("tests");
    d.push("golden");
    d.push("phase1");
    d
}

fn load(name: &str) -> Vec<u8> {
    let p = golden_dir().join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

fn manifest_digest(name: &str) -> Option<String> {
    let raw = fs::read_to_string(golden_dir().join("MANIFEST.txt")).ok()?;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let n = parts.next()?;
        let d = parts.next()?;
        if n == name {
            return Some(d.to_string());
        }
    }
    None
}

#[test]
fn commit_0parent_signing_bytes_match_golden() {
    let obj_bytes = load("commit_0parent.bin");
    let obj = deserialize(&obj_bytes).expect("commit_0parent decodes");
    let Object::Commit(c) = obj else {
        panic!("expected Commit");
    };
    let derived = commit_signing_bytes(&c).expect("derive ok");
    let want = load("commit_0parent_signing_bytes.bin");
    assert_eq!(
        derived, want,
        "commit signing bytes diverge from pinned golden"
    );
    // Manifest digest cross-check (BLAKE3 of the raw signing-bytes file
    // — NOT the domain-prefixed signing hash; that one is computed at
    // sign() time and is an internal value).
    let want_hex = manifest_digest("commit_0parent_signing_bytes").expect("manifest entry present");
    assert_eq!(to_hex(&hash(&want)), want_hex);
}

#[test]
fn remix_2sources_signing_bytes_match_golden() {
    let obj_bytes = load("remix_2sources.bin");
    let obj = deserialize(&obj_bytes).expect("remix_2sources decodes");
    let Object::Remix(r) = obj else {
        panic!("expected Remix");
    };
    let derived = remix_signing_bytes(&r).expect("derive ok");
    let want = load("remix_2sources_signing_bytes.bin");
    assert_eq!(
        derived, want,
        "remix signing bytes diverge from pinned golden"
    );
    let want_hex = manifest_digest("remix_2sources_signing_bytes").expect("manifest entry present");
    assert_eq!(to_hex(&hash(&want)), want_hex);
}

/// Pin the canonical signing hashes (`BLAKE3(domain || signing_bytes)`)
/// for the two harvested fixtures. These are the actual values that
/// `Ed25519.sign()` covers, so any silent drift in domain handling
/// (wrong terminator byte, swapped domain, accidental `derive_key`,
/// etc.) breaks this test.
#[test]
fn signing_hashes_are_stable() {
    use mkit_core::sign::{commit_signing_hash, remix_signing_hash};
    let cb = load("commit_0parent.bin");
    let rb = load("remix_2sources.bin");
    let Object::Commit(c) = deserialize(&cb).unwrap() else {
        panic!("expected Commit");
    };
    let Object::Remix(r) = deserialize(&rb).unwrap() else {
        panic!("expected Remix");
    };
    assert_eq!(
        to_hex(&commit_signing_hash(&c).unwrap()),
        "a2bcc8f3f1ee0b4877a6dce4aa8ddb2e45ba649c767d7380b075b33a2aacc66f",
    );
    assert_eq!(
        to_hex(&remix_signing_hash(&r).unwrap()),
        "80b0abe7aa35957185e9033d74a070efa01145ee948d26ed8265b013509d51fc",
    );
}
