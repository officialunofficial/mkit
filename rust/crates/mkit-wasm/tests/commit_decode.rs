//! Golden round-trip for the `commit_decode` wasm export.
//!
//! `commit_decode` is the read half of the multiplayer-log ref walk: the
//! web client walks the room's `main` chain by `get_object` →
//! `commit_decode`, rendering each commit's message + signer + following
//! its first parent. This test pins that the bytes a commit is *built*
//! with (via `commit_encode_and_sign`) decode back to the same
//! message / signer / parents, so the walked log matches what was pushed.
//!
//! Runs on native: the wasm-bindgen wrappers delegate straight to the
//! same Rust functions the wasm build exports, so covering them here
//! covers correctness without a browser test driver.

#![allow(clippy::unwrap_used)]

use mkit_wasm::{commit_decode, commit_encode_and_sign, ed25519_pubkey_from_seed};

/// Deterministic 32-byte seed (RFC 8032 §7.1 vector 1 secret key).
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// A 64-hex tree hash to build the commit over (value is opaque to the test).
const TREE_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// Root commit (no parents) round-trips message + signer; parents empty.
#[test]
fn round_trip_root_commit() {
    let msg = "gm, multiplayer mkit";
    let encoded = commit_encode_and_sign(TREE_HEX, "", msg, 1_700_000_000, SEED_HEX).unwrap();

    let info = commit_decode(&encoded.bytes()).unwrap();
    assert_eq!(info.message(), msg);
    assert_eq!(info.timestamp(), 1_700_000_000);
    assert_eq!(info.parent_count(), 0);
    assert!(info.parent(0).is_none());

    // signer_hex is the Ed25519 pubkey derived from the seed.
    let expected_signer = hex::encode(ed25519_pubkey_from_seed(&hex_to_bytes(SEED_HEX)).unwrap());
    assert_eq!(info.signer_hex(), expected_signer);
    assert_eq!(info.signer_hex().len(), 64);
}

/// A child commit decodes its parent as the first (and only) parent id.
#[test]
fn round_trip_child_commit_parent() {
    let parent = commit_encode_and_sign(TREE_HEX, "", "root", 1, SEED_HEX).unwrap();
    let parent_hash = parent.hash_hex();

    let child = commit_encode_and_sign(TREE_HEX, &parent_hash, "second", 2, SEED_HEX).unwrap();
    let info = commit_decode(&child.bytes()).unwrap();

    assert_eq!(info.message(), "second");
    assert_eq!(info.parent_count(), 1);
    assert_eq!(info.parent(0).as_deref(), Some(parent_hash.as_str()));
}

/// Non-commit / garbage bytes are a structural error, not a panic.
///
/// Gated to wasm: the `Err` arm builds a `JsError` via a wasm-bindgen
/// imported function, which panics on native targets (same constraint as
/// `tests/ed25519.rs::sign_rejects_short_seed`). Browser-side this is the
/// consumer-visible "throws on bad bytes" contract.
#[cfg(target_arch = "wasm32")]
#[test]
fn rejects_non_commit_bytes() {
    assert!(commit_decode(b"not a commit object").is_err());
}
