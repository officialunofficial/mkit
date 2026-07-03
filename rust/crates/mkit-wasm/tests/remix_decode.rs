//! Golden round-trip for the `remix_encode_and_sign` / `remix_decode` /
//! `object_kind` wasm exports.
//!
//! These are the read/write halves of the repo browser's fork path: the
//! web client builds a fork via `remix_encode_and_sign` (one source =
//! the upstream commit being forked), pushes it, and on the way back
//! routes each fetched object through `object_kind` → `remix_decode` to
//! render the "remix/fork of …" badge whose `commit_hash` links to the
//! upstream commit. This test pins that a remix built here decodes back
//! to the same message / signer / parents / sources, and that
//! `object_kind` distinguishes a commit from a remix.
//!
//! Runs on native: the wasm-bindgen wrappers delegate straight to the
//! same Rust functions the wasm build exports, so covering them here
//! covers correctness without a browser test driver.

#![allow(clippy::unwrap_used)]

use mkit_wasm::{
    commit_encode_and_sign, ed25519_pubkey_from_seed, object_kind, remix_decode,
    remix_encode_and_sign,
};

/// Deterministic 32-byte seed (RFC 8032 §7.1 vector 1 secret key).
const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// A 64-hex tree hash to build over (value is opaque to the test).
const TREE_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const UPSTREAM_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// A root remix (no parents) referencing one upstream commit round-trips
/// message / signer / source through `remix_encode_and_sign` →
/// `remix_decode`.
#[test]
fn round_trip_root_remix_single_source() {
    // The upstream commit being forked.
    let upstream =
        commit_encode_and_sign(TREE_HEX, "", "upstream root", 1_700_000_000, SEED_HEX).unwrap();
    let upstream_hash = upstream.hash_hex();

    let sources = format!(
        r#"[{{"upstream_id_hex":"{UPSTREAM_ID_HEX}","commit_hash_hex":"{upstream_hash}"}}]"#
    );
    let msg = "forked it";
    let remix =
        remix_encode_and_sign(TREE_HEX, "", &sources, msg, 1_700_000_001, SEED_HEX).unwrap();

    let info = remix_decode(&remix.bytes()).unwrap();
    assert_eq!(info.message(), msg);
    assert_eq!(info.timestamp(), 1_700_000_001);
    assert_eq!(info.parent_count(), 0);
    assert!(info.parent(0).is_none());

    // Exactly one source, pointing at the forked upstream commit.
    assert_eq!(info.source_count(), 1);
    let s0 = info.source(0).unwrap();
    assert_eq!(s0.upstream_id_hex(), UPSTREAM_ID_HEX);
    assert_eq!(s0.commit_hash_hex(), upstream_hash);
    assert!(info.source(1).is_none());

    let expected_signer = hex::encode(ed25519_pubkey_from_seed(&hex_to_bytes(SEED_HEX)).unwrap());
    assert_eq!(info.signer_hex(), expected_signer);
    assert_eq!(info.tree_hex(), TREE_HEX);
    assert_eq!(info.signature_hex(), remix.signature_hex());
    assert_eq!(info.signature_hex().len(), 128);
}

/// A remix with a parent decodes that parent; multiple sources come back
/// sorted by `(upstream_id, commit_hash)` (the order `read_remix`
/// enforces), regardless of input order.
#[test]
fn round_trip_remix_parent_and_sorted_sources() {
    let parent_remix = {
        let up = commit_encode_and_sign(TREE_HEX, "", "u", 1, SEED_HEX).unwrap();
        let srcs = format!(
            r#"[{{"upstream_id_hex":"{UPSTREAM_ID_HEX}","commit_hash_hex":"{}"}}]"#,
            up.hash_hex()
        );
        remix_encode_and_sign(TREE_HEX, "", &srcs, "parent remix", 2, SEED_HEX).unwrap()
    };
    let parent_hash = parent_remix.hash_hex();

    // Two sources under the same upstream_id, supplied OUT of order — the
    // larger commit_hash first. Decode must return them ascending.
    let lo = "00".repeat(32);
    let hi = "ff".repeat(32);
    let sources = format!(
        r#"[{{"upstream_id_hex":"{UPSTREAM_ID_HEX}","commit_hash_hex":"{hi}"}},
            {{"upstream_id_hex":"{UPSTREAM_ID_HEX}","commit_hash_hex":"{lo}"}}]"#
    );
    let child = remix_encode_and_sign(TREE_HEX, &parent_hash, &sources, "child remix", 3, SEED_HEX)
        .unwrap();
    let info = remix_decode(&child.bytes()).unwrap();

    assert_eq!(info.message(), "child remix");
    assert_eq!(info.parent_count(), 1);
    assert_eq!(info.parent(0).as_deref(), Some(parent_hash.as_str()));

    assert_eq!(info.source_count(), 2);
    assert_eq!(info.source(0).unwrap().commit_hash_hex(), lo);
    assert_eq!(info.source(1).unwrap().commit_hash_hex(), hi);
}

/// `object_kind` distinguishes a commit's bytes from a remix's bytes, so
/// the browser can route to `commit_decode` vs `remix_decode`.
#[test]
fn object_kind_separates_commit_and_remix() {
    let commit = commit_encode_and_sign(TREE_HEX, "", "a commit", 1, SEED_HEX).unwrap();
    assert_eq!(object_kind(&commit.bytes()).unwrap(), "commit");

    let sources = format!(
        r#"[{{"upstream_id_hex":"{UPSTREAM_ID_HEX}","commit_hash_hex":"{}"}}]"#,
        commit.hash_hex()
    );
    let remix = remix_encode_and_sign(TREE_HEX, "", &sources, "a remix", 2, SEED_HEX).unwrap();
    assert_eq!(object_kind(&remix.bytes()).unwrap(), "remix");
}

/// A remix with no sources is not a fork — `remix_encode_and_sign`
/// rejects it. Gated to wasm: the `Err` arm builds a `JsError` via a
/// wasm-bindgen import that panics on native (same constraint as the
/// commit/ed25519 negative tests).
#[cfg(target_arch = "wasm32")]
#[test]
fn remix_requires_at_least_one_source() {
    assert!(remix_encode_and_sign(TREE_HEX, "", "[]", "m", 1, SEED_HEX).is_err());
}

/// Native port of `remix_requires_at_least_one_source` (#505 PR 2/5): CI
/// never runs `wasm-pack test`, so the wasm-gated test above never
/// actually executes. On native the same `Err` arm panics via `JsError`
/// (wasm-bindgen imported function), so assert the panic through
/// `catch_unwind`, following
/// `webauthn.rs::challenge_not_bound_to_pae_is_rejected`.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn remix_requires_at_least_one_source() {
    let result = std::panic::catch_unwind(|| {
        let _ = remix_encode_and_sign(TREE_HEX, "", "[]", "m", 1, SEED_HEX);
    });
    assert!(
        result.is_err(),
        "remix_encode_and_sign with no sources must reject (panics natively via JsError)"
    );
}

/// `remix_decode` on commit bytes (and `commit_decode` on remix bytes)
/// is a structural error, not a panic. Gated to wasm for the same
/// `JsError` reason.
#[cfg(target_arch = "wasm32")]
#[test]
fn remix_decode_rejects_commit_bytes() {
    let commit = commit_encode_and_sign(TREE_HEX, "", "c", 1, SEED_HEX).unwrap();
    assert!(remix_decode(&commit.bytes()).is_err());
}

/// Native port of `remix_decode_rejects_commit_bytes` (#505 PR 2/5): same
/// CI gap and same `catch_unwind` porting pattern as the ports above.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn remix_decode_rejects_commit_bytes() {
    let commit = commit_encode_and_sign(TREE_HEX, "", "c", 1, SEED_HEX).unwrap();
    let result = std::panic::catch_unwind(|| {
        let _ = remix_decode(&commit.bytes());
    });
    assert!(
        result.is_err(),
        "remix_decode on commit bytes must reject (panics natively via JsError)"
    );
}
