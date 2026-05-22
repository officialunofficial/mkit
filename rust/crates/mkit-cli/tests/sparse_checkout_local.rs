//! End-to-end coverage for the local-transport sparse-checkout path
//! (issue #158 Phase 2).
//!
//! These tests exercise the in-process pipeline:
//!   1. Build a tree manually.
//!   2. Run `build_sparse` + `verify_sparse` against a filter.
//!   3. Encode + decode the wire envelope.
//!   4. Re-verify the round-tripped response.
//!
//! No HTTP / S3 / network involved — the file transport already serves
//! the full tree, so sparse-checkout over the file transport is purely
//! a client-side path. The wire round-trip still goes through the
//! encoder so regressions in either half surface here.

#![cfg(feature = "sparse-checkout")]

use std::path::PathBuf;

use mkit_core::object::{EntryMode, Tree, TreeEntry};
use mkit_core::sparse::{
    SparseResponse, build_sparse, decode_sparse_response, encode_sparse_response, hash_filter,
    tree_hash, verify_sparse,
};

fn entry(name: &[u8]) -> TreeEntry {
    TreeEntry {
        name: name.to_vec(),
        mode: EntryMode::Blob,
        object_hash: [0u8; 32],
    }
}

fn tree_for(names: &[&[u8]]) -> Tree {
    let entries: Vec<TreeEntry> = names.iter().copied().map(entry).collect();
    Tree { entries }
}

#[test]
fn local_round_trip_recovers_subset() {
    let tree = tree_for(&[
        b"docs",
        b"src/lib.rs",
        b"src/main.rs",
        b"tests/integration.rs",
    ]);
    let filter = vec![PathBuf::from("src")];
    let (delivered, manifest, proof) = build_sparse(&tree, &filter).unwrap();

    assert_eq!(delivered.len(), 2);
    assert_eq!(delivered[0].name, b"src/lib.rs");
    assert_eq!(delivered[1].name, b"src/main.rs");
    assert!(verify_sparse(&manifest, &delivered, &filter, &proof));

    // Filter hash is committed into the manifest.
    assert_eq!(manifest.filter_hash, hash_filter(&filter));
    // Tree hash binds to the canonical SPEC-OBJECTS hash.
    assert_eq!(manifest.tree_hash, tree_hash(&tree));
}

#[test]
fn local_wire_envelope_round_trip() {
    let tree = tree_for(&[b"a", b"b", b"c", b"d", b"e"]);
    let filter = vec![PathBuf::from("a"), PathBuf::from("c")];
    let (entries, manifest, proof) = build_sparse(&tree, &filter).unwrap();
    let resp = SparseResponse {
        manifest,
        entries,
        proof,
    };
    let bytes = encode_sparse_response(&resp).unwrap();
    let parsed = decode_sparse_response(&bytes).unwrap();

    assert_eq!(parsed.manifest, resp.manifest);
    assert_eq!(parsed.entries.len(), resp.entries.len());
    assert!(verify_sparse(
        &parsed.manifest,
        &parsed.entries,
        &filter,
        &parsed.proof
    ));
}

#[test]
fn tampered_extra_bit_in_bitmap_is_rejected() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let filter = vec![PathBuf::from("a")];
    let (entries, manifest, mut proof) = build_sparse(&tree, &filter).unwrap();

    // Server flips a bit it didn't earn (claims it included entry b),
    // without updating the manifest's bitmap_root.
    proof.bitmap_bytes[0] ^= 0b0000_0010;

    assert!(
        !verify_sparse(&manifest, &entries, &filter, &proof),
        "verifier MUST reject a bitmap that diverges from manifest.bitmap_root"
    );
}

#[test]
fn tampered_extra_entry_in_delivery_is_rejected() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let filter = vec![PathBuf::from("a")];
    let (mut entries, manifest, proof) = build_sparse(&tree, &filter).unwrap();

    // Server tries to slip in entry "b" — bitmap commits to 1 set bit,
    // delivered count would be 2. Cardinality check catches it.
    entries.push(entry(b"b"));
    assert!(
        !verify_sparse(&manifest, &entries, &filter, &proof),
        "verifier MUST reject a delivery whose entry count exceeds the bitmap's set-bit count"
    );
}

#[test]
fn filter_swap_is_rejected() {
    // Manifest committed against filter A. Client supplies filter B.
    // Filter-binding check fires before any bitmap reconstruction.
    let tree = tree_for(&[b"a", b"b"]);
    let (entries, manifest, proof) = build_sparse(&tree, &[PathBuf::from("a")]).unwrap();
    assert!(!verify_sparse(
        &manifest,
        &entries,
        &[PathBuf::from("b")],
        &proof,
    ));
}
