//! End-to-end coverage for the local-transport sparse-checkout path
//! (issue #158).
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
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::PathBuf;

use mkit_core::object::{EntryMode, Tree, TreeEntry};
use mkit_core::sparse::{
    build_sparse, decode_sparse_response, encode_sparse_response, hash_filter, tree_hash,
    verify_sparse,
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
    let tree = tree_for(&[b"docs", b"lib.rs", b"main.rs", b"tests"]);
    let root = tree_hash(&tree);
    let filter = vec![PathBuf::from("lib.rs"), PathBuf::from("main.rs")];
    let response = build_sparse(&tree, &filter).unwrap();
    let verified = verify_sparse(&root, &filter, &response).unwrap();
    assert_eq!(verified.entries, vec![entry(b"lib.rs"), entry(b"main.rs")]);
    assert_eq!(response.manifest.filter_hash, hash_filter(&filter));
    assert_eq!(response.manifest.tree_hash, root);
}

#[test]
fn local_wire_envelope_round_trip() {
    let tree = tree_for(&[b"a", b"b", b"c", b"d", b"e"]);
    let filter = vec![PathBuf::from("a"), PathBuf::from("c")];
    let response = build_sparse(&tree, &filter).unwrap();
    let bytes = encode_sparse_response(&response).unwrap();
    let parsed = decode_sparse_response(&bytes).unwrap();
    assert_eq!(parsed.manifest, response.manifest);
    assert_eq!(
        verify_sparse(&tree_hash(&tree), &filter, &parsed)
            .unwrap()
            .entries,
        vec![entry(b"a"), entry(b"c")]
    );
}

#[test]
fn tampered_witness_is_rejected() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let filter = vec![PathBuf::from("a")];
    let mut response = build_sparse(&tree, &filter).unwrap();
    response.proof.tree_bytes[0] ^= 2;
    assert!(verify_sparse(&tree_hash(&tree), &filter, &response).is_err());
}

#[test]
fn omitted_selected_entry_in_witness_is_rejected() {
    let tree = tree_for(&[b"a", b"b", b"c"]);
    let filter = vec![PathBuf::from("a")];
    let mut response = build_sparse(&tree, &filter).unwrap();
    response.proof = build_sparse(&tree_for(&[b"b", b"c"]), &filter)
        .unwrap()
        .proof;
    assert!(verify_sparse(&tree_hash(&tree), &filter, &response).is_err());
}

#[test]
fn filter_swap_is_rejected() {
    let tree = tree_for(&[b"a", b"b"]);
    let response = build_sparse(&tree, &[PathBuf::from("a")]).unwrap();
    assert!(verify_sparse(&tree_hash(&tree), &[PathBuf::from("b")], &response).is_err());
}
