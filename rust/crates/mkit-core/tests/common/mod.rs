//! Shared deterministic fixture repo for SPEC-DISCLOSURE goldens
//! (partial-disclosure bundles and the closure profile).
//!
//! The builder MUST stay byte-identical: disclosure goldens hash the
//! objects this function produces. Do not change seeds, timestamps,
//! tree-entry order, or file bytes.

#![allow(dead_code)] // fields and helpers are used by some consumers only
#![allow(clippy::unwrap_used)]

use mkit_core::hash::{Hash, ZERO};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::store::ObjectStore;
use mkit_core::worktree::store_file_object;

pub(crate) struct Fixture {
    pub(crate) _dir: tempfile::TempDir,
    pub(crate) store: ObjectStore,
    pub(crate) commit_id: Hash,
    pub(crate) tree_hash: Hash,
    pub(crate) range_blob: Vec<u8>,
}

/// A small xorshift64* stream, seeded fixed — deterministic, not
/// cryptographic; used only to produce non-repeating file bytes so
/// `FastCDC` yields realistic chunk boundaries.
pub(crate) fn prng_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    let mut out = vec![0u8; len];
    for b in &mut out {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = (x >> 56) as u8;
    }
    out
}

pub(crate) fn build_fixture() -> Fixture {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("store init");

    let shallow = store_file_object(&store, b"shallow file content").unwrap();
    // A blob spanning multiple 1 KiB Bao chunks, for the range-over-a-
    // small-blob vectors (first block / last partial block / whole blob).
    let range_blob = prng_bytes(0x5EED_5EED_5EED_5EED, 1536);
    let range_blob_id = store_file_object(&store, &range_blob).unwrap();
    let deep_file = store_file_object(&store, b"three levels deep, deterministic").unwrap();
    let exec = store_file_object(&store, b"#!/bin/sh\necho hi\n").unwrap();

    // 3 MiB of a fixed PRNG stream so FastCDC yields several chunks.
    let chunked_bytes = prng_bytes(0x1234_5678_9abc_def0, 3 * 1024 * 1024);
    let chunked_id = store_file_object(&store, &chunked_bytes).unwrap();

    let deep_tree = Tree {
        entries: vec![TreeEntry {
            name: b"deep.txt".to_vec(),
            mode: EntryMode::Blob,
            object_hash: deep_file,
        }],
    };
    let deep_tree_id = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(deep_tree)).unwrap())
        .unwrap();

    let mid_tree = Tree {
        entries: vec![TreeEntry {
            name: b"deep".to_vec(),
            mode: EntryMode::Tree,
            object_hash: deep_tree_id,
        }],
    };
    let mid_tree_id = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(mid_tree)).unwrap())
        .unwrap();

    let root_tree = Tree {
        entries: vec![
            TreeEntry {
                name: b"chunked.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: chunked_id,
            },
            TreeEntry {
                name: b"exec.sh".to_vec(),
                mode: EntryMode::Executable,
                object_hash: exec,
            },
            TreeEntry {
                name: b"range.bin".to_vec(),
                mode: EntryMode::Blob,
                object_hash: range_blob_id,
            },
            TreeEntry {
                name: b"shallow.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: shallow,
            },
            TreeEntry {
                name: b"sub".to_vec(),
                mode: EntryMode::Tree,
                object_hash: mid_tree_id,
            },
        ],
    };
    let tree_hash = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(root_tree)).unwrap())
        .unwrap();

    let kp = KeyPair::from_seed([0x07; 32]);
    let mut commit = Commit {
        tree_hash,
        parents: vec![],
        author: Identity::ed25519(kp.public.0),
        signer: kp.public.0,
        message: b"SPEC-DISCLOSURE golden fixture".to_vec(),
        timestamp: 1_726_300_000,
        message_hash: ZERO,
        content_digest: ZERO,
        signature: [0u8; 64],
    };
    commit.signature = sign_commit(&commit, &kp).unwrap().0;
    let commit_bytes = mkit_core::serialize::serialize(&Object::Commit(commit)).unwrap();
    let commit_id = store.write(&commit_bytes).unwrap();

    Fixture {
        _dir: dir,
        store,
        commit_id,
        tree_hash,
        range_blob,
    }
}
