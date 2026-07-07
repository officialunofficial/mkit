//! Regression tests for #208: unbounded tree-depth recursion.
//!
//! A crafted untrusted repo can nest thousands of single-entry trees in a
//! tiny pack. Content-addressing rules out true cycles, but each level still
//! costs one native stack frame, so the four core tree-walkers
//! (`index::from_tree`, `ops::diff`, `ops::merge`, `ops::restore`) would
//! stack-overflow the process. Each now caps recursion at `MAX_TREE_DEPTH`
//! and returns a typed `TreeTooDeep` error.
//!
//! These tests build a chain `2 * MAX_TREE_DEPTH` levels deep (well past the
//! cap, but small enough not to overflow on its own) and assert each walker
//! reports `TreeTooDeep` instead of recursing the whole way.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_core::index::{self, IndexError};
use mkit_core::layout::RepoLayout;
use mkit_core::ops::restore::{self, RestoreError, RestoreOptions};
use mkit_core::{
    Blob, EntryMode, MAX_TREE_DEPTH, Object, ObjectStore, StoreError, Tree, TreeEntry, diff_trees,
    merge_trees, serialize,
};
use tempfile::TempDir;

type Hash = [u8; 32];

fn fresh() -> (TempDir, ObjectStore) {
    let d = TempDir::new().unwrap();
    let s = ObjectStore::init(&RepoLayout::single(d.path())).unwrap();
    (d, s)
}

fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
    s.write(
        &serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap(),
    )
    .unwrap()
}

fn put_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
    s.write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
        .unwrap()
}

/// Build a chain of `levels` nested single-entry trees terminating in a leaf
/// blob, and return the hash of the outermost tree. Every intermediate
/// directory is named `d`; the leaf file is named `f` and holds `leaf`.
fn deep_chain(s: &ObjectStore, levels: usize, leaf: &[u8]) -> Hash {
    let leaf_blob = put_blob(s, leaf);
    let mut cur = put_tree(
        s,
        vec![TreeEntry {
            name: b"f".to_vec(),
            mode: EntryMode::Blob,
            object_hash: leaf_blob,
        }],
    );
    for _ in 0..levels {
        cur = put_tree(
            s,
            vec![TreeEntry {
                name: b"d".to_vec(),
                mode: EntryMode::Tree,
                object_hash: cur,
            }],
        );
    }
    cur
}

/// A depth past the cap so every walker must hit the limit before bottoming
/// out. A small margin over the cap is enough — the guard fires at
/// `depth > MAX_TREE_DEPTH` regardless of how much deeper the chain goes —
/// and keeps the number of fsync'd objects (and thus test runtime) modest.
fn over_cap() -> usize {
    MAX_TREE_DEPTH + 8
}

#[test]
fn index_from_tree_rejects_deep_tree() {
    let (_d, s) = fresh();
    let root = deep_chain(&s, over_cap(), b"x");
    let err = index::from_tree(&s, root).unwrap_err();
    assert!(
        matches!(err, IndexError::TreeTooDeep),
        "expected IndexError::TreeTooDeep, got {err:?}"
    );
}

#[test]
fn diff_rejects_deep_tree() {
    let (_d, s) = fresh();
    // Two chains identical in shape but with different leaves, so the diff
    // walker recurses all the way down rather than short-circuiting on equal
    // subtree hashes.
    let old = deep_chain(&s, over_cap(), b"old");
    let new = deep_chain(&s, over_cap(), b"new");
    let err = diff_trees(&s, Some(old), Some(new)).unwrap_err();
    assert!(
        matches!(err, StoreError::TreeTooDeep),
        "expected StoreError::TreeTooDeep, got {err:?}"
    );
}

#[test]
fn diff_rejects_deep_added_tree() {
    let (_d, s) = fresh();
    // Old side empty, new side deep: exercises the `add_added_entries`
    // recursion path (and symmetrically `add_removed_entries`).
    let new = deep_chain(&s, over_cap(), b"x");
    let err = diff_trees(&s, None, Some(new)).unwrap_err();
    assert!(
        matches!(err, StoreError::TreeTooDeep),
        "expected StoreError::TreeTooDeep (added path), got {err:?}"
    );
    let err = diff_trees(&s, Some(new), None).unwrap_err();
    assert!(
        matches!(err, StoreError::TreeTooDeep),
        "expected StoreError::TreeTooDeep (removed path), got {err:?}"
    );
}

#[test]
fn merge_rejects_deep_tree() {
    let (_d, s) = fresh();
    // Base unchanged on one side, changed on the other, so the merge walker
    // recurses into the differing subtree at every level.
    let base = deep_chain(&s, over_cap(), b"base");
    let ours = deep_chain(&s, over_cap(), b"ours");
    let err = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap_err();
    assert!(
        matches!(err, StoreError::TreeTooDeep),
        "expected StoreError::TreeTooDeep, got {err:?}"
    );
}

#[test]
fn restore_rejects_deep_tree() {
    let (_d, s) = fresh();
    let root = deep_chain(&s, over_cap(), b"x");
    let target = TempDir::new().unwrap();
    let err =
        restore::restore_tree_to_worktree(&s, &root, target.path(), &RestoreOptions::default())
            .unwrap_err();
    assert!(
        matches!(err, RestoreError::TreeTooDeep),
        "expected RestoreError::TreeTooDeep, got {err:?}"
    );
}
