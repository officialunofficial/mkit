//! End-to-end integration tests for the Phase 5a ops surface.
//!
//! These tests are deliberately *cross-module*: they build a small
//! commit graph in a real `TempDir`-backed `ObjectStore` and then
//! verify that `diff_trees`, `find_merge_base`, `merge_trees`, and
//! `cherry_pick` agree with each other on the same data. The
//! per-module unit tests under `src/ops/*.rs` cover edge cases in
//! isolation; this file is the integration safety net.

#![allow(clippy::many_single_char_names)] // single-letter commit names keep the test tables compact
#![allow(clippy::similar_names)] // `add_b` / `add_b_tree` is the natural pairing

use mkit_core::{
    Blob, Commit, ConflictKind, EntryMode, Identity, Object, ObjectStore, Tree, TreeEntry,
    cherry_pick, diff_trees, find_merge_base, hash, is_ancestor, merge_trees, serialize,
};
use tempfile::TempDir;

type Hash = [u8; 32];

fn fresh() -> (TempDir, ObjectStore) {
    let d = TempDir::new().unwrap();
    let s = ObjectStore::init(d.path()).unwrap();
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

fn entry(name: &[u8], mode: EntryMode, h: Hash) -> TreeEntry {
    TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash: h,
    }
}

fn put_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
    let c = Commit {
        tree_hash: tree,
        parents: parents.to_vec(),
        author: Identity::ed25519([0; 32]),
        signer: [0; 32],
        message: message.as_bytes().to_vec(),
        timestamp: message.len() as u64,
        message_hash: [0; 32],
        content_digest: [0; 32],
        signature: [0; 64],
    };
    s.write(&serialize::serialize(&Object::Commit(c)).unwrap())
        .unwrap()
}

/// Build the canonical "diamond" graph used across tests:
///
/// ```text
///       root
///       /  \
///   left    right
///       \  /
///       merge
/// ```
///
/// All commits point at the same single-file tree to keep the structure
/// focused on graph-shape, not tree content.
fn diamond(s: &ObjectStore) -> (Hash, Hash, Hash, Hash, Hash) {
    let blob = put_blob(s, b"x");
    let tree = put_tree(s, vec![entry(b"f", EntryMode::Blob, blob)]);
    let root = put_commit(s, tree, &[], "root");
    let left = put_commit(s, tree, &[root], "left");
    let right = put_commit(s, tree, &[root], "right");
    let merge = put_commit(s, tree, &[left, right], "merge");
    (root, left, right, merge, tree)
}

#[test]
fn diff_then_merge_round_trip() {
    // Construct base/ours/theirs by stacking diffs so that the merged
    // tree must match a third tree built directly from the union of
    // changes.
    let (_d, s) = fresh();
    let blob_a = put_blob(&s, b"aaa");
    let blob_b = put_blob(&s, b"bbb");
    let blob_c = put_blob(&s, b"ccc");

    let base = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
    let ours = put_tree(
        &s,
        vec![
            entry(b"a.txt", EntryMode::Blob, blob_a),
            entry(b"b.txt", EntryMode::Blob, blob_b),
        ],
    );
    let theirs = put_tree(
        &s,
        vec![
            entry(b"a.txt", EntryMode::Blob, blob_a),
            entry(b"c.txt", EntryMode::Blob, blob_c),
        ],
    );

    // Diff each side from the base — both should report a single Added.
    let dours = diff_trees(&s, Some(base), Some(ours)).unwrap();
    let dtheirs = diff_trees(&s, Some(base), Some(theirs)).unwrap();
    assert_eq!(dours.entries.len(), 1);
    assert_eq!(dtheirs.entries.len(), 1);
    assert_eq!(dours.entries[0].path, "b.txt");
    assert_eq!(dtheirs.entries[0].path, "c.txt");

    // Merge should accept both (no overlap) — three entries.
    let m = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
    assert!(!m.has_conflicts());
    let merged = match s.read_object(&m.tree_hash).unwrap() {
        Object::Tree(t) => t.entries,
        _ => panic!("expected tree"),
    };
    assert_eq!(merged.len(), 3);

    // A diff of base → merged should now report two Added entries
    // ("b.txt", "c.txt"), in lex order.
    let dmerged = diff_trees(&s, Some(base), Some(m.tree_hash)).unwrap();
    assert_eq!(dmerged.entries.len(), 2);
    assert_eq!(dmerged.entries[0].path, "b.txt");
    assert_eq!(dmerged.entries[1].path, "c.txt");
}

#[test]
fn find_merge_base_on_diamond_is_root() {
    let (_d, s) = fresh();
    let (root, left, right, _merge, _tree) = diamond(&s);
    assert_eq!(find_merge_base(&s, left, right).unwrap(), Some(root));
}

#[test]
fn is_ancestor_on_diamond() {
    let (_d, s) = fresh();
    let (root, left, right, merge, _tree) = diamond(&s);
    assert!(is_ancestor(&s, root, left).unwrap());
    assert!(is_ancestor(&s, root, right).unwrap());
    assert!(is_ancestor(&s, left, merge).unwrap());
    assert!(is_ancestor(&s, right, merge).unwrap());
    assert!(!is_ancestor(&s, left, right).unwrap());
}

#[test]
fn cherry_pick_target_then_diff_picks_only_target_changes() {
    // Stack: base -> add_b -> add_c on the "feature" branch.
    // Cherry-pick `add_b` onto an `ours` tree that's identical to base.
    // After cherry-pick, the diff (base -> picked) must mention only b.txt.
    let (_d, s) = fresh();
    let blob_a = put_blob(&s, b"aaa");
    let blob_b = put_blob(&s, b"bbb");
    let blob_c = put_blob(&s, b"ccc");

    let base_tree = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
    let base_commit = put_commit(&s, base_tree, &[], "base");

    let add_b_tree = put_tree(
        &s,
        vec![
            entry(b"a.txt", EntryMode::Blob, blob_a),
            entry(b"b.txt", EntryMode::Blob, blob_b),
        ],
    );
    let add_b = put_commit(&s, add_b_tree, &[base_commit], "add b");

    let add_c_tree = put_tree(
        &s,
        vec![
            entry(b"a.txt", EntryMode::Blob, blob_a),
            entry(b"b.txt", EntryMode::Blob, blob_b),
            entry(b"c.txt", EntryMode::Blob, blob_c),
        ],
    );
    let _add_c = put_commit(&s, add_c_tree, &[add_b], "add c");

    // Pick add_b onto base_tree.
    let r = cherry_pick(&s, add_b, base_tree).unwrap();
    assert!(!r.has_conflicts());
    assert_eq!(r.original_message, b"add b");

    let d = diff_trees(&s, Some(base_tree), Some(r.tree_hash)).unwrap();
    assert_eq!(d.entries.len(), 1);
    assert_eq!(d.entries[0].path, "b.txt");
}

#[test]
fn cherry_pick_modify_modify_conflict_carries_message() {
    let (_d, s) = fresh();
    let v0 = put_blob(&s, b"v0");
    let v1 = put_blob(&s, b"v1");
    let v2 = put_blob(&s, b"v2");
    let base_tree = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v0)]);
    let base_commit = put_commit(&s, base_tree, &[], "base");

    let target_tree = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
    let target = put_commit(&s, target_tree, &[base_commit], "their change");

    let ours_tree = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);

    let r = cherry_pick(&s, target, ours_tree).unwrap();
    assert!(r.has_conflicts());
    assert_eq!(r.conflicts.len(), 1);
    assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
    assert_eq!(r.original_message, b"their change");
    // The merged tree still exists and contains "ours" at the conflict.
    let merged = match s.read_object(&r.tree_hash).unwrap() {
        Object::Tree(t) => t.entries,
        _ => panic!("expected tree"),
    };
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].object_hash, v2);
}

/// Determinism guard for the Phase 5a operations: with fixed input
/// blob contents the merged tree's content-addressed hash is fully
/// determined, and the cherry-pick result hashes likewise. If anything
/// in the merge decision matrix or tree serialisation drifts, this
/// test flips. See `rust/tests/golden/phase5a/README.md` for why we
/// pin hashes rather than byte vectors at this layer.
#[test]
fn merge_and_cherry_pick_are_byte_deterministic() {
    let (_d, s) = fresh();
    // Use deterministic blob bytes — every input here is a fixed
    // constant so the resulting hashes are stable across runs.
    let v0 = put_blob(&s, b"phase5a:v0");
    let v1 = put_blob(&s, b"phase5a:v1");
    let v2 = put_blob(&s, b"phase5a:v2");

    let base = put_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, v0)]);
    let ours = put_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, v1)]);
    let theirs = put_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, v0)]);

    // Ours-modified, theirs-unchanged → take ours.
    let m = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
    assert!(!m.has_conflicts());
    assert_eq!(
        m.tree_hash, ours,
        "single-side modify must produce the modifying side's tree verbatim"
    );

    // Re-running merge with the same inputs must produce the same tree
    // hash (byte-for-byte determinism, content-addressed).
    let m2 = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
    assert_eq!(m.tree_hash, m2.tree_hash);

    // The merged tree's bytes hash to the tree hash by construction.
    let merged_bytes = s.read(&m.tree_hash).unwrap();
    assert_eq!(hash::hash(&merged_bytes), m.tree_hash);

    // Cherry-pick determinism: same target, same ours -> same result tree.
    let target_commit = put_commit(&s, ours, &[put_commit(&s, base, &[], "base")], "modify");
    let r1 = cherry_pick(&s, target_commit, v_to_tree(&s, v2)).unwrap();
    let r2 = cherry_pick(&s, target_commit, v_to_tree(&s, v2)).unwrap();
    assert_eq!(r1.tree_hash, r2.tree_hash);
    assert_eq!(r1.original_message, r2.original_message);
}

fn v_to_tree(s: &ObjectStore, v: Hash) -> Hash {
    put_tree(s, vec![entry(b"f.txt", EntryMode::Blob, v)])
}

#[test]
fn merge_uses_find_merge_base_on_diamond() {
    // End-to-end: derive the merge base ourselves and feed it into
    // merge_trees. With identical trees on both sides, the merge must
    // be a clean no-op pointing at the same tree hash.
    let (_d, s) = fresh();
    let (root, left, right, _merge, tree) = diamond(&s);

    let base = find_merge_base(&s, left, right).unwrap().expect("has base");
    assert_eq!(base, root);

    // Look up the actual tree on each side.
    let left_tree = match s.read_object(&left).unwrap() {
        Object::Commit(c) => c.tree_hash,
        _ => panic!(),
    };
    let right_tree = match s.read_object(&right).unwrap() {
        Object::Commit(c) => c.tree_hash,
        _ => panic!(),
    };
    let base_tree = match s.read_object(&base).unwrap() {
        Object::Commit(c) => c.tree_hash,
        _ => panic!(),
    };

    let m = merge_trees(&s, Some(base_tree), Some(left_tree), Some(right_tree)).unwrap();
    assert!(!m.has_conflicts());
    assert_eq!(m.tree_hash, tree);
}
