//! Commit-graph traversal helpers. Port of `src/graph.zig`.
//!
//! The Zig original exposes a single function — `collectAncestorSet` —
//! and that is what we mirror here. Higher-level walks (`is_ancestor`,
//! `find_merge_base`) live in [`super::merge`] alongside the merge
//! algorithm that consumes them, matching the Zig layout.
//!
//! Bound: at most `MAX_ANCESTORS` (`10_000`) commits are visited per call,
//! mirroring the `max_ancestors` constant in `src/graph.zig`. Beyond
//! that the walk stops silently — callers asking about pathologically
//! deep histories get a partial answer rather than an OOM.

use std::collections::HashSet;
use std::hash::BuildHasher;

use crate::hash::Hash;
use crate::object::Object;
use crate::store::{ObjectStore, StoreError};

/// Hard cap on commits visited per call. Matches `src/graph.zig`.
pub const MAX_ANCESTORS: usize = 10_000;

/// Collect the set of all ancestor commits of `start`, including
/// `start` itself, by DFS over `Commit::parents`. The walk:
///
/// * Adds `start` to `set` even if its object is not in the store
///   (matches Zig: the hash is recorded, then the missing-object error
///   short-circuits the parent walk for that node).
/// * Treats non-commit objects at a hash as terminators (no parents to
///   follow).
/// * Stops cleanly after [`MAX_ANCESTORS`] inserts.
///
/// # Errors
///
/// Only [`StoreError::Io`] / [`StoreError::HashMismatch`] /
/// [`StoreError::ObjectTooLarge`] / [`StoreError::Decode`] propagate.
/// `ObjectNotFound` is *swallowed* per Zig parity — see test
/// `handles_non_existent_parent_gracefully`.
pub fn collect_ancestor_set<S: BuildHasher>(
    store: &ObjectStore,
    start: Hash,
    set: &mut HashSet<Hash, S>,
) -> Result<(), StoreError> {
    let mut stack: Vec<Hash> = Vec::new();
    stack.push(start);

    let mut count: usize = 0;
    while let Some(current) = stack.pop() {
        if count >= MAX_ANCESTORS {
            break;
        }
        if !set.insert(current) {
            continue;
        }
        count += 1;

        match store.read_object(&current) {
            Ok(Object::Commit(c)) => {
                for &parent in &c.parents {
                    stack.push(parent);
                }
            }
            // Non-commit (or unreadable) — same as Zig's `obj != .commit`
            // / `store.get(...) catch continue` paths: stop walking from
            // this node, but we keep the hash in `set`.
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// =====================================================================
// Tests — parity with Zig `graph.zig`.
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // mirrors the single-letter Zig test style intentionally
mod tests {
    use super::*;
    use crate::hash;
    use crate::object::EntryMode;
    use crate::object::{Blob, Commit, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(d.path()).unwrap();
        (d, s)
    }

    fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        s.write(&bytes).unwrap()
    }

    fn put_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }

    fn make_single_file_tree(s: &ObjectStore, name: &[u8], data: &[u8]) -> Hash {
        let blob = put_blob(s, data);
        put_tree(
            s,
            vec![TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        )
    }

    fn make_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
        let c = Commit {
            tree_hash: tree,
            parents: parents.to_vec(),
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: message.as_bytes().to_vec(),
            timestamp: message.len() as u64, // tiny per-commit divergence avoids store dedup
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        let bytes = serialize::serialize(&Object::Commit(c)).unwrap();
        s.write(&bytes).unwrap()
    }

    #[test]
    fn linear_chain_3_commits() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c2], "c3");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c3, &mut set).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
    }

    #[test]
    fn diamond_dag() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c1], "c3");
        let c4 = make_commit(&s, tree, &[c2, c3], "c4");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c4, &mut set).unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
        assert!(set.contains(&c4));
    }

    #[test]
    fn root_commit_alone() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "root");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&c1));
    }

    #[test]
    fn handles_non_existent_parent_gracefully() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let fake_parent = hash::hash(b"nonexistent-parent");
        let c1 = make_commit(&s, tree, &[fake_parent], "orphan");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        // Both c1 and the fake hash end up in the set; the fake hash
        // doesn't continue the walk because the object lookup fails.
        assert_eq!(set.len(), 2);
        assert!(set.contains(&c1));
        assert!(set.contains(&fake_parent));
    }

    #[test]
    fn empty_store_records_starting_hash() {
        let (_d, s) = store();
        let fake = hash::hash(b"does-not-exist");
        let mut set = HashSet::new();
        collect_ancestor_set(&s, fake, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&fake));
    }
}
