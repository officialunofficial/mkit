//! Single-commit cherry-pick onto a different base tree. Port of
//! `src/cherry_pick.zig`.
//!
//! This is intentionally a *tree-level* operation: it computes the
//! 3-way merge of `(target.parents[0].tree, ours_tree, target.tree)`
//! and returns the resulting tree hash plus any conflicts. Building a
//! new commit on top of the merged tree is the caller's job — it
//! happens at the CLI layer in the Zig codebase too, and porting that
//! belongs to a later phase that wires `refs` and the index together.
//!
//! Notes vs the prompt's `CherryPickResult` enum: the Zig contract
//! returns a struct with `tree_hash` + `conflicts` + `original_message`,
//! and signals "the input wasn't a commit" with `error.NotACommit`.
//! There's no `AlreadyAncestor` short-circuit in the Zig source — that's
//! a higher-level decision the CLI makes before calling cherry-pick. We
//! preserve the Zig contract verbatim and document the deviation here.

use crate::hash::Hash;
use crate::object::Object;
use crate::store::{ObjectStore, StoreError};

use super::merge::{self, Conflict};

/// Errors specific to cherry-pick on top of [`StoreError`]. We split
/// these out so callers can distinguish "your input hash didn't point
/// at a commit" (a programmer error) from filesystem failures.
#[derive(Debug, thiserror::Error)]
pub enum CherryPickError {
    #[error("target hash does not refer to a commit object")]
    NotACommit,
    #[error("target commit's first parent does not refer to a commit object")]
    ParentNotACommit,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Result of [`cherry_pick`]. `tree_hash` is the merged tree (always
/// written to the store, even on conflict — the merged tree contains
/// "ours" at every conflicting path). `original_message` is the target
/// commit's message verbatim, so the caller can use it as the basis
/// for a new commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CherryPickResult {
    pub tree_hash: Hash,
    pub conflicts: Vec<Conflict>,
    pub original_message: Vec<u8>,
}

impl CherryPickResult {
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Cherry-pick `target_hash` onto `ours_tree`.
///
/// Algorithm:
///
/// 1. Load the target commit. (Error if not a commit.)
/// 2. Load the target's first parent's tree as the merge `base`. If
///    the target is a root commit (no parents), `base = None` (empty
///    tree) — same as Zig.
/// 3. 3-way merge `(base, ours_tree, target.tree_hash)`.
/// 4. Return the merged tree hash, any conflicts, and the target
///    commit's `message` so the caller can craft a new commit.
///
/// # Errors
///
/// * [`CherryPickError::NotACommit`] when `target_hash` doesn't point
///   at a commit object (mirrors Zig's `error.NotACommit`).
/// * [`CherryPickError::ParentNotACommit`] when the parent hash points
///   at something other than a commit (mirrors the `if (parent_obj !=
///   .commit) return error.NotACommit` branch in `cherry_pick.zig`).
/// * [`CherryPickError::Store`] for any wrapped store/serialize error.
pub fn cherry_pick(
    store: &ObjectStore,
    target_hash: Hash,
    ours_tree: Hash,
) -> Result<CherryPickResult, CherryPickError> {
    let Object::Commit(target_commit) = store.read_object(&target_hash)? else {
        return Err(CherryPickError::NotACommit);
    };

    let parent_tree: Option<Hash> = if target_commit.parents.is_empty() {
        None
    } else {
        let Object::Commit(parent_commit) = store.read_object(&target_commit.parents[0])? else {
            return Err(CherryPickError::ParentNotACommit);
        };
        Some(parent_commit.tree_hash)
    };

    let original_message = target_commit.message.clone();
    let merge_result = merge::merge_trees(
        store,
        parent_tree,
        Some(ours_tree),
        Some(target_commit.tree_hash),
    )?;

    Ok(CherryPickResult {
        tree_hash: merge_result.tree_hash,
        conflicts: merge_result.conflicts,
        original_message,
    })
}

// =====================================================================
// Tests — parity with Zig `cherry_pick.zig`.
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use crate::ops::merge::ConflictKind;
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
    fn make_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }
    fn entry(name: &[u8], mode: EntryMode, h: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: h,
        }
    }
    fn make_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
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
    fn tree_entries(s: &ObjectStore, h: Hash) -> Vec<TreeEntry> {
        match s.read_object(&h).unwrap() {
            Object::Tree(t) => t.entries,
            other => panic!("expected tree, got {other}"),
        }
    }

    #[test]
    fn adds_a_file_onto_branch_missing_it() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let base_commit = make_commit(&s, base_tree, &[], "initial");
        let blob_b = put_blob(&s, b"bbb");
        let target_tree = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let target_commit = make_commit(&s, target_tree, &[base_commit], "add b.txt");

        let r = cherry_pick(&s, target_commit, base_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(r.original_message, b"add b.txt");
        let merged = tree_entries(&s, r.tree_hash);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn modify_modify_conflict() {
        let (_d, s) = store();
        let blob_orig = put_blob(&s, b"original");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_orig)]);
        let base_commit = make_commit(&s, base_tree, &[], "initial");
        let blob_theirs = put_blob(&s, b"theirs-change");
        let target_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_theirs)]);
        let target_commit = make_commit(&s, target_tree, &[base_commit], "change a.txt");
        let blob_ours = put_blob(&s, b"ours-change");
        let ours_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_ours)]);

        let r = cherry_pick(&s, target_commit, ours_tree).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts.len(), 1);
        assert_eq!(r.conflicts[0].path, "a.txt");
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
        assert_eq!(r.original_message, b"change a.txt");
    }

    #[test]
    fn root_commit_no_parent() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let root_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let root_commit = make_commit(&s, root_tree, &[], "root commit");
        let blob_b = put_blob(&s, b"bbb");
        let ours_tree = make_tree(&s, vec![entry(b"b.txt", EntryMode::Blob, blob_b)]);
        let r = cherry_pick(&s, root_commit, ours_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(r.original_message, b"root commit");
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 2);
    }

    #[test]
    fn delete_modify_conflict() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"original");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let base_commit = make_commit(&s, base_tree, &[], "initial");
        let target_tree = make_tree(&s, vec![]);
        let target_commit = make_commit(&s, target_tree, &[base_commit], "remove a.txt");
        let blob_modified = put_blob(&s, b"modified content");
        let ours_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_modified)]);
        let r = cherry_pick(&s, target_commit, ours_tree).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts[0].kind, ConflictKind::DeleteModify);
        assert_eq!(r.conflicts[0].path, "a.txt");
    }

    #[test]
    fn adds_multiple_files() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let base_commit = make_commit(&s, base_tree, &[], "initial");
        let blob_b = put_blob(&s, b"bbb");
        let blob_c = put_blob(&s, b"ccc");
        let blob_d = put_blob(&s, b"ddd");
        let target_tree = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
                entry(b"c.txt", EntryMode::Blob, blob_c),
                entry(b"d.txt", EntryMode::Blob, blob_d),
            ],
        );
        let target_commit = make_commit(&s, target_tree, &[base_commit], "add b, c, d");
        let r = cherry_pick(&s, target_commit, base_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 4);
    }

    #[test]
    fn non_commit_input_returns_error() {
        let (_d, s) = store();
        let blob_hash = put_blob(&s, b"just a blob");
        let empty_tree = make_tree(&s, vec![]);
        let err = cherry_pick(&s, blob_hash, empty_tree).unwrap_err();
        assert!(matches!(err, CherryPickError::NotACommit));
    }

    #[test]
    fn root_commit_onto_empty_ours() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let blob_b = put_blob(&s, b"bbb");
        let root_tree = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let root_commit = make_commit(&s, root_tree, &[], "root");
        let empty_tree = make_tree(&s, vec![]);
        let r = cherry_pick(&s, root_commit, empty_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 2);
    }
}
