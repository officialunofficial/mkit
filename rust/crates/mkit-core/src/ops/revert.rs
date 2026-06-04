//! Single-commit revert onto a base tree — the inverse of cherry-pick.
//!
//! Where [`cherry_pick`](super::cherry_pick) applies `target`'s change to
//! `ours` via the 3-way merge `(base = target.parent.tree, ours, theirs =
//! target.tree)`, revert *undoes* it by swapping `base` and `theirs`:
//! `(base = target.tree, ours, theirs = target.parent.tree)`. The result
//! is the tree `ours` would have if `target`'s diff were reversed.
//!
//! Like cherry-pick this is a tree-level op: it returns the merged tree
//! and any conflicts, plus a generated `Revert "..."` commit message.
//! Building/committing/ref-wiring is the CLI's job. A revert is a normal
//! *forward* commit, so it is not gated on the gc recovery model.

use crate::hash::{self, Hash};
use crate::object::Object;
use crate::store::{ObjectStore, StoreError};

use super::merge::{self, Conflict};

/// Errors specific to revert on top of [`StoreError`].
#[derive(Debug, thiserror::Error)]
pub enum RevertError {
    #[error("target hash does not refer to a commit object")]
    NotACommit,
    #[error("target commit's first parent does not refer to a commit object")]
    ParentNotACommit,
    /// Reverting a merge commit is ambiguous — different parents yield
    /// different inverse patches — and mainline selection (`-m`) is not
    /// yet supported, so we refuse rather than silently pick parent 0.
    #[error("cannot revert a merge commit ({0} parents); mainline selection is not yet supported")]
    IsMergeCommit(usize),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Result of [`revert`]. `tree_hash` is the merged tree (always written,
/// even on conflict — it holds "ours" at every conflicting path).
/// `message` is the generated `Revert "<subject>"` commit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertResult {
    pub tree_hash: Hash,
    pub conflicts: Vec<Conflict>,
    pub message: Vec<u8>,
}

impl RevertResult {
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Revert `target_hash` against `ours_tree`.
///
/// 1. Load the target commit. (Error if not a commit.)
/// 2. Load the target's first parent's tree as the merge `theirs`. A
///    root commit (no parents) reverts against the empty tree, removing
///    everything it introduced.
/// 3. 3-way merge `(base = target.tree, ours = ours_tree, theirs =
///    parent.tree)` — the inverse of cherry-pick.
/// 4. Return the merged tree, any conflicts, and a `Revert "..."` message.
///
/// # Errors
/// * [`RevertError::NotACommit`] / [`RevertError::ParentNotACommit`] for
///   bad input objects.
/// * [`RevertError::Store`] for wrapped store/serialize errors.
pub fn revert(
    store: &ObjectStore,
    target_hash: Hash,
    ours_tree: Hash,
) -> Result<RevertResult, RevertError> {
    let Object::Commit(target_commit) = store.read_object(&target_hash)? else {
        return Err(RevertError::NotACommit);
    };

    // A merge commit has no single "the change it introduced": the
    // inverse depends on which parent is the mainline. Refuse (fail
    // closed) until `-m` is supported, rather than silently pick parent 0.
    if target_commit.parents.len() > 1 {
        return Err(RevertError::IsMergeCommit(target_commit.parents.len()));
    }

    let parent_tree: Option<Hash> = if target_commit.parents.is_empty() {
        None
    } else {
        let Object::Commit(parent_commit) = store.read_object(&target_commit.parents[0])? else {
            return Err(RevertError::ParentNotACommit);
        };
        Some(parent_commit.tree_hash)
    };

    // Inverse of cherry-pick: base = target's tree, theirs = parent's tree.
    let merge_result = merge::merge_trees(
        store,
        Some(target_commit.tree_hash),
        Some(ours_tree),
        parent_tree,
    )?;

    Ok(RevertResult {
        tree_hash: merge_result.tree_hash,
        conflicts: merge_result.conflicts,
        message: revert_message(&target_commit.message, &target_hash),
    })
}

/// The git-style revert message: `Revert "<subject>"` + a trailer naming
/// the reverted commit. `<subject>` is the first line of the original.
#[must_use]
pub fn revert_message(original_message: &[u8], target: &Hash) -> Vec<u8> {
    let text = String::from_utf8_lossy(original_message);
    let subject = text.lines().next().unwrap_or("");
    format!(
        "Revert \"{subject}\"\n\nThis reverts commit {}.\n",
        hash::to_hex(target)
    )
    .into_bytes()
}

// =====================================================================
// Tests
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
        s.write(
            &serialize::serialize(&Object::Blob(Blob {
                data: data.to_vec(),
            }))
            .unwrap(),
        )
        .unwrap()
    }
    fn make_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        s.write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap()
    }
    fn entry(name: &[u8], h: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
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
    fn tree_names(s: &ObjectStore, h: Hash) -> Vec<Vec<u8>> {
        match s.read_object(&h).unwrap() {
            Object::Tree(t) => t.entries.into_iter().map(|e| e.name).collect(),
            other => panic!("expected tree, got {other}"),
        }
    }

    #[test]
    fn reverting_an_add_removes_the_file() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", blob_a)]);
        let base = make_commit(&s, base_tree, &[], "initial");
        let blob_b = put_blob(&s, b"bbb");
        let target_tree = make_tree(&s, vec![entry(b"a.txt", blob_a), entry(b"b.txt", blob_b)]);
        let target = make_commit(&s, target_tree, &[base], "add b.txt");

        // Revert "add b.txt" against its own resulting tree → b.txt gone.
        let r = revert(&s, target, target_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_names(&s, r.tree_hash), vec![b"a.txt".to_vec()]);
        let msg = String::from_utf8(r.message).unwrap();
        assert!(msg.starts_with("Revert \"add b.txt\""), "{msg}");
        assert!(msg.contains("This reverts commit "), "{msg}");
    }

    #[test]
    fn reverting_a_delete_restores_the_file() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", blob_a)]);
        let base = make_commit(&s, base_tree, &[], "initial");
        let target_tree = make_tree(&s, vec![]); // a.txt removed
        let target = make_commit(&s, target_tree, &[base], "remove a.txt");

        let r = revert(&s, target, target_tree).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_names(&s, r.tree_hash), vec![b"a.txt".to_vec()]);
    }

    #[test]
    fn revert_conflicts_when_ours_changed_the_same_file() {
        let (_d, s) = store();
        let blob_orig = put_blob(&s, b"original");
        let base_tree = make_tree(&s, vec![entry(b"a.txt", blob_orig)]);
        let base = make_commit(&s, base_tree, &[], "initial");
        let blob_target = put_blob(&s, b"target-change");
        let target_tree = make_tree(&s, vec![entry(b"a.txt", blob_target)]);
        let target = make_commit(&s, target_tree, &[base], "change a.txt");
        // ours diverged from target on the same path.
        let blob_ours = put_blob(&s, b"ours-change");
        let ours_tree = make_tree(&s, vec![entry(b"a.txt", blob_ours)]);

        let r = revert(&s, target, ours_tree).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
        assert_eq!(r.conflicts[0].path, "a.txt");
    }

    #[test]
    fn non_commit_input_errors() {
        let (_d, s) = store();
        let blob = put_blob(&s, b"x");
        let empty = make_tree(&s, vec![]);
        assert!(matches!(
            revert(&s, blob, empty),
            Err(RevertError::NotACommit)
        ));
    }

    #[test]
    fn reverting_a_merge_commit_is_refused() {
        let (_d, s) = store();
        let blob = put_blob(&s, b"x");
        let t = make_tree(&s, vec![entry(b"a.txt", blob)]);
        let p1 = make_commit(&s, t, &[], "p1");
        let p2 = make_commit(&s, t, &[], "p2");
        let merge = make_commit(&s, t, &[p1, p2], "merge");
        assert!(matches!(
            revert(&s, merge, t),
            Err(RevertError::IsMergeCommit(2))
        ));
    }
}
