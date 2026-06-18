//! Single-commit cherry-pick onto a different base tree.
//!
//! This is intentionally a *tree-level* operation: it computes the
//! 3-way merge of `(target.parents[0].tree, ours_tree, target.tree)`
//! and returns the resulting tree hash plus any conflicts. Building a
//! new commit on top of the merged tree is the caller's job — the CLI
//! layer wires refs and the index together.
//!
//! There is no `AlreadyAncestor` short-circuit here — that is a
//! higher-level decision the CLI makes before calling cherry-pick.

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
    /// The target is a merge commit but no mainline parent was selected
    /// (git: "commit … is a merge but no -m option was given").
    #[error("commit is a merge but no mainline (-m <parent-number>) was given")]
    MergeNeedsMainline,
    /// A mainline parent was given for a non-merge commit (git: "mainline
    /// was specified but commit … is not a merge").
    #[error("mainline (-m) was specified but the commit is not a merge")]
    MainlineForNonMerge,
    /// The mainline parent number is out of range for this merge commit.
    #[error("invalid mainline parent {given}: commit has {parents} parents")]
    BadMainline { given: usize, parents: usize },
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
///    tree).
/// 3. 3-way merge `(base, ours_tree, target.tree_hash)`.
/// 4. Return the merged tree hash, any conflicts, and the target
///    commit's `message` so the caller can craft a new commit.
///
/// # Errors
///
/// * [`CherryPickError::NotACommit`] when `target_hash` doesn't point
///   at a commit object.
/// * [`CherryPickError::ParentNotACommit`] when the parent hash points
///   at something other than a commit.
/// * [`CherryPickError::Store`] for any wrapped store/serialize error.
pub fn cherry_pick(
    store: &ObjectStore,
    target_hash: Hash,
    ours_tree: Hash,
    mainline: Option<usize>,
) -> Result<CherryPickResult, CherryPickError> {
    let Object::Commit(target_commit) = store.read_object(&target_hash)? else {
        return Err(CherryPickError::NotACommit);
    };

    // Pick the parent whose diff is replayed, with git's `-m`/`--mainline`
    // semantics: a non-merge takes its sole parent (and rejects `-m`), while
    // a merge REQUIRES `-m <parent-number>` to choose the mainline (git
    // refuses to guess). The selected parent's tree is the base of the diff.
    let n_parents = target_commit.parents.len();
    let base_parent: Option<Hash> = match (n_parents, mainline) {
        (0, None) => None,
        (0 | 1, Some(_)) => return Err(CherryPickError::MainlineForNonMerge),
        (1, None) => Some(target_commit.parents[0]),
        (_, None) => return Err(CherryPickError::MergeNeedsMainline),
        (_, Some(m)) if m >= 1 && m <= n_parents => Some(target_commit.parents[m - 1]),
        (_, Some(m)) => {
            return Err(CherryPickError::BadMainline {
                given: m,
                parents: n_parents,
            });
        }
    };

    let parent_tree: Option<Hash> = match base_parent {
        None => None,
        Some(parent_hash) => {
            let Object::Commit(parent_commit) = store.read_object(&parent_hash)? else {
                return Err(CherryPickError::ParentNotACommit);
            };
            Some(parent_commit.tree_hash)
        }
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

        let r = cherry_pick(&s, target_commit, base_tree, None).unwrap();
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

        let r = cherry_pick(&s, target_commit, ours_tree, None).unwrap();
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
        let r = cherry_pick(&s, root_commit, ours_tree, None).unwrap();
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
        let r = cherry_pick(&s, target_commit, ours_tree, None).unwrap();
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
        let r = cherry_pick(&s, target_commit, base_tree, None).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 4);
    }

    #[test]
    fn non_commit_input_returns_error() {
        let (_d, s) = store();
        let blob_hash = put_blob(&s, b"just a blob");
        let empty_tree = make_tree(&s, vec![]);
        let err = cherry_pick(&s, blob_hash, empty_tree, None).unwrap_err();
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
        let r = cherry_pick(&s, root_commit, empty_tree, None).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 2);
    }

    /// Build a 2-parent merge commit. Parent 1 has `a.txt`, parent 2 has
    /// `b.txt`; the merge tree has both, plus `m.txt` unique to the merge.
    fn merge_fixture(s: &ObjectStore) -> (Hash, Hash, Hash) {
        let a = put_blob(s, b"a");
        let b = put_blob(s, b"b");
        let p1_tree = make_tree(s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let p2_tree = make_tree(s, vec![entry(b"b.txt", EntryMode::Blob, b)]);
        let p1 = make_commit(s, p1_tree, &[], "p1");
        let p2 = make_commit(s, p2_tree, &[], "p2");
        let m = put_blob(s, b"m");
        let merge_tree = make_tree(
            s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
                entry(b"m.txt", EntryMode::Blob, m),
            ],
        );
        let merge_commit = make_commit(s, merge_tree, &[p1, p2], "merge");
        (merge_commit, p1, p2)
    }

    #[test]
    fn merge_without_mainline_is_rejected() {
        let (_d, s) = store();
        let (merge_commit, _p1, _p2) = merge_fixture(&s);
        let empty = make_tree(&s, vec![]);
        let err = cherry_pick(&s, merge_commit, empty, None).unwrap_err();
        assert!(matches!(err, CherryPickError::MergeNeedsMainline));
    }

    #[test]
    fn mainline_on_non_merge_is_rejected() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let root = make_commit(&s, tree, &[], "root");
        let child = make_commit(&s, tree, &[root], "child");
        let empty = make_tree(&s, vec![]);
        let err = cherry_pick(&s, child, empty, Some(1)).unwrap_err();
        assert!(matches!(err, CherryPickError::MainlineForNonMerge));
    }

    #[test]
    fn out_of_range_mainline_is_rejected() {
        let (_d, s) = store();
        let (merge_commit, _p1, _p2) = merge_fixture(&s);
        let empty = make_tree(&s, vec![]);
        let err = cherry_pick(&s, merge_commit, empty, Some(3)).unwrap_err();
        assert!(matches!(
            err,
            CherryPickError::BadMainline {
                given: 3,
                parents: 2
            }
        ));
    }

    #[test]
    fn mainline_selects_the_chosen_parent_as_base() {
        // Picking the merge onto an empty tree with `-m 1` replays the merge's
        // diff against parent 1 (which has a.txt) → adds b.txt + m.txt; with
        // `-m 2` (parent has b.txt) → adds a.txt + m.txt. Different bases ⇒
        // different results, proving the mainline actually selects the parent.
        let (_d, s) = store();
        let (merge_commit, _p1, _p2) = merge_fixture(&s);
        let empty = make_tree(&s, vec![]);
        let r1 = cherry_pick(&s, merge_commit, empty, Some(1)).unwrap();
        let r2 = cherry_pick(&s, merge_commit, empty, Some(2)).unwrap();
        assert_ne!(
            r1.tree_hash, r2.tree_hash,
            "different mainline parents must yield different patches"
        );
    }
}
