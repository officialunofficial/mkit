//! Tree-level structural diff.
//!
//! Compares two trees identified by their object hash and returns the
//! minimal list of leaf-level changes (`added` / `removed` / `modified`
//! / `mode_changed`). The walk is lockstep over the two sorted entry
//! arrays, recurses into matching subtrees only when their hashes
//! differ, and treats added/removed subtrees as bulk operations on every
//! contained leaf.
//!
//! Also contains `status_diff` — the working-tree vs HEAD diff that
//! powers `mkit status`.

use std::path::Path;

use crate::hash::Hash;
use crate::index::Index;
use crate::object::{EntryMode, Object, TreeEntry};
use crate::store::{ObjectStore, StoreError};
use crate::worktree::{self, WorktreeError};

/// What kind of change a [`DiffEntry`] represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiffKind {
    /// Path was not present in the old tree, present in the new.
    Added,
    /// Path was present in the old tree, absent in the new.
    Removed,
    /// Same path, different content hash (and possibly different mode).
    Modified,
    /// Same path, same content hash, different [`EntryMode`].
    ModeChanged,
}

/// One leaf-level change. `path` is `/`-joined relative to the root
/// of the compared trees; subtree directories are NOT emitted as their
/// own entries — only the leaves they contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub path: String,
    pub kind: DiffKind,
    pub old_hash: Option<Hash>,
    pub new_hash: Option<Hash>,
}

/// Sorted (by path) sequence of [`DiffEntry`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffResult {
    pub entries: Vec<DiffEntry>,
}

impl DiffResult {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Compare two trees and return their [`DiffResult`]. `None` for either
/// hash represents the empty tree (use cases: comparing against the
/// initial commit, against a rolled-back state).
///
/// # Errors
///
/// Propagates [`StoreError`] when an expected tree object is missing or
/// fails its read-time hash check.
pub fn diff_trees(
    store: &ObjectStore,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
) -> Result<DiffResult, StoreError> {
    // Trivial cases: both empty, or identical hashes -> empty diff.
    match (old_hash, new_hash) {
        (None, None) => return Ok(DiffResult::default()),
        (Some(a), Some(b)) if a == b => return Ok(DiffResult::default()),
        _ => {}
    }

    let old_entries = load_entries(store, old_hash)?;
    let new_entries = load_entries(store, new_hash)?;

    let mut out: Vec<DiffEntry> = Vec::new();
    diff_entries_recursive(store, &old_entries, &new_entries, "", &mut out)?;
    Ok(DiffResult { entries: out })
}

/// Lockstep walk of two name-sorted entry arrays.
fn diff_entries_recursive(
    store: &ObjectStore,
    old_entries: &[TreeEntry],
    new_entries: &[TreeEntry],
    prefix: &str,
    out: &mut Vec<DiffEntry>,
) -> Result<(), StoreError> {
    let mut i = 0usize;
    let mut j = 0usize;

    while i < old_entries.len() && j < new_entries.len() {
        let o = &old_entries[i];
        let n = &new_entries[j];
        match o.name.as_slice().cmp(n.name.as_slice()) {
            std::cmp::Ordering::Less => {
                add_removed_entries(store, o, prefix, out)?;
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                add_added_entries(store, n, prefix, out)?;
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if o.mode == EntryMode::Tree && n.mode == EntryMode::Tree {
                    if o.object_hash != n.object_hash {
                        let sub_prefix = join_path(prefix, &o.name);
                        let old_sub = load_tree(store, o.object_hash)?;
                        let new_sub = load_tree(store, n.object_hash)?;
                        diff_entries_recursive(store, &old_sub, &new_sub, &sub_prefix, out)?;
                    }
                    // identical subtree hashes -> nothing changed below
                } else if o.mode != n.mode && o.object_hash == n.object_hash {
                    out.push(DiffEntry {
                        path: join_path(prefix, &o.name),
                        kind: DiffKind::ModeChanged,
                        old_hash: Some(o.object_hash),
                        new_hash: Some(n.object_hash),
                    });
                } else if o.object_hash != n.object_hash || o.mode != n.mode {
                    out.push(DiffEntry {
                        path: join_path(prefix, &o.name),
                        kind: DiffKind::Modified,
                        old_hash: Some(o.object_hash),
                        new_hash: Some(n.object_hash),
                    });
                }
                i += 1;
                j += 1;
            }
        }
    }

    while i < old_entries.len() {
        add_removed_entries(store, &old_entries[i], prefix, out)?;
        i += 1;
    }
    while j < new_entries.len() {
        add_added_entries(store, &new_entries[j], prefix, out)?;
        j += 1;
    }
    Ok(())
}

fn add_removed_entries(
    store: &ObjectStore,
    entry: &TreeEntry,
    prefix: &str,
    out: &mut Vec<DiffEntry>,
) -> Result<(), StoreError> {
    if entry.mode == EntryMode::Tree {
        let sub_prefix = join_path(prefix, &entry.name);
        let sub = load_tree(store, entry.object_hash)?;
        for sub_entry in &sub {
            add_removed_entries(store, sub_entry, &sub_prefix, out)?;
        }
    } else {
        out.push(DiffEntry {
            path: join_path(prefix, &entry.name),
            kind: DiffKind::Removed,
            old_hash: Some(entry.object_hash),
            new_hash: None,
        });
    }
    Ok(())
}

fn add_added_entries(
    store: &ObjectStore,
    entry: &TreeEntry,
    prefix: &str,
    out: &mut Vec<DiffEntry>,
) -> Result<(), StoreError> {
    if entry.mode == EntryMode::Tree {
        let sub_prefix = join_path(prefix, &entry.name);
        let sub = load_tree(store, entry.object_hash)?;
        for sub_entry in &sub {
            add_added_entries(store, sub_entry, &sub_prefix, out)?;
        }
    } else {
        out.push(DiffEntry {
            path: join_path(prefix, &entry.name),
            kind: DiffKind::Added,
            old_hash: None,
            new_hash: Some(entry.object_hash),
        });
    }
    Ok(())
}

fn load_entries(store: &ObjectStore, hash: Option<Hash>) -> Result<Vec<TreeEntry>, StoreError> {
    match hash {
        Some(h) => load_tree(store, h),
        None => Ok(Vec::new()),
    }
}

fn load_tree(store: &ObjectStore, h: Hash) -> Result<Vec<TreeEntry>, StoreError> {
    match store.read_object(&h)? {
        Object::Tree(t) => Ok(t.entries),
        other => Err(StoreError::Decode(
            crate::object::MkitError::InvalidObjectType(other.object_type() as u8),
        )),
    }
}

/// Join a path prefix and an entry name with `/`. Lossy on non-UTF-8
/// names: we use `String` rather than `Path` to avoid platform-specific
/// separator handling. Tree names are constrained at the object layer
/// to forbid `/` and `\\`, so the only lossy case is non-UTF-8 byte
/// sequences in legacy data — the caller's `path` field will then be
/// `String::from_utf8_lossy`'s replacement, which is acceptable for a
/// diagnostic.
fn join_path(prefix: &str, name: &[u8]) -> String {
    let name_str = String::from_utf8_lossy(name);
    if prefix.is_empty() {
        name_str.into_owned()
    } else {
        let mut s = String::with_capacity(prefix.len() + 1 + name_str.len());
        s.push_str(prefix);
        s.push('/');
        s.push_str(&name_str);
        s
    }
}

// =====================================================================
// status_diff — working-tree vs HEAD (for `mkit status`)
// =====================================================================

/// Staging state of a [`StatusEntry`] relative to the index.
///
/// When no index is passed to [`status_diff`], every entry has
/// `StatusStaging::Unstaged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusStaging {
    /// Change is not staged (worktree differs from HEAD, not in index).
    Unstaged,
    /// Change is staged (in the index, matching the worktree).
    Staged,
    /// Change exists in both index and worktree with different content
    /// (partially staged scenario).
    PartiallyStaged,
}

/// One entry in the `mkit status` output. Combines a [`DiffEntry`] with
/// index-awareness so the caller can render three-way status output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    /// Underlying diff entry (path, kind, old/new hashes).
    pub diff: DiffEntry,
    /// Relationship of this entry to the staging index.
    pub staging: StatusStaging,
}

/// Error type for [`status_diff`].
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    /// Underlying object-store error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Error building the worktree snapshot.
    #[error(transparent)]
    Worktree(#[from] WorktreeError),
}

/// Compare the working tree against `head_tree` and return a list of
/// [`StatusEntry`] annotated with index staging state.
///
/// - Builds a temporary tree from `worktree_root` via
///   [`worktree::build_tree`].
/// - Diffs it against `head_tree` via [`diff_trees`].
/// - If `index` is supplied, each entry is classified as `Staged`,
///   `Unstaged`, or `PartiallyStaged` by checking whether the index
///   contains the path and whether the index hash matches the worktree
///   hash.
///
/// # Errors
///
/// Propagates [`WorktreeError`] (I/O, symlink validation, chunker
/// limit) and [`StoreError`] (missing or corrupt objects).
pub fn status_diff(
    store: &ObjectStore,
    head_tree: Option<&Hash>,
    worktree_root: &Path,
    index: Option<&Index>,
) -> Result<Vec<StatusEntry>, DiffError> {
    // Snapshot the working directory into the object store.
    let work_tree_hash = worktree::build_tree(store, worktree_root)?;

    // Tree-vs-tree diff: HEAD vs worktree snapshot.
    let diff = diff_trees(store, head_tree.copied(), Some(work_tree_hash))?;

    // Annotate each entry with its staging state.
    let entries = diff
        .entries
        .into_iter()
        .map(|entry| {
            let staging = if let Some(idx) = index {
                classify_staging(&entry, idx)
            } else {
                StatusStaging::Unstaged
            };
            StatusEntry {
                diff: entry,
                staging,
            }
        })
        .collect();

    Ok(entries)
}

/// Determine the [`StatusStaging`] for a single diff entry by
/// inspecting the index.
///
/// Rules (mirror Git's logic for a two-area model):
///
/// 1. If the path is not in the index at all → `Unstaged`.
/// 2. If the path is in the index and the index hash matches the
///    worktree `new_hash` → `Staged` (the worktree change was staged).
/// 3. If the path is in the index but the index hash differs from the
///    worktree `new_hash` → `PartiallyStaged` (staged something, but
///    the worktree has additional changes).
fn classify_staging(entry: &DiffEntry, index: &Index) -> StatusStaging {
    let Some(idx_pos) = index.find_entry(&entry.path) else {
        return StatusStaging::Unstaged;
    };
    let idx_entry = &index.entries[idx_pos];
    // For a removed entry the worktree new_hash is None. If the index
    // still has the file (non-zero hash) it is not staged for removal.
    match entry.new_hash {
        Some(wt_hash) => {
            if idx_entry.object_hash == wt_hash {
                StatusStaging::Staged
            } else {
                StatusStaging::PartiallyStaged
            }
        }
        None => {
            // Worktree deletion. If index has a zero hash for this path
            // the deletion was staged; otherwise it is unstaged.
            if idx_entry.object_hash == [0u8; crate::hash::HASH_LEN] {
                StatusStaging::Staged
            } else {
                StatusStaging::PartiallyStaged
            }
        }
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter blob/entry names keep the tables compact
mod tests {
    use super::*;
    use crate::object::{Blob, Tree};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let obj = Object::Blob(Blob {
            data: data.to_vec(),
        });
        let bytes = serialize::serialize(&obj).unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_tree(store: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let obj = Object::Tree(Tree { entries });
        let bytes = serialize::serialize(&obj).unwrap();
        store.write(&bytes).unwrap()
    }

    fn entry(name: &[u8], mode: EntryMode, h: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: h,
        }
    }

    #[test]
    fn identical_trees_no_diff() {
        let (_d, s) = fresh_store();
        let blob = put_blob(&s, b"content");
        let tree = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob)]);
        let result = diff_trees(&s, Some(tree), Some(tree)).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn added_file_detected() {
        let (_d, s) = fresh_store();
        let blob_a = put_blob(&s, b"aaa");
        let blob_b = put_blob(&s, b"bbb");
        let old = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let new = put_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let r = diff_trees(&s, Some(old), Some(new)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path, "b.txt");
        assert_eq!(r.entries[0].kind, DiffKind::Added);
        assert_eq!(r.entries[0].old_hash, None);
        assert_eq!(r.entries[0].new_hash, Some(blob_b));
    }

    #[test]
    fn removed_file_detected() {
        let (_d, s) = fresh_store();
        let blob_a = put_blob(&s, b"aaa");
        let blob_b = put_blob(&s, b"bbb");
        let old = put_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let new = put_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let r = diff_trees(&s, Some(old), Some(new)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path, "b.txt");
        assert_eq!(r.entries[0].kind, DiffKind::Removed);
        assert_eq!(r.entries[0].old_hash, Some(blob_b));
        assert_eq!(r.entries[0].new_hash, None);
    }

    #[test]
    fn modified_file_detected() {
        let (_d, s) = fresh_store();
        let v1 = put_blob(&s, b"version 1");
        let v2 = put_blob(&s, b"version 2");
        let old = put_tree(&s, vec![entry(b"file.txt", EntryMode::Blob, v1)]);
        let new = put_tree(&s, vec![entry(b"file.txt", EntryMode::Blob, v2)]);
        let r = diff_trees(&s, Some(old), Some(new)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path, "file.txt");
        assert_eq!(r.entries[0].kind, DiffKind::Modified);
        assert_eq!(r.entries[0].old_hash, Some(v1));
        assert_eq!(r.entries[0].new_hash, Some(v2));
    }

    #[test]
    fn mode_change_detected() {
        let (_d, s) = fresh_store();
        let blob = put_blob(&s, b"content");
        let old = put_tree(&s, vec![entry(b"link", EntryMode::Blob, blob)]);
        let new = put_tree(&s, vec![entry(b"link", EntryMode::Symlink, blob)]);
        let r = diff_trees(&s, Some(old), Some(new)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path, "link");
        assert_eq!(r.entries[0].kind, DiffKind::ModeChanged);
        assert_eq!(r.entries[0].old_hash, Some(blob));
        assert_eq!(r.entries[0].new_hash, Some(blob));
    }

    #[test]
    fn nested_tree_diff() {
        let (_d, s) = fresh_store();
        let v1 = put_blob(&s, b"old content");
        let v2 = put_blob(&s, b"new content");
        let other = put_blob(&s, b"unchanged");
        let old_sub = put_tree(
            &s,
            vec![
                entry(b"file.txt", EntryMode::Blob, v1),
                entry(b"other.txt", EntryMode::Blob, other),
            ],
        );
        let new_sub = put_tree(
            &s,
            vec![
                entry(b"file.txt", EntryMode::Blob, v2),
                entry(b"other.txt", EntryMode::Blob, other),
            ],
        );
        let old_root = put_tree(&s, vec![entry(b"subdir", EntryMode::Tree, old_sub)]);
        let new_root = put_tree(&s, vec![entry(b"subdir", EntryMode::Tree, new_sub)]);
        let r = diff_trees(&s, Some(old_root), Some(new_root)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path, "subdir/file.txt");
        assert_eq!(r.entries[0].kind, DiffKind::Modified);
    }

    #[test]
    fn diff_against_empty_tree() {
        let (_d, s) = fresh_store();
        let blob_a = put_blob(&s, b"aaa");
        let blob_b = put_blob(&s, b"bbb");
        let new = put_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let r = diff_trees(&s, None, Some(new)).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].path, "a.txt");
        assert_eq!(r.entries[0].kind, DiffKind::Added);
        assert_eq!(r.entries[1].path, "b.txt");
        assert_eq!(r.entries[1].kind, DiffKind::Added);
    }

    #[test]
    fn empty_tree_against_non_empty() {
        let (_d, s) = fresh_store();
        let blob_a = put_blob(&s, b"aaa");
        let blob_b = put_blob(&s, b"bbb");
        let old = put_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, blob_a),
                entry(b"b.txt", EntryMode::Blob, blob_b),
            ],
        );
        let r = diff_trees(&s, Some(old), None).unwrap();
        assert_eq!(r.entries.len(), 2);
        assert_eq!(r.entries[0].kind, DiffKind::Removed);
        assert_eq!(r.entries[1].kind, DiffKind::Removed);
    }

    #[test]
    fn sorted_output() {
        let (_d, s) = fresh_store();
        let a = put_blob(&s, b"a");
        let b = put_blob(&s, b"b");
        let c = put_blob(&s, b"c");
        let new = put_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"m.txt", EntryMode::Blob, b),
                entry(b"z.txt", EntryMode::Blob, c),
            ],
        );
        let r = diff_trees(&s, None, Some(new)).unwrap();
        assert_eq!(r.entries.len(), 3);
        assert_eq!(r.entries[0].path, "a.txt");
        assert_eq!(r.entries[1].path, "m.txt");
        assert_eq!(r.entries[2].path, "z.txt");
    }

    #[test]
    fn max_length_entry_names() {
        let (_d, s) = fresh_store();
        let blob = put_blob(&s, b"data");
        let long_name = vec![b'A'; 255];
        let new = put_tree(&s, vec![entry(&long_name, EntryMode::Blob, blob)]);
        let r = diff_trees(&s, None, Some(new)).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries[0].path.len(), 255);
        assert_eq!(r.entries[0].kind, DiffKind::Added);
    }

    #[test]
    fn both_none_is_empty() {
        let (_d, s) = fresh_store();
        let r = diff_trees(&s, None, None).unwrap();
        assert!(r.is_empty());
    }

    // -----------------------------------------------------------------
    // status_diff unit tests
    // -----------------------------------------------------------------

    fn fresh_workdir() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn status_empty_worktree_no_head() {
        // Empty worktree, no HEAD → nothing to report.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        let result = status_diff(&store, None, work.path(), None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn status_worktree_equals_head_is_clean() {
        // Worktree identical to HEAD → no changes.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"hello").unwrap();
        // Build a tree from the worktree and use it as HEAD.
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert!(result.is_empty(), "expected clean, got {result:?}");
    }

    #[test]
    fn status_added_only() {
        // HEAD has {a.txt}; worktree has {a.txt, b.txt} → b.txt added.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"hello").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        std::fs::write(work.path().join("b.txt"), b"world").unwrap();
        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "b.txt");
        assert_eq!(result[0].diff.kind, DiffKind::Added);
        assert_eq!(result[0].staging, StatusStaging::Unstaged);
    }

    #[test]
    fn status_removed_only() {
        // HEAD has {a.txt, b.txt}; worktree has only {a.txt} → b.txt removed.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(work.path().join("b.txt"), b"world").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        std::fs::remove_file(work.path().join("b.txt")).unwrap();
        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "b.txt");
        assert_eq!(result[0].diff.kind, DiffKind::Removed);
        assert_eq!(result[0].staging, StatusStaging::Unstaged);
    }

    #[test]
    fn status_modified_only() {
        // HEAD has {a.txt="old"}; worktree has {a.txt="new"} → a.txt modified.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"old").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        std::fs::write(work.path().join("a.txt"), b"new").unwrap();
        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "a.txt");
        assert_eq!(result[0].diff.kind, DiffKind::Modified);
        assert_eq!(result[0].staging, StatusStaging::Unstaged);
    }

    #[test]
    fn status_mixed_changes() {
        // HEAD: {a.txt, b.txt}. Worktree: a.txt modified, b.txt removed, c.txt added.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"original").unwrap();
        std::fs::write(work.path().join("b.txt"), b"stays").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        std::fs::write(work.path().join("a.txt"), b"changed").unwrap();
        std::fs::remove_file(work.path().join("b.txt")).unwrap();
        std::fs::write(work.path().join("c.txt"), b"new").unwrap();
        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert_eq!(result.len(), 3);
        let paths: Vec<&str> = result.iter().map(|e| e.diff.path.as_str()).collect();
        assert!(paths.contains(&"a.txt"), "missing a.txt: {paths:?}");
        assert!(paths.contains(&"b.txt"), "missing b.txt: {paths:?}");
        assert!(paths.contains(&"c.txt"), "missing c.txt: {paths:?}");
    }

    #[test]
    fn status_no_head_shows_all_as_added() {
        // No HEAD (initial repo state) → every file shows as added.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(work.path().join("b.txt"), b"bbb").unwrap();
        let result = status_diff(&store, None, work.path(), None).unwrap();
        assert_eq!(result.len(), 2);
        for e in &result {
            assert_eq!(e.diff.kind, DiffKind::Added);
            assert_eq!(e.staging, StatusStaging::Unstaged);
        }
    }

    #[test]
    fn status_staged_entry_is_classified_staged() {
        use crate::index::{EntryStatus, Index, IndexEntry};
        // Worktree adds b.txt; index already has b.txt with the same hash.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"old").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        std::fs::write(work.path().join("b.txt"), b"world").unwrap();
        // Hash b.txt to the store so we can populate the index.
        let b_hash = worktree::hash_file(&store, &work.path().join("b.txt")).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "b.txt".to_string(),
            status: EntryStatus::Blob,
            object_hash: b_hash,
        });
        let result = status_diff(&store, Some(&head_hash), work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "b.txt");
        assert_eq!(result[0].staging, StatusStaging::Staged);
    }

    #[test]
    fn status_partially_staged_entry() {
        use crate::index::{EntryStatus, Index, IndexEntry};
        // Worktree has b.txt="v2"; index has b.txt hashed at "v1" content.
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"old").unwrap();
        let head_hash = worktree::build_tree(&store, work.path()).unwrap();
        // Write v1 to disk, hash it, then overwrite with v2.
        std::fs::write(work.path().join("b.txt"), b"v1").unwrap();
        let b_v1_hash = worktree::hash_file(&store, &work.path().join("b.txt")).unwrap();
        std::fs::write(work.path().join("b.txt"), b"v2").unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "b.txt".to_string(),
            status: EntryStatus::Blob,
            object_hash: b_v1_hash,
        });
        let result = status_diff(&store, Some(&head_hash), work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "b.txt");
        assert_eq!(result[0].staging, StatusStaging::PartiallyStaged);
    }
}
