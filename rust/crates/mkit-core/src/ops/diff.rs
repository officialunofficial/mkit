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

use std::fmt::Write as _;
use std::path::Path;

use crate::hash::Hash;
use crate::index::Index;
use crate::object::{EntryMode, Object, TreeEntry};
use crate::store::{MAX_TREE_DEPTH, ObjectStore, StoreError};
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
    diff_trees_inner(store, old_hash, new_hash, false)
}

fn diff_trees_inner(
    store: &ObjectStore,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
    ignore_regular_executable_mode: bool,
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
    diff_entries_recursive(
        store,
        &old_entries,
        &new_entries,
        "",
        &mut out,
        ignore_regular_executable_mode,
        0,
    )?;
    Ok(DiffResult { entries: out })
}

/// Lockstep walk of two name-sorted entry arrays.
fn diff_entries_recursive(
    store: &ObjectStore,
    old_entries: &[TreeEntry],
    new_entries: &[TreeEntry],
    prefix: &str,
    out: &mut Vec<DiffEntry>,
    ignore_regular_executable_mode: bool,
    depth: usize,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let mut i = 0usize;
    let mut j = 0usize;

    while i < old_entries.len() && j < new_entries.len() {
        let o = &old_entries[i];
        let n = &new_entries[j];
        match o.name.as_slice().cmp(n.name.as_slice()) {
            std::cmp::Ordering::Less => {
                add_removed_entries(store, o, prefix, out, depth)?;
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                add_added_entries(store, n, prefix, out, depth)?;
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if o.mode == EntryMode::Tree && n.mode == EntryMode::Tree {
                    if o.object_hash != n.object_hash {
                        let sub_prefix = join_path(prefix, &o.name);
                        let old_sub = load_tree(store, o.object_hash)?;
                        let new_sub = load_tree(store, n.object_hash)?;
                        diff_entries_recursive(
                            store,
                            &old_sub,
                            &new_sub,
                            &sub_prefix,
                            out,
                            ignore_regular_executable_mode,
                            depth + 1,
                        )?;
                    }
                    // identical subtree hashes -> nothing changed below
                } else if o.mode != n.mode && o.object_hash == n.object_hash {
                    if !ignore_regular_executable_mode || !regular_executable_pair(o.mode, n.mode) {
                        out.push(DiffEntry {
                            path: join_path(prefix, &o.name),
                            kind: DiffKind::ModeChanged,
                            old_hash: Some(o.object_hash),
                            new_hash: Some(n.object_hash),
                        });
                    }
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
        add_removed_entries(store, &old_entries[i], prefix, out, depth)?;
        i += 1;
    }
    while j < new_entries.len() {
        add_added_entries(store, &new_entries[j], prefix, out, depth)?;
        j += 1;
    }
    Ok(())
}

fn regular_executable_pair(a: EntryMode, b: EntryMode) -> bool {
    matches!(
        (a, b),
        (EntryMode::Blob, EntryMode::Executable) | (EntryMode::Executable, EntryMode::Blob)
    )
}

fn add_removed_entries(
    store: &ObjectStore,
    entry: &TreeEntry,
    prefix: &str,
    out: &mut Vec<DiffEntry>,
    depth: usize,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    if entry.mode == EntryMode::Tree {
        let sub_prefix = join_path(prefix, &entry.name);
        let sub = load_tree(store, entry.object_hash)?;
        for sub_entry in &sub {
            add_removed_entries(store, sub_entry, &sub_prefix, out, depth + 1)?;
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
    depth: usize,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    if entry.mode == EntryMode::Tree {
        let sub_prefix = join_path(prefix, &entry.name);
        let sub = load_tree(store, entry.object_hash)?;
        for sub_entry in &sub {
            add_added_entries(store, sub_entry, &sub_prefix, out, depth + 1)?;
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
// text_patch — line-based unified diff (for `mkit diff` hunks)
// =====================================================================

/// Number of unchanged context lines emitted on each side of a hunk.
const PATCH_CONTEXT: usize = 3;

/// Render a unified-diff patch between two byte blobs.
///
/// `old_path` / `new_path` are the `a/…` and `b/…` labels for the
/// `---`/`+++` headers (callers conventionally pass the same repo path
/// for both). The output is a Git-compatible unified diff:
///
/// ```text
/// --- a/<old_path>
/// +++ b/<new_path>
/// @@ -<l>,<n> +<l>,<n> @@
///  context
/// -removed
/// +added
/// ```
///
/// Either side that is not valid UTF-8 (a binary blob) yields a single
/// `Binary files a/<old> and b/<new> differ` line instead of hunks,
/// matching Git's behaviour — emitting markers into binary content
/// would be meaningless.
///
/// The algorithm is a straightforward longest-common-subsequence over
/// whole lines (not a full Myers diff): correct and deterministic, and
/// adequate for human-readable parity output. Trailing-newline handling
/// follows Git's `\ No newline at end of file` convention.
#[must_use]
pub fn text_patch(old_bytes: &[u8], new_bytes: &[u8], old_path: &str, new_path: &str) -> String {
    let (Ok(old_text), Ok(new_text)) = (
        std::str::from_utf8(old_bytes),
        std::str::from_utf8(new_bytes),
    ) else {
        return format!("Binary files a/{old_path} and b/{new_path} differ\n");
    };

    let old_lines = split_lines(old_text);
    let new_lines = split_lines(new_text);
    let ops = lcs_diff(&old_lines, &new_lines);

    let hunks = group_hunks(&ops, PATCH_CONTEXT);
    if hunks.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let _ = writeln!(out, "--- a/{old_path}");
    let _ = writeln!(out, "+++ b/{new_path}");
    for hunk in &hunks {
        render_hunk(&mut out, hunk, &old_lines, &new_lines);
    }
    out
}

/// Added / deleted line counts between two blobs, by the same whole-line
/// LCS the unified patch uses. `None` when either side is binary
/// (non-UTF-8) — `diff --stat` renders `Bin …` for those.
///
/// Used by `diff --stat`; kept here so the stat counts always agree with
/// the `+`/`-` lines `text_patch` would emit for the same blobs.
#[must_use]
pub fn diff_line_counts(old_bytes: &[u8], new_bytes: &[u8]) -> Option<(usize, usize)> {
    let (Ok(old_text), Ok(new_text)) = (
        std::str::from_utf8(old_bytes),
        std::str::from_utf8(new_bytes),
    ) else {
        return None;
    };
    let old_lines = split_lines(old_text);
    let new_lines = split_lines(new_text);
    let mut added = 0;
    let mut deleted = 0;
    for op in lcs_diff(&old_lines, &new_lines) {
        match op {
            DiffOp::Insert(_) => added += 1,
            DiffOp::Delete(_) => deleted += 1,
            DiffOp::Equal(_, _) => {}
        }
    }
    Some((added, deleted))
}

/// A single line plus whether the source had a trailing newline after it.
struct DiffLine<'a> {
    text: &'a str,
    /// `true` when this line was terminated by `\n` in the source.
    has_newline: bool,
}

/// Split text into lines, preserving whether the final line had a
/// trailing newline. An empty input yields no lines.
fn split_lines(text: &str) -> Vec<DiffLine<'_>> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(idx) = rest.find('\n') {
            lines.push(DiffLine {
                text: &rest[..idx],
                has_newline: true,
            });
            rest = &rest[idx + 1..];
        } else {
            lines.push(DiffLine {
                text: rest,
                has_newline: false,
            });
            rest = "";
        }
    }
    lines
}

/// One element of a line-level edit script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp {
    /// Line present in both sides (indices into old, new).
    Equal(usize, usize),
    /// Line only in the old side (index into old).
    Delete(usize),
    /// Line only in the new side (index into new).
    Insert(usize),
}

/// Compute a line-level edit script via classic LCS dynamic programming.
fn lcs_diff(old: &[DiffLine<'_>], new: &[DiffLine<'_>]) -> Vec<DiffOp> {
    let n = old.len();
    let m = new.len();
    // dp[i][j] = LCS length of old[i..] and new[j..].
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if lines_equal(&old[i], &new[j]) {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }

    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if lines_equal(&old[i], &new[j]) {
            ops.push(DiffOp::Equal(i, j));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(DiffOp::Delete(i));
            i += 1;
        } else {
            ops.push(DiffOp::Insert(j));
            j += 1;
        }
    }
    while i < n {
        ops.push(DiffOp::Delete(i));
        i += 1;
    }
    while j < m {
        ops.push(DiffOp::Insert(j));
        j += 1;
    }
    ops
}

fn lines_equal(a: &DiffLine<'_>, b: &DiffLine<'_>) -> bool {
    a.text == b.text && a.has_newline == b.has_newline
}

/// A contiguous group of edits plus surrounding context, with the
/// 1-based starting line numbers and lengths for the `@@` header.
struct Hunk {
    old_start: usize,
    old_len: usize,
    new_start: usize,
    new_len: usize,
    ops: Vec<DiffOp>,
}

/// Group an edit script into hunks, each padded with up to `context`
/// unchanged lines and merged when their context windows touch.
fn group_hunks(ops: &[DiffOp], context: usize) -> Vec<Hunk> {
    // Indices of ops that are actual changes.
    let change_positions: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, DiffOp::Equal(_, _)))
        .map(|(idx, _)| idx)
        .collect();
    if change_positions.is_empty() {
        return Vec::new();
    }

    // Build [start,end) op-index ranges around each change, merging
    // ranges whose context windows overlap or abut.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &pos in &change_positions {
        let start = pos.saturating_sub(context);
        let end = (pos + context + 1).min(ops.len());
        match ranges.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => ranges.push((start, end)),
        }
    }

    ranges
        .into_iter()
        .map(|(start, end)| build_hunk(&ops[start..end]))
        .collect()
}

fn build_hunk(slice: &[DiffOp]) -> Hunk {
    let mut old_start = None;
    let mut new_start = None;
    let mut old_len = 0usize;
    let mut new_len = 0usize;
    for op in slice {
        match *op {
            DiffOp::Equal(oi, ni) => {
                old_start.get_or_insert(oi);
                new_start.get_or_insert(ni);
                old_len += 1;
                new_len += 1;
            }
            DiffOp::Delete(oi) => {
                old_start.get_or_insert(oi);
                old_len += 1;
            }
            DiffOp::Insert(ni) => {
                new_start.get_or_insert(ni);
                new_len += 1;
            }
        }
    }
    Hunk {
        // Convert 0-based to 1-based; empty side starts at 0.
        old_start: old_start.map_or(0, |s| s + 1),
        old_len,
        new_start: new_start.map_or(0, |s| s + 1),
        new_len,
        ops: slice.to_vec(),
    }
}

fn render_hunk(out: &mut String, hunk: &Hunk, old: &[DiffLine<'_>], new: &[DiffLine<'_>]) {
    let _ = writeln!(
        out,
        "@@ -{},{} +{},{} @@",
        hunk.old_start, hunk.old_len, hunk.new_start, hunk.new_len
    );
    for op in &hunk.ops {
        match *op {
            DiffOp::Equal(oi, _) => emit_line(out, ' ', &old[oi]),
            DiffOp::Delete(oi) => emit_line(out, '-', &old[oi]),
            DiffOp::Insert(ni) => emit_line(out, '+', &new[ni]),
        }
    }
}

fn emit_line(out: &mut String, prefix: char, line: &DiffLine<'_>) {
    out.push(prefix);
    out.push_str(line.text);
    out.push('\n');
    if !line.has_newline {
        out.push_str("\\ No newline at end of file\n");
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

/// Compare HEAD ↔ index and index ↔ worktree, returning a list of
/// [`StatusEntry`] grouped by staging state.
///
/// Pre-#102 this function diffed only HEAD↔worktree and annotated
/// each entry with index-state. That hid one hazard: a path staged
/// to the index whose worktree was later reverted to match HEAD
/// would diff to nothing — but `mkit commit` (which signs HEAD↔
/// index post-#102) would still commit the staged content. The
/// staged change was invisible to `mkit status`.
///
/// New shape:
///
/// - `Staged` — path differs between HEAD and the index-built tree
///   (the change is what `mkit commit` will sign).
/// - `Unstaged` — path differs between the index-built tree and the
///   worktree (changes the user has not yet `mkit add`-ed).
/// - When the same path appears in both legs (e.g. staged v2, then
///   worktree edited to v3), one entry is emitted per leg so callers
///   render both sections — matching git's two-section layout. The
///   `PartiallyStaged` enum variant is retained for back-compat but
///   no longer produced by this function.
///
/// When `index` is `None`, falls back to the legacy HEAD↔worktree
/// diff and labels every entry `Unstaged` — used by callers that
/// haven't initialized a staging index yet.
///
/// # Errors
///
/// Propagates [`WorktreeError`] (I/O, symlink validation, chunker
/// limit) and [`StoreError`] (missing or corrupt objects).
#[allow(clippy::too_many_lines)]
pub fn status_diff(
    store: &ObjectStore,
    head_tree: Option<&Hash>,
    worktree_root: &Path,
    index: Option<&Index>,
) -> Result<Vec<StatusEntry>, DiffError> {
    // Always snapshot the worktree — the index↔worktree leg uses it.
    let work_tree_hash = worktree::build_tree(store, worktree_root)?;

    let Some(idx) = index else {
        // Legacy fallback: HEAD↔worktree, everything labeled Unstaged.
        let diff = diff_worktree_trees(store, head_tree.copied(), Some(work_tree_hash))?;
        return Ok(diff
            .entries
            .into_iter()
            .map(|d| StatusEntry {
                diff: d,
                staging: StatusStaging::Unstaged,
            })
            .collect());
    };

    // Build the index tree exactly the way `mkit commit` builds it.
    // This is the authoritative "what would be committed right now."
    let index_tree = worktree::build_tree_from_index(store, idx)?;

    let staged = diff_trees(store, head_tree.copied(), Some(index_tree))?;
    let unstaged = diff_worktree_trees(store, Some(index_tree), Some(work_tree_hash))?;

    // Emit one entry per (path, leg). A path appearing in both legs
    // produces two entries — one `Staged` and one `Unstaged` — so the
    // status renderer shows it under BOTH "Changes to be committed"
    // and "Changes not staged for commit", matching git's two-section
    // layout. The `PartiallyStaged` enum variant is retained for API
    // back-compat but no longer produced.
    let mut out: Vec<StatusEntry> =
        Vec::with_capacity(staged.entries.len() + unstaged.entries.len());
    for d in staged.entries {
        out.push(StatusEntry {
            diff: d,
            staging: StatusStaging::Staged,
        });
    }
    for d in unstaged.entries {
        out.push(StatusEntry {
            diff: d,
            staging: StatusStaging::Unstaged,
        });
    }
    out.sort_by(|a, b| {
        // Stable rendering order: by path, then staged before unstaged.
        a.diff.path.cmp(&b.diff.path).then_with(|| {
            #[allow(clippy::match_same_arms)]
            match (a.staging, b.staging) {
                (StatusStaging::Staged, StatusStaging::Staged) => std::cmp::Ordering::Equal,
                (StatusStaging::Staged, _) => std::cmp::Ordering::Less,
                (_, StatusStaging::Staged) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        })
    });
    Ok(out)
}

#[cfg(unix)]
fn diff_worktree_trees(
    store: &ObjectStore,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
) -> Result<DiffResult, StoreError> {
    diff_trees(store, old_hash, new_hash)
}

#[cfg(not(unix))]
fn diff_worktree_trees(
    store: &ObjectStore,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
) -> Result<DiffResult, StoreError> {
    diff_trees_inner(store, old_hash, new_hash, true)
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

    #[cfg(not(unix))]
    #[test]
    fn status_no_index_ignores_unrepresentable_executable_mode_on_non_unix() {
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("run.sh"), b"#!/bin/sh\n").unwrap();
        let h = worktree::hash_file(&store, &work.path().join("run.sh")).unwrap();
        let head_hash = put_tree(&store, vec![entry(b"run.sh", EntryMode::Executable, h)]);

        let result = status_diff(&store, Some(&head_hash), work.path(), None).unwrap();
        assert!(
            result.is_empty(),
            "non-Unix should not report executable-only noise, got {result:?}"
        );
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

    /// HEAD is empty; index has b.txt; worktree has b.txt with the
    /// same content. The HEAD↔index leg picks up b.txt as Added
    /// (Staged); the index↔worktree leg sees no delta. Single Staged
    /// entry.
    #[test]
    fn status_staged_entry_is_classified_staged() {
        use crate::index::{EntryStatus, Index, IndexEntry};
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("b.txt"), b"world").unwrap();
        let b_hash = worktree::hash_file(&store, &work.path().join("b.txt")).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "b.txt".to_string(),
            status: EntryStatus::Blob,
            object_hash: b_hash,
        });
        // No HEAD — first commit scenario.
        let result = status_diff(&store, None, work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].diff.path, "b.txt");
        assert_eq!(result[0].staging, StatusStaging::Staged);
    }

    #[cfg(not(unix))]
    #[test]
    fn status_ignores_unrepresentable_executable_mode_on_non_unix_worktree() {
        use crate::index::{EntryStatus, Index, IndexEntry};

        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("run.sh"), b"#!/bin/sh\n").unwrap();
        let h = worktree::hash_file(&store, &work.path().join("run.sh")).unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "run.sh".to_string(),
            status: EntryStatus::Executable,
            object_hash: h,
        });

        let result = status_diff(&store, None, work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 1, "expected only the staged addition");
        assert_eq!(result[0].staging, StatusStaging::Staged);
    }

    // -----------------------------------------------------------------
    // text_patch unit tests
    // -----------------------------------------------------------------

    #[test]
    fn text_patch_modified_line_emits_hunk() {
        let old = b"line1\nline2\nline3\n";
        let new = b"line1\nCHANGED\nline3\n";
        let patch = text_patch(old, new, "f.txt", "f.txt");
        assert!(patch.starts_with("--- a/f.txt\n+++ b/f.txt\n"), "{patch}");
        assert!(patch.contains("@@ -1,3 +1,3 @@"), "{patch}");
        assert!(patch.contains("-line2\n"), "{patch}");
        assert!(patch.contains("+CHANGED\n"), "{patch}");
        assert!(patch.contains(" line1\n"), "{patch}");
        assert!(patch.contains(" line3\n"), "{patch}");
    }

    #[test]
    fn text_patch_pure_addition() {
        let old = b"a\nb\n";
        let new = b"a\nb\nc\n";
        let patch = text_patch(old, new, "f", "f");
        assert!(patch.contains("+c\n"), "{patch}");
        // No deletion lines in the hunk body (the `---` header aside).
        assert!(
            !patch
                .lines()
                .any(|l| l.starts_with('-') && !l.starts_with("---")),
            "should be no deletions: {patch}"
        );
    }

    #[test]
    fn text_patch_identical_is_empty() {
        let patch = text_patch(b"same\n", b"same\n", "f", "f");
        assert!(patch.is_empty(), "{patch}");
    }

    #[test]
    fn text_patch_binary_reports_differ() {
        let old = &[0x00, 0xff, 0x01][..];
        let new = &[0x00, 0xfe, 0x02][..];
        let patch = text_patch(old, new, "bin", "bin");
        assert_eq!(patch, "Binary files a/bin and b/bin differ\n");
    }

    #[test]
    fn text_patch_no_trailing_newline_marker() {
        let old = b"x\ny";
        let new = b"x\nz";
        let patch = text_patch(old, new, "f", "f");
        assert!(patch.contains("\\ No newline at end of file\n"), "{patch}");
    }

    #[test]
    fn text_patch_separate_hunks_for_distant_changes() {
        let old = b"a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n";
        // Change line 1 and line 10; far enough apart for two hunks.
        let new = b"A\nb\nc\nd\ne\nf\ng\nh\ni\nJ\n";
        let patch = text_patch(old, new, "f", "f");
        let hunk_count = patch.matches("@@ ").count();
        assert_eq!(hunk_count, 2, "expected two hunks: {patch}");
    }

    /// HEAD empty; index has b.txt at v1; worktree has b.txt at v2.
    /// The HEAD↔index leg yields one Added (Staged) entry; the
    /// index↔worktree leg yields one Modified (Unstaged) entry. Same
    /// path appears in both sections — git's two-section layout.
    /// Pre-fix this collapsed to a single `PartiallyStaged` entry
    /// which hid the staged-vs-worktree distinction.
    #[test]
    fn status_partially_staged_entry_emits_both_legs() {
        use crate::index::{EntryStatus, Index, IndexEntry};
        let (_sd, store) = fresh_store();
        let work = fresh_workdir();
        // Write v1, hash it, then overwrite with v2.
        std::fs::write(work.path().join("b.txt"), b"v1").unwrap();
        let b_v1_hash = worktree::hash_file(&store, &work.path().join("b.txt")).unwrap();
        std::fs::write(work.path().join("b.txt"), b"v2").unwrap();
        let mut idx = Index::new();
        idx.entries.push(IndexEntry {
            path: "b.txt".to_string(),
            status: EntryStatus::Blob,
            object_hash: b_v1_hash,
        });
        let result = status_diff(&store, None, work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 2, "expected staged + unstaged entries");
        let stagings: Vec<_> = result.iter().map(|e| e.staging).collect();
        assert!(stagings.contains(&StatusStaging::Staged));
        assert!(stagings.contains(&StatusStaging::Unstaged));
        assert!(result.iter().all(|e| e.diff.path == "b.txt"));
    }
}
