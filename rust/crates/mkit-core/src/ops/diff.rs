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
use crate::index::{Index, IndexError};
use crate::object::{EntryMode, Object, TreeEntry};
use crate::store::{MAX_TREE_DEPTH, ObjectSource, ObjectStore, StoreError};
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
    /// Content moved from [`DiffEntry::old_path`] to [`DiffEntry::path`].
    /// Only produced by [`detect_exact_renames`]; an exact rename pairs a
    /// removed object id with an identical added object id, so the content
    /// is byte-identical (git's `similarity index 100%`).
    Renamed,
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
    /// File mode on each side (`None` when the side is absent), used to
    /// render git-shaped `new file mode`/`index` header lines.
    pub old_mode: Option<EntryMode>,
    pub new_mode: Option<EntryMode>,
    /// Source path for a [`DiffKind::Renamed`] entry; `None` for every
    /// other kind. `path` always holds the destination (new) path.
    pub old_path: Option<String>,
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

/// Collapse exact (identical-content) delete+add pairs in `entries` into
/// single [`DiffKind::Renamed`] entries, in place.
///
/// mkit is content-addressed, so two paths that share an object id hold
/// byte-identical content. A [`DiffKind::Removed`] entry and a
/// [`DiffKind::Added`] entry with equal object ids are therefore an exact
/// rename — git's `similarity index 100%`, but with no heuristic, no
/// threshold, and no false positives. When identical content is
/// duplicated across several removed/added paths, pairs are formed in
/// sorted-path order so the outcome is deterministic; any unpaired
/// remainder stays as a plain add/remove. The result is left sorted by
/// destination `path`, matching the rest of the diff pipeline.
///
/// Callers scope this to a single diff (git detects renames within one
/// diff): for `status`, that means applying it per staging leg so a
/// staged delete never pairs with an unstaged add.
pub fn detect_exact_renames(entries: &mut Vec<DiffEntry>) {
    use std::collections::HashMap;

    let mut removed: HashMap<Hash, Vec<usize>> = HashMap::new();
    let mut added: HashMap<Hash, Vec<usize>> = HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        match e.kind {
            DiffKind::Removed => {
                if let Some(h) = e.old_hash {
                    removed.entry(h).or_default().push(i);
                }
            }
            DiffKind::Added => {
                if let Some(h) = e.new_hash {
                    added.entry(h).or_default().push(i);
                }
            }
            _ => {}
        }
    }

    let mut consumed = vec![false; entries.len()];
    let mut renames: Vec<DiffEntry> = Vec::new();
    for (h, rem_idx) in &removed {
        let Some(add_idx) = added.get(h) else {
            continue;
        };
        let mut r = rem_idx.clone();
        let mut a = add_idx.clone();
        r.sort_by(|&x, &y| entries[x].path.cmp(&entries[y].path));
        a.sort_by(|&x, &y| entries[x].path.cmp(&entries[y].path));
        for (&ri, &ai) in r.iter().zip(a.iter()) {
            renames.push(DiffEntry {
                path: entries[ai].path.clone(),
                kind: DiffKind::Renamed,
                old_hash: Some(*h),
                new_hash: Some(*h),
                old_mode: entries[ri].old_mode,
                new_mode: entries[ai].new_mode,
                old_path: Some(entries[ri].path.clone()),
            });
            consumed[ri] = true;
            consumed[ai] = true;
        }
    }

    if renames.is_empty() {
        return;
    }
    let mut out: Vec<DiffEntry> = Vec::with_capacity(entries.len());
    for (i, e) in entries.drain(..).enumerate() {
        if !consumed[i] {
            out.push(e);
        }
    }
    out.extend(renames);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    *entries = out;
}

/// Compare two trees and return their [`DiffResult`]. `None` for either
/// hash represents the empty tree (use cases: comparing against the
/// initial commit, against a rolled-back state).
///
/// # Errors
///
/// Propagates [`StoreError`] when an expected tree object is missing or
/// fails its read-time hash check.
pub fn diff_trees<S: ObjectSource + ?Sized>(
    store: &S,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
) -> Result<DiffResult, StoreError> {
    diff_trees_inner(store, old_hash, new_hash, false)
}

fn diff_trees_inner<S: ObjectSource + ?Sized>(
    store: &S,
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
    // git orders diff entries by pathname. The name-sorted walk is already
    // sorted for the common cases; sort to also cover a dir/file replacement
    // (`d` sorts before `d/x.txt`), where a single tree position emits both a
    // shallower and a deeper path.
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(DiffResult { entries: out })
}

/// Lockstep walk of two name-sorted entry arrays.
fn diff_entries_recursive<S: ObjectSource + ?Sized>(
    store: &S,
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
                } else if o.mode == EntryMode::Tree || n.mode == EntryMode::Tree {
                    // A directory replaced by a file (or vice versa). git
                    // models this as the old subtree's leaves all deleted plus
                    // the new entry added — never a single Modified blob whose
                    // tree hash would be misread as a blob by the patch
                    // renderer.
                    add_removed_entries(store, o, prefix, out, depth)?;
                    add_added_entries(store, n, prefix, out, depth)?;
                } else if o.mode != n.mode && o.object_hash == n.object_hash {
                    if !ignore_regular_executable_mode || !regular_executable_pair(o.mode, n.mode) {
                        out.push(DiffEntry {
                            path: join_path(prefix, &o.name),
                            kind: DiffKind::ModeChanged,
                            old_hash: Some(o.object_hash),
                            new_hash: Some(n.object_hash),
                            old_mode: Some(o.mode),
                            new_mode: Some(n.mode),
                            old_path: None,
                        });
                    }
                } else if o.object_hash != n.object_hash || o.mode != n.mode {
                    out.push(DiffEntry {
                        path: join_path(prefix, &o.name),
                        kind: DiffKind::Modified,
                        old_hash: Some(o.object_hash),
                        new_hash: Some(n.object_hash),
                        old_mode: Some(o.mode),
                        new_mode: Some(n.mode),
                        old_path: None,
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

fn add_removed_entries<S: ObjectSource + ?Sized>(
    store: &S,
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
            old_mode: Some(entry.mode),
            new_mode: None,
            old_path: None,
        });
    }
    Ok(())
}

fn add_added_entries<S: ObjectSource + ?Sized>(
    store: &S,
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
            old_mode: None,
            new_mode: Some(entry.mode),
            old_path: None,
        });
    }
    Ok(())
}

fn load_entries<S: ObjectSource + ?Sized>(
    store: &S,
    hash: Option<Hash>,
) -> Result<Vec<TreeEntry>, StoreError> {
    match hash {
        Some(h) => load_tree(store, h),
        None => Ok(Vec::new()),
    }
}

fn load_tree<S: ObjectSource + ?Sized>(store: &S, h: Hash) -> Result<Vec<TreeEntry>, StoreError> {
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
/// Either side that is **binary** by Git's heuristic — a NUL byte in the
/// first 8000 bytes — yields a single `Binary files a/<old> and b/<new>
/// differ` line instead of hunks, matching Git.
///
/// The algorithm is the greedy Myers diff with Git-style hunk compaction
/// (see [`unified_hunks`]); the hunks byte-match `git diff`. Trailing-newline
/// handling follows Git's `\ No newline at end of file` convention.
///
/// Note this returns a `String` via lossy UTF-8 conversion, so a non-UTF-8
/// (but non-binary) blob's raw bytes are not preserved here — use
/// [`unified_hunks`] for byte-exact output.
#[must_use]
pub fn text_patch(old_bytes: &[u8], new_bytes: &[u8], old_path: &str, new_path: &str) -> String {
    match unified_hunks(old_bytes, new_bytes) {
        None => format!("Binary files a/{old_path} and b/{new_path} differ\n"),
        Some(hunks) if hunks.is_empty() => String::new(),
        Some(hunks) => {
            format!(
                "--- a/{old_path}\n+++ b/{new_path}\n{}",
                String::from_utf8_lossy(&hunks)
            )
        }
    }
}

/// The hunk body of a unified diff between two blobs: the `@@ … @@` headers
/// and their `+`/`-`/context lines, with no `---`/`+++` file headers, as raw
/// bytes (git diffs are byte-oriented and do not require UTF-8). Returns
/// `None` when either side is **binary** by git's heuristic — a NUL byte in
/// the first 8000 bytes — so a caller emits a `Binary files …` line instead.
/// An empty result means the blobs are textually identical.
///
/// Splitting the hunk body out lets callers wrap it in a git-shaped
/// `diff --git` header (with `/dev/null` for adds/deletes) while keeping the
/// algorithm — Myers diff with git-style hunk compaction — in one place.
#[must_use]
pub fn unified_hunks(old_bytes: &[u8], new_bytes: &[u8]) -> Option<Vec<u8>> {
    if is_binary(old_bytes) || is_binary(new_bytes) {
        return None;
    }
    let old_lines = split_lines(old_bytes);
    let new_lines = split_lines(new_bytes);
    let ops = edit_script(&old_lines, &new_lines);
    let hunks = group_hunks(&ops, PATCH_CONTEXT);
    let mut out = Vec::new();
    for hunk in &hunks {
        render_hunk(&mut out, hunk, &old_lines, &new_lines);
    }
    Some(out)
}

/// Origin of a line within a [`PatchHunk`] — context (unchanged), added on
/// the new side, or removed from the old side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkLineKind {
    /// Unchanged line present on both sides.
    Context,
    /// Line added on the new side (`+`).
    Added,
    /// Line removed from the old side (`-`).
    Removed,
}

/// One line of a hunk: its origin plus the raw bytes (no `+`/`-`/space
/// prefix) and whether the source line had a trailing newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HunkLine {
    /// Whether the line is context, added, or removed.
    pub kind: HunkLineKind,
    /// Raw line bytes, without the unified-diff prefix or trailing `\n`.
    pub text: Vec<u8>,
    /// `true` when the source had a `\n` after this line.
    pub has_newline: bool,
}

/// A single hunk for interactive staging (`add -p`): the 1-based old/new
/// line ranges (as in the `@@` header) plus the ordered context/added/
/// removed lines. Use [`apply_hunks_subset`] to materialize a chosen subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchHunk {
    /// 1-based first old-side line (0 when the old side is empty).
    pub old_start: usize,
    /// Number of old-side lines covered (context + removed).
    pub old_len: usize,
    /// 1-based first new-side line (0 when the new side is empty).
    pub new_start: usize,
    /// Number of new-side lines covered (context + added).
    pub new_len: usize,
    /// Ordered lines making up the hunk body.
    pub lines: Vec<HunkLine>,
}

/// Enumerate the hunks between two blobs as structured [`PatchHunk`]s, using
/// the same Myers diff + git-style compaction as [`unified_hunks`]. Returns
/// `None` when either side is **binary** (git's NUL heuristic); an empty
/// vector means the blobs are textually identical. Unlike `unified_hunks`,
/// which renders bytes, this exposes each hunk's lines so a caller can let
/// the user pick a subset to stage and rebuild the partial blob with
/// [`apply_hunks_subset`].
#[must_use]
pub fn enumerate_hunks(old_bytes: &[u8], new_bytes: &[u8]) -> Option<Vec<PatchHunk>> {
    if is_binary(old_bytes) || is_binary(new_bytes) {
        return None;
    }
    let old_lines = split_lines(old_bytes);
    let new_lines = split_lines(new_bytes);
    let ops = edit_script(&old_lines, &new_lines);
    let hunks = group_hunks(&ops, PATCH_CONTEXT);
    Some(
        hunks
            .iter()
            .map(|h| to_patch_hunk(h, &old_lines, &new_lines))
            .collect(),
    )
}

fn to_patch_hunk(hunk: &Hunk, old: &[DiffLine<'_>], new: &[DiffLine<'_>]) -> PatchHunk {
    let lines = hunk
        .ops
        .iter()
        .map(|op| {
            let (kind, dl) = match *op {
                DiffOp::Equal(oi, _) => (HunkLineKind::Context, &old[oi]),
                DiffOp::Delete(oi) => (HunkLineKind::Removed, &old[oi]),
                DiffOp::Insert(ni) => (HunkLineKind::Added, &new[ni]),
            };
            HunkLine {
                kind,
                text: dl.text.to_vec(),
                has_newline: dl.has_newline,
            }
        })
        .collect();
    PatchHunk {
        old_start: hunk.old_start,
        old_len: hunk.old_len,
        new_start: hunk.new_start,
        new_len: hunk.new_len,
        lines,
    }
}

/// Rebuild a blob from `base_bytes` applying only the hunks whose index (into
/// the slice returned by [`enumerate_hunks`]) is in `selected`. Selected
/// hunks have their additions applied and removals dropped; unselected hunks
/// keep the base content unchanged. `selected` order does not matter — hunks
/// are always applied in file order — and out-of-range indices are ignored.
///
/// This is the staging primitive for `add -p`: pass the index/HEAD blob as
/// the base and the accepted hunk indices to produce the partially-staged
/// blob. Applying *all* hunks reproduces the new blob exactly; applying
/// *none* reproduces the base.
#[must_use]
pub fn apply_hunks_subset(base_bytes: &[u8], hunks: &[PatchHunk], selected: &[usize]) -> Vec<u8> {
    let old_lines = split_lines(base_bytes);
    let sel: std::collections::HashSet<usize> = selected.iter().copied().collect();
    let mut out: Vec<u8> = Vec::with_capacity(base_bytes.len());
    let mut cursor = 0usize; // 0-based index into old_lines
    for (i, h) in hunks.iter().enumerate() {
        // 0-based start of this hunk's old-side region. A pure insertion into
        // an empty base has old_len == 0 and old_start == 0; otherwise the
        // hunk always carries context, so old_start is 1-based.
        let region_start = if h.old_len == 0 {
            h.old_start
        } else {
            h.old_start - 1
        }
        .min(old_lines.len());
        let region_end = (region_start + h.old_len).min(old_lines.len());
        // Untouched base lines before this hunk.
        for dl in &old_lines[cursor..region_start] {
            emit_raw_line(&mut out, dl.text, dl.has_newline);
        }
        if sel.contains(&i) {
            // Apply: emit the new side (context + added).
            for l in &h.lines {
                if l.kind != HunkLineKind::Removed {
                    emit_raw_line(&mut out, &l.text, l.has_newline);
                }
            }
        } else {
            // Keep the base region verbatim (identical to context + removed).
            for dl in &old_lines[region_start..region_end] {
                emit_raw_line(&mut out, dl.text, dl.has_newline);
            }
        }
        cursor = region_end;
    }
    for dl in &old_lines[cursor..] {
        emit_raw_line(&mut out, dl.text, dl.has_newline);
    }
    out
}

fn emit_raw_line(out: &mut Vec<u8>, text: &[u8], has_newline: bool) {
    out.extend_from_slice(text);
    if has_newline {
        out.push(b'\n');
    }
}

/// A contiguous run of base lines that one side changed, anchored on base
/// line coordinates: `base_len` base lines (0 for a pure insertion) are
/// replaced by `new`. Used by the 3-way merge to detect overlap and splice.
struct MergeRegion {
    base_start: usize,
    base_len: usize,
    new: Vec<(Vec<u8>, bool)>,
}

/// Line-level 3-way merge of three blobs (diff3-style, conservative).
///
/// Returns `Some(merged)` when `ours` and `theirs` changed **disjoint**
/// regions of `base` (so the merge is unambiguous), and `None` when their
/// changes overlap or any input is binary — the caller then records a
/// conflict. Identical `ours`/`theirs` merge trivially. Unlike a full
/// diff3 this does not auto-resolve *identical overlapping* edits (those
/// stay a conflict): it errs toward conflict, never toward a wrong merge.
/// (#298)
#[must_use]
pub fn merge_blob_3way(base: &[u8], ours: &[u8], theirs: &[u8]) -> Option<Vec<u8>> {
    if ours == theirs {
        return Some(ours.to_vec());
    }
    if is_binary(base) || is_binary(ours) || is_binary(theirs) {
        return None;
    }
    let base_lines = split_lines(base);
    let ours_regions = changed_regions(&base_lines, &split_lines(ours));
    let theirs_regions = changed_regions(&base_lines, &split_lines(theirs));
    if regions_overlap(&ours_regions, &theirs_regions) {
        return None;
    }
    Some(apply_merge_regions(
        &base_lines,
        &ours_regions,
        &theirs_regions,
    ))
}

/// Group the edit script `base → side` into base-anchored changed regions
/// (no context — adjacent equal lines bound each region).
fn changed_regions(base: &[DiffLine<'_>], side: &[DiffLine<'_>]) -> Vec<MergeRegion> {
    let mut regions: Vec<MergeRegion> = Vec::new();
    let mut cur: Option<MergeRegion> = None;
    let mut base_idx = 0usize; // next unconsumed base line
    for op in edit_script(base, side) {
        match op {
            DiffOp::Equal(bi, _) => {
                if let Some(r) = cur.take() {
                    regions.push(r);
                }
                base_idx = bi + 1;
            }
            DiffOp::Delete(bi) => {
                cur.get_or_insert(MergeRegion {
                    base_start: base_idx,
                    base_len: 0,
                    new: Vec::new(),
                })
                .base_len += 1;
                base_idx = bi + 1;
            }
            DiffOp::Insert(si) => {
                let line = &side[si];
                cur.get_or_insert(MergeRegion {
                    base_start: base_idx,
                    base_len: 0,
                    new: Vec::new(),
                })
                .new
                .push((line.text.to_vec(), line.has_newline));
            }
        }
    }
    if let Some(r) = cur.take() {
        regions.push(r);
    }
    regions
}

/// `true` if any ours-region overlaps any theirs-region on base lines.
/// Modify spans use half-open `[start, start+len)` intersection; a pure
/// insertion conflicts only when it lands strictly inside a modify span,
/// or coincides with another insertion (ambiguous order) — insertions at a
/// modify boundary are adjacent and merge cleanly.
fn regions_overlap(ours: &[MergeRegion], theirs: &[MergeRegion]) -> bool {
    ours.iter().any(|a| {
        theirs.iter().any(|b| {
            let (a_s, a_e) = (a.base_start, a.base_start + a.base_len);
            let (b_s, b_e) = (b.base_start, b.base_start + b.base_len);
            match (a.base_len == 0, b.base_len == 0) {
                (true, true) => a_s == b_s,
                (true, false) => b_s < a_s && a_s < b_e,
                (false, true) => a_s < b_s && b_s < a_e,
                (false, false) => a_s < b_e && b_s < a_e,
            }
        })
    })
}

/// Splice non-overlapping ours/theirs regions back onto `base`. Regions are
/// applied in base order; at a shared start a pure insertion (len 0) sorts
/// before a modify so inserted lines precede the replaced ones.
fn apply_merge_regions(
    base: &[DiffLine<'_>],
    ours: &[MergeRegion],
    theirs: &[MergeRegion],
) -> Vec<u8> {
    let mut all: Vec<&MergeRegion> = ours.iter().chain(theirs.iter()).collect();
    all.sort_by_key(|r| (r.base_start, r.base_len));
    let mut out: Vec<u8> = Vec::new();
    let mut cursor = 0usize;
    for r in all {
        for line in &base[cursor..r.base_start] {
            emit_raw_line(&mut out, line.text, line.has_newline);
        }
        for (text, nl) in &r.new {
            emit_raw_line(&mut out, text, *nl);
        }
        cursor = r.base_start + r.base_len;
    }
    for line in &base[cursor..] {
        emit_raw_line(&mut out, line.text, line.has_newline);
    }
    out
}

/// Added / deleted line counts between two blobs, from the same Myers edit
/// script the unified patch uses. `None` when either side is **binary** —
/// matching Git's heuristic of a NUL byte within the first 8000 bytes
/// (independent of UTF-8 validity), so `diff --stat` renders `Bin …` for
/// exactly the blobs Git would.
///
/// Used by `diff --stat`; kept here so the stat counts always agree with
/// the `+`/`-` lines `text_patch` would emit for the same blobs. Lines are
/// split on `\n` bytes, so the counts hold for any non-binary blob, including
/// non-UTF-8 text.
#[must_use]
pub fn diff_line_counts(old_bytes: &[u8], new_bytes: &[u8]) -> Option<(usize, usize)> {
    if is_binary(old_bytes) || is_binary(new_bytes) {
        return None;
    }
    let old_lines = split_lines(old_bytes);
    let new_lines = split_lines(new_bytes);
    let mut added = 0;
    let mut deleted = 0;
    for op in edit_script(&old_lines, &new_lines) {
        match op {
            DiffOp::Insert(_) => added += 1,
            DiffOp::Delete(_) => deleted += 1,
            DiffOp::Equal(_, _) => {}
        }
    }
    Some((added, deleted))
}

/// Git's binary heuristic (`buffer_is_binary`): a NUL byte within the
/// first 8000 bytes marks the blob binary, regardless of UTF-8 validity.
fn is_binary(bytes: &[u8]) -> bool {
    const FIRST_FEW_BYTES: usize = 8000;
    bytes.iter().take(FIRST_FEW_BYTES).any(|&b| b == 0)
}

/// A single line (raw bytes) plus whether the source had a trailing newline
/// after it.
struct DiffLine<'a> {
    text: &'a [u8],
    /// `true` when this line was terminated by `\n` in the source.
    has_newline: bool,
}

/// Split bytes into lines on `\n`, preserving whether the final line had a
/// trailing newline. An empty input yields no lines.
fn split_lines(text: &[u8]) -> Vec<DiffLine<'_>> {
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(idx) = rest.iter().position(|&b| b == b'\n') {
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
            rest = b"";
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

/// Compute a line-level edit script using the greedy Myers diff, then
/// canonicalize hunk boundaries the way git's xdiff does (slide each run of
/// changed lines as far down as identical neighbours allow). The result
/// matches `git diff`'s hunks for the common cases — same algorithm, same
/// boundary convention — modulo git's optional indent heuristic.
fn edit_script(old: &[DiffLine<'_>], new: &[DiffLine<'_>]) -> Vec<DiffOp> {
    let (mut old_changed, mut new_changed) = myers_changed(old, new);
    compact_changes(old, &mut old_changed);
    compact_changes(new, &mut new_changed);
    script_from_flags(old, new, &old_changed, &new_changed)
}

/// Run the greedy Myers diff and mark which old lines are deletions and which
/// new lines are insertions. Lines left unmarked are the matched (equal)
/// lines that pair up in order.
//
// Myers indexes paths by signed diagonal `k = x - y`, so the V array and
// backtrack inherently convert between `isize` (diagonals, offsets) and
// `usize` (line indices). The values are bounded by `n + m`, well within
// range, so the sign/wrap casts are safe; `x`/`y`/`k`/`d`/`v` are the
// algorithm's canonical names.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names
)]
fn myers_changed(old: &[DiffLine<'_>], new: &[DiffLine<'_>]) -> (Vec<bool>, Vec<bool>) {
    let n = old.len();
    let m = new.len();
    let mut old_changed = vec![false; n];
    let mut new_changed = vec![false; m];
    if n == 0 {
        new_changed.fill(true);
        return (old_changed, new_changed);
    }
    if m == 0 {
        old_changed.fill(true);
        return (old_changed, new_changed);
    }

    let max = n + m;
    let offset = max as isize; // shift so diagonal k maps to a non-negative index
    let mut v = vec![0isize; 2 * max + 1];
    let mut trace: Vec<Vec<isize>> = Vec::new();

    let idx = |k: isize| (k + offset) as usize;
    let mut found = max as isize;
    'outer: for d in 0..=max as isize {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            // Greedy: extend the furthest-reaching path on diagonal k.
            let mut x = if k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]) {
                v[idx(k + 1)] // down → an insertion (consume a new line)
            } else {
                v[idx(k - 1)] + 1 // right → a deletion (consume an old line)
            };
            let mut y = x - k;
            while (x as usize) < n
                && (y as usize) < m
                && lines_equal(&old[x as usize], &new[y as usize])
            {
                x += 1;
                y += 1;
            }
            v[idx(k)] = x;
            if x as usize >= n && y as usize >= m {
                found = d;
                break 'outer;
            }
            k += 2;
        }
    }

    // Backtrack through the saved V snapshots to recover the edits.
    let mut x = n as isize;
    let mut y = m as isize;
    for d in (0..=found).rev() {
        let vd = &trace[d as usize];
        let k = x - y;
        let down = k == -d || (k != d && vd[idx(k - 1)] < vd[idx(k + 1)]);
        let prev_k = if down { k + 1 } else { k - 1 };
        let prev_x = vd[idx(prev_k)];
        let prev_y = prev_x - prev_k;
        // Walk back down the snake (matched lines) — no flags set there.
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if down {
                new_changed[(y - 1) as usize] = true; // insertion
                y -= 1;
            } else {
                old_changed[(x - 1) as usize] = true; // deletion
                x -= 1;
            }
        }
    }
    (old_changed, new_changed)
}

/// Slide each maximal run of changed lines downward while the line leaving the
/// top of the run equals the line entering at the bottom — git's
/// `xdl_change_compact` canonical placement, so a change among identical
/// neighbours lands where git puts it.
fn compact_changes(lines: &[DiffLine<'_>], changed: &mut [bool]) {
    let n = lines.len();
    let mut i = 0;
    while i < n {
        if !changed[i] {
            i += 1;
            continue;
        }
        // [start, end) is a run of changed lines.
        let start = i;
        let mut end = i;
        while end < n && changed[end] {
            end += 1;
        }
        // Slide down: the line at `start` leaves the run and the line at
        // `end` joins it, valid only when they are identical.
        let (mut s, mut e) = (start, end);
        while e < n && lines_equal(&lines[s], &lines[e]) {
            changed[s] = false;
            changed[e] = true;
            s += 1;
            e += 1;
        }
        i = e;
    }
}

/// Build the `DiffOp` sequence from the per-side changed flags, in git's
/// order: within each change region, all deletions precede all insertions;
/// matched lines pair up as `Equal`.
fn script_from_flags(
    old: &[DiffLine<'_>],
    new: &[DiffLine<'_>],
    old_changed: &[bool],
    new_changed: &[bool],
) -> Vec<DiffOp> {
    let (n, m) = (old.len(), new.len());
    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n || j < m {
        if i < n && j < m && !old_changed[i] && !new_changed[j] {
            ops.push(DiffOp::Equal(i, j));
            i += 1;
            j += 1;
        } else {
            while i < n && old_changed[i] {
                ops.push(DiffOp::Delete(i));
                i += 1;
            }
            while j < m && new_changed[j] {
                ops.push(DiffOp::Insert(j));
                j += 1;
            }
        }
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

/// Format one side of an `@@` range as git does: `start,len`, but the `,len`
/// is omitted when `len == 1` (`@@ -1 +1 @@`).
fn hunk_range(start: usize, len: usize) -> String {
    if len == 1 {
        start.to_string()
    } else {
        format!("{start},{len}")
    }
}

fn render_hunk(out: &mut Vec<u8>, hunk: &Hunk, old: &[DiffLine<'_>], new: &[DiffLine<'_>]) {
    let header = format!(
        "@@ -{} +{} @@\n",
        hunk_range(hunk.old_start, hunk.old_len),
        hunk_range(hunk.new_start, hunk.new_len)
    );
    out.extend_from_slice(header.as_bytes());
    for op in &hunk.ops {
        match *op {
            DiffOp::Equal(oi, _) => emit_line(out, b' ', &old[oi]),
            DiffOp::Delete(oi) => emit_line(out, b'-', &old[oi]),
            DiffOp::Insert(ni) => emit_line(out, b'+', &new[ni]),
        }
    }
}

fn emit_line(out: &mut Vec<u8>, prefix: u8, line: &DiffLine<'_>) {
    out.push(prefix);
    out.extend_from_slice(line.text);
    out.push(b'\n');
    if !line.has_newline {
        out.extend_from_slice(b"\\ No newline at end of file\n");
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
    /// Error seeding the tracked set from a tree.
    #[error(transparent)]
    Index(#[from] IndexError),
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
    status_diff_observed(store, head_tree, worktree_root, index).map(|(entries, _)| entries)
}

/// [`status_diff`] that additionally returns the worktree walk's
/// [`worktree::StatObservation`]s — entries whose cache was absent or
/// racy-smudged but whose re-hash matched the staged hash. Callers
/// (the `status` CLI) use them to heal the stat cache from hash-time
/// stats; pairing a *later* stat with the earlier hash is unsound.
///
/// # Errors
/// See [`status_diff`].
#[allow(clippy::type_complexity)]
pub fn status_diff_observed(
    store: &ObjectStore,
    head_tree: Option<&Hash>,
    worktree_root: &Path,
    index: Option<&Index>,
) -> Result<(Vec<StatusEntry>, Vec<worktree::StatObservation>), DiffError> {
    // Always snapshot the worktree — the index↔worktree leg uses it. The
    // tracked set for ignore exemption is the staging index if present, else
    // the HEAD tree's paths (seeded here) — without it a tracked file
    // matching an ignore rule would be dropped and misreported as a deletion.
    let head_seed;
    let tracked = if let Some(i) = index {
        Some(i)
    } else if let Some(ht) = head_tree {
        head_seed = crate::index::from_tree(store, *ht)?;
        Some(&head_seed)
    } else {
        None
    };
    // Snapshot objects are ephemeral: they live in an in-memory overlay
    // (EphemeralSink) and never touch the durable store — status pays
    // no durability cost, leaves no garbage in objects/, and can never
    // make a non-durable object visible to another writer's dedup.
    // Reads fall through to the store for committed objects.
    let snapshot = crate::store::EphemeralSink::new(store);
    let mut observations = Vec::new();
    let work_tree_hash = worktree::build_tree_filtered_observed(
        &snapshot,
        worktree_root,
        tracked,
        &mut observations,
    )?;

    let Some(idx) = index else {
        // Legacy fallback: HEAD↔worktree, everything labeled Unstaged.
        let diff = diff_worktree_trees(&snapshot, head_tree.copied(), Some(work_tree_hash))?;
        return Ok((
            diff.entries
                .into_iter()
                .map(|d| StatusEntry {
                    diff: d,
                    staging: StatusStaging::Unstaged,
                })
                .collect(),
            observations,
        ));
    };

    // Build the index tree exactly the way `mkit commit` builds it.
    // This is the authoritative "what would be committed right now."
    // Ephemeral diff snapshot (no durable publish) — cheap shape check.
    let index_tree = worktree::build_tree_from_index_with(store, &snapshot, idx, false)?;

    let staged = diff_trees(&snapshot, head_tree.copied(), Some(index_tree))?;
    let unstaged = diff_worktree_trees(&snapshot, Some(index_tree), Some(work_tree_hash))?;

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
    Ok((out, observations))
}

#[cfg(unix)]
fn diff_worktree_trees<S: ObjectSource + ?Sized>(
    store: &S,
    old_hash: Option<Hash>,
    new_hash: Option<Hash>,
) -> Result<DiffResult, StoreError> {
    diff_trees(store, old_hash, new_hash)
}

#[cfg(not(unix))]
fn diff_worktree_trees<S: ObjectSource + ?Sized>(
    store: &S,
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

    #[test]
    fn diff_line_counts_counts_text_and_flags_binary() {
        // Plain text: +2/-1 (b→B replaced, d,e added).
        assert_eq!(
            diff_line_counts(b"a\nb\nc\n", b"a\nB\nc\nd\ne\n"),
            Some((3, 1))
        );
        // A NUL byte → binary by git's heuristic, even though valid UTF-8.
        assert_eq!(diff_line_counts(b"a\nb\n", b"a\x00b\n"), None);
        assert_eq!(diff_line_counts(b"x\x00y", b"z"), None);
        // No NUL but invalid UTF-8 → still counted as text (lossy), not binary.
        assert!(diff_line_counts(b"\xff\xfe\n", b"\xff\xfe\nmore\n").is_some());
    }

    // --- exact rename detection -----------------------------------------

    fn h(b: &[u8]) -> Hash {
        crate::hash::hash(b)
    }
    fn removed(path: &str, content: &[u8]) -> DiffEntry {
        DiffEntry {
            path: path.into(),
            kind: DiffKind::Removed,
            old_hash: Some(h(content)),
            new_hash: None,
            old_mode: Some(EntryMode::Blob),
            new_mode: None,
            old_path: None,
        }
    }
    fn added(path: &str, content: &[u8]) -> DiffEntry {
        DiffEntry {
            path: path.into(),
            kind: DiffKind::Added,
            old_hash: None,
            new_hash: Some(h(content)),
            old_mode: None,
            new_mode: Some(EntryMode::Blob),
            old_path: None,
        }
    }

    #[test]
    fn detect_pairs_identical_content_into_one_rename() {
        let mut es = vec![removed("old.txt", b"hello"), added("new.txt", b"hello")];
        detect_exact_renames(&mut es);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].kind, DiffKind::Renamed);
        assert_eq!(es[0].path, "new.txt");
        assert_eq!(es[0].old_path.as_deref(), Some("old.txt"));
        assert_eq!(es[0].old_hash, Some(h(b"hello")));
        assert_eq!(es[0].new_hash, Some(h(b"hello")));
    }

    #[test]
    fn detect_leaves_unrelated_delete_add_alone() {
        let mut es = vec![removed("a", b"one"), added("b", b"two")];
        let before = es.clone();
        detect_exact_renames(&mut es);
        assert_eq!(es, before);
    }

    #[test]
    fn detect_ignores_modified_in_place() {
        let mut es = vec![DiffEntry {
            path: "f".into(),
            kind: DiffKind::Modified,
            old_hash: Some(h(b"x")),
            new_hash: Some(h(b"y")),
            old_mode: Some(EntryMode::Blob),
            new_mode: Some(EntryMode::Blob),
            old_path: None,
        }];
        let before = es.clone();
        detect_exact_renames(&mut es);
        assert_eq!(es, before);
    }

    #[test]
    fn detect_pairs_duplicates_deterministically_by_path() {
        // Identical content at two old paths and two new paths → two
        // renames, paired in sorted-path order (old_a→new_a, old_b→new_b)
        // regardless of input order.
        let mut es = vec![
            added("new_b", b"dup"),
            removed("old_b", b"dup"),
            added("new_a", b"dup"),
            removed("old_a", b"dup"),
        ];
        detect_exact_renames(&mut es);
        assert_eq!(es.len(), 2);
        assert_eq!(
            (es[0].old_path.as_deref(), es[0].path.as_str()),
            (Some("old_a"), "new_a")
        );
        assert_eq!(
            (es[1].old_path.as_deref(), es[1].path.as_str()),
            (Some("old_b"), "new_b")
        );
    }

    #[test]
    fn detect_leaves_unpaired_remainder() {
        // Two deletes, one add of the same content → one rename (the
        // sorted-first old path) plus one plain delete.
        let mut es = vec![
            removed("old_a", b"c"),
            removed("old_b", b"c"),
            added("new", b"c"),
        ];
        detect_exact_renames(&mut es);
        assert_eq!(es.len(), 2);
        let r = es.iter().find(|e| e.kind == DiffKind::Renamed).unwrap();
        assert_eq!(r.old_path.as_deref(), Some("old_a"));
        let d = es.iter().find(|e| e.kind == DiffKind::Removed).unwrap();
        assert_eq!(d.path, "old_b");
    }

    #[test]
    fn detect_preserves_modes_on_rename_with_mode_change() {
        // Identical content, exec bit added on the new side: still an exact
        // rename, and both modes are preserved for the header renderer.
        let r = removed("old", b"same");
        let mut a = added("new", b"same");
        a.new_mode = Some(EntryMode::Executable);
        let mut es = vec![r, a];
        detect_exact_renames(&mut es);
        assert_eq!(es.len(), 1);
        assert_eq!(es[0].kind, DiffKind::Renamed);
        assert_eq!(es[0].old_mode, Some(EntryMode::Blob));
        assert_eq!(es[0].new_mode, Some(EntryMode::Executable));
    }

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(&crate::layout::RepoLayout::single(dir.path())).unwrap();
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
    fn status_diff_does_not_fsync() {
        // `status` is read-only from the user's perspective; its
        // worktree-snapshot objects are ephemeral and must never pay
        // durability costs (no barriers, no full flushes, no dir
        // flushes) — renames only.
        use crate::batch::testing::{Ev, RecordingSyncer};
        use std::sync::Arc;

        let (_sd, mut store) = fresh_store();
        let work = fresh_workdir();
        std::fs::write(work.path().join("a.txt"), b"some content").unwrap();
        std::fs::write(work.path().join("b.txt"), b"other content").unwrap();

        let rec = Arc::new(RecordingSyncer::default());
        store.set_syncer(rec.clone());

        let result = status_diff(&store, None, work.path(), None).unwrap();
        assert!(!result.is_empty(), "untracked files must surface");

        let evs = rec.events();
        assert!(
            evs.iter().all(|e| matches!(e, Ev::Rename { .. })),
            "status must not emit any flush events; got {evs:?}"
        );
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
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
    fn text_patch_nul_byte_is_binary_like_git() {
        // A NUL byte makes the blob binary by git's heuristic even though it
        // is valid UTF-8 — must NOT emit a textual hunk with an embedded NUL.
        let patch = text_patch(b"a\0b\n", b"a\0c\n", "f", "f");
        assert_eq!(patch, "Binary files a/f and b/f differ\n");
    }

    #[test]
    fn unified_hunks_non_utf8_without_nul_is_text_like_git() {
        // Invalid UTF-8 but no NUL: git treats it as text and diffs it
        // byte-wise. The raw bytes survive into the hunk (single-line hunk →
        // `@@ -1 +1 @@`, no `,1`).
        let hunks = unified_hunks(b"\xff\n", b"\xfe\n").expect("not binary");
        assert_eq!(
            hunks,
            b"@@ -1 +1 @@\n-\xff\n+\xfe\n".to_vec(),
            "got {hunks:?}"
        );
    }

    #[test]
    fn hunk_header_omits_count_one_like_git() {
        // A one-line-each change: git writes `@@ -1 +1 @@`, not `-1,1 +1,1`.
        let patch = text_patch(b"old\n", b"new\n", "f", "f");
        assert_eq!(
            patch, "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n",
            "{patch}"
        );
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

    #[test]
    fn text_patch_inserts_compact_to_git_position() {
        // Inserting a line into a run of identical lines: git's change
        // compaction places the `+` at the *bottom* of the run (just before
        // the differing line). Verifies the Myers + compaction pipeline picks
        // the same canonical boundary git does.
        let patch = text_patch(b"a\na\nb\n", b"a\na\na\nb\n", "f", "f");
        assert_eq!(
            patch, "--- a/f\n+++ b/f\n@@ -1,3 +1,4 @@\n a\n a\n+a\n b\n",
            "{patch}"
        );
    }

    #[test]
    fn text_patch_deletes_compact_to_git_position() {
        // The dual: deleting from a run of identical lines removes the bottom
        // one (the `-` lands just before the differing line).
        let patch = text_patch(b"a\na\na\nb\n", b"a\na\nb\n", "f", "f");
        assert_eq!(
            patch, "--- a/f\n+++ b/f\n@@ -1,4 +1,3 @@\n a\n a\n-a\n b\n",
            "{patch}"
        );
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
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        });
        let result = status_diff(&store, None, work.path(), Some(&idx)).unwrap();
        assert_eq!(result.len(), 2, "expected staged + unstaged entries");
        let stagings: Vec<_> = result.iter().map(|e| e.staging).collect();
        assert!(stagings.contains(&StatusStaging::Staged));
        assert!(stagings.contains(&StatusStaging::Unstaged));
        assert!(result.iter().all(|e| e.diff.path == "b.txt"));
    }

    // ---- enumerate_hunks / apply_hunks_subset (add -p primitives) ----

    #[test]
    fn enumerate_hunks_binary_returns_none() {
        assert!(enumerate_hunks(b"a\0b", b"c").is_none());
        assert!(enumerate_hunks(b"text\n", b"with\0nul").is_none());
    }

    #[test]
    fn enumerate_hunks_identical_is_empty() {
        assert_eq!(enumerate_hunks(b"a\nb\n", b"a\nb\n"), Some(vec![]));
    }

    // 14 lines; edits at line 2 and line 13 are >2*context apart, so they
    // stay as two distinct hunks (changes <7 lines apart would merge).
    const HUNK2_OLD: &[u8] = b"l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\n";
    const HUNK2_NEW: &[u8] = b"l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nL13\nl14\n";

    #[test]
    fn apply_all_hunks_reproduces_new_apply_none_reproduces_base() {
        let hunks = enumerate_hunks(HUNK2_OLD, HUNK2_NEW).unwrap();
        assert_eq!(hunks.len(), 2, "expected two distinct hunks");
        let all: Vec<usize> = (0..hunks.len()).collect();
        assert_eq!(
            apply_hunks_subset(HUNK2_OLD, &hunks, &all),
            HUNK2_NEW,
            "apply all == new"
        );
        assert_eq!(
            apply_hunks_subset(HUNK2_OLD, &hunks, &[]),
            HUNK2_OLD,
            "apply none == old"
        );
    }

    #[test]
    fn apply_single_hunk_picks_only_that_region() {
        let hunks = enumerate_hunks(HUNK2_OLD, HUNK2_NEW).unwrap();
        // Stage only the first hunk: line 2 → L2, line 13 stays l13.
        let staged = apply_hunks_subset(HUNK2_OLD, &hunks, &[0]);
        assert_eq!(
            staged, b"l1\nL2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nl13\nl14\n",
            "only the first hunk applied"
        );
        // Stage only the second hunk: line 13 → L13, line 2 stays l2.
        let staged = apply_hunks_subset(HUNK2_OLD, &hunks, &[1]);
        assert_eq!(
            staged, b"l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\nl11\nl12\nL13\nl14\n",
            "only the second hunk applied"
        );
    }

    #[test]
    fn apply_hunks_into_empty_base_adds_lines() {
        let old = b"";
        let new = b"alpha\nbeta\n";
        let hunks = enumerate_hunks(old, new).unwrap();
        assert_eq!(apply_hunks_subset(old, &hunks, &[0]), new);
        assert_eq!(apply_hunks_subset(old, &hunks, &[]), old);
    }

    #[test]
    fn apply_hunks_preserves_missing_eof_newline() {
        let old = b"a\nb\nc";
        let new = b"a\nB\nc"; // edit the middle line; file still lacks final \n
        let hunks = enumerate_hunks(old, new).unwrap();
        let staged = apply_hunks_subset(old, &hunks, &[0]);
        assert_eq!(staged, new, "no trailing newline must be preserved");
    }

    // ---- merge_blob_3way (#298) ----

    #[test]
    fn merge3_identical_sides_merge_trivially() {
        let x = b"a\nb\n";
        assert_eq!(merge_blob_3way(b"base\n", x, x), Some(x.to_vec()));
    }

    #[test]
    fn merge3_disjoint_line_edits_auto_merge() {
        let base = b"a\nb\nc\nd\ne\n";
        let ours = b"A\nb\nc\nd\ne\n"; // line 1
        let theirs = b"a\nb\nc\nd\nE\n"; // line 5
        assert_eq!(
            merge_blob_3way(base, ours, theirs),
            Some(b"A\nb\nc\nd\nE\n".to_vec())
        );
    }

    #[test]
    fn merge3_adjacent_line_edits_auto_merge() {
        // The motivating #298 case: line 1 changed on one side, line 2 on the
        // other. Adjacent but non-overlapping → clean merge, no conflict.
        let base = b"x\ny\n";
        let ours = b"X\ny\n"; // line 1
        let theirs = b"x\nY\n"; // line 2
        assert_eq!(
            merge_blob_3way(base, ours, theirs),
            Some(b"X\nY\n".to_vec())
        );
    }

    #[test]
    fn merge3_overlapping_line_edits_conflict() {
        let base = b"a\nb\nc\n";
        let ours = b"A\nb\nc\n"; // line 1 -> A
        let theirs = b"Z\nb\nc\n"; // line 1 -> Z
        assert_eq!(merge_blob_3way(base, ours, theirs), None);
    }

    #[test]
    fn merge3_one_side_only_takes_that_side() {
        // theirs == base (no change); ours changed → take ours.
        let base = b"a\nb\nc\n";
        let ours = b"a\nB\nc\n";
        assert_eq!(merge_blob_3way(base, ours, base), Some(ours.to_vec()));
    }

    #[test]
    fn merge3_disjoint_insertions_auto_merge() {
        let base = b"a\nb\n";
        let ours = b"a\nX\nb\n"; // insert X after a
        let theirs = b"a\nb\nY\n"; // insert Y after b
        assert_eq!(
            merge_blob_3way(base, ours, theirs),
            Some(b"a\nX\nb\nY\n".to_vec())
        );
    }

    #[test]
    fn merge3_coincident_insertions_conflict() {
        let base = b"a\nb\n";
        let ours = b"a\nX\nb\n"; // both insert at the same gap
        let theirs = b"a\nY\nb\n";
        assert_eq!(merge_blob_3way(base, ours, theirs), None);
    }

    #[test]
    fn merge3_binary_side_conflicts() {
        assert_eq!(merge_blob_3way(b"a\nb\n", b"a\0\nb\n", b"a\nb\nc\n"), None);
    }
}
