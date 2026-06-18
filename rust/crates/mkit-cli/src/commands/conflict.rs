//! Shared CLI helpers for the resolvable-conflict workflow (#177).
//!
//! Materialises conflict material into the worktree + index, classifies
//! each conflict into a presentation class, and scans for leftover
//! conflict markers so `--continue` can refuse to proceed while the user
//! has not resolved a textual conflict.
//!
//! Materialisation always honours the #176 restore guards: callers run
//! [`super::ensure_restore_safe`] over the conflict-time tree before
//! invoking [`materialize_conflicts`], so dirty tracked files and
//! untracked collisions are never clobbered.

use std::fs;
use std::io::Write;
use std::path::Path;

use mkit_core::hash::Hash;
use mkit_core::index::{self, EntryStatus, IndexEntry};
use mkit_core::object::{EntryMode, Object};
use mkit_core::ops::conflict_state::ConflictRecord;
use mkit_core::ops::merge::{Conflict, ConflictKind};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

/// Classification of how a conflicting path is presented to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictClass {
    /// Text modify/modify or add/add: classic 2-way Git markers are
    /// written into the worktree file.
    TextMarkers,
    /// Binary blob on either side: no markers (they would corrupt the
    /// file); the ours-side content is left in place for manual edit.
    Binary,
    /// Delete/modify: one side removed the path; the surviving content
    /// is left in place; resolve by `mkit add` or `mkit rm`.
    DeleteModify,
    /// Symlink or executable-mode change, or any other shape unsafe for
    /// markers: ours-side content/mode is left in place for manual edit.
    Special,
}

/// Marker lines, kept as constants so the leftover scanner and the
/// writer agree byte-for-byte.
const MARK_OURS: &str = "<<<<<<< ours";
const MARK_SEP: &str = "=======";
const MARK_THEIRS: &str = ">>>>>>> theirs";

/// Decide whether a blob's bytes are safe to wrap in text markers.
fn is_text(data: &[u8]) -> bool {
    // No NUL bytes and valid UTF-8 — the same heuristic used for the
    // diff path. A NUL is the classic "this is binary" tell.
    !data.contains(&0) && core::str::from_utf8(data).is_ok()
}

fn read_blob(store: &ObjectStore, h: Hash) -> Result<Vec<u8>, String> {
    match store.read_object(&h) {
        Ok(Object::Blob(b)) => Ok(b.data),
        Ok(_) => Err("conflict side is not a blob".to_string()),
        Err(e) => Err(format!("read conflict blob: {e}")),
    }
}

/// `true` when `h` points at a blob object (as opposed to a tree, which
/// is how a file-vs-directory conflict surfaces on one side).
fn is_blob(store: &ObjectStore, h: Hash) -> bool {
    matches!(store.read_object(&h), Ok(Object::Blob(_)))
}

/// `true` when a conflict side is absent or points at a blob. A side
/// that points at a tree (file-vs-directory) is neither.
fn side_is_blob_or_absent(store: &ObjectStore, side: Option<Hash>) -> bool {
    match side {
        None => true,
        Some(h) => is_blob(store, h),
    }
}

/// `true` when a side's tree mode is a symlink or executable — shapes
/// that conflict markers cannot represent and that must round-trip their
/// exact mode (#214).
fn side_is_special_mode(mode: Option<EntryMode>) -> bool {
    matches!(mode, Some(EntryMode::Symlink | EntryMode::Executable))
}

/// Classify a single conflict given its blob contents.
///
/// # Errors
/// Propagates object-store read failures.
pub fn classify(store: &ObjectStore, c: &Conflict) -> Result<ConflictClass, String> {
    match c.kind {
        ConflictKind::DeleteModify => Ok(ConflictClass::DeleteModify),
        ConflictKind::ModifyModify | ConflictKind::AddAdd => {
            // File-vs-directory: one side is a tree. Markers are unsafe;
            // route to Special (the blob side is left in the worktree).
            if !side_is_blob_or_absent(store, c.ours_hash)
                || !side_is_blob_or_absent(store, c.theirs_hash)
            {
                return Ok(ConflictClass::Special);
            }
            // Symlink / executable on either side (#214): the merge
            // engine now carries the real `EntryMode`, so we route these
            // to Special unambiguously instead of guessing from bytes.
            // Writing conflict markers into a symlink target is
            // meaningless, and an executable's content is rarely a clean
            // text merge — the user resolves manually and the ours-side
            // mode is preserved into the worktree + index.
            if side_is_special_mode(c.ours_mode) || side_is_special_mode(c.theirs_mode) {
                return Ok(ConflictClass::Special);
            }
            // Otherwise fall back to the byte heuristic: any non-UTF-8 /
            // NUL-bearing side is binary; everything else is text.
            let ours_text = match c.ours_hash {
                Some(h) => is_text(&read_blob(store, h)?),
                None => true,
            };
            let theirs_text = match c.theirs_hash {
                Some(h) => is_text(&read_blob(store, h)?),
                None => true,
            };
            if ours_text && theirs_text {
                Ok(ConflictClass::TextMarkers)
            } else {
                Ok(ConflictClass::Binary)
            }
        }
    }
}

/// Materialise every conflict into the worktree and stage the ours-side
/// blob into the index so each conflicting path is "resolvable":
///
/// - **text**: write `<<<<<<< ours / ======= / >>>>>>> theirs` markers.
/// - **binary / special / delete-modify**: leave the surviving content
///   in the worktree, print a per-path manual-resolution note.
///
/// The index entry for each path is set to the ours-side blob (or
/// removed for an ours-deleted delete/modify) so a subsequent
/// `mkit add` after resolution updates it normally and `--continue`
/// builds the tree from the resolved index/worktree.
///
/// `merged_tree` is the operation's full merge-result tree (holding
/// "ours" at every conflicted path and the clean changes everywhere
/// else). It is applied to the index + worktree FIRST — otherwise the
/// non-conflicting changes would never reach the index and `--continue`
/// (which builds from the index) would silently drop them (#269). The
/// caller runs [`super::ensure_restore_safe`] over `merged_tree` first,
/// so this never clobbers dirty tracked or untracked content. Conflict
/// markers are then overlaid on the conflicted paths.
///
/// Returns the per-path [`ConflictRecord`]s for the sidecar.
///
/// # Errors
/// Propagates store / filesystem failures as a message string.
pub fn materialize_conflicts(
    root: &Path,
    store: &ObjectStore,
    merged_tree: Hash,
    conflicts: &[Conflict],
) -> Result<Vec<ConflictRecord>, String> {
    // Apply the merged result (clean changes + "ours" at conflict paths)
    // to the index and worktree, then overlay markers below.
    super::restore_worktree_and_index(root, store, merged_tree)?;
    let mut idx = index::read_index(root).map_err(|e| format!("read index: {e}"))?;
    let mut records = Vec::with_capacity(conflicts.len());
    let mut stderr = std::io::stderr().lock();

    for c in conflicts {
        let class = classify(store, c)?;
        let abs = root.join(&c.path);
        match class {
            ConflictClass::TextMarkers => {
                let ours = match c.ours_hash {
                    Some(h) => read_blob(store, h)?,
                    None => Vec::new(),
                };
                let theirs = match c.theirs_hash {
                    Some(h) => read_blob(store, h)?,
                    None => Vec::new(),
                };
                write_text_markers(&abs, &ours, &theirs)?;
                let _ = writeln!(stderr, "  {} (text conflict — edit markers)", c.path);
                stage_ours(&mut idx, store, c);
            }
            ConflictClass::Binary => {
                materialize_conflict_side(store, &abs, c)?;
                let _ = writeln!(
                    stderr,
                    "  {} (binary conflict — resolve manually, then `mkit add`)",
                    c.path
                );
                stage_ours(&mut idx, store, c);
            }
            ConflictClass::DeleteModify => {
                // Keep the surviving (modified) side in the worktree,
                // honouring its exec/symlink mode (#214).
                materialize_conflict_side(store, &abs, c)?;
                let _ = writeln!(
                    stderr,
                    "  {} (delete/modify — keep with `mkit add` or drop with `mkit rm`)",
                    c.path
                );
                stage_ours(&mut idx, store, c);
            }
            ConflictClass::Special => {
                materialize_conflict_side(store, &abs, c)?;
                let _ = writeln!(
                    stderr,
                    "  {} (mode/symlink conflict — resolve manually, then `mkit add`)",
                    c.path
                );
                stage_ours(&mut idx, store, c);
            }
        }
        records.push(ConflictRecord::from(c));
    }

    index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))?;
    Ok(records)
}

/// Map a tree [`EntryMode`] to the index [`EntryStatus`] that preserves
/// it. `Tree` has no single-file index representation and is reported by
/// the caller (which only stages blob ours-sides), so it falls back to
/// `Blob` defensively.
fn status_for_mode(mode: EntryMode) -> EntryStatus {
    match mode {
        EntryMode::Executable => EntryStatus::Executable,
        EntryMode::Symlink => EntryStatus::Symlink,
        EntryMode::Blob | EntryMode::Tree => EntryStatus::Blob,
    }
}

/// Stage the ours-side blob for a conflict into the index (or mark
/// removed when ours deleted it). Keeps the index a single-stage
/// resolved snapshot.
///
/// The ours-side [`EntryMode`] carried on the [`Conflict`] (#214) is
/// preserved into the staged [`EntryStatus`] so executable bits and
/// symlinks survive `--continue` across merge / cherry-pick / rebase —
/// `build_tree_from_index` derives the committed tree mode from the
/// index status, so a default-`Blob` here would silently demote an
/// executable or symlink to a plain file.
fn stage_ours(idx: &mut mkit_core::index::Index, store: &ObjectStore, c: &Conflict) {
    let entry = match c.ours_hash {
        // Only stage a blob ours-side. A tree ours-side (file-vs-dir)
        // is left for the user to resolve and `mkit add`.
        Some(h) if is_blob(store, h) => IndexEntry {
            path: c.path.clone(),
            status: c.ours_mode.map_or(EntryStatus::Blob, status_for_mode),
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        },
        Some(_) => return,
        None => IndexEntry {
            path: c.path.clone(),
            status: EntryStatus::Removed,
            object_hash: mkit_core::hash::ZERO,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        },
    };
    if let Some(pos) = idx.find_entry(&c.path) {
        idx.entries[pos] = entry;
    } else {
        idx.entries.push(entry);
    }
}

fn write_text_markers(abs: &Path, ours: &[u8], theirs: &[u8]) -> Result<(), String> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MARK_OURS.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(ours);
    if !ours.is_empty() && ours.last() != Some(&b'\n') {
        buf.push(b'\n');
    }
    buf.extend_from_slice(MARK_SEP.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(theirs);
    if !theirs.is_empty() && theirs.last() != Some(&b'\n') {
        buf.push(b'\n');
    }
    buf.extend_from_slice(MARK_THEIRS.as_bytes());
    buf.push(b'\n');
    write_bytes(abs, &buf)
}

/// Materialise the surviving side of a binary / special conflict into
/// the worktree, honouring its tree mode (#214).
///
/// We prefer the ours-side (the side `stage_ours` records in the index)
/// so the worktree file and the staged index entry agree; if ours is
/// absent or a tree we fall back to theirs. Symlink sides become a real
/// symlink (not a regular file holding the target text); executable
/// sides get the exec bit. If neither side is a blob, whatever is
/// already in the worktree is left untouched.
fn materialize_conflict_side(store: &ObjectStore, abs: &Path, c: &Conflict) -> Result<(), String> {
    let pick = [(c.ours_hash, c.ours_mode), (c.theirs_hash, c.theirs_mode)]
        .into_iter()
        .find_map(|(h, m)| match h {
            Some(h) if is_blob(store, h) => Some((h, m)),
            _ => None,
        });
    let Some((h, mode)) = pick else {
        return Ok(());
    };
    match mode {
        Some(EntryMode::Symlink) => write_symlink_to_worktree(store, abs, h),
        Some(EntryMode::Executable) => write_blob_to_worktree(store, abs, h, true),
        _ => write_blob_to_worktree(store, abs, h, false),
    }
}

fn write_blob_to_worktree(
    store: &ObjectStore,
    abs: &Path,
    h: Hash,
    executable: bool,
) -> Result<(), String> {
    let data = read_blob(store, h)?;
    // Replace any existing symlink/file at the path so a prior shape
    // does not shadow the regular file we are about to write.
    let _ = fs::remove_file(abs);
    write_bytes(abs, &data)?;
    if executable {
        set_executable(abs)?;
    }
    Ok(())
}

/// Materialise a symlink blob (payload = target string) as a real
/// symlink, mirroring `restore::restore_symlink`'s `..`-free target
/// validation so a conflict cannot smuggle an escaping link.
fn write_symlink_to_worktree(store: &ObjectStore, abs: &Path, h: Hash) -> Result<(), String> {
    let data = read_blob(store, h)?;
    let target = core::str::from_utf8(&data)
        .map_err(|_| format!("symlink target for {} is not UTF-8", abs.display()))?;
    if !mkit_core::worktree::validate_symlink_target(target) {
        return Err(format!(
            "refusing to materialise unsafe symlink target {target:?} for {}",
            abs.display()
        ));
    }
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    // Remove any existing file/symlink so the create does not race a
    // stale entry of the wrong shape.
    let _ = fs::remove_file(abs);
    create_symlink(target, abs).map_err(|e| format!("create symlink {}: {e}", abs.display()))
}

#[cfg(unix)]
fn set_executable(abs: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(abs)
        .map_err(|e| format!("stat {}: {e}", abs.display()))?
        .permissions();
    perm.set_mode(0o755);
    fs::set_permissions(abs, perm).map_err(|e| format!("chmod {}: {e}", abs.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_executable(_abs: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &str, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &str, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink creation is not supported on this target",
    ))
}

fn write_bytes(abs: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    fs::write(abs, data).map_err(|e| format!("write {}: {e}", abs.display()))
}

/// Pre-abort safety gate: refuse the abort *before* it mutates anything
/// when restoring to `target_tree` would overwrite genuine user work on
/// a path that is **not** part of the recorded conflict set.
///
/// `--abort` works by first resetting the conflict paths (discarding the
/// conflict material mkit itself wrote) and then doing a guarded restore
/// to the pre-op tree. The conflict-path reset is destructive, so it
/// must not run if the abort is going to be refused anyway: otherwise a
/// failed abort would silently throw away the user's in-progress
/// resolution of the conflicting files while leaving operation state in
/// place. This check inspects only the non-conflict paths (the conflict
/// paths are expected to be dirty — they hold markers / partial edits)
/// and mirrors [`super::ensure_restore_safe`]'s staged / unstaged /
/// untracked-collision detection for them.
///
/// # Errors
/// Returns a message describing the blocking path when the abort would
/// be unsafe, or propagates store / filesystem failures.
pub fn ensure_abort_safe(
    root: &Path,
    store: &ObjectStore,
    records: &[ConflictRecord],
    target_tree: Hash,
    op_result_tree: Option<Hash>,
) -> Result<(), String> {
    use std::collections::HashSet;

    let current_tree = super::current_head_tree(root, store)?;
    let idx = super::read_or_seed_index_from_head(root, store)?;
    // Safety-check snapshot trees are ephemeral — in-memory overlay.
    let snapshot = mkit_core::store::EphemeralSink::new(store);
    let index_tree = mkit_core::worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("check index state: {e}"))?;

    // Paths the aborting operation itself authored are discardable, not user
    // work: the recorded conflict paths PLUS every path the operation changed
    // vs the pre-op HEAD (its clean hunks — e.g. a file the merge added
    // without conflict). With the result tree we derive the latter; without
    // it (legacy state) we fall back to the conflict records alone.
    let conflict_paths: HashSet<String> = records.iter().map(|r| r.path.clone()).collect();
    let mut discardable = conflict_paths;
    if let Some(result_tree) = op_result_tree {
        let authored =
            mkit_core::ops::diff::diff_trees(&snapshot, current_tree, Some(result_tree))
                .map_err(|e| format!("check operation changes: {e}"))?;
        for e in authored.entries {
            discardable.insert(e.path);
        }
    }
    let is_discardable = |p: &str| discardable.contains(p);

    // Staged changes on a non-conflict path.
    let staged = mkit_core::ops::diff::diff_trees(&snapshot, current_tree, Some(index_tree))
        .map_err(|e| format!("check staged changes: {e}"))?;
    if let Some(entry) = staged.entries.iter().find(|e| !is_discardable(&e.path)) {
        return Err(format!(
            "abort would overwrite staged changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    // Unstaged worktree edits on a non-conflict path. Pass the seeded index
    // as the tracked set so a tracked file matching an ignore rule isn't
    // dropped from the snapshot and misread as a deletion.
    let worktree_tree = mkit_core::worktree::build_tree_filtered(&snapshot, root, Some(&idx))
        .map_err(|e| format!("check worktree: {e}"))?;
    let unstaged =
        mkit_core::ops::diff::diff_trees(&snapshot, Some(index_tree), Some(worktree_tree))
            .map_err(|e| format!("check worktree: {e}"))?;
    if let Some(entry) = unstaged
        .entries
        .iter()
        .find(|e| e.kind != mkit_core::ops::diff::DiffKind::Added && !is_discardable(&e.path))
    {
        return Err(format!(
            "abort would overwrite local changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    // Untracked path that collides with a non-conflict path the restore
    // would write.
    let target_writes: Vec<String> =
        mkit_core::ops::diff::diff_trees(&snapshot, Some(index_tree), Some(target_tree))
            .map_err(|e| format!("check restore target: {e}"))?
            .entries
            .into_iter()
            .filter(|e| e.kind != mkit_core::ops::diff::DiffKind::Removed)
            .filter(|e| !is_discardable(&e.path))
            .map(|e| e.path)
            .collect();
    if !target_writes.is_empty() {
        for entry in &unstaged.entries {
            if entry.kind == mkit_core::ops::diff::DiffKind::Added
                && !is_discardable(&entry.path)
                && target_writes.iter().any(|t| t == &entry.path)
            {
                return Err(format!(
                    "abort would overwrite untracked path '{}'; move or remove it first",
                    entry.path
                ));
            }
        }
    }
    Ok(())
}

/// Discard conflict material on the recorded conflict paths, resetting
/// each back to its content in `target_tree` (the pre-op HEAD): write
/// the target blob into the worktree (or delete the file when the path
/// is absent from `target_tree`) and align the index entry.
///
/// This is the abort precondition: after it runs, the worktree and
/// index agree with `target_tree` on every conflict path, so the
/// subsequent guarded restore sees no spurious "local changes" on the
/// paths we ourselves mutated — while still protecting genuinely
/// unrelated dirty/untracked paths.
///
/// # Errors
/// Propagates store / filesystem failures.
pub fn reset_conflict_paths(
    root: &Path,
    store: &ObjectStore,
    records: &[ConflictRecord],
    target_tree: Hash,
    op_result_tree: Option<Hash>,
) -> Result<(), String> {
    use std::collections::{BTreeSet, HashMap};

    // Flatten the target tree into path → (mode, hash).
    let target_idx =
        index::from_tree(store, target_tree).map_err(|e| format!("read target tree: {e}"))?;
    let target_map: HashMap<&str, &IndexEntry> = target_idx
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    // Reset every path the operation authored: the recorded conflict paths
    // PLUS the operation's clean hunks (paths it changed vs the pre-op HEAD).
    // The reset is purely target-content driven, so it generalizes from
    // conflict records to any operation-authored path.
    let mut paths: BTreeSet<String> = records.iter().map(|r| r.path.clone()).collect();
    if let Some(result_tree) = op_result_tree {
        let snapshot = mkit_core::store::EphemeralSink::new(store);
        let authored =
            mkit_core::ops::diff::diff_trees(&snapshot, Some(target_tree), Some(result_tree))
                .map_err(|e| format!("check operation changes: {e}"))?;
        for e in authored.entries {
            paths.insert(e.path);
        }
    }

    let mut idx = super::read_or_seed_index_from_head(root, store)?;

    for path in &paths {
        let abs = root.join(path);
        if let Some(target_entry) = target_map.get(path.as_str()) {
            // Restore the path's pre-op content + index entry, honouring
            // the recorded symlink/exec mode (#214).
            match target_entry.status {
                EntryStatus::Symlink => {
                    write_symlink_to_worktree(store, &abs, target_entry.object_hash)?;
                }
                EntryStatus::Executable => {
                    write_blob_to_worktree(store, &abs, target_entry.object_hash, true)?;
                }
                _ => write_blob_to_worktree(store, &abs, target_entry.object_hash, false)?,
            }
            let entry = (*target_entry).clone();
            if let Some(pos) = idx.find_entry(path) {
                idx.entries[pos] = entry;
            } else {
                idx.entries.push(entry);
            }
        } else {
            // Path did not exist pre-op: remove the worktree file and
            // drop it from the index.
            if let Err(e) = fs::remove_file(&abs)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(format!("remove {}: {e}", abs.display()));
            }
            if let Some(pos) = idx.find_entry(path) {
                idx.entries.remove(pos);
            }
        }
    }
    index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))?;
    Ok(())
}

/// Scan the worktree files listed in `records` for leftover conflict
/// markers. Returns the first path that still contains markers, if any.
///
/// Only text-marker conflicts are scanned; binary/special paths are
/// resolved out-of-band and are not marker-bearing.
///
/// # Errors
/// Propagates filesystem read failures.
/// `true` when `meta` has any executable bit set (Unix). On other
/// platforms mkit never records `Executable`, so this is always false.
#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The canonical `(EntryStatus, Hash)` for the current worktree state at
/// `abs`, mirroring exactly how `mkit add` would stage it (regular →
/// Blob/Executable + `store_file_object`; symlink → Symlink + blob of the
/// link target). `None` when the path is absent or a directory — neither
/// has a single-file index representation.
///
/// # Errors
/// Read/store failures as a message string.
fn worktree_object(store: &ObjectStore, abs: &Path) -> Result<Option<(EntryStatus, Hash)>, String> {
    let meta = match abs.symlink_metadata() {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("stat {}: {e}", abs.display())),
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target =
            std::fs::read_link(abs).map_err(|e| format!("read link {}: {e}", abs.display()))?;
        let target_str = target
            .to_str()
            .ok_or_else(|| format!("symlink target not UTF-8: {}", abs.display()))?;
        let h = worktree::store_file_object(store, target_str.as_bytes())
            .map_err(|e| format!("store symlink: {e}"))?;
        return Ok(Some((EntryStatus::Symlink, h)));
    }
    if ft.is_file() {
        let (opened, bytes) = worktree::read_regular_file_bounded(abs)
            .map_err(|e| format!("read {}: {e}", abs.display()))?;
        let h = worktree::store_file_object(store, &bytes).map_err(|e| format!("store: {e}"))?;
        let status = if is_executable(&opened) {
            EntryStatus::Executable
        } else {
            EntryStatus::Blob
        };
        return Ok(Some((status, h)));
    }
    Ok(None) // directory or other special file
}

/// Refuse `--continue` when a conflicted path's worktree resolution does
/// not match what is staged in the index. The final tree is built from
/// the index, so any unstaged resolution would be silently dropped and
/// then overwritten by the worktree restore (#269).
///
/// This compares the worktree's canonical `(status, hash)` against the
/// staged index entry, so it catches every shape of unstaged resolution:
/// an edited regular **or executable** file, a path deleted/replaced
/// (file→symlink, file→dir) without `mkit rm`/`mkit add`, etc. An
/// *unchanged* conflict (worktree still equals the staged ours-side,
/// including its exec/symlink mode) matches and continues without a
/// re-`add` — preserving the #214 mode-resolution contract.
///
/// # Errors
/// Returns a message naming the first unstaged-resolution path.
pub fn ensure_conflict_paths_staged(
    root: &Path,
    store: &ObjectStore,
    records: &[ConflictRecord],
) -> Result<(), String> {
    let idx = index::read_index(root).map_err(|e| format!("read index: {e}"))?;
    for r in records {
        let wt = worktree_object(store, &root.join(&r.path))?;
        // The staged entry for this path (if any). A `Removed` entry means
        // "ours deleted it"; absence means no staged content.
        let staged = idx.entries.iter().find(|e| e.path == r.path);
        let staged_live = staged.filter(|e| e.status != EntryStatus::Removed);
        let resolved = match (&wt, staged_live) {
            // Worktree gone (deleted/dir) and nothing live staged → the
            // deletion is recorded; consistent.
            (None, None) => true,
            // Worktree content matches the live staged entry exactly
            // (content + mode) → resolved (incl. the unchanged #214 case).
            (Some((ws, wh)), Some(e)) => *ws == e.status && *wh == e.object_hash,
            // Worktree has content but nothing live staged, or worktree
            // gone while content is still staged → unstaged resolution.
            (Some(_), None) | (None, Some(_)) => false,
        };
        if !resolved {
            return Err(format!(
                "'{0}' is resolved in the worktree but not staged; run `mkit add {0}` (or `mkit rm {0}`) then `--continue`",
                r.path
            ));
        }
    }
    Ok(())
}

pub fn first_unresolved_marker(
    root: &Path,
    records: &[ConflictRecord],
) -> Result<Option<String>, String> {
    for r in records {
        let abs = root.join(&r.path);
        let data = match fs::read(&abs) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", abs.display())),
        };
        if file_has_markers(&data) {
            return Ok(Some(r.path.clone()));
        }
    }
    Ok(None)
}

fn file_has_markers(data: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(data) else {
        return false;
    };
    let mut saw_ours = false;
    let mut saw_sep = false;
    let mut saw_theirs = false;
    for line in text.lines() {
        if line == MARK_OURS {
            saw_ours = true;
        } else if line == MARK_SEP {
            saw_sep = true;
        } else if line == MARK_THEIRS {
            saw_theirs = true;
        }
    }
    saw_ours && saw_sep && saw_theirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_complete_marker_set() {
        let data = b"<<<<<<< ours\nfoo\n=======\nbar\n>>>>>>> theirs\n";
        assert!(file_has_markers(data));
    }

    #[test]
    fn ignores_partial_markers() {
        let data = b"<<<<<<< ours\nfoo\n";
        assert!(!file_has_markers(data));
    }

    #[test]
    fn clean_file_has_no_markers() {
        let data = b"just some resolved content\n";
        assert!(!file_has_markers(data));
    }

    #[test]
    fn text_detection() {
        assert!(is_text(b"hello world\n"));
        assert!(!is_text(b"\x00\x01\x02binary"));
        assert!(!is_text(&[0xff, 0xfe, 0xfd]));
    }
}
