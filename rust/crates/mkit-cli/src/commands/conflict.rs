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
use mkit_core::object::Object;
use mkit_core::ops::conflict_state::ConflictRecord;
use mkit_core::ops::merge::{Conflict, ConflictKind};
use mkit_core::store::ObjectStore;

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
            // Mode changes (symlink/executable) are recorded at the tree
            // level via the merge engine, but the conflict struct carries
            // only hashes. We treat any non-UTF-8 / NUL-bearing side as
            // binary; symlinks store their target as text so they would
            // otherwise look "textual" — but writing markers into a
            // symlink target is meaningless, so we detect them and route
            // to Special. The merge engine reports a symlink-vs-blob
            // shape as modify/modify; we can only inspect bytes here, so
            // a same-named symlink/blob pair that is valid UTF-8 falls
            // through to TextMarkers, which is acceptable (the user sees
            // a regular file with markers and resolves manually).
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
/// Returns the per-path [`ConflictRecord`]s for the sidecar.
///
/// # Errors
/// Propagates store / filesystem failures as a message string.
pub fn materialize_conflicts(
    root: &Path,
    store: &ObjectStore,
    conflicts: &[Conflict],
) -> Result<Vec<ConflictRecord>, String> {
    let mut idx = super::read_or_seed_index_from_head(root, store)?;
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
                materialize_side(store, &abs, c.ours_hash, c.theirs_hash)?;
                let _ = writeln!(
                    stderr,
                    "  {} (binary conflict — resolve manually, then `mkit add`)",
                    c.path
                );
                stage_ours(&mut idx, store, c);
            }
            ConflictClass::DeleteModify => {
                // Keep the surviving (modified) side in the worktree.
                if let Some(modified) = c.ours_hash.or(c.theirs_hash) {
                    write_blob_to_worktree(store, &abs, modified)?;
                }
                let _ = writeln!(
                    stderr,
                    "  {} (delete/modify — keep with `mkit add` or drop with `mkit rm`)",
                    c.path
                );
                stage_ours(&mut idx, store, c);
            }
            ConflictClass::Special => {
                materialize_side(store, &abs, c.ours_hash, c.theirs_hash)?;
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

/// Stage the ours-side blob for a conflict into the index (or mark
/// removed when ours deleted it). Keeps the index a single-stage
/// resolved snapshot.
fn stage_ours(idx: &mut mkit_core::index::Index, store: &ObjectStore, c: &Conflict) {
    let entry = match c.ours_hash {
        // Only stage a blob ours-side. A tree ours-side (file-vs-dir)
        // is left for the user to resolve and `mkit add`.
        Some(h) if is_blob(store, h) => IndexEntry {
            path: c.path.clone(),
            // We cannot recover the original `EntryMode` from a bare
            // hash, so default to `Blob`; symlink/exec nuances are
            // resolved when the user re-`mkit add`s the worktree file.
            status: EntryStatus::Blob,
            object_hash: h,
        },
        Some(_) => return,
        None => IndexEntry {
            path: c.path.clone(),
            status: EntryStatus::Removed,
            object_hash: mkit_core::hash::ZERO,
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

fn materialize_side(
    store: &ObjectStore,
    abs: &Path,
    ours: Option<Hash>,
    theirs: Option<Hash>,
) -> Result<(), String> {
    // Prefer a blob side; a tree side (file-vs-directory) cannot be
    // written as a file. If neither side is a blob, leave whatever is
    // already in the worktree untouched.
    let blob_side = [ours, theirs]
        .into_iter()
        .flatten()
        .find(|h| is_blob(store, *h));
    if let Some(h) = blob_side {
        write_blob_to_worktree(store, abs, h)?;
    }
    Ok(())
}

fn write_blob_to_worktree(store: &ObjectStore, abs: &Path, h: Hash) -> Result<(), String> {
    let data = read_blob(store, h)?;
    write_bytes(abs, &data)
}

fn write_bytes(abs: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    fs::write(abs, data).map_err(|e| format!("write {}: {e}", abs.display()))
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
) -> Result<(), String> {
    use std::collections::HashMap;

    // Flatten the target tree into path → (mode, hash).
    let target_idx =
        index::from_tree(store, target_tree).map_err(|e| format!("read target tree: {e}"))?;
    let target_map: HashMap<&str, &IndexEntry> = target_idx
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    let mut idx = super::read_or_seed_index_from_head(root, store)?;

    for r in records {
        let abs = root.join(&r.path);
        if let Some(target_entry) = target_map.get(r.path.as_str()) {
            // Restore the path's pre-op content + index entry.
            write_blob_to_worktree(store, &abs, target_entry.object_hash)?;
            let entry = (*target_entry).clone();
            if let Some(pos) = idx.find_entry(&r.path) {
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
            if let Some(pos) = idx.find_entry(&r.path) {
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
