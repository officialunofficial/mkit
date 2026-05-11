//! `mkit add <path>` / `mkit add .` — stage a file (or the whole
//! worktree) into `.mkit/index`.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use mkit_core::hash::ZERO;
use mkit_core::ignore::{self, IgnoreList};
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::object::{Blob, Object};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::exit;

/// Refresh already-tracked index entries from the worktree.
///
/// This backs `mkit commit -a`: it mirrors Git's tracked-only shortcut
/// by updating modified tracked files and staging tracked deletions,
/// without adding untracked paths.
pub(super) fn stage_tracked_changes(root: &Path, store: &ObjectStore) -> Result<(), String> {
    let mut idx = super::read_or_seed_index_from_head(root, store)?;

    for entry in &mut idx.entries {
        if entry.status == EntryStatus::Removed {
            continue;
        }
        if !index::validate_index_path(&entry.path) {
            return Err(format!("invalid index path: {}", entry.path));
        }

        let abs = root.join(&entry.path);
        let meta = match abs.symlink_metadata() {
            Ok(meta) => meta,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                entry.status = EntryStatus::Removed;
                entry.object_hash = ZERO;
                continue;
            }
            Err(e) => return Err(format!("metadata {}: {e}", abs.display())),
        };

        let (status, bytes) = if meta.file_type().is_file() {
            let bytes = std::fs::read(&abs).map_err(|e| format!("read {}: {e}", abs.display()))?;
            (file_status_from_meta(&meta, entry.status), bytes)
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&abs)
                .map_err(|e| format!("read link {}: {e}", abs.display()))?;
            let target_str = target
                .to_str()
                .ok_or_else(|| "symlink target is not valid UTF-8".to_string())?;
            if !worktree::validate_symlink_target(target_str) {
                return Err(format!("invalid symlink target: {target_str}"));
            }
            (EntryStatus::Symlink, target_str.as_bytes().to_vec())
        } else {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
            continue;
        };

        let blob = Object::Blob(Blob { data: bytes });
        let ser = serialize::serialize(&blob).map_err(|e| format!("serialize: {e}"))?;
        let h = store.write(&ser).map_err(|e| format!("store: {e}"))?;
        entry.status = status;
        entry.object_hash = h;
    }

    index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))
}

#[cfg(unix)]
fn file_status_from_meta(meta: &std::fs::Metadata, _previous: EntryStatus) -> EntryStatus {
    use std::os::unix::fs::PermissionsExt;

    if meta.permissions().mode() & 0o111 != 0 {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

#[cfg(not(unix))]
fn file_status_from_meta(_meta: &std::fs::Metadata, previous: EntryStatus) -> EntryStatus {
    if previous == EntryStatus::Executable {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(target) = args.first() else {
        return super::usage_error("usage: mkit add <path> | .");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mut idx = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    if target == "." {
        let ignores = match ignore::load(&cwd) {
            Ok(i) => i,
            Err(e) => return emit_err(&format!(".mkitignore: {e}"), exit::GENERAL_ERROR),
        };
        let mut seen = HashSet::new();
        if let Err(code) = add_tree(&cwd, &cwd, &store, &mut idx, &ignores, &mut seen) {
            return code;
        }
        mark_missing_paths_removed(&cwd, &mut idx, &seen);
    } else {
        match add_one(&cwd, Path::new(target), &store, &mut idx) {
            Ok(_) => {}
            Err(code) => return code,
        }
    }
    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

fn add_one(root: &Path, rel: &Path, store: &ObjectStore, idx: &mut Index) -> Result<String, u8> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let meta = abs
        .symlink_metadata()
        .map_err(|e| emit_err(&format!("metadata {}: {e}", abs.display()), exit::NOINPUT))?;
    let (status, bytes) = if meta.file_type().is_file() {
        let bytes = std::fs::read(&abs)
            .map_err(|e| emit_err(&format!("read {}: {e}", abs.display()), exit::NOINPUT))?;
        (EntryStatus::Blob, bytes)
    } else if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&abs)
            .map_err(|e| emit_err(&format!("read link {}: {e}", abs.display()), exit::NOINPUT))?;
        let target_str = match target.to_str() {
            Some(t) => t.to_string(),
            None => return Err(emit_err("symlink target is not valid UTF-8", exit::DATAERR)),
        };
        if !worktree::validate_symlink_target(&target_str) {
            return Err(emit_err(
                &format!("invalid symlink target: {target_str}"),
                exit::DATAERR,
            ));
        }
        (EntryStatus::Symlink, target_str.into_bytes())
    } else {
        return Err(emit_err(
            &format!("not a regular file: {}", abs.display()),
            exit::NOINPUT,
        ));
    };
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(emit_err(&format!("invalid path: {rel_str}"), exit::DATAERR));
    }
    let blob = Object::Blob(Blob { data: bytes });
    let ser = serialize::serialize(&blob)
        .map_err(|e| emit_err(&format!("serialize: {e}"), exit::DATAERR))?;
    let h = store
        .write(&ser)
        .map_err(|e| emit_err(&format!("store: {e}"), exit::CANTCREAT))?;
    let entry = IndexEntry {
        path: rel_str.clone(),
        status,
        object_hash: h,
    };
    remove_file_directory_conflicts(idx, &entry.path);
    if let Some(existing) = idx.find_entry(&entry.path) {
        idx.entries[existing] = entry;
    } else {
        idx.entries.push(entry);
    }
    Ok(rel_str)
}

fn remove_file_directory_conflicts(idx: &mut Index, path: &str) {
    idx.entries.retain(|entry| {
        entry.path == path
            || (!super::index_path_descends_from(&entry.path, path)
                && !super::index_path_descends_from(path, &entry.path))
    });
}

fn add_tree(
    root: &Path,
    dir: &Path,
    store: &ObjectStore,
    idx: &mut Index,
    ignores: &IgnoreList,
    seen: &mut HashSet<String>,
) -> Result<(), u8> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| emit_err(&format!("read dir {}: {e}", dir.display()), exit::NOINPUT))?;
    for ent in rd.flatten() {
        let p = ent.path();
        let name = ent.file_name();
        let name_s = name.to_string_lossy();
        let meta = p
            .symlink_metadata()
            .map_err(|e| emit_err(&format!("metadata {}: {e}", p.display()), exit::NOINPUT))?;
        let is_dir = meta.file_type().is_dir();
        if ignores.is_ignored(&name_s, is_dir) {
            continue;
        }
        if meta.file_type().is_dir() {
            add_tree(root, &p, store, idx, ignores, seen)?;
        } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
            let rel = add_one(root, &p, store, idx)?;
            seen.insert(rel);
        }
    }
    Ok(())
}

fn mark_missing_paths_removed(root: &Path, idx: &mut Index, seen: &HashSet<String>) {
    for entry in &mut idx.entries {
        if entry.status != EntryStatus::Removed
            && !seen.contains(&entry.path)
            && matches!(
                root.join(&entry.path).symlink_metadata(),
                Err(e) if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                )
            )
        {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
        }
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
