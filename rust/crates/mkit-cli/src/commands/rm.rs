//! `mkit rm <pathspec>...` — remove paths from the worktree and stage
//! the deletion for the next commit.
//!
//! Mirrors `git rm`:
//!
//! - default — stage the deletion AND delete the worktree file(s);
//! - `--cached` — stage the deletion only, leaving the worktree intact;
//! - `-r/--recursive` — required to remove a directory's entries;
//! - `-f/--force` — override the safety guard that refuses to destroy a
//!   tracked file whose worktree content differs from the staged blob.
//!
//! Multiple pathspecs may be given. The safety guard reuses the same
//! "don't clobber user work" spirit as the #176 restore guards: a
//! tracked-but-modified file is not deleted without `--force`.

use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::hash::ZERO;
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit rm",
    about = "Remove paths from the worktree and stage their deletion."
)]
struct RmOpts {
    /// Keep the worktree file(s); only stage the removal in the index.
    /// This is the historical mkit behaviour.
    #[arg(long)]
    cached: bool,

    /// Allow removing a directory and everything under it.
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Remove worktree files even when they differ from the staged
    /// blob (otherwise modified files are refused to avoid data loss).
    #[arg(short = 'f', long)]
    force: bool,

    /// Paths to remove. A directory path removes every entry at or
    /// below it (requires `-r`).
    #[arg(required = true)]
    paths: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RmOpts>("mkit rm", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let mut idx = match super::read_or_seed_index_from_head(&layout, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // Resolve every pathspec up front and gather the set of tracked
    // index paths each one matches. A pathspec matching more than one
    // entry (or being itself a directory) requires `-r`.
    let mut targets: Vec<(String, Vec<usize>)> = Vec::new();
    for raw in &opts.paths {
        let rel = match super::index_path_for_arg(&cwd, Path::new(raw)) {
            Ok(p) => p,
            Err(e) => return emit_err(&e, exit::DATAERR),
        };
        let matches: Vec<usize> = idx
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.status != EntryStatus::Removed
                    && super::index_path_matches_or_descends(&e.path, &rel)
            })
            .map(|(i, _)| i)
            .collect();

        if matches.is_empty() {
            return emit_err(
                &format!("pathspec '{raw}' did not match any tracked files"),
                exit::GENERAL_ERROR,
            );
        }
        // A pathspec that resolves to a strict descendant (i.e. it names
        // a directory, not an exact tracked file) needs --recursive.
        let names_dir = !idx
            .entries
            .iter()
            .any(|e| e.status != EntryStatus::Removed && e.path == rel);
        if names_dir && !opts.recursive {
            return emit_err(
                &format!("not removing '{raw}' recursively without -r"),
                exit::GENERAL_ERROR,
            );
        }
        targets.push((rel, matches));
    }

    // Safety pass (unless --force): refuse to destroy a worktree file
    // whose content diverges from the staged blob. Skipped for
    // --cached, which never touches the worktree.
    if !opts.force && !opts.cached {
        for (_, matches) in &targets {
            for &i in matches {
                if let Some(reason) = dirty_reason(&cwd, &store, &idx.entries[i]) {
                    return emit_err(&reason, exit::GENERAL_ERROR);
                }
            }
        }
    }

    // Mutation pass: delete worktree files (unless --cached) then mark
    // the index entries Removed.
    let mut all_matches: Vec<usize> = targets
        .iter()
        .flat_map(|(_, m)| m.iter().copied())
        .collect();
    all_matches.sort_unstable();
    all_matches.dedup();

    if !opts.cached
        && let Err(e) = remove_worktree_paths(&cwd, &idx, &all_matches)
    {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    for &i in &all_matches {
        idx.entries[i].status = EntryStatus::Removed;
        idx.entries[i].object_hash = ZERO;
    }

    match index::write_index(&layout, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

/// Return `Some(reason)` when the worktree file backing `entry` exists
/// but differs from the staged blob — the case `git rm` refuses without
/// `-f`. Returns `None` when the file is clean, absent, or a symlink
/// whose hashing we treat the same as a regular blob.
fn dirty_reason(root: &Path, store: &ObjectStore, entry: &IndexEntry) -> Option<String> {
    let abs = root.join(&entry.path);
    let meta = abs.symlink_metadata().ok()?;
    // Compute the worktree object hash the same way `add` would.
    let work_hash = if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&abs).ok()?;
        let target_str = target.to_str()?;
        symlink_blob_hash(target_str)?
    } else if meta.file_type().is_file() {
        let clean = worktree::read_regular_file_bounded(&abs)
            .ok()
            .and_then(|(opened, data)| {
                if super::file_exec_status(&opened) != entry.status {
                    return Some(false);
                }
                worktree::content_eq_bytes(store, &entry.object_hash, &data).ok()
            })
            .unwrap_or(false);
        return if clean {
            None
        } else {
            Some(format!(
                "'{}' has local modifications or unreadable staged content; use --cached to keep it, or --force to discard them",
                entry.path
            ))
        };
    } else {
        return None;
    };
    if entry.status == EntryStatus::Symlink && work_hash == entry.object_hash {
        None
    } else {
        Some(format!(
            "'{}' has local modifications; use --cached to keep it, or --force to discard them",
            entry.path
        ))
    }
}

/// Hash a symlink target as a blob (matching `worktree`/`add` semantics)
/// so the dirty-check compares like-for-like with the index entry.
fn symlink_blob_hash(target: &str) -> Option<mkit_core::hash::Hash> {
    // Pure content-addressing — change detection must not write to the
    // store. Byte layout pinned to serialize() via blob_prologue.
    let prologue = mkit_core::serialize::blob_prologue(target.len()).ok()?;
    let mut hasher = mkit_core::hash::Hasher::new();
    hasher.update(&prologue).update(target.as_bytes());
    Some(hasher.finalize())
}

/// Delete every worktree file named by the matched index entries, then
/// prune directories left empty by those deletions.
fn remove_worktree_paths(root: &Path, idx: &Index, matches: &[usize]) -> Result<(), String> {
    let mut dirs_to_prune: Vec<PathBuf> = Vec::new();
    for &i in matches {
        let rel = &idx.entries[i].path;
        let abs = root.join(rel);
        match std::fs::symlink_metadata(&abs) {
            Ok(_) => {
                std::fs::remove_file(&abs).map_err(|e| format!("remove {}: {e}", abs.display()))?;
            }
            // Already gone — treat as success (idempotent).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove {}: {e}", abs.display())),
        }
        if let Some(parent) = abs.parent() {
            dirs_to_prune.push(parent.to_path_buf());
        }
    }
    prune_empty_dirs(root, dirs_to_prune);
    Ok(())
}

/// Remove now-empty directories, walking upward toward `root` but never
/// removing `root` itself. Best-effort: non-empty dirs and errors stop
/// the upward walk for that branch.
fn prune_empty_dirs(root: &Path, mut dirs: Vec<PathBuf>) {
    // Deepest paths first so children are pruned before parents.
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    dirs.dedup();
    for dir in dirs {
        let mut cur = dir;
        while cur != root && cur.starts_with(root) {
            let is_empty = match std::fs::read_dir(&cur) {
                Ok(mut rd) => rd.next().is_none(),
                Err(_) => break,
            };
            if !is_empty || std::fs::remove_dir(&cur).is_err() {
                break;
            }
            match cur.parent() {
                Some(p) => cur = p.to_path_buf(),
                None => break,
            }
        }
    }
}

use super::error as emit_err;
