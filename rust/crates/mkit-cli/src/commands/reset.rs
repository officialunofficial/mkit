//! `mkit reset [--soft|--mixed] [<commit>]` — move the current branch
//! (or detached HEAD) to `<commit>`, optionally resetting the index.
//!
//! Two modes, mirroring `git reset`'s safe subset:
//!
//! - **`--soft`** — move HEAD / the current branch only. The index and
//!   the worktree are left exactly as they are, so the difference between
//!   the old tip and the new target shows up as staged changes.
//! - **`--mixed`** (the default) — move HEAD *and* rewrite `.mkit/index`
//!   to mirror the target commit's tree. The worktree is untouched, so
//!   changes relative to the target appear as un-staged worktree edits.
//!
//! `<commit>` defaults to `HEAD` (a no-op move that still re-syncs the
//! index under `--mixed`) and is resolved through the shared revspec
//! resolver, so a branch, tag, `HEAD`, full/short hash, or `HEAD~n`/`^`
//! navigation all work.
//!
//! - **`--hard`** — move HEAD, reset the index to the target tree, AND
//!   reset the worktree to it (discarding tracked-file changes). Like
//!   git, untracked files are left in place. This is the one destructive
//!   variant, so it runs the same dirty/untracked guard as `checkout`
//!   (#176): it **refuses** to discard locally-modified or staged content
//!   unless `-f`/`--force` is given. That guard is an mkit safety
//!   divergence — git's `reset --hard` discards silently.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::restore::{RestoreOptions, restore_tree_to_worktree};
use mkit_core::ops::{DiffKind, diff_trees};
use mkit_core::refs::{self, Head, RefWriteCondition};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit reset",
    about = "Move HEAD (and, by default, the index) to a commit."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct ResetOpts {
    /// Move HEAD only; leave the index and worktree untouched.
    #[arg(long, conflicts_with = "mixed")]
    soft: bool,

    /// Move HEAD and reset the index to the target tree; leave the
    /// worktree untouched. This is the default.
    #[arg(long)]
    mixed: bool,

    /// Move HEAD, reset the index AND the worktree to the target tree
    /// (discarding tracked-file changes; untracked files are kept).
    /// Refuses to discard locally-modified/staged content without `-f`.
    #[arg(long, conflicts_with_all = ["soft", "mixed"])]
    hard: bool,

    /// With `--hard`, discard locally-modified or staged content instead
    /// of refusing (the mkit safety guard). No effect without `--hard`.
    #[arg(short = 'f', long)]
    force: bool,

    /// Commit to reset to (branch, tag, HEAD, full/short hash, `HEAD~n`,
    /// `^`). Defaults to `HEAD`.
    target: Option<String>,
}

#[must_use]
#[allow(clippy::too_many_lines)] // linear flow over the soft/mixed/hard modes
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ResetOpts>("mkit reset", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // --soft = HEAD only; --mixed (default) and --hard also reset the
    // index; --hard additionally resets the worktree.
    let reset_index = !opts.soft;

    let spec = opts.target.as_deref().unwrap_or("HEAD");
    let target = match super::revspec::resolve_revision(&store, &mkit_dir, spec) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!("no such commit: {spec} ({e})"),
                exit::GENERAL_ERROR,
            );
        }
    };

    // The target must be a commit/remix; we need its tree for --mixed and
    // we refuse to point HEAD at a bare tree/blob.
    let tree_hash = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return emit_err(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&target, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read target commit: {e}"), exit::GENERAL_ERROR),
    };

    // --hard is the one destructive variant: it overwrites the worktree.
    // `clean = false` so the guard/restore KEEP untracked files (git
    // `reset --hard` leaves them); we delete dropped *tracked* files
    // ourselves below.
    let restore_opts = RestoreOptions {
        clean: false,
        sparse_patterns: None,
    };

    // For --hard, capture the tracked paths the target DROPS — each with
    // its current index blob hash — computed from the current index BEFORE
    // it is re-synced. `clean = false` won't delete these, so we remove
    // them ourselves; the hashes let the guard below detect local edits to
    // ignored-but-tracked files that the shared guard cannot see.
    let hard_removed: Vec<(String, Hash)> = if opts.hard {
        match dropped_tracked_paths(&cwd, &store, tree_hash) {
            Ok(p) => p,
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        }
    } else {
        Vec::new()
    };

    // Guard BEFORE any mutation, unless `-f`. The shared `checkout` guard
    // refuses if discarding would lose locally-modified, staged, or
    // colliding-untracked content — an mkit safety divergence (git's
    // `reset --hard` discards silently). That guard compares the worktree
    // via `worktree::build_tree`, which honors `.mkitignore`, so it cannot
    // see a tracked file that matches an ignore pattern; check the dropped
    // paths directly so a locally-modified ignored-but-tracked file is not
    // discarded silently.
    if opts.hard && !opts.force {
        if let Err(e) =
            super::ensure_restore_safe_with_options(&cwd, &store, tree_hash, &restore_opts)
        {
            return emit_err(
                &format!("{e}\nhint: use `mkit reset --hard -f` to discard these changes"),
                exit::GENERAL_ERROR,
            );
        }
        if let Some(path) = locally_modified_dropped_path(&cwd, &store, &hard_removed) {
            return emit_err(
                &format!(
                    "reset --hard would discard local changes to '{path}'\n\
                     hint: use `mkit reset --hard -f` to discard these changes"
                ),
                exit::GENERAL_ERROR,
            );
        }
    }

    // If reset moves the branch off its current tip, that old tip may
    // become unreachable — record it BEFORE the move (under the worktree
    // lock) so it stays recoverable, and abort if the log can't be
    // written. Fail closed: an unreadable/corrupt current ref
    // (`resolve_head` Err) aborts rather than letting `move_head` clobber
    // it unlogged. `Ok(None)` is an unborn branch (nothing to supersede);
    // a no-op move (old == target) records nothing.
    match refs::resolve_head(&mkit_dir) {
        Ok(Some(old_head)) if old_head != target => {
            let branch = super::head_branch_name(&mkit_dir);
            if let Err((msg, code)) =
                super::record_superseded(&mkit_dir, "reset", &branch, old_head)
            {
                return emit_err(&msg, code);
            }
        }
        Ok(_) => {}
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
    }

    // Move HEAD / the current branch FIRST. As in `checkout`, advancing
    // the ref before the index keeps the failure modes benign: a later
    // index-write failure leaves HEAD on the target with a stale index,
    // which `mkit status` surfaces and a re-run repairs.
    if let Err((msg, code)) = move_head(&mkit_dir, &target) {
        return emit_err(&msg, code);
    }

    if reset_index && let Err(e) = super::sync_index_to_tree(&cwd, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }

    // --hard: materialize the target tree into the worktree (overwriting
    // tracked files, keeping untracked ones), then delete the tracked
    // files the target dropped.
    if opts.hard {
        if let Err(e) = restore_tree_to_worktree(&store, &tree_hash, &cwd, &restore_opts) {
            return emit_err(&format!("reset worktree: {e}"), exit::CANTCREAT);
        }
        for (path, _) in &hard_removed {
            if let Err(e) = remove_dropped_path(&cwd.join(path)) {
                return emit_err(
                    &format!("reset worktree: remove {path}: {e}"),
                    exit::CANTCREAT,
                );
            }
        }
    }

    let mut stderr = std::io::stderr().lock();
    let mode = if opts.hard {
        "hard"
    } else if reset_index {
        "mixed"
    } else {
        "soft"
    };
    let _ = writeln!(
        stderr,
        "reset ({mode}) to {}",
        format::short_hash(&target, 8)
    );
    exit::OK
}

/// Point the current branch (or detached HEAD) at `target`. Routes branch
/// moves through the history-recording ref helper so a `history-mmr`
/// build journals the move; detached HEAD is rewritten directly.
fn move_head(mkit_dir: &std::path::Path, target: &Hash) -> Result<(), (String, u8)> {
    let head = refs::read_head(mkit_dir).map_err(|e| (format!("read HEAD: {e}"), exit::DATAERR))?;
    match head {
        Head::Branch(name) => {
            super::write_ref_recording_history(mkit_dir, &name, RefWriteCondition::Any, target)
                .map_err(|e| (format!("write ref: {e}"), exit::CANTCREAT))
        }
        Head::Detached(_) => refs::write_head_detached(mkit_dir, target)
            .map_err(|e| (format!("update HEAD: {e}"), exit::CANTCREAT)),
    }
}

/// Tracked paths present in the current index but absent from the target
/// tree, each paired with its current index blob hash — for `--hard` these
/// worktree files are deleted (git removes tracked files the target drops;
/// `restore_tree_to_worktree` with `clean = false` writes/overwrites but
/// never deletes). The hash lets the caller detect local edits.
fn dropped_tracked_paths(
    cwd: &std::path::Path,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<Vec<(String, Hash)>, String> {
    let idx = super::read_or_seed_index_from_head(cwd, store)?;
    let index_tree =
        worktree::build_tree_from_index(store, &idx).map_err(|e| format!("index tree: {e}"))?;
    let removed = diff_trees(store, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("diff index vs target: {e}"))?
        .entries
        .into_iter()
        .filter(|e| e.kind == DiffKind::Removed)
        .filter_map(|e| e.old_hash.map(|h| (e.path, h)))
        .collect();
    Ok(removed)
}

/// The first dropped path whose worktree file differs from its indexed
/// blob (a local edit), or `None` if every dropped file is unmodified /
/// already gone. Used to guard `reset --hard` against silently discarding
/// edits to tracked files that match `.mkitignore` (which the shared
/// guard's `build_tree` comparison skips).
fn locally_modified_dropped_path(
    cwd: &std::path::Path,
    store: &ObjectStore,
    dropped: &[(String, Hash)],
) -> Option<String> {
    for (path, expected) in dropped {
        match worktree::hash_file(store, &cwd.join(path)) {
            Ok(h) if h != *expected => return Some(path.clone()),
            // Unchanged, unreadable, or a non-file (dir/symlink) at the
            // path — nothing to protect here; deletion is handled safely.
            _ => {}
        }
    }
    None
}

/// Delete a dropped tracked path from the worktree. A regular file or
/// symlink is removed; a directory (untracked content that replaced the
/// tracked file) is LEFT in place rather than recursively deleted, and a
/// missing path is a no-op — so this never crashes on `IsADirectory` and
/// never nukes untracked directories.
fn remove_dropped_path(abs: &std::path::Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(abs) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => std::fs::remove_file(abs),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
