//! `mkit mv <source>... <dest>` — move or rename tracked paths, staging
//! the change (like `git mv`).
//!
//! Forms:
//! - `mv <src> <dst>` — rename `src` to `dst`, or move it into `dst` when
//!   `dst` is an existing directory.
//! - `mv <src>... <dir>` — move every source into the existing directory
//!   `<dir>`.
//!
//! The worktree file is moved and the index updated: the source path is
//! staged as removed and the destination staged with the source's blob
//! (content is unchanged, so the existing object is reused) and mode.
//! mkit has no rename detection, so `mkit status` reports the move as a
//! deletion plus an addition rather than git's `R` — a documented
//! divergence; the staged result (`mkit commit`) is equivalent.
//!
//! Safety: refuses to overwrite an existing destination without `-f`
//! (matching git's `mv` clobber guard) — an mkit data-loss guard.

use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_core::hash::ZERO;
use mkit_core::index::{self, EntryStatus, IndexEntry};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit mv",
    about = "Move or rename tracked paths, staging the change."
)]
struct MvOpts {
    /// Overwrite the destination if it already exists.
    #[arg(short = 'f', long)]
    force: bool,
    /// `<source>... <dest>`. With more than one source, `<dest>` must be
    /// an existing directory.
    #[arg(num_args = 2.., required = true)]
    paths: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<MvOpts>("mkit mv", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    // Confirm we're inside a repo, consistent with the other worktree
    // commands (clear error before we take the lock / touch the index).
    if let Err(e) = ObjectStore::open(&cwd) {
        return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR);
    }
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let mut idx = match index::read_index(&cwd) {
        Ok(i) => i,
        Err(e) => return emit_err(&format!("read index: {e}"), exit::GENERAL_ERROR),
    };

    // Split `<source>... <dest>` (clap guarantees >= 2 args).
    let Some((dest_raw, sources)) = opts.paths.split_last() else {
        return super::usage_error("usage: mkit mv <source>... <dest>");
    };
    if sources.is_empty() {
        return super::usage_error("usage: mkit mv <source>... <dest>");
    }

    let dest_rel = match super::index_path_for_arg(&cwd, Path::new(dest_raw)) {
        Ok(p) => p,
        Err(e) => return emit_err(&e, exit::USAGE),
    };
    let dest_abs = cwd.join(&dest_rel);
    // Multiple sources require an existing destination directory; a single
    // source moves into the destination when it is an existing directory,
    // otherwise it is a plain rename.
    if sources.len() > 1 && !dest_abs.is_dir() {
        return emit_err(
            &format!("destination directory does not exist: {dest_raw}"),
            exit::USAGE,
        );
    }
    let into_dir = sources.len() > 1 || dest_abs.is_dir();

    for source in sources {
        if let Err(code) = move_one(&cwd, &mut idx, source, &dest_rel, into_dir, opts.force) {
            return code;
        }
    }

    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::GENERAL_ERROR),
    }
}

/// Move one `source` (file rename or into `dest_rel` when `into_dir`),
/// updating `idx`. Returns the exit code to propagate on failure.
fn move_one(
    cwd: &Path,
    idx: &mut index::Index,
    source: &str,
    dest_rel: &str,
    into_dir: bool,
    force: bool,
) -> Result<(), u8> {
    let src_rel =
        super::index_path_for_arg(cwd, Path::new(source)).map_err(|e| emit_err(&e, exit::USAGE))?;

    // The source must be a tracked, not-yet-removed index entry.
    let src_idx = idx
        .entries
        .iter()
        .position(|e| e.path == src_rel && e.status != EntryStatus::Removed)
        .ok_or_else(|| {
            emit_err(
                &format!("not under version control: {source}"),
                exit::GENERAL_ERROR,
            )
        })?;
    let src_status = idx.entries[src_idx].status;
    let src_hash = idx.entries[src_idx].object_hash;

    let target_rel = if into_dir {
        let base = src_rel.rsplit('/').next().unwrap_or(&src_rel);
        format!("{dest_rel}/{base}")
    } else {
        dest_rel.to_string()
    };
    if target_rel == src_rel {
        return Err(emit_err(
            &format!("source and destination are the same: {source}"),
            exit::USAGE,
        ));
    }

    let src_abs = cwd.join(&src_rel);
    let target_abs = cwd.join(&target_rel);

    if !src_abs.exists() {
        return Err(emit_err(
            &format!("bad source: {source}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety guard: never clobber an existing destination without -f.
    if target_abs.exists() && !force {
        return Err(emit_err(
            &format!("destination exists (use -f to overwrite): {target_rel}"),
            exit::GENERAL_ERROR,
        ));
    }

    // Move the worktree file. Create parent dirs; under -f remove an
    // existing destination first so the rename is cross-platform.
    if let Some(parent) = target_abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            emit_err(
                &format!("create {}: {e}", parent.display()),
                exit::CANTCREAT,
            )
        })?;
    }
    if force && target_abs.exists() {
        let _ = std::fs::remove_file(&target_abs);
    }
    std::fs::rename(&src_abs, &target_abs).map_err(|e| {
        emit_err(
            &format!("move {src_rel} -> {target_rel}: {e}"),
            exit::GENERAL_ERROR,
        )
    })?;

    // Stage the change: source removed, destination added with the
    // source's blob (content unchanged → object reused) and mode.
    idx.entries[src_idx].status = EntryStatus::Removed;
    idx.entries[src_idx].object_hash = ZERO;
    match idx.entries.iter().position(|e| e.path == target_rel) {
        Some(j) => {
            idx.entries[j].status = src_status;
            idx.entries[j].object_hash = src_hash;
        }
        None => idx.entries.push(IndexEntry {
            path: target_rel,
            status: src_status,
            object_hash: src_hash,
        }),
    }
    Ok(())
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
