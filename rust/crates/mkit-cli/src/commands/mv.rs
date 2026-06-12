//! `mkit mv <source>... <dest>` — move or rename tracked paths, staging
//! the change (like `git mv`).
//!
//! Forms:
//! - `mv <src> <dst>` — rename `src` to `dst`, or move it into `dst` when
//!   `dst` is an existing directory.
//! - `mv <src>... <dir>` — move every source into the existing directory
//!   `<dir>`.
//!
//! For each source the worktree file is moved and the index updated: the
//! source path is staged as removed and the destination staged with the
//! source's blob (content is unchanged, so the existing object is reused)
//! and mode. All sources are **validated up front**; nothing on disk or in
//! the index is touched until every move is known to be legal, so a bad
//! source in a batch can't leave the worktree half-moved.
//!
//! mkit has no rename detection, so `mkit status` reports the move as a
//! deletion plus an addition rather than git's `R` — a documented
//! divergence; the staged result (`mkit commit`) is equivalent.
//!
//! Scope: moves a single tracked file per source. Moving a tracked
//! **directory** (`mv dir newdir`) is not yet supported and is refused
//! with a clear error (follow-up).
//!
//! Safety divergences:
//! - refuses to overwrite an existing destination without `-f` (matching
//!   git's `mv` clobber guard), and detects a dangling symlink at the
//!   destination as "exists" (git refuses that too);
//! - refuses a destination that escapes the repository through a
//!   symlinked parent directory (git would silently follow it) — mkit
//!   keeps writes inside the repo.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::hash::{Hash, ZERO};
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

/// A validated, ready-to-execute single-file move.
struct PlannedMove {
    /// Index slot of the source entry (still valid through execution: we
    /// only flip statuses and append, never remove from the vec).
    src_idx: usize,
    src_rel: String,
    src_abs: PathBuf,
    target_rel: String,
    target_abs: PathBuf,
    status: EntryStatus,
    hash: Hash,
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
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };
    // Seed from HEAD when the index is absent/empty, like `rm` and
    // `status`, so a HEAD-tracked source is recognized as version-controlled.
    let mut idx = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let root_canon = match cwd.canonicalize() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("repo root: {e}"), exit::GENERAL_ERROR),
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

    // Phase 1 — validate and plan every move before touching anything.
    let mut plan: Vec<PlannedMove> = Vec::new();
    for source in sources {
        match plan_move(
            &cwd,
            &root_canon,
            &idx,
            source,
            &dest_rel,
            into_dir,
            opts.force,
        ) {
            Ok(m) => plan.push(m),
            Err(code) => return code,
        }
    }
    // Reject a batch that would move two sources onto the same path.
    for i in 0..plan.len() {
        for j in (i + 1)..plan.len() {
            if plan[i].target_rel == plan[j].target_rel {
                return emit_err(
                    &format!(
                        "multiple sources map to the same destination: {}",
                        plan[i].target_rel
                    ),
                    exit::USAGE,
                );
            }
        }
    }

    // Phase 2 — execute. On a filesystem error mid-batch, persist the
    // index for the moves already done so it stays consistent with disk.
    for (done, m) in plan.iter().enumerate() {
        if let Err(code) = execute_move(m, opts.force) {
            if done > 0 {
                let _ = index::write_index(&cwd, &idx);
            }
            return code;
        }
        apply_to_index(&mut idx, m);
    }

    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::GENERAL_ERROR),
    }
}

/// Validate one `source` and return the planned move, or the exit code to
/// propagate. Performs no filesystem or index mutation.
fn plan_move(
    cwd: &Path,
    root_canon: &Path,
    idx: &index::Index,
    source: &str,
    dest_rel: &str,
    into_dir: bool,
    force: bool,
) -> Result<PlannedMove, u8> {
    let src_rel =
        super::index_path_for_arg(cwd, Path::new(source)).map_err(|e| emit_err(&e, exit::USAGE))?;

    // The source must be a tracked, not-yet-removed index entry.
    let src_idx = idx
        .entries
        .iter()
        .position(|e| e.path == src_rel && e.status != EntryStatus::Removed)
        .ok_or_else(|| {
            // Distinguish "tracked directory" (unsupported) from "untracked".
            let dir_prefix = format!("{src_rel}/");
            let is_tracked_dir = idx
                .entries
                .iter()
                .any(|e| e.status != EntryStatus::Removed && e.path.starts_with(&dir_prefix));
            if is_tracked_dir {
                emit_err(
                    &format!("moving directories is not yet supported: {source}"),
                    exit::GENERAL_ERROR,
                )
            } else {
                emit_err(
                    &format!("not under version control: {source}"),
                    exit::GENERAL_ERROR,
                )
            }
        })?;
    let status = idx.entries[src_idx].status;
    let hash = idx.entries[src_idx].object_hash;

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

    if !path_present(&src_abs) {
        return Err(emit_err(
            &format!("bad source: {source}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: keep writes inside the repo — refuse a destination whose real
    // parent (resolving symlinks) escapes the repository root.
    if !target_within_repo(root_canon, &target_abs) {
        return Err(emit_err(
            &format!("destination escapes the repository: {target_rel}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: never clobber an existing destination without -f. Use a
    // symlink-aware check so a dangling symlink still counts as "exists".
    if path_present(&target_abs) && !force {
        return Err(emit_err(
            &format!("destination exists (use -f to overwrite): {target_rel}"),
            exit::GENERAL_ERROR,
        ));
    }

    Ok(PlannedMove {
        src_idx,
        src_rel,
        src_abs,
        target_rel,
        target_abs,
        status,
        hash,
    })
}

/// Move the worktree file for one planned move. Creates parent dirs and,
/// under `-f`, removes an existing destination first so the rename is
/// cross-platform.
fn execute_move(m: &PlannedMove, force: bool) -> Result<(), u8> {
    if let Some(parent) = m.target_abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            emit_err(
                &format!("create {}: {e}", parent.display()),
                exit::CANTCREAT,
            )
        })?;
    }
    if force && path_present(&m.target_abs) {
        let _ = remove_path(&m.target_abs);
    }
    std::fs::rename(&m.src_abs, &m.target_abs).map_err(|e| {
        emit_err(
            &format!("move {} -> {}: {e}", m.src_rel, m.target_rel),
            exit::GENERAL_ERROR,
        )
    })
}

/// Apply a completed move to the index: source removed, destination added
/// with the source's blob (content unchanged → object reused) and mode.
fn apply_to_index(idx: &mut index::Index, m: &PlannedMove) {
    idx.entries[m.src_idx].status = EntryStatus::Removed;
    idx.entries[m.src_idx].object_hash = ZERO;
    match idx.entries.iter().position(|e| e.path == m.target_rel) {
        Some(j) => {
            idx.entries[j].status = m.status;
            idx.entries[j].object_hash = m.hash;
        }
        None => idx.entries.push(IndexEntry {
            path: m.target_rel.clone(),
            status: m.status,
            object_hash: m.hash,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        }),
    }
}

/// Symlink-aware existence: true even for a dangling symlink (unlike
/// [`Path::exists`], which follows the link and reports `false`).
fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// Remove a file or symlink at `p` (used to clear a destination under -f).
fn remove_path(p: &Path) -> std::io::Result<()> {
    match p.symlink_metadata() {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(p),
        _ => std::fs::remove_file(p),
    }
}

/// Does `target_abs` stay within the repo once symlinks are resolved? We
/// canonicalize its nearest existing ancestor (the leaf may not exist yet)
/// and require it to live under the canonical repo root, so a symlinked
/// parent pointing outside the repo is rejected.
fn target_within_repo(root_canon: &Path, target_abs: &Path) -> bool {
    let mut ancestor = target_abs.parent();
    while let Some(a) = ancestor {
        match a.canonicalize() {
            Ok(real) => return real.starts_with(root_canon),
            Err(_) => ancestor = a.parent(),
        }
    }
    false
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
