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
//! Directory sources (`mv dir newdir`, or `mv dir existing-dir/`) are also
//! supported: the directory is renamed on disk in one filesystem operation
//! — so untracked files inside it come along, exactly like `git mv` — and
//! every tracked file beneath it is restaged at its new path (each as a
//! delete + add, per the no-rename-detection note above). The same up-front
//! validation, clobber guard (`-f`), and repo-escape guard apply, plus a
//! refusal to move a directory into itself.
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

/// One tracked file carried by a directory move: its current index path and
/// the path it lands at, with the blob/mode reused (content is unchanged).
struct DirFileMove {
    src_rel: String,
    target_rel: String,
    status: EntryStatus,
    hash: Hash,
}

/// A validated, ready-to-execute directory move. The worktree directory is
/// renamed in one `fs::rename` (so untracked files travel with it), and each
/// tracked file beneath it is restaged via [`DirFileMove`].
struct PlannedDirMove {
    src_dir_rel: String,
    src_dir_abs: PathBuf,
    dest_dir_rel: String,
    dest_dir_abs: PathBuf,
    files: Vec<DirFileMove>,
}

/// A planned move of either kind. Single-file moves keep their original
/// path exactly; directory moves are the new case.
enum Planned {
    File(PlannedMove),
    Dir(PlannedDirMove),
}

impl Planned {
    /// Every final destination path this move stages, for the
    /// collision check across the whole batch.
    fn target_paths(&self) -> Vec<&str> {
        match self {
            Self::File(m) => vec![m.target_rel.as_str()],
            Self::Dir(m) => m.files.iter().map(|f| f.target_rel.as_str()).collect(),
        }
    }

    /// The directory landing ROOT for a directory move (`dst/dir`), or `None`
    /// for a file move. `target_paths` only exposes per-file landings, so two
    /// directory moves onto the SAME root are invisible there — they're caught
    /// by a dedicated pre-flight using this.
    fn dest_dir_root(&self) -> Option<&str> {
        match self {
            Self::Dir(m) => Some(m.dest_dir_rel.as_str()),
            Self::File(_) => None,
        }
    }

    /// The repo-relative source path this move consumes.
    fn source_rel(&self) -> &str {
        match self {
            Self::File(m) => &m.src_rel,
            Self::Dir(m) => &m.src_dir_rel,
        }
    }
}

#[must_use]
#[allow(clippy::too_many_lines)]
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

    // Phase 1 — validate and plan every move before touching anything. A
    // source that is an exact tracked entry is a file move; one that is the
    // prefix of tracked entries is a directory move; anything else is not
    // under version control.
    let mut plan: Vec<Planned> = Vec::new();
    for source in sources {
        let src_rel = match super::index_path_for_arg(&cwd, Path::new(source)) {
            Ok(p) => p,
            Err(e) => return emit_err(&e, exit::USAGE),
        };
        let is_file = idx
            .entries
            .iter()
            .any(|e| e.path == src_rel && e.status != EntryStatus::Removed);
        let dir_prefix = format!("{src_rel}/");
        let is_dir = idx
            .entries
            .iter()
            .any(|e| e.status != EntryStatus::Removed && e.path.starts_with(&dir_prefix));

        let planned = if is_file {
            plan_move(&cwd, &root_canon, &idx, source, &dest_rel, into_dir, opts.force)
                .map(Planned::File)
        } else if is_dir {
            plan_dir_move(
                &cwd,
                &root_canon,
                &idx,
                source,
                &src_rel,
                &dest_rel,
                into_dir,
                opts.force,
            )
            .map(Planned::Dir)
        } else {
            Err(emit_err(
                &format!("not under version control: {source}"),
                exit::GENERAL_ERROR,
            ))
        };
        match planned {
            Ok(p) => plan.push(p),
            Err(code) => return code,
        }
    }
    // Reject overlapping sources (e.g. `mv dir dir/file <dest>`): moving one
    // invalidates the other, which would otherwise leave a partial result on
    // disk and in the index. Git rejects this up front too.
    for i in 0..plan.len() {
        for j in 0..plan.len() {
            if i == j {
                continue;
            }
            let (a, b) = (plan[i].source_rel(), plan[j].source_rel());
            if a == b {
                return emit_err(&format!("duplicate source: {a}"), exit::USAGE);
            }
            if b.starts_with(&format!("{a}/")) {
                return emit_err(
                    &format!("overlapping sources: '{b}' is inside '{a}'"),
                    exit::USAGE,
                );
            }
        }
    }
    // Reject a batch where two staged destinations collide (across both file
    // and directory moves) — either the SAME path, or one nested UNDER the
    // other (e.g. a file at `dst/x` and a directory at `dst/x/...`), which
    // would create a file/directory conflict on disk and in the index.
    let all_targets: Vec<&str> = plan.iter().flat_map(Planned::target_paths).collect();
    for i in 0..all_targets.len() {
        for j in 0..all_targets.len() {
            if i == j {
                continue;
            }
            let (a, b) = (all_targets[i], all_targets[j]);
            if a == b {
                return emit_err(
                    &format!("multiple sources map to the same destination: {a}"),
                    exit::USAGE,
                );
            }
            if b.starts_with(&format!("{a}/")) {
                return emit_err(
                    &format!("conflicting destinations: '{a}' and '{b}' (one is inside the other)"),
                    exit::USAGE,
                );
            }
        }
    }
    // Two DIRECTORY moves must not land at the same (or a nested) destination
    // root: `target_paths` only exposes per-file landings (`dst/dir/a` vs
    // `dst/dir/b` — non-colliding), so the check above misses two directories
    // renamed onto the same `dest_dir_rel` (e.g. `mv x/dir y/dir dst` → both →
    // `dst/dir`). `execute_dir_move` does a bare `fs::rename` onto the
    // now-existing dest, failing mid-batch and leaving a partial result —
    // violating the all-or-nothing invariant. Reject it up front.
    let dir_roots: Vec<&str> = plan.iter().filter_map(Planned::dest_dir_root).collect();
    for i in 0..dir_roots.len() {
        for j in (i + 1)..dir_roots.len() {
            let (a, b) = (dir_roots[i], dir_roots[j]);
            if a == b
                || b.starts_with(&format!("{a}/"))
                || a.starts_with(&format!("{b}/"))
            {
                return emit_err(
                    &format!("multiple directory sources map to the same destination: {a}"),
                    exit::USAGE,
                );
            }
        }
    }

    // Phase 2 — execute. On a filesystem error mid-batch, persist the
    // index for the moves already done so it stays consistent with disk.
    for (done, p) in plan.iter().enumerate() {
        let exec = match p {
            Planned::File(m) => execute_move(m, opts.force),
            Planned::Dir(m) => execute_dir_move(m),
        };
        if let Err(code) = exec {
            if done > 0 {
                let _ = index::write_index(&cwd, &idx);
            }
            return code;
        }
        match p {
            Planned::File(m) => apply_to_index(&mut idx, m),
            Planned::Dir(m) => apply_dir_to_index(&mut idx, m),
        }
    }

    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::GENERAL_ERROR),
    }
}

/// Validate one `source` and return the planned move, or the exit code to
/// propagate. Performs no filesystem or index mutation.
#[allow(clippy::too_many_lines)] // a flat sequence of independent safety guards
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
    // Safety: a file source tracked in the index must still be a file/symlink
    // on disk. If it was replaced by a directory, this "file move" would
    // rename the directory while staging the destination with the OLD file
    // blob — a worktree/index divergence. Git refuses this too.
    if std::fs::symlink_metadata(&src_abs).is_ok_and(|m| m.is_dir()) {
        return Err(emit_err(
            &format!("bad source: {source} (tracked as a file but is now a directory)"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: refuse a source reached through a symlinked ancestor — it could
    // point outside the repo (see `has_symlinked_ancestor`).
    if has_symlinked_ancestor(cwd, &src_rel) {
        return Err(emit_err(
            &format!("bad source: {source} (path traverses a symlink)"),
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
    // Safety: refuse a destination reached through a symlinked ancestor, even
    // when the link resolves INSIDE the repo. `fs::rename` follows the link
    // and writes to the real location while the index is staged at the literal
    // lexical `target_rel` — an immediate worktree/index divergence.
    // `target_within_repo` only proves containment; it accepts an in-repo
    // symlink, so this guard (symmetric with the source check) is still needed.
    if has_symlinked_ancestor(cwd, &target_rel) {
        return Err(emit_err(
            &format!("destination path traverses a symlink: {target_rel}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: never clobber an existing destination without -f. Use a
    // symlink-aware check so a dangling symlink still counts as "exists".
    // Skip entirely ONLY for a genuine case-only rename (the "destination" IS
    // the source on a case-insensitive filesystem) so `mv Foo foo` is a plain
    // rename. An untracked symlink pointing AT the source must NOT bypass this.
    if path_present(&target_abs) && !is_case_only_rename(&src_rel, &target_rel, &src_abs, &target_abs)
    {
        // A file source can never replace a DIRECTORY destination — even with
        // -f. `-f` removes the destination first, and removing a directory
        // would recursively delete its (tracked + untracked) contents and
        // leave the index in a file/dir conflict. Git refuses this too.
        if std::fs::symlink_metadata(&target_abs).is_ok_and(|m| m.is_dir()) {
            return Err(emit_err(
                &format!("destination is a directory: {target_rel} (mv cannot replace a directory with a file)"),
                exit::GENERAL_ERROR,
            ));
        }
        if !force {
            return Err(emit_err(
                &format!("destination exists (use -f to overwrite): {target_rel}"),
                exit::GENERAL_ERROR,
            ));
        }
    }
    // A tracked file BENEATH the destination (e.g. tracked `dst/child` with
    // `dst` deleted from disk, then `mv src dst`) would leave both `dst` (a
    // file) and `dst/child` in the index — a file/dir conflict.
    if let Some(desc) = idx.entries.iter().find(|e| {
        e.status != EntryStatus::Removed && e.path.starts_with(&format!("{target_rel}/"))
    }) {
        return Err(emit_err(
            &format!(
                "destination has tracked descendants (e.g. '{}'); a file cannot replace it",
                desc.path
            ),
            exit::GENERAL_ERROR,
        ));
    }
    // A tracked file at an ANCESTOR of the destination would leave the index
    // with both `<ancestor>` (a file) and `<ancestor>/…/target` — a file/dir
    // conflict. This is missed by the on-disk checks when that ancestor was
    // deleted from the worktree (e.g. tracked file `dst`, removed from disk,
    // a directory `dst/` recreated, then `mv src dst`).
    if let Some(anc) = idx.entries.iter().find(|e| {
        e.status != EntryStatus::Removed && target_rel.starts_with(&format!("{}/", e.path))
    }) {
        return Err(emit_err(
            &format!(
                "destination nests under tracked file '{}'; move or remove it first",
                anc.path
            ),
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
    // Never clear the destination when it IS the source (a genuine case-only
    // rename on a case-insensitive filesystem, e.g. `Foo` -> `foo`): removing
    // it would delete the source and the rename would then fail with both
    // gone. A symlink merely pointing at the source is NOT a case-only rename.
    if force
        && path_present(&m.target_abs)
        && !is_case_only_rename(&m.src_rel, &m.target_rel, &m.src_abs, &m.target_abs)
    {
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

/// Validate a directory `source` and plan its move. Performs no filesystem
/// or index mutation. `src_rel` is the source's repo-relative path (already
/// resolved by the caller).
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // a flat sequence of independent safety guards
fn plan_dir_move(
    cwd: &Path,
    root_canon: &Path,
    idx: &index::Index,
    source: &str,
    src_rel: &str,
    dest_rel: &str,
    into_dir: bool,
    force: bool,
) -> Result<PlannedDirMove, u8> {
    let src_dir_abs = cwd.join(src_rel);
    // The worktree path must be a REAL directory. `Path::is_dir()` follows
    // symlinks, so a tracked directory replaced by a symlink-to-a-directory
    // would otherwise be "moved" as a symlink — and its tracked contents
    // restaged under a path that escapes the repo. Require the on-disk type
    // (not the link target) to be a directory.
    if !std::fs::symlink_metadata(&src_dir_abs).is_ok_and(|m| m.is_dir()) {
        return Err(emit_err(
            &format!("bad source: {source} (not a directory, or a symlink standing in for one)"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: also refuse if an ANCESTOR component is a symlink — the leaf
    // check above only proves the final component is a real directory, but a
    // symlinked ancestor could place that directory outside the repo.
    if has_symlinked_ancestor(cwd, src_rel) {
        return Err(emit_err(
            &format!("bad source: {source} (path traverses a symlink)"),
            exit::GENERAL_ERROR,
        ));
    }

    // Where the directory lands: a plain rename to `dest_rel`, or — when the
    // destination is an existing directory (or there are multiple sources) —
    // *into* it as `dest_rel/<basename>`, matching git.
    let dest_dir_rel = if into_dir {
        let base = src_rel.rsplit('/').next().unwrap_or(src_rel);
        format!("{dest_rel}/{base}")
    } else {
        dest_rel.to_string()
    };
    if dest_dir_rel == src_rel {
        return Err(emit_err(
            &format!("source and destination are the same: {source}"),
            exit::USAGE,
        ));
    }
    // Refuse moving a directory into itself or a descendant (the on-disk
    // rename would otherwise be nonsensical / lose data).
    if dest_dir_rel == src_rel || dest_dir_rel.starts_with(&format!("{src_rel}/")) {
        return Err(emit_err(
            &format!("cannot move '{source}' into itself"),
            exit::USAGE,
        ));
    }

    let dest_dir_abs = cwd.join(&dest_dir_rel);
    // Safety: keep writes inside the repo.
    if !target_within_repo(root_canon, &dest_dir_abs) {
        return Err(emit_err(
            &format!("destination escapes the repository: {dest_dir_rel}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: refuse a destination reached through a symlinked ancestor, even
    // when the link resolves INSIDE the repo (symmetric with the file-move
    // guard in `plan_move`). `fs::rename` follows the link and moves the
    // subtree to the real location while the index is staged at the literal
    // lexical `dest_dir_rel` — an immediate worktree/index divergence.
    // `target_within_repo` only proves containment; it accepts an in-repo
    // symlink target.
    if has_symlinked_ancestor(cwd, &dest_dir_rel) {
        return Err(emit_err(
            &format!("destination path traverses a symlink: {dest_dir_rel}"),
            exit::GENERAL_ERROR,
        ));
    }
    // Safety: a directory move never overwrites an existing destination —
    // even with -f. Recursively removing the destination would silently
    // delete its tracked files (leaving them dangling in the index) and any
    // untracked files under it. Git likewise refuses to clobber a directory
    // with `mv`, so this is a refusal, not a force-overridable guard.
    if path_present(&dest_dir_abs) {
        return Err(emit_err(
            &format!(
                "destination already exists: {dest_dir_rel} \
                 (refusing to overwrite it — -f does not clobber a directory)"
            ),
            exit::GENERAL_ERROR,
        ));
    }
    // Also refuse when the destination collides with a tracked INDEX path
    // even though it is absent on disk (e.g. a tracked file deleted from the
    // worktree, or an already-tracked subtree). Otherwise the move would
    // leave the index with both `<dest>` (a file) and `<dest>/<child>`
    // entries — a path conflict that breaks `status`/`commit`.
    let dest_prefix = format!("{dest_dir_rel}/");
    if idx.entries.iter().any(|e| {
        e.status != EntryStatus::Removed
            && (e.path == dest_dir_rel                         // dest tracked as a file
                || e.path.starts_with(&dest_prefix)            // dest subtree tracked
                || dest_dir_rel.starts_with(&format!("{}/", e.path))) // tracked ANCESTOR file
    }) {
        return Err(emit_err(
            &format!("destination conflicts with a tracked path: {dest_dir_rel}"),
            exit::GENERAL_ERROR,
        ));
    }
    let _ = force;

    // Restage every tracked file beneath the directory at its new path.
    let prefix = format!("{src_rel}/");
    let mut files = Vec::new();
    for e in &idx.entries {
        if e.status != EntryStatus::Removed && e.path.starts_with(&prefix) {
            let child_abs = cwd.join(&e.path);
            // The tracked child must still exist in the worktree. Otherwise the
            // directory rename moves nothing for it, yet we'd restage its old
            // blob at the destination — resurrecting a file that was deleted
            // from disk. Git refuses a move whose source is gone.
            let Ok(meta) = std::fs::symlink_metadata(&child_abs) else {
                return Err(emit_err(
                    &format!("bad source: {} (tracked file missing from the worktree)", e.path),
                    exit::GENERAL_ERROR,
                ));
            };
            // …and it must still be a file/symlink, not a directory: a child
            // replaced by a directory would restage the stale blob at the
            // destination while the worktree keeps the directory.
            if meta.is_dir() {
                return Err(emit_err(
                    &format!("bad source: {} (tracked as a file but is now a directory)", e.path),
                    exit::GENERAL_ERROR,
                ));
            }
            // …and its path must not be reached through a symlinked ancestor
            // inside the moved subtree (which the single directory rename would
            // carry along, leaving a symlink that escapes the repo).
            if has_symlinked_ancestor(cwd, &e.path) {
                return Err(emit_err(
                    &format!("bad source: {} (path traverses a symlink)", e.path),
                    exit::GENERAL_ERROR,
                ));
            }
            let sub = &e.path[prefix.len()..];
            files.push(DirFileMove {
                src_rel: e.path.clone(),
                target_rel: format!("{dest_dir_rel}/{sub}"),
                status: e.status,
                hash: e.object_hash,
            });
        }
    }
    if files.is_empty() {
        // The caller only routes here when at least one tracked entry has the
        // `src_rel/` prefix, so this is defensive.
        return Err(emit_err(
            &format!("not under version control: {source}"),
            exit::GENERAL_ERROR,
        ));
    }

    Ok(PlannedDirMove {
        src_dir_rel: src_rel.to_string(),
        src_dir_abs,
        dest_dir_rel,
        dest_dir_abs,
        files,
    })
}

/// Rename the worktree directory for one planned directory move. A single
/// `fs::rename` moves the whole subtree (tracked and untracked alike),
/// matching `git mv`. The destination is guaranteed absent (plan-time
/// guard), so this never removes an existing path.
fn execute_dir_move(m: &PlannedDirMove) -> Result<(), u8> {
    if let Some(parent) = m.dest_dir_abs.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            emit_err(
                &format!("create {}: {e}", parent.display()),
                exit::CANTCREAT,
            )
        })?;
    }
    std::fs::rename(&m.src_dir_abs, &m.dest_dir_abs).map_err(|e| {
        emit_err(
            &format!("move {} -> {}: {e}", m.src_dir_rel, m.dest_dir_rel),
            exit::GENERAL_ERROR,
        )
    })
}

/// Apply a completed directory move to the index: each source file is staged
/// as removed and its destination staged with the reused blob/mode. Only
/// flips statuses and appends — never removes from the vec — so any
/// `src_idx` captured by a sibling file move stays valid.
fn apply_dir_to_index(idx: &mut index::Index, m: &PlannedDirMove) {
    for f in &m.files {
        if let Some(i) = idx
            .entries
            .iter()
            .position(|e| e.path == f.src_rel && e.status != EntryStatus::Removed)
        {
            idx.entries[i].status = EntryStatus::Removed;
            idx.entries[i].object_hash = ZERO;
        }
        match idx.entries.iter().position(|e| e.path == f.target_rel) {
            Some(j) => {
                idx.entries[j].status = f.status;
                idx.entries[j].object_hash = f.hash;
            }
            None => idx.entries.push(IndexEntry {
                path: f.target_rel.clone(),
                status: f.status,
                object_hash: f.hash,
                mtime_ns: 0,
                size: 0,
                ino: 0,
                ctime_ns: 0,
            }),
        }
    }
}

/// Symlink-aware existence: true even for a dangling symlink (unlike
/// [`Path::exists`], which follows the link and reports `false`).
fn path_present(p: &Path) -> bool {
    p.symlink_metadata().is_ok()
}

/// Do `a` and `b` resolve to the same filesystem object? Used to detect a
/// case-only rename on a case-insensitive filesystem (`Foo` vs `foo`), where
/// the move destination IS the source — so it must not be cleared. Both paths
/// must exist; a failed canonicalization is treated as "different".
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => false,
    }
}

/// Is this move a genuine CASE-ONLY rename (`Foo` -> `foo`, including non-ASCII
/// folds like `Ä` -> `ä`) on a case-insensitive filesystem? Such a move's
/// destination resolves to the source itself, so the clobber guard /
/// force-remove must be skipped. We require distinct lexical paths that resolve
/// to the SAME object where the destination is a REGULAR FILE (the source
/// under a different case spelling). The regular-file requirement is what
/// excludes an untracked SYMLINK pointing at the source: it also resolves to
/// the source via `same_file`, but it is a distinct name the user must `-f` to
/// overwrite (matching git). A hardlink has a distinct canonical path, so
/// `same_file` already excludes it.
fn is_case_only_rename(src_rel: &str, target_rel: &str, src_abs: &Path, target_abs: &Path) -> bool {
    src_rel != target_rel
        && same_file(src_abs, target_abs)
        && std::fs::symlink_metadata(target_abs).is_ok_and(|m| !m.file_type().is_symlink())
}

/// Does any ANCESTOR component of repo-relative `rel` (under `root`) resolve
/// through a symlink? `Path::symlink_metadata` only declines to follow the
/// *final* component, so a tracked path like `link/dir/file` whose `link`
/// component is replaced by a symlink to an external directory would let `mv`
/// operate on content outside the repo. The leaf is excluded — a file move
/// may legitimately move a tracked symlink, and directory sources validate
/// the leaf separately.
fn has_symlinked_ancestor(root: &Path, rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
    let mut p = root.to_path_buf();
    for comp in comps.iter().take(comps.len().saturating_sub(1)) {
        p.push(comp);
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            return true;
        }
    }
    false
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
