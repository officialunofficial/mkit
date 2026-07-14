//! `mkit add <path>` / `mkit add .` — stage a file (or the whole
//! worktree) into `.mkit/index`. `add -p` additionally stages individual
//! hunks interactively (see `run_patch`).

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::Path;

use clap::Parser;
use mkit_core::hash::ZERO;
use mkit_core::ignore::{self, IgnoreList};
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Object};
use mkit_core::ops::{HunkLineKind, PatchHunk, apply_hunks_subset, enumerate_hunks};
use mkit_core::serialize;
use mkit_core::store::{ObjectSink, ObjectStore};
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit add",
    about = "Stage files (paths, `.`, `-A`, or `-u`) into the index."
)]
// CLI flag struct: each bool is an independent clap switch, not a state
// machine begging to be an enum.
#[allow(clippy::struct_excessive_bools)]
struct AddOpts {
    /// Stage every change in the worktree, including deletions of
    /// tracked files. Equivalent to `mkit add .` plus deletion
    /// detection; takes no path arguments.
    #[arg(short = 'A', long)]
    all: bool,

    /// Restage only files already tracked in the index: update modified
    /// ones and record deletions, without adding untracked paths. Takes
    /// no path arguments.
    #[arg(short = 'u', long)]
    update: bool,

    /// Allow staging an explicitly-named path that is ignored by
    /// `.gitignore`/`.mkitignore` (git refuses these without `-f`).
    #[arg(short = 'f', long)]
    force: bool,

    /// Interactively choose hunks to stage from each named file (like
    /// `git add -p`). Prompts per hunk: `y` stage, `n` skip, `a` stage
    /// the rest of the file, `d` skip the rest, `q` quit. Regular text
    /// files only: binary files are skipped (the command still succeeds),
    /// while symlinks and directories are refused. Requires explicit path
    /// arguments.
    #[arg(short = 'p', long)]
    patch: bool,

    /// Paths to stage. Pass `.` to stage every non-ignored file under
    /// the current directory. Multiple paths may be given.
    paths: Vec<String>,
}

/// Refresh already-tracked index entries from the worktree.
///
/// This backs `mkit commit -a`: it mirrors Git's tracked-only shortcut
/// by updating modified tracked files and staging tracked deletions,
/// without adding untracked paths.
pub(super) fn stage_tracked_changes(
    layout: &RepoLayout,
    store: &ObjectStore,
) -> Result<(), String> {
    let root = layout.worktree_root();
    let mut idx = super::read_or_seed_index_from_head(layout, store)?;

    // One durability batch for every restaged object; committed below,
    // before the index write that references them.
    let batch = store.batch();

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

        // Stat cache: an unchanged tracked file (mtime+size+exec class
        // all match what was observed at staging time) keeps its entry
        // untouched — no read, no hash, no store. O(stat) restage.
        if worktree::stat_matches(entry, &meta) {
            continue;
        }

        // Regular files route through `store_file_object` so large
        // (> CHUNK_THRESHOLD) content lands as a ChunkedBlob, matching
        // `worktree::{build_tree,hash_file}` and keeping commit/status/rm
        // hashes consistent (#203). Symlinks are always a single Blob of
        // their target path.
        let (status, h, stat) = if meta.file_type().is_file() {
            let (h, opened_meta) = worktree::hash_file_with_metadata(&batch, &abs)
                .map_err(|e| format!("read/store {}: {e}", abs.display()))?;
            let stat = worktree::stat_cache_fields(&opened_meta);
            (file_status_from_meta(&opened_meta, entry.status), h, stat)
        } else if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&abs)
                .map_err(|e| format!("read link {}: {e}", abs.display()))?;
            let target_str = target
                .to_str()
                .ok_or_else(|| "symlink target is not valid UTF-8".to_string())?;
            if !worktree::validate_symlink_target(target_str) {
                return Err(format!("invalid symlink target: {target_str}"));
            }
            let blob = Object::Blob(Blob {
                data: target_str.as_bytes().to_vec(),
            });
            let ser = serialize::serialize(&blob).map_err(|e| format!("serialize: {e}"))?;
            let h = batch.put(&ser).map_err(|e| format!("store: {e}"))?;
            // Symlinks never stat-match (see worktree::stat_matches).
            (EntryStatus::Symlink, h, (0, 0, 0, 0))
        } else {
            entry.status = EntryStatus::Removed;
            entry.object_hash = ZERO;
            continue;
        };

        entry.status = status;
        entry.object_hash = h;
        entry.mtime_ns = stat.0;
        entry.size = stat.1;
        entry.ino = stat.2;
        entry.ctime_ns = stat.3;
    }

    // Durability ordering: objects first, then the index that
    // references them.
    batch.commit().map_err(|e| format!("store: {e}"))?;
    index::write_index(layout, &idx).map_err(|e| format!("write index: {e}"))
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

/// Map a [`worktree::WorktreeError`] from `hash_file_with_metadata` to a
/// sysexits-style code, preserving the read-vs-write distinction the
/// two-step `read_regular_file_bounded` + `store_file_object` call used
/// to make explicit (`NOINPUT` vs `CANTCREAT`) now that both steps are
/// folded into one streaming call.
fn worktree_err_exit_code(e: &worktree::WorktreeError) -> u8 {
    match e {
        worktree::WorktreeError::Io(_) | worktree::WorktreeError::FileTooLarge(_) => exit::NOINPUT,
        worktree::WorktreeError::Object(_) | worktree::WorktreeError::Store(_) => exit::CANTCREAT,
        worktree::WorktreeError::InvalidSymlinkTarget(_) | worktree::WorktreeError::InvalidUtf8 => {
            exit::DATAERR
        }
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<AddOpts>("mkit add", args) {
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
    let store = match super::open_store_configured(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // Interactive hunk staging. Incompatible with the bulk modes and
    // requires explicit file paths (no `.` / `-A` / `-u`).
    if opts.patch {
        if opts.all || opts.update {
            return emit_err(
                "-p/--patch cannot be combined with -A/--all or -u/--update",
                exit::USAGE,
            );
        }
        if opts.paths.is_empty() {
            return emit_err("-p/--patch requires one or more file paths", exit::USAGE);
        }
        return run_patch(&layout, &store, &opts.paths, opts.force);
    }

    // Mode selection. `-A` and `-u` are mutually exclusive with each
    // other and with positional paths.
    if opts.all && opts.update {
        return emit_err("cannot combine -A/--all with -u/--update", exit::USAGE);
    }
    if (opts.all || opts.update) && !opts.paths.is_empty() {
        return emit_err(
            "-A/--all and -u/--update take no path arguments",
            exit::USAGE,
        );
    }

    if opts.update {
        // Tracked-only restage, reusing the shared helper that backs
        // `commit -a`.
        return match stage_tracked_changes(&layout, &store) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&e, exit::GENERAL_ERROR),
        };
    }

    let mut idx = match super::read_or_seed_index_from_head(&layout, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // One durability batch for the whole command: every staged object
    // costs zero full flushes until the single commit() below, which
    // runs before the index write that references them.
    let batch = store.batch();

    if opts.all {
        // Stage everything under cwd, then record deletions of tracked
        // files that vanished from the worktree.
        if let Err(code) = add_whole_worktree(&cwd, &batch, &mut idx) {
            return code;
        }
    } else if opts.paths.is_empty() {
        return emit_err(
            "no paths given (use `.`, -A, -u, or one or more paths)",
            exit::USAGE,
        );
    } else {
        // Explicit paths are checked against the ignore list (git refuses an
        // ignored path unless `-f`). Loaded once and shared across paths.
        let ignores = match ignore::load(&cwd) {
            Ok(i) => i,
            Err(e) => return emit_err(&format!("read ignore file: {e}"), exit::GENERAL_ERROR),
        };
        for target in &opts.paths {
            if target == "." {
                if let Err(code) = add_whole_worktree(&cwd, &batch, &mut idx) {
                    return code;
                }
            } else {
                // Reject an explicit path that escapes the repo through a
                // symlinked parent before reading/staging it (the bulk `.`/`-A`
                // walk can't reach outside, so it is exempt).
                let p = Path::new(target);
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    cwd.join(p)
                };
                if let Err(e) = ensure_within_repo(&cwd, &abs) {
                    return emit_err(&e, exit::DATAERR);
                }
                match add_one(&cwd, p, &batch, &mut idx, &ignores, opts.force) {
                    Ok(_) => {}
                    Err(code) => return code,
                }
            }
        }
    }

    // Objects become durable before the index that references them.
    if let Err(e) = batch.commit() {
        return emit_err(&format!("store: {e}"), exit::CANTCREAT);
    }
    match index::write_index(&layout, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

/// Stage every non-ignored worktree file under `root`, then mark any
/// tracked path missing from the worktree as removed. Backs both
/// `mkit add .` and `mkit add -A`.
fn add_whole_worktree(root: &Path, sink: &dyn ObjectSink, idx: &mut Index) -> Result<(), u8> {
    let ignores = match ignore::load(root) {
        Ok(i) => i,
        Err(e) => {
            return Err(emit_err(
                &format!("read ignore file: {e}"),
                exit::GENERAL_ERROR,
            ));
        }
    };
    let mut seen = HashSet::new();
    add_tree(root, root, false, sink, idx, &ignores, &mut seen)?;
    mark_missing_paths_removed(root, idx, &seen);
    Ok(())
}

fn add_one(
    root: &Path,
    rel: &Path,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<String, u8> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let meta = abs
        .symlink_metadata()
        .map_err(|e| emit_err(&format!("metadata {}: {e}", abs.display()), exit::NOINPUT))?;
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(emit_err(&format!("invalid path: {rel_str}"), exit::DATAERR));
    }
    // One O(log n) lookup shared by every check below (issue #708 —
    // `find_entry` used to be an O(n) scan, and this path once ran it
    // three times per file, making bulk staging O(N^2)).
    let existing_pos = idx.find_entry(&rel_str);
    let previous_status = existing_pos.map_or(EntryStatus::Blob, |i| idx.entries[i].status);
    // An ignored path named explicitly is refused unless `-f` — but a path
    // that is *already tracked* is never subject to ignore (git parity).
    let already_tracked = previous_status != EntryStatus::Removed && existing_pos.is_some();
    if !force && !already_tracked && ignores.is_ignored_with_ancestors(&rel_str, meta.is_dir()) {
        return Err(emit_err(
            &format!("path '{rel_str}' is ignored; use -f to add it anyway"),
            exit::USAGE,
        ));
    }
    // Stat cache: a tracked file whose mtime+size+exec class match the
    // index entry is already staged byte-for-byte — skip the read, the
    // hash, and the store write entirely.
    if let Some(existing) = existing_pos
        && worktree::stat_matches(&idx.entries[existing], &meta)
    {
        return Ok(rel_str);
    }
    // Regular files route through `store_file_object` so large
    // (> CHUNK_THRESHOLD) content lands as a ChunkedBlob, matching
    // `worktree::{build_tree,hash_file}` (#203). Symlinks stay a single
    // Blob of their target path.
    let (status, h, stat) = if meta.file_type().is_file() {
        let (h, opened_meta) = worktree::hash_file_with_metadata(sink, &abs).map_err(|e| {
            let code = worktree_err_exit_code(&e);
            emit_err(&format!("{}: {e}", abs.display()), code)
        })?;
        let stat = worktree::stat_cache_fields(&opened_meta);
        (
            file_status_from_meta(&opened_meta, previous_status),
            h,
            stat,
        )
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
        let blob = Object::Blob(Blob {
            data: target_str.into_bytes(),
        });
        let ser = serialize::serialize(&blob)
            .map_err(|e| emit_err(&format!("serialize: {e}"), exit::DATAERR))?;
        let h = sink
            .put(&ser)
            .map_err(|e| emit_err(&format!("store: {e}"), exit::CANTCREAT))?;
        // Symlinks never stat-match (see worktree::stat_matches).
        (EntryStatus::Symlink, h, (0, 0, 0, 0))
    } else {
        return Err(emit_err(
            &format!("not a regular file: {}", abs.display()),
            exit::NOINPUT,
        ));
    };
    let entry = IndexEntry {
        path: rel_str.clone(),
        status,
        object_hash: h,
        mtime_ns: stat.0,
        size: stat.1,
        ino: stat.2,
        ctime_ns: stat.3,
    };
    idx.remove_directory_conflicts(&entry.path);
    idx.upsert_entry(entry);
    Ok(rel_str)
}

fn add_tree(
    root: &Path,
    dir: &Path,
    parent_ignored: bool,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    seen: &mut HashSet<String>,
) -> Result<(), u8> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| emit_err(&format!("read dir {}: {e}", dir.display()), exit::NOINPUT))?;
    for ent in rd.flatten() {
        let p = ent.path();
        let meta = p
            .symlink_metadata()
            .map_err(|e| emit_err(&format!("metadata {}: {e}", p.display()), exit::NOINPUT))?;
        let is_dir = meta.file_type().is_dir();
        // Match ignore patterns against the repo-relative path (so anchored
        // and multi-segment patterns work), not just the basename.
        let rel_path = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        // Ignore only excludes UNTRACKED content: an ignored file that is
        // already tracked (or an ignored dir holding tracked content) is
        // still visited so `add .`/`add -A` refresh tracked modifications,
        // matching git. The ancestor-ignored bit propagates so a tracked
        // dir's untracked-ignored children stay excluded.
        let entry_ignored = parent_ignored || ignores.is_ignored(&rel_path, is_dir);
        if entry_ignored && !super::index_tracks_path_or_descendant(idx, &rel_path) {
            continue;
        }
        if meta.file_type().is_dir() {
            add_tree(root, &p, entry_ignored, sink, idx, ignores, seen)?;
        } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
            // The include decision was made above, so `force` skips a
            // redundant ignore re-check in `add_one`.
            let rel = add_one(root, &p, sink, idx, ignores, true)?;
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

// =====================================================================
// `add -p` — interactive hunk staging
// =====================================================================

/// Outcome of patching a single file.
struct PatchOutcome {
    /// At least one hunk was staged (the index needs writing).
    staged: bool,
    /// The user asked to quit (`q`) — stop processing remaining files.
    quit: bool,
}

/// Drive interactive hunk staging across the named files. The index is
/// seeded from HEAD (so a base exists for already-committed files) and only
/// written back if at least one hunk was staged — selecting nothing leaves
/// the index untouched, matching `git add -p`.
fn run_patch(layout: &RepoLayout, store: &ObjectStore, paths: &[String], force: bool) -> u8 {
    let root = layout.worktree_root();
    let mut idx = match super::read_or_seed_index_from_head(layout, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let ignores = match ignore::load(root) {
        Ok(i) => i,
        Err(e) => return emit_err(&format!("read ignore file: {e}"), exit::GENERAL_ERROR),
    };
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut any_staged = false;
    for target in paths {
        match patch_one_file(
            root,
            Path::new(target),
            store,
            &mut idx,
            &ignores,
            force,
            &mut input,
        ) {
            Ok(outcome) => {
                any_staged |= outcome.staged;
                if outcome.quit {
                    break;
                }
            }
            Err(code) => return code,
        }
    }
    if any_staged && let Err(e) = index::write_index(layout, &idx) {
        return emit_err(&format!("write index: {e}"), exit::CANTCREAT);
    }
    exit::OK
}

fn patch_one_file(
    root: &Path,
    rel: &Path,
    store: &ObjectStore,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
    input: &mut impl BufRead,
) -> Result<PatchOutcome, u8> {
    let abs = if rel.is_absolute() {
        rel.to_path_buf()
    } else {
        root.join(rel)
    };
    let meta = abs
        .symlink_metadata()
        .map_err(|e| emit_err(&format!("metadata {}: {e}", abs.display()), exit::NOINPUT))?;
    let rel_str = abs
        .strip_prefix(root)
        .unwrap_or(rel)
        .to_string_lossy()
        .replace('\\', "/");
    if !index::validate_index_path(&rel_str) {
        return Err(emit_err(&format!("invalid path: {rel_str}"), exit::DATAERR));
    }
    // Refuse a path that reaches outside the repo through a symlinked parent
    // directory (e.g. `link_out/file.txt`): the lexical `rel_str` would be an
    // in-repo index path, but reading `abs` follows the symlink and would
    // stage external content. git refuses to add "beyond a symbolic link".
    if let Err(e) = ensure_within_repo(root, &abs) {
        return Err(emit_err(&e, exit::DATAERR));
    }
    // Interactive hunk staging is for regular text files only. Directories,
    // symlinks, and special files are refused with a clear message (git's
    // `add -p` likewise only patches regular files).
    if !meta.file_type().is_file() {
        return Err(emit_err(
            &format!("-p/--patch supports regular files only: {rel_str}"),
            exit::USAGE,
        ));
    }
    // An explicitly-named ignored path is refused unless `-f`, matching plain
    // `add`; an already-tracked path is never subject to ignore (git parity).
    let already_tracked = idx
        .find_entry(&rel_str)
        .is_some_and(|i| idx.entries[i].status != EntryStatus::Removed);
    if !force && !already_tracked && ignores.is_ignored_with_ancestors(&rel_str, false) {
        return Err(emit_err(
            &format!("path '{rel_str}' is ignored; use -f to add it anyway"),
            exit::USAGE,
        ));
    }

    // Base = the currently-staged (or HEAD-seeded) blob, or empty for a new
    // file. The worktree side is the on-disk content.
    let base = match idx.find_entry(&rel_str) {
        Some(i) if idx.entries[i].status != EntryStatus::Removed => {
            worktree::read_blob(store, &idx.entries[i].object_hash)
                .map_err(|e| emit_err(&format!("read staged blob: {e}"), exit::GENERAL_ERROR))?
        }
        _ => Vec::new(),
    };
    let previous_status = idx
        .find_entry(&rel_str)
        .map_or(EntryStatus::Blob, |i| idx.entries[i].status);
    let (opened_meta, work_bytes) = worktree::read_regular_file_bounded(&abs)
        .map_err(|e| emit_err(&format!("read {}: {e}", abs.display()), exit::NOINPUT))?;

    let hunks = match enumerate_hunks(&base, &work_bytes) {
        None => {
            eprintln!("{rel_str}: binary file — skipped (use `mkit add` to stage whole)");
            return Ok(PatchOutcome {
                staged: false,
                quit: false,
            });
        }
        Some(h) if h.is_empty() => {
            eprintln!("{rel_str}: no changes to stage");
            return Ok(PatchOutcome {
                staged: false,
                quit: false,
            });
        }
        Some(h) => h,
    };

    let (selected, quit) = select_hunks(&rel_str, &hunks, input)?;
    if selected.is_empty() {
        return Ok(PatchOutcome {
            staged: false,
            quit,
        });
    }

    let new_bytes = apply_hunks_subset(&base, &hunks, &selected);
    let h = worktree::store_file_object(store, &new_bytes)
        .map_err(|e| emit_err(&format!("store: {e}"), exit::CANTCREAT))?;
    let status = file_status_from_meta(&opened_meta, previous_status);
    let entry = IndexEntry {
        path: rel_str.clone(),
        status,
        object_hash: h,
        mtime_ns: 0,
        size: 0,
        ino: 0,
        ctime_ns: 0,
    };
    idx.remove_directory_conflicts(&entry.path);
    idx.upsert_entry(entry);
    eprintln!(
        "{rel_str}: staged {} of {} hunks",
        selected.len(),
        hunks.len()
    );
    Ok(PatchOutcome { staged: true, quit })
}

/// Prompt the user for each hunk and return the indices to stage plus
/// whether they asked to quit. Prompts and hunk rendering go to stderr
/// (human-facing); stdout stays clean.
fn select_hunks(
    path: &str,
    hunks: &[PatchHunk],
    input: &mut impl BufRead,
) -> Result<(Vec<usize>, bool), u8> {
    let mut stderr = std::io::stderr().lock();
    let mut selected = Vec::new();
    // `Some(true)` = stage all remaining (`a`), `Some(false)` = skip all
    // remaining (`d`).
    let mut auto: Option<bool> = None;
    let mut i = 0;
    while i < hunks.len() {
        if let Some(stage_rest) = auto {
            if stage_rest {
                selected.push(i);
            }
            i += 1;
            continue;
        }
        render_hunk(&mut stderr, path, i, hunks.len(), &hunks[i]);
        let _ = write!(stderr, "Stage this hunk [y,n,q,a,d,?]? ");
        let _ = stderr.flush();
        let mut line = String::new();
        let read = input
            .read_line(&mut line)
            .map_err(|e| emit_err(&format!("read input: {e}"), exit::NOINPUT))?;
        if read == 0 {
            // EOF — treat as quit, staging whatever was chosen so far.
            return Ok((selected, true));
        }
        match line.trim().chars().next() {
            Some('y') => {
                selected.push(i);
                i += 1;
            }
            Some('n') => i += 1,
            Some('q') => return Ok((selected, true)),
            Some('a') => {
                selected.push(i);
                auto = Some(true);
                i += 1;
            }
            Some('d') => auto = Some(false),
            _ => {
                let _ = writeln!(
                    stderr,
                    "y - stage this hunk\nn - skip this hunk\nq - quit; stage selected hunks\na - stage this and all later hunks in the file\nd - skip this and all later hunks in the file\n? - print help"
                );
            }
        }
    }
    Ok((selected, false))
}

/// Render a hunk to `out` as a unified-diff fragment for display.
fn render_hunk(out: &mut impl Write, path: &str, idx: usize, total: usize, hunk: &PatchHunk) {
    let _ = writeln!(out, "--- {path} (hunk {}/{total}) ---", idx + 1);
    let _ = writeln!(
        out,
        "@@ -{} +{} @@",
        range_str(hunk.old_start, hunk.old_len),
        range_str(hunk.new_start, hunk.new_len)
    );
    for l in &hunk.lines {
        let prefix = match l.kind {
            HunkLineKind::Context => b' ',
            HunkLineKind::Added => b'+',
            HunkLineKind::Removed => b'-',
        };
        let mut buf = vec![prefix];
        buf.extend_from_slice(&l.text);
        buf.push(b'\n');
        let _ = out.write_all(&buf);
        if !l.has_newline {
            let _ = writeln!(out, "\\ No newline at end of file");
        }
    }
}

/// Format one side of an `@@` range: `start,len`, omitting `,len` when 1.
fn range_str(start: usize, len: usize) -> String {
    if len == 1 {
        start.to_string()
    } else {
        format!("{start},{len}")
    }
}

/// Reject an explicitly-named path that escapes the repository through a
/// symlinked parent directory. Two refusals, matching git's "beyond a
/// symbolic link" behavior:
///
/// 1. The path escapes the repo — its canonical parent is not under the
///    canonical repo root (covers `..` traversal and symlinks pointing
///    outside).
/// 2. Any intermediate (non-leaf) path component is a symlink — even one
///    resolving back *inside* the repo. Staging under the lexical path (e.g.
///    `link_in/file.txt`) would record an index/tree shape the worktree
///    snapshot can never reproduce, since the snapshot treats `link_in` as a
///    symlink, not a directory. A symlink as the *leaf* is fine (it is staged
///    as a symlink).
///
/// Only used for explicitly-named paths; the `.`/`-A` worktree walk never
/// descends symlinked directories, so it cannot reach through one this way.
fn ensure_within_repo(root: &Path, abs: &Path) -> Result<(), String> {
    use std::path::Component;

    let parent = abs
        .parent()
        .ok_or_else(|| format!("invalid path: {}", abs.display()))?;
    let real_parent = parent
        .canonicalize()
        .map_err(|e| format!("path {}: {e}", parent.display()))?;
    let real_root = root.canonicalize().map_err(|e| format!("repo root: {e}"))?;
    if real_parent != real_root && !real_parent.starts_with(&real_root) {
        return Err(format!("path is outside repository: {}", abs.display()));
    }

    // Reject a symlink anywhere in the parent chain (between root and the
    // leaf). `abs` is `root.join(rel)` for relative args, so stripping root
    // yields the user-supplied components to check; an absolute arg that does
    // not lie lexically under root is already caught by the escape check.
    if let Ok(rel) = abs.strip_prefix(root) {
        let comps: Vec<Component<'_>> = rel.components().collect();
        let parent_count = comps.len().saturating_sub(1); // exclude the leaf
        let mut cur = root.to_path_buf();
        for comp in &comps[..parent_count] {
            if let Component::Normal(name) = comp {
                cur.push(name);
                if matches!(cur.symlink_metadata(), Ok(m) if m.file_type().is_symlink()) {
                    return Err(format!(
                        "path traverses a symbolic link ({}): refusing to stage beyond it",
                        cur.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

use super::error as emit_err;
