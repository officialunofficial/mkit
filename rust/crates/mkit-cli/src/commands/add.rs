//! `mkit add <path>` / `mkit add .` — stage a file (or the whole
//! worktree) into `.mkit/index`. `add -p` additionally stages individual
//! hunks interactively (see `run_patch`).

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use mkit_core::hash::{Hash, ZERO};
use mkit_core::ignore::{self, IgnoreList};
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Object};
use mkit_core::ops::{HunkLineKind, PatchHunk, apply_hunks_subset, enumerate_hunks};
use mkit_core::serialize;
use mkit_core::store::{ObjectSink, ObjectStore};
use mkit_core::worktree;
use rayon::prelude::*;

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

    let previous = idx.clone();

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
    retain_content_identities(store, &previous, &mut idx)?;
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

    let previous = idx.clone();

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
    if let Err(e) = retain_content_identities(&store, &previous, &mut idx) {
        return emit_err(&e, exit::DATAERR);
    }
    match index::write_index(&layout, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

/// Preserve an existing staged representation when restaging identical content.
/// Called after the object batch is durable, so comparison reads the exact bytes
/// just hashed (never a second, potentially raced worktree read).
fn retain_content_identities(
    store: &ObjectStore,
    previous: &Index,
    next: &mut Index,
) -> Result<(), String> {
    let old: std::collections::HashMap<_, _> = previous
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();
    for entry in &mut next.entries {
        if entry.status == EntryStatus::Removed {
            continue;
        }
        if let Some(before) = old.get(entry.path.as_str())
            && before.status != EntryStatus::Removed
            && worktree::content_eq(store, &before.object_hash, &entry.object_hash)
                .map_err(|e| format!("compare staged {}: {e}", entry.path))?
        {
            entry.object_hash = before.object_hash;
        }
    }
    Ok(())
}

/// Stage every non-ignored worktree file under `root`, then mark any
/// tracked path missing from the worktree as removed. Backs both
/// `mkit add .` and `mkit add -A`.
fn add_whole_worktree(
    root: &Path,
    sink: &(dyn ObjectSink + Sync),
    idx: &mut Index,
) -> Result<(), u8> {
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
    let mut pending = Vec::new();
    add_tree(
        root,
        root,
        false,
        sink,
        idx,
        &ignores,
        &mut seen,
        &mut pending,
    )?;

    // The walk above only stats/validates paths (cheap); the expensive
    // part — open + read + BLAKE3, streaming through `FastCdc` for large
    // files — happens in `hash_pending_batch`, sequentially or via
    // rayon depending on how many files are pending (see
    // `hash_fanout_threshold`). Index mutation stays single-threaded and
    // in walk order below regardless of which path hashed the files, so
    // `remove_directory_conflicts`/`upsert_entry` (via `stage_hashed`)
    // see the same order the fully-sequential pre-parallelism code did.
    let hashed = hash_pending_batch(&pending, sink);

    // Any single failure aborts the whole command — the caller never
    // calls `batch.commit()`/`index::write_index()` on an `Err` path, so
    // nothing persists regardless of how many files hashed successfully
    // first. That's why it's fine to skip applying anything to `idx`
    // below once a failure is known, and why `hash_one`'s `aborted` flag
    // is worth having: it lets not-yet-started hashes skip entirely
    // once one file has failed, instead of every pending file paying
    // its full hash cost only to have the result discarded.
    //
    // Report the first failure in walk order (`hashed` mirrors
    // `pending`'s order 1:1) — the same file `add` would have stopped
    // on before this was parallelized — printed exactly once here
    // rather than once per failing closure.
    if let Some(pos) = hashed
        .iter()
        .position(|h| matches!(h, HashOutcome::Failed(_)))
    {
        let HashOutcome::Failed(e) = &hashed[pos] else {
            unreachable!("position() just matched a Failed variant")
        };
        return Err(emit_err(&e.message, e.code));
    }

    for (p, outcome) in pending.into_iter().zip(hashed) {
        let HashOutcome::Done(hashed_file) = outcome else {
            unreachable!(
                "Skipped only occurs once a Failed entry exists, and the check above already returned on any Failed entry"
            )
        };
        stage_hashed(idx, p.rel_str.clone(), hashed_file);
        seen.insert(p.rel_str);
    }

    mark_missing_paths_removed(root, idx, &seen);
    Ok(())
}

/// Files-per-thread budget below which [`hash_pending_batch`] hashes
/// sequentially instead of fanning out across rayon's thread pool, for
/// a pool of a given size.
///
/// Measured with `cargo bench -p mkit-benches --bench add_hash_fanout`
/// (PR #951 Slack thread) on a 4-core box: rayon's pool-dispatch
/// overhead makes it 25-100% slower than a plain loop for 1-16 files,
/// roughly ties a plain loop at 32, and wins clearly from 64 files up
/// (the realistic-bulk-add case `add_staging`'s 10k/100k cases already
/// cover) — 32 files / 4 threads = 8 files/thread, the conservative
/// side of that crossover. [`hash_fanout_threshold`] scales this by
/// the *actual* pool size rather than hardcoding 32, so the decision
/// stays meaningful on a CI runner or contributor machine with a
/// different core count than the one this was measured on — the ratio
/// is assumed to hold rather than re-measured per core count.
///
/// A `commonware_parallel::Rayon`-backed adaptive strategy (raised in
/// the same Slack thread, see `mkit-core/src/pack_shard.rs`'s
/// `should_use_parallel_strategy`) was considered and rejected: that
/// function is the same kind of static threshold as this one (a plain
/// byte-length comparison), not commonware's learned-history policy,
/// and it only needs `OnceLock`-memoized pool construction because it
/// is forced to own a dedicated `commonware_parallel::Rayon` pool.
/// Plain `rayon::prelude::*` (used here) already reuses rayon's own
/// cached global pool across calls for free, so adopting
/// commonware-parallel here would add its dependency weight to
/// mkit-cli for no benefit over what this file already does.
const HASH_FANOUT_FILES_PER_THREAD: usize = 8;

/// The pending-file count below which [`hash_pending_batch`] hashes
/// sequentially — see [`HASH_FANOUT_FILES_PER_THREAD`] for where the
/// budget comes from. Reads rayon's already-initialized global pool
/// size (cheap: an atomic load after first use, no allocation).
fn hash_fanout_threshold() -> usize {
    crate::fanout::threshold(HASH_FANOUT_FILES_PER_THREAD)
}

/// Hash one [`PendingHash`], short-circuiting to [`HashOutcome::Skipped`]
/// once `aborted` is set by an earlier failure (from this call or a
/// concurrent one). Shared by both branches of [`hash_pending_batch`]
/// — an `AtomicBool` costs nothing extra in the sequential branch's
/// single-threaded loop, and sharing this closure keeps the two
/// branches' fail-fast/`Skipped` semantics from drifting apart.
fn hash_one(sink: &dyn ObjectSink, aborted: &AtomicBool, p: &PendingHash) -> HashOutcome {
    if aborted.load(Ordering::Relaxed) {
        return HashOutcome::Skipped;
    }
    match hash_pending(sink, p) {
        Ok(v) => HashOutcome::Done(v),
        Err(e) => {
            aborted.store(true, Ordering::Relaxed);
            HashOutcome::Failed(e)
        }
    }
}

/// Hash every `pending` file — sequentially below
/// [`hash_fanout_threshold`], via rayon's global thread pool at or
/// above it. Output mirrors `pending`'s order 1:1 either way, and both
/// paths stop starting new hashes once one file has failed (see
/// [`HashOutcome::Skipped`]) — nothing downstream uses a `Skipped`
/// entry's value, since [`add_whole_worktree`] discards all of
/// `hashed` on any [`HashOutcome::Failed`].
///
/// `WriteBatch::write` (batch.rs) short-locks only its staged-dedup
/// check and does file I/O outside that lock specifically so
/// concurrent writers sharing one batch don't convoy on each other —
/// this is the "future parallel ingest" its own doc comment
/// anticipated.
fn hash_pending_batch(pending: &[PendingHash], sink: &(dyn ObjectSink + Sync)) -> Vec<HashOutcome> {
    let aborted = AtomicBool::new(false);
    if pending.len() < hash_fanout_threshold() {
        return pending
            .iter()
            .map(|p| hash_one(sink, &aborted, p))
            .collect();
    }
    pending
        .par_iter()
        .map(|p| hash_one(sink, &aborted, p))
        .collect()
}

/// Result of hashing one [`PendingHash`] inside [`hash_pending_batch`].
enum HashOutcome {
    Done(HashedFile),
    Failed(HashError),
    /// A different file already failed (`aborted` was set) — this one
    /// never ran `hash_pending` at all.
    Skipped,
}

/// A regular file whose staging was routed by [`route_path`] but whose
/// hash is not yet computed — the expensive part (open + read + BLAKE3,
/// possibly a whole-file streaming chunk pass) is deferred so a
/// tree-wide walk can run it across files in parallel (see
/// [`add_whole_worktree`]).
struct PendingHash {
    abs: PathBuf,
    rel_str: String,
    previous_status: EntryStatus,
}

/// Outcome of routing one worktree path through the shared validate /
/// ignore / stat-cache checks that used to live inline in `add_one`.
enum Routed {
    /// Already staged byte-for-byte (stat cache hit, or nothing to do).
    Done(String),
    /// Regular file that needs hashing — see [`PendingHash`].
    NeedsHash(PendingHash),
}

/// Validate `abs`/`rel`, resolve the ignore/stat-cache decision, and
/// stage symlinks inline (cheap: no file-content I/O). Regular files are
/// handed back as a [`PendingHash`] rather than hashed here, so callers
/// that stage many files at once (the `add_tree` walk) can hash them in
/// parallel instead of one at a time.
///
/// Shared by [`add_one`] (single explicit path, hashed synchronously)
/// and [`add_tree`] (whole-worktree walk, hashed via rayon).
fn route_path(
    root: &Path,
    rel: &Path,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<Routed, u8> {
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
        return Ok(Routed::Done(rel_str));
    }
    // Regular files route through `store_file_object` (via
    // `hash_file_with_metadata`, called by the caller once hashing
    // actually runs) so large (> CHUNK_THRESHOLD) content lands as a
    // ChunkedBlob, matching `worktree::{build_tree,hash_file}` (#203).
    // Symlinks stay a single Blob of their target path and are cheap
    // enough (no file-content I/O) to stage right here.
    if meta.file_type().is_file() {
        Ok(Routed::NeedsHash(PendingHash {
            abs,
            rel_str,
            previous_status,
        }))
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
        let entry = IndexEntry {
            path: rel_str.clone(),
            // Symlinks never stat-match (see worktree::stat_matches).
            status: EntryStatus::Symlink,
            object_hash: h,
            mtime_ns: 0,
            size: 0,
            ino: 0,
            ctime_ns: 0,
        };
        idx.remove_directory_conflicts(&entry.path);
        idx.upsert_entry(entry);
        Ok(Routed::Done(rel_str))
    } else {
        Err(emit_err(
            &format!("not a regular file: {}", abs.display()),
            exit::NOINPUT,
        ))
    }
}

/// A hashed file's staging fields: status, content hash, and the
/// `(mtime_ns, size, ino, ctime_ns)` stat-cache tuple.
type HashedFile = (EntryStatus, Hash, (u64, u64, u64, u64));

/// A hashing failure that hasn't been reported yet: message + sysexits
/// code, matching what `emit_err` takes. Kept unprinted until exactly
/// one survives (see [`hash_pending`]'s doc) — `hash_pending` runs
/// concurrently across a rayon thread pool, and `emit_err` prints as a
/// side effect, so printing inside it would echo one line per failing
/// file in the batch instead of the single error the command ultimately
/// returns.
struct HashError {
    message: String,
    code: u8,
}

/// Hash a [`PendingHash`]'s file content. Pure function of `sink` and
/// `p` (no index access, no printing), so it is safe to call
/// concurrently across a batch's `PendingHash` list — `sink` (a
/// `WriteBatch`) short-locks only its staged-dedup check and runs file
/// I/O outside that lock. Callers report the error themselves via
/// `emit_err` at the one point it's known to be *the* reported error
/// (see [`add_one`] and [`add_whole_worktree`]).
fn hash_pending(sink: &dyn ObjectSink, p: &PendingHash) -> Result<HashedFile, HashError> {
    let (h, opened_meta) =
        worktree::hash_file_with_metadata(sink, &p.abs).map_err(|e| HashError {
            message: format!("{}: {e}", p.abs.display()),
            code: worktree_err_exit_code(&e),
        })?;
    let stat = worktree::stat_cache_fields(&opened_meta);
    let status = file_status_from_meta(&opened_meta, p.previous_status);
    Ok((status, h, stat))
}

/// Build the index entry for a successfully-hashed file and apply it —
/// the tail shared by [`add_one`]'s single-path hash and
/// [`add_whole_worktree`]'s parallel-hash apply loop.
fn stage_hashed(idx: &mut Index, rel_str: String, hashed: HashedFile) {
    let (status, h, stat) = hashed;
    let entry = IndexEntry {
        path: rel_str,
        status,
        object_hash: h,
        mtime_ns: stat.0,
        size: stat.1,
        ino: stat.2,
        ctime_ns: stat.3,
    };
    idx.remove_directory_conflicts(&entry.path);
    idx.upsert_entry(entry);
}

fn add_one(
    root: &Path,
    rel: &Path,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    force: bool,
) -> Result<String, u8> {
    match route_path(root, rel, sink, idx, ignores, force)? {
        Routed::Done(rel_str) => Ok(rel_str),
        Routed::NeedsHash(p) => {
            let hashed = hash_pending(sink, &p).map_err(|e| emit_err(&e.message, e.code))?;
            stage_hashed(idx, p.rel_str.clone(), hashed);
            Ok(p.rel_str)
        }
    }
}

/// Walk `dir`, routing each included file/symlink through [`route_path`].
/// Symlinks (and stat-cache hits) are fully staged as they're visited;
/// regular files that need hashing are appended to `pending` instead, so
/// [`add_whole_worktree`] can hash the whole tree's files in parallel
/// once the (cheap, metadata-only) walk finishes.
fn add_tree(
    root: &Path,
    dir: &Path,
    parent_ignored: bool,
    sink: &dyn ObjectSink,
    idx: &mut Index,
    ignores: &IgnoreList,
    seen: &mut HashSet<String>,
    pending: &mut Vec<PendingHash>,
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
            add_tree(root, &p, entry_ignored, sink, idx, ignores, seen, pending)?;
        } else if meta.file_type().is_file() || meta.file_type().is_symlink() {
            // The include decision was made above, so `force` skips a
            // redundant ignore re-check in `route_path`.
            match route_path(root, &p, sink, idx, ignores, true)? {
                Routed::Done(rel) => {
                    seen.insert(rel);
                }
                Routed::NeedsHash(pend) => pending.push(pend),
            }
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
