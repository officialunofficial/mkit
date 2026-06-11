//! Subcommand implementations. Each top-level command is its own
//! module.
//!
//! Dispatch lives in `main.rs`; business logic lives in library
//! crates; this module is the thin presentation shim.

pub mod add;
pub mod attest;
pub mod attest_factory;
pub mod bisect;
pub mod blame;
pub mod branch;
pub mod cat;
pub mod cat_file;
pub mod checkout;
pub mod cherry_pick;
pub mod clean;
pub mod clone;
pub mod commit;
pub mod config_cmd;
pub mod conflict;
pub mod diff;
pub mod fetch;
pub mod for_each_ref;
pub mod gc;
#[cfg(feature = "git-bridge")]
pub mod git;
#[cfg(feature = "git-bridge")]
pub mod git_import;
pub mod hash_cmd;
pub mod init;
pub mod key;
pub mod keygen;
pub mod log;
pub mod ls_files;
pub mod ls_tree;
pub mod merge;
pub mod mv;
#[cfg(feature = "pack-shards")]
pub mod pack_shard;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod reflog;
pub mod remote;
pub mod reset;
pub mod restore;
pub mod rev_parse;
pub mod revert;
pub mod revspec;
pub mod rm;
pub mod serve;
pub mod show;
pub mod show_ref;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod symbolic_ref;
pub mod tag;
pub mod tree;
pub mod update_ref;
pub mod verify;
pub mod verify_attest;

use crate::exit;
use mkit_core::hash::Hash;
use mkit_core::index::{EntryStatus, Index};
use mkit_core::object::Object;
use mkit_core::ops::diff::{DiffKind, diff_trees};
use mkit_core::ops::recovery::{self, RecoveryEntry};
use mkit_core::ops::restore::{RestoreOptions, matches_sparse, restore_tree_to_worktree};
use mkit_core::refs::{self, Head, RefError, RefWriteCondition};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Shared helper: emit a "not yet wired" notice and return the
/// tempfail exit code. Commands whose backing state-machines haven't
/// been wired into the CLI yet say so honestly rather than pretending
/// to work.
#[must_use]
pub fn not_yet_ported(cmd: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: `mkit {cmd}` is not yet wired");
    exit::TEMPFAIL
}

/// Shared helper: print a usage error and return the USAGE exit code.
#[must_use]
pub fn usage_error(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
}

/// Basename of the repo-level lock that serialises worktree/index
/// read-modify-write commands (`add`, `rm`, `commit`, `merge`,
/// `checkout`, `rebase`, `cherry-pick`, `stash`, `sparse-checkout`).
///
/// Ref-only mutations (`branch`/`tag`) and config-only mutations do not
/// take this lock — they rely on ref-CAS / atomic-config writes instead.
pub const WORKTREE_LOCK: &str = "worktree.lock";

/// Acquire the shared worktree/index lock for the repo rooted at `root`.
///
/// Hold the returned guard across the whole read-modify-write so a
/// second mutating `mkit` blocks (then times out) instead of racing on
/// the worktree + `.mkit/index`. On failure, the lock message has
/// already been printed to stderr and the returned [`u8`] is the exit
/// code to propagate.
///
/// Mirrors the pattern already used in `sparse_checkout` and
/// `remote_dispatch`; new mutating commands should reuse this helper
/// rather than calling `repo_lock::acquire_default` directly.
///
/// # Errors
/// Returns [`exit::TEMPFAIL`] when the lock cannot be taken within the
/// default timeout (another `mkit` holds it, or a stale lockfile is
/// present).
pub fn acquire_worktree_lock(root: &Path) -> Result<mkit_core::repo_lock::RepoLock, u8> {
    let mkit_dir = root.join(mkit_core::MKIT_DIR);
    mkit_core::repo_lock::acquire_default(&mkit_dir, WORKTREE_LOCK).map_err(|e| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "error: repo lock: {e}");
        exit::TEMPFAIL
    })
}

/// C-style-quote `path` the way Git does for porcelain / `--name-*`
/// output when a path contains bytes that need escaping. Returns `None`
/// when the path is "plain" (all printable ASCII except `"`/`\`) and can
/// be emitted as-is. Shared by `status` and `diff --name-only/-status`.
///
/// Quoting rule (matches Git's `quote_c_style` with the default
/// `core.quotePath=true`): quote if any byte is a control char (`< 0x20`),
/// `"`, `\`, or non-printable / non-ASCII (`>= 0x7f`). Inside the quotes,
/// the common control chars use their `\a\b\t\n\v\f\r` escapes, `"` and
/// `\` are backslash-escaped, printable ASCII is literal, and everything
/// else is a 3-digit `\NNN` octal escape (per UTF-8 byte).
pub(crate) fn c_quote_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let needs = bytes
        .iter()
        .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b >= 0x7f);
    if !needs {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0b => out.push_str("\\v"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\{other:03o}");
            }
        }
    }
    out.push('"');
    Some(out)
}

/// Resolve a CLI path argument to a repo-relative, `/`-separated index
/// path, validating it. Shared by `rm` and `mv` so both resolve and
/// validate pathspecs identically (absolute args are mapped under the
/// repo root, `.`/`..` are normalized, and the result is checked against
/// [`mkit_core::index::validate_index_path`]).
pub(crate) fn index_path_for_arg(root: &Path, arg: &Path) -> Result<String, String> {
    use std::path::Component;
    let rel = if arg.is_absolute() {
        absolute_arg_to_repo_relative(root, arg)?
    } else {
        arg.to_path_buf()
    };

    let mut parts: Vec<String> = Vec::new();
    for component in rel.as_path().components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| "path is not valid UTF-8".to_string())?;
                parts.push(part.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err(format!("invalid path: {}", arg.display()));
                }
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(format!("invalid path: {}", arg.display()));
            }
        }
    }

    let path = parts.join("/");
    if !mkit_core::index::validate_index_path(&path) {
        return Err(format!("invalid path: {path}"));
    }
    Ok(path)
}

/// Map an absolute path argument to a path relative to the repo `root`,
/// erroring if it escapes the repository. Handles not-yet-existing tail
/// components (the leaf may not exist yet, e.g. an `mv` destination).
pub(crate) fn absolute_arg_to_repo_relative(
    root: &Path,
    arg: &Path,
) -> Result<std::path::PathBuf, String> {
    use std::ffi::OsString;
    let root = root.canonicalize().map_err(|e| format!("repo root: {e}"))?;

    if let Ok(rel) = arg.strip_prefix(&root) {
        return Ok(rel.to_path_buf());
    }

    let mut suffix: Vec<OsString> = vec![
        arg.file_name()
            .ok_or_else(|| format!("invalid path: {}", arg.display()))?
            .to_os_string(),
    ];
    let mut ancestor = arg
        .parent()
        .ok_or_else(|| format!("invalid path: {}", arg.display()))?;
    while ancestor.symlink_metadata().is_err() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| format!("path is outside repository: {}", arg.display()))?;
    }

    let mut normalized = ancestor
        .canonicalize()
        .map_err(|e| format!("path {}: {e}", ancestor.display()))?;
    for component in suffix.iter().rev() {
        normalized.push(component);
    }

    normalized
        .strip_prefix(&root)
        .map(Path::to_path_buf)
        .map_err(|_| format!("path is outside repository: {}", arg.display()))
}

/// The worktree's current staged representation `(status, hash)` for
/// `path`: a regular file (with its exec bit), a symlink (blob of its
/// target), or `None` when the path is missing or not a stageable type
/// (e.g. a directory). Mirrors how `add` stages one entry, so a caller can
/// compare a worktree path to an index entry by **content AND mode/type** —
/// catching symlink-target and chmod-only changes that a content-only hash
/// would miss.
pub(crate) fn worktree_entry_state(
    root: &Path,
    store: &ObjectStore,
    path: &str,
) -> Result<Option<(EntryStatus, Hash)>, String> {
    let abs = root.join(path);
    let meta = match abs.symlink_metadata() {
        Ok(m) => m,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(format!("metadata {}: {e}", abs.display())),
    };
    if meta.file_type().is_file() {
        let (opened_meta, bytes) = worktree::read_regular_file_bounded(&abs)
            .map_err(|e| format!("read {}: {e}", abs.display()))?;
        let h = worktree::store_file_object(store, &bytes).map_err(|e| format!("store: {e}"))?;
        Ok(Some((file_exec_status(&opened_meta), h)))
    } else if meta.file_type().is_symlink() {
        let target =
            fs::read_link(&abs).map_err(|e| format!("read link {}: {e}", abs.display()))?;
        let target_str = target
            .to_str()
            .ok_or_else(|| "symlink target is not valid UTF-8".to_string())?;
        if !worktree::validate_symlink_target(target_str) {
            return Err(format!("invalid symlink target: {target_str}"));
        }
        let blob = Object::Blob(mkit_core::object::Blob {
            data: target_str.as_bytes().to_vec(),
        });
        let ser = mkit_core::serialize::serialize(&blob).map_err(|e| format!("serialize: {e}"))?;
        let h = store.write(&ser).map_err(|e| format!("store: {e}"))?;
        Ok(Some((EntryStatus::Symlink, h)))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn file_exec_status(meta: &fs::Metadata) -> EntryStatus {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o111 != 0 {
        EntryStatus::Executable
    } else {
        EntryStatus::Blob
    }
}

#[cfg(not(unix))]
fn file_exec_status(_meta: &fs::Metadata) -> EntryStatus {
    EntryStatus::Blob
}

pub(crate) fn index_path_matches_or_descends(path: &str, base: &str) -> bool {
    path == base || index_path_descends_from(path, base)
}

pub(crate) fn index_path_descends_from(path: &str, base: &str) -> bool {
    path.len() > base.len()
        && path.starts_with(base)
        && path.as_bytes().get(base.len()) == Some(&b'/')
}

// ---------------------------------------------------------------------------
// History-MMR ref-write helper (feature: history-mmr)
// ---------------------------------------------------------------------------
//
// Phase 2 of issue #157. Every CLI subcommand that advances a branch ref
// MUST route the write through this helper instead of calling
// `refs::write_ref` / `refs::update_ref` directly. Default builds
// (no `history-mmr` feature) keep the old direct semantics; the
// feature-gated path opens a per-branch journaled `CommitHistory`, takes
// a single repo-level lock around (ref-write + MMR-append), and syncs
// the journal to disk before returning.
//
// The executor is a **process-global** `Arc<TokioExecutor>` — we
// construct exactly one per process via `OnceLock` so multiple branch
// advances share one tokio runtime. Threading the executor through
// every CLI helper would force `history-mmr` into the signature of
// every subcommand entry point, so we keep it local to this module.

/// Construct (lazily) and share the process-wide `TokioExecutor` used
/// by every history-MMR-coupled ref write in the CLI.
///
/// One executor per process: each `TokioExecutor` owns a multi-thread
/// tokio runtime, and re-constructing it per ref-write would burn a
/// fresh runtime for every commit. The `OnceLock` is initialised on the
/// first call; subsequent calls reuse the same `Arc` clone.
#[cfg(feature = "history-mmr")]
pub(crate) fn history_executor() -> std::sync::Arc<mkit_core::history::TokioExecutor> {
    use std::sync::{Arc, OnceLock};
    static EXECUTOR: OnceLock<Arc<mkit_core::history::TokioExecutor>> = OnceLock::new();
    EXECUTOR
        .get_or_init(|| {
            let exec = mkit_core::history::TokioExecutor::new()
                .expect("history-mmr tokio runtime must initialise");
            Arc::new(exec)
        })
        .clone()
}

/// CLI-side ref-write helper that records every advance in the
/// branch's history MMR when `history-mmr` is enabled.
///
/// Behaviour matrix:
///
/// - **Default build (no `history-mmr`)** — exactly equivalent to
///   `refs::update_ref(mkit_dir, branch, condition, new_hash)`.
/// - **`--features history-mmr`** — opens a journaled
///   `CommitHistory` for `branch` under `<mkit_dir>/history/`, takes
///   the `refs-history.lock` repo lock, performs the CAS ref-write,
///   appends `new_hash` to the MMR, and `sync()`s the journal before
///   returning. The journal survives `SIGKILL` immediately after the
///   call returns. See `mkit-core::refs::update_ref_with_history` and
///   SPEC-HISTORY-PROOF §4 for the contract.
///
/// All CLI subcommands that move a branch ref MUST funnel through this
/// helper rather than calling `refs::write_ref` or `refs::update_ref`
/// directly. Detached-HEAD writes (`refs::write_head_detached`) are
/// not history-tracked: the per-branch journal is keyed on the branch
/// name, and detached HEADs have none.
pub fn write_ref_recording_history(
    mkit_dir: &Path,
    branch: &str,
    condition: RefWriteCondition,
    new_hash: &Hash,
) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        let exec = history_executor();
        let mut history = mkit_core::history::CommitHistory::open_at(exec, mkit_dir, branch)
            .map_err(|e| RefError::InvalidRef(format!("{branch}: open history journal: {e}")))?;
        refs::update_ref_with_history(mkit_dir, branch, condition, new_hash, &mut history)
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::update_ref(mkit_dir, branch, condition, new_hash)
    }
}

/// Current branch name for recovery logging — empty for a detached HEAD
/// or an unreadable/symbolic-only HEAD.
#[must_use]
pub fn head_branch_name(mkit_dir: &Path) -> String {
    match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => name,
        _ => String::new(),
    }
}

/// Record `superseded` (the old branch tip a history-rewriting op is
/// about to replace) in the recovery log so `mkit gc` keeps it
/// recoverable.
///
/// Call this **before** moving the ref and while holding the worktree
/// lock (every caller does both): recording first guarantees that a
/// persisted ref move always has a persisted recovery entry, and the
/// lock keeps a concurrent `recovery::expire` from clobbering the append.
/// On failure the caller MUST abort the rewrite (propagate the returned
/// error) rather than orphan an unrecoverable commit. The zero hash is a
/// no-op inside [`recovery::record`].
pub fn record_superseded(
    mkit_dir: &Path,
    op: &str,
    branch: &str,
    superseded: Hash,
) -> Result<(), (String, u8)> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let entry = RecoveryEntry {
        timestamp,
        op: op.to_owned(),
        superseded,
        branch: branch.to_owned(),
    };
    recovery::record(mkit_dir, &entry).map_err(|e| (format!("recovery log: {e}"), exit::CANTCREAT))
}

/// Rewrite `.mkit/index` so it exactly mirrors `tree_hash`.
///
/// `mkit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(root: &Path, store: &ObjectStore, tree_hash: Hash) -> Result<(), String> {
    let idx = mkit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    mkit_core::index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))
}

/// Materialise `tree_hash` and align the index while preserving `.mkitignore` entries.
pub fn restore_worktree_and_index(
    root: &Path,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    restore_tree_to_worktree(store, &tree_hash, root, &RestoreOptions::default())
        .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree(root, store, tree_hash)
}

/// Refuse a destructive restore when the index/worktree contains user work.
pub fn ensure_restore_safe(
    root: &Path,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<(), String> {
    ensure_restore_safe_with_options(root, store, target_tree, &RestoreOptions::default())
}

/// Refuse a destructive restore when affected index/worktree paths contain user work.
pub fn ensure_restore_safe_with_options(
    root: &Path,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
) -> Result<(), String> {
    let current_tree = current_head_tree(root, store)?;
    let idx = read_or_seed_index_from_head(root, store)?;
    let index_tree = worktree::build_tree_from_index(store, &idx)
        .map_err(|e| format!("check index state: {e}"))?;

    let staged = diff_trees(store, current_tree, Some(index_tree))
        .map_err(|e| format!("check staged changes: {e}"))?;
    if let Some(entry) = staged
        .entries
        .iter()
        .find(|entry| restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite staged changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let worktree_tree = worktree::build_tree_filtered(store, root, Some(&idx))
        .map_err(|e| format!("check working tree changes: {e}"))?;
    let unstaged = diff_trees(store, Some(index_tree), Some(worktree_tree))
        .map_err(|e| format!("check working tree changes: {e}"))?;
    if let Some(entry) = unstaged
        .entries
        .iter()
        .find(|entry| entry.kind != DiffKind::Added && restore_affects_path(options, &entry.path))
    {
        return Err(format!(
            "restore would overwrite local changes; commit, stash, or reset '{}' first",
            entry.path
        ));
    }

    let target_writes = diff_trees(store, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("check restore target: {e}"))?
        .entries
        .into_iter()
        .filter(|entry| entry.kind != DiffKind::Removed)
        .filter(|entry| restore_affects_path(options, &entry.path))
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    if target_writes.is_empty() && !options.clean {
        return Ok(());
    }

    let ignore = mkit_core::ignore::load(root).map_err(|e| format!("read ignore file: {e}"))?;
    let mut worktree_paths = Vec::new();
    collect_worktree_paths(root, root, "", &mut worktree_paths)
        .map_err(|e| format!("check untracked paths: {e}"))?;
    if let Some(path) = worktree_paths.iter().find(|path| {
        !index_tracks_path_or_descendant(&idx, path)
            && target_writes
                .iter()
                .any(|target| paths_overlap(path, target))
    }) {
        return Err(format!(
            "restore would overwrite untracked path '{path}'; move or remove it first"
        ));
    }

    if options.clean
        && let Some(path) = worktree_paths.iter().find(|path| {
            !index_tracks_path_or_descendant(&idx, path)
                && restore_affects_path(options, path)
                && *path != ".mkitignore"
                && *path != ".gitignore"
                && !is_ignored_worktree_path(root, &ignore, path)
        })
    {
        return Err(format!(
            "restore would remove untracked path '{path}'; move or remove it first"
        ));
    }

    Ok(())
}

pub(crate) fn restore_affects_path(options: &RestoreOptions, path: &str) -> bool {
    options
        .sparse_patterns
        .as_deref()
        .is_none_or(|patterns| matches_sparse(patterns, path, false))
}

/// Tracked paths present in the current index but absent from the target
/// tree, each paired with its index entry's `(status, hash)` — for
/// destructive worktree moves (`reset --hard`, `checkout`) these files
/// are deleted explicitly (`restore_tree_to_worktree` with `clean =
/// false` writes/overwrites but never deletes). The `(status, hash)`
/// lets the caller detect local edits by content AND mode/type.
pub(crate) fn dropped_tracked_paths(
    cwd: &Path,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<Vec<(String, EntryStatus, Hash)>, String> {
    let idx = read_or_seed_index_from_head(cwd, store)?;
    let index_tree =
        worktree::build_tree_from_index(store, &idx).map_err(|e| format!("index tree: {e}"))?;
    let mut out = Vec::new();
    for e in diff_trees(store, Some(index_tree), Some(target_tree))
        .map_err(|e| format!("diff index vs target: {e}"))?
        .entries
        .into_iter()
        .filter(|e| e.kind == DiffKind::Removed)
    {
        if let Some(entry) = idx
            .entries
            .iter()
            .find(|ie| ie.path == e.path && ie.status != EntryStatus::Removed)
        {
            out.push((e.path, entry.status, entry.object_hash));
        }
    }
    Ok(out)
}

/// The first dropped path whose worktree entry differs from its indexed
/// `(status, hash)` — a local edit to content, mode (exec bit), or symlink
/// target. `None` if every dropped path is unmodified, missing, or a
/// directory (no file to lose). This is a direct per-dropped-path check, so
/// destructive moves never silently discard a local edit — independent of
/// how the shared worktree-snapshot guard treats ignored files.
pub(crate) fn locally_modified_dropped_path(
    cwd: &Path,
    store: &ObjectStore,
    dropped: &[(String, EntryStatus, Hash)],
) -> Result<Option<String>, String> {
    for (path, idx_status, idx_hash) in dropped {
        if let Some((wt_status, wt_hash)) = worktree_entry_state(cwd, store, path)?
            && (wt_status != *idx_status || wt_hash != *idx_hash)
        {
            return Ok(Some(path.clone()));
        }
    }
    Ok(None)
}

/// Delete a dropped tracked path from the worktree. A regular file or
/// symlink is removed; a directory (untracked content that replaced the
/// tracked file) is LEFT in place rather than recursively deleted, and a
/// missing path is a no-op — so this never crashes on `IsADirectory` and
/// never nukes untracked directories.
pub(crate) fn remove_dropped_path(abs: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(abs) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => fs::remove_file(abs),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn is_ignored_worktree_path(
    root: &Path,
    ignore: &mkit_core::ignore::IgnoreList,
    path: &str,
) -> bool {
    let full_path = root.join(path);
    let Ok(meta) = fs::symlink_metadata(&full_path) else {
        return false;
    };
    // Match on the repo-relative path, and treat a path under an ignored
    // directory as ignored too (no top-down walk here to carry that bit).
    ignore.is_ignored_with_ancestors(path, meta.is_dir())
}

pub(crate) fn current_head_tree(root: &Path, store: &ObjectStore) -> Result<Option<Hash>, String> {
    let mkit_dir = root.join(mkit_core::MKIT_DIR);
    let Some(head_hash) =
        refs::resolve_head(&mkit_dir).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(None);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => Ok(Some(c.tree_hash)),
        Object::Remix(r) => Ok(Some(r.tree_hash)),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}

fn collect_worktree_paths(
    root: &Path,
    dir: &Path,
    prefix: &str,
    out: &mut Vec<String>,
) -> std::io::Result<()> {
    let read = match fs::read_dir(dir) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.eq_ignore_ascii_case(".mkit") || name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        out.push(path.clone());
        let full_path = root.join(&path);
        let meta = fs::symlink_metadata(&full_path)?;
        if meta.is_dir() {
            collect_worktree_paths(root, &full_path, &path, out)?;
        }
    }
    Ok(())
}

pub(crate) fn index_tracks_path_or_descendant(index: &Index, path: &str) -> bool {
    index.entries.iter().any(|entry| {
        entry.status != EntryStatus::Removed
            && (entry.path == path || index_path_descends_from(&entry.path, path))
    })
}

fn paths_overlap(left: &str, right: &str) -> bool {
    index_path_matches_or_descends(left, right) || index_path_descends_from(right, left)
}

/// Read the index, seeding an absent/empty one from HEAD when possible.
///
/// This lets old repositories or manually removed indexes keep the
/// expected staging invariant: adding/removing one path starts from the
/// current commit snapshot instead of making the next commit forget all
/// unchanged tracked files.
pub fn read_or_seed_index_from_head(
    root: &Path,
    store: &ObjectStore,
) -> Result<mkit_core::index::Index, String> {
    let idx = mkit_core::index::read_index(root).map_err(|e| format!("read index: {e}"))?;
    if !idx.entries.is_empty() {
        return Ok(idx);
    }

    let mkit_dir = root.join(mkit_core::MKIT_DIR);
    let Some(head_hash) =
        mkit_core::refs::resolve_head(&mkit_dir).map_err(|e| format!("resolve HEAD: {e}"))?
    else {
        return Ok(idx);
    };
    match store
        .read_object(&head_hash)
        .map_err(|e| format!("read HEAD: {e}"))?
    {
        Object::Commit(c) => mkit_core::index::from_tree(store, c.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        Object::Remix(r) => mkit_core::index::from_tree(store, r.tree_hash)
            .map_err(|e| format!("index from HEAD: {e}")),
        _ => Err("HEAD does not resolve to a commit or remix".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::c_quote_path;

    #[test]
    fn c_quote_leaves_plain_paths_alone() {
        assert_eq!(c_quote_path("a.txt"), None);
        assert_eq!(c_quote_path("dir/with space.txt"), None); // space is plain
        assert_eq!(c_quote_path("weird-but-ascii_!@#$%.rs"), None);
    }

    #[test]
    fn c_quote_escapes_special_bytes() {
        assert_eq!(c_quote_path("a\tb.txt").as_deref(), Some(r#""a\tb.txt""#));
        assert_eq!(
            c_quote_path("line\nfeed").as_deref(),
            Some(r#""line\nfeed""#)
        );
        assert_eq!(c_quote_path("q\"x").as_deref(), Some(r#""q\"x""#));
        assert_eq!(
            c_quote_path("back\\slash").as_deref(),
            Some(r#""back\\slash""#)
        );
    }

    #[test]
    fn c_quote_octal_escapes_non_ascii() {
        // "é" is UTF-8 0xC3 0xA9 → \303\251 (matches git core.quotePath).
        assert_eq!(c_quote_path("é").as_deref(), Some(r#""\303\251""#));
        // Combined with ASCII: only the non-ASCII bytes are octal-escaped.
        assert_eq!(c_quote_path("x-é").as_deref(), Some(r#""x-\303\251""#));
    }
}
