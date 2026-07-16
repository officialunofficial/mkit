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
#[cfg(feature = "git-bridge")]
pub mod git_tools;
pub mod hash_cmd;
pub mod init;
pub mod key;
pub mod keygen;
pub mod log;
pub mod ls_files;
pub mod ls_tree;
pub mod mcp;
pub mod merge;
pub mod merge_base;
pub mod mv;
#[cfg(feature = "pack-shards")]
pub mod pack_shard;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod ref_cmd;
pub mod reflog;
pub mod remote;
pub mod reset;
pub mod restore;
pub mod rev_list;
pub mod rev_parse;
pub mod revert;
pub mod revspec;
pub mod rm;
pub mod self_update;
pub mod serve;
pub mod show;
pub mod show_ref;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod summary;
pub mod switch;
pub mod symbolic_ref;
pub mod tag;
pub mod tree;
pub mod trust;
pub mod trust_roots;
pub mod update_ref;
pub mod verify;
pub mod verify_attest;
pub mod worktree;

use crate::exit;
use mkit_core::hash::Hash;
use mkit_core::index::{EntryStatus, Index};
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::diff::{DiffKind, diff_trees};
use mkit_core::ops::recovery::{self, RecoveryEntry};
use mkit_core::ops::restore::{RestoreOptions, matches_sparse, restore_tree_to_worktree};
use mkit_core::refs::{self, Head, RefError, RefWriteCondition};
use mkit_core::store::ObjectStore;
use mkit_core::worktree as core_worktree;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Open the object store for a mutating command, honoring the repo's
/// configured durability schedule (`durability.objects`, see
/// [`crate::config::Config::object_sync_policy`]). Falls back to the
/// First line of a commit/remix message (empty string on any read
/// failure). Shared by `checkout`'s detached-HEAD report and `blame`'s
/// porcelain `summary` field so the "subject" extraction can't drift.
pub(crate) fn commit_subject(store: &ObjectStore, commit: &Hash) -> String {
    let msg = match store.read_object(commit) {
        Ok(Object::Commit(c)) => c.message,
        _ => return String::new(),
    };
    String::from_utf8_lossy(&msg)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned()
}

/// batched default when the config cannot be read — a broken config
/// must not change write semantics silently, and Batch is the default
/// contract.
pub fn open_store_configured(
    layout: &RepoLayout,
) -> Result<ObjectStore, mkit_core::store::StoreError> {
    let mut store = ObjectStore::open(layout)?;
    if let Ok(cfg) = crate::config::read_or_default(layout) {
        store.set_sync_policy(cfg.object_sync_policy());
    }
    Ok(store)
}

/// Read an object's serialised bytes from `store`, mapping a failure to
/// the `(message, exit-code)` shape commands return. Shared by `attest`,
/// `git`'s `publish_attestations`, and `git_import`'s `mint_attestations`
/// — each needs a commit's raw bytes (not just its hash) to compute the
/// attestation subject's paired `sha256` digest (SPEC-ATTESTATIONS
/// §4.2), and previously duplicated this read-and-format-error shape
/// independently.
pub(crate) fn read_object_bytes(store: &ObjectStore, hash: &Hash) -> Result<Vec<u8>, (String, u8)> {
    store.read(hash).map_err(|e| {
        (
            format!("read {}: {e}", mkit_core::hash::to_hex(hash)),
            exit::GENERAL_ERROR,
        )
    })
}

/// Resolve the [`RepoLayout`] a command operates on (#493 Phase 1):
/// pointer-following discovery. A `.mkit` DIRECTORY (or none at all)
/// resolves to the classic single-worktree layout exactly as before; a
/// `.mkit` pointer FILE resolves to the linked tree's split layout. On
/// a broken pointer the error has already been printed and the
/// returned code is the exit status to propagate — a broken linked
/// tree must never silently operate on the wrong directory. Command
/// code must obtain its layout HERE and never construct one ad hoc.
pub fn resolve_layout(cwd: &Path) -> Result<RepoLayout, u8> {
    mkit_core::layout::discover(cwd)
        .map_err(|e| error(&format!("worktree discovery: {e}"), exit::DATAERR))
}

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

/// Shared helper: print `error: <msg>` to stderr and return `code`.
///
/// This is the single source of truth for the `error: …`-prefixed
/// stderr channel used by every subcommand. It generalises
/// [`usage_error`] (which hardcodes [`exit::USAGE`]) to an arbitrary
/// exit code so command modules don't each carry their own copy.
#[must_use]
pub(crate) fn error(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

/// Load the tree hash of a commit object, surfacing a CLI error code.
///
/// Shared by the `cherry-pick`/`revert`/`merge` replay+rollback paths,
/// which all need the tree of a resolved commit before restoring it.
///
/// # Errors
/// Returns [`exit::DATAERR`] if the object is not a commit, or
/// [`exit::GENERAL_ERROR`] if it cannot be read.
pub(crate) fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, u8> {
    match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(_) => Err(error("object is not a commit", exit::DATAERR)),
        Err(e) => Err(error(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    }
}

/// Point the current branch (or detached HEAD) at `new_head`, routing a
/// branch advance through the history-MMR helper.
///
/// Shared by `cherry-pick`/`revert`/`merge`. Unlike the historical
/// per-command copies, a failure to read HEAD is propagated as an error
/// rather than silently fabricating `Head::Branch("main")` and writing
/// the commit pointer to the wrong (or a non-existent) `main` ref.
///
/// # Errors
/// Returns a human-readable message if HEAD cannot be read or the ref
/// write fails.
pub(crate) fn advance_head(layout: &RepoLayout, new_head: &Hash) -> Result<(), String> {
    let head = refs::read_head(layout).map_err(|e| format!("read HEAD: {e}"))?;
    match head {
        Head::Branch(name) => {
            write_ref_recording_history(layout, &name, RefWriteCondition::Any, new_head)
                .map_err(|e| format!("write ref: {e}"))
        }
        Head::Detached(_) => {
            refs::write_head_detached(layout, new_head).map_err(|e| format!("update HEAD: {e}"))
        }
    }
}

/// Restore the current branch (or detached HEAD) to `target` as the
/// final step of a conflict `--abort`/rollback.
///
/// Shared by `cherry-pick`/`revert`/`merge` `restore_to`. As with
/// [`advance_head`], an unreadable HEAD is reported as an error instead
/// of defaulting to `main` — a corrupted HEAD during `--abort` must not
/// silently clobber/create a `main` branch.
///
/// # Errors
/// Returns a CLI exit code (already printed via [`error`]) on failure.
pub(crate) fn restore_head_ref(layout: &RepoLayout, target: &Hash) -> Result<(), u8> {
    let head =
        refs::read_head(layout).map_err(|e| error(&format!("read HEAD: {e}"), exit::DATAERR))?;
    match head {
        Head::Branch(name) => {
            write_ref_recording_history(layout, &name, RefWriteCondition::Any, target)
                .map_err(|e| error(&format!("restore ref: {e}"), exit::CANTCREAT))
        }
        Head::Detached(_) => refs::write_head_detached(layout, target)
            .map_err(|e| error(&format!("restore HEAD: {e}"), exit::CANTCREAT)),
    }
}

/// Basename of the repo-level lock that serialises worktree/index
/// read-modify-write commands (`add`, `rm`, `commit`, `merge`,
/// `checkout`, `rebase`, `cherry-pick`, `stash`, `sparse-checkout`).
///
/// Ref-only mutations (`branch`/`tag`) and config-only mutations do not
/// take this lock — they rely on ref-CAS / atomic-config writes instead.
pub const WORKTREE_LOCK: &str = "worktree.lock";

/// Acquire the shared worktree/index lock for this worktree.
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
pub fn acquire_worktree_lock(layout: &RepoLayout) -> Result<mkit_core::repo_lock::RepoLock, u8> {
    // Per-worktree state: the lock serialises THIS tree's worktree/
    // index mutations (#493 Phase 3 adds a separate shared lock for
    // store/refs/gc mutation).
    mkit_core::repo_lock::acquire_default(layout.worktree_state_dir(), WORKTREE_LOCK).map_err(|e| {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "error: repo lock: {e}");
        exit::TEMPFAIL
    })
}

/// Basename of the common-dir lock serialising linked-worktree
/// registry mutations (`worktree add`/`remove`/`prune`), the
/// branch-checkout guard + HEAD-write critical sections
/// (`checkout`/`switch`, `branch -d`/`-m`), and gc's freeze of the
/// worktree set. Distinct from [`WORKTREE_LOCK`], which guards ONE
/// tree's worktree/index state.
///
/// GLOBAL LOCK ORDER (SPEC-WORKTREE §4.3): a process that takes more
/// than one of these MUST acquire in this order —
/// `worktrees.lock` ≺ per-tree `worktree.lock`(s) ≺
/// `refs-history.lock` — or two multi-lock takers can stall each
/// other until the 5s timeout.
pub const WORKTREES_REGISTRY_LOCK: &str = "worktrees.lock";

/// Acquire the shared worktree-registry lock (common dir).
///
/// # Errors
/// [`exit::TEMPFAIL`] when the lock cannot be taken (message already
/// printed), mirroring [`acquire_worktree_lock`].
pub fn acquire_worktrees_registry_lock(
    layout: &RepoLayout,
) -> Result<mkit_core::repo_lock::RepoLock, u8> {
    mkit_core::repo_lock::acquire_default(layout.common_dir(), WORKTREES_REGISTRY_LOCK).map_err(
        |e| {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "error: worktree registry lock: {e}");
            exit::TEMPFAIL
        },
    )
}

/// Every worktree of `layout`'s repository as `(tree root, layout)`
/// pairs: the main tree first, then each healthy linked tree from the
/// registry. Broken (prunable) registry entries are skipped — they
/// have no live HEAD to consult; `worktree prune` reaps them.
///
/// # Errors
/// A human-readable message when the registry cannot be enumerated
/// (fail closed: a caller consulting sibling HEADs must not treat an
/// unreadable registry as "no siblings").
pub(crate) fn all_worktree_layouts(
    layout: &RepoLayout,
) -> Result<Vec<(std::path::PathBuf, RepoLayout)>, String> {
    let mut out = Vec::new();
    if let Some(main_root) = layout.common_dir().parent() {
        out.push((main_root.to_path_buf(), RepoLayout::single(main_root)));
    }
    for wt in mkit_core::layout::worktrees(layout).map_err(|e| format!("worktree registry: {e}"))? {
        if wt.prunable.is_some() {
            continue;
        }
        let Some(tree_root) = wt.tree_root else {
            continue;
        };
        out.push((
            tree_root.clone(),
            RepoLayout::linked(tree_root, wt.state_dir, layout.common_dir()),
        ));
    }
    Ok(out)
}

/// The tree (other than the invoking one) that has `branch` checked
/// out, if any. Branch moves are single-writer-per-branch (the
/// history-MMR journal assumes it), so `checkout`/`switch`/`worktree
/// add` refuse to put one branch on two trees, and `branch -d`/`-m`
/// refuse to pull a branch out from under a sibling tree.
///
/// # Errors
/// Propagates registry/HEAD read failures as a message — fail closed.
pub(crate) fn branch_checked_out_elsewhere(
    layout: &RepoLayout,
    branch: &str,
) -> Result<Option<std::path::PathBuf>, String> {
    let self_state = layout
        .worktree_state_dir()
        .canonicalize()
        .unwrap_or_else(|_| layout.worktree_state_dir().to_path_buf());
    for (tree_root, candidate) in all_worktree_layouts(layout)? {
        let candidate_state = candidate
            .worktree_state_dir()
            .canonicalize()
            .unwrap_or_else(|_| candidate.worktree_state_dir().to_path_buf());
        if candidate_state == self_state {
            continue; // the invoking tree itself
        }
        match refs::read_head(&candidate) {
            Ok(Head::Branch(name)) if name == branch => return Ok(Some(tree_root)),
            // A sibling with no HEAD yet (mid-add) holds no branch.
            Ok(_) | Err(RefError::NoHead) => {}
            Err(e) => {
                return Err(format!(
                    "read HEAD of worktree at {}: {e}",
                    tree_root.display()
                ));
            }
        }
    }
    Ok(None)
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
        let (opened_meta, bytes) = core_worktree::read_regular_file_bounded(&abs)
            .map_err(|e| format!("read {}: {e}", abs.display()))?;
        let h =
            core_worktree::store_file_object(store, &bytes).map_err(|e| format!("store: {e}"))?;
        Ok(Some((file_exec_status(&opened_meta), h)))
    } else if meta.file_type().is_symlink() {
        let target =
            fs::read_link(&abs).map_err(|e| format!("read link {}: {e}", abs.display()))?;
        let target_str = target
            .to_str()
            .ok_or_else(|| "symlink target is not valid UTF-8".to_string())?;
        if !core_worktree::validate_symlink_target(target_str) {
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
// Branch-ref history journaling (issue #157). Every CLI subcommand that
// advances a branch ref MUST route the write through this helper instead of calling
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
/// - **`--features history-mmr`** — takes the `refs-history.lock`
///   repo lock, THEN opens a journaled `CommitHistory` for `branch`
///   under `<mkit_dir>/history/` (lock-then-open, not the reverse —
///   see `mkit_core::refs::open_and_update_ref_with_history_and_backfill`'s
///   doc comment for why), performs the CAS ref-write, appends
///   `new_hash` to the MMR, and `sync()`s the journal before
///   returning. The journal survives `SIGKILL` immediately after the
///   call returns. See
///   `mkit-core::refs::open_and_update_ref_with_history_and_backfill`
///   and SPEC-HISTORY-PROOF §4 for the contract.
///
/// If the journal is empty but `branch` already has a ref value on
/// disk (a v0.1.x-era repo enabling `history-mmr` for the first time,
/// or a crash on the branch's very first tracked write), this backfills
/// the full known chain via [`mkit_core::history::rebuild_from_chain`]
/// before proceeding — SPEC-HISTORY-PROOF §4.5. The empty-journal check
/// AND the backfill loop run inside
/// [`mkit_core::refs::update_ref_with_history_and_backfill`]'s
/// `refs-history.lock` critical section (issue #638 / INV-18): running
/// them before the lock (as this used to) let two ref-only writers on
/// the same never-before-journaled branch — e.g. two concurrent
/// `update-ref` calls, which deliberately skip the worktree lock — both
/// observe an empty journal and both independently backfill, corrupting
/// the journal's leaf positions.
///
/// All CLI subcommands that move a branch ref MUST funnel through this
/// helper rather than calling `refs::write_ref` or `refs::update_ref`
/// directly. Detached-HEAD writes (`refs::write_head_detached`) are
/// not history-tracked: the per-branch journal is keyed on the branch
/// name, and detached HEADs have none.
pub fn write_ref_recording_history(
    layout: &RepoLayout,
    branch: &str,
    condition: RefWriteCondition,
    new_hash: &Hash,
) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        let exec = history_executor();

        // Opening the object store is read-only and touches none of the
        // history-journal state that's actually racy here, so it's fine
        // to do before the lock.
        let store = ObjectStore::open(layout)
            .map_err(|e| RefError::InvalidRef(format!("{branch}: open object store: {e}")))?;

        // `open_and_update_ref_with_history_and_backfill` (not the
        // open-then-call shape this used to have) acquires the
        // per-branch lock BEFORE opening the journal, closing a race
        // two concurrent first-writers on a never-before-journaled
        // branch could hit: `CommitHistory::open_at` reads the on-disk
        // metadata blob, and reading it while the OTHER thread is mid
        // -`sync` (writing that same blob under its own lock hold) can
        // observe a torn/zeroed blob and fail as "corrupt" even though
        // nothing is actually wrong once the write finishes. See
        // `mkit_core::refs::update_ref_with_history_critical_section`'s
        // doc comment for the full mechanism.
        refs::open_and_update_ref_with_history_and_backfill(
            layout,
            branch,
            condition,
            new_hash,
            exec,
            |h| match store.read_object(h) {
                Ok(Object::Commit(c)) => Ok(c.parents.first().copied()),
                Ok(Object::Remix(r)) => Ok(r.parents.first().copied()),
                Ok(_) => Err(format!(
                    "{}: object is not a commit or remix",
                    mkit_core::hash::to_hex(h)
                )),
                Err(e) => Err(e.to_string()),
            },
        )
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::update_ref(layout, branch, condition, new_hash)
    }
}

/// `mkit branch -d`/`-D` helper: deletes a branch ref and, on
/// `--features history-mmr` builds, also destroys its history-MMR
/// journal partition (issue #648). Refuses the checked-out branch, same
/// as plain `refs::delete_ref_safe`.
///
/// Without this, a branch recreated under a previously-deleted name
/// would reopen the dead incarnation's non-empty journal (the
/// commonware partition is keyed on the sanitized branch name, not any
/// per-incarnation identifier) and resume appending on top of its old
/// leaves — the new branch's MMR root would then span two unrelated
/// incarnations, and the deleted incarnation's stale leaves would keep
/// producing valid-looking inclusion proofs "on this branch". See
/// [`mkit_core::refs::delete_ref_safe_with_history`] for the full
/// crash-ordering contract.
///
/// - **Default build (no `history-mmr`)** — exactly
///   `refs::delete_ref_safe(layout, branch)`.
/// - **`--features history-mmr`** — routes through
///   [`mkit_core::refs::delete_ref_safe_with_history`], sharing the same
///   process-global executor as [`write_ref_recording_history`].
pub fn delete_ref_recording_history(layout: &RepoLayout, branch: &str) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        refs::delete_ref_safe_with_history(layout, branch, history_executor())
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::delete_ref_safe(layout, branch)
    }
}

/// `mkit branch -m` helper: deletes the OLD name's ref after a rename
/// and, on `--features history-mmr` builds, also destroys its history-MMR
/// journal partition (issue #648).
///
/// Unlike [`delete_ref_recording_history`], this does NOT refuse the
/// checked-out branch — `branch -m` legitimately renames the current
/// branch and moves HEAD to the new name immediately after this call.
/// The NEW name's ref is created first by the caller (via
/// [`write_ref_recording_history`], which seeds it with a fresh
/// journal), so by the time this runs the old and new incarnations are
/// already disjoint; this just makes sure the OLD name's journal is not
/// left behind to be inherited by a future branch of the same name.
///
/// - **Default build (no `history-mmr`)** — exactly
///   `refs::delete_ref(layout, branch)`.
/// - **`--features history-mmr`** — routes through
///   [`mkit_core::refs::delete_ref_with_history`].
pub fn delete_ref_dropping_history(layout: &RepoLayout, branch: &str) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        refs::delete_ref_with_history(layout, branch, history_executor())
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::delete_ref(layout, branch)
    }
}

/// CAS-guarded sibling of [`delete_ref_dropping_history`] (issue #658):
/// only deletes `branch` (and, on `--features history-mmr` builds,
/// destroys its journal) if its current value is exactly `expected`.
///
/// `mkit branch -m` uses this — not the unconditional version — for
/// BOTH the source-branch drop and, on a lost race, the rollback delete
/// of the just-created destination: an unconditional delete here can't
/// tell "the branch tip I read is still current" from "a concurrent
/// `commit` just advanced it out from under me", so it would silently
/// destroy the concurrently-landed commit's only ref. See
/// [`mkit_core::refs::delete_ref_if_matches`] for the full race
/// analysis.
///
/// - **Default build (no `history-mmr`)** — exactly
///   `refs::delete_ref_if_matches(layout, branch, expected)`.
/// - **`--features history-mmr`** — routes through
///   [`mkit_core::refs::delete_ref_with_history_if_matches`], sharing
///   the same process-global executor as [`write_ref_recording_history`].
pub fn delete_ref_dropping_history_if_matches(
    layout: &RepoLayout,
    branch: &str,
    expected: Hash,
) -> Result<(), RefError> {
    #[cfg(feature = "history-mmr")]
    {
        refs::delete_ref_with_history_if_matches(layout, branch, expected, history_executor())
    }
    #[cfg(not(feature = "history-mmr"))]
    {
        refs::delete_ref_if_matches(layout, branch, expected)
    }
}

/// Current branch name for recovery logging — empty for a detached HEAD
/// or an unreadable/symbolic-only HEAD.
#[must_use]
pub fn head_branch_name(layout: &RepoLayout) -> String {
    match refs::read_head(layout) {
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
    layout: &RepoLayout,
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
    recovery::record(layout, &entry).map_err(|e| (format!("recovery log: {e}"), exit::CANTCREAT))
}

/// Rewrite `.mkit/index` so it exactly mirrors `tree_hash`.
///
/// `mkit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    let mut idx =
        mkit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    // Tree-derived entries carry no stat cache. Carry it over from the
    // outgoing index wherever path AND object hash agree: a later stat
    // match against the old observation still proves the same bytes,
    // so commit/checkout don't wipe the O(stat) fast path.
    if let Ok(old) = mkit_core::index::read_index(layout) {
        // O(1) lookups: find_entry is a linear scan and this loop runs
        // once per tree entry (was O(n²) per commit/checkout).
        let by_path: std::collections::HashMap<&str, &mkit_core::index::IndexEntry> =
            old.entries.iter().map(|o| (o.path.as_str(), o)).collect();
        for e in &mut idx.entries {
            if let Some(o) = by_path.get(e.path.as_str())
                && o.object_hash == e.object_hash
                && o.status == e.status
            {
                e.mtime_ns = o.mtime_ns;
                e.size = o.size;
                e.ino = o.ino;
                e.ctime_ns = o.ctime_ns;
            }
        }
    }
    mkit_core::index::write_index(layout, &idx).map_err(|e| format!("write index: {e}"))
}

/// After staging a `result_tree` (which, being a tree, omits removed paths),
/// add `Removed` tombstones to the index for every path present in
/// `base_tree` but absent from `result_tree`.
///
/// `sync_index_to_tree`/`restore_worktree_and_index` set the index from a
/// tree, so a staged DELETION is silently dropped. Callers that stage a
/// computed result without committing (e.g. `cherry-pick -n` / `revert -n`)
/// use this so the deletion stays staged — otherwise an all-deletions result
/// leaves an empty index and `mkit commit` rejects it as "nothing staged".
pub fn stage_removed_tombstones(
    layout: &RepoLayout,
    store: &ObjectStore,
    base_tree: Option<Hash>,
    result_tree: Hash,
) -> Result<(), String> {
    let diff = diff_trees(store, base_tree, Some(result_tree))
        .map_err(|e| format!("diff for staged deletions: {e}"))?;
    let removed: Vec<String> = diff
        .entries
        .iter()
        .filter(|e| e.kind == DiffKind::Removed)
        .map(|e| e.path.clone())
        .collect();
    if removed.is_empty() {
        return Ok(());
    }
    let mut idx = mkit_core::index::read_index(layout).map_err(|e| format!("read index: {e}"))?;
    for path in removed {
        match idx.find_entry(&path) {
            Some(j) => {
                idx.entries[j].status = EntryStatus::Removed;
                idx.entries[j].object_hash = mkit_core::hash::ZERO;
            }
            None => idx.upsert_entry(mkit_core::index::IndexEntry {
                path,
                status: EntryStatus::Removed,
                object_hash: mkit_core::hash::ZERO,
                mtime_ns: 0,
                size: 0,
                ino: 0,
                ctime_ns: 0,
            }),
        }
    }
    mkit_core::index::write_index(layout, &idx).map_err(|e| format!("write index: {e}"))
}

/// Materialise `tree_hash` and align the index while preserving `.mkitignore` entries.
pub fn restore_worktree_and_index(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
) -> Result<(), String> {
    restore_tree_to_worktree(
        store,
        &tree_hash,
        layout.worktree_root(),
        &RestoreOptions::default(),
    )
    .map_err(|e| format!("restore worktree: {e}"))?;
    sync_index_to_tree(layout, store, tree_hash)
}

/// Refuse a destructive restore when the index/worktree contains user work.
pub fn ensure_restore_safe(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<(), String> {
    ensure_restore_safe_with_options(layout, store, target_tree, &RestoreOptions::default())
}

/// Refuse a destructive restore when affected index/worktree paths contain user work.
pub fn ensure_restore_safe_with_options(
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
    options: &RestoreOptions,
) -> Result<(), String> {
    let root = layout.worktree_root();
    let current_tree = current_head_tree(layout, store)?;
    let idx = read_or_seed_index_from_head(layout, store)?;
    // Safety-check snapshot trees are ephemeral — in-memory overlay,
    // no durability cost, no garbage objects in the store.
    let snapshot = mkit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("check index state: {e}"))?;

    let staged = diff_trees(&snapshot, current_tree, Some(index_tree))
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

    let worktree_tree = core_worktree::build_tree_filtered(&snapshot, root, Some(&idx))
        .map_err(|e| format!("check working tree changes: {e}"))?;
    let unstaged = diff_trees(&snapshot, Some(index_tree), Some(worktree_tree))
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

    let target_writes = diff_trees(&snapshot, Some(index_tree), Some(target_tree))
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
    layout: &RepoLayout,
    store: &ObjectStore,
    target_tree: Hash,
) -> Result<Vec<(String, EntryStatus, Hash)>, String> {
    let idx = read_or_seed_index_from_head(layout, store)?;
    let snapshot = mkit_core::store::EphemeralSink::new(store);
    let index_tree = core_worktree::build_tree_from_index_with(store, &snapshot, &idx, false)
        .map_err(|e| format!("index tree: {e}"))?;
    let mut out = Vec::new();
    for e in diff_trees(&snapshot, Some(index_tree), Some(target_tree))
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

pub(crate) fn current_head_tree(
    layout: &RepoLayout,
    store: &ObjectStore,
) -> Result<Option<Hash>, String> {
    let Some(head_hash) = refs::resolve_head(layout).map_err(|e| format!("resolve HEAD: {e}"))?
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

pub(crate) fn collect_worktree_paths(
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
    // Delegates to `Index::tracks_path_or_descendant`, which answers via
    // the maintained `path -> position` map in `O(log n + k)` instead of
    // this function's old `O(n)` full scan (issue #708) — `add_tree` calls
    // this once per directory/file it walks.
    index.tracks_path_or_descendant(path)
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
    layout: &RepoLayout,
    store: &ObjectStore,
) -> Result<mkit_core::index::Index, String> {
    let idx = mkit_core::index::read_index(layout).map_err(|e| format!("read index: {e}"))?;
    if !idx.entries.is_empty() {
        return Ok(idx);
    }

    let Some(head_hash) =
        mkit_core::refs::resolve_head(layout).map_err(|e| format!("resolve HEAD: {e}"))?
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
    use super::{advance_head, c_quote_path, restore_head_ref};
    use mkit_core::hash::Hash;

    #[cfg(feature = "history-mmr")]
    fn write_commit(store: &mkit_core::store::ObjectStore, parents: Vec<Hash>, seed: u8) -> Hash {
        use mkit_core::object::{Commit, Identity, Object};

        let commit = Commit::new_unannotated(
            [seed; 32],
            parents,
            Identity::ed25519([seed; 32]),
            [seed; 32],
            b"msg".to_vec(),
            0,
            [0u8; 64],
        );
        let bytes = mkit_core::serialize::serialize(&Object::Commit(commit)).unwrap();
        store.write(&bytes).unwrap()
    }

    #[cfg(feature = "history-mmr")]
    #[test]
    fn write_ref_recording_history_backfills_v01x_style_repo_from_object_store() {
        use super::write_ref_recording_history;
        use mkit_core::history::{CommitHistory, Position, TokioExecutor, verify_inclusion};
        use mkit_core::refs::{self, RefWriteCondition};
        use mkit_core::store::ObjectStore;
        use std::sync::Arc;

        let td = tempfile::tempdir().unwrap();
        let repo_root = td.path();
        let layout = mkit_core::layout::RepoLayout::single(repo_root);
        let store = ObjectStore::init(&layout).unwrap();

        // Build a 3-commit chain entirely via the object store and point
        // `refs/heads/main` at the tip directly — simulating a repo
        // whose commits predate `history-mmr`: the ref exists, but
        // `<mkit_dir>/history/` has never been touched.
        let c0 = write_commit(&store, vec![], 1);
        let c1 = write_commit(&store, vec![c0], 2);
        let c2 = write_commit(&store, vec![c1], 3);
        refs::write_ref(&layout, "main", &c2).unwrap();

        // The first history-mmr-enabled write for this branch: a new
        // commit c3 on top of the pre-existing tip c2.
        let c3 = write_commit(&store, vec![c2], 4);
        write_ref_recording_history(&layout, "main", RefWriteCondition::Match(c2), &c3).unwrap();

        assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(c3));

        // The journal must now hold the full backfilled chain (c0, c1,
        // c2) PLUS the new c3 — not just c3 alone.
        let exec = Arc::new(TokioExecutor::new().unwrap());
        let hist = CommitHistory::open_at(exec, &layout, "main").unwrap();
        assert_eq!(hist.len(), 4);
        let root = hist.root();
        for (i, c) in [c0, c1, c2, c3].into_iter().enumerate() {
            let pos = Position(i as u64);
            let proof = hist.prove(pos).unwrap();
            assert!(
                verify_inclusion(&c, pos, &proof, &root),
                "commit at position {i} failed inclusion proof after backfill"
            );
        }
    }

    #[cfg(feature = "history-mmr")]
    #[test]
    fn write_ref_recording_history_does_not_backfill_a_genuinely_fresh_branch() {
        use super::write_ref_recording_history;
        use mkit_core::history::{CommitHistory, TokioExecutor};
        use mkit_core::refs::RefWriteCondition;
        use mkit_core::store::ObjectStore;
        use std::sync::Arc;

        let td = tempfile::tempdir().unwrap();
        let repo_root = td.path();
        let layout = mkit_core::layout::RepoLayout::single(repo_root);
        let store = ObjectStore::init(&layout).unwrap();

        // No pre-existing ref: this is a brand new branch's first ever
        // commit, not a v0.1.x migration. There is nothing to backfill.
        let c0 = write_commit(&store, vec![], 1);
        write_ref_recording_history(&layout, "main", RefWriteCondition::Missing, &c0).unwrap();

        let exec = Arc::new(TokioExecutor::new().unwrap());
        let hist = CommitHistory::open_at(exec, &layout, "main").unwrap();
        assert_eq!(
            hist.len(),
            1,
            "only the one real write, no phantom backfill entries"
        );
    }

    /// A long v0.1.x-style chain (ref exists on disk, journal never
    /// touched) — simulates an existing repo enabling `history-mmr` for
    /// the first time.
    #[cfg(feature = "history-mmr")]
    const CONCURRENT_BACKFILL_CHAIN_LEN: usize = 500;

    /// INV-18 regression (issue #638): the empty-journal check and the
    /// entire backfill-from-object-store loop must run *inside*
    /// `refs-history.lock`, not before it. `update-ref`/`branch` calls
    /// deliberately skip the worktree lock, so two ref-only writers on
    /// the same never-before-journaled branch can both call this
    /// function concurrently. Pre-fix, both threads independently
    /// observe an empty journal (the check happens before any lock is
    /// taken) and both independently backfill the whole chain, landing
    /// duplicate leaves. Post-fix, only one of them may see the empty
    /// journal and perform the backfill; the other must see a
    /// non-empty journal once it acquires the lock and skip straight to
    /// its own append.
    ///
    /// The chain is long enough (500 commits) that the pre-fix unlocked
    /// backfill loop — which, before the fsync-batching fix also lands,
    /// syncs once per commit — takes long enough in wall-clock terms
    /// for both threads (released simultaneously via a barrier) to
    /// almost certainly overlap.
    #[cfg(feature = "history-mmr")]
    #[test]
    fn write_ref_recording_history_concurrent_backfill_does_not_duplicate_journal_leaves() {
        use super::write_ref_recording_history;
        use mkit_core::history::{CommitHistory, TokioExecutor};
        use mkit_core::refs::{self, RefWriteCondition};
        use mkit_core::store::ObjectStore;
        use std::sync::{Arc, Barrier};

        let td = tempfile::tempdir().unwrap();
        let repo_root = td.path();
        let layout = Arc::new(mkit_core::layout::RepoLayout::single(repo_root));
        let store = ObjectStore::init(&layout).unwrap();

        let mut tip: Option<Hash> = None;
        for seed in 0..CONCURRENT_BACKFILL_CHAIN_LEN {
            let seed = u8::try_from(seed % 256).expect("seed % 256 fits in u8");
            tip = Some(write_commit(&store, tip.into_iter().collect(), seed));
        }
        let tip = tip.unwrap();
        refs::write_ref(&layout, "main", &tip).unwrap();

        // Two independent new commits, each racing to be the first
        // history-mmr-enabled write for this branch.
        let c_a = write_commit(&store, vec![tip], 250);
        let c_b = write_commit(&store, vec![tip], 251);

        let barrier = Arc::new(Barrier::new(2));

        let (layout_a, barrier_a) = (Arc::clone(&layout), Arc::clone(&barrier));
        let t_a = std::thread::spawn(move || {
            barrier_a.wait();
            write_ref_recording_history(&layout_a, "main", RefWriteCondition::Any, &c_a)
        });
        let (layout_b, barrier_b) = (Arc::clone(&layout), Arc::clone(&barrier));
        let t_b = std::thread::spawn(move || {
            barrier_b.wait();
            write_ref_recording_history(&layout_b, "main", RefWriteCondition::Any, &c_b)
        });

        let res_a = t_a.join().expect("thread a must not panic");
        let res_b = t_b.join().expect("thread b must not panic");
        res_a.expect("writer a must succeed");
        res_b.expect("writer b must succeed");

        let exec = Arc::new(TokioExecutor::new().unwrap());
        let hist = CommitHistory::open_at(exec, &layout, "main").unwrap();
        assert_eq!(
            hist.len(),
            CONCURRENT_BACKFILL_CHAIN_LEN as u64 + 2,
            "two concurrent first-writers on a never-journaled branch \
             must backfill the shared chain exactly once between them \
             (plus their own two real appends) — a leaf count above \
             this means the backfill ran twice and duplicated leaves"
        );
    }

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

    // Regression: the shared replay helpers must NOT fabricate
    // `Head::Branch("main")` when HEAD is unreadable/missing. A missing
    // HEAD previously caused cherry-pick/revert/merge (and especially the
    // `--abort` recovery path) to silently write the commit pointer to
    // `refs/heads/main`, clobbering or creating a `main` branch the user
    // never had. Both helpers must surface the read error instead.

    #[test]
    fn advance_head_errors_when_head_missing_instead_of_writing_main() {
        let td = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(td.path());
        // No HEAD file exists → refs::read_head returns NoHead.
        let new_head: Hash = [0x11; 32];
        let err = advance_head(&layout, &new_head).expect_err("missing HEAD must error");
        assert!(err.contains("read HEAD"), "unexpected error: {err}");
        // Crucially, no `main` ref was fabricated.
        assert!(
            !layout.heads_dir().join("main").exists(),
            "advance_head must not write refs/heads/main when HEAD is unreadable"
        );
    }

    #[test]
    fn restore_head_ref_errors_when_head_missing_instead_of_writing_main() {
        let td = tempfile::tempdir().unwrap();
        let layout = mkit_core::layout::RepoLayout::single(td.path());
        let target: Hash = [0x22; 32];
        let code = restore_head_ref(&layout, &target).expect_err("missing HEAD must error");
        assert_eq!(code, crate::exit::DATAERR);
        assert!(
            !layout.heads_dir().join("main").exists(),
            "restore_head_ref must not write refs/heads/main when HEAD is unreadable"
        );
    }
}
