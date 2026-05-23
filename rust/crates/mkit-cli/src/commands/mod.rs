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
pub mod checkout;
pub mod cherry_pick;
pub mod clone;
pub mod commit;
pub mod config_cmd;
pub mod diff;
pub mod fetch;
pub mod hash_cmd;
pub mod init;
pub mod key;
pub mod keygen;
pub mod log;
pub mod merge;
#[cfg(feature = "pack-shards")]
pub mod pack_shard;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod remote;
pub mod rm;
pub mod serve;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod tag;
pub mod tree;
pub mod verify;
pub mod verify_attest;

use crate::exit;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::refs::{self, RefError, RefWriteCondition};
use mkit_core::store::ObjectStore;
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
/// One executor per process: each [`TokioExecutor`] owns a multi-thread
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

/// Rewrite `.mkit/index` so it exactly mirrors `tree_hash`.
///
/// `mkit commit` now signs the index, so commands that move HEAD and
/// materialize a committed tree must keep the index aligned with that
/// snapshot.
pub fn sync_index_to_tree(root: &Path, store: &ObjectStore, tree_hash: Hash) -> Result<(), String> {
    let idx = mkit_core::index::from_tree(store, tree_hash).map_err(|e| format!("index: {e}"))?;
    mkit_core::index::write_index(root, &idx).map_err(|e| format!("write index: {e}"))
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
