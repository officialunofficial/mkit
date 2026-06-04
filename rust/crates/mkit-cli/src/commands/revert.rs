//! `mkit revert <commit> | --continue | --abort` — create a new commit
//! that undoes a previous commit, with the resolvable-conflict workflow.
//!
//! Revert is the inverse of cherry-pick (it applies the *reverse* of the
//! target's diff) and a normal **forward** commit — it does not rewrite
//! history, so the reverted commit stays reachable and it is not gated on
//! gc/recovery. On a clean revert we commit the reversed tree with a
//! generated `Revert "<subject>"` message. On conflict we materialise the
//! conflict material, persist `REVERT_HEAD`/`REVERT_MSG`/`ORIG_HEAD` + the
//! `mkit-conflicts` sidecar, and exit non-zero; the user resolves,
//! `mkit add`s, then runs `mkit revert --continue` (or `--abort`).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::conflict_state::{
    self, RevertState, in_progress_op_name, is_revert_in_progress,
};
use mkit_core::ops::revert::revert as revert_tree;
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit revert",
    about = "Create a new commit that undoes a previous commit."
)]
struct RevertOpts {
    /// Continue an in-progress revert after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "commit"])]
    cont: bool,
    /// Abort the in-progress revert and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "commit"])]
    abort: bool,
    /// Stage the reverted tree in the index + worktree without creating a
    /// commit (like `git revert --no-commit`). Applies to a clean revert;
    /// if the revert conflicts, resolve it with `--continue` / `--abort`.
    #[arg(short = 'n', long = "no-commit", conflicts_with_all = ["cont", "abort"])]
    no_commit: bool,
    /// Commit to revert: a ref, full/short hash, or `HEAD~n` revspec.
    commit: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RevertOpts>("mkit revert", args) {
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
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    if opts.abort {
        abort(&cwd, &mkit_dir, &store)
    } else if opts.cont {
        cont(&cwd, &mkit_dir, &store)
    } else if let Some(hex) = opts.commit.as_deref() {
        start(&cwd, &mkit_dir, &store, hex, opts.no_commit)
    } else {
        super::usage_error("usage: mkit revert <commit> | --continue | --abort")
    }
}

fn start(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    hex: &str,
    no_commit: bool,
) -> u8 {
    if let Some(op) = in_progress_op_name(mkit_dir) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }
    let target: Hash = match super::revspec::resolve_revision(store, mkit_dir, hex) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad commit: {e}"), exit::DATAERR),
    };
    let ours = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let ours_tree = match store.read_object(&ours) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(_) => return emit_err("HEAD is not a commit", exit::DATAERR),
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };

    let result = match revert_tree(store, target, ours_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("revert: {e}"), exit::GENERAL_ERROR),
    };

    if result.has_conflicts() {
        if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let records = match super::conflict::materialize_conflicts(cwd, store, &result.conflicts) {
            Ok(r) => r,
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        };
        let state = RevertState {
            revert_head: target,
            orig_head: ours,
            message: result.message.clone(),
        };
        if let Err(e) = conflict_state::write_revert_state(mkit_dir, &state, &records) {
            return emit_err(&format!("write revert state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "revert conflict; resolve the files above, `mkit add` them, then run \
             `mkit revert --continue` (or `mkit revert --abort`)"
        );
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // --no-commit: apply the reverted tree to the index + worktree but do
    // not create a commit or move HEAD. The user commits when ready.
    if no_commit {
        if let Err(e) = super::restore_worktree_and_index(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "staged revert of {} (no commit; run `mkit commit` when ready)",
            format::short_hash(&target, 8),
        );
        return exit::OK;
    }

    let commit_hash = match create_commit(cwd, store, result.tree_hash, ours, &result.message) {
        Ok(h) => h,
        Err(code) => return code,
    };
    if let Err(e) = super::restore_worktree_and_index(cwd, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(mkit_dir, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "reverted {} as {}",
        format::short_hash(&target, 8),
        format::short_hash(&commit_hash, 8),
    );
    exit::OK
}

fn cont(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    let state = match conflict_state::read_revert_state(mkit_dir) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no revert in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read revert state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    match super::conflict::first_unresolved_marker(cwd, &records) {
        Ok(Some(path)) => {
            return emit_err(
                &format!(
                    "unresolved conflict markers remain in '{path}'; resolve and `mkit add` it"
                ),
                exit::GENERAL_ERROR,
            );
        }
        Ok(None) => {}
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    }

    let idx = match super::read_or_seed_index_from_head(cwd, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let tree_hash = match worktree::build_tree_from_index(store, &idx) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR),
    };
    let parent = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => state.orig_head,
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let commit_hash = match create_commit(cwd, store, tree_hash, parent, &state.message) {
        Ok(h) => h,
        Err(code) => return code,
    };
    if let Err(e) = super::restore_worktree_and_index(cwd, store, tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(mkit_dir, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    if let Err(e) = conflict_state::clear_revert_state(mkit_dir) {
        return emit_err(&format!("clear revert state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "reverted {} as {}",
        format::short_hash(&state.revert_head, 8),
        format::short_hash(&commit_hash, 8),
    );
    exit::OK
}

fn abort(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_revert_in_progress(mkit_dir) {
        return emit_err("no revert in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_revert_state(mkit_dir) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no revert in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read revert state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = restore_to(cwd, mkit_dir, store, state.orig_head, &records) {
        return code;
    }
    if let Err(e) = conflict_state::clear_revert_state(mkit_dir) {
        return emit_err(&format!("clear revert state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "revert aborted; HEAD restored");
    exit::OK
}

fn restore_to(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    target: Hash,
    records: &[mkit_core::ops::conflict_state::ConflictRecord],
) -> Result<(), u8> {
    let target_tree = load_tree_hash(store, target)?;
    if let Err(e) = super::conflict::ensure_abort_safe(cwd, store, records, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = super::conflict::reset_conflict_paths(cwd, store, records, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = super::ensure_restore_safe(cwd, store, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = super::restore_worktree_and_index(cwd, store, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    let head = refs::read_head(mkit_dir).unwrap_or(Head::Branch("main".to_string()));
    match head {
        Head::Branch(name) => super::write_ref_recording_history(
            mkit_dir,
            &name,
            refs::RefWriteCondition::Any,
            &target,
        )
        .map_err(|e| emit_err(&format!("restore ref: {e}"), exit::CANTCREAT)),
        Head::Detached(_) => refs::write_head_detached(mkit_dir, &target)
            .map_err(|e| emit_err(&format!("restore HEAD: {e}"), exit::CANTCREAT)),
    }
}

fn create_commit(
    cwd: &std::path::Path,
    store: &ObjectStore,
    tree_hash: Hash,
    parent: Hash,
    message: &[u8],
) -> Result<Hash, u8> {
    let cfg = config::read_or_default(cwd)
        .map_err(|e| emit_err(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let mut signer =
        super::commit::load_commit_signer(cwd, &cfg).map_err(|(msg, code)| emit_err(&msg, code))?;
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    let author = super::commit::resolve_author(None, &cfg.user_identity, &signer_public)
        .map_err(|e| emit_err(&format!("author: {e}"), exit::CONFIG_ERROR))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        vec![parent],
        author,
        signer_public,
        message.to_vec(),
        timestamp,
        [0u8; 64],
    );
    let sig = signer
        .sign_commit(&unsigned)
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    unsigned.signature = sig;
    let bytes = serialize::serialize(&Object::Commit(unsigned))
        .map_err(|e| emit_err(&format!("serialize: {e}"), exit::DATAERR))?;
    store
        .write(&bytes)
        .map_err(|e| emit_err(&format!("store commit: {e}"), exit::CANTCREAT))
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, u8> {
    match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(_) => Err(emit_err("object is not a commit", exit::DATAERR)),
        Err(e) => Err(emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    }
}

fn advance_head(mkit_dir: &std::path::Path, new_head: &Hash) -> Result<(), String> {
    let head = refs::read_head(mkit_dir).unwrap_or(Head::Branch("main".to_string()));
    match head {
        Head::Branch(name) => super::write_ref_recording_history(
            mkit_dir,
            &name,
            refs::RefWriteCondition::Any,
            new_head,
        )
        .map_err(|e| format!("write ref: {e}")),
        Head::Detached(_) => {
            refs::write_head_detached(mkit_dir, new_head).map_err(|e| format!("update HEAD: {e}"))
        }
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
