//! `mkit merge <branch> | --continue | --abort` — merge a branch into
//! HEAD, with a resolvable-conflict workflow (#177).
//!
//! Behaviour:
//!
//! 1. Resolve HEAD (ours) and the target ref (theirs).
//! 2. If equal → "already up to date".
//! 3. Find the merge base; if `base == ours`, fast-forward HEAD to
//!    theirs and restore the worktree to theirs' tree.
//! 4. Otherwise run a 3-way tree merge. On conflict, materialise the
//!    conflict material (markers for text, ours-side for binary/special)
//!    into the worktree + index, persist `MERGE_HEAD`/`MERGE_MSG`/
//!    `ORIG_HEAD` and the `mkit-conflicts` sidecar, and exit non-zero
//!    with resolve instructions. The user resolves, `mkit add`s, then
//!    runs `mkit merge --continue`.
//! 5. Clean merge: sign a new merge commit with two parents and advance
//!    the current branch.
//!
//! `--continue` refuses unless `MERGE_HEAD` exists and no marker-bearing
//! conflicting file remains; it builds the final tree from the resolved
//! index (NOT the conflict-time ours-wins tree). `--abort` restores
//! HEAD/ref/index/worktree to `ORIG_HEAD` and clears all state.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::conflict_state::{self, MergeState, in_progress_op_name, is_merge_in_progress};
use mkit_core::ops::merge::{find_merge_base, merge_trees};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit merge", about = "Three-way merge a branch into HEAD.")]
struct MergeOpts {
    /// Continue an in-progress merge after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "branch"])]
    cont: bool,
    /// Abort the in-progress merge and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "branch"])]
    abort: bool,
    /// Branch to merge into HEAD.
    branch: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<MergeOpts>("mkit merge", args) {
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
    } else if let Some(branch) = opts.branch.as_deref() {
        start(&cwd, &mkit_dir, &store, branch)
    } else {
        super::usage_error("usage: mkit merge <branch> | --continue | --abort")
    }
}

#[allow(clippy::too_many_lines)]
fn start(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    branch: &str,
) -> u8 {
    if let Some(op) = in_progress_op_name(mkit_dir) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }

    let ours = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let theirs = match refs::read_ref(mkit_dir, branch) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err(&format!("branch '{branch}' not found"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    };

    if ours == theirs {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "already up to date");
        return exit::OK;
    }

    let base = match find_merge_base(store, ours, theirs) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("find merge base: {e}"), exit::GENERAL_ERROR),
    };

    // Fast-forward when base == ours.
    if let Some(bh) = base
        && bh == ours
    {
        let theirs_tree = match load_tree_hash(store, theirs) {
            Ok(t) => t,
            Err(code) => return code,
        };
        if let Err(e) = super::ensure_restore_safe(cwd, store, theirs_tree) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = super::restore_worktree_and_index(cwd, store, theirs_tree) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = advance_head(mkit_dir, &theirs) {
            return emit_err(&e, exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "fast-forward {}", format::short_hash(&theirs, 8));
        return exit::OK;
    }

    let ours_tree = match load_tree_hash(store, ours) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let theirs_tree = match load_tree_hash(store, theirs) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let base_tree: Option<Hash> = match base {
        Some(b) => match load_tree_hash(store, b) {
            Ok(t) => Some(t),
            Err(code) => return code,
        },
        None => None,
    };

    let result = match merge_trees(store, base_tree, Some(ours_tree), Some(theirs_tree)) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("merge: {e}"), exit::GENERAL_ERROR),
    };

    let msg = format!("Merge branch '{branch}'");

    if result.has_conflicts() {
        // Guard: never clobber dirty tracked / untracked collisions.
        if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let records = match super::conflict::materialize_conflicts(cwd, store, &result.conflicts) {
            Ok(r) => r,
            Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
        };
        let state = MergeState {
            merge_head: theirs,
            orig_head: ours,
            message: msg.into_bytes(),
        };
        if let Err(e) = conflict_state::write_merge_state(mkit_dir, &state, &records) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "merge conflict; resolve the files above, `mkit add` them, then run \
             `mkit merge --continue` (or `mkit merge --abort`)"
        );
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // Clean merge — build a merge commit with two parents.
    let commit_hash =
        match create_merge_commit(cwd, store, result.tree_hash, ours, theirs, msg.as_bytes()) {
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
        "merge {} into HEAD ({})",
        format::short_hash(&theirs, 8),
        format::short_hash(&commit_hash, 8)
    );
    exit::OK
}

fn cont(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_merge_in_progress(mkit_dir) {
        return emit_err("no merge in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_merge_state(mkit_dir) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no merge in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
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

    // Build the final tree from the resolved index — NOT the
    // conflict-time ours-wins tree.
    let idx = match super::read_or_seed_index_from_head(cwd, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let tree_hash = match worktree::build_tree_from_index(store, &idx) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR),
    };

    let commit_hash = match create_merge_commit(
        cwd,
        store,
        tree_hash,
        state.orig_head,
        state.merge_head,
        &state.message,
    ) {
        Ok(h) => h,
        Err(code) => return code,
    };
    if let Err(e) = super::restore_worktree_and_index(cwd, store, tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(mkit_dir, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    if let Err(e) = conflict_state::clear_merge_state(mkit_dir) {
        return emit_err(&format!("clear merge state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "merge {} into HEAD ({})",
        format::short_hash(&state.merge_head, 8),
        format::short_hash(&commit_hash, 8)
    );
    exit::OK
}

fn abort(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_merge_in_progress(mkit_dir) {
        return emit_err("no merge in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_merge_state(mkit_dir) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no merge in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = restore_to(cwd, mkit_dir, store, state.orig_head, &records) {
        return code;
    }
    if let Err(e) = conflict_state::clear_merge_state(mkit_dir) {
        return emit_err(&format!("clear merge state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "merge aborted; HEAD restored");
    exit::OK
}

/// Restore worktree + index + HEAD/ref to `target` (the pre-op HEAD).
/// Routes the branch advance through the history-MMR helper.
fn restore_to(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    target: Hash,
    records: &[mkit_core::ops::conflict_state::ConflictRecord],
) -> Result<(), u8> {
    let target_tree = load_tree_hash(store, target)?;
    // Pre-flight: refuse the abort *before* any mutation when restoring
    // would clobber genuine user work on a non-conflict path. The reset
    // below is destructive (it discards the user's in-progress conflict
    // resolution), so it must not run if the abort is going to fail.
    if let Err(e) = super::conflict::ensure_abort_safe(cwd, store, records, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    // Discard the conflict material we materialised on the recorded
    // paths so the guarded restore below does not see them as user
    // "local changes" (it still protects unrelated dirty/untracked work).
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
        Head::Branch(name) => {
            if let Err(e) = super::write_ref_recording_history(
                mkit_dir,
                &name,
                refs::RefWriteCondition::Any,
                &target,
            ) {
                return Err(emit_err(&format!("restore ref: {e}"), exit::CANTCREAT));
            }
        }
        Head::Detached(_) => {
            if let Err(e) = refs::write_head_detached(mkit_dir, &target) {
                return Err(emit_err(&format!("restore HEAD: {e}"), exit::CANTCREAT));
            }
        }
    }
    Ok(())
}

fn create_merge_commit(
    cwd: &std::path::Path,
    store: &ObjectStore,
    tree_hash: Hash,
    parent_ours: Hash,
    parent_theirs: Hash,
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
        vec![parent_ours, parent_theirs],
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
