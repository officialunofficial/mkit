//! `mkit rebase <branch> | --continue | --abort | --skip` — replay
//! commits onto a different base.
//!
//! The rebase state machine lives in `mkit_core::ops::rebase`. This
//! shim loads / writes that state and drives the replay loop via
//! [`mkit_core::ops::cherry_pick`].
//!
//! On conflict the loop **pauses**: it materialises conflict material
//! into the worktree + index (via the shared `conflict` helper) and
//! writes a `mkit-conflicts` sidecar inside `.mkit/rebase-apply/`.
//!
//! `--continue` does NOT re-run cherry-pick on the paused commit (the
//! #177 bug). Instead it builds the rewritten commit's tree from the
//! resolved index/worktree, creates the commit, moves `todo[0]` to
//! `done`, and keeps replaying the remaining commits.
//!
//! `--skip` drops the current `todo[0]` with no replacement commit and
//! continues. `--abort` restores `HEAD` to `orig_head` and removes all
//! rebase state (including the sidecar).

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_core::hash::Hash;
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::ops::cherry_pick::cherry_pick;
use mkit_core::ops::conflict_state::{self, in_progress_op_name};
use mkit_core::ops::rebase::{
    RebaseState, cleanup_rebase, collect_commits_to_replay, is_rebase_in_progress, read_state,
    rebase_dir_path, write_state,
};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit rebase", about = "Replay commits onto a different base.")]
struct RebaseOpts {
    /// Continue an in-progress rebase after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "skip", "branch"])]
    cont: bool,
    /// Abort the in-progress rebase and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "skip", "branch"])]
    abort: bool,
    /// Skip the current commit (drop it) and continue the rebase.
    #[arg(long, conflicts_with_all = ["cont", "abort", "branch"])]
    skip: bool,
    /// Branch to replay commits onto.
    branch: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RebaseOpts>("mkit rebase", args) {
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
        resume(&cwd, &mkit_dir, &store, false)
    } else if opts.skip {
        resume(&cwd, &mkit_dir, &store, true)
    } else if let Some(branch) = opts.branch.as_deref() {
        start(&cwd, &mkit_dir, &store, branch)
    } else {
        super::usage_error("usage: mkit rebase <branch> | --continue | --abort | --skip")
    }
}

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
    let onto = match refs::read_ref(mkit_dir, branch) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err(&format!("branch '{branch}' not found"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    };
    let orig_head = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let head_name = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => name,
        Ok(Head::Detached(_)) => {
            return emit_err("cannot rebase with detached HEAD", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let todo = match collect_commits_to_replay(store, orig_head, onto) {
        Ok(v) => v,
        Err(e) => return emit_err(&format!("collect commits: {e}"), exit::GENERAL_ERROR),
    };
    let state = RebaseState {
        head_name,
        orig_head,
        onto,
        todo,
        done: Vec::new(),
    };
    let signing = match load_rebase_signing(cwd) {
        Ok(signing) => signing,
        Err(code) => return code,
    };
    let onto_tree = match load_tree_hash(store, onto) {
        Ok(t) => t,
        Err(c) => return c,
    };
    if let Err(e) = super::ensure_restore_safe(cwd, store, onto_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("write rebase state: {e}"), exit::CANTCREAT);
    }
    // Start HEAD at `onto` and drive the replay.
    if let Err(e) = super::restore_worktree_and_index(cwd, store, onto_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = refs::write_head_detached(mkit_dir, &onto) {
        return emit_err(&format!("detach HEAD: {e}"), exit::CANTCREAT);
    }
    replay(cwd, mkit_dir, store, Some(signing))
}

/// Resume after a pause. When `skip` is set, drop the paused `todo[0]`
/// with no replacement commit; otherwise create the rewritten commit
/// for `todo[0]` from the resolved index, then keep replaying.
fn resume(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    skip: bool,
) -> u8 {
    if !is_rebase_in_progress(mkit_dir) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    let rebase_dir = rebase_dir_path(mkit_dir);
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(&rebase_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };

    if skip {
        if let Err(code) =
            skip_paused_commit(cwd, mkit_dir, store, &rebase_dir, &mut state, &records)
        {
            return code;
        }
    } else if !records.is_empty()
        && let Err(code) =
            commit_resolved_commit(cwd, mkit_dir, store, &rebase_dir, &mut state, &records)
    {
        return code;
    }
    // Either nothing was paused (plain resume) or we just consumed the
    // paused commit; keep replaying the remaining todo.
    replay(cwd, mkit_dir, store, None)
}

/// `--skip`: drop the paused `todo[0]` with no replacement, discarding
/// its conflict material from the worktree/index.
fn skip_paused_commit(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    rebase_dir: &std::path::Path,
    state: &mut RebaseState,
    records: &[conflict_state::ConflictRecord],
) -> Result<(), u8> {
    if state.todo.is_empty() {
        return Err(emit_err(
            "nothing to skip; no commit is paused",
            exit::GENERAL_ERROR,
        ));
    }
    let head_hash = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        _ => state.onto,
    };
    let head_tree = load_tree_hash(store, head_hash)?;
    if let Err(e) = super::conflict::reset_conflict_paths(cwd, store, records, head_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    state.todo.remove(0);
    persist_after_consume(mkit_dir, rebase_dir, state)
}

/// `--continue` on a paused commit: refuse if markers remain, build the
/// rewritten commit's tree from the RESOLVED index (not the
/// conflict-time tree), create the commit, and move `todo[0]` → `done`.
fn commit_resolved_commit(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    rebase_dir: &std::path::Path,
    state: &mut RebaseState,
    records: &[conflict_state::ConflictRecord],
) -> Result<(), u8> {
    match super::conflict::first_unresolved_marker(cwd, records) {
        Ok(Some(path)) => {
            return Err(emit_err(
                &format!(
                    "unresolved conflict markers remain in '{path}'; resolve and `mkit add` it"
                ),
                exit::GENERAL_ERROR,
            ));
        }
        Ok(None) => {}
        Err(e) => return Err(emit_err(&e, exit::GENERAL_ERROR)),
    }
    if state.todo.is_empty() {
        return Err(emit_err(
            "rebase state is inconsistent: no paused commit",
            exit::GENERAL_ERROR,
        ));
    }
    let target = state.todo[0];
    let parent = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        _ => state.onto,
    };
    let idx = super::read_or_seed_index_from_head(cwd, store)
        .map_err(|e| emit_err(&e, exit::GENERAL_ERROR))?;
    let tree_hash = worktree::build_tree_from_index(store, &idx)
        .map_err(|e| emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR))?;
    let mut signing = load_rebase_signing(cwd)?;
    let new_hash = build_commit(
        store,
        &mut signing.signer,
        signing.author.clone(),
        parent,
        target,
        tree_hash,
    )?;
    if let Err(e) = super::restore_worktree_and_index(cwd, store, tree_hash) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = refs::write_head_detached(mkit_dir, &new_hash) {
        return Err(emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT));
    }
    state.done.push(target);
    state.todo.remove(0);
    persist_after_consume(mkit_dir, rebase_dir, state)
}

/// Clear the conflict sidecar and persist the updated rebase state.
fn persist_after_consume(
    mkit_dir: &std::path::Path,
    rebase_dir: &std::path::Path,
    state: &RebaseState,
) -> Result<(), u8> {
    if let Err(e) = conflict_state::write_conflicts(rebase_dir, &[]) {
        return Err(emit_err(
            &format!("clear conflicts: {e}"),
            exit::GENERAL_ERROR,
        ));
    }
    if let Err(e) = write_state(mkit_dir, state) {
        return Err(emit_err(&format!("persist state: {e}"), exit::CANTCREAT));
    }
    Ok(())
}

fn abort(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_rebase_in_progress(mkit_dir) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    let state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let orig_tree = match load_tree_hash(store, state.orig_head) {
        Ok(tree) => tree,
        Err(code) => return code,
    };
    // Discard any conflict material we materialised before guarding the
    // restore (the sidecar lives inside the rebase-apply dir). Reset the
    // recorded conflict paths to the CURRENT detached-HEAD tree so the
    // worktree/index match HEAD (no spurious staged/local changes); the
    // guarded restore below then moves cleanly back to orig_head.
    let rebase_dir = rebase_dir_path(mkit_dir);
    let records = match conflict_state::read_conflicts(&rebase_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    // Pre-flight: refuse before any mutation when the abort would clobber
    // genuine user work on a non-conflict path. The conflict-path reset
    // below is destructive, so it must not run if the abort is going to
    // be refused by the guarded restore. The final restore target is
    // `orig_tree`, so the safety of non-conflict paths is judged against
    // it.
    if let Err(e) = super::conflict::ensure_abort_safe(cwd, store, &records, orig_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if !records.is_empty() {
        let head_hash = match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => h,
            _ => state.onto,
        };
        let head_tree = match load_tree_hash(store, head_hash) {
            Ok(t) => t,
            Err(c) => return c,
        };
        if let Err(e) = super::conflict::reset_conflict_paths(cwd, store, &records, head_tree) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
    }
    if let Err(e) = super::ensure_restore_safe(cwd, store, orig_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = super::restore_worktree_and_index(cwd, store, orig_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    // Rebase abort rolls the branch tip back to `orig_head`. Route
    // through the history-MMR-coupled helper so the rollback append
    // is recorded under the repo lock; the MMR is append-only, so
    // "rollback" surfaces as another leaf, not a rewind.
    if let Err(e) = super::write_ref_recording_history(
        mkit_dir,
        &state.head_name,
        refs::RefWriteCondition::Any,
        &state.orig_head,
    ) {
        return emit_err(&format!("restore ref: {e}"), exit::CANTCREAT);
    }
    if let Err(e) = refs::write_head_branch(mkit_dir, &state.head_name) {
        return emit_err(&format!("restore HEAD: {e}"), exit::CANTCREAT);
    }
    let _ = cleanup_rebase(mkit_dir);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rebase aborted; HEAD restored to {}",
        &state.head_name
    );
    exit::OK
}

#[allow(clippy::too_many_lines)]
fn replay(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    signing: Option<RebaseSigning>,
) -> u8 {
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let mut signing = match signing {
        Some(signing) => signing,
        None => match load_rebase_signing(cwd) {
            Ok(signing) => signing,
            Err(code) => return code,
        },
    };
    let rebase_dir = rebase_dir_path(mkit_dir);

    while !state.todo.is_empty() {
        let target = state.todo[0];
        let head_hash = match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => h,
            _ => state.onto,
        };
        let ours_tree = match load_tree_hash(store, head_hash) {
            Ok(t) => t,
            Err(c) => return c,
        };
        let result = match cherry_pick(store, target, ours_tree) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("cherry-pick: {e}"), exit::GENERAL_ERROR),
        };
        if result.has_conflicts() {
            // Pause: persist state, materialise conflict material into
            // the worktree + index, and write the sidecar so
            // `--continue` consumes the resolved tree (not re-running
            // cherry-pick).
            let _ = write_state(mkit_dir, &state);
            if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
                return emit_err(&e, exit::GENERAL_ERROR);
            }
            let records =
                match super::conflict::materialize_conflicts(cwd, store, &result.conflicts) {
                    Ok(r) => r,
                    Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
                };
            if let Err(e) = conflict_state::write_conflicts(&rebase_dir, &records) {
                return emit_err(&format!("write conflicts: {e}"), exit::CANTCREAT);
            }
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "rebase paused: conflict while replaying {}",
                format::short_hash(&target, 8)
            );
            let _ = writeln!(
                stderr,
                "resolve the files above, `mkit add` them, then run `mkit rebase --continue` \
                 (or `--skip` to drop this commit, or `--abort`)"
            );
            return exit::GENERAL_ERROR;
        }
        if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let new_hash = match build_commit(
            store,
            &mut signing.signer,
            signing.author.clone(),
            head_hash,
            target,
            result.tree_hash,
        ) {
            Ok(h) => h,
            Err(c) => return c,
        };
        if let Err(e) = super::restore_worktree_and_index(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = refs::write_head_detached(mkit_dir, &new_hash) {
            return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
        }
        state.done.push(target);
        state.todo.remove(0);
        if let Err(e) = write_state(mkit_dir, &state) {
            return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
        }
    }

    // Finish: move the branch to current HEAD and reattach.
    let final_head = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        _ => state.onto,
    };
    if let Err(e) = super::write_ref_recording_history(
        mkit_dir,
        &state.head_name,
        refs::RefWriteCondition::Any,
        &final_head,
    ) {
        return emit_err(&format!("write ref: {e}"), exit::CANTCREAT);
    }
    if let Err(e) = refs::write_head_branch(mkit_dir, &state.head_name) {
        return emit_err(&format!("reattach HEAD: {e}"), exit::CANTCREAT);
    }
    let _ = cleanup_rebase(mkit_dir);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rebased {} commit(s) onto {}",
        state.done.len(),
        format::short_hash(&state.onto, 8)
    );
    exit::OK
}

struct RebaseSigning {
    signer: super::commit::CommitSigner,
    author: Identity,
}

fn load_rebase_signing(cwd: &std::path::Path) -> Result<RebaseSigning, u8> {
    let cfg = config::read_or_default(cwd)
        .map_err(|e| emit_err(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let signer =
        super::commit::load_commit_signer(cwd, &cfg).map_err(|(msg, code)| emit_err(&msg, code))?;
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    let author = super::commit::resolve_author(None, &cfg.user_identity, &signer_public)
        .map_err(|error| emit_err(&format!("author: {error}"), exit::CONFIG_ERROR))?;
    Ok(RebaseSigning { signer, author })
}

fn build_commit(
    store: &ObjectStore,
    signer: &mut super::commit::CommitSigner,
    author: Identity,
    parent: Hash,
    original: Hash,
    tree_hash: Hash,
) -> Result<Hash, u8> {
    let original_msg = match store.read_object(&original) {
        Ok(Object::Commit(c)) => c.message.clone(),
        Ok(_) => return Err(emit_err("original is not a commit", exit::DATAERR)),
        Err(e) => return Err(emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    };
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        vec![parent],
        author,
        signer_public,
        original_msg,
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
        .map_err(|e| emit_err(&format!("store: {e}"), exit::CANTCREAT))
}

fn load_tree_hash(store: &ObjectStore, commit_hash: Hash) -> Result<Hash, u8> {
    match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(_) => Err(emit_err("object is not a commit", exit::DATAERR)),
        Err(e) => Err(emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
