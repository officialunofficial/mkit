//! `mkit rebase [-i] <revspec> | --continue | --abort | --skip` — replay
//! commits onto a different base. The target is resolved through the
//! shared revspec resolver, so a branch, tag, `HEAD~n`, or full/short
//! hash all work.
//!
//! The rebase state machine lives in `mkit_core::ops::rebase`. This
//! shim loads / writes that state and drives the replay loop via
//! [`mkit_core::ops::cherry_pick()`].
//!
//! With `-i`/`--interactive`, the todo list is opened in `$EDITOR`
//! before any mutation: lines can be reordered, `drop`ped (deleted),
//! `reword`ed, or folded into the previous commit with `squash` (combine
//! messages) / `fixup` (keep the previous message). Each commit's action
//! is persisted alongside `todo` in the rebase state, so a reword/squash
//! that pauses on conflict still reopens the editor on `--continue`. A
//! squash/fixup may not be the first line. `edit` (stop to amend) is not
//! yet supported and is rejected at parse time before HEAD is touched.
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

use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::ops::cherry_pick::cherry_pick;
use mkit_core::ops::conflict_state::{self, in_progress_op_name};
use mkit_core::ops::rebase::{
    RebaseAction, RebaseState, cleanup_rebase, collect_commits_to_replay, is_rebase_in_progress,
    read_state, rebase_dir_path, write_state,
};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::editor;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit rebase", about = "Replay commits onto a different base.")]
// CLI flag struct: each bool is an independent clap switch.
#[allow(clippy::struct_excessive_bools)]
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
    /// Edit the todo list in `$EDITOR` before replaying: reorder lines,
    /// `drop` (or delete) lines, `reword`, or fold with `squash`/`fixup`.
    /// (`edit` is not yet supported.)
    #[arg(short = 'i', long, conflicts_with_all = ["cont", "abort", "skip"])]
    interactive: bool,
    /// Branch, tag, or revision (e.g. `HEAD~2`, a full/short hash) to
    /// replay commits onto. Resolved through the shared revspec resolver.
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
    let layout = super::resolve_layout(&cwd);
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };

    if opts.abort {
        abort(&layout, &store)
    } else if opts.cont {
        resume(&layout, &store, false)
    } else if opts.skip {
        resume(&layout, &store, true)
    } else if let Some(branch) = opts.branch.as_deref() {
        start(&layout, &store, branch, opts.interactive)
    } else {
        super::usage_error("usage: mkit rebase [-i] <revspec> | --continue | --abort | --skip")
    }
}

fn start(layout: &RepoLayout, store: &ObjectStore, branch: &str, interactive: bool) -> u8 {
    if let Some(op) = in_progress_op_name(layout) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }
    // Resolve the rebase target through the shared revspec resolver
    // (#227) so `rebase HEAD~2`, short/full hashes, tags, and branch
    // names all work — the same grammar `reset`/`restore`/`cherry-pick`
    // accept. The current branch name recorded in the rebase state
    // (`head_name`) comes from HEAD below, not from this argument.
    let onto = match super::revspec::resolve_revision(store, layout, branch) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!("no such commit: {branch} ({e})"),
                exit::GENERAL_ERROR,
            );
        }
    };
    let orig_head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let head_name = match refs::read_head(layout) {
        Ok(Head::Branch(name)) => name,
        Ok(Head::Detached(_)) => {
            return emit_err("cannot rebase with detached HEAD", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let candidates = match collect_commits_to_replay(store, orig_head, onto) {
        Ok(v) => v,
        Err(e) => return emit_err(&format!("collect commits: {e}"), exit::GENERAL_ERROR),
    };

    // Already at the target → nothing to do (git's `Current branch … is up
    // to date.`), for both interactive and non-interactive. When HEAD is
    // merely *behind* `onto` (an ancestor of it) we fall through and let the
    // finalize flow fast-forward the branch.
    if orig_head == onto {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Current branch {head_name} is up to date.");
        return exit::OK;
    }

    // Interactive: let the user reorder / drop / reword the todo before any
    // mutation. Non-interactive: every commit is a plain pick.
    let (todo, actions) = if interactive {
        if candidates.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            match edit_todo(store, &candidates, orig_head, onto) {
                Ok(plan) => plan,
                Err(code) => return code,
            }
        }
    } else {
        let actions = vec![RebaseAction::Pick; candidates.len()];
        (candidates, actions)
    };
    let state = RebaseState {
        head_name,
        orig_head,
        onto,
        todo,
        actions,
        done: Vec::new(),
    };
    let signing = match load_rebase_signing(layout) {
        Ok(signing) => signing,
        Err(code) => return code,
    };
    let onto_tree = match load_tree_hash(store, onto) {
        Ok(t) => t,
        Err(c) => return c,
    };
    if let Err(e) = super::ensure_restore_safe(layout, store, onto_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = write_state(layout, &state) {
        return emit_err(&format!("write rebase state: {e}"), exit::CANTCREAT);
    }
    // Start HEAD at `onto` and drive the replay.
    if let Err(e) = super::restore_worktree_and_index(layout, store, onto_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = refs::write_head_detached(layout, &onto) {
        return emit_err(&format!("detach HEAD: {e}"), exit::CANTCREAT);
    }
    replay(layout, store, Some(signing))
}

/// Resume after a pause. When `skip` is set, drop the paused `todo[0]`
/// with no replacement commit; otherwise create the rewritten commit
/// for `todo[0]` from the resolved index, then keep replaying.
fn resume(layout: &RepoLayout, store: &ObjectStore, skip: bool) -> u8 {
    if !is_rebase_in_progress(layout) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    let rebase_dir = rebase_dir_path(layout);
    let mut state = match read_state(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(&rebase_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };

    if skip {
        if let Err(code) = skip_paused_commit(layout, store, &rebase_dir, &mut state, &records) {
            return code;
        }
    } else if !records.is_empty()
        && let Err(code) = commit_resolved_commit(layout, store, &rebase_dir, &mut state, &records)
    {
        return code;
    }
    // Either nothing was paused (plain resume) or we just consumed the
    // paused commit; keep replaying the remaining todo.
    replay(layout, store, None)
}

/// `--skip`: drop the paused `todo[0]` with no replacement, discarding
/// its conflict material from the worktree/index.
fn skip_paused_commit(
    layout: &RepoLayout,
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
    let head_hash = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        _ => state.onto,
    };
    let head_tree = load_tree_hash(store, head_hash)?;
    // Also discard the skipped step's clean hunks (not just conflict paths).
    let op_result = conflict_state::read_result_tree(rebase_dir).ok().flatten();
    // Pre-flight before any mutation: refuse if discarding the step would
    // destroy genuine user work — an edit to a cleanly-applied path, or
    // unrelated staged/worktree changes — exactly as `--abort` does.
    if let Err(e) = super::conflict::ensure_abort_safe(layout, store, records, head_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) =
        super::conflict::reset_conflict_paths(layout, store, records, head_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    state.consume_front();
    persist_after_consume(layout, rebase_dir, state)
}

/// `--continue` on a paused commit: refuse if markers remain, build the
/// rewritten commit's tree from the RESOLVED index (not the
/// conflict-time tree), create the commit, and move `todo[0]` → `done`.
fn commit_resolved_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    rebase_dir: &std::path::Path,
    state: &mut RebaseState,
    records: &[conflict_state::ConflictRecord],
) -> Result<(), u8> {
    match super::conflict::first_unresolved_marker(layout.worktree_root(), records) {
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
    if let Err(e) = super::conflict::ensure_conflict_paths_staged(layout, store, records) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if state.todo.is_empty() {
        return Err(emit_err(
            "rebase state is inconsistent: no paused commit",
            exit::GENERAL_ERROR,
        ));
    }
    let target = state.todo[0];
    let head_hash = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        _ => state.onto,
    };
    let idx = super::read_or_seed_index_from_head(layout, store)
        .map_err(|e| emit_err(&e, exit::GENERAL_ERROR))?;
    let tree_hash = worktree::build_tree_from_index(store, &idx)
        .map_err(|e| emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR))?;
    let mut signing = load_rebase_signing(layout)?;
    // Same parent/message policy as the no-conflict path: pick/reword make a
    // child of HEAD, squash/fixup fold into it (parent = HEAD's parent). The
    // reword/squash editor opens now that the tree is resolved.
    let plan = plan_step_commit(store, state.front_action(), target, head_hash)?;
    let new_hash = build_commit(
        store,
        &mut signing.signer,
        plan.author,
        plan.timestamp,
        plan.parent,
        plan.message,
        tree_hash,
    )?;
    // Sync the index to the committed tree WITHOUT rewriting the worktree:
    // the tree was built from the index, so the worktree already holds the
    // resolved content; restoring it would clobber unstaged edits made on a
    // cleanly-replayed path before `--continue`.
    if let Err(e) = super::sync_index_to_tree(layout, store, tree_hash) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = refs::write_head_detached(layout, &new_hash) {
        return Err(emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT));
    }
    state.done.push(target);
    state.consume_front();
    persist_after_consume(layout, rebase_dir, state)
}

/// Clear the conflict sidecar and persist the updated rebase state.
fn persist_after_consume(
    layout: &RepoLayout,
    rebase_dir: &std::path::Path,
    state: &RebaseState,
) -> Result<(), u8> {
    if let Err(e) = conflict_state::write_conflicts(rebase_dir, &[]) {
        return Err(emit_err(
            &format!("clear conflicts: {e}"),
            exit::GENERAL_ERROR,
        ));
    }
    if let Err(e) = write_state(layout, state) {
        return Err(emit_err(&format!("persist state: {e}"), exit::CANTCREAT));
    }
    Ok(())
}

fn abort(layout: &RepoLayout, store: &ObjectStore) -> u8 {
    if !is_rebase_in_progress(layout) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    let state = match read_state(layout) {
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
    let rebase_dir = rebase_dir_path(layout);
    let records = match conflict_state::read_conflicts(&rebase_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    // The paused step's result tree lets the guards treat its clean hunks
    // (not just conflict paths) as discardable.
    let op_result = conflict_state::read_result_tree(&rebase_dir).ok().flatten();
    // Pre-flight: refuse before any mutation when the abort would clobber
    // genuine user work on a non-discardable path. The reset below is
    // destructive, so it must not run if the abort is going to be refused by
    // the guarded restore. The final restore target is `orig_tree`, so the
    // safety of non-discardable paths is judged against it.
    if let Err(e) =
        super::conflict::ensure_abort_safe(layout, store, &records, orig_tree, op_result)
    {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if !records.is_empty() || op_result.is_some() {
        let head_hash = match refs::resolve_head(layout) {
            Ok(Some(h)) => h,
            _ => state.onto,
        };
        let head_tree = match load_tree_hash(store, head_hash) {
            Ok(t) => t,
            Err(c) => return c,
        };
        if let Err(e) =
            super::conflict::reset_conflict_paths(layout, store, &records, head_tree, op_result)
        {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
    }
    if let Err(e) = super::ensure_restore_safe(layout, store, orig_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = super::restore_worktree_and_index(layout, store, orig_tree) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    // Rebase abort rolls the branch tip back to `orig_head`. Route
    // through the history-MMR-coupled helper so the rollback append
    // is recorded under the repo lock; the MMR is append-only, so
    // "rollback" surfaces as another leaf, not a rewind.
    if let Err(e) = super::write_ref_recording_history(
        layout,
        &state.head_name,
        refs::RefWriteCondition::Any,
        &state.orig_head,
    ) {
        return emit_err(&format!("restore ref: {e}"), exit::CANTCREAT);
    }
    if let Err(e) = refs::write_head_branch(layout, &state.head_name) {
        return emit_err(&format!("restore HEAD: {e}"), exit::CANTCREAT);
    }
    let _ = cleanup_rebase(layout);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "rebase aborted; HEAD restored to {}",
        &state.head_name
    );
    exit::OK
}

#[allow(clippy::too_many_lines)]
fn replay(layout: &RepoLayout, store: &ObjectStore, signing: Option<RebaseSigning>) -> u8 {
    let mut state = match read_state(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let mut signing = match signing {
        Some(signing) => signing,
        None => match load_rebase_signing(layout) {
            Ok(signing) => signing,
            Err(code) => return code,
        },
    };
    let rebase_dir = rebase_dir_path(layout);

    while !state.todo.is_empty() {
        // Clear any result tree left by a prior (now-resolved) conflict step
        // so a later non-conflict pause (e.g. interactive `edit`) doesn't let
        // `--abort`/`--skip` read a stale operation result.
        conflict_state::clear_result_tree(&rebase_dir);
        // Runtime leading-fold guard: a squash/fixup must fold into a commit
        // that this rebase has already applied. The parse-time guard only runs
        // when the todo is edited; `--skip`ping a conflicted leading pick can
        // leave a squash/fixup as the first APPLIED step. `state.done` is
        // empty iff nothing has been applied yet, so this fails closed BEFORE
        // any mutation (HEAD still at its current step), preserving --abort.
        if state.front_action().folds_into_previous() && state.done.is_empty() {
            let verb = if state.front_action() == RebaseAction::Fixup {
                "fixup"
            } else {
                "squash"
            };
            return emit_err(
                &format!("cannot '{verb}' as the first commit; it has nothing to fold into"),
                exit::USAGE,
            );
        }
        let target = state.todo[0];
        let head_hash = match refs::resolve_head(layout) {
            Ok(Some(h)) => h,
            _ => state.onto,
        };
        let ours_tree = match load_tree_hash(store, head_hash) {
            Ok(t) => t,
            Err(c) => return c,
        };
        // A replayed range can include MERGE commits (the first-parent walk
        // keeps them). Core cherry-pick refuses a merge without a mainline,
        // so replay merges against their first parent (`-m 1` semantics) —
        // the historical behavior — instead of failing mid-rebase with the
        // ref already moved.
        let mainline = match store.read_object(&target) {
            Ok(Object::Commit(c)) if c.parents.len() >= 2 => Some(1),
            _ => None,
        };
        let result = match cherry_pick(store, target, ours_tree, mainline) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("cherry-pick: {e}"), exit::GENERAL_ERROR),
        };
        if result.has_conflicts() {
            // Pause: persist state, materialise conflict material into
            // the worktree + index, and write the sidecar so
            // `--continue` consumes the resolved tree (not re-running
            // cherry-pick).
            let _ = write_state(layout, &state);
            if let Err(e) = super::ensure_restore_safe(layout, store, result.tree_hash) {
                return emit_err(&e, exit::GENERAL_ERROR);
            }
            let records = match super::conflict::materialize_conflicts(
                layout,
                store,
                result.tree_hash,
                &result.conflicts,
            ) {
                Ok(r) => r,
                Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
            };
            if let Err(e) = conflict_state::write_conflicts(&rebase_dir, &records) {
                return emit_err(&format!("write conflicts: {e}"), exit::CANTCREAT);
            }
            // Record the result tree so `--abort` treats this step's clean
            // hunks (not just conflict paths) as discardable.
            if let Err(e) = conflict_state::write_result_tree(&rebase_dir, &result.tree_hash) {
                return emit_err(&format!("write conflicts: {e}"), exit::CANTCREAT);
            }
            let mut stderr = std::io::stderr().lock();
            // git-shaped per-path conflict lines (additive).
            for rec in &records {
                let _ = writeln!(stderr, "CONFLICT (content): Merge conflict in {}", rec.path);
            }
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
        if let Err(e) = super::ensure_restore_safe(layout, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        // Compute the new commit's parent + message for this action (pick/
        // reword make a child of HEAD; squash/fixup fold into HEAD). Any
        // editor (reword/squash) runs here, after the tree is clean — the
        // conflict-resume path does the same in `commit_resolved_commit`.
        let plan = match plan_step_commit(store, state.front_action(), target, head_hash) {
            Ok(p) => p,
            Err(c) => return c,
        };
        let new_hash = match build_commit(
            store,
            &mut signing.signer,
            plan.author,
            plan.timestamp,
            plan.parent,
            plan.message,
            result.tree_hash,
        ) {
            Ok(h) => h,
            Err(c) => return c,
        };
        if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = refs::write_head_detached(layout, &new_hash) {
            return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
        }
        state.done.push(target);
        state.consume_front();
        if let Err(e) = write_state(layout, &state) {
            return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
        }
    }

    // Finish: move the branch to current HEAD and reattach. HEAD is
    // detached to a hash for the entire rebase (start detaches to `onto`,
    // each replay advances it), so a finalized rebase ALWAYS resolves to
    // `Some` — even an empty rebase leaves HEAD at `onto`. `None`/`Err`
    // therefore means HEAD was lost or corrupted mid-rebase: fail closed
    // rather than silently move the branch to `onto` and drop the
    // replayed tip.
    let final_head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => {
            return emit_err(
                "rebase: HEAD missing at finalize (in-progress state may be corrupted); aborting",
                exit::DATAERR,
            );
        }
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
    };
    // The original tip is superseded by the replayed history. Record it
    // BEFORE finalizing the branch (still under the worktree lock) so it
    // survives gc once the in-progress rebase state — which currently
    // pins it — is cleaned up below. Abort if the log can't be written.
    if state.orig_head != final_head
        && let Err((m, c)) =
            super::record_superseded(layout, "rebase", &state.head_name, state.orig_head)
    {
        return emit_err(&m, c);
    }
    if let Err(e) = super::write_ref_recording_history(
        layout,
        &state.head_name,
        refs::RefWriteCondition::Any,
        &final_head,
    ) {
        return emit_err(&format!("write ref: {e}"), exit::CANTCREAT);
    }
    if let Err(e) = refs::write_head_branch(layout, &state.head_name) {
        return emit_err(&format!("reattach HEAD: {e}"), exit::CANTCREAT);
    }
    let _ = cleanup_rebase(layout);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "Successfully rebased and updated refs/heads/{}.",
        state.head_name
    );
    exit::OK
}

struct RebaseSigning {
    signer: super::commit::CommitSigner,
}

fn load_rebase_signing(layout: &RepoLayout) -> Result<RebaseSigning, u8> {
    let cfg = config::read_or_default(layout)
        .map_err(|e| emit_err(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let signer = super::commit::load_commit_signer(layout, &cfg)
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    Ok(RebaseSigning { signer })
}

fn build_commit(
    store: &ObjectStore,
    signer: &mut super::commit::CommitSigner,
    author: Identity,
    timestamp: u64,
    parent: Hash,
    message: Vec<u8>,
    tree_hash: Hash,
) -> Result<Hash, u8> {
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        vec![parent],
        author,
        signer_public,
        message,
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

/// The parent and message a replayed commit gets under `action`.
///
/// `pick`/`reword` create a NEW commit as a child of `head_hash`.
/// `squash`/`fixup` **fold** the target into `head_hash`: the new commit
/// replaces it, so its parent is HEAD's own parent and the message combines
/// (`squash`) or is kept from HEAD (`fixup`). Both the no-conflict replay
/// and the `--continue` resume path call this, so they cannot diverge.
struct StepCommit {
    parent: Hash,
    message: Vec<u8>,
    /// Replayed commits keep the original authorship: pick/reword use
    /// the target's author + timestamp; squash/fixup keep the folded-
    /// into commit's (git's behavior — replays re-sign but never
    /// re-attribute, and mkit's single timestamp takes author-date
    /// semantics on replay).
    author: Identity,
    timestamp: u64,
}

fn plan_step_commit(
    store: &ObjectStore,
    action: RebaseAction,
    target: Hash,
    head_hash: Hash,
) -> Result<StepCommit, u8> {
    match action {
        RebaseAction::Pick => {
            let original = read_commit(store, target)?;
            Ok(StepCommit {
                parent: head_hash,
                message: original.message,
                author: original.author,
                timestamp: original.timestamp,
            })
        }
        RebaseAction::Reword => {
            let original = read_commit(store, target)?;
            Ok(StepCommit {
                parent: head_hash,
                message: reworded_message(&original.message)?,
                author: original.author,
                timestamp: original.timestamp,
            })
        }
        RebaseAction::Squash | RebaseAction::Fixup => {
            // Fold into HEAD: the new commit takes HEAD's place, so its
            // parent is HEAD's parent. A squash/fixup is rejected at parse
            // time when it would be the first applied commit, so HEAD here is
            // always a just-built commit with exactly one parent.
            let head_commit = read_commit(store, head_hash)?;
            let parent = head_commit.parents.first().copied().ok_or_else(|| {
                emit_err(
                    "'squash'/'fixup' has no preceding commit to fold into",
                    exit::DATAERR,
                )
            })?;
            let message = if action == RebaseAction::Fixup {
                head_commit.message.clone()
            } else {
                let target_msg = read_commit(store, target)?.message;
                squashed_message(&head_commit.message, &target_msg)?
            };
            Ok(StepCommit {
                parent,
                message,
                author: head_commit.author,
                timestamp: head_commit.timestamp,
            })
        }
    }
}

fn read_commit(store: &ObjectStore, h: Hash) -> Result<Commit, u8> {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => Ok(c),
        Ok(_) => Err(emit_err("object is not a commit", exit::DATAERR)),
        Err(e) => Err(emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    }
}

/// Open the editor on a reword seed; an empty result keeps the original
/// message rather than aborting the rebase.
fn reworded_message(original: &[u8]) -> Result<Vec<u8>, u8> {
    let seed = reword_template(original);
    match editor::spawn_editor(&seed) {
        Ok(s) if !s.trim().is_empty() => Ok(s.into_bytes()),
        Ok(_) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "reword: empty message; keeping the original");
            Ok(original.to_vec())
        }
        Err(e) => Err(emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR)),
    }
}

/// Combine the kept commit's message with the squashed commit's via the
/// editor. An empty result falls back to plain concatenation (never aborts).
fn squashed_message(head_msg: &[u8], target_msg: &[u8]) -> Result<Vec<u8>, u8> {
    let seed = format!(
        "{}\n\n{}\n\n\
         # This is a combination of 2 commits; the first message is the one\n\
         # being squashed into. Edit the combined message above. Lines\n\
         # starting with '#' are ignored.\n",
        String::from_utf8_lossy(head_msg),
        String::from_utf8_lossy(target_msg),
    );
    match editor::spawn_editor(&seed) {
        Ok(s) if !s.trim().is_empty() => Ok(s.into_bytes()),
        Ok(_) => {
            let mut combined = head_msg.to_vec();
            combined.extend_from_slice(b"\n\n");
            combined.extend_from_slice(target_msg);
            Ok(combined)
        }
        Err(e) => Err(emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR)),
    }
}

/// Editor seed for a reword: the original message followed by ignored
/// `#`-comment guidance (stripped on read by `spawn_editor`).
fn reword_template(original: &[u8]) -> String {
    format!(
        "{}\n\
         # Reword: edit the commit message above. Lines starting with '#'\n\
         # are ignored. An empty message keeps the original message.\n",
        String::from_utf8_lossy(original)
    )
}

/// First line of a commit's message, for the interactive todo display.
fn commit_subject(store: &ObjectStore, h: Hash) -> String {
    match store.read_object(&h) {
        Ok(Object::Commit(c)) => {
            let text = String::from_utf8_lossy(&c.message);
            text.lines().next().unwrap_or("").trim().to_string()
        }
        _ => String::new(),
    }
}

/// Render the interactive todo from a non-empty candidate list, open the
/// editor, and parse the result into a `(todo, actions)` plan in the edited
/// order. The returned `todo` may be empty if the user dropped every line
/// (which resets the branch to the base). Mutating nothing, it is safe to
/// fail here before the rebase touches HEAD. (The empty-candidate case is
/// handled by the caller.)
#[allow(clippy::type_complexity)]
fn edit_todo(
    store: &ObjectStore,
    candidates: &[Hash],
    orig_head: Hash,
    onto: Hash,
) -> Result<(Vec<Hash>, Vec<RebaseAction>), u8> {
    use std::fmt::Write as _;
    // Build the template: one `pick <short> <subject>` line per candidate,
    // oldest-first (the order `collect_commits_to_replay` returns).
    let mut template = String::new();
    for h in candidates {
        let _ = writeln!(
            template,
            "pick {} {}",
            format::short_hash(h, 12),
            commit_subject(store, *h)
        );
    }
    let _ = write!(
        template,
        "\n\
         # Rebase {}..{} onto {}.\n\
         #\n\
         # Commands (one per line, in apply order — top is applied first):\n\
         #   p, pick   <commit>  = use the commit\n\
         #   r, reword <commit>  = use the commit, but edit its message\n\
         #   s, squash <commit>  = fold into the previous commit, combining messages\n\
         #   f, fixup  <commit>  = fold into the previous commit, discard this message\n\
         #   d, drop   <commit>  = remove the commit\n\
         #\n\
         # Reorder lines to reorder commits. Deleting a line drops that commit.\n\
         # A squash/fixup cannot be the first line. 'edit' is not yet supported.\n\
         # Removing every line resets the branch to the base.\n",
        format::short_hash(&onto, 12),
        format::short_hash(&orig_head, 12),
        format::short_hash(&onto, 12),
    );

    let edited = editor::spawn_editor(&template).map_err(|e| {
        // spawn_editor strips comment lines, so the seed text never counts as
        // "content"; an editor failure is the only real error here.
        emit_err(&format!("editor: {e}"), exit::GENERAL_ERROR)
    })?;

    parse_todo(candidates, &edited)
}

/// Parse the edited todo text into `(todo, actions)`. Validates verbs and
/// resolves each abbreviated commit against `candidates`. Fails (before any
/// mutation) on an unknown verb, an unknown/ambiguous commit, the still-
/// unsupported `edit` verb, or a leading `squash`/`fixup` (which has no
/// preceding commit to fold into).
#[allow(clippy::type_complexity)]
fn parse_todo(candidates: &[Hash], edited: &str) -> Result<(Vec<Hash>, Vec<RebaseAction>), u8> {
    let mut todo = Vec::new();
    let mut actions = Vec::new();
    for raw in edited.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let verb = parts.next().unwrap_or("");
        let action = match verb {
            "p" | "pick" => RebaseAction::Pick,
            "r" | "reword" => RebaseAction::Reword,
            "s" | "squash" => RebaseAction::Squash,
            "f" | "fixup" => RebaseAction::Fixup,
            "d" | "drop" => {
                // Dropped: still validate the hash so a typo is caught, then
                // omit the commit.
                let _ = resolve_todo_hash(candidates, parts.next(), line)?;
                continue;
            }
            "e" | "edit" => {
                return Err(emit_err(
                    "'edit' (stop to amend) is not yet supported; use pick, reword, squash, fixup, or drop",
                    exit::USAGE,
                ));
            }
            other => {
                return Err(emit_err(
                    &format!("unknown rebase command '{other}'"),
                    exit::USAGE,
                ));
            }
        };
        // A squash/fixup folds into the previous commit, so it cannot be the
        // first applied line (git: "cannot 'squash' without a previous
        // commit"). Reject before any mutation.
        if todo.is_empty() && action.folds_into_previous() {
            return Err(emit_err(
                &format!("cannot '{verb}' as the first commit; it has nothing to fold into"),
                exit::USAGE,
            ));
        }
        let h = resolve_todo_hash(candidates, parts.next(), line)?;
        todo.push(h);
        actions.push(action);
    }
    Ok((todo, actions))
}

/// Resolve an abbreviated commit token from a todo line against the original
/// candidate set (unambiguous prefix match or full hash).
fn resolve_todo_hash(candidates: &[Hash], token: Option<&str>, line: &str) -> Result<Hash, u8> {
    let token = token.ok_or_else(|| {
        emit_err(
            &format!("missing commit on todo line: '{line}'"),
            exit::USAGE,
        )
    })?;
    let token = token.to_ascii_lowercase();
    let matches: Vec<&Hash> = candidates
        .iter()
        .filter(|h| mkit_core::hash::to_hex(h).starts_with(&token))
        .collect();
    match matches.as_slice() {
        [h] => Ok(**h),
        [] => Err(emit_err(
            &format!("todo line refers to an unknown commit: '{line}'"),
            exit::USAGE,
        )),
        _ => Err(emit_err(
            &format!("ambiguous commit '{token}' on todo line: '{line}'"),
            exit::USAGE,
        )),
    }
}

use super::error as emit_err;
