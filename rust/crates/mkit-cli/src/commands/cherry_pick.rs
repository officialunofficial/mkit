//! `mkit cherry-pick <commit> | --continue | --abort` — replay a single
//! commit onto HEAD, with a resolvable-conflict workflow (#177).
//!
//! On a clean merge we create a new commit on the current branch using
//! the original commit's message. On conflict we materialise the
//! conflict material into the worktree + index, persist
//! `CHERRY_PICK_HEAD`/`CHERRY_PICK_MSG`/`ORIG_HEAD` and the
//! `mkit-conflicts` sidecar, and exit non-zero. The user resolves,
//! `mkit add`s, then runs `mkit cherry-pick --continue`.
//!
//! `--continue` refuses unless `CHERRY_PICK_HEAD` exists and no
//! marker-bearing file remains; it builds the final tree from the
//! resolved index. `--abort` restores HEAD/ref/index/worktree to
//! `ORIG_HEAD`.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::cherry_pick::{CherryPickError, cherry_pick};
use mkit_core::ops::conflict_state::{
    self, CherryPickState, in_progress_op_name, is_cherry_pick_in_progress,
};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use super::{advance_head, error as emit_err, load_tree_hash};
use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit cherry-pick", about = "Apply a single commit onto HEAD.")]
struct CherryPickOpts {
    /// Continue an in-progress cherry-pick after resolving conflicts.
    #[arg(long = "continue", conflicts_with_all = ["abort", "commit"])]
    cont: bool,
    /// Abort the in-progress cherry-pick and restore the original HEAD.
    #[arg(long, conflicts_with_all = ["cont", "commit"])]
    abort: bool,
    /// Apply the picked change to the index + worktree without creating a
    /// commit (like `git cherry-pick -n`). Run `mkit commit` when ready;
    /// the result has the current branch as its single parent.
    #[arg(short = 'n', long = "no-commit", conflicts_with_all = ["cont", "abort"])]
    no_commit: bool,
    /// Select the mainline parent (1-based) when replaying a merge commit,
    /// like `git cherry-pick -m`. Required for a merge (mkit refuses to
    /// guess which side is the mainline) and rejected for a non-merge.
    #[arg(short = 'm', long = "mainline", value_name = "PARENT-NUMBER", conflicts_with_all = ["cont", "abort"])]
    mainline: Option<usize>,
    /// Commit to replay: a ref, full/short hash, or `HEAD~n` revspec.
    commit: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CherryPickOpts>("mkit cherry-pick", args) {
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
        cont(&layout, &store)
    } else if let Some(hex) = opts.commit.as_deref() {
        start(&layout, &store, hex, opts.no_commit, opts.mainline)
    } else {
        super::usage_error("usage: mkit cherry-pick <commit> | --continue | --abort")
    }
}

#[allow(clippy::too_many_lines)]
fn start(
    layout: &RepoLayout,
    store: &ObjectStore,
    hex: &str,
    no_commit: bool,
    mainline: Option<usize>,
) -> u8 {
    if let Some(op) = in_progress_op_name(layout) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }
    let target: Hash = match super::revspec::resolve_revision(store, layout, hex) {
        // Peel annotated/signed tags to their target commit so
        // `mkit cherry-pick <annotated-tag>` works like git (a tag is a
        // ref, which the doc comment advertises as acceptable). Mirrors
        // `merge`'s behavior.
        Ok(h) => super::log::peel_tags(store, h),
        Err(e) => return emit_err(&format!("bad commit: {e}"), exit::DATAERR),
    };

    let ours = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let ours_tree = match store.read_object(&ours) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(_) => return emit_err("HEAD is not a commit", exit::DATAERR),
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };

    let result = match cherry_pick(store, target, ours_tree, mainline) {
        Ok(r) => r,
        // Mainline-selection misuse is a usage error (bad invocation),
        // distinct from a runtime store/merge failure.
        Err(
            e @ (CherryPickError::MergeNeedsMainline
            | CherryPickError::MainlineForNonMerge
            | CherryPickError::BadMainline { .. }),
        ) => return emit_err(&format!("cherry-pick: {e}"), exit::USAGE),
        Err(e) => return emit_err(&format!("cherry-pick: {e}"), exit::GENERAL_ERROR),
    };

    if result.has_conflicts() {
        // `-n` must never leave a committable conflict. mkit cannot represent
        // a "staged but unresolved" conflict the way git's index can, and
        // recording markers with no sequencer state would let a later
        // `mkit commit` (which only guards merges) commit unresolved `<<<<<<<`
        // markers. So we refuse the conflicting `-n` pick BEFORE touching the
        // worktree — nothing is written. Re-run without `-n` (resumable via
        // `--continue`/`--abort`) or resolve manually.
        if no_commit {
            return emit_err(
                &format!(
                    "cherry-pick -n of {} conflicts; mkit cannot stage an unresolved \
                     conflict without committing — re-run without -n, then resolve and \
                     `mkit cherry-pick --continue`",
                    format::short_hash(&target, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
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
        let state = CherryPickState {
            cherry_pick_head: target,
            orig_head: ours,
            message: result.original_message.clone(),
        };
        if let Err(e) = conflict_state::write_cherry_pick_state(layout, &state, &records) {
            return emit_err(&format!("write cherry-pick state: {e}"), exit::CANTCREAT);
        }
        // Record the result tree so `--abort` treats the operation's clean
        // hunks (not just conflict paths) as discardable.
        if let Err(e) =
            conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
        {
            return emit_err(&format!("write cherry-pick state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        // git-shaped per-path conflict lines (additive), then mkit's
        // resumable-flow hint.
        for rec in &records {
            let _ = writeln!(stderr, "CONFLICT (content): Merge conflict in {}", rec.path);
        }
        let _ = writeln!(
            stderr,
            "hint: resolve the files above, `mkit add` them, then run \
             `mkit cherry-pick --continue` (or `mkit cherry-pick --abort`)"
        );
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(layout, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // `--no-commit`: stage the picked tree into the index + worktree but do
    // not commit or move HEAD. The next `mkit commit` records it as an
    // ordinary single-parent commit on the current branch.
    if no_commit {
        if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        // Restoring from a tree drops staged DELETIONS; re-stage them as
        // tombstones so a deletion-bearing pick (or an all-deletions pick)
        // stays staged and `mkit commit` records it.
        if let Err(e) =
            super::stage_removed_tombstones(layout, store, Some(ours_tree), result.tree_hash)
        {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "staged cherry-pick of {} (no commit; run `mkit commit` when ready)",
            format::short_hash(&target, 8),
        );
        return exit::OK;
    }

    let commit_hash = match create_commit(
        layout,
        store,
        result.tree_hash,
        ours,
        &result.original_message,
        target,
    ) {
        Ok(h) => h,
        Err(code) => return code,
    };
    if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(layout, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    // git-shaped summary: `[<branch> <hash>] <subject>` + diffstat.
    let subject = String::from_utf8_lossy(&result.original_message)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    let branch_name = match refs::read_head(layout) {
        Ok(Head::Branch(b)) => Some(b),
        _ => None,
    };
    let head_ref = match &branch_name {
        Some(b) => super::summary::HeadRef::Branch(b),
        None => super::summary::HeadRef::Detached,
    };
    let mut stderr = std::io::stderr().lock();
    super::summary::print_commit_summary(
        &mut stderr,
        store,
        &head_ref,
        &commit_hash,
        &subject,
        false,
        Some(ours_tree),
        Some(result.tree_hash),
    );
    exit::OK
}

fn cont(layout: &RepoLayout, store: &ObjectStore) -> u8 {
    if !is_cherry_pick_in_progress(layout) {
        return emit_err("no cherry-pick in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_cherry_pick_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no cherry-pick in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read cherry-pick state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(layout.worktree_state_dir()) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    match super::conflict::first_unresolved_marker(layout.worktree_root(), &records) {
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
    if let Err(e) = super::conflict::ensure_conflict_paths_staged(layout, store, &records) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // Single parent = current HEAD (== orig_head). Build tree from the
    // resolved index, NOT the conflict-time tree.
    let idx = match super::read_or_seed_index_from_head(layout, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let tree_hash = match worktree::build_tree_from_index(store, &idx) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR),
    };

    let parent = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => state.orig_head,
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let commit_hash = match create_commit(
        layout,
        store,
        tree_hash,
        parent,
        &state.message,
        state.cherry_pick_head,
    ) {
        Ok(h) => h,
        Err(code) => return code,
    };
    // Sync the index to the committed tree WITHOUT rewriting the worktree:
    // the tree was built from the index, so the worktree already holds the
    // resolved content; restoring it would clobber any unstaged edits the
    // user made (e.g. on a cleanly-merged path) before `--continue`.
    if let Err(e) = super::sync_index_to_tree(layout, store, tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(layout, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    if let Err(e) = conflict_state::clear_cherry_pick_state(layout) {
        return emit_err(
            &format!("clear cherry-pick state: {e}"),
            exit::GENERAL_ERROR,
        );
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "cherry-picked {} as {}",
        format::short_hash(&state.cherry_pick_head, 8),
        format::short_hash(&commit_hash, 8),
    );
    exit::OK
}

fn abort(layout: &RepoLayout, store: &ObjectStore) -> u8 {
    if !is_cherry_pick_in_progress(layout) {
        return emit_err("no cherry-pick in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_cherry_pick_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no cherry-pick in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read cherry-pick state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(layout.worktree_state_dir()) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = restore_to(layout, store, state.orig_head, &records) {
        return code;
    }
    if let Err(e) = conflict_state::clear_cherry_pick_state(layout) {
        return emit_err(
            &format!("clear cherry-pick state: {e}"),
            exit::GENERAL_ERROR,
        );
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "cherry-pick aborted; HEAD restored");
    exit::OK
}

fn restore_to(
    layout: &RepoLayout,
    store: &ObjectStore,
    target: Hash,
    records: &[mkit_core::ops::conflict_state::ConflictRecord],
) -> Result<(), u8> {
    let target_tree = load_tree_hash(store, target)?;
    // The operation's result tree lets the guards treat its clean hunks (not
    // just conflict paths) as discardable.
    let op_result = conflict_state::read_result_tree(layout.worktree_state_dir())
        .ok()
        .flatten();
    // Pre-flight: refuse before any mutation when the abort would clobber
    // genuine user work on a non-discardable path (the reset below discards
    // the user's in-progress conflict resolution, so it must not run if
    // the abort is going to fail).
    if let Err(e) =
        super::conflict::ensure_abort_safe(layout, store, records, target_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) =
        super::conflict::reset_conflict_paths(layout, store, records, target_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = super::ensure_restore_safe(layout, store, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    if let Err(e) = super::restore_worktree_and_index(layout, store, target_tree) {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    super::restore_head_ref(layout, &target)
}

fn create_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
    parent: Hash,
    message: &[u8],
    picked: Hash,
) -> Result<Hash, u8> {
    let cfg = config::read_or_default(layout)
        .map_err(|e| emit_err(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let mut signer = super::commit::load_commit_signer(layout, &cfg)
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    let signer_public = signer
        .public_key()
        .map_err(|(msg, code)| emit_err(&msg, code))?;
    // A replay keeps the picked commit's authorship + timestamp (the
    // fresh signature/signer mark the replay), matching git.
    let (author, timestamp) = match store.read_object(&picked) {
        Ok(Object::Commit(c)) => (c.author, c.timestamp),
        Ok(_) => return Err(emit_err("picked object is not a commit", exit::DATAERR)),
        Err(e) => {
            return Err(emit_err(
                &format!("read picked commit: {e}"),
                exit::GENERAL_ERROR,
            ));
        }
    };
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
