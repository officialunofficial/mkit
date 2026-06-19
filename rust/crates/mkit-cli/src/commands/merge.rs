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
use std::path::Path;
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
    /// Perform the merge but stop before creating the merge commit (like
    /// `git merge --no-commit`): stage the merged tree and record
    /// `MERGE_HEAD`. Finish with `mkit commit` (a two-parent merge commit)
    /// or `mkit merge --continue`. Fast-forward updates create no commit,
    /// so `--no-commit` does not affect them.
    #[arg(long = "no-commit", conflicts_with_all = ["cont", "abort"])]
    no_commit: bool,
    /// Override the merge commit message (default `Merge branch '<name>'`).
    #[arg(short = 'm', long = "message", conflicts_with_all = ["cont", "abort"])]
    message: Option<String>,
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
        start(
            &cwd,
            &mkit_dir,
            &store,
            branch,
            opts.no_commit,
            opts.message.as_deref(),
        )
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
    no_commit: bool,
    message: Option<&str>,
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
    // Accept any revspec — branches, tags, remote-tracking refs
    // (`<remote>/<branch>`), hashes — peeling annotated tags to the
    // commit. Branch names keep their historical precedence because
    // resolve_revision checks refs/heads first.
    let theirs = match super::revspec::resolve_revision(store, mkit_dir, branch) {
        Ok(h) => peel_tags(store, h),
        Err(e) => return emit_err(&format!("merge target: {e}"), exit::GENERAL_ERROR),
    };

    if ours == theirs {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Already up to date.");
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
        // git-shaped fast-forward report: `Updating <old>..<new>` +
        // `Fast-forward` + the diffstat.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "Updating {}..{}",
            format::short_hash(&ours, format::SUMMARY_ABBREV),
            format::short_hash(&theirs, format::SUMMARY_ABBREV),
        );
        let _ = writeln!(stderr, "Fast-forward");
        drop(stderr);
        print_merge_stat(store, ours, theirs);
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

    // git's convention distinguishes the source kind in the message; `-m`
    // overrides it outright.
    let msg = match message {
        Some(m) => m.to_string(),
        None if merge_source_is_remote_tracking(mkit_dir, branch) => {
            let short = branch.strip_prefix("refs/remotes/").unwrap_or(branch);
            format!("Merge remote-tracking branch '{short}'")
        }
        None => format!("Merge branch '{branch}'"),
    };

    if result.has_conflicts() {
        // Guard: never clobber dirty tracked / untracked collisions.
        if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let records = match super::conflict::materialize_conflicts(
            cwd,
            store,
            result.tree_hash,
            &result.conflicts,
        ) {
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
        // Record the merge result tree so `--abort` treats the operation's
        // clean hunks (not just conflict paths) as discardable.
        if let Err(e) = conflict_state::write_result_tree(mkit_dir, &result.tree_hash) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        // git-shaped conflict lines, additive — followed by mkit's own
        // resumable-flow hint.
        for rec in &records {
            let _ = writeln!(stderr, "CONFLICT (content): Merge conflict in {}", rec.path);
        }
        let _ = writeln!(
            stderr,
            "Automatic merge failed; fix conflicts and then commit the result."
        );
        let _ = writeln!(
            stderr,
            "hint: resolve the files above, `mkit add` them, then run \
             `mkit merge --continue` (or `mkit merge --abort`)"
        );
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(cwd, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // `--no-commit`: stage the merged tree and record `MERGE_HEAD` with no
    // conflicts, then stop. The next `mkit commit` records a two-parent
    // merge commit (it consumes `MERGE_HEAD`); `mkit merge --continue`
    // does the same.
    if no_commit {
        if let Err(e) = super::restore_worktree_and_index(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        // A tree can't encode deletions, so staging the result tree drops
        // them. Re-stage Removed tombstones (like cherry-pick/revert -n) so an
        // all-deletions merge leaves a non-empty index: otherwise `commit`'s
        // index reads as empty and `merge --continue`/`merge --abort` (which
        // seed an empty index from HEAD) would build/judge against the OLD
        // tree, dropping the deletions.
        if let Err(e) =
            super::stage_removed_tombstones(cwd, store, Some(ours_tree), result.tree_hash)
        {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let state = MergeState {
            merge_head: theirs,
            orig_head: ours,
            message: msg.into_bytes(),
        };
        if let Err(e) = conflict_state::write_merge_state(mkit_dir, &state, &[]) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        // Record the merge result tree so `--abort` can tell the staged merge
        // (discardable) from genuine user work staged on top of it.
        if let Err(e) = conflict_state::write_result_tree(mkit_dir, &result.tree_hash) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "automatic merge went well; stopped before committing as requested\n\
             commit the result with `mkit commit` (or `mkit merge --continue`)"
        );
        return exit::OK;
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
    // git-shaped true-merge report: `Merge made by the 'ort' strategy.` +
    // the diffstat (ours → merged tree).
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Merge made by the 'ort' strategy.");
    }
    print_merge_stat_trees(store, Some(ours_tree), Some(result.tree_hash));
    exit::OK
}

/// Best-effort `Fast-forward` / merge diffstat between two commits' trees,
/// reusing `diff`'s renderer. Failures are silent (the headline already
/// printed).
fn print_merge_stat(store: &ObjectStore, old: Hash, new: Hash) {
    let old_tree = load_tree_hash(store, old).ok();
    let new_tree = load_tree_hash(store, new).ok();
    print_merge_stat_trees(store, old_tree, new_tree);
}

fn print_merge_stat_trees(store: &ObjectStore, old_tree: Option<Hash>, new_tree: Option<Hash>) {
    if let Ok(result) = mkit_core::ops::diff_trees(store, old_tree, new_tree) {
        let mut stderr = std::io::stderr().lock();
        let _ = super::diff::render_stat(&mut stderr, store, result.entries.iter());
    }
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
    if let Err(e) = super::conflict::ensure_conflict_paths_staged(cwd, store, &records) {
        return emit_err(&e, exit::GENERAL_ERROR);
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
    // Sync the index to the committed tree WITHOUT rewriting the worktree.
    // The tree was built from the index, so the worktree already holds the
    // resolved content; restoring it would clobber any unstaged edits the
    // user made after staging — `git commit` (and `mkit commit`) leave the
    // worktree untouched here.
    if let Err(e) = super::sync_index_to_tree(cwd, store, tree_hash) {
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
    // The operation's result tree — written for BOTH conflict merges and a
    // clean `merge --no-commit` — lets the guards treat the merge's own,
    // user-untouched output as discardable while protecting genuine work the
    // user staged or edited on top of it (a conflict resolution, an unrelated
    // `mkit add`, or an edit to a cleanly-merged file).
    let op_result = conflict_state::read_result_tree(mkit_dir).ok().flatten();
    // Pre-flight: refuse *before* any mutation when restoring would clobber
    // genuine user work on a non-discardable path (the reset below discards
    // the operation material).
    if let Err(e) = super::conflict::ensure_abort_safe(cwd, store, records, target_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    // Discard the operation material on the discardable paths so the guarded
    // restore doesn't see it as user "local changes" (it still protects
    // unrelated dirty/untracked work).
    if let Err(e) =
        super::conflict::reset_conflict_paths(cwd, store, records, target_tree, op_result)
    {
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

/// Bounded annotated-tag peel (mirrors `log.rs`/`diff.rs`).
const MAX_TAG_DEPTH: usize = 16;

/// Whether `spec` names a remote-tracking ref under revspec
/// precedence (local branches and tags win over `<remote>/<branch>`).
fn merge_source_is_remote_tracking(mkit_dir: &Path, spec: &str) -> bool {
    let rel = spec.strip_prefix("refs/remotes/").map_or(spec, |r| r);
    let Some((remote, branch)) = rel.split_once('/') else {
        return false;
    };
    if refs::read_ref(mkit_dir, spec).is_ok_and(|r| r.is_some())
        || refs::read_tag(mkit_dir, spec).is_ok_and(|r| r.is_some())
    {
        return false; // a local ref of the same spelling shadows it
    }
    refs::read_remote_ref(mkit_dir, remote, branch).is_ok_and(|r| r.is_some())
}

fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
    for _ in 0..MAX_TAG_DEPTH {
        match store.read_object(&h) {
            Ok(Object::Tag(t)) => h = t.target,
            _ => break,
        }
    }
    h
}
