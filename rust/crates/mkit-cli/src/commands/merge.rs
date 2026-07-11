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

use clap::{Parser, ValueEnum};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::conflict_state::{self, MergeState, in_progress_op_name, is_merge_in_progress};
use mkit_core::ops::merge::{find_merge_base, merge_trees};
use mkit_core::refs;
use mkit_core::serialize;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use super::{advance_head, error as emit_err, load_tree_hash};
use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format::{self, JsonObject, json_string_array};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MergeFormat {
    Default,
    Json,
}

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
    /// Emit a machine-readable JSON result object to stdout describing
    /// the outcome: a clean merge/fast-forward, `--no-commit` staging, a
    /// conflict pause (`"conflicts":[<path>,...]`), or an error.
    #[arg(long, value_enum, default_value = "default")]
    format: MergeFormat,
    /// Branch to merge into HEAD.
    branch: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<MergeOpts>("mkit merge", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, MergeFormat::Json);
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };

    if opts.abort {
        abort(&layout, &store, json)
    } else if opts.cont {
        cont(&layout, &store, json)
    } else if let Some(branch) = opts.branch.as_deref() {
        start(
            &layout,
            &store,
            branch,
            opts.no_commit,
            opts.message.as_deref(),
            json,
        )
    } else {
        super::usage_error("usage: mkit merge <branch> | --continue | --abort")
    }
}

/// `error(msg, code)` plus, when `json` is set, a `{"ok":false,...}`
/// line on stdout — so every exit path leaves `--format=json` callers
/// with a self-contained payload, not just the documented conflict
/// shape.
fn emit_err_json(msg: &str, code: u8, json: bool) -> u8 {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", msg);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    emit_err(msg, code)
}

#[allow(clippy::too_many_lines)]
fn start(
    layout: &RepoLayout,
    store: &ObjectStore,
    branch: &str,
    no_commit: bool,
    message: Option<&str>,
    json: bool,
) -> u8 {
    // Shadow the module-level `emit_err` for the rest of this function:
    // every early-return error now also prints a `{"ok":false,...}` line
    // to stdout when `--format=json` is set, without touching each call
    // site below individually.
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);

    if let Some(op) = in_progress_op_name(layout) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }

    let ours = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    // Accept any revspec — branches, tags, remote-tracking refs
    // (`<remote>/<branch>`), hashes — peeling annotated tags to the
    // commit. Branch names keep their historical precedence because
    // resolve_revision checks refs/heads first.
    let theirs = match super::revspec::resolve_revision(store, layout, branch) {
        Ok(h) => super::log::peel_tags(store, h),
        Err(e) => return emit_err(&format!("merge target: {e}"), exit::GENERAL_ERROR),
    };

    if ours == theirs {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Already up to date.");
        drop(stderr);
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_str("kind", "up-to-date")
                .field_hash("hash", &ours);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
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
        if let Err(e) = super::ensure_restore_safe(layout, store, theirs_tree) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = super::restore_worktree_and_index(layout, store, theirs_tree) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        if let Err(e) = advance_head(layout, &theirs) {
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
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_str("kind", "fast-forward")
                .field_hash("old", &ours)
                .field_hash("new", &theirs);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
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
        None if merge_source_is_remote_tracking(layout, branch) => {
            let short = branch.strip_prefix("refs/remotes/").unwrap_or(branch);
            format!("Merge remote-tracking branch '{short}'")
        }
        None => format!("Merge branch '{branch}'"),
    };

    if result.has_conflicts() {
        // Guard: never clobber dirty tracked / untracked collisions.
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
        let state = MergeState {
            merge_head: theirs,
            orig_head: ours,
            message: msg.into_bytes(),
        };
        if let Err(e) = conflict_state::write_merge_state(layout, &state, &records) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        // Record the merge result tree so `--abort` treats the operation's
        // clean hunks (not just conflict paths) as discardable.
        if let Err(e) =
            conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
        {
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
        drop(stderr);
        if json {
            let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
            let mut obj = JsonObject::new();
            obj.field_bool("ok", false)
                .field_str("kind", "conflict")
                .field_raw("conflicts", &json_string_array(&paths))
                .field_str(
                    "error",
                    "automatic merge failed; fix conflicts and then commit the result",
                );
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(layout, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // `--no-commit`: stage the merged tree and record `MERGE_HEAD` with no
    // conflicts, then stop. The next `mkit commit` records a two-parent
    // merge commit (it consumes `MERGE_HEAD`); `mkit merge --continue`
    // does the same.
    if no_commit {
        if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        // A tree can't encode deletions, so staging the result tree drops
        // them. Re-stage Removed tombstones (like cherry-pick/revert -n) so an
        // all-deletions merge leaves a non-empty index: otherwise `commit`'s
        // index reads as empty and `merge --continue`/`merge --abort` (which
        // seed an empty index from HEAD) would build/judge against the OLD
        // tree, dropping the deletions.
        if let Err(e) =
            super::stage_removed_tombstones(layout, store, Some(ours_tree), result.tree_hash)
        {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let state = MergeState {
            merge_head: theirs,
            orig_head: ours,
            message: msg.into_bytes(),
        };
        if let Err(e) = conflict_state::write_merge_state(layout, &state, &[]) {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        // Record the merge result tree so `--abort` can tell the staged merge
        // (discardable) from genuine user work staged on top of it.
        if let Err(e) =
            conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
        {
            return emit_err(&format!("write merge state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "automatic merge went well; stopped before committing as requested\n\
             commit the result with `mkit commit` (or `mkit merge --continue`)"
        );
        drop(stderr);
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_str("kind", "no-commit")
                .field_hash("tree", &result.tree_hash);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
        return exit::OK;
    }

    // Clean merge — build a merge commit with two parents.
    let commit_hash = match create_merge_commit(
        layout,
        store,
        result.tree_hash,
        ours,
        theirs,
        msg.as_bytes(),
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
    // git-shaped true-merge report: `Merge made by the 'ort' strategy.` +
    // the diffstat (ours → merged tree).
    {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Merge made by the 'ort' strategy.");
    }
    print_merge_stat_trees(store, Some(ours_tree), Some(result.tree_hash));
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "merge-commit")
            .field_hash("hash", &commit_hash)
            .field_raw(
                "parents",
                &json_string_array(&[format::hex_hash(&ours), format::hex_hash(&theirs)]),
            )
            .field_hash("tree", &result.tree_hash);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
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
        // `render_stat` hoists its own `DisplaySource` wrapping (#625).
        let _ = super::diff::render_stat(&mut stderr, store, result.entries.iter());
    }
}

fn cont(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);
    if !is_merge_in_progress(layout) {
        return emit_err("no merge in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_merge_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no merge in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
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

    // Build the final tree from the resolved index — NOT the
    // conflict-time ours-wins tree.
    let idx = match super::read_or_seed_index_from_head(layout, store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let tree_hash = match worktree::build_tree_from_index(store, &idx) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("build tree from index: {e}"), exit::GENERAL_ERROR),
    };

    let commit_hash = match create_merge_commit(
        layout,
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
    if let Err(e) = super::sync_index_to_tree(layout, store, tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(layout, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    if let Err(e) = conflict_state::clear_merge_state(layout) {
        return emit_err(&format!("clear merge state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "merge {} into HEAD ({})",
        format::short_hash(&state.merge_head, 8),
        format::short_hash(&commit_hash, 8)
    );
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "merge-commit")
            .field_hash("hash", &commit_hash)
            .field_raw(
                "parents",
                &json_string_array(&[
                    format::hex_hash(&state.orig_head),
                    format::hex_hash(&state.merge_head),
                ]),
            )
            .field_hash("tree", &tree_hash);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

fn abort(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);
    if !is_merge_in_progress(layout) {
        return emit_err("no merge in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_merge_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no merge in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read merge state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(layout.worktree_state_dir()) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = restore_to(layout, store, state.orig_head, &records) {
        return code;
    }
    if let Err(e) = conflict_state::clear_merge_state(layout) {
        return emit_err(&format!("clear merge state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "merge aborted; HEAD restored");
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "aborted")
            .field_hash("hash", &state.orig_head);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

/// Restore worktree + index + HEAD/ref to `target` (the pre-op HEAD).
/// Routes the branch advance through the history-MMR helper.
fn restore_to(
    layout: &RepoLayout,
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
    let op_result = conflict_state::read_result_tree(layout.worktree_state_dir())
        .ok()
        .flatten();
    // Pre-flight: refuse *before* any mutation when restoring would clobber
    // genuine user work on a non-discardable path (the reset below discards
    // the operation material).
    if let Err(e) =
        super::conflict::ensure_abort_safe(layout, store, records, target_tree, op_result)
    {
        return Err(emit_err(&e, exit::GENERAL_ERROR));
    }
    // Discard the operation material on the discardable paths so the guarded
    // restore doesn't see it as user "local changes" (it still protects
    // unrelated dirty/untracked work).
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

fn create_merge_commit(
    layout: &RepoLayout,
    store: &ObjectStore,
    tree_hash: Hash,
    parent_ours: Hash,
    parent_theirs: Hash,
    message: &[u8],
) -> Result<Hash, u8> {
    let cfg = config::read_or_default(layout)
        .map_err(|e| emit_err(&format!("config: {e}"), exit::CONFIG_ERROR))?;
    let mut signer = super::commit::load_commit_signer(layout, &cfg)
        .map_err(|(msg, code)| emit_err(&msg, code))?;
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

/// Whether `spec` names a remote-tracking ref under revspec
/// precedence (local branches and tags win over `<remote>/<branch>`).
fn merge_source_is_remote_tracking(layout: &RepoLayout, spec: &str) -> bool {
    let rel = spec.strip_prefix("refs/remotes/").map_or(spec, |r| r);
    let Some((remote, branch)) = rel.split_once('/') else {
        return false;
    };
    if refs::read_ref(layout, spec).is_ok_and(|r| r.is_some())
        || refs::read_tag(layout, spec).is_ok_and(|r| r.is_some())
    {
        return false; // a local ref of the same spelling shadows it
    }
    refs::read_remote_ref(layout, remote, branch).is_ok_and(|r| r.is_some())
}
