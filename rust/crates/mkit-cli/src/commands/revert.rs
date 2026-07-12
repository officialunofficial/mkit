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

use clap::{Parser, ValueEnum};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::conflict_state::{
    self, RevertState, in_progress_op_name, is_revert_in_progress,
};
use mkit_core::ops::revert::revert as revert_tree;
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
enum RevertFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit revert",
    about = "Create a new commit that undoes a previous commit."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
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
    /// Accepted for git compatibility; mkit auto-generates the revert
    /// message, so `--no-edit` is the default behavior (no-op).
    #[arg(long = "no-edit")]
    no_edit: bool,
    /// Emit a machine-readable JSON result object to stdout describing
    /// the outcome: a new commit, `--no-commit` staging, a conflict
    /// pause (`"conflicts":[<path>,...]`), or an error.
    #[arg(long, value_enum, default_value = "default")]
    format: RevertFormat,
    /// Commit to revert: a ref, full/short hash, or `HEAD~n` revspec.
    commit: Option<String>,
}

/// `error(msg, code)` plus, when `json` is set, a `{"ok":false,...}`
/// line on stdout.
fn emit_err_json(msg: &str, code: u8, json: bool) -> u8 {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", msg);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    emit_err(msg, code)
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RevertOpts>("mkit revert", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let _ = opts.no_edit; // accepted no-op (mkit auto-generates the message)
    let json = matches!(opts.format, RevertFormat::Json);
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
    } else if let Some(hex) = opts.commit.as_deref() {
        start(&layout, &store, hex, opts.no_commit, json)
    } else {
        super::usage_error("usage: mkit revert <commit> | --continue | --abort")
    }
}

#[allow(clippy::too_many_lines)] // linear flow: apply + commit + report
fn start(layout: &RepoLayout, store: &ObjectStore, hex: &str, no_commit: bool, json: bool) -> u8 {
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);
    if let Some(op) = in_progress_op_name(layout) {
        return emit_err(
            &format!("a {op} is already in progress (use --continue or --abort)"),
            exit::GENERAL_ERROR,
        );
    }
    let target: Hash = match super::revspec::resolve_revision(store, layout, hex) {
        // Peel annotated/signed tags to their target commit so
        // `mkit revert <annotated-tag>` works like git (a tag is a ref,
        // which the doc comment advertises as acceptable). Mirrors
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

    let result = match revert_tree(store, target, ours_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("revert: {e}"), exit::GENERAL_ERROR),
    };

    if result.has_conflicts() {
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
        let state = RevertState {
            revert_head: target,
            orig_head: ours,
            message: result.message.clone(),
        };
        if let Err(e) = conflict_state::write_revert_state(layout, &state, &records) {
            return emit_err(&format!("write revert state: {e}"), exit::CANTCREAT);
        }
        // Record the result tree so `--abort` treats the operation's clean
        // hunks (not just conflict paths) as discardable.
        if let Err(e) =
            conflict_state::write_result_tree(layout.worktree_state_dir(), &result.tree_hash)
        {
            return emit_err(&format!("write revert state: {e}"), exit::CANTCREAT);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "revert conflict; resolve the files above, `mkit add` them, then run \
             `mkit revert --continue` (or `mkit revert --abort`)"
        );
        drop(stderr);
        if json {
            let paths: Vec<&str> = records.iter().map(|r| r.path.as_str()).collect();
            let mut obj = JsonObject::new();
            obj.field_bool("ok", false)
                .field_str("kind", "conflict")
                .field_raw("conflicts", &json_string_array(&paths))
                .field_str("error", "revert conflict; resolve and continue or abort");
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(layout, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    // --no-commit: apply the reverted tree to the index + worktree but do
    // not create a commit or move HEAD. The user commits when ready.
    if no_commit {
        if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        // Restoring from a tree drops staged DELETIONS; re-stage them as
        // tombstones so a revert that removes files stays staged and
        // `mkit commit` records it.
        if let Err(e) =
            super::stage_removed_tombstones(layout, store, Some(ours_tree), result.tree_hash)
        {
            return emit_err(&e, exit::GENERAL_ERROR);
        }
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "staged revert of {} (no commit; run `mkit commit` when ready)",
            format::short_hash(&target, 8),
        );
        drop(stderr);
        if json {
            let mut obj = JsonObject::new();
            obj.field_bool("ok", true)
                .field_str("kind", "no-commit")
                .field_hash("reverted", &target)
                .field_hash("tree", &result.tree_hash);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", obj.finish());
        }
        return exit::OK;
    }

    let commit_hash = match create_commit(layout, store, result.tree_hash, ours, &result.message) {
        Ok(h) => h,
        Err(code) => return code,
    };
    if let Err(e) = super::restore_worktree_and_index(layout, store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(layout, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    // git-shaped summary: `[<branch> <hash>] Revert "<subject>"` + diffstat.
    let subject = String::from_utf8_lossy(&result.message)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned();
    let branch_name = match mkit_core::refs::read_head(layout) {
        Ok(mkit_core::refs::Head::Branch(b)) => Some(b),
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
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "commit")
            .field_hash("hash", &commit_hash)
            .field_hash("reverted", &target)
            .field_hash("tree", &result.tree_hash);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

fn cont(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);
    let state = match conflict_state::read_revert_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no revert in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read revert state: {e}"), exit::GENERAL_ERROR),
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
    let commit_hash = match create_commit(layout, store, tree_hash, parent, &state.message) {
        Ok(h) => h,
        Err(code) => return code,
    };
    // Sync the index to the committed tree WITHOUT rewriting the worktree:
    // the tree was built from the index, so the worktree already holds the
    // resolved content; restoring it would clobber unstaged edits made on a
    // cleanly-applied path before `--continue`.
    if let Err(e) = super::sync_index_to_tree(layout, store, tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err(e) = advance_head(layout, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    if let Err(e) = conflict_state::clear_revert_state(layout) {
        return emit_err(&format!("clear revert state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "reverted {} as {}",
        format::short_hash(&state.revert_head, 8),
        format::short_hash(&commit_hash, 8),
    );
    drop(stderr);
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", true)
            .field_str("kind", "commit")
            .field_hash("hash", &commit_hash)
            .field_hash("reverted", &state.revert_head)
            .field_hash("tree", &tree_hash);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    exit::OK
}

fn abort(layout: &RepoLayout, store: &ObjectStore, json: bool) -> u8 {
    let emit_err = |msg: &str, code: u8| emit_err_json(msg, code, json);
    if !is_revert_in_progress(layout) {
        return emit_err("no revert in progress", exit::GENERAL_ERROR);
    }
    let state = match conflict_state::read_revert_state(layout) {
        Ok(Some(s)) => s,
        Ok(None) => return emit_err("no revert in progress", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read revert state: {e}"), exit::GENERAL_ERROR),
    };
    let records = match conflict_state::read_conflicts(layout.worktree_state_dir()) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("read conflicts: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(code) = restore_to(layout, store, state.orig_head, &records) {
        return code;
    }
    if let Err(e) = conflict_state::clear_revert_state(layout) {
        return emit_err(&format!("clear revert state: {e}"), exit::GENERAL_ERROR);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "revert aborted; HEAD restored");
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
