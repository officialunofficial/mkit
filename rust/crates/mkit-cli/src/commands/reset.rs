//! `mkit reset [--soft|--mixed] [<commit>]` — move the current branch
//! (or detached HEAD) to `<commit>`, optionally resetting the index.
//!
//! Two modes, mirroring `git reset`'s safe subset:
//!
//! - **`--soft`** — move HEAD / the current branch only. The index and
//!   the worktree are left exactly as they are, so the difference between
//!   the old tip and the new target shows up as staged changes.
//! - **`--mixed`** (the default) — move HEAD *and* rewrite `.mkit/index`
//!   to mirror the target commit's tree. The worktree is untouched, so
//!   changes relative to the target appear as un-staged worktree edits.
//!
//! `<commit>` defaults to `HEAD` (a no-op move that still re-syncs the
//! index under `--mixed`) and is resolved through the shared revspec
//! resolver, so a branch, tag, `HEAD`, full/short hash, or `HEAD~n`/`^`
//! navigation all work.
//!
//! `--hard` (reset HEAD + index + worktree, discarding worktree changes)
//! is intentionally NOT implemented here: it is the one destructive
//! variant, and `mkit checkout <commit>` already provides a guarded
//! worktree-resetting path (it runs the #176 dirty/untracked guards).
//! `--hard` can be added later behind those same guards.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::refs::{self, Head, RefWriteCondition};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit reset",
    about = "Move HEAD (and, by default, the index) to a commit."
)]
struct ResetOpts {
    /// Move HEAD only; leave the index and worktree untouched.
    #[arg(long, conflicts_with = "mixed")]
    soft: bool,

    /// Move HEAD and reset the index to the target tree; leave the
    /// worktree untouched. This is the default.
    #[arg(long)]
    mixed: bool,

    /// Commit to reset to (branch, tag, HEAD, full/short hash, `HEAD~n`,
    /// `^`). Defaults to `HEAD`.
    target: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ResetOpts>("mkit reset", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    // --soft = HEAD only; --mixed (or no flag) also resets the index.
    let reset_index = !opts.soft;

    let spec = opts.target.as_deref().unwrap_or("HEAD");
    let target = match super::revspec::resolve_revision(&store, &mkit_dir, spec) {
        Ok(h) => h,
        Err(e) => {
            return emit_err(
                &format!("no such commit: {spec} ({e})"),
                exit::GENERAL_ERROR,
            );
        }
    };

    // The target must be a commit/remix; we need its tree for --mixed and
    // we refuse to point HEAD at a bare tree/blob.
    let tree_hash = match store.read_object(&target) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return emit_err(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&target, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read target commit: {e}"), exit::GENERAL_ERROR),
    };

    // If reset moves the branch off its current tip, that old tip may
    // become unreachable — record it BEFORE the move (under the worktree
    // lock) so it stays recoverable, and abort if the log can't be
    // written. Fail closed: an unreadable/corrupt current ref
    // (`resolve_head` Err) aborts rather than letting `move_head` clobber
    // it unlogged. `Ok(None)` is an unborn branch (nothing to supersede);
    // a no-op move (old == target) records nothing.
    match refs::resolve_head(&mkit_dir) {
        Ok(Some(old_head)) if old_head != target => {
            let branch = super::head_branch_name(&mkit_dir);
            if let Err((msg, code)) =
                super::record_superseded(&mkit_dir, "reset", &branch, old_head)
            {
                return emit_err(&msg, code);
            }
        }
        Ok(_) => {}
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
    }

    // Move HEAD / the current branch FIRST. As in `checkout`, advancing
    // the ref before the index keeps the failure modes benign: a later
    // index-write failure leaves HEAD on the target with a stale index,
    // which `mkit status` surfaces and a re-run repairs.
    if let Err((msg, code)) = move_head(&mkit_dir, &target) {
        return emit_err(&msg, code);
    }

    if reset_index && let Err(e) = super::sync_index_to_tree(&cwd, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }

    let mut stderr = std::io::stderr().lock();
    let mode = if reset_index { "mixed" } else { "soft" };
    let _ = writeln!(
        stderr,
        "reset ({mode}) to {}",
        format::short_hash(&target, 8)
    );
    exit::OK
}

/// Point the current branch (or detached HEAD) at `target`. Routes branch
/// moves through the history-recording ref helper so a `history-mmr`
/// build journals the move; detached HEAD is rewritten directly.
fn move_head(mkit_dir: &std::path::Path, target: &Hash) -> Result<(), (String, u8)> {
    let head = refs::read_head(mkit_dir).map_err(|e| (format!("read HEAD: {e}"), exit::DATAERR))?;
    match head {
        Head::Branch(name) => {
            super::write_ref_recording_history(mkit_dir, &name, RefWriteCondition::Any, target)
                .map_err(|e| (format!("write ref: {e}"), exit::CANTCREAT))
        }
        Head::Detached(_) => refs::write_head_detached(mkit_dir, target)
            .map_err(|e| (format!("update HEAD: {e}"), exit::CANTCREAT)),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
