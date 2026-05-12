//! `mkit checkout <branch>` — switch HEAD to a branch and materialise
//! the branch tip's tree into the working directory.
//!
//! The file-restoration half was previously a Phase 10 follow-up; this
//! wire-up calls `mkit_core::ops::restore::restore_tree_to_worktree`
//! which respects `.mkitignore` and rejects symlinks that would escape
//! the repo root.

use std::io::Write;

use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::restore::{RestoreOptions, restore_tree_to_worktree};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(name) = args.first() else {
        return super::usage_error("usage: mkit checkout <branch>");
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

    // Resolve <name> — try ref first (branch / tag), then fall back to
    // a raw 64-char commit hash.
    let commit_hash: Hash = match refs::read_ref(&mkit_dir, name) {
        Ok(Some(h)) => h,
        Ok(None) => match refs::read_tag(&mkit_dir, name) {
            Ok(Some(h)) => h,
            Ok(None) => match mkit_core::hash::from_hex(name) {
                Ok(h) if store.contains(&h) => h,
                _ => {
                    return emit_err(
                        &format!("no such branch, tag, or commit: {name}"),
                        exit::GENERAL_ERROR,
                    );
                }
            },
            Err(e) => return emit_err(&format!("read tag: {e}"), exit::GENERAL_ERROR),
        },
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve the commit's tree so we can materialise it.
    let tree_hash = match store.read_object(&commit_hash) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(Object::Remix(r)) => r.tree_hash,
        Ok(_) => {
            return emit_err(
                &format!(
                    "{} does not resolve to a commit or remix",
                    format::short_hash(&commit_hash, 8)
                ),
                exit::GENERAL_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR),
    };

    // Materialise the tree. `clean=true` is the default — `checkout`
    // reshapes the worktree to the branch tip. `.mkitignore` is
    // honoured inside the helper so locally-ignored files (editor
    // swapfiles, build artefacts) survive the transition.
    let report =
        match restore_tree_to_worktree(&store, &tree_hash, &cwd, &RestoreOptions::default()) {
            Ok(r) => r,
            Err(e) => return emit_err(&format!("restore: {e}"), exit::CANTCREAT),
        };
    if let Err(e) = super::sync_index_to_tree(&cwd, &store, tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }

    // Update HEAD last. If the input was a ref name we know we saw a
    // branch/tag above; for tags + bare commit hashes we go detached.
    let is_branch = matches!(refs::read_ref(&mkit_dir, name), Ok(Some(_)));
    let head_err = if is_branch {
        refs::write_head_branch(&mkit_dir, name)
    } else {
        refs::write_head_detached(&mkit_dir, &commit_hash)
    };
    if let Err(e) = head_err {
        return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
    }

    let mut stderr = std::io::stderr().lock();
    if is_branch {
        let _ = writeln!(stderr, "switched to branch {name}");
    } else {
        let _ = writeln!(
            stderr,
            "switched to detached {}",
            format::short_hash(&commit_hash, 8)
        );
    }
    let _ = writeln!(
        stderr,
        "  {} file(s), {} dir(s), {} symlink(s) restored ({} ignored)",
        report.files_written,
        report.directories_created,
        report.symlinks_written,
        report.skipped_by_ignore
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
