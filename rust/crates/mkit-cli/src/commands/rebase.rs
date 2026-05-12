//! `mkit rebase <branch> | --continue | --abort` — replay commits onto
//! a different base.
//!
//! The rebase state machine lives in `mkit_core::ops::rebase`. This
//! shim loads / writes that state and drives the replay loop via
//! [`mkit_core::ops::cherry_pick`].
//!
//! Scope: fast-forward-on-conflict stop is implemented; `--continue`
//! resumes by consuming the head of `todo` (after the caller resolved
//! the conflicting tree manually or via a future `mkit merge --continue`
//! helper). `--abort` restores `HEAD` to `orig_head` and removes state.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_core::hash::Hash;
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::ops::cherry_pick::cherry_pick;
use mkit_core::ops::merge::ConflictKind;
use mkit_core::ops::rebase::{
    RebaseState, cleanup_rebase, collect_commits_to_replay, is_rebase_in_progress, read_state,
    write_state,
};
use mkit_core::ops::restore::{self, RestoreOptions};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;

use crate::config;
use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match args.first().map(String::as_str) {
        Some("--abort") => abort(&cwd, &mkit_dir, &store),
        Some("--continue") => resume(&cwd, &mkit_dir, &store),
        Some(branch) => start(&cwd, &mkit_dir, &store, branch),
        None => super::usage_error("usage: mkit rebase <branch> | --continue | --abort"),
    }
}

fn start(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    store: &ObjectStore,
    branch: &str,
) -> u8 {
    if is_rebase_in_progress(mkit_dir) {
        return emit_err(
            "a rebase is already in progress (use --continue or --abort)",
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
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("write rebase state: {e}"), exit::CANTCREAT);
    }
    // Start HEAD at `onto` and drive the replay.
    if let Err(e) = refs::write_head_detached(mkit_dir, &onto) {
        return emit_err(&format!("detach HEAD: {e}"), exit::CANTCREAT);
    }
    let onto_tree = match load_tree_hash(store, onto) {
        Ok(t) => t,
        Err(c) => return c,
    };
    if let Err(e) = restore::restore_tree(store, onto_tree, cwd, &RestoreOptions::default()) {
        return emit_err(&format!("restore worktree: {e}"), exit::GENERAL_ERROR);
    }
    if let Err(e) = super::sync_index_to_tree(cwd, store, onto_tree) {
        return emit_err(&e, exit::CANTCREAT);
    }
    replay(cwd, mkit_dir, store)
}

fn resume(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_rebase_in_progress(mkit_dir) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    replay(cwd, mkit_dir, store)
}

fn abort(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    if !is_rebase_in_progress(mkit_dir) {
        return emit_err("no rebase in progress", exit::GENERAL_ERROR);
    }
    let state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = refs::write_head_branch(mkit_dir, &state.head_name) {
        return emit_err(&format!("restore HEAD: {e}"), exit::CANTCREAT);
    }
    if let Err(e) = refs::write_ref(mkit_dir, &state.head_name, &state.orig_head) {
        return emit_err(&format!("restore ref: {e}"), exit::CANTCREAT);
    }
    if let Ok(tree) = load_tree_hash(store, state.orig_head) {
        let _ = restore::restore_tree(store, tree, cwd, &RestoreOptions::default());
        let _ = super::sync_index_to_tree(cwd, store, tree);
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

fn replay(cwd: &std::path::Path, mkit_dir: &std::path::Path, store: &ObjectStore) -> u8 {
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let cfg = match config::read_or_default(cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let key_path = match config::resolve_key_path(cwd, &cfg.signing_key) {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let kp: KeyPair = match sign::load_key(&key_path) {
        Ok(k) => k,
        Err(e) => return emit_err(&format!("load key: {e}"), exit::NOPERM),
    };

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
            let _ = write_state(mkit_dir, &state);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "rebase paused: conflict while replaying {}",
                format::short_hash(&target, 8)
            );
            for c in &result.conflicts {
                let kind = match c.kind {
                    ConflictKind::ModifyModify => "both modified",
                    ConflictKind::DeleteModify => "delete/modify",
                    ConflictKind::AddAdd => "both added",
                };
                let _ = writeln!(stderr, "  {} ({kind})", c.path);
            }
            let _ = writeln!(
                stderr,
                "resolve conflicts, then run `mkit rebase --continue` or `mkit rebase --abort`"
            );
            return exit::GENERAL_ERROR;
        }
        let new_hash = match build_commit(store, &kp, head_hash, target, result.tree_hash) {
            Ok(h) => h,
            Err(c) => return c,
        };
        if let Err(e) = refs::write_head_detached(mkit_dir, &new_hash) {
            return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
        }
        if let Err(e) =
            restore::restore_tree(store, result.tree_hash, cwd, &RestoreOptions::default())
        {
            return emit_err(&format!("restore worktree: {e}"), exit::GENERAL_ERROR);
        }
        if let Err(e) = super::sync_index_to_tree(cwd, store, result.tree_hash) {
            return emit_err(&e, exit::CANTCREAT);
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
    if let Err(e) = refs::write_ref(mkit_dir, &state.head_name, &final_head) {
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

fn build_commit(
    store: &ObjectStore,
    kp: &KeyPair,
    parent: Hash,
    original: Hash,
    tree_hash: Hash,
) -> Result<Hash, u8> {
    let original_msg = match store.read_object(&original) {
        Ok(Object::Commit(c)) => c.message.clone(),
        Ok(_) => return Err(emit_err("original is not a commit", exit::DATAERR)),
        Err(e) => return Err(emit_err(&format!("read commit: {e}"), exit::GENERAL_ERROR)),
    };
    let author = Identity::ed25519(kp.public.0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        vec![parent],
        author,
        kp.public.0,
        original_msg,
        timestamp,
        [0u8; 64],
    );
    let sig = sign::sign_commit(&unsigned, kp)
        .map_err(|e| emit_err(&format!("sign: {e}"), exit::GENERAL_ERROR))?;
    unsigned.signature = sig.0;
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
