//! `mkit cherry-pick <commit>` — replay a single commit onto HEAD.
//!
//! On a clean merge we create a new commit on the current branch using
//! the original commit's message; on conflict we report per-path and
//! exit non-zero.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::hash::{self, Hash};
use mkit_core::object::{Commit, Object};
use mkit_core::ops::cherry_pick::cherry_pick;
use mkit_core::ops::merge::ConflictKind;
use mkit_core::ops::restore::{self, RestoreOptions};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit cherry-pick", about = "Apply a single commit onto HEAD.")]
struct CherryPickOpts {
    /// 64-char hex commit hash to replay.
    commit: String,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CherryPickOpts>("mkit cherry-pick", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let hex = &opts.commit;
    let target: Hash = match hash::from_hex(hex) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad commit hash: {e}"), exit::DATAERR),
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

    let ours = match refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits on current branch", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let ours_tree = match store.read_object(&ours) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(_) => return emit_err("HEAD is not a commit", exit::DATAERR),
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };

    let result = match cherry_pick(&store, target, ours_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("cherry-pick: {e}"), exit::GENERAL_ERROR),
    };

    if result.has_conflicts() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "cherry-pick conflict:");
        for c in &result.conflicts {
            let kind = match c.kind {
                ConflictKind::ModifyModify => "both modified",
                ConflictKind::DeleteModify => "delete/modify",
                ConflictKind::AddAdd => "both added",
            };
            let _ = writeln!(stderr, "  {} ({kind})", c.path);
        }
        return exit::GENERAL_ERROR;
    }

    if let Err(e) = super::ensure_restore_safe(&cwd, &store, result.tree_hash) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }

    let cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let mut signer = match super::commit::load_commit_signer(&cwd, &cfg) {
        Ok(signer) => signer,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let signer_public = match signer.public_key() {
        Ok(public) => public,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    let author = match super::commit::resolve_author(None, &cfg.user_identity, &signer_public) {
        Ok(id) => id,
        Err(e) => return emit_err(&format!("author: {e}"), exit::CONFIG_ERROR),
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        result.tree_hash,
        vec![ours],
        author,
        signer_public,
        result.original_message.clone(),
        timestamp,
        [0u8; 64],
    );
    let sig = match signer.sign_commit(&unsigned) {
        Ok(signature) => signature,
        Err((msg, code)) => return emit_err(&msg, code),
    };
    unsigned.signature = sig;
    let bytes = match serialize::serialize(&Object::Commit(unsigned)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize: {e}"), exit::DATAERR),
    };
    let commit_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store commit: {e}"), exit::CANTCREAT),
    };
    let head = refs::read_head(&mkit_dir).unwrap_or(Head::Branch("main".to_string()));
    // Route the branch-tip advance through the history-MMR-coupled
    // helper so cherry-picked commits land as the next leaf in the
    // current branch's journal (no-op on default builds).
    let write_result = match head {
        Head::Branch(name) => super::write_ref_recording_history(
            &mkit_dir,
            &name,
            refs::RefWriteCondition::Any,
            &commit_hash,
        ),
        Head::Detached(_) => refs::write_head_detached(&mkit_dir, &commit_hash),
    };
    if let Err(e) = write_result {
        return emit_err(&format!("write ref: {e}"), exit::CANTCREAT);
    }
    if let Err(e) =
        restore::restore_tree(&store, result.tree_hash, &cwd, &RestoreOptions::default())
    {
        return emit_err(&format!("restore worktree: {e}"), exit::GENERAL_ERROR);
    }
    if let Err(e) = super::sync_index_to_tree(&cwd, &store, result.tree_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "cherry-picked {} onto {} as {}",
        format::short_hash(&target, 8),
        format::short_hash(&ours, 8),
        format::short_hash(&commit_hash, 8),
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
