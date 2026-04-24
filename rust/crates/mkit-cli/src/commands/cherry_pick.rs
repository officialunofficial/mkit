//! `mkit cherry-pick <commit>` — replay a single commit onto HEAD.
//!
//! On a clean merge we create a new commit on the current branch using
//! the original commit's message; on conflict we report per-path and
//! exit non-zero, matching the Zig reference.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_core::hash::{self, Hash};
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::ops::cherry_pick::cherry_pick;
use mkit_core::ops::merge::ConflictKind;
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
    let Some(hex) = args.first() else {
        return super::usage_error("usage: mkit cherry-pick <commit>");
    };
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

    let cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let key_path = cwd.join(&cfg.signing_key);
    let kp: KeyPair = match sign::load_key(&key_path) {
        Ok(k) => k,
        Err(e) => return emit_err(&format!("load key: {e}"), exit::NOPERM),
    };
    let author = Identity::ed25519(kp.public.0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut unsigned = Commit::new_unannotated(
        result.tree_hash,
        vec![ours],
        author,
        kp.public.0,
        result.original_message.clone(),
        timestamp,
        [0u8; 64],
    );
    let sig = match sign::sign_commit(&unsigned, &kp) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("sign: {e}"), exit::GENERAL_ERROR),
    };
    unsigned.signature = sig.0;
    let bytes = match serialize::serialize(&Object::Commit(unsigned)) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("serialize: {e}"), exit::DATAERR),
    };
    let commit_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store commit: {e}"), exit::CANTCREAT),
    };
    let head = refs::read_head(&mkit_dir).unwrap_or(Head::Branch("main".to_string()));
    let write_result = match head {
        Head::Branch(name) => refs::write_ref(&mkit_dir, &name, &commit_hash),
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
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
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
