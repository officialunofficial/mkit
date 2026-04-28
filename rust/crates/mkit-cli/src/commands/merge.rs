//! `mkit merge <branch>` — merge a branch into HEAD.
//!
//! Behaviour:
//!
//! 1. Resolve HEAD (ours) and the target ref (theirs).
//! 2. If equal → "already up to date".
//! 3. Find the merge base; if `base == ours`, fast-forward HEAD to
//!    theirs and restore the worktree to theirs' tree.
//! 4. Otherwise run a 3-way tree merge. If it reports conflicts, emit
//!    a per-path summary on stderr and exit non-zero WITHOUT creating
//!    a merge commit. The merged tree is still written to the object
//!    store, so a higher-level resolver could pick it up.
//! 5. Clean merge: sign a new merge commit with two parents and
//!    advance the current branch.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_core::hash::Hash;
use mkit_core::object::{Commit, Identity, Object};
use mkit_core::ops::merge::{ConflictKind, find_merge_base, merge_trees};
use mkit_core::ops::restore::{self, RestoreOptions};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;

use crate::config;
use crate::exit;
use crate::format;

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(args: &[String]) -> u8 {
    let Some(branch) = args.first() else {
        return super::usage_error("usage: mkit merge <branch>");
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
    let theirs = match refs::read_ref(&mkit_dir, branch) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err(&format!("branch '{branch}' not found"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    };

    if ours == theirs {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "already up to date");
        return exit::OK;
    }

    let base = match find_merge_base(&store, ours, theirs) {
        Ok(b) => b,
        Err(e) => return emit_err(&format!("find merge base: {e}"), exit::GENERAL_ERROR),
    };

    // Fast-forward when base == ours.
    if let Some(bh) = base
        && bh == ours
    {
        let theirs_tree = match load_tree_hash(&store, theirs) {
            Ok(t) => t,
            Err(code) => return code,
        };
        if let Err(e) = restore::restore_tree(&store, theirs_tree, &cwd, &RestoreOptions::default())
        {
            return emit_err(&format!("restore worktree: {e}"), exit::GENERAL_ERROR);
        }
        if let Err(e) = advance_head(&mkit_dir, &theirs) {
            return emit_err(&e, exit::CANTCREAT);
        }
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "fast-forward {}", format::short_hash(&theirs, 8));
        return exit::OK;
    }

    let ours_tree = match load_tree_hash(&store, ours) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let theirs_tree = match load_tree_hash(&store, theirs) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let base_tree: Option<Hash> = match base {
        Some(b) => match load_tree_hash(&store, b) {
            Ok(t) => Some(t),
            Err(code) => return code,
        },
        None => None,
    };

    let result = match merge_trees(&store, base_tree, Some(ours_tree), Some(theirs_tree)) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("merge: {e}"), exit::GENERAL_ERROR),
    };

    if result.has_conflicts() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "merge conflict:");
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

    // Clean merge — build a merge commit with two parents.
    let cfg = match config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let key_path = match config::resolve_key_path(&cwd, &cfg.signing_key) {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let kp: KeyPair = match sign::load_key(&key_path) {
        Ok(k) => k,
        Err(e) => return emit_err(&format!("load key: {e}"), exit::NOPERM),
    };
    let author = Identity::ed25519(kp.public.0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let msg = format!("Merge branch '{branch}'");
    let mut unsigned = Commit::new_unannotated(
        result.tree_hash,
        vec![ours, theirs],
        author,
        kp.public.0,
        msg.as_bytes().to_vec(),
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
    if let Err(e) = advance_head(&mkit_dir, &commit_hash) {
        return emit_err(&e, exit::CANTCREAT);
    }
    // Restore the worktree to the merged tree so it reflects the new HEAD.
    if let Err(e) =
        restore::restore_tree(&store, result.tree_hash, &cwd, &RestoreOptions::default())
    {
        return emit_err(&format!("restore worktree: {e}"), exit::GENERAL_ERROR);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "merge {} into HEAD ({})",
        format::short_hash(&theirs, 8),
        format::short_hash(&commit_hash, 8)
    );
    exit::OK
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
        Head::Branch(name) => {
            refs::write_ref(mkit_dir, &name, new_head).map_err(|e| format!("write ref: {e}"))
        }
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
