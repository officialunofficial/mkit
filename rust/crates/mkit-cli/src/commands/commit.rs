//! `mkit commit` — build a signed commit object from the worktree.
//!
//! Implementation scope: minimal viable port. We:
//!   1. Require `-m <msg>` for now (Rust port defers `$EDITOR` until
//!      Phase 10 — the Zig helper is a few dozen lines but relies on
//!      `std.process.spawn` semantics the Rust SDK deferred).
//!   2. Build a tree from the working directory (not the index yet —
//!      Phase 10 follow-up; see PR body).
//!   3. Load or generate the signing key, derive the author Identity
//!      from the public key unless `user.identity` is set in config.
//!   4. Write the Commit object and update `refs/heads/<current>` +
//!      `HEAD`.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_core::object::{Commit, Identity, Object};
use mkit_core::refs::{self, Head};
use mkit_core::serialize;
use mkit_core::sign::{self, KeyPair};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let mut message: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-m" && i + 1 < args.len() {
            message = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    let Some(msg) = message else {
        return super::usage_error(
            "mkit commit: -m <msg> required (EDITOR flow deferred to Phase 10)",
        );
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

    let cfg = match crate::config::read_or_default(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let key_path = cwd.join(&cfg.signing_key);
    let kp: KeyPair = if key_path.exists() {
        match sign::load_key(&key_path) {
            Ok(k) => k,
            Err(e) => return emit_err(&format!("load key: {e}"), exit::NOPERM),
        }
    } else {
        // Auto-generate on first commit. Matches the Zig behaviour for
        // `mkit commit` when `.mkit/keys/default.key` is missing.
        let kp = match KeyPair::generate() {
            Ok(kp) => kp,
            Err(e) => return emit_err(&format!("rng: {e}"), exit::GENERAL_ERROR),
        };
        if let Err(e) = sign::save_key(&key_path, &kp) {
            return emit_err(&format!("save key: {e}"), exit::CANTCREAT);
        }
        kp
    };

    let tree_hash = match worktree::build_tree(&store, &cwd) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
    };
    let parents = match refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => vec![h],
        _ => vec![],
    };
    let author = Identity::ed25519(kp.public.0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Sign then build with signature.
    let mut unsigned = Commit::new_unannotated(
        tree_hash,
        parents,
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
        Err(e) => return emit_err(&format!("serialize commit: {e}"), exit::DATAERR),
    };
    let commit_hash = match store.write(&bytes) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("store commit: {e}"), exit::CANTCREAT),
    };
    // Advance the current branch.
    let head = refs::read_head(&mkit_dir).unwrap_or(Head::Branch("main".to_string()));
    match head {
        Head::Branch(name) => {
            if let Err(e) = refs::write_ref(&mkit_dir, &name, &commit_hash) {
                return emit_err(&format!("write ref: {e}"), exit::CANTCREAT);
            }
        }
        Head::Detached(_) => {
            if let Err(e) = refs::write_head_detached(&mkit_dir, &commit_hash) {
                return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
            }
        }
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
        "committed {} ({})",
        format::short_hash(&commit_hash, 8),
        msg.lines().next().unwrap_or("")
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
