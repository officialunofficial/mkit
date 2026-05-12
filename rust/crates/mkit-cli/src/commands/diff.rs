//! `mkit diff` — summarize path-level differences between two trees.
//!
//! With two hash arguments, diffs those tree hashes. With no args,
//! diffs the HEAD tree against a fresh snapshot of the worktree.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::from_hex;
use mkit_core::object::Object;
use mkit_core::ops::{DiffKind, diff_trees};
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit diff",
    about = "Summarize path-level differences between two trees, or HEAD vs worktree."
)]
struct DiffOpts {
    /// Optional two tree hashes to diff against each other.
    /// With no args, diffs HEAD vs worktree.
    hashes: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<DiffOpts>("mkit diff", args) {
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
    let (old_tree, new_tree) = if opts.hashes.len() >= 2 {
        let a = match from_hex(&opts.hashes[0]) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("bad hash arg 1: {e}"), exit::DATAERR),
        };
        let b = match from_hex(&opts.hashes[1]) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("bad hash arg 2: {e}"), exit::DATAERR),
        };
        (Some(a), Some(b))
    } else {
        let head = refs::resolve_head(&mkit_dir).unwrap_or(None);
        let old_tree = match head {
            None => None,
            Some(h) => match store.read_object(&h) {
                Ok(Object::Commit(c)) => Some(c.tree_hash),
                _ => None,
            },
        };
        let new_tree = match worktree::build_tree(&store, &cwd) {
            Ok(h) => Some(h),
            Err(e) => return emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
        };
        (old_tree, new_tree)
    };
    let result = match diff_trees(&store, old_tree, new_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("diff: {e}"), exit::GENERAL_ERROR),
    };
    let mut stdout = std::io::stdout().lock();
    for e in result.entries {
        let tag = match e.kind {
            DiffKind::Added => "A",
            DiffKind::Removed => "D",
            DiffKind::Modified => "M",
            DiffKind::ModeChanged => "T",
        };
        let _ = writeln!(stdout, "{tag} {}", e.path);
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
