//! `mkit merge-base [--is-ancestor] <a> <b>` — print the best common
//! ancestor of two commits, or test ancestry. Reuses the merge engine's
//! `find_merge_base` / `is_ancestor` (the algorithms already power
//! `merge`/`rebase`). Object ids are full 64-hex BLAKE3 (the documented
//! hash-length divergence); everything else matches git.

use std::io::Write;

use clap::Parser;
use mkit_core::ops::merge::{find_merge_base, is_ancestor};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit merge-base",
    about = "Find a common ancestor of two commits."
)]
struct MergeBaseOpts {
    /// Test whether <a> is an ancestor of <b>: exit 0 if yes, 1 if no
    /// (no output), like `git merge-base --is-ancestor`.
    #[arg(long = "is-ancestor")]
    is_ancestor: bool,
    a: String,
    b: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<MergeBaseOpts>("mkit merge-base", args) {
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
    let a = match super::revspec::resolve_revision(&store, &mkit_dir, &opts.a) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad revision '{}': {e}", opts.a), exit::GENERAL_ERROR),
    };
    let b = match super::revspec::resolve_revision(&store, &mkit_dir, &opts.b) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad revision '{}': {e}", opts.b), exit::GENERAL_ERROR),
    };

    if opts.is_ancestor {
        return match is_ancestor(&store, a, b) {
            Ok(true) => exit::OK,
            Ok(false) => exit::GENERAL_ERROR,
            Err(e) => emit_err(&format!("merge-base: {e}"), exit::GENERAL_ERROR),
        };
    }

    match find_merge_base(&store, a, b) {
        Ok(Some(base)) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::hex_hash(&base));
            exit::OK
        }
        // No common ancestor — git exits 1 with no output.
        Ok(None) => exit::GENERAL_ERROR,
        Err(e) => emit_err(&format!("merge-base: {e}"), exit::GENERAL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
