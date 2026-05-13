//! `mkit sparse-checkout set|list|disable|reapply` — manage the sparse
//! checkout pattern set at `.mkit/sparse-checkout`. Pattern parsing +
//! tree-materialisation live in `mkit_core::ops::restore`.

use std::fs;
use std::io::Write;

use clap::{Parser, Subcommand};
use mkit_core::object::Object;
use mkit_core::ops::restore::{self, RestoreOptions, load_sparse_checkout, write_sparse_checkout};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit sparse-checkout",
    about = "Manage sparse-checkout patterns."
)]
struct SparseOpts {
    #[command(subcommand)]
    sub: Option<SparseCmd>,
}

#[derive(Debug, Subcommand)]
enum SparseCmd {
    /// List current patterns.
    List,
    /// Replace the pattern set and re-materialize.
    Set {
        /// One or more patterns.
        #[arg(required = true)]
        patterns: Vec<String>,
    },
    /// Drop patterns and re-materialize the full worktree.
    Disable,
    /// Re-apply the current patterns to the worktree.
    Reapply,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<SparseOpts>("mkit sparse-checkout", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    match opts.sub.unwrap_or(SparseCmd::List) {
        SparseCmd::List => list_patterns(&cwd),
        SparseCmd::Set { patterns } => {
            let pat_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
            if let Err(e) = write_sparse_checkout(&cwd, &pat_refs) {
                return emit_err(&format!("write sparse-checkout: {e}"), exit::CANTCREAT);
            }
            reapply(&cwd)
        }
        SparseCmd::Disable => disable(&cwd),
        SparseCmd::Reapply => reapply(&cwd),
    }
}

fn list_patterns(cwd: &std::path::Path) -> u8 {
    match load_sparse_checkout(cwd) {
        Ok(Some(pats)) => {
            let mut stdout = std::io::stdout().lock();
            for p in pats {
                let neg = if p.negated { "!" } else { "" };
                let slash = if p.dir_only { "/" } else { "" };
                let _ = writeln!(stdout, "{neg}{}{slash}", p.pattern);
            }
            exit::OK
        }
        Ok(None) => {
            // Empty listing → empty stdout; the human note goes to stderr.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "(no sparse-checkout patterns)");
            exit::OK
        }
        Err(e) => emit_err(&format!("load sparse-checkout: {e}"), exit::GENERAL_ERROR),
    }
}

fn disable(cwd: &std::path::Path) -> u8 {
    let path = cwd.join(".mkit/sparse-checkout");
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return emit_err(&format!("remove: {e}"), exit::GENERAL_ERROR),
    }
    // Re-materialise HEAD with full (non-sparse) patterns.
    reapply(cwd)
}

fn reapply(cwd: &std::path::Path) -> u8 {
    let store = match ObjectStore::open(cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let head = match refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => {
            // Nothing to materialise yet.
            return exit::OK;
        }
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let tree_hash = match store.read_object(&head) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(_) => return emit_err("HEAD is not a commit", exit::DATAERR),
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let sparse = match load_sparse_checkout(cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("load sparse-checkout: {e}"), exit::GENERAL_ERROR),
    };
    let opts = RestoreOptions {
        clean: true,
        sparse_patterns: sparse,
    };
    match restore::restore_tree(&store, tree_hash, cwd, &opts) {
        Ok(()) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "sparse-checkout applied");
            exit::OK
        }
        Err(e) => emit_err(&format!("restore: {e}"), exit::GENERAL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
