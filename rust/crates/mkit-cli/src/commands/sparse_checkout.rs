//! `mkit sparse-checkout set|list|disable|reapply` — manage the sparse
//! checkout pattern set at `.mkit/sparse-checkout`. Pattern parsing +
//! tree-materialisation live in `mkit_core::ops::restore`.

use std::fs;
use std::io::Write;

use clap::{Parser, Subcommand};
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::restore::{
    self, RestoreOptions, load_sparse_checkout, parse_sparse_patterns, write_sparse_checkout,
};
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
    let layout = super::resolve_layout(&cwd);
    match opts.sub.unwrap_or(SparseCmd::List) {
        SparseCmd::List => list_patterns(&layout),
        SparseCmd::Set { patterns } => {
            let joined = patterns.join("\n");
            let opts = RestoreOptions {
                clean: true,
                sparse_patterns: Some(parse_sparse_patterns(&joined)),
            };
            apply_sparse_change(&layout, &opts, || {
                let pat_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
                write_sparse_checkout(&layout, &pat_refs)
                    .map_err(|e| (format!("write sparse-checkout: {e}"), exit::CANTCREAT))
            })
        }
        SparseCmd::Disable => disable(&layout),
        SparseCmd::Reapply => reapply(&layout),
    }
}

fn list_patterns(layout: &RepoLayout) -> u8 {
    match load_sparse_checkout(layout) {
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

fn disable(layout: &RepoLayout) -> u8 {
    let opts = RestoreOptions {
        clean: true,
        sparse_patterns: None,
    };
    apply_sparse_change(layout, &opts, || {
        let path = layout.sparse_checkout_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err((format!("remove: {e}"), exit::GENERAL_ERROR)),
        }
    })
}

fn reapply(layout: &RepoLayout) -> u8 {
    let sparse = match load_sparse_checkout(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("load sparse-checkout: {e}"), exit::GENERAL_ERROR),
    };
    let opts = RestoreOptions {
        clean: true,
        sparse_patterns: sparse,
    };
    apply_sparse_change(layout, &opts, || Ok(()))
}

fn apply_sparse_change<F>(layout: &RepoLayout, opts: &RestoreOptions, mutate_config: F) -> u8
where
    F: FnOnce() -> Result<(), (String, u8)>,
{
    let store = match ObjectStore::open(layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let _lock = match super::acquire_worktree_lock(layout) {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    let head = match refs::resolve_head(layout) {
        Ok(Some(h)) => h,
        Ok(None) => {
            if let Err((msg, code)) = mutate_config() {
                return emit_err(&msg, code);
            }
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "sparse-checkout applied");
            return exit::OK;
        }
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let tree_hash = match store.read_object(&head) {
        Ok(Object::Commit(c)) => c.tree_hash,
        Ok(_) => return emit_err("HEAD is not a commit", exit::DATAERR),
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = super::ensure_restore_safe_with_options(layout, &store, tree_hash, opts) {
        return emit_err(&e, exit::GENERAL_ERROR);
    }
    if let Err((msg, code)) = mutate_config() {
        return emit_err(&msg, code);
    }
    match restore::restore_tree_to_worktree(&store, &tree_hash, layout.worktree_root(), opts) {
        Ok(_) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "sparse-checkout applied");
            exit::OK
        }
        Err(e) => emit_err(&format!("restore: {e}"), exit::GENERAL_ERROR),
    }
}

use super::error as emit_err;
