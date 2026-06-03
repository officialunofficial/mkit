//! `mkit diff` — show changes as a unified patch.
//!
//! Modes:
//!
//! - no args — HEAD tree vs a fresh worktree snapshot;
//! - `--staged` / `--cached` — HEAD tree vs the staged index tree
//!   (what `mkit commit` would record);
//! - two tree hashes — diff those tree hashes against each other.
//!
//! Trailing positional paths (pathspecs) filter the output to entries
//! at or below those paths. Output is a Git-compatible unified diff:
//! a `diff --mkit a/<p> b/<p>` header per changed path followed by the
//! `text_patch` hunks (or `Binary files … differ`).

use std::io::Write;

use clap::Parser;
use mkit_core::hash::{Hash, from_hex};
use mkit_core::object::Object;
use mkit_core::ops::{DiffEntry, DiffKind, diff_trees, text_patch};
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit diff",
    about = "Show changes as a unified patch (HEAD vs worktree, --staged, or two trees)."
)]
struct DiffOpts {
    /// Diff the staged index tree against HEAD (the change `mkit commit`
    /// would record) instead of HEAD vs worktree.
    #[arg(long, visible_alias = "cached")]
    staged: bool,

    /// Optional two tree hashes to diff against each other, followed by
    /// optional pathspecs to limit the output. With no hashes, diffs
    /// HEAD vs worktree (or HEAD vs index with --staged); any
    /// non-hex-hash arguments are treated as pathspecs.
    args: Vec<String>,
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

    // Two leading 64-hex arguments select explicit tree-vs-tree mode;
    // anything else after them is a pathspec.
    let (old_tree, new_tree, pathspecs) =
        if opts.args.len() >= 2 && is_hash(&opts.args[0]) && is_hash(&opts.args[1]) {
            let a = match from_hex(&opts.args[0]) {
                Ok(h) => h,
                Err(e) => return emit_err(&format!("bad hash arg 1: {e}"), exit::DATAERR),
            };
            let b = match from_hex(&opts.args[1]) {
                Ok(h) => h,
                Err(e) => return emit_err(&format!("bad hash arg 2: {e}"), exit::DATAERR),
            };
            (Some(a), Some(b), opts.args[2..].to_vec())
        } else {
            let head_tree = match head_tree(&store, &mkit_dir) {
                Ok(t) => t,
                Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
            };
            let new_tree = if opts.staged {
                match index_tree(&cwd, &store) {
                    Ok(t) => t,
                    Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
                }
            } else {
                match worktree::build_tree(&store, &cwd) {
                    Ok(h) => Some(h),
                    Err(e) => return emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
                }
            };
            (head_tree, new_tree, opts.args.clone())
        };

    let result = match diff_trees(&store, old_tree, new_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("diff: {e}"), exit::GENERAL_ERROR),
    };

    let normalized: Vec<String> = pathspecs.iter().map(|p| normalize_pathspec(p)).collect();

    let mut stdout = std::io::stdout().lock();
    for e in &result.entries {
        if !normalized.is_empty() && !path_matches_any(&e.path, &normalized) {
            continue;
        }
        if let Err(msg) = emit_entry_patch(&mut stdout, &store, e) {
            return emit_err(&msg, exit::GENERAL_ERROR);
        }
    }
    exit::OK
}

/// Heuristic: a 64-char lowercase-or-uppercase hex string is treated as
/// a tree hash; everything else is a pathspec.
fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn head_tree(store: &ObjectStore, mkit_dir: &std::path::Path) -> Result<Option<Hash>, String> {
    let head = refs::resolve_head(mkit_dir).map_err(|e| format!("resolve HEAD: {e}"))?;
    match head {
        None => Ok(None),
        Some(h) => match store.read_object(&h) {
            Ok(Object::Commit(c)) => Ok(Some(c.tree_hash)),
            Ok(Object::Remix(r)) => Ok(Some(r.tree_hash)),
            Ok(_) => Ok(None),
            Err(e) => Err(format!("read HEAD: {e}")),
        },
    }
}

fn index_tree(root: &std::path::Path, store: &ObjectStore) -> Result<Option<Hash>, String> {
    let idx = super::read_or_seed_index_from_head(root, store)?;
    let tree = worktree::build_tree_from_index(store, &idx)
        .map_err(|e| format!("build index tree: {e}"))?;
    Ok(Some(tree))
}

/// Normalize a pathspec to the index/diff path form: strip a leading
/// `./`, collapse `\\` to `/`, drop a trailing `/`.
fn normalize_pathspec(spec: &str) -> String {
    let s = spec.replace('\\', "/");
    let s = s.strip_prefix("./").unwrap_or(&s);
    s.strip_suffix('/').unwrap_or(s).to_string()
}

fn path_matches_any(path: &str, specs: &[String]) -> bool {
    specs
        .iter()
        .any(|spec| super::index_path_matches_or_descends(path, spec))
}

/// Emit the `diff --mkit` header plus hunks for one changed entry.
fn emit_entry_patch(
    out: &mut impl Write,
    store: &ObjectStore,
    e: &DiffEntry,
) -> Result<(), String> {
    let _ = writeln!(out, "diff --mkit a/{} b/{}", e.path, e.path);
    match e.kind {
        DiffKind::ModeChanged => {
            // Same content, mode flip — no textual hunk to show.
            let _ = writeln!(out, "mode changed: {}", e.path);
            return Ok(());
        }
        DiffKind::Added => {
            let _ = writeln!(out, "new file: {}", e.path);
        }
        DiffKind::Removed => {
            let _ = writeln!(out, "deleted file: {}", e.path);
        }
        DiffKind::Modified => {}
    }

    let old_bytes = match e.old_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    let new_bytes = match e.new_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    let patch = text_patch(&old_bytes, &new_bytes, &e.path, &e.path);
    let _ = out.write_all(patch.as_bytes());
    Ok(())
}

/// Read a blob's bytes from the store, reassembling chunked blobs.
fn read_blob(store: &ObjectStore, h: &Hash) -> Result<Vec<u8>, String> {
    match store.read_object(h) {
        Ok(Object::Blob(b)) => Ok(b.data),
        Ok(Object::ChunkedBlob(manifest)) => {
            let mut data = Vec::new();
            for chunk in &manifest.chunks {
                match store.read_object(chunk) {
                    Ok(Object::Blob(b)) => data.extend_from_slice(&b.data),
                    Ok(_) => {
                        return Err(format!(
                            "chunk {} is not a blob",
                            mkit_core::hash::to_hex(chunk)
                        ));
                    }
                    Err(e) => return Err(format!("read chunk: {e}")),
                }
            }
            Ok(data)
        }
        Ok(_) => Err("object is not a blob".to_string()),
        Err(e) => Err(format!("read object: {e}")),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
