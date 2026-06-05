//! `mkit ls-tree [-r] [-z] <tree-ish> [<path>...]` — list the entries of a
//! tree, like `git ls-tree`.
//!
//! Each entry prints as `<mode> <type> <hash>\t<name>` where `<mode>` is
//! the git octal mode (`100644`/`100755`/`120000`/`040000`) and `<hash>`
//! is a 64-hex BLAKE3 id. `-r` recurses (showing leaf blobs with full
//! paths and omitting tree lines, like git); `-z` NUL-terminates records
//! and emits raw paths (otherwise special-byte paths are C-style quoted).

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::{EntryMode, Object};
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit ls-tree", about = "List the contents of a tree object.")]
struct LsTreeOpts {
    /// Recurse into sub-trees (show leaf blobs with full paths).
    #[arg(short = 'r')]
    recursive: bool,
    /// NUL-terminate records and emit raw (unquoted) paths.
    #[arg(short = 'z')]
    z: bool,
    /// Tree-ish (commit, tag, tree, ref, or hash) followed by optional
    /// pathspecs limiting the listing.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<LsTreeOpts>("mkit ls-tree", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let Some((spec, pathspecs)) = opts.args.split_first() else {
        return super::usage_error("usage: mkit ls-tree [-r] [-z] <tree-ish> [<path>...]");
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

    let tree_hash = match resolve_tree(&store, &mkit_dir, spec) {
        Ok(h) => h,
        Err(msg) => return emit_err(&msg, exit::GENERAL_ERROR),
    };

    let normalized: Vec<String> = pathspecs.iter().map(|p| normalize(p)).collect();
    let mut stdout = std::io::stdout().lock();
    if let Err(msg) = list(
        &store,
        &tree_hash,
        "",
        opts.recursive,
        opts.z,
        &normalized,
        &mut stdout,
    ) {
        return emit_err(&msg, exit::GENERAL_ERROR);
    }
    exit::OK
}

/// Recursively emit a tree's entries. Trees are recursed (and their own
/// line omitted) under `-r`; otherwise a tree prints as `040000 tree`.
fn list(
    store: &ObjectStore,
    tree_hash: &Hash,
    prefix: &str,
    recursive: bool,
    z: bool,
    pathspecs: &[String],
    out: &mut impl Write,
) -> Result<(), String> {
    let Object::Tree(tree) = store
        .read_object(tree_hash)
        .map_err(|e| format!("read tree: {e}"))?
    else {
        return Err(format!("{} is not a tree", format::hex_hash(tree_hash)));
    };
    for e in &tree.entries {
        let Ok(name) = std::str::from_utf8(&e.name) else {
            return Err("tree entry name is not valid UTF-8".to_string());
        };
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if e.mode == EntryMode::Tree && recursive {
            list(store, &e.object_hash, &path, recursive, z, pathspecs, out)?;
            continue;
        }
        if !pathspecs.is_empty() && !path_matches(&path, pathspecs) {
            continue;
        }
        let (mode, ty) = git_mode_and_type(e.mode);
        let hash = format::hex_hash(&e.object_hash);
        if z {
            let _ = write!(out, "{mode} {ty} {hash}\t{path}\0");
        } else {
            let shown = super::c_quote_path(&path);
            let shown = shown.as_deref().unwrap_or(&path);
            let _ = writeln!(out, "{mode} {ty} {hash}\t{shown}");
        }
    }
    Ok(())
}

/// Map an [`EntryMode`] to git's octal mode + object type token.
fn git_mode_and_type(mode: EntryMode) -> (&'static str, &'static str) {
    match mode {
        EntryMode::Blob => ("100644", "blob"),
        EntryMode::Executable => ("100755", "blob"),
        EntryMode::Symlink => ("120000", "blob"),
        EntryMode::Tree => ("040000", "tree"),
    }
}

/// Resolve a tree-ish spec to a tree hash: commit/remix → its tree, tag →
/// its target's tree, a tree → itself.
fn resolve_tree(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    spec: &str,
) -> Result<Hash, String> {
    let h = revspec::resolve_revision(store, mkit_dir, spec)
        .map_err(|e| format!("bad revision '{spec}': {e}"))?;
    object_to_tree(store, &h)
}

fn object_to_tree(store: &ObjectStore, h: &Hash) -> Result<Hash, String> {
    match store
        .read_object(h)
        .map_err(|e| format!("read object: {e}"))?
    {
        Object::Commit(c) => Ok(c.tree_hash),
        Object::Remix(r) => Ok(r.tree_hash),
        Object::Tree(_) => Ok(*h),
        Object::Tag(t) => object_to_tree(store, &t.target),
        _ => Err(format!("{} is not a tree-ish", format::hex_hash(h))),
    }
}

fn normalize(spec: &str) -> String {
    let s = spec.replace('\\', "/");
    let s = s.strip_prefix("./").unwrap_or(&s);
    s.strip_suffix('/').unwrap_or(s).to_string()
}

fn path_matches(path: &str, specs: &[String]) -> bool {
    specs
        .iter()
        .any(|s| super::index_path_matches_or_descends(path, s))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
