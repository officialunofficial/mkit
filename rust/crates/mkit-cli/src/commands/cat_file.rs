//! `mkit cat-file (-t | -s | -p) <object>` — inspect an object, like
//! `git cat-file`.
//!
//! - `-t` — print the object type (`blob`/`tree`/`commit`/`tag`; mkit's
//!   `remix` is the one non-git type);
//! - `-s` — print the object size. For blobs this is the content byte
//!   length (matches git); for trees/commits it is mkit's serialized size,
//!   which differs from git's (different object format);
//! - `-p` — pretty-print: a blob's raw bytes, a tree as
//!   `<mode> <type> <hash>\t<name>` lines (git-shaped, modulo hash length),
//!   or a readable commit/tag/remix summary.
//!
//! `<object>` is resolved through the shared revspec grammar (full/short
//! hash, ref, `HEAD`, `HEAD~n`/`^`).

use std::io::Write;

use clap::Parser;
use mkit_core::object::{EntryMode, Object};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit cat-file", about = "Inspect a stored object.")]
struct CatFileOpts {
    /// Print the object type.
    #[arg(short = 't', conflicts_with_all = ["size", "pretty"])]
    type_: bool,
    /// Print the object size.
    #[arg(short = 's', conflicts_with = "pretty")]
    size: bool,
    /// Pretty-print the object content.
    #[arg(short = 'p')]
    pretty: bool,
    /// Object to inspect (hash, ref, HEAD, …).
    object: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CatFileOpts>("mkit cat-file", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if !(opts.type_ || opts.size || opts.pretty) {
        return super::usage_error("usage: mkit cat-file (-t | -s | -p) <object>");
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    let h = match revspec::resolve_revision(&store, &mkit_dir, &opts.object) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad object '{}': {e}", opts.object), exit::DATAERR),
    };
    let obj = match store.read_object(&h) {
        Ok(o) => o,
        Err(e) => return emit_err(&format!("read: {e}"), exit::NOINPUT),
    };

    let mut stdout = std::io::stdout().lock();
    if opts.type_ {
        let _ = writeln!(stdout, "{}", git_type(&obj));
        return exit::OK;
    }
    if opts.size {
        let size = match object_size(&store, &h, &obj) {
            Ok(s) => s,
            Err(msg) => return emit_err(&msg, exit::GENERAL_ERROR),
        };
        let _ = writeln!(stdout, "{size}");
        return exit::OK;
    }
    // -p
    match pretty_print(&store, &h, &obj, &mut stdout) {
        Ok(()) => exit::OK,
        Err(msg) => emit_err(&msg, exit::GENERAL_ERROR),
    }
}

/// git-compatible type token. mkit's `remix` has no git equivalent.
fn git_type(obj: &Object) -> &'static str {
    match obj {
        Object::Blob(_) | Object::ChunkedBlob(_) => "blob",
        Object::Tree(_) => "tree",
        Object::Commit(_) => "commit",
        Object::Tag(_) => "tag",
        Object::Remix(_) => "remix",
        Object::Delta(_) => "delta",
    }
}

/// Object size: blob content length (git-compatible) / chunked total size,
/// else mkit's serialized object size (differs from git).
fn object_size(
    store: &ObjectStore,
    h: &mkit_core::hash::Hash,
    obj: &Object,
) -> Result<u64, String> {
    Ok(match obj {
        Object::Blob(b) => b.data.len() as u64,
        Object::ChunkedBlob(c) => c.total_size,
        _ => store.read(h).map_err(|e| format!("read: {e}"))?.len() as u64,
    })
}

fn pretty_print(
    store: &ObjectStore,
    h: &mkit_core::hash::Hash,
    obj: &Object,
    out: &mut impl Write,
) -> Result<(), String> {
    match obj {
        Object::Blob(b) => {
            let _ = out.write_all(&b.data);
        }
        Object::ChunkedBlob(_) => {
            let data = worktree::read_blob(store, h).map_err(|e| format!("reassemble: {e}"))?;
            let _ = out.write_all(&data);
        }
        Object::Tree(t) => {
            for e in &t.entries {
                let (mode, ty) = git_mode_and_type(e.mode);
                let _ = writeln!(
                    out,
                    "{mode} {ty} {}\t{}",
                    format::hex_hash(&e.object_hash),
                    String::from_utf8_lossy(&e.name)
                );
            }
        }
        Object::Commit(c) => {
            let _ = writeln!(out, "tree {}", format::hex_hash(&c.tree_hash));
            for p in &c.parents {
                let _ = writeln!(out, "parent {}", format::hex_hash(p));
            }
            let _ = writeln!(out, "author {}", format::full_identity(&c.author));
            let _ = writeln!(out, "timestamp {}", c.timestamp);
            let _ = writeln!(out);
            let _ = out.write_all(&c.message);
            let _ = writeln!(out);
        }
        Object::Tag(t) => {
            let _ = writeln!(out, "object {}", format::hex_hash(&t.target));
            let _ = writeln!(out, "type {}", t.target_type.name());
            let _ = writeln!(out, "tag {}", String::from_utf8_lossy(&t.name));
            let _ = writeln!(out, "tagger {}", format::full_identity(&t.tagger));
            let _ = writeln!(out, "timestamp {}", t.timestamp);
            let _ = writeln!(out);
            let _ = out.write_all(&t.message);
            let _ = writeln!(out);
        }
        other => {
            let _ = writeln!(out, "{other}");
        }
    }
    Ok(())
}

fn git_mode_and_type(mode: EntryMode) -> (&'static str, &'static str) {
    match mode {
        EntryMode::Blob => ("100644", "blob"),
        EntryMode::Executable => ("100755", "blob"),
        EntryMode::Symlink => ("120000", "blob"),
        EntryMode::Tree => ("040000", "tree"),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
