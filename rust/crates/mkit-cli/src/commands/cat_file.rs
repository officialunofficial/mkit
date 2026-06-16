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
//!   or a readable commit/tag/remix summary;
//! - `--batch` — read object names from stdin (one per line) and emit, per
//!   object, a `<hash> <type> <size>` header then the content (or
//!   `<name> missing` for unknown objects).
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
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct CatFileOpts {
    /// Print the object type.
    #[arg(short = 't', conflicts_with_all = ["size", "pretty", "batch"])]
    type_: bool,
    /// Print the object size.
    #[arg(short = 's', conflicts_with_all = ["pretty", "batch"])]
    size: bool,
    /// Pretty-print the object content.
    #[arg(short = 'p', conflicts_with = "batch")]
    pretty: bool,
    /// Batch mode: read object names from stdin, emitting
    /// `<hash> <type> <size>` then content for each (`<name> missing` for
    /// unknown objects).
    #[arg(long)]
    batch: bool,
    /// Object to inspect (hash, ref, HEAD, …). Omitted in `--batch` mode.
    object: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CatFileOpts>("mkit cat-file", args) {
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

    if opts.batch {
        if opts.object.is_some() {
            return super::usage_error("mkit cat-file --batch takes no object argument");
        }
        return run_batch(&store, &mkit_dir);
    }
    if !(opts.type_ || opts.size || opts.pretty) {
        return super::usage_error("usage: mkit cat-file (-t | -s | -p) <object>  |  --batch");
    }
    let Some(object) = opts.object.as_deref() else {
        return super::usage_error("usage: mkit cat-file (-t | -s | -p) <object>");
    };

    let h = match revspec::resolve_revision(&store, &mkit_dir, object) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad object '{object}': {e}"), exit::DATAERR),
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

/// `--batch`: read object names (one per line) from stdin and emit, per
/// object, a `<hash> <type> <size>` header line followed by the content and
/// a trailing newline. Unknown objects print `<name> missing`, matching
/// `git cat-file --batch`. `<size>` is the byte length of the content that
/// follows, so blobs are byte-exact with git; commit/tree/tag content is
/// mkit-shaped (and so is its size), as with `-p`.
fn run_batch(store: &ObjectStore, mkit_dir: &std::path::Path) -> u8 {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        // One output record per input line. The whole line is the object
        // name (no trimming, no skipping) — mkit has no `%(rest)` format —
        // so a blank or whitespace-bearing line simply fails to resolve and
        // yields a `<name> missing` record, exactly like git.
        let name = match line {
            Ok(l) => l,
            Err(e) => return emit_err(&format!("read stdin: {e}"), exit::NOINPUT),
        };
        let Ok(h) = revspec::resolve_revision(store, mkit_dir, &name) else {
            let _ = writeln!(stdout, "{name} missing");
            continue;
        };
        let Ok(obj) = store.read_object(&h) else {
            let _ = writeln!(stdout, "{name} missing");
            continue;
        };
        // Render content to a buffer so the advertised size is exactly the
        // byte length we emit (self-consistent for every object type).
        let mut buf: Vec<u8> = Vec::new();
        if let Err(msg) = pretty_print(store, &h, &obj, &mut buf) {
            return emit_err(&msg, exit::GENERAL_ERROR);
        }
        let _ = writeln!(
            stdout,
            "{} {} {}",
            format::hex_hash(&h),
            git_type(&obj),
            buf.len()
        );
        let _ = stdout.write_all(&buf);
        let _ = stdout.write_all(b"\n");
    }
    exit::OK
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

/// `(octal mode, type)` for a tree entry, in git's `ls-tree`/`cat-file -p`
/// form. Shared with `mkit show` so its tree listing matches.
pub(super) fn git_mode_and_type(mode: EntryMode) -> (&'static str, &'static str) {
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
