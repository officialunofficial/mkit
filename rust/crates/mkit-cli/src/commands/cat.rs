//! `mkit cat <hash>` — decode and print an object by its hash.

use std::io::Write;

use clap::Parser;
use mkit_core::hash::from_hex;
use mkit_core::object::Object;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit cat", about = "Display an object by its hash.")]
struct CatOpts {
    /// 64-char hex object hash.
    hash: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CatOpts>("mkit cat", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let hash_hex = &opts.hash;
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let h = match from_hex(hash_hex) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("bad hash: {e}"), exit::DATAERR),
    };
    let obj = match store.read_object(&h) {
        Ok(o) => o,
        Err(e) => return emit_err(&format!("read: {e}"), exit::NOINPUT),
    };
    let mut stdout = std::io::stdout().lock();
    match obj {
        Object::Blob(b) => {
            let _ = stdout.write_all(&b.data);
        }
        // A ChunkedBlob is the canonical representation for files above
        // the chunking threshold (#203). Reassemble its chunks and
        // stream the full content, matching `mkit cat` on a plain Blob.
        Object::ChunkedBlob(_) => match worktree::read_blob(&store, &h) {
            Ok(data) => {
                let _ = stdout.write_all(&data);
            }
            Err(e) => return emit_err(&format!("reassemble chunked blob: {e}"), exit::NOINPUT),
        },
        Object::Tree(t) => {
            for e in t.entries {
                let _ = writeln!(
                    stdout,
                    "{:02x} {} {}",
                    e.mode as u8,
                    format::hex_hash(&e.object_hash),
                    String::from_utf8_lossy(&e.name)
                );
            }
        }
        Object::Commit(c) => {
            let _ = writeln!(stdout, "tree {}", format::hex_hash(&c.tree_hash));
            for p in &c.parents {
                let _ = writeln!(stdout, "parent {}", format::hex_hash(p));
            }
            let _ = writeln!(stdout, "author {}", format::short_identity(&c.author));
            let _ = writeln!(stdout, "timestamp {}", c.timestamp);
            let _ = writeln!(stdout);
            let _ = stdout.write_all(&c.message);
            let _ = writeln!(stdout);
        }
        Object::Tag(t) => {
            let _ = writeln!(stdout, "object {}", format::hex_hash(&t.target));
            let _ = writeln!(stdout, "type {}", t.target_type.name());
            let _ = writeln!(stdout, "tag {}", String::from_utf8_lossy(&t.name));
            let _ = writeln!(stdout, "tagger {}", format::short_identity(&t.tagger));
            let _ = writeln!(stdout, "timestamp {}", t.timestamp);
            let signed = t.signature != [0u8; 64];
            let _ = writeln!(stdout, "signed {signed}");
            let _ = writeln!(stdout);
            let _ = stdout.write_all(&t.message);
            let _ = writeln!(stdout);
        }
        other => {
            let _ = writeln!(stdout, "{other}");
        }
    }
    exit::OK
}

use super::error as emit_err;
