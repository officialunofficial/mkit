//! `mkit cat <hash>` — decode and print an object by its hash.

use std::io::Write;

use mkit_core::hash::from_hex;
use mkit_core::object::Object;
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(hash_hex) = args.first() else {
        return super::usage_error("usage: mkit cat <hash>");
    };
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
        other => {
            let _ = writeln!(stdout, "{other}");
        }
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
