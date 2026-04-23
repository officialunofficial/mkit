//! `mkit rm <path>` — mark a path for removal in the next commit.

use std::io::Write;

use mkit_core::hash::ZERO;
use mkit_core::index::{self, EntryStatus, Index, IndexEntry};

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(path) = args.first() else {
        return super::usage_error("usage: mkit rm <path>");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mut idx = match index::read_index(&cwd) {
        Ok(i) => i,
        Err(_) => Index::new(),
    };
    let entry = IndexEntry {
        path: path.clone(),
        status: EntryStatus::Removed,
        object_hash: ZERO,
    };
    if let Some(at) = idx.find_entry(path) {
        idx.entries[at] = entry;
    } else {
        idx.entries.push(entry);
    }
    match index::write_index(&cwd, &idx) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write index: {e}"), exit::CANTCREAT),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
