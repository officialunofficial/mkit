//! `mkit status` — summarise the index contents.

use std::io::Write;

use mkit_core::index::{self, EntryStatus, Index};
use mkit_core::refs;

use crate::exit;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    if !mkit_dir.is_dir() {
        return emit_err("not a mkit repository", exit::GENERAL_ERROR);
    }
    let mut stdout = std::io::stdout().lock();
    match refs::read_head(&mkit_dir) {
        Ok(refs::Head::Branch(name)) => {
            let _ = writeln!(stdout, "on branch {name}");
        }
        Ok(refs::Head::Detached(h)) => {
            let _ = writeln!(stdout, "detached HEAD at {}", mkit_core::hash::to_hex(&h));
        }
        Err(_) => {
            let _ = writeln!(stdout, "no HEAD yet");
        }
    }
    let idx = match index::read_index(&cwd) {
        Ok(i) => i,
        Err(_) => Index::new(),
    };
    if idx.entries.is_empty() {
        let _ = writeln!(stdout, "nothing staged");
        return exit::OK;
    }
    let _ = writeln!(stdout, "staged:");
    for e in &idx.entries {
        let tag = match e.status {
            EntryStatus::Removed => "D",
            EntryStatus::Blob => "A",
            EntryStatus::Tree => "T",
            EntryStatus::Symlink => "L",
            EntryStatus::Executable => "X",
        };
        let _ = writeln!(stdout, "  {tag} {}", e.path);
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
