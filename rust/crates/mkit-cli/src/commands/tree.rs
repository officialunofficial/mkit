//! `mkit tree` — snapshot the working directory as a tree object,
//! printing the resulting tree hash.

use std::io::Write;

use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    match worktree::build_tree(&store, &cwd) {
        Ok(h) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::hex_hash(&h));
            exit::OK
        }
        Err(e) => emit_err(&format!("build tree: {e}"), exit::GENERAL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
