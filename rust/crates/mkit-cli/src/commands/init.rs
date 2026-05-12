//! `mkit init` — create a fresh repository rooted at the current dir.

use std::io::Write;
use std::path::Path;

use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};

use crate::exit;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cannot read cwd: {e}"), exit::NOINPUT),
    };
    match ObjectStore::init(&cwd) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => {
            return emit_err("already a mkit repository", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("init failed: {e}"), exit::CANTCREAT),
    }
    // Initialize refs + HEAD — HEAD points at refs/heads/main.
    if let Err(e) = refs::init(&cwd.join(mkit_core::MKIT_DIR)) {
        return emit_err(&format!("refs init failed: {e}"), exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "initialized empty mkit repository in {}/.mkit/",
        display(&cwd)
    );
    exit::OK
}

fn display(p: &Path) -> String {
    p.display().to_string()
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
