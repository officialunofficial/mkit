//! `mkit checkout <branch>` — switch HEAD to a branch. File-restoration
//! is delegated to a Phase 10 follow-up (the `restore` op exists in
//! `mkit-core::ops::restore` but tying it to the worktree behaviour the
//! Zig version expects is non-trivial — flag in the PR body).

use std::io::Write;

use mkit_core::refs;

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(name) = args.first() else {
        return super::usage_error("usage: mkit checkout <branch>");
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    match refs::read_ref(&mkit_dir, name) {
        Ok(Some(_)) => {}
        Ok(None) => return emit_err(&format!("no such branch: {name}"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read ref: {e}"), exit::GENERAL_ERROR),
    }
    if let Err(e) = refs::write_head_branch(&mkit_dir, name) {
        return emit_err(&format!("update HEAD: {e}"), exit::CANTCREAT);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "switched to branch {name}");
    let _ = writeln!(
        stdout,
        "note: worktree file restoration is a Phase 10 follow-up"
    );
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
