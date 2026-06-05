//! `mkit symbolic-ref [--short] <name>` — read a symbolic ref (currently
//! only `HEAD`), like `git symbolic-ref`.
//!
//! Prints the full target ref (`refs/heads/main`), or just the branch name
//! with `--short`. Errors when the ref is detached / not symbolic, like
//! git. Writing symbolic refs is a Phase-4 (#252) follow-up.

use std::io::Write;

use clap::Parser;
use mkit_core::refs::{self, Head};

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(name = "mkit symbolic-ref", about = "Read a symbolic ref (e.g. HEAD).")]
struct SymbolicRefOpts {
    /// Print the short ref name (`main`) instead of `refs/heads/main`.
    #[arg(long)]
    short: bool,
    /// The symbolic ref to read (currently only `HEAD`).
    name: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<SymbolicRefOpts>("mkit symbolic-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.name != "HEAD" {
        return emit_err(
            &format!(
                "only HEAD is a readable symbolic ref in mkit (got '{}')",
                opts.name
            ),
            exit::GENERAL_ERROR,
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match refs::read_head(&mkit_dir) {
        Ok(Head::Branch(name)) => {
            let mut stdout = std::io::stdout().lock();
            if opts.short {
                let _ = writeln!(stdout, "{name}");
            } else {
                let _ = writeln!(stdout, "refs/heads/{name}");
            }
            exit::OK
        }
        // Detached HEAD: not a symbolic ref (git errors here too).
        Ok(Head::Detached(_)) => emit_err("ref HEAD is not a symbolic ref", exit::GENERAL_ERROR),
        Err(e) => emit_err(&format!("read HEAD: {e}"), exit::DATAERR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
