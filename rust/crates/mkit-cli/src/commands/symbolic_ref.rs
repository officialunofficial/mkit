//! `mkit symbolic-ref [--short] <name> [<ref>]` — read or write a symbolic
//! ref (currently only `HEAD`), like `git symbolic-ref`.
//!
//! - Read: `symbolic-ref HEAD` prints the full target ref
//!   (`refs/heads/main`), or just the branch with `--short`. Errors when
//!   HEAD is detached / not symbolic, like git.
//! - Write: `symbolic-ref HEAD refs/heads/<branch>` repoints HEAD at a
//!   branch (the plumbing form — it does not touch the worktree). The target
//!   must be under `refs/heads/`; the branch need not exist yet (matching
//!   git).

use std::io::Write;

use clap::Parser;
use mkit_core::refs::{self, Head};

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit symbolic-ref",
    about = "Read or write a symbolic ref (e.g. HEAD)."
)]
struct SymbolicRefOpts {
    /// Print the short ref name (`main`) instead of `refs/heads/main`.
    #[arg(long)]
    short: bool,
    /// The symbolic ref to read or write (currently only `HEAD`).
    name: String,
    /// When given, the target ref to point `<name>` at (write mode), e.g.
    /// `refs/heads/main`.
    target: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<SymbolicRefOpts>("mkit symbolic-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.name != "HEAD" {
        return emit_err(
            &format!("only HEAD is a symbolic ref in mkit (got '{}')", opts.name),
            exit::GENERAL_ERROR,
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match opts.target {
        Some(target) => write_head(&mkit_dir, &target),
        None => read_head(&mkit_dir, opts.short),
    }
}

/// Read mode: print HEAD's target (full ref, or short branch name).
fn read_head(mkit_dir: &std::path::Path, short: bool) -> u8 {
    match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => {
            let mut stdout = std::io::stdout().lock();
            if short {
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

/// Write mode: repoint HEAD at `<target>` (must be `refs/heads/<branch>`).
/// Like git, the branch need not exist yet, and the worktree is untouched.
fn write_head(mkit_dir: &std::path::Path, target: &str) -> u8 {
    let Some(branch) = target.strip_prefix("refs/heads/") else {
        return emit_err(
            &format!("HEAD can only point at a branch under refs/heads/ (got '{target}')"),
            exit::USAGE,
        );
    };
    if !refs::validate_ref_name(branch) {
        return emit_err(&format!("invalid branch name '{branch}'"), exit::USAGE);
    }
    match refs::write_head_branch(mkit_dir, branch) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write HEAD: {e}"), exit::CANTCREAT),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
