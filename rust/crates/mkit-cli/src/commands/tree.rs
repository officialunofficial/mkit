//! `mkit tree` — snapshot the working directory as a tree object,
//! printing the resulting tree hash.

use std::io::Write;

use clap::Parser;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit tree",
    about = "Snapshot the working directory as a tree object."
)]
struct TreeOpts {}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    if let Err(code) = clap_shim::parse::<TreeOpts>("mkit tree", args) {
        return code;
    }
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

use super::error as emit_err;
