//! `mkit init` — create a fresh repository rooted at the current dir.

use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_core::refs;
use mkit_core::store::{ObjectStore, StoreError};

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit init",
    about = "Create a new mkit repository in the current directory."
)]
struct InitOpts {}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    if let Err(code) = clap_shim::parse::<InitOpts>("mkit init", args) {
        return code;
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cannot read cwd: {e}"), exit::NOINPUT),
    };
    let layout = super::resolve_layout(&cwd);
    match ObjectStore::init(&layout) {
        Ok(_) => {}
        Err(StoreError::AlreadyInitialized) => {
            return emit_err("already a mkit repository", exit::GENERAL_ERROR);
        }
        Err(e) => return emit_err(&format!("init failed: {e}"), exit::CANTCREAT),
    }
    // Initialize refs + HEAD — HEAD points at refs/heads/main.
    if let Err(e) = refs::init(&layout) {
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

use super::error as emit_err;
