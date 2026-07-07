//! `mkit rev-list [--count] <rev>` — list the commit ids reachable from
//! `<rev>` in reverse-chronological (topological) order, or just their
//! count. Reuses `log`'s ordered walk so ordering matches `mkit log`.
//! Object ids are full 64-hex BLAKE3 (the documented divergence).

use std::collections::HashSet;
use std::io::Write;

use clap::Parser;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit rev-list",
    about = "List commit objects reachable from a revision."
)]
struct RevListOpts {
    /// Print the number of commits instead of the list.
    #[arg(long)]
    count: bool,
    /// Starting revision (branch / tag / commit / HEAD).
    rev: String,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RevListOpts>("mkit rev-list", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = super::resolve_layout(&cwd);
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let tip = match super::revspec::resolve_revision(&store, &layout, &opts.rev) {
        // Peel annotated/signed tags to the commit they point at, like
        // `log`/`diff`/`branch` (resolve_revision returns the tag object).
        Ok(h) => super::log::peel_tags(&store, h),
        Err(e) => {
            return emit_err(
                &format!("bad revision '{}': {e}", opts.rev),
                exit::GENERAL_ERROR,
            );
        }
    };
    let commits = match super::log::ordered_commits(&store, &[tip], &HashSet::new()) {
        Ok(c) => c,
        Err(code) => return code,
    };
    let mut stdout = std::io::stdout().lock();
    if opts.count {
        let _ = writeln!(stdout, "{}", commits.len());
    } else {
        for (h, _) in &commits {
            let _ = writeln!(stdout, "{}", format::hex_hash(h));
        }
    }
    exit::OK
}

use super::error as emit_err;
