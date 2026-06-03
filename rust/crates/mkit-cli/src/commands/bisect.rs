//! `mkit bisect start|good|bad|reset|skip` — binary-search a history
//! for the commit that introduced a regression. Backing state + search
//! logic live in `mkit_core::ops::bisect`.

use std::collections::BTreeSet;
use std::io::Write;

use mkit_core::hash::Hash;
use mkit_core::ops::bisect::{
    BisectState, BisectStep, cleanup_bisect, is_bisect_in_progress, next_step, read_state,
    write_state,
};
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use clap::{Parser, Subcommand};

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit bisect",
    about = "Binary-search for a regression-introducing commit."
)]
struct BisectOpts {
    #[command(subcommand)]
    sub: BisectCmd,
}

#[derive(Debug, Subcommand)]
enum BisectCmd {
    /// Begin a bisect session at HEAD.
    Start,
    /// Mark a commit (or HEAD) as good.
    Good { commit: Option<String> },
    /// Mark a commit (or HEAD) as bad.
    Bad { commit: Option<String> },
    /// Skip the current candidate.
    Skip,
    /// End the session and restore the original HEAD.
    Reset,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BisectOpts>("mkit bisect", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match opts.sub {
        BisectCmd::Start => start(&mkit_dir),
        BisectCmd::Good { commit } => mark(&store, &mkit_dir, commit.as_deref(), true),
        BisectCmd::Bad { commit } => mark(&store, &mkit_dir, commit.as_deref(), false),
        BisectCmd::Skip => skip(&store, &mkit_dir),
        BisectCmd::Reset => reset(&mkit_dir),
    }
}

fn start(mkit_dir: &std::path::Path) -> u8 {
    if is_bisect_in_progress(mkit_dir) {
        return emit_err(
            "a bisect is already in progress (use `mkit bisect reset` first)",
            exit::GENERAL_ERROR,
        );
    }
    let orig_head = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits yet", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let orig_branch = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => Some(name),
        _ => None,
    };
    let state = BisectState {
        orig_head,
        orig_branch,
        bad_hash: None,
        good_hashes: Vec::new(),
        skipped: BTreeSet::default(),
    };
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("write state: {e}"), exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "bisect started; mark endpoints with `mkit bisect good <hash>` and `mkit bisect bad <hash>`"
    );
    exit::OK
}

fn mark(store: &ObjectStore, mkit_dir: &std::path::Path, arg: Option<&str>, good: bool) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let hash_: Hash = match arg {
        Some(s) => match super::revspec::resolve_revision(store, mkit_dir, s) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("bad commit: {e}"), exit::DATAERR),
        },
        None => match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => h,
            _ => return emit_err("no HEAD; provide an explicit hash", exit::GENERAL_ERROR),
        },
    };
    if good {
        state.good_hashes.push(hash_);
    } else {
        state.bad_hash = Some(hash_);
    }
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
    }
    report_step(store, &state)
}

fn skip(store: &ObjectStore, mkit_dir: &std::path::Path) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    // Determine the current midpoint to skip.
    let current_mid = match next_step(store, &state) {
        Ok(BisectStep::Testing { hash, .. }) => hash,
        Ok(_) => {
            // Nothing to skip: either already found or not enough data.
            // User error (skip invoked when bisect has no current
            // candidate); USAGE rather than OK so scripts see the
            // failure.
            return emit_err("bisect skip: no current candidate to skip", exit::USAGE);
        }
        Err(e) => return emit_err(&format!("bisect skip: {e}"), exit::GENERAL_ERROR),
    };
    // Add the current midpoint to the exclusion set, then advance.
    state.skipped.insert(current_mid);
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "skipped {}; advancing to next candidate",
        format::short_hash(&current_mid, 12)
    );
    drop(stderr);
    report_step(store, &state)
}

fn reset(mkit_dir: &std::path::Path) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    if let Some(branch) = state.orig_branch.as_deref() {
        let _ = refs::write_head_branch(mkit_dir, branch);
    } else {
        let _ = refs::write_head_detached(mkit_dir, &state.orig_head);
    }
    let _ = cleanup_bisect(mkit_dir);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "bisect reset");
    exit::OK
}

fn report_step(store: &ObjectStore, state: &BisectState) -> u8 {
    match next_step(store, state) {
        Ok(BisectStep::NeedMore) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "need at least one good and a bad commit to start searching"
            );
            exit::OK
        }
        Ok(BisectStep::Testing { hash, remaining }) => {
            // Progress prose to stderr; the candidate hash itself to
            // stdout so `H=$(mkit bisect good)` keeps working.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "bisect: testing ({remaining} candidates remaining)");
            drop(stderr);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::short_hash(&hash, 12));
            exit::OK
        }
        Ok(BisectStep::Found(h)) => {
            // The "found" result is genuinely a data point — emit the
            // hash on stdout and the prose on stderr.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "bisect found first bad commit:");
            drop(stderr);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::short_hash(&h, 12));
            exit::OK
        }
        Err(e) => emit_err(&format!("bisect: {e}"), exit::GENERAL_ERROR),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
