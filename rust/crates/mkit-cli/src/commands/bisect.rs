//! `mkit bisect start|good|bad|reset|skip` — binary-search a history
//! for the commit that introduced a regression. Port of `cmdBisect` in
//! the Zig CLI; backing state + search logic live in
//! `mkit_core::ops::bisect`.

use std::io::Write;

use mkit_core::hash::{self, Hash};
use mkit_core::ops::bisect::{
    BisectState, BisectStep, cleanup_bisect, is_bisect_in_progress, next_step, read_state,
    write_state,
};
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    let Some(sub) = args.first() else {
        return super::usage_error("usage: mkit bisect (start|good|bad|reset|skip) [<commit>]");
    };
    match sub.as_str() {
        "start" => start(&mkit_dir),
        "good" => mark(&store, &mkit_dir, args.get(1).map(String::as_str), true),
        "bad" => mark(&store, &mkit_dir, args.get(1).map(String::as_str), false),
        "skip" => skip(&store, &mkit_dir),
        "reset" => reset(&mkit_dir),
        other => super::usage_error(&format!("unknown bisect subcommand: {other}")),
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
    };
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("write state: {e}"), exit::CANTCREAT);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(
        stdout,
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
        Some(s) => match hash::from_hex(s) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("bad hash: {e}"), exit::DATAERR),
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
    // "skip" is a light marker: we leave the state unchanged and re-run
    // the search; resolving skips into a proper exclusion set is a
    // library-side follow-up (see TODO in PR body).
    let state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
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
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "bisect reset");
    exit::OK
}

fn report_step(store: &ObjectStore, state: &BisectState) -> u8 {
    match next_step(store, state) {
        Ok(BisectStep::NeedMore) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(
                stdout,
                "need at least one good and a bad commit to start searching"
            );
            exit::OK
        }
        Ok(BisectStep::Testing { hash, remaining }) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(
                stdout,
                "bisect: testing {} ({} candidates remaining)",
                format::short_hash(&hash, 12),
                remaining
            );
            exit::OK
        }
        Ok(BisectStep::Found(h)) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(
                stdout,
                "bisect found first bad commit: {}",
                format::short_hash(&h, 12)
            );
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
