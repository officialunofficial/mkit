//! `mkit stash save|list|pop|drop|show` — stash working-directory
//! changes. Port of `cmdStash` in the Zig CLI; backing logic lives in
//! `mkit_core::ops::stash`.
//!
//! `show` needs diff formatting; we defer to a TODO for now and emit a
//! clear message when invoked.

use std::io::Write;

use mkit_core::ops::stash;
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

    // `mkit stash` with no args = `save` with an empty message.
    let sub = args.first().map_or("save", String::as_str);
    match sub {
        "save" => {
            let msg = parse_save_message(args);
            match stash::save(&store, &cwd, &msg) {
                Ok(()) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(stdout, "stashed: {msg}");
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash save: {e}"), exit::GENERAL_ERROR),
            }
        }
        "list" => match stash::list(&cwd) {
            Ok(list) => {
                let mut stdout = std::io::stdout().lock();
                if list.entries.is_empty() {
                    let _ = writeln!(stdout, "(no stash entries)");
                    return exit::OK;
                }
                for (i, e) in list.entries.iter().enumerate() {
                    let _ = writeln!(
                        stdout,
                        "stash@{{{i}}}: {} {}",
                        format::short_hash(&e.commit_hash, 8),
                        e.message
                    );
                }
                exit::OK
            }
            Err(e) => emit_err(&format!("stash list: {e}"), exit::GENERAL_ERROR),
        },
        "pop" => {
            let idx = parse_idx(args);
            match stash::pop(&store, &cwd, idx) {
                Ok(()) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(stdout, "popped stash@{{{idx}}}");
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash pop: {e}"), exit::GENERAL_ERROR),
            }
        }
        "drop" => {
            let idx = parse_idx(args);
            match stash::drop(&cwd, idx) {
                Ok(()) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(stdout, "dropped stash@{{{idx}}}");
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash drop: {e}"), exit::GENERAL_ERROR),
            }
        }
        "show" => emit_err(
            "stash show: diff rendering not yet implemented in the Rust port",
            exit::TEMPFAIL,
        ),
        other => super::usage_error(&format!("unknown stash subcommand: {other}")),
    }
}

fn parse_save_message(args: &[String]) -> String {
    // Accept `stash`, `stash save`, `stash save -m <msg>`, `stash -m <msg>`.
    let mut iter = args.iter().peekable();
    if iter.peek().map(|s| s.as_str()) == Some("save") {
        iter.next();
    }
    while let Some(a) = iter.next() {
        if a == "-m"
            && let Some(next) = iter.next()
        {
            return next.clone();
        }
    }
    String::new()
}

fn parse_idx(args: &[String]) -> usize {
    args.iter()
        .skip(1)
        .find_map(|a| a.parse::<usize>().ok())
        .unwrap_or(0)
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
