//! `mkit log` — walk commits from HEAD. Recognised flags: `--oneline`,
//! `-n <N>`. `--graph` is a Phase 10 follow-up.

use std::io::Write;

use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;
use crate::signal;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let mut oneline = false;
    let mut limit: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--oneline" => oneline = true,
            "-n" if i + 1 < args.len() => {
                limit = args[i + 1].parse().ok();
                i += 1;
            }
            "--graph" => {
                // Silently accept for now — presentation-only flag.
            }
            other => {
                return super::usage_error(&format!("unknown flag for log: {other}"));
            }
        }
        i += 1;
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let Ok(Some(start)) = refs::resolve_head(&mkit_dir) else {
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "no commits yet");
        return exit::OK;
    };
    let mut stdout = std::io::stdout().lock();
    let mut cur = start;
    let mut shown = 0usize;
    loop {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        if let Some(lim) = limit
            && shown >= lim
        {
            break;
        }
        let obj = match store.read_object(&cur) {
            Ok(o) => o,
            Err(e) => {
                let _ = writeln!(stdout, "(read error: {e})");
                break;
            }
        };
        let Object::Commit(c) = obj else {
            let _ = writeln!(stdout, "(not a commit: {})", format::hex_hash(&cur));
            break;
        };
        let title = String::from_utf8_lossy(&c.message);
        let title = title.lines().next().unwrap_or("");
        if oneline {
            let _ = writeln!(stdout, "{} {}", format::short_hash(&cur, 8), title);
        } else {
            let _ = writeln!(stdout, "commit {}", format::hex_hash(&cur));
            let _ = writeln!(stdout, "Author: {}", format::short_identity(&c.author));
            let _ = writeln!(stdout, "Date:   {}", c.timestamp);
            let _ = writeln!(stdout);
            let _ = writeln!(stdout, "    {title}");
            let _ = writeln!(stdout);
        }
        shown += 1;
        if let Some(p) = c.parents.first() {
            cur = *p;
        } else {
            break;
        }
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
