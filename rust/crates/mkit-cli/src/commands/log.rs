//! `mkit log` — walk commits from HEAD.
//!
//! Output modes:
//!
//! - default — human-oriented multi-line per commit on stdout.
//! - `--oneline` — `<8-hex> <title>` per commit on stdout.
//! - `--format=json` — JSONL, one self-contained JSON object per
//!   commit. Suitable for piping into `jq`.
//!
//! `--graph` is silently accepted as a no-op pending Phase 10.

use std::io::Write;

use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;
use crate::signal;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Default,
    Oneline,
    Json,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let (fmt, limit) = match parse_args(args) {
        Ok(v) => v,
        Err(code) => return code,
    };
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
        // No HEAD: emit nothing on stdout (JSON callers see an empty
        // stream; human callers see a note on stderr).
        if matches!(fmt, Format::Default | Format::Oneline) {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "no commits yet");
        }
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
                return emit_err(
                    &format!("read {}: {e}", format::hex_hash(&cur)),
                    exit::DATAERR,
                );
            }
        };
        let Object::Commit(c) = obj else {
            return emit_err(
                &format!("not a commit: {}", format::hex_hash(&cur)),
                exit::DATAERR,
            );
        };
        let full_message: String = String::from_utf8_lossy(&c.message).into_owned();
        let title = full_message.lines().next().unwrap_or("");
        match fmt {
            Format::Oneline => {
                let _ = writeln!(stdout, "{} {}", format::short_hash(&cur, 8), title);
            }
            Format::Default => {
                let _ = writeln!(stdout, "commit {}", format::hex_hash(&cur));
                let _ = writeln!(stdout, "Author: {}", format::short_identity(&c.author));
                let _ = writeln!(stdout, "Date:   {}", c.timestamp);
                let _ = writeln!(stdout);
                let _ = writeln!(stdout, "    {title}");
                let _ = writeln!(stdout);
            }
            Format::Json => {
                emit_json_entry(&mut stdout, &cur, &c, title, &full_message);
            }
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

/// Emit one JSONL record for a commit. Schema:
///
/// ```json
/// {
///   "hash": "<64-hex>",
///   "parents": ["<64-hex>", ...],
///   "tree": "<64-hex>",
///   "author": "<identity-string>",
///   "timestamp": <unix-seconds>,
///   "title": "<first line of message>",
///   "message": "<full message, JSON-escaped>"
/// }
/// ```
///
/// Keys are written in a deterministic order so the output is
/// reproducible and easy to snapshot-test.
fn emit_json_entry(
    out: &mut impl Write,
    hash: &mkit_core::Hash,
    c: &mkit_core::object::Commit,
    title: &str,
    full_message: &str,
) {
    let _ = out.write_all(b"{");
    let _ = write!(out, "\"hash\":\"{}\"", format::hex_hash(hash));
    let _ = out.write_all(b",\"parents\":[");
    for (i, p) in c.parents.iter().enumerate() {
        if i > 0 {
            let _ = out.write_all(b",");
        }
        let _ = write!(out, "\"{}\"", format::hex_hash(p));
    }
    let _ = out.write_all(b"]");
    let _ = write!(out, ",\"tree\":\"{}\"", format::hex_hash(&c.tree_hash));
    let _ = write!(
        out,
        ",\"author\":\"{}\"",
        format::json_escape(&format::full_identity(&c.author))
    );
    let _ = write!(out, ",\"timestamp\":{}", c.timestamp);
    let _ = write!(out, ",\"title\":\"{}\"", format::json_escape(title));
    let _ = write!(
        out,
        ",\"message\":\"{}\"",
        format::json_escape(full_message)
    );
    let _ = out.write_all(b"}\n");
}

fn parse_args(args: &[String]) -> Result<(Format, Option<usize>), u8> {
    let mut fmt = Format::Default;
    let mut limit: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--oneline" => fmt = Format::Oneline,
            "--format=json" => fmt = Format::Json,
            "--format" if i + 1 < args.len() => {
                match args[i + 1].as_str() {
                    "json" => fmt = Format::Json,
                    "oneline" => fmt = Format::Oneline,
                    "default" => fmt = Format::Default,
                    other => {
                        return Err(super::usage_error(&format!(
                            "unknown --format value: {other} (expected: default, oneline, json)"
                        )));
                    }
                }
                i += 1;
            }
            "-n" if i + 1 < args.len() => {
                limit = args[i + 1].parse().ok();
                i += 1;
            }
            "--graph" => {
                // Silently accept for now — presentation-only flag.
            }
            other => {
                return Err(super::usage_error(&format!(
                    "unknown flag for log: {other}"
                )));
            }
        }
        i += 1;
    }
    Ok((fmt, limit))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
