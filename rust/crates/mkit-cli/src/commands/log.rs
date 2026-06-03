//! `mkit log` — walk commits from HEAD.
//!
//! Output modes:
//!
//! - default — human-oriented multi-line per commit on stdout. The
//!   full commit message body is printed indented (four spaces) and the
//!   timestamp is rendered as a stable UTC date
//!   (`YYYY-MM-DD HH:MM:SS +0000`), not the raw integer.
//! - `--oneline` — `<8-hex> <title>` per commit on stdout.
//! - `--format=json` — JSONL, one self-contained JSON object per
//!   commit. Suitable for piping into `jq`.
//!
//! `--graph` is silently accepted as a no-op pending Phase 10.
//!
//! Argument parsing is delegated to clap-derive via
//! [`crate::clap_shim::parse`]; clap emits standard diagnostics on
//! errors and the shim maps them to mkit sysexits (`USAGE` for
//! unknown flags, `DATAERR` for malformed `-n` values, etc.).

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::object::Object;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;
use crate::signal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Default,
    Oneline,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit log",
    about = "Show commit history.",
    disable_help_flag = false,
    disable_version_flag = true
)]
struct LogOpts {
    /// Compact one-line-per-commit output. Equivalent to
    /// `--format=oneline`; if both are given, `--format` wins.
    #[arg(long)]
    oneline: bool,

    /// Output format.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Cap the number of commits printed.
    #[arg(short = 'n')]
    limit: Option<usize>,

    /// Render an ASCII graph. Accepted for compatibility; Phase-10
    /// follow-up.
    #[arg(long)]
    graph: bool,
}

impl LogOpts {
    /// Resolve `(oneline, format)` into the single `Format` the
    /// renderer consumes. Explicit `--format` wins over `--oneline`.
    fn render_format(&self) -> Format {
        match self.format {
            Some(f) => f,
            None if self.oneline => Format::Oneline,
            None => Format::Default,
        }
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<LogOpts>("mkit log", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let fmt = opts.render_format();
    let _ = opts.graph; // accepted, currently no-op.

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
        if let Some(lim) = opts.limit
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
                let _ = writeln!(stdout, "Date:   {}", format::human_date_utc(c.timestamp));
                let _ = writeln!(stdout);
                // Full message body, indented like git. Each line is
                // prefixed with four spaces; blank lines stay blank.
                for line in full_message.lines() {
                    if line.is_empty() {
                        let _ = writeln!(stdout);
                    } else {
                        let _ = writeln!(stdout, "    {line}");
                    }
                }
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

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_format_explicit_format_wins_over_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: Some(Format::Default),
            limit: None,
            graph: false,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_oneline_alone_resolves_to_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: None,
            limit: None,
            graph: false,
        };
        assert_eq!(opts.render_format(), Format::Oneline);
    }

    #[test]
    fn render_format_default_when_no_flags() {
        let opts = LogOpts {
            oneline: false,
            format: None,
            limit: None,
            graph: false,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_json_via_format_flag() {
        let opts = LogOpts {
            oneline: false,
            format: Some(Format::Json),
            limit: None,
            graph: false,
        };
        assert_eq!(opts.render_format(), Format::Json);
    }
}
