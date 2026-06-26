//! `mkit blame [<rev>] [-L <range>] <file>` — line-level attribution.
//!
//! Blames `<file>` as of `<rev>` (default `HEAD`), optionally restricted
//! to a line range with `-L`.
//!
//! Output modes:
//!
//! - default — `<short12>\t<line_num>\t<text>\n` per line, pinned by
//!   the integration test in `tests/cli_wire.rs:233-243`.
//! - `--format=json` — JSONL, one self-contained record per line with
//!   keys `hash`, `line_num`, `author`, `timestamp`, `text`. Schema
//!   diverges from the tab format because mkit's author is an
//!   Identity, not a `Name <email>` string — see commands/log.rs for
//!   the same divergence.
//!
//! Line numbers in the output are always the file's own 1-based numbers,
//! so a `-L 40,60` slice still prints `40..=60`, matching `git blame -L`.

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::ops::blame::{BlameResult, blame_file, format_blame_text};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BlameFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit blame",
    about = "Show line-level commit attribution.",
    override_usage = "mkit blame [OPTIONS] [<rev>] [--] <file>"
)]
struct BlameOpts {
    /// Output format. Default emits `<short12>\t<line_num>\t<text>`
    /// per line; `json` emits JSONL with `hash`, `line_num`,
    /// `author`, `timestamp`, `text` keys.
    #[arg(long, value_enum, default_value = "default")]
    format: BlameFormat,
    /// Restrict output to a line range, like `git blame -L`. Accepts
    /// `<start>,<end>`, `<start>,+<n>` (n lines from start), `<start>,`
    /// (start to EOF), `,<end>` (start of file to end), or a bare
    /// `<start>` (start to EOF). Lines are 1-based and inclusive; an
    /// inverted range is swapped and an over-long end is clamped to EOF,
    /// matching git.
    #[arg(short = 'L', long = "lines", value_name = "START,END")]
    lines: Option<String>,
    /// `[<rev>] <file>`: the file to blame, optionally preceded by the
    /// revision to blame it at (a ref, hash, or `HEAD~2`-style spec).
    /// Without a revision the file is blamed against HEAD. A `--`
    /// separator before the file is accepted and ignored.
    #[arg(value_name = "REV/FILE", num_args = 1..=2, required = true)]
    rev_and_file: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BlameOpts>("mkit blame", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, BlameFormat::Json);

    // `rev_and_file` is clamped to 1..=2 by clap: one value is the file
    // (blame against HEAD); two values are `<rev> <file>`.
    let (rev_spec, file) = match opts.rev_and_file.as_slice() {
        [file] => (None, file),
        [rev, file] => (Some(rev), file),
        // Unreachable: clap enforces num_args = 1..=2.
        _ => return emit_err("expected [<rev>] <file>", exit::USAGE),
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

    // Resolve the commit to blame against: an explicit <rev> via the
    // shared revspec grammar, otherwise HEAD.
    let head = if let Some(spec) = rev_spec {
        match revspec::resolve_revision(&store, &mkit_dir, spec) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("{e}"), exit::NOINPUT),
        }
    } else {
        match refs::resolve_head(&mkit_dir) {
            Ok(Some(h)) => h,
            Ok(None) => return emit_err("no commits yet", exit::GENERAL_ERROR),
            Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
        }
    };

    let result = match blame_file(&store, head, file) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("blame: {e}"), exit::NOINPUT),
    };

    // `-L` slices the per-line attributions to the requested range,
    // preserving the file's own 1-based line numbers in the output.
    let result = match &opts.lines {
        Some(spec) => match parse_line_range(spec, result.lines.len()) {
            Ok((start, end)) => BlameResult {
                lines: result.lines[start - 1..end].to_vec(),
            },
            Err(msg) => return emit_err(&format!("file {file}: {msg}"), exit::USAGE),
        },
        None => result,
    };

    if json {
        render_json(&result)
    } else {
        let text = format_blame_text(&result);
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(text.as_bytes());
        exit::OK
    }
}

/// Parse a `git blame -L` style range spec into an inclusive, 1-based
/// `(start, end)` pair validated against `total` (the file's line count).
///
/// Accepted forms — `<start>,<end>`, `<start>,+<n>`, `<start>,`,
/// `,<end>`, and a bare `<start>` (treated as `<start>,` → to EOF).
/// An omitted start defaults to line 1; an omitted end to `total`.
/// To match git: an inverted range (`start > end`) is swapped, and an
/// end past EOF is clamped to `total`. A start past EOF, a zero/empty
/// start, or a non-numeric token is an error.
///
/// Returns `Err(message)` with a git-flavored diagnostic on bad input.
fn parse_line_range(spec: &str, total: usize) -> Result<(usize, usize), String> {
    let (start_tok, end_tok) = match spec.split_once(',') {
        Some((s, e)) => (s.trim(), Some(e.trim())),
        None => (spec.trim(), None),
    };

    // Start: defaults to 1 when omitted (the `,<end>` form). An explicit
    // `0` is rejected here; git: `fatal: -L invalid line number: 0`.
    let start = if start_tok.is_empty() {
        1
    } else {
        parse_one_based(start_tok)?
    };

    // End: omitted or empty → EOF; `+<n>` → n lines from start; else an
    // absolute, also-1-based line number (`,0` / `3,0` are rejected).
    let end = match end_tok {
        None | Some("") => total,
        Some(tok) if tok.starts_with('+') => {
            let n = parse_line_num(&tok[1..])?;
            if n == 0 {
                return Err("line count after '+' must be at least 1".to_string());
            }
            // n lines starting at `start`, inclusive: `+2` from 3 → 3,4.
            start.saturating_add(n - 1)
        }
        Some(tok) => parse_one_based(tok)?,
    };

    // git swaps an inverted range rather than erroring.
    let (start, mut end) = if start > end {
        (end, start)
    } else {
        (start, end)
    };

    // Validate the final bounds after the swap. Zero tokens are rejected
    // above, so this is belt-and-suspenders against an internal slip —
    // but it must be a real error, not a debug assert: in release the
    // `lines[start - 1..end]` slice would underflow and panic on start 0.
    if start == 0 || end == 0 {
        return Err("invalid -L line number: 0".to_string());
    }
    if total == 0 {
        return Err("has only 0 lines".to_string());
    }
    if start > total {
        return Err(format!("has only {total} lines"));
    }
    // Clamp an over-long end to EOF, like git.
    if end > total {
        end = total;
    }
    Ok((start, end))
}

/// Parse a single decimal line-number token, rejecting empty/non-numeric
/// input with a git-flavored message.
fn parse_line_num(tok: &str) -> Result<usize, String> {
    tok.parse::<usize>()
        .map_err(|_| format!("invalid line number '{tok}' in -L range"))
}

/// Parse a 1-based line-number token, rejecting both non-numeric input
/// and an explicit `0`, mirroring git's `-L invalid line number: 0`.
fn parse_one_based(tok: &str) -> Result<usize, String> {
    let n = parse_line_num(tok)?;
    if n == 0 {
        return Err("invalid -L line number: 0".to_string());
    }
    Ok(n)
}

/// JSONL output for `--format=json`. One record per source line:
///
/// ```json
/// {"hash":"<64-hex>","line_num":<int>,"author":"<identity>","timestamp":<int>,"text":"<line>"}
/// ```
fn render_json(result: &BlameResult) -> u8 {
    let mut stdout = std::io::stdout().lock();
    for line in &result.lines {
        let _ = stdout.write_all(b"{");
        let _ = write!(
            stdout,
            "\"hash\":\"{}\"",
            format::hex_hash(&line.commit_hash)
        );
        let _ = write!(stdout, ",\"line_num\":{}", line.line_num);
        let _ = write!(
            stdout,
            ",\"author\":\"{}\"",
            format::json_escape(&format::full_identity(&line.author))
        );
        let _ = write!(stdout, ",\"timestamp\":{}", line.timestamp);
        // Line text may contain arbitrary bytes from the source file.
        // Render via lossy UTF-8 — the original bytes are recoverable
        // via the default tab format for callers that care.
        let text = String::from_utf8_lossy(&line.text);
        let _ = write!(stdout, ",\"text\":\"{}\"", format::json_escape(&text));
        let _ = stdout.write_all(b"}\n");
    }
    exit::OK
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::parse_line_range;

    // Semantics here are pinned against real `git blame -L` behavior
    // (verified empirically): inclusive bounds, `+n` = n lines, bare
    // start runs to EOF, inverted ranges swap, over-long ends clamp.

    #[test]
    fn explicit_range_is_inclusive() {
        assert_eq!(parse_line_range("3,5", 8), Ok((3, 5)));
    }

    #[test]
    fn plus_n_is_n_lines_from_start() {
        // `git blame -L 3,+2` → lines 3,4.
        assert_eq!(parse_line_range("3,+2", 8), Ok((3, 4)));
        assert_eq!(parse_line_range("1,+1", 8), Ok((1, 1)));
    }

    #[test]
    fn open_ended_start_runs_to_eof() {
        assert_eq!(parse_line_range("4,", 8), Ok((4, 8)));
    }

    #[test]
    fn bare_start_runs_to_eof() {
        // `git blame -L 3` → 3..EOF.
        assert_eq!(parse_line_range("3", 8), Ok((3, 8)));
    }

    #[test]
    fn open_ended_end_starts_at_one() {
        assert_eq!(parse_line_range(",3", 8), Ok((1, 3)));
    }

    #[test]
    fn inverted_range_is_swapped() {
        // `git blame -L 5,2` → 2..5.
        assert_eq!(parse_line_range("5,2", 8), Ok((2, 5)));
    }

    #[test]
    fn end_past_eof_is_clamped() {
        assert_eq!(parse_line_range("3,99", 8), Ok((3, 8)));
    }

    #[test]
    fn start_past_eof_errors() {
        let err = parse_line_range("99,100", 8).unwrap_err();
        assert!(err.contains("only 8 lines"), "got {err:?}");
    }

    #[test]
    fn empty_file_errors() {
        assert!(parse_line_range("1,", 0).is_err());
    }

    #[test]
    fn zero_start_errors() {
        assert!(parse_line_range("0,5", 8).is_err());
    }

    #[test]
    fn zero_end_errors_without_panicking() {
        // Regression: `,0` defaults start to 1, parses end 0, then the
        // inverted-range swap used to yield start == 0 and panic the
        // debug assertion (and underflow the slice in release). git:
        // `fatal: -L invalid line number: 0`.
        for spec in [",0", "3,0", "0,0"] {
            let err = parse_line_range(spec, 8).unwrap_err();
            assert!(
                err.contains("invalid -L line number: 0"),
                "spec {spec:?} → {err:?}"
            );
        }
    }

    #[test]
    fn non_numeric_errors() {
        assert!(parse_line_range("a,b", 8).is_err());
        assert!(parse_line_range("3,+x", 8).is_err());
    }

    #[test]
    fn zero_plus_offset_errors() {
        assert!(parse_line_range("3,+0", 8).is_err());
    }
}
