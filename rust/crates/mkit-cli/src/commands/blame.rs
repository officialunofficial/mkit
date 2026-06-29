//! `mkit blame [-w] [<rev>] [-L <range>] <file>` — line-level attribution.
//!
//! Blames `<file>` as of `<rev>` (default `HEAD`), optionally restricted
//! to a line range with `-L`. `-w` ignores whitespace when matching
//! lines across revisions (git `-w`).
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
use mkit_core::ops::blame::{BlameOptions, BlameResult, blame_file_with, format_blame_text};
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
    /// Ignore whitespace when matching lines across revisions, like
    /// `git blame -w`, so a whitespace-only edit (reindent, tab↔space,
    /// spacing tweak) doesn't reattribute the line. Output still shows
    /// the file's current bytes.
    #[arg(short = 'w', long = "ignore-whitespace")]
    ignore_whitespace: bool,
    /// Restrict output to a line range, like `git blame -L`. Accepts
    /// `<start>,<end>`, `<start>,+<n>` (n lines forward), `<start>,-<n>`
    /// (n lines back, ending at start), `<start>,` (start to EOF),
    /// `,<end>` (start of file to end), or a bare `<start>` (start to
    /// EOF). Lines are 1-based and inclusive; an inverted range is
    /// swapped and an over-long end is clamped to EOF, matching git.
    // `allow_hyphen_values` so a pathological negative start (`-3,5`)
    // reaches the parser for a git-faithful diagnostic instead of clap
    // mistaking `-3` for a flag. Valid values never start with `-` (the
    // `-<n>` offset is always the second field).
    #[arg(
        short = 'L',
        long = "lines",
        value_name = "START,END",
        allow_hyphen_values = true
    )]
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

    let blame_opts = BlameOptions {
        ignore_whitespace: opts.ignore_whitespace,
    };
    let result = match blame_file_with(&store, head, file, &blame_opts) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("blame: {e}"), exit::NOINPUT),
    };

    // `-L` slices the per-line attributions to the requested range,
    // preserving the file's own 1-based line numbers in the output.
    let result = match &opts.lines {
        Some(spec) => match parse_line_range(spec, result.lines.len(), file) {
            Ok((start, end)) => BlameResult {
                lines: result.lines[start - 1..end].to_vec(),
            },
            // The message is already git-faithful and self-contained
            // (it carries `file` where git does), so it prints verbatim.
            Err(msg) => return emit_err(&msg, exit::USAGE),
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
/// `file` only feeds git-faithful "has only N lines" diagnostics.
///
/// Accepted forms — `<start>,<end>`, `<start>,+<n>` (n lines forward),
/// `<start>,-<n>` (n lines back, ending at `<start>`), `<start>,`,
/// `,<end>`, and a bare `<start>` (treated as `<start>,` → to EOF).
/// An omitted start defaults to line 1; an omitted end to `total`.
/// To match git: an inverted absolute range (`5,2`) is swapped, a low
/// bound past EOF errors `file <f> has only N lines`, and an over-long
/// high bound is clamped to `total`. A zero/negative line number errors
/// `-L invalid line number: <tok>` and a zero offset `-L invalid empty
/// range`.
///
/// Returns `Err(message)` with a git-faithful diagnostic on bad input.
fn parse_line_range(spec: &str, total: usize, file: &str) -> Result<(usize, usize), String> {
    let (start_tok, end_tok) = match spec.split_once(',') {
        Some((s, e)) => (s.trim(), Some(e.trim())),
        None => (spec.trim(), None),
    };

    // Start anchor: defaults to 1 when omitted (the `,<end>` form).
    let start = if start_tok.is_empty() {
        1
    } else {
        parse_one_based(start_tok)?
    };

    // Resolve the inclusive `(lo, hi)` bounds from the end token. git's
    // end forms:
    //   omitted / empty  → to EOF
    //   absolute `<m>`   → swap with start if inverted (`5,2` → 2..5)
    //   `+<n>`           → n lines forward from start (`5,+2` → 5..6)
    //   `-<n>`           → n lines back, *ending* at start (`5,-2` → 4..5),
    //                      the low bound clamped up to line 1
    // A `+0` / `-0` offset is an empty range.
    let (lo, hi) = match end_tok {
        None | Some("") => (start, total),
        Some(tok) if tok.starts_with('+') => (start, start.saturating_add(parse_offset(tok)? - 1)),
        Some(tok) if tok.starts_with('-') => {
            let n = parse_offset(tok)?;
            (start.saturating_sub(n - 1).max(1), start)
        }
        Some(tok) => {
            let m = parse_one_based(tok)?;
            if start > m { (m, start) } else { (start, m) }
        }
    };

    // Empty file: no blamable lines. Checked *after* token validation so
    // an explicit zero / empty-range token reports its own error first,
    // matching git for every form.
    if total == 0 {
        return Err(format!("file {file} has only 0 lines"));
    }

    // git validates the low bound (the actual range start) against EOF for
    // every form — including `-<n>`, whose anchor may itself sit past EOF —
    // and clamps an over-long high bound down to the last line. `lo >= 1`
    // here by construction, so the `lines[lo - 1..hi]` slice is safe.
    if lo > total {
        return Err(format!("file {file} has only {total} lines"));
    }
    Ok((lo, hi.min(total)))
}

/// Parse a single decimal line-number token. Junk (non-integer) gets a
/// clear mkit diagnostic; git instead dumps usage here.
fn parse_line_num(tok: &str) -> Result<usize, String> {
    tok.parse::<usize>()
        .map_err(|_| format!("invalid line number '{tok}' in -L range"))
}

/// Parse a 1-based absolute line number, rejecting `0` and negatives the
/// way git does: a parseable-but-invalid integer (e.g. `0`, `-3`) yields
/// `-L invalid line number: <tok>`, while non-integer junk keeps the
/// clearer [`parse_line_num`] message.
fn parse_one_based(tok: &str) -> Result<usize, String> {
    match tok.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        // `0`, or (via the usize parse failing) a negative integer.
        _ if tok.parse::<i64>().is_ok() => Err(format!("-L invalid line number: {tok}")),
        _ => Err(format!("invalid line number '{tok}' in -L range")),
    }
}

/// Parse the `<n>` in a `+<n>` / `-<n>` end offset (the leading sign is
/// included in `tok`). A zero offset is git's `-L invalid empty range`.
fn parse_offset(tok: &str) -> Result<usize, String> {
    let n = parse_line_num(&tok[1..])?;
    if n == 0 {
        return Err("-L invalid empty range".to_string());
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
    // Semantics here are pinned against real `git blame -L` behavior
    // (verified empirically): inclusive bounds, `+n` = n lines, bare
    // start runs to EOF, inverted ranges swap, over-long ends clamp.

    /// Thin wrapper supplying a fixed filename so the range cases read
    /// cleanly; the filename only colors the "has only N lines" message.
    fn range(spec: &str, total: usize) -> Result<(usize, usize), String> {
        super::parse_line_range(spec, total, "f.txt")
    }

    #[test]
    fn explicit_range_is_inclusive() {
        assert_eq!(range("3,5", 8), Ok((3, 5)));
    }

    #[test]
    fn plus_n_is_n_lines_from_start() {
        // `git blame -L 3,+2` → lines 3,4.
        assert_eq!(range("3,+2", 8), Ok((3, 4)));
        assert_eq!(range("1,+1", 8), Ok((1, 1)));
    }

    #[test]
    fn minus_n_is_n_lines_ending_at_start() {
        // `git blame -L <start>,-<n>` → n lines ending at start, low bound
        // clamped up to line 1. Verified against real git.
        assert_eq!(range("5,-2", 8), Ok((4, 5)));
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
        assert_eq!(range("3,-1", 8), Ok((3, 3)));
        assert_eq!(range("2,-5", 8), Ok((1, 2))); // clamps to line 1
    }

    #[test]
    fn minus_n_anchor_past_eof_still_validates_low_bound() {
        // `12,-3` on an 8-line file → [10,12] → low bound 10 > 8: error,
        // matching git (it validates the range start, not the anchor).
        assert!(range("12,-3", 8).unwrap_err().contains("only 8 lines"));
        // `8,-3` → [6,8] → fine; high bound already within EOF.
        assert_eq!(range("8,-3", 8), Ok((6, 8)));
    }

    #[test]
    fn open_ended_start_runs_to_eof() {
        assert_eq!(range("4,", 8), Ok((4, 8)));
    }

    #[test]
    fn bare_start_runs_to_eof() {
        // `git blame -L 3` → 3..EOF.
        assert_eq!(range("3", 8), Ok((3, 8)));
    }

    #[test]
    fn open_ended_end_starts_at_one() {
        assert_eq!(range(",3", 8), Ok((1, 3)));
    }

    #[test]
    fn inverted_range_is_swapped() {
        // `git blame -L 5,2` → 2..5.
        assert_eq!(range("5,2", 8), Ok((2, 5)));
    }

    #[test]
    fn end_past_eof_is_clamped() {
        assert_eq!(range("3,99", 8), Ok((3, 8)));
    }

    #[test]
    fn start_past_eof_errors() {
        let err = range("99,100", 8).unwrap_err();
        assert!(err.contains("only 8 lines"), "got {err:?}");
    }

    #[test]
    fn empty_file_message_is_git_faithful_for_every_form() {
        // git validates explicit line-number tokens *before* the
        // line-count check, so on an empty file the "has only 0 lines"
        // message applies only to forms without an explicit zero; an
        // explicit `0` (`,0` / `3,0`) still reports the invalid-zero error
        // first. Both halves are pinned against real git.
        for spec in ["1,", "3", "1,3", "2,5"] {
            let err = super::parse_line_range(spec, 0, "empty.txt").unwrap_err();
            assert_eq!(err, "file empty.txt has only 0 lines", "spec {spec:?}");
        }
        for spec in [",0", "3,0"] {
            let err = super::parse_line_range(spec, 0, "empty.txt").unwrap_err();
            assert_eq!(err, "-L invalid line number: 0", "spec {spec:?}");
        }
    }

    #[test]
    fn zero_start_errors() {
        assert_eq!(range("0,5", 8).unwrap_err(), "-L invalid line number: 0");
    }

    #[test]
    fn zero_line_number_uses_git_message() {
        // Regression: `,0` defaults start to 1, parses end 0, then the old
        // inverted-range swap yielded start == 0 and panicked. git reports
        // `-L invalid line number: 0` (exact word order) for every form
        // carrying an explicit zero.
        for spec in [",0", "3,0", "0,0", "0", "0,"] {
            assert_eq!(
                range(spec, 8).unwrap_err(),
                "-L invalid line number: 0",
                "spec {spec:?}"
            );
        }
    }

    #[test]
    fn negative_line_number_uses_git_message() {
        // A parseable-but-invalid integer reports its token, like git's
        // `-L invalid line number: -3` (negatives only valid as `-<n>`
        // *offsets*, handled separately).
        assert_eq!(range("-3,5", 8).unwrap_err(), "-L invalid line number: -3");
    }

    #[test]
    fn zero_offset_is_invalid_empty_range() {
        // git: `+0` / `-0` → `-L invalid empty range`.
        assert_eq!(range("3,+0", 8).unwrap_err(), "-L invalid empty range");
        assert_eq!(range("3,-0", 8).unwrap_err(), "-L invalid empty range");
    }

    #[test]
    fn non_numeric_errors() {
        // True junk keeps mkit's clearer message (git dumps usage here).
        assert!(range("a,b", 8).is_err());
        assert!(range("3,+x", 8).is_err());
    }
}
