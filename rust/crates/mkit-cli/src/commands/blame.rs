//! `mkit blame <file>` — line-level attribution against HEAD.
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

use std::io::Write;

use mkit_core::ops::blame::{BlameResult, blame_file, format_blame_text};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let (file, json) = match parse_args(args) {
        Ok(v) => v,
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
    let head = match refs::resolve_head(&mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits yet", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let result = match blame_file(&store, head, file) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("blame: {e}"), exit::NOINPUT),
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

fn parse_args(args: &[String]) -> Result<(&str, bool), u8> {
    let mut file: Option<&str> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format=json" => json = true,
            "--format" if i + 1 < args.len() => {
                match args[i + 1].as_str() {
                    "json" => json = true,
                    "default" => json = false,
                    other => {
                        return Err(super::usage_error(&format!(
                            "unknown --format value: {other} (expected: default, json)"
                        )));
                    }
                }
                i += 1;
            }
            other if !other.starts_with("--") && file.is_none() => {
                file = Some(other);
            }
            other => {
                return Err(super::usage_error(&format!(
                    "unknown argument for blame: {other}"
                )));
            }
        }
        i += 1;
    }
    let Some(f) = file else {
        return Err(super::usage_error(
            "usage: mkit blame [--format=json] <file>",
        ));
    };
    Ok((f, json))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
