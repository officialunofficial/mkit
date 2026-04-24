//! `mkit blame <file>` — line-level attribution against HEAD.
//!
//! Output is pinned against `rust/tests/golden/phase5b/blame_three_commit.txt`:
//! `<short12>\t<line_num>\t<text>\n` — emitted verbatim by
//! [`mkit_core::ops::blame::format_blame_text`].

use std::io::Write;

use mkit_core::ops::blame::{blame_file, format_blame_text};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let Some(file) = args.first() else {
        return super::usage_error("usage: mkit blame <file>");
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
    let text = format_blame_text(&result);
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
