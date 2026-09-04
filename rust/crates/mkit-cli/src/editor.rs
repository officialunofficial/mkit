//! `$EDITOR` / `$VISUAL` spawn helper for `mkit commit`.
//!
//! Behaviour:
//! * Honour `$GIT_EDITOR` first, then `$EDITOR`, then `$VISUAL`.
//! * Fall back to `vi` when no env var is set, so `mkit commit` works
//!   out-of-the-box.
//! * Write `template` to a tempfile, spawn the editor, wait, read the
//!   file back, strip any line whose first non-whitespace byte is `#`,
//!   and return the trimmed message.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::Command;

/// Maximum commit-message file size read back from the editor (1 MiB).
pub const MAX_COMMIT_MSG_BYTES: u64 = 1024 * 1024;

/// Spawn the user's editor on a tempfile pre-populated with `template`,
/// then read the file back, strip `#`-comment lines, and return the
/// trimmed result.
///
/// The editor is chosen in this order:
/// 1. `$GIT_EDITOR`
/// 2. `$EDITOR`
/// 3. `$VISUAL`
/// 4. platform default (`vi`)
///
/// The editor invocation parses the chosen value as a shell-like
/// command: the first whitespace-separated token is the program, the
/// rest are arguments, and the tempfile path is appended as a final
/// argument. This matches how `git`'s `GIT_EDITOR` is conventionally
/// parsed (e.g. `EDITOR="vim -c 'set nowrap'"`).
///
/// # Errors
/// - [`io::ErrorKind::NotFound`] if the editor binary cannot be spawned.
/// - [`io::ErrorKind::Other`] with a descriptive message if the editor
///   exits non-zero or the file exceeds [`MAX_COMMIT_MSG_BYTES`].
pub fn spawn_editor(template: &str) -> io::Result<String> {
    let editor = pick_editor();
    if editor.is_empty() {
        return Err(io::Error::other(
            "no editor configured; set $EDITOR or pass -m <msg>",
        ));
    }

    // Write template to a tempfile. We use `tempfile` to get a
    // predictable cleanup path — the file's dropped when `file` goes
    // out of scope even if the editor crashed.
    let tmp = tempfile::NamedTempFile::with_suffix(".mkit-commit.txt")?;
    {
        let mut f = fs::OpenOptions::new().write(true).open(tmp.path())?;
        f.write_all(template.as_bytes())?;
        f.sync_all()?;
    }

    // Parse the editor string into [program, args...] and append the
    // tempfile path. Whitespace-split is intentionally crude — quoted
    // arguments with embedded whitespace are rare in practice and
    // require a full shell to handle correctly. The test suite uses
    // the simple `sh -c '…' sh` idiom which works under this split.
    let mut parts = editor.split_whitespace();
    let program = parts.next().unwrap_or("");
    let extra_args: Vec<&str> = parts.collect();
    let path_arg: PathBuf = tmp.path().to_path_buf();

    let status = Command::new(program)
        .args(&extra_args)
        .arg(&path_arg)
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "editor exited with status {status:?}"
        )));
    }

    // Read the file back. Bounded to MAX_COMMIT_MSG_BYTES.
    let f = fs::File::open(tmp.path())?;
    let mut buf = Vec::new();
    f.take(MAX_COMMIT_MSG_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io::Error::other)?;
    if buf.len() as u64 > MAX_COMMIT_MSG_BYTES {
        return Err(io::Error::other("commit message file too large (>1 MiB)"));
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();
    Ok(strip_comments_and_trim(&raw))
}

/// Pick an editor from the environment. Returns an empty string if
/// nothing usable is set AND no platform default applies.
fn pick_editor() -> String {
    pick_editor_with(|name| std::env::var(name).ok())
}

/// Test-friendly variant of [`pick_editor`] — `resolver` is called
/// once per candidate env var, and the first non-empty trimmed value
/// wins. On a fully-empty environment, falls back to the platform
/// default (`vi`).
fn pick_editor_with(resolver: impl Fn(&str) -> Option<String>) -> String {
    for var in ["GIT_EDITOR", "EDITOR", "VISUAL"] {
        if let Some(v) = resolver(var)
            && !v.trim().is_empty()
        {
            return v;
        }
    }
    "vi".to_string()
}

/// Strip all lines whose first non-whitespace byte is `#`, then trim
/// trailing whitespace.
#[must_use]
pub fn strip_comments_and_trim(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split('\n') {
        let first_nws = line.trim_start();
        if first_nws.starts_with('#') {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out.trim_matches(|c: char| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .to_string()
}

/// Template rendered into the tempfile before spawning the editor.
pub const COMMIT_EDITMSG_TEMPLATE: &str = "\n\
# Please enter the commit message for your changes. Lines starting\n\
# with '#' will be ignored, and an empty message aborts the commit.\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comments_drops_hash_lines() {
        let input = "\nhello\n# a comment\nworld\n   # indented comment\n\n";
        let out = strip_comments_and_trim(input);
        assert_eq!(out, "hello\nworld");
    }

    #[test]
    fn strip_comments_all_comment_yields_empty() {
        let out = strip_comments_and_trim("# foo\n# bar\n");
        assert!(out.is_empty());
    }

    #[test]
    fn strip_comments_trims_trailing_crlf() {
        let out = strip_comments_and_trim("hello\r\n# drop\r\n\r\n");
        assert_eq!(out, "hello");
    }

    #[test]
    fn pick_editor_prefers_git_editor_over_editor() {
        let got = pick_editor_with(|name| match name {
            "GIT_EDITOR" => Some("from-git".to_string()),
            "EDITOR" => Some("from-editor".to_string()),
            _ => None,
        });
        assert_eq!(got, "from-git");
    }

    #[test]
    fn pick_editor_prefers_editor_over_visual() {
        let got = pick_editor_with(|name| match name {
            "EDITOR" => Some("from-editor".to_string()),
            "VISUAL" => Some("from-visual".to_string()),
            _ => None,
        });
        assert_eq!(got, "from-editor");
    }

    #[test]
    fn pick_editor_skips_empty_strings() {
        let got = pick_editor_with(|name| match name {
            "GIT_EDITOR" => Some(String::new()),
            "EDITOR" => Some("   ".to_string()),
            "VISUAL" => Some("nano".to_string()),
            _ => None,
        });
        assert_eq!(got, "nano");
    }

    #[test]
    fn pick_editor_falls_back_to_platform_default() {
        let got = pick_editor_with(|_| None);
        assert_eq!(got, "vi");
    }
}
