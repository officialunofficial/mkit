//! `mkit status` — show working-tree changes relative to HEAD.
//!
//! ## Default (human) output
//!
//! ```text
//! on branch <name>           # to stderr  (or "detached HEAD at <hash>" / "no HEAD yet")
//!                            #
//! Changes to be committed:   # to stderr
//!   A  added.txt             # to stderr
//!   D  deleted.txt           # to stderr
//!
//! Changes not staged for commit:    # to stderr
//!   M  modified.txt                 # to stderr
//! ```
//!
//! Banners and section headers go to stderr; per-file lines also go to
//! stderr in default mode because they are formatted for humans.
//! Scripts should use `--porcelain` (see below) for stdout output
//! that is safe to parse.
//!
//! ## `--porcelain[=v1]` / `-s` (`--short`) output
//!
//! `-s`/`--short` is an alias for `--porcelain=v1`; both select the
//! same renderer. Compatible with `git status --porcelain` — one entry
//! per line,
//! two-character XY status code, space, path:
//!
//! ```text
//! M  modified-staged.txt
//!  M unstaged-edit.txt
//! A  newly-staged.txt
//! ?? untracked.txt
//! ```
//!
//! `X` is the staged-vs-HEAD state; `Y` is the worktree-vs-index
//! state. mkit's `DiffKind::ModeChanged` renders as `T` (a non-git
//! extension). `??` is the conventional code for untracked files.
//!
//! Paths containing special bytes are C-style quoted (matching git's
//! default `core.quotePath`). With `-z`, records are NUL-terminated and
//! paths are emitted raw (unquoted) — the round-trip-safe form for paths
//! with newlines or other special bytes; `-z` implies porcelain.
//!
//! Empty stdout means "nothing to commit, working tree clean."

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::index;
use mkit_core::object::Object;
use mkit_core::ops::{DiffKind, StatusEntry, StatusStaging, status_diff};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PorcelainVersion {
    V1,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit status",
    about = "Show working-tree changes relative to HEAD."
)]
struct StatusOpts {
    /// Emit machine-readable XY-code-plus-path on stdout. Default
    /// `v1` matches `git status --porcelain=v1`.
    #[arg(long, value_name = "VERSION", num_args = 0..=1, default_missing_value = "v1")]
    porcelain: Option<PorcelainVersion>,

    /// Short format. Alias for `--porcelain=v1`: emits the same
    /// XY-code-plus-path lines on stdout.
    #[arg(short = 's', long = "short")]
    short: bool,

    /// NUL-terminate entries instead of newline, and emit raw (unquoted)
    /// paths — like `git status -z`. Implies porcelain output. Without
    /// `-z`, paths with special bytes are C-style quoted.
    #[arg(short = 'z')]
    z: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<StatusOpts>("mkit status", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // `-s`/`--short` is an alias for `--porcelain=v1`; `-z` also implies
    // porcelain output. All select the line-oriented XY renderer on stdout.
    let porcelain = opts.porcelain.is_some() || opts.short || opts.z;

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // Resolve HEAD tree hash (None on a HEAD-less repo).
    let head_tree: Option<mkit_core::Hash> = match refs::resolve_head(&mkit_dir) {
        Ok(Some(commit_hash)) => match store.read_object(&commit_hash) {
            Ok(Object::Commit(c)) => Some(c.tree_hash),
            _ => None,
        },
        _ => None,
    };

    // Load the index, falling back to None only when absent/empty.
    // Corrupt or invalid persisted state must surface instead of
    // silently reverting to the HEAD<->worktree comparison.
    let idx = match index::read_index(&cwd) {
        Ok(idx) if idx.entries.is_empty() => None,
        Ok(idx) => Some(idx),
        Err(e) => return emit_err(&format!("read index: {e}"), exit::GENERAL_ERROR),
    };

    let entries = match status_diff(&store, head_tree.as_ref(), &cwd, idx.as_ref()) {
        Ok(e) => e,
        Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
    };

    if porcelain {
        render_porcelain(&entries, opts.z)
    } else {
        render_human(&mkit_dir, &entries)
    }
}

/// `--porcelain[=v1]` output — XY-code-plus-path, one entry per record.
/// Empty stdout means clean. Matches `git status --porcelain` for the
/// codes mkit and git share; `T ` (`ModeChanged`) is the only non-git
/// extension.
///
/// With `z = false` (default), records are newline-terminated and a path
/// containing special bytes is C-style quoted (matching git's default
/// `core.quotePath`). With `z = true` (`-z`), records are NUL-terminated
/// and paths are emitted **raw** (unquoted) — the round-trip-safe form
/// for paths that contain newlines or other special bytes.
fn render_porcelain(entries: &[StatusEntry], z: bool) -> u8 {
    let mut stdout = std::io::stdout().lock();
    for (xy, path) in combine_porcelain(entries) {
        // `xy` is two ASCII status columns by construction.
        let code = std::str::from_utf8(&xy).unwrap_or("??");
        if z {
            let _ = write!(stdout, "{code} {path}\0");
        } else if let Some(quoted) = c_quote_path(path) {
            let _ = writeln!(stdout, "{code} {quoted}");
        } else {
            let _ = writeln!(stdout, "{code} {path}");
        }
    }
    exit::OK
}

/// Collapse `status_diff`'s per-(staging) entries into one `XY` record
/// per path, matching `git status --porcelain`. A path that is staged
/// **and** further changed in the worktree produces a single combined
/// code (e.g. `MM`, `AM`) rather than two records. `X` is the staged
/// (index-vs-HEAD) side, `Y` the unstaged (worktree-vs-index) side;
/// `porcelain_code` already returns each side in its column, so we OR the
/// non-space columns together. First-seen path order is preserved.
fn combine_porcelain(entries: &[StatusEntry]) -> Vec<([u8; 2], &str)> {
    let mut order: Vec<&str> = Vec::new();
    let mut codes: std::collections::HashMap<&str, [u8; 2]> = std::collections::HashMap::new();
    for e in entries {
        let c = porcelain_code(e.staging, e.diff.kind).as_bytes();
        let slot = codes.entry(&e.diff.path).or_insert_with(|| {
            order.push(&e.diff.path);
            [b' ', b' ']
        });
        // Fill each column from whichever entry sets it (non-space wins).
        if c[0] != b' ' {
            slot[0] = c[0];
        }
        if c[1] != b' ' {
            slot[1] = c[1];
        }
    }
    order.into_iter().map(|p| (codes[p], p)).collect()
}

/// C-style-quote `path` the way Git does for porcelain output when a path
/// contains bytes that need escaping. Returns `None` when the path is
/// "plain" (all printable ASCII except `"`/`\`) and can be emitted as-is.
///
/// Quoting rule (matches Git's `quote_c_style` with the default
/// `core.quotePath=true`): quote if any byte is a control char (`< 0x20`),
/// `"`, `\`, or non-printable / non-ASCII (`>= 0x7f`). Inside the quotes,
/// the common control chars use their `\a\b\t\n\v\f\r` escapes, `"` and
/// `\` are backslash-escaped, printable ASCII is literal, and everything
/// else is a 3-digit `\NNN` octal escape (per UTF-8 byte).
fn c_quote_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let needs = bytes
        .iter()
        .any(|&b| b < 0x20 || b == b'"' || b == b'\\' || b >= 0x7f);
    if !needs {
        return None;
    }
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0a => out.push_str("\\n"),
            0x0b => out.push_str("\\v"),
            0x0c => out.push_str("\\f"),
            0x0d => out.push_str("\\r"),
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            other => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\{other:03o}");
            }
        }
    }
    out.push('"');
    Some(out)
}

/// Map (staging, kind) → two-char XY code per the porcelain format.
fn porcelain_code(staging: StatusStaging, kind: DiffKind) -> &'static str {
    match (staging, kind) {
        (StatusStaging::Staged, DiffKind::Added) => "A ",
        (StatusStaging::Staged, DiffKind::Removed) => "D ",
        (StatusStaging::Staged, DiffKind::Modified) => "M ",
        (StatusStaging::Staged, DiffKind::ModeChanged) => "T ",
        // Unstaged Added with an index present means the worktree has
        // a path the index doesn't know about — i.e. untracked. With
        // no index, every worktree-only entry is also untracked.
        (StatusStaging::Unstaged, DiffKind::Added) => "??",
        (StatusStaging::Unstaged, DiffKind::Removed) => " D",
        (StatusStaging::Unstaged, DiffKind::Modified) => " M",
        (StatusStaging::Unstaged, DiffKind::ModeChanged) => " T",
        // PartiallyStaged is documented as retained-for-back-compat
        // and no longer produced by status_diff post-#102, but render
        // defensively in case it ever resurfaces. `MM` matches git's
        // double-mod indicator.
        (StatusStaging::PartiallyStaged, DiffKind::Added) => "AM",
        (StatusStaging::PartiallyStaged, DiffKind::Removed) => "MD",
        (StatusStaging::PartiallyStaged, DiffKind::Modified) => "MM",
        (StatusStaging::PartiallyStaged, DiffKind::ModeChanged) => "MT",
    }
}

/// Default human output. All lines go to stderr — stdout is reserved
/// for porcelain/data callers. A consumer that wants the human format
/// in a pipeline can `mkit status 2>&1` explicitly; the default
/// pipeline behaviour stays empty-on-clean.
fn render_human(mkit_dir: &std::path::Path, entries: &[StatusEntry]) -> u8 {
    let mut stderr = std::io::stderr().lock();

    // Branch / HEAD line.
    match refs::read_head(mkit_dir) {
        Ok(refs::Head::Branch(name)) => {
            let _ = writeln!(stderr, "on branch {name}");
        }
        Ok(refs::Head::Detached(h)) => {
            let _ = writeln!(stderr, "detached HEAD at {}", mkit_core::hash::to_hex(&h));
        }
        Err(_) => {
            let _ = writeln!(stderr, "no HEAD yet");
        }
    }

    if entries.is_empty() {
        let _ = writeln!(stderr, "nothing to commit, working tree clean");
        return exit::OK;
    }

    let staged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Staged)
        .collect();
    let unstaged: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::Unstaged)
        .collect();
    let partial: Vec<_> = entries
        .iter()
        .filter(|e| e.staging == StatusStaging::PartiallyStaged)
        .collect();

    if !staged.is_empty() {
        let _ = writeln!(stderr, "\nChanges to be committed:");
        for e in &staged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }
    if !unstaged.is_empty() {
        let _ = writeln!(stderr, "\nChanges not staged for commit:");
        for e in &unstaged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }
    if !partial.is_empty() {
        let _ = writeln!(stderr, "\nChanges partially staged:");
        for e in &partial {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stderr, "  {tag}  {}", e.diff.path);
        }
    }

    exit::OK
}

fn diff_tag(kind: DiffKind) -> &'static str {
    match kind {
        DiffKind::Added => "A",
        DiffKind::Removed => "D",
        DiffKind::Modified => "M",
        DiffKind::ModeChanged => "T",
    }
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
    fn porcelain_code_matrix() {
        // Spot-check the matrix corners.
        assert_eq!(porcelain_code(StatusStaging::Staged, DiffKind::Added), "A ",);
        assert_eq!(
            porcelain_code(StatusStaging::Staged, DiffKind::Removed),
            "D ",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Staged, DiffKind::Modified),
            "M ",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Added),
            "??",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Modified),
            " M",
        );
        assert_eq!(
            porcelain_code(StatusStaging::Unstaged, DiffKind::Removed),
            " D",
        );
    }

    #[test]
    fn c_quote_leaves_plain_paths_alone() {
        assert_eq!(c_quote_path("a.txt"), None);
        assert_eq!(c_quote_path("dir/with space.txt"), None); // space is plain
        assert_eq!(c_quote_path("weird-but-ascii_!@#$%.rs"), None);
    }

    #[test]
    fn c_quote_escapes_special_bytes() {
        assert_eq!(c_quote_path("a\tb.txt").as_deref(), Some(r#""a\tb.txt""#));
        assert_eq!(
            c_quote_path("line\nfeed").as_deref(),
            Some(r#""line\nfeed""#)
        );
        assert_eq!(c_quote_path("q\"x").as_deref(), Some(r#""q\"x""#));
        assert_eq!(
            c_quote_path("back\\slash").as_deref(),
            Some(r#""back\\slash""#)
        );
    }

    #[test]
    fn c_quote_octal_escapes_non_ascii() {
        // "é" is UTF-8 0xC3 0xA9 → \303\251 (matches git core.quotePath).
        assert_eq!(c_quote_path("é").as_deref(), Some(r#""\303\251""#));
        // Combined with ASCII: only the non-ASCII bytes are octal-escaped.
        assert_eq!(c_quote_path("x-é").as_deref(), Some(r#""x-\303\251""#));
    }

    fn entry(path: &str, staging: StatusStaging, kind: DiffKind) -> StatusEntry {
        StatusEntry {
            diff: mkit_core::ops::DiffEntry {
                path: path.to_string(),
                kind,
                old_hash: None,
                new_hash: None,
            },
            staging,
        }
    }

    fn combined(entries: &[StatusEntry]) -> Vec<(String, String)> {
        combine_porcelain(entries)
            .into_iter()
            .map(|(xy, p)| (std::str::from_utf8(&xy).unwrap().to_string(), p.to_string()))
            .collect()
    }

    #[test]
    fn combine_merges_staged_and_unstaged_same_path_into_one_record() {
        use DiffKind::Modified;
        use StatusStaging::{Staged, Unstaged};
        // Staged modify + further worktree modify on the same path → one
        // `MM a.txt` record, not two (git porcelain semantics).
        let entries = [
            entry("a.txt", Staged, Modified),
            entry("a.txt", Unstaged, Modified),
        ];
        assert_eq!(combined(&entries), vec![("MM".into(), "a.txt".into())]);
    }

    #[test]
    fn combine_staged_add_plus_worktree_modify_is_am() {
        let entries = [
            entry("n.txt", StatusStaging::Staged, DiffKind::Added),
            entry("n.txt", StatusStaging::Unstaged, DiffKind::Modified),
        ];
        assert_eq!(combined(&entries), vec![("AM".into(), "n.txt".into())]);
    }

    #[test]
    fn combine_preserves_lone_records_and_untracked() {
        let entries = [
            entry("staged.txt", StatusStaging::Staged, DiffKind::Added),
            entry("dirty.txt", StatusStaging::Unstaged, DiffKind::Modified),
            entry("new.txt", StatusStaging::Unstaged, DiffKind::Added), // untracked → ??
        ];
        assert_eq!(
            combined(&entries),
            vec![
                ("A ".into(), "staged.txt".into()),
                (" M".into(), "dirty.txt".into()),
                ("??".into(), "new.txt".into()),
            ]
        );
    }

    #[test]
    fn porcelain_codes_are_two_chars() {
        use DiffKind::{Added, ModeChanged, Modified, Removed};
        use StatusStaging::{PartiallyStaged, Staged, Unstaged};
        for s in [Staged, Unstaged, PartiallyStaged] {
            for k in [Added, Removed, Modified, ModeChanged] {
                assert_eq!(porcelain_code(s, k).len(), 2, "{s:?} + {k:?}");
            }
        }
    }
}
