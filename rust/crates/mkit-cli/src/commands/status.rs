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
//! ## `--porcelain[=v1]` output
//!
//! Compatible with `git status --porcelain` — one entry per line,
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
//! Empty stdout means "nothing to commit, working tree clean."

use std::io::Write;

use mkit_core::index;
use mkit_core::object::Object;
use mkit_core::ops::{DiffKind, StatusEntry, StatusStaging, status_diff};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let mut porcelain = false;
    for a in args {
        match a.as_str() {
            "--porcelain" | "--porcelain=v1" => porcelain = true,
            other => {
                return super::usage_error(&format!("unknown flag for status: {other}"));
            }
        }
    }

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

    // Load the index, falling back to None when absent/empty.
    let idx = index::read_index(&cwd)
        .ok()
        .filter(|idx| !idx.entries.is_empty());

    let entries = match status_diff(&store, head_tree.as_ref(), &cwd, idx.as_ref()) {
        Ok(e) => e,
        Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
    };

    if porcelain {
        render_porcelain(&entries)
    } else {
        render_human(&mkit_dir, &entries)
    }
}

/// `--porcelain[=v1]` output — line-oriented XY-code-plus-path, one
/// entry per line. Empty stdout means clean. Matches `git status
/// --porcelain` for the codes mkit and git share; `T ` (`ModeChanged`)
/// is the only non-git extension.
fn render_porcelain(entries: &[StatusEntry]) -> u8 {
    let mut stdout = std::io::stdout().lock();
    for e in entries {
        let code = porcelain_code(e.staging, e.diff.kind);
        let _ = writeln!(stdout, "{code} {}", e.diff.path);
    }
    exit::OK
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
