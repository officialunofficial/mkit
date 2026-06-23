//! Shared git-shaped post-commit summary: the `[<branch> <hash>]
//! <subject>` headline, the diffstat, and the `create/delete mode`
//! trailers. Used by commit / cherry-pick / revert / merge so their
//! human output matches git's. All lines go to the caller-provided
//! writer (the commands route it to stderr, per mkit's channel rule).

use std::io::Write;

use mkit_core::hash::Hash;
use mkit_core::object::EntryMode;
use mkit_core::ops::{DiffKind, diff_trees};
use mkit_core::store::ObjectStore;

use crate::format;

/// Where HEAD points, for the summary headline.
#[derive(Debug)]
pub enum HeadRef<'a> {
    /// On a branch — `[<name> <hash>] <subject>`.
    Branch(&'a str),
    /// Detached HEAD — `[detached HEAD <hash>] <subject>`.
    Detached,
}

/// Render git's post-commit summary on `out`:
/// ```text
/// [main (root-commit) 1a2b3c4] subject
///  2 files changed, 2 insertions(+)
///  create mode 100644 a.txt
/// ```
/// `old_tree`/`new_tree` bound the diffstat (`None` = the empty tree, e.g.
/// a root commit). The diffstat + mode trailers are best-effort: a failure
/// to compute them still leaves the `[...]` headline intact. Object ids are
/// BLAKE3 prefixes (the documented hash-length divergence).
pub fn print_commit_summary(
    out: &mut impl Write,
    store: &ObjectStore,
    head: &HeadRef,
    hash: &Hash,
    subject: &str,
    is_root: bool,
    old_tree: Option<Hash>,
    new_tree: Option<Hash>,
) {
    let short = format::short_hash(hash, format::SUMMARY_ABBREV);
    let head_part = match head {
        HeadRef::Detached => format!("detached HEAD {short}"),
        HeadRef::Branch(b) if is_root => format!("{b} (root-commit) {short}"),
        HeadRef::Branch(b) => format!("{b} {short}"),
    };
    let _ = writeln!(out, "[{head_part}] {subject}");
    let Ok(result) = diff_trees(store, old_tree, new_tree) else {
        return;
    };
    let _ = super::diff::render_stat(out, store, result.entries.iter());
    for e in &result.entries {
        match e.kind {
            DiffKind::Added => {
                let _ = writeln!(out, " create mode {} {}", octal(e.new_mode), e.path);
            }
            DiffKind::Removed => {
                let _ = writeln!(out, " delete mode {} {}", octal(e.old_mode), e.path);
            }
            DiffKind::Modified | DiffKind::ModeChanged | DiffKind::Renamed => {}
        }
    }
}

/// git octal mode string for a diff entry side (`None` → regular file).
/// Mirrors `diff::git_octal`.
fn octal(mode: Option<EntryMode>) -> &'static str {
    match mode {
        Some(EntryMode::Executable) => "100755",
        Some(EntryMode::Symlink) => "120000",
        Some(EntryMode::Tree) => "040000",
        _ => "100644",
    }
}
