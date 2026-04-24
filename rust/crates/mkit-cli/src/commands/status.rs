//! `mkit status` — show working-tree changes relative to HEAD.
//!
//! Output format (verbatim port of the Zig CLI output):
//!
//! ```text
//! on branch <name>      (or "detached HEAD at <hash>", or "no HEAD yet")
//!
//! Changes to be committed:
//!   A  added.txt
//!   D  deleted.txt
//!
//! Changes not staged for commit:
//!   M  modified.txt
//!
//! Untracked files:
//!   (listed with "?" prefix in a simple no-index run)
//! ```
//!
//! When no index is available (e.g. `mkit status` on a repo that was
//! never `add`-ed to), the staged/unstaged sections are collapsed into
//! a single "changed" section with raw diff kind letters (A/D/M/T).

use std::io::Write;

use mkit_core::index;
use mkit_core::object::Object;
use mkit_core::ops::{DiffKind, StatusStaging, status_diff};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use crate::exit;

#[must_use]
pub fn run(_args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let mut stdout = std::io::stdout().lock();

    // --- Branch / HEAD line -------------------------------------------
    match refs::read_head(&mkit_dir) {
        Ok(refs::Head::Branch(name)) => {
            let _ = writeln!(stdout, "on branch {name}");
        }
        Ok(refs::Head::Detached(h)) => {
            let _ = writeln!(stdout, "detached HEAD at {}", mkit_core::hash::to_hex(&h));
        }
        Err(_) => {
            let _ = writeln!(stdout, "no HEAD yet");
        }
    }

    // --- Resolve HEAD tree hash ---------------------------------------
    let head_tree: Option<mkit_core::Hash> = match refs::resolve_head(&mkit_dir) {
        Ok(Some(commit_hash)) => match store.read_object(&commit_hash) {
            Ok(Object::Commit(c)) => Some(c.tree_hash),
            _ => None,
        },
        _ => None,
    };

    // --- Load index (best-effort) -------------------------------------
    let idx = index::read_index(&cwd).ok();

    // --- Compute status -----------------------------------------------
    let entries = match status_diff(&store, head_tree.as_ref(), &cwd, idx.as_ref()) {
        Ok(e) => e,
        Err(e) => return emit_err(&format!("status: {e}"), exit::GENERAL_ERROR),
    };

    if entries.is_empty() {
        let _ = writeln!(stdout, "nothing to commit, working tree clean");
        return exit::OK;
    }

    // --- Render three-way output -------------------------------------
    // Partition into staged / unstaged / partially staged.
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
        let _ = writeln!(stdout, "\nChanges to be committed:");
        for e in &staged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stdout, "  {tag}  {}", e.diff.path);
        }
    }
    if !unstaged.is_empty() {
        let _ = writeln!(stdout, "\nChanges not staged for commit:");
        for e in &unstaged {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stdout, "  {tag}  {}", e.diff.path);
        }
    }
    if !partial.is_empty() {
        let _ = writeln!(stdout, "\nChanges partially staged:");
        for e in &partial {
            let tag = diff_tag(e.diff.kind);
            let _ = writeln!(stdout, "  {tag}  {}", e.diff.path);
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
