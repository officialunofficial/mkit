//! `mkit ls-files [-s] [-z] [--others] [--ignored] [--exclude-standard]`
//! — list files in the index or untracked worktree files, like
//! `git ls-files`.
//!
//! Default: tracked paths (one per line, sorted). `-s` prints stage info
//! (`<mode> <hash> <stage>\t<path>`; stage is always 0 — mkit has no merge
//! stages). `--others` lists untracked worktree files instead;
//! `--exclude-standard` drops `.mkitignore`-ignored ones, and `--ignored`
//! inverts to show only the ignored. `-z` NUL-terminates with raw paths.

use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_core::ignore::{self, IgnoreList};
use mkit_core::index::{self, EntryStatus};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit ls-files", about = "List tracked or untracked files.")]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct LsFilesOpts {
    /// Show stage info: `<mode> <hash> <stage>\t<path>`.
    #[arg(short = 's', long = "stage")]
    stage: bool,
    /// NUL-terminate records and emit raw paths.
    #[arg(short = 'z')]
    z: bool,
    /// List untracked worktree files instead of tracked ones.
    #[arg(long)]
    others: bool,
    /// Drop `.mkitignore`-ignored files (with `--others`).
    #[arg(long = "exclude-standard")]
    exclude_standard: bool,
    /// Show only ignored files (requires `--others`).
    #[arg(long)]
    ignored: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<LsFilesOpts>("mkit ls-files", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let idx = match super::read_or_seed_index_from_head(&layout, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    // `--ignored` (and an exclude filter) only mean something for the
    // `--others` walk; git rejects `-i` outside an `-o`/`-c` selection rather
    // than silently printing the tracked listing, so we fail closed too.
    if opts.ignored && !opts.others {
        return super::usage_error("mkit ls-files --ignored must be used with --others");
    }

    let mut stdout = std::io::stdout().lock();
    let sep = if opts.z { '\0' } else { '\n' };

    if opts.others {
        let ignore = match ignore::load(&cwd) {
            Ok(i) => i,
            Err(e) => return emit_err(&format!("read ignore file: {e}"), exit::GENERAL_ERROR),
        };
        let mut others: Vec<String> = Vec::new();
        if let Err(e) = collect_others(&cwd, &cwd, "", false, &idx, &ignore, &opts, &mut others) {
            return emit_err(&format!("scan worktree: {e}"), exit::GENERAL_ERROR);
        }
        others.sort();
        for path in &others {
            write_path(&mut stdout, path, opts.z, sep);
        }
        return exit::OK;
    }

    // Tracked entries, sorted by path.
    let mut entries: Vec<&index::IndexEntry> = idx
        .entries
        .iter()
        .filter(|e| e.status != EntryStatus::Removed)
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    for e in entries {
        if opts.stage {
            let mode = git_mode(e.status);
            // Like the default listing, the `-s` pathname is C-style quoted
            // when not in `-z` mode (git's `core.quotePath` default).
            let _ = write!(
                stdout,
                "{mode} {} 0\t{}{sep}",
                format::hex_hash(&e.object_hash),
                shown_path(&e.path, opts.z)
            );
        } else {
            write_path(&mut stdout, &e.path, opts.z, sep);
        }
    }
    exit::OK
}

/// The displayed form of a path: raw bytes under `-z`, otherwise git-style
/// C-quoted when it contains special bytes.
fn shown_path(path: &str, z: bool) -> std::borrow::Cow<'_, str> {
    if z {
        std::borrow::Cow::Borrowed(path)
    } else {
        match super::c_quote_path(path) {
            Some(q) => std::borrow::Cow::Owned(q),
            None => std::borrow::Cow::Borrowed(path),
        }
    }
}

fn write_path(out: &mut impl Write, path: &str, z: bool, sep: char) {
    let _ = write!(out, "{}{sep}", shown_path(path, z));
}

/// git octal mode for a tracked index entry.
fn git_mode(status: EntryStatus) -> &'static str {
    match status {
        EntryStatus::Executable => "100755",
        EntryStatus::Symlink => "120000",
        _ => "100644",
    }
}

/// Recursively gather untracked worktree files under `dir`, applying the
/// `--exclude-standard` / `--ignored` filters.
///
/// `parent_ignored` carries down whether an ancestor directory is ignored:
/// git treats everything under an excluded directory as excluded (you cannot
/// re-include a file whose parent dir is ignored), so a file is ignored if
/// any ancestor is or it matches a pattern itself. Matching is against the
/// repo-relative path so anchored/multi-segment patterns apply.
fn collect_others(
    root: &Path,
    dir: &Path,
    prefix: &str,
    parent_ignored: bool,
    idx: &index::Index,
    ignore: &IgnoreList,
    opts: &LsFilesOpts,
    out: &mut Vec<String>,
) -> std::io::Result<()> {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.eq_ignore_ascii_case(".mkit") || name.eq_ignore_ascii_case(".git") {
            continue;
        }
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let abs = root.join(&path);
        let is_dir = std::fs::symlink_metadata(&abs)?.is_dir();
        let entry_ignored = parent_ignored || ignore.is_ignored(&path, is_dir);
        if is_dir {
            // NOTE: unlike `status` and `clean`, git's `ls-files --others`
            // does NOT suppress a directory that shadows a tracked file — it
            // lists the contents (`f/child`) as raw untracked plumbing. So no
            // collision check here; descend normally (#288).
            collect_others(root, &abs, &path, entry_ignored, idx, ignore, opts, out)?;
            continue;
        }
        // Untracked = not present in the index (any non-removed entry).
        if super::index_tracks_path_or_descendant(idx, &path) {
            continue;
        }
        let include = if opts.ignored {
            entry_ignored // --ignored: only ignored
        } else if opts.exclude_standard {
            !entry_ignored // drop ignored
        } else {
            true // all untracked
        };
        if include {
            out.push(path);
        }
    }
    Ok(())
}

use super::error as emit_err;
