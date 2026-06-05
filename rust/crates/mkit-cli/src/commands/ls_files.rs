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
    /// Show only ignored files (with `--others`).
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
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let idx = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };

    let mut stdout = std::io::stdout().lock();
    let sep = if opts.z { '\0' } else { '\n' };

    if opts.others {
        let ignore = match ignore::load(&cwd) {
            Ok(i) => i,
            Err(e) => return emit_err(&format!("read .mkitignore: {e}"), exit::GENERAL_ERROR),
        };
        let mut others: Vec<String> = Vec::new();
        if let Err(e) = collect_others(&cwd, &cwd, "", &idx, &ignore, &opts, &mut others) {
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
            let _ = write!(
                stdout,
                "{mode} {} 0\t{}{sep}",
                format::hex_hash(&e.object_hash),
                e.path
            );
        } else {
            write_path(&mut stdout, &e.path, opts.z, sep);
        }
    }
    exit::OK
}

fn write_path(out: &mut impl Write, path: &str, z: bool, sep: char) {
    if z {
        let _ = write!(out, "{path}{sep}");
    } else {
        // git ls-files C-style quotes special-byte paths by default.
        let shown = super::c_quote_path(path);
        let _ = write!(out, "{}{sep}", shown.as_deref().unwrap_or(path));
    }
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
fn collect_others(
    root: &Path,
    dir: &Path,
    prefix: &str,
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
        if is_dir {
            collect_others(root, &abs, &path, idx, ignore, opts, out)?;
            continue;
        }
        // Untracked = not present in the index (any non-removed entry).
        if super::index_tracks_path_or_descendant(idx, &path) {
            continue;
        }
        let ignored = ignore.is_ignored(name, false);
        let include = if opts.ignored {
            ignored // --ignored: only ignored
        } else if opts.exclude_standard {
            !ignored // drop ignored
        } else {
            true // all untracked
        };
        if include {
            out.push(path);
        }
    }
    Ok(())
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
