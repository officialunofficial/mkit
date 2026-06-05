//! `mkit clean` — remove untracked files from the worktree (like
//! `git clean`).
//!
//! Safety: this is destructive, so — matching git's `clean.requireForce`
//! default — it **refuses to delete anything** unless `-f`/`--force` is
//! given; `-n`/`--dry-run` previews instead. Without `-d`, untracked
//! *directories* are left alone (git semantics). Ignored files are kept
//! unless `-x` (also remove ignored) or `-X` (remove *only* ignored).
//!
//! Ignore matching uses mkit's `.mkitignore` matcher (basename/root-only,
//! the documented subset pending the `.gitignore` upgrade in #256), so
//! `-x`/`-X` honor that subset.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::ignore::{self, IgnoreList};
use mkit_core::index::Index;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

#[derive(Debug, Parser)]
#[command(
    name = "mkit clean",
    about = "Remove untracked files from the worktree."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct CleanOpts {
    /// Dry run: list what would be removed without deleting anything.
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,
    /// Actually delete. Required (or `-n`) — clean refuses otherwise.
    #[arg(short = 'f', long)]
    force: bool,
    /// Also remove untracked directories.
    #[arg(short = 'd')]
    directories: bool,
    /// Also remove ignored files (not just untracked ones).
    #[arg(short = 'x')]
    ignored_too: bool,
    /// Remove ONLY ignored files.
    #[arg(short = 'X')]
    only_ignored: bool,
    /// Optional pathspecs limiting what is cleaned.
    paths: Vec<String>,
}

/// One worktree entry slated for removal.
struct Victim {
    /// Display path (git appends `/` to directories).
    display: String,
    abs: PathBuf,
    is_dir: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<CleanOpts>("mkit clean", args) {
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
    // Safety: never delete without an explicit -f, mirroring git's
    // `clean.requireForce`. `-n` previews without deleting.
    if !opts.force && !opts.dry_run {
        return emit_err(
            "refusing to clean without -f (use -n to preview, -f to delete)",
            exit::GENERAL_ERROR,
        );
    }
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let index = match super::read_or_seed_index_from_head(&cwd, &store) {
        Ok(i) => i,
        Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
    };
    let ignore = match ignore::load(&cwd) {
        Ok(i) => i,
        Err(e) => return emit_err(&format!("read .mkitignore: {e}"), exit::GENERAL_ERROR),
    };

    let mut victims: Vec<Victim> = Vec::new();
    if let Err(e) = collect(&cwd, &cwd, "", &index, &ignore, &opts, &mut victims) {
        return emit_err(&format!("scan worktree: {e}"), exit::GENERAL_ERROR);
    }

    // Pathspec filter (repo-relative match-or-descend), if any.
    let specs: Vec<String> = opts.paths.iter().map(|p| normalize_pathspec(p)).collect();
    if !specs.is_empty() {
        victims.retain(|v| {
            let p = v.display.strip_suffix('/').unwrap_or(&v.display);
            specs
                .iter()
                .any(|s| super::index_path_matches_or_descends(p, s))
        });
    }

    // Deterministic, git-like ordering.
    victims.sort_by(|a, b| a.display.cmp(&b.display));

    let mut out = std::io::stdout().lock();
    for v in &victims {
        if opts.dry_run {
            let _ = writeln!(out, "Would remove {}", v.display);
            continue;
        }
        if let Err(e) = remove(&v.abs, v.is_dir) {
            return emit_err(&format!("remove {}: {e}", v.display), exit::GENERAL_ERROR);
        }
        let _ = writeln!(out, "Removing {}", v.display);
    }
    exit::OK
}

/// Recursively gather removal candidates under `dir`, applying git's
/// untracked-directory and ignore rules.
fn collect(
    root: &Path,
    dir: &Path,
    prefix: &str,
    index: &Index,
    ignore: &IgnoreList,
    opts: &CleanOpts,
    out: &mut Vec<Victim>,
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
        // A symlink is treated as a file (never followed/recursed).
        let is_dir = std::fs::symlink_metadata(&abs)?.is_dir();

        if super::index_tracks_path_or_descendant(index, &path) {
            // Tracked file → keep. Directory with tracked content → recurse
            // to find untracked files inside it.
            if is_dir {
                collect(root, &abs, &path, index, ignore, opts, out)?;
            }
            continue;
        }

        // Fully untracked from here. Apply the ignore filter: `-X` keeps
        // only ignored entries; otherwise keep non-ignored entries and
        // ignored ones only with `-x`.
        let ignored = ignore.is_ignored(&path, is_dir);
        let include = if opts.only_ignored {
            ignored
        } else {
            !ignored || opts.ignored_too
        };
        if !include {
            continue;
        }

        if is_dir {
            // Untracked directories need -d; without it, git leaves them
            // (and their contents) untouched.
            if !opts.directories {
                continue;
            }
            out.push(Victim {
                display: format!("{path}/"),
                abs,
                is_dir: true,
            });
        } else {
            out.push(Victim {
                display: path,
                abs,
                is_dir: false,
            });
        }
    }
    Ok(())
}

fn remove(abs: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        std::fs::remove_dir_all(abs)
    } else {
        std::fs::remove_file(abs)
    }
}

/// Normalize a pathspec to the index path form: strip a leading `./`,
/// collapse `\\` to `/`, drop a trailing `/`.
fn normalize_pathspec(spec: &str) -> String {
    let s = spec.replace('\\', "/");
    let s = s.strip_prefix("./").unwrap_or(&s);
    s.strip_suffix('/').unwrap_or(s).to_string()
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
