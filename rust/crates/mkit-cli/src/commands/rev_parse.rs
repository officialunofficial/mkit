//! `mkit rev-parse [--verify] [--short[=N]] [--abbrev-ref] [--show-toplevel] [<rev>...]`
//! — resolve revisions to object ids, like `git rev-parse`.
//!
//! - bare `<rev>...` — print each resolved 64-hex id, one per line;
//! - `--short[=N]` — abbreviate to N chars (default 7);
//! - `--abbrev-ref <ref>` — print the short symbolic name (`HEAD` → the
//!   current branch);
//! - `--verify` — error if a revision does not resolve (the default error
//!   behavior already matches, but the flag is accepted for parity);
//! - `--show-toplevel` — print the repository root (the dir holding
//!   `.mkit`).
//!
//! Resolution reuses the shared revspec grammar (refs, full/short hashes,
//! `HEAD~n`/`^`). The abbreviated id is a BLAKE3 prefix, not a SHA-1 one.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Parser)]
#[command(name = "mkit rev-parse", about = "Resolve revisions to object ids.")]
struct RevParseOpts {
    /// Error if a revision does not resolve.
    #[arg(long)]
    verify: bool,
    /// Abbreviate the id to N chars (default 7). Value must be attached
    /// (`--short` or `--short=N`) so it does not swallow a following rev.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "7")]
    short: Option<usize>,
    /// Print the short symbolic ref name (`HEAD` → the current branch).
    #[arg(long = "abbrev-ref")]
    abbrev_ref: bool,
    /// Print the repository root and exit.
    #[arg(long = "show-toplevel")]
    show_toplevel: bool,
    /// Revisions to resolve.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RevParseOpts>("mkit rev-parse", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mut stdout = std::io::stdout().lock();

    // `--show-toplevel` only needs to find the repo root (walking up from a
    // subdirectory), so handle it before opening the object store.
    if opts.show_toplevel {
        let Some(root) = find_repo_root(&cwd) else {
            return emit_err("not inside a mkit repository", exit::GENERAL_ERROR);
        };
        let _ = writeln!(stdout, "{}", root.display());
        return exit::OK;
    }

    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    if opts.args.is_empty() {
        return super::usage_error("usage: mkit rev-parse [opts] <rev>...");
    }

    for spec in &opts.args {
        if opts.abbrev_ref {
            match abbrev_ref(&mkit_dir, spec) {
                Ok(name) => {
                    let _ = writeln!(stdout, "{name}");
                }
                Err(code) => return code,
            }
            continue;
        }
        let hash = match revspec::resolve_revision(&store, &mkit_dir, spec) {
            Ok(h) => h,
            Err(e) => {
                // `--verify` or not, a bad revision is an error (matching
                // git, which refuses rather than echoing the bad token).
                let _ = opts.verify;
                return emit_err(&format!("bad revision '{spec}': {e}"), exit::GENERAL_ERROR);
            }
        };
        let rendered = match opts.short {
            Some(n) => format::short_hash(&hash, if n == 0 { DEFAULT_ABBREV } else { n }),
            None => format::hex_hash(&hash),
        };
        let _ = writeln!(stdout, "{rendered}");
    }
    exit::OK
}

/// `--abbrev-ref` rendering: `HEAD` → the current branch (or `HEAD` when
/// detached); any other token is echoed as the already-short name.
fn abbrev_ref(mkit_dir: &Path, spec: &str) -> Result<String, u8> {
    if spec == "HEAD" {
        return match refs::read_head(mkit_dir) {
            Ok(Head::Branch(name)) => Ok(name),
            Ok(Head::Detached(_)) => Ok("HEAD".to_string()),
            Err(e) => Err(emit_err(&format!("read HEAD: {e}"), exit::DATAERR)),
        };
    }
    // Strip a fully-qualified ref prefix if present; else echo as-is.
    let short = spec
        .strip_prefix("refs/heads/")
        .or_else(|| spec.strip_prefix("refs/tags/"))
        .or_else(|| spec.strip_prefix("refs/remotes/"))
        .unwrap_or(spec);
    Ok(short.to_string())
}

/// Walk up from `start` to the directory that contains `.mkit`.
fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut cur = start;
    loop {
        if cur.join(mkit_core::MKIT_DIR).is_dir() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
