//! `mkit ref list [--pattern <glob>]` / `mkit ref cat <name>` — stable
//! ref-inspection plumbing (#652).
//!
//! The epic (#634) settled on keeping refs as plain loose files rather
//! than migrating them to a denser storage primitive, but that decision
//! only holds up if "ls-able" is satisfied by a stable command surface
//! rather than by shelling out to `ls`/`cat` on `.mkit/refs/`. These two
//! commands are that surface, modeled on git's `for-each-ref`/`show-ref`
//! plumbing:
//!
//! - `ref list` prints every ref's full name and resolved hash, one per
//!   line as `<refname> <hash>`, sorted lexicographically by name.
//!   Covers `refs/heads/*`, `refs/tags/*`, and `refs/remotes/*/*` — the
//!   same read scope as `show-ref`/`for-each-ref`. An empty repo prints
//!   nothing and still exits 0 (unlike `show-ref`, whose "nothing
//!   matched" exit-1 convention is a git-inherited existence test, not
//!   what a structured listing command should do). `--pattern <glob>`
//!   filters to full ref names matching a shell glob (`*` spans `/`,
//!   `?`/`[...]` supported — see [`super::branch::glob_match`]).
//! - `ref cat <name>` prints the resolved hash for exactly one ref,
//!   following `HEAD`'s symbolic indirection (`HEAD` is mkit's only
//!   symbolic ref: it either names a branch or holds a detached hash).
//!   `<name>` must be a fully-qualified ref name — `refs/heads/<b>`,
//!   `refs/tags/<t>`, `refs/remotes/<r>/<b>` — or the literal `HEAD`;
//!   these are exactly the names `ref list` prints, so the two commands
//!   round-trip.
//!
//! Both commands are read-only and reuse `mkit-core::refs`'s existing
//! read/list helpers (`read_ref`, `read_tag`, `read_remote_ref`,
//! `resolve_head`, `list_refs`, `list_tags`, `list_remote_refs`,
//! `list_remote_names`) — no new storage-layer code.

use std::io::Write;

use clap::{Parser, Subcommand};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::refs::{self, RefError};

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit ref", about = "Inspect refs: list them, or resolve one.")]
struct RefOpts {
    #[command(subcommand)]
    sub: RefCmd,
}

#[derive(Debug, Subcommand)]
enum RefCmd {
    /// List every ref's full name and resolved hash, sorted by name.
    List {
        /// Shell-glob filter on the full ref name (`*` spans `/`).
        #[arg(long)]
        pattern: Option<String>,
    },
    /// Print the resolved hash for one ref, following HEAD's symbolic
    /// indirection.
    Cat {
        /// Fully-qualified ref name (`refs/heads/<b>`, `refs/tags/<t>`,
        /// `refs/remotes/<r>/<b>`), or the literal `HEAD`.
        name: String,
    },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RefOpts>("mkit ref", args) {
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

    match opts.sub {
        RefCmd::List { pattern } => run_list(&layout, pattern.as_deref()),
        RefCmd::Cat { name } => run_cat(&layout, &name),
    }
}

/// One resolved `ref list` row: full ref name and target hash.
struct Row {
    name: String,
    hash: Hash,
}

fn run_list(layout: &RepoLayout, pattern: Option<&str>) -> u8 {
    let mut rows: Vec<Row> = Vec::new();
    match refs::list_refs(layout) {
        Ok(rs) => push_rows(&mut rows, &rs, "refs/heads/"),
        Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
    }
    match refs::list_tags(layout) {
        Ok(rs) => push_rows(&mut rows, &rs, "refs/tags/"),
        Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
    }
    match refs::list_remote_names(layout) {
        Ok(remotes) => {
            for remote in remotes {
                match refs::list_remote_refs(layout, &remote) {
                    Ok(rs) => push_rows(&mut rows, &rs, &format!("refs/remotes/{remote}/")),
                    Err(e) => {
                        return emit_err(&format!("list remote refs: {e}"), exit::GENERAL_ERROR);
                    }
                }
            }
        }
        Err(e) => return emit_err(&format!("list remotes: {e}"), exit::GENERAL_ERROR),
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));

    if let Some(pat) = pattern {
        rows.retain(|r| super::branch::glob_match(pat, &r.name));
    }

    let mut stdout = std::io::stdout().lock();
    for r in &rows {
        let _ = writeln!(stdout, "{} {}", r.name, format::hex_hash(&r.hash));
    }
    exit::OK
}

/// Push `(<prefix><name>, hash)` for every ref with a readable hash
/// (mirrors `show_ref::collect` / `for_each_ref::push_rows`).
fn push_rows(out: &mut Vec<Row>, rs: &[refs::Ref], prefix: &str) {
    for r in rs {
        if let Some(h) = r.hash {
            out.push(Row {
                name: format!("{prefix}{}", r.name),
                hash: h,
            });
        }
    }
}

fn run_cat(layout: &RepoLayout, name: &str) -> u8 {
    let resolved: Result<Option<Hash>, RefError> = if name == "HEAD" {
        refs::resolve_head(layout)
    } else if let Some(short) = name.strip_prefix("refs/heads/") {
        refs::read_ref(layout, short)
    } else if let Some(short) = name.strip_prefix("refs/tags/") {
        refs::read_tag(layout, short)
    } else if let Some(rest) = name.strip_prefix("refs/remotes/") {
        match rest.split_once('/') {
            Some((remote, branch)) => refs::read_remote_ref(layout, remote, branch),
            None => {
                return emit_err(
                    &format!(
                        "invalid remote ref '{name}': expected refs/remotes/<remote>/<branch>"
                    ),
                    exit::USAGE,
                );
            }
        }
    } else {
        return emit_err(
            &format!(
                "unsupported ref '{name}': ref cat handles HEAD, refs/heads/<b>, refs/tags/<t>, \
                 and refs/remotes/<r>/<b>"
            ),
            exit::USAGE,
        );
    };

    match resolved {
        Ok(Some(h)) => {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::hex_hash(&h));
            exit::OK
        }
        Ok(None) => emit_err(&format!("ref '{name}' not found"), exit::GENERAL_ERROR),
        Err(e) => emit_err(&format!("ref cat {name}: {e}"), exit::GENERAL_ERROR),
    }
}

use super::error as emit_err;
