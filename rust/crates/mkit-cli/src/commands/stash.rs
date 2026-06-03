//! `mkit stash save|list|pop|drop|show` — stash working-directory
//! changes. Backing logic lives in `mkit_core::ops::stash`.

use std::io::Write;

use clap::{Parser, Subcommand};
use mkit_core::ops::stash;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit stash", about = "Stash working-directory changes.")]
struct StashOpts {
    #[command(subcommand)]
    sub: StashCmd,
}

#[derive(Debug, Parser)]
struct SaveOpts {
    /// Stash message.
    #[arg(short, long, default_value = "")]
    message: String,
}

#[derive(Debug, Subcommand)]
enum StashCmd {
    /// Save the current worktree changes as a new stash entry.
    Save(SaveOpts),
    /// List all stash entries.
    List,
    /// Apply and remove a stash entry (default: entry 0).
    Pop {
        #[arg(default_value_t = 0)]
        index: usize,
    },
    /// Remove a stash entry without applying it (default: entry 0).
    Drop {
        #[arg(default_value_t = 0)]
        index: usize,
    },
    /// Show the diff of a stash entry (default: entry 0).
    Show {
        #[arg(default_value_t = 0)]
        index: usize,
    },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    // `mkit stash` (no args) = save with empty message.
    // `mkit stash -m <msg>` = save with message.
    // Either is the "save is the default subcommand" form, which
    // clap doesn't model directly; rewrite the argv so clap sees an
    // explicit `save` subcommand when the user omitted it.
    let needs_default = args.first().is_none_or(|a| {
        !matches!(
            a.as_str(),
            "save" | "list" | "pop" | "drop" | "show" | "-h" | "--help"
        )
    });
    let rewritten: Vec<String> = if needs_default {
        std::iter::once("save".to_owned())
            .chain(args.iter().cloned())
            .collect()
    } else {
        args.to_vec()
    };

    let opts = match clap_shim::parse::<StashOpts>("mkit stash", &rewritten) {
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

    // `save`, `pop`, and `drop` mutate the worktree/index/manifest and
    // must serialise against other worktree commands. `list` and `show`
    // are read-only and run unlocked.
    let _lock = match opts.sub {
        StashCmd::Save(_) | StashCmd::Pop { .. } | StashCmd::Drop { .. } => {
            match super::acquire_worktree_lock(&cwd) {
                Ok(l) => Some(l),
                Err(code) => return code,
            }
        }
        StashCmd::List | StashCmd::Show { .. } => None,
    };

    match opts.sub {
        StashCmd::Save(save) => match stash::save(&store, &cwd, &save.message) {
            Ok(()) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "stashed: {}", save.message);
                exit::OK
            }
            Err(e) => emit_err(&format!("stash save: {e}"), exit::GENERAL_ERROR),
        },
        StashCmd::List => match stash::list(&cwd) {
            Ok(list) => {
                if list.entries.is_empty() {
                    let mut stderr = std::io::stderr().lock();
                    let _ = writeln!(stderr, "(no stash entries)");
                    return exit::OK;
                }
                let mut stdout = std::io::stdout().lock();
                for (i, e) in list.entries.iter().enumerate() {
                    let _ = writeln!(
                        stdout,
                        "stash@{{{i}}}: {} {}",
                        format::short_hash(&e.commit_hash, 8),
                        e.message
                    );
                }
                exit::OK
            }
            Err(e) => emit_err(&format!("stash list: {e}"), exit::GENERAL_ERROR),
        },
        StashCmd::Pop { index } => {
            // #205: run the #176 destructive-restore guard over the
            // stash tree BEFORE restoring, so a `stash pop` never
            // silently clobbers uncommitted edits on unrelated paths.
            // `stash::pop` drops the entry only after a successful
            // restore, so refusing here leaves the stash intact.
            let tree_hash = match stash::entry_tree_hash(&store, &cwd, index) {
                Ok(h) => h,
                Err(e) => return emit_err(&format!("stash pop: {e}"), exit::GENERAL_ERROR),
            };
            if let Err(e) = super::ensure_restore_safe(&cwd, &store, tree_hash) {
                return emit_err(&format!("stash pop: {e}"), exit::GENERAL_ERROR);
            }
            match stash::pop(&store, &cwd, index) {
                Ok(()) => {
                    let mut stderr = std::io::stderr().lock();
                    let _ = writeln!(stderr, "popped stash@{{{index}}}");
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash pop: {e}"), exit::GENERAL_ERROR),
            }
        }
        StashCmd::Drop { index } => match stash::drop(&cwd, index) {
            Ok(()) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "dropped stash@{{{index}}}");
                exit::OK
            }
            Err(e) => emit_err(&format!("stash drop: {e}"), exit::GENERAL_ERROR),
        },
        StashCmd::Show { index } => match stash::render_stash_show(&store, &cwd, index) {
            Ok(output) => {
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(output.as_bytes());
                exit::OK
            }
            Err(e) => emit_err(&format!("stash show: {e}"), exit::GENERAL_ERROR),
        },
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
