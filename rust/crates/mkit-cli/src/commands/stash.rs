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
        /// Also restore the staged state recorded by the stash (like
        /// `git stash pop --index`), not just the worktree changes.
        #[arg(long = "index")]
        restore_index: bool,
        #[arg(default_value = "0")]
        index: String,
    },
    /// Apply a stash entry WITHOUT removing it (default: entry 0).
    Apply {
        /// Also restore the staged state recorded by the stash (like
        /// `git stash apply --index`), not just the worktree changes.
        #[arg(long = "index")]
        restore_index: bool,
        #[arg(default_value = "0")]
        index: String,
    },
    /// Remove ALL stash entries.
    Clear,
    /// Remove a stash entry without applying it (default: entry 0).
    Drop {
        #[arg(default_value = "0")]
        index: String,
    },
    /// Show the diff of a stash entry (default: entry 0).
    Show {
        #[arg(default_value = "0")]
        index: String,
    },
}

/// Parse a stash entry reference. Accepts a bare index (`2`) or git's
/// `stash@{N}` revision syntax (`stash@{2}`) — the same spelling `stash
/// list` prints, so users can copy it back verbatim.
fn parse_stash_index(spec: &str) -> Result<usize, String> {
    let core = spec
        .strip_prefix("stash@{")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(spec);
    core.parse::<usize>()
        .map_err(|_| format!("invalid stash reference '{spec}' (expected N or stash@{{N}})"))
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
            "save" | "list" | "pop" | "apply" | "drop" | "clear" | "show" | "-h" | "--help"
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
    let store = match super::open_store_configured(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Commands that mutate the worktree/index/manifest must serialise
    // against other worktree commands: `save`/`pop`/`apply`/`drop`/`clear`.
    // (`apply` writes the worktree; `clear` rewrites the manifest.)
    // `list` and `show` are read-only and run unlocked.
    let lock = match opts.sub {
        StashCmd::Save(_)
        | StashCmd::Pop { .. }
        | StashCmd::Apply { .. }
        | StashCmd::Drop { .. }
        | StashCmd::Clear => match super::acquire_worktree_lock(&cwd) {
            Ok(l) => Some(l),
            Err(code) => return code,
        },
        StashCmd::List | StashCmd::Show { .. } => None,
    };

    // `lock` is held until this binding drops at the end of `run`, so the
    // worktree stays serialised across the whole `dispatch` call.
    let code = dispatch(opts.sub, &store, &cwd);
    drop(lock);
    code
}

/// Run a parsed stash subcommand. Split out of [`run`] so the worktree
/// lock acquisition / mode dispatch stays small enough for clippy's
/// `too_many_lines`.
fn dispatch(sub: StashCmd, store: &ObjectStore, cwd: &std::path::Path) -> u8 {
    match sub {
        StashCmd::Save(save) => {
            // git stores the descriptor in the stash message itself, so a
            // no-message save records the auto `WIP on <branch>: <hash>
            // <subject>` line and `stash list` shows it verbatim. An
            // explicit message records `On <branch>: <message>`.
            let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
            let branch = super::head_branch_name(&mkit_dir);
            let effective = if save.message.is_empty() {
                match head_descriptor(store, &mkit_dir) {
                    Some((short, subject)) => format!("WIP on {branch}: {short} {subject}"),
                    None => format!("WIP on {branch}"),
                }
            } else {
                format!("On {branch}: {}", save.message)
            };
            match stash::save(store, cwd, &effective) {
                Ok(()) => {
                    let mut stderr = std::io::stderr().lock();
                    let _ = writeln!(
                        stderr,
                        "Saved working directory and index state {effective}"
                    );
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash save: {e}"), exit::GENERAL_ERROR),
            }
        }
        StashCmd::List => match stash::list(cwd) {
            Ok(list) => {
                // git prints nothing for an empty stash; one
                // `stash@{N}: <message>` line per entry otherwise (no hash
                // column, matching git).
                let mut stdout = std::io::stdout().lock();
                for (i, e) in list.entries.iter().enumerate() {
                    let _ = writeln!(stdout, "stash@{{{i}}}: {}", e.message);
                }
                exit::OK
            }
            Err(e) => emit_err(&format!("stash list: {e}"), exit::GENERAL_ERROR),
        },
        // `pop` removes the entry after a successful restore; `apply`
        // leaves it in place. Both run the same #205/#176 destructive-
        // restore guard so they never clobber uncommitted edits on
        // unrelated paths.
        StashCmd::Pop {
            index,
            restore_index,
        } => match parse_stash_index(&index) {
            Ok(i) => restore_entry(store, cwd, i, true, restore_index),
            Err(e) => emit_err(&e, exit::USAGE),
        },
        StashCmd::Apply {
            index,
            restore_index,
        } => match parse_stash_index(&index) {
            Ok(i) => restore_entry(store, cwd, i, false, restore_index),
            Err(e) => emit_err(&e, exit::USAGE),
        },
        StashCmd::Clear => match stash::clear(cwd) {
            Ok(()) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "cleared all stash entries");
                exit::OK
            }
            Err(e) => emit_err(&format!("stash clear: {e}"), exit::GENERAL_ERROR),
        },
        StashCmd::Drop { index } => match parse_stash_index(&index) {
            Ok(i) => {
                // Capture the entry id before removal for git's
                // `Dropped stash@{N} (<id>)` confirmation.
                let was = stash::list(cwd)
                    .ok()
                    .and_then(|l| l.entries.get(i).map(|e| e.commit_hash));
                match stash::drop(cwd, i) {
                    Ok(()) => {
                        let mut stderr = std::io::stderr().lock();
                        match was {
                            Some(h) => {
                                let _ = writeln!(
                                    stderr,
                                    "Dropped refs/stash@{{{i}}} ({})",
                                    format::short_hash(&h, format::SUMMARY_ABBREV)
                                );
                            }
                            None => {
                                let _ = writeln!(stderr, "Dropped refs/stash@{{{i}}}");
                            }
                        }
                        exit::OK
                    }
                    Err(e) => emit_err(&format!("stash drop: {e}"), exit::GENERAL_ERROR),
                }
            }
            Err(e) => emit_err(&e, exit::USAGE),
        },
        StashCmd::Show { index } => match parse_stash_index(&index) {
            Ok(i) => match stash::render_stash_show(store, cwd, i) {
                Ok(output) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(output.as_bytes());
                    exit::OK
                }
                Err(e) => emit_err(&format!("stash show: {e}"), exit::GENERAL_ERROR),
            },
            Err(e) => emit_err(&e, exit::USAGE),
        },
    }
}

/// Restore stash entry `index` into the worktree. `drop_entry` chooses
/// between `pop` (removes the entry after a clean restore) and `apply`
/// (leaves it on the stack). Both run the #205/#176 destructive-restore
/// guard up-front so a refusal leaves the stash and worktree untouched.
fn restore_entry(
    store: &ObjectStore,
    cwd: &std::path::Path,
    index: usize,
    drop_entry: bool,
    restore_index: bool,
) -> u8 {
    let verb = if drop_entry { "pop" } else { "apply" };
    // Empty stash → git's `No stash entries found.` (exit 1).
    let entries = stash::list(cwd).map(|l| l.entries).unwrap_or_default();
    if entries.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "No stash entries found.");
        return exit::GENERAL_ERROR;
    }
    let entry_short = entries
        .get(index)
        .map(|e| format::short_hash(&e.commit_hash, format::SUMMARY_ABBREV));
    let tree_hash = match stash::entry_tree_hash(store, cwd, index) {
        Ok(h) => h,
        Err(e) => return emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = super::ensure_restore_safe(cwd, store, tree_hash) {
        return emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR);
    }

    // Without `--index`, keep the original behavior: `pop` restores the
    // worktree, records recovery, and drops the entry; `apply` restores and
    // keeps it.
    if !restore_index {
        let result = if drop_entry {
            stash::pop(store, cwd, index)
        } else {
            stash::apply(store, cwd, index)
        };
        return match result {
            Ok(()) => {
                report_restore(drop_entry, index, entry_short.as_deref());
                exit::OK
            }
            Err(e) => emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR),
        };
    }

    // `--index`: restore the worktree (keeping the entry), then re-stage the
    // recorded index, and only THEN drop the entry (for `pop`). Sequencing
    // the entry removal last means a failure in the index rewrite leaves the
    // stash in place for a normal retry, rather than dropping it with the
    // index half-restored.
    let snapshot_index = match stash::entry_index(store, cwd, index) {
        Ok(i) => i,
        Err(e) => return emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR),
    };
    if let Err(e) = stash::apply(store, cwd, index) {
        return emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR);
    }
    if let Some(restored) = snapshot_index {
        // Write the exact recorded index — preserving staged deletions, which
        // a tree round-trip would drop.
        if let Err(e) = mkit_core::index::write_index(cwd, &restored) {
            return emit_err(
                &format!("stash {verb}: restore index: {e}"),
                exit::GENERAL_ERROR,
            );
        }
    } else {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: this stash has no recorded index state; --index had no effect"
        );
    }
    if drop_entry && let Err(e) = stash::pop_finalize(cwd, index) {
        return emit_err(&format!("stash {verb}: {e}"), exit::GENERAL_ERROR);
    }
    report_restore(drop_entry, index, entry_short.as_deref());
    exit::OK
}

/// git-shaped post-restore line: `pop` reports `Dropped refs/stash@{N}
/// (<id>)` (the entry was removed); `apply` reports it stays on the stack.
fn report_restore(drop_entry: bool, index: usize, entry_short: Option<&str>) {
    let mut stderr = std::io::stderr().lock();
    if drop_entry {
        match entry_short {
            Some(id) => {
                let _ = writeln!(stderr, "Dropped refs/stash@{{{index}}} ({id})");
            }
            None => {
                let _ = writeln!(stderr, "Dropped refs/stash@{{{index}}}");
            }
        }
    } else {
        let _ = writeln!(stderr, "Applied stash@{{{index}}} (kept on the stack)");
    }
}

/// `(short-hash, subject)` of the current HEAD commit, for git's auto
/// stash message. `None` when HEAD is unborn or unreadable.
fn head_descriptor(store: &ObjectStore, mkit_dir: &std::path::Path) -> Option<(String, String)> {
    let head = mkit_core::refs::resolve_head(mkit_dir).ok().flatten()?;
    let subject = match store.read_object(&head).ok()? {
        mkit_core::object::Object::Commit(c) => String::from_utf8_lossy(&c.message)
            .lines()
            .next()
            .unwrap_or("")
            .to_owned(),
        _ => String::new(),
    };
    Some((format::short_hash(&head, format::SUMMARY_ABBREV), subject))
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::parse_stash_index;

    #[test]
    fn parses_bare_index() {
        assert_eq!(parse_stash_index("0").unwrap(), 0);
        assert_eq!(parse_stash_index("3").unwrap(), 3);
    }

    #[test]
    fn parses_stash_at_brace_syntax() {
        assert_eq!(parse_stash_index("stash@{0}").unwrap(), 0);
        assert_eq!(parse_stash_index("stash@{12}").unwrap(), 12);
    }

    #[test]
    fn rejects_malformed_references() {
        assert!(parse_stash_index("stash@{}").is_err());
        assert!(parse_stash_index("stash@{x}").is_err());
        assert!(parse_stash_index("-1").is_err());
        assert!(parse_stash_index("stash@{1").is_err());
    }
}
