//! `mkit branch` — list / create / delete branches.
//!
//! Output modes for the list form:
//!
//! - default — `<marker> <name> <short8>` per line, `*` marks current.
//! - `--format=json` — JSONL: `{"name":"...","current":bool,"hash":"<64-hex>"}`.

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::refs::{self, Head};

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BranchFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit branch",
    about = "List, create, rename, or delete branches."
)]
struct BranchOpts {
    /// Delete the named branch (safe — refuses the current branch and a
    /// non-existent branch).
    #[arg(short = 'd', long)]
    delete: bool,
    /// Force-delete the named branch. Like `-d` it still refuses the
    /// branch HEAD points at (that would leave HEAD dangling), but it
    /// reports a clean success when the branch is absent.
    #[arg(short = 'D')]
    force_delete: bool,
    /// Rename a branch. `branch -m <old> <new>` renames `<old>`;
    /// `branch -m <new>` renames the current branch. Moves HEAD when the
    /// renamed branch is the checked-out one.
    #[arg(short = 'm', long)]
    rename: bool,
    /// Output format for the list form. JSONL with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: BranchFormat,
    /// Positional arguments: branch name(s). Meaning depends on the mode.
    #[arg(num_args = 0..=2)]
    names: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BranchOpts>("mkit branch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // `-m` / `-d` / `-D` are mutually exclusive mode flags.
    let mode_flags = u8::from(opts.delete) + u8::from(opts.force_delete) + u8::from(opts.rename);
    if mode_flags > 1 {
        return super::usage_error("usage: mkit branch [-d|-D|-m] ...  (modes are exclusive)");
    }

    if opts.rename {
        return rename(&mkit_dir, &opts.names);
    }
    if opts.delete || opts.force_delete {
        return delete(&mkit_dir, &opts.names, opts.force_delete);
    }

    match opts.names.as_slice() {
        [] => list(&mkit_dir, matches!(opts.format, BranchFormat::Json)),
        [name] => create(&mkit_dir, name),
        _ => super::usage_error("usage: mkit branch <name>  (create takes one name)"),
    }
}

/// `mkit branch <name>` — create a new branch at HEAD.
fn create(mkit_dir: &std::path::Path, name: &str) -> u8 {
    let Ok(Some(h)) = refs::resolve_head(mkit_dir) else {
        return emit_err("no HEAD commit to branch from", exit::GENERAL_ERROR);
    };
    // `MustNotExist` (issue #206) refuses to silently clobber an
    // existing branch of the same name. Route through
    // `write_ref_recording_history` so the new branch picks up a
    // fresh history-MMR journal (the empty pre-leaf root + this
    // first append) on builds with `--features history-mmr`.
    match super::write_ref_recording_history(mkit_dir, name, refs::RefWriteCondition::Missing, &h) {
        Ok(()) => exit::OK,
        Err(refs::RefError::Conflict(_)) => {
            emit_err(&format!("branch '{name}' already exists"), exit::CANTCREAT)
        }
        Err(e) => emit_err(&format!("write {name}: {e}"), exit::CANTCREAT),
    }
}

/// `mkit branch -d/-D <name>` — delete a branch.
///
/// Both `-d` and `-D` route through `delete_ref_safe`, which refuses to
/// delete the branch HEAD currently points at (issue #206) — deleting
/// the current branch would leave HEAD dangling, and git refuses this
/// even under `-D`. mkit does not track per-branch merge status, so the
/// only material difference is that `-D` (force) treats an absent branch
/// as a no-op success instead of an error.
fn delete(mkit_dir: &std::path::Path, names: &[String], force: bool) -> u8 {
    let [name] = names else {
        let flag = if force { "-D" } else { "-d" };
        return super::usage_error(&format!("usage: mkit branch {flag} <name>"));
    };
    match refs::delete_ref_safe(mkit_dir, name) {
        Ok(()) => exit::OK,
        // Force-delete of a missing branch is a clean no-op.
        Err(refs::RefError::NotFound(_)) if force => exit::OK,
        Err(e) => emit_err(&format!("delete {name}: {e}"), exit::GENERAL_ERROR),
    }
}

/// `mkit branch -m [<old>] <new>` — rename a branch.
///
/// With two names renames `<old>` → `<new>`; with one name renames the
/// current branch → `<new>`. Implemented as a CAS-guarded create of the
/// destination (`RefWriteCondition::Missing` refuses to clobber) followed
/// by deletion of the source, then a HEAD update when the source was the
/// checked-out branch. The create routes through
/// `write_ref_recording_history` so the renamed branch seeds a fresh
/// history-MMR journal on `--features history-mmr` builds, exactly as a
/// freshly created branch would.
fn rename(mkit_dir: &std::path::Path, names: &[String]) -> u8 {
    let (old, new) = match names {
        [new] => {
            let Ok(refs::Head::Branch(cur)) = refs::read_head(mkit_dir) else {
                return emit_err(
                    "cannot rename: HEAD is detached (specify <old> <new>)",
                    exit::GENERAL_ERROR,
                );
            };
            (cur, new.clone())
        }
        [old, new] => (old.clone(), new.clone()),
        _ => return super::usage_error("usage: mkit branch -m [<old>] <new>"),
    };

    if old == new {
        return exit::OK;
    }

    let hash = match refs::read_ref(mkit_dir, &old) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err(&format!("branch '{old}' not found"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read {old}: {e}"), exit::GENERAL_ERROR),
    };

    // Create the destination first under a CAS that refuses to clobber an
    // existing branch. Only after it lands do we drop the source, so a
    // mid-operation failure never loses the branch tip.
    match super::write_ref_recording_history(
        mkit_dir,
        &new,
        refs::RefWriteCondition::Missing,
        &hash,
    ) {
        Ok(()) => {}
        Err(refs::RefError::Conflict(_)) => {
            return emit_err(&format!("branch '{new}' already exists"), exit::CANTCREAT);
        }
        Err(e) => return emit_err(&format!("write {new}: {e}"), exit::CANTCREAT),
    }

    if let Err(e) = refs::delete_ref(mkit_dir, &old) {
        return emit_err(&format!("delete {old}: {e}"), exit::GENERAL_ERROR);
    }

    // Move HEAD if we renamed the checked-out branch.
    if let Ok(refs::Head::Branch(cur)) = refs::read_head(mkit_dir)
        && cur == old
        && let Err(e) = refs::write_head_branch(mkit_dir, &new)
    {
        return emit_err(&format!("update HEAD to {new}: {e}"), exit::GENERAL_ERROR);
    }
    exit::OK
}

fn list(mkit_dir: &std::path::Path, json: bool) -> u8 {
    let current = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(n)) => Some(n),
        _ => None,
    };
    let refs = match refs::list_refs(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
    };
    let mut stdout = std::io::stdout().lock();
    if json {
        for r in &refs {
            let is_current = current.as_deref() == Some(r.name.as_str());
            let _ = stdout.write_all(b"{");
            let _ = write!(stdout, "\"name\":\"{}\"", format::json_escape(&r.name));
            let _ = write!(stdout, ",\"current\":{is_current}");
            if let Some(h) = &r.hash {
                let _ = write!(stdout, ",\"hash\":\"{}\"", format::hex_hash(h));
            } else {
                let _ = stdout.write_all(b",\"hash\":null");
            }
            let _ = stdout.write_all(b"}\n");
        }
        return exit::OK;
    }
    for r in refs {
        let marker = current
            .as_deref()
            .map_or(' ', |cur| if cur == r.name { '*' } else { ' ' });
        let short = r
            .hash
            .map(|h| format::short_hash(&h, 8))
            .unwrap_or_default();
        let _ = writeln!(stdout, "{marker} {} {short}", r.name);
    }
    exit::OK
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
