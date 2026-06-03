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
#[command(name = "mkit branch", about = "List, create, or delete branches.")]
struct BranchOpts {
    /// Delete the named branch instead of creating one.
    #[arg(short = 'd', long)]
    delete: bool,
    /// Output format for the list form. JSONL with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: BranchFormat,
    /// Branch name. Omit to list all branches.
    name: Option<String>,
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

    match (opts.delete, opts.name.as_deref()) {
        (false, None) => list(&mkit_dir, matches!(opts.format, BranchFormat::Json)),
        (true, None) => super::usage_error("usage: mkit branch -d <name>"),
        // `delete_ref_safe` refuses to delete the branch HEAD currently
        // points at (issue #206) — deleting the current branch would
        // leave HEAD dangling.
        (true, Some(name)) => match refs::delete_ref_safe(&mkit_dir, name) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&format!("delete {name}: {e}"), exit::GENERAL_ERROR),
        },
        (false, Some(name)) => {
            let Ok(Some(h)) = refs::resolve_head(&mkit_dir) else {
                return emit_err("no HEAD commit to branch from", exit::GENERAL_ERROR);
            };
            // `mkit branch <name>` creates a new branch at HEAD.
            // `MustNotExist` (issue #206) refuses to silently clobber an
            // existing branch of the same name. Route through
            // `write_ref_recording_history` so the new branch picks up a
            // fresh history-MMR journal (the empty pre-leaf root + this
            // first append) on builds with `--features history-mmr`.
            match super::write_ref_recording_history(
                &mkit_dir,
                name,
                refs::RefWriteCondition::Missing,
                &h,
            ) {
                Ok(()) => exit::OK,
                Err(refs::RefError::Conflict(_)) => {
                    emit_err(&format!("branch '{name}' already exists"), exit::CANTCREAT)
                }
                Err(e) => emit_err(&format!("write {name}: {e}"), exit::CANTCREAT),
            }
        }
    }
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
