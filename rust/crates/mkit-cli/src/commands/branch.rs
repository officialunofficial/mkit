//! `mkit branch` — list / create / delete branches.

use std::io::Write;

use mkit_core::refs::{self, Head};

use crate::exit;
use crate::format;

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    if args.is_empty() {
        return list(&mkit_dir);
    }
    if args[0] == "-d" {
        let Some(name) = args.get(1) else {
            return super::usage_error("usage: mkit branch -d <name>");
        };
        return match refs::delete_ref(&mkit_dir, name) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&format!("delete {name}: {e}"), exit::GENERAL_ERROR),
        };
    }
    // Create a branch at HEAD.
    let name = &args[0];
    let Ok(Some(h)) = refs::resolve_head(&mkit_dir) else {
        return emit_err("no HEAD commit to branch from", exit::GENERAL_ERROR);
    };
    match refs::write_ref(&mkit_dir, name, &h) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write {name}: {e}"), exit::CANTCREAT),
    }
}

fn list(mkit_dir: &std::path::Path) -> u8 {
    let current = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(n)) => Some(n),
        _ => None,
    };
    let refs = match refs::list_refs(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
    };
    let mut stdout = std::io::stdout().lock();
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
