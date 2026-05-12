//! `mkit tag` — list / create / delete tags.

use std::io::Write;

use clap::Parser;
use mkit_core::refs;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit tag", about = "List, create, or delete tags.")]
struct TagOpts {
    /// Delete the named tag instead of creating one.
    #[arg(short = 'd', long)]
    delete: bool,
    /// Tag name. Omit to list all tags.
    name: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<TagOpts>("mkit tag", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match (opts.delete, opts.name.as_deref()) {
        (false, None) => list(&mkit_dir),
        (true, None) => super::usage_error("usage: mkit tag -d <name>"),
        (true, Some(name)) => match refs::delete_tag(&mkit_dir, name) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&format!("delete tag {name}: {e}"), exit::GENERAL_ERROR),
        },
        (false, Some(name)) => create(&mkit_dir, name),
    }
}

fn list(mkit_dir: &std::path::Path) -> u8 {
    let tags = match refs::list_tags(mkit_dir) {
        Ok(t) => t,
        Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
    };
    let mut stdout = std::io::stdout().lock();
    for t in tags {
        let short = t
            .hash
            .map(|h| format::short_hash(&h, 8))
            .unwrap_or_default();
        let _ = writeln!(stdout, "{} {short}", t.name);
    }
    exit::OK
}

fn create(mkit_dir: &std::path::Path, name: &str) -> u8 {
    let Ok(Some(h)) = refs::resolve_head(mkit_dir) else {
        return emit_err("no HEAD commit to tag", exit::GENERAL_ERROR);
    };
    match refs::write_tag(mkit_dir, name, &h) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write tag {name}: {e}"), exit::CANTCREAT),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
