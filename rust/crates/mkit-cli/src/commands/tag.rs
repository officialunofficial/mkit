//! `mkit tag` — list / create / delete tags.

use std::io::Write;

use mkit_core::refs;

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
        let tags = match refs::list_tags(&mkit_dir) {
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
        return exit::OK;
    }
    if args[0] == "-d" {
        let Some(name) = args.get(1) else {
            return super::usage_error("usage: mkit tag -d <name>");
        };
        return match refs::delete_tag(&mkit_dir, name) {
            Ok(()) => exit::OK,
            Err(e) => emit_err(&format!("delete tag {name}: {e}"), exit::GENERAL_ERROR),
        };
    }
    let name = &args[0];
    let Ok(Some(h)) = refs::resolve_head(&mkit_dir) else {
        return emit_err("no HEAD commit to tag", exit::GENERAL_ERROR);
    };
    match refs::write_tag(&mkit_dir, name, &h) {
        Ok(()) => exit::OK,
        Err(e) => emit_err(&format!("write tag {name}: {e}"), exit::CANTCREAT),
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
