//! `mkit show-ref [--heads] [--tags]` — list refs as `<hash> <refname>`,
//! like `git show-ref`. Output is sorted by full ref name; the hash is a
//! 64-hex BLAKE3 id (vs git's 40-hex SHA-1).

use std::io::Write;

use clap::Parser;
use mkit_core::refs;

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(name = "mkit show-ref", about = "List refs and their object ids.")]
struct ShowRefOpts {
    /// Limit to `refs/heads/*` (branches).
    #[arg(long)]
    heads: bool,
    /// Limit to `refs/tags/*`.
    #[arg(long)]
    tags: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ShowRefOpts>("mkit show-ref", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // Neither flag → show both heads and tags; either flag selects only
    // that namespace (both flags → the union, matching git).
    let want_heads = opts.heads || !opts.tags;
    let want_tags = opts.tags || !opts.heads;

    let mut lines: Vec<(String, String)> = Vec::new(); // (full refname, hash hex)
    if want_heads {
        match refs::list_refs(&mkit_dir) {
            Ok(rs) => collect(&mut lines, &rs, "refs/heads/"),
            Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
        }
    }
    if want_tags {
        match refs::list_tags(&mkit_dir) {
            Ok(rs) => collect(&mut lines, &rs, "refs/tags/"),
            Err(e) => return emit_err(&format!("list tags: {e}"), exit::GENERAL_ERROR),
        }
    }
    // Remote-tracking refs are listed in the unfiltered view (like
    // git show-ref); --heads/--tags keep their narrow meaning.
    if !opts.heads && !opts.tags {
        match refs::list_remote_names(&mkit_dir) {
            Ok(remotes) => {
                for remote in remotes {
                    match refs::list_remote_refs(&mkit_dir, &remote) {
                        Ok(rs) => {
                            collect(&mut lines, &rs, &format!("refs/remotes/{remote}/"));
                        }
                        Err(e) => {
                            return emit_err(
                                &format!("list remote refs: {e}"),
                                exit::GENERAL_ERROR,
                            );
                        }
                    }
                }
            }
            Err(e) => return emit_err(&format!("list remotes: {e}"), exit::GENERAL_ERROR),
        }
    }
    lines.sort_by(|a, b| a.0.cmp(&b.0));

    let mut stdout = std::io::stdout().lock();
    for (name, hash) in &lines {
        let _ = writeln!(stdout, "{hash} {name}");
    }
    // Like git, exit non-zero (no diagnostic) when nothing matched, so a
    // script can test for the existence of any head/tag.
    if lines.is_empty() {
        exit::GENERAL_ERROR
    } else {
        exit::OK
    }
}

/// Push `(<prefix><name>, hex hash)` for every ref with a readable hash.
fn collect(out: &mut Vec<(String, String)>, rs: &[refs::Ref], prefix: &str) {
    for r in rs {
        if let Some(h) = &r.hash {
            out.push((format!("{prefix}{}", r.name), format::hex_hash(h)));
        }
    }
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
