//! `mkit fetch [<remote>]` — like `pull` but does NOT move HEAD.
//! Downloads every object reachable from each remote ref and updates
//! the `refs/remotes/<remote>/<name>` tracking refs.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_core::hash::Hash;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format;
use crate::remote_dispatch;

#[derive(Debug, Parser)]
#[command(
    name = "mkit fetch",
    about = "Download from the configured remote without merging."
)]
struct FetchOpts {
    /// Named remote to fetch from (default: the flat default remote).
    remote: Option<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<FetchOpts>("mkit fetch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let cfg = match config::read_layered(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    let Some(resolved) = config::resolve_remote(&cfg, opts.remote.as_deref().unwrap_or("")) else {
        return emit_err(
            &match opts.remote.as_deref() {
                Some(name) => format!("unknown remote '{name}'"),
                None => "no remote configured — use `mkit remote add <url>`".to_owned(),
            },
            exit::CONFIG_ERROR,
        );
    };
    let endpoint = resolved.endpoint.as_str();
    // Snapshot the remote-tracking refs so we can report exactly which
    // ones moved (git prints nothing when nothing changed).
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let before = tracking_snapshot(&mkit_dir, &resolved.name);
    match remote_dispatch::open_trusted(endpoint, resolved.repo_chosen, &cfg) {
        Ok(tx) => match remote_dispatch::fetch_all(&cwd, tx.as_ref(), &resolved.name) {
            Ok(_) => {
                let after = tracking_snapshot(&mkit_dir, &resolved.name);
                report_fetch(endpoint, &resolved.name, &before, &after);
                exit::OK
            }
            Err(remote_dispatch::DispatchError::Interrupted) => {
                emit_err("fetch: interrupted", exit::TEMPFAIL)
            }
            Err(e) => emit_err(&format!("fetch: {e}"), exit::GENERAL_ERROR),
        },
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            emit_err(&msg, exit::CONFIG_ERROR)
        }
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

/// Map of `refs/remotes/<remote>/<branch>` → tip, used to diff the
/// tracking-ref state across a fetch.
fn tracking_snapshot(mkit_dir: &Path, remote: &str) -> HashMap<String, Hash> {
    mkit_core::refs::list_remote_refs(mkit_dir, remote)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.hash.map(|h| (r.name, h)))
        .collect()
}

/// Print git's `From <url>` block with one summary line per moved
/// tracking ref. Stays silent when nothing changed.
fn report_fetch(
    endpoint: &str,
    remote: &str,
    before: &HashMap<String, Hash>,
    after: &HashMap<String, Hash>,
) {
    let mut changed: Vec<(&String, Option<Hash>, Hash)> = after
        .iter()
        .filter(|(name, new)| before.get(*name) != Some(*new))
        .map(|(name, new)| (name, before.get(name).copied(), *new))
        .collect();
    if changed.is_empty() {
        return;
    }
    changed.sort_by(|a, b| a.0.cmp(b.0));
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "From {endpoint}");
    for (name, old, new) in changed {
        // Tracking-ref updates are rendered as fast-forwards; detecting a
        // forced (`+ old...new`) tracking update would need per-ref
        // ancestry checks against the store — deferred (cosmetic only).
        let dst = format!("{remote}/{name}");
        let _ = writeln!(
            stderr,
            "{}",
            format::ref_update_line(old.as_ref(), &new, name, &dst, false)
        );
    }
}

use super::error as emit_err;
