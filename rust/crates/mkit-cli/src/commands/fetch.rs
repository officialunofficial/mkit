//! `mkit fetch [<remote>]` — like `pull` but does NOT move HEAD.
//! Downloads every object reachable from each remote ref and updates
//! the `refs/remotes/<remote>/<name>` tracking refs.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;

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
    /// Skip Ed25519 signature verification on newly-fetched commits/
    /// remixes/tags (issue #692). Verification is ON by default and fails
    /// closed on an unsigned or invalid signature — this flag, or the
    /// user-scoped `pull.require_signed = false` config, is the only way
    /// to opt out. Not settable from repo-scoped config.
    #[arg(long = "no-verify-signatures")]
    no_verify_signatures: bool,
    /// Fetch every configured remote (the flat default plus every
    /// named `remote.<name>.url`) instead of just one. Mutually
    /// exclusive with an explicit `<remote>` argument.
    #[arg(long, conflicts_with = "remote")]
    all: bool,
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
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let cfg = match config::read_layered(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    // Fail closed by default (issue #692): verify unless `--no-verify-signatures`
    // or the user-scoped `pull.require_signed = false` config opted out.
    let require_signed = !opts.no_verify_signatures && cfg.merged.pull_require_signed_or_default();
    if opts.all {
        let names = config::configured_remote_names(&cfg);
        if names.is_empty() {
            return emit_err(
                "no remote configured — use `mkit remote add <url>`",
                exit::CONFIG_ERROR,
            );
        }
        // Fetch every remote in turn, continuing past a per-remote
        // failure so one broken remote doesn't block the others; the
        // worst exit code observed is returned at the end.
        let mut worst = exit::OK;
        for name in names {
            let code = fetch_one(&cwd, &layout, &cfg, &name, require_signed);
            if code != exit::OK {
                worst = code;
            }
        }
        return worst;
    }
    fetch_one(
        &cwd,
        &layout,
        &cfg,
        opts.remote.as_deref().unwrap_or(""),
        require_signed,
    )
}

/// Fetch a single named remote (or the flat default when `remote` is
/// empty), snapshotting + reporting its tracking-ref movement. Shared
/// by the single-remote path and the `--all` loop.
fn fetch_one(
    cwd: &Path,
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    remote: &str,
    require_signed: bool,
) -> u8 {
    let Some(resolved) = config::resolve_remote(cfg, remote) else {
        return emit_err(
            &if remote.is_empty() {
                "no remote configured — use `mkit remote add <url>`".to_owned()
            } else {
                format!("unknown remote '{remote}'")
            },
            exit::CONFIG_ERROR,
        );
    };
    let endpoint = resolved.endpoint.as_str();
    // Snapshot the remote-tracking refs so we can report exactly which
    // ones moved (git prints nothing when nothing changed).
    let before = tracking_snapshot(layout, &resolved.name);
    match remote_dispatch::open_trusted(endpoint, resolved.repo_chosen, cfg) {
        Ok(tx) => {
            match remote_dispatch::fetch_all_with(cwd, tx.as_ref(), &resolved.name, require_signed)
            {
                Ok(_) => {
                    let after = tracking_snapshot(layout, &resolved.name);
                    report_fetch(endpoint, &resolved.name, &before, &after);
                    exit::OK
                }
                Err(remote_dispatch::DispatchError::Interrupted) => {
                    emit_err("fetch: interrupted", exit::TEMPFAIL)
                }
                Err(e @ remote_dispatch::DispatchError::UnsignedOrInvalidObject { .. }) => {
                    emit_err(&format!("fetch: {e}"), exit::DATAERR)
                }
                Err(e) => emit_err(&format!("fetch: {e}"), exit::GENERAL_ERROR),
            }
        }
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            emit_err(&msg, exit::CONFIG_ERROR)
        }
        Err(e) => emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    }
}

/// Map of `refs/remotes/<remote>/<branch>` → tip, used to diff the
/// tracking-ref state across a fetch.
fn tracking_snapshot(layout: &RepoLayout, remote: &str) -> HashMap<String, Hash> {
    mkit_core::refs::list_remote_refs(layout, remote)
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
