//! `mkit push` — push refs/packs to a remote with CAS safety.
//!
//! Default (no `--all`): push the current branch to its upstream only,
//! with non-fast-forward rejection via CAS (the remote-tracking ref is
//! the lease). `--all` mirrors every `refs/heads/*` (now CAS-safe).
//! `--force` / `--force-with-lease` control the CAS policy; `--dry-run`
//! resolves the plan without contacting the remote.
//!
//! Every endpoint flows through `remote_dispatch::open_trusted`, so the
//! #97 per-endpoint credential gate applies to named remotes too —
//! trust is keyed on the resolved ENDPOINT, never the remote name.

use std::io::Write;

use clap::Parser;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::remote_dispatch::{self, PushLease};

#[derive(Debug, Parser)]
#[command(
    name = "mkit push",
    about = "Push the current branch to its upstream (or --all branches)."
)]
#[allow(clippy::struct_excessive_bools)]
struct PushOpts {
    /// Remote name to push to (defaults to the branch's upstream remote,
    /// else the configured default remote).
    remote: Option<String>,
    /// Mirror every local branch instead of just the current one.
    #[arg(long)]
    all: bool,
    /// Overwrite the remote branch unconditionally (skip CAS).
    #[arg(long)]
    force: bool,
    /// Overwrite only if the remote hasn't moved past our last-seen tip.
    #[arg(long)]
    force_with_lease: bool,
    /// Print what would be pushed without contacting the remote.
    #[arg(long)]
    dry_run: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<PushOpts>("mkit push", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    if opts.force && opts.force_with_lease {
        return emit_err(
            "--force and --force-with-lease are mutually exclusive",
            exit::USAGE,
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let cfg = match config::read_layered(&cwd) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    if opts.all {
        push_all(&cwd, &cfg, &opts)
    } else {
        push_current(&cwd, &cfg, &opts)
    }
}

/// Default push: current branch → its upstream, CAS-protected.
fn push_current(cwd: &std::path::Path, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let branch = match mkit_core::refs::read_head(&mkit_dir) {
        Ok(mkit_core::refs::Head::Branch(b)) => b,
        Ok(mkit_core::refs::Head::Detached(_)) => {
            return emit_err(
                "cannot push a detached HEAD; check out a branch first",
                exit::CONFIG_ERROR,
            );
        }
        Err(e) => return emit_err(&format!("read HEAD: {e}"), exit::CONFIG_ERROR),
    };

    // Resolve the (remote, remote-branch) to push to. An explicit
    // `mkit push <remote> [branch]`-style positional remote overrides
    // the configured upstream; otherwise fall back to the upstream.
    let (remote_name, remote_branch) = match &opts.remote {
        Some(name) => (name.clone(), branch.clone()),
        None => match config::resolve_upstream(cfg, &branch) {
            Some(up) => (up.remote, up.branch),
            None => {
                return emit_err(
                    &format!(
                        "no upstream configured for branch '{branch}' and no default remote; \
                         run `mkit push <remote>` to push it (the upstream will be remembered)"
                    ),
                    exit::CONFIG_ERROR,
                );
            }
        },
    };

    let Some(resolved) = config::resolve_remote(cfg, &remote_name) else {
        return emit_err(
            &format!(
                "unknown remote '{remote_name}' — add it with `mkit remote add {remote_name} <url>`"
            ),
            exit::CONFIG_ERROR,
        );
    };

    let lease = lease_for(opts);
    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would push {branch} -> {}:{remote_branch} ({})",
            resolved.name, resolved.endpoint
        );
        return exit::OK;
    }

    let tx = match remote_dispatch::open_trusted(&resolved.endpoint, resolved.repo_chosen, cfg) {
        Ok(tx) => tx,
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            return emit_err(&msg, exit::CONFIG_ERROR);
        }
        Err(e) => return emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    };

    match remote_dispatch::push_branch_tracked(
        cwd,
        tx.as_ref(),
        &resolved.name,
        &branch,
        &remote_branch,
        lease,
    ) {
        Ok(_) => {
            // Remember the upstream so a bare `mkit push` works next
            // time (Git-like first-push convenience). Only persisted
            // when not already set, and never for a detached/forced
            // overwrite of an unrelated branch.
            record_upstream_if_unset(cwd, cfg, &branch, &resolved.name, &remote_branch);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "pushed {branch} -> {}:{remote_branch} ({})",
                resolved.name, resolved.endpoint
            );
            exit::OK
        }
        Err(remote_dispatch::DispatchError::NonFastForwardPush { branch }) => emit_err(
            &format!(
                "updates were rejected for '{branch}' (non-fast-forward); \
                 `mkit fetch` and merge/rebase first, or re-run with --force-with-lease / --force"
            ),
            exit::GENERAL_ERROR,
        ),
        Err(remote_dispatch::DispatchError::Interrupted) => {
            emit_err("push: interrupted", exit::TEMPFAIL)
        }
        Err(e) => emit_err(&format!("push: {e}"), exit::GENERAL_ERROR),
    }
}

/// `--all`: mirror every local branch to the remote (CAS-safe).
fn push_all(cwd: &std::path::Path, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
    let remote_name = opts
        .remote
        .clone()
        .unwrap_or_else(|| config::DEFAULT_REMOTE_NAME.to_owned());
    let Some(resolved) = config::resolve_remote(cfg, &remote_name) else {
        return emit_err(
            "no remote configured — use `mkit remote add <url>`",
            exit::CONFIG_ERROR,
        );
    };
    if opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "(dry-run) would mirror all branches to {} ({})",
            resolved.name, resolved.endpoint
        );
        return exit::OK;
    }
    let tx = match remote_dispatch::open_trusted(&resolved.endpoint, resolved.repo_chosen, cfg) {
        Ok(tx) => tx,
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            return emit_err(&msg, exit::CONFIG_ERROR);
        }
        Err(e) => return emit_err(&format!("open remote: {e}"), exit::PROTOCOL_ERROR),
    };
    match remote_dispatch::push_all_with(cwd, tx.as_ref(), Some(&resolved.name), opts.force) {
        Ok(n) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "pushed {n} ref(s) to {} ({})",
                resolved.name, resolved.endpoint
            );
            exit::OK
        }
        Err(remote_dispatch::DispatchError::NonFastForwardPush { branch }) => emit_err(
            &format!(
                "updates were rejected for '{branch}' (non-fast-forward); \
                 `mkit fetch` first, or re-run with --force"
            ),
            exit::GENERAL_ERROR,
        ),
        Err(remote_dispatch::DispatchError::Interrupted) => {
            emit_err("push: interrupted", exit::TEMPFAIL)
        }
        Err(e) => emit_err(&format!("push: {e}"), exit::GENERAL_ERROR),
    }
}

fn lease_for(opts: &PushOpts) -> PushLease {
    if opts.force {
        PushLease::Force
    } else if opts.force_with_lease {
        PushLease::WithLease
    } else {
        PushLease::FastForward
    }
}

/// Persist `branch.<b>.{remote,merge}` after a successful first push, so
/// a subsequent bare `mkit push` resolves the upstream. Best-effort: a
/// write failure is non-fatal (the push already succeeded).
fn record_upstream_if_unset(
    cwd: &std::path::Path,
    cfg: &config::LayeredConfig,
    branch: &str,
    remote: &str,
    remote_branch: &str,
) {
    if cfg
        .merged
        .branch_upstreams
        .get(branch)
        .is_some_and(|u| !u.remote.is_empty())
    {
        return;
    }
    // Re-read the on-disk repo config and add the upstream entry without
    // disturbing the existing remotes / flat fields.
    let Ok(mut on_disk) = config::read_or_default(cwd) else {
        return;
    };
    on_disk.branch_upstreams.insert(
        branch.to_owned(),
        config::Upstream {
            remote: remote.to_owned(),
            branch: remote_branch.to_owned(),
        },
    );
    let _ = config::write(cwd, &on_disk);
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
