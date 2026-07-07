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
use mkit_core::layout::RepoLayout;

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
    #[arg(short = 'f', long)]
    force: bool,
    /// Record the pushed remote as this branch's upstream, even if one is
    /// already set (`git push -u` / `--set-upstream`).
    #[arg(short = 'u', long = "set-upstream")]
    set_upstream: bool,
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
    let layout = super::resolve_layout(&cwd);
    let cfg = match config::read_layered(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };

    if opts.all {
        push_all(&layout, &cfg, &opts)
    } else {
        push_current(&layout, &cfg, &opts)
    }
}

/// Default push: current branch → its upstream, CAS-protected.
#[allow(clippy::too_many_lines)] // linear flow: resolve + no-op + push + report
fn push_current(layout: &RepoLayout, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
    let branch = match mkit_core::refs::read_head(layout) {
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

    // Snapshot the local tip and the last-seen remote-tracking ref so we
    // can render git's ref-update summary block and detect a no-op push.
    let local_tip = mkit_core::refs::read_ref(layout, &branch).ok().flatten();
    let old_tracked = mkit_core::refs::read_remote_ref(layout, &resolved.name, &remote_branch)
        .ok()
        .flatten();
    // Nothing to do when the remote-tracking ref already matches the local
    // tip (and we're not forcing). Matches git's `Everything up-to-date`.
    if !opts.force && local_tip.is_some() && local_tip == old_tracked {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Everything up-to-date");
        return exit::OK;
    }

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
        layout.worktree_root(),
        tx.as_ref(),
        &resolved.name,
        &branch,
        &remote_branch,
        lease,
    ) {
        Ok(new_tip) => {
            // Remember the upstream so a bare `mkit push` works next
            // time (Git-like first-push convenience). Only persisted
            // when not already set, and never for a detached/forced
            // overwrite of an unrelated branch.
            record_upstream(
                layout,
                cfg,
                &branch,
                &resolved.name,
                &remote_branch,
                opts.set_upstream,
            );
            // git-style ref-update summary block: `To <url>` then one
            // `<old>..<new>` / `* [new branch]` / `+ …(forced)` line.
            // On a store error during the ancestry check, assume a
            // fast-forward (don't mislabel an ordinary push as forced).
            let forced =
                !remote_dispatch::is_fast_forward(layout.worktree_root(), old_tracked, new_tip)
                    .unwrap_or(true);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "To {}", resolved.endpoint);
            let _ = writeln!(
                stderr,
                "{}",
                crate::format::ref_update_line(
                    old_tracked.as_ref(),
                    &new_tip,
                    &branch,
                    &remote_branch,
                    forced,
                )
            );
            exit::OK
        }
        Err(remote_dispatch::DispatchError::NonFastForwardPush { branch }) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "To {}", resolved.endpoint);
            let _ = writeln!(
                stderr,
                "{}",
                crate::format::ref_rejected_line(&branch, &branch)
            );
            emit_err(
                &format!(
                    "updates were rejected for '{branch}' (non-fast-forward); \
                     `mkit fetch` and merge/rebase first, or re-run with --force-with-lease / --force"
                ),
                exit::GENERAL_ERROR,
            )
        }
        Err(remote_dispatch::DispatchError::Interrupted) => {
            emit_err("push: interrupted", exit::TEMPFAIL)
        }
        Err(e) => emit_err(&format!("push: {e}"), exit::GENERAL_ERROR),
    }
}

/// `--all`: mirror every local branch to the remote (CAS-safe).
fn push_all(layout: &RepoLayout, cfg: &config::LayeredConfig, opts: &PushOpts) -> u8 {
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
    match remote_dispatch::push_all_with(
        layout.worktree_root(),
        tx.as_ref(),
        Some(&resolved.name),
        opts.force,
    ) {
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
fn record_upstream(
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    branch: &str,
    remote: &str,
    remote_branch: &str,
    force: bool,
) {
    // Without `-u`, only record on the FIRST push (git-like convenience);
    // `-u`/`--set-upstream` re-points the upstream even if already set.
    if !force
        && cfg
            .merged
            .branch_upstreams
            .get(branch)
            .is_some_and(|u| !u.remote.is_empty())
    {
        return;
    }
    // Re-read the on-disk REPO config (not the merged view) and add the
    // upstream entry without disturbing the existing remotes / flat
    // fields. Using the repo layer ensures user-scoped values (e.g. a
    // private `user.email`) are never materialized into `.mkit/config`.
    let Ok(layered) = config::read_layered(layout) else {
        return;
    };
    let mut on_disk = layered.repo;
    on_disk.branch_upstreams.insert(
        branch.to_owned(),
        config::Upstream {
            remote: remote.to_owned(),
            branch: remote_branch.to_owned(),
        },
    );
    let _ = config::write(layout, &on_disk);
}

use super::error as emit_err;
