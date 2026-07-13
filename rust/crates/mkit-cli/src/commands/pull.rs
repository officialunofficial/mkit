//! `mkit pull [<remote>]` — fetch refs from the configured remote
//! (named, or the flat default) and fast-forward the current branch.

use std::io::Write;
use std::path::Path;

use clap::{Parser, ValueEnum};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;

use crate::clap_shim;
use crate::config;
use crate::exit;
use crate::format::{self, JsonObject};
use crate::remote_dispatch;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PullFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "mkit pull", about = "Pull changes from the configured remote.")]
struct PullOpts {
    /// Named remote to pull from (default: the flat default remote).
    remote: Option<String>,
    /// Skip Ed25519 signature verification on newly-fetched commits/
    /// remixes/tags (issue #692). Verification is ON by default and fails
    /// closed on an unsigned or invalid signature — this flag, or the
    /// user-scoped `pull.require_signed = false` config, is the only way
    /// to opt out. Not settable from repo-scoped config.
    #[arg(long = "no-verify-signatures")]
    no_verify_signatures: bool,
    /// Pull from every configured remote (the flat default plus every
    /// named `remote.<name>.url`) instead of just one, fast-forwarding
    /// the current branch from each in turn. Mutually exclusive with an
    /// explicit `<remote>` argument.
    #[arg(long, conflicts_with = "remote")]
    all: bool,
    /// Emit a machine-readable JSON result object to stdout:
    /// `{"ok":true,"remote":"...","endpoint":"...","branch":"...",
    /// "old":"<hex>|null","new":"<hex>|null","up_to_date":<bool>}`. With
    /// `--all`, one JSON object is printed per remote pulled.
    #[arg(long, value_enum, default_value = "default")]
    format: PullFormat,
    /// Suppress transfer progress output on stderr (#711).
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<PullOpts>("mkit pull", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let json = matches!(opts.format, PullFormat::Json);
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
        Err(e) => return emit_err_json(&format!("config: {e}"), exit::CONFIG_ERROR, json),
    };
    // Fail closed by default (issue #692): verify unless `--no-verify-signatures`
    // or the user-scoped `pull.require_signed = false` config opted out.
    let require_signed = !opts.no_verify_signatures && cfg.merged.pull_require_signed_or_default();
    if opts.all {
        let names = config::configured_remote_names(&cfg);
        if names.is_empty() {
            return emit_err_json(
                "no remote configured — use `mkit remote add <url>`",
                exit::CONFIG_ERROR,
                json,
            );
        }
        // Pull from every remote in turn, continuing past a per-remote
        // failure so one broken remote doesn't block the others; the
        // worst exit code observed is returned at the end.
        let mut worst = exit::OK;
        for name in names {
            let code = pull_one(&cwd, &layout, &cfg, &name, require_signed, json, opts.quiet);
            if code != exit::OK {
                worst = code;
            }
        }
        return worst;
    }
    pull_one(
        &cwd,
        &layout,
        &cfg,
        opts.remote.as_deref().unwrap_or(""),
        require_signed,
        json,
        opts.quiet,
    )
}

/// Pull from a single named remote (or the flat default when `remote`
/// is empty), fast-forwarding the current branch and reporting a
/// git-style summary. Shared by the single-remote path and the `--all`
/// loop.
fn pull_one(
    cwd: &Path,
    layout: &RepoLayout,
    cfg: &config::LayeredConfig,
    remote: &str,
    require_signed: bool,
    json: bool,
    quiet: bool,
) -> u8 {
    let Some(resolved) = config::resolve_remote(cfg, remote) else {
        return emit_err_json(
            &if remote.is_empty() {
                "no remote configured — use `mkit remote add <url>`".to_owned()
            } else {
                format!("unknown remote '{remote}'")
            },
            exit::CONFIG_ERROR,
            json,
        );
    };
    let endpoint = resolved.endpoint.as_str();
    // Snapshot the current branch tip so we can report a git-style
    // `Updating <old>..<new>` / `Fast-forward` block (or `Already up to
    // date.`) once the fast-forward completes.
    let branch = match mkit_core::refs::read_head(layout) {
        Ok(mkit_core::refs::Head::Branch(b)) => Some(b),
        _ => None,
    };
    let old_tip = branch
        .as_deref()
        .and_then(|b| mkit_core::refs::read_ref(layout, b).ok().flatten());
    match remote_dispatch::open_trusted(endpoint, resolved.repo_chosen, cfg, layout) {
        Ok(tx) => {
            let pull_outcome = {
                // Scoped tightly so the progress guard's final line
                // lands before the `Updating <a>..<b>` / diffstat
                // summary printed below, not after it.
                let _progress = crate::progress::start(
                    "Unpacking objects",
                    None,
                    crate::progress::should_report(quiet),
                );
                remote_dispatch::pull_all_with(
                    cwd,
                    tx.as_ref(),
                    &resolved.name,
                    None,
                    require_signed,
                )
            };
            match pull_outcome {
                Ok(_) => {
                    let new_tip = branch
                        .as_deref()
                        .and_then(|b| mkit_core::refs::read_ref(layout, b).ok().flatten());
                    report_pull(layout, endpoint, old_tip, new_tip);
                    if json {
                        let mut obj = JsonObject::new();
                        obj.field_bool("ok", true)
                            .field_str("remote", &resolved.name)
                            .field_str("endpoint", endpoint)
                            .field_opt_str("branch", branch.as_deref())
                            .field_opt_hash("old", old_tip.as_ref())
                            .field_opt_hash("new", new_tip.as_ref())
                            .field_bool("up_to_date", old_tip == new_tip);
                        let mut stdout = std::io::stdout().lock();
                        let _ = writeln!(stdout, "{}", obj.finish());
                    }
                    exit::OK
                }
                Err(remote_dispatch::DispatchError::Interrupted) => {
                    emit_err_json("pull: interrupted", exit::TEMPFAIL, json)
                }
                Err(e @ remote_dispatch::DispatchError::UnsignedOrInvalidObject { .. }) => {
                    emit_err_json(&format!("pull: {e}"), exit::DATAERR, json)
                }
                Err(e) => emit_err_json(&format!("pull: {e}"), exit::GENERAL_ERROR, json),
            }
        }
        Err(remote_dispatch::DispatchError::UntrustedRemote(msg)) => {
            emit_err_json(&msg, exit::CONFIG_ERROR, json)
        }
        Err(e) => emit_err_json(&format!("open remote: {e}"), exit::PROTOCOL_ERROR, json),
    }
}

/// `error(msg, code)` plus, when `json` is set, a `{"ok":false,...}`
/// line on stdout.
fn emit_err_json(msg: &str, code: u8, json: bool) -> u8 {
    if json {
        let mut obj = JsonObject::new();
        obj.field_bool("ok", false).field_str("error", msg);
        let mut stdout = std::io::stdout().lock();
        let _ = writeln!(stdout, "{}", obj.finish());
    }
    emit_err(msg, code)
}

/// Render git's post-pull summary on stderr: `Already up to date.` for a
/// no-op, else `From <url>` + `Updating <old>..<new>` + `Fast-forward` +
/// the diffstat. The diffstat is best-effort — a failure to compute it
/// still leaves the headline lines intact.
fn report_pull(layout: &RepoLayout, endpoint: &str, old: Option<Hash>, new: Option<Hash>) {
    let mut stderr = std::io::stderr().lock();
    match (old, new) {
        (o, n) if o == n => {
            let _ = writeln!(stderr, "Already up to date.");
        }
        (Some(o), Some(n)) => {
            let _ = writeln!(stderr, "From {endpoint}");
            let _ = writeln!(
                stderr,
                "Updating {}..{}",
                format::short_hash(&o, format::SUMMARY_ABBREV),
                format::short_hash(&n, format::SUMMARY_ABBREV),
            );
            let _ = writeln!(stderr, "Fast-forward");
            drop(stderr);
            print_ff_stat(layout, o, n);
        }
        _ => {
            // First-ever pull populating an empty branch: objects, HEAD,
            // and worktree are already updated by `pull_all`; stay quiet
            // rather than print a misleading `Updating <none>..` line.
        }
    }
}

/// Best-effort `Fast-forward` diffstat between two commits' trees,
/// reusing `diff`'s renderer.
fn print_ff_stat(layout: &RepoLayout, old: Hash, new: Hash) {
    let Ok(store) = crate::commands::open_store_configured(layout) else {
        return;
    };
    let (Some(old_tree), Some(new_tree)) = (tree_of(&store, old), tree_of(&store, new)) else {
        return;
    };
    if let Ok(result) = mkit_core::ops::diff_trees(&store, Some(old_tree), Some(new_tree)) {
        let mut stderr = std::io::stderr().lock();
        // `render_stat` hoists its own `DisplaySource` wrapping (#625).
        let _ = super::diff::render_stat(&mut stderr, &store, result.entries.iter());
    }
}

fn tree_of(store: &mkit_core::store::ObjectStore, commit: Hash) -> Option<Hash> {
    match store.read_object(&commit).ok()? {
        Object::Commit(c) => Some(c.tree_hash),
        Object::Remix(r) => Some(r.tree_hash),
        _ => None,
    }
}

use super::error as emit_err;
