//! `mkit remote` — show / add / set the configured remote.
//!
//! URL validation: only `mkit+<scheme>://` is accepted. Recognised
//! schemes: `file`, `https`, `s3`, `ssh`, `memory`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use mkit_core::layout::RepoLayout;

use crate::clap_shim;
use crate::config::{self, Config, RemoteEntry};
use crate::exit;
use crate::format;
use crate::remote_dispatch::applied_packs::AppliedPacks;

const ACCEPTED_SCHEMES: &[(&str, &str)] = &[
    ("mkit+file://", "file"),
    ("mkit+https://", "http"),
    ("mkit+s3://", "s3"),
    ("mkit+ssh://", "ssh"),
    ("mkit+memory://", "memory"),
    // Git-bridge remotes (SPEC-GIT-BRIDGE / SPEC-GIT-IMPORT). Native
    // push/pull/fetch/clone REFUSE these with a pointer to the
    // `mkit git` subcommands — the transports are not interchangeable.
    ("git+https://", "git"),
    ("git+ssh://", "git"),
    ("git+file://", "git"),
];

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RemoteFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "mkit remote", about = "Show or configure the remote.")]
struct RemoteOpts {
    /// Output format for the show form. JSON object with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: RemoteFormat,
    /// Verbose: list each remote's URL and direction (`<name>\t<url>
    /// (fetch)` / `(push)`), like `git remote -v`.
    #[arg(short = 'v', long)]
    verbose: bool,
    #[command(subcommand)]
    sub: Option<RemoteCmd>,
}

#[derive(Debug, Subcommand)]
enum RemoteCmd {
    /// Configure a remote. With one argument, sets the flat default
    /// remote (`mkit remote add <url>`). With two, adds/updates a named
    /// remote (`mkit remote add <name> <url>`). The URL must be
    /// `mkit+<scheme>://...`.
    Add {
        name_or_url: String,
        url: Option<String>,
    },
    /// Alias for `add`.
    Set {
        name_or_url: String,
        url: Option<String>,
    },
    /// Remove a named remote (`mkit remote remove <name>`). Use the
    /// reserved name `default` to clear the flat default remote.
    #[command(alias = "rm")]
    Remove { name: String },
    /// Rename a named remote (`mkit remote rename <old> <new>`). Also
    /// rewrites any `branch.<b>.remote` upstream pointing at `<old>`.
    #[command(alias = "mv")]
    Rename { old: String, new: String },
    /// Print a remote's URL (`mkit remote get-url <name>`; use `default`
    /// for the flat default remote).
    #[command(name = "get-url")]
    GetUrl { name: String },
    /// Change a remote's URL (`mkit remote set-url <name> <url>`).
    #[command(name = "set-url")]
    SetUrl { name: String, url: String },
}

#[must_use]
#[allow(clippy::too_many_lines)] // flat dispatch over the remote subcommands
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<RemoteOpts>("mkit remote", args) {
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
    let layered = match config::read_layered(&layout) {
        Ok(c) => c,
        Err(e) => return emit_err(&format!("config: {e}"), exit::CONFIG_ERROR),
    };
    // `show` reflects the merged view; every mutating subcommand operates
    // on and persists ONLY the repo layer, so a user-scoped value (e.g. a
    // private `user.email`) is never materialized into the clone-traveling
    // `.mkit/config` by `config::write`.
    if opts.sub.is_none() {
        return show(
            &layered.merged,
            matches!(opts.format, RemoteFormat::Json),
            opts.verbose,
        );
    }
    let mut cfg = layered.repo;

    match opts.sub {
        None => unreachable!("handled above"),
        Some(RemoteCmd::Add { name_or_url, url } | RemoteCmd::Set { name_or_url, url }) => {
            // Two forms:
            //   `mkit remote add <url>`         -> flat default remote
            //   `mkit remote add <name> <url>`  -> named remote
            let (name, url) = match url {
                Some(url) => (Some(name_or_url), url),
                None => (None, name_or_url),
            };
            // Reject control characters (newline et al.) before the URL
            // ever reaches `config::write`, which emits values raw — a
            // newline would inject extra `key = value` lines into
            // `.mkit/config` (config injection).
            if config::validate_value(&url).is_err() {
                return emit_err(
                    &format!("invalid remote URL '{url}': contains control characters"),
                    exit::PROTOCOL_ERROR,
                );
            }
            let Some(scheme) = validate_url(&url) else {
                return emit_err(
                    &format!(
                        "invalid remote URL '{url}': must start with 'mkit+<scheme>://'\n\
                         hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)",
                    ),
                    exit::PROTOCOL_ERROR,
                );
            };
            if let Some(name) = name {
                if let Err(code) = validate_remote_name(&name) {
                    return code;
                }
                cfg.remotes.insert(
                    name,
                    RemoteEntry {
                        url,
                        remote_type: scheme.to_owned(),
                    },
                );
            } else {
                cfg.remote_endpoint = url;
                scheme.clone_into(&mut cfg.remote_type);
            }
            match config::write(&layout, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        Some(RemoteCmd::Remove { name }) => {
            // Removing a remote only touches the repo-scoped address
            // book. The user-scoped `trusted_remote_endpoint` (#97) is
            // keyed by exact URL, not by remote name, and is never
            // serialised by `config::write`, so the credential-trust
            // boundary is unaffected: a later remote reusing the same URL
            // would still be trusted, and one with a new URL still
            // requires an explicit `config trusted_remote_endpoint`.
            if name == config::DEFAULT_REMOTE_NAME {
                if cfg.remote_endpoint.is_empty() {
                    return emit_err("no default remote configured", exit::GENERAL_ERROR);
                }
                cfg.remote_endpoint.clear();
                cfg.remote_type.clear();
                cfg.remote_bucket.clear();
            } else if cfg.remotes.remove(&name).is_none() {
                return emit_err(&format!("remote '{name}' not found"), exit::GENERAL_ERROR);
            }
            // Configured remotes nested under `name` (#660): their ref
            // and bridge-state subtrees must survive the removal even
            // though they share `name`'s directory prefix.
            let siblings = nested_sibling_names(&cfg.remotes, &name);
            match config::write(&layout, &cfg) {
                Ok(()) => {
                    // Stale tracking refs would shadow a future remote
                    // reusing the name; objects stay (gc owns them).
                    remove_tracking_refs(&layout, &name, &siblings);
                    remove_applied_packs_record(&layout, &name);
                    warn_orphaned_bridge_state(&layout, &name);
                    exit::OK
                }
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        Some(RemoteCmd::Rename { old, new }) => {
            if old == config::DEFAULT_REMOTE_NAME || new == config::DEFAULT_REMOTE_NAME {
                return emit_err(
                    "cannot rename the reserved `default` remote; use `remote add`/`remote remove`",
                    exit::PROTOCOL_ERROR,
                );
            }
            if let Err(code) = validate_remote_name(&new) {
                return code;
            }
            let Some(entry) = cfg.remotes.remove(&old) else {
                return emit_err(&format!("remote '{old}' not found"), exit::GENERAL_ERROR);
            };
            if cfg.remotes.contains_key(&new) {
                // Put the source back so a failed rename is a no-op.
                cfg.remotes.insert(old, entry);
                return emit_err(&format!("remote '{new}' already exists"), exit::CANTCREAT);
            }
            // Configured remotes nested under `old` (#660): computed
            // before `new` is inserted below, so `new` can never be
            // mistaken for one of `old`'s own siblings even when `new`
            // itself extends `old` (`rename a a/sub`).
            let siblings = nested_sibling_names(&cfg.remotes, &old);
            cfg.remotes.insert(new.clone(), entry);
            // Repoint any branch upstreams that tracked the old name.
            for up in cfg.branch_upstreams.values_mut() {
                if up.remote == old {
                    up.remote.clone_from(&new);
                }
            }
            match config::write(&layout, &cfg) {
                Ok(()) => {
                    move_tracking_refs(&layout, &old, &new, &siblings);
                    move_bridge_state(&layout, &old, &new, &siblings);
                    move_applied_packs_record(&layout, &old, &new);
                    exit::OK
                }
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
        Some(RemoteCmd::GetUrl { name }) => {
            // Read-only — reflect the merged view (a default endpoint may be
            // user-scoped).
            let url = if name == config::DEFAULT_REMOTE_NAME {
                (!layered.merged.remote_endpoint.is_empty())
                    .then(|| layered.merged.remote_endpoint.clone())
            } else {
                layered.merged.remotes.get(&name).map(|e| e.url.clone())
            };
            match url {
                Some(u) => {
                    let mut stdout = std::io::stdout().lock();
                    let _ = writeln!(stdout, "{u}");
                    exit::OK
                }
                None => emit_err(&format!("remote '{name}' not found"), exit::GENERAL_ERROR),
            }
        }
        Some(RemoteCmd::SetUrl { name, url }) => {
            if config::validate_value(&url).is_err() {
                return emit_err(
                    &format!("invalid remote URL '{url}': contains control characters"),
                    exit::PROTOCOL_ERROR,
                );
            }
            let Some(scheme) = validate_url(&url) else {
                return emit_err(
                    &format!("invalid remote URL '{url}': must start with 'mkit+<scheme>://'"),
                    exit::PROTOCOL_ERROR,
                );
            };
            if name == config::DEFAULT_REMOTE_NAME {
                if cfg.remote_endpoint.is_empty() {
                    return emit_err("no default remote configured", exit::GENERAL_ERROR);
                }
                cfg.remote_endpoint = url;
                scheme.clone_into(&mut cfg.remote_type);
            } else {
                let Some(entry) = cfg.remotes.get_mut(&name) else {
                    return emit_err(&format!("remote '{name}' not found"), exit::GENERAL_ERROR);
                };
                entry.url = url;
                scheme.clone_into(&mut entry.remote_type);
            }
            match config::write(&layout, &cfg) {
                Ok(()) => exit::OK,
                Err(e) => emit_err(&format!("write: {e}"), exit::CANTCREAT),
            }
        }
    }
}

/// Best-effort move of `refs/remotes/<old>/` to `refs/remotes/<new>/`
/// after a rename. Failure is reported but non-fatal: the config
/// rename already happened, and a follow-up fetch repopulates.
///
/// `siblings` lists the configured remote names nested under `old`
/// (#660, `nested_sibling_names`); this joins them against the root it
/// already owns (`layout.remotes_dir()`) to build the protected set that
/// `move_state_dir` needs — empty in the overwhelmingly common case, in
/// which `move_state_dir` takes its whole-directory fast path.
fn move_tracking_refs(layout: &RepoLayout, old: &str, new: &str, siblings: &[String]) {
    let root = layout.remotes_dir();
    let protected: Vec<PathBuf> = siblings.iter().map(|s| root.join(s)).collect();
    if let Err(e) = move_state_dir(&root, old, new, &protected) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not move tracking refs {old} -> {new}: {e}; \
             run `mkit fetch {new}` to repopulate"
        );
    }
}

/// Bridge state under `.mkit/git/<name>/` follows a rename so leases,
/// maps, and the staging mirror stay bound to the same remote name.
///
/// `siblings` lists the configured remote names nested under `old`
/// (#660, `nested_sibling_names`); this joins them against the root it
/// already owns (`layout.git_state_dir()`) to build the protected set —
/// see `move_tracking_refs` for the shared `move_state_dir` call.
fn move_bridge_state(layout: &RepoLayout, old: &str, new: &str, siblings: &[String]) {
    let root = layout.git_state_dir();
    let protected: Vec<PathBuf> = siblings.iter().map(|s| root.join(s)).collect();
    if let Err(e) = move_state_dir(&root, old, new, &protected) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not move git-bridge state {old} -> {new}: {e}"
        );
    }
}

/// The applied-packs record (`<common dir>/applied-packs/<name>`, #409) is a
/// pure per-remote cache whose lifecycle follows the remote's (#545): drop it
/// on remove so a later re-add of the same name starts from an empty record
/// instead of inheriting a stale one (which would trip the fetch-side
/// self-heal's spurious full re-download once the store has been gc'd).
/// Best-effort and non-fatal, like the tracking-ref cleanup: on failure the
/// self-heal still recovers, at the cost of that one re-download.
fn remove_applied_packs_record(layout: &RepoLayout, name: &str) {
    if let Err(e) = AppliedPacks::remove_record(layout, name) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not remove applied-packs record for '{name}': {e}"
        );
    }
}

/// The applied-packs record follows a rename (#545), so the renamed remote's
/// next fetch reuses its redownload-avoidance cache instead of pulling the
/// full pack chain again, and no orphan record is left under the old name.
/// Best-effort and non-fatal, like `move_tracking_refs`: on failure the next
/// `mkit fetch <new>` rebuilds the record with one full download.
fn move_applied_packs_record(layout: &RepoLayout, old: &str, new: &str) {
    if let Err(e) = AppliedPacks::rename_record(layout, old, new) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not move applied-packs record {old} -> {new}: {e}"
        );
    }
}

/// Move the per-remote state directory for `old` to `new` under `root`,
/// tolerating multi-segment remote names (which map to nested
/// subdirectories) on both sides, *including* the case where one name is
/// a path-prefix of the other (`a` <-> `a/b`), and *including* the case
/// where a configured sibling remote nests inside `old`'s own directory
/// prefix (`a/b` configured while `a` is renamed or removed, #660) and
/// must not be dragged along or deleted with it. `protected` (built by
/// the caller via `nested_sibling_names` + its own root) lists the
/// absolute paths of those siblings' state directories; empty in the
/// overwhelmingly common case.
///
/// A direct `fs::rename(src, dst)` breaks on the prefix case in both
/// directions: renaming `a` to `a/b` asks the OS to move a directory into
/// its own subtree (EINVAL), and renaming `a/b` to `a` lands on the
/// non-empty old ancestor (ENOTEMPTY). git's per-ref transactions don't
/// have this problem, so this was a real parity gap, not an exotic
/// input.
///
/// # Mechanism: one two-phase move through a temp sibling
///
/// The fix is a move through a dot-named temp directory directly under
/// `root`, `.rename.tmp.<pid>.0` — one path, no prefix-nesting or
/// protected-sibling case analysis at the call site.
///
/// Phase 1 extracts `src`'s content into `tmp`:
/// - `protected.is_empty()` (no sibling in the way): a single
///   whole-directory `fs::rename(&src, &tmp)` — always legal, since
///   renaming a directory to a fresh sibling of `root` is never a move
///   into its own subtree. This is the pre-#660 fast path, still exactly
///   two renames total for the common case.
/// - otherwise: `tmp` is created empty and `walk_unprotected` extracts
///   every unprotected entry under `src` into it one at a time (skipping
///   protected roots whole, recursing through their ancestors), leaving
///   each protected subtree exactly where it is — still under `src`, not
///   dragged to the equivalent position under `dst`.
///
/// Either way `tmp` ends up holding exactly what should land at `dst`.
/// Phase 2 (`prune_empty_parents`) tidies `src`'s now-empty ancestors —
/// `src` itself may legitimately remain non-empty when protected content
/// stayed behind, which is the point. Phase 3 creates `dst`'s parents
/// (`fs::rename` won't). Phase 4 is the single `fs::rename(&tmp, &dst)`
/// that completes the move.
///
/// A missing source directory is a no-op (nothing to move).
///
/// # Restore / "parked at" contract — covers every phase, not just the
/// final rename
///
/// If anything from phase 1 through phase 4 fails after content has
/// actually reached `tmp`, the move backs out on a best-effort basis
/// before the error is returned, so a failed move is a clean no-op
/// rather than stranding state — the caller's existing warning then
/// fires as before, and a follow-up fetch self-heals. If `tmp` never
/// received any content (phase 1 itself failed outright — `create_dir`
/// or the whole-dir rename never succeeded), there is nothing to restore
/// and the original error is returned unadorned.
///
/// The restore is one helper for both shapes: try `fs::rename(&tmp,
/// &src)` first — this succeeds outright when `src` vanished entirely
/// (the fast-path case, where nothing remains at `src` to collide with).
/// If that fails (the selective case, where `src` still exists holding
/// retained protected content, so a whole-directory rename onto it is
/// rejected), fall back to `merge_tree_into(&tmp, &src)`, which merges
/// `tmp`'s entries back into `src` one at a time, recursing into any
/// like-named retained ancestor directory instead of clobbering it.
///
/// When the restore succeeds — by either path — the original error is
/// returned as-is. The `"; state parked at <tmp>"` annotation is added
/// ONLY when the restore itself also fails, since that's the one case
/// where the plain error text says nothing about where the content
/// actually went. A `merge_tree_into` success followed by a failed
/// best-effort `remove_dir(&tmp)` cleanup does NOT count as a restore
/// failure and must NOT trigger the annotation (finding 5c, #789): the
/// content is home, and a leftover (near-)empty `tmp` husk is inert
/// debris, not stranded state.
///
/// Parent creation/pruning (phases 2 and 3) are themselves best-effort:
/// a creation failure falls through to the following `rename`, which
/// then fails and is handled by the same restore path; a prune failure
/// is silent since it's tidiness, not correctness.
///
/// # Crash safety
///
/// A crash between phases leaves a `.rename.tmp.<pid>.0` directory
/// orphaned directly under `root` (the same temp-name convention as
/// `atomic::write_atomic`, `atomic.rs:44-46`, so crash debris is
/// grep-able by one pattern across the codebase). Unlike the
/// pre-existing empty-dir warts on this warn-only path, this one may be
/// fully populated — but a dot-leading path component is invalid per
/// `validate_ref_name` (`refs::validate_ref_name`, SPEC-REFS §3), so
/// every listing enumerator (`show-ref`, `for-each-ref`,
/// `list_remote_names`) and the git-bridge `state_names` scan treat it
/// as inert rather than a phantom remote or ref namespace. The temp name
/// can't collide with any live remote's state directory either, since
/// remote names are validated dot-free (`validate_remote_name`). The
/// "name" component is the fixed literal `rename` rather than
/// `old`/`new`: those may be multi-segment remote names
/// (`team/upstream`), and embedding a `/` into a single path component
/// here would make `root.join(...)` build a *nested* path instead of a
/// flat sibling, defeating the one-temp-dir-directly-under-`root`
/// invariant this whole function relies on. The suffix is fixed at `.0`
/// rather than reusing `atomic`'s process-wide counter (private to
/// `mkit-core`, unreachable from this crate) because a single call
/// creates and consumes at most one temp dir before returning, so
/// nothing within one call can collide with it.
///
/// # Adopted edge case
///
/// A protected root that exists as a plain *file* (a branch-path /
/// remote-name collision inherent to the directory-keyed layout, and
/// predating #660) is adopted into the protection set by
/// `walk_unprotected`'s exact-path check and left untouched — the safe
/// direction for an input this function doesn't otherwise reason about.
///
/// # Destination-side nesting boundary (finding 3, #789 — not fixed here)
///
/// `protected` is always computed by the caller from `old`
/// (`nested_sibling_names(remotes, old)`), never from `new`. When a
/// configured sibling instead nests under the DESTINATION — `rename a/b
/// a` while `a/x` is configured, or `rename a a/b` while `a/b/c` is
/// configured — this function has no way to see that from `old` alone,
/// so it takes the ordinary fast or selective path as if no sibling were
/// involved, and the final `fs::rename(&tmp, &dst)` lands on `dst`'s
/// already-occupied directory and fails closed: the restore contract
/// above fires, the caller's standard warning is emitted, and the
/// source state is intact rather than merged into the sibling's
/// directory or dragging it along. This is a deliberate boundary, not a
/// bug — see the #660/#789 PR discussion for why destination-side
/// protection (computing and reasoning about siblings of `new` too) is
/// out of scope here. `rename_round_trip_into_sibling_fails_closed`
/// pins this exact shape.
fn move_state_dir(root: &Path, old: &str, new: &str, protected: &[PathBuf]) -> std::io::Result<()> {
    let (src, dst) = (root.join(old), root.join(new));
    if !src.is_dir() {
        return Ok(());
    }
    let tmp = root.join(format!(".rename.tmp.{}.0", std::process::id()));

    let extracted = if protected.is_empty() {
        std::fs::rename(&src, &tmp)
    } else {
        std::fs::create_dir(&tmp).and_then(|()| {
            walk_unprotected(&src, protected, &mut |entry: &Path| {
                // `entry` always came from `read_dir(src)` (directly, or
                // via a recursive `walk_unprotected` call rooted at an
                // ancestor under `src`), so it is always under `src` —
                // never leave an entry behind on the strength of a
                // silently-ignored mismatch here (finding 5a, #789).
                let rel = entry
                    .strip_prefix(&src)
                    .expect("walk_unprotected only ever yields entries located under src");
                let target = tmp.join(rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(entry, &target)
            })
        })
    };

    let result = extracted.and_then(|()| {
        prune_empty_parents(&src, root);
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::rename(&tmp, &dst)
    });

    let Err(e) = result else {
        return Ok(());
    };
    if !tmp.exists() {
        // Phase 1 never got as far as creating/populating `tmp`: `src`
        // is untouched, so there is nothing to restore.
        return Err(e);
    }
    let _ = std::fs::create_dir_all(&src);
    if std::fs::rename(&tmp, &src).is_ok() {
        return Err(e);
    }
    if merge_tree_into(&tmp, &src).is_err() {
        // The restore itself failed too: state is now parked at `tmp`,
        // not `src`. Say so — the original error alone doesn't tell the
        // caller (and its warning) where the state actually ended up.
        return Err(std::io::Error::new(
            e.kind(),
            format!("{e}; state parked at {}", tmp.display()),
        ));
    }
    // Merge succeeded: the state is home. `tmp` is now an inert
    // (near-)empty husk; best-effort cleanup only — its failure is
    // tidiness debris, not stranded state, so the annotation above must
    // not fire for it (finding 5c, #789).
    let _ = std::fs::remove_dir(&tmp);
    Err(e)
}

/// Walk up from `dir`, removing empty directories, until `root` is
/// reached or a removal fails (a non-empty directory is the natural
/// terminator — no need to distinguish that from other errors).
fn prune_empty_parents(dir: &Path, root: &Path) {
    let mut dir = dir.parent();
    while let Some(d) = dir {
        if d == root || std::fs::remove_dir(d).is_err() {
            break;
        }
        dir = d.parent();
    }
}

/// Configured remote names that are proper extensions of `name`
/// (`name + "/"` prefix): the subtrees under `name`'s state directories
/// that actually belong to OTHER configured remotes and must survive a
/// rename/remove of `name` (#660). Empty in the overwhelmingly common
/// case, in which callers take the pre-existing whole-directory fast
/// path unchanged.
fn nested_sibling_names(remotes: &BTreeMap<String, RemoteEntry>, name: &str) -> Vec<String> {
    let prefix = format!("{name}/");
    remotes
        .keys()
        .filter(|k| k.starts_with(&prefix))
        .cloned()
        .collect()
}

/// Visit the entries of `dir` bottom-up, skipping any entry that IS a
/// protected root (left untouched — not handed to `f`, not recursed
/// into) and recursing into any entry that is an ANCESTOR of a
/// protected root; every other entry is handed to `f` whole, since its
/// subtree cannot contain a protected path. After visiting, `dir`
/// itself is opportunistically removed via `remove_dir`: success means
/// every unprotected entry left and no protected subtree remains
/// beneath it; failure (non-empty) is the natural terminator, not an
/// error, mirroring `prune_empty_parents`.
///
/// The entry list is snapshotted with one `read_dir` before any
/// mutation happens, so a destination created inside `dir` by `f`
/// itself (a rename into `dir`'s own subtree) is never iterated.
///
/// A missing `dir` is a no-op, matching the fast paths this is an
/// alternative to. Like every other helper on these rename/remove
/// paths, failure is best-effort: the first error from `f` (or from
/// `read_dir`) aborts the walk immediately and propagates to the
/// caller's existing warn-only handling — partial state is acceptable
/// here and self-heals on the next fetch.
fn walk_unprotected(
    dir: &Path,
    protected: &[PathBuf],
    f: &mut dyn FnMut(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    for entry in entries {
        if protected.iter().any(|p| p == &entry) {
            // `entry` IS a protected root: leave it, and everything
            // beneath it, entirely alone.
            continue;
        }
        if protected.iter().any(|p| p.starts_with(&entry)) {
            // `entry` is an ancestor of some protected root: recurse so
            // its unprotected children are still visited individually.
            walk_unprotected(&entry, protected, f)?;
        } else {
            // No protected path can live under `entry` — hand it to `f`
            // whole.
            f(&entry)?;
        }
    }
    let _ = std::fs::remove_dir(dir);
    Ok(())
}

/// Restore helper for `move_state_dir`'s occupied-destination /
/// mid-extraction failure: moves every entry under `from` into `into`,
/// recursing into any like-named directory that already exists at the
/// destination (needed because `into` — `src` — may have retained
/// ancestor directories of protected content that a moved entry's
/// relative path nests under, finding 4 / #789) and renaming everything
/// else directly. Not a general merge utility: used only to put
/// `move_state_dir`'s temp contents back where they came from.
fn merge_tree_into(from: &Path, into: &Path) -> std::io::Result<()> {
    // Snapshot the entry list before any mutation, the same discipline
    // as `walk_unprotected` (finding 5b, #789): recursing into a
    // like-named destination directory below mutates `into`, and a
    // naive un-snapshotted `read_dir(from)` iterator is only required to
    // reflect entries present at some unspecified point during the
    // scan, not to ignore ones renamed away out from under it mid-walk.
    let entries: Vec<PathBuf> = std::fs::read_dir(from)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    for path in entries {
        let name = path
            .file_name()
            .expect("read_dir entries always have a file name");
        let target = into.join(name);
        if path.is_dir() && target.is_dir() {
            merge_tree_into(&path, &target)?;
            std::fs::remove_dir(&path)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&path, &target)?;
        }
    }
    Ok(())
}

/// Removing a remote leaves its bridge state in place (it holds the
/// staging mirror + retained provenance, which are durable artifacts,
/// not caches) — but say so.
fn warn_orphaned_bridge_state(layout: &RepoLayout, name: &str) {
    let dir = layout.git_state_dir().join(name);
    if dir.is_dir() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "note: git-bridge state for '{name}' remains at .mkit/git/{name}/ \
             (staging mirror + provenance); delete it manually if unwanted"
        );
    }
}

/// Best-effort removal of `refs/remotes/<name>/` after a remove.
///
/// `siblings` lists the configured remote names nested under `name`
/// (#660, `nested_sibling_names`); this joins them against the root it
/// already owns (`layout.remotes_dir()`) to build the protected set. When
/// empty (the overwhelmingly common case) this is the unchanged
/// whole-directory `remove_dir_all` fast path; otherwise a selective walk
/// deletes only the entries not on a protected sibling's path, so `a/b`'s
/// refs survive `remove a`.
fn remove_tracking_refs(layout: &RepoLayout, name: &str, siblings: &[String]) {
    let root = layout.remotes_dir();
    let dir = root.join(name);
    let protected: Vec<PathBuf> = siblings.iter().map(|s| root.join(s)).collect();
    let result = if protected.is_empty() {
        if dir.is_dir() {
            std::fs::remove_dir_all(&dir)
        } else {
            Ok(())
        }
    } else {
        walk_unprotected(&dir, &protected, &mut |entry: &Path| {
            if entry.is_dir() {
                std::fs::remove_dir_all(entry)
            } else {
                std::fs::remove_file(entry)
            }
        })
    };
    if let Err(e) = result {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: could not remove tracking refs for '{name}': {e}"
        );
    }
}

/// Validate a named-remote name: rejects control characters, non
/// ref-safe names, dots (which would collide with the
/// `remote.<name>.<field>` config key grammar), and the reserved
/// `default` name. Returns the CLI exit code to propagate on failure.
fn validate_remote_name(name: &str) -> Result<(), u8> {
    if config::validate_value(name).is_err() {
        return Err(emit_err(
            &format!("invalid remote name '{name}': contains control characters"),
            exit::PROTOCOL_ERROR,
        ));
    }
    if !mkit_core::refs::validate_ref_name(name)
        || name.contains('.')
        || name == config::DEFAULT_REMOTE_NAME
    {
        return Err(emit_err(
            &format!(
                "invalid remote name '{name}': must be a dot-free ref-safe name \
                 (and not the reserved `default`)"
            ),
            exit::PROTOCOL_ERROR,
        ));
    }
    Ok(())
}

fn validate_url(url: &str) -> Option<&'static str> {
    for (prefix, kind) in ACCEPTED_SCHEMES {
        if url.starts_with(prefix) {
            return Some(kind);
        }
    }
    None
}

fn show(cfg: &Config, json: bool, verbose: bool) -> u8 {
    let has_default = !cfg.remote_endpoint.is_empty();
    if !has_default && cfg.remotes.is_empty() {
        // Empty listing → empty stdout in both modes. The default
        // mode emits a human note on stderr.
        if !json {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "(no remote configured)");
        }
        return exit::OK;
    }
    let mut stdout = std::io::stdout().lock();
    if json {
        // Additive shape: when only the default remote is configured,
        // emit the historical single-line object so existing JSON
        // snapshots stay valid. When named remotes exist, emit one JSON
        // object per line (JSONL) carrying a `name` field; the default
        // remote (if any) appears as `name=default`.
        if has_default && cfg.remotes.is_empty() {
            let _ = stdout.write_all(b"{");
            let _ = write!(
                stdout,
                "\"url\":\"{}\"",
                format::json_escape(&cfg.remote_endpoint)
            );
            let _ = write!(
                stdout,
                ",\"transport\":\"{}\"",
                format::json_escape(&cfg.remote_type)
            );
            let _ = stdout.write_all(b"}\n");
            return exit::OK;
        }
        if has_default {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                config::DEFAULT_REMOTE_NAME,
                format::json_escape(&cfg.remote_endpoint),
                format::json_escape(&cfg.remote_type)
            );
        }
        for (name, entry) in &cfg.remotes {
            let _ = writeln!(
                stdout,
                "{{\"name\":\"{}\",\"url\":\"{}\",\"transport\":\"{}\"}}",
                format::json_escape(name),
                format::json_escape(&entry.url),
                format::json_escape(&entry.remote_type)
            );
        }
        return exit::OK;
    }
    // Default (human) form, git-shaped:
    //   `mkit remote`      → one remote NAME per line
    //   `mkit remote -v`   → `<name>\t<url> (fetch)` and `(push)` per remote
    // The flat default remote shows under the reserved name `default`.
    if verbose {
        if has_default {
            let url = &cfg.remote_endpoint;
            let name = config::DEFAULT_REMOTE_NAME;
            let _ = writeln!(stdout, "{name}\t{url} (fetch)");
            let _ = writeln!(stdout, "{name}\t{url} (push)");
        }
        for (name, entry) in &cfg.remotes {
            let _ = writeln!(stdout, "{name}\t{} (fetch)", entry.url);
            let _ = writeln!(stdout, "{name}\t{} (push)", entry.url);
        }
        return exit::OK;
    }
    if has_default {
        let _ = writeln!(stdout, "{}", config::DEFAULT_REMOTE_NAME);
    }
    for name in cfg.remotes.keys() {
        let _ = writeln!(stdout, "{name}");
    }
    exit::OK
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::{PathBuf, walk_unprotected};

    fn touch(path: &std::path::Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn protected_root_is_left_untouched() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("keep/marker.txt"));
        touch(&root.join("drop.txt"));
        let protected = vec![root.join("keep")];
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            if p.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            }
        })
        .unwrap();
        assert!(
            root.join("keep/marker.txt").exists(),
            "protected subtree must survive whole"
        );
        assert!(
            !root.join("drop.txt").exists(),
            "unprotected entry must be visited and removed"
        );
        assert_eq!(visited, vec![root.join("drop.txt")]);
    }

    #[test]
    fn ancestor_of_protected_root_is_recursed_not_removed_whole() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("a/b/c/marker.txt")); // protected root is a/b/c
        touch(&root.join("a/other.txt")); // unprotected sibling under ancestor `a`
        let protected = vec![root.join("a/b/c")];
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            if p.is_dir() {
                std::fs::remove_dir_all(p)
            } else {
                std::fs::remove_file(p)
            }
        })
        .unwrap();
        assert!(
            root.join("a/b/c/marker.txt").exists(),
            "deeply nested protected root must survive"
        );
        assert!(
            !root.join("a/other.txt").exists(),
            "unprotected file under the ancestor must be removed"
        );
        assert_eq!(visited, vec![root.join("a/other.txt")]);
        // `a` and `a/b` survive only because `a/b/c` remains beneath them
        // — proof the ancestor dirs were recursed into, not deleted
        // whole, and that they are NOT force-pruned once emptied of
        // unprotected content.
        assert!(root.join("a").is_dir());
        assert!(root.join("a/b").is_dir());
    }

    #[test]
    fn snapshot_is_taken_before_any_mutation() {
        // Mirrors a rename into the walked directory's own subtree:
        // `f` creates a NEW entry inside `dir` as a side effect. That
        // entry must never be visited by this same walk, since the
        // entry list was snapshotted up front.
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        touch(&root.join("existing.txt"));
        let protected: Vec<PathBuf> = Vec::new();
        let mut visited = Vec::new();
        walk_unprotected(root, &protected, &mut |p| {
            visited.push(p.to_path_buf());
            std::fs::write(root.join("created-during-walk.txt"), b"new").unwrap();
            std::fs::remove_file(p)
        })
        .unwrap();
        assert_eq!(visited, vec![root.join("existing.txt")]);
        assert!(
            root.join("created-during-walk.txt").exists(),
            "entry created mid-walk must not be picked up by the same walk"
        );
    }

    #[test]
    fn dir_is_removed_bottom_up_after_its_entries_are_individually_processed() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path();
        let sub = root.join("a");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("one.txt"), b"1").unwrap();
        std::fs::write(sub.join("two.txt"), b"2").unwrap();
        let protected: Vec<PathBuf> = Vec::new();
        walk_unprotected(&sub, &protected, &mut |p| {
            assert!(
                p.is_file(),
                "each entry is handed to f individually, never the dir itself"
            );
            std::fs::remove_file(p)
        })
        .unwrap();
        // `f` only ever saw the two files; `sub`'s own removal is the
        // walker's bottom-up cleanup once it is empty, not something
        // `f` did.
        assert!(
            !sub.exists(),
            "now-empty dir must be removed by the walk itself"
        );
    }
}
