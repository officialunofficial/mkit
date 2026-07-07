//! `mkit gc` — reclaim unreachable objects (mark-and-sweep prune).
//!
//! Under the repo lock: expire the recovery log, compute the live-object
//! keep-set (every object reachable from the retention roots — refs,
//! stash, in-progress op state, attestations, and the recovery log), then
//! delete unreachable objects that are older than the grace window.
//!
//! Safety: the live set is computed **before** anything is deleted and
//! the whole run is **fail-closed** — a missing/corrupt root, a malformed
//! ref, or the reachability cap aborts with nothing removed (see
//! `mkit_core::ops::gc`). Unreachable objects younger than the grace
//! window (default 14 days) are kept as a belt-and-suspenders against
//! objects written just before a reference that points at them. Use
//! `--dry-run` to preview, and `--grace-secs 0` to prune every
//! unreachable object regardless of age.
//!
//! Concurrency: gc holds the repo lock for its whole run, and the
//! root-publishing paths now take the same lock around their object-write +
//! ref/attestation-publish window — `tag` (annotated/signed), `fetch` /
//! `pull`, and `attest` (#267) — so they are serialized against gc. The
//! grace window remains the belt-and-suspenders net (like Git's default
//! `gc.pruneExpire`, vs `prune --expire=now`): `--grace-secs 0` bypasses it
//! and prints a warning, but with the publishers now locked it is safe even
//! under concurrency.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use mkit_core::ops::recovery::{self, RetentionPolicy};
use mkit_core::ops::run_gc;
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;

/// Default object grace window: 14 days, matching Git's `gc.pruneExpire`.
const DEFAULT_GRACE_SECS: u64 = 14 * 24 * 60 * 60;

#[derive(Debug, Parser)]
#[command(
    name = "mkit gc",
    about = "Reclaim unreachable objects (delete unreachable objects older than the grace window)."
)]
struct GcOpts {
    /// Show what would be pruned without deleting anything.
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,

    /// Keep unreachable objects younger than this many seconds (default
    /// 14 days). `0` prunes every unreachable object, but bypasses the
    /// grace window that protects in-flight objects — only safe when no
    /// other mkit process is operating on the repo.
    #[arg(long = "grace-secs", value_name = "SECS", default_value_t = DEFAULT_GRACE_SECS)]
    grace_secs: u64,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<GcOpts>("mkit gc", args) {
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

    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Hold EVERY worktree's lock for the whole run (#493 Phase 3) —
    // the shared lock spanning trees. Root collection unions each
    // tree's HEAD/index/op-state, so gc must serialize against
    // worktree/index-mutating commands in ALL trees, not just the
    // invoking one, plus other gc runs. Acquisition order is
    // deterministic (main first, then registry ids ascending, from
    // `all_state_layouts`) so concurrent multi-lock takers cannot
    // deadlock. It still does NOT serialize against the non-worktree
    // root publishers (`tag`, `fetch`, `attest`) — those don't take
    // this lock (#267); the grace window protects their in-flight
    // objects, exactly as in the single-tree case.
    // Registry lock FIRST (global lock order: worktrees.lock before
    // any per-tree worktree.lock, see SPEC-WORKTREE §4.3): freezes the
    // worktree set for the whole run, so a `worktree add` cannot
    // register a fresh tree — and start staging into it — between
    // enumeration and the sweep.
    let _registry_lock = match super::acquire_worktrees_registry_lock(&layout) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let state_layouts = match mkit_core::layout::all_state_layouts(&layout) {
        Ok(l) => l,
        Err(e) => return super::error(&format!("worktree registry: {e}"), exit::DATAERR),
    };
    let mut locks = Vec::with_capacity(state_layouts.len());
    for tree in &state_layouts {
        match super::acquire_worktree_lock(tree) {
            Ok(l) => locks.push(l),
            Err(code) => return code,
        }
    }
    let _locks = locks;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    if opts.grace_secs == 0 && !opts.dry_run {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "warning: --grace-secs 0 prunes every unreachable object, bypassing the grace window; \
             ensure no other mkit process is operating on this repo"
        );
    }

    // Expire stale recovery entries first so they stop pinning objects;
    // abort on error (fail closed — don't prune against a half-expired log).
    // A dry run must not mutate state, so it only *counts* what would
    // expire (and therefore reports a conservative prune set, since those
    // soon-to-expire commits are still pinned during the preview).
    let policy = RetentionPolicy::default();
    let expired = if opts.dry_run {
        match recovery::would_expire(&layout, now, &policy) {
            Ok(n) => n,
            Err(e) => return emit_err(&format!("recovery log: {e}"), exit::GENERAL_ERROR),
        }
    } else {
        match recovery::expire(&layout, now, &policy) {
            Ok(n) => n,
            Err(e) => return emit_err(&format!("expire recovery log: {e}"), exit::CANTCREAT),
        }
    };

    let report = match run_gc(&store, &layout, now, opts.grace_secs, opts.dry_run) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("gc: {e}"), exit::GENERAL_ERROR),
    };

    let mut stderr = std::io::stderr().lock();
    let (prune_verb, expire_verb) = if report.dry_run {
        ("would prune", "would expire")
    } else {
        ("pruned", "expired")
    };
    let _ = writeln!(
        stderr,
        "gc{}: {prune_verb} {} object(s), {} bytes; scanned {}, live {}, kept-recent {}; {expire_verb} {} recovery entr{}",
        if report.dry_run { " (dry run)" } else { "" },
        report.pruned,
        report.bytes_reclaimed,
        report.scanned,
        report.live,
        report.kept_recent,
        expired,
        if expired == 1 { "y" } else { "ies" },
    );
    exit::OK
}

use super::error as emit_err;
