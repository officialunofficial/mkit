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
    /// 14 days). `0` prunes every unreachable object.
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
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // Serialize against every mutating command for the whole run, so the
    // live set can't shift between expire, the reachability walk, and the
    // sweep.
    let _lock = match super::acquire_worktree_lock(&cwd) {
        Ok(l) => l,
        Err(code) => return code,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Expire stale recovery entries first so they stop pinning objects;
    // abort on error (fail closed — don't prune against a half-expired log).
    let expired = match recovery::expire(&mkit_dir, now, &RetentionPolicy::default()) {
        Ok(n) => n,
        Err(e) => return emit_err(&format!("expire recovery log: {e}"), exit::CANTCREAT),
    };

    let report = match run_gc(&store, &mkit_dir, now, opts.grace_secs, opts.dry_run) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("gc: {e}"), exit::GENERAL_ERROR),
    };

    let mut stderr = std::io::stderr().lock();
    let verb = if report.dry_run {
        "would prune"
    } else {
        "pruned"
    };
    let _ = writeln!(
        stderr,
        "gc{}: {verb} {} object(s), {} bytes; scanned {}, live {}, kept-recent {}; expired {} recovery entr{}",
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

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}
