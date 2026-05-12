//! Signal handling — SIGINT / SIGTERM set a graceful-shutdown flag
//! that long-running operations (`push` / `pull` / `clone` / `log`)
//! poll at natural checkpoints, so a `Ctrl-C` aborts cleanly with
//! `exit::TEMPFAIL` (75) rather than leaving a half-finished transfer.
//!
//! ## SIGPIPE is intentionally not registered here
//!
//! Rust's runtime sets `SIGPIPE` to `SIG_IGN` at process start since
//! 1.65, which means `write(2)` on a closed pipe returns `EPIPE`
//! instead of terminating the process. The CLI uses
//! `let _ = writeln!(stdout, …)` everywhere, so the `EPIPE` propagates
//! as a silently-dropped `io::Error` and the program exits at its
//! next natural completion point — exactly the pipeline-friendly
//! behaviour `docs/CLI.md` advertises.
//!
//! Registering a signal-hook handler over the runtime's `SIG_IGN`
//! would replace a clean kernel-level ignore with a userspace handler
//! that does an atomic store and returns — observationally
//! equivalent but strictly worse (extra wakeups, a window where a
//! different thread might briefly observe a flipped flag we never
//! consume). The integration test in `tests/sigpipe.rs` is the
//! regression guard: it pipes `mkit cat <large-blob>` through
//! `head -1` and asserts the left-hand exit code is `0`. If anyone
//! ever opts mkit out of Rust's default with `#[unix_sigpipe]`, that
//! test goes red.
//!
//! ## Implementation
//!
//! `signal-hook`'s `flag` module installs the handlers via
//! `sigaction(2)` and exposes a fully safe API (atomic-bool stores
//! are async-signal-safe; the `unsafe` lives inside the crate). The
//! CLI stays under its crate-level `#![deny(unsafe_code)]`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Shared shutdown flag. Lazily initialised so tests that exercise the
/// flag without going through [`install`] still observe a coherent
/// value. The `Arc` is required because `signal_hook::flag::register`
/// takes an owned `Arc<AtomicBool>` — it does not accept a `&'static`.
static SHUTDOWN: OnceLock<Arc<AtomicBool>> = OnceLock::new();

fn shutdown_flag() -> &'static Arc<AtomicBool> {
    SHUTDOWN.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Install SIGINT/SIGTERM handlers that flip the shared shutdown flag.
/// Idempotent on the `signal-hook` side: re-registering the same
/// signal layers another handler on top, but the cost is a few bytes
/// and the observable behaviour is unchanged, so callers can invoke
/// this more than once without harm.
///
/// On non-Unix targets this is a no-op (Windows signal semantics
/// differ; the CLI does not currently ship on Windows).
pub fn install() {
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};

        let flag = Arc::clone(shutdown_flag());
        // Errors here are effectively unreachable (they only fail if
        // the OS refuses to install a handler, e.g. for SIGKILL).
        // Silently fall back to the default disposition in that case
        // — the user sees the same behaviour they would have seen
        // before this change.
        let _ = signal_hook::flag::register(SIGINT, Arc::clone(&flag));
        let _ = signal_hook::flag::register(SIGTERM, flag);
    }
}

/// Returns `true` once a shutdown was requested via signal. Long-
/// running poll loops should call this at natural checkpoints and
/// return `exit::TEMPFAIL` when it flips.
#[must_use]
pub fn is_shutdown() -> bool {
    SHUTDOWN
        .get()
        .is_some_and(|f| f.load(Ordering::Relaxed))
}

/// Alias kept for historical callers. Prefer [`is_shutdown`].
#[must_use]
pub fn interrupted() -> bool {
    is_shutdown()
}

/// Test hook — flips the shutdown flag so unit tests can verify that
/// long-running callers do honour it once it flips.
#[doc(hidden)]
pub fn set_interrupted_for_tests(v: bool) {
    shutdown_flag().store(v, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_round_trips() {
        set_interrupted_for_tests(true);
        assert!(interrupted());
        set_interrupted_for_tests(false);
        assert!(!interrupted());
    }

    /// `install()` must not pre-flip the flag — long-running callers
    /// poll `is_shutdown()` and would otherwise abort immediately.
    #[test]
    fn install_then_is_shutdown_returns_false() {
        set_interrupted_for_tests(false);
        install();
        assert!(!is_shutdown());
        assert!(!interrupted(), "alias must agree with is_shutdown");
    }

    /// Double-install must not panic. Tests share a process, so any
    /// other test that calls `install()` first must leave this one
    /// in a working state.
    #[test]
    fn install_is_idempotent() {
        install();
        install();
        set_interrupted_for_tests(false);
    }
}
