//! Signal handling — SIGINT / SIGTERM set a graceful-shutdown flag;
//! SIGPIPE is ignored so `mkit log | head -1` exits cleanly.
//!
//! ## Current behavior
//!
//! `install()` is currently a **no-op placeholder**. No OS signal
//! handler is registered. The shared [`SHUTDOWN`] atomic can only be
//! flipped by [`set_interrupted_for_tests`] or by an eventual future
//! hookup once a dependency on `signal-hook` (or equivalent) is
//! accepted. Pulling in `signal-hook` was deliberately deferred to
//! keep `mkit-cli`'s transitive dep set small while the long-running
//! transport verbs (push/pull/clone) are still learning where their
//! natural interruption checkpoints should sit.
//!
//! Callers SHOULD nonetheless call [`is_shutdown`] / [`interrupted`]
//! at poll-loop boundaries so wiring a real handler later is
//! a no-behaviour-change drop-in.
//!
//! TODO(signal-hook): once transport verbs grow interruptible poll
//! loops, register `signal_hook::flag::register(SIGINT, SHUTDOWN)`
//! (and SIGTERM) inside `install()`. Until then it is intentionally
//! empty — see module-level docs.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Install SIGINT/SIGTERM/SIGPIPE handlers. Idempotent; cheap.
///
/// **Today this is a no-op.** It does NOT register an OS-level signal
/// handler; the shared [`SHUTDOWN`] atomic stays `false` until a test
/// flips it via [`set_interrupted_for_tests`]. See module docs for
/// why. Callers (push/pull/clone) should still call [`is_shutdown`]
/// at natural checkpoints so future wiring is transparent.
pub fn install() {
    // Intentionally empty — see module docs.
}

/// Returns `true` when a shutdown was requested via signal. This is
/// the canonical check callers should use at poll-loop boundaries.
///
/// While [`install`] is a no-op this always returns `false` outside
/// tests; wiring a real handler later does not change the API.
#[must_use]
pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
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
    SHUTDOWN.store(v, Ordering::Relaxed);
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

    /// `install()` is a documented no-op: it must not set the flag,
    /// and `is_shutdown()` must report `false` immediately after.
    #[test]
    fn install_then_is_shutdown_returns_false() {
        // Reset in case an earlier test in the same binary left it hot.
        set_interrupted_for_tests(false);
        install();
        assert!(!is_shutdown());
        assert!(!interrupted(), "alias must agree with is_shutdown");
    }
}
