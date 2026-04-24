//! Signal handling — SIGINT / SIGTERM set a graceful-shutdown flag;
//! SIGPIPE is ignored so `mkit log | head -1` exits cleanly.
//!
//! This module is dependency-free: we use the `Arc<AtomicBool>` pattern
//! and rely on libc's default SIGPIPE policy (which the process inherits
//! from the shell) rather than pulling in `signal-hook`. `install()` is
//! a no-op placeholder — it will gain real signal handling once
//! long-running transport verbs grow interruptible poll loops.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Install SIGINT/SIGTERM/SIGPIPE handlers. Idempotent; cheap. Today
/// this is a no-op — see module docs. Callers (push/pull/clone) should
/// still call `interrupted()` at natural checkpoints so a later wiring
/// is transparent.
pub fn install() {
    // Intentionally empty — see module docs.
}

/// Returns `true` when a shutdown was requested via signal.
#[must_use]
pub fn interrupted() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
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
}
