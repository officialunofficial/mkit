//! Signal handling — SIGINT / SIGTERM set a graceful-shutdown flag;
//! SIGPIPE is ignored so `mkit log | head -1` exits cleanly.
//!
//! The Rust port keeps the behaviour dependency-free: we use the
//! `Arc<AtomicBool>` pattern and rely on libc's default SIGPIPE policy
//! (which the process inherits from the shell) rather than pulling in
//! `signal-hook` just for this. The long-running commands (push / pull
//! / clone) are not yet wired into the Rust CLI, so `install()` is a
//! no-op placeholder that lives here to match the Zig module layout —
//! the porting plan promotes it to real signal handling in Phase 10
//! once `mkit-transport-*` crates gain interruptible poll loops.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Install SIGINT/SIGTERM/SIGPIPE handlers. Idempotent; cheap. On
/// 0.2.x this is a no-op — see module docs. Callers (push/pull/clone)
/// should still call `interrupted()` at natural checkpoints so the
/// eventual Phase 10 wiring is transparent.
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
