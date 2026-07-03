//! Dev-only helpers shared by test suites across the workspace.
//!
//! Not published — add this crate to `[dev-dependencies]` only.

use std::process::{Command, Stdio};

/// True if `name` can be spawned as a subprocess (i.e. it resolves on
/// `PATH`). We only care whether the OS could exec it, not its exit code —
/// some tools (e.g. `ssh`) reject `--version`-style flags but are still
/// present.
#[must_use]
pub fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Returns `true` if `name` is available. If it is not: panic when
/// `MKIT_TEST_STRICT` is set (a CI job that is supposed to have this tool
/// silently not running the test is a bug), otherwise print a loud `SKIP:`
/// line to stderr and return `false` so the caller can skip.
///
/// # Panics
///
/// Panics if `name` is unavailable and `MKIT_TEST_STRICT` is set.
#[must_use]
pub fn require_tool(name: &str) -> bool {
    if tool_available(name) {
        return true;
    }
    assert!(
        std::env::var_os("MKIT_TEST_STRICT").is_none(),
        "{name} required (MKIT_TEST_STRICT set) but not found"
    );
    eprintln!("SKIP: {name} not available");
    false
}
