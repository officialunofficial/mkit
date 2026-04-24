//! Subcommand implementations. Each top-level command is its own
//! module, matching the Zig split of `src/main.zig` into per-command
//! `cmdFoo` functions.
//!
//! Dispatch lives in `main.rs`; business logic lives in library
//! crates; this module is the thin presentation shim.

pub mod add;
pub mod bisect;
pub mod blame;
pub mod branch;
pub mod cat;
pub mod checkout;
pub mod cherry_pick;
pub mod clone;
pub mod commit;
pub mod config_cmd;
pub mod diff;
pub mod fetch;
pub mod hash_cmd;
pub mod init;
pub mod keygen;
pub mod log;
pub mod merge;
pub mod pull;
pub mod push;
pub mod rebase;
pub mod remote;
pub mod rm;
pub mod serve;
pub mod sparse_checkout;
pub mod stash;
pub mod status;
pub mod tag;
pub mod tree;
pub mod verify;

use crate::exit;
use std::io::Write;

/// Shared helper: emit a "not yet wired in the Rust port" notice and
/// return the tempfail exit code. The Rust CLI exists primarily to get
/// the binary, version contract, and plumbing in place for Phase 10;
/// commands whose backing state-machines have not been ported yet say
/// so honestly rather than pretending to work.
#[must_use]
pub fn not_yet_ported(cmd: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "error: `mkit {cmd}` is not yet wired in the Rust port (Phase 10 follow-up)"
    );
    exit::TEMPFAIL
}

/// Shared helper: print a usage error and return the USAGE exit code.
#[must_use]
pub fn usage_error(msg: &str) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    exit::USAGE
}
