//! `mkit-server`'s exit codes: sysexits(3) values, the same numbers as
//! `mkit-cli`'s `exit` module (`docs/CLI.md`, "Exit codes"), so scripts
//! that drove `mkit serve --http` read them unchanged.

/// Clean shutdown.
pub const OK: u8 = 0;
/// Bad flags: an unknown or malformed flag, or flags that exclude each
/// other.
pub const USAGE: u8 = 64;
/// `--repo-root` is not a directory holding `.mkit`.
pub const DATAERR: u8 = 65;
/// `--repo-root` does not exist.
pub const NOINPUT: u8 = 66;
/// The listener could not bind, or the server failed while running.
pub const UNAVAILABLE: u8 = 69;
/// The shared `serve.lock` could not be taken in time; retry.
pub const TEMPFAIL: u8 = 75;
/// `--repo-root` lies outside `MKIT_SERVE_ROOT`.
pub const NOPERM: u8 = 77;
/// A configuration the server refuses to run: no auth choice, an empty
/// token, auth v2 without `SQLite` metadata, a root whose refs live
/// elsewhere, a store that cannot open.
pub const CONFIG_ERROR: u8 = 78;
