//! sysexits(3)-style exit codes for the mkit CLI.
//!
//! Shell scripts that pipe `mkit ... || handle` use `$?` to distinguish
//! usage errors from transient transport failures. See `docs/CLI.md`
//! §"Exit codes" for the documented contract.

/// Successful termination.
pub const OK: u8 = 0;

/// Catch-all for errors that do not fit a more specific category.
pub const GENERAL_ERROR: u8 = 1;

/// Wrong args or unknown subcommand.
pub const USAGE: u8 = 64;

/// Malformed input — corrupt object, bad hash literal on the CLI, etc.
pub const DATAERR: u8 = 65;

/// Input file does not exist or is unreadable.
pub const NOINPUT: u8 = 66;

/// Transport could not connect.
pub const UNAVAILABLE: u8 = 69;

/// Cannot create an output file.
pub const CANTCREAT: u8 = 73;

/// Temporary failure; retry is safe.
pub const TEMPFAIL: u8 = 75;

/// Bad URL scheme or malformed server response.
pub const PROTOCOL_ERROR: u8 = 76;

/// Permission denied.
pub const NOPERM: u8 = 77;

/// Unknown config key or invalid config value.
pub const CONFIG_ERROR: u8 = 78;
