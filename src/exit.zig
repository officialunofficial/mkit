// SPDX-License-Identifier: MIT OR Apache-2.0
//
// sysexits(3)-style exit code constants for the mkit CLI.
//
// Motivation: when a shell script pipes `mkit ... || handle`, having every
// failure collapse to exit 1 makes it impossible to tell a usage error
// ("you typed the wrong thing") from a transient transport failure
// ("retry me") from a hard configuration error ("don't bother retrying").
// The BSD `sysexits.h` constants are the closest thing to a *nix lingua
// franca for this, so we adopt them.
//
// Callers should use these constants at `std.process.exit(...)` sites
// rather than bare integer literals, so that the intent of each exit path
// is self-documenting.
//
// NOTE: We deliberately expose these as `u8` since `std.process.exit`
// takes `u8` on POSIX (exit codes are 8-bit).

/// Successful termination.
pub const ok: u8 = 0;

/// Catch-all for errors that don't fit a more specific category. Prefer a
/// specific code below whenever possible.
pub const general_error: u8 = 1;

/// Command line usage error — wrong number of args, unknown subcommand,
/// unknown flag. Shell scripts that inspect `$?` can distinguish "user
/// typo" (64) from "operation failed" (1).
pub const usage: u8 = 64;

/// Input data was incorrect in some way — malformed object, corrupt pack,
/// invalid hash on the CLI, etc.
pub const dataerr: u8 = 65;

/// An input file (not a system file) did not exist or was not readable.
/// Distinct from `cantcreat` (output-side failure).
pub const noinput: u8 = 66;

/// Service (transport) unavailable: connection refused, DNS resolution
/// failed, TLS handshake failed, etc. Generally NOT retry-safe on its own
/// — the caller likely needs to fix config before retrying.
pub const unavailable: u8 = 69;

/// Cannot create a (user-specified) output file. E.g. permission denied
/// writing `.mkit/refs/heads/<branch>`, or destination directory missing.
pub const cantcreat: u8 = 73;

/// Temporary failure, indicating something that is not really an error.
/// The caller is encouraged to retry — e.g. 5xx after our internal
/// retry budget is exhausted, or a SIGINT/SIGTERM interrupted a long
/// operation.
pub const tempfail: u8 = 75;

/// Remote protocol error — e.g. URL scheme rejected, malformed response
/// from server, unexpected packfile framing.
pub const protocol_error: u8 = 76;

/// Permission denied. Distinct from `cantcreat` because this is about the
/// permission *check*, not the write failing for another reason (disk
/// full, etc.).
pub const noperm: u8 = 77;

/// Something was found in an unconfigured or misconfigured state —
/// unknown config key, invalid config value, missing required field.
pub const config_error: u8 = 78;

// -------------------------------------------------------------------------
// Inline tests. We intentionally do NOT try to exec `mkit` and observe the
// exit code from here — that would be process-level and brittle. We just
// assert that the constants are the bytes we expect. Downstream integration
// tests can do full exit-code verification in a shell.
// -------------------------------------------------------------------------

const std = @import("std");

test "sysexits constants have their documented values" {
    try std.testing.expectEqual(@as(u8, 0), ok);
    try std.testing.expectEqual(@as(u8, 1), general_error);
    try std.testing.expectEqual(@as(u8, 64), usage);
    try std.testing.expectEqual(@as(u8, 65), dataerr);
    try std.testing.expectEqual(@as(u8, 66), noinput);
    try std.testing.expectEqual(@as(u8, 69), unavailable);
    try std.testing.expectEqual(@as(u8, 73), cantcreat);
    try std.testing.expectEqual(@as(u8, 75), tempfail);
    try std.testing.expectEqual(@as(u8, 76), protocol_error);
    try std.testing.expectEqual(@as(u8, 77), noperm);
    try std.testing.expectEqual(@as(u8, 78), config_error);
}

test "sysexits error codes are non-zero" {
    // Paranoia: the whole point of a non-ok code is that `||` in a shell
    // treats it as failure.
    const all_err = [_]u8{
        general_error, usage,        dataerr,  noinput,
        unavailable,   cantcreat,    tempfail, protocol_error,
        noperm,        config_error,
    };
    for (all_err) |code| {
        try std.testing.expect(code != 0);
    }
}

test "sysexits codes fit in the 0-255 POSIX exit range" {
    // `std.process.exit` on POSIX passes the low 8 bits of the argument to
    // the kernel; anything above 255 is silently wrapped. These are all
    // already u8 so the check is a formality, but it documents intent.
    try std.testing.expect(@as(u16, general_error) <= 255);
    try std.testing.expect(@as(u16, config_error) <= 255);
}
