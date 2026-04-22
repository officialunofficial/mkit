// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Terminal (TTY) helpers: isatty detection, NO_COLOR / CLICOLOR_FORCE
// handling, and a tiny set of ANSI SGR constants.
//
// Scope is intentionally small — this is the decision layer, not a full
// ANSI rendering library. Callers pick the color string they want, wrap
// it in `term.redLit("...")` style helpers, and trust `colorEnabled()`
// to enforce the user's preference globally.
//
// Environment precedence (highest wins, matching the de-facto standard
// documented at https://bixense.com/clicolors/ and https://no-color.org):
//   1. `NO_COLOR` set (any value)        -> disable
//   2. `CLICOLOR_FORCE=1`                -> enable (even when piped)
//   3. stdout is a TTY                   -> enable
//   4. otherwise                         -> disable
//
// We do NOT observe `TERM=dumb` here — that adds complexity without real
// user value on modern systems, and nothing in mkit renders anything
// beyond ~4-color SGR that a "dumb" terminal couldn't already mangle
// harmlessly.
//
// Portability: POSIX only (macOS + Linux). We use `std.posix.isatty`
// directly, not a Windows fallback.

const std = @import("std");

/// Returns true if stdout is a terminal.
pub fn stdoutIsTty() bool {
    return std.posix.isatty(std.posix.STDOUT_FILENO);
}

/// Returns true if stderr is a terminal. Useful for deciding whether to
/// emit progress bars (which should go to stderr even when stdout is
/// piped, e.g. `mkit log | less`).
pub fn stderrIsTty() bool {
    return std.posix.isatty(std.posix.STDERR_FILENO);
}

/// Pure decision function: given the raw environment-variable values and
/// a boolean for whether stdout is a TTY, return whether color should be
/// enabled. Split out from `colorEnabled()` so tests can exercise the
/// precedence rules without mutating the process environment (Zig's
/// standard library on 0.15.2 has no `setenv` binding).
pub fn colorEnabledFor(
    no_color: ?[]const u8,
    clicolor_force: ?[]const u8,
    is_tty: bool,
) bool {
    // NO_COLOR wins unconditionally (per no-color.org: the mere presence
    // of the variable — even empty — disables color).
    if (no_color != null) return false;

    // CLICOLOR_FORCE=1 forces color on even when stdout is not a TTY.
    // Anything else (including CLICOLOR_FORCE=0 or empty) is ignored and
    // we fall through to the isatty check.
    if (clicolor_force) |v| {
        if (v.len > 0 and v[0] == '1') return true;
    }

    return is_tty;
}

/// Returns true if the process should emit ANSI color on stdout.
/// See the header comment for precedence rules.
pub fn colorEnabled() bool {
    return colorEnabledFor(
        std.posix.getenv("NO_COLOR"),
        std.posix.getenv("CLICOLOR_FORCE"),
        stdoutIsTty(),
    );
}

// -------------------------------------------------------------------------
// ANSI SGR helpers. `wrapComptime` takes a comptime color prefix and a
// comptime string, and returns one of two comptime-known slices depending
// on the runtime `colorEnabled()` check. This is the right shape for
// static messages ("error: ", progress markers, etc.) — it never
// allocates.
//
// For colorization of runtime-formatted strings, callers should emit the
// bare SGR constants directly, gated on `colorEnabled()`.
// -------------------------------------------------------------------------

pub const sgr_reset = "\x1b[0m";
pub const sgr_red = "\x1b[31m";
pub const sgr_green = "\x1b[32m";
pub const sgr_yellow = "\x1b[33m";
pub const sgr_blue = "\x1b[34m";
pub const sgr_dim = "\x1b[2m";
pub const sgr_bold = "\x1b[1m";

/// Wrap a comptime string in a comptime-known SGR color if color is
/// enabled at runtime. Returns a plain string otherwise. No allocation.
pub fn wrapComptime(comptime color: []const u8, comptime s: []const u8) []const u8 {
    if (colorEnabled()) {
        return color ++ s ++ sgr_reset;
    }
    return s;
}

pub fn redLit(comptime s: []const u8) []const u8 {
    return wrapComptime(sgr_red, s);
}
pub fn greenLit(comptime s: []const u8) []const u8 {
    return wrapComptime(sgr_green, s);
}
pub fn yellowLit(comptime s: []const u8) []const u8 {
    return wrapComptime(sgr_yellow, s);
}
pub fn dimLit(comptime s: []const u8) []const u8 {
    return wrapComptime(sgr_dim, s);
}

// -------------------------------------------------------------------------
// Tests. We test the pure `colorEnabledFor` function directly rather
// than mutating the process environment — Zig 0.15.2's std has no
// cross-platform `setenv` and we don't want these tests to depend on
// libc linkage. Downstream shell integration tests can exercise the
// real env path.
// -------------------------------------------------------------------------

test "colorEnabledFor: NO_COLOR set (any value) disables color" {
    // Empty string still counts as "set", per no-color.org.
    try std.testing.expect(!colorEnabledFor("", null, true));
    try std.testing.expect(!colorEnabledFor("", "1", true));
    try std.testing.expect(!colorEnabledFor("1", null, true));
    try std.testing.expect(!colorEnabledFor("anything", "1", false));
}

test "colorEnabledFor: CLICOLOR_FORCE=1 without NO_COLOR forces color" {
    // On even when stdout is not a TTY (piped output).
    try std.testing.expect(colorEnabledFor(null, "1", false));
    try std.testing.expect(colorEnabledFor(null, "1", true));
}

test "colorEnabledFor: CLICOLOR_FORCE=0 is NOT a force — falls through to TTY" {
    try std.testing.expect(!colorEnabledFor(null, "0", false));
    try std.testing.expect(colorEnabledFor(null, "0", true));
}

test "colorEnabledFor: CLICOLOR_FORCE empty string is NOT a force" {
    try std.testing.expect(!colorEnabledFor(null, "", false));
    try std.testing.expect(colorEnabledFor(null, "", true));
}

test "colorEnabledFor: NO_COLOR takes precedence over CLICOLOR_FORCE" {
    try std.testing.expect(!colorEnabledFor("1", "1", true));
    try std.testing.expect(!colorEnabledFor("", "1", true));
}

test "colorEnabledFor: no env vars -> TTY decides" {
    try std.testing.expect(colorEnabledFor(null, null, true));
    try std.testing.expect(!colorEnabledFor(null, null, false));
}

test "SGR constants are the standard ANSI escape sequences" {
    try std.testing.expectEqualStrings("\x1b[0m", sgr_reset);
    try std.testing.expectEqualStrings("\x1b[31m", sgr_red);
    try std.testing.expectEqualStrings("\x1b[32m", sgr_green);
    try std.testing.expectEqualStrings("\x1b[33m", sgr_yellow);
    try std.testing.expectEqualStrings("\x1b[34m", sgr_blue);
    try std.testing.expectEqualStrings("\x1b[2m", sgr_dim);
    try std.testing.expectEqualStrings("\x1b[1m", sgr_bold);
}

test "stdoutIsTty / stderrIsTty: smoke (no crash, returns bool)" {
    // Under `zig build test` both are likely pipes, but we don't assert
    // the value — just that the function is callable and returns a bool.
    _ = stdoutIsTty();
    _ = stderrIsTty();
}

test "colorEnabled: smoke (no crash, returns bool)" {
    _ = colorEnabled();
}
