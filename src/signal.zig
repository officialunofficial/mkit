// SPDX-License-Identifier: MIT OR Apache-2.0
//
// POSIX signal handling for the mkit CLI.
//
// Three signals of interest, all handled via `std.posix.sigaction`:
//
//   SIGINT (Ctrl-C):  Set an atomic "shutdown requested" flag. Long-running
//                     loops (push, pull, clone) poll `shouldExit()` at
//                     natural checkpoints (e.g. between packs) and return
//                     cleanly with `exit.tempfail` so the operation can be
//                     retried.
//
//   SIGTERM:          Same as SIGINT. Container orchestrators (Kubernetes,
//                     systemd) send SIGTERM before SIGKILL; handling it
//                     lets us flush state and exit cleanly within the
//                     termination grace period.
//
//   SIGPIPE:          Ignore. The default disposition is to terminate the
//                     process when a write goes to a closed pipe, which
//                     breaks the common `mkit log | head -1` idiom (head
//                     closes its stdin after reading one line, and our
//                     next write aborts with "Broken pipe"). Ignoring
//                     SIGPIPE makes those writes return EPIPE, which
//                     propagates up as a normal I/O error and exits
//                     with a clean non-zero code.
//
// Portability: POSIX only. `std.posix.sigaction` compiles on macOS and
// Linux; we do not add a Windows branch (mkit is POSIX-only).
//
// Idempotency: `setupHandlers()` may be called multiple times without
// harm — installing the same handler twice is a no-op at the kernel
// level, and the atomic flag is only set by the handlers themselves.

const std = @import("std");
const posix = std.posix;

/// Set to true by the SIGINT / SIGTERM handler. Read with `shouldExit()`.
/// Must be signal-safe — we use an atomic bool and never call back into
/// user code from the handler.
var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

/// Has a shutdown-triggering signal (SIGINT / SIGTERM) been delivered?
/// Use this at the top of long-running loops: if true, clean up and
/// return `exit.tempfail`.
pub fn shouldExit() bool {
    return shutdown_requested.load(.acquire);
}

/// Reset the shutdown flag. Useful in tests and for subcommands that
/// want to absorb a signal without propagating (rare — usually the
/// right answer is to honor it).
pub fn resetShutdown() void {
    shutdown_requested.store(false, .release);
}

/// Signal-safe handler for SIGINT and SIGTERM. Stores the shutdown
/// flag and returns immediately; the main thread's next `shouldExit()`
/// poll does the actual cleanup + exit.
fn handleShutdown(_: std.c.SIG) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

/// Install the SIGINT / SIGTERM flag handler and ignore SIGPIPE. Safe
/// to call multiple times.
pub fn setupHandlers() void {
    // Block no other signals during our handler (empty mask) — we want
    // the handler to be as short as possible, so there's no benefit to
    // masking. `sa_flags = 0` -> no SA_RESTART, meaning slow syscalls
    // (read/write on a socket) will return EINTR when a signal arrives,
    // which is what we want for prompt shutdown.
    var empty_mask: posix.sigset_t = undefined;
    // Initialize to "no signals" — struct layout differs across
    // platforms, so zero it rather than memsetting a specific type.
    const zeroed = std.mem.zeroes(@TypeOf(empty_mask));
    empty_mask = zeroed;

    const flag_action: posix.Sigaction = .{
        .handler = .{ .handler = handleShutdown },
        .mask = empty_mask,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &flag_action, null);
    posix.sigaction(posix.SIG.TERM, &flag_action, null);

    const ignore_action: posix.Sigaction = .{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = empty_mask,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &ignore_action, null);
}

// -------------------------------------------------------------------------
// Tests. We do NOT actually raise signals here — that's fragile across
// test harnesses. We just assert:
//   - `setupHandlers()` is idempotent (doesn't crash on repeated calls)
//   - `shouldExit()` starts false
//   - `resetShutdown()` / the flag round-trips correctly
// -------------------------------------------------------------------------

test "shouldExit is false on a fresh process" {
    // The test runner shares process state across tests, so if another
    // test in the same binary flipped the flag, this assertion could
    // fail. To be safe, reset first.
    resetShutdown();
    try std.testing.expect(!shouldExit());
}

test "setupHandlers is idempotent (can be called repeatedly)" {
    setupHandlers();
    setupHandlers();
    setupHandlers();
    // No assertion beyond "didn't crash" — success is reaching this line.
}

test "shutdown flag round-trip: set, read, reset" {
    resetShutdown();
    try std.testing.expect(!shouldExit());

    // Simulate the handler by storing directly (not by raising a signal).
    shutdown_requested.store(true, .release);
    try std.testing.expect(shouldExit());

    resetShutdown();
    try std.testing.expect(!shouldExit());
}
