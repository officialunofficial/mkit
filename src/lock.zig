// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Repo-level lockfile helper.
//
// Pattern: O_EXCL create, spin with sleep + timeout, delete on release.
// Same shape W5 put in transport/file.zig for ref CAS, generalized so
// command handlers (`mkit commit`, `mkit checkout`, `mkit merge`,
// `mkit rebase`) can all serialize against `.mkit/index.lock` (or any
// other named lock) without each one re-implementing the spin loop.
//
// We deliberately do NOT use advisory `flock(2)`:
//
//   - `flock` semantics on NFS are historically broken (macOS defers
//     to fcntl locking, Linux emulates since 2.6.12, but older NFS
//     servers drop locks silently).
//
//   - An O_EXCL lockfile is visible on the filesystem, so a stale lock
//     is debuggable by the user (`ls .mkit/*.lock`) and removable by
//     hand if a previous mkit process was SIGKILL'd.
//
//   - Consistent with git's convention of `<file>.lock` for index,
//     HEAD, and refs.
//
// Platform: POSIX only (macOS + Linux). `std.fs.Dir.createFile` with
// `{ .exclusive = true }` maps to O_EXCL under the hood on both.
//
// Scope: intentionally CLI-handler-level. Lower-level modules (state,
// store, refs) must NOT call into this — they're expected to be pure
// data manipulators that don't know about CLI lifecycle.

const std = @import("std");

/// Default per-attempt sleep between retries. Keep this short so that
/// fast operations (e.g. another mkit instance finishing a quick
/// commit) see the lock release promptly. Long enough that we don't
/// monopolize the CPU when a slow operation is in progress.
pub const default_sleep_ns: u64 = 50 * std.time.ns_per_ms;

/// Default total timeout (≈5s). Long enough that a slow commit in
/// another process finishes; short enough that a stale lock from a
/// SIGKILL'd mkit doesn't wedge the user for more than a moment.
pub const default_timeout_ns: u64 = 5 * std.time.ns_per_s;

/// Holder for an acquired lock. `release()` removes the lockfile.
/// Uses a stack-allocated path buffer so no allocator is required.
pub const RepoLock = struct {
    dir: std.Io.Dir,
    io: std.Io,
    /// Null-terminated path of the lock file, relative to `dir`.
    path_buf: [256]u8,
    path_len: usize,

    /// Release the lock by deleting the lockfile. Safe to call
    /// multiple times (re-deletion is ignored). Also invoked by
    /// `defer` at the caller's natural cleanup point.
    pub fn release(self: *RepoLock) void {
        const p = self.path_buf[0..self.path_len];
        if (p.len == 0) return;
        self.dir.deleteFile(self.io, p) catch {};
        // Mark as released so a subsequent call is a cheap no-op.
        self.path_len = 0;
    }

    /// Returns the relative path of the held lock, for diagnostics.
    pub fn path(self: *const RepoLock) []const u8 {
        return self.path_buf[0..self.path_len];
    }
};

/// Acquire a repo-level lock. `dir` is usually the `.mkit/` directory
/// (not the worktree root). `name` is the lockfile's basename
/// (e.g. "index.lock"). Spins up to `timeout_ns` (see
/// `default_timeout_ns`) waiting for a competing holder to release.
///
/// Errors:
///   - `error.LockBusy` — timeout exhausted; another process holds it.
///   - `error.LockNameTooLong` — `name` doesn't fit in the path buffer.
///   - underlying I/O errors from `createFile` (disk full, etc.)
pub fn acquire(
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    timeout_ns: u64,
) !RepoLock {
    if (name.len >= 255) return error.LockNameTooLong;
    if (name.len == 0) return error.LockNameTooLong;

    var lock: RepoLock = .{
        .dir = dir,
        .io = io,
        .path_buf = undefined,
        .path_len = name.len,
    };
    @memcpy(lock.path_buf[0..name.len], name);
    lock.path_buf[name.len] = 0;

    const start = std.Io.Clock.awake.now(io);
    var attempts: u32 = 0;
    const max_attempts: u32 = 1000; // hard iteration cap per the project rules

    while (true) : (attempts += 1) {
        if (attempts >= max_attempts) return error.LockBusy;

        const f = dir.createFile(io, lock.path_buf[0..name.len], .{ .exclusive = true }) catch |err| switch (err) {
            error.PathAlreadyExists => {
                // Check wall-clock timeout in addition to the iteration
                // cap — this is the user-visible bound.
                const now = std.Io.Clock.awake.now(io);
                const elapsed = start.durationTo(now);
                if (@as(u64, @intCast(elapsed.nanoseconds)) >= timeout_ns) {
                    return error.LockBusy;
                }
                // Why: std.Thread.sleep is removed in 0.16; use Io clock sleep.
                std.Io.sleep(io, std.Io.Duration.fromNanoseconds(@intCast(default_sleep_ns)), .awake) catch {};
                continue;
            },
            else => return err,
        };
        f.close(io);
        return lock;
    }
}

/// Convenience wrapper: acquire with the default timeout.
pub fn acquireDefault(io: std.Io, dir: std.Io.Dir, name: []const u8) !RepoLock {
    return acquire(io, dir, name, default_timeout_ns);
}

// -------------------------------------------------------------------------
// Tests. Use tmpDir for isolation; keep under 1000 iterations of any
// loop and under 1 MiB of data.
// -------------------------------------------------------------------------

test "acquire + release round-trip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var lock = try acquireDefault(io, tmp.dir, "index.lock");
    try std.testing.expectEqualStrings("index.lock", lock.path());

    // File exists while held.
    try tmp.dir.access(io, "index.lock", .{});

    lock.release();

    // File gone after release.
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "index.lock", .{}));
}

test "second acquire after release succeeds" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var lock1 = try acquireDefault(io, tmp.dir, "index.lock");
    lock1.release();

    var lock2 = try acquireDefault(io, tmp.dir, "index.lock");
    defer lock2.release();
    try tmp.dir.access(io, "index.lock", .{});
}

test "acquire while held returns LockBusy after short timeout" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var lock1 = try acquireDefault(io, tmp.dir, "index.lock");
    defer lock1.release();

    // 100 ms timeout — long enough to sleep at least once, short
    // enough the test doesn't drag.
    const short_timeout_ns: u64 = 100 * std.time.ns_per_ms;
    try std.testing.expectError(
        error.LockBusy,
        acquire(io, tmp.dir, "index.lock", short_timeout_ns),
    );
}

test "release is idempotent (safe to call twice)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var lock = try acquireDefault(io, tmp.dir, "index.lock");
    lock.release();
    lock.release(); // No crash, no error.
}

test "acquire rejects empty name" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try std.testing.expectError(
        error.LockNameTooLong,
        acquire(io, tmp.dir, "", default_timeout_ns),
    );
}

test "acquire rejects names that overflow the 255-byte buffer" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var huge: [300]u8 = undefined;
    @memset(&huge, 'a');
    try std.testing.expectError(
        error.LockNameTooLong,
        acquire(io, tmp.dir, &huge, default_timeout_ns),
    );
}

test "two distinct lock names coexist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    var a = try acquireDefault(io, tmp.dir, "a.lock");
    defer a.release();
    var b = try acquireDefault(io, tmp.dir, "b.lock");
    defer b.release();

    try tmp.dir.access(io, "a.lock", .{});
    try tmp.dir.access(io, "b.lock", .{});
}
