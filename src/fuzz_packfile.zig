// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bounded property tests for `packfile.unpack`.
//
// Guardrails — see docs/FUZZ.md:
//   * FixedBufferAllocator backed by a static 2 MiB buffer. If the target
//     tries to allocate beyond that it gets `error.OutOfMemory` — that is
//     GOOD; it exercises the target's bounds checking.
//   * At most 100 PRNG iterations per test block.
//   * Each iteration's input is at most 64 KiB.
//   * Per-iteration wall-clock cap of 100 ms — any single iteration that
//     exceeds the cap aborts the remainder of the test.
//   * Deterministic PRNG seeds so failures reproduce.
//
// This file contains NO `std.testing.fuzz` calls. We drive inputs
// synchronously from a seeded `DefaultPrng` so a normal `zig build test`
// cannot explode into a multi-gigabyte corpus run.

const std = @import("std");
const packfile = @import("packfile.zig");
const testing = std.testing;

/// Static buffer for every fuzz allocator. 2 MiB is enough to decode any
/// input under our 64 KiB cap while still catching "parser tries to
/// allocate 1 GiB" bugs via `error.OutOfMemory`.
var fba_buf: [2 * 1024 * 1024]u8 = undefined;

const MAX_ITER: u32 = 100;
const MAX_INPUT: usize = 64 * 1024; // 64 KiB
const PER_ITER_NS: u64 = 100 * std.time.ns_per_ms;

fn makeFba() std.heap.FixedBufferAllocator {
    return std.heap.FixedBufferAllocator.init(&fba_buf);
}

/// Run `packfile.unpack` against `data`, freeing whatever comes back.
/// Swallows all errors — the invariant is "no panic, no UB, no runaway".
fn tryUnpack(allocator: std.mem.Allocator, data: []const u8) void {
    const result = packfile.unpack(allocator, data) catch return;
    defer {
        for (result) |obj| allocator.free(obj);
        allocator.free(result);
    }
}

// ---------------------------------------------------------------------------
// Fixed hand-crafted seed cases
// ---------------------------------------------------------------------------

test "fuzz packfile: empty input errors cleanly" {
    var fba = makeFba();
    const a = fba.allocator();
    try testing.expectError(error.PackfileTooShort, packfile.unpack(a, ""));
}

test "fuzz packfile: valid empty pack (magic + v1 + count=0)" {
    var fba = makeFba();
    const a = fba.allocator();
    // MAGIC "MKIT" + version=1 (LE u32) + count=0 (LE u32) = 12 bytes.
    const bytes = [_]u8{ 'M', 'K', 'I', 'T', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try packfile.unpack(a, &bytes);
    defer a.free(result);
    try testing.expectEqual(@as(usize, 0), result.len);
}

test "fuzz packfile: truncated header errors" {
    var fba = makeFba();
    const a = fba.allocator();
    try testing.expectError(error.PackfileTooShort, packfile.unpack(a, "MKI"));
    try testing.expectError(error.PackfileTooShort, packfile.unpack(a, "MKIT"));
    try testing.expectError(error.PackfileTooShort, packfile.unpack(a, "MKIT\x01\x00\x00\x00\x00"));
}

test "fuzz packfile: wrong magic rejected" {
    var fba = makeFba();
    const a = fba.allocator();
    // Wrong 4-byte magic ('X','X','X','X') + otherwise-valid tail.
    const bytes = [_]u8{ 'X', 'X', 'X', 'X', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.InvalidMagic, packfile.unpack(a, &bytes));
}

test "fuzz packfile: unsupported version rejected" {
    var fba = makeFba();
    const a = fba.allocator();
    // MKIT + version=99 + count=0.
    const bytes = [_]u8{ 'M', 'K', 'I', 'T', 99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.UnsupportedVersion, packfile.unpack(a, &bytes));
}

test "fuzz packfile: oversize count does NOT blow allocator" {
    // CRITICAL: a pack claiming count=9_999_999 with 12 bytes of body must
    // NOT allocate an array of ~240 MiB before bounds-checking. The parser
    // has a 10M entry cap. With our 2 MiB FBA the allocation must also fail
    // with OutOfMemory before hitting the cap — either outcome is acceptable
    // as long as it does NOT panic and does NOT run us out of real memory.
    var fba = makeFba();
    const a = fba.allocator();
    // count = 9_999_999 (below 10M cap but would need 240 MiB for the entry array)
    const bytes = [_]u8{ 'M', 'K', 'I', 'T', 0x01, 0x00, 0x00, 0x00, 0x7F, 0x96, 0x98, 0x00 };
    const result = packfile.unpack(a, &bytes);
    try testing.expect(std.meta.isError(result));
}

test "fuzz packfile: count over hard cap rejected" {
    var fba = makeFba();
    const a = fba.allocator();
    // count = 0xFFFFFFFF — must trip the TooManyObjects cap.
    const bytes = [_]u8{ 'M', 'K', 'I', 'T', 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expectError(error.TooManyObjects, packfile.unpack(a, &bytes));
}

test "fuzz packfile: entry with obj_len > remaining data rejected" {
    var fba = makeFba();
    const a = fba.allocator();
    // count=1, obj_len = 1_000_000, body = empty.
    const bytes = [_]u8{
        'M',  'K',  'I',  'T',
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, // count=1
        0x40, 0x42, 0x0F, 0x00, // obj_len=1_000_000
    };
    try testing.expectError(error.UnexpectedEof, packfile.unpack(a, &bytes));
}

// ---------------------------------------------------------------------------
// PRNG-driven cases (bounded)
// ---------------------------------------------------------------------------

test "fuzz packfile: random bytes never panic" {
    var prng = std.Random.DefaultPrng.init(0xDEADBEEFCAFE);
    const rand = prng.random();

    var buf: [MAX_INPUT]u8 = undefined;

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        // Vary length from 0 up to MAX_INPUT.
        const len = rand.uintLessThan(usize, MAX_INPUT + 1);
        rand.bytes(buf[0..len]);

        var fba = makeFba();
        const a = fba.allocator();

        // Why: std.time.nanoTimestamp was removed in 0.16; monotonic clock
        // readings now come from the Io capability. std.testing.io is the
        // per-test threaded Io instance set up by the test runner.
        const start = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
        tryUnpack(a, buf[0..len]);
        const elapsed: u64 = @intCast(std.Io.Clock.awake.now(std.testing.io).nanoseconds - start);
        if (elapsed > PER_ITER_NS) {
            std.debug.print(
                "fuzz_packfile iter {d} took {d} ns — stopping early\n",
                .{ i, elapsed },
            );
            return error.FuzzIterationTooSlow;
        }
    }
}

test "fuzz packfile: bit-flips on valid 12-byte pack" {
    // Start from a known-good empty pack. Flip one byte per iteration and
    // check: parse either succeeds (the flip happened to hit a harmless
    // position) or fails gracefully — never panics or hangs.
    const base = [_]u8{ 'M', 'K', 'I', 'T', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var prng = std.Random.DefaultPrng.init(0x1234_5678_9ABC_DEF0);
    const rand = prng.random();

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        var bytes = base;
        const idx = rand.uintLessThan(usize, bytes.len);
        const mask: u8 = @intCast(@as(u16, 1) << @intCast(rand.uintLessThan(u8, 8)));
        bytes[idx] ^= mask;

        var fba = makeFba();
        const a = fba.allocator();

        const start = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
        tryUnpack(a, &bytes);
        const elapsed: u64 = @intCast(std.Io.Clock.awake.now(std.testing.io).nanoseconds - start);
        if (elapsed > PER_ITER_NS) return error.FuzzIterationTooSlow;
    }
}
