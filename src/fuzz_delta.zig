// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bounded property tests for `delta.applyDelta`.
//
// Guardrails — see docs/FUZZ.md:
//   * FixedBufferAllocator backed by a static 2 MiB buffer. Decoding a
//     malicious delta that tries to grow the output unboundedly surfaces
//     as `error.OutOfMemory` from the FBA rather than as real memory
//     exhaustion.
//   * At most 100 PRNG iterations per test block.
//   * Each iteration's base+instructions input is at most 16 KiB combined
//     (8 KiB base + 8 KiB instructions) — well under the 64 KiB ceiling.
//   * Per-iteration wall-clock cap of 100 ms.
//   * Deterministic PRNG seeds.
//
// This file contains NO `std.testing.fuzz` calls. The memory bomb on the
// first W6.5 attempt came from std.testing.fuzz + page_allocator; we don't
// use either here.
//
// Note: delta.applyDelta takes a `result_size_hint` that the current
// implementation ignores (grows dynamically). The fuzz invariants we
// assert below are the actual parser contract:
//   * COPY offset + length must stay within base bounds
//   * INSERT literal length must not overrun the instruction stream
//   * opcode 0 and malformed copy headers produce DeltaCorrupt

const std = @import("std");
const delta = @import("delta.zig");
const testing = std.testing;

var fba_buf: [2 * 1024 * 1024]u8 = undefined;

const MAX_ITER: u32 = 100;
const MAX_BASE: usize = 8 * 1024;
const MAX_INSTR: usize = 8 * 1024;
const PER_ITER_NS: u64 = 100 * std.time.ns_per_ms;

fn makeFba() std.heap.FixedBufferAllocator {
    return std.heap.FixedBufferAllocator.init(&fba_buf);
}

fn tryApply(allocator: std.mem.Allocator, base: []const u8, instructions: []const u8) void {
    const out = delta.applyDelta(allocator, base, instructions, 0) catch return;
    allocator.free(out);
}

// ---------------------------------------------------------------------------
// Fixed hand-crafted seed cases
// ---------------------------------------------------------------------------

test "fuzz delta: empty instruction stream yields empty output" {
    var fba = makeFba();
    const a = fba.allocator();

    const base = "hello";
    const out = try delta.applyDelta(a, base, "", 0);
    defer a.free(out);
    try testing.expectEqual(@as(usize, 0), out.len);
}

test "fuzz delta: pure INSERT reproduces inserted bytes" {
    var fba = makeFba();
    const a = fba.allocator();

    // INSERT opcode = length (1..127); here 5 literal bytes "hello".
    const instructions = [_]u8{ 5, 'h', 'e', 'l', 'l', 'o' };
    const out = try delta.applyDelta(a, "unused-base", &instructions, 0);
    defer a.free(out);
    try testing.expectEqualStrings("hello", out);
}

test "fuzz delta: COPY of full base reproduces base" {
    var fba = makeFba();
    const a = fba.allocator();

    const base = "0123456789abcdef"; // 16 bytes
    // COPY opcode=0x80 | offset=0 (u32 LE) | length=16 (u16 LE)
    const instructions = [_]u8{
        0x80,
        0x00, 0x00, 0x00, 0x00, // offset = 0
        0x10, 0x00, //              length = 16
    };
    const out = try delta.applyDelta(a, base, &instructions, 0);
    defer a.free(out);
    try testing.expectEqualStrings(base, out);
}

test "fuzz delta: COPY past end of base rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    const base = "short"; // 5 bytes
    // Ask for bytes 0..100 of a 5-byte base.
    const instructions = [_]u8{
        0x80,
        0x00, 0x00, 0x00, 0x00, // offset = 0
        0x64, 0x00, //              length = 100
    };
    try testing.expectError(error.DeltaCorrupt, delta.applyDelta(a, base, &instructions, 0));
}

test "fuzz delta: truncated COPY header rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    // COPY opcode but only 3 bytes of its 6-byte payload.
    const instructions = [_]u8{ 0x80, 0x00, 0x00, 0x00 };
    try testing.expectError(error.DeltaCorrupt, delta.applyDelta(a, "abcdef", &instructions, 0));
}

test "fuzz delta: opcode 0x00 rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    const instructions = [_]u8{0x00};
    try testing.expectError(error.DeltaCorrupt, delta.applyDelta(a, "abc", &instructions, 0));
}

test "fuzz delta: truncated INSERT literal rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    // Claims 10 bytes of literal but only supplies 3.
    const instructions = [_]u8{ 10, 'a', 'b', 'c' };
    try testing.expectError(error.DeltaCorrupt, delta.applyDelta(a, "", &instructions, 0));
}

// ---------------------------------------------------------------------------
// PRNG-driven cases (bounded)
// ---------------------------------------------------------------------------

test "fuzz delta: random instructions never panic" {
    var prng = std.Random.DefaultPrng.init(0xDE174AAADA7A);
    const rand = prng.random();

    const base_buf = try testing.allocator.alloc(u8, MAX_BASE);
    defer testing.allocator.free(base_buf);
    const instr_buf = try testing.allocator.alloc(u8, MAX_INSTR);
    defer testing.allocator.free(instr_buf);

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        const base_len = rand.uintLessThan(usize, MAX_BASE + 1);
        const instr_len = rand.uintLessThan(usize, MAX_INSTR + 1);
        rand.bytes(base_buf[0..base_len]);
        rand.bytes(instr_buf[0..instr_len]);

        var fba = makeFba();
        const a = fba.allocator();

        const start = std.time.nanoTimestamp();
        tryApply(a, base_buf[0..base_len], instr_buf[0..instr_len]);
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start);
        if (elapsed > PER_ITER_NS) return error.FuzzIterationTooSlow;
    }
}

test "fuzz delta: COPY output never exceeds base bounds (when parse succeeds)" {
    // Build inputs that are always well-formed COPY-of-full-base deltas
    // and verify the output slice length matches the declared COPY length.
    var prng = std.Random.DefaultPrng.init(0xBADC0FFEE123);
    const rand = prng.random();

    const base_buf = try testing.allocator.alloc(u8, MAX_BASE);
    defer testing.allocator.free(base_buf);

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        // Base length between 16 and MAX_BASE.
        const base_len = 16 + rand.uintLessThan(usize, MAX_BASE - 16 + 1);
        rand.bytes(base_buf[0..base_len]);

        // Pick a random valid (offset, length) pair inside the base.
        const offset = rand.uintLessThan(u32, @intCast(base_len));
        const max_copy: u32 = @intCast(base_len - offset);
        const copy_len: u16 = @intCast(@min(max_copy, @as(u32, std.math.maxInt(u16))));
        if (copy_len == 0) continue;

        var instr: [7]u8 = undefined;
        instr[0] = 0x80;
        std.mem.writeInt(u32, instr[1..5], offset, .little);
        std.mem.writeInt(u16, instr[5..7], copy_len, .little);

        var fba = makeFba();
        const a = fba.allocator();

        const start = std.time.nanoTimestamp();
        const out = delta.applyDelta(a, base_buf[0..base_len], &instr, 0) catch |e| {
            // Only OutOfMemory is acceptable for a well-formed input here.
            try testing.expectEqual(error.OutOfMemory, e);
            continue;
        };
        defer a.free(out);
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start);
        if (elapsed > PER_ITER_NS) return error.FuzzIterationTooSlow;

        try testing.expectEqual(@as(usize, copy_len), out.len);
        try testing.expectEqualSlices(u8, base_buf[offset..][0..copy_len], out);
    }
}
