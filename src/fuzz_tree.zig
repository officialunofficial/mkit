// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Bounded property tests for the tree-object deserializer in serialize.zig.
//
// Guardrails — see docs/FUZZ.md:
//   * FixedBufferAllocator backed by a static 2 MiB buffer. Parser
//     allocations beyond that surface as `error.OutOfMemory` — which is
//     the desired outcome for adversarial inputs, not a panic.
//   * At most 100 PRNG iterations per test block.
//   * Each iteration's input is at most 64 KiB.
//   * Per-iteration wall-clock cap of 100 ms.
//   * Deterministic PRNG seeds.
//
// This file contains NO `std.testing.fuzz` calls.

const std = @import("std");
const serialize = @import("serialize.zig");
const object = @import("object.zig");
const testing = std.testing;

var fba_buf: [2 * 1024 * 1024]u8 = undefined;

const MAX_ITER: u32 = 100;
const MAX_INPUT: usize = 64 * 1024;
const PER_ITER_NS: u64 = 100 * std.time.ns_per_ms;

fn makeFba() std.heap.FixedBufferAllocator {
    return std.heap.FixedBufferAllocator.init(&fba_buf);
}

/// 6-byte tree prologue: `[0x02][MKT1][0x01]`.
const TREE_PROLOGUE = [_]u8{ @intFromEnum(object.ObjectType.tree), 'M', 'K', 'T', '1', 0x01 };

fn tryDeserialize(allocator: std.mem.Allocator, data: []const u8) void {
    var obj = serialize.deserialize(allocator, data) catch return;
    obj.deinit(allocator);
}

/// Encode a little-endian u32 into a 4-byte array.
fn u32le(v: u32) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, v, .little);
    return out;
}

// ---------------------------------------------------------------------------
// Fixed hand-crafted seed cases
// ---------------------------------------------------------------------------

test "fuzz tree: empty tree (count=0) succeeds" {
    var fba = makeFba();
    const a = fba.allocator();

    var bytes: [10]u8 = undefined;
    @memcpy(bytes[0..6], &TREE_PROLOGUE);
    @memcpy(bytes[6..10], &u32le(0));

    var obj = try serialize.deserialize(a, &bytes);
    defer obj.deinit(a);
    try testing.expectEqual(@as(usize, 0), obj.tree.entries.len);
}

test "fuzz tree: single valid entry succeeds" {
    var fba = makeFba();
    const a = fba.allocator();

    // 1 entry: name="a" (len=1), mode=blob (0x01), hash=zeros
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(1)); // count
    try buf.appendSlice(a, &u32le(1)); // name_len
    try buf.append(a, 'a'); // name
    try buf.append(a, @intFromEnum(object.EntryMode.blob)); // mode
    try buf.appendSlice(a, &[_]u8{0} ** 32); // hash

    var obj = try serialize.deserialize(a, buf.items);
    defer obj.deinit(a);
    try testing.expectEqual(@as(usize, 1), obj.tree.entries.len);
    try testing.expectEqualStrings("a", obj.tree.entries[0].name);
}

test "fuzz tree: entry named '..' rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(1));
    try buf.appendSlice(a, &u32le(2));
    try buf.appendSlice(a, "..");
    try buf.append(a, @intFromEnum(object.EntryMode.tree));
    try buf.appendSlice(a, &[_]u8{0} ** 32);

    try testing.expectError(error.InvalidEntryName, serialize.deserialize(a, buf.items));
}

test "fuzz tree: entry name with embedded null rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(1));
    try buf.appendSlice(a, &u32le(3));
    try buf.appendSlice(a, &[_]u8{ 'a', 0, 'b' });
    try buf.append(a, @intFromEnum(object.EntryMode.blob));
    try buf.appendSlice(a, &[_]u8{0} ** 32);

    try testing.expectError(error.InvalidEntryName, serialize.deserialize(a, buf.items));
}

test "fuzz tree: entry mode 0xFF rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(1));
    try buf.appendSlice(a, &u32le(1));
    try buf.append(a, 'x');
    try buf.append(a, 0xFF); // invalid mode
    try buf.appendSlice(a, &[_]u8{0} ** 32);

    try testing.expectError(error.InvalidEntryMode, serialize.deserialize(a, buf.items));
}

test "fuzz tree: declared name length > remaining bytes rejected" {
    var fba = makeFba();
    const a = fba.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(1));
    try buf.appendSlice(a, &u32le(1_000_000)); // impossible name_len
    // No further bytes.

    try testing.expectError(error.UnexpectedEof, serialize.deserialize(a, buf.items));
}

test "fuzz tree: oversize entry count rejected without allocator blow-up" {
    // deserializeTree caps count at 1_000_000 via TooManyEntries. Even if
    // we sit below the cap, the FBA-backed allocator will reject a giant
    // allocation with OutOfMemory rather than actually reserving it.
    var fba = makeFba();
    const a = fba.allocator();

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(a);
    try buf.appendSlice(a, &TREE_PROLOGUE);
    try buf.appendSlice(a, &u32le(0xFFFFFFFF)); // count > cap

    try testing.expectError(error.TooManyEntries, serialize.deserialize(a, buf.items));
}

// ---------------------------------------------------------------------------
// PRNG-driven cases (bounded)
// ---------------------------------------------------------------------------

test "fuzz tree: random bytes never panic" {
    var prng = std.Random.DefaultPrng.init(0xC0FFEEBAB55EED);
    const rand = prng.random();

    // Heap-allocate the scratch buffer to avoid 64 KiB of test-frame stack
    // on platforms with small default stacks. The scratch buffer uses the
    // testing allocator (outside the fuzz target's FBA); only the target
    // parser runs under the FBA.
    const buf = try testing.allocator.alloc(u8, MAX_INPUT);
    defer testing.allocator.free(buf);

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        const len = rand.uintLessThan(usize, MAX_INPUT + 1);
        rand.bytes(buf[0..len]);

        var fba = makeFba();
        const a = fba.allocator();

        const start = std.time.nanoTimestamp();
        tryDeserialize(a, buf[0..len]);
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start);
        if (elapsed > PER_ITER_NS) return error.FuzzIterationTooSlow;
    }
}

test "fuzz tree: bit-flips on valid tree header" {
    // Start from a valid single-entry tree, flip a random byte per iter.
    const base = comptime blk: {
        var out: [10 + 4 + 1 + 1 + 32]u8 = undefined;
        out[0] = @intFromEnum(object.ObjectType.tree);
        out[1] = 'M';
        out[2] = 'K';
        out[3] = 'T';
        out[4] = '1';
        out[5] = 0x01;
        // count = 1
        std.mem.writeInt(u32, out[6..10], 1, .little);
        // name_len = 1
        std.mem.writeInt(u32, out[10..14], 1, .little);
        out[14] = 'a';
        out[15] = @intFromEnum(object.EntryMode.blob);
        @memset(out[16..48], 0);
        break :blk out;
    };

    var prng = std.Random.DefaultPrng.init(0xA5A5_0F0F_1234_ABCD);
    const rand = prng.random();

    var i: u32 = 0;
    while (i < MAX_ITER) : (i += 1) {
        var bytes = base;
        const idx = rand.uintLessThan(usize, bytes.len);
        const mask: u8 = @intCast(@as(u16, 1) << @intCast(rand.uintLessThan(u8, 8)));
        bytes[idx] ^= mask;

        var fba = makeFba();
        const a = fba.allocator();

        const start = std.time.nanoTimestamp();
        tryDeserialize(a, &bytes);
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start);
        if (elapsed > PER_ITER_NS) return error.FuzzIterationTooSlow;
    }
}
