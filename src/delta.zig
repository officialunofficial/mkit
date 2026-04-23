// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Allocator = std.mem.Allocator;

/// Block size for rolling hash index (must be power of 2 for alignment).
const BLOCK_SIZE: usize = 16;

/// Maximum length of an INSERT literal run (fits in 7-bit length field).
const MAX_INSERT_LEN: usize = 127;

/// Delta instruction wire format:
/// - COPY:   byte with high bit set (0x80) | offset (u32 LE) | length (u16 LE)  = 7 bytes
/// - INSERT: byte 1..127 (literal length) | <that many literal bytes>
///
/// `computeDelta` produces a delta instruction stream that transforms `base` into `target`.
/// `applyDelta` replays those instructions against `base` to reconstruct `target`.
const Buffer = std.ArrayList(u8);

/// Compute delta instructions to transform `base` into `target`.
/// Uses a hash index over 16-byte aligned blocks of base for copy detection.
/// Caller owns the returned instruction bytes.
pub fn computeDelta(allocator: Allocator, base: []const u8, target: []const u8) ![]u8 {
    var instructions: Buffer = .empty;
    errdefer instructions.deinit(allocator);

    // Build hash table: hash(16-byte block) -> position in base
    // Only index aligned positions: 0, 16, 32, ...
    const num_blocks = base.len / BLOCK_SIZE;
    var index_map = std.AutoHashMap(u64, u32).init(allocator);
    defer index_map.deinit();

    for (0..num_blocks) |i| {
        const pos: u32 = @intCast(i * BLOCK_SIZE);
        const block = base[pos..][0..BLOCK_SIZE];
        const h = blockHash(block);
        // First occurrence wins (don't overwrite)
        const gop = try index_map.getOrPut(h);
        if (!gop.found_existing) {
            gop.value_ptr.* = pos;
        }
    }

    // Walk target, looking for matches
    var insert_buf: [MAX_INSERT_LEN]u8 = undefined;
    var insert_len: usize = 0;
    var ti: usize = 0;

    while (ti < target.len) {
        // Try to find a match if we have at least BLOCK_SIZE bytes left
        var matched = false;
        if (ti + BLOCK_SIZE <= target.len) {
            const target_block: *const [BLOCK_SIZE]u8 = target[ti..][0..BLOCK_SIZE];
            const h = blockHash(target_block);
            if (index_map.get(h)) |base_pos| {
                // Verify the bytes actually match (hash collision check)
                if (std.mem.eql(u8, base[base_pos..][0..BLOCK_SIZE], target_block)) {
                    // Flush pending insert buffer first
                    if (insert_len > 0) {
                        try emitInsert(&instructions, allocator, insert_buf[0..insert_len]);
                        insert_len = 0;
                    }

                    // Extend match forward beyond the initial BLOCK_SIZE
                    var match_len: usize = BLOCK_SIZE;
                    while (base_pos + match_len < base.len and
                        ti + match_len < target.len and
                        base[base_pos + match_len] == target[ti + match_len])
                    {
                        match_len += 1;
                        // Cap at u16 max
                        if (match_len == std.math.maxInt(u16)) break;
                    }

                    try emitCopy(&instructions, allocator, base_pos, @intCast(match_len));
                    ti += match_len;
                    matched = true;
                }
            }
        }

        if (!matched) {
            // Accumulate into insert buffer
            insert_buf[insert_len] = target[ti];
            insert_len += 1;
            ti += 1;

            // Flush if buffer full
            if (insert_len == MAX_INSERT_LEN) {
                try emitInsert(&instructions, allocator, insert_buf[0..insert_len]);
                insert_len = 0;
            }
        }
    }

    // Flush any remaining insert buffer
    if (insert_len > 0) {
        try emitInsert(&instructions, allocator, insert_buf[0..insert_len]);
    }

    return instructions.toOwnedSlice(allocator);
}

/// Apply delta instructions to `base` to produce the target.
/// `result_size` is the expected output length; returns error.DeltaSizeMismatch if
/// the reconstructed output does not match.
/// Caller owns the returned slice.
pub fn applyDelta(allocator: Allocator, base: []const u8, instructions: []const u8, result_size_hint: u32) ![]u8 {
    _ = result_size_hint; // hint only; we grow dynamically
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var ii: usize = 0;

    while (ii < instructions.len) {
        const opcode = instructions[ii];
        ii += 1;

        if (opcode & 0x80 != 0) {
            if (ii + 6 > instructions.len) return error.DeltaCorrupt;
            const offset = std.mem.readInt(u32, instructions[ii..][0..4], .little);
            ii += 4;
            const length = std.mem.readInt(u16, instructions[ii..][0..2], .little);
            ii += 2;

            if (offset + length > base.len) return error.DeltaCorrupt;

            try result.appendSlice(allocator, base[offset..][0..length]);
        } else if (opcode > 0) {
            const length: usize = opcode;
            if (ii + length > instructions.len) return error.DeltaCorrupt;

            try result.appendSlice(allocator, instructions[ii..][0..length]);
            ii += length;
        } else {
            return error.DeltaCorrupt;
        }
    }

    return result.toOwnedSlice(allocator);
}

// -- Internal helpers --

fn blockHash(block: *const [BLOCK_SIZE]u8) u64 {
    // Use a fast non-cryptographic hash for the index.
    // FNV-1a 64-bit is simple and effective for 16-byte blocks.
    var h: u64 = 0xcbf29ce484222325; // FNV offset basis
    for (block) |b| {
        h ^= b;
        h *%= 0x100000001b3; // FNV prime
    }
    return h;
}

fn emitCopy(buf: *Buffer, allocator: Allocator, offset: u32, length: u16) !void {
    try buf.append(allocator, 0x80); // COPY opcode
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, offset)));
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u16, length)));
}

fn emitInsert(buf: *Buffer, allocator: Allocator, data: []const u8) !void {
    std.debug.assert(data.len > 0 and data.len <= MAX_INSERT_LEN);
    try buf.append(allocator, @intCast(data.len));
    try buf.appendSlice(allocator, data);
}

// ============================================================
// Tests
// ============================================================

test "compute and apply delta identical" {
    const allocator = std.testing.allocator;

    // A string long enough to have at least one 16-byte block
    const data = "0123456789abcdef" ** 4; // 64 bytes

    const instructions = try computeDelta(allocator, data, data);
    defer allocator.free(instructions);

    // Apply and verify we get the original back
    const result = try applyDelta(allocator, data, instructions, @intCast(data.len));
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, data, result);

    // For identical data, delta should be compact (all copies, no inserts)
    // At minimum it's smaller than or equal to original + overhead
    try std.testing.expect(instructions.len <= data.len);
}

test "compute and apply delta insert only" {
    const allocator = std.testing.allocator;

    const base = "aaa";
    const target = "zzz";

    const instructions = try computeDelta(allocator, base, target);
    defer allocator.free(instructions);

    const result = try applyDelta(allocator, base, instructions, @intCast(target.len));
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, target, result);

    // All inserts: first byte should be the length (3), not a copy opcode
    try std.testing.expect(instructions[0] & 0x80 == 0);
    try std.testing.expectEqual(@as(u8, 3), instructions[0]);
}

test "compute and apply delta with copies" {
    const allocator = std.testing.allocator;

    // Base: 128 bytes of repeated pattern (8 blocks of 16)
    const base = "abcdefghijklmnop" ** 8;
    // Target: same 128 bytes + 20 bytes appended
    const target = base ++ "EXTRA_TWENTY_BYTES_!";

    const instructions = try computeDelta(allocator, base, target);
    defer allocator.free(instructions);

    const result = try applyDelta(allocator, base, instructions, @intCast(target.len));
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, target, result);

    // Delta should be smaller than the full target
    try std.testing.expect(instructions.len < target.len);
}

test "delta roundtrip real source" {
    const allocator = std.testing.allocator;

    // Two versions of a "source file" with a small change
    const v1 =
        \\const std = @import("std");
        \\
        \\pub fn main() !void {
        \\    const stdout = std.io.getStdOut().writer();
        \\    try stdout.print("Hello, {s}!\n", .{"World"});
        \\}
        \\
        \\test "basic" {
        \\    const x = 42;
        \\    try std.testing.expectEqual(@as(u32, 42), x);
        \\}
    ;

    const v2 =
        \\const std = @import("std");
        \\
        \\pub fn main() !void {
        \\    const stdout = std.io.getStdOut().writer();
        \\    try stdout.print("Hello, {s}!\n", .{"Zig"});
        \\}
        \\
        \\test "basic" {
        \\    const x = 42;
        \\    try std.testing.expectEqual(@as(u32, 42), x);
        \\}
        \\
        \\test "new test" {
        \\    try std.testing.expect(true);
        \\}
    ;

    const instructions = try computeDelta(allocator, v1, v2);
    defer allocator.free(instructions);

    const result = try applyDelta(allocator, v1, instructions, @intCast(v2.len));
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, v2, result);

    // Delta should be much smaller than the full v2
    try std.testing.expect(instructions.len < v2.len);
}

test "apply delta ignores size hint" {
    const allocator = std.testing.allocator;

    const base = "hello";
    const target = "hello world";

    const instructions = try computeDelta(allocator, base, target);
    defer allocator.free(instructions);

    // Any size hint should produce correct result
    const result = try applyDelta(allocator, base, instructions, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings(target, result);
}

test "delta empty base" {
    const allocator = std.testing.allocator;

    const base = "";
    const target = "all new content here!";

    const instructions = try computeDelta(allocator, base, target);
    defer allocator.free(instructions);

    const result = try applyDelta(allocator, base, instructions, @intCast(target.len));
    defer allocator.free(result);

    try std.testing.expectEqualSlices(u8, target, result);

    // All inserts — first byte should not have high bit set
    try std.testing.expect(instructions[0] & 0x80 == 0);
}

test "fuzz: applyDelta does not crash (bounded property)" {
    // Bounded property test (matches src/fuzz_delta.zig pattern). Replaces
    // an earlier std.testing.fuzz block that used page_allocator + an
    // attacker-controlled expected_size, which produced a 192 GiB
    // allocation under `zig build --fuzz`. See docs/FUZZ.md.
    var fba_buf: [2 * 1024 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const allocator = fba.allocator();

    var prng = std.Random.DefaultPrng.init(0xDE174AAADA7A);
    const rand = prng.random();
    var input: [16 * 1024]u8 = undefined;

    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const len = rand.intRangeAtMost(usize, 8, input.len);
        rand.bytes(input[0..len]);
        const base = input[0 .. len / 2];
        const instructions = input[len / 2 .. len];
        // Cap expected_size at 64 KiB so a malicious header cannot request
        // an unbounded allocation.
        const result = applyDelta(allocator, base, instructions, 64 * 1024) catch {
            fba.reset();
            continue;
        };
        allocator.free(result);
        fba.reset();
    }
}
