// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Allocator = std.mem.Allocator;

/// FastCDC (Fast Content-Defined Chunking) implementation.
/// Uses a gear-hash rolling algorithm with two-level masking to find
/// chunk boundaries that are stable across insertions and deletions.
/// Gear hash lookup table, computed at compile time.
/// Each byte maps to a pseudo-random u64 for the rolling hash.
const GEAR_TABLE: [256]u64 = blk: {
    var state: u64 = 0x4D4B495446434443; // "MKITFCDC"
    var table: [256]u64 = undefined;
    for (&table) |*entry| {
        state +%= 0x9e3779b97f4a7c15;
        var z = state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        z = z ^ (z >> 31);
        entry.* = z;
    }
    break :blk table;
};

pub const ChunkBoundary = struct { offset: usize, length: usize };

pub const FastCDC = struct {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    mask_s: u64,
    mask_l: u64,

    pub fn init(min: usize, avg: usize, max: usize) FastCDC {
        const bits = std.math.log2_int(usize, avg);
        const mask: u64 = (@as(u64, 1) << @intCast(bits)) - 1;
        return .{
            .min_size = min,
            .avg_size = avg,
            .max_size = max,
            .mask_s = mask | (mask << 1),
            .mask_l = mask >> 1,
        };
    }

    /// Find the cut point in `data`. Returns the length of the first chunk.
    /// - Data shorter than min_size: returns data.len (single chunk).
    /// - Between min_size and avg_size: uses strict mask (fewer boundaries).
    /// - Between avg_size and max_size: uses loose mask (more boundaries).
    /// - At max_size: forces a cut.
    pub fn cut(self: FastCDC, data: []const u8) usize {
        if (data.len <= self.min_size) return data.len;
        var hash: u64 = 0;
        var i: usize = self.min_size;
        const avg_end = @min(self.avg_size, data.len);
        while (i < avg_end) : (i += 1) {
            hash = (hash << 1) +% GEAR_TABLE[data[i]];
            if ((hash & self.mask_s) == 0) return i;
        }
        const max_end = @min(self.max_size, data.len);
        while (i < max_end) : (i += 1) {
            hash = (hash << 1) +% GEAR_TABLE[data[i]];
            if ((hash & self.mask_l) == 0) return i;
        }
        return max_end;
    }
};

/// Iterator that yields chunk boundaries from an in-memory buffer.
pub const ChunkIterator = struct {
    cdc: FastCDC,
    data: []const u8,
    offset: usize,

    pub fn init(cdc: FastCDC, data: []const u8) ChunkIterator {
        return .{ .cdc = cdc, .data = data, .offset = 0 };
    }

    pub fn next(self: *ChunkIterator) ?ChunkBoundary {
        if (self.offset >= self.data.len) return null;
        const remaining = self.data[self.offset..];
        const len = self.cdc.cut(remaining);
        const boundary = ChunkBoundary{ .offset = self.offset, .length = len };
        self.offset += len;
        return boundary;
    }
};

/// Streaming chunker for files too large to fit in memory.
/// Reads from a file handle and yields chunk slices on demand.
pub const StreamingChunker = struct {
    cdc: FastCDC,
    buf: []u8,
    buf_len: usize,
    eof: bool,
    allocator: Allocator,

    pub fn init(allocator: Allocator, cdc: FastCDC) !StreamingChunker {
        const buf = try allocator.alloc(u8, cdc.max_size * 2);
        return .{ .cdc = cdc, .buf = buf, .buf_len = 0, .eof = false, .allocator = allocator };
    }

    pub fn deinit(self: *StreamingChunker) void {
        self.allocator.free(self.buf);
    }

    /// Read the next chunk from the file. Returns a slice into the internal
    /// buffer (valid until the next call to nextChunk) or null at EOF.
    pub fn nextChunk(self: *StreamingChunker, file: std.fs.File) !?[]const u8 {
        // Fill buffer if needed
        while (!self.eof and self.buf_len < self.cdc.max_size) {
            const n = try file.read(self.buf[self.buf_len..]);
            if (n == 0) {
                self.eof = true;
                break;
            }
            self.buf_len += n;
        }
        if (self.buf_len == 0) return null;

        const chunk_len = self.cdc.cut(self.buf[0..self.buf_len]);
        const chunk = self.buf[0..chunk_len];

        // Shift remaining data to the front
        const remaining = self.buf_len - chunk_len;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[chunk_len..self.buf_len]);
        }
        self.buf_len = remaining;

        return chunk;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "determinism: same data produces identical boundaries" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);

    // Generate deterministic test data
    var data: [200 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xDEADBEEF);
    rng.fill(&data);

    // First pass
    var iter1 = ChunkIterator.init(cdc, &data);
    var boundaries1: std.ArrayList(ChunkBoundary) = .empty;
    defer boundaries1.deinit(std.testing.allocator);
    while (iter1.next()) |b| {
        try boundaries1.append(std.testing.allocator, b);
    }

    // Second pass
    var iter2 = ChunkIterator.init(cdc, &data);
    var boundaries2: std.ArrayList(ChunkBoundary) = .empty;
    defer boundaries2.deinit(std.testing.allocator);
    while (iter2.next()) |b| {
        try boundaries2.append(std.testing.allocator, b);
    }

    try std.testing.expectEqual(boundaries1.items.len, boundaries2.items.len);
    for (boundaries1.items, boundaries2.items) |a, b| {
        try std.testing.expectEqual(a.offset, b.offset);
        try std.testing.expectEqual(a.length, b.length);
    }
}

test "min/max size constraints respected" {
    const min = 16 * 1024;
    const max = 256 * 1024;
    const cdc = FastCDC.init(min, 64 * 1024, max);

    var data: [512 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xCAFEBABE);
    rng.fill(&data);

    var iter = ChunkIterator.init(cdc, &data);
    var total_bytes: usize = 0;
    var chunk_count: usize = 0;
    while (iter.next()) |b| {
        // No chunk larger than max_size
        try std.testing.expect(b.length <= max);
        // No chunk smaller than min_size except the final one
        if (b.offset + b.length < data.len) {
            try std.testing.expect(b.length >= min);
        }
        total_bytes += b.length;
        chunk_count += 1;
    }

    // All bytes accounted for
    try std.testing.expectEqual(data.len, total_bytes);
    try std.testing.expect(chunk_count > 1);
}

test "small input returns single chunk" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    const small_data = "hello, this is a tiny file";

    const len = cdc.cut(small_data);
    try std.testing.expectEqual(small_data.len, len);

    var iter = ChunkIterator.init(cdc, small_data);
    const first = iter.next().?;
    try std.testing.expectEqual(@as(usize, 0), first.offset);
    try std.testing.expectEqual(small_data.len, first.length);
    try std.testing.expect(iter.next() == null);
}

test "ChunkIterator total bytes equals input length" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);

    var data: [300 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(42);
    rng.fill(&data);

    var iter = ChunkIterator.init(cdc, &data);
    var total: usize = 0;
    while (iter.next()) |b| {
        total += b.length;
    }
    try std.testing.expectEqual(data.len, total);
}

test "StreamingChunker matches ChunkIterator" {
    const allocator = std.testing.allocator;
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);

    // Generate test data
    var data: [300 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xF00D);
    rng.fill(&data);

    // Write to temp file
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const f = try tmp.dir.createFile("test.bin", .{});
    try f.writeAll(&data);
    f.close();

    // Collect boundaries from ChunkIterator
    var iter = ChunkIterator.init(cdc, &data);
    var expected: std.ArrayList(usize) = .empty;
    defer expected.deinit(allocator);
    while (iter.next()) |b| {
        try expected.append(allocator, b.length);
    }

    // Collect chunk lengths from StreamingChunker
    var chunker = try StreamingChunker.init(allocator, cdc);
    defer chunker.deinit();

    var file = try tmp.dir.openFile("test.bin", .{});
    defer file.close();

    var actual: std.ArrayList(usize) = .empty;
    defer actual.deinit(allocator);
    while (try chunker.nextChunk(file)) |chunk| {
        try actual.append(allocator, chunk.len);
    }

    try std.testing.expectEqual(expected.items.len, actual.items.len);
    for (expected.items, actual.items) |e, a| {
        try std.testing.expectEqual(e, a);
    }
}

test "stability: single byte insertion causes minimal boundary changes" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);

    // Original data: 64KB
    var original: [64 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xBEEF);
    rng.fill(&original);

    // Modified data: insert 1 byte at offset 32KB
    const allocator = std.testing.allocator;
    const insert_point = 32 * 1024;
    var modified = try allocator.alloc(u8, original.len + 1);
    defer allocator.free(modified);
    @memcpy(modified[0..insert_point], original[0..insert_point]);
    modified[insert_point] = 0xFF;
    @memcpy(modified[insert_point + 1 ..], original[insert_point..]);

    // Collect chunk hashes from both
    var orig_iter = ChunkIterator.init(cdc, &original);
    var orig_chunks: std.ArrayList(ChunkBoundary) = .empty;
    defer orig_chunks.deinit(allocator);
    while (orig_iter.next()) |b| {
        try orig_chunks.append(allocator, b);
    }

    var mod_iter = ChunkIterator.init(cdc, modified);
    var mod_chunks: std.ArrayList(ChunkBoundary) = .empty;
    defer mod_chunks.deinit(allocator);
    while (mod_iter.next()) |b| {
        try mod_chunks.append(allocator, b);
    }

    // Count chunks that differ (by comparing actual content hashes)
    const max_chunks = @max(orig_chunks.items.len, mod_chunks.items.len);
    var differing: usize = 0;
    for (0..max_chunks) |i| {
        if (i >= orig_chunks.items.len or i >= mod_chunks.items.len) {
            differing += 1;
            continue;
        }
        const ob = orig_chunks.items[i];
        const mb = mod_chunks.items[i];
        const orig_slice = original[ob.offset..][0..ob.length];
        const mod_slice = modified[mb.offset..][0..mb.length];
        if (!std.mem.eql(u8, orig_slice, mod_slice)) {
            differing += 1;
        }
    }

    // With CDC, at most a few chunks should differ (typically 1-3)
    try std.testing.expect(differing <= 3);
}

test "gear table values are non-zero and unique" {
    // Verify the comptime-generated table has reasonable properties
    var seen = std.AutoHashMap(u64, void).init(std.testing.allocator);
    defer seen.deinit();
    for (GEAR_TABLE) |v| {
        try std.testing.expect(v != 0);
        try seen.put(v, {});
    }
    // All 256 entries should be unique
    try std.testing.expectEqual(@as(usize, 256), seen.count());
}

test "cut on empty input" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    try std.testing.expectEqual(@as(usize, 0), cdc.cut(""));
}

test "cut on exactly min_size input" {
    const min = 1024;
    const cdc = FastCDC.init(min, 4096, 16384);
    var data: [1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(99);
    rng.fill(&data);

    const len = cdc.cut(&data);
    // Should return the full length since data.len <= min_size
    try std.testing.expectEqual(data.len, len);
}

test "fuzz: chunking covers all bytes" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, input: []const u8) anyerror!void {
            const cdc = FastCDC.init(64, 256, 1024);
            var iter = ChunkIterator.init(cdc, input);
            var total: usize = 0;
            while (iter.next()) |b| {
                total += b.length;
            }
            if (total != input.len) return error.TestUnexpectedResult;
        }
    }.run, .{});
}

test "ChunkIterator on empty input returns null" {
    const cdc = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    var iter = ChunkIterator.init(cdc, "");
    try std.testing.expect(iter.next() == null);
}

test "cut at max_size forces boundary" {
    // Use small sizes so we can test with a reasonable buffer.
    // min=4, avg=8, max=16. Data is 32 bytes of 0xFF (unlikely to trigger
    // natural boundaries because the gear hash bit patterns are deterministic
    // but we're past avg_size before any hit).
    const max = 16;
    const cdc = FastCDC.init(4, 8, max);

    // Uniform 0x00 bytes -- the gear hash accumulates the same table entry
    // repeatedly, making natural boundary hits unpredictable, but max_size
    // always forces a cut.
    var data: [64]u8 = .{0} ** 64;
    _ = &data; // prevent comptime evaluation

    const first_cut = cdc.cut(&data);
    // First chunk must be at most max_size
    try std.testing.expect(first_cut <= max);
}

test "different avg_size produces different boundaries" {
    const allocator = std.testing.allocator;

    // Generate 100KB deterministic data
    var data: [100 * 1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0xABCD);
    rng.fill(&data);

    // CDC with avg=32KB
    const cdc_small = FastCDC.init(8 * 1024, 32 * 1024, 128 * 1024);
    var iter_small = ChunkIterator.init(cdc_small, &data);
    var boundaries_small: std.ArrayList(usize) = .empty;
    defer boundaries_small.deinit(allocator);
    while (iter_small.next()) |b| {
        try boundaries_small.append(allocator, b.offset + b.length);
    }

    // CDC with avg=64KB
    const cdc_large = FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    var iter_large = ChunkIterator.init(cdc_large, &data);
    var boundaries_large: std.ArrayList(usize) = .empty;
    defer boundaries_large.deinit(allocator);
    while (iter_large.next()) |b| {
        try boundaries_large.append(allocator, b.offset + b.length);
    }

    // At least one boundary position should differ
    // (different avg implies different masks, so different chunk boundaries)
    var any_differ = false;
    const min_len = @min(boundaries_small.items.len, boundaries_large.items.len);
    for (0..min_len) |i| {
        if (boundaries_small.items[i] != boundaries_large.items[i]) {
            any_differ = true;
            break;
        }
    }
    // If lengths differ, that also counts as different boundaries
    if (boundaries_small.items.len != boundaries_large.items.len) {
        any_differ = true;
    }
    try std.testing.expect(any_differ);
}
