// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;

pub const Hash = [32]u8;
pub const hex_len = 64;
pub const HexHash = [hex_len]u8;

pub const zero: Hash = .{0} ** 32;

/// Hash arbitrary bytes with BLAKE3.
pub fn hash(data: []const u8) Hash {
    var out: Hash = undefined;
    Blake3.hash(data, &out, .{});
    return out;
}

/// Incremental hasher for streaming data.
pub const Hasher = struct {
    state: Blake3,

    pub fn init() Hasher {
        return .{ .state = Blake3.init(.{}) };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        self.state.update(data);
    }

    pub fn final(self: *Hasher) Hash {
        var out: Hash = undefined;
        self.state.final(&out);
        return out;
    }
};

/// Convert hash to lowercase hex string.
pub fn toHex(h: Hash) HexHash {
    return std.fmt.bytesToHex(h, .lower);
}

/// Parse hex string to hash. Returns error if invalid.
pub fn fromHex(hex: []const u8) !Hash {
    if (hex.len != hex_len) return error.InvalidLength;
    var out: Hash = undefined;
    for (&out, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch return error.InvalidHex;
    }
    return out;
}

/// Format a hash for display (first 2 bytes / rest split for object store paths).
pub fn objectPath(h: Hash) struct { dir: [2]u8, file: [62]u8 } {
    const hex = toHex(h);
    return .{
        .dir = hex[0..2].*,
        .file = hex[2..64].*,
    };
}

test "hash known value" {
    // BLAKE3("hello") should produce the known hash
    const result = hash("hello");
    const hex = toHex(result);
    try std.testing.expectEqualStrings(
        "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
        &hex,
    );
}

test "incremental hash matches single-shot" {
    const data = "hello world";
    const single = hash(data);

    var h = Hasher.init();
    h.update("hello ");
    h.update("world");
    const incremental = h.final();

    try std.testing.expectEqual(single, incremental);
}

test "fromHex roundtrip" {
    const original = hash("test");
    const hex = toHex(original);
    const parsed = try fromHex(&hex);
    try std.testing.expectEqual(original, parsed);
}

/// Join a prefix and a name with "/" separator.
/// If prefix is empty, returns a dupe of name.
pub fn joinPath(allocator: std.mem.Allocator, prefix: []const u8, name: []const u8) ![]u8 {
    if (prefix.len == 0) {
        return allocator.dupe(u8, name);
    }
    const path = try allocator.alloc(u8, prefix.len + 1 + name.len);
    @memcpy(path[0..prefix.len], prefix);
    path[prefix.len] = '/';
    @memcpy(path[prefix.len + 1 ..], name);
    return path;
}

test "objectPath splits correctly" {
    const h = hash("test");
    const path = objectPath(h);
    const hex = toHex(h);
    try std.testing.expectEqualStrings(hex[0..2], &path.dir);
    try std.testing.expectEqualStrings(hex[2..64], &path.file);
}

test "fromHex rejects too-short input" {
    try std.testing.expectError(error.InvalidLength, fromHex("abcdef1234"));
}

test "fromHex rejects invalid hex chars" {
    // 64 chars with 'g' characters which are not valid hex
    const bad_hex = "gg" ++ "00" ** 31;
    try std.testing.expectError(error.InvalidHex, fromHex(bad_hex));
}

test "toHex of zero hash" {
    const hex = toHex(zero);
    try std.testing.expectEqual(@as(usize, 64), hex.len);
    for (hex) |c| {
        try std.testing.expectEqual(@as(u8, '0'), c);
    }
}
