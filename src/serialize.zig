// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const object = @import("object.zig");
const hash_mod = @import("hash.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

const Buffer = std.ArrayList(u8);

/// Serialize an object to bytes. Caller owns returned slice.
pub fn serialize(allocator: Allocator, obj: object.Object) ![]u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);

    switch (obj) {
        .blob => |b| try serializeBlob(&buf, allocator, b),
        .tree => |t| try serializeTree(&buf, allocator, t),
        .commit => |c| try serializeCommit(&buf, allocator, c),
        .remix => |r| try serializeRemix(&buf, allocator, r),
        .chunked_blob => |cb| try serializeChunkedBlob(&buf, allocator, cb),
        .delta => |d| try serializeDelta(&buf, allocator, d),
    }

    return buf.toOwnedSlice(allocator);
}

/// Deserialize bytes into an object. Caller owns the returned object and must call deinit.
pub fn deserialize(allocator: Allocator, data: []const u8) !object.Object {
    if (data.len < 1 + 4 + 1) return error.EmptyData;

    const tag = std.enums.fromInt(object.ObjectType, data[0]) orelse return error.InvalidObjectType;
    // v1 prologue: [type:u8][magic:4 = "MKT1"][schema_version:u8 = 1]
    if (!std.mem.eql(u8, data[1..5], &object.MAGIC)) return error.InvalidMagic;
    if (data[5] != object.SCHEMA_VERSION) return error.UnsupportedObjectVersion;

    const payload = data[6..];

    return switch (tag) {
        .blob => .{ .blob = try deserializeBlob(allocator, payload) },
        .tree => .{ .tree = try deserializeTree(allocator, payload) },
        .commit => .{ .commit = try deserializeCommit(allocator, payload) },
        .remix => .{ .remix = try deserializeRemix(allocator, payload) },
        .chunked_blob => .{ .chunked_blob = try deserializeChunkedBlob(allocator, payload) },
        .delta => .{ .delta = try deserializeDelta(allocator, payload) },
    };
}

// -- Buffer helpers --

fn bufWriteByte(buf: *Buffer, allocator: Allocator, v: u8) !void {
    try buf.append(allocator, v);
}

fn bufWriteU16(buf: *Buffer, allocator: Allocator, v: u16) !void {
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u16, v)));
}

fn bufWriteU32(buf: *Buffer, allocator: Allocator, v: u32) !void {
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
}

fn bufWriteU64(buf: *Buffer, allocator: Allocator, v: u64) !void {
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u64, v)));
}

fn bufWriteHash(buf: *Buffer, allocator: Allocator, h: Hash) !void {
    try buf.appendSlice(allocator, &h);
}

fn bufWriteBytes(buf: *Buffer, allocator: Allocator, data: []const u8) !void {
    try bufWriteU32(buf, allocator, @intCast(data.len));
    try buf.appendSlice(allocator, data);
}

/// Serialize an `Identity` to the wire format shared by on-disk objects
/// and signing bytes. See docs/SPEC-OBJECTS.md §9. Errors out if the
/// identity would violate the length cap.
pub fn writeIdentity(buf: *Buffer, allocator: Allocator, id: object.Identity) !void {
    if (!id.isValid()) return error.InvalidIdentity;
    try bufWriteByte(buf, allocator, @intFromEnum(id.kind));
    try bufWriteU16(buf, allocator, @intCast(id.bytes.len));
    try buf.appendSlice(allocator, id.bytes);
}

/// Write the 6-byte v1 prologue: `[type][magic][schema_version]`.
fn writePrologue(buf: *Buffer, allocator: Allocator, t: object.ObjectType) !void {
    try bufWriteByte(buf, allocator, @intFromEnum(t));
    try buf.appendSlice(allocator, &object.MAGIC);
    try bufWriteByte(buf, allocator, object.SCHEMA_VERSION);
}

fn serializeBlob(buf: *Buffer, allocator: Allocator, b: object.Blob) !void {
    try writePrologue(buf, allocator, .blob);
    try bufWriteBytes(buf, allocator, b.data);
}

fn serializeTree(buf: *Buffer, allocator: Allocator, t: object.Tree) !void {
    try writePrologue(buf, allocator, .tree);
    try bufWriteU32(buf, allocator, @intCast(t.entries.len));
    for (t.entries) |entry| {
        try bufWriteBytes(buf, allocator, entry.name);
        try bufWriteByte(buf, allocator, @intFromEnum(entry.mode));
        try bufWriteHash(buf, allocator, entry.object_hash);
    }
}

fn serializeCommit(buf: *Buffer, allocator: Allocator, c: object.Commit) !void {
    try writePrologue(buf, allocator, .commit);
    try bufWriteHash(buf, allocator, c.tree_hash);
    try bufWriteU32(buf, allocator, @intCast(c.parents.len));
    for (c.parents) |p| {
        try bufWriteHash(buf, allocator, p);
    }
    try writeIdentity(buf, allocator, c.author);
    try bufWriteBytes(buf, allocator, c.message);
    try bufWriteU64(buf, allocator, c.timestamp);
    try buf.appendSlice(allocator, &c.signer);
    try bufWriteHash(buf, allocator, c.message_hash);
    try bufWriteHash(buf, allocator, c.content_digest);
    try buf.appendSlice(allocator, &c.signature);
}

fn serializeRemix(buf: *Buffer, allocator: Allocator, r: object.Remix) !void {
    try writePrologue(buf, allocator, .remix);
    try bufWriteHash(buf, allocator, r.tree_hash);
    try bufWriteU32(buf, allocator, @intCast(r.parents.len));
    for (r.parents) |p| {
        try bufWriteHash(buf, allocator, p);
    }
    try bufWriteU32(buf, allocator, @intCast(r.sources.len));
    for (r.sources) |s| {
        try bufWriteHash(buf, allocator, s.upstream_id);
        try bufWriteHash(buf, allocator, s.commit_hash);
    }
    try writeIdentity(buf, allocator, r.author);
    try bufWriteBytes(buf, allocator, r.message);
    try bufWriteU64(buf, allocator, r.timestamp);
    try buf.appendSlice(allocator, &r.signer);
    try buf.appendSlice(allocator, &r.signature);
}

fn serializeChunkedBlob(buf: *Buffer, allocator: Allocator, cb: object.ChunkedBlob) !void {
    try writePrologue(buf, allocator, .chunked_blob);
    try bufWriteU64(buf, allocator, cb.total_size);
    try bufWriteU32(buf, allocator, cb.chunk_size);
    try bufWriteU32(buf, allocator, @intCast(cb.chunks.len));
    for (cb.chunks) |chunk| {
        try bufWriteHash(buf, allocator, chunk);
    }
}

fn serializeDelta(buf: *Buffer, allocator: Allocator, d: object.Delta) !void {
    try writePrologue(buf, allocator, .delta);
    try bufWriteHash(buf, allocator, d.base_hash);
    try bufWriteU32(buf, allocator, d.result_size);
    try bufWriteBytes(buf, allocator, d.instructions);
}

// -- Readers --

const Reader = struct {
    data: []const u8,
    pos: usize,

    fn init(data: []const u8) Reader {
        return .{ .data = data, .pos = 0 };
    }

    fn remaining(self: Reader) usize {
        return self.data.len - self.pos;
    }

    fn readByte(self: *Reader) !u8 {
        if (self.remaining() < 1) return error.UnexpectedEof;
        const v = self.data[self.pos];
        self.pos += 1;
        return v;
    }

    fn readU16(self: *Reader) !u16 {
        if (self.remaining() < 2) return error.UnexpectedEof;
        const bytes = self.data[self.pos..][0..2];
        self.pos += 2;
        return std.mem.littleToNative(u16, @bitCast(bytes.*));
    }

    fn readU32(self: *Reader) !u32 {
        if (self.remaining() < 4) return error.UnexpectedEof;
        const bytes = self.data[self.pos..][0..4];
        self.pos += 4;
        return std.mem.littleToNative(u32, @bitCast(bytes.*));
    }

    fn readU64(self: *Reader) !u64 {
        if (self.remaining() < 8) return error.UnexpectedEof;
        const bytes = self.data[self.pos..][0..8];
        self.pos += 8;
        return std.mem.littleToNative(u64, @bitCast(bytes.*));
    }

    fn readHash(self: *Reader) !Hash {
        if (self.remaining() < 32) return error.UnexpectedEof;
        const h: Hash = self.data[self.pos..][0..32].*;
        self.pos += 32;
        return h;
    }

    fn readFixed(self: *Reader, comptime n: usize) ![n]u8 {
        if (self.remaining() < n) return error.UnexpectedEof;
        const v: [n]u8 = self.data[self.pos..][0..n].*;
        self.pos += n;
        return v;
    }

    fn readBytes(self: *Reader, allocator: Allocator) ![]u8 {
        const len = try self.readU32();
        if (self.remaining() < len) return error.UnexpectedEof;
        const slice = try allocator.dupe(u8, self.data[self.pos..][0..len]);
        self.pos += len;
        return slice;
    }

    fn readIdentity(self: *Reader, allocator: Allocator) !object.Identity {
        const kind_byte = try self.readByte();
        const kind = std.enums.fromInt(object.IdentityKind, kind_byte) orelse return error.UnknownIdentityKind;
        const len = try self.readU16();
        if (len == 0) return error.InvalidIdentity;
        if (len > object.IDENTITY_MAX_LEN) return error.IdentityTooLarge;
        if (self.remaining() < len) return error.UnexpectedEof;
        // Enforce per-kind structural constraints at decode time so callers
        // never see an invalid Identity.
        switch (kind) {
            .ed25519 => if (len != 32) return error.InvalidIdentity,
            .did_key, .@"opaque" => {},
        }
        const bytes = try allocator.dupe(u8, self.data[self.pos..][0..len]);
        self.pos += len;
        return .{ .kind = kind, .bytes = bytes };
    }
};

fn deserializeBlob(allocator: Allocator, data: []const u8) !object.Blob {
    var r = Reader.init(data);
    const content = try r.readBytes(allocator);
    if (r.remaining() != 0) {
        allocator.free(content);
        return error.TrailingData;
    }
    return .{ .data = content };
}

fn deserializeTree(allocator: Allocator, data: []const u8) !object.Tree {
    var r = Reader.init(data);
    const count = try r.readU32();
    if (count > 1_000_000) return error.TooManyEntries;
    const entries = try allocator.alloc(object.TreeEntry, count);
    var initialized: usize = 0;
    errdefer {
        for (entries[0..initialized]) |entry| {
            allocator.free(entry.name);
        }
        allocator.free(entries);
    }
    var prev_name: ?[]const u8 = null;
    for (entries) |*entry| {
        entry.name = try r.readBytes(allocator);
        initialized += 1;
        if (!object.Tree.validateEntryName(entry.name)) {
            return error.InvalidEntryName;
        }
        if (prev_name) |prev| {
            if (std.mem.order(u8, prev, entry.name) != .lt) {
                return error.InvalidEntryOrder;
            }
        }
        entry.mode = std.enums.fromInt(object.EntryMode, try r.readByte()) orelse return error.InvalidEntryMode;
        entry.object_hash = try r.readHash();
        prev_name = entry.name;
    }
    if (r.remaining() != 0) return error.TrailingData;
    return .{ .entries = entries };
}

fn deserializeCommit(allocator: Allocator, data: []const u8) !object.Commit {
    var r = Reader.init(data);
    const tree_hash = try r.readHash();
    const parent_count = try r.readU32();
    if (parent_count > 1_000) return error.TooManyParents;
    const parents = try allocator.alloc(Hash, parent_count);
    errdefer allocator.free(parents);
    for (parents) |*p| {
        p.* = try r.readHash();
    }
    const author = try r.readIdentity(allocator);
    errdefer allocator.free(author.bytes);
    const message = try r.readBytes(allocator);
    errdefer allocator.free(message);
    const timestamp = try r.readU64();
    const signer = try r.readFixed(32);
    const message_hash = try r.readHash();
    const content_digest = try r.readHash();
    const signature = try r.readFixed(64);
    if (r.remaining() != 0) return error.TrailingData;

    return .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = signer,
        .message = message,
        .timestamp = timestamp,
        .message_hash = message_hash,
        .content_digest = content_digest,
        .signature = signature,
    };
}

fn deserializeRemix(allocator: Allocator, data: []const u8) !object.Remix {
    var r = Reader.init(data);
    const tree_hash = try r.readHash();
    const parent_count = try r.readU32();
    if (parent_count > 1_000) return error.TooManyParents;
    const parents = try allocator.alloc(Hash, parent_count);
    errdefer allocator.free(parents);
    for (parents) |*p| {
        p.* = try r.readHash();
    }
    const source_count = try r.readU32();
    if (source_count > 10_000) return error.TooManySources;
    const sources = try allocator.alloc(object.RemixSource, source_count);
    errdefer allocator.free(sources);
    for (sources) |*s| {
        s.upstream_id = try r.readHash();
        s.commit_hash = try r.readHash();
    }
    const author = try r.readIdentity(allocator);
    errdefer allocator.free(author.bytes);
    const message = try r.readBytes(allocator);
    errdefer allocator.free(message);
    const timestamp = try r.readU64();
    const signer = try r.readFixed(32);
    const signature = try r.readFixed(64);
    if (sources.len > 1) {
        for (sources[0 .. sources.len - 1], sources[1..]) |a, b| {
            const upstream_order = std.mem.order(u8, &a.upstream_id, &b.upstream_id);
            if (upstream_order == .gt or (upstream_order == .eq and std.mem.order(u8, &a.commit_hash, &b.commit_hash) != .lt)) {
                return error.InvalidSourceOrder;
            }
        }
    }
    if (r.remaining() != 0) return error.TrailingData;

    return .{
        .tree_hash = tree_hash,
        .parents = parents,
        .sources = sources,
        .author = author,
        .signer = signer,
        .message = message,
        .timestamp = timestamp,
        .signature = signature,
    };
}

fn deserializeChunkedBlob(allocator: Allocator, data: []const u8) !object.ChunkedBlob {
    var r = Reader.init(data);
    const total_size = try r.readU64();
    const chunk_size = try r.readU32();
    // chunk_size == 0 is valid and indicates content-defined chunking (CDC)
    const chunk_count = try r.readU32();
    if (chunk_count > 1_000_000) return error.TooManyChunks;
    const chunks = try allocator.alloc(Hash, chunk_count);
    errdefer allocator.free(chunks);
    for (chunks) |*chunk| {
        chunk.* = try r.readHash();
    }
    if (r.remaining() != 0) return error.TrailingData;
    return .{
        .total_size = total_size,
        .chunk_size = chunk_size,
        .chunks = chunks,
    };
}

fn deserializeDelta(allocator: Allocator, data: []const u8) !object.Delta {
    var r = Reader.init(data);
    const base_hash = try r.readHash();
    const result_size = try r.readU32();
    const instructions = try r.readBytes(allocator);
    if (r.remaining() != 0) {
        allocator.free(instructions);
        return error.TrailingData;
    }
    return .{
        .base_hash = base_hash,
        .result_size = result_size,
        .instructions = instructions,
    };
}

// -- Tests --

fn ownedEd25519(allocator: Allocator, pk: [32]u8) !object.Identity {
    const bytes = try allocator.dupe(u8, &pk);
    return .{ .kind = .ed25519, .bytes = bytes };
}

fn ownedOpaque(allocator: Allocator, b: []const u8) !object.Identity {
    const bytes = try allocator.dupe(u8, b);
    return .{ .kind = .@"opaque", .bytes = bytes };
}

test "blob roundtrip" {
    const allocator = std.testing.allocator;
    const original = object.Object{ .blob = .{ .data = "hello world" } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);

    // Verify type tag + magic + schema version
    try std.testing.expectEqual(@as(u8, 0x01), bytes[0]);
    try std.testing.expectEqualSlices(u8, "MKT1", bytes[1..5]);
    try std.testing.expectEqual(@as(u8, 0x01), bytes[5]);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualStrings("hello world", parsed.blob.data);
}

test "tree roundtrip" {
    const allocator = std.testing.allocator;
    const h1 = hash_mod.hash("file1");
    const h2 = hash_mod.hash("file2");

    var entries = try allocator.alloc(object.TreeEntry, 2);
    entries[0] = .{ .name = try allocator.dupe(u8, "alpha.txt"), .mode = .blob, .object_hash = h1 };
    entries[1] = .{ .name = try allocator.dupe(u8, "beta"), .mode = .tree, .object_hash = h2 };

    var original = object.Object{ .tree = .{ .entries = entries } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), parsed.tree.entries.len);
    try std.testing.expectEqualStrings("alpha.txt", parsed.tree.entries[0].name);
    try std.testing.expectEqual(object.EntryMode.blob, parsed.tree.entries[0].mode);
    try std.testing.expectEqual(h1, parsed.tree.entries[0].object_hash);
    try std.testing.expectEqualStrings("beta", parsed.tree.entries[1].name);
    try std.testing.expectEqual(object.EntryMode.tree, parsed.tree.entries[1].mode);
}

test "tree executable mode roundtrip" {
    const allocator = std.testing.allocator;
    const h1 = hash_mod.hash("file1");

    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "script.sh"), .mode = .executable, .object_hash = h1 };

    var original = object.Object{ .tree = .{ .entries = entries } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(object.EntryMode.executable, parsed.tree.entries[0].mode);
}

test "commit roundtrip" {
    const allocator = std.testing.allocator;
    const tree_hash = hash_mod.hash("tree");
    const parent = hash_mod.hash("parent");
    var parents = try allocator.alloc(Hash, 1);
    parents[0] = parent;

    const author = try ownedEd25519(allocator, [_]u8{0xAA} ** 32);

    var original = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = .{0xAA} ** 32,
        .message = try allocator.dupe(u8, "initial commit"),
        .timestamp = 1711300000,
        .signature = .{0xBB} ** 64,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(tree_hash, parsed.commit.tree_hash);
    try std.testing.expectEqual(@as(usize, 1), parsed.commit.parents.len);
    try std.testing.expectEqual(parent, parsed.commit.parents[0]);
    try std.testing.expectEqual(object.IdentityKind.ed25519, parsed.commit.author.kind);
    try std.testing.expectEqual(@as(usize, 32), parsed.commit.author.bytes.len);
    try std.testing.expectEqualStrings("initial commit", parsed.commit.message);
    try std.testing.expectEqual(@as(u64, 1711300000), parsed.commit.timestamp);
}

test "commit roundtrip with opaque identity (8-byte LE counter)" {
    const allocator = std.testing.allocator;
    const tree_hash = hash_mod.hash("tree");
    const parents = try allocator.alloc(Hash, 0);

    // 8-byte LE u64 = 42
    const mid_bytes = [_]u8{ 42, 0, 0, 0, 0, 0, 0, 0 };
    const author = try ownedOpaque(allocator, &mid_bytes);

    var original = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = .{0xAA} ** 32,
        .message = try allocator.dupe(u8, "opaque author"),
        .timestamp = 1700000000,
        .signature = .{0xBB} ** 64,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(object.IdentityKind.@"opaque", parsed.commit.author.kind);
    try std.testing.expectEqualSlices(u8, &mid_bytes, parsed.commit.author.bytes);
}

test "remix roundtrip" {
    const allocator = std.testing.allocator;
    const tree_hash = hash_mod.hash("remix-tree");
    const parents = try allocator.alloc(Hash, 0);

    var sources = try allocator.alloc(object.RemixSource, 1);
    sources[0] = .{
        .upstream_id = hash_mod.hash("project-a"),
        .commit_hash = hash_mod.hash("commit-x"),
    };

    const author = try ownedEd25519(allocator, [_]u8{0xCC} ** 32);

    var original = object.Object{ .remix = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .sources = sources,
        .author = author,
        .signer = .{0xCC} ** 32,
        .message = try allocator.dupe(u8, "remixed audio"),
        .timestamp = 1711300100,
        .signature = .{0xDD} ** 64,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), parsed.remix.sources.len);
    try std.testing.expectEqual(hash_mod.hash("project-a"), parsed.remix.sources[0].upstream_id);
    try std.testing.expectEqual(object.IdentityKind.ed25519, parsed.remix.author.kind);
    try std.testing.expectEqualStrings("remixed audio", parsed.remix.message);
}

test "deterministic serialization" {
    const allocator = std.testing.allocator;
    const obj = object.Object{ .blob = .{ .data = "deterministic" } };
    const bytes1 = try serialize(allocator, obj);
    defer allocator.free(bytes1);
    const bytes2 = try serialize(allocator, obj);
    defer allocator.free(bytes2);
    try std.testing.expectEqualSlices(u8, bytes1, bytes2);

    // Same content -> same hash
    try std.testing.expectEqual(hash_mod.hash(bytes1), hash_mod.hash(bytes2));
}

test "empty blob roundtrip" {
    const allocator = std.testing.allocator;
    const original = object.Object{ .blob = .{ .data = "" } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);

    // prologue(6) + len(4) + data(0) = 10 bytes
    try std.testing.expectEqual(@as(usize, 10), bytes.len);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualStrings("", parsed.blob.data);
}

test "root commit (zero parents) roundtrip" {
    const allocator = std.testing.allocator;
    const tree_hash = hash_mod.hash("tree");
    const parents = try allocator.alloc(Hash, 0);

    const author = try ownedEd25519(allocator, [_]u8{0x11} ** 32);

    var original = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = .{0x11} ** 32,
        .message = try allocator.dupe(u8, "genesis"),
        .timestamp = 1000000,
        .signature = .{0x22} ** 64,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), parsed.commit.parents.len);
    try std.testing.expectEqualStrings("genesis", parsed.commit.message);
}

test "empty tree roundtrip" {
    const allocator = std.testing.allocator;
    const entries = try allocator.alloc(object.TreeEntry, 0);

    var original = object.Object{ .tree = .{ .entries = entries } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), parsed.tree.entries.len);
}

test "invalid object type tag" {
    const allocator = std.testing.allocator;
    const bad_data = [_]u8{ 0xFF, 'M', 'K', 'T', '1', 0x01 };
    try std.testing.expectError(error.InvalidObjectType, deserialize(allocator, &bad_data));
}

test "reject bad magic" {
    const allocator = std.testing.allocator;
    // type=blob, magic clearly not "MKT1"
    const bad_data = [_]u8{ 0x01, 'X', 'Y', 'Z', 'W', 0x01, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidMagic, deserialize(allocator, &bad_data));
}

test "reject unsupported schema version" {
    const allocator = std.testing.allocator;
    const bad_data = [_]u8{ 0x01, 'M', 'K', 'T', '1', 0x02, 0, 0, 0, 0 };
    try std.testing.expectError(error.UnsupportedObjectVersion, deserialize(allocator, &bad_data));
}

test "empty data" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.EmptyData, deserialize(allocator, ""));
}

test "truncated blob" {
    const allocator = std.testing.allocator;
    // prologue + length says 100 bytes but only 2 bytes follow
    const bad_data = [_]u8{ 0x01, 'M', 'K', 'T', '1', 0x01, 0x64, 0x00, 0x00, 0x00, 0xAA, 0xBB };
    try std.testing.expectError(error.UnexpectedEof, deserialize(allocator, &bad_data));
}

test "reject unsorted tree entries" {
    const allocator = std.testing.allocator;
    var buf: Buffer = .empty;
    defer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .tree);
    try bufWriteU32(&buf, allocator, 2);
    try bufWriteBytes(&buf, allocator, "z.txt");
    try bufWriteByte(&buf, allocator, @intFromEnum(object.EntryMode.blob));
    try bufWriteHash(&buf, allocator, hash_mod.hash("z"));
    try bufWriteBytes(&buf, allocator, "a.txt");
    try bufWriteByte(&buf, allocator, @intFromEnum(object.EntryMode.blob));
    try bufWriteHash(&buf, allocator, hash_mod.hash("a"));

    try std.testing.expectError(error.InvalidEntryOrder, deserialize(allocator, buf.items));
}

test "reject trailing bytes" {
    const allocator = std.testing.allocator;
    const original = object.Object{ .blob = .{ .data = "hello" } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);

    const tailed = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(tailed);
    @memcpy(tailed[0..bytes.len], bytes);
    tailed[bytes.len] = 0xFF;

    try std.testing.expectError(error.TrailingData, deserialize(allocator, tailed));
}

test "reject identity with zero length" {
    const allocator = std.testing.allocator;
    var buf: Buffer = .empty;
    defer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .commit);
    try bufWriteHash(&buf, allocator, hash_mod.zero);
    try bufWriteU32(&buf, allocator, 0); // 0 parents
    // Identity with zero length — must be rejected.
    try bufWriteByte(&buf, allocator, @intFromEnum(object.IdentityKind.@"opaque"));
    try bufWriteU16(&buf, allocator, 0);

    try std.testing.expectError(error.InvalidIdentity, deserialize(allocator, buf.items));
}

test "reject identity with unknown kind" {
    const allocator = std.testing.allocator;
    var buf: Buffer = .empty;
    defer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .commit);
    try bufWriteHash(&buf, allocator, hash_mod.zero);
    try bufWriteU32(&buf, allocator, 0);
    try bufWriteByte(&buf, allocator, 0xEE); // unknown kind
    try bufWriteU16(&buf, allocator, 4);
    try buf.appendSlice(allocator, "xxxx");

    try std.testing.expectError(error.UnknownIdentityKind, deserialize(allocator, buf.items));
}

test "reject ed25519 identity with wrong length" {
    const allocator = std.testing.allocator;
    var buf: Buffer = .empty;
    defer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .commit);
    try bufWriteHash(&buf, allocator, hash_mod.zero);
    try bufWriteU32(&buf, allocator, 0);
    // ed25519 with len=8 — invalid.
    try bufWriteByte(&buf, allocator, @intFromEnum(object.IdentityKind.ed25519));
    try bufWriteU16(&buf, allocator, 8);
    try buf.appendSlice(allocator, "12345678");

    try std.testing.expectError(error.InvalidIdentity, deserialize(allocator, buf.items));
}

test "chunked blob roundtrip" {
    const allocator = std.testing.allocator;
    const h1 = hash_mod.hash("chunk1");
    const h2 = hash_mod.hash("chunk2");
    const h3 = hash_mod.hash("chunk3");

    var chunks = try allocator.alloc(hash_mod.Hash, 3);
    chunks[0] = h1;
    chunks[1] = h2;
    chunks[2] = h3;

    var original = object.Object{ .chunked_blob = .{
        .total_size = 3 * 65536,
        .chunk_size = 65536,
        .chunks = chunks,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    // Verify type tag is 0x05
    try std.testing.expectEqual(@as(u8, 0x05), bytes[0]);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 3 * 65536), parsed.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 65536), parsed.chunked_blob.chunk_size);
    try std.testing.expectEqual(@as(usize, 3), parsed.chunked_blob.chunks.len);
    try std.testing.expectEqual(h1, parsed.chunked_blob.chunks[0]);
    try std.testing.expectEqual(h2, parsed.chunked_blob.chunks[1]);
    try std.testing.expectEqual(h3, parsed.chunked_blob.chunks[2]);
}

test "chunked blob empty chunks" {
    const allocator = std.testing.allocator;

    const chunks = try allocator.alloc(hash_mod.Hash, 0);

    var original = object.Object{ .chunked_blob = .{
        .total_size = 0,
        .chunk_size = 65536,
        .chunks = chunks,
    } };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 0), parsed.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 65536), parsed.chunked_blob.chunk_size);
    try std.testing.expectEqual(@as(usize, 0), parsed.chunked_blob.chunks.len);
}

test "chunked blob CDC (chunk_size=0) roundtrip" {
    const allocator = std.testing.allocator;
    const h1 = hash_mod.hash("cdc-chunk1");
    const h2 = hash_mod.hash("cdc-chunk2");

    var chunks = try allocator.alloc(hash_mod.Hash, 2);
    chunks[0] = h1;
    chunks[1] = h2;

    var original = object.Object{
        .chunked_blob = .{
            .total_size = 100000,
            .chunk_size = 0, // content-defined chunking
            .chunks = chunks,
        },
    };
    const bytes = try serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 100000), parsed.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 0), parsed.chunked_blob.chunk_size);
    try std.testing.expectEqual(@as(usize, 2), parsed.chunked_blob.chunks.len);
    try std.testing.expectEqual(h1, parsed.chunked_blob.chunks[0]);
    try std.testing.expectEqual(h2, parsed.chunked_blob.chunks[1]);
}

test "fuzz: deserialize does not crash on arbitrary bytes" {
    try std.testing.fuzz({}, struct {
        // Why: 0.16 changed the fuzz callback signature. Input bytes now
        // come from a *std.testing.Smith via smith.slice(&buf).
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            const allocator = std.heap.page_allocator;
            var buf: [64 * 1024]u8 = undefined;
            const len = smith.slice(&buf);
            var obj = deserialize(allocator, buf[0..len]) catch return;
            obj.deinit(allocator);
        }
    }.run, .{});
}

test "fuzz: blob serialize-deserialize roundtrip" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            const allocator = std.heap.page_allocator;
            var buf: [64 * 1024]u8 = undefined;
            const len = smith.slice(&buf);
            const original = object.Object{ .blob = .{ .data = buf[0..len] } };
            const bytes = serialize(allocator, original) catch return;
            defer allocator.free(bytes);
            var parsed = deserialize(allocator, bytes) catch return;
            defer parsed.deinit(allocator);
        }
    }.run, .{});
}
