// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const serialize = @import("serialize.zig");
const store_mod = @import("store.zig");
const delta_mod = @import("delta.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

const Buffer = std.ArrayList(u8);

pub const MAGIC = "MKIT".*;
pub const VERSION: u32 = 1;

/// Packfile version 2 supports delta-encoded objects.
pub const VERSION_DELTA: u32 = 2;

/// Object entry type within a packfile v2.
pub const EntryType = enum(u8) {
    /// Raw serialized object (same as v1)
    raw = 0x00,
    /// Delta-encoded object: base_hash (32 bytes) + delta instructions
    delta = 0x01,
};

pub const PackResult = struct {
    bytes: []u8,
    digest: Hash,
};

/// Pack a list of raw serialized objects into packfile bytes.
/// Returns packfile bytes and BLAKE3 digest of the packfile.
/// Caller owns the returned bytes.
pub fn pack(allocator: Allocator, objects: []const []const u8) !PackResult {
    var buf: Buffer = .{};
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, &MAGIC);
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, VERSION)));
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(objects.len))));

    for (objects) |obj_bytes| {
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(obj_bytes.len))));
        try buf.appendSlice(allocator, obj_bytes);
    }

    const bytes = try buf.toOwnedSlice(allocator);
    const digest = hash_mod.hash(bytes);
    return .{ .bytes = bytes, .digest = digest };
}

/// Unpack packfile bytes into individual serialized objects.
/// Caller owns each returned slice and the outer slice.
pub fn unpack(allocator: Allocator, data: []const u8) ![][]u8 {
    if (data.len < 12) return error.PackfileTooShort;

    if (!std.mem.eql(u8, data[0..4], &MAGIC)) return error.InvalidMagic;

    const version = std.mem.littleToNative(u32, @bitCast(data[4..8].*));
    if (version != VERSION) return error.UnsupportedVersion;

    const count = std.mem.littleToNative(u32, @bitCast(data[8..12].*));
    if (count > 10_000_000) return error.TooManyObjects;

    var objects = try allocator.alloc([]u8, count);
    var initialized: u32 = 0;
    errdefer {
        for (objects[0..initialized]) |obj| {
            allocator.free(obj);
        }
        allocator.free(objects);
    }

    const max_total_bytes: usize = 4 * 1024 * 1024 * 1024; // 4GB safety limit
    var total_bytes: usize = 0;
    var pos: usize = 12;
    for (0..count) |i| {
        if (pos + 4 > data.len) return error.UnexpectedEof;
        const obj_len = std.mem.littleToNative(u32, @bitCast(data[pos..][0..4].*));
        pos += 4;

        total_bytes += obj_len;
        if (total_bytes > max_total_bytes) return error.PackfileTooLarge;
        if (pos + obj_len > data.len) return error.UnexpectedEof;
        objects[i] = try allocator.dupe(u8, data[pos..][0..obj_len]);
        initialized += 1;
        pos += obj_len;
    }

    return objects;
}

/// Collect all objects reachable from a commit.
/// Walks: commit -> tree -> blobs/subtrees, plus the full parent chain.
/// Deduplicates by hash. Returns packfile bytes and BLAKE3 digest.
/// Caller owns the returned bytes.
pub fn packReachable(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    commit_hash: Hash,
) !PackResult {
    var seen = std.AutoHashMap(Hash, void).init(allocator);
    defer seen.deinit();

    var raw_objects: std.ArrayList([]const u8) = .{};
    defer {
        for (raw_objects.items) |item| {
            allocator.free(item);
        }
        raw_objects.deinit(allocator);
    }

    try collectObject(allocator, store, commit_hash, &seen, &raw_objects);

    // Convert to const slice for pack()
    const const_items = @as([]const []const u8, raw_objects.items);
    return pack(allocator, const_items);
}

/// Recursively collect an object and its children into the list, deduplicating by hash.
fn collectObject(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    h: Hash,
    seen: *std.AutoHashMap(Hash, void),
    raw_objects: *std.ArrayList([]const u8),
) !void {
    // Skip if already seen
    const gop = try seen.getOrPut(h);
    if (gop.found_existing) return;

    const raw = try store.getRaw(allocator, h);
    errdefer allocator.free(raw);

    var obj = try serialize.deserialize(allocator, raw);
    defer obj.deinit(allocator);

    try raw_objects.append(allocator, raw);

    switch (obj) {
        .commit => |c| {
            try collectObject(allocator, store, c.tree_hash, seen, raw_objects);
            for (c.parents) |parent| {
                try collectObject(allocator, store, parent, seen, raw_objects);
            }
        },
        .tree => |t| {
            for (t.entries) |entry| {
                try collectObject(allocator, store, entry.object_hash, seen, raw_objects);
            }
        },
        .blob => {},
        .remix => |r| {
            try collectObject(allocator, store, r.tree_hash, seen, raw_objects);
        },
        .chunked_blob => |cb| {
            for (cb.chunks) |chunk| {
                try collectObject(allocator, store, chunk, seen, raw_objects);
            }
        },
        .delta => {},
    }
}

/// Unpack packfile and store all objects into a target store.
pub fn unpackInto(
    allocator: Allocator,
    data: []const u8,
    store: *store_mod.ObjectStore,
) !void {
    const objects = try unpack(allocator, data);
    defer {
        for (objects) |obj| {
            allocator.free(obj);
        }
        allocator.free(objects);
    }

    for (objects) |obj_bytes| {
        _ = try store.putRaw(obj_bytes);
    }
}

/// Walk from tip following parents, tracking depth per commit.
/// When depth >= max_depth, record parent hashes as boundaries (don't follow them).
/// Returns the boundary hashes. Caller owns the returned slice.
pub fn collectShallowBoundaries(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tip: Hash,
    max_depth: u32,
) ![]Hash {
    if (max_depth == 0) {
        var tip_obj = store.get(allocator, tip) catch return allocator.alloc(Hash, 0);
        defer tip_obj.deinit(allocator);
        if (tip_obj != .commit) return allocator.alloc(Hash, 0);
        const parents = tip_obj.commit.parents;
        const result = try allocator.alloc(Hash, parents.len);
        @memcpy(result, parents);
        return result;
    }

    const DepthEntry = struct { h: Hash, depth: u32 };

    var queue: std.ArrayList(DepthEntry) = .{};
    defer queue.deinit(allocator);

    var visited = std.AutoHashMap(Hash, void).init(allocator);
    defer visited.deinit();

    var boundaries = std.AutoHashMap(Hash, void).init(allocator);
    defer boundaries.deinit();

    try queue.append(allocator, .{ .h = tip, .depth = 0 });
    try visited.put(tip, {});

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const entry = queue.items[head];

        var obj = store.get(allocator, entry.h) catch continue;
        defer obj.deinit(allocator);

        if (obj != .commit) continue;
        const parents = obj.commit.parents;

        if (entry.depth + 1 >= max_depth) {
            for (parents) |parent| {
                if (!visited.contains(parent)) {
                    try boundaries.put(parent, {});
                }
            }
        } else {
            for (parents) |parent| {
                const gop = try visited.getOrPut(parent);
                if (!gop.found_existing) {
                    try queue.append(allocator, .{ .h = parent, .depth = entry.depth + 1 });
                }
            }
        }
    }

    const result = try allocator.alloc(Hash, boundaries.count());
    var i: usize = 0;
    var iter = boundaries.keyIterator();
    while (iter.next()) |key| {
        result[i] = key.*;
        i += 1;
    }
    return result;
}

// -- Tests --

test "pack single blob" {
    const allocator = std.testing.allocator;

    // Serialize a blob
    const blob = object.Object{ .blob = .{ .data = "hello packfile" } };
    const blob_bytes = try serialize.serialize(allocator, blob);
    defer allocator.free(blob_bytes);

    const items = [_][]const u8{blob_bytes};
    const result = try pack(allocator, &items);
    defer allocator.free(result.bytes);

    // Verify magic
    try std.testing.expectEqualStrings("MKIT", result.bytes[0..4]);

    // Verify version = 1
    const version = std.mem.littleToNative(u32, @bitCast(result.bytes[4..8].*));
    try std.testing.expectEqual(@as(u32, 1), version);

    // Verify count = 1
    const count = std.mem.littleToNative(u32, @bitCast(result.bytes[8..12].*));
    try std.testing.expectEqual(@as(u32, 1), count);
}

test "pack unpack roundtrip" {
    const allocator = std.testing.allocator;

    // Serialize 3 objects
    const blob1 = object.Object{ .blob = .{ .data = "first" } };
    const blob2 = object.Object{ .blob = .{ .data = "second" } };
    const blob3 = object.Object{ .blob = .{ .data = "third" } };

    const b1 = try serialize.serialize(allocator, blob1);
    defer allocator.free(b1);
    const b2 = try serialize.serialize(allocator, blob2);
    defer allocator.free(b2);
    const b3 = try serialize.serialize(allocator, blob3);
    defer allocator.free(b3);

    const items = [_][]const u8{ b1, b2, b3 };
    const result = try pack(allocator, &items);
    defer allocator.free(result.bytes);

    // Unpack
    const unpacked = try unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }

    // Verify 3 objects returned, byte-identical
    try std.testing.expectEqual(@as(usize, 3), unpacked.len);
    try std.testing.expectEqualSlices(u8, b1, unpacked[0]);
    try std.testing.expectEqualSlices(u8, b2, unpacked[1]);
    try std.testing.expectEqualSlices(u8, b3, unpacked[2]);
}

test "pack reachable from commit" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create a blob
    const blob_obj = object.Object{ .blob = .{ .data = "file content" } };
    const blob_hash = try store.put(allocator, blob_obj);

    // Create a tree with one entry
    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "file.txt"), .mode = .blob, .object_hash = blob_hash };
    var tree_obj = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try store.put(allocator, tree_obj);
    tree_obj.deinit(allocator);

    // Create a commit pointing to the tree
    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "initial"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    // Pack reachable objects
    const result = try packReachable(allocator, &store, commit_hash);
    defer allocator.free(result.bytes);

    // Unpack and verify we got 3 objects (commit + tree + blob)
    const unpacked = try unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }
    try std.testing.expectEqual(@as(usize, 3), unpacked.len);
}

test "pack reachable includes commit ancestors" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Commit A: blob/tree/commit
    const blob_a = object.Object{ .blob = .{ .data = "file A" } };
    const blob_a_hash = try store.put(allocator, blob_a);

    var entries_a = try allocator.alloc(object.TreeEntry, 1);
    entries_a[0] = .{ .name = try allocator.dupe(u8, "a.txt"), .mode = .blob, .object_hash = blob_a_hash };
    var tree_a_obj = object.Object{ .tree = .{ .entries = entries_a } };
    const tree_a_hash = try store.put(allocator, tree_a_obj);
    tree_a_obj.deinit(allocator);

    const parents_a = try allocator.alloc(Hash, 0);
    const commit_a_obj = object.Object{ .commit = .{
        .tree_hash = tree_a_hash,
        .parents = parents_a,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "commit A"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_a_mut = commit_a_obj;
    const commit_a_hash = try store.put(allocator, commit_a_obj);
    commit_a_mut.deinit(allocator);

    // Commit B: blob/tree/commit with parent A
    const blob_b = object.Object{ .blob = .{ .data = "file B" } };
    const blob_b_hash = try store.put(allocator, blob_b);

    var entries_b = try allocator.alloc(object.TreeEntry, 1);
    entries_b[0] = .{ .name = try allocator.dupe(u8, "b.txt"), .mode = .blob, .object_hash = blob_b_hash };
    var tree_b_obj = object.Object{ .tree = .{ .entries = entries_b } };
    const tree_b_hash = try store.put(allocator, tree_b_obj);
    tree_b_obj.deinit(allocator);

    var parents_b = try allocator.alloc(Hash, 1);
    parents_b[0] = commit_a_hash;
    const commit_b_obj = object.Object{ .commit = .{
        .tree_hash = tree_b_hash,
        .parents = parents_b,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "commit B"),
        .timestamp = 2000,
        .signature = .{0} ** 64,
    } };
    var commit_b_mut = commit_b_obj;
    const commit_b_hash = try store.put(allocator, commit_b_obj);
    commit_b_mut.deinit(allocator);

    const result = try packReachable(allocator, &store, commit_b_hash);
    defer allocator.free(result.bytes);

    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(dst_tmp.dir);
    defer dst_store.close();

    try unpackInto(allocator, result.bytes, &dst_store);

    try std.testing.expect(dst_store.exists(commit_a_hash));
    try std.testing.expect(dst_store.exists(commit_b_hash));
    try std.testing.expect(dst_store.exists(tree_a_hash));
    try std.testing.expect(dst_store.exists(tree_b_hash));
    try std.testing.expect(dst_store.exists(blob_a_hash));
    try std.testing.expect(dst_store.exists(blob_b_hash));

    var pulled_commit = try dst_store.get(allocator, commit_b_hash);
    defer pulled_commit.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), pulled_commit.commit.parents.len);
    try std.testing.expectEqual(commit_a_hash, pulled_commit.commit.parents[0]);
}

test "pack deduplicates" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create ONE blob, referenced by two tree entries
    const blob_obj = object.Object{ .blob = .{ .data = "shared content" } };
    const blob_hash = try store.put(allocator, blob_obj);

    // Tree with two entries pointing to the SAME blob
    var entries = try allocator.alloc(object.TreeEntry, 2);
    entries[0] = .{ .name = try allocator.dupe(u8, "copy_a.txt"), .mode = .blob, .object_hash = blob_hash };
    entries[1] = .{ .name = try allocator.dupe(u8, "copy_b.txt"), .mode = .blob, .object_hash = blob_hash };
    var tree_obj = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try store.put(allocator, tree_obj);
    tree_obj.deinit(allocator);

    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "dedup test"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    const result = try packReachable(allocator, &store, commit_hash);
    defer allocator.free(result.bytes);

    const unpacked = try unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }

    // Should be 3, not 4: commit + tree + blob (deduplicated)
    try std.testing.expectEqual(@as(usize, 3), unpacked.len);
}

test "pack content_digest" {
    const allocator = std.testing.allocator;

    const blob = object.Object{ .blob = .{ .data = "digest test" } };
    const blob_bytes = try serialize.serialize(allocator, blob);
    defer allocator.free(blob_bytes);

    const items = [_][]const u8{blob_bytes};
    const result = try pack(allocator, &items);
    defer allocator.free(result.bytes);

    // Verify digest matches BLAKE3 of the packfile bytes
    const expected_digest = hash_mod.hash(result.bytes);
    try std.testing.expectEqual(expected_digest, result.digest);
}

test "pack nested trees" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // blob in subdirectory
    const blob_obj = object.Object{ .blob = .{ .data = "nested content" } };
    const blob_hash = try store.put(allocator, blob_obj);

    // subtree
    var sub_entries = try allocator.alloc(object.TreeEntry, 1);
    sub_entries[0] = .{ .name = try allocator.dupe(u8, "inner.txt"), .mode = .blob, .object_hash = blob_hash };
    var sub_tree = object.Object{ .tree = .{ .entries = sub_entries } };
    const sub_tree_hash = try store.put(allocator, sub_tree);
    sub_tree.deinit(allocator);

    // root tree
    var root_entries = try allocator.alloc(object.TreeEntry, 1);
    root_entries[0] = .{ .name = try allocator.dupe(u8, "subdir"), .mode = .tree, .object_hash = sub_tree_hash };
    var root_tree = object.Object{ .tree = .{ .entries = root_entries } };
    const root_tree_hash = try store.put(allocator, root_tree);
    root_tree.deinit(allocator);

    // commit
    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = root_tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "nested"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    const result = try packReachable(allocator, &store, commit_hash);
    defer allocator.free(result.bytes);

    const unpacked = try unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }

    // commit + root_tree + sub_tree + blob = 4
    try std.testing.expectEqual(@as(usize, 4), unpacked.len);
}

test "unpack into store" {
    const allocator = std.testing.allocator;

    // Source store
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(src_tmp.dir);
    defer src_store.close();

    // Create objects in source store
    const blob_obj = object.Object{ .blob = .{ .data = "transfer me" } };
    const blob_hash = try src_store.put(allocator, blob_obj);

    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "data.txt"), .mode = .blob, .object_hash = blob_hash };
    var tree_obj = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try src_store.put(allocator, tree_obj);
    tree_obj.deinit(allocator);

    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "for transfer"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try src_store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    // Pack from source
    const result = try packReachable(allocator, &src_store, commit_hash);
    defer allocator.free(result.bytes);

    // Destination store
    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(dst_tmp.dir);
    defer dst_store.close();

    // Verify objects don't exist in destination yet
    try std.testing.expect(!dst_store.exists(commit_hash));
    try std.testing.expect(!dst_store.exists(tree_hash));
    try std.testing.expect(!dst_store.exists(blob_hash));

    // Unpack into destination
    try unpackInto(allocator, result.bytes, &dst_store);

    // Verify all objects are now accessible
    try std.testing.expect(dst_store.exists(commit_hash));
    try std.testing.expect(dst_store.exists(tree_hash));
    try std.testing.expect(dst_store.exists(blob_hash));

    // Verify blob content is correct
    var retrieved = try dst_store.get(allocator, blob_hash);
    defer retrieved.deinit(allocator);
    try std.testing.expectEqualStrings("transfer me", retrieved.blob.data);
}

/// Pack objects reachable from tip but not already known to the remote.
/// If remote_hash is null, packs everything (same as packReachable).
/// If remote_hash is set, skips objects reachable from remote_hash.
pub fn packReachableIncremental(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tip_hash: Hash,
    remote_hash: ?Hash,
) !PackResult {
    var seen = std.AutoHashMap(Hash, void).init(allocator);
    defer seen.deinit();

    // If we have a remote base, mark all its reachable objects as "seen"
    if (remote_hash) |base| {
        collectObjectHashes(allocator, store, base, &seen) catch {};
    }

    var raw_objects: std.ArrayList([]const u8) = .{};
    defer {
        for (raw_objects.items) |item| {
            allocator.free(item);
        }
        raw_objects.deinit(allocator);
    }

    try collectObject(allocator, store, tip_hash, &seen, &raw_objects);

    const const_items = @as([]const []const u8, raw_objects.items);
    return pack(allocator, const_items);
}

/// Collect all object hashes reachable from a root (without storing raw bytes).
/// Used to mark objects as "seen" for incremental packing.
fn collectObjectHashes(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    root: Hash,
    seen: *std.AutoHashMap(Hash, void),
) !void {
    const gop = try seen.getOrPut(root);
    if (gop.found_existing) return;

    var obj = store.get(allocator, root) catch return;
    defer obj.deinit(allocator);

    switch (obj) {
        .commit => |c| {
            try collectObjectHashes(allocator, store, c.tree_hash, seen);
            for (c.parents) |parent| {
                try collectObjectHashes(allocator, store, parent, seen);
            }
        },
        .tree => |t| {
            for (t.entries) |entry| {
                try collectObjectHashes(allocator, store, entry.object_hash, seen);
            }
        },
        .chunked_blob => |cb| {
            for (cb.chunks) |chunk| {
                try collectObjectHashes(allocator, store, chunk, seen);
            }
        },
        .remix => |r| {
            try collectObjectHashes(allocator, store, r.tree_hash, seen);
        },
        .blob => {},
        .delta => {},
    }
}

/// A collected raw object with its hash and type info for delta pairing.
const CollectedBlob = struct {
    hash: Hash,
    raw: []const u8,
    size: usize,
    is_blob: bool,
};

/// Pack objects reachable from tip with delta compression for blobs.
/// Similar blobs (adjacent by size) are delta-encoded when the delta is < 50% of original.
/// The packfile uses VERSION_DELTA (v2) format:
///   MAGIC (4) | VERSION (4) | COUNT (4)
///   For each object: ENTRY_TYPE (1) | OBJ_LEN (4) | OBJ_DATA
///     - raw:   type=0x00, data = serialized object bytes
///     - delta: type=0x01, data = base_hash (32) + delta instructions
pub fn packWithDeltas(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tip_hash: Hash,
    remote_hash: ?Hash,
) !PackResult {
    var seen = std.AutoHashMap(Hash, void).init(allocator);
    defer seen.deinit();

    // If we have a remote base, mark all its reachable objects as "seen"
    if (remote_hash) |base| {
        collectObjectHashes(allocator, store, base, &seen) catch {};
    }

    // Collect all raw objects
    var raw_objects: std.ArrayList([]const u8) = .{};
    defer {
        for (raw_objects.items) |item| {
            allocator.free(item);
        }
        raw_objects.deinit(allocator);
    }

    try collectObject(allocator, store, tip_hash, &seen, &raw_objects);

    if (raw_objects.items.len == 0) {
        return packV2(allocator, &.{}, &.{}, &.{});
    }

    // Classify objects: separate blobs (delta candidates) from non-blobs
    var blobs: std.ArrayList(CollectedBlob) = .{};
    defer blobs.deinit(allocator);

    var non_blob_indices: std.ArrayList(usize) = .{};
    defer non_blob_indices.deinit(allocator);

    for (raw_objects.items, 0..) |raw, idx| {
        if (raw.len > 0 and raw[0] == @intFromEnum(object.ObjectType.blob)) {
            const h = hash_mod.hash(raw);
            try blobs.append(allocator, .{
                .hash = h,
                .raw = raw,
                .size = raw.len,
                .is_blob = true,
            });
        } else {
            try non_blob_indices.append(allocator, idx);
        }
    }

    // Sort blobs by size for adjacent pairing
    std.mem.sort(CollectedBlob, blobs.items, {}, struct {
        fn lessThan(_: void, a: CollectedBlob, b: CollectedBlob) bool {
            return a.size < b.size;
        }
    }.lessThan);

    // Try delta encoding: for each blob, try delta against its size-adjacent neighbor
    // Use the previous blob (in size order) as base
    var delta_entries: std.ArrayList(DeltaEntry) = .{};
    defer {
        for (delta_entries.items) |entry| {
            allocator.free(entry.delta_data);
        }
        delta_entries.deinit(allocator);
    }

    var delta_set = std.AutoHashMap(Hash, usize).init(allocator); // hash -> index in delta_entries
    defer delta_set.deinit();

    if (blobs.items.len >= 2) {
        for (1..blobs.items.len) |i| {
            const target = blobs.items[i];
            const base = blobs.items[i - 1];

            // Skip small blobs (delta overhead not worth it for < 64 bytes)
            if (target.size < 64) continue;

            // Compute delta
            const delta_data = delta_mod.computeDelta(allocator, base.raw, target.raw) catch continue;

            // Use delta only if < 50% of original
            if (delta_data.len < target.size / 2) {
                // Build delta entry: base_hash (32) + delta instructions
                const entry_data = try allocator.alloc(u8, 32 + delta_data.len);
                @memcpy(entry_data[0..32], &base.hash);
                @memcpy(entry_data[32..], delta_data);
                allocator.free(delta_data);

                try delta_entries.append(allocator, .{
                    .target_hash = target.hash,
                    .base_hash = base.hash,
                    .delta_data = entry_data,
                });
                try delta_set.put(target.hash, delta_entries.items.len - 1);
            } else {
                allocator.free(delta_data);
            }
        }
    }

    // Build the final entry lists for packV2:
    // - All non-blob raw objects (commits, trees, etc.) go first
    // - Base blobs (those used as bases) go next
    // - Delta blobs go last (so bases are always before deltas)
    var final_raw: std.ArrayList([]const u8) = .{};
    defer final_raw.deinit(allocator);
    var final_delta: std.ArrayList([]const u8) = .{};
    defer final_delta.deinit(allocator);
    var final_entry_types: std.ArrayList(EntryType) = .{};
    defer final_entry_types.deinit(allocator);

    // 1. Non-blob objects (raw)
    for (non_blob_indices.items) |idx| {
        try final_raw.append(allocator, raw_objects.items[idx]);
        try final_entry_types.append(allocator, .raw);
    }

    // 2. Blobs: base blobs as raw, delta blobs as delta
    for (blobs.items) |blob| {
        if (delta_set.contains(blob.hash)) {
            // This blob is delta-encoded; skip raw, will be added in delta pass
        } else {
            // Raw blob (either a base or non-delta blob)
            try final_raw.append(allocator, blob.raw);
            try final_entry_types.append(allocator, .raw);
        }
    }

    // 3. Delta entries last (bases already emitted above)
    for (delta_entries.items) |entry| {
        try final_delta.append(allocator, entry.delta_data);
        try final_entry_types.append(allocator, .delta);
    }

    return packV2Mixed(allocator, final_raw.items, final_delta.items, final_entry_types.items);
}

const DeltaEntry = struct {
    target_hash: Hash,
    base_hash: Hash,
    delta_data: []u8, // base_hash (32) + delta instructions
};

/// Pack a v2 packfile with mixed raw and delta entries.
fn packV2Mixed(
    allocator: Allocator,
    raw_items: []const []const u8,
    delta_items: []const []const u8,
    entry_types: []const EntryType,
) !PackResult {
    var buf: Buffer = .{};
    errdefer buf.deinit(allocator);

    const total_count: u32 = @intCast(raw_items.len + delta_items.len);

    try buf.appendSlice(allocator, &MAGIC);
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, VERSION_DELTA)));
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, total_count)));

    var raw_idx: usize = 0;
    var delta_idx: usize = 0;

    for (entry_types) |entry_type| {
        try buf.append(allocator, @intFromEnum(entry_type));
        switch (entry_type) {
            .raw => {
                const data = raw_items[raw_idx];
                raw_idx += 1;
                try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(data.len))));
                try buf.appendSlice(allocator, data);
            },
            .delta => {
                const data = delta_items[delta_idx];
                delta_idx += 1;
                try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(data.len))));
                try buf.appendSlice(allocator, data);
            },
        }
    }

    const bytes = try buf.toOwnedSlice(allocator);
    const digest = hash_mod.hash(bytes);
    return .{ .bytes = bytes, .digest = digest };
}

/// Pack a v2 packfile (unused helper, kept for API symmetry).
fn packV2(
    allocator: Allocator,
    raw_items: []const []const u8,
    delta_items: []const []const u8,
    entry_types: []const EntryType,
) !PackResult {
    return packV2Mixed(allocator, raw_items, delta_items, entry_types);
}

/// Unpack a v2 (delta-aware) packfile and store all objects.
/// Resolves deltas inline: base objects must appear before their deltas.
pub fn unpackDeltaInto(
    allocator: Allocator,
    data: []const u8,
    store: *store_mod.ObjectStore,
) !void {
    if (data.len < 12) return error.PackfileTooShort;

    if (!std.mem.eql(u8, data[0..4], &MAGIC)) return error.InvalidMagic;

    const version = std.mem.littleToNative(u32, @bitCast(data[4..8].*));

    if (version == VERSION) {
        // V1 packfile: delegate to existing unpackInto
        return unpackInto(allocator, data, store);
    }

    if (version != VERSION_DELTA) return error.UnsupportedVersion;

    const count = std.mem.littleToNative(u32, @bitCast(data[8..12].*));
    if (count > 10_000_000) return error.TooManyObjects;

    // Track stored objects by hash for delta resolution
    var stored_raw = std.AutoHashMap(Hash, []const u8).init(allocator);
    defer {
        var it = stored_raw.valueIterator();
        while (it.next()) |val| {
            allocator.free(val.*);
        }
        stored_raw.deinit();
    }

    const max_total_bytes: usize = 4 * 1024 * 1024 * 1024; // 4GB safety limit
    var total_bytes: usize = 0;
    var pos: usize = 12;

    for (0..count) |_| {
        if (pos + 1 > data.len) return error.UnexpectedEof;
        const entry_type_byte = data[pos];
        pos += 1;

        const entry_type = std.meta.intToEnum(EntryType, entry_type_byte) catch return error.InvalidEntryType;

        if (pos + 4 > data.len) return error.UnexpectedEof;
        const obj_len = std.mem.littleToNative(u32, @bitCast(data[pos..][0..4].*));
        pos += 4;

        total_bytes += obj_len;
        if (total_bytes > max_total_bytes) return error.PackfileTooLarge;
        if (pos + obj_len > data.len) return error.UnexpectedEof;
        const entry_data = data[pos..][0..obj_len];
        pos += obj_len;

        switch (entry_type) {
            .raw => {
                // Store raw object directly
                const h = try store.putRaw(entry_data);
                // Keep a copy for potential delta resolution
                const copy = try allocator.dupe(u8, entry_data);
                try stored_raw.put(h, copy);
            },
            .delta => {
                // Resolve delta: entry_data = base_hash (32) + delta instructions
                if (entry_data.len < 32) return error.DeltaEntryTooShort;
                const base_hash: Hash = entry_data[0..32].*;
                const delta_instructions = entry_data[32..];

                // Look up base in our stored objects
                const base_raw = stored_raw.get(base_hash) orelse {
                    // Base might already be in the store (from a previous pack or pre-existing)
                    const fetched = store.getRaw(allocator, base_hash) catch return error.DeltaBaseMissing;
                    defer allocator.free(fetched);

                    const resolved = try delta_mod.applyDelta(allocator, fetched, delta_instructions, 0);
                    defer allocator.free(resolved);

                    const h = try store.putRaw(resolved);
                    const copy = try allocator.dupe(u8, resolved);
                    try stored_raw.put(h, copy);
                    continue;
                };

                const resolved = try delta_mod.applyDelta(allocator, base_raw, delta_instructions, 0);
                defer allocator.free(resolved);

                const h = try store.putRaw(resolved);
                const copy = try allocator.dupe(u8, resolved);
                try stored_raw.put(h, copy);
            },
        }
    }
}

test "unpack corrupted data" {
    const allocator = std.testing.allocator;

    // Too short
    try std.testing.expectError(error.PackfileTooShort, unpack(allocator, "ZMI"));

    // Wrong magic
    const bad_magic = "NOPE\x01\x00\x00\x00\x01\x00\x00\x00";
    try std.testing.expectError(error.InvalidMagic, unpack(allocator, bad_magic));

    // Wrong version (v1 unpack rejects v2+)
    const bad_version = "MKIT\x03\x00\x00\x00\x01\x00\x00\x00";
    try std.testing.expectError(error.UnsupportedVersion, unpack(allocator, bad_version));

    // Truncated object data: says 1 object of length 100 but no data follows
    const truncated = "MKIT\x01\x00\x00\x00\x01\x00\x00\x00\x64\x00\x00\x00";
    try std.testing.expectError(error.UnexpectedEof, unpack(allocator, truncated));
}

test "incremental pack excludes base" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create commit A: blob_a -> tree_a -> commit_a
    const blob_a = object.Object{ .blob = .{ .data = "file A" } };
    const blob_a_hash = try store.put(allocator, blob_a);

    var entries_a = try allocator.alloc(object.TreeEntry, 1);
    entries_a[0] = .{ .name = try allocator.dupe(u8, "a.txt"), .mode = .blob, .object_hash = blob_a_hash };
    var tree_a = object.Object{ .tree = .{ .entries = entries_a } };
    const tree_a_hash = try store.put(allocator, tree_a);
    tree_a.deinit(allocator);

    const parents_a = try allocator.alloc(Hash, 0);
    const commit_a_obj = object.Object{ .commit = .{
        .tree_hash = tree_a_hash,
        .parents = parents_a,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "commit A"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_a_mut = commit_a_obj;
    const commit_a_hash = try store.put(allocator, commit_a_obj);
    commit_a_mut.deinit(allocator);

    // Create commit B: blob_b -> tree_b -> commit_b (parent: commit_a)
    const blob_b = object.Object{ .blob = .{ .data = "file B" } };
    const blob_b_hash = try store.put(allocator, blob_b);

    var entries_b = try allocator.alloc(object.TreeEntry, 1);
    entries_b[0] = .{ .name = try allocator.dupe(u8, "b.txt"), .mode = .blob, .object_hash = blob_b_hash };
    var tree_b = object.Object{ .tree = .{ .entries = entries_b } };
    const tree_b_hash = try store.put(allocator, tree_b);
    tree_b.deinit(allocator);

    var parents_b = try allocator.alloc(Hash, 1);
    parents_b[0] = commit_a_hash;
    const commit_b_obj = object.Object{ .commit = .{
        .tree_hash = tree_b_hash,
        .parents = parents_b,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "commit B"),
        .timestamp = 2000,
        .signature = .{0} ** 64,
    } };
    var commit_b_mut = commit_b_obj;
    const commit_b_hash = try store.put(allocator, commit_b_obj);
    commit_b_mut.deinit(allocator);

    // Pack from B with base A: should only include commit_b + tree_b + blob_b (3 objects)
    // NOT commit_a, tree_a, or blob_a
    const result = try packReachableIncremental(allocator, &store, commit_b_hash, commit_a_hash);
    defer allocator.free(result.bytes);

    const unpacked = try unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }

    // Should be 3: commit_b + tree_b + blob_b (A's objects excluded)
    try std.testing.expectEqual(@as(usize, 3), unpacked.len);
}

test "incremental pack null base packs all" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create a simple commit: blob -> tree -> commit
    const blob = object.Object{ .blob = .{ .data = "full pack" } };
    const blob_hash = try store.put(allocator, blob);

    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "file.txt"), .mode = .blob, .object_hash = blob_hash };
    var tree = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try store.put(allocator, tree);
    tree.deinit(allocator);

    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "full"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    // Incremental with null base = full pack (same as packReachable)
    const incr_result = try packReachableIncremental(allocator, &store, commit_hash, null);
    defer allocator.free(incr_result.bytes);

    const full_result = try packReachable(allocator, &store, commit_hash);
    defer allocator.free(full_result.bytes);

    // Both should produce same number of objects
    const incr_unpacked = try unpack(allocator, incr_result.bytes);
    defer {
        for (incr_unpacked) |obj| allocator.free(obj);
        allocator.free(incr_unpacked);
    }

    const full_unpacked = try unpack(allocator, full_result.bytes);
    defer {
        for (full_unpacked) |obj| allocator.free(obj);
        allocator.free(full_unpacked);
    }

    try std.testing.expectEqual(full_unpacked.len, incr_unpacked.len);
    try std.testing.expectEqual(@as(usize, 3), incr_unpacked.len);
}

test "pack with deltas smaller than raw" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create two similar 1KB blobs that differ only slightly.
    // This should trigger delta encoding since the delta will be much smaller.
    var base_content: [1024]u8 = undefined;
    var target_content: [1024]u8 = undefined;

    for (&base_content, 0..) |*b, i| {
        b.* = @intCast(i % 251);
    }
    @memcpy(&target_content, &base_content);
    // Change a few bytes
    target_content[500] = 0xFF;
    target_content[501] = 0xFE;
    target_content[502] = 0xFD;

    const blob_a = object.Object{ .blob = .{ .data = &base_content } };
    const blob_a_hash = try store.put(allocator, blob_a);

    const blob_b = object.Object{ .blob = .{ .data = &target_content } };
    const blob_b_hash = try store.put(allocator, blob_b);

    // Create tree with both blobs
    var entries = try allocator.alloc(object.TreeEntry, 2);
    entries[0] = .{ .name = try allocator.dupe(u8, "base.bin"), .mode = .blob, .object_hash = blob_a_hash };
    entries[1] = .{ .name = try allocator.dupe(u8, "target.bin"), .mode = .blob, .object_hash = blob_b_hash };
    var tree = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try store.put(allocator, tree);
    tree.deinit(allocator);

    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "delta test"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    // Pack with deltas
    const delta_result = try packWithDeltas(allocator, &store, commit_hash, null);
    defer allocator.free(delta_result.bytes);

    // Pack without deltas (v1)
    const raw_result = try packReachable(allocator, &store, commit_hash);
    defer allocator.free(raw_result.bytes);

    // Delta pack should be smaller than raw pack
    try std.testing.expect(delta_result.bytes.len < raw_result.bytes.len);

    // Verify v2 magic
    try std.testing.expectEqualStrings("MKIT", delta_result.bytes[0..4]);
    const version = std.mem.littleToNative(u32, @bitCast(delta_result.bytes[4..8].*));
    try std.testing.expectEqual(VERSION_DELTA, version);
}

test "unpack delta restores original" {
    const allocator = std.testing.allocator;

    // Source store with two similar blobs
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(src_tmp.dir);
    defer src_store.close();

    var base_content: [1024]u8 = undefined;
    var target_content: [1024]u8 = undefined;

    for (&base_content, 0..) |*b, i| {
        b.* = @intCast(i % 251);
    }
    @memcpy(&target_content, &base_content);
    target_content[500] = 0xFF;
    target_content[501] = 0xFE;
    target_content[502] = 0xFD;

    const blob_a = object.Object{ .blob = .{ .data = &base_content } };
    const blob_a_hash = try src_store.put(allocator, blob_a);

    const blob_b = object.Object{ .blob = .{ .data = &target_content } };
    const blob_b_hash = try src_store.put(allocator, blob_b);

    // Create tree + commit
    var entries = try allocator.alloc(object.TreeEntry, 2);
    entries[0] = .{ .name = try allocator.dupe(u8, "base.bin"), .mode = .blob, .object_hash = blob_a_hash };
    entries[1] = .{ .name = try allocator.dupe(u8, "target.bin"), .mode = .blob, .object_hash = blob_b_hash };
    var tree = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try src_store.put(allocator, tree);
    tree.deinit(allocator);

    const parents = try allocator.alloc(Hash, 0);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, "delta roundtrip"),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try src_store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);

    // Pack with deltas
    const delta_pack = try packWithDeltas(allocator, &src_store, commit_hash, null);
    defer allocator.free(delta_pack.bytes);

    // Unpack into a fresh destination store
    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(dst_tmp.dir);
    defer dst_store.close();

    try unpackDeltaInto(allocator, delta_pack.bytes, &dst_store);

    // Verify all objects exist
    try std.testing.expect(dst_store.exists(commit_hash));
    try std.testing.expect(dst_store.exists(tree_hash));
    try std.testing.expect(dst_store.exists(blob_a_hash));
    try std.testing.expect(dst_store.exists(blob_b_hash));

    // Verify blob content is correct
    var retrieved_a = try dst_store.get(allocator, blob_a_hash);
    defer retrieved_a.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &base_content, retrieved_a.blob.data);

    var retrieved_b = try dst_store.get(allocator, blob_b_hash);
    defer retrieved_b.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &target_content, retrieved_b.blob.data);
}

// -- Shallow clone tests --

/// Fixture helper: build an 8-byte-LE opaque Identity on the heap so that
/// subsequent `commit.deinit(allocator)` can free it uniformly with other
/// owned fields. `mid` is a numeric u64 counter identity.
fn dupOpaqueMid(allocator: Allocator, mid: u64) !object.Identity {
    const bytes = try allocator.alloc(u8, 8);
    std.mem.writeInt(u64, bytes[0..8], mid, .little);
    return .{ .kind = .@"opaque", .bytes = bytes };
}

fn makeTestCommit(allocator: Allocator, store: *store_mod.ObjectStore, message: []const u8, parents: []const Hash) !Hash {
    const blob_obj = object.Object{ .blob = .{ .data = message } };
    const blob_hash = try store.put(allocator, blob_obj);
    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "file.txt"), .mode = .blob, .object_hash = blob_hash };
    var tree_obj = object.Object{ .tree = .{ .entries = entries } };
    const tree_hash = try store.put(allocator, tree_obj);
    tree_obj.deinit(allocator);
    const parent_copy = try allocator.dupe(Hash, parents);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parent_copy,
        .author = try dupOpaqueMid(allocator, 1),
        .signer = .{0} ** 32,
        .message = try allocator.dupe(u8, message),
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    var commit_mut = commit_obj;
    const commit_hash = try store.put(allocator, commit_obj);
    commit_mut.deinit(allocator);
    return commit_hash;
}

test "collectShallowBoundaries depth 2 with 5 commits" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();
    const c1 = try makeTestCommit(allocator, &store, "commit 1", &.{});
    const c2 = try makeTestCommit(allocator, &store, "commit 2", &.{c1});
    const c3 = try makeTestCommit(allocator, &store, "commit 3", &.{c2});
    const c4 = try makeTestCommit(allocator, &store, "commit 4", &.{c3});
    const c5 = try makeTestCommit(allocator, &store, "commit 5", &.{c4});
    const boundaries = try collectShallowBoundaries(allocator, &store, c5, 2);
    defer allocator.free(boundaries);
    try std.testing.expectEqual(@as(usize, 1), boundaries.len);
    try std.testing.expectEqual(c3, boundaries[0]);
}

test "collectShallowBoundaries depth 1" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();
    const c1 = try makeTestCommit(allocator, &store, "commit 1", &.{});
    const c2 = try makeTestCommit(allocator, &store, "commit 2", &.{c1});
    const c3 = try makeTestCommit(allocator, &store, "commit 3", &.{c2});
    const boundaries = try collectShallowBoundaries(allocator, &store, c3, 1);
    defer allocator.free(boundaries);
    try std.testing.expectEqual(@as(usize, 1), boundaries.len);
    try std.testing.expectEqual(c2, boundaries[0]);
}

test "collectShallowBoundaries no parents" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();
    const c1 = try makeTestCommit(allocator, &store, "root commit", &.{});
    const boundaries = try collectShallowBoundaries(allocator, &store, c1, 2);
    defer allocator.free(boundaries);
    try std.testing.expectEqual(@as(usize, 0), boundaries.len);
}

test "collectShallowBoundaries merge commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();
    const c1 = try makeTestCommit(allocator, &store, "base", &.{});
    const c2 = try makeTestCommit(allocator, &store, "branch a", &.{c1});
    const c3 = try makeTestCommit(allocator, &store, "branch b", &.{c1});
    const c4 = try makeTestCommit(allocator, &store, "merge", &.{ c2, c3 });
    const boundaries = try collectShallowBoundaries(allocator, &store, c4, 1);
    defer allocator.free(boundaries);
    try std.testing.expectEqual(@as(usize, 2), boundaries.len);
    var found_c2 = false;
    var found_c3 = false;
    for (boundaries) |b| {
        if (std.mem.eql(u8, &b, &c2)) found_c2 = true;
        if (std.mem.eql(u8, &b, &c3)) found_c3 = true;
    }
    try std.testing.expect(found_c2);
    try std.testing.expect(found_c3);
}

test "collectShallowBoundaries depth exceeds chain" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();
    const c1 = try makeTestCommit(allocator, &store, "commit 1", &.{});
    const c2 = try makeTestCommit(allocator, &store, "commit 2", &.{c1});
    const boundaries = try collectShallowBoundaries(allocator, &store, c2, 100);
    defer allocator.free(boundaries);
    try std.testing.expectEqual(@as(usize, 0), boundaries.len);
}
