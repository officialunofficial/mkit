// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const protocol = @import("../protocol.zig");
const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// In-memory Transport implementation for testing.
///
/// Stores packfiles and refs as key-value pairs in a `StringHashMap`.
/// Packs are keyed by `"packs/<hex-digest>"`, refs are stored by their
/// full ref name (e.g. `"refs/heads/main"`). Values are stored using the
/// same wire format as the real transports: packs as raw bytes, refs as
/// 65-byte hex+newline via `protocol.formatRef`.
///
/// All keys and values are owned copies allocated with the MemoryTransport's
/// allocator and freed on `deinit`.
pub const MemoryTransport = struct {
    objects: std.StringHashMap([]u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator) MemoryTransport {
        return .{
            .objects = std.StringHashMap([]u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MemoryTransport) void {
        var iter = self.objects.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.objects.deinit();
    }

    /// Return a `protocol.Transport` interface backed by this instance.
    pub fn transport(self: *MemoryTransport) protocol.Transport {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    /// Number of entries (packs + refs) currently stored.
    pub fn count(self: *const MemoryTransport) usize {
        return self.objects.count();
    }

    const vtable = protocol.Transport.VTable{
        .uploadPack = uploadPackImpl,
        .downloadPack = downloadPackImpl,
        .packExists = packExistsImpl,
        .writeRef = writeRefImpl,
        .updateRef = updateRefImpl,
        .readRef = readRefImpl,
        .listRefs = listRefsImpl,
    };

    fn uploadPackImpl(ptr: *anyopaque, _: Allocator, bytes: []const u8, digest: Hash) anyerror!void {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        const pk = protocol.packKey(digest);
        const key = try self.allocator.dupe(u8, &pk);
        errdefer self.allocator.free(key);
        const value = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(value);

        // If key already exists, free old entry before overwriting
        if (self.objects.fetchRemove(key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        try self.objects.put(key, value);
    }

    fn downloadPackImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror![]u8 {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        const pk = protocol.packKey(digest);
        const entry = self.objects.get(&pk) orelse return error.PackNotFound;
        return allocator.dupe(u8, entry);
    }

    fn packExistsImpl(ptr: *anyopaque, _: Allocator, digest: Hash) anyerror!bool {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        const pk = protocol.packKey(digest);
        return self.objects.contains(&pk);
    }

    fn writeRefImpl(ptr: *anyopaque, _: Allocator, ref_name: []const u8, h: Hash) anyerror!void {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        return updateRefImpl(ptr, self.allocator, ref_name, .any, h);
    }

    fn updateRefImpl(ptr: *anyopaque, _: Allocator, ref_name: []const u8, condition: protocol.RefWriteCondition, h: Hash) anyerror!void {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        const current = try readRefImpl(ptr, self.allocator, ref_name);

        switch (condition) {
            .any => {},
            .missing => if (current != null) return error.RefConflict,
            .match => |expected| {
                if (current == null or !std.mem.eql(u8, &current.?, &expected)) return error.RefConflict;
            },
        }

        const key = try self.allocator.dupe(u8, ref_name);
        errdefer self.allocator.free(key);
        const ref_data = protocol.formatRef(h);
        const value = try self.allocator.dupe(u8, &ref_data);
        errdefer self.allocator.free(value);

        if (self.objects.fetchRemove(key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        try self.objects.put(key, value);
    }

    fn readRefImpl(ptr: *anyopaque, _: Allocator, ref_name: []const u8) anyerror!?Hash {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        const entry = self.objects.get(ref_name) orelse return null;
        return protocol.parseRef(entry) catch error.InvalidRef;
    }

    fn listRefsImpl(ptr: *anyopaque, allocator: Allocator, prefix: []const u8) anyerror![]protocol.Ref {
        const self: *MemoryTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefPrefix(prefix)) return error.InvalidRef;

        var result: std.ArrayList(protocol.Ref) = .{};
        errdefer {
            for (result.items) |ref| allocator.free(ref.name);
            result.deinit(allocator);
        }

        var iter = self.objects.iterator();
        while (iter.next()) |entry| {
            if (std.mem.startsWith(u8, entry.key_ptr.*, prefix) and protocol.validateRefName(entry.key_ptr.*)) {
                const suffix = entry.key_ptr.*[prefix.len..];
                if (!protocol.validateRefName(suffix)) continue;
                const trimmed = std.mem.trimRight(u8, entry.value_ptr.*, "\n\r ");
                const h = hash_mod.fromHex(trimmed) catch continue;
                const name = try allocator.dupe(u8, suffix);
                errdefer allocator.free(name);
                try result.append(allocator, .{ .name = name, .hash = h });
            }
        }

        // Sort by name for deterministic ordering
        std.mem.sort(protocol.Ref, result.items, {}, struct {
            fn lessThan(_: void, a: protocol.Ref, b: protocol.Ref) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lessThan);

        return result.toOwnedSlice(allocator);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "upload and download pack" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const data = "pack file content here";
    const digest = hash_mod.hash(data);

    var t = mem.transport();
    try t.uploadPack(allocator, data, digest);

    const downloaded = try t.downloadPack(allocator, digest);
    defer allocator.free(downloaded);
    try std.testing.expectEqualStrings(data, downloaded);
}

test "download missing pack" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const fake_digest = hash_mod.hash("nonexistent");
    var t = mem.transport();
    try std.testing.expectError(error.PackNotFound, t.downloadPack(allocator, fake_digest));
}

test "pack exists true" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const data = "some pack bytes";
    const digest = hash_mod.hash(data);

    var t = mem.transport();
    try t.uploadPack(allocator, data, digest);

    const exists = try t.packExists(allocator, digest);
    try std.testing.expect(exists);
}

test "pack exists false" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    var t = mem.transport();
    const exists = try t.packExists(allocator, hash_mod.zero);
    try std.testing.expect(!exists);
}

test "write and read ref" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const h = hash_mod.hash("commit-abc");
    var t = mem.transport();
    try t.writeRef(allocator, "refs/heads/main", h);

    const read = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expectEqual(h, read.?);
}

test "read missing ref" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    var t = mem.transport();
    const result = try t.readRef(allocator, "refs/heads/nonexistent");
    try std.testing.expectEqual(@as(?Hash, null), result);
}

test "overwrite ref" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const h1 = hash_mod.hash("commit-1");
    const h2 = hash_mod.hash("commit-2");

    var t = mem.transport();
    try t.writeRef(allocator, "refs/heads/main", h1);

    // Overwrite with different hash
    try t.writeRef(allocator, "refs/heads/main", h2);

    const read = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expectEqual(h2, read.?);
}

test "update ref rejects stale expected hash" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const current = hash_mod.hash("current");
    const stale = hash_mod.hash("stale");
    const next = hash_mod.hash("next");

    var t = mem.transport();
    try t.writeRef(allocator, "refs/heads/main", current);
    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .{ .match = stale }, next),
    );
}

test "update ref creates only when missing" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const h = hash_mod.hash("initial");
    var t = mem.transport();
    try t.updateRef(allocator, "refs/heads/main", .missing, h);
    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .missing, h),
    );
}

test "list refs with prefix" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    const h1 = hash_mod.hash("main-commit");
    const h2 = hash_mod.hash("dev-commit");
    const h3 = hash_mod.hash("tag-v1");

    var t = mem.transport();
    try t.writeRef(allocator, "refs/heads/main", h1);
    try t.writeRef(allocator, "refs/heads/dev", h2);
    try t.writeRef(allocator, "refs/tags/v1", h3);

    // List only heads
    const heads = try t.listRefs(allocator, "refs/heads/");
    defer {
        for (heads) |ref| allocator.free(ref.name);
        allocator.free(heads);
    }

    try std.testing.expectEqual(@as(usize, 2), heads.len);
    // Names are the suffix after prefix, sorted alphabetically
    try std.testing.expectEqualStrings("dev", heads[0].name);
    try std.testing.expectEqual(h2, heads[0].hash);
    try std.testing.expectEqualStrings("main", heads[1].name);
    try std.testing.expectEqual(h1, heads[1].hash);

    // List only tags
    const tags = try t.listRefs(allocator, "refs/tags/");
    defer {
        for (tags) |ref| allocator.free(ref.name);
        allocator.free(tags);
    }

    try std.testing.expectEqual(@as(usize, 1), tags.len);
    try std.testing.expectEqualStrings("v1", tags[0].name);
    try std.testing.expectEqual(h3, tags[0].hash);
}

test "list refs empty" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    var t = mem.transport();
    const refs_list = try t.listRefs(allocator, "refs/heads/");
    defer allocator.free(refs_list);
    try std.testing.expectEqual(@as(usize, 0), refs_list.len);
}

test "list refs sorted" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    var t = mem.transport();
    // Insert in non-alphabetical order
    try t.writeRef(allocator, "refs/heads/zebra", hash_mod.hash("z"));
    try t.writeRef(allocator, "refs/heads/alpha", hash_mod.hash("a"));
    try t.writeRef(allocator, "refs/heads/middle", hash_mod.hash("m"));

    const refs_list = try t.listRefs(allocator, "refs/heads/");
    defer {
        for (refs_list) |ref| allocator.free(ref.name);
        allocator.free(refs_list);
    }

    try std.testing.expectEqual(@as(usize, 3), refs_list.len);
    try std.testing.expectEqualStrings("alpha", refs_list[0].name);
    try std.testing.expectEqualStrings("middle", refs_list[1].name);
    try std.testing.expectEqualStrings("zebra", refs_list[2].name);
}

test "transport interface works" {
    const allocator = std.testing.allocator;
    var mem = MemoryTransport.init(allocator);
    defer mem.deinit();

    // Get the vtable-backed interface
    var t = mem.transport();

    // 1. uploadPack + downloadPack
    const pack_data = "full interface test pack";
    const pack_digest = hash_mod.hash(pack_data);
    try t.uploadPack(allocator, pack_data, pack_digest);

    const downloaded = try t.downloadPack(allocator, pack_digest);
    defer allocator.free(downloaded);
    try std.testing.expectEqualStrings(pack_data, downloaded);

    // 2. packExists
    try std.testing.expect(try t.packExists(allocator, pack_digest));
    try std.testing.expect(!try t.packExists(allocator, hash_mod.zero));

    // 3. writeRef + readRef
    const commit_hash = hash_mod.hash("interface-commit");
    try t.writeRef(allocator, "refs/heads/main", commit_hash);

    const read_hash = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expectEqual(commit_hash, read_hash.?);

    const missing = try t.readRef(allocator, "refs/heads/missing");
    try std.testing.expectEqual(@as(?Hash, null), missing);

    // 4. listRefs
    try t.writeRef(allocator, "refs/heads/dev", hash_mod.hash("dev-commit"));

    const refs_list = try t.listRefs(allocator, "refs/heads/");
    defer {
        for (refs_list) |ref| allocator.free(ref.name);
        allocator.free(refs_list);
    }

    try std.testing.expectEqual(@as(usize, 2), refs_list.len);
    try std.testing.expectEqualStrings("dev", refs_list[0].name);
    try std.testing.expectEqualStrings("main", refs_list[1].name);
}
