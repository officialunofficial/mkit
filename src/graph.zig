// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Collect the set of all ancestors of `start` (including `start` itself) via DFS.
/// Stops after `max_ancestors` commits to bound memory usage.
pub fn collectAncestorSet(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    start: Hash,
    set: *std.AutoHashMap(Hash, void),
) !void {
    var stack: std.ArrayList(Hash) = .empty;
    defer stack.deinit(allocator);
    try stack.append(allocator, start);

    const max_ancestors: usize = 10000;
    var count: usize = 0;

    while (stack.pop()) |current| {
        if (count >= max_ancestors) break;
        const gop = try set.getOrPut(current);
        if (gop.found_existing) continue;
        count += 1;

        var obj = store.get(allocator, current) catch continue;
        defer obj.deinit(allocator);
        if (obj != .commit) continue;

        for (obj.commit.parents) |parent| {
            try stack.append(allocator, parent);
        }
    }
}

// -- Tests --

test "collectAncestorSet on linear chain" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);

    const blob_obj = object.Object{ .blob = .{ .data = "data" } };
    const blob_hash = try store.put(allocator, blob_obj);

    const entries = &[_]object.TreeEntry{.{ .name = "f", .mode = .blob, .object_hash = blob_hash }};
    const tree_obj = object.Object{ .tree = .{ .entries = @constCast(entries) } };
    const tree_hash = try store.put(allocator, tree_obj);

    const zero_pk = [_]u8{0} ** 32;

    // c1 (root) <- c2 <- c3
    const c1_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = &.{},
        .author = .{ .kind = .ed25519, .bytes = &zero_pk },
        .signer = .{0} ** 32,
        .message = "c1",
        .timestamp = 1,
        .signature = .{0} ** 64,
    } };
    const c1 = try store.put(allocator, c1_obj);

    const c2_parents = try allocator.dupe(Hash, &.{c1});
    defer allocator.free(c2_parents);
    const c2_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = c2_parents,
        .author = .{ .kind = .ed25519, .bytes = &zero_pk },
        .signer = .{0} ** 32,
        .message = "c2",
        .timestamp = 2,
        .signature = .{0} ** 64,
    } };
    const c2 = try store.put(allocator, c2_obj);

    const c3_parents = try allocator.dupe(Hash, &.{c2});
    defer allocator.free(c3_parents);
    const c3_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = c3_parents,
        .author = .{ .kind = .ed25519, .bytes = &zero_pk },
        .signer = .{0} ** 32,
        .message = "c3",
        .timestamp = 3,
        .signature = .{0} ** 64,
    } };
    const c3 = try store.put(allocator, c3_obj);

    var set = std.AutoHashMap(Hash, void).init(allocator);
    defer set.deinit();
    try collectAncestorSet(allocator, &store, c3, &set);

    try std.testing.expectEqual(@as(usize, 3), set.count());
    try std.testing.expect(set.contains(c1));
    try std.testing.expect(set.contains(c2));
    try std.testing.expect(set.contains(c3));
}

test "collectAncestorSet on diamond DAG" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // C1 (root) <- C2, C1 <- C3, C2+C3 <- C4 (diamond)
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    const c2 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c2");
    const c3 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c3");
    const c4 = try th.makeCommit(allocator, &store, tree, &.{ c2, c3 }, "c4");

    var set = std.AutoHashMap(Hash, void).init(allocator);
    defer set.deinit();
    try collectAncestorSet(allocator, &store, c4, &set);

    try std.testing.expectEqual(@as(usize, 4), set.count());
    try std.testing.expect(set.contains(c1));
    try std.testing.expect(set.contains(c2));
    try std.testing.expect(set.contains(c3));
    try std.testing.expect(set.contains(c4));
}

test "collectAncestorSet on root commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "root");

    var set = std.AutoHashMap(Hash, void).init(allocator);
    defer set.deinit();
    try collectAncestorSet(allocator, &store, c1, &set);

    try std.testing.expectEqual(@as(usize, 1), set.count());
    try std.testing.expect(set.contains(c1));
}

test "collectAncestorSet handles non-existent parent gracefully" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // Create a commit whose parent hash doesn't exist in store
    const fake_parent = hash_mod.hash("nonexistent-parent");
    const c1 = try th.makeCommit(allocator, &store, tree, &.{fake_parent}, "orphan");

    var set = std.AutoHashMap(Hash, void).init(allocator);
    defer set.deinit();
    try collectAncestorSet(allocator, &store, c1, &set);

    // Should contain c1 and the fake parent hash (added to set, but store.get fails -> continue)
    try std.testing.expect(set.contains(c1));
    try std.testing.expect(set.contains(fake_parent));
    try std.testing.expectEqual(@as(usize, 2), set.count());
}

test "collectAncestorSet on empty store" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Non-existent start hash
    const fake_hash = hash_mod.hash("does-not-exist");

    var set = std.AutoHashMap(Hash, void).init(allocator);
    defer set.deinit();
    try collectAncestorSet(allocator, &store, fake_hash, &set);

    // Should add the hash to set (getOrPut succeeds) but store.get fails -> continue
    try std.testing.expectEqual(@as(usize, 1), set.count());
    try std.testing.expect(set.contains(fake_hash));
}
