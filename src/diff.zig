// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const worktree = @import("worktree.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const DiffKind = enum {
    added,
    removed,
    modified,
    mode_changed,
};

pub const DiffEntry = struct {
    path: []const u8,
    kind: DiffKind,
    old_hash: ?Hash,
    new_hash: ?Hash,
};

pub const DiffResult = struct {
    entries: []DiffEntry,
    allocator: Allocator,

    pub fn deinit(self: *DiffResult) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.path);
        }
        if (self.entries.len > 0) {
            self.allocator.free(self.entries);
        }
    }
};

/// Compare working directory against a stored tree (for `mkit status`).
/// Builds a temporary tree from work_dir and diffs against head_tree_hash.
pub fn statusDiff(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    head_tree_hash: ?Hash,
    work_dir: std.fs.Dir,
) !DiffResult {
    const work_tree_hash = try worktree.buildTree(allocator, store, work_dir);
    return diffTrees(allocator, store, head_tree_hash, work_tree_hash);
}

/// Compare two trees and return differences.
/// null hash means empty tree (for comparing against nothing).
pub fn diffTrees(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    old_hash: ?Hash,
    new_hash: ?Hash,
) !DiffResult {
    if (old_hash == null and new_hash == null) {
        return .{ .entries = &.{}, .allocator = allocator };
    }
    if (old_hash != null and new_hash != null and std.mem.eql(u8, &old_hash.?, &new_hash.?)) {
        return .{ .entries = &.{}, .allocator = allocator };
    }

    var old_obj: ?object.Object = null;
    defer if (old_obj) |*o| o.deinit(allocator);
    var new_obj: ?object.Object = null;
    defer if (new_obj) |*o| o.deinit(allocator);

    const old_entries: []const object.TreeEntry = if (old_hash) |h| blk: {
        old_obj = try store.get(allocator, h);
        break :blk old_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    const new_entries: []const object.TreeEntry = if (new_hash) |h| blk: {
        new_obj = try store.get(allocator, h);
        break :blk new_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    var result: std.ArrayList(DiffEntry) = .empty;
    errdefer {
        for (result.items) |entry| {
            allocator.free(entry.path);
        }
        result.deinit(allocator);
    }

    try diffEntriesRecursive(allocator, store, old_entries, new_entries, "", &result);

    return .{ .entries = try result.toOwnedSlice(allocator), .allocator = allocator };
}

/// Recursive lockstep merge of two sorted entry lists.
fn diffEntriesRecursive(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    old_entries: []const object.TreeEntry,
    new_entries: []const object.TreeEntry,
    prefix: []const u8,
    result: *std.ArrayList(DiffEntry),
) !void {
    var i: usize = 0;
    var j: usize = 0;

    while (i < old_entries.len and j < new_entries.len) {
        const old_entry = old_entries[i];
        const new_entry = new_entries[j];
        const order = std.mem.order(u8, old_entry.name, new_entry.name);

        switch (order) {
            .lt => {
                // Entry only in old tree -> removed
                try addRemovedEntries(allocator, store, old_entry, prefix, result);
                i += 1;
            },
            .gt => {
                // Entry only in new tree -> added
                try addAddedEntries(allocator, store, new_entry, prefix, result);
                j += 1;
            },
            .eq => {
                // Same name in both trees
                if (old_entry.mode == .tree and new_entry.mode == .tree) {
                    // Both are subtrees -> recurse
                    if (!std.mem.eql(u8, &old_entry.object_hash, &new_entry.object_hash)) {
                        const sub_prefix = try joinPath(allocator, prefix, old_entry.name);
                        defer allocator.free(sub_prefix);

                        var old_sub = try store.get(allocator, old_entry.object_hash);
                        defer old_sub.deinit(allocator);
                        var new_sub = try store.get(allocator, new_entry.object_hash);
                        defer new_sub.deinit(allocator);

                        try diffEntriesRecursive(
                            allocator,
                            store,
                            old_sub.tree.entries,
                            new_sub.tree.entries,
                            sub_prefix,
                            result,
                        );
                    }
                    // If hashes are equal, subtrees are identical — skip
                } else if (old_entry.mode != new_entry.mode and
                    std.mem.eql(u8, &old_entry.object_hash, &new_entry.object_hash))
                {
                    // Same hash, different mode -> mode_changed
                    const path = try joinPath(allocator, prefix, old_entry.name);
                    try result.append(allocator, .{
                        .path = path,
                        .kind = .mode_changed,
                        .old_hash = old_entry.object_hash,
                        .new_hash = new_entry.object_hash,
                    });
                } else if (!std.mem.eql(u8, &old_entry.object_hash, &new_entry.object_hash) or
                    old_entry.mode != new_entry.mode)
                {
                    // Different hash (and/or different mode with different hash) -> modified
                    const path = try joinPath(allocator, prefix, old_entry.name);
                    try result.append(allocator, .{
                        .path = path,
                        .kind = .modified,
                        .old_hash = old_entry.object_hash,
                        .new_hash = new_entry.object_hash,
                    });
                }
                // Otherwise identical — skip
                i += 1;
                j += 1;
            },
        }
    }

    // Remaining old entries are removed
    while (i < old_entries.len) : (i += 1) {
        try addRemovedEntries(allocator, store, old_entries[i], prefix, result);
    }

    // Remaining new entries are added
    while (j < new_entries.len) : (j += 1) {
        try addAddedEntries(allocator, store, new_entries[j], prefix, result);
    }
}

/// For a removed entry: if it's a tree, recursively add all contained files as removed.
fn addRemovedEntries(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    entry: object.TreeEntry,
    prefix: []const u8,
    result: *std.ArrayList(DiffEntry),
) !void {
    if (entry.mode == .tree) {
        const sub_prefix = try joinPath(allocator, prefix, entry.name);
        defer allocator.free(sub_prefix);

        var sub_obj = try store.get(allocator, entry.object_hash);
        defer sub_obj.deinit(allocator);

        for (sub_obj.tree.entries) |sub_entry| {
            try addRemovedEntries(allocator, store, sub_entry, sub_prefix, result);
        }
    } else {
        const path = try joinPath(allocator, prefix, entry.name);
        try result.append(allocator, .{
            .path = path,
            .kind = .removed,
            .old_hash = entry.object_hash,
            .new_hash = null,
        });
    }
}

/// For an added entry: if it's a tree, recursively add all contained files as added.
fn addAddedEntries(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    entry: object.TreeEntry,
    prefix: []const u8,
    result: *std.ArrayList(DiffEntry),
) !void {
    if (entry.mode == .tree) {
        const sub_prefix = try joinPath(allocator, prefix, entry.name);
        defer allocator.free(sub_prefix);

        var sub_obj = try store.get(allocator, entry.object_hash);
        defer sub_obj.deinit(allocator);

        for (sub_obj.tree.entries) |sub_entry| {
            try addAddedEntries(allocator, store, sub_entry, sub_prefix, result);
        }
    } else {
        const path = try joinPath(allocator, prefix, entry.name);
        try result.append(allocator, .{
            .path = path,
            .kind = .added,
            .old_hash = null,
            .new_hash = entry.object_hash,
        });
    }
}

const joinPath = hash_mod.joinPath;

// ---------------------------------------------------------------------------
// Helper: create a tree object in the store from a slice of entries.
// The entries slice is NOT owned by this function — caller keeps ownership.
// ---------------------------------------------------------------------------
fn putTree(allocator: Allocator, store: *store_mod.ObjectStore, entries: []const object.TreeEntry) !Hash {
    // We need to dupe entries for serialize because Object.tree expects mutable slice
    const tree_obj = object.Object{ .tree = .{ .entries = @constCast(entries) } };
    return store.put(allocator, tree_obj);
}

fn putBlob(allocator: Allocator, store: *store_mod.ObjectStore, data: []const u8) !Hash {
    const blob_obj = object.Object{ .blob = .{ .data = data } };
    return store.put(allocator, blob_obj);
}

// ===========================================================================
// Tests
// ===========================================================================

test "identical trees no diff" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create a blob
    const blob_hash = try putBlob(allocator, &store, "content");

    // Build the same tree twice
    const entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try putTree(allocator, &store, &entries);

    var result = try diffTrees(allocator, &store, tree_hash, tree_hash);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.entries.len);
}

test "added file detected" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_a = try putBlob(allocator, &store, "aaa");
    const blob_b = try putBlob(allocator, &store, "bbb");

    // Old tree: {a.txt}
    const old_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const old_hash = try putTree(allocator, &store, &old_entries);

    // New tree: {a.txt, b.txt}
    const new_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, old_hash, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("b.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[0].kind);
    try std.testing.expectEqual(@as(?Hash, null), result.entries[0].old_hash);
    try std.testing.expectEqual(@as(?Hash, blob_b), result.entries[0].new_hash);
}

test "removed file detected" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_a = try putBlob(allocator, &store, "aaa");
    const blob_b = try putBlob(allocator, &store, "bbb");

    // Old tree: {a.txt, b.txt}
    const old_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const old_hash = try putTree(allocator, &store, &old_entries);

    // New tree: {a.txt}
    const new_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, old_hash, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("b.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.removed, result.entries[0].kind);
    try std.testing.expectEqual(@as(?Hash, blob_b), result.entries[0].old_hash);
    try std.testing.expectEqual(@as(?Hash, null), result.entries[0].new_hash);
}

test "modified file detected" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_v1 = try putBlob(allocator, &store, "version 1");
    const blob_v2 = try putBlob(allocator, &store, "version 2");

    const old_entries = [_]object.TreeEntry{
        .{ .name = "file.txt", .mode = .blob, .object_hash = blob_v1 },
    };
    const old_hash = try putTree(allocator, &store, &old_entries);

    const new_entries = [_]object.TreeEntry{
        .{ .name = "file.txt", .mode = .blob, .object_hash = blob_v2 },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, old_hash, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("file.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.modified, result.entries[0].kind);
    try std.testing.expectEqual(@as(?Hash, blob_v1), result.entries[0].old_hash);
    try std.testing.expectEqual(@as(?Hash, blob_v2), result.entries[0].new_hash);
}

test "mode change detected" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Same content, different mode (blob vs symlink)
    const blob_hash = try putBlob(allocator, &store, "content");

    const old_entries = [_]object.TreeEntry{
        .{ .name = "link", .mode = .blob, .object_hash = blob_hash },
    };
    const old_hash = try putTree(allocator, &store, &old_entries);

    const new_entries = [_]object.TreeEntry{
        .{ .name = "link", .mode = .symlink, .object_hash = blob_hash },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, old_hash, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("link", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.mode_changed, result.entries[0].kind);
    try std.testing.expectEqual(@as(?Hash, blob_hash), result.entries[0].old_hash);
    try std.testing.expectEqual(@as(?Hash, blob_hash), result.entries[0].new_hash);
}

test "nested tree diff" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_v1 = try putBlob(allocator, &store, "old content");
    const blob_v2 = try putBlob(allocator, &store, "new content");
    const blob_other = try putBlob(allocator, &store, "unchanged");

    // Old subtree: {file.txt=v1, other.txt=unchanged}
    const old_sub_entries = [_]object.TreeEntry{
        .{ .name = "file.txt", .mode = .blob, .object_hash = blob_v1 },
        .{ .name = "other.txt", .mode = .blob, .object_hash = blob_other },
    };
    const old_sub_hash = try putTree(allocator, &store, &old_sub_entries);

    // New subtree: {file.txt=v2, other.txt=unchanged}
    const new_sub_entries = [_]object.TreeEntry{
        .{ .name = "file.txt", .mode = .blob, .object_hash = blob_v2 },
        .{ .name = "other.txt", .mode = .blob, .object_hash = blob_other },
    };
    const new_sub_hash = try putTree(allocator, &store, &new_sub_entries);

    // Root trees with subdir
    const old_root_entries = [_]object.TreeEntry{
        .{ .name = "subdir", .mode = .tree, .object_hash = old_sub_hash },
    };
    const old_root = try putTree(allocator, &store, &old_root_entries);

    const new_root_entries = [_]object.TreeEntry{
        .{ .name = "subdir", .mode = .tree, .object_hash = new_sub_hash },
    };
    const new_root = try putTree(allocator, &store, &new_root_entries);

    var result = try diffTrees(allocator, &store, old_root, new_root);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("subdir/file.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.modified, result.entries[0].kind);
}

test "diff against empty tree" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_a = try putBlob(allocator, &store, "aaa");
    const blob_b = try putBlob(allocator, &store, "bbb");

    const new_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, null, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    // Sorted alphabetically
    try std.testing.expectEqualStrings("a.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[0].kind);
    try std.testing.expectEqualStrings("b.txt", result.entries[1].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[1].kind);
}

test "empty tree against non-empty" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_a = try putBlob(allocator, &store, "aaa");
    const blob_b = try putBlob(allocator, &store, "bbb");

    const old_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const old_hash = try putTree(allocator, &store, &old_entries);

    var result = try diffTrees(allocator, &store, old_hash, null);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    try std.testing.expectEqualStrings("a.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.removed, result.entries[0].kind);
    try std.testing.expectEqualStrings("b.txt", result.entries[1].path);
    try std.testing.expectEqual(DiffKind.removed, result.entries[1].kind);
}

test "sorted output" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_a = try putBlob(allocator, &store, "a");
    const blob_b = try putBlob(allocator, &store, "b");
    const blob_c = try putBlob(allocator, &store, "c");

    // Old tree empty, new tree has {z.txt, a.txt, m.txt} — entries sorted in tree already
    const new_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "m.txt", .mode = .blob, .object_hash = blob_b },
        .{ .name = "z.txt", .mode = .blob, .object_hash = blob_c },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, null, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.entries.len);
    try std.testing.expectEqualStrings("a.txt", result.entries[0].path);
    try std.testing.expectEqualStrings("m.txt", result.entries[1].path);
    try std.testing.expectEqualStrings("z.txt", result.entries[2].path);
}

test "max-length entry names" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const blob_hash = try putBlob(allocator, &store, "data");

    // 255-byte file name (max typical filesystem name length)
    const long_name = "A" ** 255;

    const new_entries = [_]object.TreeEntry{
        .{ .name = long_name, .mode = .blob, .object_hash = blob_hash },
    };
    const new_hash = try putTree(allocator, &store, &new_entries);

    var result = try diffTrees(allocator, &store, null, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqual(@as(usize, 255), result.entries[0].path.len);
    try std.testing.expectEqualStrings(long_name, result.entries[0].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[0].kind);
}

// ===========================================================================
// statusDiff tests
// ===========================================================================

test "status shows added file" {
    const allocator = std.testing.allocator;

    // Create object store in a separate temp dir
    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with {a.txt}; build a tree from it as the "old" HEAD tree
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("hello");
    f1.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    const old_tree_hash = try worktree.buildTree(allocator, &store, d1);

    // Now add b.txt to workdir
    const f2 = try work_tmp.dir.createFile("b.txt", .{});
    try f2.writeAll("world");
    f2.close();

    // statusDiff: old tree vs current workdir (which now has a.txt + b.txt)
    var d2 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d2.close();
    var result = try statusDiff(allocator, &store, old_tree_hash, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("b.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[0].kind);
}

test "status shows removed file" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with {a.txt, b.txt}; build old tree
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("hello");
    f1.close();
    const f2 = try work_tmp.dir.createFile("b.txt", .{});
    try f2.writeAll("world");
    f2.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    const old_tree_hash = try worktree.buildTree(allocator, &store, d1);

    // Remove b.txt from workdir
    try work_tmp.dir.deleteFile("b.txt");

    // statusDiff: old tree (a.txt + b.txt) vs current workdir (only a.txt)
    var d2 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d2.close();
    var result = try statusDiff(allocator, &store, old_tree_hash, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("b.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.removed, result.entries[0].kind);
}

test "status shows modified file" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with {a.txt content="old"}; build old tree
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("old");
    f1.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    const old_tree_hash = try worktree.buildTree(allocator, &store, d1);

    // Modify a.txt to "new"
    const f2 = try work_tmp.dir.createFile("a.txt", .{});
    try f2.writeAll("new");
    f2.close();

    // statusDiff: old tree vs current workdir
    var d2 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d2.close();
    var result = try statusDiff(allocator, &store, old_tree_hash, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("a.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.modified, result.entries[0].kind);
}

test "status clean working directory" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with {a.txt}; build old tree
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("content");
    f1.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    const old_tree_hash = try worktree.buildTree(allocator, &store, d1);

    // Don't change anything — statusDiff should show 0 entries
    var d2 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d2.close();
    var result = try statusDiff(allocator, &store, old_tree_hash, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.entries.len);
}

test "status no commits" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with some files, head_tree_hash = null (no commits yet)
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("aaa");
    f1.close();
    const f2 = try work_tmp.dir.createFile("b.txt", .{});
    try f2.writeAll("bbb");
    f2.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    var result = try statusDiff(allocator, &store, null, d1);
    defer result.deinit();

    // All files should appear as added
    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    try std.testing.expectEqualStrings("a.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[0].kind);
    try std.testing.expectEqualStrings("b.txt", result.entries[1].path);
    try std.testing.expectEqual(DiffKind.added, result.entries[1].kind);
}

test "status nested changes" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create workdir with {src/a.txt}; build old tree
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    try work_tmp.dir.makeDir("src");
    const f1 = try work_tmp.dir.createFile("src/a.txt", .{});
    try f1.writeAll("original");
    f1.close();

    var d1 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d1.close();
    const old_tree_hash = try worktree.buildTree(allocator, &store, d1);

    // Modify src/a.txt
    const f2 = try work_tmp.dir.createFile("src/a.txt", .{});
    try f2.writeAll("modified");
    f2.close();

    // statusDiff should show src/a.txt as modified
    var d2 = try work_tmp.dir.openDir(".", .{ .iterate = true });
    defer d2.close();
    var result = try statusDiff(allocator, &store, old_tree_hash, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.entries.len);
    try std.testing.expectEqualStrings("src/a.txt", result.entries[0].path);
    try std.testing.expectEqual(DiffKind.modified, result.entries[0].kind);
}
