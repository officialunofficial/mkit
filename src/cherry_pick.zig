// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const merge_mod = @import("merge.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const CherryPickResult = struct {
    tree_hash: Hash,
    conflicts: []merge_mod.Conflict,
    original_message: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *CherryPickResult) void {
        self.allocator.free(self.original_message);
        for (self.conflicts) |c| {
            self.allocator.free(c.path);
        }
        if (self.conflicts.len > 0) {
            self.allocator.free(self.conflicts);
        }
    }

    pub fn hasConflicts(self: CherryPickResult) bool {
        return self.conflicts.len > 0;
    }
};

/// Cherry-pick a single commit onto the current tree using 3-way merge.
///
/// Algorithm:
/// 1. Load target commit, get its first parent hash (or null if root commit)
/// 2. Get parent's tree_hash (base) and target's tree_hash (theirs)
/// 3. Call mergeTrees(parent_tree, ours_tree, target_tree)
/// 4. Return result with merged tree hash + conflicts + original message
pub fn cherryPick(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    target_hash: Hash,
    ours_tree: Hash,
) !CherryPickResult {
    // Load the target commit
    var target_obj = try store.get(allocator, target_hash);
    defer target_obj.deinit(allocator);

    if (target_obj != .commit) return error.NotACommit;

    const target_commit = target_obj.commit;

    // Get parent's tree hash. If root commit (no parents), use null (empty tree).
    var parent_tree: ?Hash = null;
    if (target_commit.parents.len > 0) {
        var parent_obj = try store.get(allocator, target_commit.parents[0]);
        defer parent_obj.deinit(allocator);
        if (parent_obj != .commit) return error.NotACommit;
        parent_tree = parent_obj.commit.tree_hash;
    }

    // Dupe the message before we lose the reference (target_obj is deferred deinit)
    const original_message = try allocator.dupe(u8, target_commit.message);
    errdefer allocator.free(original_message);

    // 3-way merge: base=parent_tree, ours=ours_tree, theirs=target_tree
    var merge_result = try merge_mod.mergeTrees(
        allocator,
        store,
        parent_tree,
        ours_tree,
        target_commit.tree_hash,
    );
    // Take ownership of merge_result's conflicts; prevent merge deinit from freeing them.
    const tree_hash = merge_result.tree_hash;
    const conflicts = merge_result.conflicts;
    merge_result.conflicts = @constCast(&[_]merge_mod.Conflict{});
    merge_result.deinit();

    return CherryPickResult{
        .tree_hash = tree_hash,
        .conflicts = conflicts,
        .original_message = original_message,
        .allocator = allocator,
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "cherry-pick adds a file onto branch missing it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Base: one file "a.txt"
    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_tree = try th.makeTree(allocator, &store, &base_entries);
    const base_commit = try th.makeCommit(allocator, &store, base_tree, &.{}, "initial");

    // Target commit: adds "b.txt" on top of base
    const blob_b = try th.makeBlob(allocator, &store, "bbb");
    const target_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const target_tree = try th.makeTree(allocator, &store, &target_entries);
    const target_parents = [_]Hash{base_commit};
    const target_commit = try th.makeCommit(allocator, &store, target_tree, &target_parents, "add b.txt");

    // Our branch: same as base (only a.txt)
    // Cherry-pick target onto our tree
    var result = try cherryPick(allocator, &store, target_commit, base_tree);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqualStrings("add b.txt", result.original_message);

    // Verify merged tree has both a.txt and b.txt
    var merged_obj = try store.get(allocator, result.tree_hash);
    defer merged_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), merged_obj.tree.entries.len);

    // Check entries
    var found_a = false;
    var found_b = false;
    for (merged_obj.tree.entries) |entry| {
        if (std.mem.eql(u8, entry.name, "a.txt")) {
            try std.testing.expectEqual(blob_a, entry.object_hash);
            found_a = true;
        } else if (std.mem.eql(u8, entry.name, "b.txt")) {
            try std.testing.expectEqual(blob_b, entry.object_hash);
            found_b = true;
        }
    }
    try std.testing.expect(found_a);
    try std.testing.expect(found_b);
}

test "cherry-pick with modify-modify conflict" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Base: "a.txt" with content "original"
    const blob_orig = try th.makeBlob(allocator, &store, "original");
    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_orig },
    };
    const base_tree = try th.makeTree(allocator, &store, &base_entries);
    const base_commit = try th.makeCommit(allocator, &store, base_tree, &.{}, "initial");

    // Target commit: modifies "a.txt" to "theirs-change"
    const blob_theirs = try th.makeBlob(allocator, &store, "theirs-change");
    const target_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_theirs },
    };
    const target_tree = try th.makeTree(allocator, &store, &target_entries);
    const target_parents = [_]Hash{base_commit};
    const target_commit = try th.makeCommit(allocator, &store, target_tree, &target_parents, "change a.txt");

    // Our branch: also modified "a.txt" to "ours-change"
    const blob_ours = try th.makeBlob(allocator, &store, "ours-change");
    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_ours },
    };
    const ours_tree = try th.makeTree(allocator, &store, &ours_entries);

    // Cherry-pick: should produce a conflict
    var result = try cherryPick(allocator, &store, target_commit, ours_tree);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    try std.testing.expectEqualStrings("a.txt", result.conflicts[0].path);
    try std.testing.expectEqual(merge_mod.ConflictKind.modify_modify, result.conflicts[0].kind);
    try std.testing.expectEqualStrings("change a.txt", result.original_message);
}

test "cherry-pick a root commit (no parent)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Root commit with "a.txt"
    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const root_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const root_tree = try th.makeTree(allocator, &store, &root_entries);
    const root_commit = try th.makeCommit(allocator, &store, root_tree, &.{}, "root commit");

    // Our tree has "b.txt" only
    const blob_b = try th.makeBlob(allocator, &store, "bbb");
    const ours_entries = [_]object.TreeEntry{
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const ours_tree = try th.makeTree(allocator, &store, &ours_entries);

    // Cherry-pick root commit (no parent -> null base tree)
    // merge(null, ours_tree, root_tree) => should add a.txt from root, keep b.txt from ours
    var result = try cherryPick(allocator, &store, root_commit, ours_tree);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqualStrings("root commit", result.original_message);

    // Verify merged tree has both files
    var merged_obj = try store.get(allocator, result.tree_hash);
    defer merged_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), merged_obj.tree.entries.len);
}

test "cherry-pick with delete-modify conflict" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Base: file "a.txt"
    const blob_a = try th.makeBlob(allocator, &store, "original");
    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_tree = try th.makeTree(allocator, &store, &base_entries);
    const base_commit = try th.makeCommit(allocator, &store, base_tree, &.{}, "initial");

    // Target commit: removes "a.txt" (empty tree)
    const target_tree = try th.makeTree(allocator, &store, &.{});
    const target_parents = [_]Hash{base_commit};
    const target_commit = try th.makeCommit(allocator, &store, target_tree, &target_parents, "remove a.txt");

    // Ours: modified "a.txt"
    const blob_modified = try th.makeBlob(allocator, &store, "modified content");
    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_modified },
    };
    const ours_tree = try th.makeTree(allocator, &store, &ours_entries);

    // Cherry-pick: should produce a delete_modify conflict
    var result = try cherryPick(allocator, &store, target_commit, ours_tree);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    try std.testing.expectEqualStrings("a.txt", result.conflicts[0].path);
    try std.testing.expectEqual(merge_mod.ConflictKind.delete_modify, result.conflicts[0].kind);
}

test "cherry-pick adds multiple files" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Base: single file
    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_tree = try th.makeTree(allocator, &store, &base_entries);
    const base_commit = try th.makeCommit(allocator, &store, base_tree, &.{}, "initial");

    // Target commit adds 3 files on top of base
    const blob_b = try th.makeBlob(allocator, &store, "bbb");
    const blob_c = try th.makeBlob(allocator, &store, "ccc");
    const blob_d = try th.makeBlob(allocator, &store, "ddd");
    const target_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
        .{ .name = "c.txt", .mode = .blob, .object_hash = blob_c },
        .{ .name = "d.txt", .mode = .blob, .object_hash = blob_d },
    };
    const target_tree = try th.makeTree(allocator, &store, &target_entries);
    const target_parents = [_]Hash{base_commit};
    const target_commit = try th.makeCommit(allocator, &store, target_tree, &target_parents, "add b, c, d");

    // Ours is same as base
    var result = try cherryPick(allocator, &store, target_commit, base_tree);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());

    // Verify merged tree has all 4 files
    var merged_obj = try store.get(allocator, result.tree_hash);
    defer merged_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), merged_obj.tree.entries.len);
}

test "cherry-pick non-commit returns error" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Store a blob and try to cherry-pick it
    const blob_hash = try th.makeBlob(allocator, &store, "just a blob");
    const empty_tree = try th.makeTree(allocator, &store, &.{});

    try std.testing.expectError(error.NotACommit, cherryPick(allocator, &store, blob_hash, empty_tree));
}

test "cherry-pick root commit with empty ours" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Root commit with "a.txt" and "b.txt"
    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");
    const root_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const root_tree = try th.makeTree(allocator, &store, &root_entries);
    const root_commit = try th.makeCommit(allocator, &store, root_tree, &.{}, "root");

    // Ours is empty tree
    const empty_tree = try th.makeTree(allocator, &store, &.{});

    // Cherry-pick root onto empty: merge(null, empty, root_tree)
    // Both base and ours are empty, theirs has files -> should add them
    var result = try cherryPick(allocator, &store, root_commit, empty_tree);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());

    // Result should have the target's tree content
    var merged_obj = try store.get(allocator, result.tree_hash);
    defer merged_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), merged_obj.tree.entries.len);
}
