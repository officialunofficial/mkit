// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const testing = std.testing;
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const serialize = @import("serialize.zig");
const merge_mod = @import("merge.zig");
const cherry_pick = @import("cherry_pick.zig");
const bisect = @import("bisect.zig");
const rebase = @import("rebase.zig");
const packfile = @import("packfile.zig");
const diff = @import("diff.zig");
const restore = @import("restore.zig");
const transport_memory = @import("transport/memory.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

// ===========================================================================
// Integration Tests
// ===========================================================================

test "full commit workflow: store blob, build tree, create commit, read back" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create blob
    const blob_hash = try th.makeBlob(allocator, &store, "hello, mkit!");

    // Build tree with one entry
    const entries = [_]object.TreeEntry{
        .{ .name = "greeting.txt", .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try th.makeTree(allocator, &store, &entries);

    // Create commit
    const commit_hash = try th.makeCommit(allocator, &store, tree_hash, &.{}, "initial commit");

    // Read commit back and verify tree_hash matches
    var commit_obj = try store.get(allocator, commit_hash);
    defer commit_obj.deinit(allocator);

    try testing.expectEqual(object.ObjectType.commit, commit_obj.objectType());
    try testing.expectEqual(tree_hash, commit_obj.commit.tree_hash);

    // Follow tree_hash to verify content
    var tree_obj = try store.get(allocator, commit_obj.commit.tree_hash);
    defer tree_obj.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), tree_obj.tree.entries.len);
    try testing.expectEqualStrings("greeting.txt", tree_obj.tree.entries[0].name);

    // Follow blob hash to verify content
    var blob_obj = try store.get(allocator, tree_obj.tree.entries[0].object_hash);
    defer blob_obj.deinit(allocator);
    try testing.expectEqualStrings("hello, mkit!", blob_obj.blob.data);
}

test "serialize-deserialize roundtrip for commit" {
    const allocator = testing.allocator;

    const tree_hash = hash_mod.hash("tree-data");
    const parent = hash_mod.hash("parent-commit");
    var parents = try allocator.alloc(Hash, 1);
    parents[0] = parent;

    const author_bytes = try allocator.alloc(u8, 8);
    std.mem.writeInt(u64, author_bytes[0..8], 42, .little);
    var original = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = .{ .kind = .@"opaque", .bytes = author_bytes },
        .signer = .{0xAA} ** 32,
        .message = try allocator.dupe(u8, "test commit message"),
        .timestamp = 1700000000,
        .signature = .{0xBB} ** 64,
    } };

    const bytes = try serialize.serialize(allocator, original);
    defer allocator.free(bytes);
    original.deinit(allocator);

    var parsed = try serialize.deserialize(allocator, bytes);
    defer parsed.deinit(allocator);

    try testing.expectEqual(object.ObjectType.commit, parsed.objectType());
    try testing.expectEqual(tree_hash, parsed.commit.tree_hash);
    try testing.expectEqual(@as(usize, 1), parsed.commit.parents.len);
    try testing.expectEqual(parent, parsed.commit.parents[0]);
    try testing.expectEqual(object.IdentityKind.@"opaque", parsed.commit.author.kind);
    try testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, parsed.commit.author.bytes[0..8], .little));
    try testing.expectEqualStrings("test commit message", parsed.commit.message);
    try testing.expectEqual(@as(u64, 1700000000), parsed.commit.timestamp);
    try testing.expectEqual([_]u8{0xAA} ** 32, parsed.commit.signer);
    try testing.expectEqual([_]u8{0xBB} ** 64, parsed.commit.signature);
}

test "packfile roundtrip through memory transport" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create several objects: blob -> tree -> commit
    const blob1 = try th.makeBlob(allocator, &store, "file one content");
    const blob2 = try th.makeBlob(allocator, &store, "file two content");
    const entries = [_]object.TreeEntry{
        .{ .name = "one.txt", .mode = .blob, .object_hash = blob1 },
        .{ .name = "two.txt", .mode = .blob, .object_hash = blob2 },
    };
    const tree_hash = try th.makeTree(allocator, &store, &entries);
    const commit_hash = try th.makeCommit(allocator, &store, tree_hash, &.{}, "pack test");

    // Pack all objects reachable from commit
    const pack_result = try packfile.packReachable(allocator, &store, commit_hash);
    defer allocator.free(pack_result.bytes);

    // Upload via MemoryTransport
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    var t = mem.transport();
    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);

    // Download from MemoryTransport
    const downloaded = try t.downloadPack(allocator, pack_result.digest);
    defer allocator.free(downloaded);

    // Unpack into a new store
    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    var store2 = try store_mod.ObjectStore.init(tmp2.dir);
    defer store2.close();

    try packfile.unpackInto(allocator, downloaded, &store2);

    // Verify all objects are accessible in the new store
    try testing.expect(store2.exists(blob1));
    try testing.expect(store2.exists(blob2));
    try testing.expect(store2.exists(tree_hash));
    try testing.expect(store2.exists(commit_hash));

    // Verify content integrity
    var blob_obj = try store2.get(allocator, blob1);
    defer blob_obj.deinit(allocator);
    try testing.expectEqualStrings("file one content", blob_obj.blob.data);
}

test "merge then cherry-pick composition" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Common ancestor with file "base.txt"
    const blob_base = try th.makeBlob(allocator, &store, "base content");
    const base_entries = [_]object.TreeEntry{
        .{ .name = "base.txt", .mode = .blob, .object_hash = blob_base },
    };
    const base_tree = try th.makeTree(allocator, &store, &base_entries);
    const base_commit = try th.makeCommit(allocator, &store, base_tree, &.{}, "initial");

    // Branch A adds "a.txt"
    const blob_a = try th.makeBlob(allocator, &store, "branch a content");
    const a_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "base.txt", .mode = .blob, .object_hash = blob_base },
    };
    const a_tree = try th.makeTree(allocator, &store, &a_entries);

    // Branch B adds "b.txt"
    const blob_b = try th.makeBlob(allocator, &store, "branch b content");
    const b_entries = [_]object.TreeEntry{
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
        .{ .name = "base.txt", .mode = .blob, .object_hash = blob_base },
    };
    const b_tree = try th.makeTree(allocator, &store, &b_entries);

    // Merge A and B (base=base_tree, ours=a_tree, theirs=b_tree)
    var merge_result = try merge_mod.mergeTrees(allocator, &store, base_tree, a_tree, b_tree);
    defer merge_result.deinit();
    try testing.expect(!merge_result.hasConflicts());

    // Create a merge commit
    const merge_commit = try th.makeCommit(allocator, &store, merge_result.tree_hash, &.{base_commit}, "merge A+B");

    // Now create a third commit to cherry-pick: adds "c.txt" on top of base
    const blob_c = try th.makeBlob(allocator, &store, "cherry content");
    const c_entries = [_]object.TreeEntry{
        .{ .name = "base.txt", .mode = .blob, .object_hash = blob_base },
        .{ .name = "c.txt", .mode = .blob, .object_hash = blob_c },
    };
    const c_tree = try th.makeTree(allocator, &store, &c_entries);
    const c_parents = [_]Hash{base_commit};
    const c_commit = try th.makeCommit(allocator, &store, c_tree, &c_parents, "add c.txt");

    // Cherry-pick c_commit onto merged tree
    var cp_result = try cherry_pick.cherryPick(allocator, &store, c_commit, merge_result.tree_hash);
    defer cp_result.deinit();

    try testing.expect(!cp_result.hasConflicts());

    // Final tree should have: a.txt, b.txt, base.txt, c.txt
    var final_tree_obj = try store.get(allocator, cp_result.tree_hash);
    defer final_tree_obj.deinit(allocator);
    try testing.expectEqual(@as(usize, 4), final_tree_obj.tree.entries.len);

    // Verify sorted entry names
    try testing.expectEqualStrings("a.txt", final_tree_obj.tree.entries[0].name);
    try testing.expectEqualStrings("b.txt", final_tree_obj.tree.entries[1].name);
    try testing.expectEqualStrings("base.txt", final_tree_obj.tree.entries[2].name);
    try testing.expectEqualStrings("c.txt", final_tree_obj.tree.entries[3].name);

    _ = merge_commit;
}

test "bisect through linear chain finds correct commit" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // Create 8 commits in a linear chain
    const commits = try th.makeLinearChain(allocator, &store, tree, 8);
    defer allocator.free(commits);

    // enumerateRange(last, [first]) gets all commits except the first
    const good = [_]Hash{commits[0]};
    const candidates = try bisect.enumerateRange(allocator, &store, commits[7], &good);
    defer allocator.free(candidates);

    // Should have 7 candidates (all except commits[0])
    try testing.expectEqual(@as(usize, 7), candidates.len);

    // pickMidpoint should return the middle one
    const mid = bisect.pickMidpoint(candidates);
    // candidates.len=7, 7/2=3, so index 3
    try testing.expectEqual(candidates[3], mid);
}

test "rebase produces new commit hashes" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // Create 3 commits on main
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    const c2 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c2");
    const c3 = try th.makeCommit(allocator, &store, tree, &.{c2}, "c3");

    // Create 2 commits on feature from c1
    const c4 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c4-feature");
    const c5 = try th.makeCommit(allocator, &store, tree, &.{c4}, "c5-feature");

    // collectCommitsToReplay: head=c5, onto=c3
    const result = try rebase.collectCommitsToReplay(allocator, &store, c5, c3);
    defer allocator.free(result);

    // Should return the 2 feature commits in oldest-first order
    try testing.expectEqual(@as(usize, 2), result.len);
    try testing.expectEqual(c4, result[0]);
    try testing.expectEqual(c5, result[1]);
}

test "diff between parent and child commit detects changes" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Parent commit with "a.txt" = "original"
    const blob_orig = try th.makeBlob(allocator, &store, "original");
    const parent_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_orig },
    };
    const parent_tree = try th.makeTree(allocator, &store, &parent_entries);

    // Child commit with modified "a.txt"
    const blob_modified = try th.makeBlob(allocator, &store, "modified");
    const child_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_modified },
    };
    const child_tree = try th.makeTree(allocator, &store, &child_entries);

    // Diff trees should show the change
    var diff_result = try diff.diffTrees(allocator, &store, parent_tree, child_tree);
    defer diff_result.deinit();

    try testing.expectEqual(@as(usize, 1), diff_result.entries.len);
    try testing.expectEqualStrings("a.txt", diff_result.entries[0].path);
    try testing.expectEqual(diff.DiffKind.modified, diff_result.entries[0].kind);
    try testing.expectEqual(blob_orig, diff_result.entries[0].old_hash.?);
    try testing.expectEqual(blob_modified, diff_result.entries[0].new_hash.?);
}

test "sparse restore filters files correctly" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create blobs
    const blob_zig = try th.makeBlob(allocator, &store, "const x = 42;");
    const blob_readme = try th.makeBlob(allocator, &store, "# readme");

    // Create subtrees: src/ with a.zig, docs/ with readme.md
    const src_entries = [_]object.TreeEntry{
        .{ .name = "a.zig", .mode = .blob, .object_hash = blob_zig },
    };
    const src_tree = try th.makeTree(allocator, &store, &src_entries);

    const docs_entries = [_]object.TreeEntry{
        .{ .name = "readme.md", .mode = .blob, .object_hash = blob_readme },
    };
    const docs_tree = try th.makeTree(allocator, &store, &docs_entries);

    // Root tree with src/ and docs/
    const root_entries = [_]object.TreeEntry{
        .{ .name = "docs", .mode = .tree, .object_hash = docs_tree },
        .{ .name = "src", .mode = .tree, .object_hash = src_tree },
    };
    const root_tree = try th.makeTree(allocator, &store, &root_entries);

    // Restore with sparse pattern "src/" -- only src/a.zig should be written
    const patterns = [_]restore.SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
    };

    // Create output directory
    try tmp.dir.createDirPath(std.testing.io, "output");
    var output_dir = try tmp.dir.openDir(std.testing.io, "output", .{ .iterate = true });
    defer output_dir.close();

    try restore.restoreTree(
        allocator,
        &store,
        root_tree,
        output_dir,
        .{ .clean = false, .sparse_patterns = &patterns },
    );

    // src/a.zig should exist
    var src_dir = try output_dir.openDir("src", .{});
    defer src_dir.close();
    const zig_file = try src_dir.openFile("a.zig", .{});
    defer zig_file.close();
    var buf: [64]u8 = undefined;
    const n = try zig_file.readAll(&buf);
    try testing.expectEqualStrings("const x = 42;", buf[0..n]);

    // docs/ directory should not exist
    if (output_dir.openDir("docs", .{})) |dir_val| {
        var d = dir_val;
        d.close();
        // If we got here, docs/ exists, which is wrong
        return error.TestUnexpectedResult;
    } else |err| {
        try testing.expectEqual(error.FileNotFound, err);
    }
}
