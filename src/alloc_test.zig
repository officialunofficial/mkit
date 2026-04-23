// SPDX-License-Identifier: MIT OR Apache-2.0
// Allocator stress tests proving every module is leak-free.
//
// Every test uses `std.testing.allocator` (a DebugAllocator that fails the test
// if any allocation is not freed). Exercising the full alloc-use-deinit lifecycle
// therefore proves no leaks, double-frees, or use-after-free for each module.

const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const serialize = @import("serialize.zig");
const store_mod = @import("store.zig");
const sign = @import("sign.zig");
const worktree = @import("worktree.zig");
const refs = @import("refs.zig");
const diff_mod = @import("diff.zig");
const merge_mod = @import("merge.zig");
const packfile = @import("packfile.zig");
const restore_mod = @import("restore.zig");
const config_mod = @import("config.zig");
const ignore_mod = @import("ignore.zig");
const format_mod = @import("format.zig");

const Hash = hash_mod.Hash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a signed commit object in the store. Returns commit hash.
/// Caller does NOT own any returned memory (all stored internally).
fn createCommit(
    allocator: std.mem.Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    parents: []const Hash,
    message: []const u8,
    kp: sign.KeyPair,
) !Hash {
    const parents_dupe = try allocator.dupe(Hash, parents);
    const msg_dupe = try allocator.dupe(u8, message);
    const author_bytes = try allocator.alloc(u8, 8);
    std.mem.writeInt(u64, author_bytes[0..8], 42, .little);

    var commit = object.Commit{
        .tree_hash = tree_hash,
        .parents = parents_dupe,
        .author = .{ .kind = .@"opaque", .bytes = author_bytes },
        .signer = kp.public_key,
        .message = msg_dupe,
        .timestamp = 1711300000,
        .message_hash = hash_mod.hash(message),
        .content_digest = hash_mod.zero,
        .signature = .{0} ** 64,
    };
    commit.signature = try sign.signCommit(allocator, commit, kp);

    var commit_obj = object.Object{ .commit = commit };
    const h = try store.put(allocator, commit_obj);
    commit_obj.deinit(allocator);
    return h;
}

/// Store a blob and return its hash.
fn storeBlob(allocator: std.mem.Allocator, store: *store_mod.ObjectStore, data: []const u8) !Hash {
    return store.put(allocator, object.Object{ .blob = .{ .data = data } });
}

/// Create and store a tree with the given entries spec. Returns tree hash.
fn storeTree(allocator: std.mem.Allocator, store: *store_mod.ObjectStore, specs: []const struct { name: []const u8, mode: object.EntryMode, hash: Hash }) !Hash {
    var entries = try allocator.alloc(object.TreeEntry, specs.len);
    for (specs, 0..) |s, i| {
        entries[i] = .{
            .name = try allocator.dupe(u8, s.name),
            .mode = s.mode,
            .object_hash = s.hash,
        };
    }
    var tree_obj = object.Object{ .tree = .{ .entries = entries } };
    const h = try store.put(allocator, tree_obj);
    tree_obj.deinit(allocator);
    return h;
}

// ===========================================================================
// 1. Full commit workflow: init -> buildTree -> sign -> store -> updateHead
// ===========================================================================

test "commit workflow no leaks" {
    const allocator = std.testing.allocator;

    // Separate temp dirs for store and working directory
    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    // Init refs
    try work_tmp.dir.createDirPath(std.testing.io, ".mkit");
    try refs.init(work_tmp.dir);

    // Create some files
    const f1 = try work_tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f1.writeStreamingAll(std.testing.io, "hello world");
    f1.close(std.testing.io);

    try work_tmp.dir.createDirPath(std.testing.io, "src");
    const f2 = try work_tmp.dir.createFile(std.testing.io, "src/main.zig", .{});
    try f2.writeStreamingAll(std.testing.io, "pub fn main() void {}");
    f2.close(std.testing.io);

    // Build tree from working directory
    var d = try work_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d.close();
    const tree_hash = try worktree.buildTree(allocator, std.testing.io, &store, d);

    // Sign and store commit
    const kp = sign.KeyPair.generate();
    const commit_hash = try createCommit(allocator, &store, tree_hash, &.{}, "initial commit", kp);

    // Update HEAD
    try refs.updateHead(allocator, work_tmp.dir, commit_hash);

    // Verify roundtrip: read commit back
    var obj = try store.get(allocator, commit_hash);
    defer obj.deinit(allocator);
    try std.testing.expectEqual(tree_hash, obj.commit.tree_hash);
    try std.testing.expectEqualStrings("initial commit", obj.commit.message);

    // Verify signature
    const valid = try sign.verifyCommit(allocator, obj.commit);
    try std.testing.expect(valid);
}

// ===========================================================================
// 2. Diff workflow: two trees, diffTrees, deinit
// ===========================================================================

test "diff workflow no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    const blob_a = try storeBlob(allocator, &store, "content A");
    const blob_b = try storeBlob(allocator, &store, "content B");
    const blob_c = try storeBlob(allocator, &store, "content C");

    // Old tree: {a.txt, shared.txt}
    const old_hash = try storeTree(allocator, &store, &.{
        .{ .name = "a.txt", .mode = .blob, .hash = blob_a },
        .{ .name = "shared.txt", .mode = .blob, .hash = blob_c },
    });

    // New tree: {b.txt, shared.txt} (a removed, b added)
    const new_hash = try storeTree(allocator, &store, &.{
        .{ .name = "b.txt", .mode = .blob, .hash = blob_b },
        .{ .name = "shared.txt", .mode = .blob, .hash = blob_c },
    });

    var result = try diff_mod.diffTrees(allocator, &store, old_hash, new_hash);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
}

// ===========================================================================
// 3. Status diff: build tree, modify file, statusDiff
// ===========================================================================

test "status diff workflow no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    // Create initial file
    const f1 = try work_tmp.dir.createFile(std.testing.io, "file.txt", .{});
    try f1.writeStreamingAll(std.testing.io, "original");
    f1.close(std.testing.io);

    // Build HEAD tree
    var d1 = try work_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d1.close();
    const head_tree = try worktree.buildTree(allocator, std.testing.io, &store, d1);

    // Modify the file
    const f2 = try work_tmp.dir.createFile(std.testing.io, "file.txt", .{});
    try f2.writeStreamingAll(std.testing.io, "modified");
    f2.close(std.testing.io);

    // Add a new file
    const f3 = try work_tmp.dir.createFile(std.testing.io, "new.txt", .{});
    try f3.writeStreamingAll(std.testing.io, "new content");
    f3.close(std.testing.io);

    // Compute status diff
    var d2 = try work_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d2.close();
    var result = try diff_mod.statusDiff(allocator, &store, head_tree, d2);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
}

// ===========================================================================
// 4. Merge workflow: clean merge (no conflicts)
// ===========================================================================

test "merge workflow no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    const blob_base = try storeBlob(allocator, &store, "base content");
    const blob_ours = try storeBlob(allocator, &store, "ours content");
    const blob_theirs = try storeBlob(allocator, &store, "theirs content");

    // Base: {a.txt}
    const base_hash = try storeTree(allocator, &store, &.{
        .{ .name = "a.txt", .mode = .blob, .hash = blob_base },
    });

    // Ours: {a.txt, b.txt} (added b.txt)
    const ours_hash = try storeTree(allocator, &store, &.{
        .{ .name = "a.txt", .mode = .blob, .hash = blob_base },
        .{ .name = "b.txt", .mode = .blob, .hash = blob_ours },
    });

    // Theirs: {a.txt, c.txt} (added c.txt)
    const theirs_hash = try storeTree(allocator, &store, &.{
        .{ .name = "a.txt", .mode = .blob, .hash = blob_base },
        .{ .name = "c.txt", .mode = .blob, .hash = blob_theirs },
    });

    var result = try merge_mod.mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    // Merged tree should have {a.txt, b.txt, c.txt}
    var merged_obj = try store.get(allocator, result.tree_hash);
    defer merged_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), merged_obj.tree.entries.len);
}

// ===========================================================================
// 5. Merge with conflicts
// ===========================================================================

test "merge with conflicts no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    const blob_base = try storeBlob(allocator, &store, "base");
    const blob_ours = try storeBlob(allocator, &store, "ours version");
    const blob_theirs = try storeBlob(allocator, &store, "theirs version");

    // Base: {file.txt}
    const base_hash = try storeTree(allocator, &store, &.{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_base },
    });

    // Ours: {file.txt} modified differently
    const ours_hash = try storeTree(allocator, &store, &.{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_ours },
    });

    // Theirs: {file.txt} modified differently
    const theirs_hash = try storeTree(allocator, &store, &.{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_theirs },
    });

    var result = try merge_mod.mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    // Should have one modify-modify conflict
    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    try std.testing.expectEqualStrings("file.txt", result.conflicts[0].path);
}

// ===========================================================================
// 6. Packfile roundtrip: packReachable -> unpackInto
// ===========================================================================

test "packfile roundtrip no leaks" {
    const allocator = std.testing.allocator;

    // Source store
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(std.testing.io, src_tmp.dir);
    defer src_store.close();

    // Create blob + tree + commit
    const blob_hash = try storeBlob(allocator, &src_store, "packfile content");

    const tree_hash = try storeTree(allocator, &src_store, &.{
        .{ .name = "data.txt", .mode = .blob, .hash = blob_hash },
    });

    const kp = sign.KeyPair.generate();
    const commit_hash = try createCommit(allocator, &src_store, tree_hash, &.{}, "pack test", kp);

    // Pack reachable objects
    const pack_result = try packfile.packReachable(allocator, &src_store, commit_hash);
    defer allocator.free(pack_result.bytes);

    // Verify digest
    try std.testing.expectEqual(hash_mod.hash(pack_result.bytes), pack_result.digest);

    // Destination store
    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(std.testing.io, dst_tmp.dir);
    defer dst_store.close();

    // Unpack into destination
    try packfile.unpackInto(allocator, pack_result.bytes, &dst_store);

    // Verify all objects are accessible
    try std.testing.expect(dst_store.exists(commit_hash));
    try std.testing.expect(dst_store.exists(tree_hash));
    try std.testing.expect(dst_store.exists(blob_hash));

    // Read back and verify content
    var obj = try dst_store.get(allocator, blob_hash);
    defer obj.deinit(allocator);
    try std.testing.expectEqualStrings("packfile content", obj.blob.data);
}

// ===========================================================================
// 7. (Bundle build is not part of core mkit; its allocator tests live
//    with the downstream consumer that needs it.)
// ===========================================================================

// ===========================================================================
// 8. Restore workflow: store tree -> restoreTree -> verify files
// ===========================================================================

test "restore workflow no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    // Build a tree with nested structure: src/main.zig, README.md
    const blob_main = try storeBlob(allocator, &store, "pub fn main() !void {}");
    const blob_readme = try storeBlob(allocator, &store, "# Project");

    const src_tree = try storeTree(allocator, &store, &.{
        .{ .name = "main.zig", .mode = .blob, .hash = blob_main },
    });

    const root_tree = try storeTree(allocator, &store, &.{
        .{ .name = "README.md", .mode = .blob, .hash = blob_readme },
        .{ .name = "src", .mode = .tree, .hash = src_tree },
    });

    // Restore to temp directory
    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restore_mod.restoreTree(allocator, &store, root_tree, target_dir, .{});

    // Verify files exist with correct content
    const readme = try target_tmp.dir.readFileAlloc(allocator, "README.md", 4096);
    defer allocator.free(readme);
    try std.testing.expectEqualStrings("# Project", readme);

    const main_zig = try target_tmp.dir.readFileAlloc(allocator, "src/main.zig", 4096);
    defer allocator.free(main_zig);
    try std.testing.expectEqualStrings("pub fn main() !void {}", main_zig);
}

// ===========================================================================
// 9. Config roundtrip: write -> read -> deinit
// ===========================================================================

test "config roundtrip no leaks" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // Write config with non-default values (exercises heap allocation paths)
    const original = config_mod.Config{
        .user_identity = "03" ++ "0800" ++ "2a00000000000000", // mid:42
        .signing_key = "/custom/path/to/key.pem",
        .default_branch = "develop",
    };
    try config_mod.writeConfig(tmp.dir, original);

    // Read it back
    var read = try config_mod.readConfig(allocator, tmp.dir);
    defer read.deinit();

    try std.testing.expectEqualStrings("030800" ++ "2a00000000000000", read.user_identity);
    try std.testing.expectEqualStrings("/custom/path/to/key.pem", read.signing_key);
    try std.testing.expectEqualStrings("develop", read.default_branch);
}

test "config parse with all features no leaks" {
    const allocator = std.testing.allocator;

    // Exercise comments, blank lines, unknown keys, and duplicate keys
    const content =
        \\# Config file
        \\
        \\user.identity = mid:100
        \\signing_key = first.key
        \\unknown_field = should_skip
        \\default_branch = feature
        \\
        \\# Override signing_key (tests free of prior heap value)
        \\signing_key = second.key
        \\# Override user.identity too (tests free of prior user_identity)
        \\user.identity = mid:200
    ;
    var config = try config_mod.parseConfig(allocator, content);
    defer config.deinit();

    // 200 LE = c8 00 00 00 00 00 00 00
    try std.testing.expectEqualStrings("030800" ++ "c800000000000000", config.user_identity);
    try std.testing.expectEqualStrings("second.key", config.signing_key);
    try std.testing.expectEqualStrings("feature", config.default_branch);
}

// ===========================================================================
// 10. Ignore load: create .mkitignore -> load -> deinit
// ===========================================================================

test "ignore load no leaks" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkitignore with various patterns
    const f = try tmp.dir.createFile(std.testing.io, ".mkitignore", .{});
    try f.writeStreamingAll(std.testing.io,
        \\# build artifacts
        \\*.o
        \\*.a
        \\build/
        \\!build/keep.txt
        \\
        \\# editor files
        \\.*.swp
        \\
    );
    f.close(std.testing.io);

    var il = try ignore_mod.load(allocator, tmp.dir);
    defer il.deinit();

    try std.testing.expectEqual(@as(usize, 5), il.patterns.len);
    try std.testing.expect(il.isIgnored("test.o", false));
    try std.testing.expect(il.isIgnored("libfoo.a", false));
    try std.testing.expect(il.isIgnored("build", true));
    try std.testing.expect(!il.isIgnored("build/keep.txt", false));
    try std.testing.expect(!il.isIgnored("src/main.zig", false));
}

// ===========================================================================
// 11. Refs lifecycle: init -> write -> list -> delete -> free
// ===========================================================================

test "refs lifecycle no leaks" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(std.testing.io, ".mkit");
    try refs.init(std.testing.io, tmp.dir);

    // Write several branch refs
    const h1 = hash_mod.hash("commit-main");
    const h2 = hash_mod.hash("commit-dev");
    const h3 = hash_mod.hash("commit-feature");
    try refs.writeRef(tmp.dir, "main", h1);
    try refs.writeRef(tmp.dir, "dev", h2);
    try refs.writeRef(tmp.dir, "feature", h3);

    // Write some tags
    try refs.writeTag(tmp.dir, "v1.0", h1);
    try refs.writeTag(tmp.dir, "v2.0", h2);

    // Read HEAD (returns allocated branch name)
    const head = try refs.readHead(allocator, tmp.dir);
    switch (head) {
        .branch => |branch| {
            defer allocator.free(branch);
            try std.testing.expectEqualStrings("main", branch);
        },
        .detached => return error.ExpectedBranch,
    }

    // Resolve HEAD
    const resolved = try refs.resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h1, resolved.?);

    // List all branch refs (returns allocated slice with allocated names)
    const ref_list = try refs.listRefs(allocator, tmp.dir);
    defer {
        for (ref_list) |ref| {
            allocator.free(ref.name);
        }
        allocator.free(ref_list);
    }
    try std.testing.expectEqual(@as(usize, 3), ref_list.len);

    // List all tags
    const tag_list = try refs.listTags(allocator, tmp.dir);
    defer {
        for (tag_list) |t| {
            allocator.free(t.name);
        }
        allocator.free(tag_list);
    }
    try std.testing.expectEqual(@as(usize, 2), tag_list.len);

    // Delete a branch ref
    try refs.deleteRef(tmp.dir, "feature");
    const after_ref = try refs.readRef(allocator, tmp.dir, "feature");
    try std.testing.expectEqual(@as(?Hash, null), after_ref);

    // Delete a tag
    try refs.deleteTag(tmp.dir, "v1.0");
    const after_tag = try refs.readTag(allocator, tmp.dir, "v1.0");
    try std.testing.expectEqual(@as(?Hash, null), after_tag);

    // Update HEAD
    try refs.updateHead(allocator, tmp.dir, h2);
    const resolved2 = try refs.resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h2, resolved2.?);
}

// ===========================================================================
// 12. Serialize roundtrip: all four object types
// ===========================================================================

test "serialize all types no leaks" {
    const allocator = std.testing.allocator;

    // Blob
    {
        const blob = object.Object{ .blob = .{ .data = "binary data here" } };
        const bytes = try serialize.serialize(allocator, blob);
        defer allocator.free(bytes);
        var parsed = try serialize.deserialize(allocator, bytes);
        defer parsed.deinit(allocator);
        try std.testing.expectEqualStrings("binary data here", parsed.blob.data);
    }

    // Tree
    {
        var entries = try allocator.alloc(object.TreeEntry, 2);
        entries[0] = .{ .name = try allocator.dupe(u8, "alpha.txt"), .mode = .blob, .object_hash = hash_mod.hash("a") };
        entries[1] = .{ .name = try allocator.dupe(u8, "beta"), .mode = .tree, .object_hash = hash_mod.hash("b") };
        var tree_obj = object.Object{ .tree = .{ .entries = entries } };
        const bytes = try serialize.serialize(allocator, tree_obj);
        defer allocator.free(bytes);
        tree_obj.deinit(allocator);

        var parsed = try serialize.deserialize(allocator, bytes);
        defer parsed.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), parsed.tree.entries.len);
    }

    // Commit
    {
        var parents = try allocator.alloc(Hash, 1);
        parents[0] = hash_mod.hash("parent");
        const author_bytes = try allocator.alloc(u8, 8);
        std.mem.writeInt(u64, author_bytes[0..8], 99, .little);
        var commit_obj = object.Object{ .commit = .{
            .tree_hash = hash_mod.hash("tree"),
            .parents = parents,
            .author = .{ .kind = .@"opaque", .bytes = author_bytes },
            .signer = .{0xAA} ** 32,
            .message = try allocator.dupe(u8, "test msg"),
            .timestamp = 1711300000,
            .message_hash = hash_mod.hash("test msg"),
            .content_digest = hash_mod.zero,
            .signature = .{0xBB} ** 64,
        } };
        const bytes = try serialize.serialize(allocator, commit_obj);
        defer allocator.free(bytes);
        commit_obj.deinit(allocator);

        var parsed = try serialize.deserialize(allocator, bytes);
        defer parsed.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 99), std.mem.readInt(u64, parsed.commit.author.bytes[0..8], .little));
    }

    // Remix
    {
        const parents = try allocator.alloc(Hash, 0);
        var sources = try allocator.alloc(object.RemixSource, 1);
        sources[0] = .{
            .upstream_id = hash_mod.hash("proj"),
            .commit_hash = hash_mod.hash("commit"),
        };
        const author_bytes = try allocator.alloc(u8, 8);
        std.mem.writeInt(u64, author_bytes[0..8], 77, .little);
        var remix_obj = object.Object{ .remix = .{
            .tree_hash = hash_mod.hash("remix-tree"),
            .parents = parents,
            .sources = sources,
            .author = .{ .kind = .@"opaque", .bytes = author_bytes },
            .signer = .{0xCC} ** 32,
            .message = try allocator.dupe(u8, "remix msg"),
            .timestamp = 2000,
            .signature = .{0xDD} ** 64,
        } };
        const bytes = try serialize.serialize(allocator, remix_obj);
        defer allocator.free(bytes);
        remix_obj.deinit(allocator);

        var parsed = try serialize.deserialize(allocator, bytes);
        defer parsed.deinit(allocator);
        try std.testing.expectEqual(@as(u64, 77), std.mem.readInt(u64, parsed.remix.author.bytes[0..8], .little));
    }
}

// ===========================================================================
// 13. Format module: all object types
// ===========================================================================

test "format all types no leaks" {
    const allocator = std.testing.allocator;

    // Format blob
    {
        const obj = object.Object{ .blob = .{ .data = "format test" } };
        const out = try format_mod.formatObject(allocator, obj, hash_mod.zero);
        defer allocator.free(out);
        try std.testing.expectEqualStrings("format test", out);
    }

    // Format tree
    {
        const entries = [_]object.TreeEntry{
            .{ .name = "file.txt", .mode = .blob, .object_hash = hash_mod.hash("f") },
        };
        const obj = object.Object{ .tree = .{ .entries = @constCast(&entries) } };
        const out = try format_mod.formatObject(allocator, obj, hash_mod.zero);
        defer allocator.free(out);
        try std.testing.expect(out.len > 0);
    }

    // Format commit
    {
        const parents = [_]Hash{hash_mod.hash("p1")};
        var mid_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &mid_buf, 42, .little);
        const obj = object.Object{ .commit = .{
            .tree_hash = hash_mod.hash("tree"),
            .parents = @constCast(&parents),
            .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
            .signer = .{0xAA} ** 32,
            .message = "commit msg",
            .timestamp = 1000,
            .message_hash = hash_mod.hash("commit msg"),
            .content_digest = hash_mod.hash("digest"),
            .signature = .{0xBB} ** 64,
        } };
        const out = try format_mod.formatObject(allocator, obj, hash_mod.hash("commit-id"));
        defer allocator.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "commit ") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "parent ") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "mhash  ") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "digest ") != null);
    }

    // Format remix
    {
        const parents = [_]Hash{};
        const sources = [_]object.RemixSource{
            .{ .upstream_id = hash_mod.hash("proj"), .commit_hash = hash_mod.hash("c") },
        };
        var mid_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &mid_buf, 99, .little);
        const obj = object.Object{ .remix = .{
            .tree_hash = hash_mod.hash("tree"),
            .parents = @constCast(&parents),
            .sources = @constCast(&sources),
            .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
            .signer = .{0} ** 32,
            .message = "remix msg",
            .timestamp = 2000,
            .signature = .{0} ** 64,
        } };
        const out = try format_mod.formatObject(allocator, obj, hash_mod.hash("remix-id"));
        defer allocator.free(out);
        try std.testing.expect(std.mem.indexOf(u8, out, "remix  ") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "source ") != null);
    }
}

// ===========================================================================
// 14. Store put/get/getRaw lifecycle with all object types
// ===========================================================================

test "store lifecycle all types no leaks" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Store and retrieve a blob
    const blob_hash = try store.put(allocator, object.Object{ .blob = .{ .data = "blob data" } });
    {
        var obj = try store.get(allocator, blob_hash);
        defer obj.deinit(allocator);
        try std.testing.expectEqualStrings("blob data", obj.blob.data);
    }

    // getRaw + manual deserialize
    {
        const raw = try store.getRaw(allocator, blob_hash);
        defer allocator.free(raw);
        var obj = try serialize.deserialize(allocator, raw);
        defer obj.deinit(allocator);
        try std.testing.expectEqualStrings("blob data", obj.blob.data);
    }
}

// ===========================================================================
// 15. Packfile pack/unpack of raw buffers (no store)
// ===========================================================================

test "packfile pack unpack raw no leaks" {
    const allocator = std.testing.allocator;

    // Serialize a few objects to raw bytes
    const blob1_bytes = try serialize.serialize(allocator, object.Object{ .blob = .{ .data = "first" } });
    defer allocator.free(blob1_bytes);
    const blob2_bytes = try serialize.serialize(allocator, object.Object{ .blob = .{ .data = "second" } });
    defer allocator.free(blob2_bytes);

    // Pack
    const items = [_][]const u8{ blob1_bytes, blob2_bytes };
    const result = try packfile.pack(allocator, &items);
    defer allocator.free(result.bytes);

    // Unpack
    const unpacked = try packfile.unpack(allocator, result.bytes);
    defer {
        for (unpacked) |obj| {
            allocator.free(obj);
        }
        allocator.free(unpacked);
    }

    try std.testing.expectEqual(@as(usize, 2), unpacked.len);
    try std.testing.expectEqualSlices(u8, blob1_bytes, unpacked[0]);
    try std.testing.expectEqualSlices(u8, blob2_bytes, unpacked[1]);
}

// ===========================================================================
// 16. End-to-end: init -> commit -> diff -> pack -> bundle -> restore
// ===========================================================================

test "end-to-end workflow no leaks" {
    const allocator = std.testing.allocator;

    // Create repo
    var repo_tmp = std.testing.tmpDir(.{});
    defer repo_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, repo_tmp.dir);
    defer store.close();
    try refs.init(repo_tmp.dir);

    // Create work files
    var work_tmp = std.testing.tmpDir(.{});
    defer work_tmp.cleanup();

    const f1 = try work_tmp.dir.createFile(std.testing.io, "README.md", .{});
    try f1.writeStreamingAll(std.testing.io, "# Hello");
    f1.close(std.testing.io);
    try work_tmp.dir.createDirPath(std.testing.io, "src");
    const f2 = try work_tmp.dir.createFile(std.testing.io, "src/lib.zig", .{});
    try f2.writeStreamingAll(std.testing.io, "pub const version = 1;");
    f2.close(std.testing.io);

    // Build tree and commit
    var d1 = try work_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d1.close();
    const tree1 = try worktree.buildTree(allocator, std.testing.io, &store, d1);

    const kp = sign.KeyPair.generate();
    const commit1 = try createCommit(allocator, &store, tree1, &.{}, "initial", kp);
    try refs.updateHead(allocator, repo_tmp.dir, commit1);

    // Modify a file and make a second commit
    const f3 = try work_tmp.dir.createFile(std.testing.io, "src/lib.zig", .{});
    try f3.writeStreamingAll(std.testing.io, "pub const version = 2;");
    f3.close(std.testing.io);

    var d2 = try work_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d2.close();
    const tree2 = try worktree.buildTree(allocator, std.testing.io, &store, d2);

    const commit2 = try createCommit(allocator, &store, tree2, &.{commit1}, "bump version", kp);
    try refs.updateHead(allocator, repo_tmp.dir, commit2);

    // Diff between the two commits
    var diff_result = try diff_mod.diffTrees(allocator, &store, tree1, tree2);
    defer diff_result.deinit();
    try std.testing.expectEqual(@as(usize, 1), diff_result.entries.len);
    try std.testing.expectEqualStrings("src/lib.zig", diff_result.entries[0].path);

    // Pack the tip commit
    const pack_result = try packfile.packReachable(allocator, &store, commit2);
    defer allocator.free(pack_result.bytes);

    // (Bundle build step is not part of core mkit; restore path still
    // proves the end-to-end workflow is leak-free.)

    // Restore the latest tree to a fresh directory
    var restore_tmp = std.testing.tmpDir(.{});
    defer restore_tmp.cleanup();
    var restore_dir = try restore_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer restore_dir.close();
    try restore_mod.restoreTree(allocator, &store, tree2, restore_dir, .{});

    const restored_lib = try restore_tmp.dir.readFileAlloc(allocator, "src/lib.zig", 4096);
    defer allocator.free(restored_lib);
    try std.testing.expectEqualStrings("pub const version = 2;", restored_lib);
}

// ===========================================================================
// 17. Stress: many small allocations in a loop
// ===========================================================================

test "stress many serialize roundtrips no leaks" {
    const allocator = std.testing.allocator;

    for (0..100) |i| {
        var msg_buf: [32]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "commit number {d}", .{i}) catch continue;

        const parents = [_]Hash{};
        var mid_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &mid_buf, i, .little);
        const commit = object.Commit{
            .tree_hash = hash_mod.hash(msg),
            .parents = @constCast(&parents),
            .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
            .signer = .{@as(u8, @intCast(i & 0xFF))} ** 32,
            .message = msg,
            .timestamp = @intCast(i),
            .signature = .{0} ** 64,
        };

        const signing_bytes = try sign.commitSigningBytes(allocator, commit);
        defer allocator.free(signing_bytes);

        const bytes = try serialize.serialize(allocator, object.Object{ .commit = commit });
        defer allocator.free(bytes);

        var parsed = try serialize.deserialize(allocator, bytes);
        defer parsed.deinit(allocator);
    }
}

// ===========================================================================
// 18. Stress: repeated diff on changing trees
// ===========================================================================

test "stress repeated diff no leaks" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var prev_hash: ?Hash = null;

    for (0..20) |i| {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "file_{d:0>2}.txt", .{i}) catch continue;
        var data_buf: [16]u8 = undefined;
        const data = std.fmt.bufPrint(&data_buf, "data {d}", .{i}) catch continue;

        const blob_hash = try storeBlob(allocator, &store, data);
        const tree_hash = try storeTree(allocator, &store, &.{
            .{ .name = name, .mode = .blob, .hash = blob_hash },
        });

        if (prev_hash) |ph| {
            var result = try diff_mod.diffTrees(allocator, &store, ph, tree_hash);
            defer result.deinit();
            try std.testing.expect(result.entries.len > 0);
        }

        prev_hash = tree_hash;
    }
}
