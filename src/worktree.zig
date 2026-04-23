// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const ignore_mod = @import("ignore.zig");
const fastcdc_mod = @import("fastcdc.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Build a tree object from a directory, storing all blobs and subtrees
/// in the object store. Returns the root tree hash.
/// Loads .mkitignore from the root directory to filter entries.
pub fn buildTree(allocator: Allocator, io: std.Io, store: *store_mod.ObjectStore, dir: std.Io.Dir) !Hash {
    var ignores = try ignore_mod.load(allocator, io, dir);
    defer ignores.deinit();
    return buildTreeInner(allocator, io, store, dir, &ignores);
}

pub fn validateSymlinkTarget(target: []const u8) bool {
    if (target.len == 0) return false;
    if (target[0] == '/') return false;

    var parts = std.mem.splitScalar(u8, target, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return false;
    }

    return true;
}

fn buildTreeInner(allocator: Allocator, io: std.Io, store: *store_mod.ObjectStore, dir: std.Io.Dir, ignores: *const ignore_mod.IgnoreList) !Hash {
    var entries: std.ArrayList(object.TreeEntry) = .empty;
    defer {
        for (entries.items) |entry| {
            allocator.free(entry.name);
        }
        entries.deinit(allocator);
    }

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;

    var iter = dir.iterate(io);
    while (try iter.next(io)) |entry| {
        const is_dir = entry.kind == .directory;
        if (ignores.isIgnored(entry.name, is_dir)) continue;

        const name = try allocator.dupe(u8, entry.name);
        errdefer allocator.free(name);

        switch (entry.kind) {
            .file => {
                const h = try hashFile(allocator, io, store, dir, entry.name);
                try entries.append(allocator, .{
                    .name = name,
                    .mode = .blob,
                    .object_hash = h,
                });
            },
            .directory => {
                var subdir = try dir.openDir(io, entry.name, .{ .iterate = true });
                defer subdir.close(io);
                const h = try buildTreeInner(allocator, io, store, subdir, ignores);
                try entries.append(allocator, .{
                    .name = name,
                    .mode = .tree,
                    .object_hash = h,
                });
            },
            .sym_link => {
                const read = try dir.readLink(io, entry.name, &link_buf);
                const target = link_buf[0..read];
                if (!validateSymlinkTarget(target)) return error.InvalidSymlinkTarget;
                const h = try hashBlob(allocator, store, target);
                try entries.append(allocator, .{
                    .name = name,
                    .mode = .symlink,
                    .object_hash = h,
                });
            },
            else => {
                allocator.free(name);
                continue;
            },
        }
    }

    std.mem.sort(object.TreeEntry, entries.items, {}, struct {
        fn lessThan(_: void, a: object.TreeEntry, b: object.TreeEntry) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lessThan);

    const tree_obj = object.Object{ .tree = .{ .entries = entries.items } };
    return store.put(allocator, tree_obj);
}

/// Files larger than this threshold are stored as chunked blobs.
pub const chunk_threshold: usize = 1 * 1024 * 1024; // 1MB

pub fn hashFile(allocator: Allocator, io: std.Io, store: *store_mod.ObjectStore, dir: std.Io.Dir, name: []const u8) !Hash {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size > 1024 * 1024 * 1024) return error.FileTooLarge;

    if (stat.size > chunk_threshold) {
        return hashFileChunked(allocator, store, file, stat.size);
    }

    const data = try allocator.alloc(u8, stat.size);
    defer allocator.free(data);
    const read = try file.readPositionalAll(io, data, 0);

    const blob = object.Object{ .blob = .{ .data = data[0..read] } };
    return store.put(allocator, blob);
}

fn hashFileChunked(allocator: Allocator, store: *store_mod.ObjectStore, file: std.Io.File, total_size: u64) !Hash {
    var chunk_hashes: std.ArrayList(hash_mod.Hash) = .empty;
    defer chunk_hashes.deinit(allocator);

    var chunker = try fastcdc_mod.StreamingChunker.init(allocator, fastcdc_mod.FastCDC.init(
        16 * 1024,
        64 * 1024,
        256 * 1024,
    ));
    defer chunker.deinit();

    while (try chunker.nextChunk(file)) |chunk_data| {
        const chunk_blob = object.Object{ .blob = .{ .data = chunk_data } };
        const chunk_hash = try store.put(allocator, chunk_blob);
        try chunk_hashes.append(allocator, chunk_hash);
    }

    const owned_chunks = try allocator.dupe(hash_mod.Hash, chunk_hashes.items);
    var cb = object.Object{
        .chunked_blob = .{
            .total_size = total_size,
            .chunk_size = 0, // 0 = content-defined chunks
            .chunks = owned_chunks,
        },
    };
    const h = try store.put(allocator, cb);
    cb.deinit(allocator);
    return h;
}

fn hashBlob(allocator: Allocator, store: *store_mod.ObjectStore, data: []const u8) !Hash {
    const blob = object.Object{ .blob = .{ .data = data } };
    return store.put(allocator, blob);
}

// -- Tests --

test "build tree from empty directory" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Init store in a separate temp dir
    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    // Build tree from empty dir
    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    // Should produce a valid tree with 0 entries
    var obj = try store.get(allocator, h);
    defer obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), obj.tree.entries.len);
}

test "build tree from single file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file
    const f = try tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "hello world");
    f.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var obj = try store.get(allocator, h);
    defer obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), obj.tree.entries.len);
    try std.testing.expectEqualStrings("hello.txt", obj.tree.entries[0].name);
    try std.testing.expectEqual(object.EntryMode.blob, obj.tree.entries[0].mode);

    // Verify the blob content
    var blob = try store.get(allocator, obj.tree.entries[0].object_hash);
    defer blob.deinit(allocator);
    try std.testing.expectEqualStrings("hello world", blob.blob.data);
}

test "reject invalid symlink targets" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.symLink(std.testing.io, "/etc/passwd", "bad-link", .{});

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    try std.testing.expectError(error.InvalidSymlinkTarget, buildTree(allocator, std.testing.io, &store, work_dir));
}

test "build tree with nested directories" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create nested structure
    try tmp.dir.createDirPath(std.testing.io, "subdir");
    const f1 = try tmp.dir.createFile(std.testing.io, "a.txt", .{});
    try f1.writeStreamingAll(std.testing.io, "file a");
    f1.close(std.testing.io);
    const f2 = try tmp.dir.createFile(std.testing.io, "subdir/b.txt", .{});
    try f2.writeStreamingAll(std.testing.io, "file b");
    f2.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var obj = try store.get(allocator, h);
    defer obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), obj.tree.entries.len);

    // Entries should be sorted: a.txt before subdir
    try std.testing.expectEqualStrings("a.txt", obj.tree.entries[0].name);
    try std.testing.expectEqual(object.EntryMode.blob, obj.tree.entries[0].mode);
    try std.testing.expectEqualStrings("subdir", obj.tree.entries[1].name);
    try std.testing.expectEqual(object.EntryMode.tree, obj.tree.entries[1].mode);

    // Verify subtree
    var subtree = try store.get(allocator, obj.tree.entries[1].object_hash);
    defer subtree.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), subtree.tree.entries.len);
    try std.testing.expectEqualStrings("b.txt", subtree.tree.entries[0].name);
}

test "build tree skips .mkit directory" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a .mkit dir that should be skipped
    try tmp.dir.createDirPath(std.testing.io, ".mkit");
    const f1 = try tmp.dir.createFile(std.testing.io, ".mkit/should_skip", .{});
    f1.close(std.testing.io);
    const f2 = try tmp.dir.createFile(std.testing.io, "keep.txt", .{});
    try f2.writeStreamingAll(std.testing.io, "kept");
    f2.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var obj = try store.get(allocator, h);
    defer obj.deinit(allocator);
    // Only keep.txt should be in the tree, .mkit is skipped
    try std.testing.expectEqual(@as(usize, 1), obj.tree.entries.len);
    try std.testing.expectEqualStrings("keep.txt", obj.tree.entries[0].name);
}

test "build tree is deterministic" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const f1 = try tmp.dir.createFile(std.testing.io, "z.txt", .{});
    try f1.writeStreamingAll(std.testing.io, "z");
    f1.close(std.testing.io);
    const f2 = try tmp.dir.createFile(std.testing.io, "a.txt", .{});
    try f2.writeStreamingAll(std.testing.io, "a");
    f2.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    // Build twice — must produce same hash
    var d1 = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d1.close(std.testing.io);
    const h1 = try buildTree(allocator, std.testing.io, &store, d1);

    var d2 = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer d2.close(std.testing.io);
    const h2 = try buildTree(allocator, std.testing.io, &store, d2);

    try std.testing.expectEqual(h1, h2);
}

test "build tree respects mkitignore" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkitignore containing "*.log"
    const ignore_file = try tmp.dir.createFile(std.testing.io, ".mkitignore", .{});
    try ignore_file.writeStreamingAll(std.testing.io, "*.log\n");
    ignore_file.close(std.testing.io);

    // Create files: keep.txt (should appear), debug.log (should be ignored)
    const f1 = try tmp.dir.createFile(std.testing.io, "keep.txt", .{});
    try f1.writeStreamingAll(std.testing.io, "kept");
    f1.close(std.testing.io);
    const f2 = try tmp.dir.createFile(std.testing.io, "debug.log", .{});
    try f2.writeStreamingAll(std.testing.io, "ignored");
    f2.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var obj = try store.get(allocator, h);
    defer obj.deinit(allocator);

    // Only keep.txt and .mkitignore should be in the tree (debug.log is ignored)
    try std.testing.expectEqual(@as(usize, 2), obj.tree.entries.len);
    // Entries are sorted: .mkitignore before keep.txt
    try std.testing.expectEqualStrings(".mkitignore", obj.tree.entries[0].name);
    try std.testing.expectEqualStrings("keep.txt", obj.tree.entries[1].name);
}

test "large file creates chunked blob" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file larger than chunk_threshold (1MB)
    const large_size = chunk_threshold + 1024; // just over 1MB
    const f = try tmp.dir.createFile(std.testing.io, "large.bin", .{});
    // Write deterministic data
    const buf = try allocator.alloc(u8, 4096);
    defer allocator.free(buf);
    @memset(buf, 0xAB);
    var written: usize = 0;
    while (written < large_size) {
        const to_write = @min(buf.len, large_size - written);
        try f.writeStreamingAll(std.testing.io, buf[0..to_write]);
        written += to_write;
    }
    f.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var tree_obj = try store.get(allocator, h);
    defer tree_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), tree_obj.tree.entries.len);
    try std.testing.expectEqualStrings("large.bin", tree_obj.tree.entries[0].name);

    // The entry hash should point to a chunked_blob object
    var entry_obj = try store.get(allocator, tree_obj.tree.entries[0].object_hash);
    defer entry_obj.deinit(allocator);
    try std.testing.expectEqual(object.ObjectType.chunked_blob, entry_obj.objectType());
    try std.testing.expectEqual(@as(u64, large_size), entry_obj.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 0), entry_obj.chunked_blob.chunk_size);
    // With CDC, there should be at least 1 chunk
    try std.testing.expect(entry_obj.chunked_blob.chunks.len >= 1);
}

test "small file stays as regular blob" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file smaller than chunk_threshold
    const f = try tmp.dir.createFile(std.testing.io, "small.txt", .{});
    try f.writeStreamingAll(std.testing.io, "hello world");
    f.close(std.testing.io);

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);
    defer store.close();

    var work_dir = try tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const h = try buildTree(allocator, std.testing.io, &store, work_dir);

    var tree_obj = try store.get(allocator, h);
    defer tree_obj.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), tree_obj.tree.entries.len);

    // The entry hash should point to a regular blob object
    var entry_obj = try store.get(allocator, tree_obj.tree.entries[0].object_hash);
    defer entry_obj.deinit(allocator);
    try std.testing.expectEqual(object.ObjectType.blob, entry_obj.objectType());
    try std.testing.expectEqualStrings("hello world", entry_obj.blob.data);
}
