// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const worktree_mod = @import("worktree.zig");
const ignore_mod = @import("ignore.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const index_file = ".mkit/index";

/// Magic bytes for index file format: "ZMIX" (ZMit IndeX).
const magic: [4]u8 = .{ 'Z', 'M', 'I', 'X' };
/// Current index format version.
const format_version: u8 = 1;

pub const EntryStatus = enum(u8) {
    blob = 0x01,
    tree = 0x02,
    symlink = 0x03,
    removed = 0x00,
};

pub const IndexEntry = struct {
    path: []const u8,
    status: EntryStatus,
    object_hash: Hash,
};

const FlatPathEntry = struct {
    path: []const u8,
    mode: object.EntryMode,
    object_hash: Hash,
};

pub const Index = struct {
    entries: std.ArrayList(IndexEntry),
    allocator: Allocator,

    pub fn init(allocator: Allocator) Index {
        return .{ .entries = .{}, .allocator = allocator };
    }

    pub fn deinit(self: *Index) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.path);
        }
        self.entries.deinit(self.allocator);
    }

    /// Find the position of an entry by path. Returns null if not found.
    pub fn findEntry(self: *const Index, path: []const u8) ?usize {
        for (self.entries.items, 0..) |entry, i| {
            if (std.mem.eql(u8, entry.path, path)) return i;
        }
        return null;
    }

    /// Count non-removed entries.
    pub fn stagedCount(self: *const Index) usize {
        var count: usize = 0;
        for (self.entries.items) |entry| {
            if (entry.status != .removed) count += 1;
        }
        return count;
    }
};

/// Read an index from `.mkit/index`. Returns an empty index if the file doesn't exist.
pub fn readIndex(allocator: Allocator, dir: std.fs.Dir) !Index {
    const file = dir.openFile(index_file, .{}) catch |err| switch (err) {
        error.FileNotFound => return Index.init(allocator),
        else => return err,
    };
    defer file.close();

    const stat = try file.stat();
    if (stat.size == 0) return Index.init(allocator);
    if (stat.size > 64 * 1024 * 1024) return error.IndexTooLarge; // 64MB safety limit

    const data = try allocator.alloc(u8, stat.size);
    defer allocator.free(data);
    const read = try file.readAll(data);
    if (read != stat.size) return error.UnexpectedEof;

    return deserializeIndex(allocator, data[0..read]);
}

/// Write an index to `.mkit/index`.
pub fn writeIndex(dir: std.fs.Dir, idx: *const Index) !void {
    const data = try serializeIndex(idx.allocator, idx);
    defer idx.allocator.free(data);
    try writeAtomicFile(dir, index_file, data);
}

/// Serialize the index to bytes.
/// Format: magic(4) + version(1) + entry_count(4 LE) + entries...
/// Each entry: status(1) + hash(32) + path_len(2 LE) + path(path_len)
fn serializeIndex(allocator: Allocator, idx: *const Index) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);

    // Header
    try buf.appendSlice(allocator, &magic);
    try buf.append(allocator, format_version);

    // Entry count (4 bytes LE)
    const count: u32 = @intCast(idx.entries.items.len);
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, count)));

    // Entries
    for (idx.entries.items) |entry| {
        try buf.append(allocator, @intFromEnum(entry.status));
        try buf.appendSlice(allocator, &entry.object_hash);
        const path_len: u16 = @intCast(entry.path.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u16, path_len)));
        try buf.appendSlice(allocator, entry.path);
    }

    return buf.toOwnedSlice(allocator);
}

/// Deserialize bytes into an Index.
fn deserializeIndex(allocator: Allocator, data: []const u8) !Index {
    if (data.len < 9) return error.IndexCorrupt; // magic(4) + version(1) + count(4)

    // Verify magic
    if (!std.mem.eql(u8, data[0..4], &magic)) return error.IndexCorrupt;

    // Verify version
    if (data[4] != format_version) return error.UnsupportedIndexVersion;

    // Read entry count
    const count = std.mem.littleToNative(u32, std.mem.bytesToValue(u32, data[5..9]));

    var idx = Index.init(allocator);
    errdefer idx.deinit();

    var offset: usize = 9;
    for (0..count) |_| {
        if (offset + 35 > data.len) return error.IndexCorrupt; // status(1) + hash(32) + path_len(2)

        const status = std.meta.intToEnum(EntryStatus, data[offset]) catch return error.IndexCorrupt;
        offset += 1;

        const entry_hash: Hash = data[offset..][0..32].*;
        offset += 32;

        const path_len = std.mem.littleToNative(u16, std.mem.bytesToValue(u16, data[offset..][0..2]));
        offset += 2;

        if (offset + path_len > data.len) return error.IndexCorrupt;
        const path = try allocator.dupe(u8, data[offset..][0..path_len]);
        offset += path_len;

        try idx.entries.append(allocator, .{
            .path = path,
            .status = status,
            .object_hash = entry_hash,
        });
    }

    return idx;
}

fn writeAtomicFile(dir: std.fs.Dir, path: []const u8, data: []const u8) !void {
    var write_buffer: [1024]u8 = undefined;
    var atomic_file = try dir.atomicFile(path, .{
        .mode = std.fs.File.default_mode,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    try atomic_file.file_writer.interface.writeAll(data);
    try atomic_file.flush();
    try atomic_file.file_writer.file.sync();
    try atomic_file.renameIntoPlace();
}

/// Stage a single file by path. Reads the file, hashes it, stores the blob,
/// and adds or updates the index entry.
pub fn addFile(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    dir: std.fs.Dir,
    idx: *Index,
    path: []const u8,
) !void {
    if (!validateIndexPath(path)) return error.InvalidPath;
    const h = try worktree_mod.hashFile(allocator, store, dir, path);

    if (idx.findEntry(path)) |i| {
        idx.entries.items[i].object_hash = h;
        idx.entries.items[i].status = .blob;
    } else {
        const duped = try allocator.dupe(u8, path);
        try idx.entries.append(allocator, .{
            .path = duped,
            .status = .blob,
            .object_hash = h,
        });
    }
}

/// Stage all non-ignored files in the working directory.
pub fn addAll(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    dir: std.fs.Dir,
    idx: *Index,
) !void {
    var ignores = try ignore_mod.load(allocator, dir);
    defer ignores.deinit();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        const path = entry.path;

        // Skip .mkit/ and .git/ directories (but not .mkitignore etc.)
        if (std.mem.startsWith(u8, path, ".mkit/") or std.mem.eql(u8, path, ".mkit")) continue;
        if (std.mem.startsWith(u8, path, ".git/") or std.mem.eql(u8, path, ".git")) continue;

        // Check ignore patterns against basename
        const basename = std.fs.path.basename(path);
        if (ignores.isIgnored(basename, false)) continue;

        try addFile(allocator, store, dir, idx, path);
    }
}

/// Mark a file for removal in the index.
pub fn removeFile(idx: *Index, allocator: Allocator, path: []const u8) !void {
    if (!validateIndexPath(path)) return error.InvalidPath;
    if (idx.findEntry(path)) |i| {
        idx.entries.items[i].status = .removed;
    } else {
        const duped = try allocator.dupe(u8, path);
        try idx.entries.append(allocator, .{
            .path = duped,
            .status = .removed,
            .object_hash = hash_mod.zero,
        });
    }
}

/// Build a tree object from the index entries, supporting nested directories.
/// Only non-removed entries are included. Returns the root tree hash.
pub fn buildTreeFromIndex(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    idx: *const Index,
) !Hash {
    return buildCommitTreeFromIndex(allocator, store, null, idx);
}

/// Build the next committed tree by overlaying index entries onto an existing base tree.
/// This preserves unstaged tracked files while applying staged additions/modifications/removals.
pub fn buildCommitTreeFromIndex(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    base_tree: ?Hash,
    idx: *const Index,
) !Hash {
    var flat = std.StringArrayHashMap(FlatPathEntry).init(allocator);
    defer {
        for (flat.keys()) |path| allocator.free(path);
        flat.deinit();
    }

    if (base_tree) |tree_hash| {
        try collectTreeEntries(allocator, store, tree_hash, "", &flat);
    }

    for (idx.entries.items) |entry| {
        if (!validateIndexPath(entry.path)) return error.InvalidPath;
        if (entry.status == .removed) {
            if (flat.fetchSwapRemove(entry.path)) |removed| {
                allocator.free(removed.key);
            }
            continue;
        }

        const mode: object.EntryMode = switch (entry.status) {
            .blob => .blob,
            .tree => .tree,
            .symlink => .symlink,
            .removed => unreachable,
        };

        if (flat.getPtr(entry.path)) |existing| {
            existing.* = .{
                .path = existing.path,
                .mode = mode,
                .object_hash = entry.object_hash,
            };
        } else {
            const duped = try allocator.dupe(u8, entry.path);
            try flat.put(duped, .{
                .path = duped,
                .mode = mode,
                .object_hash = entry.object_hash,
            });
        }
    }

    const flat_entries = try allocator.alloc(FlatPathEntry, flat.count());
    defer allocator.free(flat_entries);
    for (flat.values(), 0..) |entry, i| {
        flat_entries[i] = entry;
    }

    std.mem.sort(FlatPathEntry, flat_entries, {}, struct {
        fn lessThan(_: void, a: FlatPathEntry, b: FlatPathEntry) bool {
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lessThan);

    try ensureNoPathConflicts(flat_entries);
    return buildTreeRecursiveFromFlat(allocator, store, flat_entries, "");
}

pub fn validateIndexPath(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/') return false;
    if (std.mem.eql(u8, path, ".mkit") or std.mem.eql(u8, path, ".git")) return false;
    if (std.mem.startsWith(u8, path, ".mkit/") or std.mem.startsWith(u8, path, ".git/")) return false;

    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0) return false;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return false;
        for (part) |c| {
            if (c == 0 or c == '\\') return false;
        }
    }
    return true;
}

fn ensureNoPathConflicts(entries: []const FlatPathEntry) !void {
    if (entries.len <= 1) return;
    for (entries[0 .. entries.len - 1], entries[1..]) |a, b| {
        if (std.mem.startsWith(u8, b.path, a.path) and b.path.len > a.path.len and b.path[a.path.len] == '/') {
            return error.PathConflict;
        }
    }
}

fn collectTreeEntries(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    prefix: []const u8,
    flat: *std.StringArrayHashMap(FlatPathEntry),
) !void {
    var obj = try store.get(allocator, tree_hash);
    defer obj.deinit(allocator);
    if (obj != .tree) return error.NotATree;

    for (obj.tree.entries) |entry| {
        const full_path = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try hash_mod.joinPath(allocator, prefix, entry.name);
        defer allocator.free(full_path);

        switch (entry.mode) {
            .tree => try collectTreeEntries(allocator, store, entry.object_hash, full_path, flat),
            .blob, .symlink, .executable => {
                const owned = try allocator.dupe(u8, full_path);
                try flat.put(owned, .{
                    .path = owned,
                    .mode = entry.mode,
                    .object_hash = entry.object_hash,
                });
            },
        }
    }
}

fn buildTreeRecursiveFromFlat(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    entries: []const FlatPathEntry,
    prefix: []const u8,
) !Hash {
    // Collect all non-removed entries
    var tree_entries: std.ArrayList(object.TreeEntry) = .{};
    defer {
        for (tree_entries.items) |te| {
            allocator.free(te.name);
        }
        tree_entries.deinit(allocator);
    }

    // Track which subdirectory names we've already processed
    var seen_dirs: std.ArrayList([]const u8) = .{};
    defer {
        for (seen_dirs.items) |s| allocator.free(s);
        seen_dirs.deinit(allocator);
    }

    for (entries) |entry| {
        // Check if this entry is under our prefix
        const rel_path = if (prefix.len == 0)
            entry.path
        else blk: {
            if (!std.mem.startsWith(u8, entry.path, prefix)) continue;
            if (entry.path.len <= prefix.len) continue;
            if (entry.path[prefix.len] != '/') continue;
            break :blk entry.path[prefix.len + 1 ..];
        };

        // Check if this entry is directly at this level or in a subdirectory
        if (std.mem.indexOfScalar(u8, rel_path, '/')) |slash_pos| {
            // This entry is in a subdirectory
            const dir_name = rel_path[0..slash_pos];

            // Check if we already processed this directory
            var already_seen = false;
            for (seen_dirs.items) |s| {
                if (std.mem.eql(u8, s, dir_name)) {
                    already_seen = true;
                    break;
                }
            }
            if (already_seen) continue;

            const duped_dir = try allocator.dupe(u8, dir_name);
            try seen_dirs.append(allocator, duped_dir);

            // Build the subdirectory prefix
            const sub_prefix = if (prefix.len == 0)
                try allocator.dupe(u8, dir_name)
            else
                try hash_mod.joinPath(allocator, prefix, dir_name);
            defer allocator.free(sub_prefix);

            // Recursively build tree for subdirectory
            const sub_hash = try buildTreeRecursiveFromFlat(allocator, store, entries, sub_prefix);

            const name = try allocator.dupe(u8, dir_name);
            try tree_entries.append(allocator, .{
                .name = name,
                .mode = .tree,
                .object_hash = sub_hash,
            });
        } else {
            // Direct file at this level
            const name = try allocator.dupe(u8, rel_path);
            try tree_entries.append(allocator, .{
                .name = name,
                .mode = entry.mode,
                .object_hash = entry.object_hash,
            });
        }
    }

    // Sort entries by name for deterministic hashing
    std.mem.sort(object.TreeEntry, tree_entries.items, {}, struct {
        fn lessThan(_: void, a: object.TreeEntry, b: object.TreeEntry) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lessThan);

    return store.put(allocator, object.Object{ .tree = .{ .entries = tree_entries.items } });
}

// =============================================================================
// Tests
// =============================================================================

test "index init and deinit" {
    const allocator = std.testing.allocator;
    var idx = Index.init(allocator);
    defer idx.deinit();
    try std.testing.expectEqual(@as(usize, 0), idx.entries.items.len);
}

test "index serialize and deserialize roundtrip" {
    const allocator = std.testing.allocator;

    var idx = Index.init(allocator);
    defer idx.deinit();

    const path1 = try allocator.dupe(u8, "hello.txt");
    const path2 = try allocator.dupe(u8, "src/main.zig");
    const h1 = hash_mod.hash("content1");
    const h2 = hash_mod.hash("content2");

    try idx.entries.append(allocator, .{ .path = path1, .status = .blob, .object_hash = h1 });
    try idx.entries.append(allocator, .{ .path = path2, .status = .removed, .object_hash = h2 });

    const data = try serializeIndex(allocator, &idx);
    defer allocator.free(data);

    var idx2 = try deserializeIndex(allocator, data);
    defer idx2.deinit();

    try std.testing.expectEqual(@as(usize, 2), idx2.entries.items.len);
    try std.testing.expectEqualStrings("hello.txt", idx2.entries.items[0].path);
    try std.testing.expectEqual(EntryStatus.blob, idx2.entries.items[0].status);
    try std.testing.expectEqual(h1, idx2.entries.items[0].object_hash);
    try std.testing.expectEqualStrings("src/main.zig", idx2.entries.items[1].path);
    try std.testing.expectEqual(EntryStatus.removed, idx2.entries.items[1].status);
}

test "index readIndex returns empty for missing file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var idx = try readIndex(allocator, tmp.dir);
    defer idx.deinit();
    try std.testing.expectEqual(@as(usize, 0), idx.entries.items.len);
}

test "index writeIndex and readIndex roundtrip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkit directory for index file
    try tmp.dir.makeDir(".mkit");

    var idx = Index.init(allocator);
    defer idx.deinit();

    const path = try allocator.dupe(u8, "test.txt");
    const h = hash_mod.hash("test content");
    try idx.entries.append(allocator, .{ .path = path, .status = .blob, .object_hash = h });

    try writeIndex(tmp.dir, &idx);

    var idx2 = try readIndex(allocator, tmp.dir);
    defer idx2.deinit();

    try std.testing.expectEqual(@as(usize, 1), idx2.entries.items.len);
    try std.testing.expectEqualStrings("test.txt", idx2.entries.items[0].path);
    try std.testing.expectEqual(h, idx2.entries.items[0].object_hash);
}

test "index addFile stages a file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create a file to stage
    const f = try tmp.dir.createFile("hello.txt", .{});
    try f.writeAll("hello world");
    f.close();

    // Init object store
    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var idx = Index.init(allocator);
    defer idx.deinit();

    try addFile(allocator, &store, tmp.dir, &idx, "hello.txt");

    try std.testing.expectEqual(@as(usize, 1), idx.entries.items.len);
    try std.testing.expectEqualStrings("hello.txt", idx.entries.items[0].path);
    try std.testing.expectEqual(EntryStatus.blob, idx.entries.items[0].status);

    // Verify the blob was stored
    try std.testing.expect(store.exists(idx.entries.items[0].object_hash));
}

test "index addFile updates existing entry" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Create and stage a file
    const f1 = try tmp.dir.createFile("hello.txt", .{});
    try f1.writeAll("version 1");
    f1.close();

    var idx = Index.init(allocator);
    defer idx.deinit();

    try addFile(allocator, &store, tmp.dir, &idx, "hello.txt");
    const hash1 = idx.entries.items[0].object_hash;

    // Update the file and re-stage
    const f2 = try tmp.dir.createFile("hello.txt", .{});
    try f2.writeAll("version 2");
    f2.close();

    try addFile(allocator, &store, tmp.dir, &idx, "hello.txt");

    // Should still be 1 entry, but with a different hash
    try std.testing.expectEqual(@as(usize, 1), idx.entries.items.len);
    try std.testing.expect(!std.mem.eql(u8, &hash1, &idx.entries.items[0].object_hash));
}

test "index removeFile marks entry as removed" {
    const allocator = std.testing.allocator;

    var idx = Index.init(allocator);
    defer idx.deinit();

    // Add an entry manually
    const path = try allocator.dupe(u8, "hello.txt");
    try idx.entries.append(allocator, .{
        .path = path,
        .status = .blob,
        .object_hash = hash_mod.hash("content"),
    });

    try removeFile(&idx, allocator, "hello.txt");

    try std.testing.expectEqual(@as(usize, 1), idx.entries.items.len);
    try std.testing.expectEqual(EntryStatus.removed, idx.entries.items[0].status);
}

test "index removeFile creates entry for untracked file" {
    const allocator = std.testing.allocator;

    var idx = Index.init(allocator);
    defer idx.deinit();

    try removeFile(&idx, allocator, "new_file.txt");

    try std.testing.expectEqual(@as(usize, 1), idx.entries.items.len);
    try std.testing.expectEqual(EntryStatus.removed, idx.entries.items[0].status);
    try std.testing.expectEqualStrings("new_file.txt", idx.entries.items[0].path);
    try std.testing.expectEqual(hash_mod.zero, idx.entries.items[0].object_hash);
}

test "index stagedCount excludes removed entries" {
    const allocator = std.testing.allocator;

    var idx = Index.init(allocator);
    defer idx.deinit();

    const p1 = try allocator.dupe(u8, "a.txt");
    const p2 = try allocator.dupe(u8, "b.txt");
    const p3 = try allocator.dupe(u8, "c.txt");
    try idx.entries.append(allocator, .{ .path = p1, .status = .blob, .object_hash = hash_mod.hash("a") });
    try idx.entries.append(allocator, .{ .path = p2, .status = .removed, .object_hash = hash_mod.zero });
    try idx.entries.append(allocator, .{ .path = p3, .status = .blob, .object_hash = hash_mod.hash("c") });

    try std.testing.expectEqual(@as(usize, 2), idx.stagedCount());
}

test "index buildTreeFromIndex flat" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    // Store some blobs
    const h1 = try store.put(allocator, object.Object{ .blob = .{ .data = "content a" } });
    const h2 = try store.put(allocator, object.Object{ .blob = .{ .data = "content b" } });

    var idx = Index.init(allocator);
    defer idx.deinit();

    const p1 = try allocator.dupe(u8, "a.txt");
    const p2 = try allocator.dupe(u8, "b.txt");
    try idx.entries.append(allocator, .{ .path = p1, .status = .blob, .object_hash = h1 });
    try idx.entries.append(allocator, .{ .path = p2, .status = .blob, .object_hash = h2 });

    const tree_hash = try buildTreeFromIndex(allocator, &store, &idx);

    var tree_obj = try store.get(allocator, tree_hash);
    defer tree_obj.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), tree_obj.tree.entries.len);
    try std.testing.expectEqualStrings("a.txt", tree_obj.tree.entries[0].name);
    try std.testing.expectEqualStrings("b.txt", tree_obj.tree.entries[1].name);
    try std.testing.expectEqual(h1, tree_obj.tree.entries[0].object_hash);
    try std.testing.expectEqual(h2, tree_obj.tree.entries[1].object_hash);
}

test "index buildTreeFromIndex nested directories" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const h1 = try store.put(allocator, object.Object{ .blob = .{ .data = "root file" } });
    const h2 = try store.put(allocator, object.Object{ .blob = .{ .data = "sub file" } });
    const h3 = try store.put(allocator, object.Object{ .blob = .{ .data = "deep file" } });

    var idx = Index.init(allocator);
    defer idx.deinit();

    const p1 = try allocator.dupe(u8, "README.md");
    const p2 = try allocator.dupe(u8, "src/main.zig");
    const p3 = try allocator.dupe(u8, "src/lib/utils.zig");
    try idx.entries.append(allocator, .{ .path = p1, .status = .blob, .object_hash = h1 });
    try idx.entries.append(allocator, .{ .path = p2, .status = .blob, .object_hash = h2 });
    try idx.entries.append(allocator, .{ .path = p3, .status = .blob, .object_hash = h3 });

    const tree_hash = try buildTreeFromIndex(allocator, &store, &idx);

    var root = try store.get(allocator, tree_hash);
    defer root.deinit(allocator);

    // Root should have README.md and src/
    try std.testing.expectEqual(@as(usize, 2), root.tree.entries.len);
    try std.testing.expectEqualStrings("README.md", root.tree.entries[0].name);
    try std.testing.expectEqual(object.EntryMode.blob, root.tree.entries[0].mode);
    try std.testing.expectEqualStrings("src", root.tree.entries[1].name);
    try std.testing.expectEqual(object.EntryMode.tree, root.tree.entries[1].mode);

    // src/ should have lib/ and main.zig
    var src = try store.get(allocator, root.tree.entries[1].object_hash);
    defer src.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), src.tree.entries.len);
    try std.testing.expectEqualStrings("lib", src.tree.entries[0].name);
    try std.testing.expectEqual(object.EntryMode.tree, src.tree.entries[0].mode);
    try std.testing.expectEqualStrings("main.zig", src.tree.entries[1].name);
    try std.testing.expectEqual(object.EntryMode.blob, src.tree.entries[1].mode);
}

test "index buildTreeFromIndex excludes removed entries" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    const h1 = try store.put(allocator, object.Object{ .blob = .{ .data = "kept" } });

    var idx = Index.init(allocator);
    defer idx.deinit();

    const p1 = try allocator.dupe(u8, "keep.txt");
    const p2 = try allocator.dupe(u8, "remove.txt");
    try idx.entries.append(allocator, .{ .path = p1, .status = .blob, .object_hash = h1 });
    try idx.entries.append(allocator, .{ .path = p2, .status = .removed, .object_hash = hash_mod.zero });

    const tree_hash = try buildTreeFromIndex(allocator, &store, &idx);

    var tree_obj = try store.get(allocator, tree_hash);
    defer tree_obj.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), tree_obj.tree.entries.len);
    try std.testing.expectEqualStrings("keep.txt", tree_obj.tree.entries[0].name);
}

test "index addAll stages all non-ignored files" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create files
    const f1 = try tmp.dir.createFile("a.txt", .{});
    try f1.writeAll("aaa");
    f1.close();
    const f2 = try tmp.dir.createFile("b.txt", .{});
    try f2.writeAll("bbb");
    f2.close();

    // Create an ignore file
    const ig = try tmp.dir.createFile(".mkitignore", .{});
    try ig.writeAll("*.log\n");
    ig.close();
    const f3 = try tmp.dir.createFile("debug.log", .{});
    try f3.writeAll("log stuff");
    f3.close();

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var idx = Index.init(allocator);
    defer idx.deinit();

    var work_dir = try tmp.dir.openDir(".", .{ .iterate = true });
    defer work_dir.close();

    try addAll(allocator, &store, work_dir, &idx);

    // Should have a.txt, b.txt, and .mkitignore but NOT debug.log
    try std.testing.expectEqual(@as(usize, 3), idx.entries.items.len);

    // Verify debug.log is not staged
    for (idx.entries.items) |entry| {
        try std.testing.expect(!std.mem.eql(u8, std.fs.path.basename(entry.path), "debug.log"));
    }
}

test "index corrupt data returns error" {
    const allocator = std.testing.allocator;

    // Bad magic
    const bad_magic = [_]u8{ 'B', 'A', 'D', '!' } ++ [_]u8{format_version} ++ std.mem.toBytes(std.mem.nativeToLittle(u32, @as(u32, 0)));
    try std.testing.expectError(error.IndexCorrupt, deserializeIndex(allocator, &bad_magic));

    // Too short
    try std.testing.expectError(error.IndexCorrupt, deserializeIndex(allocator, "ZMIX"));
}

test "reject path traversal in staged paths" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var idx = Index.init(allocator);
    defer idx.deinit();

    try std.testing.expectError(error.InvalidPath, addFile(allocator, &store, tmp.dir, &idx, "../secret.txt"));
    try std.testing.expectError(error.InvalidPath, removeFile(&idx, allocator, "../secret.txt"));
}

test "build commit tree preserves unstaged tracked files" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const base_a_hash = try store.put(allocator, object.Object{ .blob = .{ .data = "tracked-a" } });
    const base_b_hash = try store.put(allocator, object.Object{ .blob = .{ .data = "tracked-b" } });

    var base_entries = try allocator.alloc(object.TreeEntry, 2);
    base_entries[0] = .{ .name = try allocator.dupe(u8, "a.txt"), .mode = .blob, .object_hash = base_a_hash };
    base_entries[1] = .{ .name = try allocator.dupe(u8, "b.txt"), .mode = .blob, .object_hash = base_b_hash };
    var base_tree = object.Object{ .tree = .{ .entries = base_entries } };
    const base_tree_hash = try store.put(allocator, base_tree);
    base_tree.deinit(allocator);

    const staged_hash = try store.put(allocator, object.Object{ .blob = .{ .data = "updated-a" } });

    var idx = Index.init(allocator);
    defer idx.deinit();
    try idx.entries.append(allocator, .{
        .path = try allocator.dupe(u8, "a.txt"),
        .status = .blob,
        .object_hash = staged_hash,
    });

    const commit_tree_hash = try buildCommitTreeFromIndex(allocator, &store, base_tree_hash, &idx);
    var commit_tree = try store.get(allocator, commit_tree_hash);
    defer commit_tree.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), commit_tree.tree.entries.len);
    try std.testing.expectEqualStrings("a.txt", commit_tree.tree.entries[0].name);
    try std.testing.expectEqual(staged_hash, commit_tree.tree.entries[0].object_hash);
    try std.testing.expectEqualStrings("b.txt", commit_tree.tree.entries[1].name);
    try std.testing.expectEqual(base_b_hash, commit_tree.tree.entries[1].object_hash);
}

test "build commit tree applies staged removals without live additions" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const blob_hash = try store.put(allocator, object.Object{ .blob = .{ .data = "tracked" } });

    var entries = try allocator.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = try allocator.dupe(u8, "gone.txt"), .mode = .blob, .object_hash = blob_hash };
    var base_tree = object.Object{ .tree = .{ .entries = entries } };
    const base_tree_hash = try store.put(allocator, base_tree);
    base_tree.deinit(allocator);

    var idx = Index.init(allocator);
    defer idx.deinit();
    try idx.entries.append(allocator, .{
        .path = try allocator.dupe(u8, "gone.txt"),
        .status = .removed,
        .object_hash = hash_mod.zero,
    });

    const commit_tree_hash = try buildCommitTreeFromIndex(allocator, &store, base_tree_hash, &idx);
    var commit_tree = try store.get(allocator, commit_tree_hash);
    defer commit_tree.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), commit_tree.tree.entries.len);
}

test "build commit tree rejects conflicting staged paths" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const hash_a = try store.put(allocator, object.Object{ .blob = .{ .data = "a" } });
    const hash_b = try store.put(allocator, object.Object{ .blob = .{ .data = "b" } });

    var idx = Index.init(allocator);
    defer idx.deinit();
    try idx.entries.append(allocator, .{ .path = try allocator.dupe(u8, "a"), .status = .blob, .object_hash = hash_a });
    try idx.entries.append(allocator, .{ .path = try allocator.dupe(u8, "a/b.txt"), .status = .blob, .object_hash = hash_b });

    try std.testing.expectError(error.PathConflict, buildCommitTreeFromIndex(allocator, &store, null, &idx));
}
