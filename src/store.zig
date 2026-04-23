// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const serialize_mod = @import("serialize.zig");
const object = @import("object.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const mkit_dir = ".mkit";
pub const objects_dir = "objects";

/// Local content-addressed object store backed by the filesystem.
/// Objects are stored at `.mkit/objects/<2-hex>/<62-hex>`.
pub const ObjectStore = struct {
    root: std.fs.Dir,

    /// Returns true when `dir` is the repository root that contains `.mkit/objects`.
    pub fn isRepoRoot(dir: std.fs.Dir) bool {
        dir.access(mkit_dir ++ "/" ++ objects_dir, .{}) catch return false;
        return true;
    }

    /// Open the object store rooted in `dir`.
    ///
    /// Commands intentionally require the repository root so refs, index, config,
    /// and worktree operations all use the same base directory.
    pub fn open(dir: std.fs.Dir) !ObjectStore {
        const obj_dir = dir.openDir(mkit_dir ++ "/" ++ objects_dir, .{}) catch {
            return error.NotAZmitRepository;
        };
        return .{ .root = obj_dir };
    }

    /// Initialize a new .mkit repository in the given directory.
    pub fn init(dir: std.fs.Dir) !ObjectStore {
        dir.makeDir(mkit_dir) catch |err| switch (err) {
            error.PathAlreadyExists => return error.AlreadyInitialized,
            else => return err,
        };
        const obj_dir = try dir.makeOpenPath(mkit_dir ++ "/" ++ objects_dir, .{});
        return .{ .root = obj_dir };
    }

    pub fn close(self: *ObjectStore) void {
        self.root.close();
    }

    /// Store an object, returning its content hash.
    pub fn put(self: *ObjectStore, allocator: Allocator, obj: object.Object) !Hash {
        const bytes = try serialize_mod.serialize(allocator, obj);
        defer allocator.free(bytes);
        return self.putRaw(bytes);
    }

    /// Store raw serialized bytes, returning their content hash.
    pub fn putRaw(self: *ObjectStore, bytes: []const u8) !Hash {
        const h = hash_mod.hash(bytes);
        const path = hash_mod.objectPath(h);

        // Ensure shard directory exists
        self.root.makeDir(&path.dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var sub = try self.root.openDir(&path.dir, .{});
        defer sub.close();
        try writeAtomicBytes(sub, &path.file, bytes);

        return h;
    }

    /// Read raw bytes for an object hash.
    pub fn getRaw(self: *ObjectStore, allocator: Allocator, h: Hash) ![]u8 {
        const path = hash_mod.objectPath(h);
        var sub = self.root.openDir(&path.dir, .{}) catch return error.ObjectNotFound;
        defer sub.close();
        const file = sub.openFile(&path.file, .{}) catch return error.ObjectNotFound;
        defer file.close();

        const stat = try file.stat();
        if (stat.size > 1024 * 1024 * 1024) return error.ObjectTooLarge; // 1GB safety limit
        const bytes = try allocator.alloc(u8, stat.size);
        errdefer allocator.free(bytes);
        const read = try file.readAll(bytes);
        if (read != stat.size) return error.UnexpectedEof;

        // Verify integrity
        const actual = hash_mod.hash(bytes);
        if (!std.mem.eql(u8, &actual, &h)) return error.HashMismatch;

        return bytes;
    }

    /// Read and deserialize an object.
    pub fn get(self: *ObjectStore, allocator: Allocator, h: Hash) !object.Object {
        const bytes = try self.getRaw(allocator, h);
        defer allocator.free(bytes);
        return serialize_mod.deserialize(allocator, bytes);
    }

    /// Check if an object exists.
    pub fn exists(self: *ObjectStore, h: Hash) bool {
        const path = hash_mod.objectPath(h);
        var sub = self.root.openDir(&path.dir, .{}) catch return false;
        defer sub.close();
        const file = sub.openFile(&path.file, .{}) catch return false;
        file.close();
        return true;
    }
};

fn writeAtomicBytes(dir: std.fs.Dir, path: []const u8, bytes: []const u8) !void {
    var write_buffer: [4096]u8 = undefined;
    var atomic_file = try dir.atomicFile(path, .{
        .mode = std.fs.File.default_mode,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    try atomic_file.file_writer.interface.writeAll(bytes);
    try atomic_file.flush();
    try atomic_file.file_writer.file.sync();
    try atomic_file.renameIntoPlace();
}

// -- Tests --

test "init and put/get roundtrip" {
    const allocator = std.testing.allocator;

    // Create a temp directory
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Init store
    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    // Store a blob
    const blob_obj = object.Object{ .blob = .{ .data = "test content" } };
    const h = try store.put(allocator, blob_obj);

    // Verify it exists
    try std.testing.expect(store.exists(h));

    // Read it back
    var retrieved = try store.get(allocator, h);
    defer retrieved.deinit(allocator);
    try std.testing.expectEqualStrings("test content", retrieved.blob.data);
}

test "put is idempotent" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    const obj = object.Object{ .blob = .{ .data = "duplicate" } };
    const h1 = try store.put(allocator, obj);
    const h2 = try store.put(allocator, obj);
    try std.testing.expectEqual(h1, h2);
}

test "nonexistent object" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    const fake_hash = hash_mod.hash("nonexistent");
    try std.testing.expect(!store.exists(fake_hash));
}

test "already initialized" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(tmp.dir);
    store.close();

    // Second init should fail
    const result = ObjectStore.init(tmp.dir);
    try std.testing.expectError(error.AlreadyInitialized, result);
}

test "is repo root only at repository root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect(!ObjectStore.isRepoRoot(tmp.dir));

    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    try std.testing.expect(ObjectStore.isRepoRoot(tmp.dir));

    try tmp.dir.createDirPath(std.testing.io, "nested");
    var nested = try tmp.dir.openDir(std.testing.io, "nested", .{});
    defer nested.close();
    try std.testing.expect(!ObjectStore.isRepoRoot(nested));
}

test "open rejects subdirectories inside a repository" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    try tmp.dir.createDirPath(std.testing.io, "nested");
    var nested = try tmp.dir.openDir(std.testing.io, "nested", .{});
    defer nested.close();

    try std.testing.expectError(error.NotAZmitRepository, ObjectStore.open(nested));
}

test "store chunked blob" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(tmp.dir);
    defer store.close();

    // Create chunk hashes
    var chunks = try allocator.alloc(hash_mod.Hash, 2);
    chunks[0] = hash_mod.hash("chunk-0");
    chunks[1] = hash_mod.hash("chunk-1");

    var cb_obj = object.Object{ .chunked_blob = .{
        .total_size = 2 * 65536,
        .chunk_size = 65536,
        .chunks = chunks,
    } };
    const h = try store.put(allocator, cb_obj);
    cb_obj.deinit(allocator);

    // Verify it exists
    try std.testing.expect(store.exists(h));

    // Read it back
    var retrieved = try store.get(allocator, h);
    defer retrieved.deinit(allocator);
    try std.testing.expectEqual(object.ObjectType.chunked_blob, retrieved.objectType());
    try std.testing.expectEqual(@as(u64, 2 * 65536), retrieved.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 65536), retrieved.chunked_blob.chunk_size);
    try std.testing.expectEqual(@as(usize, 2), retrieved.chunked_blob.chunks.len);
}
