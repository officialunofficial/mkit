// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const serialize_mod = @import("serialize.zig");
const object = @import("object.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const mkit_dir = ".mkit";
pub const objects_dir = "objects";

/// Local content-addressed object store backed by the filesystem.
/// Objects are stored at `.mkit/objects/<2-hex>/<62-hex>`.
pub const ObjectStore = struct {
    io: Io,
    root: Io.Dir,

    /// Returns true when `dir` is the repository root that contains `.mkit/objects`.
    pub fn isRepoRoot(io: Io, dir: Io.Dir) bool {
        dir.access(io, mkit_dir ++ "/" ++ objects_dir, .{}) catch return false;
        return true;
    }

    /// Open the object store rooted in `dir`.
    ///
    /// Commands intentionally require the repository root so refs, index, config,
    /// and worktree operations all use the same base directory.
    pub fn open(io: Io, dir: Io.Dir) !ObjectStore {
        const obj_dir = dir.openDir(io, mkit_dir ++ "/" ++ objects_dir, .{}) catch {
            return error.NotAMkitRepository;
        };
        return .{ .io = io, .root = obj_dir };
    }

    /// Initialize a new .mkit repository in the given directory.
    pub fn init(io: Io, dir: Io.Dir) !ObjectStore {
        dir.createDir(io, mkit_dir, .default_dir) catch |err| switch (err) {
            error.PathAlreadyExists => return error.AlreadyInitialized,
            else => return err,
        };
        try dir.createDirPath(io, mkit_dir ++ "/" ++ objects_dir);
        const obj_dir = try dir.openDir(io, mkit_dir ++ "/" ++ objects_dir, .{});
        return .{ .io = io, .root = obj_dir };
    }

    pub fn close(self: *ObjectStore) void {
        self.root.close(self.io);
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
        self.root.createDirPath(self.io, &path.dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        var sub = try self.root.openDir(self.io, &path.dir, .{});
        defer sub.close(self.io);
        try writeAtomicBytes(self.io, sub, &path.file, bytes);

        return h;
    }

    /// Read raw bytes for an object hash.
    pub fn getRaw(self: *ObjectStore, allocator: Allocator, h: Hash) ![]u8 {
        const path = hash_mod.objectPath(h);
        var sub = self.root.openDir(self.io, &path.dir, .{}) catch return error.ObjectNotFound;
        defer sub.close(self.io);
        const file = sub.openFile(self.io, &path.file, .{}) catch return error.ObjectNotFound;
        defer file.close(self.io);

        const size = try file.length(self.io);
        if (size > 1024 * 1024 * 1024) return error.ObjectTooLarge; // 1GB safety limit
        const bytes = try allocator.alloc(u8, size);
        errdefer allocator.free(bytes);
        const read = try file.readPositionalAll(self.io, bytes, 0);
        if (read != size) return error.UnexpectedEof;

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
        var sub = self.root.openDir(self.io, &path.dir, .{}) catch return false;
        defer sub.close(self.io);
        const file = sub.openFile(self.io, &path.file, .{}) catch return false;
        file.close(self.io);
        return true;
    }
};

fn writeAtomicBytes(io: Io, dir: Io.Dir, path: []const u8, bytes: []const u8) !void {
    var atomic_file = try dir.createFileAtomic(io, path, .{
        .replace = true,
    });
    defer atomic_file.deinit(io);

    var buffer: [4096]u8 = undefined;
    var file_writer = atomic_file.file.writer(io, &buffer);
    try file_writer.interface.writeAll(bytes);
    try file_writer.interface.flush();
    try file_writer.file.sync(io);
    try atomic_file.replace(io);
}

// -- Tests --

test "init and put/get roundtrip" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

    const blob_obj = object.Object{ .blob = .{ .data = "test content" } };
    const h = try store.put(allocator, blob_obj);

    try std.testing.expect(store.exists(h));

    var retrieved = try store.get(allocator, h);
    defer retrieved.deinit(allocator);
    try std.testing.expectEqualStrings("test content", retrieved.blob.data);
}

test "put is idempotent" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

    const obj = object.Object{ .blob = .{ .data = "duplicate" } };
    const h1 = try store.put(allocator, obj);
    const h2 = try store.put(allocator, obj);
    try std.testing.expectEqual(h1, h2);
}

test "nonexistent object" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

    const fake_hash = hash_mod.hash("nonexistent");
    try std.testing.expect(!store.exists(fake_hash));
}

test "already initialized" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    store.close();

    const result = ObjectStore.init(io, tmp.dir);
    try std.testing.expectError(error.AlreadyInitialized, result);
}

test "is repo root only at repository root" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect(!ObjectStore.isRepoRoot(io, tmp.dir));

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

    try std.testing.expect(ObjectStore.isRepoRoot(io, tmp.dir));

    try tmp.dir.createDirPath(std.testing.io, "nested");
    var nested = try tmp.dir.openDir(std.testing.io, "nested", .{});
    defer nested.close(io);
    try std.testing.expect(!ObjectStore.isRepoRoot(io, nested));
}

test "open rejects subdirectories inside a repository" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

    try tmp.dir.createDirPath(std.testing.io, "nested");
    var nested = try tmp.dir.openDir(std.testing.io, "nested", .{});
    defer nested.close(io);

    try std.testing.expectError(error.NotAMkitRepository, ObjectStore.open(io, nested));
}

test "store chunked blob" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try ObjectStore.init(io, tmp.dir);
    defer store.close();

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

    try std.testing.expect(store.exists(h));

    var retrieved = try store.get(allocator, h);
    defer retrieved.deinit(allocator);
    try std.testing.expectEqual(object.ObjectType.chunked_blob, retrieved.objectType());
    try std.testing.expectEqual(@as(u64, 2 * 65536), retrieved.chunked_blob.total_size);
    try std.testing.expectEqual(@as(u32, 65536), retrieved.chunked_blob.chunk_size);
    try std.testing.expectEqual(@as(usize, 2), retrieved.chunked_blob.chunks.len);
}
