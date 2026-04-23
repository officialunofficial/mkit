// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const refs = @import("refs.zig");
const worktree = @import("worktree.zig");
const restore = @import("restore.zig");
const diff_mod = @import("diff.zig");
const index_mod = @import("index.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const stash_file = ".mkit/stash";

/// Magic bytes for stash file format: "ZMST" (ZMit STash).
const magic: [4]u8 = .{ 'Z', 'M', 'S', 'T' };

pub const StashEntry = struct {
    commit_hash: Hash,
    parent_hash: Hash,
    timestamp: u32,
    message: []const u8,
};

pub const StashList = struct {
    entries: []StashEntry,
    allocator: Allocator,

    pub fn deinit(self: *StashList) void {
        for (self.entries) |entry| {
            self.allocator.free(entry.message);
        }
        self.allocator.free(self.entries);
    }
};

/// Save current working directory state as a stash entry.
/// Creates a commit from the working dir, appends to stash stack,
/// then restores working dir to HEAD's tree.
pub fn save(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    io: std.Io,
    cwd: std.Io.Dir,
    message: []const u8,
) !void {
    // Build tree from working dir
    var work_dir = try cwd.openDir(io, ".", .{ .iterate = true });
    defer work_dir.close(io);
    const tree_hash = try worktree.buildTree(allocator, io, store, work_dir);

    // Get HEAD
    const head_hash = try refs.resolveHead(allocator, io, cwd);

    // Get timestamp (u64 Unix seconds per SPEC-OBJECTS §5).
    const timestamp: u64 = @intCast(@max(@divTrunc(std.Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s), 0));

    // Create unsigned commit for stash (no signing needed)
    var parents_buf: [1]Hash = undefined;
    var parents: []Hash = undefined;
    if (head_hash) |ph| {
        parents_buf[0] = ph;
        parents = parents_buf[0..1];
    } else {
        parents = parents_buf[0..0];
    }

    // Stash commits use a zero-pubkey ed25519 Identity — stash is local-only
    // and never signed, so this is a canonical "unauthored" marker.
    const zero_pk = [_]u8{0} ** 32;
    const commit = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = .{ .kind = .ed25519, .bytes = zero_pk[0..] },
        .signer = .{0} ** 32,
        .message = message,
        .timestamp = timestamp,
        .signature = .{0} ** 64,
    } };
    const stash_hash = try store.put(allocator, commit);

    // Read existing stash list, prepend new entry, write back
    var stash_list = try readStashList(allocator, io, cwd);
    defer stash_list.deinit();

    // Build new entries list with prepended entry.
    // StashEntry on-disk format still uses u32 seconds — this sidecar is
    // unrelated to the core commit timestamp. Saturate rather than wrap.
    const ts_u32: u32 = if (timestamp > std.math.maxInt(u32))
        std.math.maxInt(u32)
    else
        @intCast(timestamp);
    const new_entries = try allocator.alloc(StashEntry, stash_list.entries.len + 1);
    new_entries[0] = .{
        .commit_hash = stash_hash,
        .parent_hash = head_hash orelse hash_mod.zero,
        .timestamp = ts_u32,
        .message = try allocator.dupe(u8, message),
    };
    for (stash_list.entries, 0..) |entry, i| {
        new_entries[i + 1] = .{
            .commit_hash = entry.commit_hash,
            .parent_hash = entry.parent_hash,
            .timestamp = entry.timestamp,
            .message = try allocator.dupe(u8, entry.message),
        };
    }

    // Write updated stash list
    try writeStashList(allocator, io, cwd, new_entries);

    // Free our new_entries (writeStashList doesn't take ownership)
    for (new_entries) |entry| {
        allocator.free(entry.message);
    }
    allocator.free(new_entries);

    // Restore working dir to HEAD's tree
    if (head_hash) |hh| {
        var head_obj = try store.get(allocator, hh);
        defer head_obj.deinit(allocator);
        if (head_obj == .commit) {
            var restore_dir = try cwd.openDir(io, ".", .{ .iterate = true });
            defer restore_dir.close(io);
            try restore.restoreTree(allocator, io, store, head_obj.commit.tree_hash, restore_dir, .{});
        }
    }

    // Clear index
    var empty_idx = index_mod.Index.init(allocator);
    defer empty_idx.deinit();
    index_mod.writeIndex(io, cwd, &empty_idx) catch {};
}

/// List all stash entries (newest first).
pub fn list(allocator: Allocator, io: std.Io, cwd: std.Io.Dir) !StashList {
    return readStashList(allocator, io, cwd);
}

/// Pop: apply stash entry to working dir and remove from stack.
pub fn pop(
    allocator: Allocator,
    io: std.Io,
    store: *store_mod.ObjectStore,
    cwd: std.Io.Dir,
    index: usize,
) !void {
    var stash_list = try readStashList(allocator, io, cwd);
    defer stash_list.deinit();

    if (index >= stash_list.entries.len) return error.StashIndexOutOfRange;

    const entry = stash_list.entries[index];

    // Load stash commit -> tree_hash
    var commit_obj = try store.get(allocator, entry.commit_hash);
    defer commit_obj.deinit(allocator);
    if (commit_obj != .commit) return error.NotACommit;

    // Restore working dir to stash tree
    var restore_dir = try cwd.openDir(io, ".", .{ .iterate = true });
    defer restore_dir.close(io);
    try restore.restoreTree(allocator, io, store, commit_obj.commit.tree_hash, restore_dir, .{});

    // Remove entry from list, write back
    const new_len = stash_list.entries.len - 1;
    const new_entries = try allocator.alloc(StashEntry, new_len);
    defer {
        for (new_entries) |e| allocator.free(e.message);
        allocator.free(new_entries);
    }
    var j: usize = 0;
    for (stash_list.entries, 0..) |e, i| {
        if (i == index) continue;
        new_entries[j] = .{
            .commit_hash = e.commit_hash,
            .parent_hash = e.parent_hash,
            .timestamp = e.timestamp,
            .message = try allocator.dupe(u8, e.message),
        };
        j += 1;
    }

    try writeStashList(allocator, io, cwd, new_entries);
}

/// Drop: remove stash entry without applying.
pub fn drop(allocator: Allocator, io: std.Io, cwd: std.Io.Dir, index: usize) !void {
    var stash_list = try readStashList(allocator, io, cwd);
    defer stash_list.deinit();

    if (index >= stash_list.entries.len) return error.StashIndexOutOfRange;

    // Remove entry from list, write back
    const new_len = stash_list.entries.len - 1;
    const new_entries = try allocator.alloc(StashEntry, new_len);
    defer {
        for (new_entries) |e| allocator.free(e.message);
        allocator.free(new_entries);
    }
    var j: usize = 0;
    for (stash_list.entries, 0..) |e, i| {
        if (i == index) continue;
        new_entries[j] = .{
            .commit_hash = e.commit_hash,
            .parent_hash = e.parent_hash,
            .timestamp = e.timestamp,
            .message = try allocator.dupe(u8, e.message),
        };
        j += 1;
    }

    try writeStashList(allocator, io, cwd, new_entries);
}

/// Show: diff stash tree vs parent tree.
pub fn show(
    allocator: Allocator,
    io: std.Io,
    store: *store_mod.ObjectStore,
    cwd: std.Io.Dir,
    index: usize,
) !diff_mod.DiffResult {
    var stash_list = try readStashList(allocator, io, cwd);
    defer stash_list.deinit();

    if (index >= stash_list.entries.len) return error.StashIndexOutOfRange;

    const entry = stash_list.entries[index];

    // Load stash commit -> tree_hash
    var stash_obj = try store.get(allocator, entry.commit_hash);
    defer stash_obj.deinit(allocator);
    if (stash_obj != .commit) return error.NotACommit;

    // Load parent commit -> tree_hash (if parent is not zero)
    var parent_tree: ?Hash = null;
    if (!std.mem.eql(u8, &entry.parent_hash, &hash_mod.zero)) {
        var parent_obj = try store.get(allocator, entry.parent_hash);
        defer parent_obj.deinit(allocator);
        if (parent_obj == .commit) {
            parent_tree = parent_obj.commit.tree_hash;
        }
    }

    return diff_mod.diffTrees(allocator, store, parent_tree, stash_obj.commit.tree_hash);
}

// -- Binary stash manifest read/write --

fn readStashList(allocator: Allocator, io: std.Io, cwd: std.Io.Dir) !StashList {
    const file = cwd.openFile(io, stash_file, .{}) catch |err| switch (err) {
        error.FileNotFound => return StashList{
            .entries = try allocator.alloc(StashEntry, 0),
            .allocator = allocator,
        },
        else => return err,
    };
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size == 0) return StashList{
        .entries = try allocator.alloc(StashEntry, 0),
        .allocator = allocator,
    };
    if (stat.size > 16 * 1024 * 1024) return error.StashTooLarge; // 16MB safety limit

    const data = try allocator.alloc(u8, stat.size);
    defer allocator.free(data);
    const read = try file.readPositionalAll(io, data, 0);
    if (read != stat.size) return error.UnexpectedEof;

    return deserializeStashList(allocator, data[0..read]);
}

fn deserializeStashList(allocator: Allocator, data: []const u8) !StashList {
    if (data.len < 8) return error.InvalidStashFormat; // magic(4) + count(4)

    // Check magic
    if (!std.mem.eql(u8, data[0..4], &magic)) return error.InvalidStashFormat;

    // Read count
    const count = std.mem.readInt(u32, data[4..8], .little);

    var entries = try allocator.alloc(StashEntry, count);
    errdefer {
        for (entries[0..0]) |entry| allocator.free(entry.message);
        allocator.free(entries);
    }

    var pos: usize = 8;
    var initialized: usize = 0;
    errdefer {
        for (entries[0..initialized]) |entry| allocator.free(entry.message);
    }

    for (0..count) |i| {
        if (pos + 32 + 32 + 4 + 2 > data.len) return error.InvalidStashFormat;

        const commit_hash = data[pos..][0..32].*;
        pos += 32;
        const parent_hash = data[pos..][0..32].*;
        pos += 32;
        const timestamp = std.mem.readInt(u32, data[pos..][0..4], .little);
        pos += 4;
        const msg_len = std.mem.readInt(u16, data[pos..][0..2], .little);
        pos += 2;

        if (pos + msg_len > data.len) return error.InvalidStashFormat;
        const msg = try allocator.dupe(u8, data[pos..][0..msg_len]);
        pos += msg_len;

        entries[i] = .{
            .commit_hash = commit_hash,
            .parent_hash = parent_hash,
            .timestamp = timestamp,
            .message = msg,
        };
        initialized += 1;
    }

    return StashList{
        .entries = entries,
        .allocator = allocator,
    };
}

fn writeStashList(allocator: Allocator, io: std.Io, cwd: std.Io.Dir, entries: []const StashEntry) !void {
    // Calculate total size
    var total_size: usize = 4 + 4; // magic + count
    for (entries) |entry| {
        total_size += 32 + 32 + 4 + 2 + entry.message.len; // commit_hash + parent_hash + timestamp + msg_len + msg
    }

    const data = try allocator.alloc(u8, total_size);
    defer allocator.free(data);

    // Write magic
    @memcpy(data[0..4], &magic);

    // Write count
    std.mem.writeInt(u32, data[4..8], @intCast(entries.len), .little);

    var pos: usize = 8;
    for (entries) |entry| {
        @memcpy(data[pos..][0..32], &entry.commit_hash);
        pos += 32;
        @memcpy(data[pos..][0..32], &entry.parent_hash);
        pos += 32;
        std.mem.writeInt(u32, data[pos..][0..4], entry.timestamp, .little);
        pos += 4;
        std.mem.writeInt(u16, data[pos..][0..2], @intCast(entry.message.len), .little);
        pos += 2;
        @memcpy(data[pos..][0..entry.message.len], entry.message);
        pos += entry.message.len;
    }

    try writeAtomicFile(io, cwd, stash_file, data);
}

fn writeAtomicFile(io: std.Io, dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    var atomic_file = try dir.createFileAtomic(io, path, .{
        .make_path = true,
        .replace = true,
    });
    defer atomic_file.deinit(io);
    var write_buffer: [4096]u8 = undefined;
    var file_writer = atomic_file.file.writer(io, &write_buffer);
    try file_writer.interface.writeAll(data);
    try file_writer.interface.flush();
    try file_writer.file.sync(io);
    try atomic_file.replace(io);
}

// -- Helper: set up a test repo with a store, refs, and an initial commit --

fn initTestRepo(_: Allocator) !struct {
    tmp: std.testing.TmpDir,
    store_tmp: std.testing.TmpDir,
    store: store_mod.ObjectStore,

    fn deinit(self: *@This()) void {
        self.store.close();
        self.store_tmp.cleanup();
        self.tmp.cleanup();
    }
} {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");
    try refs.init(std.testing.io, tmp.dir);

    var store_tmp = std.testing.tmpDir(.{});
    errdefer store_tmp.cleanup();
    const store = try store_mod.ObjectStore.init(std.testing.io, store_tmp.dir);

    return .{
        .tmp = tmp,
        .store_tmp = store_tmp,
        .store = store,
    };
}

/// Create a file, build tree, commit, update HEAD, return commit hash.
fn makeTestCommit(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    dir: std.Io.Dir,
    file_name: []const u8,
    file_content: []const u8,
    message: []const u8,
) !Hash {
    // Write file
    const f = try dir.createFile(std.testing.io, file_name, .{});
    try f.writeStreamingAll(std.testing.io, file_content);
    f.close(std.testing.io);

    // Build tree
    var work_dir = try dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer work_dir.close(std.testing.io);
    const tree_hash = try worktree.buildTree(allocator, std.testing.io, store, work_dir);

    // Get parent
    const parent_hash = try refs.resolveHead(allocator, std.testing.io, dir);
    var parents_buf: [1]Hash = undefined;
    var parents: []Hash = undefined;
    if (parent_hash) |ph| {
        parents_buf[0] = ph;
        parents = parents_buf[0..1];
    } else {
        parents = parents_buf[0..0];
    }

    // Create commit
    const zero_pk = [_]u8{0} ** 32;
    const commit = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = .{ .kind = .ed25519, .bytes = zero_pk[0..] },
        .signer = .{0} ** 32,
        .message = message,
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    const commit_hash = try store.put(allocator, commit);

    // Update HEAD
    try refs.updateHead(allocator, std.testing.io, dir, commit_hash);

    return commit_hash;
}

// ========================
// Tests
// ========================

test "stash save creates entry" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Modify file
    const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "modified content");
    f.close(std.testing.io);

    // Stash
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP changes");

    // List should have 1 entry
    var stash_list = try list(allocator, std.testing.io, repo.tmp.dir);
    defer stash_list.deinit();
    try std.testing.expectEqual(@as(usize, 1), stash_list.entries.len);
    try std.testing.expectEqualStrings("WIP changes", stash_list.entries[0].message);
}

test "stash restores clean state" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit with "original"
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Modify file
    const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "modified content");
    f.close(std.testing.io);

    // Stash
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP");

    // Working dir should be back to "original"
    const content = try repo.tmp.dir.readFileAlloc(std.testing.io, "hello.txt", allocator, .limited(4096));
    defer allocator.free(content);
    try std.testing.expectEqualStrings("original", content);
}

test "stash pop restores changes" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Modify file
    const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "modified content");
    f.close(std.testing.io);

    // Stash
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP");

    // Pop
    try pop(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0);

    // File should have the modification again
    const content = try repo.tmp.dir.readFileAlloc(std.testing.io, "hello.txt", allocator, .limited(4096));
    defer allocator.free(content);
    try std.testing.expectEqualStrings("modified content", content);
}

test "stash pop removes from list" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Modify and stash
    const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "modified");
    f.close(std.testing.io);
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP");

    // Pop
    try pop(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0);

    // List should be empty
    var stash_list = try list(allocator, std.testing.io, repo.tmp.dir);
    defer stash_list.deinit();
    try std.testing.expectEqual(@as(usize, 0), stash_list.entries.len);
}

test "stash drop removes without applying" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Modify and stash
    const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
    try f.writeStreamingAll(std.testing.io, "modified");
    f.close(std.testing.io);
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP");

    // Drop (don't apply)
    try drop(allocator, std.testing.io, repo.tmp.dir, 0);

    // List should be empty
    var stash_list = try list(allocator, std.testing.io, repo.tmp.dir);
    defer stash_list.deinit();
    try std.testing.expectEqual(@as(usize, 0), stash_list.entries.len);

    // Working dir should still be clean (HEAD state, not stash state)
    const content = try repo.tmp.dir.readFileAlloc(std.testing.io, "hello.txt", allocator, .limited(4096));
    defer allocator.free(content);
    try std.testing.expectEqualStrings("original", content);
}

test "multiple stashes LIFO" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit with file A
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "a.txt", "original-a", "initial commit");

    // Modify A, stash
    {
        const f = try repo.tmp.dir.createFile(std.testing.io, "a.txt", .{});
        try f.writeStreamingAll(std.testing.io, "modified-a");
        f.close(std.testing.io);
    }
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "stash A");

    // Modify A again differently, stash
    {
        const f = try repo.tmp.dir.createFile(std.testing.io, "a.txt", .{});
        try f.writeStreamingAll(std.testing.io, "modified-a-again");
        f.close(std.testing.io);
    }
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "stash B");

    // List should have 2 entries, newest first
    {
        var stash_list = try list(allocator, std.testing.io, repo.tmp.dir);
        defer stash_list.deinit();
        try std.testing.expectEqual(@as(usize, 2), stash_list.entries.len);
        try std.testing.expectEqualStrings("stash B", stash_list.entries[0].message);
        try std.testing.expectEqualStrings("stash A", stash_list.entries[1].message);
    }

    // Pop gives B's changes first (LIFO)
    try pop(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0);
    const content_b = try repo.tmp.dir.readFileAlloc(std.testing.io, "a.txt", allocator, .limited(4096));
    defer allocator.free(content_b);
    try std.testing.expectEqualStrings("modified-a-again", content_b);

    // Pop gives A's changes next
    try pop(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0);
    const content_a = try repo.tmp.dir.readFileAlloc(std.testing.io, "a.txt", allocator, .limited(4096));
    defer allocator.free(content_a);
    try std.testing.expectEqualStrings("modified-a", content_a);

    // List should be empty
    var stash_list = try list(allocator, std.testing.io, repo.tmp.dir);
    defer stash_list.deinit();
    try std.testing.expectEqual(@as(usize, 0), stash_list.entries.len);
}

test "stash show diffs against parent" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Create initial commit
    _ = try makeTestCommit(allocator, &repo.store, repo.tmp.dir, "hello.txt", "original", "initial commit");

    // Add a new file and modify existing
    {
        const f = try repo.tmp.dir.createFile(std.testing.io, "hello.txt", .{});
        try f.writeStreamingAll(std.testing.io, "modified");
        f.close(std.testing.io);
    }
    {
        const f = try repo.tmp.dir.createFile(std.testing.io, "new.txt", .{});
        try f.writeStreamingAll(std.testing.io, "brand new");
        f.close(std.testing.io);
    }

    // Stash
    try save(allocator, &repo.store, std.testing.io, repo.tmp.dir, "WIP with new file");

    // Show should show the diff
    var diff_result = try show(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0);
    defer diff_result.deinit();

    // Should have 2 changes: hello.txt modified, new.txt added
    try std.testing.expectEqual(@as(usize, 2), diff_result.entries.len);

    // Entries are sorted by path
    var found_hello = false;
    var found_new = false;
    for (diff_result.entries) |entry| {
        if (std.mem.eql(u8, entry.path, "hello.txt")) {
            try std.testing.expectEqual(diff_mod.DiffKind.modified, entry.kind);
            found_hello = true;
        } else if (std.mem.eql(u8, entry.path, "new.txt")) {
            try std.testing.expectEqual(diff_mod.DiffKind.added, entry.kind);
            found_new = true;
        }
    }
    try std.testing.expect(found_hello);
    try std.testing.expect(found_new);
}

test "stash index out of range" {
    const allocator = std.testing.allocator;

    var repo = try initTestRepo(allocator);
    defer repo.deinit();

    // Pop on empty stash
    try std.testing.expectError(error.StashIndexOutOfRange, pop(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0));
    try std.testing.expectError(error.StashIndexOutOfRange, drop(allocator, std.testing.io, repo.tmp.dir, 0));
    try std.testing.expectError(error.StashIndexOutOfRange, show(allocator, std.testing.io, &repo.store, repo.tmp.dir, 0));
}

test "stash manifest roundtrip" {
    const allocator = std.testing.allocator;

    const entries = [_]StashEntry{
        .{
            .commit_hash = hash_mod.hash("commit1"),
            .parent_hash = hash_mod.hash("parent1"),
            .timestamp = 1000,
            .message = "first stash",
        },
        .{
            .commit_hash = hash_mod.hash("commit2"),
            .parent_hash = hash_mod.zero,
            .timestamp = 2000,
            .message = "second stash",
        },
    };

    // Calculate total size for serialization
    var total_size: usize = 4 + 4;
    for (&entries) |*entry| {
        total_size += 32 + 32 + 4 + 2 + entry.message.len;
    }

    const data = try allocator.alloc(u8, total_size);
    defer allocator.free(data);

    // Write magic
    @memcpy(data[0..4], &magic);
    std.mem.writeInt(u32, data[4..8], 2, .little);

    var pos: usize = 8;
    for (&entries) |*entry| {
        @memcpy(data[pos..][0..32], &entry.commit_hash);
        pos += 32;
        @memcpy(data[pos..][0..32], &entry.parent_hash);
        pos += 32;
        std.mem.writeInt(u32, data[pos..][0..4], entry.timestamp, .little);
        pos += 4;
        std.mem.writeInt(u16, data[pos..][0..2], @intCast(entry.message.len), .little);
        pos += 2;
        @memcpy(data[pos..][0..entry.message.len], entry.message);
        pos += entry.message.len;
    }

    // Deserialize
    var result = try deserializeStashList(allocator, data);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.entries.len);
    try std.testing.expectEqual(entries[0].commit_hash, result.entries[0].commit_hash);
    try std.testing.expectEqual(entries[0].parent_hash, result.entries[0].parent_hash);
    try std.testing.expectEqual(@as(u32, 1000), result.entries[0].timestamp);
    try std.testing.expectEqualStrings("first stash", result.entries[0].message);
    try std.testing.expectEqual(entries[1].commit_hash, result.entries[1].commit_hash);
    try std.testing.expectEqual(hash_mod.zero, result.entries[1].parent_hash);
    try std.testing.expectEqual(@as(u32, 2000), result.entries[1].timestamp);
    try std.testing.expectEqualStrings("second stash", result.entries[1].message);
}
