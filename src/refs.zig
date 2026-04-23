// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const protocol = @import("protocol.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const refs_dir = ".mkit/refs";
pub const heads_dir = ".mkit/refs/heads";
pub const tags_dir = ".mkit/refs/tags";
pub const head_file = ".mkit/HEAD";

pub const Ref = struct {
    name: []const u8,
    hash: ?Hash,
};

/// List all branch refs. Caller owns returned slice and must free names and slice.
pub fn listRefs(allocator: Allocator, dir: std.fs.Dir) ![]Ref {
    return listRefsFromDir(allocator, dir, heads_dir);
}

/// Delete a branch ref. Returns error if ref doesn't exist.
pub fn deleteRef(dir: std.fs.Dir, branch: []const u8) !void {
    if (!protocol.validateRefName(branch)) return error.InvalidRefName;
    deleteRefFromDir(dir, heads_dir, branch) catch |err| switch (err) {
        error.NotFound => return error.RefNotFound,
        else => return err,
    };
}

/// Delete a branch ref, checking it's not the current branch.
pub fn deleteRefSafe(allocator: Allocator, dir: std.fs.Dir, branch: []const u8) !void {
    const head = readHead(allocator, dir) catch return deleteRef(dir, branch);
    switch (head) {
        .branch => |current_branch| {
            defer allocator.free(current_branch);
            if (std.mem.eql(u8, current_branch, branch)) {
                return error.CannotDeleteCurrentBranch;
            }
            return deleteRef(dir, branch);
        },
        .detached => return deleteRef(dir, branch),
    }
}

pub const Head = union(enum) {
    /// HEAD points to a branch: "ref: refs/heads/<name>"
    branch: []const u8,
    /// HEAD is detached at a specific commit hash
    detached: Hash,
};

/// Initialize ref storage directories.
pub fn init(dir: std.fs.Dir) !void {
    dir.makeDir(refs_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    dir.makeDir(heads_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    dir.makeDir(tags_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    // Create default HEAD pointing to main
    const f = dir.createFile(head_file, .{ .exclusive = true }) catch |err| switch (err) {
        error.PathAlreadyExists => return, // Already initialized
        else => return err,
    };
    defer f.close();
    try f.writeAll("ref: refs/heads/main\n");
}

/// Read HEAD. Caller must free branch name if Head is .branch.
pub fn readHead(allocator: Allocator, dir: std.fs.Dir) !Head {
    const content = dir.readFileAlloc(allocator, head_file, 4096) catch return error.NoHead;
    defer allocator.free(content);

    const trimmed = std.mem.trimEnd(u8, content, "\n\r ");

    if (std.mem.startsWith(u8, trimmed, "ref: refs/heads/")) {
        const branch_name = trimmed["ref: refs/heads/".len..];
        if (!protocol.validateRefName(branch_name)) return error.InvalidHead;
        return .{ .branch = try allocator.dupe(u8, branch_name) };
    }

    // Try to parse as hex hash
    if (trimmed.len == 64) {
        const h = hash_mod.fromHex(trimmed) catch return error.InvalidHead;
        return .{ .detached = h };
    }

    return error.InvalidHead;
}

/// Write HEAD as a symbolic ref to a branch.
pub fn writeHeadBranch(dir: std.fs.Dir, branch: []const u8) !void {
    if (!protocol.validateRefName(branch)) return error.InvalidRefName;
    var buf: [128]u8 = undefined;
    const data = try std.fmt.bufPrint(&buf, "ref: refs/heads/{s}\n", .{branch});
    try writeAtomicFile(dir, head_file, data, false);
}

/// Write HEAD as a detached hash.
pub fn writeHeadDetached(dir: std.fs.Dir, h: Hash) !void {
    const hex = hash_mod.toHex(h);
    var buf: [66]u8 = undefined;
    const data = try std.fmt.bufPrint(&buf, "{s}\n", .{hex});
    try writeAtomicFile(dir, head_file, data, false);
}

/// Read the hash that a branch ref points to. Returns null if branch doesn't exist.
pub fn readRef(allocator: Allocator, dir: std.fs.Dir, branch: []const u8) !?Hash {
    if (!protocol.validateRefName(branch)) return error.InvalidRefName;
    var heads = dir.openDir(heads_dir, .{}) catch return null;
    defer heads.close();
    return readRefFromDir(allocator, heads, branch) catch return null;
}

/// Read a ref hash from an already-opened directory handle.
fn readRefFromDir(allocator: Allocator, heads: std.fs.Dir, branch: []const u8) !?Hash {
    const content = heads.readFileAlloc(allocator, branch, 128) catch return null;
    defer allocator.free(content);

    const trimmed = std.mem.trimEnd(u8, content, "\n\r ");
    if (trimmed.len != 64) return error.InvalidRef;
    return hash_mod.fromHex(trimmed) catch error.InvalidRef;
}

/// Write a branch ref to point to a commit hash.
pub fn writeRef(dir: std.fs.Dir, branch: []const u8, h: Hash) !void {
    if (!protocol.validateRefName(branch)) return error.InvalidRefName;
    return writeRefToDir(dir, heads_dir, branch, h);
}

/// Resolve HEAD to a commit hash. Returns null if HEAD's branch has no commits yet.
pub fn resolveHead(allocator: Allocator, dir: std.fs.Dir) !?Hash {
    const head = readHead(allocator, dir) catch return null;
    switch (head) {
        .branch => |branch| {
            defer allocator.free(branch);
            return try readRef(allocator, dir, branch);
        },
        .detached => |h| return h,
    }
}

/// Update the ref that HEAD points to.
pub fn updateHead(allocator: Allocator, dir: std.fs.Dir, commit_hash: Hash) !void {
    const head = try readHead(allocator, dir);
    switch (head) {
        .branch => |branch| {
            defer allocator.free(branch);
            try writeRef(dir, branch, commit_hash);
        },
        .detached => {
            try writeHeadDetached(dir, commit_hash);
        },
    }
}

// -- Tag functions --

/// Write a tag to point to a commit hash.
pub fn writeTag(dir: std.fs.Dir, name: []const u8, h: Hash) !void {
    if (!protocol.validateRefName(name)) return error.InvalidRefName;
    return writeRefToDir(dir, tags_dir, name, h);
}

/// Read the hash that a tag points to. Returns null if tag doesn't exist.
pub fn readTag(allocator: Allocator, dir: std.fs.Dir, name: []const u8) !?Hash {
    if (!protocol.validateRefName(name)) return error.InvalidRefName;
    var tags = dir.openDir(tags_dir, .{}) catch return null;
    defer tags.close();
    return readRefFromDir(allocator, tags, name) catch return null;
}

/// Delete a tag. Returns error if tag doesn't exist.
pub fn deleteTag(dir: std.fs.Dir, name: []const u8) !void {
    if (!protocol.validateRefName(name)) return error.InvalidRefName;
    deleteRefFromDir(dir, tags_dir, name) catch |err| switch (err) {
        error.NotFound => return error.TagNotFound,
        else => return err,
    };
}

/// List all tags. Caller owns returned slice and must free names and slice.
pub fn listTags(allocator: Allocator, dir: std.fs.Dir) ![]Ref {
    return listRefsFromDir(allocator, dir, tags_dir);
}

// -- Shared internal helpers --

fn writeRefToDir(dir: std.fs.Dir, sub_dir: []const u8, name: []const u8, h: Hash) !void {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ sub_dir, name }) catch return error.NameTooLong;
    const hex = hash_mod.toHex(h);
    var data_buf: [65]u8 = undefined;
    const data = try std.fmt.bufPrint(&data_buf, "{s}\n", .{hex});
    try writeAtomicFile(dir, path, data, true);
}

fn deleteRefFromDir(dir: std.fs.Dir, sub_dir: []const u8, name: []const u8) !void {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ sub_dir, name }) catch return error.NameTooLong;

    dir.deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return err,
    };
}

fn listRefsFromDir(allocator: Allocator, dir: std.fs.Dir, sub_dir: []const u8) ![]Ref {
    var ref_list: std.ArrayList(Ref) = .empty;
    errdefer {
        for (ref_list.items) |ref| {
            allocator.free(ref.name);
        }
        ref_list.deinit(allocator);
    }

    var sub = dir.openDir(sub_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return ref_list.toOwnedSlice(allocator),
        else => return err,
    };
    defer sub.close();

    try collectRefsRecursive(allocator, dir, sub_dir, "", &ref_list);

    std.mem.sort(Ref, ref_list.items, {}, struct {
        fn lessThan(_: void, a: Ref, b: Ref) bool {
            return std.mem.order(u8, a.name, b.name) == .lt;
        }
    }.lessThan);

    return ref_list.toOwnedSlice(allocator);
}

fn ensureParentDirs(dir: std.fs.Dir, path: []const u8) !void {
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, i, '/')) |slash| {
        const prefix = path[0..slash];
        dir.makeDir(prefix) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        i = slash + 1;
    }
}

fn writeAtomicFile(dir: std.fs.Dir, path: []const u8, data: []const u8, make_path: bool) !void {
    var write_buffer: [1024]u8 = undefined;
    var atomic_file = try dir.atomicFile(path, .{
        .mode = std.fs.File.default_mode,
        .make_path = make_path,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    try atomic_file.file_writer.interface.writeAll(data);
    try atomic_file.flush();
    try atomic_file.file_writer.file.sync();
    try atomic_file.renameIntoPlace();
}

fn collectRefsRecursive(
    allocator: Allocator,
    root: std.fs.Dir,
    sub_dir: []const u8,
    prefix: []const u8,
    ref_list: *std.ArrayList(Ref),
) !void {
    const dir_path = if (prefix.len == 0)
        try allocator.dupe(u8, sub_dir)
    else
        try std.fmt.allocPrint(allocator, "{s}/{s}", .{ sub_dir, prefix });
    defer allocator.free(dir_path);

    var current = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return,
        else => return err,
    };
    defer current.close();

    var iter = current.iterate();
    while (try iter.next()) |entry| {
        const child_name = if (prefix.len == 0)
            try allocator.dupe(u8, entry.name)
        else
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, entry.name });
        defer allocator.free(child_name);

        switch (entry.kind) {
            .file => {
                if (!protocol.validateRefName(child_name)) continue;
                const name = try allocator.dupe(u8, child_name);
                errdefer allocator.free(name);
                const ref_hash = readRefFromDir(allocator, current, entry.name) catch |err| switch (err) {
                    error.InvalidRef => {
                        allocator.free(name);
                        continue;
                    },
                    else => return err,
                };
                try ref_list.append(allocator, .{ .name = name, .hash = ref_hash });
            },
            .directory => try collectRefsRecursive(allocator, root, sub_dir, child_name, ref_list),
            else => {},
        }
    }
}

// -- Shallow boundary management --

pub const shallow_file = ".mkit/shallow";

/// Load shallow boundary hashes from .mkit/shallow.
/// Returns null if the file does not exist.
/// Caller owns the returned hashmap.
pub fn loadShallowBoundaries(allocator: Allocator, mkit_dir: std.fs.Dir) !?std.AutoHashMap(Hash, void) {
    const content = mkit_dir.readFileAlloc(allocator, shallow_file, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(content);

    if (content.len == 0) return null;

    var map = std.AutoHashMap(Hash, void).init(allocator);
    errdefer map.deinit();

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, "\r ");
        if (trimmed.len != 64) continue;
        const h = hash_mod.fromHex(trimmed) catch continue;
        try map.put(h, {});
    }

    if (map.count() == 0) return null;
    return map;
}

/// Write shallow boundary hashes to .mkit/shallow.
pub fn writeShallowBoundaries(mkit_dir: std.fs.Dir, boundaries: []const Hash) !void {
    if (boundaries.len == 0) {
        mkit_dir.deleteFile(shallow_file) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        return;
    }

    var write_buffer: [1024]u8 = undefined;
    var atomic_file = try mkit_dir.atomicFile(shallow_file, .{
        .mode = std.fs.File.default_mode,
        .make_path = true,
        .write_buffer = &write_buffer,
    });
    defer atomic_file.deinit();

    for (boundaries) |h| {
        const hex = hash_mod.toHex(h);
        try atomic_file.file_writer.interface.writeAll(&hex);
        try atomic_file.file_writer.interface.writeAll("\n");
    }
    try atomic_file.flush();
    try atomic_file.file_writer.file.sync();
    try atomic_file.renameIntoPlace();
}

// -- Tests --

test "init creates refs structure and HEAD" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // HEAD should exist and point to main
    const allocator = std.testing.allocator;
    const head = try readHead(allocator, tmp.dir);
    switch (head) {
        .branch => |branch| {
            defer allocator.free(branch);
            try std.testing.expectEqualStrings("main", branch);
        },
        .detached => return error.ExpectedBranch,
    }
}

test "write and read branch ref" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("commit1");
    try writeRef(tmp.dir, "main", h);

    const read = try readRef(allocator, tmp.dir, "main");
    try std.testing.expectEqual(h, read.?);
}

test "resolve HEAD with no commits returns null" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // HEAD points to main, but main has no ref file yet
    const resolved = try resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(@as(?Hash, null), resolved);
}

test "resolve HEAD after commit" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("commit1");
    try writeRef(tmp.dir, "main", h);

    const resolved = try resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h, resolved.?);
}

test "update HEAD updates current branch" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h1 = hash_mod.hash("commit1");
    try updateHead(allocator, tmp.dir, h1);

    const resolved = try resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h1, resolved.?);

    // Update again
    const h2 = hash_mod.hash("commit2");
    try updateHead(allocator, tmp.dir, h2);

    const resolved2 = try resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h2, resolved2.?);
}

test "detached HEAD" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    const h = hash_mod.hash("commit-detached");
    try writeHeadDetached(tmp.dir, h);

    const head = try readHead(allocator, tmp.dir);
    switch (head) {
        .branch => return error.ExpectedDetached,
        .detached => |dh| try std.testing.expectEqual(h, dh),
    }

    const resolved = try resolveHead(allocator, tmp.dir);
    try std.testing.expectEqual(h, resolved.?);
}

test "nonexistent branch returns null" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const result = try readRef(allocator, tmp.dir, "nonexistent");
    try std.testing.expectEqual(@as(?Hash, null), result);
}

test "list refs empty" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // After init, no branch ref files exist (only HEAD), so listRefs returns empty
    const ref_list = try listRefs(allocator, tmp.dir);
    defer {
        for (ref_list) |ref| {
            allocator.free(ref.name);
        }
        allocator.free(ref_list);
    }
    try std.testing.expectEqual(@as(usize, 0), ref_list.len);
}

test "list refs after writes" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h1 = hash_mod.hash("commit-main");
    const h2 = hash_mod.hash("commit-dev");
    try writeRef(tmp.dir, "main", h1);
    try writeRef(tmp.dir, "dev", h2);

    const ref_list = try listRefs(allocator, tmp.dir);
    defer {
        for (ref_list) |ref| {
            allocator.free(ref.name);
        }
        allocator.free(ref_list);
    }

    // Should return both sorted alphabetically: dev, main
    try std.testing.expectEqual(@as(usize, 2), ref_list.len);
    try std.testing.expectEqualStrings("dev", ref_list[0].name);
    try std.testing.expectEqual(h2, ref_list[0].hash.?);
    try std.testing.expectEqualStrings("main", ref_list[1].name);
    try std.testing.expectEqual(h1, ref_list[1].hash.?);
}

test "delete ref" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("commit-to-delete");
    try writeRef(tmp.dir, "feature", h);

    // Verify it exists
    const before = try readRef(allocator, tmp.dir, "feature");
    try std.testing.expectEqual(h, before.?);

    // Delete it
    try deleteRef(tmp.dir, "feature");

    // Verify it's gone
    const after = try readRef(allocator, tmp.dir, "feature");
    try std.testing.expectEqual(@as(?Hash, null), after);
}

test "delete nonexistent ref" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // Try to delete a ref that doesn't exist
    const result = deleteRef(tmp.dir, "nonexistent");
    try std.testing.expectError(error.RefNotFound, result);
}

test "checkout switches HEAD" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // Switch HEAD to "dev"
    try writeHeadBranch(tmp.dir, "dev");

    // Verify HEAD now points to "dev"
    const head = try readHead(allocator, tmp.dir);
    switch (head) {
        .branch => |branch| {
            defer allocator.free(branch);
            try std.testing.expectEqualStrings("dev", branch);
        },
        .detached => return error.ExpectedBranch,
    }
}

test "refuse delete current branch" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    // HEAD points to "main" by default. Write a ref so it exists.
    const h = hash_mod.hash("commit-main");
    try writeRef(tmp.dir, "main", h);

    // Try to delete "main" while HEAD points to it
    const result = deleteRefSafe(allocator, tmp.dir, "main");
    try std.testing.expectError(error.CannotDeleteCurrentBranch, result);
}

// -- Tag tests --

test "write and read tag" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("release-v1.0");
    try writeTag(tmp.dir, "v1.0", h);

    const read = try readTag(allocator, tmp.dir, "v1.0");
    try std.testing.expectEqual(h, read.?);
}

test "list tags empty" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const tag_list = try listTags(allocator, tmp.dir);
    defer {
        for (tag_list) |t| {
            allocator.free(t.name);
        }
        allocator.free(tag_list);
    }
    try std.testing.expectEqual(@as(usize, 0), tag_list.len);
}

test "list tags sorted" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h1 = hash_mod.hash("release-v2.0");
    const h2 = hash_mod.hash("release-v1.0");
    const h3 = hash_mod.hash("release-alpha");
    try writeTag(tmp.dir, "v2.0", h1);
    try writeTag(tmp.dir, "v1.0", h2);
    try writeTag(tmp.dir, "alpha", h3);

    const tag_list = try listTags(allocator, tmp.dir);
    defer {
        for (tag_list) |t| {
            allocator.free(t.name);
        }
        allocator.free(tag_list);
    }

    try std.testing.expectEqual(@as(usize, 3), tag_list.len);
    try std.testing.expectEqualStrings("alpha", tag_list[0].name);
    try std.testing.expectEqualStrings("v1.0", tag_list[1].name);
    try std.testing.expectEqualStrings("v2.0", tag_list[2].name);
}

test "delete tag" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("tag-to-delete");
    try writeTag(tmp.dir, "release", h);

    // Verify it exists
    const before = try readTag(allocator, tmp.dir, "release");
    try std.testing.expectEqual(h, before.?);

    // Delete it
    try deleteTag(tmp.dir, "release");

    // Verify it's gone
    const after = try readTag(allocator, tmp.dir, "release");
    try std.testing.expectEqual(@as(?Hash, null), after);
}

test "delete nonexistent tag" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const result = deleteTag(tmp.dir, "nonexistent");
    try std.testing.expectError(error.TagNotFound, result);
}

test "tag and branch same name" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const tag_hash = hash_mod.hash("tag-commit");
    const branch_hash = hash_mod.hash("branch-commit");

    try writeTag(tmp.dir, "main", tag_hash);
    try writeRef(tmp.dir, "main", branch_hash);

    // Both should be independently readable
    const read_tag = try readTag(allocator, tmp.dir, "main");
    const read_branch = try readRef(allocator, tmp.dir, "main");

    try std.testing.expectEqual(tag_hash, read_tag.?);
    try std.testing.expectEqual(branch_hash, read_branch.?);
}

test "reject invalid branch names" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("commit");
    try std.testing.expectError(error.InvalidRefName, writeRef(tmp.dir, "../escape", h));
    try std.testing.expectError(error.InvalidRefName, writeHeadBranch(tmp.dir, "bad//branch"));
}

test "nested refs are listed recursively" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try init(tmp.dir);

    const h = hash_mod.hash("nested");
    try writeRef(tmp.dir, "feature/deep/topic", h);

    const refs = try listRefs(allocator, tmp.dir);
    defer {
        for (refs) |ref| allocator.free(ref.name);
        allocator.free(refs);
    }

    try std.testing.expectEqual(@as(usize, 1), refs.len);
    try std.testing.expectEqualStrings("feature/deep/topic", refs[0].name);
    try std.testing.expectEqual(h, refs[0].hash.?);
}

// -- Shallow boundary tests --

test "loadShallowBoundaries returns null when file missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");
    const result = try loadShallowBoundaries(allocator, tmp.dir);
    try std.testing.expect(result == null);
}

test "writeShallowBoundaries and loadShallowBoundaries roundtrip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");
    const h1 = hash_mod.hash("boundary-1");
    const h2 = hash_mod.hash("boundary-2");
    const h3 = hash_mod.hash("boundary-3");
    const boundaries = [_]Hash{ h1, h2, h3 };
    try writeShallowBoundaries(tmp.dir, &boundaries);
    var loaded = (try loadShallowBoundaries(allocator, tmp.dir)).?;
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 3), loaded.count());
    try std.testing.expect(loaded.contains(h1));
    try std.testing.expect(loaded.contains(h2));
    try std.testing.expect(loaded.contains(h3));
}

test "writeShallowBoundaries empty removes file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");
    const h = hash_mod.hash("boundary-to-remove");
    const boundaries = [_]Hash{h};
    try writeShallowBoundaries(tmp.dir, &boundaries);
    var loaded = (try loadShallowBoundaries(allocator, tmp.dir)).?;
    loaded.deinit();
    try writeShallowBoundaries(tmp.dir, &[_]Hash{});
    const result = try loadShallowBoundaries(allocator, tmp.dir);
    try std.testing.expect(result == null);
}

test "loadShallowBoundaries empty file returns null" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");
    const f = try tmp.dir.createFile(shallow_file, .{});
    f.close();
    const result = try loadShallowBoundaries(allocator, tmp.dir);
    try std.testing.expect(result == null);
}

test "loadShallowBoundaries skips invalid lines" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");
    const h = hash_mod.hash("valid-boundary");
    const hex = hash_mod.toHex(h);
    const f = try tmp.dir.createFile(shallow_file, .{});
    defer f.close();
    try f.writeAll("short\n");
    try f.writeAll(&hex);
    try f.writeAll("\n");
    try f.writeAll("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n");
    try f.writeAll("\n");
    var loaded = (try loadShallowBoundaries(allocator, tmp.dir)).?;
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u32, 1), loaded.count());
    try std.testing.expect(loaded.contains(h));
}
