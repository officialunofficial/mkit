// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const worktree_mod = @import("worktree.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const SparsePattern = struct {
    pattern: []const u8,
    negated: bool,
    dir_only: bool, // trailing /
};

pub const RestoreOptions = struct {
    /// If true, remove files/directories not present in the tree (except .mkit, .git).
    clean: bool = true,
    /// If set, only restore files matching these sparse patterns.
    sparse_patterns: ?[]const SparsePattern = null,
};

/// Parse sparse checkout pattern content into SparsePattern slices.
/// Lines starting with # are comments. Empty lines are skipped.
/// Leading ! means negation. Trailing / means directory-only.
/// Caller owns returned slice and must free with freeSparsePatterns.
pub fn parseSparsePatterns(allocator: Allocator, content: []const u8) ![]SparsePattern {
    var patterns: std.ArrayList(SparsePattern) = .empty;
    errdefer {
        for (patterns.items) |p| allocator.free(p.pattern);
        patterns.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r ");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        var negated = false;
        var pat = line;
        if (pat[0] == '!') {
            negated = true;
            pat = pat[1..];
        }

        var dir_only = false;
        if (pat.len > 0 and pat[pat.len - 1] == '/') {
            dir_only = true;
            pat = pat[0 .. pat.len - 1];
        }

        if (pat.len == 0) continue;

        const duped = try allocator.dupe(u8, pat);
        try patterns.append(allocator, .{ .pattern = duped, .negated = negated, .dir_only = dir_only });
    }

    return patterns.toOwnedSlice(allocator);
}

/// Free patterns allocated by parseSparsePatterns.
pub fn freeSparsePatterns(allocator: Allocator, patterns: []SparsePattern) void {
    for (patterns) |p| allocator.free(p.pattern);
    allocator.free(patterns);
}

/// Check if a path matches the sparse checkout patterns.
/// Patterns are evaluated in order; last match wins.
/// Default when no pattern matches = excluded.
pub fn matchesSparse(patterns: []const SparsePattern, path: []const u8, is_dir: bool) bool {
    var matched = false;

    for (patterns) |pat| {
        if (pathMatchesPattern(pat.pattern, path)) {
            // For dir_only patterns: exact name match requires is_dir=true,
            // but prefix/descendant matches (path is inside the dir) always apply.
            if (pat.dir_only and !is_dir) {
                const pat_stripped = if (pat.pattern.len > 0 and pat.pattern[pat.pattern.len - 1] == '/')
                    pat.pattern[0 .. pat.pattern.len - 1]
                else
                    pat.pattern;
                // Exact match to the dir name as a file → skip
                if (std.mem.eql(u8, pat_stripped, path)) continue;
            }
            matched = !pat.negated;
        }
    }

    return matched;
}

/// Check if a directory prefix could match any descendant.
/// Returns true if any non-negated pattern starts with the dir prefix or matches within it.
pub fn couldMatchDescendant(patterns: []const SparsePattern, dir_prefix: []const u8) bool {
    for (patterns) |pat| {
        if (pat.negated) continue;

        // If the pattern itself starts with the dir prefix, descendants could match
        if (std.mem.startsWith(u8, pat.pattern, dir_prefix)) {
            return true;
        }

        // If the dir prefix starts with the pattern, the entire subtree matches
        if (std.mem.startsWith(u8, dir_prefix, pat.pattern)) {
            return true;
        }

        // Check if directory prefix is a parent of the pattern
        if (dir_prefix.len > 0 and dir_prefix[dir_prefix.len - 1] != '/') {
            if (pat.pattern.len > dir_prefix.len and
                std.mem.startsWith(u8, pat.pattern, dir_prefix) and
                pat.pattern[dir_prefix.len] == '/')
            {
                return true;
            }
        }
    }
    return false;
}

/// Load sparse checkout patterns from .mkit/sparse-checkout file.
/// Returns null if the file does not exist.
/// Caller must free with freeSparsePatterns.
pub fn loadSparseCheckout(allocator: Allocator, io: std.Io, mkit_dir: std.Io.Dir) !?[]SparsePattern {
    const content = mkit_dir.readFileAlloc(io, ".mkit/sparse-checkout", allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(content);
    const patterns = try parseSparsePatterns(allocator, content);
    if (patterns.len == 0) {
        allocator.free(patterns);
        return null;
    }
    return patterns;
}

/// Write sparse checkout patterns to .mkit/sparse-checkout file.
pub fn writeSparseCheckout(io: std.Io, mkit_dir: std.Io.Dir, pattern_lines: []const []const u8) !void {
    mkit_dir.createDirPath(io, ".mkit") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var atomic_file = try mkit_dir.createFileAtomic(io, ".mkit/sparse-checkout", .{
        .make_path = true,
        .replace = true,
    });
    defer atomic_file.deinit(io);

    var write_buffer: [1024]u8 = undefined;
    var file_writer = atomic_file.file.writer(io, &write_buffer);

    for (pattern_lines) |line| {
        try file_writer.interface.writeAll(line);
        try file_writer.interface.writeAll("\n");
    }
    try file_writer.interface.flush();
    try file_writer.file.sync(io);
    try atomic_file.replace(io);
}

/// Check if a path matches a simple pattern.
fn pathMatchesPattern(pattern: []const u8, path: []const u8) bool {
    // Strip trailing slash from pattern for matching (e.g., "src/" -> "src")
    const pat = if (pattern.len > 0 and pattern[pattern.len - 1] == '/')
        pattern[0 .. pattern.len - 1]
    else
        pattern;

    // Exact match
    if (std.mem.eql(u8, pat, path)) return true;

    // Pattern as a prefix directory: "src" matches "src/foo.txt"
    if (path.len > pat.len and
        std.mem.startsWith(u8, path, pat) and
        path[pat.len] == '/')
    {
        return true;
    }

    // Pattern is a bare name -- match against the last component
    if (std.mem.indexOfScalar(u8, pat, '/') == null) {
        if (std.mem.lastIndexOfScalar(u8, path, '/')) |last_slash| {
            const basename = path[last_slash + 1 ..];
            if (std.mem.eql(u8, pat, basename)) return true;
        }
    }

    return false;
}

/// Restore a tree object from the store into a target directory.
/// Writes blobs as files, recurses into subtrees as directories,
/// and creates symlinks for symlink entries.
pub fn restoreTree(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    target_dir: std.fs.Dir,
    options: RestoreOptions,
) !void {
    try restoreTreeInner(allocator, store, tree_hash, target_dir, options, "");
}

fn restoreTreeInner(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    target_dir: std.fs.Dir,
    options: RestoreOptions,
    path_prefix: []const u8,
) !void {
    var tree_obj = try store.get(allocator, tree_hash);
    defer tree_obj.deinit(allocator);

    if (tree_obj != .tree) return error.NotATree;

    const entries = tree_obj.tree.entries;

    if (options.clean) {
        try cleanDirectory(allocator, target_dir, entries, options.sparse_patterns, path_prefix);
    }

    for (entries) |entry| {
        // Defense-in-depth: reject names with path traversal components
        if (!object.Tree.validateEntryName(entry.name)) continue;

        // Build full path for sparse matching
        const full_path = if (path_prefix.len > 0)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ path_prefix, entry.name })
        else
            try allocator.dupe(u8, entry.name);
        defer allocator.free(full_path);

        switch (entry.mode) {
            .blob, .executable => {
                if (options.sparse_patterns) |patterns| {
                    if (!matchesSparse(patterns, full_path, false)) continue;
                }
                try restoreBlob(allocator, store, target_dir, entry.name, entry.object_hash);
                if (entry.mode == .executable) {
                    // Best-effort POSIX chmod 0755 for executable entries.
                    // Silent no-op on hosts without fchmodat.
                    if (@hasDecl(std.posix, "fchmodat")) {
                        std.posix.fchmodat(target_dir.fd, entry.name, 0o755, 0) catch {};
                    }
                }
            },
            .tree => {
                if (options.sparse_patterns) |patterns| {
                    if (!couldMatchDescendant(patterns, full_path)) continue;
                }
                try preparePathForKind(target_dir, entry.name, .directory, false);
                target_dir.makeDir(entry.name) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
                var subdir = try target_dir.openDir(entry.name, .{ .iterate = true });
                defer subdir.close();
                try restoreTreeInner(allocator, store, entry.object_hash, subdir, options, full_path);
            },
            .symlink => {
                if (options.sparse_patterns) |patterns| {
                    if (!matchesSparse(patterns, full_path, false)) continue;
                }
                try restoreSymlink(allocator, store, target_dir, entry.name, entry.object_hash);
            },
        }
    }
}

/// Write a blob or chunked_blob object to a file in the target directory.
fn restoreBlob(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    dir: std.fs.Dir,
    name: []const u8,
    blob_hash: Hash,
) !void {
    var blob_obj = try store.get(allocator, blob_hash);
    defer blob_obj.deinit(allocator);

    switch (blob_obj) {
        .blob => |b| {
            try preparePathForKind(dir, name, .file, false);
            const file = try dir.createFile(name, .{});
            defer file.close();
            try file.writeAll(b.data);
        },
        .chunked_blob => |cb| {
            try preparePathForKind(dir, name, .file, false);
            const file = try dir.createFile(name, .{});
            defer file.close();
            for (cb.chunks) |chunk_hash| {
                var chunk = try store.get(allocator, chunk_hash);
                defer chunk.deinit(allocator);
                if (chunk != .blob) return error.InvalidChunk;
                try file.writeAll(chunk.blob.data);
            }
        },
        else => return error.NotABlob,
    }
}

/// Create a symlink from a blob whose content is the link target path.
fn restoreSymlink(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    dir: std.fs.Dir,
    name: []const u8,
    blob_hash: Hash,
) !void {
    var blob_obj = try store.get(allocator, blob_hash);
    defer blob_obj.deinit(allocator);

    if (blob_obj != .blob) return error.NotABlob;

    const target = blob_obj.blob.data;
    if (!worktree_mod.validateSymlinkTarget(target)) return error.InvalidSymlinkTarget;

    try preparePathForKind(dir, name, .sym_link, true);

    dir.symLink(target, name, .{}) catch return error.SymlinkFailed;
}

fn preparePathForKind(
    dir: std.fs.Dir,
    name: []const u8,
    expected_kind: std.fs.File.Kind,
    replace_same_kind: bool,
) !void {
    const current_kind = try existingPathKind(dir, name);
    if (current_kind == null) return;
    if (current_kind.? == expected_kind and !replace_same_kind) return;

    switch (current_kind.?) {
        .directory => try dir.deleteTree(name),
        else => try dir.deleteFile(name),
    }
}

fn existingPathKind(dir: std.fs.Dir, name: []const u8) !?std.fs.File.Kind {
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (dir.readLink(name, &link_buf)) |_| {
        return .sym_link;
    } else |err| switch (err) {
        error.FileNotFound => return null,
        error.NotLink => {},
        else => return err,
    }

    const stat = try dir.statFile(name);
    return stat.kind;
}

/// Remove files and directories from target_dir that are not in tree entries.
/// Always preserves .mkit and .git directories.
/// When sparse patterns are active, only clean files within the sparse set.
fn cleanDirectory(
    allocator: Allocator,
    target_dir: std.fs.Dir,
    tree_entries: []const object.TreeEntry,
    sparse_patterns: ?[]const SparsePattern,
    path_prefix: []const u8,
) !void {
    // Collect names to delete (cannot mutate dir while iterating)
    var to_delete: std.ArrayList(CleanEntry) = .empty;
    defer {
        for (to_delete.items) |item| {
            allocator.free(item.name);
        }
        to_delete.deinit(allocator);
    }

    var iter = target_dir.iterate();
    while (try iter.next()) |fs_entry| {
        // Always preserve .mkit and .git
        if (std.mem.eql(u8, fs_entry.name, ".mkit") or std.mem.eql(u8, fs_entry.name, ".git")) {
            continue;
        }

        // Check if this name exists in tree entries
        var found = false;
        for (tree_entries) |te| {
            if (std.mem.eql(u8, te.name, fs_entry.name)) {
                found = true;
                break;
            }
        }

        if (!found) {
            // When sparse patterns are active, only clean files within the sparse set
            if (sparse_patterns) |patterns| {
                const full_path = if (path_prefix.len > 0)
                    std.fmt.allocPrint(allocator, "{s}/{s}", .{ path_prefix, fs_entry.name }) catch continue
                else
                    allocator.dupe(u8, fs_entry.name) catch continue;
                defer allocator.free(full_path);

                const is_dir = fs_entry.kind == .directory;
                if (!matchesSparse(patterns, full_path, is_dir) and
                    !(is_dir and couldMatchDescendant(patterns, full_path)))
                {
                    continue; // Outside sparse set, don't clean
                }
            }

            try to_delete.append(allocator, .{
                .name = try allocator.dupe(u8, fs_entry.name),
                .kind = fs_entry.kind,
            });
        }
    }

    // Delete collected entries
    for (to_delete.items) |item| {
        switch (item.kind) {
            .directory => {
                target_dir.deleteTree(item.name) catch {};
            },
            else => {
                target_dir.deleteFile(item.name) catch {};
            },
        }
    }
}

const CleanEntry = struct {
    name: []const u8,
    kind: std.fs.File.Kind,
};

// -- Helper for tests: create a store and populate it --

fn makeTestTree(allocator: Allocator, store: *store_mod.ObjectStore, entries: []const TestEntry) !Hash {
    var tree_entries = try allocator.alloc(object.TreeEntry, entries.len);
    defer {
        for (tree_entries) |te| {
            allocator.free(te.name);
        }
        allocator.free(tree_entries);
    }

    for (entries, 0..) |te, i| {
        tree_entries[i] = .{
            .name = try allocator.dupe(u8, te.name),
            .mode = te.mode,
            .object_hash = te.hash,
        };
    }

    const tree_obj = object.Object{ .tree = .{ .entries = tree_entries } };
    return store.put(allocator, tree_obj);
}

const TestEntry = struct {
    name: []const u8,
    mode: object.EntryMode,
    hash: Hash,
};

fn storeBlob(allocator: Allocator, store: *store_mod.ObjectStore, data: []const u8) !Hash {
    const blob_obj = object.Object{ .blob = .{ .data = data } };
    return store.put(allocator, blob_obj);
}

// ========================
// Tests
// ========================

test "restore empty tree" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    // Create empty tree
    const empty_entries = [_]TestEntry{};
    const tree_hash = try makeTestTree(allocator, &store, &empty_entries);

    // Restore
    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    // Verify no files created
    var iter = target_dir.iterate();
    var count: usize = 0;
    while (try iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "restore single file" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    // Store blob "hello"
    const blob_hash = try storeBlob(allocator, &store, "hello");

    // Create tree with one entry
    const entries = [_]TestEntry{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    // Restore
    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    // Verify file exists with content "hello"
    const content = try target_tmp.dir.readFileAlloc(allocator, "file.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("hello", content);
}

test "restore nested directories" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const blob_hash = try storeBlob(allocator, &store, "const main = void;");
    const sub_entries = [_]TestEntry{
        .{ .name = "main.zig", .mode = .blob, .hash = blob_hash },
    };
    const src_hash = try makeTestTree(allocator, &store, &sub_entries);

    const root_entries = [_]TestEntry{
        .{ .name = "src", .mode = .tree, .hash = src_hash },
    };
    const root_hash = try makeTestTree(allocator, &store, &root_entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, root_hash, target_dir, .{});

    const content = try target_tmp.dir.readFileAlloc(allocator, "src/main.zig", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("const main = void;", content);
}

test "restore overwrites existing files" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const old_file = try target_tmp.dir.createFile(std.testing.io, "file.txt", .{});
    try old_file.writeAll("old content");
    old_file.close();

    const blob_hash = try storeBlob(allocator, &store, "new content");
    const entries = [_]TestEntry{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    const content = try target_tmp.dir.readFileAlloc(allocator, "file.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("new content", content);
}

test "restore removes untracked files" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const extra = try target_tmp.dir.createFile(std.testing.io, "extra.txt", .{});
    try extra.writeAll("should be removed");
    extra.close();

    const blob_hash = try storeBlob(allocator, &store, "tracked");
    const entries = [_]TestEntry{
        .{ .name = "tracked.txt", .mode = .blob, .hash = blob_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    const stat = target_tmp.dir.statFile(std.testing.io, "extra.txt");
    try std.testing.expectError(error.FileNotFound, stat);

    const content = try target_tmp.dir.readFileAlloc(allocator, "tracked.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("tracked", content);
}

test "restore preserves mkit directory" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    try target_tmp.dir.createDirPath(std.testing.io, ".mkit");
    const mkit_file = try target_tmp.dir.createFile(std.testing.io, ".mkit/config", .{});
    try mkit_file.writeAll("important data");
    mkit_file.close();

    const empty_entries = [_]TestEntry{};
    const tree_hash = try makeTestTree(allocator, &store, &empty_entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    const content = try target_tmp.dir.readFileAlloc(allocator, ".mkit/config", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("important data", content);
}

test "restore creates parent directories" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const blob_hash = try storeBlob(allocator, &store, "deep content");
    const file_entries = [_]TestEntry{
        .{ .name = "file.txt", .mode = .blob, .hash = blob_hash },
    };
    const b_hash = try makeTestTree(allocator, &store, &file_entries);

    const b_entries = [_]TestEntry{
        .{ .name = "b", .mode = .tree, .hash = b_hash },
    };
    const a_hash = try makeTestTree(allocator, &store, &b_entries);

    const root_entries = [_]TestEntry{
        .{ .name = "a", .mode = .tree, .hash = a_hash },
    };
    const root_hash = try makeTestTree(allocator, &store, &root_entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, root_hash, target_dir, .{});

    const content = try target_tmp.dir.readFileAlloc(allocator, "a/b/file.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("deep content", content);
}

test "restore is idempotent" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const h1 = try storeBlob(allocator, &store, "alpha");
    const h2 = try storeBlob(allocator, &store, "beta");
    const entries = [_]TestEntry{
        .{ .name = "a.txt", .mode = .blob, .hash = h1 },
        .{ .name = "b.txt", .mode = .blob, .hash = h2 },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    {
        var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
        defer target_dir.close();
        try restoreTree(allocator, &store, tree_hash, target_dir, .{});
    }
    {
        var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
        defer target_dir.close();
        try restoreTree(allocator, &store, tree_hash, target_dir, .{});
    }

    const content_a = try target_tmp.dir.readFileAlloc(allocator, "a.txt", 4096);
    defer allocator.free(content_a);
    try std.testing.expectEqualStrings("alpha", content_a);

    const content_b = try target_tmp.dir.readFileAlloc(allocator, "b.txt", 4096);
    defer allocator.free(content_b);
    try std.testing.expectEqualStrings("beta", content_b);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    var iter = target_dir.iterate();
    var count: usize = 0;
    while (try iter.next()) |_| {
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "restore with symlink" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const link_target_hash = try storeBlob(allocator, &store, "target.txt");
    const file_hash = try storeBlob(allocator, &store, "real content");

    const entries = [_]TestEntry{
        .{ .name = "link", .mode = .symlink, .hash = link_target_hash },
        .{ .name = "target.txt", .mode = .blob, .hash = file_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_target = try target_tmp.dir.readLink("link", &link_buf);
    try std.testing.expectEqualStrings("target.txt", link_target);

    const content = try target_tmp.dir.readFileAlloc(allocator, "target.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("real content", content);
}

test "restore replaces mismatched kinds" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const old_dir_file = try target_tmp.dir.createFile(std.testing.io, "dir-from-file", .{});
    try old_dir_file.writeAll("stale file");
    old_dir_file.close();

    try target_tmp.dir.createDirPath(std.testing.io, "file-from-dir");

    const old_link_file = try target_tmp.dir.createFile(std.testing.io, "link-from-file", .{});
    try old_link_file.writeAll("stale file");
    old_link_file.close();

    try target_tmp.dir.symLink(std.testing.io, "old-target", "relink", .{});

    const dir_child_hash = try storeBlob(allocator, &store, "inside directory");
    const dir_entries = [_]TestEntry{
        .{ .name = "child.txt", .mode = .blob, .hash = dir_child_hash },
    };
    const nested_dir_hash = try makeTestTree(allocator, &store, &dir_entries);

    const file_hash = try storeBlob(allocator, &store, "fresh file");
    const link_target_hash = try storeBlob(allocator, &store, "target.txt");
    const relink_target_hash = try storeBlob(allocator, &store, "target-two.txt");

    const root_entries = [_]TestEntry{
        .{ .name = "dir-from-file", .mode = .tree, .hash = nested_dir_hash },
        .{ .name = "file-from-dir", .mode = .blob, .hash = file_hash },
        .{ .name = "link-from-file", .mode = .symlink, .hash = link_target_hash },
        .{ .name = "relink", .mode = .symlink, .hash = relink_target_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &root_entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    const nested_content = try target_tmp.dir.readFileAlloc(allocator, "dir-from-file/child.txt", 4096);
    defer allocator.free(nested_content);
    try std.testing.expectEqualStrings("inside directory", nested_content);

    const file_content = try target_tmp.dir.readFileAlloc(allocator, "file-from-dir", 4096);
    defer allocator.free(file_content);
    try std.testing.expectEqualStrings("fresh file", file_content);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_target = try target_tmp.dir.readLink("link-from-file", &link_buf);
    try std.testing.expectEqualStrings("target.txt", link_target);

    const relink_target = try target_tmp.dir.readLink("relink", &link_buf);
    try std.testing.expectEqualStrings("target-two.txt", relink_target);
}

test "restore rejects invalid symlink targets" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const bad_link_hash = try storeBlob(allocator, &store, "/etc/passwd");
    const entries = [_]TestEntry{
        .{ .name = "link", .mode = .symlink, .hash = bad_link_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try std.testing.expectError(error.InvalidSymlinkTarget, restoreTree(allocator, &store, tree_hash, target_dir, .{}));
}

test "restore clean false keeps untracked" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const extra = try target_tmp.dir.createFile(std.testing.io, "extra.txt", .{});
    try extra.writeAll("should survive");
    extra.close();

    const blob_hash = try storeBlob(allocator, &store, "tracked");
    const entries = [_]TestEntry{
        .{ .name = "tracked.txt", .mode = .blob, .hash = blob_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{ .clean = false });

    const extra_content = try target_tmp.dir.readFileAlloc(allocator, "extra.txt", 4096);
    defer allocator.free(extra_content);
    try std.testing.expectEqualStrings("should survive", extra_content);

    const tracked_content = try target_tmp.dir.readFileAlloc(allocator, "tracked.txt", 4096);
    defer allocator.free(tracked_content);
    try std.testing.expectEqualStrings("tracked", tracked_content);
}

test "restore chunked blob" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const chunk0_data = "Hello, ";
    const chunk1_data = "chunked ";
    const chunk2_data = "world!";
    const chunk0_hash = try storeBlob(allocator, &store, chunk0_data);
    const chunk1_hash = try storeBlob(allocator, &store, chunk1_data);
    const chunk2_hash = try storeBlob(allocator, &store, chunk2_data);

    var chunks = try allocator.alloc(hash_mod.Hash, 3);
    chunks[0] = chunk0_hash;
    chunks[1] = chunk1_hash;
    chunks[2] = chunk2_hash;

    var cb_obj = object.Object{ .chunked_blob = .{
        .total_size = chunk0_data.len + chunk1_data.len + chunk2_data.len,
        .chunk_size = 64 * 1024,
        .chunks = chunks,
    } };
    const cb_hash = try store.put(allocator, cb_obj);
    cb_obj.deinit(allocator);

    const entries = [_]TestEntry{
        .{ .name = "reassembled.txt", .mode = .blob, .hash = cb_hash },
    };
    const tree_hash = try makeTestTree(allocator, &store, &entries);

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, tree_hash, target_dir, .{});

    const content = try target_tmp.dir.readFileAlloc(allocator, "reassembled.txt", 4096);
    defer allocator.free(content);
    try std.testing.expectEqualStrings("Hello, chunked world!", content);
}

// ========================
// Sparse checkout tests
// ========================

test "parseSparsePatterns basic" {
    const allocator = std.testing.allocator;
    const content =
        \\# comment line
        \\src
        \\!tests
        \\docs/
        \\
        \\README.md
    ;

    const patterns = try parseSparsePatterns(allocator, content);
    defer freeSparsePatterns(allocator, patterns);

    try std.testing.expectEqual(@as(usize, 4), patterns.len);
    try std.testing.expectEqualStrings("src", patterns[0].pattern);
    try std.testing.expect(!patterns[0].negated);
    try std.testing.expect(!patterns[0].dir_only);

    try std.testing.expectEqualStrings("tests", patterns[1].pattern);
    try std.testing.expect(patterns[1].negated);
    try std.testing.expect(!patterns[1].dir_only);

    try std.testing.expectEqualStrings("docs", patterns[2].pattern);
    try std.testing.expect(!patterns[2].negated);
    try std.testing.expect(patterns[2].dir_only);

    try std.testing.expectEqualStrings("README.md", patterns[3].pattern);
    try std.testing.expect(!patterns[3].negated);
    try std.testing.expect(!patterns[3].dir_only);
}

test "parseSparsePatterns empty content" {
    const allocator = std.testing.allocator;
    const patterns = try parseSparsePatterns(allocator, "");
    defer allocator.free(patterns);
    try std.testing.expectEqual(@as(usize, 0), patterns.len);
}

test "parseSparsePatterns only comments" {
    const allocator = std.testing.allocator;
    const content =
        \\# just a comment
        \\# another comment
    ;
    const patterns = try parseSparsePatterns(allocator, content);
    defer allocator.free(patterns);
    try std.testing.expectEqual(@as(usize, 0), patterns.len);
}

test "matchesSparse exact match" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src/main.zig", .negated = false, .dir_only = false },
    };
    try std.testing.expect(matchesSparse(&patterns, "src/main.zig", false));
    try std.testing.expect(!matchesSparse(&patterns, "src/other.zig", false));
}

test "matchesSparse prefix match" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
    };
    try std.testing.expect(matchesSparse(&patterns, "src/main.zig", false));
    try std.testing.expect(matchesSparse(&patterns, "src/lib/util.zig", false));
    try std.testing.expect(!matchesSparse(&patterns, "tests/test.zig", false));
}

test "matchesSparse negation" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
        .{ .pattern = "src/secret", .negated = true, .dir_only = false },
    };
    try std.testing.expect(matchesSparse(&patterns, "src/main.zig", false));
    try std.testing.expect(!matchesSparse(&patterns, "src/secret/key.pem", false));
}

test "matchesSparse dir_only" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "build", .negated = false, .dir_only = true },
    };
    try std.testing.expect(matchesSparse(&patterns, "build", true));
    try std.testing.expect(!matchesSparse(&patterns, "build", false));
}

test "matchesSparse last match wins" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
        .{ .pattern = "src", .negated = true, .dir_only = false },
    };
    try std.testing.expect(!matchesSparse(&patterns, "src/main.zig", false));
}

test "matchesSparse no match means excluded" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
    };
    try std.testing.expect(!matchesSparse(&patterns, "tests/foo.zig", false));
}

test "matchesSparse bare name matches basename" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "Makefile", .negated = false, .dir_only = false },
    };
    try std.testing.expect(matchesSparse(&patterns, "Makefile", false));
    try std.testing.expect(matchesSparse(&patterns, "sub/Makefile", false));
    try std.testing.expect(!matchesSparse(&patterns, "Makefile.bak", false));
}

test "couldMatchDescendant returns true for prefix" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src/lib", .negated = false, .dir_only = false },
    };
    try std.testing.expect(couldMatchDescendant(&patterns, "src"));
    try std.testing.expect(couldMatchDescendant(&patterns, "src/lib"));
    try std.testing.expect(!couldMatchDescendant(&patterns, "tests"));
}

test "couldMatchDescendant ignores negated patterns" {
    const patterns = [_]SparsePattern{
        .{ .pattern = "src/lib", .negated = true, .dir_only = false },
    };
    try std.testing.expect(!couldMatchDescendant(&patterns, "src"));
}

test "sparse restore only restores matched files" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const main_hash = try storeBlob(allocator, &store, "pub fn main() void {}");
    const test_hash = try storeBlob(allocator, &store, "test {}");
    const readme_hash = try storeBlob(allocator, &store, "# Project");

    const src_entries = [_]TestEntry{
        .{ .name = "main.zig", .mode = .blob, .hash = main_hash },
    };
    const src_hash = try makeTestTree(allocator, &store, &src_entries);

    const test_entries = [_]TestEntry{
        .{ .name = "test.zig", .mode = .blob, .hash = test_hash },
    };
    const tests_hash = try makeTestTree(allocator, &store, &test_entries);

    const root_entries = [_]TestEntry{
        .{ .name = "README.md", .mode = .blob, .hash = readme_hash },
        .{ .name = "src", .mode = .tree, .hash = src_hash },
        .{ .name = "tests", .mode = .tree, .hash = tests_hash },
    };
    const root_hash = try makeTestTree(allocator, &store, &root_entries);

    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
    };

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, root_hash, target_dir, .{
        .sparse_patterns = &patterns,
    });

    const main_content = try target_tmp.dir.readFileAlloc(allocator, "src/main.zig", 4096);
    defer allocator.free(main_content);
    try std.testing.expectEqualStrings("pub fn main() void {}", main_content);

    const tests_stat = target_tmp.dir.statFile(std.testing.io, "tests/test.zig");
    try std.testing.expectError(error.FileNotFound, tests_stat);

    const readme_stat = target_tmp.dir.statFile(std.testing.io, "README.md");
    try std.testing.expectError(error.FileNotFound, readme_stat);
}

test "sparse restore with negation excludes subtree" {
    const allocator = std.testing.allocator;

    var store_tmp = std.testing.tmpDir(.{});
    defer store_tmp.cleanup();
    var store = try store_mod.ObjectStore.init(store_tmp.dir);
    defer store.close();

    var target_tmp = std.testing.tmpDir(.{});
    defer target_tmp.cleanup();

    const main_hash = try storeBlob(allocator, &store, "main code");
    const key_hash = try storeBlob(allocator, &store, "secret key");

    const secret_entries = [_]TestEntry{
        .{ .name = "key.pem", .mode = .blob, .hash = key_hash },
    };
    const secret_hash = try makeTestTree(allocator, &store, &secret_entries);

    const src_entries = [_]TestEntry{
        .{ .name = "main.zig", .mode = .blob, .hash = main_hash },
        .{ .name = "secret", .mode = .tree, .hash = secret_hash },
    };
    const src_hash = try makeTestTree(allocator, &store, &src_entries);

    const root_entries = [_]TestEntry{
        .{ .name = "src", .mode = .tree, .hash = src_hash },
    };
    const root_hash = try makeTestTree(allocator, &store, &root_entries);

    const patterns = [_]SparsePattern{
        .{ .pattern = "src", .negated = false, .dir_only = false },
        .{ .pattern = "src/secret", .negated = true, .dir_only = false },
    };

    var target_dir = try target_tmp.dir.openDir(std.testing.io, ".", .{ .iterate = true });
    defer target_dir.close();
    try restoreTree(allocator, &store, root_hash, target_dir, .{
        .sparse_patterns = &patterns,
    });

    const main_content = try target_tmp.dir.readFileAlloc(allocator, "src/main.zig", 4096);
    defer allocator.free(main_content);
    try std.testing.expectEqualStrings("main code", main_content);

    const key_stat = target_tmp.dir.statFile(std.testing.io, "src/secret/key.pem");
    try std.testing.expectError(error.FileNotFound, key_stat);
}

test "writeSparseCheckout and loadSparseCheckout roundtrip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    const lines = [_][]const u8{ "src", "!src/secret", "docs/" };
    try writeSparseCheckout(std.testing.io, tmp.dir, &lines);

    const patterns = (try loadSparseCheckout(allocator, std.testing.io, tmp.dir)).?;
    defer freeSparsePatterns(allocator, patterns);

    try std.testing.expectEqual(@as(usize, 3), patterns.len);
    try std.testing.expectEqualStrings("src", patterns[0].pattern);
    try std.testing.expect(!patterns[0].negated);
    try std.testing.expectEqualStrings("src/secret", patterns[1].pattern);
    try std.testing.expect(patterns[1].negated);
    try std.testing.expectEqualStrings("docs", patterns[2].pattern);
    try std.testing.expect(patterns[2].dir_only);
}

test "loadSparseCheckout returns null when file missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    const result = try loadSparseCheckout(allocator, std.testing.io, tmp.dir);
    try std.testing.expect(result == null);
}

test "fuzz: parseSparsePatterns does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            const input = smith.in orelse return;
            const allocator = std.heap.page_allocator;
            const patterns = parseSparsePatterns(allocator, input) catch return;
            freeSparsePatterns(allocator, patterns);
        }
    }.run, .{});
}
