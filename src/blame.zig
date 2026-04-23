// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const BlameLine = struct {
    line_num: usize, // 1-based line number
    commit_hash: Hash,
    /// Borrowed Identity from the owning commit object. Not owned by the
    /// BlameLine — the caller must keep the commit objects alive if they
    /// want to read this after BlameResult is dropped.
    author: object.Identity,
    timestamp: u64,
    text: []const u8, // line content (without newline), owned

    pub fn deinit(self: *const BlameLine, allocator: Allocator) void {
        allocator.free(self.text);
    }
};

pub const BlameResult = struct {
    lines: []BlameLine,
    /// Pool of author-identity byte slices. Each entry is deep-copied from
    /// the commits the walker visited. `BlameLine.author.bytes` references
    /// into this pool.
    author_bytes_pool: []const []const u8,
    allocator: Allocator,

    pub fn deinit(self: *BlameResult) void {
        for (self.lines) |line| {
            self.allocator.free(line.text);
        }
        self.allocator.free(self.lines);
        for (self.author_bytes_pool) |b| {
            self.allocator.free(b);
        }
        self.allocator.free(self.author_bytes_pool);
    }
};

/// Blame a file at a given path, starting from a commit.
/// Walks the first-parent chain comparing line content via LCS.
/// Returns attribution for each line to the commit that introduced it.
pub fn blameFile(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    head_hash: Hash,
    file_path: []const u8,
) !BlameResult {
    // Step 1: Walk history collecting (commit_hash, blob_hash) for the file.
    // Stop when file disappears or we run out of parents.
    //
    // `author_kind` + `author_bytes` are a duped copy of the commit's
    // Identity, because the commit object is freed immediately after we
    // read it. The duped byte slices are stashed in `author_bytes_pool`
    // below and handed to the returned BlameResult, which frees them.
    const HistoryEntry = struct {
        commit_hash: Hash,
        blob_hash: Hash,
        author_kind: object.IdentityKind,
        author_bytes: []const u8,
        timestamp: u64,
    };
    var history: std.ArrayList(HistoryEntry) = .empty;
    defer history.deinit(allocator);

    var author_bytes_pool: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (author_bytes_pool.items) |b| allocator.free(b);
        author_bytes_pool.deinit(allocator);
    }

    var current: ?Hash = head_hash;
    while (current) |commit_hash| {
        var commit_obj = try store.get(allocator, commit_hash);
        defer commit_obj.deinit(allocator);

        if (commit_obj != .commit) return error.NotACommit;
        const commit = commit_obj.commit;

        const blob_hash = try findBlobInTree(allocator, store, commit.tree_hash, file_path);
        if (blob_hash) |bh| {
            const dup_bytes = try allocator.dupe(u8, commit.author.bytes);
            try author_bytes_pool.append(allocator, dup_bytes);
            try history.append(allocator, .{
                .commit_hash = commit_hash,
                .blob_hash = bh,
                .author_kind = commit.author.kind,
                .author_bytes = dup_bytes,
                .timestamp = commit.timestamp,
            });
            // Follow first parent
            if (commit.parents.len > 0) {
                current = commit.parents[0];
            } else {
                current = null;
            }
        } else {
            // File doesn't exist at this commit, stop
            break;
        }
    }

    if (history.items.len == 0) {
        // errdefer above frees the pool when we return this error.
        return error.FileNotFound;
    }

    // Step 2: Start from the oldest commit where file exists, attribute all lines to it.
    // Then walk forward applying diffs.
    const items = history.items;

    // Load the oldest version's lines — all attributed to that commit.
    const oldest = items[items.len - 1];
    const oldest_lines = try loadBlobLines(allocator, store, oldest.blob_hash);
    defer {
        for (oldest_lines) |line| allocator.free(line);
        allocator.free(oldest_lines);
    }

    // Build initial attribution: every line → oldest commit
    var attributions = try allocator.alloc(Attribution, oldest_lines.len);
    defer allocator.free(attributions);
    for (attributions, 0..) |*attr, i| {
        attr.* = .{
            .commit_hash = oldest.commit_hash,
            .author_kind = oldest.author_kind,
            .author_bytes = oldest.author_bytes,
            .timestamp = oldest.timestamp,
            .line_idx = i,
        };
    }

    // Step 3: Walk from second-oldest to newest, updating attributions.
    // items[items.len-1] is oldest, items[0] is newest (head).
    if (items.len > 1) {
        var idx = items.len - 1;
        while (idx > 0) {
            idx -= 1;
            const newer = items[idx];
            const older_idx = idx + 1;
            const older = items[older_idx];

            // If blob hash is the same, no changes — keep attributions as-is
            if (std.mem.eql(u8, &newer.blob_hash, &older.blob_hash)) continue;

            // Load both versions
            const old_lines = try loadBlobLines(allocator, store, older.blob_hash);
            defer {
                for (old_lines) |line| allocator.free(line);
                allocator.free(old_lines);
            }
            const new_lines = try loadBlobLines(allocator, store, newer.blob_hash);
            defer {
                for (new_lines) |line| allocator.free(line);
                allocator.free(new_lines);
            }

            // Match lines via LCS
            const mapping = try matchLines(allocator, old_lines, new_lines);
            defer allocator.free(mapping);

            // Build new attributions
            const new_attrs = try allocator.alloc(Attribution, new_lines.len);
            for (new_attrs, 0..) |*attr, ni| {
                if (mapping[ni]) |old_idx| {
                    // This line existed in old version — inherit attribution
                    if (old_idx < attributions.len) {
                        attr.* = attributions[old_idx];
                    } else {
                        // Shouldn't happen, but safe fallback
                        attr.* = .{
                            .commit_hash = newer.commit_hash,
                            .author_kind = newer.author_kind,
                            .author_bytes = newer.author_bytes,
                            .timestamp = newer.timestamp,
                            .line_idx = ni,
                        };
                    }
                } else {
                    // New or changed line — attribute to this commit
                    attr.* = .{
                        .commit_hash = newer.commit_hash,
                        .author_kind = newer.author_kind,
                        .author_bytes = newer.author_bytes,
                        .timestamp = newer.timestamp,
                        .line_idx = ni,
                    };
                }
            }

            // Replace attributions
            allocator.free(attributions);
            attributions = new_attrs;
        }
    }

    // Step 4: Load final version lines and build BlameLine result
    const head_blob = items[0].blob_hash;
    const final_lines = try loadBlobLines(allocator, store, head_blob);
    defer {
        for (final_lines) |line| allocator.free(line);
        allocator.free(final_lines);
    }

    var result_lines = try allocator.alloc(BlameLine, final_lines.len);
    errdefer {
        for (result_lines[0..final_lines.len]) |rl| {
            allocator.free(rl.text);
        }
        allocator.free(result_lines);
    }

    for (result_lines, 0..) |*rl, i| {
        rl.* = .{
            .line_num = i + 1,
            .commit_hash = attributions[i].commit_hash,
            .author = .{
                .kind = attributions[i].author_kind,
                .bytes = attributions[i].author_bytes,
            },
            .timestamp = attributions[i].timestamp,
            .text = try allocator.dupe(u8, final_lines[i]),
        };
    }

    const pool_slice = try author_bytes_pool.toOwnedSlice(allocator);

    return .{
        .lines = result_lines,
        .author_bytes_pool = pool_slice,
        .allocator = allocator,
    };
}

const Attribution = struct {
    commit_hash: Hash,
    author_kind: object.IdentityKind,
    /// Borrowed from `author_bytes_pool` in `blameFile`.
    author_bytes: []const u8,
    timestamp: u64,
    line_idx: usize,
};

/// Find a blob in a tree by walking a "/"-separated path.
/// Returns null if any component is not found.
pub fn findBlobInTree(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    path: []const u8,
) !?Hash {
    var components: std.ArrayList([]const u8) = .empty;
    defer components.deinit(allocator);

    var iter = std.mem.splitScalar(u8, path, '/');
    while (iter.next()) |component| {
        if (component.len > 0) {
            try components.append(allocator, component);
        }
    }

    if (components.items.len == 0) return null;

    var current_tree_hash = tree_hash;

    for (components.items, 0..) |component, ci| {
        var tree_obj = try store.get(allocator, current_tree_hash);
        defer tree_obj.deinit(allocator);

        if (tree_obj != .tree) return null;

        const is_last = (ci == components.items.len - 1);
        var found = false;
        for (tree_obj.tree.entries) |entry| {
            if (std.mem.eql(u8, entry.name, component)) {
                if (is_last) {
                    // Last component: should be a blob
                    if (entry.mode == .blob) {
                        return entry.object_hash;
                    } else {
                        return null; // Found a tree/symlink at file position
                    }
                } else {
                    // Intermediate: should be a tree
                    if (entry.mode == .tree) {
                        current_tree_hash = entry.object_hash;
                        found = true;
                        break;
                    } else {
                        return null; // Not a directory
                    }
                }
            }
        }
        if (!found and !is_last) return null;
    }

    return null;
}

/// Load blob data and split into lines (without trailing newlines).
fn loadBlobLines(allocator: Allocator, store: *store_mod.ObjectStore, blob_hash: Hash) ![][]const u8 {
    var blob_obj = try store.get(allocator, blob_hash);
    defer blob_obj.deinit(allocator);

    if (blob_obj != .blob) return error.NotABlob;

    const data = blob_obj.blob.data;
    return splitLines(allocator, data);
}

/// Split text into lines. Each line is an owned copy.
fn splitLines(allocator: Allocator, data: []const u8) ![][]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    if (data.len == 0) return try lines.toOwnedSlice(allocator);

    var iter = std.mem.splitScalar(u8, data, '\n');
    while (iter.next()) |line| {
        try lines.append(allocator, try allocator.dupe(u8, line));
    }

    // If data ends with '\n', the split produces an empty trailing element.
    // Remove it to match expected behavior (trailing newline doesn't create blank line).
    if (data[data.len - 1] == '\n' and lines.items.len > 0) {
        if (lines.pop()) |last| {
            allocator.free(last);
        }
    }

    return try lines.toOwnedSlice(allocator);
}

/// LCS-based line matching. For each line in `new_lines`, returns the index
/// in `old_lines` it corresponds to (or null if it's new/changed).
pub fn matchLines(
    allocator: Allocator,
    old_lines: []const []const u8,
    new_lines: []const []const u8,
) ![]?usize {
    const m = old_lines.len;
    const n = new_lines.len;

    // Build DP table: dp[i][j] = LCS length of old[0..i] and new[0..j]
    // Use (m+1) x (n+1) table
    const dp = try allocator.alloc([]u32, m + 1);
    defer {
        for (dp) |row| allocator.free(row);
        allocator.free(dp);
    }
    for (dp) |*row| {
        row.* = try allocator.alloc(u32, n + 1);
        @memset(row.*, 0);
    }

    for (1..m + 1) |i| {
        for (1..n + 1) |j| {
            if (std.mem.eql(u8, old_lines[i - 1], new_lines[j - 1])) {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = @max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }

    // Backtrack to find the mapping
    var mapping = try allocator.alloc(?usize, n);
    @memset(mapping, null);

    var i = m;
    var j = n;
    while (i > 0 and j > 0) {
        if (std.mem.eql(u8, old_lines[i - 1], new_lines[j - 1])) {
            mapping[j - 1] = i - 1;
            i -= 1;
            j -= 1;
        } else if (dp[i - 1][j] >= dp[i][j - 1]) {
            i -= 1;
        } else {
            j -= 1;
        }
    }

    return mapping;
}

// ===========================================================================
// Test helpers
// ===========================================================================

/// Create a commit with a single file, store blob + tree + commit, return commit hash.
/// `author_mid` is wrapped as an 8-byte LE opaque Identity.
fn makeFileCommit(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    filename: []const u8,
    content: []const u8,
    parents: []const Hash,
    msg: []const u8,
    author_mid: u64,
    timestamp: u64,
) !Hash {
    const blob_hash = try th.makeBlob(allocator, store, content);

    const entries = [_]object.TreeEntry{
        .{ .name = filename, .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try th.makeTree(allocator, store, &entries);

    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, author_mid, .little);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = @constCast(parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0} ** 32,
        .message = msg,
        .timestamp = timestamp,
        .signature = .{0} ** 64,
    } };
    return store.put(allocator, commit_obj);
}

/// Create a commit with multiple files.
fn makeMultiFileCommit(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    filenames: []const []const u8,
    contents: []const []const u8,
    parents: []const Hash,
    msg: []const u8,
    author_mid: u64,
    timestamp: u64,
) !Hash {
    var entries = try allocator.alloc(object.TreeEntry, filenames.len);
    defer allocator.free(entries);

    for (filenames, contents, 0..) |fname, content, i| {
        const blob_hash = try th.makeBlob(allocator, store, content);
        entries[i] = .{ .name = fname, .mode = .blob, .object_hash = blob_hash };
    }

    const tree_hash = try th.makeTree(allocator, store, entries);

    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, author_mid, .little);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = @constCast(parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0} ** 32,
        .message = msg,
        .timestamp = timestamp,
        .signature = .{0} ** 64,
    } };
    return store.put(allocator, commit_obj);
}

// ===========================================================================
// Tests
// ===========================================================================

test "blame single commit" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nline2\nline3\n",
        &.{},
        "initial commit",
        42,
        1000,
    );

    var result = try blameFile(allocator, &store, commit_a, "file.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.lines.len);

    // All lines attributed to the single commit
    try std.testing.expectEqual(@as(usize, 1), result.lines[0].line_num);
    try std.testing.expectEqual(commit_a, result.lines[0].commit_hash);
    try std.testing.expectEqual(object.IdentityKind.@"opaque", result.lines[0].author.kind);
    try std.testing.expectEqual(@as(usize, 8), result.lines[0].author.bytes.len);
    try std.testing.expectEqual(@as(u64, 42), std.mem.readInt(u64, result.lines[0].author.bytes[0..8], .little));
    try std.testing.expectEqual(@as(u64, 1000), result.lines[0].timestamp);
    try std.testing.expectEqualStrings("line1", result.lines[0].text);

    try std.testing.expectEqual(@as(usize, 2), result.lines[1].line_num);
    try std.testing.expectEqualStrings("line2", result.lines[1].text);
    try std.testing.expectEqual(commit_a, result.lines[1].commit_hash);

    try std.testing.expectEqual(@as(usize, 3), result.lines[2].line_num);
    try std.testing.expectEqualStrings("line3", result.lines[2].text);
    try std.testing.expectEqual(commit_a, result.lines[2].commit_hash);
}

test "blame two commits" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Commit A: line1, line2, line3
    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nline2\nline3\n",
        &.{},
        "initial",
        42,
        1000,
    );

    // Commit B: line1, MODIFIED, line3
    const commit_b = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nMODIFIED\nline3\n",
        &.{commit_a},
        "modify line2",
        42,
        2000,
    );

    var result = try blameFile(allocator, &store, commit_b, "file.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.lines.len);

    // Line 1: unchanged, from commit A
    try std.testing.expectEqual(commit_a, result.lines[0].commit_hash);
    try std.testing.expectEqualStrings("line1", result.lines[0].text);

    // Line 2: modified, from commit B
    try std.testing.expectEqual(commit_b, result.lines[1].commit_hash);
    try std.testing.expectEqualStrings("MODIFIED", result.lines[1].text);

    // Line 3: unchanged, from commit A
    try std.testing.expectEqual(commit_a, result.lines[2].commit_hash);
    try std.testing.expectEqualStrings("line3", result.lines[2].text);
}

test "blame tracks additions" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Commit A: line1, line2
    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nline2\n",
        &.{},
        "initial",
        42,
        1000,
    );

    // Commit B: line1, NEW LINE, line2
    const commit_b = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nNEW LINE\nline2\n",
        &.{commit_a},
        "add middle line",
        42,
        2000,
    );

    var result = try blameFile(allocator, &store, commit_b, "file.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.lines.len);

    // Line 1: from A
    try std.testing.expectEqual(commit_a, result.lines[0].commit_hash);
    try std.testing.expectEqualStrings("line1", result.lines[0].text);

    // Line 2: new, from B
    try std.testing.expectEqual(commit_b, result.lines[1].commit_hash);
    try std.testing.expectEqualStrings("NEW LINE", result.lines[1].text);

    // Line 3: from A (was line2)
    try std.testing.expectEqual(commit_a, result.lines[2].commit_hash);
    try std.testing.expectEqualStrings("line2", result.lines[2].text);
}

test "blame tracks deletions" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Commit A: line1, line2, line3
    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nline2\nline3\n",
        &.{},
        "initial",
        42,
        1000,
    );

    // Commit B: line1, line3 (line2 deleted)
    const commit_b = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "line1\nline3\n",
        &.{commit_a},
        "delete line2",
        42,
        2000,
    );

    var result = try blameFile(allocator, &store, commit_b, "file.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.lines.len);

    // Both remaining lines attributed to commit A
    try std.testing.expectEqual(commit_a, result.lines[0].commit_hash);
    try std.testing.expectEqualStrings("line1", result.lines[0].text);

    try std.testing.expectEqual(commit_a, result.lines[1].commit_hash);
    try std.testing.expectEqualStrings("line3", result.lines[1].text);
}

test "blame file not found" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "file.txt",
        "content\n",
        &.{},
        "initial",
        42,
        1000,
    );

    const result = blameFile(allocator, &store, commit_a, "nonexistent.txt");
    try std.testing.expectError(error.FileNotFound, result);
}

test "lcs identical lines" {
    const allocator = std.testing.allocator;

    const lines = [_][]const u8{ "a", "b", "c" };
    const mapping = try matchLines(allocator, &lines, &lines);
    defer allocator.free(mapping);

    try std.testing.expectEqual(@as(usize, 3), mapping.len);
    try std.testing.expectEqual(@as(?usize, 0), mapping[0]);
    try std.testing.expectEqual(@as(?usize, 1), mapping[1]);
    try std.testing.expectEqual(@as(?usize, 2), mapping[2]);
}

test "lcs completely different" {
    const allocator = std.testing.allocator;

    const old = [_][]const u8{ "a", "b", "c" };
    const new = [_][]const u8{ "x", "y", "z" };
    const mapping = try matchLines(allocator, &old, &new);
    defer allocator.free(mapping);

    try std.testing.expectEqual(@as(usize, 3), mapping.len);
    try std.testing.expectEqual(@as(?usize, null), mapping[0]);
    try std.testing.expectEqual(@as(?usize, null), mapping[1]);
    try std.testing.expectEqual(@as(?usize, null), mapping[2]);
}

test "blame nested file path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Create nested tree: src/main.txt
    const blob_hash = try th.makeBlob(allocator, &store, "hello\nworld\n");

    const inner_entries = [_]object.TreeEntry{
        .{ .name = "main.txt", .mode = .blob, .object_hash = blob_hash },
    };
    const inner_tree = try th.makeTree(allocator, &store, &inner_entries);

    const outer_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = inner_tree },
    };
    const outer_tree = try th.makeTree(allocator, &store, &outer_entries);

    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 42, .little);
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = outer_tree,
        .parents = @constCast(&[_]Hash{}),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0} ** 32,
        .message = "initial",
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    const commit_hash = try store.put(allocator, commit_obj);

    var result = try blameFile(allocator, &store, commit_hash, "src/main.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 2), result.lines.len);
    try std.testing.expectEqualStrings("hello", result.lines[0].text);
    try std.testing.expectEqualStrings("world", result.lines[1].text);
    try std.testing.expectEqual(commit_hash, result.lines[0].commit_hash);
}

test "blame three commits progressive changes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Commit A: a, b
    const commit_a = try makeFileCommit(
        allocator,
        &store,
        "f.txt",
        "a\nb\n",
        &.{},
        "first",
        1,
        100,
    );

    // Commit B: a, b, c (added line)
    const commit_b = try makeFileCommit(
        allocator,
        &store,
        "f.txt",
        "a\nb\nc\n",
        &.{commit_a},
        "second",
        2,
        200,
    );

    // Commit C: a, X, c (modified middle line)
    const commit_c = try makeFileCommit(
        allocator,
        &store,
        "f.txt",
        "a\nX\nc\n",
        &.{commit_b},
        "third",
        3,
        300,
    );

    var result = try blameFile(allocator, &store, commit_c, "f.txt");
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 3), result.lines.len);

    // "a" from commit A
    try std.testing.expectEqual(commit_a, result.lines[0].commit_hash);
    try std.testing.expectEqualStrings("a", result.lines[0].text);

    // "X" from commit C (was "b" in A and B, changed to "X" in C)
    try std.testing.expectEqual(commit_c, result.lines[1].commit_hash);
    try std.testing.expectEqualStrings("X", result.lines[1].text);

    // "c" from commit B
    try std.testing.expectEqual(commit_b, result.lines[2].commit_hash);
    try std.testing.expectEqualStrings("c", result.lines[2].text);
}

test "findBlobInTree returns null for nonexistent path" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_hash = try th.makeBlob(allocator, &store, "data");
    const entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try th.makeTree(allocator, &store, &entries);

    const result = try findBlobInTree(allocator, &store, tree_hash, "nonexistent.txt");
    try std.testing.expectEqual(@as(?Hash, null), result);
}

test "findBlobInTree finds file at root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_hash = try th.makeBlob(allocator, &store, "data");
    const entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try th.makeTree(allocator, &store, &entries);

    const result = try findBlobInTree(allocator, &store, tree_hash, "a.txt");
    try std.testing.expectEqual(@as(?Hash, blob_hash), result);
}

test "splitLines handles trailing newline" {
    const allocator = std.testing.allocator;

    const lines = try splitLines(allocator, "a\nb\nc\n");
    defer {
        for (lines) |line| allocator.free(line);
        allocator.free(lines);
    }

    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("a", lines[0]);
    try std.testing.expectEqualStrings("b", lines[1]);
    try std.testing.expectEqualStrings("c", lines[2]);
}

test "splitLines handles no trailing newline" {
    const allocator = std.testing.allocator;

    const lines = try splitLines(allocator, "a\nb\nc");
    defer {
        for (lines) |line| allocator.free(line);
        allocator.free(lines);
    }

    try std.testing.expectEqual(@as(usize, 3), lines.len);
    try std.testing.expectEqualStrings("a", lines[0]);
    try std.testing.expectEqualStrings("b", lines[1]);
    try std.testing.expectEqualStrings("c", lines[2]);
}

test "splitLines empty input" {
    const allocator = std.testing.allocator;

    const lines = try splitLines(allocator, "");
    defer allocator.free(lines);

    try std.testing.expectEqual(@as(usize, 0), lines.len);
}
