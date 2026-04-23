// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const graph_mod = @import("graph.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

const bisect_file = ".mkit/bisect";

pub const BisectState = struct {
    orig_head: Hash,
    orig_branch: ?[]const u8,
    bad_hash: ?Hash,
    good_hashes: []Hash,
    allocator: Allocator,

    pub fn deinit(self: *BisectState) void {
        if (self.orig_branch) |branch| {
            self.allocator.free(branch);
        }
        self.allocator.free(self.good_hashes);
    }
};

pub const BisectStep = union(enum) {
    /// We are now testing this commit; `remaining` says how many candidates are left.
    testing: struct { hash: Hash, remaining: usize },
    /// The first bad commit has been found.
    found: Hash,
    /// Need both good and bad before we can compute a midpoint.
    need_more: void,
};

/// Check if a bisect session is currently in progress.
pub fn isBisectInProgress(io: std.Io, mkit_dir: std.Io.Dir) bool {
    mkit_dir.access(io, bisect_file, .{}) catch return false;
    return true;
}

/// Read bisect state from `.mkit/bisect`.
///
/// File format (text):
/// - Line 1: orig_head hex hash
/// - Line 2: orig_branch name (or empty for detached)
/// - Line 3: bad hash (or empty if not set)
/// - Line 4+: good hashes (one per line)
pub fn readState(allocator: Allocator, io: std.Io, mkit_dir: std.Io.Dir) !BisectState {
    const content = mkit_dir.readFileAlloc(io, bisect_file, allocator, .limited(1024 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return error.NoBisectInProgress,
        else => return err,
    };
    defer allocator.free(content);

    if (content.len == 0) return error.InvalidBisectState;

    var lines = std.mem.splitScalar(u8, content, '\n');

    // Line 1: orig_head
    const orig_head_line = lines.next() orelse return error.InvalidBisectState;
    const orig_head_trimmed = std.mem.trimEnd(u8, orig_head_line, "\r ");
    if (orig_head_trimmed.len == 0) return error.InvalidBisectState;
    const orig_head = hash_mod.fromHex(orig_head_trimmed) catch return error.InvalidBisectState;

    // Line 2: orig_branch (or empty)
    const branch_line = lines.next() orelse return error.InvalidBisectState;
    const branch_trimmed = std.mem.trimEnd(u8, branch_line, "\r ");
    const orig_branch: ?[]const u8 = if (branch_trimmed.len > 0)
        try allocator.dupe(u8, branch_trimmed)
    else
        null;
    errdefer if (orig_branch) |b| allocator.free(b);

    // Line 3: bad hash (or empty)
    const bad_line = lines.next() orelse return error.InvalidBisectState;
    const bad_trimmed = std.mem.trimEnd(u8, bad_line, "\r ");
    const bad_hash: ?Hash = if (bad_trimmed.len > 0)
        hash_mod.fromHex(bad_trimmed) catch return error.InvalidBisectState
    else
        null;

    // Remaining lines: good hashes
    var good_list: std.ArrayList(Hash) = .empty;
    errdefer good_list.deinit(allocator);

    while (lines.next()) |line| {
        const line_trimmed = std.mem.trimEnd(u8, line, "\r ");
        if (line_trimmed.len == 0) continue;
        const h = hash_mod.fromHex(line_trimmed) catch return error.InvalidBisectState;
        try good_list.append(allocator, h);
    }

    return BisectState{
        .orig_head = orig_head,
        .orig_branch = orig_branch,
        .bad_hash = bad_hash,
        .good_hashes = try good_list.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

/// Write bisect state to `.mkit/bisect`.
pub fn writeState(io: std.Io, mkit_dir: std.Io.Dir, state: BisectState) !void {
    // Calculate buffer size
    // orig_head (64) + \n + branch + \n + bad (64 or empty) + \n + good hashes
    const branch_len = if (state.orig_branch) |b| b.len else 0;
    const bad_len: usize = if (state.bad_hash != null) 64 else 0;
    const total_len = 64 + 1 + branch_len + 1 + bad_len + 1 + state.good_hashes.len * 65;

    const buf = try state.allocator.alloc(u8, total_len);
    defer state.allocator.free(buf);

    var pos: usize = 0;

    // Line 1: orig_head
    const orig_hex = hash_mod.toHex(state.orig_head);
    @memcpy(buf[pos..][0..64], &orig_hex);
    pos += 64;
    buf[pos] = '\n';
    pos += 1;

    // Line 2: orig_branch
    if (state.orig_branch) |branch| {
        @memcpy(buf[pos..][0..branch.len], branch);
        pos += branch.len;
    }
    buf[pos] = '\n';
    pos += 1;

    // Line 3: bad hash
    if (state.bad_hash) |bad| {
        const bad_hex = hash_mod.toHex(bad);
        @memcpy(buf[pos..][0..64], &bad_hex);
        pos += 64;
    }
    buf[pos] = '\n';
    pos += 1;

    // Lines 4+: good hashes
    for (state.good_hashes) |good| {
        const good_hex = hash_mod.toHex(good);
        @memcpy(buf[pos..][0..64], &good_hex);
        pos += 64;
        buf[pos] = '\n';
        pos += 1;
    }

    const file = try mkit_dir.createFile(io, bisect_file, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, buf[0..pos]);
}

/// Enumerate the range of candidate commits between bad and good.
/// BFS from bad hash, stopping at any commit in good_hashes set or their ancestors.
/// Returns the list of candidate commits (order: BFS from bad).
pub fn enumerateRange(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    bad: Hash,
    good_hashes: []const Hash,
) ![]Hash {
    // Build the set of good commits and their ancestors
    var good_set = std.AutoHashMap(Hash, void).init(allocator);
    defer good_set.deinit();

    for (good_hashes) |good| {
        try graph_mod.collectAncestorSet(allocator, store, good, &good_set);
    }

    // BFS from bad, collect candidates that are not in the good set
    var candidates: std.ArrayList(Hash) = .empty;
    errdefer candidates.deinit(allocator);

    var visited = std.AutoHashMap(Hash, void).init(allocator);
    defer visited.deinit();

    var queue: std.ArrayList(Hash) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, bad);

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const current = queue.items[head];

        const gop = try visited.getOrPut(current);
        if (gop.found_existing) continue;

        // If this is a good commit or ancestor of good, stop this path
        if (good_set.contains(current)) continue;

        try candidates.append(allocator, current);

        // Enqueue parents
        var obj = store.get(allocator, current) catch continue;
        defer obj.deinit(allocator);
        if (obj != .commit) continue;

        for (obj.commit.parents) |parent| {
            try queue.append(allocator, parent);
        }
    }

    return candidates.toOwnedSlice(allocator);
}

/// Pick the midpoint commit from a list of candidates.
/// Returns candidates[len/2].
pub fn pickMidpoint(candidates: []const Hash) Hash {
    if (candidates.len == 0) return hash_mod.zero;
    return candidates[candidates.len / 2];
}

/// Remove the bisect state file.
pub fn cleanupBisect(io: std.Io, mkit_dir: std.Io.Dir) !void {
    mkit_dir.deleteFile(io, bisect_file) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// ===========================================================================
// Tests
// ===========================================================================

test "state write/read round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    const orig_head = hash_mod.hash("orig-head");
    const bad = hash_mod.hash("bad-commit");
    const good_1 = hash_mod.hash("good-1");
    const good_2 = hash_mod.hash("good-2");

    const good_hashes = try allocator.alloc(Hash, 2);
    defer allocator.free(good_hashes);
    good_hashes[0] = good_1;
    good_hashes[1] = good_2;

    const branch = try allocator.dupe(u8, "main");
    defer allocator.free(branch);

    const state = BisectState{
        .orig_head = orig_head,
        .orig_branch = branch,
        .bad_hash = bad,
        .good_hashes = good_hashes,
        .allocator = allocator,
    };

    try writeState(std.testing.io, tmp.dir, state);

    var read_state = try readState(allocator, std.testing.io, tmp.dir);
    defer read_state.deinit();

    try std.testing.expectEqual(orig_head, read_state.orig_head);
    try std.testing.expectEqualStrings("main", read_state.orig_branch.?);
    try std.testing.expectEqual(bad, read_state.bad_hash.?);
    try std.testing.expectEqual(@as(usize, 2), read_state.good_hashes.len);
    try std.testing.expectEqual(good_1, read_state.good_hashes[0]);
    try std.testing.expectEqual(good_2, read_state.good_hashes[1]);
}

test "state write/read with no bad hash and no branch" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    const good_hashes = try allocator.alloc(Hash, 0);
    defer allocator.free(good_hashes);

    const state = BisectState{
        .orig_head = hash_mod.hash("head"),
        .orig_branch = null,
        .bad_hash = null,
        .good_hashes = good_hashes,
        .allocator = allocator,
    };

    try writeState(std.testing.io, tmp.dir, state);

    var read_state = try readState(allocator, std.testing.io, tmp.dir);
    defer read_state.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), read_state.orig_branch);
    try std.testing.expectEqual(@as(?Hash, null), read_state.bad_hash);
    try std.testing.expectEqual(@as(usize, 0), read_state.good_hashes.len);
}

test "enumerateRange on a linear chain of 8 commits" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    // Create linear chain: C1 -> C2 -> C3 -> C4 -> C5 -> C6 -> C7 -> C8
    const blob = try th.makeBlob(allocator, &store, "data");
    const tree_entries = [_]object.TreeEntry{
        .{ .name = "f.txt", .mode = .blob, .object_hash = blob },
    };
    const tree = try th.makeTree(allocator, &store, &tree_entries);

    var commits: [8]Hash = undefined;
    commits[0] = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    for (1..8) |i| {
        const parents = [_]Hash{commits[i - 1]};
        commits[i] = try th.makeCommit(allocator, &store, tree, &parents, "commit");
    }

    // bad = C8, good = [C2]
    // Should enumerate C8, C7, C6, C5, C4, C3 (stop before C2 and C1)
    const good = [_]Hash{commits[1]}; // C2
    const candidates = try enumerateRange(allocator, &store, commits[7], &good);
    defer allocator.free(candidates);

    // Should have 6 candidates: C3, C4, C5, C6, C7, C8 (BFS order from bad)
    try std.testing.expectEqual(@as(usize, 6), candidates.len);
    // First should be C8 (bad itself)
    try std.testing.expectEqual(commits[7], candidates[0]);
}

test "pickMidpoint returns middle element" {
    const c1 = hash_mod.hash("c1");
    const c2 = hash_mod.hash("c2");
    const c3 = hash_mod.hash("c3");
    const c4 = hash_mod.hash("c4");
    const c5 = hash_mod.hash("c5");

    const candidates = [_]Hash{ c1, c2, c3, c4, c5 };
    const mid = pickMidpoint(&candidates);
    // len=5, 5/2=2, so index 2 = c3
    try std.testing.expectEqual(c3, mid);

    // Even count
    const even = [_]Hash{ c1, c2, c3, c4 };
    const mid_even = pickMidpoint(&even);
    // len=4, 4/2=2, so index 2 = c3
    try std.testing.expectEqual(c3, mid_even);

    // Single element
    const single = [_]Hash{c1};
    const mid_single = pickMidpoint(&single);
    try std.testing.expectEqual(c1, mid_single);
}

test "pickMidpoint empty returns zero" {
    const candidates = [_]Hash{};
    const mid = pickMidpoint(&candidates);
    try std.testing.expectEqual(hash_mod.zero, mid);
}

test "isBisectInProgress detection" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // No bisect file -> not in progress
    try std.testing.expect(!isBisectInProgress(std.testing.io, tmp.dir));

    // Create bisect file -> in progress
    const file = try tmp.dir.createFile(std.testing.io, bisect_file, .{});
    try file.writeStreamingAll(std.testing.io, "placeholder\n");
    file.close(std.testing.io);

    try std.testing.expect(isBisectInProgress(std.testing.io, tmp.dir));
}

test "cleanupBisect removes state file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    const file = try tmp.dir.createFile(std.testing.io, bisect_file, .{});
    try file.writeStreamingAll(std.testing.io, "data\n");
    file.close(std.testing.io);

    try std.testing.expect(isBisectInProgress(std.testing.io, tmp.dir));

    try cleanupBisect(std.testing.io, tmp.dir);

    try std.testing.expect(!isBisectInProgress(std.testing.io, tmp.dir));
}

test "cleanupBisect on nonexistent file is fine" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");
    try cleanupBisect(std.testing.io, tmp.dir);
}

test "enumerateRange with diamond merge" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // C1 <- C2, C1 <- C3, C2+C3 <- C4 (diamond)
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    const c2 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c2");
    const c3 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c3");
    const c4 = try th.makeCommit(allocator, &store, tree, &.{ c2, c3 }, "c4");

    // bad=C4, good=[C1]. Should get C2, C3, C4 (all non-good commits)
    const good = [_]Hash{c1};
    const candidates = try enumerateRange(allocator, &store, c4, &good);
    defer allocator.free(candidates);

    try std.testing.expectEqual(@as(usize, 3), candidates.len);
    // First candidate should be C4 (BFS starts from bad)
    try std.testing.expectEqual(c4, candidates[0]);
}

test "enumerateRange same good and bad" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");

    // bad=C1, good=[C1]. C1 is in good set, so no candidates.
    const good = [_]Hash{c1};
    const candidates = try enumerateRange(allocator, &store, c1, &good);
    defer allocator.free(candidates);

    try std.testing.expectEqual(@as(usize, 0), candidates.len);
}

test "readState rejects empty file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // Create empty bisect file
    const file = try tmp.dir.createFile(std.testing.io, bisect_file, .{});
    file.close(std.testing.io);

    try std.testing.expectError(error.InvalidBisectState, readState(allocator, std.testing.io, tmp.dir));
}
