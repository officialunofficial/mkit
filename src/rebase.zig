// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const graph_mod = @import("graph.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

const rebase_dir = ".mkit/rebase-apply";
const head_name_file = "head-name";
const orig_head_file = "orig-head";
const onto_file = "onto";
const todo_file = "todo";
const done_file = "done";

pub const RebaseState = struct {
    head_name: []const u8,
    orig_head: Hash,
    onto: Hash,
    todo: []Hash,
    done: []Hash,
    allocator: Allocator,

    pub fn deinit(self: *RebaseState) void {
        self.allocator.free(self.head_name);
        self.allocator.free(self.todo);
        self.allocator.free(self.done);
    }
};

/// Check if a rebase is currently in progress.
pub fn isRebaseInProgress(mkit_dir: std.fs.Dir) bool {
    mkit_dir.access(rebase_dir, .{}) catch return false;
    return true;
}

/// Read rebase state from the `.mkit/rebase-apply/` directory.
pub fn readState(allocator: Allocator, mkit_dir: std.fs.Dir) !RebaseState {
    var dir = mkit_dir.openDir(rebase_dir, .{}) catch return error.NoRebaseInProgress;
    defer dir.close();

    // Read head-name
    const head_name_raw = dir.readFileAlloc(allocator, head_name_file, 4096) catch return error.InvalidRebaseState;
    const head_name = std.mem.trimRight(u8, head_name_raw, "\n\r ");
    const head_name_duped = allocator.dupe(u8, head_name) catch {
        allocator.free(head_name_raw);
        return error.OutOfMemory;
    };
    allocator.free(head_name_raw);
    errdefer allocator.free(head_name_duped);

    // Read orig-head
    const orig_head_raw = dir.readFileAlloc(allocator, orig_head_file, 128) catch return error.InvalidRebaseState;
    defer allocator.free(orig_head_raw);
    const orig_head_trimmed = std.mem.trimRight(u8, orig_head_raw, "\n\r ");
    const orig_head = hash_mod.fromHex(orig_head_trimmed) catch return error.InvalidRebaseState;

    // Read onto
    const onto_raw = dir.readFileAlloc(allocator, onto_file, 128) catch return error.InvalidRebaseState;
    defer allocator.free(onto_raw);
    const onto_trimmed = std.mem.trimRight(u8, onto_raw, "\n\r ");
    const onto = hash_mod.fromHex(onto_trimmed) catch return error.InvalidRebaseState;

    // Read todo
    const todo = try readHashList(allocator, dir, todo_file);
    errdefer allocator.free(todo);

    // Read done
    const done = try readHashList(allocator, dir, done_file);
    errdefer allocator.free(done);

    return RebaseState{
        .head_name = head_name_duped,
        .orig_head = orig_head,
        .onto = onto,
        .todo = todo,
        .done = done,
        .allocator = allocator,
    };
}

/// Write rebase state to the `.mkit/rebase-apply/` directory.
pub fn writeState(mkit_dir: std.fs.Dir, state: RebaseState) !void {
    // Ensure rebase-apply directory exists
    mkit_dir.makeDir(rebase_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var dir = try mkit_dir.openDir(rebase_dir, .{});
    defer dir.close();

    // Write head-name
    try writeFileContent(dir, head_name_file, state.head_name);

    // Write orig-head
    const orig_hex = hash_mod.toHex(state.orig_head);
    try writeFileContent(dir, orig_head_file, &orig_hex);

    // Write onto
    const onto_hex = hash_mod.toHex(state.onto);
    try writeFileContent(dir, onto_file, &onto_hex);

    // Write todo
    try writeHashList(state.allocator, dir, todo_file, state.todo);

    // Write done
    try writeHashList(state.allocator, dir, done_file, state.done);
}

/// Collect commits to replay: walk first-parent chain from head_hash back,
/// stopping when we reach onto_hash or an ancestor of onto_hash.
/// Returns commits in oldest-first order.
pub fn collectCommitsToReplay(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    head_hash: Hash,
    onto_hash: Hash,
) ![]Hash {
    // If they are the same commit, nothing to replay
    if (std.mem.eql(u8, &head_hash, &onto_hash)) {
        return allocator.alloc(Hash, 0);
    }

    // Collect ancestors of onto (for stopping condition)
    var onto_ancestors = std.AutoHashMap(Hash, void).init(allocator);
    defer onto_ancestors.deinit();
    try graph_mod.collectAncestorSet(allocator, store, onto_hash, &onto_ancestors);

    // Walk first-parent chain from head_hash, collecting commits
    var commits: std.ArrayList(Hash) = .{};
    errdefer commits.deinit(allocator);

    var current = head_hash;
    const max_depth: usize = 10000; // safety limit
    var depth: usize = 0;

    while (depth < max_depth) : (depth += 1) {
        // Stop if we have reached onto or an ancestor of onto
        if (std.mem.eql(u8, &current, &onto_hash)) break;
        if (onto_ancestors.contains(current)) break;

        try commits.append(allocator, current);

        // Walk to first parent
        var obj = store.get(allocator, current) catch break;
        defer obj.deinit(allocator);
        if (obj != .commit) break;
        if (obj.commit.parents.len == 0) break;
        current = obj.commit.parents[0];
    }

    // Reverse to get oldest-first
    const result = try commits.toOwnedSlice(allocator);
    std.mem.reverse(Hash, result);
    return result;
}

/// Remove the rebase state directory.
pub fn cleanupRebase(mkit_dir: std.fs.Dir) !void {
    mkit_dir.deleteTree(rebase_dir) catch {};
}

// ===========================================================================
// Internal helpers
// ===========================================================================

fn readHashList(allocator: Allocator, dir: std.fs.Dir, filename: []const u8) ![]Hash {
    const content = dir.readFileAlloc(allocator, filename, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc(Hash, 0),
        else => return err,
    };
    defer allocator.free(content);

    const trimmed = std.mem.trimRight(u8, content, "\n\r ");
    if (trimmed.len == 0) return allocator.alloc(Hash, 0);

    var list: std.ArrayList(Hash) = .{};
    errdefer list.deinit(allocator);

    var lines = std.mem.splitScalar(u8, trimmed, '\n');
    while (lines.next()) |line| {
        const line_trimmed = std.mem.trimRight(u8, line, "\r ");
        if (line_trimmed.len == 0) continue;
        const h = hash_mod.fromHex(line_trimmed) catch return error.InvalidRebaseState;
        try list.append(allocator, h);
    }

    return list.toOwnedSlice(allocator);
}

fn writeHashList(allocator: Allocator, dir: std.fs.Dir, filename: []const u8, hashes: []const Hash) !void {
    if (hashes.len == 0) {
        try writeFileContent(dir, filename, "");
        return;
    }

    // Each hash is 64 hex chars + newline
    const total_len = hashes.len * 65;
    const buf = try allocator.alloc(u8, total_len);
    defer allocator.free(buf);

    var pos: usize = 0;
    for (hashes) |h| {
        const hex = hash_mod.toHex(h);
        @memcpy(buf[pos..][0..64], &hex);
        buf[pos + 64] = '\n';
        pos += 65;
    }

    try writeFileContent(dir, filename, buf);
}

fn writeFileContent(dir: std.fs.Dir, filename: []const u8, content: []const u8) !void {
    const file = try dir.createFile(filename, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    if (content.len == 0 or content[content.len - 1] != '\n') {
        try file.writeAll("\n");
    }
}

// ===========================================================================
// Tests
// ===========================================================================

test "collectCommitsToReplay on a linear chain" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    // Create a linear chain: C1 -> C2 -> C3 -> C4
    const blob = try th.makeBlob(allocator, &store, "data");
    const tree_entries = [_]object.TreeEntry{
        .{ .name = "f.txt", .mode = .blob, .object_hash = blob },
    };
    const tree = try th.makeTree(allocator, &store, &tree_entries);

    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    const c1_parents = [_]Hash{c1};
    const c2 = try th.makeCommit(allocator, &store, tree, &c1_parents, "c2");
    const c2_parents = [_]Hash{c2};
    const c3 = try th.makeCommit(allocator, &store, tree, &c2_parents, "c3");
    const c3_parents = [_]Hash{c3};
    const c4 = try th.makeCommit(allocator, &store, tree, &c3_parents, "c4");

    // Replay C3, C4 onto C2 (i.e., head=C4, onto=C2)
    const result = try collectCommitsToReplay(allocator, &store, c4, c2);
    defer allocator.free(result);

    // Should return [C3, C4] in oldest-first order
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(c3, result[0]);
    try std.testing.expectEqual(c4, result[1]);
}

test "collectCommitsToReplay same commit returns empty" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const blob = try th.makeBlob(allocator, &store, "data");
    const tree_entries = [_]object.TreeEntry{
        .{ .name = "f.txt", .mode = .blob, .object_hash = blob },
    };
    const tree = try th.makeTree(allocator, &store, &tree_entries);
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");

    const result = try collectCommitsToReplay(allocator, &store, c1, c1);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "state write/read round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkit directory
    try tmp.dir.makeDir(".mkit");

    const orig_head = hash_mod.hash("orig-head");
    const onto = hash_mod.hash("onto");
    const todo_1 = hash_mod.hash("todo-1");
    const todo_2 = hash_mod.hash("todo-2");
    const done_1 = hash_mod.hash("done-1");

    const todo_arr = try allocator.alloc(Hash, 2);
    defer allocator.free(todo_arr);
    todo_arr[0] = todo_1;
    todo_arr[1] = todo_2;

    const done_arr = try allocator.alloc(Hash, 1);
    defer allocator.free(done_arr);
    done_arr[0] = done_1;

    const head_name = try allocator.dupe(u8, "feature-branch");
    defer allocator.free(head_name);

    const state = RebaseState{
        .head_name = head_name,
        .orig_head = orig_head,
        .onto = onto,
        .todo = todo_arr,
        .done = done_arr,
        .allocator = allocator,
    };

    try writeState(tmp.dir, state);

    // Read it back
    var read_state = try readState(allocator, tmp.dir);
    defer read_state.deinit();

    try std.testing.expectEqualStrings("feature-branch", read_state.head_name);
    try std.testing.expectEqual(orig_head, read_state.orig_head);
    try std.testing.expectEqual(onto, read_state.onto);
    try std.testing.expectEqual(@as(usize, 2), read_state.todo.len);
    try std.testing.expectEqual(todo_1, read_state.todo[0]);
    try std.testing.expectEqual(todo_2, read_state.todo[1]);
    try std.testing.expectEqual(@as(usize, 1), read_state.done.len);
    try std.testing.expectEqual(done_1, read_state.done[0]);
}

test "isRebaseInProgress detection" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    // No rebase dir -> not in progress
    try std.testing.expect(!isRebaseInProgress(tmp.dir));

    // Create rebase dir -> in progress
    try tmp.dir.makeDir(rebase_dir);
    try std.testing.expect(isRebaseInProgress(tmp.dir));
}

test "cleanupRebase removes state dir" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");
    try tmp.dir.makeDir(rebase_dir);

    // Create a file inside to make sure deleteTree works
    const file = try tmp.dir.createFile(rebase_dir ++ "/head-name", .{});
    try file.writeAll("main\n");
    file.close();

    try std.testing.expect(isRebaseInProgress(tmp.dir));

    try cleanupRebase(tmp.dir);

    try std.testing.expect(!isRebaseInProgress(tmp.dir));
}

test "cleanupRebase on nonexistent dir is fine" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    // Should not error
    try cleanupRebase(tmp.dir);
}

test "state write/read with empty todo and done" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    const head_name = try allocator.dupe(u8, "main");
    defer allocator.free(head_name);
    const todo_arr = try allocator.alloc(Hash, 0);
    defer allocator.free(todo_arr);
    const done_arr = try allocator.alloc(Hash, 0);
    defer allocator.free(done_arr);

    const state = RebaseState{
        .head_name = head_name,
        .orig_head = hash_mod.hash("head"),
        .onto = hash_mod.hash("onto"),
        .todo = todo_arr,
        .done = done_arr,
        .allocator = allocator,
    };

    try writeState(tmp.dir, state);

    var read_state = try readState(allocator, tmp.dir);
    defer read_state.deinit();

    try std.testing.expectEqualStrings("main", read_state.head_name);
    try std.testing.expectEqual(@as(usize, 0), read_state.todo.len);
    try std.testing.expectEqual(@as(usize, 0), read_state.done.len);
}

test "collectCommitsToReplay Y-shape" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");

    // C1 <- C2 <- C3 (main), C1 <- C4 <- C5 (feature)
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");
    const c2 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c2");
    const c3 = try th.makeCommit(allocator, &store, tree, &.{c2}, "c3");
    const c4 = try th.makeCommit(allocator, &store, tree, &.{c1}, "c4");
    const c5 = try th.makeCommit(allocator, &store, tree, &.{c4}, "c5");

    // Replay feature onto main: head=C5, onto=C3
    // C1 is ancestor of C3, so should stop there
    const result = try collectCommitsToReplay(allocator, &store, c5, c3);
    defer allocator.free(result);

    // Should return [C4, C5] in oldest-first order
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(c4, result[0]);
    try std.testing.expectEqual(c5, result[1]);
}

test "collectCommitsToReplay single commit onto itself" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(tmp.dir);
    defer store.close();

    const tree = try th.makeSingleFileTree(allocator, &store, "f.txt", "data");
    const c1 = try th.makeCommit(allocator, &store, tree, &.{}, "c1");

    const result = try collectCommitsToReplay(allocator, &store, c1, c1);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "readState with missing directory returns error" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkit but NOT .mkit/rebase-apply/
    try tmp.dir.makeDir(".mkit");

    try std.testing.expectError(error.NoRebaseInProgress, readState(allocator, tmp.dir));
}
