// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

pub const ConflictKind = enum {
    modify_modify,
    delete_modify,
    add_add,
};

pub const Conflict = struct {
    path: []const u8,
    kind: ConflictKind,
    base_hash: ?Hash,
    ours_hash: ?Hash,
    theirs_hash: ?Hash,
};

pub const MergeResult = struct {
    tree_hash: Hash,
    conflicts: []Conflict,
    allocator: Allocator,

    pub fn deinit(self: *MergeResult) void {
        for (self.conflicts) |c| {
            self.allocator.free(c.path);
        }
        if (self.conflicts.len > 0) {
            self.allocator.free(self.conflicts);
        }
    }

    pub fn hasConflicts(self: MergeResult) bool {
        return self.conflicts.len > 0;
    }
};

const AncestorNode = struct {
    hash: Hash,
    depth: usize,
};

/// 3-way merge of trees. Returns merged tree hash + conflicts.
/// null hash means empty tree.
pub fn mergeTrees(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    base_hash: ?Hash,
    ours_hash: ?Hash,
    theirs_hash: ?Hash,
) !MergeResult {
    var base_obj: ?object.Object = null;
    defer if (base_obj) |*o| o.deinit(allocator);
    var ours_obj: ?object.Object = null;
    defer if (ours_obj) |*o| o.deinit(allocator);
    var theirs_obj: ?object.Object = null;
    defer if (theirs_obj) |*o| o.deinit(allocator);

    const base_entries: []const object.TreeEntry = if (base_hash) |h| blk: {
        base_obj = try store.get(allocator, h);
        break :blk base_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    const ours_entries: []const object.TreeEntry = if (ours_hash) |h| blk: {
        ours_obj = try store.get(allocator, h);
        break :blk ours_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    const theirs_entries: []const object.TreeEntry = if (theirs_hash) |h| blk: {
        theirs_obj = try store.get(allocator, h);
        break :blk theirs_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    var merged: std.ArrayList(object.TreeEntry) = .empty;
    errdefer {
        for (merged.items) |entry| {
            allocator.free(entry.name);
        }
        merged.deinit(allocator);
    }
    var conflicts: std.ArrayList(Conflict) = .empty;
    errdefer {
        for (conflicts.items) |c| {
            allocator.free(c.path);
        }
        conflicts.deinit(allocator);
    }

    try mergeEntriesRecursive(allocator, store, base_entries, ours_entries, theirs_entries, "", &merged, &conflicts);

    const merged_entries = try merged.toOwnedSlice(allocator);
    defer {
        for (merged_entries) |entry| {
            allocator.free(entry.name);
        }
        allocator.free(merged_entries);
    }

    const tree_obj = object.Object{ .tree = .{ .entries = merged_entries } };
    const tree_hash = try store.put(allocator, tree_obj);

    const conflict_slice: []Conflict = if (conflicts.items.len > 0)
        try conflicts.toOwnedSlice(allocator)
    else
        @constCast(&[_]Conflict{});

    return .{
        .tree_hash = tree_hash,
        .conflicts = conflict_slice,
        .allocator = allocator,
    };
}

fn collectAncestors(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    start: Hash,
) !std.AutoHashMap(Hash, usize) {
    var ancestors = std.AutoHashMap(Hash, usize).init(allocator);
    errdefer ancestors.deinit();

    var queue: std.ArrayList(AncestorNode) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, .{ .hash = start, .depth = 0 });

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const node = queue.items[head];
        if (ancestors.contains(node.hash)) continue;
        try ancestors.put(node.hash, node.depth);

        var obj = store.get(allocator, node.hash) catch continue;
        defer obj.deinit(allocator);
        if (obj != .commit) continue;

        for (obj.commit.parents) |parent| {
            try queue.append(allocator, .{
                .hash = parent,
                .depth = node.depth + 1,
            });
        }
    }

    return ancestors;
}

/// Find the merge base (best common ancestor) of two commits.
/// Walks the full DAG on both sides so merge commits reachable only through
/// non-first parents are handled correctly.
pub fn findMergeBase(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    hash_a: Hash,
    hash_b: Hash,
) !?Hash {
    // If same commit, return immediately
    if (std.mem.eql(u8, &hash_a, &hash_b)) return hash_a;

    // Build the full ancestor set for A, including merge parents.
    var ancestors_a = try collectAncestors(allocator, store, hash_a);
    defer ancestors_a.deinit();

    // Walk B's DAG breadth-first until we hit a node that A can reach.
    var queue: std.ArrayList(AncestorNode) = .empty;
    defer queue.deinit(allocator);
    try queue.append(allocator, .{ .hash = hash_b, .depth = 0 });

    var best: ?AncestorNode = null;
    var best_total: usize = std.math.maxInt(usize);

    var head: usize = 0;
    while (head < queue.items.len) : (head += 1) {
        const node = queue.items[head];
        if (node.depth > best_total) break;

        if (ancestors_a.get(node.hash)) |ancestor_depth| {
            const total_depth = ancestor_depth + node.depth;
            if (best == null or total_depth < best_total) {
                best = node;
                best_total = total_depth;
            }
        }

        var obj = store.get(allocator, node.hash) catch continue;
        defer obj.deinit(allocator);
        if (obj != .commit) continue;

        for (obj.commit.parents) |parent| {
            try queue.append(allocator, .{
                .hash = parent,
                .depth = node.depth + 1,
            });
        }
    }

    return if (best) |candidate| candidate.hash else null;
}

/// Returns true when `ancestor` is reachable from `descendant` by walking commit parents.
pub fn isAncestor(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    ancestor: Hash,
    descendant: Hash,
) !bool {
    if (std.mem.eql(u8, &ancestor, &descendant)) return true;

    var seen = std.AutoHashMap(Hash, void).init(allocator);
    defer seen.deinit();

    var stack: std.ArrayList(Hash) = .empty;
    defer stack.deinit(allocator);
    try stack.append(allocator, descendant);

    while (stack.pop()) |current| {
        const gop = try seen.getOrPut(current);
        if (gop.found_existing) continue;
        if (std.mem.eql(u8, &current, &ancestor)) return true;

        var obj = store.get(allocator, current) catch continue;
        defer obj.deinit(allocator);
        if (obj != .commit) continue;

        for (obj.commit.parents) |parent| {
            try stack.append(allocator, parent);
        }
    }

    return false;
}

const MergeError = error{
    OutOfMemory,
    ObjectNotFound,
    ObjectTooLarge,
    HashMismatch,
    UnexpectedEof,
    EmptyData,
    InvalidObjectType,
    InvalidEntryMode,
    InvalidEntryName,
    InvalidEntryOrder,
    TooManyEntries,
    TooManyParents,
    TooManySources,
    TooManyChunks,
    InvalidChunkSize,
    InvalidSourceOrder,
    TrailingData,
    DeltaCorrupt,
    DeltaSizeMismatch,
    LinkQuotaExceeded,
    ReadOnlyFileSystem,
    RenameAcrossMountPoints,
    WriteFailed,
    // New in v1 (object prologue + Identity):
    InvalidMagic,
    UnsupportedObjectVersion,
    UnknownIdentityKind,
    InvalidIdentity,
    IdentityTooLarge,
} || std.Io.File.OpenError || std.Io.File.WriteError || std.Io.File.ReadError || std.Io.Dir.OpenError;

/// Recursive 3-pointer lockstep merge over sorted entry arrays.
fn mergeEntriesRecursive(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    base_entries: []const object.TreeEntry,
    ours_entries: []const object.TreeEntry,
    theirs_entries: []const object.TreeEntry,
    prefix: []const u8,
    merged: *std.ArrayList(object.TreeEntry),
    conflicts: *std.ArrayList(Conflict),
) MergeError!void {
    var bi: usize = 0;
    var oi: usize = 0;
    var ti: usize = 0;

    while (bi < base_entries.len or oi < ours_entries.len or ti < theirs_entries.len) {
        // Find the lexicographically smallest name among the three current entries
        const b_name: ?[]const u8 = if (bi < base_entries.len) base_entries[bi].name else null;
        const o_name: ?[]const u8 = if (oi < ours_entries.len) ours_entries[oi].name else null;
        const t_name: ?[]const u8 = if (ti < theirs_entries.len) theirs_entries[ti].name else null;

        const min_name = minOfThree(b_name, o_name, t_name) orelse break;

        const has_base = b_name != null and std.mem.eql(u8, b_name.?, min_name);
        const has_ours = o_name != null and std.mem.eql(u8, o_name.?, min_name);
        const has_theirs = t_name != null and std.mem.eql(u8, t_name.?, min_name);

        const base_entry: ?object.TreeEntry = if (has_base) base_entries[bi] else null;
        const ours_entry: ?object.TreeEntry = if (has_ours) ours_entries[oi] else null;
        const theirs_entry: ?object.TreeEntry = if (has_theirs) theirs_entries[ti] else null;

        if (has_base) bi += 1;
        if (has_ours) oi += 1;
        if (has_theirs) ti += 1;

        // Decision matrix
        if (has_base and has_ours and has_theirs) {
            // All three have this entry
            const b = base_entry.?;
            const o = ours_entry.?;
            const t = theirs_entry.?;

            const b_eq_o = hashAndModeEqual(b, o);
            const b_eq_t = hashAndModeEqual(b, t);
            const o_eq_t = hashAndModeEqual(o, t);

            if (b_eq_o and b_eq_t) {
                // All identical -> keep base
                try addEntry(allocator, merged, min_name, b.mode, b.object_hash);
            } else if (b_eq_t and !b_eq_o) {
                // Theirs unchanged, ours changed -> take ours
                // If both are trees and hash differs, recurse
                if (b.mode == .tree and o.mode == .tree) {
                    try recurseSubtreeMerge(allocator, store, b.object_hash, o.object_hash, b.object_hash, min_name, prefix, merged, conflicts);
                } else {
                    try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
                }
            } else if (b_eq_o and !b_eq_t) {
                // Ours unchanged, theirs changed -> take theirs
                if (b.mode == .tree and t.mode == .tree) {
                    try recurseSubtreeMerge(allocator, store, b.object_hash, b.object_hash, t.object_hash, min_name, prefix, merged, conflicts);
                } else {
                    try addEntry(allocator, merged, min_name, t.mode, t.object_hash);
                }
            } else if (o_eq_t) {
                // Both changed the same way -> take ours (same as theirs)
                if (b.mode == .tree and o.mode == .tree) {
                    try recurseSubtreeMerge(allocator, store, b.object_hash, o.object_hash, t.object_hash, min_name, prefix, merged, conflicts);
                } else {
                    try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
                }
            } else {
                // Both changed differently -> CONFLICT modify_modify
                // If both sides are trees, recurse to find per-file conflicts
                if (b.mode == .tree and o.mode == .tree and t.mode == .tree) {
                    try recurseSubtreeMerge(allocator, store, b.object_hash, o.object_hash, t.object_hash, min_name, prefix, merged, conflicts);
                } else {
                    const path = try joinPath(allocator, prefix, min_name);
                    try conflicts.append(allocator, .{
                        .path = path,
                        .kind = .modify_modify,
                        .base_hash = b.object_hash,
                        .ours_hash = o.object_hash,
                        .theirs_hash = t.object_hash,
                    });
                    // Include ours in merged tree (conflict marker — ours wins in tree)
                    try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
                }
            }
        } else if (!has_base and has_ours and !has_theirs) {
            // Only ours has it -> add ours
            const o = ours_entry.?;
            try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
        } else if (!has_base and !has_ours and has_theirs) {
            // Only theirs has it -> add theirs
            const t = theirs_entry.?;
            try addEntry(allocator, merged, min_name, t.mode, t.object_hash);
        } else if (!has_base and has_ours and has_theirs) {
            // Both added (not in base)
            const o = ours_entry.?;
            const t = theirs_entry.?;
            if (hashAndModeEqual(o, t)) {
                // Same content -> take ours
                try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
            } else if (o.mode == .tree and t.mode == .tree) {
                // Both added subtrees -> recurse with empty base
                try recurseSubtreeMerge(allocator, store, null, o.object_hash, t.object_hash, min_name, prefix, merged, conflicts);
            } else {
                // Different content -> CONFLICT add_add
                const path = try joinPath(allocator, prefix, min_name);
                try conflicts.append(allocator, .{
                    .path = path,
                    .kind = .add_add,
                    .base_hash = null,
                    .ours_hash = o.object_hash,
                    .theirs_hash = t.object_hash,
                });
                // Include ours in merged tree
                try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
            }
        } else if (has_base and has_ours and !has_theirs) {
            // Theirs deleted
            const b = base_entry.?;
            const o = ours_entry.?;
            if (hashAndModeEqual(b, o)) {
                // Ours unchanged, theirs deleted -> delete (omit from merged)
            } else {
                // Ours modified, theirs deleted -> CONFLICT delete_modify
                const path = try joinPath(allocator, prefix, min_name);
                try conflicts.append(allocator, .{
                    .path = path,
                    .kind = .delete_modify,
                    .base_hash = b.object_hash,
                    .ours_hash = o.object_hash,
                    .theirs_hash = null,
                });
                // Include ours in merged tree
                try addEntry(allocator, merged, min_name, o.mode, o.object_hash);
            }
        } else if (has_base and !has_ours and has_theirs) {
            // Ours deleted
            const b = base_entry.?;
            const t = theirs_entry.?;
            if (hashAndModeEqual(b, t)) {
                // Theirs unchanged, ours deleted -> delete (omit from merged)
            } else {
                // Theirs modified, ours deleted -> CONFLICT delete_modify
                const path = try joinPath(allocator, prefix, min_name);
                try conflicts.append(allocator, .{
                    .path = path,
                    .kind = .delete_modify,
                    .base_hash = b.object_hash,
                    .ours_hash = null,
                    .theirs_hash = t.object_hash,
                });
                // Include theirs in merged tree
                try addEntry(allocator, merged, min_name, t.mode, t.object_hash);
            }
        } else if (has_base and !has_ours and !has_theirs) {
            // Both deleted -> delete (omit from merged)
        }
        // Remaining cases (only base) handled above
    }
}

/// Recurse into subtrees for merge. Stores the resulting subtree and adds it as an entry.
fn recurseSubtreeMerge(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    base_sub_hash: ?Hash,
    ours_sub_hash: ?Hash,
    theirs_sub_hash: ?Hash,
    entry_name: []const u8,
    prefix: []const u8,
    merged: *std.ArrayList(object.TreeEntry),
    conflicts: *std.ArrayList(Conflict),
) MergeError!void {
    const sub_prefix = try joinPath(allocator, prefix, entry_name);
    defer allocator.free(sub_prefix);

    var base_sub_obj: ?object.Object = null;
    defer if (base_sub_obj) |*o| o.deinit(allocator);
    var ours_sub_obj: ?object.Object = null;
    defer if (ours_sub_obj) |*o| o.deinit(allocator);
    var theirs_sub_obj: ?object.Object = null;
    defer if (theirs_sub_obj) |*o| o.deinit(allocator);

    const base_sub_entries: []const object.TreeEntry = if (base_sub_hash) |h| blk: {
        base_sub_obj = try store.get(allocator, h);
        break :blk base_sub_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    const ours_sub_entries: []const object.TreeEntry = if (ours_sub_hash) |h| blk: {
        ours_sub_obj = try store.get(allocator, h);
        break :blk ours_sub_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    const theirs_sub_entries: []const object.TreeEntry = if (theirs_sub_hash) |h| blk: {
        theirs_sub_obj = try store.get(allocator, h);
        break :blk theirs_sub_obj.?.tree.entries;
    } else &[_]object.TreeEntry{};

    var sub_merged: std.ArrayList(object.TreeEntry) = .empty;
    errdefer {
        for (sub_merged.items) |entry| {
            allocator.free(entry.name);
        }
        sub_merged.deinit(allocator);
    }

    try mergeEntriesRecursive(allocator, store, base_sub_entries, ours_sub_entries, theirs_sub_entries, sub_prefix, &sub_merged, conflicts);

    const sub_entries_slice = try sub_merged.toOwnedSlice(allocator);
    defer {
        for (sub_entries_slice) |entry| {
            allocator.free(entry.name);
        }
        allocator.free(sub_entries_slice);
    }

    const sub_tree_obj = object.Object{ .tree = .{ .entries = sub_entries_slice } };
    const sub_tree_hash = try store.put(allocator, sub_tree_obj);

    try addEntry(allocator, merged, entry_name, .tree, sub_tree_hash);
}

/// Compare hash and mode of two tree entries.
fn hashAndModeEqual(a: object.TreeEntry, b: object.TreeEntry) bool {
    return a.mode == b.mode and std.mem.eql(u8, &a.object_hash, &b.object_hash);
}

/// Find the lexicographically smallest name among up to three optional names.
fn minOfThree(a: ?[]const u8, b: ?[]const u8, c: ?[]const u8) ?[]const u8 {
    var result: ?[]const u8 = a;
    if (b) |bv| {
        if (result) |rv| {
            if (std.mem.order(u8, bv, rv) == .lt) result = bv;
        } else {
            result = bv;
        }
    }
    if (c) |cv| {
        if (result) |rv| {
            if (std.mem.order(u8, cv, rv) == .lt) result = cv;
        } else {
            result = cv;
        }
    }
    return result;
}

/// Add a tree entry with a duped name.
fn addEntry(
    allocator: Allocator,
    merged: *std.ArrayList(object.TreeEntry),
    name: []const u8,
    mode: object.EntryMode,
    obj_hash: Hash,
) !void {
    const duped_name = try allocator.dupe(u8, name);
    errdefer allocator.free(duped_name);
    try merged.append(allocator, .{
        .name = duped_name,
        .mode = mode,
        .object_hash = obj_hash,
    });
}

const joinPath = hash_mod.joinPath;

// ===========================================================================
// Test helpers
// ===========================================================================

/// Verify the merged tree contains an entry with the given name and hash.
fn verifyTreeEntry(allocator: Allocator, store: *store_mod.ObjectStore, tree_hash: Hash, name: []const u8, expected_hash: Hash) !void {
    var tree_obj = try store.get(allocator, tree_hash);
    defer tree_obj.deinit(allocator);
    for (tree_obj.tree.entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) {
            try std.testing.expectEqual(expected_hash, entry.object_hash);
            return;
        }
    }
    return error.TestUnexpectedResult; // entry not found
}

/// Count entries in a tree.
fn treeEntryCount(allocator: Allocator, store: *store_mod.ObjectStore, tree_hash: Hash) !usize {
    var tree_obj = try store.get(allocator, tree_hash);
    defer tree_obj.deinit(allocator);
    return tree_obj.tree.entries.len;
}

// ===========================================================================
// Tests
// ===========================================================================

test "merge identical trees" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const tree_hash = try th.makeTree(allocator, &store, &entries);

    var result = try mergeTrees(allocator, &store, tree_hash, tree_hash, tree_hash);
    defer result.deinit();

    try std.testing.expectEqual(tree_hash, result.tree_hash);
    try std.testing.expect(!result.hasConflicts());
}

test "merge ours adds file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, base_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 2), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
    try verifyTreeEntry(allocator, &store, result.tree_hash, "b.txt", blob_b);
}

test "merge theirs adds file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_c = try th.makeBlob(allocator, &store, "ccc");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "c.txt", .mode = .blob, .object_hash = blob_c },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, base_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 2), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
    try verifyTreeEntry(allocator, &store, result.tree_hash, "c.txt", blob_c);
}

test "merge both add different files" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");
    const blob_c = try th.makeBlob(allocator, &store, "ccc");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "c.txt", .mode = .blob, .object_hash = blob_c },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 3), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
    try verifyTreeEntry(allocator, &store, result.tree_hash, "b.txt", blob_b);
    try verifyTreeEntry(allocator, &store, result.tree_hash, "c.txt", blob_c);
}

test "merge both add same file same content" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    // Both sides add b.txt with same content
    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 2), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "b.txt", blob_b);
}

test "merge both add same file different content" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b1 = try th.makeBlob(allocator, &store, "bbb-ours");
    const blob_b2 = try th.makeBlob(allocator, &store, "bbb-theirs");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b1 },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b2 },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    const c = result.conflicts[0];
    try std.testing.expectEqualStrings("b.txt", c.path);
    try std.testing.expectEqual(ConflictKind.add_add, c.kind);
    try std.testing.expectEqual(@as(?Hash, null), c.base_hash);
    try std.testing.expectEqual(@as(?Hash, blob_b1), c.ours_hash);
    try std.testing.expectEqual(@as(?Hash, blob_b2), c.theirs_hash);
}

test "merge ours modifies" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_v1 = try th.makeBlob(allocator, &store, "v1");
    const blob_v2 = try th.makeBlob(allocator, &store, "v2");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v1 },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v2 },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, base_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_v2);
}

test "merge theirs modifies" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_v1 = try th.makeBlob(allocator, &store, "v1");
    const blob_v2 = try th.makeBlob(allocator, &store, "v2");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v1 },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v2 },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, base_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_v2);
}

test "merge both modify same way" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_v1 = try th.makeBlob(allocator, &store, "v1");
    const blob_v2 = try th.makeBlob(allocator, &store, "v2");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v1 },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const modified_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v2 },
    };
    const modified_hash = try th.makeTree(allocator, &store, &modified_entries);

    var result = try mergeTrees(allocator, &store, base_hash, modified_hash, modified_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_v2);
}

test "merge both modify differently" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_v1 = try th.makeBlob(allocator, &store, "v1");
    const blob_v2 = try th.makeBlob(allocator, &store, "v2-ours");
    const blob_v3 = try th.makeBlob(allocator, &store, "v3-theirs");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v1 },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v2 },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_v3 },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    const c = result.conflicts[0];
    try std.testing.expectEqualStrings("a.txt", c.path);
    try std.testing.expectEqual(ConflictKind.modify_modify, c.kind);
    try std.testing.expectEqual(@as(?Hash, blob_v1), c.base_hash);
    try std.testing.expectEqual(@as(?Hash, blob_v2), c.ours_hash);
    try std.testing.expectEqual(@as(?Hash, blob_v3), c.theirs_hash);
}

test "merge ours deletes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, base_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
}

test "merge theirs deletes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, base_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
}

test "merge both delete" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    const both_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const both_hash = try th.makeTree(allocator, &store, &both_entries);

    var result = try mergeTrees(allocator, &store, base_hash, both_hash, both_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
}

test "merge delete vs modify" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b_v1 = try th.makeBlob(allocator, &store, "bbb-v1");
    const blob_b_v2 = try th.makeBlob(allocator, &store, "bbb-v2");

    const base_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b_v1 },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_entries);

    // Ours deletes b.txt
    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    // Theirs modifies b.txt
    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b_v2 },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    const c = result.conflicts[0];
    try std.testing.expectEqualStrings("b.txt", c.path);
    try std.testing.expectEqual(ConflictKind.delete_modify, c.kind);
    try std.testing.expectEqual(@as(?Hash, blob_b_v1), c.base_hash);
    try std.testing.expectEqual(@as(?Hash, null), c.ours_hash);
    try std.testing.expectEqual(@as(?Hash, blob_b_v2), c.theirs_hash);
}

test "merge nested tree changes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_main_v1 = try th.makeBlob(allocator, &store, "fn main() {}");
    const blob_main_v2 = try th.makeBlob(allocator, &store, "fn main() { run(); }");
    const blob_util = try th.makeBlob(allocator, &store, "fn util() {}");

    // Base: src/ contains {main.zig}
    const base_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_main_v1 },
    };
    const base_sub_hash = try th.makeTree(allocator, &store, &base_sub_entries);

    const base_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = base_sub_hash },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_root_entries);

    // Ours: src/ modified main.zig
    const ours_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_main_v2 },
    };
    const ours_sub_hash = try th.makeTree(allocator, &store, &ours_sub_entries);

    const ours_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = ours_sub_hash },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_root_entries);

    // Theirs: src/ adds util.zig
    const theirs_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_main_v1 },
        .{ .name = "util.zig", .mode = .blob, .object_hash = blob_util },
    };
    const theirs_sub_hash = try th.makeTree(allocator, &store, &theirs_sub_entries);

    const theirs_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = theirs_sub_hash },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_root_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());

    // Read the merged src/ subtree
    var merged_root = try store.get(allocator, result.tree_hash);
    defer merged_root.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), merged_root.tree.entries.len);
    try std.testing.expectEqualStrings("src", merged_root.tree.entries[0].name);

    var merged_src = try store.get(allocator, merged_root.tree.entries[0].object_hash);
    defer merged_src.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), merged_src.tree.entries.len);
    try std.testing.expectEqualStrings("main.zig", merged_src.tree.entries[0].name);
    try std.testing.expectEqual(blob_main_v2, merged_src.tree.entries[0].object_hash);
    try std.testing.expectEqualStrings("util.zig", merged_src.tree.entries[1].name);
    try std.testing.expectEqual(blob_util, merged_src.tree.entries[1].object_hash);
}

test "merge nested conflict" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_v1 = try th.makeBlob(allocator, &store, "original");
    const blob_v2 = try th.makeBlob(allocator, &store, "ours-change");
    const blob_v3 = try th.makeBlob(allocator, &store, "theirs-change");

    // Base: src/ contains {main.zig=v1}
    const base_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_v1 },
    };
    const base_sub_hash = try th.makeTree(allocator, &store, &base_sub_entries);

    const base_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = base_sub_hash },
    };
    const base_hash = try th.makeTree(allocator, &store, &base_root_entries);

    // Ours: src/main.zig -> v2
    const ours_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_v2 },
    };
    const ours_sub_hash = try th.makeTree(allocator, &store, &ours_sub_entries);

    const ours_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = ours_sub_hash },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_root_entries);

    // Theirs: src/main.zig -> v3
    const theirs_sub_entries = [_]object.TreeEntry{
        .{ .name = "main.zig", .mode = .blob, .object_hash = blob_v3 },
    };
    const theirs_sub_hash = try th.makeTree(allocator, &store, &theirs_sub_entries);

    const theirs_root_entries = [_]object.TreeEntry{
        .{ .name = "src", .mode = .tree, .object_hash = theirs_sub_hash },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_root_entries);

    var result = try mergeTrees(allocator, &store, base_hash, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 1), result.conflicts.len);
    try std.testing.expectEqualStrings("src/main.zig", result.conflicts[0].path);
    try std.testing.expectEqual(ConflictKind.modify_modify, result.conflicts[0].kind);
    try std.testing.expectEqual(@as(?Hash, blob_v1), result.conflicts[0].base_hash);
    try std.testing.expectEqual(@as(?Hash, blob_v2), result.conflicts[0].ours_hash);
    try std.testing.expectEqual(@as(?Hash, blob_v3), result.conflicts[0].theirs_hash);
}

test "merge empty base" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const blob_a = try th.makeBlob(allocator, &store, "aaa");
    const blob_b = try th.makeBlob(allocator, &store, "bbb");

    const ours_entries = [_]object.TreeEntry{
        .{ .name = "a.txt", .mode = .blob, .object_hash = blob_a },
    };
    const ours_hash = try th.makeTree(allocator, &store, &ours_entries);

    const theirs_entries = [_]object.TreeEntry{
        .{ .name = "b.txt", .mode = .blob, .object_hash = blob_b },
    };
    const theirs_hash = try th.makeTree(allocator, &store, &theirs_entries);

    var result = try mergeTrees(allocator, &store, null, ours_hash, theirs_hash);
    defer result.deinit();

    try std.testing.expect(!result.hasConflicts());
    try std.testing.expectEqual(@as(usize, 2), try treeEntryCount(allocator, &store, result.tree_hash));
    try verifyTreeEntry(allocator, &store, result.tree_hash, "a.txt", blob_a);
    try verifyTreeEntry(allocator, &store, result.tree_hash, "b.txt", blob_b);
}

// ===========================================================================
// findMergeBase tests
// ===========================================================================

test "find merge base linear" {
    // A -> B -> C on main, B -> D on branch
    // merge base of C and D should be B
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const a = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "commit A");
    const b = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{a}, "commit B");
    const c = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{b}, "commit C");
    const d = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{b}, "commit D");

    const base = try findMergeBase(allocator, &store, c, d);
    try std.testing.expect(base != null);
    try std.testing.expectEqual(b, base.?);
}

test "find merge base root" {
    // A -> B on main, A -> C on branch
    // merge base of B and C should be A
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const a = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "commit A");
    const b = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{a}, "commit B");
    const c_hash = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{a}, "commit C");

    const base = try findMergeBase(allocator, &store, b, c_hash);
    try std.testing.expect(base != null);
    try std.testing.expectEqual(a, base.?);
}

test "find merge base no common ancestor" {
    // Two independent root commits with no shared history
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const x = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "commit X");
    const y = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "commit Y");

    const base = try findMergeBase(allocator, &store, x, y);
    try std.testing.expectEqual(@as(?Hash, null), base);
}

test "find merge base same commit" {
    // Both point to the same commit — base is that commit
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const a = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "commit A");

    const base = try findMergeBase(allocator, &store, a, a);
    try std.testing.expect(base != null);
    try std.testing.expectEqual(a, base.?);
}

test "find merge base walks non-first parents" {
    //        root
    //        /  \
    //      left  right
    //        \    /
    //         merge
    //           |
    //         tip
    //
    // The merge base of tip and right should be right, which is only reachable
    // from tip through merge's second parent.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const root = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "root");
    const left = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{root}, "left");
    const right = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{root}, "right");
    const merge_commit = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{ left, right }, "merge");
    const tip = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{merge_commit}, "tip");

    const base = try findMergeBase(allocator, &store, tip, right);
    try std.testing.expect(base != null);
    try std.testing.expectEqual(right, base.?);
}

test "is ancestor walks merge parents" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    const empty_tree = try th.makeTree(allocator, &store, &[_]object.TreeEntry{});

    const root = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{}, "root");
    const left = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{root}, "left");
    const right = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{root}, "right");
    const merge_commit = try th.makeCommit(allocator, &store, empty_tree, &[_]Hash{ left, right }, "merge");

    try std.testing.expect(try isAncestor(allocator, &store, root, merge_commit));
    try std.testing.expect(try isAncestor(allocator, &store, right, merge_commit));
    try std.testing.expect(!try isAncestor(allocator, &store, merge_commit, right));
}
