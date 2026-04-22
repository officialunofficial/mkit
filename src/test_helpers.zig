// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Default Ed25519 identity for tests — a 32-byte all-zero public key.
/// Tests that care about authorship should override .author explicitly.
pub const ZERO_ED25519_PUBKEY: [32]u8 = .{0} ** 32;

/// Returns a borrowed ed25519 Identity pointing at ZERO_ED25519_PUBKEY.
/// The returned slice is backed by module-global const memory — safe to
/// use across Commit / Remix lifetimes as long as no one deinits it.
pub fn testIdentity() object.Identity {
    return .{ .kind = .ed25519, .bytes = ZERO_ED25519_PUBKEY[0..] };
}

/// Build an opaque Identity over an 8-byte LE u64 counter. Returns a
/// borrowed Identity whose bytes are owned by the supplied `buf` (must
/// outlive the returned Identity).
pub fn midIdentity(mid: u64, buf: *[8]u8) object.Identity {
    std.mem.writeInt(u64, buf, mid, .little);
    return .{ .kind = .@"opaque", .bytes = buf[0..] };
}

pub fn makeBlob(allocator: Allocator, store: *store_mod.ObjectStore, content: []const u8) !Hash {
    const blob_obj = object.Object{ .blob = .{ .data = content } };
    return store.put(allocator, blob_obj);
}

pub fn makeTree(allocator: Allocator, store: *store_mod.ObjectStore, entries: []const object.TreeEntry) !Hash {
    const tree_obj = object.Object{ .tree = .{ .entries = @constCast(entries) } };
    return store.put(allocator, tree_obj);
}

pub fn makeCommit(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    parents: []const Hash,
    message: []const u8,
) !Hash {
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = @constCast(parents),
        .author = testIdentity(),
        .signer = .{0} ** 32,
        .message = message,
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    return store.put(allocator, commit_obj);
}

pub fn makeCommitWithTimestamp(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    parents: []const Hash,
    message: []const u8,
    timestamp: u64,
) !Hash {
    const commit_obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = @constCast(parents),
        .author = testIdentity(),
        .signer = .{0} ** 32,
        .message = message,
        .timestamp = timestamp,
        .signature = .{0} ** 64,
    } };
    return store.put(allocator, commit_obj);
}

pub fn makeSingleFileTree(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    filename: []const u8,
    content: []const u8,
) !Hash {
    const blob_hash = try makeBlob(allocator, store, content);
    const entries = [_]object.TreeEntry{
        .{ .name = filename, .mode = .blob, .object_hash = blob_hash },
    };
    return makeTree(allocator, store, &entries);
}

pub fn makeLinearChain(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    tree_hash: Hash,
    count: usize,
) ![]Hash {
    const commits = try allocator.alloc(Hash, count);
    errdefer allocator.free(commits);
    for (0..count) |i| {
        if (i == 0) {
            commits[i] = try makeCommit(allocator, store, tree_hash, &.{}, "commit-0");
        } else {
            const parents = [_]Hash{commits[i - 1]};
            commits[i] = try makeCommit(allocator, store, tree_hash, &parents, "commit");
        }
    }
    return commits;
}
