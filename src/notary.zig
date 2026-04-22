// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Notary abstraction. A Notary is anything that wants to witness or attest
// to a push (commits + ref update). Core mkit ships only NullNotary — a
// no-op default. Downstream consumers that import mkit as a Zig library
// implement their own Notary types and wire them in.
//
// The public `mkit` binary does not expose any notary surface in its CLI;
// this trait exists purely as a library extension point.

const std = @import("std");
const hash_mod = @import("hash.zig");
const Allocator = std.mem.Allocator;
const Hash = hash_mod.Hash;

/// Opaque attestation receipt. Bytes are defined by the notary that produced
/// it; foreign notaries treat them as opaque.
pub const Receipt = struct {
    bytes: []const u8,
    allocator: ?Allocator = null,

    pub fn deinit(self: *Receipt) void {
        if (self.allocator) |a| {
            if (self.bytes.len > 0) a.free(self.bytes);
        }
        self.bytes = &.{};
    }
};

pub const ProjectId = [32]u8;

pub const ProjectSpec = struct {
    name: []const u8,
    description: []const u8 = "",
    license: []const u8 = "",
};

pub const CommitMeta = struct {
    hash: Hash,
    parents: []const Hash,
    tree_root: Hash,
    author: []const u8, // opaque identity bytes; notaries decide how to interpret
    author_timestamp: u64,
    title: []const u8,
    message_hash: Hash,
};

pub const RefUpdate = struct {
    project_id: Hash,
    ref_name: []const u8,
    old_hash: ?Hash,
    new_hash: Hash,
};

pub const AttestInput = struct {
    commits: []const CommitMeta,
    ref_update: RefUpdate,
    project_id: ProjectId,
    content_digest: ?Hash = null,
    url: []const u8 = "",
};

pub const Notary = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        attest: *const fn (*anyopaque, Allocator, AttestInput) anyerror!Receipt,
        verifyReceipt: *const fn (*anyopaque, Allocator, Receipt) anyerror!bool,
        createProject: *const fn (*anyopaque, Allocator, ProjectSpec) anyerror!ProjectId,
    };

    pub fn attest(self: Notary, allocator: Allocator, input: AttestInput) !Receipt {
        return self.vtable.attest(self.ptr, allocator, input);
    }
    pub fn verifyReceipt(self: Notary, allocator: Allocator, receipt: Receipt) !bool {
        return self.vtable.verifyReceipt(self.ptr, allocator, receipt);
    }
    pub fn createProject(self: Notary, allocator: Allocator, spec: ProjectSpec) !ProjectId {
        return self.vtable.createProject(self.ptr, allocator, spec);
    }
};

pub const NullNotary = struct {
    var dummy: u8 = 0;

    const vtable: Notary.VTable = .{
        .attest = attestImpl,
        .verifyReceipt = verifyReceiptImpl,
        .createProject = createProjectImpl,
    };

    pub fn init() Notary {
        return .{ .ptr = @ptrCast(&dummy), .vtable = &vtable };
    }

    fn attestImpl(_: *anyopaque, allocator: Allocator, _: AttestInput) !Receipt {
        return .{ .bytes = try allocator.dupe(u8, &.{}), .allocator = allocator };
    }
    fn verifyReceiptImpl(_: *anyopaque, _: Allocator, receipt: Receipt) !bool {
        return receipt.bytes.len == 0;
    }
    fn createProjectImpl(_: *anyopaque, _: Allocator, spec: ProjectSpec) !ProjectId {
        var id: ProjectId = undefined;
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(spec.name);
        hasher.final(&id);
        return id;
    }
};

test "null notary attest returns empty receipt" {
    const allocator = std.testing.allocator;
    var notary = NullNotary.init();
    const input: AttestInput = .{
        .commits = &.{},
        .ref_update = .{ .project_id = [_]u8{0} ** 32, .ref_name = "refs/heads/main", .old_hash = null, .new_hash = [_]u8{0} ** 32 },
        .project_id = [_]u8{0} ** 32,
    };
    var r = try notary.attest(allocator, input);
    defer r.deinit();
    try std.testing.expectEqual(@as(usize, 0), r.bytes.len);
}

test "null notary createProject is deterministic" {
    const allocator = std.testing.allocator;
    var notary = NullNotary.init();
    const a = try notary.createProject(allocator, .{ .name = "alpha" });
    const b = try notary.createProject(allocator, .{ .name = "alpha" });
    try std.testing.expectEqualSlices(u8, &a, &b);
}
