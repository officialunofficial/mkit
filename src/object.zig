// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// mkit v1 on-disk magic. Every stored object begins with:
///   [object_type:u8][magic:4 = "MKT1"][schema_version:u8 = 1][body...]
/// See docs/SPEC-OBJECTS.md §2.
pub const MAGIC: [4]u8 = .{ 'M', 'K', 'T', '1' };
pub const SCHEMA_VERSION: u8 = 0x01;

/// Upper bound on Identity payload length. Anything larger is rejected as
/// `IdentityTooLarge` at decode time. Present so that adversarial input
/// cannot force an allocator blow-up by claiming a 4 GiB identity.
pub const IDENTITY_MAX_LEN: u16 = 4096;

/// Object type tag (1 byte).
pub const ObjectType = enum(u8) {
    blob = 0x01,
    tree = 0x02,
    commit = 0x03,
    remix = 0x04,
    chunked_blob = 0x05,
    delta = 0x06,

    pub fn name(self: ObjectType) []const u8 {
        return switch (self) {
            .blob => "blob",
            .tree => "tree",
            .commit => "commit",
            .remix => "remix",
            .chunked_blob => "chunked_blob",
            .delta => "delta",
        };
    }
};

/// Tree entry mode.
pub const EntryMode = enum(u8) {
    blob = 0x01,
    tree = 0x02,
    symlink = 0x03,
    /// Regular file, executable bit set (POSIX 0o755). New in v1.
    executable = 0x04,

    pub fn name(self: EntryMode) []const u8 {
        return switch (self) {
            .blob => "blob",
            .tree => "tree",
            .symlink => "symlink",
            .executable => "executable",
        };
    }
};

/// Identity tag. See docs/SPEC-OBJECTS.md §9.
///
/// `opaque` is a Zig keyword so we spell the variant with the @"..."
/// escape. The on-disk byte value is 0x03 regardless.
pub const IdentityKind = enum(u8) {
    /// Raw 32-byte Ed25519 public key (payload length MUST be 32).
    ed25519 = 0x01,
    /// UTF-8 `did:key:...` multibase-encoded key material, minus the
    /// `did:key:` scheme prefix (typically starts with `z`).
    did_key = 0x02,
    /// Arbitrary bytes defined by the producer. Typical use is an
    /// 8-byte little-endian u64 counter as an opaque account identity.
    @"opaque" = 0x03,
};

/// Opaque identity tagged union for commit / remix authors. Bytes are
/// held by reference; the producer owns the underlying allocation.
///
/// Wire format (both on-disk and signing bytes, identical layout):
///   [kind:u8][len:u16 LE][bytes:len]
pub const Identity = struct {
    kind: IdentityKind,
    bytes: []const u8,

    /// Deep-copy an `Identity`. Caller owns `.bytes` on the result.
    pub fn dupe(self: Identity, allocator: Allocator) !Identity {
        return .{
            .kind = self.kind,
            .bytes = try allocator.dupe(u8, self.bytes),
        };
    }

    /// Free the owned byte slice. Callers that constructed an Identity with
    /// a borrowed slice MUST NOT call this.
    pub fn deinitOwned(self: *Identity, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.bytes = &.{};
    }

    /// Structural validity check. Does NOT allocate.
    pub fn isValid(self: Identity) bool {
        if (self.bytes.len == 0) return false;
        if (self.bytes.len > IDENTITY_MAX_LEN) return false;
        switch (self.kind) {
            .ed25519 => if (self.bytes.len != 32) return false,
            .did_key, .@"opaque" => {},
        }
        return true;
    }

    /// Byte-equal comparison. No case folding, no canonicalisation.
    pub fn eql(a: Identity, b: Identity) bool {
        return a.kind == b.kind and std.mem.eql(u8, a.bytes, b.bytes);
    }

    /// Convenience constructor for a 32-byte Ed25519 pubkey. Does NOT copy.
    pub fn ed25519Ref(pubkey: []const u8) Identity {
        return .{ .kind = .ed25519, .bytes = pubkey };
    }

    /// Convenience constructor for an opaque producer-defined identity.
    /// Does NOT copy.
    pub fn opaqueRef(bytes: []const u8) Identity {
        return .{ .kind = .@"opaque", .bytes = bytes };
    }
};

/// A single entry in a tree object.
pub const TreeEntry = struct {
    name: []const u8,
    mode: EntryMode,
    object_hash: Hash,
};

/// Source reference for remix provenance.
/// `upstream_id` is an opaque 32-byte identifier chosen by the producer
/// of the remix (for example `BLAKE3(repo_url)` or any other 32-byte
/// blob that uniquely names the upstream). Core never interprets it.
pub const RemixSource = struct {
    upstream_id: Hash,
    commit_hash: Hash,
};

/// A chunked blob manifest for files larger than the chunk threshold.
/// Each chunk is stored as a regular blob object; this manifest lists
/// the hashes in order so the file can be reassembled.
pub const ChunkedBlob = struct {
    total_size: u64,
    chunk_size: u32,
    chunks: []Hash,

    pub fn deinit(self: *ChunkedBlob, allocator: Allocator) void {
        allocator.free(self.chunks);
    }
};

/// A delta-encoded object for pack transfer.
/// References a base object by hash; instructions transform base into target.
/// Deltas exist only inside packfiles and are resolved during unpack —
/// the object store never contains delta objects.
pub const Delta = struct {
    base_hash: Hash,
    result_size: u32,
    instructions: []const u8,

    pub fn deinit(self: *Delta, allocator: Allocator) void {
        allocator.free(self.instructions);
    }
};

/// A mkit object.
pub const Object = union(ObjectType) {
    blob: Blob,
    tree: Tree,
    commit: Commit,
    remix: Remix,
    chunked_blob: ChunkedBlob,
    delta: Delta,

    pub fn deinit(self: *Object, allocator: Allocator) void {
        switch (self.*) {
            .blob => |*b| b.deinit(allocator),
            .tree => |*t| t.deinit(allocator),
            .commit => |*c| c.deinit(allocator),
            .remix => |*r| r.deinit(allocator),
            .chunked_blob => |*cb| cb.deinit(allocator),
            .delta => |*d| d.deinit(allocator),
        }
    }

    pub fn objectType(self: Object) ObjectType {
        return std.meta.activeTag(self);
    }
};

pub const Blob = struct {
    data: []const u8,

    pub fn deinit(self: *Blob, allocator: Allocator) void {
        allocator.free(self.data);
    }
};

pub const Tree = struct {
    entries: []TreeEntry,

    pub fn deinit(self: *Tree, allocator: Allocator) void {
        for (self.entries) |entry| {
            allocator.free(entry.name);
        }
        allocator.free(self.entries);
    }

    /// Validate a tree entry name is safe for filesystem operations.
    /// Rejects names containing path separators, parent traversal, null bytes, or empty names.
    pub fn validateEntryName(name: []const u8) bool {
        if (name.len == 0) return false;
        if (name.len > 255) return false;
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
        for (name) |c| {
            if (c == '/' or c == '\\' or c == 0) return false;
        }
        return true;
    }

    /// Validate that entries are sorted by name (required for deterministic hashing).
    pub fn isSorted(self: Tree) bool {
        if (self.entries.len <= 1) return true;
        for (self.entries[0 .. self.entries.len - 1], self.entries[1..]) |a, b| {
            if (std.mem.order(u8, a.name, b.name) != .lt) return false;
        }
        return true;
    }
};

pub const Commit = struct {
    tree_hash: Hash,
    parents: []Hash,
    /// Opaque tagged-union author identity. Adapter-defined interpretation.
    /// See docs/SPEC-OBJECTS.md §9. The `bytes` slice is owned by the
    /// commit once the commit itself is owned — deinit frees it.
    author: Identity,
    signer: [32]u8,
    message: []const u8,
    /// Unix epoch seconds. u64. Bumped from u32 to avoid the 2106
    /// overflow (see docs/SPEC-OBJECTS.md §5).
    timestamp: u64,
    /// Optional off-chain annotation: BLAKE3 hash of the full commit
    /// message. Zero = absent. Excluded from signing bytes — see
    /// docs/SPEC-SIGNING.md §3.
    message_hash: Hash = hash_mod.zero,
    /// Optional off-chain annotation: BLAKE3 root hash of the
    /// packfile/bundle. Zero = absent. Excluded from signing bytes —
    /// see docs/SPEC-SIGNING.md §3.
    content_digest: Hash = hash_mod.zero,
    signature: [64]u8,

    pub fn deinit(self: *Commit, allocator: Allocator) void {
        allocator.free(self.parents);
        allocator.free(self.message);
        if (self.author.bytes.len > 0) {
            allocator.free(self.author.bytes);
            self.author.bytes = &.{};
        }
    }

    /// Extract title (first line of message, capped at 200 chars) for COMMIT_BUNDLE.title.
    pub fn title(self: Commit) []const u8 {
        const msg = self.message;
        const newline = std.mem.indexOf(u8, msg, "\n") orelse msg.len;
        return msg[0..@min(newline, 200)];
    }
};

pub const Remix = struct {
    tree_hash: Hash,
    parents: []Hash,
    sources: []RemixSource,
    /// Opaque tagged-union author identity — same shape as Commit.author.
    author: Identity,
    signer: [32]u8,
    message: []const u8,
    timestamp: u64,
    signature: [64]u8,

    pub fn deinit(self: *Remix, allocator: Allocator) void {
        allocator.free(self.parents);
        allocator.free(self.sources);
        allocator.free(self.message);
        if (self.author.bytes.len > 0) {
            allocator.free(self.author.bytes);
            self.author.bytes = &.{};
        }
    }

    /// Validate that sources are sorted by (upstream_id, commit_hash) for deterministic hashing.
    pub fn sourcesSorted(self: Remix) bool {
        if (self.sources.len <= 1) return true;
        for (self.sources[0 .. self.sources.len - 1], self.sources[1..]) |a, b| {
            const order = std.mem.order(u8, &a.upstream_id, &b.upstream_id);
            if (order == .gt) return false;
            if (order == .eq) {
                if (std.mem.order(u8, &a.commit_hash, &b.commit_hash) != .lt) return false;
            }
        }
        return true;
    }
};

test "object type names" {
    try std.testing.expectEqualStrings("blob", ObjectType.blob.name());
    try std.testing.expectEqualStrings("tree", ObjectType.tree.name());
    try std.testing.expectEqualStrings("commit", ObjectType.commit.name());
    try std.testing.expectEqualStrings("remix", ObjectType.remix.name());
    try std.testing.expectEqualStrings("chunked_blob", ObjectType.chunked_blob.name());
    try std.testing.expectEqualStrings("delta", ObjectType.delta.name());
}

test "tree sorting check" {
    const entries = [_]TreeEntry{
        .{ .name = "alpha", .mode = .blob, .object_hash = hash_mod.zero },
        .{ .name = "beta", .mode = .blob, .object_hash = hash_mod.zero },
        .{ .name = "gamma", .mode = .tree, .object_hash = hash_mod.zero },
    };
    const tree = Tree{ .entries = @constCast(&entries) };
    try std.testing.expect(tree.isSorted());

    const bad_entries = [_]TreeEntry{
        .{ .name = "beta", .mode = .blob, .object_hash = hash_mod.zero },
        .{ .name = "alpha", .mode = .blob, .object_hash = hash_mod.zero },
    };
    const bad_tree = Tree{ .entries = @constCast(&bad_entries) };
    try std.testing.expect(!bad_tree.isSorted());
}

test "commit title extraction" {
    const parents = [_]Hash{};
    const pk = [_]u8{0} ** 32;
    const commit = Commit{
        .tree_hash = hash_mod.zero,
        .parents = @constCast(&parents),
        .author = Identity.ed25519Ref(&pk),
        .signer = .{0} ** 32,
        .message = "first line\nsecond line\nthird",
        .timestamp = 0,
        .signature = .{0} ** 64,
    };
    try std.testing.expectEqualStrings("first line", commit.title());
}

test "commit title single line" {
    const parents = [_]Hash{};
    const pk = [_]u8{0} ** 32;
    const commit = Commit{
        .tree_hash = hash_mod.zero,
        .parents = @constCast(&parents),
        .author = Identity.ed25519Ref(&pk),
        .signer = .{0} ** 32,
        .message = "no newline here",
        .timestamp = 0,
        .signature = .{0} ** 64,
    };
    try std.testing.expectEqualStrings("no newline here", commit.title());
}

test "commit title capped at 200 chars" {
    const parents = [_]Hash{};
    const pk = [_]u8{0} ** 32;
    const long_msg = "A" ** 250 ++ "\nrest";
    const commit = Commit{
        .tree_hash = hash_mod.zero,
        .parents = @constCast(&parents),
        .author = Identity.ed25519Ref(&pk),
        .signer = .{0} ** 32,
        .message = long_msg,
        .timestamp = 0,
        .signature = .{0} ** 64,
    };
    try std.testing.expectEqual(@as(usize, 200), commit.title().len);
}

test "validateEntryName rejects empty" {
    try std.testing.expect(!Tree.validateEntryName(""));
}

test "validateEntryName rejects path separators" {
    try std.testing.expect(!Tree.validateEntryName("foo/bar"));
    try std.testing.expect(!Tree.validateEntryName("foo\\bar"));
}

test "validateEntryName rejects dot and dotdot" {
    try std.testing.expect(!Tree.validateEntryName("."));
    try std.testing.expect(!Tree.validateEntryName(".."));
}

test "validateEntryName accepts normal names" {
    try std.testing.expect(Tree.validateEntryName("file.txt"));
    try std.testing.expect(Tree.validateEntryName("a"));
    try std.testing.expect(Tree.validateEntryName("foo-bar_baz.zig"));
}

test "Identity.isValid rejects empty payload for all kinds" {
    const ed = Identity{ .kind = .ed25519, .bytes = &.{} };
    try std.testing.expect(!ed.isValid());
    const did = Identity{ .kind = .did_key, .bytes = &.{} };
    try std.testing.expect(!did.isValid());
    const op = Identity{ .kind = .@"opaque", .bytes = &.{} };
    try std.testing.expect(!op.isValid());
}

test "Identity.isValid rejects oversize payload" {
    const buf = [_]u8{0xAA} ** (IDENTITY_MAX_LEN + 1);
    const id = Identity{ .kind = .@"opaque", .bytes = &buf };
    try std.testing.expect(!id.isValid());
}

test "Identity.isValid requires 32 bytes for ed25519" {
    const short = [_]u8{0xAA} ** 16;
    const id = Identity{ .kind = .ed25519, .bytes = &short };
    try std.testing.expect(!id.isValid());
    const full = [_]u8{0xAA} ** 32;
    const ok = Identity{ .kind = .ed25519, .bytes = &full };
    try std.testing.expect(ok.isValid());
}

test "Identity.eql is byte-wise and kind-aware" {
    const a = Identity{ .kind = .@"opaque", .bytes = "hello" };
    const b = Identity{ .kind = .@"opaque", .bytes = "hello" };
    const c = Identity{ .kind = .did_key, .bytes = "hello" };
    const d = Identity{ .kind = .@"opaque", .bytes = "world" };
    try std.testing.expect(Identity.eql(a, b));
    try std.testing.expect(!Identity.eql(a, c));
    try std.testing.expect(!Identity.eql(a, d));
}
