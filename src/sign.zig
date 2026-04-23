// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const object = @import("object.zig");
const serialize = @import("serialize.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

const Ed25519 = std.crypto.sign.Ed25519;
const Blake3 = std.crypto.hash.Blake3;

pub const PublicKey = [32]u8;
pub const SecretSeed = [32]u8;
pub const Signature = [64]u8;

/// Domain separators. See docs/SPEC-SIGNING.md §2.
///
/// The trailing `\x00` is load-bearing: it prevents any well-formed domain
/// from being a prefix of another, which makes the cross-domain-collision
/// argument trivial for static analysis. Do NOT drop it, and do NOT rely
/// on BLAKE3 derive_key here — we byte-prepend so that the same bytes are
/// hashable by external implementations that lack derive_key.
pub const COMMIT_DOMAIN: []const u8 = "mkit.commit\x00";
pub const REMIX_DOMAIN: []const u8 = "mkit.remix\x00";

pub const KeyPair = struct {
    public_key: PublicKey,
    seed: SecretSeed,

    /// Generate a new random keypair.
    pub fn generate(io: std.Io) KeyPair {
        const kp = Ed25519.KeyPair.generate(io);
        return .{
            .public_key = kp.public_key.bytes,
            .seed = kp.secret_key.seed(),
        };
    }

    /// Recreate keypair from a saved seed.
    pub fn fromSeed(seed: SecretSeed) !KeyPair {
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        return .{
            .public_key = kp.public_key.bytes,
            .seed = kp.secret_key.seed(),
        };
    }

    pub fn toEd25519(self: KeyPair) !Ed25519.KeyPair {
        return Ed25519.KeyPair.generateDeterministic(self.seed);
    }

    pub fn zeroize(self: *KeyPair) void {
        std.crypto.secureZero(u8, self.seed[0..]);
        std.crypto.secureZero(u8, self.public_key[0..]);
    }
};

const Buffer = std.ArrayList(u8);

fn writeU32Le(buf: *Buffer, allocator: Allocator, v: u32) !void {
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, v)));
}

fn writeU64Le(buf: *Buffer, allocator: Allocator, v: u64) !void {
    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u64, v)));
}

fn writePrologue(buf: *Buffer, allocator: Allocator, t: object.ObjectType) !void {
    try buf.append(allocator, @intFromEnum(t));
    try buf.appendSlice(allocator, &object.MAGIC);
    try buf.append(allocator, object.SCHEMA_VERSION);
}

/// Serialize a commit's fields for signing. The exact bytes covered by an
/// Ed25519 signature (after domain separation) — see docs/SPEC-SIGNING.md §3.
///
/// INCLUDED, in order:
///   1. Object prologue: `[type=0x03][magic="MKT1"][schema_version=0x01]`
///   2. `tree_hash` (32)
///   3. `parent_count` (u32 LE), `parent_hash` * parent_count (32 each)
///   4. Identity author: `[kind:u8][len:u16 LE][bytes:len]`
///   5. `message_len` (u32 LE), message bytes
///   6. `timestamp` (u64 LE)
///   7. `signer` (32)
///
/// EXCLUDED: `signature` (self-cover impossible), `message_hash`,
/// `content_digest` (see docs/SPEC-OBJECTS.md §5.1 for the canonical
/// signing-bytes pattern).
pub fn commitSigningBytes(allocator: Allocator, c: object.Commit) ![]u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .commit);
    try buf.appendSlice(allocator, &c.tree_hash);
    try writeU32Le(&buf, allocator, @intCast(c.parents.len));
    for (c.parents) |p| {
        try buf.appendSlice(allocator, &p);
    }
    try serialize.writeIdentity(&buf, allocator, c.author);
    try writeU32Le(&buf, allocator, @intCast(c.message.len));
    try buf.appendSlice(allocator, c.message);
    try writeU64Le(&buf, allocator, c.timestamp);
    try buf.appendSlice(allocator, &c.signer);

    return buf.toOwnedSlice(allocator);
}

/// Serialize a remix's fields for signing. See docs/SPEC-SIGNING.md §4.
pub fn remixSigningBytes(allocator: Allocator, r: object.Remix) ![]u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);

    try writePrologue(&buf, allocator, .remix);
    try buf.appendSlice(allocator, &r.tree_hash);
    try writeU32Le(&buf, allocator, @intCast(r.parents.len));
    for (r.parents) |p| {
        try buf.appendSlice(allocator, &p);
    }
    try writeU32Le(&buf, allocator, @intCast(r.sources.len));
    for (r.sources) |s| {
        try buf.appendSlice(allocator, &s.upstream_id);
        try buf.appendSlice(allocator, &s.commit_hash);
    }
    try serialize.writeIdentity(&buf, allocator, r.author);
    try writeU32Le(&buf, allocator, @intCast(r.message.len));
    try buf.appendSlice(allocator, r.message);
    try writeU64Le(&buf, allocator, r.timestamp);
    try buf.appendSlice(allocator, &r.signer);

    return buf.toOwnedSlice(allocator);
}

/// Compute the 32-byte BLAKE3 digest `BLAKE3(domain || signing_bytes)`
/// that an Ed25519 signature actually covers.
fn domainDigest(domain: []const u8, signing_bytes: []const u8) Hash {
    var out: Hash = undefined;
    var hasher = Blake3.init(.{});
    hasher.update(domain);
    hasher.update(signing_bytes);
    hasher.final(&out);
    return out;
}

/// Public helper: `BLAKE3("mkit.commit\x00" || commitSigningBytes)`.
pub fn commitSigningHash(allocator: Allocator, c: object.Commit) !Hash {
    const sb = try commitSigningBytes(allocator, c);
    defer allocator.free(sb);
    return domainDigest(COMMIT_DOMAIN, sb);
}

/// Public helper: `BLAKE3("mkit.remix\x00" || remixSigningBytes)`.
pub fn remixSigningHash(allocator: Allocator, r: object.Remix) !Hash {
    const sb = try remixSigningBytes(allocator, r);
    defer allocator.free(sb);
    return domainDigest(REMIX_DOMAIN, sb);
}

/// Sign a commit object. Returns the Ed25519 signature.
/// Covered bytes = BLAKE3(COMMIT_DOMAIN || commitSigningBytes).
pub fn signCommit(allocator: Allocator, commit: object.Commit, kp: KeyPair) !Signature {
    const signing_hash = try commitSigningHash(allocator, commit);
    const ed_kp = try kp.toEd25519();
    const sig = try ed_kp.sign(&signing_hash, null);
    return sig.toBytes();
}

/// Sign a remix object. Returns the Ed25519 signature.
pub fn signRemix(allocator: Allocator, remix: object.Remix, kp: KeyPair) !Signature {
    const signing_hash = try remixSigningHash(allocator, remix);
    const ed_kp = try kp.toEd25519();
    const sig = try ed_kp.sign(&signing_hash, null);
    return sig.toBytes();
}

/// Verify a commit's signature against the signer public key embedded in the commit.
pub fn verifyCommit(allocator: Allocator, commit: object.Commit) !bool {
    const signing_hash = commitSigningHash(allocator, commit) catch return false;
    const pub_key = Ed25519.PublicKey.fromBytes(commit.signer) catch return false;
    const sig = Ed25519.Signature.fromBytes(commit.signature);
    sig.verify(&signing_hash, pub_key) catch return false;
    return true;
}

/// Verify a remix's signature against the signer public key embedded in the remix.
pub fn verifyRemix(allocator: Allocator, remix: object.Remix) !bool {
    const signing_hash = remixSigningHash(allocator, remix) catch return false;
    const pub_key = Ed25519.PublicKey.fromBytes(remix.signer) catch return false;
    const sig = Ed25519.Signature.fromBytes(remix.signature);
    sig.verify(&signing_hash, pub_key) catch return false;
    return true;
}

// -- Tests --

/// Build an ed25519 Identity that references the caller-owned `pk` array.
/// `pk` MUST outlive the returned Identity — typically it lives on the
/// caller's stack.
fn makeEd25519Identity(pk: *const [32]u8) object.Identity {
    return .{ .kind = .ed25519, .bytes = pk[0..] };
}

test "keypair generate and recreate from seed" {
    const kp1 = KeyPair.generate(std.testing.io);
    const kp2 = try KeyPair.fromSeed(kp1.seed);
    try std.testing.expectEqual(kp1.public_key, kp2.public_key);
}

test "sign and verify commit" {
    const allocator = std.testing.allocator;
    const kp = KeyPair.generate(std.testing.io);

    const parents = try allocator.alloc(Hash, 0);
    defer allocator.free(parents);

    const author_bytes: [32]u8 = kp.public_key;
    var commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = parents,
        .author = makeEd25519Identity(&author_bytes),
        .signer = kp.public_key,
        .message = "signed commit",
        .timestamp = 1711300000,
        .signature = .{0} ** 64,
    };

    // Sign
    commit.signature = try signCommit(allocator, commit, kp);

    // Verify
    const valid = try verifyCommit(allocator, commit);
    try std.testing.expect(valid);
}

test "reject tampered commit" {
    const allocator = std.testing.allocator;
    const kp = KeyPair.generate(std.testing.io);

    const parents = try allocator.alloc(Hash, 0);
    defer allocator.free(parents);

    const author_bytes: [32]u8 = kp.public_key;
    var commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = parents,
        .author = makeEd25519Identity(&author_bytes),
        .signer = kp.public_key,
        .message = "original",
        .timestamp = 1711300000,
        .signature = .{0} ** 64,
    };
    commit.signature = try signCommit(allocator, commit, kp);

    // Tamper with the message
    commit.message = "tampered";
    const valid = try verifyCommit(allocator, commit);
    try std.testing.expect(!valid);
}

test "reject wrong signer key" {
    const allocator = std.testing.allocator;
    const kp1 = KeyPair.generate(std.testing.io);
    const kp2 = KeyPair.generate(std.testing.io);

    const parents = try allocator.alloc(Hash, 0);
    defer allocator.free(parents);

    const author_bytes: [32]u8 = kp1.public_key;
    var commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = parents,
        .author = makeEd25519Identity(&author_bytes),
        .signer = kp1.public_key, // signed by kp1
        .message = "test",
        .timestamp = 1000,
        .signature = .{0} ** 64,
    };
    commit.signature = try signCommit(allocator, commit, kp1);

    // Replace signer with kp2's key (but signature is from kp1)
    commit.signer = kp2.public_key;
    const valid = try verifyCommit(allocator, commit);
    try std.testing.expect(!valid);
}

test "sign and verify remix" {
    const allocator = std.testing.allocator;
    const kp = KeyPair.generate(std.testing.io);

    const parents = try allocator.alloc(Hash, 0);
    defer allocator.free(parents);
    var sources = try allocator.alloc(object.RemixSource, 1);
    defer allocator.free(sources);
    sources[0] = .{
        .upstream_id = hash_mod.hash("project"),
        .commit_hash = hash_mod.hash("commit"),
    };

    const author_bytes: [32]u8 = kp.public_key;
    var remix = object.Remix{
        .tree_hash = hash_mod.hash("tree"),
        .parents = parents,
        .sources = sources,
        .author = makeEd25519Identity(&author_bytes),
        .signer = kp.public_key,
        .message = "remixed track",
        .timestamp = 2000,
        .signature = .{0} ** 64,
    };
    remix.signature = try signRemix(allocator, remix, kp);

    const valid = try verifyRemix(allocator, remix);
    try std.testing.expect(valid);
}

test "signing bytes are deterministic" {
    const allocator = std.testing.allocator;
    const parents = [_]Hash{};
    const pk = [_]u8{0xAA} ** 32;
    const commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "deterministic",
        .timestamp = 1000,
        .signature = .{0xBB} ** 64,
    };

    const bytes1 = try commitSigningBytes(allocator, commit);
    defer allocator.free(bytes1);
    const bytes2 = try commitSigningBytes(allocator, commit);
    defer allocator.free(bytes2);

    try std.testing.expectEqualSlices(u8, bytes1, bytes2);
}

test "signing bytes exclude signature" {
    const allocator = std.testing.allocator;
    const parents = [_]Hash{};
    const pk = [_]u8{0xAA} ** 32;

    const c1 = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "test",
        .timestamp = 1000,
        .signature = .{0x00} ** 64,
    };
    const c2 = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "test",
        .timestamp = 1000,
        .signature = .{0xFF} ** 64,
    };

    const bytes1 = try commitSigningBytes(allocator, c1);
    defer allocator.free(bytes1);
    const bytes2 = try commitSigningBytes(allocator, c2);
    defer allocator.free(bytes2);

    // Same signing bytes despite different signatures
    try std.testing.expectEqualSlices(u8, bytes1, bytes2);
}

test "signing bytes exclude message_hash and content_digest" {
    // Two commits differing only in message_hash / content_digest MUST
    // produce byte-identical signing bytes (and therefore byte-identical
    // signing hashes). Resolves red-team R-45.
    const allocator = std.testing.allocator;
    const parents = [_]Hash{};
    const pk = [_]u8{0xAA} ** 32;

    const c1 = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "test",
        .timestamp = 1000,
        .message_hash = hash_mod.zero,
        .content_digest = hash_mod.zero,
        .signature = .{0} ** 64,
    };
    const c2 = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "test",
        .timestamp = 1000,
        .message_hash = hash_mod.hash("message-hash-x"),
        .content_digest = hash_mod.hash("content-digest-y"),
        .signature = .{0} ** 64,
    };

    const sb1 = try commitSigningBytes(allocator, c1);
    defer allocator.free(sb1);
    const sb2 = try commitSigningBytes(allocator, c2);
    defer allocator.free(sb2);
    try std.testing.expectEqualSlices(u8, sb1, sb2);

    const h1 = try commitSigningHash(allocator, c1);
    const h2 = try commitSigningHash(allocator, c2);
    try std.testing.expectEqual(h1, h2);
}

test "domain separation: commit domain differs from remix" {
    // A commit's signing hash MUST differ from BLAKE3("mkit.remix\x00" ||
    // same_bytes). Guards against cross-domain collisions.
    const allocator = std.testing.allocator;
    const parents = [_]Hash{};
    const pk = [_]u8{0xAA} ** 32;
    const commit = object.Commit{
        .tree_hash = hash_mod.zero,
        .parents = @constCast(&parents),
        .author = makeEd25519Identity(&pk),
        .signer = .{0xAA} ** 32,
        .message = "",
        .timestamp = 0,
        .signature = .{0} ** 64,
    };
    const sb = try commitSigningBytes(allocator, commit);
    defer allocator.free(sb);

    const commit_hash = domainDigest(COMMIT_DOMAIN, sb);
    const remix_hash = domainDigest(REMIX_DOMAIN, sb);

    try std.testing.expect(!std.mem.eql(u8, &commit_hash, &remix_hash));
}

test "commit with parents signs correctly" {
    const allocator = std.testing.allocator;
    const kp = KeyPair.generate(std.testing.io);

    var parents = try allocator.alloc(Hash, 2);
    defer allocator.free(parents);
    parents[0] = hash_mod.hash("parent1");
    parents[1] = hash_mod.hash("parent2");

    const author_bytes: [32]u8 = kp.public_key;
    var commit = object.Commit{
        .tree_hash = hash_mod.hash("merge-tree"),
        .parents = parents,
        .author = makeEd25519Identity(&author_bytes),
        .signer = kp.public_key,
        .message = "merge commit",
        .timestamp = 3000,
        .signature = .{0} ** 64,
    };
    commit.signature = try signCommit(allocator, commit, kp);

    const valid = try verifyCommit(allocator, commit);
    try std.testing.expect(valid);
}
