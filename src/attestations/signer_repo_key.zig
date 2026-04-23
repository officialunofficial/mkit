// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Repo-key signer — the default `Signer` impl.
//
// Wraps the same Ed25519 `sign.KeyPair` that signs commits. The caller
// loads the key from `.mkit/keys/default.key` (this module does no I/O)
// and hands us the KeyPair. `signDsse` signs the DSSE PAE bytes directly:
// no extra domain prefix, because the PAE's own `"DSSEv1 "` prefix is
// the domain separator per SPEC-ATTESTATIONS §7.2 and §2.1.
//
// keyid convention (SPEC-ATTESTATIONS §6.3):
//     "blake3:" || hex(BLAKE3(pubkey))
// where `pubkey` is the 32-byte Ed25519 public key.

const std = @import("std");
const Allocator = std.mem.Allocator;

const sign = @import("../sign.zig");
const hash_mod = @import("../hash.zig");

const signer_mod = @import("signer.zig");
const Signer = signer_mod.Signer;

const Ed25519 = std.crypto.sign.Ed25519;

pub const KEYID_PREFIX = "blake3:";

pub const RepoKeySigner = struct {
    kp: sign.KeyPair,

    pub fn init(kp: sign.KeyPair) RepoKeySigner {
        return .{ .kp = kp };
    }

    pub fn asSigner(self: *RepoKeySigner) Signer {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    const vtable: Signer.VTable = .{
        .keyid = keyidImpl,
        .signDsse = signDsseImpl,
    };

    fn keyidImpl(ptr: *anyopaque, allocator: Allocator) anyerror![]u8 {
        const self: *RepoKeySigner = @ptrCast(@alignCast(ptr));
        const pk_digest = hash_mod.hash(&self.kp.public_key);
        const hex = hash_mod.toHex(pk_digest);
        var out = try allocator.alloc(u8, KEYID_PREFIX.len + hex.len);
        @memcpy(out[0..KEYID_PREFIX.len], KEYID_PREFIX);
        @memcpy(out[KEYID_PREFIX.len..], &hex);
        return out;
    }

    fn signDsseImpl(ptr: *anyopaque, allocator: Allocator, pae: []const u8) anyerror![]u8 {
        const self: *RepoKeySigner = @ptrCast(@alignCast(ptr));
        const ed_kp = try self.kp.toEd25519();
        // Sign the PAE bytes directly — no extra domain prefix (the
        // "DSSEv1 " inside the PAE is already the domain separator).
        const sig = try ed_kp.sign(pae, null);
        const bytes = sig.toBytes();
        const out = try allocator.alloc(u8, bytes.len);
        @memcpy(out, &bytes);
        return out;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "repo-key signer: signature verifies with std.crypto.sign.Ed25519" {
    const allocator = testing.allocator;

    // Deterministic keypair so the test is fully reproducible.
    const seed: sign.SecretSeed = .{0x42} ** 32;
    const kp = try sign.KeyPair.fromSeed(seed);

    var rks = RepoKeySigner.init(kp);
    const s = rks.asSigner();

    const pae = "DSSEv1 28 application/vnd.in-toto+json 2 {}";
    const sig_bytes = try s.signDsse(allocator, pae);
    defer allocator.free(sig_bytes);

    try testing.expectEqual(@as(usize, 64), sig_bytes.len);

    // Verify the signature is valid for this PAE under the keypair's pubkey.
    const pk = try Ed25519.PublicKey.fromBytes(kp.public_key);
    const sig = Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
    try sig.verify(pae, pk);

    // Tampering with the PAE must break verification.
    const tampered = "DSSEv1 28 application/vnd.in-toto+json 2 {X";
    try testing.expectError(error.SignatureVerificationFailed, sig.verify(tampered, pk));
}

test "repo-key signer: keyid is blake3:<64-hex>, total 71 bytes" {
    const allocator = testing.allocator;

    const seed: sign.SecretSeed = .{0x11} ** 32;
    const kp = try sign.KeyPair.fromSeed(seed);

    var rks = RepoKeySigner.init(kp);
    const s = rks.asSigner();

    const kid = try s.keyid(allocator);
    defer allocator.free(kid);

    try testing.expectEqual(@as(usize, 71), kid.len);
    try testing.expect(std.mem.startsWith(u8, kid, "blake3:"));

    // Remainder must be 64 lowercase hex chars.
    const hex_part = kid[KEYID_PREFIX.len..];
    try testing.expectEqual(@as(usize, 64), hex_part.len);
    for (hex_part) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try testing.expect(ok);
    }

    // Value must equal BLAKE3(pubkey) in hex.
    const expected = hash_mod.toHex(hash_mod.hash(&kp.public_key));
    try testing.expectEqualStrings(&expected, hex_part);
}

test "repo-key signer: keyid is deterministic across calls" {
    const allocator = testing.allocator;

    const seed: sign.SecretSeed = .{0x7F} ** 32;
    const kp = try sign.KeyPair.fromSeed(seed);

    var rks = RepoKeySigner.init(kp);
    const s = rks.asSigner();

    const a = try s.keyid(allocator);
    defer allocator.free(a);
    const b = try s.keyid(allocator);
    defer allocator.free(b);
    try testing.expectEqualStrings(a, b);
}
