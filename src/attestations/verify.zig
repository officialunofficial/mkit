// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Attestation verification — §5.3 of docs/SPEC-ATTESTATIONS.md.
//
// This module only validates envelope well-formedness and per-signature
// cryptographic integrity against a caller-supplied trust root registry.
// Binding an attestation to a particular commit (subject check) is the
// caller's responsibility; `extractPrimaryCommitHash` is exposed as a
// convenience for that step.
//
// The registry dispatches on the DSSE `keyid` (§6.3). `repo-key` signers
// are keyed as `blake3:<hex>`; sigstore-keyless uses `sigstore:<san>`.
// Verification of sigstore signatures requires a full Rekor/Fulcio
// trust-root walk and is deliberately scaffolded here — §6.2 TODO.

const std = @import("std");
const Allocator = std.mem.Allocator;

const envelope = @import("envelope.zig");
const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;

const Ed25519 = std.crypto.sign.Ed25519;

// -----------------------------------------------------------------------------
// Trust root registry
// -----------------------------------------------------------------------------

pub const TrustRoot = union(enum) {
    ed25519_pubkey: [32]u8,
    /// Scaffold — sigstore verification requires a Rekor + Fulcio walk that
    /// we don't ship yet. See SPEC-ATTESTATIONS §6.2. For now any signature
    /// dispatched to this trust root reports `unsupported_trust_root`.
    // TODO(§6.2): replace with a struct carrying Fulcio cert chain + Rekor
    // log endpoint so `verifyEnvelope` can perform the real walk.
    sigstore_ca: void,
};

pub const Registry = struct {
    allocator: Allocator,
    entries: std.StringHashMap(TrustRoot),

    pub fn init(allocator: Allocator) Registry {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(TrustRoot).init(allocator),
        };
    }

    pub fn deinit(self: *Registry) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();
    }

    /// Add a trust root. `keyid` is duplicated; the caller retains ownership
    /// of the slice they passed in.
    pub fn add(self: *Registry, keyid: []const u8, root: TrustRoot) !void {
        const owned_key = try self.allocator.dupe(u8, keyid);
        errdefer self.allocator.free(owned_key);

        const gop = try self.entries.getOrPut(owned_key);
        if (gop.found_existing) {
            // Replace value; free the duplicate key we just made.
            self.allocator.free(owned_key);
        }
        gop.value_ptr.* = root;
    }

    pub fn lookup(self: *Registry, keyid: []const u8) ?TrustRoot {
        return self.entries.get(keyid);
    }
};

// -----------------------------------------------------------------------------
// Verify API
// -----------------------------------------------------------------------------

pub const Reason = enum {
    ok,
    unknown_keyid,
    signature_mismatch,
    unsupported_trust_root,
};

pub const SignatureResult = struct {
    /// Borrowed from the decoded envelope; valid only while the
    /// containing `EnvelopeResult` is live (it owns duplicated copies).
    keyid: []const u8,
    verified: bool,
    reason: Reason,
};

pub const EnvelopeResult = struct {
    any_verified: bool,
    signatures: []SignatureResult,
    allocator: Allocator,

    pub fn deinit(self: *EnvelopeResult) void {
        for (self.signatures) |sr| {
            self.allocator.free(sr.keyid);
        }
        self.allocator.free(self.signatures);
    }
};

/// Verify a DSSE envelope against a trust root registry. The caller is
/// responsible for further checks (e.g. that the Statement subject
/// matches the commit being asked about). This function only validates
/// envelope well-formedness + per-signature crypto.
///
/// Returns errors for hard-fail conditions (malformed envelope, wrong
/// payload type, no signatures). Returns an `EnvelopeResult` with a
/// per-signature verdict otherwise.
pub fn verifyEnvelope(
    allocator: Allocator,
    envelope_bytes: []const u8,
    registry: *Registry,
) !EnvelopeResult {
    var dec = try envelope.decode(allocator, envelope_bytes);
    defer dec.deinit();

    if (!std.mem.eql(u8, dec.payload_type, envelope.PAYLOAD_TYPE_IN_TOTO)) {
        return error.UnsupportedPayloadType;
    }
    if (dec.signatures.len == 0) {
        return error.EmptySignatures;
    }

    const pae_bytes = try envelope.pae(allocator, dec.payload_type, dec.payload);
    defer allocator.free(pae_bytes);

    var results = try allocator.alloc(SignatureResult, dec.signatures.len);
    errdefer {
        // Best-effort cleanup if we fail mid-loop.
        for (results, 0..) |r, i| {
            if (i >= dec.signatures.len) break;
            allocator.free(r.keyid);
        }
        allocator.free(results);
    }

    var any_verified = false;
    var filled: usize = 0;
    for (dec.signatures, 0..) |sig, i| {
        const keyid_copy = try allocator.dupe(u8, sig.keyid);
        results[i] = .{
            .keyid = keyid_copy,
            .verified = false,
            .reason = .unknown_keyid,
        };
        filled = i + 1;

        const maybe_root = registry.lookup(sig.keyid);
        if (maybe_root == null) {
            results[i].reason = .unknown_keyid;
            continue;
        }

        switch (maybe_root.?) {
            .ed25519_pubkey => |pk_bytes| {
                results[i].reason = verifyEd25519Signature(pk_bytes, sig.sig, pae_bytes);
                if (results[i].reason == .ok) {
                    results[i].verified = true;
                    any_verified = true;
                }
            },
            .sigstore_ca => {
                // TODO(§6.2): dispatch to a Rekor/Fulcio verifier. Until
                // then we surface the scaffold verdict and move on.
                results[i].reason = .unsupported_trust_root;
            },
        }
    }

    return .{
        .any_verified = any_verified,
        .signatures = results,
        .allocator = allocator,
    };
}

fn verifyEd25519Signature(pk_bytes: [32]u8, sig_bytes: []const u8, pae_bytes: []const u8) Reason {
    if (sig_bytes.len != Ed25519.Signature.encoded_length) return .signature_mismatch;
    var sig_arr: [Ed25519.Signature.encoded_length]u8 = undefined;
    @memcpy(sig_arr[0..], sig_bytes);

    const pub_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch return .signature_mismatch;
    const sig = Ed25519.Signature.fromBytes(sig_arr);
    sig.verify(pae_bytes, pub_key) catch return .signature_mismatch;
    return .ok;
}

// -----------------------------------------------------------------------------
// Subject check helper
// -----------------------------------------------------------------------------

/// Parse the in-toto Statement payload and return the first
/// `subject[].digest.blake3` as a `Hash`. Errors if the JSON is malformed,
/// subject[] is missing/empty, or the first entry is missing a blake3
/// digest with the expected 64-char hex shape.
///
/// We use a relaxed JSON parser here (not the strict JCS decoder) because
/// we do not need to re-canonicalise on the verify side — we just want to
/// read the subject hash out for binding to a commit.
pub fn extractPrimaryCommitHash(
    allocator: Allocator,
    statement_json: []const u8,
) !Hash {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, statement_json, .{}) catch {
        return error.MalformedStatement;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.MalformedStatement;

    const subject_val = root.object.get("subject") orelse return error.SubjectMissing;
    if (subject_val != .array) return error.MalformedStatement;
    if (subject_val.array.items.len == 0) return error.SubjectMissing;

    const first = subject_val.array.items[0];
    if (first != .object) return error.MalformedStatement;

    const digest_val = first.object.get("digest") orelse return error.SubjectDigestMissing;
    if (digest_val != .object) return error.MalformedStatement;

    const blake3_val = digest_val.object.get("blake3") orelse return error.SubjectDigestMissing;
    if (blake3_val != .string) return error.MalformedStatement;

    const hex = blake3_val.string;
    if (hex.len != hash_mod.hex_len) return error.InvalidDigestLength;

    var out: Hash = undefined;
    _ = std.fmt.hexToBytes(out[0..], hex) catch return error.InvalidDigestHex;
    return out;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;
const statement_mod = @import("statement.zig");

/// Build a DSSE envelope with a single ed25519 signature over an in-toto
/// Statement that claims `commit_hex` as its subject. Returns the encoded
/// envelope bytes (owned) and the public key bytes the signature will
/// verify under.
fn buildSignedEnvelope(
    allocator: Allocator,
    seed: [32]u8,
    keyid: []const u8,
    commit_hex: []const u8,
    predicate_jcs: []const u8,
) !struct { bytes: []u8, pubkey: [32]u8 } {
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pk_bytes = kp.public_key.toBytes();

    const subjects = [_]statement_mod.Subject{.{
        .name = "commit",
        .digest_blake3_hex = commit_hex,
    }};
    const stmt_bytes = try statement_mod.encode(allocator, .{
        .subjects = subjects[0..],
        .predicate_type = "https://example.com/predicate/v1",
        .predicate_jcs = predicate_jcs,
    });
    defer allocator.free(stmt_bytes);

    const pae_bytes = try envelope.pae(allocator, envelope.PAYLOAD_TYPE_IN_TOTO, stmt_bytes);
    defer allocator.free(pae_bytes);

    const sig = try kp.sign(pae_bytes, null);
    const sig_bytes = sig.toBytes();

    const env_bytes = try envelope.encode(allocator, .{
        .payload_type = envelope.PAYLOAD_TYPE_IN_TOTO,
        .payload = stmt_bytes,
        .signatures = &.{.{ .keyid = keyid, .sig = sig_bytes[0..] }},
    });

    return .{ .bytes = env_bytes, .pubkey = pk_bytes };
}

test "deterministic_repo_key_roundtrip" {
    const seed: [32]u8 = .{0xAB} ** 32;
    const keyid = "blake3:deadbeef";
    const commit_hex = "0011223344556677889900112233445566778899001122334455667788990011";

    const built = try buildSignedEnvelope(testing.allocator, seed, keyid, commit_hex, "{}");
    defer testing.allocator.free(built.bytes);

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.add(keyid, .{ .ed25519_pubkey = built.pubkey });

    var result = try verifyEnvelope(testing.allocator, built.bytes, &registry);
    defer result.deinit();

    try testing.expect(result.any_verified);
    try testing.expectEqual(@as(usize, 1), result.signatures.len);
    try testing.expectEqual(Reason.ok, result.signatures[0].reason);
    try testing.expect(result.signatures[0].verified);
    try testing.expectEqualStrings(keyid, result.signatures[0].keyid);
}

test "rejects_empty_signatures" {
    // We can't build a zero-signature envelope via `envelope.encode` (it
    // errors out), but we can hand-craft the JCS bytes the decoder accepts.
    const bytes = "{\"payload\":\"e30=\",\"payloadType\":\"application/vnd.in-toto+json\",\"signatures\":[]}";

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    try testing.expectError(
        error.EmptySignatures,
        verifyEnvelope(testing.allocator, bytes, &registry),
    );
}

test "rejects_bad_payload_type" {
    // Hand-crafted envelope with wrong payloadType but a plausible signature
    // block so the decoder accepts it.
    const bytes = "{\"payload\":\"e30=\",\"payloadType\":\"application/x-foo\",\"signatures\":[{\"keyid\":\"k\",\"sig\":\"AQID\"}]}";

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    try testing.expectError(
        error.UnsupportedPayloadType,
        verifyEnvelope(testing.allocator, bytes, &registry),
    );
}

test "unknown_keyid_does_not_verify" {
    const seed: [32]u8 = .{0x11} ** 32;
    const keyid = "blake3:unknown";
    const commit_hex = "a" ** 64;

    const built = try buildSignedEnvelope(testing.allocator, seed, keyid, commit_hex, "{}");
    defer testing.allocator.free(built.bytes);

    // Deliberately do NOT register the keyid.
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    var result = try verifyEnvelope(testing.allocator, built.bytes, &registry);
    defer result.deinit();

    try testing.expect(!result.any_verified);
    try testing.expectEqual(@as(usize, 1), result.signatures.len);
    try testing.expectEqual(Reason.unknown_keyid, result.signatures[0].reason);
    try testing.expect(!result.signatures[0].verified);
}

test "tampered_payload_fails_signature" {
    const seed: [32]u8 = .{0x42} ** 32;
    const keyid = "blake3:tampered";
    const commit_hex = "b" ** 64;

    const built = try buildSignedEnvelope(testing.allocator, seed, keyid, commit_hex, "{}");
    defer testing.allocator.free(built.bytes);

    // Decode, flip one byte inside the payload, re-encode.
    var dec = try envelope.decode(testing.allocator, built.bytes);
    defer dec.deinit();

    // Flip a byte somewhere in the middle of the payload.
    dec.payload[dec.payload.len / 2] ^= 0x01;

    const tampered = try envelope.encode(testing.allocator, .{
        .payload_type = dec.payload_type,
        .payload = dec.payload,
        .signatures = &.{.{ .keyid = dec.signatures[0].keyid, .sig = dec.signatures[0].sig }},
    });
    defer testing.allocator.free(tampered);

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.add(keyid, .{ .ed25519_pubkey = built.pubkey });

    var result = try verifyEnvelope(testing.allocator, tampered, &registry);
    defer result.deinit();

    try testing.expect(!result.any_verified);
    try testing.expectEqual(@as(usize, 1), result.signatures.len);
    try testing.expectEqual(Reason.signature_mismatch, result.signatures[0].reason);
}

test "extractPrimaryCommitHash_happy_path" {
    const commit: Hash = .{0xCC} ** 32;
    const hex = hash_mod.toHex(commit);
    const subjects = [_]statement_mod.Subject{.{
        .name = "commit",
        .digest_blake3_hex = hex[0..],
    }};
    const stmt_bytes = try statement_mod.encode(testing.allocator, .{
        .subjects = subjects[0..],
        .predicate_type = "https://example.com/p",
        .predicate_jcs = "{}",
    });
    defer testing.allocator.free(stmt_bytes);

    const parsed_hash = try extractPrimaryCommitHash(testing.allocator, stmt_bytes);
    try testing.expectEqual(commit, parsed_hash);
}

test "extractPrimaryCommitHash_rejects_missing_subject" {
    // Hand-crafted statement with an empty `subject` array.
    const empty_subject =
        "{\"_type\":\"https://in-toto.io/Statement/v1\"," ++
        "\"predicate\":{}," ++
        "\"predicateType\":\"https://example.com/p\"," ++
        "\"subject\":[]}";
    try testing.expectError(
        error.SubjectMissing,
        extractPrimaryCommitHash(testing.allocator, empty_subject),
    );

    // Also: no subject key at all.
    const no_subject =
        "{\"_type\":\"https://in-toto.io/Statement/v1\"," ++
        "\"predicate\":{}," ++
        "\"predicateType\":\"https://example.com/p\"}";
    try testing.expectError(
        error.SubjectMissing,
        extractPrimaryCommitHash(testing.allocator, no_subject),
    );
}

test "sigstore trust root is scaffold: unsupported_trust_root" {
    const seed: [32]u8 = .{0x33} ** 32;
    const keyid = "sigstore:https://example.com/workflow";
    const commit_hex = "c" ** 64;

    const built = try buildSignedEnvelope(testing.allocator, seed, keyid, commit_hex, "{}");
    defer testing.allocator.free(built.bytes);

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.add(keyid, .{ .sigstore_ca = {} });

    var result = try verifyEnvelope(testing.allocator, built.bytes, &registry);
    defer result.deinit();

    try testing.expect(!result.any_verified);
    try testing.expectEqual(Reason.unsupported_trust_root, result.signatures[0].reason);
}

test "registry.add replaces existing entry without leaking" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    try registry.add("k", .{ .ed25519_pubkey = .{0} ** 32 });
    try registry.add("k", .{ .ed25519_pubkey = .{1} ** 32 });

    const got = registry.lookup("k").?;
    try testing.expectEqual(@as(u8, 1), got.ed25519_pubkey[0]);
}
