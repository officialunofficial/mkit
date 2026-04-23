// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DSSE envelope — the outer signed container for every mkit attestation.
// See docs/SPEC-ATTESTATIONS.md §2 and
// https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
//
// Envelope shape (JCS-canonical JSON):
//   {
//     "payload":     "<base64(payload_bytes)>",
//     "payloadType": "<media-type>",
//     "signatures":  [ { "keyid": <string>, "sig": "<base64(sig_bytes)>" }, ... ]
//   }
//
// Signed bytes are the DSSE Pre-Authentication Encoding (PAE):
//   "DSSEv1" SP ascii(len(type)) SP type SP ascii(len(payload)) SP payload
// where `payload` is the UTF-8 bytes (not base64) of the payload.
//
// mkit does not implement the hashed-PAE variant (DSSEv1 + SHA-256); we
// stick to the one-variant-only form because our signer trait always
// hands the signer the raw PAE and lets it decide whether to pre-hash.

const std = @import("std");
const Allocator = std.mem.Allocator;

const jcs = @import("jcs.zig");
const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;

/// MIME type written into `payloadType` for every mkit attestation.
pub const PAYLOAD_TYPE_IN_TOTO = "application/vnd.in-toto+json";

pub const Signature = struct {
    keyid: []const u8,
    /// Raw signature bytes (not base64). Encoder base64s them on the way out.
    sig: []const u8,
};

pub const Envelope = struct {
    payload_type: []const u8,
    /// Raw payload bytes (not base64). Encoder base64s them on the way out.
    payload: []const u8,
    signatures: []const Signature,
};

/// Build the DSSE PAE for a `(payloadType, payload)` pair.
/// Returns allocator-owned bytes.
pub fn pae(allocator: Allocator, payload_type: []const u8, payload: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "DSSEv1 {d} {s} {d} {s}",
        .{ payload_type.len, payload_type, payload.len, payload },
    );
}

/// Encode an envelope to JCS-canonical JSON. Caller owns the returned slice.
pub fn encode(allocator: Allocator, env: Envelope) ![]u8 {
    if (env.signatures.len == 0) return error.EnvelopeNeedsAtLeastOneSignature;
    if (env.payload_type.len == 0) return error.PayloadTypeEmpty;

    // Pre-compute base64 buffers so we can stick them in a jcs.Value tree.
    const b64 = std.base64.standard.Encoder;
    const payload_b64 = try allocator.alloc(u8, b64.calcSize(env.payload.len));
    defer allocator.free(payload_b64);
    _ = b64.encode(payload_b64, env.payload);

    // signatures[] — allocate one jcs.Member list per signature. We track
    // per-entry base64 allocations so we can free them all on the way out.
    const sig_b64s = try allocator.alloc([]u8, env.signatures.len);
    defer {
        for (sig_b64s) |s| allocator.free(s);
        allocator.free(sig_b64s);
    }

    const sig_values = try allocator.alloc(jcs.Value, env.signatures.len);
    defer allocator.free(sig_values);

    const sig_members_storage = try allocator.alloc([2]jcs.Member, env.signatures.len);
    defer allocator.free(sig_members_storage);

    for (env.signatures, 0..) |s, i| {
        const buf = try allocator.alloc(u8, b64.calcSize(s.sig.len));
        _ = b64.encode(buf, s.sig);
        sig_b64s[i] = buf;

        sig_members_storage[i] = [2]jcs.Member{
            .{ .key = "keyid", .value = .{ .string = s.keyid } },
            .{ .key = "sig", .value = .{ .string = buf } },
        };
        sig_values[i] = .{ .object = sig_members_storage[i][0..] };
    }

    const root: jcs.Value = .{ .object = &.{
        .{ .key = "payload", .value = .{ .string = payload_b64 } },
        .{ .key = "payloadType", .value = .{ .string = env.payload_type } },
        .{ .key = "signatures", .value = .{ .array = sig_values } },
    } };

    return try jcs.encode(allocator, root);
}

/// Compute the attestation id: BLAKE3 over the encoded envelope bytes.
pub fn attestationId(envelope_bytes: []const u8) Hash {
    return hash_mod.hash(envelope_bytes);
}

// -----------------------------------------------------------------------------
// Decoder — minimal, only what `mkit attest verify` / `show` need.
//
// We do NOT round-trip arbitrary JSON. We accept the shape our encoder
// produces and extract the four fields we care about. Anything else is
// rejected with `error.MalformedEnvelope`. This is a trade-off — it keeps
// us from needing a full JSON parser, at the cost of being intolerant of
// attestations produced by other tools with non-JCS spacing.
//
// Mitigation: if we ever need to ingest third-party DSSE envelopes we
// re-canonicalise via their JSON + our writer before storing; on disk
// mkit only ever sees its own output, where the decoder's strictness
// is a feature.
// -----------------------------------------------------------------------------

pub const DecodedEnvelope = struct {
    payload_type: []u8,
    payload: []u8,
    signatures: []DecodedSignature,
    allocator: Allocator,

    pub fn deinit(self: *DecodedEnvelope) void {
        for (self.signatures) |s| {
            self.allocator.free(s.keyid);
            self.allocator.free(s.sig);
        }
        self.allocator.free(self.signatures);
        self.allocator.free(self.payload);
        self.allocator.free(self.payload_type);
    }
};

pub const DecodedSignature = struct {
    keyid: []u8,
    sig: []u8,
};

/// Decode the JCS-canonical DSSE envelope bytes our `encode` produces.
/// Accepts only the exact shape + key order we emit. Strict by design.
pub fn decode(allocator: Allocator, bytes: []const u8) !DecodedEnvelope {
    const b64 = std.base64.standard.Decoder;

    // Expected form:
    // {"payload":"<..>","payloadType":"<..>","signatures":[{"keyid":"..","sig":".."},...]}
    var p = Parser{ .src = bytes, .pos = 0 };
    try p.expect("{\"payload\":");
    const payload_b64 = try p.takeString(allocator);
    errdefer allocator.free(payload_b64);

    try p.expect(",\"payloadType\":");
    const payload_type = try p.takeString(allocator);
    errdefer allocator.free(payload_type);

    try p.expect(",\"signatures\":[");
    var sigs: std.ArrayList(DecodedSignature) = .empty;
    errdefer {
        for (sigs.items) |s| {
            allocator.free(s.keyid);
            allocator.free(s.sig);
        }
        sigs.deinit(allocator);
    }
    if (!p.peek(']')) {
        while (true) {
            try p.expect("{\"keyid\":");
            const keyid = try p.takeString(allocator);
            errdefer allocator.free(keyid);
            try p.expect(",\"sig\":");
            const sig_b64 = try p.takeString(allocator);
            errdefer allocator.free(sig_b64);
            try p.expect("}");

            const sig_bytes = try allocator.alloc(u8, b64.calcSizeForSlice(sig_b64) catch return error.MalformedEnvelope);
            errdefer allocator.free(sig_bytes);
            b64.decode(sig_bytes, sig_b64) catch return error.MalformedEnvelope;
            allocator.free(sig_b64);

            try sigs.append(allocator, .{ .keyid = keyid, .sig = sig_bytes });

            if (p.peek(',')) {
                p.pos += 1;
                continue;
            }
            break;
        }
    }
    try p.expect("]}");
    if (p.pos != bytes.len) return error.MalformedEnvelope;

    const payload = try allocator.alloc(u8, b64.calcSizeForSlice(payload_b64) catch return error.MalformedEnvelope);
    errdefer allocator.free(payload);
    b64.decode(payload, payload_b64) catch return error.MalformedEnvelope;
    allocator.free(payload_b64);

    return .{
        .payload_type = payload_type,
        .payload = payload,
        .signatures = try sigs.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

const Parser = struct {
    src: []const u8,
    pos: usize,

    fn expect(self: *Parser, s: []const u8) !void {
        if (self.pos + s.len > self.src.len) return error.MalformedEnvelope;
        if (!std.mem.eql(u8, self.src[self.pos .. self.pos + s.len], s)) return error.MalformedEnvelope;
        self.pos += s.len;
    }

    fn peek(self: *const Parser, c: u8) bool {
        return self.pos < self.src.len and self.src[self.pos] == c;
    }

    fn takeString(self: *Parser, allocator: Allocator) ![]u8 {
        if (self.pos >= self.src.len or self.src[self.pos] != '"') return error.MalformedEnvelope;
        self.pos += 1;
        const start = self.pos;
        // Payload / sig are base64 — no escapes. Keyid uses our JCS short-form
        // escapes at emit time but in practice mkit keyids are ASCII-only.
        // Reject any backslash for simplicity; we never emit them.
        while (self.pos < self.src.len and self.src[self.pos] != '"') : (self.pos += 1) {
            if (self.src[self.pos] == '\\') return error.MalformedEnvelope;
        }
        if (self.pos >= self.src.len) return error.MalformedEnvelope;
        const buf = try allocator.dupe(u8, self.src[start..self.pos]);
        self.pos += 1; // closing "
        return buf;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "pae: DSSE v1 reference encoding" {
    // Taken straight from the DSSE spec example.
    // PAE("hello", "body") = "DSSEv1 5 hello 4 body"
    const got = try pae(testing.allocator, "hello", "body");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("DSSEv1 5 hello 4 body", got);
}

test "pae: empty payload is allowed but length is 0" {
    const got = try pae(testing.allocator, "t", "");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("DSSEv1 1 t 0 ", got);
}

test "encode: one signature, canonical shape" {
    const got = try encode(testing.allocator, .{
        .payload_type = "application/vnd.in-toto+json",
        .payload = "{}",
        .signatures = &.{.{ .keyid = "blake3:aa", .sig = "\x01\x02\x03" }},
    });
    defer testing.allocator.free(got);
    // payload "{}" = 7b 7d → base64 "e30="
    // sig 01 02 03      → base64 "AQID"
    try testing.expectEqualStrings(
        "{\"payload\":\"e30=\"," ++
            "\"payloadType\":\"application/vnd.in-toto+json\"," ++
            "\"signatures\":[{\"keyid\":\"blake3:aa\",\"sig\":\"AQID\"}]}",
        got,
    );
}

test "encode: zero signatures rejected" {
    try testing.expectError(
        error.EnvelopeNeedsAtLeastOneSignature,
        encode(testing.allocator, .{
            .payload_type = "x",
            .payload = "{}",
            .signatures = &.{},
        }),
    );
}

test "encode: empty payload_type rejected" {
    try testing.expectError(
        error.PayloadTypeEmpty,
        encode(testing.allocator, .{
            .payload_type = "",
            .payload = "{}",
            .signatures = &.{.{ .keyid = "k", .sig = "s" }},
        }),
    );
}

test "encode/decode round-trip" {
    const env: Envelope = .{
        .payload_type = PAYLOAD_TYPE_IN_TOTO,
        .payload = "{\"a\":1}",
        .signatures = &.{
            .{ .keyid = "blake3:aa", .sig = "\x10\x20\x30\x40" },
            .{ .keyid = "sigstore:https://example.com", .sig = "\xAA\xBB\xCC" },
        },
    };
    const bytes = try encode(testing.allocator, env);
    defer testing.allocator.free(bytes);

    var decoded = try decode(testing.allocator, bytes);
    defer decoded.deinit();

    try testing.expectEqualStrings(env.payload_type, decoded.payload_type);
    try testing.expectEqualStrings(env.payload, decoded.payload);
    try testing.expectEqual(@as(usize, 2), decoded.signatures.len);
    try testing.expectEqualStrings("blake3:aa", decoded.signatures[0].keyid);
    try testing.expectEqualSlices(u8, "\x10\x20\x30\x40", decoded.signatures[0].sig);
    try testing.expectEqualStrings("sigstore:https://example.com", decoded.signatures[1].keyid);
    try testing.expectEqualSlices(u8, "\xAA\xBB\xCC", decoded.signatures[1].sig);
}

test "decode: rejects malformed envelope" {
    try testing.expectError(error.MalformedEnvelope, decode(testing.allocator, "not json"));
    try testing.expectError(error.MalformedEnvelope, decode(testing.allocator, "{}"));
    // trailing garbage
    const good = try encode(testing.allocator, .{
        .payload_type = "x",
        .payload = "",
        .signatures = &.{.{ .keyid = "k", .sig = "" }},
    });
    defer testing.allocator.free(good);
    const with_trailer = try std.fmt.allocPrint(testing.allocator, "{s}trailing", .{good});
    defer testing.allocator.free(with_trailer);
    try testing.expectError(error.MalformedEnvelope, decode(testing.allocator, with_trailer));
}

test "attestationId is stable across equivalent envelopes" {
    const a = try encode(testing.allocator, .{
        .payload_type = PAYLOAD_TYPE_IN_TOTO,
        .payload = "{}",
        .signatures = &.{.{ .keyid = "k", .sig = "\x01" }},
    });
    defer testing.allocator.free(a);
    const b = try encode(testing.allocator, .{
        .payload_type = PAYLOAD_TYPE_IN_TOTO,
        .payload = "{}",
        .signatures = &.{.{ .keyid = "k", .sig = "\x01" }},
    });
    defer testing.allocator.free(b);
    try testing.expectEqual(attestationId(a), attestationId(b));
}
