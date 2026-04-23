// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Golden-vector harvester for the Rust port (Phase 1).
//
// This harness is deliberately I/O-minimal: it takes a single argument
// naming the vector to emit, constructs the corresponding in-memory
// object using the live Zig `object` + `serialize` + `hash` modules,
// and writes the raw canonical bytes to stdout. The shell wrapper
// (scripts/harvest-golden-vectors.sh) captures that stdout into the
// appropriate `.bin` file and emits the matching `.json` metadata.
//
// The split exists because Zig 0.16 redesigned std.fs and std.process,
// so doing filesystem work from a short-lived harness is significantly
// easier in shell than in Zig. The only Zig-side I/O used here is
// writing raw bytes to stdout, which remained stable across 0.15 / 0.16.
//
// Determinism contract: every input is a fixed constant. Re-running the
// harvester produces byte-identical output. Do NOT introduce time /
// random / env reads.

const std = @import("std");
const mkit = @import("mkit_src");
const object = mkit.object;
const serialize = mkit.serialize;
const hash_mod = mkit.hash;
const sign = mkit.sign;
const attestations = mkit.attestations;
const fastcdc = mkit.fastcdc;
const s3_auth = mkit.s3;
const remote_mod = mkit.remote;

const Allocator = std.mem.Allocator;
const Hash = hash_mod.Hash;

// Deterministic test inputs — never change these. Golden vectors pin
// the resulting byte sequences and their BLAKE3 hashes.
const PUBKEY_A: [32]u8 = .{0xAA} ** 32;
const PUBKEY_B: [32]u8 = .{0xBB} ** 32;
const SIGNER: [32]u8 = .{0x11} ** 32;
const SIGNATURE: [64]u8 = .{0x22} ** 64;
const FIXED_TIMESTAMP: u64 = 1_700_000_000;

// ------------------------------------------------------------------------
// Vector builders
// ------------------------------------------------------------------------

fn buildBlob(arena: Allocator) ![]u8 {
    const obj = object.Object{ .blob = .{ .data = "hello mkit\n" } };
    return try serialize.serialize(arena, obj);
}

fn buildEmptyBlob(arena: Allocator) ![]u8 {
    const obj = object.Object{ .blob = .{ .data = "" } };
    return try serialize.serialize(arena, obj);
}

fn buildEmptyTree(arena: Allocator) ![]u8 {
    const entries = try arena.alloc(object.TreeEntry, 0);
    const obj = object.Object{ .tree = .{ .entries = entries } };
    return try serialize.serialize(arena, obj);
}

fn buildTreeSingleFile(arena: Allocator) ![]u8 {
    // Per SPEC-OBJECTS §13.3 — single-entry tree where the entry's
    // object_hash is BLAKE3 of the empty-blob bytes (§13.1).
    const empty_blob_bytes = try buildEmptyBlob(arena);
    defer arena.free(empty_blob_bytes);
    const blob_hash = hash_mod.hash(empty_blob_bytes);
    var entries = try arena.alloc(object.TreeEntry, 1);
    entries[0] = .{ .name = "README.md", .mode = .blob, .object_hash = blob_hash };
    const obj = object.Object{ .tree = .{ .entries = entries } };
    return try serialize.serialize(arena, obj);
}

fn buildIdentityEd25519(arena: Allocator) ![]u8 {
    // Raw wire format per SPEC-OBJECTS §9: [u8 kind][u16 LE len][payload].
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(arena);
    try buf.append(arena, @intFromEnum(object.IdentityKind.ed25519));
    var len_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_le, 32, .little);
    try buf.appendSlice(arena, &len_le);
    try buf.appendSlice(arena, &PUBKEY_A);
    return try buf.toOwnedSlice(arena);
}

fn buildIdentityOpaque(arena: Allocator) ![]u8 {
    // 8-byte little-endian u64 = 42, typical opaque identity shape.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(arena);
    try buf.append(arena, @intFromEnum(object.IdentityKind.@"opaque"));
    var len_le: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_le, 8, .little);
    try buf.appendSlice(arena, &len_le);
    const payload = [_]u8{ 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try buf.appendSlice(arena, &payload);
    return try buf.toOwnedSlice(arena);
}

fn buildTree(arena: Allocator) ![]u8 {
    // Stable child hashes so the tree bytes never shift.
    const blob_child: Hash = .{0x55} ** 32;
    const tree_child: Hash = .{0x33} ** 32;
    const exec_child: Hash = .{0x66} ** 32;

    var entries = try arena.alloc(object.TreeEntry, 3);
    // Lex-sorted: "README.md" < "scripts" < "src".
    entries[0] = .{ .name = "README.md", .mode = .blob, .object_hash = blob_child };
    entries[1] = .{ .name = "scripts", .mode = .executable, .object_hash = exec_child };
    entries[2] = .{ .name = "src", .mode = .tree, .object_hash = tree_child };
    const obj = object.Object{ .tree = .{ .entries = entries } };
    return try serialize.serialize(arena, obj);
}

fn buildCommit(arena: Allocator, parent_count: u32) ![]u8 {
    // Stable tree hash so commits are deterministic across vectors.
    const tree_hash: Hash = .{0x77} ** 32;

    var parents = try arena.alloc(Hash, parent_count);
    if (parent_count >= 1) parents[0] = .{0xA0} ** 32;
    if (parent_count >= 2) parents[1] = .{0xB0} ** 32;

    const author = object.Identity{ .kind = .ed25519, .bytes = &PUBKEY_A };
    const message: []const u8 = switch (parent_count) {
        0 => "genesis",
        1 => "second",
        2 => "merge",
        else => "commit",
    };

    const obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = SIGNER,
        .message = message,
        .timestamp = FIXED_TIMESTAMP + parent_count,
        .signature = SIGNATURE,
    } };
    return try serialize.serialize(arena, obj);
}

fn buildRemix(arena: Allocator) ![]u8 {
    const tree_hash: Hash = .{0x77} ** 32;
    const parents = try arena.alloc(Hash, 0);

    // Two sources sorted by (upstream_id, commit_hash).
    var sources = try arena.alloc(object.RemixSource, 2);
    sources[0] = .{
        .upstream_id = .{0x10} ** 32,
        .commit_hash = .{0x30} ** 32,
    };
    sources[1] = .{
        .upstream_id = .{0x20} ** 32,
        .commit_hash = .{0x40} ** 32,
    };

    const author = object.Identity{ .kind = .ed25519, .bytes = &PUBKEY_B };
    const obj = object.Object{ .remix = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .sources = sources,
        .author = author,
        .signer = SIGNER,
        .message = "remix two",
        .timestamp = FIXED_TIMESTAMP + 10,
        .signature = SIGNATURE,
    } };
    return try serialize.serialize(arena, obj);
}

// Build the canonical signing bytes for the commit_0parent vector. This
// must use the *exact same* inputs as buildCommit(arena, 0) so the Rust
// port can deserialize commit_0parent.bin and re-derive identical bytes.
fn buildCommitSigningBytes(arena: Allocator, parent_count: u32) ![]u8 {
    const tree_hash: Hash = .{0x77} ** 32;
    var parents = try arena.alloc(Hash, parent_count);
    if (parent_count >= 1) parents[0] = .{0xA0} ** 32;
    if (parent_count >= 2) parents[1] = .{0xB0} ** 32;
    const author = object.Identity{ .kind = .ed25519, .bytes = &PUBKEY_A };
    const message: []const u8 = switch (parent_count) {
        0 => "genesis",
        1 => "second",
        2 => "merge",
        else => "commit",
    };
    const c = object.Commit{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author,
        .signer = SIGNER,
        .message = message,
        .timestamp = FIXED_TIMESTAMP + parent_count,
        .signature = SIGNATURE,
    };
    return try sign.commitSigningBytes(arena, c);
}

// Build the canonical signing bytes for the remix_2sources vector. Must
// match buildRemix above field-for-field.
fn buildRemixSigningBytes(arena: Allocator) ![]u8 {
    const tree_hash: Hash = .{0x77} ** 32;
    const parents = try arena.alloc(Hash, 0);

    var sources = try arena.alloc(object.RemixSource, 2);
    sources[0] = .{
        .upstream_id = .{0x10} ** 32,
        .commit_hash = .{0x30} ** 32,
    };
    sources[1] = .{
        .upstream_id = .{0x20} ** 32,
        .commit_hash = .{0x40} ** 32,
    };

    const author = object.Identity{ .kind = .ed25519, .bytes = &PUBKEY_B };
    const r = object.Remix{
        .tree_hash = tree_hash,
        .parents = parents,
        .sources = sources,
        .author = author,
        .signer = SIGNER,
        .message = "remix two",
        .timestamp = FIXED_TIMESTAMP + 10,
        .signature = SIGNATURE,
    };
    return try sign.remixSigningBytes(arena, r);
}

fn buildChunkedBlob(arena: Allocator) ![]u8 {
    var chunks = try arena.alloc(Hash, 4);
    chunks[0] = .{0x01} ** 32;
    chunks[1] = .{0x02} ** 32;
    chunks[2] = .{0x03} ** 32;
    chunks[3] = .{0x04} ** 32;
    const obj = object.Object{ .chunked_blob = .{
        .total_size = 4 * 65536,
        .chunk_size = 65536,
        .chunks = chunks,
    } };
    return try serialize.serialize(arena, obj);
}

fn buildChunkedBlobCs0(arena: Allocator) ![]u8 {
    // Per SPEC-OBJECTS §13.7 — chunk_size=0 (CDC marker) with 3 chunks.
    // Length must equal 6 (prologue) + 8 + 4 + 4 + 32*3 = 118 bytes.
    var chunks = try arena.alloc(Hash, 3);
    chunks[0] = .{0xA1} ** 32;
    chunks[1] = .{0xA2} ** 32;
    chunks[2] = .{0xA3} ** 32;
    const obj = object.Object{ .chunked_blob = .{
        .total_size = 1_000_000,
        .chunk_size = 0,
        .chunks = chunks,
    } };
    return try serialize.serialize(arena, obj);
}

fn buildRemixIdenticalUpstream(arena: Allocator) ![]u8 {
    // Per SPEC-OBJECTS §13.6 — two sources sharing upstream_id but with
    // distinct commit_hash, sorted ascending by the secondary key.
    const tree_hash: Hash = .{0x77} ** 32;
    const parents = try arena.alloc(Hash, 0);
    var sources = try arena.alloc(object.RemixSource, 2);
    sources[0] = .{
        .upstream_id = .{0x10} ** 32,
        .commit_hash = .{0x30} ** 32,
    };
    sources[1] = .{
        .upstream_id = .{0x10} ** 32,
        .commit_hash = .{0x31} ** 32,
    };
    const author = object.Identity{ .kind = .ed25519, .bytes = &PUBKEY_B };
    const obj = object.Object{ .remix = .{
        .tree_hash = tree_hash,
        .parents = parents,
        .sources = sources,
        .author = author,
        .signer = SIGNER,
        .message = "remix same upstream",
        .timestamp = FIXED_TIMESTAMP + 11,
        .signature = SIGNATURE,
    } };
    return try serialize.serialize(arena, obj);
}

// ------------------------------------------------------------------------
// Phase 8 — attestation vectors (JCS-canonical bytes for cross-impl tests)
// ------------------------------------------------------------------------

// Fixed commit hash 0xCC*32; matches the "commit"-named subject. Predicate
// is intentionally tiny ({}) so the byte sequence is short and easy to
// inspect by hand. Producers using different predicates round-trip via
// the encoder; the cross-impl invariant is "same inputs → same bytes".
const ATTEST_COMMIT_HASH: [32]u8 = .{0xCC} ** 32;
const ATTEST_PREDICATE_TYPE = "https://example.com/predicate/v1";
const ATTEST_PREDICATE_JCS = "{}";
// Fixed Ed25519 seed used to sign envelope_basic. Matches the
// `verify::tests::deterministic_repo_key_roundtrip` style — fully
// reproducible across runs and across implementations.
const ATTEST_ED25519_SEED: [32]u8 = .{0xAB} ** 32;
// ATTEST_KEYID is derived at runtime in buildEnvelopeBasic via
// attestKeyid() — no hardcoded constant.

fn buildStatementBasic(arena: Allocator) ![]u8 {
    const hex = hash_mod.toHex(ATTEST_COMMIT_HASH);
    const subjects = [_]attestations.Subject{.{
        .name = "commit",
        .digest_blake3_hex = hex[0..],
    }};
    return try attestations.statement.encode(arena, .{
        .subjects = subjects[0..],
        .predicate_type = ATTEST_PREDICATE_TYPE,
        .predicate_jcs = ATTEST_PREDICATE_JCS,
    });
}

/// Derive "blake3:<hex64>" keyid from a 32-byte Ed25519 seed.
/// The keyid is BLAKE3(pubkey) where pubkey is derived deterministically
/// from the seed via Ed25519 key generation. Result is written into `buf`
/// and the full 71-byte slice is returned (borrowed from `buf`).
fn attestKeyid(seed: [32]u8, buf: *[71]u8) ![]const u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pubkey = kp.public_key.toBytes();
    const digest = hash_mod.hash(&pubkey);
    const hex = std.fmt.bytesToHex(digest, .lower);
    @memcpy(buf[0..7], "blake3:");
    @memcpy(buf[7..71], &hex);
    return buf[0..71];
}

fn buildEnvelopeBasic(arena: Allocator) ![]u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(ATTEST_ED25519_SEED);

    // Derive keyid from the actual pubkey so the golden pins the real
    // derivation path rather than a placeholder constant.
    var keyid_buf: [71]u8 = undefined;
    const keyid = try attestKeyid(ATTEST_ED25519_SEED, &keyid_buf);

    const stmt_bytes = try buildStatementBasic(arena);
    defer arena.free(stmt_bytes);

    const pae_bytes = try attestations.envelope.pae(
        arena,
        attestations.PAYLOAD_TYPE_IN_TOTO,
        stmt_bytes,
    );
    defer arena.free(pae_bytes);

    const sig = try kp.sign(pae_bytes, null);
    const sig_bytes = sig.toBytes();

    return try attestations.envelope.encode(arena, .{
        .payload_type = attestations.PAYLOAD_TYPE_IN_TOTO,
        .payload = stmt_bytes,
        .signatures = &.{.{ .keyid = keyid, .sig = sig_bytes[0..] }},
    });
}

// Phase 3 — FastCDC vector builders. These mirror the v1 frozen
// parameters in `docs/SPEC-FASTCDC.md` and produce inputs the Rust
// port (rust/crates/mkit-core/src/chunker.rs) consumes byte-identically.

/// Deterministic 1 MiB pseudo-random buffer driven by splitmix64 with a
/// fixed seed. Linear `i*31+7 mod 256` doesn't excite the gear-hash mask
/// (the high bits never change), so we use a real splitmix to generate
/// boundary-rich input. No env reads, no time reads — fully reproducible.
fn fastcdcInput1Mib(arena: Allocator) ![]u8 {
    const total: usize = 1024 * 1024;
    const buf = try arena.alloc(u8, total);
    var state: u64 = 0xA5A5_F00D_DEAD_BEEF;
    var i: usize = 0;
    while (i < total) : (i += 8) {
        state +%= 0x9e3779b97f4a7c15;
        var z = state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        z = z ^ (z >> 31);
        const end = @min(i + 8, total);
        const bytes = std.mem.toBytes(z);
        for (i..end) |j| buf[j] = bytes[j - i];
    }
    return buf;
}

/// Emit chunk-end offsets as JSON: `[N1, N2, ..., Nk]` with `Nk = total`.
/// Caller frees.
fn buildFastcdcBoundariesJson(arena: Allocator) ![]u8 {
    const data = try fastcdcInput1Mib(arena);
    defer arena.free(data);

    const cdc = fastcdc.FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    var boundaries: std.ArrayList(usize) = .empty;
    defer boundaries.deinit(arena);
    var offset: usize = 0;
    while (offset < data.len) {
        const len = cdc.cut(data[offset..]);
        offset += len;
        try boundaries.append(arena, offset);
    }

    var json: std.ArrayList(u8) = .empty;
    errdefer json.deinit(arena);
    try json.append(arena, '[');
    for (boundaries.items, 0..) |b, idx| {
        if (idx > 0) try json.appendSlice(arena, ", ");
        var nbuf: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&nbuf, "{d}", .{b}) catch unreachable;
        try json.appendSlice(arena, s);
    }
    try json.append(arena, ']');
    try json.append(arena, '\n');
    return try json.toOwnedSlice(arena);
}

/// Smaller deterministic input for a second boundary vector — 256 KiB
/// of splitmix64 bytes from a different seed.
fn fastcdcInput256kRepeating(arena: Allocator) ![]u8 {
    const total: usize = 256 * 1024;
    const buf = try arena.alloc(u8, total);
    var state: u64 = 0xCAFE_BABE_1234_5678;
    var i: usize = 0;
    while (i < total) : (i += 8) {
        state +%= 0x9e3779b97f4a7c15;
        var z = state;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        z = z ^ (z >> 31);
        const end = @min(i + 8, total);
        const bytes = std.mem.toBytes(z);
        for (i..end) |j| buf[j] = bytes[j - i];
    }
    return buf;
}

fn buildFastcdcBoundariesSmallJson(arena: Allocator) ![]u8 {
    const data = try fastcdcInput256kRepeating(arena);
    defer arena.free(data);
    const cdc = fastcdc.FastCDC.init(16 * 1024, 64 * 1024, 256 * 1024);
    var boundaries: std.ArrayList(usize) = .empty;
    defer boundaries.deinit(arena);
    var offset: usize = 0;
    while (offset < data.len) {
        const len = cdc.cut(data[offset..]);
        offset += len;
        try boundaries.append(arena, offset);
    }
    var json: std.ArrayList(u8) = .empty;
    errdefer json.deinit(arena);
    try json.append(arena, '[');
    for (boundaries.items, 0..) |b, idx| {
        if (idx > 0) try json.appendSlice(arena, ", ");
        var nbuf: [24]u8 = undefined;
        const s = std.fmt.bufPrint(&nbuf, "{d}", .{b}) catch unreachable;
        try json.appendSlice(arena, s);
    }
    try json.append(arena, ']');
    try json.append(arena, '\n');
    return try json.toOwnedSlice(arena);
}

// ------------------------------------------------------------------------
// Phase 7d: S3 SigV4 golden. Emits a JSON blob carrying
// `canonical_request`, `string_to_sign`, and `signature_hex` so the
// Rust SigV4 signer can assert byte-identical output against Zig's
// `src/s3.zig`. All inputs are fixed constants — re-running produces
// identical bytes.
// ------------------------------------------------------------------------
fn buildSigv4Basic(arena: Allocator) ![]u8 {
    const config = s3_auth.S3Config{
        .endpoint = "https://abc123.r2.cloudflarestorage.com",
        .bucket = "mkit-storage",
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "auto",
    };
    const method = "PUT";
    const path = "/mkit-storage/packs/0101010101010101010101010101010101010101010101010101010101010101";
    const query = "";
    const payload = "mkit-sigv4-golden-payload";
    const timestamp: i64 = 1_711_300_000; // 2024-03-24T17:06:40Z

    // Re-derive the canonical request / string-to-sign here so we can
    // emit them alongside the final signature — the public signer only
    // returns the Authorization header.
    const payload_hash = s3_auth.sha256Hex(payload);
    const date = s3_auth.formatDate(timestamp);
    const datetime = s3_auth.formatIso8601(timestamp);
    const host = "abc123.r2.cloudflarestorage.com";
    const signed_headers = "host;x-amz-content-sha256;x-amz-date";

    const canonical_request = try std.fmt.allocPrint(arena,
        \\{s}
        \\{s}
        \\{s}
        \\host:{s}
        \\x-amz-content-sha256:{s}
        \\x-amz-date:{s}
        \\
        \\{s}
        \\{s}
    , .{
        method,
        path,
        query,
        host,
        &payload_hash,
        &datetime,
        signed_headers,
        &payload_hash,
    });
    defer arena.free(canonical_request);

    const canonical_hash = s3_auth.sha256Hex(canonical_request);
    const scope = try std.fmt.allocPrint(arena, "{s}/{s}/s3/aws4_request", .{ &date, config.region });
    defer arena.free(scope);
    const string_to_sign = try std.fmt.allocPrint(arena,
        \\AWS4-HMAC-SHA256
        \\{s}
        \\{s}
        \\{s}
    , .{
        &datetime,
        scope,
        &canonical_hash,
    });
    defer arena.free(string_to_sign);

    const signing_key = s3_auth.deriveSigningKey(config.secret_access_key, &date, config.region);
    const signature_bytes = s3_auth.hmacSha256(&signing_key, string_to_sign);
    const signature_hex = std.fmt.bytesToHex(signature_bytes, .lower);

    // JSON-escape canonical_request + string_to_sign so Rust's serde can
    // round-trip the exact bytes. All we need to escape is LF, quote,
    // and backslash — no other control chars appear in SigV4 inputs.
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(arena);

    try out.appendSlice(arena, "{\n  \"method\": \"");
    try out.appendSlice(arena, method);
    try out.appendSlice(arena, "\",\n  \"path\": \"");
    try out.appendSlice(arena, path);
    try out.appendSlice(arena, "\",\n  \"query\": \"");
    try out.appendSlice(arena, query);
    try out.appendSlice(arena, "\",\n  \"payload\": \"");
    try out.appendSlice(arena, payload);
    try out.appendSlice(arena, "\",\n  \"endpoint\": \"");
    try out.appendSlice(arena, config.endpoint);
    try out.appendSlice(arena, "\",\n  \"region\": \"");
    try out.appendSlice(arena, config.region);
    try out.appendSlice(arena, "\",\n  \"access_key_id\": \"");
    try out.appendSlice(arena, config.access_key_id);
    try out.appendSlice(arena, "\",\n  \"secret_access_key\": \"");
    try out.appendSlice(arena, config.secret_access_key);
    try out.appendSlice(arena, "\",\n  \"timestamp\": ");
    var tsbuf: [24]u8 = undefined;
    const tss = std.fmt.bufPrint(&tsbuf, "{d}", .{timestamp}) catch unreachable;
    try out.appendSlice(arena, tss);
    try out.appendSlice(arena, ",\n  \"canonical_request\": \"");
    try appendJsonEscaped(arena, &out, canonical_request);
    try out.appendSlice(arena, "\",\n  \"string_to_sign\": \"");
    try appendJsonEscaped(arena, &out, string_to_sign);
    try out.appendSlice(arena, "\",\n  \"signature_hex\": \"");
    try out.appendSlice(arena, &signature_hex);
    try out.appendSlice(arena, "\"\n}\n");

    return try out.toOwnedSlice(arena);
}

fn appendJsonEscaped(arena: Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '\n' => try out.appendSlice(arena, "\\n"),
            '"' => try out.appendSlice(arena, "\\\""),
            '\\' => try out.appendSlice(arena, "\\\\"),
            else => try out.append(arena, c),
        }
    }
}

// Dispatch: returns bytes for the named vector. Caller frees.
fn buildByName(arena: Allocator, name: []const u8) !?[]u8 {
    if (std.mem.eql(u8, name, "blob")) return try buildBlob(arena);
    if (std.mem.eql(u8, name, "empty_blob")) return try buildEmptyBlob(arena);
    if (std.mem.eql(u8, name, "tree")) return try buildTree(arena);
    if (std.mem.eql(u8, name, "empty_tree")) return try buildEmptyTree(arena);
    if (std.mem.eql(u8, name, "tree_single_file")) return try buildTreeSingleFile(arena);
    if (std.mem.eql(u8, name, "commit_0parent")) return try buildCommit(arena, 0);
    if (std.mem.eql(u8, name, "commit_1parent")) return try buildCommit(arena, 1);
    if (std.mem.eql(u8, name, "commit_2parent")) return try buildCommit(arena, 2);
    if (std.mem.eql(u8, name, "remix_2sources")) return try buildRemix(arena);
    if (std.mem.eql(u8, name, "remix_identical_upstream_distinct_commit"))
        return try buildRemixIdenticalUpstream(arena);
    if (std.mem.eql(u8, name, "commit_0parent_signing_bytes")) return try buildCommitSigningBytes(arena, 0);
    if (std.mem.eql(u8, name, "remix_2sources_signing_bytes")) return try buildRemixSigningBytes(arena);
    if (std.mem.eql(u8, name, "chunked_blob")) return try buildChunkedBlob(arena);
    if (std.mem.eql(u8, name, "chunked_blob_cs0_3chunks")) return try buildChunkedBlobCs0(arena);
    if (std.mem.eql(u8, name, "identity_ed25519")) return try buildIdentityEd25519(arena);
    if (std.mem.eql(u8, name, "identity_opaque")) return try buildIdentityOpaque(arena);
    // Phase 8 attestation vectors (see Phase 8 README).
    if (std.mem.eql(u8, name, "statement_basic")) return try buildStatementBasic(arena);
    if (std.mem.eql(u8, name, "envelope_basic")) return try buildEnvelopeBasic(arena);
    // Phase 3 vectors (additive — keep at the end of the dispatch).
    if (std.mem.eql(u8, name, "fastcdc_boundaries_1mib")) return try buildFastcdcBoundariesJson(arena);
    if (std.mem.eql(u8, name, "fastcdc_boundaries_256k")) return try buildFastcdcBoundariesSmallJson(arena);
    // Phase 7d vectors (additive — keep at the end of the dispatch).
    if (std.mem.eql(u8, name, "sigv4_basic")) return try buildSigv4Basic(arena);
    return null;
}

// ------------------------------------------------------------------------
// Entry: works under both Zig 0.15.2 (pub fn main()) and Zig 0.16
// (pub fn main(init: std.process.Init.Minimal)). We detect by trying to
// reference the 0.16-only symbol; if absent, comptime selects the
// legacy form.
// ------------------------------------------------------------------------

const has_init_minimal = @hasDecl(std.process, "Init");

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        // No arg: emit usage hint; shell wrapper iterates names.
        const stderr = std.Io.File.stderr();
        const msg = "usage: harvest <vector-name>\n";
        _ = stderr.writeStreamingAll(init.io, msg) catch {};
        return error.MissingArg;
    }
    const vector_name = args[1];
    const bytes = (try buildByName(arena, vector_name)) orelse {
        const stderr = std.Io.File.stderr();
        const msg = "harvest: unknown vector\n";
        _ = stderr.writeStreamingAll(init.io, msg) catch {};
        return error.UnknownVector;
    };
    // Emit raw bytes on stdout, and a "BLAKE3: <hex>" line on stderr
    // so the shell wrapper can record the digest without needing an
    // external hasher (b3sum / python-blake3) to be installed.
    const stdout = std.Io.File.stdout();
    _ = try stdout.writeStreamingAll(init.io, bytes);

    const digest = hash_mod.hash(bytes);
    const hex = std.fmt.bytesToHex(digest, .lower);
    var buf: [8 + 64 + 1]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "BLAKE3: {s}\n", .{&hex}) catch unreachable;
    const stderr = std.Io.File.stderr();
    _ = stderr.writeStreamingAll(init.io, msg) catch {};
}

comptime {
    // Keep the compile-time check so tooling sees we explicitly support
    // the post-0.16 init shape. If a future Zig drops `Init`, we'd need
    // to rewrite main().
    if (!has_init_minimal) @compileError("harvest.zig requires Zig 0.16+ std.process.Init");
}
