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
const ATTEST_KEYID = "blake3:00000000000000000000000000000000000000000000000000000000000000aa";

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

fn buildEnvelopeBasic(arena: Allocator) ![]u8 {
    const Ed25519 = std.crypto.sign.Ed25519;
    const kp = try Ed25519.KeyPair.generateDeterministic(ATTEST_ED25519_SEED);

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
        .signatures = &.{.{ .keyid = ATTEST_KEYID, .sig = sig_bytes[0..] }},
    });
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
