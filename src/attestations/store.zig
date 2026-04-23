// SPDX-License-Identifier: MIT OR Apache-2.0
//
// On-disk store for DSSE attestation envelopes.
// See docs/SPEC-ATTESTATIONS.md §3.
//
// Layout (rooted at the mkit directory the caller opens — typically
// `.mkit/`, not the `attestations/` subdir; every function opens
// subdirectories as needed):
//
//     <root-dir>/
//       attestations/
//         <64-hex-commit>/
//           <64-hex-att-id>.dsse
//
// Envelope bytes are written exactly as supplied. SPEC-ATTESTATIONS §3
// line 95 says the on-disk form terminates with a single `\n`, but that
// newline is the *encoder's* responsibility (the canonical JCS output
// has no trailing newline; the encoder in envelope.zig does not emit
// one either). We preserve byte-exact input so that
// `attestationId(bytes)` — the filename — and the file contents agree;
// appending a newline here would mean the file's blake3 no longer
// matches the att-id, breaking the content-addressing invariant.
//
// Durability pattern mirrors src/store.zig and
// src/transport/file.zig (commit 41be906, which introduced the
// containing-directory fsync to close the crash-durability gap after
// rename(2)):
//
//     createFileAtomic → writeAll → flush → file.sync → Atomic.replace
//     → fsync the commit directory (via libc fsync on dir.handle)
//
// `std.Io.Dir` in Zig 0.16 has no `sync` method, but `dir.handle` is
// the raw POSIX fd and `std.c.fsync` accepts directory descriptors on
// both Linux and Darwin. mkit links libc unconditionally so this is
// safe without further build changes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;
const protocol = @import("../protocol.zig");
const envelope_mod = @import("envelope.zig");

/// Errors specific to the attestation store.
pub const Error = error{
    NotFound,
};

/// The subdirectory under `root_dir` that owns every envelope on disk.
pub const subdir = "attestations";

/// Envelope file extension. Keep in sync with SPEC-ATTESTATIONS §3.
pub const file_ext = ".dsse";

/// Safety cap on a single envelope read. A well-formed envelope with a
/// few signatures is well under a kilobyte; even an absurd multi-sig
/// case stays in the low tens of kilobytes. 1 MiB is a generous ceiling
/// that still protects against a corrupt or malicious pathname landing
/// a giant file in this tree and starving the reader.
pub const MAX_ENVELOPE_SIZE: usize = 1 * 1024 * 1024;

/// "<64-hex>" — the directory name used for a commit's attestations.
pub fn commitDirName(commit: Hash) [hash_mod.hex_len]u8 {
    return hash_mod.toHex(commit);
}

/// "<64-hex>.dsse" — the filename used for a single envelope.
pub fn attFileName(att_id: Hash) [hash_mod.hex_len + file_ext.len]u8 {
    var out: [hash_mod.hex_len + file_ext.len]u8 = undefined;
    const hex = hash_mod.toHex(att_id);
    @memcpy(out[0..hash_mod.hex_len], &hex);
    @memcpy(out[hash_mod.hex_len..], file_ext);
    return out;
}

/// Write a DSSE envelope for `commit`. Returns the att-id.
///
/// Idempotent via content-addressing: the filename is the BLAKE3 of
/// the bytes, so if the target already exists we return the same id
/// without rewriting.
pub fn writeAttestation(
    _: Allocator,
    io: Io,
    root_dir: Io.Dir,
    commit: Hash,
    envelope_bytes: []const u8,
) !Hash {
    if (envelope_bytes.len > MAX_ENVELOPE_SIZE) return error.ObjectTooLarge;

    const att_id = envelope_mod.attestationId(envelope_bytes);
    const commit_hex = commitDirName(commit);
    const file_name = attFileName(att_id);

    root_dir.createDir(io, subdir, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var att_root = try root_dir.openDir(io, subdir, .{});
    defer att_root.close(io);

    att_root.createDir(io, &commit_hex, .default_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var commit_dir = try att_root.openDir(io, &commit_hex, .{});
    defer commit_dir.close(io);

    // Idempotency via content-addressing: the filename IS the BLAKE3 of
    // the bytes, so presence implies equality. One stat beats a full
    // read+compare.
    commit_dir.access(io, &file_name, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            var atomic_file = try commit_dir.createFileAtomic(io, &file_name, .{ .replace = true });
            defer atomic_file.deinit(io);

            var buffer: [4096]u8 = undefined;
            var file_writer = atomic_file.file.writer(io, &buffer);
            try file_writer.interface.writeAll(envelope_bytes);
            try file_writer.interface.flush();
            try file_writer.file.sync(io);
            try atomic_file.replace(io);

            // fsync the containing directory so rename(2) survives a
            // power loss. Best-effort: tmpfs rejects dir-fd fsync.
            syncDir(commit_dir) catch {};
            return att_id;
        },
        else => return err,
    };
    return att_id;
}

/// Read the envelope for `commit` + `att_id`. Allocator-owned bytes.
pub fn readAttestation(
    allocator: Allocator,
    io: Io,
    root_dir: Io.Dir,
    commit: Hash,
    att_id: Hash,
) ![]u8 {
    const commit_hex = commitDirName(commit);
    const file_name = attFileName(att_id);

    var att_root = root_dir.openDir(io, subdir, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return err,
    };
    defer att_root.close(io);

    var commit_dir = att_root.openDir(io, &commit_hex, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return err,
    };
    defer commit_dir.close(io);

    return commit_dir.readFileAlloc(io, &file_name, allocator, .limited(MAX_ENVELOPE_SIZE)) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return err,
    };
}

/// List every att-id attached to `commit`, sorted ascending
/// byte-wise on the raw 32-byte hash. An unattested commit (no
/// directory) returns an empty slice — NOT an error, per
/// SPEC-ATTESTATIONS §7.1 (a commit with zero and a commit with five
/// attestations are indistinguishable at the commit layer).
pub fn listAttestations(
    allocator: Allocator,
    io: Io,
    root_dir: Io.Dir,
    commit: Hash,
) ![]Hash {
    const commit_hex = commitDirName(commit);

    var att_root = root_dir.openDir(io, subdir, .{}) catch |err| switch (err) {
        error.FileNotFound => return &[_]Hash{},
        else => return err,
    };
    defer att_root.close(io);

    var commit_dir = att_root.openDir(io, &commit_hex, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return &[_]Hash{},
        else => return err,
    };
    defer commit_dir.close(io);

    var ids: std.ArrayList(Hash) = .empty;
    errdefer ids.deinit(allocator);

    var iter = commit_dir.iterate();
    while (try iter.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const id = parseAttFileName(entry.name) orelse continue;
        try ids.append(allocator, id);
    }

    const slice = try ids.toOwnedSlice(allocator);
    std.sort.pdq(Hash, slice, {}, protocol.hashLessThan);
    return slice;
}

/// Remove a single attestation. Idempotent: removing a non-existent
/// att-id (or a commit that has no attestations at all) returns
/// successfully. When the commit directory becomes empty, it is
/// removed as well — tolerating `DirNotEmpty` if a concurrent writer
/// landed a new envelope in the interim.
pub fn removeAttestation(
    io: Io,
    root_dir: Io.Dir,
    commit: Hash,
    att_id: Hash,
) !void {
    const commit_hex = commitDirName(commit);
    const file_name = attFileName(att_id);

    var att_root = root_dir.openDir(io, subdir, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer att_root.close(io);

    {
        var commit_dir = att_root.openDir(io, &commit_hex, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer commit_dir.close(io);

        commit_dir.deleteFile(io, &file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }

    // Attempt to garbage-collect the now-possibly-empty commit dir.
    att_root.deleteDir(io, &commit_hex) catch |err| switch (err) {
        error.DirNotEmpty, error.FileNotFound => {},
        else => return err,
    };
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

const parseAttFileName = protocol.parseAttestationFilename;

/// fsync a directory file descriptor. See the module doc comment for
/// why this is needed and why it uses libc directly.
fn syncDir(dir: Io.Dir) !void {
    if (std.c.fsync(dir.handle) != 0) return error.SyncFailed;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

/// Build a fake `Hash` from a seed byte, so tests don't depend on any
/// particular real commit hash.
fn fakeHash(seed: u8) Hash {
    var h: Hash = undefined;
    for (&h, 0..) |*b, i| b.* = seed +% @as(u8, @intCast(i));
    return h;
}

test "write/read roundtrip" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x11);
    const envelope = "x" ** 50;

    const att_id = try writeAttestation(allocator, io, tmp.dir, commit, envelope);
    try testing.expectEqual(envelope_mod.attestationId(envelope), att_id);

    const got = try readAttestation(allocator, io, tmp.dir, commit, att_id);
    defer allocator.free(got);
    try testing.expectEqualSlices(u8, envelope, got);
}

test "write is idempotent: same bytes produce same id and one file" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x22);
    const envelope = "hello envelope";

    const a = try writeAttestation(allocator, io, tmp.dir, commit, envelope);
    const b = try writeAttestation(allocator, io, tmp.dir, commit, envelope);
    try testing.expectEqual(a, b);

    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 1), ids.len);
    try testing.expectEqual(a, ids[0]);
}

test "list returns att-ids sorted ascending" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x33);

    var envelopes: [5][16]u8 = undefined;
    var written: [5]Hash = undefined;
    for (&envelopes, 0..) |*e, i| {
        @memcpy(e, "envelope-00-tail");
        e.*[9] = '0' + @as(u8, @intCast(i));
        written[i] = try writeAttestation(allocator, io, tmp.dir, commit, e);
    }

    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 5), ids.len);

    // Sorted ascending byte-wise.
    var j: usize = 1;
    while (j < ids.len) : (j += 1) {
        try testing.expect(std.mem.order(u8, &ids[j - 1], &ids[j]) == .lt);
    }

    // Every written id must appear in the result set.
    for (written) |w| {
        var found = false;
        for (ids) |id| {
            if (std.mem.eql(u8, &w, &id)) {
                found = true;
                break;
            }
        }
        try testing.expect(found);
    }
}

test "list on unattested commit returns empty slice, no error" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x44);
    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 0), ids.len);

    // Same result even after another commit's attestations exist.
    const other = fakeHash(0x55);
    _ = try writeAttestation(allocator, io, tmp.dir, other, "some envelope");

    const ids2 = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids2);
    try testing.expectEqual(@as(usize, 0), ids2.len);
}

test "remove is idempotent on missing att-id" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x66);
    const missing = fakeHash(0x77);

    // No attestations dir at all.
    try removeAttestation(io, tmp.dir, commit, missing);

    // attestations dir exists, commit dir doesn't.
    const allocator = testing.allocator;
    const other = fakeHash(0x88);
    _ = try writeAttestation(allocator, io, tmp.dir, other, "keep me");
    try removeAttestation(io, tmp.dir, commit, missing);

    // commit dir exists but the specific att-id doesn't.
    _ = try writeAttestation(allocator, io, tmp.dir, commit, "present");
    try removeAttestation(io, tmp.dir, commit, missing);

    // Nothing we had should have been clobbered.
    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 1), ids.len);
}

test "remove cleans up an empty commit dir" {
    const allocator = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0x99);
    const att_id = try writeAttestation(allocator, io, tmp.dir, commit, "only one");

    try removeAttestation(io, tmp.dir, commit, att_id);

    // list on the now-gone commit dir should be empty and not error.
    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 0), ids.len);

    // The commit dir itself is gone.
    var att_root = try tmp.dir.openDir(io, subdir, .{});
    defer att_root.close(io);
    const commit_hex = commitDirName(commit);
    try testing.expectError(error.FileNotFound, att_root.openDir(io, &commit_hex, .{}));
}

test "list ignores non-.dsse and non-hex-stem files" {
    const allocator = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const commit = fakeHash(0xAA);
    const good_id = try writeAttestation(allocator, io, tmp.dir, commit, "legit envelope");

    // Drop two junk files directly into the commit dir.
    {
        var att_root = try tmp.dir.openDir(io, subdir, .{});
        defer att_root.close(io);
        const commit_hex = commitDirName(commit);
        var commit_dir = try att_root.openDir(io, &commit_hex, .{});
        defer commit_dir.close(io);

        // (a) Wrong extension entirely.
        try commit_dir.writeFile(io, .{ .sub_path = "notes.txt", .data = "ignored" });
        // (b) Right extension, wrong-shaped stem (too short + non-hex char).
        try commit_dir.writeFile(io, .{ .sub_path = "zzz.dsse", .data = "ignored" });
        // (c) Right length, right extension, but non-hex stem ('g' is invalid).
        const bad_hex_stem = "g" ++ ("0" ** 63) ++ ".dsse";
        try commit_dir.writeFile(io, .{ .sub_path = bad_hex_stem, .data = "ignored" });
    }

    const ids = try listAttestations(allocator, io, tmp.dir, commit);
    defer allocator.free(ids);
    try testing.expectEqual(@as(usize, 1), ids.len);
    try testing.expectEqual(good_id, ids[0]);
}

test "attFileName and commitDirName are deterministic hex" {
    const h = fakeHash(0xBB);
    const hex = hash_mod.toHex(h);

    const dir_name = commitDirName(h);
    try testing.expectEqualSlices(u8, &hex, &dir_name);

    const file_name = attFileName(h);
    try testing.expectEqualSlices(u8, &hex, file_name[0..64]);
    try testing.expectEqualStrings(".dsse", file_name[64..]);
}
