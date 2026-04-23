// SPDX-License-Identifier: MIT OR Apache-2.0
//
// in-toto v1 Statement — the payload wrapped by every DSSE envelope mkit
// produces. See docs/SPEC-ATTESTATIONS.md §4.2 and
// https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
//
// Statement shape:
//   {
//     "_type": "https://in-toto.io/Statement/v1",
//     "subject": [ { "name": <optional>, "digest": { "blake3": <hex> } } ],
//     "predicateType": <uri>,
//     "predicate": <arbitrary JSON object>
//   }
//
// mkit never parses `predicate`. Producers hand us a byte slice that is
// ALREADY a JCS-canonical JSON object; we pass it through verbatim inside
// the enclosing Statement's canonicalisation. This keeps mkit predicate-
// type-agnostic (see spec §1.4).

const std = @import("std");
const Allocator = std.mem.Allocator;

const jcs = @import("jcs.zig");
const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;

pub const IN_TOTO_TYPE = "https://in-toto.io/Statement/v1";

/// A single subject entry. `name` is optional (nullable) per the in-toto
/// spec; mkit always emits one subject with `name = "commit"` pointing at
/// the subject commit's BLAKE3 hash.
pub const Subject = struct {
    name: ?[]const u8 = null,
    digest_blake3_hex: []const u8,
};

pub const Statement = struct {
    subjects: []const Subject,
    predicate_type: []const u8,
    /// Predicate body as already-canonicalised JSON bytes (an OBJECT,
    /// starting with `{` and ending with `}`). mkit does not validate the
    /// internal structure — that's the predicate type's schema's job.
    predicate_jcs: []const u8,
};

/// Build a JCS-canonical in-toto Statement.
/// Returns allocator-owned bytes.
pub fn encode(allocator: Allocator, statement: Statement) ![]u8 {
    // We hand-roll the Statement encoding rather than going through
    // `jcs.Value` so we can pass `predicate_jcs` through without
    // round-tripping. Emit in JCS-sorted key order:
    //   _type, predicate, predicateType, subject
    var alloc_w: std.Io.Writer.Allocating = .init(allocator);
    defer alloc_w.deinit();
    const w = &alloc_w.writer;

    try w.writeByte('{');

    // "_type"
    try jcs.write(w, .{ .string = "_type" });
    try w.writeByte(':');
    try jcs.write(w, .{ .string = IN_TOTO_TYPE });
    try w.writeByte(',');

    // "predicate" — verbatim pass-through of caller-provided JCS bytes.
    // We minimally validate it starts with '{' and ends with '}' so we
    // don't break the enclosing Statement's well-formedness.
    if (statement.predicate_jcs.len < 2 or
        statement.predicate_jcs[0] != '{' or
        statement.predicate_jcs[statement.predicate_jcs.len - 1] != '}')
    {
        return error.PredicateMustBeJsonObject;
    }
    try jcs.write(w, .{ .string = "predicate" });
    try w.writeByte(':');
    try w.writeAll(statement.predicate_jcs);
    try w.writeByte(',');

    // "predicateType"
    try jcs.write(w, .{ .string = "predicateType" });
    try w.writeByte(':');
    try jcs.write(w, .{ .string = statement.predicate_type });
    try w.writeByte(',');

    // "subject"
    try jcs.write(w, .{ .string = "subject" });
    try w.writeByte(':');
    try w.writeByte('[');
    for (statement.subjects, 0..) |subj, i| {
        if (i != 0) try w.writeByte(',');
        try w.writeByte('{');
        // Subject keys in JCS order: digest, (name)
        try jcs.write(w, .{ .string = "digest" });
        try w.writeByte(':');
        try jcs.write(w, .{ .object = &.{
            .{ .key = "blake3", .value = .{ .string = subj.digest_blake3_hex } },
        } });
        if (subj.name) |name| {
            try w.writeByte(',');
            try jcs.write(w, .{ .string = "name" });
            try w.writeByte(':');
            try jcs.write(w, .{ .string = name });
        }
        try w.writeByte('}');
    }
    try w.writeByte(']');

    try w.writeByte('}');
    try w.flush();
    return try alloc_w.toOwnedSlice();
}

/// Convenience: build a single-subject Statement from a commit hash +
/// predicate. `name` defaults to "commit".
pub fn forCommit(
    allocator: Allocator,
    commit: Hash,
    predicate_type: []const u8,
    predicate_jcs: []const u8,
) ![]u8 {
    const hex = hash_mod.toHex(commit);
    const subjects = [_]Subject{.{
        .name = "commit",
        .digest_blake3_hex = hex[0..],
    }};
    return encode(allocator, .{
        .subjects = subjects[0..],
        .predicate_type = predicate_type,
        .predicate_jcs = predicate_jcs,
    });
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const testing = std.testing;

test "statement: single subject, empty predicate" {
    const got = try encode(testing.allocator, .{
        .subjects = &.{
            .{ .name = "commit", .digest_blake3_hex = "deadbeef" },
        },
        .predicate_type = "https://example.com/x",
        .predicate_jcs = "{}",
    });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        "{\"_type\":\"https://in-toto.io/Statement/v1\"," ++
            "\"predicate\":{}," ++
            "\"predicateType\":\"https://example.com/x\"," ++
            "\"subject\":[{\"digest\":{\"blake3\":\"deadbeef\"},\"name\":\"commit\"}]}",
        got,
    );
}

test "statement: subject without name emits digest only" {
    const got = try encode(testing.allocator, .{
        .subjects = &.{
            .{ .digest_blake3_hex = "abcd" },
        },
        .predicate_type = "https://example.com/x",
        .predicate_jcs = "{}",
    });
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        "{\"_type\":\"https://in-toto.io/Statement/v1\"," ++
            "\"predicate\":{}," ++
            "\"predicateType\":\"https://example.com/x\"," ++
            "\"subject\":[{\"digest\":{\"blake3\":\"abcd\"}}]}",
        got,
    );
}

test "statement: predicate body passes through verbatim" {
    const predicate = "{\"buildType\":\"https://ex.com/b\",\"stepCount\":7}";
    const got = try encode(testing.allocator, .{
        .subjects = &.{
            .{ .name = "commit", .digest_blake3_hex = "00" },
        },
        .predicate_type = "https://slsa.dev/provenance/v1",
        .predicate_jcs = predicate,
    });
    defer testing.allocator.free(got);
    try testing.expect(std.mem.indexOf(u8, got, predicate) != null);
}

test "statement: rejects predicate that isn't a JSON object" {
    try testing.expectError(
        error.PredicateMustBeJsonObject,
        encode(testing.allocator, .{
            .subjects = &.{.{ .digest_blake3_hex = "00" }},
            .predicate_type = "x",
            .predicate_jcs = "[1,2,3]",
        }),
    );
    try testing.expectError(
        error.PredicateMustBeJsonObject,
        encode(testing.allocator, .{
            .subjects = &.{.{ .digest_blake3_hex = "00" }},
            .predicate_type = "x",
            .predicate_jcs = "",
        }),
    );
}

test "statement: forCommit helper" {
    const commit: Hash = .{0xAB} ** 32;
    const got = try forCommit(
        testing.allocator,
        commit,
        "https://example.com/predicate/v1",
        "{\"x\":1}",
    );
    defer testing.allocator.free(got);
    try testing.expect(std.mem.indexOf(u8, got, "abababababababababababababababababababababababababababababababab") != null);
    try testing.expect(std.mem.indexOf(u8, got, "\"x\":1") != null);
}
