// SPDX-License-Identifier: MIT OR Apache-2.0
//
// JCS — JSON Canonicalisation Scheme (RFC 8785) writer restricted to the
// subset mkit attestations actually need:
//
//   * strings  (UTF-8, short-form escapes per RFC 8259 §7)
//   * integers (u64; no floating point, no bignum)
//   * booleans
//   * null
//   * arrays
//   * objects with lexicographically-sorted keys (UCS-2 code units per
//     RFC 8785 §3.2.3 — equivalent to sorting UTF-8 bytes because JSON
//     keys are always ASCII in our schemas; we assert-check this)
//
// Not supported (by design, not a TODO):
//   * floats / non-integer numbers — JSON's number grammar + IEEE-754
//     round-tripping is the hardest part of JCS and we never emit one.
//   * object keys with non-ASCII characters — in-toto v1 + DSSE both
//     use ASCII keys, and the UCS-2 codepoint sort rule would require
//     a real UTF-16 ordering table for non-ASCII keys.
//
// The writer emits directly into an `std.Io.Writer` so callers control
// allocation. Call sites want a contiguous `[]u8`; `encode` is the
// convenience wrapper that buffers via `std.Io.Writer.Allocating`.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A single JSON value in the subset we handle.
pub const Value = union(enum) {
    null_value,
    bool_value: bool,
    /// Unsigned integer. Signed ints are rejected at the Value level — if
    /// you need negatives, widen the union before us.
    uint_value: u64,
    string: []const u8,
    array: []const Value,
    /// Object members. MUST be pre-sorted by `key` ascending (byte-wise),
    /// no duplicates. We assert both in debug.
    object: []const Member,
};

pub const Member = struct {
    key: []const u8,
    value: Value,
};

/// Write `value` to `writer` in JCS-canonical form.
pub fn write(writer: *std.Io.Writer, value: Value) !void {
    switch (value) {
        .null_value => try writer.writeAll("null"),
        .bool_value => |b| try writer.writeAll(if (b) "true" else "false"),
        .uint_value => |n| try writer.print("{d}", .{n}),
        .string => |s| try writeString(writer, s),
        .array => |items| {
            try writer.writeByte('[');
            for (items, 0..) |item, i| {
                if (i != 0) try writer.writeByte(',');
                try write(writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |members| {
            assertSortedAsciiKeys(members);
            try writer.writeByte('{');
            for (members, 0..) |member, i| {
                if (i != 0) try writer.writeByte(',');
                try writeString(writer, member.key);
                try writer.writeByte(':');
                try write(writer, member.value);
            }
            try writer.writeByte('}');
        },
    }
}

/// Wrap `write` with an allocating writer; caller owns the returned slice.
pub fn encode(allocator: Allocator, value: Value) ![]u8 {
    var alloc_w: std.Io.Writer.Allocating = .init(allocator);
    defer alloc_w.deinit();
    try write(&alloc_w.writer, value);
    try alloc_w.writer.flush();
    return try alloc_w.toOwnedSlice();
}

fn assertSortedAsciiKeys(members: []const Member) void {
    if (members.len <= 1) return;
    var prev = members[0].key;
    assertAscii(prev);
    var i: usize = 1;
    while (i < members.len) : (i += 1) {
        const cur = members[i].key;
        assertAscii(cur);
        std.debug.assert(std.mem.order(u8, prev, cur) == .lt);
        prev = cur;
    }
}

fn assertAscii(s: []const u8) void {
    for (s) |c| std.debug.assert(c < 0x80);
}

/// JSON string serialisation per RFC 8785 §3.2.3:
///   * Short-form escape for \" \\ \b \f \n \r \t
///   * \uXXXX (lowercase hex) for every other control character < 0x20
///   * Everything else emitted verbatim as UTF-8.
/// We do NOT escape forward slash (optional per RFC 8259; JCS says don't).
/// We do NOT escape non-ASCII Unicode (JCS §3.2.3 rule 3).
fn writeString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x00...0x07, 0x0B, 0x0E...0x1F => try writer.print("\\u{x:0>4}", .{c}),
            else => try writer.writeByte(c),
        }
    }
    try writer.writeByte('"');
}

// -----------------------------------------------------------------------------
// Tests — drawn from RFC 8785 test vectors and DSSE conformance tests.
// -----------------------------------------------------------------------------

const testing = std.testing;

fn expectEncoded(expected: []const u8, value: Value) !void {
    const got = try encode(testing.allocator, value);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

test "jcs: primitives" {
    try expectEncoded("null", .null_value);
    try expectEncoded("true", .{ .bool_value = true });
    try expectEncoded("false", .{ .bool_value = false });
    try expectEncoded("0", .{ .uint_value = 0 });
    try expectEncoded("42", .{ .uint_value = 42 });
    try expectEncoded("18446744073709551615", .{ .uint_value = std.math.maxInt(u64) });
}

test "jcs: simple strings are emitted verbatim" {
    try expectEncoded("\"\"", .{ .string = "" });
    try expectEncoded("\"hello\"", .{ .string = "hello" });
    try expectEncoded("\"a/b\"", .{ .string = "a/b" });
}

test "jcs: short-form escapes for control / special chars" {
    try expectEncoded("\"\\\"\"", .{ .string = "\"" });
    try expectEncoded("\"\\\\\"", .{ .string = "\\" });
    try expectEncoded("\"\\n\"", .{ .string = "\n" });
    try expectEncoded("\"\\r\"", .{ .string = "\r" });
    try expectEncoded("\"\\t\"", .{ .string = "\t" });
    try expectEncoded("\"\\b\"", .{ .string = "\x08" });
    try expectEncoded("\"\\f\"", .{ .string = "\x0C" });
}

test "jcs: \\uXXXX for remaining control chars" {
    try expectEncoded("\"\\u0000\"", .{ .string = "\x00" });
    try expectEncoded("\"\\u0001\"", .{ .string = "\x01" });
    try expectEncoded("\"\\u001f\"", .{ .string = "\x1f" });
    try expectEncoded("\"\\u000e\"", .{ .string = "\x0e" });
}

test "jcs: utf-8 passes through unescaped" {
    // JCS §3.2.3 rule 3: non-ASCII is NOT escaped.
    try expectEncoded("\"café\"", .{ .string = "café" });
    try expectEncoded("\"日本語\"", .{ .string = "日本語" });
    try expectEncoded("\"🔒\"", .{ .string = "🔒" });
}

test "jcs: arrays" {
    try expectEncoded("[]", .{ .array = &.{} });
    try expectEncoded(
        "[1,2,3]",
        .{ .array = &.{
            .{ .uint_value = 1 },
            .{ .uint_value = 2 },
            .{ .uint_value = 3 },
        } },
    );
    try expectEncoded(
        "[\"a\",null,true]",
        .{ .array = &.{
            .{ .string = "a" },
            .null_value,
            .{ .bool_value = true },
        } },
    );
}

test "jcs: objects emit pre-sorted keys verbatim" {
    try expectEncoded("{}", .{ .object = &.{} });
    try expectEncoded(
        "{\"a\":1}",
        .{ .object = &.{
            .{ .key = "a", .value = .{ .uint_value = 1 } },
        } },
    );
    try expectEncoded(
        "{\"a\":1,\"b\":2}",
        .{ .object = &.{
            .{ .key = "a", .value = .{ .uint_value = 1 } },
            .{ .key = "b", .value = .{ .uint_value = 2 } },
        } },
    );
}

test "jcs: nested object with predicate-like shape" {
    const nested: Value = .{ .object = &.{
        .{ .key = "_type", .value = .{ .string = "https://in-toto.io/Statement/v1" } },
        .{ .key = "predicate", .value = .{ .object = &.{
            .{ .key = "buildType", .value = .{ .string = "https://example.com/t" } },
            .{ .key = "stepCount", .value = .{ .uint_value = 3 } },
        } } },
        .{ .key = "predicateType", .value = .{ .string = "https://slsa.dev/provenance/v1" } },
        .{ .key = "subject", .value = .{ .array = &.{
            .{ .object = &.{
                .{ .key = "digest", .value = .{ .object = &.{
                    .{ .key = "blake3", .value = .{ .string = "deadbeef" } },
                } } },
                .{ .key = "name", .value = .{ .string = "commit" } },
            } },
        } } },
    } };
    const got = try encode(testing.allocator, nested);
    defer testing.allocator.free(got);
    // Exact byte sequence — this is the contract.
    try testing.expectEqualStrings(
        "{\"_type\":\"https://in-toto.io/Statement/v1\"," ++
            "\"predicate\":{\"buildType\":\"https://example.com/t\",\"stepCount\":3}," ++
            "\"predicateType\":\"https://slsa.dev/provenance/v1\"," ++
            "\"subject\":[{\"digest\":{\"blake3\":\"deadbeef\"},\"name\":\"commit\"}]}",
        got,
    );
}
