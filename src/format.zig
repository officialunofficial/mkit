// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const object = @import("object.zig");
const hash_mod = @import("hash.zig");

const Allocator = std.mem.Allocator;
const Buffer = std.ArrayList(u8);

/// Format an object to a byte buffer. Caller owns returned slice.
pub fn formatObject(allocator: Allocator, obj: object.Object, obj_hash: hash_mod.Hash) ![]u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);

    switch (obj) {
        .blob => |b| try formatBlob(&buf, allocator, b),
        .tree => |t| try formatTree(&buf, allocator, t),
        .commit => |c| try formatCommit(&buf, allocator, c, obj_hash),
        .remix => |r| try formatRemix(&buf, allocator, r, obj_hash),
        .chunked_blob => |cb| try formatChunkedBlob(&buf, allocator, cb, obj_hash),
        .delta => |d| try formatDelta(&buf, allocator, d),
    }

    return buf.toOwnedSlice(allocator);
}

/// Write formatted object to a file.
pub fn printObject(file: std.fs.File, allocator: Allocator, obj: object.Object, obj_hash: hash_mod.Hash) !void {
    const formatted = try formatObject(allocator, obj, obj_hash);
    defer allocator.free(formatted);
    try file.writeStreamingAll(std.testing.io, formatted);
}

fn formatBlob(buf: *Buffer, allocator: Allocator, b: object.Blob) !void {
    try buf.appendSlice(allocator, b.data);
}

/// Write a single `author ...` line describing the Identity. The exact
/// shape is intentionally human-readable, not round-trippable — callers
/// that need the raw bytes should go through serialize.zig.
fn writeAuthor(buf: *Buffer, allocator: Allocator, id: object.Identity) !void {
    try buf.appendSlice(allocator, "author ");
    switch (id.kind) {
        .ed25519 => {
            try buf.appendSlice(allocator, "ed25519:");
            try writeHexTruncated(buf, allocator, id.bytes, 16);
        },
        .did_key => {
            try buf.appendSlice(allocator, "did:key:");
            try buf.appendSlice(allocator, id.bytes);
        },
        .@"opaque" => {
            // Preserve the "mid N" rendering when the opaque payload is an
            // 8-byte little-endian integer (the u64 LE counter convention).
            // For anything else, dump a hex prefix.
            if (id.bytes.len == 8) {
                const mid = std.mem.readInt(u64, id.bytes[0..8], .little);
                var mid_buf: [24]u8 = undefined;
                const mid_str = std.fmt.bufPrint(&mid_buf, "mid {d}", .{mid}) catch "mid ?";
                try buf.appendSlice(allocator, mid_str);
            } else {
                try buf.appendSlice(allocator, "opaque:");
                try writeHexTruncated(buf, allocator, id.bytes, 16);
            }
        },
    }
    try buf.appendSlice(allocator, "\n");
}

fn writeHexTruncated(buf: *Buffer, allocator: Allocator, bytes: []const u8, max_chars: usize) !void {
    const hex_alphabet = "0123456789abcdef";
    const limit = @min(bytes.len, max_chars / 2);
    var tmp: [128]u8 = undefined;
    var i: usize = 0;
    for (bytes[0..limit]) |b| {
        tmp[i] = hex_alphabet[b >> 4];
        tmp[i + 1] = hex_alphabet[b & 0x0F];
        i += 2;
    }
    try buf.appendSlice(allocator, tmp[0..i]);
    if (bytes.len > limit) try buf.appendSlice(allocator, "..");
}

fn formatTree(buf: *Buffer, allocator: Allocator, t: object.Tree) !void {
    for (t.entries) |entry| {
        const hex = hash_mod.toHex(entry.object_hash);
        try buf.appendSlice(allocator, entry.mode.name());
        try buf.appendSlice(allocator, " ");
        try buf.appendSlice(allocator, &hex);
        try buf.appendSlice(allocator, "    ");
        try buf.appendSlice(allocator, entry.name);
        try buf.appendSlice(allocator, "\n");
    }
}

fn formatCommit(buf: *Buffer, allocator: Allocator, c: object.Commit, obj_hash: hash_mod.Hash) !void {
    const commit_hex = hash_mod.toHex(obj_hash);
    try buf.appendSlice(allocator, "commit ");
    try buf.appendSlice(allocator, &commit_hex);
    try buf.appendSlice(allocator, "\n");

    const tree_hex = hash_mod.toHex(c.tree_hash);
    try buf.appendSlice(allocator, "tree   ");
    try buf.appendSlice(allocator, &tree_hex);
    try buf.appendSlice(allocator, "\n");

    for (c.parents) |p| {
        const parent_hex = hash_mod.toHex(p);
        try buf.appendSlice(allocator, "parent ");
        try buf.appendSlice(allocator, &parent_hex);
        try buf.appendSlice(allocator, "\n");
    }

    try writeAuthor(buf, allocator, c.author);

    const signer_hex = hash_mod.toHex(c.signer);
    try buf.appendSlice(allocator, "signer ");
    try buf.appendSlice(allocator, &signer_hex);
    try buf.appendSlice(allocator, "\n");

    var ts_buf: [24]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{c.timestamp}) catch "?";
    try buf.appendSlice(allocator, "time   ");
    try buf.appendSlice(allocator, ts_str);
    try buf.appendSlice(allocator, "\n");

    // Show message_hash and content_digest if non-zero
    if (!std.mem.eql(u8, &c.message_hash, &hash_mod.zero)) {
        const mh_hex = hash_mod.toHex(c.message_hash);
        try buf.appendSlice(allocator, "mhash  ");
        try buf.appendSlice(allocator, &mh_hex);
        try buf.appendSlice(allocator, "\n");
    }
    if (!std.mem.eql(u8, &c.content_digest, &hash_mod.zero)) {
        const cd_hex = hash_mod.toHex(c.content_digest);
        try buf.appendSlice(allocator, "digest ");
        try buf.appendSlice(allocator, &cd_hex);
        try buf.appendSlice(allocator, "\n");
    }

    try buf.appendSlice(allocator, "\n");
    try buf.appendSlice(allocator, c.message);
    try buf.appendSlice(allocator, "\n");
}

fn formatRemix(buf: *Buffer, allocator: Allocator, r: object.Remix, obj_hash: hash_mod.Hash) !void {
    const remix_hex = hash_mod.toHex(obj_hash);
    try buf.appendSlice(allocator, "remix  ");
    try buf.appendSlice(allocator, &remix_hex);
    try buf.appendSlice(allocator, "\n");

    const tree_hex = hash_mod.toHex(r.tree_hash);
    try buf.appendSlice(allocator, "tree   ");
    try buf.appendSlice(allocator, &tree_hex);
    try buf.appendSlice(allocator, "\n");

    for (r.parents) |p| {
        const parent_hex = hash_mod.toHex(p);
        try buf.appendSlice(allocator, "parent ");
        try buf.appendSlice(allocator, &parent_hex);
        try buf.appendSlice(allocator, "\n");
    }

    for (r.sources) |s| {
        const proj_hex = hash_mod.toHex(s.upstream_id);
        const commit_hex = hash_mod.toHex(s.commit_hash);
        try buf.appendSlice(allocator, "source ");
        try buf.appendSlice(allocator, &proj_hex);
        try buf.appendSlice(allocator, " ");
        try buf.appendSlice(allocator, &commit_hex);
        try buf.appendSlice(allocator, "\n");
    }

    try writeAuthor(buf, allocator, r.author);

    const signer_hex = hash_mod.toHex(r.signer);
    try buf.appendSlice(allocator, "signer ");
    try buf.appendSlice(allocator, &signer_hex);
    try buf.appendSlice(allocator, "\n");

    var ts_buf: [24]u8 = undefined;
    const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{r.timestamp}) catch "?";
    try buf.appendSlice(allocator, "time   ");
    try buf.appendSlice(allocator, ts_str);
    try buf.appendSlice(allocator, "\n");

    try buf.appendSlice(allocator, "\n");
    try buf.appendSlice(allocator, r.message);
    try buf.appendSlice(allocator, "\n");
}

fn formatChunkedBlob(buf: *Buffer, allocator: Allocator, cb: object.ChunkedBlob, obj_hash: hash_mod.Hash) !void {
    const hex = hash_mod.toHex(obj_hash);
    try buf.appendSlice(allocator, "chunked_blob ");
    try buf.appendSlice(allocator, &hex);
    try buf.appendSlice(allocator, "\n");

    var size_buf: [20]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{cb.total_size}) catch "?";
    try buf.appendSlice(allocator, "size   ");
    try buf.appendSlice(allocator, size_str);
    try buf.appendSlice(allocator, "\n");

    if (cb.chunk_size == 0) {
        try buf.appendSlice(allocator, "chunk  variable (content-defined)\n");
    } else {
        var cs_buf: [20]u8 = undefined;
        const cs_str = std.fmt.bufPrint(&cs_buf, "{d}", .{cb.chunk_size}) catch "?";
        try buf.appendSlice(allocator, "chunk  ");
        try buf.appendSlice(allocator, cs_str);
        try buf.appendSlice(allocator, "\n");
    }

    var count_buf: [20]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{cb.chunks.len}) catch "?";
    try buf.appendSlice(allocator, "chunks ");
    try buf.appendSlice(allocator, count_str);
    try buf.appendSlice(allocator, "\n");
}

fn formatDelta(buf: *Buffer, allocator: Allocator, d: object.Delta) !void {
    const base_hex = hash_mod.toHex(d.base_hash);
    try buf.appendSlice(allocator, "delta\n");
    try buf.appendSlice(allocator, "base   ");
    try buf.appendSlice(allocator, &base_hex);
    try buf.appendSlice(allocator, "\n");

    var size_buf: [20]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{d.result_size}) catch "?";
    try buf.appendSlice(allocator, "size   ");
    try buf.appendSlice(allocator, size_str);
    try buf.appendSlice(allocator, "\n");

    var instr_buf: [20]u8 = undefined;
    const instr_str = std.fmt.bufPrint(&instr_buf, "{d}", .{d.instructions.len}) catch "?";
    try buf.appendSlice(allocator, "instr  ");
    try buf.appendSlice(allocator, instr_str);
    try buf.appendSlice(allocator, " bytes\n");
}

/// Format a commit as a single line: "<hash8> <title>\n"
/// Caller owns the returned slice.
pub fn formatCommitOneline(allocator: Allocator, commit_hash: hash_mod.Hash, commit: object.Commit) ![]u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);

    const hex = hash_mod.toHex(commit_hash);
    try buf.appendSlice(allocator, hex[0..8]);
    try buf.appendSlice(allocator, " ");
    try buf.appendSlice(allocator, commit.title());
    try buf.appendSlice(allocator, "\n");

    return buf.toOwnedSlice(allocator);
}

// -- Tests --

test "format blob outputs raw data" {
    const allocator = std.testing.allocator;
    const obj = object.Object{ .blob = .{ .data = "hello world" } };
    const out = try formatObject(allocator, obj, hash_mod.zero);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello world", out);
}

test "format empty blob" {
    const allocator = std.testing.allocator;
    const obj = object.Object{ .blob = .{ .data = "" } };
    const out = try formatObject(allocator, obj, hash_mod.zero);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "format tree shows entries" {
    const allocator = std.testing.allocator;
    const h = hash_mod.hash("test");
    const hex = hash_mod.toHex(h);
    const entries = [_]object.TreeEntry{
        .{ .name = "file.txt", .mode = .blob, .object_hash = h },
    };
    const obj = object.Object{ .tree = .{ .entries = @constCast(&entries) } };
    const out = try formatObject(allocator, obj, hash_mod.zero);
    defer allocator.free(out);

    // Should contain mode, hash, and name
    try std.testing.expect(std.mem.indexOf(u8, out, "blob") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, &hex) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "file.txt") != null);
}

test "format commit shows all fields" {
    const allocator = std.testing.allocator;
    const tree_hash = hash_mod.hash("tree");
    const obj_hash = hash_mod.hash("commit-obj");

    const parents = [_]hash_mod.Hash{};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 42, .little);
    const obj = object.Object{ .commit = .{
        .tree_hash = tree_hash,
        .parents = @constCast(&parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0xAA} ** 32,
        .message = "test commit",
        .timestamp = 1711300000,
        .signature = .{0xBB} ** 64,
    } };
    const out = try formatObject(allocator, obj, obj_hash);
    defer allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "commit ") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "tree   ") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "author mid 42") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "time   1711300000") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "test commit") != null);
    // Should NOT contain "parent" since no parents
    try std.testing.expect(std.mem.indexOf(u8, out, "parent ") == null);
}

test "format commit with parent" {
    const allocator = std.testing.allocator;
    const parent = hash_mod.hash("parent");
    const parents = [_]hash_mod.Hash{parent};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 1, .little);
    const obj = object.Object{ .commit = .{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0} ** 32,
        .message = "second",
        .timestamp = 1000,
        .signature = .{0} ** 64,
    } };
    const out = try formatObject(allocator, obj, hash_mod.zero);
    defer allocator.free(out);

    const parent_hex = hash_mod.toHex(parent);
    try std.testing.expect(std.mem.indexOf(u8, out, "parent ") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, &parent_hex) != null);
}

test "format commit oneline" {
    const allocator = std.testing.allocator;
    const obj_hash = hash_mod.hash("commit-obj");
    const hex = hash_mod.toHex(obj_hash);

    const parents = [_]hash_mod.Hash{};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 42, .little);
    const commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0xAA} ** 32,
        .message = "add new feature",
        .timestamp = 1711300000,
        .signature = .{0xBB} ** 64,
    };
    const out = try formatCommitOneline(allocator, obj_hash, commit);
    defer allocator.free(out);

    // Should be "<8-char hash> <title>\n"
    var expected_buf: [8 + 1 + 15 + 1]u8 = undefined;
    @memcpy(expected_buf[0..8], hex[0..8]);
    expected_buf[8] = ' ';
    @memcpy(expected_buf[9..24], "add new feature");
    expected_buf[24] = '\n';
    try std.testing.expectEqualStrings(&expected_buf, out);
}

test "format commit oneline multiline message" {
    const allocator = std.testing.allocator;
    const obj_hash = hash_mod.hash("commit2");

    const parents = [_]hash_mod.Hash{};
    var mid_buf2: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf2, 1, .little);
    const commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf2[0..] },
        .signer = .{0} ** 32,
        .message = "first line\nsecond line\nthird",
        .timestamp = 1000,
        .signature = .{0} ** 64,
    };
    const out = try formatCommitOneline(allocator, obj_hash, commit);
    defer allocator.free(out);

    // title() returns only the first line
    try std.testing.expect(std.mem.indexOf(u8, out, "first line\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "second") == null);
}

test "format commit oneline long title" {
    const allocator = std.testing.allocator;
    const obj_hash = hash_mod.hash("commit3");

    const parents = [_]hash_mod.Hash{};
    const long_msg = "A" ** 250 ++ "\nrest";
    var mid_buf3: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf3, 1, .little);
    const commit = object.Commit{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf3[0..] },
        .signer = .{0} ** 32,
        .message = long_msg,
        .timestamp = 1000,
        .signature = .{0} ** 64,
    };
    const out = try formatCommitOneline(allocator, obj_hash, commit);
    defer allocator.free(out);

    // 8 hash chars + 1 space + 200 title chars + 1 newline = 210
    try std.testing.expectEqual(@as(usize, 210), out.len);
}

test "format remix shows sources" {
    const allocator = std.testing.allocator;
    const proj_id = hash_mod.hash("project");
    const commit_h = hash_mod.hash("commit");
    const sources = [_]object.RemixSource{
        .{ .upstream_id = proj_id, .commit_hash = commit_h },
    };
    const parents = [_]hash_mod.Hash{};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 99, .little);
    const obj = object.Object{ .remix = .{
        .tree_hash = hash_mod.hash("tree"),
        .parents = @constCast(&parents),
        .sources = @constCast(&sources),
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0} ** 32,
        .message = "remixed",
        .timestamp = 2000,
        .signature = .{0} ** 64,
    } };
    const out = try formatObject(allocator, obj, hash_mod.zero);
    defer allocator.free(out);

    try std.testing.expect(std.mem.indexOf(u8, out, "remix  ") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "source ") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "author mid 99") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "remixed") != null);
}

// ===========================================================================
// Graph visualization for `log --graph`
// ===========================================================================

pub const GraphColumn = struct {
    target: ?hash_mod.Hash,
};

pub const GraphState = struct {
    columns: std.ArrayList(GraphColumn),
    allocator: Allocator,

    pub fn init(allocator: Allocator) GraphState {
        return .{
            .columns = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *GraphState) void {
        self.columns.deinit(self.allocator);
    }
};

pub const GraphLines = struct {
    commit_prefix: []const u8,
    post_lines: [][]const u8,
    allocator: Allocator,

    pub fn deinit(self: *GraphLines) void {
        self.allocator.free(self.commit_prefix);
        for (self.post_lines) |line| {
            self.allocator.free(line);
        }
        self.allocator.free(self.post_lines);
    }
};

pub fn graphRenderCommit(
    allocator: Allocator,
    state: *GraphState,
    commit_hash: hash_mod.Hash,
    parents: []const hash_mod.Hash,
) !GraphLines {
    var commit_col: ?usize = null;
    for (state.columns.items, 0..) |col, i| {
        if (col.target) |target| {
            if (std.mem.eql(u8, &target, &commit_hash)) {
                commit_col = i;
                break;
            }
        }
    }

    if (commit_col == null) {
        commit_col = state.columns.items.len;
        try state.columns.append(state.allocator, .{ .target = commit_hash });
    }

    const col_idx = commit_col.?;

    var prefix_buf: Buffer = .empty;
    errdefer prefix_buf.deinit(allocator);

    for (state.columns.items, 0..) |_, i| {
        if (i == col_idx) {
            try prefix_buf.appendSlice(allocator, "* ");
        } else {
            try prefix_buf.appendSlice(allocator, "| ");
        }
    }

    const commit_prefix = try prefix_buf.toOwnedSlice(allocator);
    errdefer allocator.free(commit_prefix);

    var post_lines_list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (post_lines_list.items) |line| allocator.free(line);
        post_lines_list.deinit(allocator);
    }

    if (parents.len == 0) {
        state.columns.items[col_idx].target = null;
        var has_active = false;
        for (state.columns.items) |col| {
            if (col.target != null) {
                has_active = true;
                break;
            }
        }
        if (has_active) {
            const cont_line = try buildContinuationLine(allocator, state.columns.items);
            try post_lines_list.append(allocator, cont_line);
        }
        collapseDeadColumns(state);
    } else if (parents.len == 1) {
        state.columns.items[col_idx].target = parents[0];
        const cont_line = try buildContinuationLine(allocator, state.columns.items);
        try post_lines_list.append(allocator, cont_line);
    } else {
        state.columns.items[col_idx].target = parents[0];
        for (parents[1..]) |parent| {
            try state.columns.append(state.allocator, .{ .target = parent });
        }
        var merge_buf: Buffer = .empty;
        errdefer merge_buf.deinit(allocator);
        for (state.columns.items, 0..) |_, i| {
            if (i == col_idx) {
                try merge_buf.appendSlice(allocator, "|\\ ");
            } else if (i > col_idx and i <= col_idx + parents.len - 1) {
                // covered by backslash
            } else {
                try merge_buf.appendSlice(allocator, "| ");
            }
        }
        const merge_line = try merge_buf.toOwnedSlice(allocator);
        try post_lines_list.append(allocator, merge_line);

        const cont_line = try buildContinuationLine(allocator, state.columns.items);
        try post_lines_list.append(allocator, cont_line);
    }

    return .{
        .commit_prefix = commit_prefix,
        .post_lines = try post_lines_list.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

fn buildContinuationLine(allocator: Allocator, columns: []const GraphColumn) ![]const u8 {
    var buf: Buffer = .empty;
    errdefer buf.deinit(allocator);
    for (columns) |col| {
        if (col.target != null) {
            try buf.appendSlice(allocator, "| ");
        } else {
            try buf.appendSlice(allocator, "  ");
        }
    }
    return buf.toOwnedSlice(allocator);
}

fn collapseDeadColumns(state: *GraphState) void {
    while (state.columns.items.len > 0) {
        if (state.columns.items[state.columns.items.len - 1].target == null) {
            _ = state.columns.pop();
        } else {
            break;
        }
    }
}

test "graph linear history produces single column" {
    const allocator = std.testing.allocator;
    var state = GraphState.init(allocator);
    defer state.deinit();

    const c1 = hash_mod.hash("c1");
    const c2 = hash_mod.hash("c2");
    const c3 = hash_mod.hash("c3");

    const c3_parents = [_]hash_mod.Hash{c2};
    var lines3 = try graphRenderCommit(allocator, &state, c3, &c3_parents);
    defer lines3.deinit();
    try std.testing.expectEqualStrings("* ", lines3.commit_prefix);
    try std.testing.expect(lines3.post_lines.len >= 1);
    try std.testing.expectEqualStrings("| ", lines3.post_lines[0]);

    const c2_parents = [_]hash_mod.Hash{c1};
    var lines2 = try graphRenderCommit(allocator, &state, c2, &c2_parents);
    defer lines2.deinit();
    try std.testing.expectEqualStrings("* ", lines2.commit_prefix);

    var lines1 = try graphRenderCommit(allocator, &state, c1, &.{});
    defer lines1.deinit();
    try std.testing.expectEqualStrings("* ", lines1.commit_prefix);
}

test "graph merge commit produces branch connectors" {
    const allocator = std.testing.allocator;
    var state = GraphState.init(allocator);
    defer state.deinit();

    const c_base = hash_mod.hash("base");
    const c_branch = hash_mod.hash("branch");
    const c_merge = hash_mod.hash("merge");

    const merge_parents = [_]hash_mod.Hash{ c_base, c_branch };
    var lines_merge = try graphRenderCommit(allocator, &state, c_merge, &merge_parents);
    defer lines_merge.deinit();
    try std.testing.expectEqualStrings("* ", lines_merge.commit_prefix);
    try std.testing.expect(lines_merge.post_lines.len >= 1);
    try std.testing.expect(std.mem.indexOf(u8, lines_merge.post_lines[0], "\\") != null);
    try std.testing.expectEqual(@as(usize, 2), state.columns.items.len);
}

test "graph multiple parallel branches" {
    const allocator = std.testing.allocator;
    var state = GraphState.init(allocator);
    defer state.deinit();

    const c_root = hash_mod.hash("root");
    const c_left = hash_mod.hash("left");
    const c_right = hash_mod.hash("right");
    const c_merge = hash_mod.hash("merge");

    const merge_parents = [_]hash_mod.Hash{ c_left, c_right };
    var lines_merge = try graphRenderCommit(allocator, &state, c_merge, &merge_parents);
    defer lines_merge.deinit();
    try std.testing.expectEqualStrings("* ", lines_merge.commit_prefix);

    const left_parents = [_]hash_mod.Hash{c_root};
    var lines_left = try graphRenderCommit(allocator, &state, c_left, &left_parents);
    defer lines_left.deinit();
    try std.testing.expect(std.mem.indexOf(u8, lines_left.commit_prefix, "*") != null);
    try std.testing.expect(std.mem.indexOf(u8, lines_left.commit_prefix, "|") != null);

    const right_parents = [_]hash_mod.Hash{c_root};
    var lines_right = try graphRenderCommit(allocator, &state, c_right, &right_parents);
    defer lines_right.deinit();
    try std.testing.expect(std.mem.indexOf(u8, lines_right.commit_prefix, "*") != null);

    var lines_root = try graphRenderCommit(allocator, &state, c_root, &.{});
    defer lines_root.deinit();
    try std.testing.expect(std.mem.indexOf(u8, lines_root.commit_prefix, "*") != null);
}
