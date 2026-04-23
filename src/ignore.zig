// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Pattern = struct {
    pattern: []const u8,
    negated: bool,
    dir_only: bool,
};

pub const IgnoreList = struct {
    patterns: []Pattern,
    allocator: Allocator,

    pub fn deinit(self: *IgnoreList) void {
        for (self.patterns) |p| {
            self.allocator.free(p.pattern);
        }
        self.allocator.free(self.patterns);
    }

    /// Check if a path should be ignored. Last matching pattern wins.
    /// Default ignores (.mkit, .git) are always checked first.
    pub fn isIgnored(self: IgnoreList, path: []const u8, is_dir: bool) bool {
        // Default ignores — always skip .mkit and .git
        if (std.mem.eql(u8, path, ".mkit") or std.mem.eql(u8, path, ".git")) {
            return true;
        }

        // Walk patterns in order; last match wins
        var ignored = false;
        for (self.patterns) |p| {
            // dir_only patterns only match directories
            if (p.dir_only and !is_dir) continue;

            if (globMatch(p.pattern, path)) {
                ignored = !p.negated;
            }
        }
        return ignored;
    }
};

/// Load .mkitignore from a directory. Returns empty list if file doesn't exist.
pub fn load(allocator: Allocator, io: std.Io, dir: std.Io.Dir) !IgnoreList {
    const file = dir.openFile(io, ".mkitignore", .{}) catch |err| switch (err) {
        error.FileNotFound => return IgnoreList{
            .patterns = &.{},
            .allocator = allocator,
        },
        else => return err,
    };
    defer file.close(io);

    const stat = try file.stat(io);
    if (stat.size > 1024 * 1024) return error.IgnoreFileTooLarge; // 1MB limit
    const content = try allocator.alloc(u8, stat.size);
    defer allocator.free(content);
    const read = try file.readPositionalAll(io, content, 0);
    return parse(allocator, content[0..read]);
}

/// Parse ignore file content into patterns.
pub fn parse(allocator: Allocator, content: []const u8) !IgnoreList {
    var patterns: std.ArrayList(Pattern) = .empty;
    errdefer {
        for (patterns.items) |p| {
            allocator.free(p.pattern);
        }
        patterns.deinit(allocator);
    }

    var iter = std.mem.splitScalar(u8, content, '\n');
    while (iter.next()) |raw_line| {
        // Strip trailing \r for Windows-style line endings
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;

        // Skip blank lines
        if (line.len == 0) continue;

        // Skip comments
        if (line[0] == '#') continue;

        var pat = line;
        var negated = false;
        var dir_only = false;

        // Check for negation prefix
        if (pat.len > 0 and pat[0] == '!') {
            negated = true;
            pat = pat[1..];
        }

        // Check for trailing slash (directory-only pattern)
        if (pat.len > 0 and pat[pat.len - 1] == '/') {
            dir_only = true;
            pat = pat[0 .. pat.len - 1];
        }

        if (pat.len == 0) continue;

        const duped = try allocator.dupe(u8, pat);
        try patterns.append(allocator, .{
            .pattern = duped,
            .negated = negated,
            .dir_only = dir_only,
        });
    }

    return IgnoreList{
        .patterns = try patterns.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

/// Match a path component against a glob pattern (fnmatch-style).
/// Supports: * (any chars except /), ? (one char), exact match.
pub fn globMatch(pattern: []const u8, name: []const u8) bool {
    var pi: usize = 0;
    var ni: usize = 0;

    // For backtracking on '*'
    var star_pi: ?usize = null;
    var star_ni: usize = 0;

    while (ni < name.len or pi < pattern.len) {
        if (pi < pattern.len) {
            const pc = pattern[pi];
            if (pc == '*') {
                // Save backtrack position
                star_pi = pi;
                star_ni = ni;
                pi += 1;
                continue;
            }
            if (ni < name.len) {
                if (pc == '?') {
                    // Match any single char (except /)
                    if (name[ni] != '/') {
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                } else if (pc == name[ni]) {
                    pi += 1;
                    ni += 1;
                    continue;
                }
            }
        }

        // No match at current position — try backtracking to last '*'
        if (star_pi) |sp| {
            star_ni += 1;
            if (star_ni <= name.len) {
                // Don't let '*' match '/'
                if (star_ni > 0 and name[star_ni - 1] == '/') {
                    return false;
                }
                pi = sp + 1;
                ni = star_ni;
                continue;
            }
        }

        return false;
    }

    return true;
}

// -- Tests --

test "empty patterns matches nothing" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "");
    defer il.deinit();
    try std.testing.expect(!il.isIgnored("anything.txt", false));
    try std.testing.expect(!il.isIgnored("somedir", true));
}

test "exact filename match" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "secret.key");
    defer il.deinit();
    try std.testing.expect(il.isIgnored("secret.key", false));
    try std.testing.expect(!il.isIgnored("other.key", false));
}

test "glob star pattern" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "*.log");
    defer il.deinit();
    try std.testing.expect(il.isIgnored("debug.log", false));
    try std.testing.expect(!il.isIgnored("debug.txt", false));
}

test "directory pattern trailing slash" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "build/");
    defer il.deinit();
    try std.testing.expect(il.isIgnored("build", true));
    try std.testing.expect(!il.isIgnored("build", false));
}

test "negation pattern" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "*.log\n!important.log");
    defer il.deinit();
    try std.testing.expect(il.isIgnored("debug.log", false));
    try std.testing.expect(!il.isIgnored("important.log", false));
}

test "comment lines ignored" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "# this is a comment\n*.tmp");
    defer il.deinit();
    try std.testing.expectEqual(@as(usize, 1), il.patterns.len);
}

test "blank lines ignored" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "\n\n*.tmp\n\n");
    defer il.deinit();
    try std.testing.expectEqual(@as(usize, 1), il.patterns.len);
}

test "glob question mark" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "file?.txt");
    defer il.deinit();
    try std.testing.expect(il.isIgnored("file1.txt", false));
    try std.testing.expect(!il.isIgnored("file12.txt", false));
}

test "default ignores" {
    const allocator = std.testing.allocator;
    var il = try parse(allocator, "");
    defer il.deinit();
    // .mkit and .git are always ignored, even with empty patterns
    try std.testing.expect(il.isIgnored(".mkit", true));
    try std.testing.expect(il.isIgnored(".git", true));
    try std.testing.expect(il.isIgnored(".mkit", false));
    try std.testing.expect(il.isIgnored(".git", false));
}

test "glob match exact" {
    try std.testing.expect(globMatch("hello", "hello"));
    try std.testing.expect(!globMatch("hello", "world"));
}

test "glob match star" {
    try std.testing.expect(globMatch("*.zig", "main.zig"));
    try std.testing.expect(!globMatch("*.zig", "main.txt"));
    try std.testing.expect(globMatch("test*", "testing"));
    try std.testing.expect(globMatch("*", "anything"));
}

test "load from directory without mkitignore" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    var il = try load(allocator, std.testing.io, tmp.dir);
    defer il.deinit();
    try std.testing.expectEqual(@as(usize, 0), il.patterns.len);
}

test "load from directory with mkitignore" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create .mkitignore file
    const f = try tmp.dir.createFile(std.testing.io, ".mkitignore", .{});
    try f.writeStreamingAll(std.testing.io, "*.log\nbuild/\n");
    f.close(std.testing.io);

    var il = try load(allocator, std.testing.io, tmp.dir);
    defer il.deinit();
    try std.testing.expectEqual(@as(usize, 2), il.patterns.len);
    try std.testing.expect(il.isIgnored("test.log", false));
    try std.testing.expect(il.isIgnored("build", true));
}
