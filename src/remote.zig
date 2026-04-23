// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const config_mod = @import("config.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Configuration for connecting to an S3-compatible remote (R2, MinIO, etc.).
pub const RemoteConfig = struct {
    endpoint: []const u8, // e.g. "https://abc123.r2.cloudflarestorage.com"
    bucket: []const u8, // e.g. "mkit-storage"
    access_key_id: []const u8, // from MKIT_R2_ACCESS_KEY env
    secret_access_key: []const u8, // from MKIT_R2_SECRET_KEY env
    region: []const u8, // "auto" for R2
    allocator: ?Allocator = null,

    pub fn deinit(self: *RemoteConfig) void {
        if (self.allocator) |alloc| {
            alloc.free(self.endpoint);
            alloc.free(self.bucket);
            alloc.free(self.access_key_id);
            alloc.free(self.secret_access_key);
            alloc.free(self.region);
        }
    }
};

/// Build the full URL for an object key.
/// Example: endpoint="https://r2.example.com", bucket="mybucket", key="packs/abc"
///       -> "https://r2.example.com/mybucket/packs/abc"
/// Caller owns returned slice.
pub fn buildUrl(allocator: Allocator, cfg: RemoteConfig, key: []const u8) ![]u8 {
    // endpoint + "/" + bucket + "/" + key
    const len = cfg.endpoint.len + 1 + cfg.bucket.len + 1 + key.len;
    var buf = try allocator.alloc(u8, len);
    var pos: usize = 0;

    @memcpy(buf[pos..][0..cfg.endpoint.len], cfg.endpoint);
    pos += cfg.endpoint.len;
    buf[pos] = '/';
    pos += 1;
    @memcpy(buf[pos..][0..cfg.bucket.len], cfg.bucket);
    pos += cfg.bucket.len;
    buf[pos] = '/';
    pos += 1;
    @memcpy(buf[pos..][0..key.len], key);

    return buf;
}

/// Build the S3 path for an object key: /<bucket>/<key>
/// Caller owns returned slice.
pub fn buildPath(allocator: Allocator, cfg: RemoteConfig, key: []const u8) ![]u8 {
    // "/" + bucket + "/" + key
    const len = 1 + cfg.bucket.len + 1 + key.len;
    var buf = try allocator.alloc(u8, len);
    var pos: usize = 0;

    buf[pos] = '/';
    pos += 1;
    @memcpy(buf[pos..][0..cfg.bucket.len], cfg.bucket);
    pos += cfg.bucket.len;
    buf[pos] = '/';
    pos += 1;
    @memcpy(buf[pos..][0..key.len], key);

    return buf;
}

/// Parse the host from an endpoint URL.
/// "https://abc.r2.cloudflarestorage.com" -> "abc.r2.cloudflarestorage.com"
/// "http://localhost:9000" -> "localhost:9000"
pub fn parseHost(endpoint: []const u8) []const u8 {
    if (std.mem.indexOf(u8, endpoint, "://")) |idx| {
        return endpoint[idx + 3 ..];
    }
    return endpoint;
}

/// Parse an S3 ListBucketResult XML response to extract object keys.
/// Extracts the text content of each <Key>...</Key> element inside <Contents>.
/// Caller owns returned slice and each string within it.
pub fn parseListXml(allocator: Allocator, xml: []const u8) ![][]u8 {
    var keys: std.ArrayList([]u8) = .empty;
    errdefer {
        for (keys.items) |k| {
            allocator.free(k);
        }
        keys.deinit(allocator);
    }

    const key_open = "<Key>";
    const key_close = "</Key>";

    var pos: usize = 0;
    while (pos < xml.len) {
        const start = std.mem.indexOf(u8, xml[pos..], key_open) orelse break;
        const abs_start = pos + start + key_open.len;
        const end = std.mem.indexOf(u8, xml[abs_start..], key_close) orelse break;
        const abs_end = abs_start + end;

        const key_text = xml[abs_start..abs_end];
        const duped = try allocator.dupe(u8, key_text);
        errdefer allocator.free(duped);
        try keys.append(allocator, duped);

        pos = abs_end + key_close.len;
    }

    return keys.toOwnedSlice(allocator);
}

/// Use protocol.formatRef and protocol.parseRef for wire format.
const protocol = @import("protocol.zig");
pub const formatRef = protocol.formatRef;
pub const parseRef = protocol.parseRef;

/// Re-export of the strict URL parser so call sites importing `remote.zig`
/// (e.g. `mkit remote add`) can validate URLs before persisting them.
pub const parseRemoteUrl = protocol.parseRemoteUrl;
pub const StrictRemoteUrl = protocol.StrictRemoteUrl;
pub const StrictParseError = protocol.StrictParseError;

/// Validate that `url` conforms to the strict `mkit+<scheme>://...` shape.
/// Returns the parsed form on success; returns the same errors parseRemoteUrl
/// does (InvalidScheme, UnknownScheme, MalformedUrl) on failure.
///
/// Intended for `mkit remote add` to call before writing the URL to config,
/// so malformed or ambiguous URLs never round-trip through disk.
// TODO(W5): wire `validateRemoteUrl` into the `mkit remote add` CLI handler
//   once that handler (currently in main.zig, W4 territory) moves to a
//   helper we can call from here. Until then, the CLI still accepts the
//   legacy `parseUrl` forms for backwards compat.
pub fn validateRemoteUrl(url: []const u8) StrictParseError!StrictRemoteUrl {
    return protocol.parseRemoteUrl(url);
}

/// Read RemoteConfig from environment variables.
/// Required: MKIT_R2_ENDPOINT, MKIT_R2_BUCKET, MKIT_R2_ACCESS_KEY, MKIT_R2_SECRET_KEY
/// Optional: MKIT_R2_REGION (defaults to "auto")
/// Returns null if any required variable is missing. Caller must call deinit().
pub fn configFromEnv(allocator: Allocator) !?RemoteConfig {
    const endpoint = @import("term.zig").posixGetenv("MKIT_R2_ENDPOINT") orelse return null;
    const bucket = @import("term.zig").posixGetenv("MKIT_R2_BUCKET") orelse return null;
    const access_key = @import("term.zig").posixGetenv("MKIT_R2_ACCESS_KEY") orelse return null;
    const secret_key = @import("term.zig").posixGetenv("MKIT_R2_SECRET_KEY") orelse return null;
    const region = @import("term.zig").posixGetenv("MKIT_R2_REGION") orelse "auto";

    const ep = try allocator.dupe(u8, endpoint);
    errdefer allocator.free(ep);
    const bk = try allocator.dupe(u8, bucket);
    errdefer allocator.free(bk);
    const ak = try allocator.dupe(u8, access_key);
    errdefer allocator.free(ak);
    const sk = try allocator.dupe(u8, secret_key);
    errdefer allocator.free(sk);
    const rg = try allocator.dupe(u8, region);

    return RemoteConfig{
        .endpoint = ep,
        .bucket = bk,
        .access_key_id = ak,
        .secret_access_key = sk,
        .region = rg,
        .allocator = allocator,
    };
}

/// Read RemoteConfig from .mkit/config file.
/// Looks for keys: remote_endpoint, remote_bucket, remote_access_key, remote_secret_key, remote_region.
/// Returns null if endpoint or bucket is missing. Caller must call deinit().
pub fn configFromFile(allocator: Allocator, io: std.Io, dir: std.Io.Dir) !?RemoteConfig {
    // Why: std.fs.Dir → std.Io.Dir in Zig 0.16; readFileAlloc now takes io
    // and a typed Io.Limit instead of a raw usize max_size.
    const content = dir.readFileAlloc(io, config_mod.config_file, allocator, .limited(8192)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(content);

    var endpoint: ?[]const u8 = null;
    var bucket: ?[]const u8 = null;
    var access_key: ?[]const u8 = null;
    var secret_key: ?[]const u8 = null;
    var region: ?[]const u8 = null;
    errdefer {
        if (endpoint) |e| allocator.free(e);
        if (bucket) |b| allocator.free(b);
        if (access_key) |a| allocator.free(a);
        if (secret_key) |s| allocator.free(s);
        if (region) |r| allocator.free(r);
    }

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const key = std.mem.trimEnd(u8, trimmed[0..eq_pos], " \t");
        const value = std.mem.trimStart(u8, trimmed[eq_pos + 1 ..], " \t");

        if (std.mem.eql(u8, key, "remote_endpoint")) {
            if (endpoint) |prev| allocator.free(prev);
            endpoint = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_bucket")) {
            if (bucket) |prev| allocator.free(prev);
            bucket = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_access_key")) {
            if (access_key) |prev| allocator.free(prev);
            access_key = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_secret_key")) {
            if (secret_key) |prev| allocator.free(prev);
            secret_key = try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_region")) {
            if (region) |prev| allocator.free(prev);
            region = try allocator.dupe(u8, value);
        }
    }

    // Require at least endpoint and bucket
    if (endpoint == null or bucket == null) {
        if (endpoint) |e| allocator.free(e);
        if (bucket) |b| allocator.free(b);
        if (access_key) |a| allocator.free(a);
        if (secret_key) |s| allocator.free(s);
        if (region) |r| allocator.free(r);
        return null;
    }

    // Default access_key/secret_key to empty, region to "auto"
    return RemoteConfig{
        .endpoint = endpoint.?,
        .bucket = bucket.?,
        .access_key_id = access_key orelse try allocator.dupe(u8, ""),
        .secret_access_key = secret_key orelse try allocator.dupe(u8, ""),
        .region = region orelse try allocator.dupe(u8, "auto"),
        .allocator = allocator,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "build url" {
    const allocator = std.testing.allocator;
    const cfg = RemoteConfig{
        .endpoint = "https://r2.example.com",
        .bucket = "mybucket",
        .access_key_id = "key",
        .secret_access_key = "secret",
        .region = "auto",
    };
    const url = try buildUrl(allocator, cfg, "packs/abc");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("https://r2.example.com/mybucket/packs/abc", url);
}

test "build path" {
    const allocator = std.testing.allocator;
    const cfg = RemoteConfig{
        .endpoint = "https://r2.example.com",
        .bucket = "mybucket",
        .access_key_id = "key",
        .secret_access_key = "secret",
        .region = "auto",
    };
    const path = try buildPath(allocator, cfg, "packs/abc");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/mybucket/packs/abc", path);
}

test "parse host" {
    // HTTPS
    try std.testing.expectEqualStrings(
        "abc.r2.cloudflarestorage.com",
        parseHost("https://abc.r2.cloudflarestorage.com"),
    );
    // HTTP with port
    try std.testing.expectEqualStrings(
        "localhost:9000",
        parseHost("http://localhost:9000"),
    );
    // No scheme
    try std.testing.expectEqualStrings(
        "bare-host.com",
        parseHost("bare-host.com"),
    );
}

test "parse list xml basic" {
    const allocator = std.testing.allocator;
    const xml =
        \\<?xml version="1.0"?>
        \\<ListBucketResult>
        \\  <Contents><Key>refs/heads/main</Key></Contents>
        \\  <Contents><Key>refs/heads/dev</Key></Contents>
        \\</ListBucketResult>
    ;
    const keys = try parseListXml(allocator, xml);
    defer {
        for (keys) |k| allocator.free(k);
        allocator.free(keys);
    }
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualStrings("refs/heads/main", keys[0]);
    try std.testing.expectEqualStrings("refs/heads/dev", keys[1]);
}

test "parse list xml empty" {
    const allocator = std.testing.allocator;
    const xml =
        \\<?xml version="1.0"?>
        \\<ListBucketResult>
        \\</ListBucketResult>
    ;
    const keys = try parseListXml(allocator, xml);
    defer allocator.free(keys);
    try std.testing.expectEqual(@as(usize, 0), keys.len);
}

test "format ref" {
    const h = hash_mod.hash("test-ref");
    const buf = formatRef(h);
    // Last byte is newline
    try std.testing.expectEqual(@as(u8, '\n'), buf[64]);
    // First 64 bytes are hex
    const hex = hash_mod.toHex(h);
    try std.testing.expectEqualStrings(&hex, buf[0..64]);
}

test "parse ref" {
    const h = hash_mod.hash("test-ref");
    const hex = hash_mod.toHex(h);

    // With newline
    var with_nl: [65]u8 = undefined;
    with_nl[0..64].* = hex;
    with_nl[64] = '\n';
    const parsed1 = try parseRef(&with_nl);
    try std.testing.expectEqual(h, parsed1);

    // Without newline
    const parsed2 = try parseRef(&hex);
    try std.testing.expectEqual(h, parsed2);
}

test "parse ref invalid" {
    try std.testing.expectError(error.InvalidRef, parseRef("short"));
    try std.testing.expectError(error.InvalidRef, parseRef(""));
    // 64 chars but invalid hex
    try std.testing.expectError(error.InvalidRef, parseRef("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
}

test "config from file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // Write a config file with remote fields
    const f = try tmp.dir.createFile(std.testing.io, config_mod.config_file, .{});
    defer f.close(std.testing.io);
    try f.writeStreamingAll(std.testing.io,
        \\author_mid = 42
        \\remote_endpoint = https://r2.test.com
        \\remote_bucket = test-bucket
        \\remote_access_key = AKID123
        \\remote_secret_key = SECRET456
        \\remote_region = us-east-1
        \\
    );

    var cfg = (try configFromFile(allocator, std.testing.io, tmp.dir)).?;
    defer cfg.deinit();

    try std.testing.expectEqualStrings("https://r2.test.com", cfg.endpoint);
    try std.testing.expectEqualStrings("test-bucket", cfg.bucket);
    try std.testing.expectEqualStrings("AKID123", cfg.access_key_id);
    try std.testing.expectEqualStrings("SECRET456", cfg.secret_access_key);
    try std.testing.expectEqualStrings("us-east-1", cfg.region);
}

test "config from file missing required" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // Write a config file without remote fields
    const f = try tmp.dir.createFile(std.testing.io, config_mod.config_file, .{});
    defer f.close(std.testing.io);
    try f.writeStreamingAll(std.testing.io, "author_mid = 1\n");

    const result = try configFromFile(allocator, std.testing.io, tmp.dir);
    try std.testing.expectEqual(@as(?RemoteConfig, null), result);
}

test "config from file defaults" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // Write a config file with only endpoint and bucket (minimal required)
    const f = try tmp.dir.createFile(std.testing.io, config_mod.config_file, .{});
    defer f.close(std.testing.io);
    try f.writeStreamingAll(std.testing.io,
        \\remote_endpoint = https://r2.minimal.com
        \\remote_bucket = my-bucket
        \\
    );

    var cfg = (try configFromFile(allocator, std.testing.io, tmp.dir)).?;
    defer cfg.deinit();

    try std.testing.expectEqualStrings("https://r2.minimal.com", cfg.endpoint);
    try std.testing.expectEqualStrings("my-bucket", cfg.bucket);
    try std.testing.expectEqualStrings("", cfg.access_key_id);
    try std.testing.expectEqualStrings("", cfg.secret_access_key);
    try std.testing.expectEqualStrings("auto", cfg.region);
}

test "config from file no file" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(std.testing.io, ".mkit");

    // No config file exists
    const result = try configFromFile(allocator, std.testing.io, tmp.dir);
    try std.testing.expectEqual(@as(?RemoteConfig, null), result);
}

test "parse list xml nested" {
    const allocator = std.testing.allocator;
    // Test with more realistic XML that has other elements mixed in
    const xml =
        \\<?xml version="1.0" encoding="UTF-8"?>
        \\<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        \\  <Name>my-bucket</Name>
        \\  <Prefix>objects/</Prefix>
        \\  <IsTruncated>false</IsTruncated>
        \\  <Contents>
        \\    <Key>objects/ab/cdef1234</Key>
        \\    <Size>1024</Size>
        \\    <LastModified>2024-01-01T00:00:00Z</LastModified>
        \\  </Contents>
        \\  <Contents>
        \\    <Key>objects/ff/00112233</Key>
        \\    <Size>2048</Size>
        \\  </Contents>
        \\</ListBucketResult>
    ;
    const keys = try parseListXml(allocator, xml);
    defer {
        for (keys) |k| allocator.free(k);
        allocator.free(keys);
    }
    try std.testing.expectEqual(@as(usize, 2), keys.len);
    try std.testing.expectEqualStrings("objects/ab/cdef1234", keys[0]);
    try std.testing.expectEqualStrings("objects/ff/00112233", keys[1]);
}

test "format and parse ref roundtrip" {
    const h = hash_mod.hash("roundtrip-test");
    const wire = formatRef(h);
    const parsed = try parseRef(&wire);
    try std.testing.expectEqual(h, parsed);
}

test "validateRemoteUrl accepts strict mkit+file" {
    const parsed = try validateRemoteUrl("mkit+file:///tmp/repo");
    try std.testing.expectEqualStrings("/tmp/repo", parsed.file);
}

test "validateRemoteUrl rejects bare URL" {
    try std.testing.expectError(error.InvalidScheme, validateRemoteUrl("/tmp/repo"));
    try std.testing.expectError(error.InvalidScheme, validateRemoteUrl("https://host/v1"));
}

test "validateRemoteUrl rejects unknown scheme" {
    try std.testing.expectError(error.UnknownScheme, validateRemoteUrl("mkit+gopher://example.com"));
}

test "build url empty key" {
    const allocator = std.testing.allocator;
    const cfg = RemoteConfig{
        .endpoint = "https://r2.example.com",
        .bucket = "bucket",
        .access_key_id = "",
        .secret_access_key = "",
        .region = "auto",
    };
    const url = try buildUrl(allocator, cfg, "");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("https://r2.example.com/bucket/", url);
}
