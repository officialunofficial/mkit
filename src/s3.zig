// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Allocator = std.mem.Allocator;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const remote = @import("remote.zig");

/// Re-export RemoteConfig as the config type for signing.
pub const S3Config = remote.RemoteConfig;

pub const SignedRequest = struct {
    authorization: []const u8, // heap-allocated, caller must free
    x_amz_date: [16]u8, // "YYYYMMDDTHHMMSSZ"
    x_amz_content_sha256: [64]u8, // lowercase hex of SHA256(payload)
    allocator: Allocator,

    pub fn deinit(self: *SignedRequest) void {
        self.allocator.free(self.authorization);
    }
};

/// Calendar date/time components derived from a Unix timestamp.
const Calendar = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

/// Convert Unix timestamp (seconds since 1970-01-01T00:00:00Z) to calendar date/time.
fn unixToCalendar(timestamp: i64) Calendar {
    // Handle the timestamp as total seconds; split into days and time-of-day.
    const secs_per_day: i64 = 86400;
    var days = @divFloor(timestamp, secs_per_day);
    var remaining = @mod(timestamp, secs_per_day);

    const hour: u8 = @intCast(@divFloor(remaining, 3600));
    remaining = @mod(remaining, 3600);
    const minute: u8 = @intCast(@divFloor(remaining, 60));
    const second: u8 = @intCast(@mod(remaining, 60));

    // Shift epoch from 1970-01-01 to 0000-03-01 (makes leap year calc easier).
    // Days from 0000-03-01 to 1970-01-01 = 719468
    days += 719468;

    // 400-year cycle
    const era: i64 = @divFloor(days, 146097);
    const doe: u32 = @intCast(days - era * 146097); // day of era [0, 146096]
    const yoe: u32 = @intCast(@divFloor(
        doe -| @as(u32, @intCast(@divFloor(doe, 1460))) +| @as(u32, @intCast(@divFloor(doe, 36524))) -| @as(u32, @intCast(@divFloor(doe, 146096))),
        365,
    )); // year of era [0, 399]
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy: u32 = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    const mp: u32 = (5 * doy + 2) / 153; // month index from March [0, 11]
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1); // day [1, 31]
    const m_raw: u32 = if (mp < 10) mp + 3 else mp - 9;
    const m: u8 = @intCast(m_raw); // month [1, 12]
    const year_adj: i64 = if (m <= 2) y + 1 else y;

    return .{
        .year = @intCast(year_adj),
        .month = m,
        .day = d,
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

/// Format Unix timestamp as ISO 8601 basic format: YYYYMMDDTHHMMSSZ
pub fn formatIso8601(timestamp: i64) [16]u8 {
    const cal = unixToCalendar(timestamp);
    var buf: [16]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        cal.year, cal.month,  cal.day,
        cal.hour, cal.minute, cal.second,
    }) catch unreachable;
    return buf;
}

/// Format Unix timestamp as date only: YYYYMMDD
pub fn formatDate(timestamp: i64) [8]u8 {
    const cal = unixToCalendar(timestamp);
    var buf: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}{d:0>2}{d:0>2}", .{
        cal.year, cal.month, cal.day,
    }) catch unreachable;
    return buf;
}

/// SHA256 hash of data, returned as 64-char lowercase hex.
pub fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// HMAC-SHA256: returns 32-byte MAC.
pub fn hmacSha256(key: []const u8, msg: []const u8) [32]u8 {
    var out: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&out, msg, key);
    return out;
}

/// Derive the AWS Signature V4 signing key.
/// signingKey = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"), "aws4_request")
pub fn deriveSigningKey(secret: []const u8, date: []const u8, region: []const u8) [32]u8 {
    // Step 1: HMAC("AWS4" + secret, date)
    var aws4_key_buf: [4 + 256]u8 = undefined; // "AWS4" + up to 256 bytes of secret
    const prefix = "AWS4";
    @memcpy(aws4_key_buf[0..4], prefix);
    @memcpy(aws4_key_buf[4 .. 4 + secret.len], secret);
    const aws4_key = aws4_key_buf[0 .. 4 + secret.len];

    const date_key = hmacSha256(aws4_key, date);
    const region_key = hmacSha256(&date_key, region);
    const service_key = hmacSha256(&region_key, "s3");
    const signing_key = hmacSha256(&service_key, "aws4_request");
    return signing_key;
}

/// Extract host from an endpoint URL (strip scheme prefix).
fn parseHost(endpoint: []const u8) []const u8 {
    if (std.mem.startsWith(u8, endpoint, "https://")) {
        return endpoint["https://".len..];
    } else if (std.mem.startsWith(u8, endpoint, "http://")) {
        return endpoint["http://".len..];
    }
    return endpoint;
}

/// Sign an S3 request and return the Authorization header + required headers.
pub fn signRequest(
    allocator: Allocator,
    config: S3Config,
    method: []const u8, // "PUT", "GET", "HEAD", "DELETE"
    path: []const u8, // "/<bucket>/<key>"
    query: []const u8, // "" or "list-type=2&prefix=refs/"
    payload: []const u8, // request body (empty string for GET)
    timestamp: i64, // Unix timestamp
) !SignedRequest {
    // 1. Compute payload hash
    const payload_hash = sha256Hex(payload);

    // 2. Compute date strings
    const date = formatDate(timestamp);
    const datetime = formatIso8601(timestamp);

    // 3. Parse host from endpoint
    const host = parseHost(config.endpoint);

    // 4. Build canonical request
    // FORMAT:
    //   METHOD\n
    //   path\n
    //   query\n
    //   host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{datetime}\n\n
    //   host;x-amz-content-sha256;x-amz-date\n
    //   {payload_hash}
    const signed_headers = "host;x-amz-content-sha256;x-amz-date";
    const canonical_request = try std.fmt.allocPrint(allocator,
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
    defer allocator.free(canonical_request);

    // 5. Build string to sign
    const scope = try std.fmt.allocPrint(allocator, "{s}/{s}/s3/aws4_request", .{ &date, config.region });
    defer allocator.free(scope);

    const canonical_hash = sha256Hex(canonical_request);
    const string_to_sign = try std.fmt.allocPrint(allocator,
        \\AWS4-HMAC-SHA256
        \\{s}
        \\{s}
        \\{s}
    , .{
        &datetime,
        scope,
        &canonical_hash,
    });
    defer allocator.free(string_to_sign);

    // 6. Derive signing key
    const signing_key = deriveSigningKey(config.secret_access_key, &date, config.region);

    // 7. Compute signature
    const signature_bytes = hmacSha256(&signing_key, string_to_sign);
    const signature_hex = std.fmt.bytesToHex(signature_bytes, .lower);

    // 8. Build Authorization header
    const authorization = try std.fmt.allocPrint(
        allocator,
        "AWS4-HMAC-SHA256 Credential={s}/{s}, SignedHeaders={s}, Signature={s}",
        .{ config.access_key_id, scope, signed_headers, &signature_hex },
    );

    return SignedRequest{
        .authorization = authorization,
        .x_amz_date = datetime,
        .x_amz_content_sha256 = payload_hash,
        .allocator = allocator,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "format iso8601" {
    // 1711300000 = 2024-03-24 17:06:40 UTC
    const result = formatIso8601(1711300000);
    try std.testing.expectEqualStrings("20240324T170640Z", &result);
}

test "format date" {
    const result = formatDate(1711300000);
    try std.testing.expectEqualStrings("20240324", &result);
}

test "format iso8601 epoch" {
    const result = formatIso8601(0);
    try std.testing.expectEqualStrings("19700101T000000Z", &result);
}

test "format iso8601 y2k" {
    // 946684800 = 2000-01-01 00:00:00 UTC
    const result = formatIso8601(946684800);
    try std.testing.expectEqualStrings("20000101T000000Z", &result);
}

test "sha256 hex empty" {
    const result = sha256Hex("");
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        &result,
    );
}

test "sha256 hex hello" {
    // SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    const result = sha256Hex("hello");
    try std.testing.expectEqualStrings(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        &result,
    );
}

test "hmac sha256 known vector" {
    // HMAC-SHA256(key="key", msg="message")
    // = 6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a
    const result = hmacSha256("key", "message");
    const hex = std.fmt.bytesToHex(result, .lower);
    try std.testing.expectEqualStrings(
        "6e9ef29b75fffc5b7abae527d58fdadb2fe42e7219011976917343065f58ed4a",
        &hex,
    );
}

test "derive signing key" {
    // AWS Signature V4 signing key derivation for s3 service:
    // secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    // date = "20120215", region = "us-east-1", service = "s3"
    const signing_key = deriveSigningKey(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20120215",
        "us-east-1",
    );
    const hex = std.fmt.bytesToHex(signing_key, .lower);
    try std.testing.expectEqualStrings(
        "f22dfcb5da3bb8d6c924d26e9bb28e9f96ba691a1b1791d907c06f10ede94251",
        &hex,
    );
}

test "sign request put" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .endpoint = "https://abc123.r2.cloudflarestorage.com",
        .bucket = "mkit-storage",
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "auto",
    };

    var result = try signRequest(
        allocator,
        config,
        "PUT",
        "/mkit-storage/objects/abc123",
        "",
        "hello world",
        1711300000,
    );
    defer result.deinit();

    // Verify Authorization header starts with the correct prefix
    try std.testing.expect(std.mem.startsWith(u8, result.authorization, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240324/auto/s3/aws4_request"));

    // Verify it contains SignedHeaders and Signature
    try std.testing.expect(std.mem.indexOf(u8, result.authorization, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.authorization, "Signature=") != null);

    // Verify date header
    try std.testing.expectEqualStrings("20240324T170640Z", &result.x_amz_date);

    // Verify content hash is SHA256 of "hello world"
    const expected_hash = sha256Hex("hello world");
    try std.testing.expectEqualStrings(&expected_hash, &result.x_amz_content_sha256);
}

test "sign request get" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .endpoint = "https://abc123.r2.cloudflarestorage.com",
        .bucket = "mkit-storage",
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "auto",
    };

    var result = try signRequest(
        allocator,
        config,
        "GET",
        "/mkit-storage/objects/abc123",
        "",
        "", // GET has empty payload
        1711300000,
    );
    defer result.deinit();

    // content-sha256 should be hash of empty string
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        &result.x_amz_content_sha256,
    );

    // Authorization header should start with AWS4-HMAC-SHA256
    try std.testing.expect(std.mem.startsWith(u8, result.authorization, "AWS4-HMAC-SHA256 Credential="));
}

test "parse host from endpoint" {
    try std.testing.expectEqualStrings(
        "abc.r2.cloudflarestorage.com",
        parseHost("https://abc.r2.cloudflarestorage.com"),
    );
    try std.testing.expectEqualStrings(
        "abc.r2.cloudflarestorage.com",
        parseHost("http://abc.r2.cloudflarestorage.com"),
    );
    try std.testing.expectEqualStrings(
        "localhost:9000",
        parseHost("localhost:9000"),
    );
}

test "sign request deterministic" {
    // Two calls with identical inputs must produce identical output
    const allocator = std.testing.allocator;

    const config = S3Config{
        .endpoint = "https://abc123.r2.cloudflarestorage.com",
        .bucket = "mkit-storage",
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "auto",
    };

    var r1 = try signRequest(allocator, config, "PUT", "/mkit-storage/obj", "", "data", 1711300000);
    defer r1.deinit();

    var r2 = try signRequest(allocator, config, "PUT", "/mkit-storage/obj", "", "data", 1711300000);
    defer r2.deinit();

    try std.testing.expectEqualStrings(r1.authorization, r2.authorization);
    try std.testing.expectEqual(r1.x_amz_date, r2.x_amz_date);
    try std.testing.expectEqual(r1.x_amz_content_sha256, r2.x_amz_content_sha256);
}

test "sign request with query string" {
    const allocator = std.testing.allocator;

    const config = S3Config{
        .endpoint = "https://abc123.r2.cloudflarestorage.com",
        .bucket = "mkit-storage",
        .access_key_id = "AKIAIOSFODNN7EXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "auto",
    };

    // With query string should produce different signature than without
    var with_query = try signRequest(allocator, config, "GET", "/mkit-storage/", "list-type=2&prefix=refs/", "", 1711300000);
    defer with_query.deinit();

    var without_query = try signRequest(allocator, config, "GET", "/mkit-storage/", "", "", 1711300000);
    defer without_query.deinit();

    // Same dates
    try std.testing.expectEqual(with_query.x_amz_date, without_query.x_amz_date);

    // Different signatures (query changes canonical request)
    try std.testing.expect(!std.mem.eql(u8, with_query.authorization, without_query.authorization));
}

test "format iso8601 leap year 2024-02-29" {
    // 2024-02-29 00:00:00 UTC = 1709164800
    const result = formatIso8601(1709164800);
    try std.testing.expectEqualStrings("20240229T000000Z", &result);
}

test "format iso8601 end of year" {
    // 2023-12-31 23:59:59 UTC = 1704067199
    const result = formatIso8601(1704067199);
    try std.testing.expectEqualStrings("20231231T235959Z", &result);
}
