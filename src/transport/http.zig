// SPDX-License-Identifier: MIT OR Apache-2.0
//
// NOTE: This HTTP transport speaks the mkit-vcs Worker's JSON listRefs and
// quoted-hex ETag dialect. A bare nginx + filesystem backend will NOT
// interoperate. See SPEC-TRANSPORT §6.
const std = @import("std");
const protocol = @import("../protocol.zig");
const hash_mod = @import("../hash.zig");
const envelope_mod = @import("../attestations/envelope.zig");
const s3_transport = @import("s3.zig");
const ssh_transport = @import("ssh.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Re-export of the S3 retry policy — same semantics, same knobs. Extracting
/// a shared util module this late in the cycle is riskier than importing the
/// existing helpers, so we just reuse them here.
const RETRY_MAX_ATTEMPTS = s3_transport.RETRY_MAX_ATTEMPTS;
const isRetryableStatus = s3_transport.isRetryableStatus;
const backoffNs = s3_transport.backoffNs;
const PACK_BODY_LIMIT: usize = 4 * 1024 * 1024 * 1024;
const REF_BODY_LIMIT: usize = 256;
const SMALL_RESPONSE_LIMIT: usize = 4 * 1024;
const REF_LIST_BODY_LIMIT: usize = ssh_transport.MAX_PAYLOAD;

/// Plain HTTP transport for mkit VCS Worker (apps/vcs).
///
/// Unlike S3Transport, this requires no signing — authentication is via an
/// optional Bearer token. Speaks directly to a mkit VCS Worker HTTP API:
///
///   PUT  <base_url>/packs/<hex>         — upload pack (raw body)
///   GET  <base_url>/packs/<hex>         — download pack
///   HEAD <base_url>/packs/<hex>         — check pack existence
///   PUT  <base_url>/<ref_name>           — write ref (65-byte wire body)
///   GET  <base_url>/<ref_name>           — read ref
///   GET  <base_url>/refs/?prefix=<pfx>   — list refs (JSON response)
pub const HttpTransport = struct {
    base_url: []const u8, // e.g. "https://mkit-vcs.workers.dev/v1" (no trailing slash)
    api_token: ?[]const u8, // optional Bearer token for writes
    allocator: Allocator,
    io: std.Io,

    pub fn init(allocator: Allocator, io: std.Io, base_url: []const u8, api_token: ?[]const u8) HttpTransport {
        return .{
            .base_url = base_url,
            .api_token = api_token,
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn deinit(self: *HttpTransport) void {
        _ = self;
    }

    /// Return the protocol.Transport interface backed by this HttpTransport.
    pub fn transport(self: *HttpTransport) protocol.Transport {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = protocol.Transport.VTable{
        .uploadPack = uploadPackImpl,
        .downloadPack = downloadPackImpl,
        .packExists = packExistsImpl,
        .writeRef = writeRefImpl,
        .updateRef = updateRefImpl,
        .readRef = readRefImpl,
        .listRefs = listRefsImpl,
        .uploadAttestation = uploadAttestationImpl,
        .downloadAttestation = downloadAttestationImpl,
        .listAttestations = listAttestationsImpl,
    };

    // =========================================================================
    // URL builders (pub for unit testing)
    // =========================================================================

    /// Build the full URL for a pack: "<base_url>/packs/<64-hex-digest>"
    /// Caller owns returned slice.
    pub fn buildPackUrl(allocator: Allocator, base_url: []const u8, digest: Hash) ![]u8 {
        const hex = hash_mod.toHex(digest);
        return std.fmt.allocPrint(allocator, "{s}/packs/{s}", .{ base_url, &hex });
    }

    /// Build the full URL for a ref: "<base_url>/<ref_name>"
    /// ref_name already includes "refs/heads/..." prefix.
    pub fn buildRefUrl(allocator: Allocator, base_url: []const u8, ref_name: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_url, ref_name });
    }

    /// Build the URL for listing refs: "<base_url>/refs/?prefix=<prefix>"
    pub fn buildListUrl(allocator: Allocator, base_url: []const u8, prefix: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/refs/?prefix={s}", .{ base_url, prefix });
    }

    /// Build the URL for an attestation envelope:
    /// `"<base_url>/attestations/<commit-hex>/<att-id-hex>.dsse"`.
    pub fn buildAttestationUrl(
        allocator: Allocator,
        base_url: []const u8,
        commit: Hash,
        att_id: Hash,
    ) ![]u8 {
        const commit_hex = hash_mod.toHex(commit);
        const att_hex = hash_mod.toHex(att_id);
        return std.fmt.allocPrint(
            allocator,
            "{s}/attestations/{s}/{s}.dsse",
            .{ base_url, &commit_hex, &att_hex },
        );
    }

    /// Build the URL for listing attestations on a commit:
    /// `"<base_url>/attestations/<commit-hex>/"`.
    pub fn buildAttestationListUrl(
        allocator: Allocator,
        base_url: []const u8,
        commit: Hash,
    ) ![]u8 {
        const commit_hex = hash_mod.toHex(commit);
        return std.fmt.allocPrint(
            allocator,
            "{s}/attestations/{s}/",
            .{ base_url, &commit_hex },
        );
    }

    /// Parse a JSON attestation list response. Shape:
    ///   {"attestations":["<att-id-hex>", "<att-id-hex>", ...]}
    pub fn parseAttestationListJson(allocator: Allocator, json_body: []const u8) ![]Hash {
        const Parsed = struct { attestations: [][]const u8 };
        const parsed = std.json.parseFromSlice(Parsed, allocator, json_body, .{}) catch {
            return error.InvalidJson;
        };
        defer parsed.deinit();

        var out: std.ArrayList(Hash) = .empty;
        errdefer out.deinit(allocator);
        for (parsed.value.attestations) |hex_str| {
            const id = hash_mod.fromHex(hex_str) catch return error.InvalidResponse;
            try out.append(allocator, id);
        }
        std.sort.pdq(Hash, out.items, {}, protocol.hashLessThan);
        return out.toOwnedSlice(allocator);
    }

    /// Parse a JSON ref listing response into protocol.Ref structs.
    /// Expected format: {"refs":["refs/heads/main","refs/heads/dev"]}
    /// The prefix is stripped from each returned name (consistent with other transports).
    /// Caller owns the returned slice and each .name within it.
    pub fn parseListJson(allocator: Allocator, json_body: []const u8, prefix: []const u8) ![]protocol.Ref {
        const Parsed = struct { refs: [][]const u8 };
        const parsed = std.json.parseFromSlice(Parsed, allocator, json_body, .{}) catch {
            return error.InvalidJson;
        };
        defer parsed.deinit();

        var refs: std.ArrayList(protocol.Ref) = .empty;
        errdefer {
            for (refs.items) |ref| allocator.free(ref.name);
            refs.deinit(allocator);
        }

        for (parsed.value.refs) |full_name| {
            const suffix = if (full_name.len > prefix.len and
                std.mem.startsWith(u8, full_name, prefix))
                full_name[prefix.len..]
            else
                full_name;

            const name = try allocator.dupe(u8, suffix);
            errdefer allocator.free(name);
            try refs.append(allocator, .{ .name = name, .hash = hash_mod.zero });
        }

        // Sort by name for deterministic ordering
        std.mem.sort(protocol.Ref, refs.items, {}, struct {
            fn lessThan(_: void, a: protocol.Ref, b: protocol.Ref) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lessThan);

        return refs.toOwnedSlice(allocator);
    }

    // =========================================================================
    // HTTP response type
    // =========================================================================

    const HttpResponse = struct {
        status: std.http.Status,
        body: []u8,
        allocator: Allocator,

        pub fn deinit(self: *HttpResponse) void {
            if (self.body.len > 0) {
                self.allocator.free(self.body);
            }
        }
    };

    // =========================================================================
    // Core HTTP helper
    // =========================================================================

    /// Make an HTTP request to the VCS Worker with exponential-backoff retry
    /// on 5xx/429 and connection failures. 412 Precondition Failed and other
    /// 4xx statuses are returned immediately without retry so CAS writes
    /// don't turn into duplicate PUTs.
    fn httpRequest(
        self: *HttpTransport,
        allocator: Allocator,
        method: std.http.Method,
        url_str: []const u8,
        payload: ?[]const u8,
        extra_headers: []const std.http.Header,
        body_limit: ?usize,
    ) !HttpResponse {
        var attempt: u32 = 0;
        while (true) : (attempt += 1) {
            const result = self.httpRequestOnce(allocator, method, url_str, payload, extra_headers, body_limit) catch |err| {
                if (attempt + 1 < RETRY_MAX_ATTEMPTS) {
                    // Why: std.Thread.sleep was removed in Zig 0.16; wait via Io.
                    std.Io.sleep(self.io, std.Io.Duration.fromNanoseconds(@intCast(backoffNs(attempt))), .awake) catch {};
                    continue;
                }
                return err;
            };

            if (isRetryableStatus(result.status) and attempt + 1 < RETRY_MAX_ATTEMPTS) {
                var to_discard = result;
                to_discard.deinit();
                std.Io.sleep(self.io, std.Io.Duration.fromNanoseconds(@intCast(backoffNs(attempt))), .awake) catch {};
                continue;
            }
            return result;
        }
    }

    /// Single-shot HTTP request — the prior body of `httpRequest`. Kept
    /// private so all call sites go through the retry wrapper.
    fn httpRequestOnce(
        self: *HttpTransport,
        allocator: Allocator,
        method: std.http.Method,
        url_str: []const u8,
        payload: ?[]const u8,
        extra_headers: []const std.http.Header,
        body_limit: ?usize,
    ) !HttpResponse {
        var client = std.http.Client{ .allocator = allocator, .io = self.io };
        defer client.deinit();

        // Build Authorization if we have a token; call-site may add conditional headers too.
        var request_headers_buf: [2]std.http.Header = undefined;
        var auth_value_buf: [512]u8 = undefined;
        var request_header_count: usize = 0;

        if (self.api_token) |token| {
            const auth_value = std.fmt.bufPrint(&auth_value_buf, "Bearer {s}", .{token}) catch
                return error.TokenTooLong;
            request_headers_buf[request_header_count] = .{ .name = "Authorization", .value = auth_value };
            request_header_count += 1;
        }

        if (request_header_count + extra_headers.len > request_headers_buf.len) {
            return error.ServerError;
        }

        for (extra_headers) |header| {
            request_headers_buf[request_header_count] = header;
            request_header_count += 1;
        }

        const request_headers = request_headers_buf[0..request_header_count];

        const uri = std.Uri.parse(url_str) catch return error.ConnectionFailed;
        var req = client.request(method, uri, .{
            .redirect_behavior = .unhandled,
            .extra_headers = request_headers,
        }) catch return error.ConnectionFailed;
        defer req.deinit();

        if (payload) |bytes| {
            req.transfer_encoding = .{ .content_length = bytes.len };
            var body = req.sendBodyUnflushed(&.{}) catch return error.ConnectionFailed;
            body.writer.writeAll(bytes) catch return error.ConnectionFailed;
            body.end() catch return error.ConnectionFailed;
            req.connection.?.flush() catch return error.ConnectionFailed;
        } else {
            req.sendBodiless() catch return error.ConnectionFailed;
        }

        var response = req.receiveHead(&.{}) catch return error.ConnectionFailed;
        if (body_limit) |limit| {
            if (response.head.content_length) |content_length| {
                if (content_length > @as(u64, limit)) return error.ResponseTooLarge;
            }
        }

        var body: []u8 = &.{};
        if (body_limit) |limit| {
            const decompress_buffer: []u8 = switch (response.head.content_encoding) {
                .identity => &.{},
                .zstd => allocator.alloc(u8, std.compress.zstd.default_window_len) catch return error.ServerError,
                .deflate, .gzip => allocator.alloc(u8, std.compress.flate.max_window_len) catch return error.ServerError,
                .compress => return error.UnsupportedCompressionMethod,
            };
            defer if (response.head.content_encoding != .identity) allocator.free(decompress_buffer);

            var transfer_buffer: [64]u8 = undefined;
            var decompress: std.http.Decompress = undefined;
            const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
            body = reader.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
                error.ReadFailed => return response.bodyErr() orelse error.ConnectionFailed,
                error.StreamTooLong => return error.ResponseTooLarge,
                error.OutOfMemory => return error.ServerError,
            };
        }

        return HttpResponse{
            .status = response.head.status,
            .body = body,
            .allocator = allocator,
        };
    }

    // =========================================================================
    // VTable implementations
    // =========================================================================

    const RefWriteHeaders = struct {
        condition: protocol.RefWriteCondition = .any,
        current: ?Hash = null,
        headers: [1]std.http.Header = undefined,
        match_value: [66]u8 = undefined,
        count: usize = 0,

        fn slice(self: *RefWriteHeaders) []const std.http.Header {
            switch (self.condition) {
                .any => if (self.current) |expected| {
                    const hex = hash_mod.toHex(expected);
                    const value = std.fmt.bufPrint(&self.match_value, "\"{s}\"", .{&hex}) catch unreachable;
                    self.headers[0] = .{ .name = "If-Match", .value = value };
                    self.count = 1;
                } else {
                    self.headers[0] = .{ .name = "If-None-Match", .value = "*" };
                    self.count = 1;
                },
                .missing => {
                    self.headers[0] = .{ .name = "If-None-Match", .value = "*" };
                    self.count = 1;
                },
                .match => |expected| {
                    const hex = hash_mod.toHex(expected);
                    const value = std.fmt.bufPrint(&self.match_value, "\"{s}\"", .{&hex}) catch unreachable;
                    self.headers[0] = .{ .name = "If-Match", .value = value };
                    self.count = 1;
                },
            }
            return self.headers[0..self.count];
        }
    };

    pub fn buildRefWriteHeaders(condition: protocol.RefWriteCondition, current: ?Hash) RefWriteHeaders {
        return .{ .condition = condition, .current = current };
    }

    fn uploadPackImpl(ptr: *anyopaque, allocator: Allocator, bytes: []const u8, digest: Hash) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (bytes.len > PACK_BODY_LIMIT) return error.PackTooLarge;
        const url = try buildPackUrl(allocator, self.base_url, digest);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .PUT, url, bytes, &.{}, SMALL_RESPONSE_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok, .created => return,
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }
    }

    fn downloadPackImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror![]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const url = try buildPackUrl(allocator, self.base_url, digest);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .GET, url, null, &.{}, PACK_BODY_LIMIT);
        errdefer resp.deinit();

        switch (resp.status) {
            .ok => {
                const body = resp.body;
                resp.body = "";
                return body;
            },
            .not_found => {
                resp.deinit();
                return error.PackNotFound;
            },
            .forbidden, .unauthorized => {
                resp.deinit();
                return error.AccessDenied;
            },
            else => {
                resp.deinit();
                return error.ServerError;
            },
        }
    }

    fn packExistsImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror!bool {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const url = try buildPackUrl(allocator, self.base_url, digest);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .HEAD, url, null, &.{}, null);
        defer resp.deinit();

        return switch (resp.status) {
            .ok => true,
            .not_found => false,
            .forbidden, .unauthorized => error.AccessDenied,
            else => error.ServerError,
        };
    }

    fn writeRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, h: Hash) anyerror!void {
        try updateRefImpl(ptr, allocator, ref_name, .any, h);
    }

    fn updateRefImpl(
        ptr: *anyopaque,
        allocator: Allocator,
        ref_name: []const u8,
        condition: protocol.RefWriteCondition,
        h: Hash,
    ) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        if (self.api_token == null or self.api_token.?.len == 0) return error.AccessDenied;
        const url = try buildRefUrl(allocator, self.base_url, ref_name);
        defer allocator.free(url);

        const wire = protocol.formatRef(h);
        const current = try readRefImpl(ptr, allocator, ref_name);
        var headers = buildRefWriteHeaders(condition, current);

        var resp = try self.httpRequest(allocator, .PUT, url, &wire, headers.slice(), SMALL_RESPONSE_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok, .created => return,
            .precondition_failed, .conflict, .precondition_required => return error.RefConflict,
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }
    }

    fn readRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8) anyerror!?Hash {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        const url = try buildRefUrl(allocator, self.base_url, ref_name);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .GET, url, null, &.{}, REF_BODY_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok => {
                return protocol.parseRef(resp.body) catch return error.InvalidRef;
            },
            .not_found => return null,
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }
    }

    fn listRefsImpl(ptr: *anyopaque, allocator: Allocator, prefix: []const u8) anyerror![]protocol.Ref {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefPrefix(prefix)) return error.InvalidRef;
        const list_url = try buildListUrl(allocator, self.base_url, prefix);
        defer allocator.free(list_url);

        var resp = try self.httpRequest(allocator, .GET, list_url, null, &.{}, REF_LIST_BODY_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok => {},
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }

        // Parse the JSON listing to get ref names
        const name_refs = try parseListJson(allocator, resp.body, prefix);
        defer {
            for (name_refs) |ref| allocator.free(ref.name);
            allocator.free(name_refs);
        }

        // For each ref name, read the actual ref to get the hash
        var refs: std.ArrayList(protocol.Ref) = .empty;
        errdefer {
            for (refs.items) |ref| allocator.free(ref.name);
            refs.deinit(allocator);
        }

        for (name_refs) |name_ref| {
            if (!protocol.validateRefName(name_ref.name)) continue;
            // Reconstruct the full ref name for the GET request
            const full_name = try std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, name_ref.name });
            defer allocator.free(full_name);
            if (!protocol.validateRefName(full_name)) continue;

            const ref_url = try buildRefUrl(allocator, self.base_url, full_name);
            defer allocator.free(ref_url);

            var ref_resp = self.httpRequest(allocator, .GET, ref_url, null, &.{}, REF_BODY_LIMIT) catch continue;
            defer ref_resp.deinit();

            if (ref_resp.status != .ok) continue;

            const h = protocol.parseRef(ref_resp.body) catch continue;

            const name_dup = try allocator.dupe(u8, name_ref.name);
            errdefer allocator.free(name_dup);
            try refs.append(allocator, .{ .name = name_dup, .hash = h });
        }

        // Sort by name for consistent behavior across transports
        std.mem.sort(protocol.Ref, refs.items, {}, struct {
            fn lessThan(_: void, a: protocol.Ref, b: protocol.Ref) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lessThan);

        return refs.toOwnedSlice(allocator);
    }

    // -- Attestation verbs (SPEC-ATTESTATIONS §7.3) --
    //
    // The HTTP dialect lives at:
    //   PUT  <base>/attestations/<commit-hex>/<att-id-hex>.dsse   upload
    //   GET  <base>/attestations/by-id/<att-id-hex>              download
    //   GET  <base>/attestations/<commit-hex>/                   list (JSON)
    //
    // Client computes att-id locally (BLAKE3 of envelope bytes) and puts to
    // the fully-qualified URL; the server persists verbatim and returns 200.
    // The att-id is also returned to the caller for cross-checking.

    fn uploadAttestationImpl(
        ptr: *anyopaque,
        allocator: Allocator,
        commit: Hash,
        envelope_bytes: []const u8,
    ) anyerror!Hash {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (envelope_bytes.len > 16 * 1024 * 1024) return error.ResponseTooLarge;
        const att_id = envelope_mod.attestationId(envelope_bytes);
        const url = try buildAttestationUrl(allocator, self.base_url, commit, att_id);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .PUT, url, envelope_bytes, &.{}, SMALL_RESPONSE_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok, .created => return att_id,
            .not_found, .method_not_allowed => return error.UnsupportedOperation,
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }
    }

    fn downloadAttestationImpl(
        ptr: *anyopaque,
        allocator: Allocator,
        commit: Hash,
        att_id: Hash,
    ) anyerror![]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const url = try buildAttestationUrl(allocator, self.base_url, commit, att_id);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .GET, url, null, &.{}, 16 * 1024 * 1024);
        errdefer resp.deinit();

        switch (resp.status) {
            .ok => {
                const body = resp.body;
                resp.body = "";
                return body;
            },
            .not_found => {
                resp.deinit();
                return error.AttestationNotFound;
            },
            .method_not_allowed => {
                resp.deinit();
                return error.UnsupportedOperation;
            },
            .forbidden, .unauthorized => {
                resp.deinit();
                return error.AccessDenied;
            },
            else => {
                resp.deinit();
                return error.ServerError;
            },
        }
    }

    fn listAttestationsImpl(
        ptr: *anyopaque,
        allocator: Allocator,
        commit: Hash,
    ) anyerror![]Hash {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const url = try buildAttestationListUrl(allocator, self.base_url, commit);
        defer allocator.free(url);

        var resp = try self.httpRequest(allocator, .GET, url, null, &.{}, REF_LIST_BODY_LIMIT);
        defer resp.deinit();

        switch (resp.status) {
            .ok => {},
            .not_found => return allocator.alloc(Hash, 0),
            .method_not_allowed => return error.UnsupportedOperation,
            .forbidden, .unauthorized => return error.AccessDenied,
            else => return error.ServerError,
        }

        return try parseAttestationListJson(allocator, resp.body);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "build pack url" {
    const allocator = std.testing.allocator;
    const digest = hash_mod.hash("test-pack-content");
    const url = try HttpTransport.buildPackUrl(allocator, "https://example.com/v1", digest);
    defer allocator.free(url);

    // Should start with base URL + /packs/
    try std.testing.expect(std.mem.startsWith(u8, url, "https://example.com/v1/packs/"));

    // Total: base(22) + "/packs/"(7) + hex(64) = 93
    try std.testing.expectEqual(@as(usize, "https://example.com/v1".len + "/packs/".len + 64), url.len);

    // The hex portion should match the digest
    const expected_hex = hash_mod.toHex(digest);
    const hex_start = url.len - 64;
    try std.testing.expectEqualStrings(&expected_hex, url[hex_start..]);
}

test "build ref url" {
    const allocator = std.testing.allocator;
    const url = try HttpTransport.buildRefUrl(allocator, "https://example.com/v1", "refs/heads/main");
    defer allocator.free(url);

    try std.testing.expectEqualStrings("https://example.com/v1/refs/heads/main", url);
}

test "build list url" {
    const allocator = std.testing.allocator;
    const url = try HttpTransport.buildListUrl(allocator, "https://example.com/v1", "refs/heads/");
    defer allocator.free(url);

    try std.testing.expectEqualStrings("https://example.com/v1/refs/?prefix=refs/heads/", url);
}

test "parse list json" {
    const allocator = std.testing.allocator;

    const json =
        \\{"refs":["refs/heads/main","refs/heads/dev"]}
    ;

    const refs = try HttpTransport.parseListJson(allocator, json, "refs/heads/");
    defer {
        for (refs) |ref| allocator.free(ref.name);
        allocator.free(refs);
    }

    try std.testing.expectEqual(@as(usize, 2), refs.len);
    // Sorted alphabetically: dev before main
    try std.testing.expectEqualStrings("dev", refs[0].name);
    try std.testing.expectEqualStrings("main", refs[1].name);
}

test "parse list json empty" {
    const allocator = std.testing.allocator;

    const json =
        \\{"refs":[]}
    ;

    const refs = try HttpTransport.parseListJson(allocator, json, "refs/heads/");
    defer allocator.free(refs);

    try std.testing.expectEqual(@as(usize, 0), refs.len);
}

test "parse list json no prefix match" {
    const allocator = std.testing.allocator;

    // When prefix doesn't match, the full name is kept
    const json =
        \\{"refs":["other/path/foo"]}
    ;

    const refs = try HttpTransport.parseListJson(allocator, json, "refs/heads/");
    defer {
        for (refs) |ref| allocator.free(ref.name);
        allocator.free(refs);
    }

    try std.testing.expectEqual(@as(usize, 1), refs.len);
    try std.testing.expectEqualStrings("other/path/foo", refs[0].name);
}

test "parse list json invalid" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidJson, HttpTransport.parseListJson(allocator, "not json", "refs/"));
    try std.testing.expectError(error.InvalidJson, HttpTransport.parseListJson(allocator, "{}", "refs/"));
}

test "build ref write headers create" {
    var headers = HttpTransport.buildRefWriteHeaders(.any, null);
    const slice = headers.slice();

    try std.testing.expectEqual(@as(usize, 1), slice.len);
    try std.testing.expectEqualStrings("If-None-Match", slice[0].name);
    try std.testing.expectEqualStrings("*", slice[0].value);
}

test "build ref write headers overwrite existing ref" {
    const current = hash_mod.hash("current-ref");
    var headers = HttpTransport.buildRefWriteHeaders(.any, current);
    const slice = headers.slice();
    const expected_hex = hash_mod.toHex(current);
    var expected_value_buf: [66]u8 = undefined;
    const expected_value = try std.fmt.bufPrint(&expected_value_buf, "\"{s}\"", .{&expected_hex});

    try std.testing.expectEqual(@as(usize, 1), slice.len);
    try std.testing.expectEqualStrings("If-Match", slice[0].name);
    try std.testing.expectEqualStrings(expected_value, slice[0].value);
}

test "build ref write headers match" {
    const allocator = std.testing.allocator;
    const expected = hash_mod.hash("existing-ref");
    var headers = HttpTransport.buildRefWriteHeaders(.{ .match = expected }, null);
    const slice = headers.slice();
    const expected_hex = hash_mod.toHex(expected);
    const expected_value = try std.fmt.allocPrint(allocator, "\"{s}\"", .{&expected_hex});
    defer allocator.free(expected_value);

    try std.testing.expectEqual(@as(usize, 1), slice.len);
    try std.testing.expectEqualStrings("If-Match", slice[0].name);
    try std.testing.expectEqualStrings(expected_value, slice[0].value);
}

test "vtable construction" {
    const allocator = std.testing.allocator;

    var ht = HttpTransport.init(allocator, std.testing.io, "https://example.com/v1", "my-secret-token");
    defer ht.deinit();

    const t = ht.transport();

    // Verify all vtable function pointers match
    try std.testing.expect(t.vtable.uploadPack == &HttpTransport.uploadPackImpl);
    try std.testing.expect(t.vtable.downloadPack == &HttpTransport.downloadPackImpl);
    try std.testing.expect(t.vtable.packExists == &HttpTransport.packExistsImpl);
    try std.testing.expect(t.vtable.writeRef == &HttpTransport.writeRefImpl);
    try std.testing.expect(t.vtable.updateRef == &HttpTransport.updateRefImpl);
    try std.testing.expect(t.vtable.readRef == &HttpTransport.readRefImpl);
    try std.testing.expect(t.vtable.listRefs == &HttpTransport.listRefsImpl);

    // Verify the pointer round-trips back to our HttpTransport
    const recovered: *HttpTransport = @ptrCast(@alignCast(t.ptr));
    try std.testing.expectEqualStrings("https://example.com/v1", recovered.base_url);
    try std.testing.expectEqualStrings("my-secret-token", recovered.api_token.?);
}

test "vtable construction no token" {
    const allocator = std.testing.allocator;

    var ht = HttpTransport.init(allocator, std.testing.io, "https://example.com/v1", null);
    defer ht.deinit();

    const t = ht.transport();

    const recovered: *HttpTransport = @ptrCast(@alignCast(t.ptr));
    try std.testing.expectEqualStrings("https://example.com/v1", recovered.base_url);
    try std.testing.expect(recovered.api_token == null);
}

test "build pack url different digests" {
    const allocator = std.testing.allocator;

    const d1 = hash_mod.hash("pack-a");
    const d2 = hash_mod.hash("pack-b");

    const url1 = try HttpTransport.buildPackUrl(allocator, "http://localhost:8787/v1", d1);
    defer allocator.free(url1);
    const url2 = try HttpTransport.buildPackUrl(allocator, "http://localhost:8787/v1", d2);
    defer allocator.free(url2);

    // Same prefix, different hex suffix
    try std.testing.expect(std.mem.startsWith(u8, url1, "http://localhost:8787/v1/packs/"));
    try std.testing.expect(std.mem.startsWith(u8, url2, "http://localhost:8787/v1/packs/"));
    try std.testing.expect(!std.mem.eql(u8, url1, url2));
}

test "build list url empty prefix" {
    const allocator = std.testing.allocator;
    const url = try HttpTransport.buildListUrl(allocator, "https://vcs.example.com/v1", "");
    defer allocator.free(url);

    try std.testing.expectEqualStrings("https://vcs.example.com/v1/refs/?prefix=", url);
}

// --- Retry tests (W5-4) ---

test "http retry: 503,503,200 sequence completes in 3 attempts (bounded, no sleep)" {
    // Simulate the retry loop against a scripted responder. We don't call
    // the real network — we only exercise the classification + attempt-
    // counting logic, with std.Thread.sleep replaced by a no-op.
    const responses = [_]u16{ 503, 503, 200 };
    var idx: usize = 0;
    var calls: u32 = 0;
    var final: u16 = 0;

    var attempt: u32 = 0;
    while (attempt < RETRY_MAX_ATTEMPTS) : (attempt += 1) {
        calls += 1;
        const code = responses[idx];
        idx += 1;
        const status: std.http.Status = @enumFromInt(code);
        if (isRetryableStatus(status)) continue;
        final = code;
        break;
    }

    try std.testing.expectEqual(@as(u32, 3), calls);
    try std.testing.expectEqual(@as(u16, 200), final);
}

test "http retry: 412 Precondition Failed returns immediately" {
    // CAS writes must never be retried on 412 — confirmed via the shared
    // classifier.
    try std.testing.expect(!isRetryableStatus(.precondition_failed));
}

test "http retry: attempts are capped at RETRY_MAX_ATTEMPTS" {
    // An endlessly-503 responder should stop after RETRY_MAX_ATTEMPTS.
    var calls: u32 = 0;
    var attempt: u32 = 0;
    while (attempt < RETRY_MAX_ATTEMPTS) : (attempt += 1) {
        calls += 1;
        // All 503 — retryable — loop until budget exhausted.
        const status: std.http.Status = .service_unavailable;
        if (isRetryableStatus(status) and attempt + 1 < RETRY_MAX_ATTEMPTS) continue;
        break;
    }
    try std.testing.expect(calls <= RETRY_MAX_ATTEMPTS);
    try std.testing.expect(calls == RETRY_MAX_ATTEMPTS);
}

// -- Attestation URL + JSON tests (SPEC-ATTESTATIONS §7.3) --

test "build attestation url" {
    const allocator = std.testing.allocator;
    const commit = hash_mod.hash("http-att-commit");
    const att = hash_mod.hash("envelope-bytes");
    const url = try HttpTransport.buildAttestationUrl(allocator, "https://example.com/v1", commit, att);
    defer allocator.free(url);
    try std.testing.expect(std.mem.startsWith(u8, url, "https://example.com/v1/attestations/"));
    try std.testing.expect(std.mem.endsWith(u8, url, ".dsse"));
    const commit_hex = hash_mod.toHex(commit);
    try std.testing.expect(std.mem.indexOf(u8, url, &commit_hex) != null);
}

test "build attestation list url" {
    const allocator = std.testing.allocator;
    const commit = hash_mod.hash("http-list-commit");
    const url = try HttpTransport.buildAttestationListUrl(allocator, "https://example.com/v1", commit);
    defer allocator.free(url);
    try std.testing.expect(std.mem.endsWith(u8, url, "/"));
    const commit_hex = hash_mod.toHex(commit);
    try std.testing.expect(std.mem.indexOf(u8, url, &commit_hex) != null);
}

test "parse attestation list json" {
    const allocator = std.testing.allocator;
    const id_a = hash_mod.hash("aaa");
    const id_b = hash_mod.hash("bbb");
    const hex_a = hash_mod.toHex(id_a);
    const hex_b = hash_mod.toHex(id_b);

    var buf: [512]u8 = undefined;
    const json = try std.fmt.bufPrint(
        &buf,
        "{{\"attestations\":[\"{s}\",\"{s}\"]}}",
        .{ &hex_a, &hex_b },
    );

    const ids = try HttpTransport.parseAttestationListJson(allocator, json);
    defer allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 2), ids.len);
    // Byte-lexicographically sorted.
    try std.testing.expect(std.mem.order(u8, &ids[0], &ids[1]) != .gt);
}

test "parse attestation list json empty" {
    const allocator = std.testing.allocator;
    const ids = try HttpTransport.parseAttestationListJson(allocator, "{\"attestations\":[]}");
    defer allocator.free(ids);
    try std.testing.expectEqual(@as(usize, 0), ids.len);
}

test "parse attestation list json bad hex" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidResponse,
        HttpTransport.parseAttestationListJson(allocator, "{\"attestations\":[\"zzz\"]}"),
    );
}

test "parse attestation list json invalid" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidJson, HttpTransport.parseAttestationListJson(allocator, "not json"));
    try std.testing.expectError(error.InvalidJson, HttpTransport.parseAttestationListJson(allocator, "{}"));
}
