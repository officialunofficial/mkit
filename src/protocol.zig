// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// A remote ref: name + commit hash.
pub const Ref = struct {
    name: []const u8,
    hash: Hash,
};

pub const RefWriteCondition = union(enum) {
    any,
    missing,
    match: Hash,
};

/// The mkit transfer protocol interface.
/// Transports implement this vtable to provide remote storage for packfiles and refs.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        uploadPack: *const fn (ptr: *anyopaque, allocator: Allocator, bytes: []const u8, digest: Hash) anyerror!void,
        downloadPack: *const fn (ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror![]u8,
        packExists: *const fn (ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror!bool,
        writeRef: *const fn (ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, hash: Hash) anyerror!void,
        updateRef: *const fn (ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, condition: RefWriteCondition, hash: Hash) anyerror!void,
        readRef: *const fn (ptr: *anyopaque, allocator: Allocator, ref_name: []const u8) anyerror!?Hash,
        listRefs: *const fn (ptr: *anyopaque, allocator: Allocator, prefix: []const u8) anyerror![]Ref,
        // Attestation verbs (SPEC-ATTESTATIONS §7.3).
        //
        // `uploadAttestation` takes the commit hash + the serialised DSSE
        // envelope bytes, stores them keyed by `BLAKE3(envelope_bytes)`, and
        // returns the computed attestation id so the client can cross-check
        // against its own local BLAKE3 of the bytes.
        //
        // `downloadAttestation` fetches an envelope by (commit, att-id).
        // Both are required so transports can build a direct `O(1)` key
        // (`attestations/<commit-hex>/<att-id-hex>.dsse`) without scanning.
        //
        // `listAttestations` returns every attestation id currently stored
        // against the given commit, byte-lexicographically sorted. Unknown
        // commits return an empty slice, not an error.
        uploadAttestation: *const fn (ptr: *anyopaque, allocator: Allocator, commit: Hash, envelope_bytes: []const u8) anyerror!Hash,
        downloadAttestation: *const fn (ptr: *anyopaque, allocator: Allocator, commit: Hash, att_id: Hash) anyerror![]u8,
        listAttestations: *const fn (ptr: *anyopaque, allocator: Allocator, commit: Hash) anyerror![]Hash,
    };

    pub fn uploadPack(self: Transport, allocator: Allocator, bytes: []const u8, digest: Hash) !void {
        return self.vtable.uploadPack(self.ptr, allocator, bytes, digest);
    }

    pub fn downloadPack(self: Transport, allocator: Allocator, digest: Hash) ![]u8 {
        return self.vtable.downloadPack(self.ptr, allocator, digest);
    }

    pub fn packExists(self: Transport, allocator: Allocator, digest: Hash) !bool {
        return self.vtable.packExists(self.ptr, allocator, digest);
    }

    pub fn writeRef(self: Transport, allocator: Allocator, ref_name: []const u8, hash: Hash) !void {
        return self.vtable.writeRef(self.ptr, allocator, ref_name, hash);
    }

    pub fn updateRef(self: Transport, allocator: Allocator, ref_name: []const u8, condition: RefWriteCondition, hash: Hash) !void {
        return self.vtable.updateRef(self.ptr, allocator, ref_name, condition, hash);
    }

    pub fn readRef(self: Transport, allocator: Allocator, ref_name: []const u8) !?Hash {
        return self.vtable.readRef(self.ptr, allocator, ref_name);
    }

    pub fn listRefs(self: Transport, allocator: Allocator, prefix: []const u8) ![]Ref {
        return self.vtable.listRefs(self.ptr, allocator, prefix);
    }

    pub fn uploadAttestation(self: Transport, allocator: Allocator, commit: Hash, envelope_bytes: []const u8) !Hash {
        return self.vtable.uploadAttestation(self.ptr, allocator, commit, envelope_bytes);
    }

    pub fn downloadAttestation(self: Transport, allocator: Allocator, commit: Hash, att_id: Hash) ![]u8 {
        return self.vtable.downloadAttestation(self.ptr, allocator, commit, att_id);
    }

    pub fn listAttestations(self: Transport, allocator: Allocator, commit: Hash) ![]Hash {
        return self.vtable.listAttestations(self.ptr, allocator, commit);
    }
};

// -- Attestation path helpers --

pub const ATTESTATION_PREFIX = "attestations/";
pub const ATTESTATION_EXT = ".dsse";

/// Build the directory prefix for a commit's attestations:
/// `"attestations/<64-char commit hex>/"` (trailing slash included so it
/// doubles as an S3/list prefix).
pub fn attestationDirPrefix(commit: Hash) [ATTESTATION_PREFIX.len + 64 + 1]u8 {
    var buf: [ATTESTATION_PREFIX.len + 64 + 1]u8 = undefined;
    @memcpy(buf[0..ATTESTATION_PREFIX.len], ATTESTATION_PREFIX);
    const hex = hash_mod.toHex(commit);
    @memcpy(buf[ATTESTATION_PREFIX.len..][0..64], &hex);
    buf[ATTESTATION_PREFIX.len + 64] = '/';
    return buf;
}

/// Build the full object key for a single attestation:
/// `"attestations/<commit-hex>/<att-id-hex>.dsse"`.
pub fn attestationKey(commit: Hash, att_id: Hash) [ATTESTATION_PREFIX.len + 64 + 1 + 64 + ATTESTATION_EXT.len]u8 {
    var buf: [ATTESTATION_PREFIX.len + 64 + 1 + 64 + ATTESTATION_EXT.len]u8 = undefined;
    @memcpy(buf[0..ATTESTATION_PREFIX.len], ATTESTATION_PREFIX);
    const commit_hex = hash_mod.toHex(commit);
    @memcpy(buf[ATTESTATION_PREFIX.len..][0..64], &commit_hex);
    buf[ATTESTATION_PREFIX.len + 64] = '/';
    const att_hex = hash_mod.toHex(att_id);
    @memcpy(buf[ATTESTATION_PREFIX.len + 64 + 1 ..][0..64], &att_hex);
    @memcpy(buf[ATTESTATION_PREFIX.len + 64 + 1 + 64 ..][0..ATTESTATION_EXT.len], ATTESTATION_EXT);
    return buf;
}

/// Parse an attestation filename (`<att-id-hex>.dsse`) and return the att id.
/// Returns null if the name does not match the expected shape.
pub fn parseAttestationFilename(name: []const u8) ?Hash {
    if (name.len != 64 + ATTESTATION_EXT.len) return null;
    if (!std.mem.endsWith(u8, name, ATTESTATION_EXT)) return null;
    const hex = name[0..64];
    return hash_mod.fromHex(hex) catch null;
}

/// Byte-lexicographic `Hash` ordering for `std.sort.pdq`.
pub fn hashLessThan(_: void, a: Hash, b: Hash) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

// -- Wire format --

/// Format a hash as ref wire format: 64-char lowercase hex + newline (65 bytes).
pub fn formatRef(h: Hash) [65]u8 {
    var buf: [65]u8 = undefined;
    const hex = hash_mod.toHex(h);
    @memcpy(buf[0..64], &hex);
    buf[64] = '\n';
    return buf;
}

/// Parse ref wire format back to a Hash. Accepts optional trailing whitespace.
pub fn parseRef(data: []const u8) !Hash {
    const trimmed = std.mem.trimEnd(u8, data, "\n\r \t");
    if (trimmed.len != 64) return error.InvalidRef;
    return hash_mod.fromHex(trimmed) catch error.InvalidRef;
}

/// Validate a ref name is safe for filesystem and transport operations.
/// Rejects names containing ".." path traversal, null bytes, or leading "/".
pub fn validateRefName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '/') return false;
    // Reject ".." path components
    var parts = std.mem.splitScalar(u8, name, '/');
    while (parts.next()) |part| {
        if (part.len == 0) return false;
        if (std.mem.eql(u8, part, "..") or std.mem.eql(u8, part, ".")) return false;
        for (part) |c| {
            if (c == 0 or c == '\\') return false;
            if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) return false;
        }
    }
    return true;
}

/// Validate a ref prefix used for listings. Allows an optional trailing slash.
pub fn validateRefPrefix(prefix: []const u8) bool {
    if (prefix.len == 0) return true;
    const trimmed = std.mem.trimEnd(u8, prefix, "/");
    if (trimmed.len == 0) return false;
    return validateRefName(trimmed);
}

/// Build a pack key from a digest: "packs/<64-char hex>"
pub fn packKey(digest: Hash) [70]u8 {
    var buf: [70]u8 = undefined;
    @memcpy(buf[0..6], "packs/");
    const hex = hash_mod.toHex(digest);
    @memcpy(buf[6..70], &hex);
    return buf;
}

// -- URL scheme parsing --

pub const S3Url = struct {
    endpoint: []const u8,
    bucket: []const u8,
};

pub const FileUrl = struct {
    path: []const u8,
};

pub const HttpUrl = struct {
    base_url: []const u8,
};

pub const SshUrl = struct {
    user: ?[]const u8,
    host: []const u8,
    port: ?u16,
    path: []const u8,
};

/// Validate the repository-path portion of an SSH remote.
/// The path must be non-empty, must not contain empty / dot / dot-dot
/// components, and is restricted to a conservative ASCII subset so both the
/// on-disk config and the remote-shell transport stay unambiguous.
pub fn validateSshPath(path: []const u8) error{InvalidUrl}!void {
    if (path.len == 0) return error.InvalidUrl;

    var start: usize = 0;
    if (path[0] == '/') {
        if (path.len == 1) return error.InvalidUrl;
        start = 1;
    }

    var parts = std.mem.splitScalar(u8, path[start..], '/');
    while (parts.next()) |part| {
        if (part.len == 0) return error.InvalidUrl;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidUrl;
        for (part) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-')) {
                return error.InvalidUrl;
            }
        }
    }
}

pub fn formatStrictSshUrl(
    allocator: Allocator,
    user: []const u8,
    host: []const u8,
    port: ?u16,
    path: []const u8,
) ![]u8 {
    try validateSshPath(path);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "mkit+ssh://");
    try out.appendSlice(allocator, user);
    try out.append(allocator, '@');
    try out.appendSlice(allocator, host);
    if (port) |p| {
        // std.ArrayList in Zig 0.16 has no `.writer()` helper; go through
        // fmt.allocPrint + appendSlice.
        const port_str = try std.fmt.allocPrint(allocator, ":{d}", .{p});
        defer allocator.free(port_str);
        try out.appendSlice(allocator, port_str);
    }
    // URL-style `/path`, not SCP-style `:path`. Ensure exactly one leading
    // slash — append `/` only if the path doesn't already carry one.
    if (path.len == 0 or path[0] != '/') {
        try out.append(allocator, '/');
    }
    try out.appendSlice(allocator, path);
    return try out.toOwnedSlice(allocator);
}

pub const RemoteUrl = union(enum) {
    s3: S3Url,
    file: FileUrl,
    http: HttpUrl,
    ssh: SshUrl,
};

/// Parse a remote URL into a typed RemoteUrl.
/// Supported formats:
///   s3://host/bucket                    → S3 transport
///   file:///path/to/dir                 → file transport
///   /path/to/dir                        → file transport (bare path)
///   https://host/v1                     → HTTP transport (mkit VCS Worker)
///   http://host:port/v1                 → HTTP transport
///   ssh://user@host:port/path           → SSH transport
///   user@host:path                      → SSH transport (SCP-style)
pub fn parseUrl(raw_url: []const u8) !RemoteUrl {
    // Strict namespace: mkit remote URLs are prefixed with `mkit+<scheme>://`.
    // Strip the `mkit+` prefix here so the legacy body below can match the
    // unqualified scheme. Bare `file://` / `https://` / `ssh://` / etc. are
    // still accepted for backwards-compat.
    const url = if (std.mem.startsWith(u8, raw_url, "mkit+"))
        raw_url["mkit+".len..]
    else
        raw_url;

    if (std.mem.startsWith(u8, url, "file://")) {
        const path = url["file://".len..];
        if (path.len == 0) return error.InvalidUrl;
        return .{ .file = .{ .path = path } };
    }

    if (url.len > 0 and url[0] == '/') {
        return .{ .file = .{ .path = url } };
    }

    if (std.mem.startsWith(u8, url, "s3://")) {
        const after_scheme = url["s3://".len..];
        const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return error.InvalidUrl;
        const host = after_scheme[0..slash];
        const bucket = after_scheme[slash + 1 ..];
        if (host.len == 0 or bucket.len == 0) return error.InvalidUrl;
        return .{ .s3 = .{ .endpoint = host, .bucket = bucket } };
    }

    if (std.mem.startsWith(u8, url, "ssh://")) {
        return parseSshSchemeUrlInternal(url);
    }

    if (std.mem.startsWith(u8, url, "https://") or std.mem.startsWith(u8, url, "http://")) {
        if (parseHttpsStyleS3Url(url)) |s3| {
            return .{ .s3 = s3 };
        }
        return .{ .http = .{ .base_url = url } };
    }

    // SCP-style: user@host:path (has @ and : but no ://)
    if (std.mem.indexOf(u8, url, "://") == null) {
        if (parseScpStyleUrlInternal(url)) |ssh| {
            return .{ .ssh = ssh };
        }
    }

    return error.InvalidUrl;
}

fn parseSshSchemeUrlInternal(url: []const u8) !RemoteUrl {
    const after_scheme = url["ssh://".len..];
    if (after_scheme.len == 0) return error.InvalidUrl;
    var user: ?[]const u8 = null;
    var rest = after_scheme;
    if (std.mem.indexOfScalar(u8, after_scheme, '@')) |at_pos| {
        const slash_pos = std.mem.indexOfScalar(u8, after_scheme, '/');
        if (slash_pos == null or at_pos < slash_pos.?) {
            user = after_scheme[0..at_pos];
            if (user.?.len == 0) return error.InvalidUrl;
            rest = after_scheme[at_pos + 1 ..];
        }
    }
    const slash_pos = std.mem.indexOfScalar(u8, rest, '/') orelse return error.InvalidUrl;
    const host_port = rest[0..slash_pos];
    const path = rest[slash_pos..];
    if (path.len == 0) return error.InvalidUrl;
    var host: []const u8 = host_port;
    var port: ?u16 = null;
    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon_pos| {
        host = host_port[0..colon_pos];
        const port_str = host_port[colon_pos + 1 ..];
        port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidUrl;
    }
    if (host.len == 0) return error.InvalidUrl;
    try validateSshPath(path);
    return .{ .ssh = .{ .user = user, .host = host, .port = port, .path = path } };
}

fn parseScpStyleUrlInternal(url: []const u8) ?SshUrl {
    const at_pos = std.mem.indexOfScalar(u8, url, '@') orelse return null;
    const after_at = url[at_pos + 1 ..];
    const colon_pos = std.mem.indexOfScalar(u8, after_at, ':') orelse return null;
    const user = url[0..at_pos];
    const host = after_at[0..colon_pos];
    const path = after_at[colon_pos + 1 ..];
    if (user.len == 0 or host.len == 0 or path.len == 0) return null;
    validateSshPath(path) catch return null;
    return .{ .user = user, .host = host, .port = null, .path = path };
}

// -- Strict `mkit+<scheme>://` URL parser (W5-2) --
//
// The legacy `parseUrl` above accepts bare URLs (e.g. `https://host/v1`,
// `git@host:path`) for backwards compat. For 0.1.0 we want a strict
// namespace: every mkit remote URL MUST start with `mkit+`. This parser
// rejects anything else so we can't be confused by a stray git or plain
// HTTPS URL that happens to look like ours.

pub const StrictS3Url = struct { bucket: []const u8, prefix: []const u8 };
pub const StrictHttpsUrl = struct { host: []const u8, port: ?u16, path: []const u8 };
pub const StrictSshUrl = struct { user: []const u8, host: []const u8, port: ?u16, path: []const u8 };

pub const StrictRemoteUrl = union(enum) {
    file: []const u8, // mkit+file:///abs/path
    https: StrictHttpsUrl, // mkit+https://host[:port]/path
    s3: StrictS3Url, // mkit+s3://bucket/prefix (prefix may be empty)
    ssh: StrictSshUrl, // mkit+ssh://user@host[:port]:path
    memory: void, // mkit+memory:// (testing only)
};

pub const StrictParseError = error{
    InvalidScheme,
    UnknownScheme,
    MalformedUrl,
};

/// Parse a strict `mkit+<scheme>://...` URL.
///
/// - Anything not starting with `mkit+` returns `error.InvalidScheme`.
/// - A recognized prefix but unknown scheme (e.g. `mkit+gopher://...`)
///   returns `error.UnknownScheme`.
/// - A recognized scheme with missing/invalid fields returns
///   `error.MalformedUrl`.
pub fn parseRemoteUrl(input: []const u8) StrictParseError!StrictRemoteUrl {
    const prefix = "mkit+";
    if (!std.mem.startsWith(u8, input, prefix)) return error.InvalidScheme;
    const rest = input[prefix.len..];

    // Find the scheme terminator "://".
    const sep = std.mem.indexOf(u8, rest, "://") orelse return error.MalformedUrl;
    const scheme = rest[0..sep];
    const after = rest[sep + 3 ..];

    if (std.mem.eql(u8, scheme, "file")) {
        if (after.len == 0) return error.MalformedUrl;
        // We only accept absolute paths so the URL form is unambiguous.
        if (after[0] != '/') return error.MalformedUrl;
        return .{ .file = after };
    }

    if (std.mem.eql(u8, scheme, "memory")) {
        // `mkit+memory://` and `mkit+memory:///anything` both valid (testing).
        return .{ .memory = {} };
    }

    if (std.mem.eql(u8, scheme, "https")) {
        return parseStrictHttps(after);
    }

    if (std.mem.eql(u8, scheme, "s3")) {
        return parseStrictS3(after);
    }

    if (std.mem.eql(u8, scheme, "ssh")) {
        return parseStrictSsh(after);
    }

    return error.UnknownScheme;
}

fn parseStrictHttps(after: []const u8) StrictParseError!StrictRemoteUrl {
    if (after.len == 0) return error.MalformedUrl;
    // host[:port][/path]
    const path_start = std.mem.indexOfScalar(u8, after, '/');
    const host_port = if (path_start) |idx| after[0..idx] else after;
    const path = if (path_start) |idx| after[idx..] else "/";
    if (host_port.len == 0) return error.MalformedUrl;

    var host: []const u8 = host_port;
    var port: ?u16 = null;
    if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
        host = host_port[0..colon];
        const port_str = host_port[colon + 1 ..];
        if (host.len == 0 or port_str.len == 0) return error.MalformedUrl;
        port = std.fmt.parseInt(u16, port_str, 10) catch return error.MalformedUrl;
    }
    if (host.len == 0) return error.MalformedUrl;
    return .{ .https = .{ .host = host, .port = port, .path = path } };
}

fn parseStrictS3(after: []const u8) StrictParseError!StrictRemoteUrl {
    if (after.len == 0) return error.MalformedUrl;
    if (std.mem.indexOfScalar(u8, after, '/')) |idx| {
        const bucket = after[0..idx];
        const prefix = after[idx + 1 ..];
        if (bucket.len == 0) return error.MalformedUrl;
        return .{ .s3 = .{ .bucket = bucket, .prefix = prefix } };
    }
    // mkit+s3://bucket (no slash) is acceptable — empty prefix.
    return .{ .s3 = .{ .bucket = after, .prefix = "" } };
}

fn parseStrictSsh(after: []const u8) StrictParseError!StrictRemoteUrl {
    // Accepted forms (mirroring the spec's `mkit+ssh://user@host[:port]:path`):
    //   user@host:path
    //   user@host:port:path
    //
    // We split on `@` for user, then on the first `:` for the host, then —
    // if the next segment is all digits and followed by another `:` — the
    // digits are the port and what remains is the path. Otherwise the first
    // `:` terminates the host and what remains is the path.
    // Accepted forms:
    //   user@host/path                        — URL-style, no port
    //   user@host:port/path                   — URL-style, explicit port
    //   user@host:path                        — SCP-style, no port
    //   user@host:port:path                   — SCP-style with port
    //
    // The URL-style (slash before path) is what users actually type and
    // what `mkit+ssh://user@host:port/path` naturally produces when
    // parroting standard `ssh://` conventions; an earlier version only
    // accepted the SCP-style colon-colon form, which silently mis-parsed
    // real inputs (the port would disappear into the path component).
    const at = std.mem.indexOfScalar(u8, after, '@') orelse return error.MalformedUrl;
    const user = after[0..at];
    const rest = after[at + 1 ..];
    if (user.len == 0 or rest.len == 0) return error.MalformedUrl;

    // Split host[:port] on the first '/' if present — that's the URL form.
    //
    // We only commit to URL-style if the resulting host_port part parses
    // cleanly. For an SCP-style input like `host:port:rel/path` the first
    // slash lives INSIDE the path component, so host_port would end with
    // `...:rel` and its port-string parse would fail; in that case we
    // fall through to the SCP parser below.
    if (std.mem.indexOfScalar(u8, rest, '/')) |slash| url: {
        const host_port = rest[0..slash];
        const path = rest[slash..]; // path keeps its leading '/'
        if (host_port.len == 0 or path.len == 0) break :url;
        var host: []const u8 = host_port;
        var port: ?u16 = null;
        if (std.mem.indexOfScalar(u8, host_port, ':')) |colon| {
            host = host_port[0..colon];
            const port_str = host_port[colon + 1 ..];
            if (host.len == 0 or port_str.len == 0) break :url;
            port = std.fmt.parseInt(u16, port_str, 10) catch break :url;
        }
        if (host.len == 0) break :url;
        validateSshPath(path) catch break :url;
        return .{ .ssh = .{ .user = user, .host = host, .port = port, .path = path } };
    }

    // No slash — legacy SCP form: `host[:port]:path`.
    const first_colon = std.mem.indexOfScalar(u8, rest, ':') orelse return error.MalformedUrl;
    const host = rest[0..first_colon];
    const tail = rest[first_colon + 1 ..];
    if (host.len == 0 or tail.len == 0) return error.MalformedUrl;

    if (std.mem.indexOfScalar(u8, tail, ':')) |second_colon| {
        const maybe_port = tail[0..second_colon];
        const path = tail[second_colon + 1 ..];
        if (maybe_port.len > 0 and path.len > 0) {
            if (std.fmt.parseInt(u16, maybe_port, 10)) |port| {
                validateSshPath(path) catch return error.MalformedUrl;
                return .{ .ssh = .{ .user = user, .host = host, .port = port, .path = path } };
            } else |_| {}
        }
    }

    validateSshPath(tail) catch return error.MalformedUrl;
    return .{ .ssh = .{ .user = user, .host = host, .port = null, .path = tail } };
}

fn parseHttpsStyleS3Url(url: []const u8) ?S3Url {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return null;
    const after_scheme = url[scheme_end + 3 ..];
    const slash = std.mem.indexOfScalar(u8, after_scheme, '/') orelse return null;

    const host = after_scheme[0..slash];
    const path = after_scheme[slash + 1 ..];
    if (host.len == 0 or path.len == 0) return null;
    if (std.mem.indexOfScalar(u8, path, '/')) |_| return null;

    if (!(std.mem.indexOf(u8, host, "r2.cloudflarestorage.com") != null or
        std.mem.indexOf(u8, host, "s3.amazonaws.com") != null or
        std.mem.indexOf(u8, host, "minio") != null))
    {
        return null;
    }

    return .{
        .endpoint = url[0 .. scheme_end + 3 + host.len],
        .bucket = path,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "formatRef roundtrip" {
    const h = hash_mod.hash("test-ref");
    const wire = formatRef(h);
    const parsed = try parseRef(&wire);
    try std.testing.expectEqual(h, parsed);
}

test "parseRef valid" {
    const h = hash_mod.hash("test");
    const hex = hash_mod.toHex(h);
    const parsed = try parseRef(&hex);
    try std.testing.expectEqual(h, parsed);
}

test "parseRef no newline" {
    const h = hash_mod.hash("no-newline");
    const hex = hash_mod.toHex(h);
    const parsed = try parseRef(&hex);
    try std.testing.expectEqual(h, parsed);
}

test "parseRef too short" {
    try std.testing.expectError(error.InvalidRef, parseRef("abc"));
}

test "parseRef invalid hex" {
    const bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    try std.testing.expectError(error.InvalidRef, parseRef(bad));
}

test "validateRefName rejects empty path components" {
    try std.testing.expect(!validateRefName("refs//heads/main"));
    try std.testing.expect(!validateRefName("refs/heads/main/"));
}

test "validateRefPrefix allows trailing slash" {
    try std.testing.expect(validateRefPrefix("refs/heads/"));
    try std.testing.expect(validateRefPrefix("refs/heads"));
    try std.testing.expect(!validateRefPrefix("refs//heads/"));
}

test "packKey format" {
    const h = hash_mod.hash("pack-test");
    const key = packKey(h);
    try std.testing.expect(std.mem.startsWith(u8, &key, "packs/"));
    try std.testing.expectEqual(@as(usize, 70), key.len);
}

test "parseUrl file scheme" {
    const result = try parseUrl("file:///tmp/repo");
    try std.testing.expectEqualStrings("/tmp/repo", result.file.path);
}

test "parseUrl bare path" {
    const result = try parseUrl("/tmp/repo");
    try std.testing.expectEqualStrings("/tmp/repo", result.file.path);
}

test "parseUrl https" {
    const result = try parseUrl("https://vcs.example.com/v1");
    try std.testing.expectEqualStrings("https://vcs.example.com/v1", result.http.base_url);
}

test "parseUrl https s3 style" {
    const result = try parseUrl("https://account.r2.cloudflarestorage.com/mybucket");
    try std.testing.expectEqualStrings("https://account.r2.cloudflarestorage.com", result.s3.endpoint);
    try std.testing.expectEqualStrings("mybucket", result.s3.bucket);
}

test "parseUrl s3" {
    const result = try parseUrl("s3://host.example.com/mybucket");
    try std.testing.expectEqualStrings("host.example.com", result.s3.endpoint);
    try std.testing.expectEqualStrings("mybucket", result.s3.bucket);
}

test "parseUrl ssh scheme full" {
    const result = try parseUrl("ssh://user@host.example.com:2222/repos/project");
    try std.testing.expectEqualStrings("user", result.ssh.user.?);
    try std.testing.expectEqualStrings("host.example.com", result.ssh.host);
    try std.testing.expectEqual(@as(u16, 2222), result.ssh.port.?);
    try std.testing.expectEqualStrings("/repos/project", result.ssh.path);
}

test "parseUrl ssh scheme minimal" {
    const result = try parseUrl("ssh://myhost/path/to/repo");
    try std.testing.expect(result.ssh.user == null);
    try std.testing.expectEqualStrings("myhost", result.ssh.host);
    try std.testing.expect(result.ssh.port == null);
    try std.testing.expectEqualStrings("/path/to/repo", result.ssh.path);
}

test "validateSshPath rejects control characters" {
    try std.testing.expectError(error.InvalidUrl, validateSshPath("/tmp/repo\nname"));
    try std.testing.expectError(error.InvalidUrl, validateSshPath("repo\tname"));
}

test "parseUrl scp style" {
    const result = try parseUrl("git@github.com:org/repo");
    try std.testing.expectEqualStrings("git", result.ssh.user.?);
    try std.testing.expectEqualStrings("github.com", result.ssh.host);
    try std.testing.expect(result.ssh.port == null);
    try std.testing.expectEqualStrings("org/repo", result.ssh.path);
}

test "parseUrl rejects unsafe ssh paths" {
    try std.testing.expectError(error.InvalidUrl, parseUrl("git@github.com:org/repo;rm"));
    try std.testing.expectError(error.InvalidUrl, parseUrl("ssh://git@github.com/org/../repo"));
}

test "parseUrl ssh no path" {
    try std.testing.expectError(error.InvalidUrl, parseUrl("ssh://host"));
}

test "parseUrl ssh empty host" {
    try std.testing.expectError(error.InvalidUrl, parseUrl("ssh:///path"));
}

test "parseUrl empty" {
    try std.testing.expectError(error.InvalidUrl, parseUrl(""));
}

test "parseUrl s3 no bucket" {
    try std.testing.expectError(error.InvalidUrl, parseUrl("s3://host"));
}

// --- Strict parseRemoteUrl tests (W5-2) ---

test "parseRemoteUrl file" {
    const r = try parseRemoteUrl("mkit+file:///abs/path/to/repo");
    try std.testing.expectEqualStrings("/abs/path/to/repo", r.file);
}

test "parseRemoteUrl file rejects relative" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+file://relative"));
}

test "parseRemoteUrl https with port" {
    const r = try parseRemoteUrl("mkit+https://vcs.example.com:8443/v1");
    try std.testing.expectEqualStrings("vcs.example.com", r.https.host);
    try std.testing.expectEqual(@as(?u16, 8443), r.https.port);
    try std.testing.expectEqualStrings("/v1", r.https.path);
}

test "parseRemoteUrl https without port" {
    const r = try parseRemoteUrl("mkit+https://vcs.example.com/v1");
    try std.testing.expectEqualStrings("vcs.example.com", r.https.host);
    try std.testing.expect(r.https.port == null);
    try std.testing.expectEqualStrings("/v1", r.https.path);
}

test "parseRemoteUrl s3 with prefix" {
    const r = try parseRemoteUrl("mkit+s3://my-bucket/project-a");
    try std.testing.expectEqualStrings("my-bucket", r.s3.bucket);
    try std.testing.expectEqualStrings("project-a", r.s3.prefix);
}

test "parseRemoteUrl s3 empty prefix" {
    const r = try parseRemoteUrl("mkit+s3://my-bucket");
    try std.testing.expectEqualStrings("my-bucket", r.s3.bucket);
    try std.testing.expectEqualStrings("", r.s3.prefix);
}

test "parseRemoteUrl ssh full" {
    const r = try parseRemoteUrl("mkit+ssh://alice@host.example.com:2222/repos/project");
    try std.testing.expectEqualStrings("alice", r.ssh.user);
    try std.testing.expectEqualStrings("host.example.com", r.ssh.host);
    try std.testing.expectEqual(@as(?u16, 2222), r.ssh.port);
    try std.testing.expectEqualStrings("/repos/project", r.ssh.path);
}

test "parseRemoteUrl ssh full legacy SCP double-colon form" {
    // The strict parser also accepts the older `user@host:port:path`
    // spelling for parity with git-over-ssh SCP-style inputs. New code
    // should use the slash form (see the previous test).
    const r = try parseRemoteUrl("mkit+ssh://alice@host.example.com:2222:repos/project");
    try std.testing.expectEqualStrings("alice", r.ssh.user);
    try std.testing.expectEqualStrings("host.example.com", r.ssh.host);
    try std.testing.expectEqual(@as(?u16, 2222), r.ssh.port);
    try std.testing.expectEqualStrings("repos/project", r.ssh.path);
}

test "parseRemoteUrl ssh no port" {
    const r = try parseRemoteUrl("mkit+ssh://alice@host.example.com/repos/project");
    try std.testing.expectEqualStrings("alice", r.ssh.user);
    try std.testing.expectEqualStrings("host.example.com", r.ssh.host);
    try std.testing.expect(r.ssh.port == null);
    try std.testing.expectEqualStrings("/repos/project", r.ssh.path);
}

test "parseRemoteUrl rejects ssh path with dot segments" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+ssh://alice@host.example.com:/repos/../project"));
}

test "parseRemoteUrl rejects unsafe ssh paths" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+ssh://alice@host.example.com:/repos/project;touch"));
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+ssh://alice@host.example.com:/repos/../project"));
}

test "formatStrictSshUrl emits URL-style slash-path" {
    const formatted = try formatStrictSshUrl(std.testing.allocator, "alice", "host.example.com", 2222, "/repos/project");
    defer std.testing.allocator.free(formatted);
    try std.testing.expectEqualStrings("mkit+ssh://alice@host.example.com:2222/repos/project", formatted);
}

test "formatStrictSshUrl normalizes path without leading slash" {
    const formatted = try formatStrictSshUrl(std.testing.allocator, "alice", "host.example.com", null, "repos/project");
    defer std.testing.allocator.free(formatted);
    try std.testing.expectEqualStrings("mkit+ssh://alice@host.example.com/repos/project", formatted);
}

test "parseRemoteUrl memory" {
    const r = try parseRemoteUrl("mkit+memory://");
    try std.testing.expect(r == .memory);
}

test "parseRemoteUrl rejects bare https" {
    try std.testing.expectError(error.InvalidScheme, parseRemoteUrl("https://example.com"));
}

test "parseRemoteUrl rejects bare git ssh" {
    try std.testing.expectError(error.InvalidScheme, parseRemoteUrl("git@github.com:org/repo"));
}

test "parseRemoteUrl rejects empty" {
    try std.testing.expectError(error.InvalidScheme, parseRemoteUrl(""));
}

test "parseRemoteUrl unknown scheme" {
    try std.testing.expectError(error.UnknownScheme, parseRemoteUrl("mkit+gopher://example.com"));
    try std.testing.expectError(error.UnknownScheme, parseRemoteUrl("mkit+ftp://example.com/x"));
}

test "parseRemoteUrl malformed ssh no colon after host" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+ssh://user@hostonly"));
}

test "parseRemoteUrl malformed ssh no user" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+ssh://host.example.com:/path"));
}

test "parseRemoteUrl malformed s3 empty bucket" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+s3:///only-slash"));
}

test "parseRemoteUrl malformed https empty host" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+https:///path"));
}

test "parseRemoteUrl malformed missing scheme separator" {
    try std.testing.expectError(error.MalformedUrl, parseRemoteUrl("mkit+file"));
}

test "parseRemoteUrl bounded input does not crash" {
    // 256-byte bound matches the W5 test-input cap.
    var buf: [256]u8 = undefined;
    @memset(&buf, 'a');
    // Worst-case: all `a` chars — doesn't start with mkit+ → InvalidScheme.
    try std.testing.expectError(error.InvalidScheme, parseRemoteUrl(&buf));
}

test "fuzz: parseUrl does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            const n = smith.slice(&buf);
            _ = parseUrl(buf[0..n]) catch return;
        }
    }.run, .{});
}

test "attestationDirPrefix shape" {
    const h = hash_mod.hash("some-commit");
    const prefix = attestationDirPrefix(h);
    try std.testing.expect(std.mem.startsWith(u8, &prefix, "attestations/"));
    try std.testing.expectEqual(@as(u8, '/'), prefix[prefix.len - 1]);
    const hex = hash_mod.toHex(h);
    try std.testing.expectEqualStrings(&hex, prefix["attestations/".len..][0..64]);
}

test "attestationKey roundtrip" {
    const commit = hash_mod.hash("c1");
    const att = hash_mod.hash("envelope-bytes");
    const key = attestationKey(commit, att);

    try std.testing.expect(std.mem.startsWith(u8, &key, "attestations/"));
    try std.testing.expect(std.mem.endsWith(u8, &key, ".dsse"));

    const att_hex = hash_mod.toHex(att);
    const fname = key[key.len - (64 + ".dsse".len) ..];
    const parsed = parseAttestationFilename(fname) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(att, parsed);
    _ = att_hex;
}

test "parseAttestationFilename rejects junk" {
    try std.testing.expect(parseAttestationFilename("not-an-att.dsse") == null);
    try std.testing.expect(parseAttestationFilename("abc.dsse") == null);
    try std.testing.expect(parseAttestationFilename("") == null);
    // 64 hex but wrong extension
    const hex = [_]u8{'a'} ** 64;
    try std.testing.expect(parseAttestationFilename(&hex) == null);
}

test "fuzz: validateRefName does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            const n = smith.slice(&buf);
            _ = validateRefName(buf[0..n]);
        }
    }.run, .{});
}
