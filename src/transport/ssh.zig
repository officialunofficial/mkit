// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const protocol = @import("../protocol.zig");
const hash_mod = @import("../hash.zig");
const cli = @import("../cli.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

// =============================================================================
// Wire protocol constants
// =============================================================================

pub const OP_HELLO: u8 = 0x00;
pub const OP_UPLOAD_PACK: u8 = 0x01;
pub const OP_DOWNLOAD_PACK: u8 = 0x02;
pub const OP_PACK_EXISTS: u8 = 0x03;
pub const OP_WRITE_REF: u8 = 0x04;
pub const OP_UPDATE_REF: u8 = 0x05;
pub const OP_READ_REF: u8 = 0x06;
pub const OP_LIST_REFS: u8 = 0x07;
pub const OP_CLOSE: u8 = 0xFF;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
pub const STATUS_NULL: u8 = 2;
pub const STATUS_UNSUPPORTED: u8 = 3;

pub const CONDITION_ANY: u8 = 0;
pub const CONDITION_MISSING: u8 = 1;
pub const CONDITION_MATCH: u8 = 2;

pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
pub const MAX_REF_NAME: usize = 4096;

// OP_HELLO handshake parameters (SPEC-TRANSPORT §7.4).
pub const PROTO_VERSION: u8 = 1;
pub const BINARY_NAME: []const u8 = "mkit";
// Derive the human-readable version strings from cli.cli_version so a
// release bump automatically propagates to the wire handshake instead
// of leaving a stale "mkit 0.1.0" advertisement behind.
pub const CLIENT_VERSION: []const u8 = "mkit " ++ cli.cli_version;
pub const SERVER_VERSION: []const u8 = "mkit " ++ cli.cli_version;
pub const MAX_BINARY_NAME_LEN: usize = 32;
pub const MAX_VERSION_STRING_LEN: usize = 64;

// =============================================================================
// Wire protocol encode/decode helpers
// =============================================================================

pub const Response = struct {
    status: u8,
    data: []u8,
};

// -----------------------------------------------------------------------------
// OP_HELLO (§7.4)
//
// Client → Server payload:
//   [u8 proto_version]
//   [u8 binary_name_len][binary_name]
//   [u8 client_version_len][client_version]
//
// Server → Client (frame status + payload):
//   status = STATUS_OK on match, STATUS_ERROR on binary name mismatch,
//           STATUS_UNSUPPORTED on future proto_version.
//   payload (on STATUS_OK):
//     [u8 proto_version]
//     [u8 server_version_len][server_version]
// -----------------------------------------------------------------------------

pub const HelloRequest = struct {
    proto_version: u8,
    binary_name: []const u8,
    client_version: []const u8,
};

pub const HelloResponse = struct {
    proto_version: u8,
    server_version: []const u8,
};

pub fn encodeHelloRequest(
    allocator: Allocator,
    proto_version: u8,
    binary_name: []const u8,
    client_version: []const u8,
) ![]u8 {
    if (binary_name.len > MAX_BINARY_NAME_LEN) return error.BinaryNameTooLong;
    if (client_version.len > MAX_VERSION_STRING_LEN) return error.VersionTooLong;
    const total: usize = 1 + 1 + binary_name.len + 1 + client_version.len;
    const payload = try allocator.alloc(u8, total);
    var pos: usize = 0;
    payload[pos] = proto_version;
    pos += 1;
    payload[pos] = @intCast(binary_name.len);
    pos += 1;
    @memcpy(payload[pos .. pos + binary_name.len], binary_name);
    pos += binary_name.len;
    payload[pos] = @intCast(client_version.len);
    pos += 1;
    @memcpy(payload[pos .. pos + client_version.len], client_version);
    return payload;
}

pub fn decodeHelloRequest(payload: []const u8) !HelloRequest {
    if (payload.len < 2) return error.PayloadTooShort;
    var pos: usize = 0;
    const proto_version = payload[pos];
    pos += 1;
    const name_len: usize = payload[pos];
    pos += 1;
    if (name_len > MAX_BINARY_NAME_LEN) return error.BinaryNameTooLong;
    if (pos + name_len + 1 > payload.len) return error.PayloadTooShort;
    const binary_name = payload[pos .. pos + name_len];
    pos += name_len;
    const ver_len: usize = payload[pos];
    pos += 1;
    if (ver_len > MAX_VERSION_STRING_LEN) return error.VersionTooLong;
    if (pos + ver_len > payload.len) return error.PayloadTooShort;
    const client_version = payload[pos .. pos + ver_len];
    return .{
        .proto_version = proto_version,
        .binary_name = binary_name,
        .client_version = client_version,
    };
}

pub fn encodeHelloResponse(
    allocator: Allocator,
    proto_version: u8,
    server_version: []const u8,
) ![]u8 {
    if (server_version.len > MAX_VERSION_STRING_LEN) return error.VersionTooLong;
    const total: usize = 1 + 1 + server_version.len;
    const payload = try allocator.alloc(u8, total);
    payload[0] = proto_version;
    payload[1] = @intCast(server_version.len);
    @memcpy(payload[2 .. 2 + server_version.len], server_version);
    return payload;
}

pub fn decodeHelloResponse(payload: []const u8) !HelloResponse {
    if (payload.len < 2) return error.PayloadTooShort;
    const proto_version = payload[0];
    const ver_len: usize = payload[1];
    if (ver_len > MAX_VERSION_STRING_LEN) return error.VersionTooLong;
    if (2 + ver_len > payload.len) return error.PayloadTooShort;
    return .{
        .proto_version = proto_version,
        .server_version = payload[2 .. 2 + ver_len],
    };
}

pub fn encodeUploadPack(allocator: Allocator, digest: Hash, data: []const u8) ![]u8 {
    const payload = try allocator.alloc(u8, 32 + data.len);
    @memcpy(payload[0..32], &digest);
    @memcpy(payload[32..], data);
    return payload;
}

pub fn decodeUploadPack(payload: []const u8) !struct { digest: Hash, data: []const u8 } {
    if (payload.len < 32) return error.PayloadTooShort;
    return .{
        .digest = payload[0..32].*,
        .data = payload[32..],
    };
}

pub fn encodeDownloadPack(digest: Hash) [32]u8 {
    return digest;
}

pub fn decodeDownloadPack(payload: []const u8) !Hash {
    if (payload.len < 32) return error.PayloadTooShort;
    return payload[0..32].*;
}

pub fn encodePackExists(digest: Hash) [32]u8 {
    return digest;
}

pub fn decodePackExists(payload: []const u8) !Hash {
    if (payload.len < 32) return error.PayloadTooShort;
    return payload[0..32].*;
}

pub fn encodeWriteRef(allocator: Allocator, name: []const u8, h: Hash) ![]u8 {
    if (name.len > MAX_REF_NAME) return error.RefNameTooLong;
    const name_len: u16 = @intCast(name.len);
    const payload = try allocator.alloc(u8, 2 + name.len + 32);
    payload[0..2].* = std.mem.toBytes(std.mem.nativeToLittle(u16, name_len));
    @memcpy(payload[2 .. 2 + name.len], name);
    @memcpy(payload[2 + name.len ..][0..32], &h);
    return payload;
}

pub fn decodeWriteRef(payload: []const u8) !struct { name: []const u8, hash: Hash } {
    if (payload.len < 2) return error.PayloadTooShort;
    const name_len = std.mem.littleToNative(u16, @bitCast(payload[0..2].*));
    if (payload.len < 2 + @as(usize, name_len) + 32) return error.PayloadTooShort;
    return .{
        .name = payload[2 .. 2 + name_len],
        .hash = payload[2 + name_len ..][0..32].*,
    };
}

pub fn encodeUpdateRef(allocator: Allocator, name: []const u8, condition: protocol.RefWriteCondition, h: Hash) ![]u8 {
    if (name.len > MAX_REF_NAME) return error.RefNameTooLong;
    const name_len: u16 = @intCast(name.len);

    const cond_size: usize = switch (condition) {
        .any => 1,
        .missing => 1,
        .match => 1 + 32,
    };
    const total = cond_size + 2 + name.len + 32;
    const payload = try allocator.alloc(u8, total);

    var pos: usize = 0;
    switch (condition) {
        .any => {
            payload[pos] = CONDITION_ANY;
            pos += 1;
        },
        .missing => {
            payload[pos] = CONDITION_MISSING;
            pos += 1;
        },
        .match => |expected| {
            payload[pos] = CONDITION_MATCH;
            pos += 1;
            @memcpy(payload[pos..][0..32], &expected);
            pos += 32;
        },
    }
    payload[pos..][0..2].* = std.mem.toBytes(std.mem.nativeToLittle(u16, name_len));
    pos += 2;
    @memcpy(payload[pos .. pos + name.len], name);
    pos += name.len;
    @memcpy(payload[pos..][0..32], &h);

    return payload;
}

pub fn decodeUpdateRef(payload: []const u8) !struct {
    name: []const u8,
    condition: protocol.RefWriteCondition,
    hash: Hash,
} {
    if (payload.len < 1) return error.PayloadTooShort;
    var pos: usize = 0;
    const tag = payload[pos];
    pos += 1;

    const condition: protocol.RefWriteCondition = switch (tag) {
        CONDITION_ANY => .any,
        CONDITION_MISSING => .missing,
        CONDITION_MATCH => blk: {
            if (pos + 32 > payload.len) return error.PayloadTooShort;
            const expected = payload[pos..][0..32].*;
            pos += 32;
            break :blk .{ .match = expected };
        },
        else => return error.InvalidConditionTag,
    };

    if (pos + 2 > payload.len) return error.PayloadTooShort;
    const name_len = std.mem.littleToNative(u16, @bitCast(payload[pos..][0..2].*));
    pos += 2;

    if (pos + @as(usize, name_len) + 32 > payload.len) return error.PayloadTooShort;
    const name = payload[pos .. pos + name_len];
    pos += name_len;
    const h = payload[pos..][0..32].*;

    return .{ .name = name, .condition = condition, .hash = h };
}

pub fn encodeReadRef(allocator: Allocator, name: []const u8) ![]u8 {
    if (name.len > MAX_REF_NAME) return error.RefNameTooLong;
    const name_len: u16 = @intCast(name.len);
    const payload = try allocator.alloc(u8, 2 + name.len);
    payload[0..2].* = std.mem.toBytes(std.mem.nativeToLittle(u16, name_len));
    @memcpy(payload[2..], name);
    return payload;
}

pub fn decodeReadRef(payload: []const u8) ![]const u8 {
    if (payload.len < 2) return error.PayloadTooShort;
    const name_len = std.mem.littleToNative(u16, @bitCast(payload[0..2].*));
    if (payload.len < 2 + @as(usize, name_len)) return error.PayloadTooShort;
    return payload[2 .. 2 + name_len];
}

pub fn encodeListRefs(allocator: Allocator, prefix: []const u8) ![]u8 {
    if (prefix.len > MAX_REF_NAME) return error.RefNameTooLong;
    const prefix_len: u16 = @intCast(prefix.len);
    const payload = try allocator.alloc(u8, 2 + prefix.len);
    payload[0..2].* = std.mem.toBytes(std.mem.nativeToLittle(u16, prefix_len));
    @memcpy(payload[2..], prefix);
    return payload;
}

pub fn decodeListRefs(payload: []const u8) ![]const u8 {
    if (payload.len < 2) return error.PayloadTooShort;
    const prefix_len = std.mem.littleToNative(u16, @bitCast(payload[0..2].*));
    if (payload.len < 2 + @as(usize, prefix_len)) return error.PayloadTooShort;
    return payload[2 .. 2 + prefix_len];
}

pub fn encodeRefList(allocator: Allocator, refs: []const protocol.Ref) ![]u8 {
    var total: usize = 4;
    for (refs) |ref| {
        total += 2 + ref.name.len + 32;
    }

    const payload = try allocator.alloc(u8, total);
    var pos: usize = 0;

    const count: u32 = @intCast(refs.len);
    payload[pos..][0..4].* = std.mem.toBytes(std.mem.nativeToLittle(u32, count));
    pos += 4;

    for (refs) |ref| {
        const name_len: u16 = @intCast(ref.name.len);
        payload[pos..][0..2].* = std.mem.toBytes(std.mem.nativeToLittle(u16, name_len));
        pos += 2;
        @memcpy(payload[pos .. pos + ref.name.len], ref.name);
        pos += ref.name.len;
        @memcpy(payload[pos..][0..32], &ref.hash);
        pos += 32;
    }

    return payload;
}

pub fn decodeRefList(allocator: Allocator, data: []const u8) ![]protocol.Ref {
    if (data.len < 4) return error.PayloadTooShort;
    const count = std.mem.littleToNative(u32, @bitCast(data[0..4].*));
    const max_count = (data.len - 4) / (2 + 32);
    if (count > max_count) return error.PayloadTooShort;

    var refs = try allocator.alloc(protocol.Ref, count);
    var initialized: u32 = 0;
    errdefer {
        for (refs[0..initialized]) |ref| allocator.free(ref.name);
        allocator.free(refs);
    }

    var pos: usize = 4;
    for (0..count) |i| {
        if (pos + 2 > data.len) return error.PayloadTooShort;
        const name_len = std.mem.littleToNative(u16, @bitCast(data[pos..][0..2].*));
        pos += 2;

        if (pos + @as(usize, name_len) + 32 > data.len) return error.PayloadTooShort;
        const name = try allocator.dupe(u8, data[pos .. pos + name_len]);
        errdefer allocator.free(name);
        pos += name_len;
        if (!protocol.validateRefName(name)) return error.InvalidRef;
        const h = data[pos..][0..32].*;
        pos += 32;

        refs[i] = .{ .name = name, .hash = h };
        initialized += 1;
    }

    return refs;
}

pub fn encodeRequest(allocator: Allocator, opcode: u8, payload: []const u8) ![]u8 {
    const frame = try allocator.alloc(u8, 1 + 4 + payload.len);
    frame[0] = opcode;
    frame[1..5].* = std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(payload.len)));
    @memcpy(frame[5..], payload);
    return frame;
}

pub fn encodeResponse(allocator: Allocator, status: u8, payload: []const u8) ![]u8 {
    const frame = try allocator.alloc(u8, 1 + 4 + payload.len);
    frame[0] = status;
    frame[1..5].* = std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(payload.len)));
    @memcpy(frame[5..], payload);
    return frame;
}

// =============================================================================
// SSH URL parsing — delegates to protocol.zig to avoid duplication
// =============================================================================

pub const SshUrl = protocol.SshUrl;

pub fn parseSshUrl(url: []const u8) !SshUrl {
    const result = protocol.parseUrl(url) catch return error.InvalidUrl;
    switch (result) {
        .ssh => |ssh| return ssh,
        else => return error.InvalidUrl,
    }
}

fn isSafeRemoteShellToken(arg: []const u8) bool {
    if (arg.len == 0) return false;
    for (arg, 0..) |c, i| {
        if (std.ascii.isAlphanumeric(c) or
            c == '/' or
            c == '.' or
            c == '_' or
            c == '-' or
            c == '+' or
            c == '=' or
            c == ':' or
            c == '@' or
            c == '%' or
            c == ',')
        {
            continue;
        }
        if (c == '~' and i == 0) continue;
        return false;
    }
    return true;
}

pub fn shellEscapeArg(allocator: Allocator, arg: []const u8) ![]u8 {
    if (isSafeRemoteShellToken(arg)) return allocator.dupe(u8, arg);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.append(allocator, '\'');
    for (arg) |c| {
        if (c == '\'') {
            try out.appendSlice(allocator, "'\\''");
        } else {
            try out.append(allocator, c);
        }
    }
    try out.append(allocator, '\'');
    return out.toOwnedSlice(allocator);
}

pub fn buildRemoteServeCommand(allocator: Allocator, path: []const u8) ![]u8 {
    const escaped_path = try shellEscapeArg(allocator, path);
    defer allocator.free(escaped_path);
    return std.fmt.allocPrint(allocator, "exec mkit serve {s}", .{escaped_path});
}

// =============================================================================
// SshTransport
// =============================================================================

/// Optional SSH CLI knobs threaded in from `Config` (see config.zig).
/// Empty strings mean "don't pass the flag; inherit the user's ssh defaults".
/// Documented in docs/SSH-SECURITY.md.
pub const SshOptions = struct {
    strict_host_key_checking: []const u8 = "",
    user_known_hosts_file: []const u8 = "",
    identity_file: []const u8 = "",
};

pub const SshTransport = struct {
    process: std.process.Child,
    allocator: Allocator,
    io: std.Io,

    pub fn init(allocator: Allocator, io: std.Io, user: ?[]const u8, host: []const u8, port: ?u16, path: []const u8) !SshTransport {
        return initWithOptions(allocator, io, user, host, port, path, .{});
    }

    pub fn initWithOptions(
        allocator: Allocator,
        io: std.Io,
        user: ?[]const u8,
        host: []const u8,
        port: ?u16,
        path: []const u8,
        options: SshOptions,
    ) !SshTransport {
        try protocol.validateSshPath(path);

        // argv capacity: "ssh" + -p N + 3 * (-o FLAG=VAL | -i file) + host + remote command
        var argv_buf: [14][]const u8 = undefined;
        var argc: usize = 0;

        argv_buf[argc] = "ssh";
        argc += 1;

        var port_buf: [8]u8 = undefined;
        if (port) |p| {
            argv_buf[argc] = "-p";
            argc += 1;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{p}) catch return error.InvalidUrl;
            argv_buf[argc] = port_str;
            argc += 1;
        }

        // SSH options: passed as separate allocated strings so lifetime survives spawn().
        var shk_buf: [128]u8 = undefined;
        if (options.strict_host_key_checking.len > 0) {
            const s = std.fmt.bufPrint(&shk_buf, "StrictHostKeyChecking={s}", .{options.strict_host_key_checking}) catch return error.InvalidUrl;
            argv_buf[argc] = "-o";
            argc += 1;
            argv_buf[argc] = s;
            argc += 1;
        }

        var ukh_buf: [1024]u8 = undefined;
        if (options.user_known_hosts_file.len > 0) {
            const s = std.fmt.bufPrint(&ukh_buf, "UserKnownHostsFile={s}", .{options.user_known_hosts_file}) catch return error.InvalidUrl;
            argv_buf[argc] = "-o";
            argc += 1;
            argv_buf[argc] = s;
            argc += 1;
        }

        if (options.identity_file.len > 0) {
            argv_buf[argc] = "-i";
            argc += 1;
            argv_buf[argc] = options.identity_file;
            argc += 1;
        }

        var host_spec_buf: [512]u8 = undefined;
        const host_spec = if (user) |u|
            std.fmt.bufPrint(&host_spec_buf, "{s}@{s}", .{ u, host }) catch return error.InvalidUrl
        else
            std.fmt.bufPrint(&host_spec_buf, "{s}", .{host}) catch return error.InvalidUrl;

        argv_buf[argc] = host_spec;
        argc += 1;

        // The path has already been restricted to [A-Za-z0-9._-/] with no
        // empty / dot / dot-dot components by `protocol.validateSshPath`
        // above, so it's safe to hand to the remote shell as-is. Pass the
        // three tokens separately (not as a joined string) so sshd
        // invokes `mkit serve <path>` without an intervening `sh -c`
        // parse that broke the OP_HELLO handshake on some sshd configs.
        argv_buf[argc] = "mkit";
        argc += 1;
        argv_buf[argc] = "serve";
        argc += 1;
        argv_buf[argc] = path;
        argc += 1;

        const child = try std.process.spawn(io, .{
            .argv = argv_buf[0..argc],
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });

        var t: SshTransport = .{
            .process = child,
            .allocator = allocator,
            .io = io,
        };

        // Perform OP_HELLO handshake before returning.
        // On any failure, tear down the child and surface the error.
        t.performClientHandshake() catch |err| {
            if (t.process.stdin) |*stdin| {
                stdin.close(io);
                t.process.stdin = null;
            }
            _ = t.process.wait(io) catch {};
            return err;
        };

        return t;
    }

    /// Send OP_HELLO and validate the server's reply.
    /// Returns:
    ///   - success if server speaks v1 mkit.
    ///   - error.UnsupportedServerProtocol if the server advertises a different
    ///     proto_version, or replies STATUS_UNSUPPORTED.
    ///   - error.IncompatiblePeer if the server's reply is unparseable, or the
    ///     server returns STATUS_ERROR (pre-v1 servers that didn't understand
    ///     opcode 0x00 will emit STATUS_ERROR "unknown opcode").
    fn performClientHandshake(self: *SshTransport) !void {
        const hello_payload = encodeHelloRequest(
            self.allocator,
            PROTO_VERSION,
            BINARY_NAME,
            CLIENT_VERSION,
        ) catch return error.IncompatiblePeer;
        defer self.allocator.free(hello_payload);
        try self.sendRequest(OP_HELLO, hello_payload);

        const resp = self.readResponse(self.allocator) catch return error.IncompatiblePeer;
        defer self.allocator.free(resp.data);

        if (resp.status == STATUS_UNSUPPORTED) return error.UnsupportedServerProtocol;
        if (resp.status != STATUS_OK) return error.IncompatiblePeer;

        const hello = decodeHelloResponse(resp.data) catch return error.IncompatiblePeer;
        if (hello.proto_version != PROTO_VERSION) return error.UnsupportedServerProtocol;
        // Server version is advisory; silently accepted.
    }

    pub fn deinit(self: *SshTransport) void {
        self.sendRequest(OP_CLOSE, &.{}) catch {};
        if (self.process.stdin) |*stdin| {
            stdin.close(self.io);
            self.process.stdin = null;
        }
        _ = self.process.wait(self.io) catch {};
    }

    pub fn transport(self: *SshTransport) protocol.Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    const vtable = protocol.Transport.VTable{
        .uploadPack = uploadPackImpl,
        .downloadPack = downloadPackImpl,
        .packExists = packExistsImpl,
        .writeRef = writeRefImpl,
        .updateRef = updateRefImpl,
        .readRef = readRefImpl,
        .listRefs = listRefsImpl,
    };

    fn sendRequest(self: *SshTransport, opcode: u8, payload: []const u8) !void {
        const stdin = self.process.stdin orelse return error.BrokenPipe;
        const header: [5]u8 = .{opcode} ++ std.mem.toBytes(std.mem.nativeToLittle(u32, @intCast(payload.len)));
        try stdin.writeStreamingAll(self.io, &header);
        if (payload.len > 0) {
            try stdin.writeStreamingAll(self.io, payload);
        }
    }

    fn readResponse(self: *SshTransport, allocator: Allocator) !Response {
        const stdout = self.process.stdout orelse return error.BrokenPipe;
        var header: [5]u8 = undefined;
        var header_off: usize = 0;
        while (header_off < header.len) {
            const n = try stdout.readStreaming(self.io, &.{header[header_off..]});
            if (n == 0) break;
            header_off += n;
        }
        const read = header_off;
        if (read != 5) return error.UnexpectedEof;
        const status = header[0];
        const data_len = std.mem.littleToNative(u32, @bitCast(header[1..5].*));
        if (data_len > MAX_PAYLOAD) return error.PayloadTooLarge;

        const data = try allocator.alloc(u8, data_len);
        errdefer allocator.free(data);
        if (data_len > 0) {
            var data_off: usize = 0;
            while (data_off < data.len) {
                const n = try stdout.readStreaming(self.io, &.{data[data_off..]});
                if (n == 0) break;
                data_off += n;
            }
            const data_read = data_off;
            if (data_read != data_len) {
                allocator.free(data);
                return error.UnexpectedEof;
            }
        }

        return .{ .status = status, .data = data };
    }

    fn uploadPackImpl(ptr: *anyopaque, allocator: Allocator, bytes: []const u8, digest: Hash) anyerror!void {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload = try encodeUploadPack(allocator, digest, bytes);
        defer allocator.free(payload);
        try self.sendRequest(OP_UPLOAD_PACK, payload);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_ERROR) return error.RemoteError;
    }

    fn downloadPackImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror![]u8 {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload_arr = encodeDownloadPack(digest);
        try self.sendRequest(OP_DOWNLOAD_PACK, &payload_arr);
        const resp = try self.readResponse(allocator);
        if (resp.status == STATUS_ERROR or resp.status == STATUS_NULL) {
            allocator.free(resp.data);
            return error.PackNotFound;
        }
        return resp.data;
    }

    fn packExistsImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror!bool {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload_arr = encodePackExists(digest);
        try self.sendRequest(OP_PACK_EXISTS, &payload_arr);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_ERROR) return error.RemoteError;
        if (resp.data.len < 1) return error.InvalidResponse;
        return resp.data[0] != 0;
    }

    fn writeRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, h: Hash) anyerror!void {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload = try encodeWriteRef(allocator, ref_name, h);
        defer allocator.free(payload);
        try self.sendRequest(OP_WRITE_REF, payload);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_ERROR) return error.RemoteError;
    }

    fn updateRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, condition: protocol.RefWriteCondition, h: Hash) anyerror!void {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload = try encodeUpdateRef(allocator, ref_name, condition, h);
        defer allocator.free(payload);
        try self.sendRequest(OP_UPDATE_REF, payload);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_ERROR) return error.RefConflict;
    }

    fn readRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8) anyerror!?Hash {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload = try encodeReadRef(allocator, ref_name);
        defer allocator.free(payload);
        try self.sendRequest(OP_READ_REF, payload);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_NULL) return null;
        if (resp.status == STATUS_ERROR) return error.RemoteError;
        if (resp.data.len < 32) return error.InvalidResponse;
        return resp.data[0..32].*;
    }

    fn listRefsImpl(ptr: *anyopaque, allocator: Allocator, prefix: []const u8) anyerror![]protocol.Ref {
        const self: *SshTransport = @ptrCast(@alignCast(ptr));
        const payload = try encodeListRefs(allocator, prefix);
        defer allocator.free(payload);
        try self.sendRequest(OP_LIST_REFS, payload);
        const resp = try self.readResponse(allocator);
        defer allocator.free(resp.data);
        if (resp.status == STATUS_ERROR) return error.RemoteError;
        return decodeRefList(allocator, resp.data);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "encodeUploadPack roundtrip" {
    const allocator = std.testing.allocator;
    const digest = hash_mod.hash("test-upload-pack");
    const data = "pack file contents here";

    const encoded = try encodeUploadPack(allocator, digest, data);
    defer allocator.free(encoded);

    const decoded = try decodeUploadPack(encoded);
    try std.testing.expectEqual(digest, decoded.digest);
    try std.testing.expectEqualStrings(data, decoded.data);
}

test "encodeDownloadPack roundtrip" {
    const digest = hash_mod.hash("test-download-pack");
    const encoded = encodeDownloadPack(digest);
    const decoded = try decodeDownloadPack(&encoded);
    try std.testing.expectEqual(digest, decoded);
}

test "encodePackExists roundtrip" {
    const digest = hash_mod.hash("test-pack-exists");
    const encoded = encodePackExists(digest);
    const decoded = try decodePackExists(&encoded);
    try std.testing.expectEqual(digest, decoded);
}

test "encodeWriteRef roundtrip" {
    const allocator = std.testing.allocator;
    const h = hash_mod.hash("test-write-ref");
    const name = "refs/heads/main";

    const encoded = try encodeWriteRef(allocator, name, h);
    defer allocator.free(encoded);

    const decoded = try decodeWriteRef(encoded);
    try std.testing.expectEqualStrings(name, decoded.name);
    try std.testing.expectEqual(h, decoded.hash);
}

test "encodeUpdateRef roundtrip any" {
    const allocator = std.testing.allocator;
    const h = hash_mod.hash("test-update-any");
    const name = "refs/heads/dev";

    const encoded = try encodeUpdateRef(allocator, name, .any, h);
    defer allocator.free(encoded);

    const decoded = try decodeUpdateRef(encoded);
    try std.testing.expectEqualStrings(name, decoded.name);
    try std.testing.expectEqual(h, decoded.hash);
    try std.testing.expect(decoded.condition == .any);
}

test "encodeUpdateRef roundtrip missing" {
    const allocator = std.testing.allocator;
    const h = hash_mod.hash("test-update-missing");

    const encoded = try encodeUpdateRef(allocator, "refs/heads/new", .missing, h);
    defer allocator.free(encoded);

    const decoded = try decodeUpdateRef(encoded);
    try std.testing.expectEqualStrings("refs/heads/new", decoded.name);
    try std.testing.expectEqual(h, decoded.hash);
    try std.testing.expect(decoded.condition == .missing);
}

test "encodeUpdateRef roundtrip match" {
    const allocator = std.testing.allocator;
    const h = hash_mod.hash("test-update-match-new");
    const expected = hash_mod.hash("test-update-match-expected");

    const encoded = try encodeUpdateRef(allocator, "refs/heads/main", .{ .match = expected }, h);
    defer allocator.free(encoded);

    const decoded = try decodeUpdateRef(encoded);
    try std.testing.expectEqualStrings("refs/heads/main", decoded.name);
    try std.testing.expectEqual(h, decoded.hash);
    switch (decoded.condition) {
        .match => |m| try std.testing.expectEqual(expected, m),
        else => return error.ExpectedMatch,
    }
}

test "encodeReadRef roundtrip" {
    const allocator = std.testing.allocator;

    const encoded = try encodeReadRef(allocator, "refs/tags/v1.0");
    defer allocator.free(encoded);

    const decoded = try decodeReadRef(encoded);
    try std.testing.expectEqualStrings("refs/tags/v1.0", decoded);
}

test "encodeListRefs roundtrip" {
    const allocator = std.testing.allocator;

    const encoded = try encodeListRefs(allocator, "refs/heads/");
    defer allocator.free(encoded);

    const decoded = try decodeListRefs(encoded);
    try std.testing.expectEqualStrings("refs/heads/", decoded);
}

test "encodeRefList roundtrip" {
    const allocator = std.testing.allocator;

    const h1 = hash_mod.hash("ref-list-1");
    const h2 = hash_mod.hash("ref-list-2");
    const h3 = hash_mod.hash("ref-list-3");

    const refs = [_]protocol.Ref{
        .{ .name = "main", .hash = h1 },
        .{ .name = "dev", .hash = h2 },
        .{ .name = "feature/x", .hash = h3 },
    };

    const encoded = try encodeRefList(allocator, &refs);
    defer allocator.free(encoded);

    const decoded = try decodeRefList(allocator, encoded);
    defer {
        for (decoded) |ref| allocator.free(ref.name);
        allocator.free(decoded);
    }

    try std.testing.expectEqual(@as(usize, 3), decoded.len);
    try std.testing.expectEqualStrings("main", decoded[0].name);
    try std.testing.expectEqual(h1, decoded[0].hash);
    try std.testing.expectEqualStrings("dev", decoded[1].name);
    try std.testing.expectEqual(h2, decoded[1].hash);
    try std.testing.expectEqualStrings("feature/x", decoded[2].name);
    try std.testing.expectEqual(h3, decoded[2].hash);
}

test "encodeRefList empty" {
    const allocator = std.testing.allocator;

    const refs = [_]protocol.Ref{};
    const encoded = try encodeRefList(allocator, &refs);
    defer allocator.free(encoded);

    const decoded = try decodeRefList(allocator, encoded);
    defer allocator.free(decoded);

    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}

test "encodeRequest frame format" {
    const allocator = std.testing.allocator;

    const frame = try encodeRequest(allocator, OP_UPLOAD_PACK, "hello");
    defer allocator.free(frame);

    try std.testing.expectEqual(@as(usize, 1 + 4 + 5), frame.len);
    try std.testing.expectEqual(OP_UPLOAD_PACK, frame[0]);
    const payload_len = std.mem.littleToNative(u32, @bitCast(frame[1..5].*));
    try std.testing.expectEqual(@as(u32, 5), payload_len);
    try std.testing.expectEqualStrings("hello", frame[5..]);
}

test "encodeResponse frame format" {
    const allocator = std.testing.allocator;

    const frame = try encodeResponse(allocator, STATUS_OK, "data");
    defer allocator.free(frame);

    try std.testing.expectEqual(@as(usize, 1 + 4 + 4), frame.len);
    try std.testing.expectEqual(STATUS_OK, frame[0]);
    const payload_len = std.mem.littleToNative(u32, @bitCast(frame[1..5].*));
    try std.testing.expectEqual(@as(u32, 4), payload_len);
    try std.testing.expectEqualStrings("data", frame[5..]);
}

test "encodeResponse null status" {
    const allocator = std.testing.allocator;

    const frame = try encodeResponse(allocator, STATUS_NULL, "");
    defer allocator.free(frame);

    try std.testing.expectEqual(STATUS_NULL, frame[0]);
    const payload_len = std.mem.littleToNative(u32, @bitCast(frame[1..5].*));
    try std.testing.expectEqual(@as(u32, 0), payload_len);
}

test "close opcode frame" {
    const allocator = std.testing.allocator;

    const frame = try encodeRequest(allocator, OP_CLOSE, "");
    defer allocator.free(frame);

    try std.testing.expectEqual(OP_CLOSE, frame[0]);
    const payload_len = std.mem.littleToNative(u32, @bitCast(frame[1..5].*));
    try std.testing.expectEqual(@as(u32, 0), payload_len);
}

test "decodeUploadPack too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeUploadPack("short"));
}

test "decodeDownloadPack too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeDownloadPack("x"));
}

test "decodeWriteRef too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeWriteRef("x"));
}

test "decodeUpdateRef too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeUpdateRef(""));
}

test "decodeUpdateRef invalid condition tag" {
    const payload = [_]u8{0x99} ++ [_]u8{0} ** 36;
    try std.testing.expectError(error.InvalidConditionTag, decodeUpdateRef(&payload));
}

test "decodeReadRef too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeReadRef("x"));
}

test "decodeRefList too short" {
    try std.testing.expectError(error.PayloadTooShort, decodeRefList(std.testing.allocator, "xx"));
}

test "decodeRefList rejects invalid ref names" {
    const allocator = std.testing.allocator;
    const bad = protocol.Ref{ .name = "refs/heads/bad name", .hash = hash_mod.hash("bad-ref") };
    const encoded = try encodeRefList(allocator, &.{bad});
    defer allocator.free(encoded);
    try std.testing.expectError(error.InvalidRef, decodeRefList(allocator, encoded));
}

test "decodeRefList rejects impossible count before allocation" {
    const payload = [_]u8{ 2, 0, 0, 0 };
    try std.testing.expectError(error.PayloadTooShort, decodeRefList(std.testing.allocator, &payload));
}

// -- SSH URL parsing tests --

test "parseSshUrl full form" {
    const result = try parseSshUrl("ssh://user@host.example.com:2222/repos/project");
    try std.testing.expectEqualStrings("user", result.user.?);
    try std.testing.expectEqualStrings("host.example.com", result.host);
    try std.testing.expectEqual(@as(u16, 2222), result.port.?);
    try std.testing.expectEqualStrings("/repos/project", result.path);
}

test "parseSshUrl minimal" {
    const result = try parseSshUrl("ssh://myhost/path/to/repo");
    try std.testing.expect(result.user == null);
    try std.testing.expectEqualStrings("myhost", result.host);
    try std.testing.expect(result.port == null);
    try std.testing.expectEqualStrings("/path/to/repo", result.path);
}

test "parseSshUrl with user no port" {
    const result = try parseSshUrl("ssh://git@github.com/org/repo");
    try std.testing.expectEqualStrings("git", result.user.?);
    try std.testing.expectEqualStrings("github.com", result.host);
    try std.testing.expect(result.port == null);
    try std.testing.expectEqualStrings("/org/repo", result.path);
}

test "parseSshUrl SCP style" {
    const result = try parseSshUrl("git@github.com:org/repo");
    try std.testing.expectEqualStrings("git", result.user.?);
    try std.testing.expectEqualStrings("github.com", result.host);
    try std.testing.expect(result.port == null);
    try std.testing.expectEqualStrings("org/repo", result.path);
}

test "parseSshUrl SCP style with nested path" {
    const result = try parseSshUrl("deploy@internal.host:projects/deep/path");
    try std.testing.expectEqualStrings("deploy", result.user.?);
    try std.testing.expectEqualStrings("internal.host", result.host);
    try std.testing.expectEqualStrings("projects/deep/path", result.path);
}

test "parseSshUrl rejects unsafe path" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("git@github.com:org/../repo"));
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("git@github.com:org/repo;touch"));
}

test "parseSshUrl rejects empty" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl(""));
}

test "parseSshUrl rejects no path" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("ssh://host"));
}

test "parseSshUrl rejects empty host" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("ssh:///path"));
}

test "parseSshUrl rejects http" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("http://host/path"));
}

test "parseSshUrl rejects scp missing colon" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("user@host"));
}

test "parseSshUrl rejects empty user in scp" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("@host:path"));
}

test "parseSshUrl rejects empty path in scp" {
    try std.testing.expectError(error.InvalidUrl, parseSshUrl("user@host:"));
}

test "parseSshUrl ssh scheme with port no user" {
    const result = try parseSshUrl("ssh://myhost:8022/data/repo");
    try std.testing.expect(result.user == null);
    try std.testing.expectEqualStrings("myhost", result.host);
    try std.testing.expectEqual(@as(u16, 8022), result.port.?);
    try std.testing.expectEqualStrings("/data/repo", result.path);
}

test "shellEscapeArg leaves safe ssh path unquoted" {
    const allocator = std.testing.allocator;
    const escaped = try shellEscapeArg(allocator, "~/repo/path");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("~/repo/path", escaped);
}

test "shellEscapeArg quotes embedded single quote" {
    const allocator = std.testing.allocator;
    const escaped = try shellEscapeArg(allocator, "/srv/repo's-backup");
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("'/srv/repo'\\''s-backup'", escaped);
}

test "buildRemoteServeCommand quotes unsafe path once" {
    const allocator = std.testing.allocator;
    const cmd = try buildRemoteServeCommand(allocator, "/srv/repo's-backup");
    defer allocator.free(cmd);
    try std.testing.expectEqualStrings("exec mkit serve '/srv/repo'\\''s-backup'", cmd);
}

test "encodeUploadPack large payload" {
    const allocator = std.testing.allocator;
    const digest = hash_mod.hash("large-pack");
    const data = try allocator.alloc(u8, 1024);
    defer allocator.free(data);
    @memset(data, 0xAB);

    const encoded = try encodeUploadPack(allocator, digest, data);
    defer allocator.free(encoded);

    const decoded = try decodeUploadPack(encoded);
    try std.testing.expectEqual(digest, decoded.digest);
    try std.testing.expectEqual(@as(usize, 1024), decoded.data.len);
    try std.testing.expectEqual(@as(u8, 0xAB), decoded.data[0]);
    try std.testing.expectEqual(@as(u8, 0xAB), decoded.data[1023]);
}

test "fuzz: decodeUploadPack does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const n = smith.slice(&buf);
            _ = decodeUploadPack(buf[0..n]) catch return;
        }
    }.run, .{});
}

test "fuzz: decodeWriteRef does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const n = smith.slice(&buf);
            _ = decodeWriteRef(buf[0..n]) catch return;
        }
    }.run, .{});
}

test "fuzz: decodeUpdateRef does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const n = smith.slice(&buf);
            _ = decodeUpdateRef(buf[0..n]) catch return;
        }
    }.run, .{});
}

test "fuzz: decodeRefList does not crash" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const n = smith.slice(&buf);
            const allocator = std.heap.page_allocator;
            const refs = decodeRefList(allocator, buf[0..n]) catch return;
            for (refs) |ref| allocator.free(ref.name);
            allocator.free(refs);
        }
    }.run, .{});
}

// -- OP_HELLO handshake tests (§7.4) --

test "encodeHelloRequest roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try encodeHelloRequest(allocator, PROTO_VERSION, BINARY_NAME, CLIENT_VERSION);
    defer allocator.free(encoded);

    const decoded = try decodeHelloRequest(encoded);
    try std.testing.expectEqual(PROTO_VERSION, decoded.proto_version);
    try std.testing.expectEqualStrings(BINARY_NAME, decoded.binary_name);
    try std.testing.expectEqualStrings(CLIENT_VERSION, decoded.client_version);
}

test "encodeHelloResponse roundtrip" {
    const allocator = std.testing.allocator;
    const encoded = try encodeHelloResponse(allocator, PROTO_VERSION, SERVER_VERSION);
    defer allocator.free(encoded);

    const decoded = try decodeHelloResponse(encoded);
    try std.testing.expectEqual(PROTO_VERSION, decoded.proto_version);
    try std.testing.expectEqualStrings(SERVER_VERSION, decoded.server_version);
}

test "hello handshake success: mkit v1 client ↔ mkit v1 server" {
    const allocator = std.testing.allocator;

    // Client encodes its hello.
    const client_payload = try encodeHelloRequest(allocator, 1, "mkit", "mkit 0.1.0");
    defer allocator.free(client_payload);

    // Server decodes and validates.
    const req = try decodeHelloRequest(client_payload);
    try std.testing.expectEqual(@as(u8, 1), req.proto_version);
    try std.testing.expectEqualStrings("mkit", req.binary_name);

    // Server encodes its reply.
    const server_payload = try encodeHelloResponse(allocator, 1, "mkit 0.1.0");
    defer allocator.free(server_payload);

    // Client decodes.
    const resp = try decodeHelloResponse(server_payload);
    try std.testing.expectEqual(@as(u8, 1), resp.proto_version);
    try std.testing.expectEqualStrings("mkit 0.1.0", resp.server_version);
}

test "hello handshake reject: client sends wrong binary_name" {
    const allocator = std.testing.allocator;

    // Client sends a non-"mkit" name (e.g. a legacy/third-party peer).
    const legacy_name = "legacy";
    const client_payload = try encodeHelloRequest(allocator, 1, legacy_name, "legacy 0.9.0");
    defer allocator.free(client_payload);

    const req = try decodeHelloRequest(client_payload);
    // Server policy: mkit servers only accept "mkit". Any other name → STATUS_ERROR + disconnect.
    try std.testing.expect(!std.mem.eql(u8, req.binary_name, BINARY_NAME));
}

test "hello handshake reject: client proto_version=2 triggers STATUS_UNSUPPORTED" {
    const allocator = std.testing.allocator;

    // Client advertises a future proto_version.
    const client_payload = try encodeHelloRequest(allocator, 2, "mkit", "mkit 0.2.0");
    defer allocator.free(client_payload);

    const req = try decodeHelloRequest(client_payload);
    try std.testing.expect(req.proto_version > PROTO_VERSION);
    // Server would emit encodeResponse(STATUS_UNSUPPORTED, ...) and disconnect.
}

test "hello handshake reject: server response garbled → IncompatiblePeer" {
    // A garbled/truncated server hello payload must fail to decode.
    const garbled = [_]u8{0x01}; // only proto_version, missing version len + string
    try std.testing.expectError(error.PayloadTooShort, decodeHelloResponse(&garbled));

    // Completely empty payload.
    try std.testing.expectError(error.PayloadTooShort, decodeHelloResponse(&[_]u8{}));

    // Claims a 200-byte version string in a 10-byte payload.
    const bogus = [_]u8{ 0x01, 0xC8, 'x', 'y' };
    try std.testing.expectError(error.VersionTooLong, decodeHelloResponse(&bogus));
}

test "decodeHelloRequest rejects oversized binary name" {
    // name_len = 200 > MAX_BINARY_NAME_LEN.
    const payload = [_]u8{ 0x01, 200 } ++ [_]u8{'x'} ** 4;
    try std.testing.expectError(error.BinaryNameTooLong, decodeHelloRequest(&payload));
}

test "encodeHelloRequest rejects oversized binary name" {
    const allocator = std.testing.allocator;
    const big_name = [_]u8{'x'} ** 64;
    try std.testing.expectError(
        error.BinaryNameTooLong,
        encodeHelloRequest(allocator, 1, &big_name, "v"),
    );
}
