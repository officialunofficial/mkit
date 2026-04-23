// SPDX-License-Identifier: MIT OR Apache-2.0
//
// External signer — subprocess-based `Signer` impl.
//
// Protocol (SPEC-ATTESTATIONS §6.2):
//
//     spawn  `<binary>` with stdin/stdout/stderr pipes
//     write   {"pae_base64":"<...>"}\n     to child stdin, then close stdin
//     read    {"keyid":"<...>","sig_base64":"<...>"}  from child stdout
//     wait    child to exit; exit 0 = success, non-zero = failure
//
// On non-zero exit the child's stderr is forwarded via `std.debug.print`
// with an `external signer: ` prefix, and the caller sees
// `error.ExternalSignerFailed`.
//
// Note on `keyid`: the protocol only surfaces the keyid in the child's
// response to a sign request. We cache it on the first `signDsse` call;
// calling `keyid()` before any `signDsse()` returns
// `error.KeyIdNotKnownUntilFirstSign`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const signer_mod = @import("signer.zig");
const Signer = signer_mod.Signer;

/// Cap for each of child-stdout and child-stderr. 1 MiB is generous —
/// the protocol response is a single JSON line.
const MAX_DRAIN = 1 * 1024 * 1024;

pub const ExternalSigner = struct {
    allocator: Allocator,
    io: std.Io,
    binary_path: []const u8,
    /// Cached keyid from the most recent `signDsse` response, if any.
    /// Owned by this struct; freed in `deinit`.
    cached_keyid: ?[]u8 = null,

    pub fn init(allocator: Allocator, io: std.Io, binary_path: []const u8) ExternalSigner {
        return .{
            .allocator = allocator,
            .io = io,
            .binary_path = binary_path,
        };
    }

    pub fn deinit(self: *ExternalSigner) void {
        if (self.cached_keyid) |k| {
            self.allocator.free(k);
            self.cached_keyid = null;
        }
    }

    pub fn asSigner(self: *ExternalSigner) Signer {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    const vtable: Signer.VTable = .{
        .keyid = keyidImpl,
        .signDsse = signDsseImpl,
    };

    fn keyidImpl(ptr: *anyopaque, allocator: Allocator) anyerror![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(ptr));
        const k = self.cached_keyid orelse return error.KeyIdNotKnownUntilFirstSign;
        return allocator.dupe(u8, k);
    }

    fn signDsseImpl(ptr: *anyopaque, allocator: Allocator, pae: []const u8) anyerror![]u8 {
        const self: *ExternalSigner = @ptrCast(@alignCast(ptr));
        return self.runOnce(allocator, pae);
    }

    /// One round-trip: spawn → write request → drain stdout+stderr → wait.
    /// Stores the returned keyid in `cached_keyid` on success.
    fn runOnce(self: *ExternalSigner, allocator: Allocator, pae: []const u8) anyerror![]u8 {
        // Build the request body: {"pae_base64":"<..>"}\n
        const b64 = std.base64.standard.Encoder;
        const pae_b64 = try allocator.alloc(u8, b64.calcSize(pae.len));
        defer allocator.free(pae_b64);
        _ = b64.encode(pae_b64, pae);

        const request = try std.fmt.allocPrint(
            allocator,
            "{{\"pae_base64\":\"{s}\"}}\n",
            .{pae_b64},
        );
        defer allocator.free(request);

        const argv = [_][]const u8{self.binary_path};
        var child = try std.process.spawn(self.io, .{
            .argv = argv[0..],
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });

        // If anything below fails before we wait, make sure we don't leak the child.
        var waited = false;
        errdefer {
            if (!waited) {
                if (child.stdin) |*stdin| {
                    stdin.close(self.io);
                    child.stdin = null;
                }
                child.kill(self.io);
            }
        }

        // Write the request, then close stdin so the child sees EOF.
        if (child.stdin) |*stdin| {
            stdin.writeStreamingAll(self.io, request) catch |e| {
                stdin.close(self.io);
                child.stdin = null;
                return e;
            };
            stdin.close(self.io);
            child.stdin = null;
        } else return error.ExternalSignerSpawnBroken;

        // Drain stdout then stderr. The protocol response is a single short
        // line, so reading sequentially is fine as long as the child's stderr
        // doesn't overflow the pipe before we get to it. `MAX_DRAIN` bounds
        // both to 1 MiB each.
        const stdout_buf = try drainFile(allocator, self.io, child.stdout.?);
        errdefer allocator.free(stdout_buf);
        child.stdout.?.close(self.io);
        child.stdout = null;

        const stderr_buf = try drainFile(allocator, self.io, child.stderr.?);
        defer allocator.free(stderr_buf);
        child.stderr.?.close(self.io);
        child.stderr = null;

        const term = try child.wait(self.io);
        waited = true;

        switch (term) {
            .exited => |code| if (code != 0) {
                if (stderr_buf.len > 0) {
                    std.debug.print("external signer: {s}", .{stderr_buf});
                    if (stderr_buf[stderr_buf.len - 1] != '\n') std.debug.print("\n", .{});
                }
                allocator.free(stdout_buf);
                return error.ExternalSignerFailed;
            },
            else => {
                if (stderr_buf.len > 0) {
                    std.debug.print("external signer: {s}", .{stderr_buf});
                    if (stderr_buf[stderr_buf.len - 1] != '\n') std.debug.print("\n", .{});
                }
                allocator.free(stdout_buf);
                return error.ExternalSignerFailed;
            },
        }

        // Parse the response line.
        const response_line = trimTrailing(stdout_buf, "\r\n ");
        const parsed = parseResponse(allocator, response_line) catch |e| {
            allocator.free(stdout_buf);
            return e;
        };
        defer {
            allocator.free(parsed.keyid);
            allocator.free(parsed.sig);
        }
        allocator.free(stdout_buf);

        // Cache keyid for future keyid() calls.
        if (self.cached_keyid) |old| self.allocator.free(old);
        self.cached_keyid = try self.allocator.dupe(u8, parsed.keyid);

        return allocator.dupe(u8, parsed.sig);
    }
};

fn trimTrailing(buf: []const u8, drop: []const u8) []const u8 {
    var end = buf.len;
    while (end > 0) {
        const c = buf[end - 1];
        if (std.mem.indexOfScalar(u8, drop, c) == null) break;
        end -= 1;
    }
    return buf[0..end];
}

fn drainFile(allocator: Allocator, io: std.Io, file: std.Io.File) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = file.readStreaming(io, &.{&chunk}) catch |e| switch (e) {
            error.EndOfStream => break,
            else => return e,
        };
        if (n == 0) break;
        if (buf.items.len + n > MAX_DRAIN) return error.ExternalSignerOutputTooLarge;
        try buf.appendSlice(allocator, chunk[0..n]);
    }
    return buf.toOwnedSlice(allocator);
}

const ParsedResponse = struct {
    keyid: []u8,
    sig: []u8, // raw signature bytes (base64-decoded)
};

/// Minimal parser for {"keyid":"<..>","sig_base64":"<..>"}. Accepts that
/// exact shape in that exact order with no whitespace — same strictness
/// philosophy as the DSSE envelope decoder.
fn parseResponse(allocator: Allocator, line: []const u8) !ParsedResponse {
    const b64 = std.base64.standard.Decoder;

    var p = StringParser{ .src = line, .pos = 0 };
    try p.expect("{\"keyid\":");
    const keyid = try p.takeString(allocator);
    errdefer allocator.free(keyid);
    try p.expect(",\"sig_base64\":");
    const sig_b64 = try p.takeString(allocator);
    defer allocator.free(sig_b64);
    try p.expect("}");
    if (p.pos != p.src.len) return error.ExternalSignerBadResponse;

    const sig_len = b64.calcSizeForSlice(sig_b64) catch return error.ExternalSignerBadResponse;
    const sig = try allocator.alloc(u8, sig_len);
    errdefer allocator.free(sig);
    b64.decode(sig, sig_b64) catch return error.ExternalSignerBadResponse;

    return .{ .keyid = keyid, .sig = sig };
}

const StringParser = struct {
    src: []const u8,
    pos: usize,

    fn expect(self: *StringParser, s: []const u8) !void {
        if (self.pos + s.len > self.src.len) return error.ExternalSignerBadResponse;
        if (!std.mem.eql(u8, self.src[self.pos .. self.pos + s.len], s)) return error.ExternalSignerBadResponse;
        self.pos += s.len;
    }

    fn takeString(self: *StringParser, allocator: Allocator) ![]u8 {
        if (self.pos >= self.src.len or self.src[self.pos] != '"') return error.ExternalSignerBadResponse;
        self.pos += 1;
        const start = self.pos;
        while (self.pos < self.src.len and self.src[self.pos] != '"') : (self.pos += 1) {
            if (self.src[self.pos] == '\\') return error.ExternalSignerBadResponse;
        }
        if (self.pos >= self.src.len) return error.ExternalSignerBadResponse;
        const buf = try allocator.dupe(u8, self.src[start..self.pos]);
        self.pos += 1;
        return buf;
    }
};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

const builtin = @import("builtin");
const testing = std.testing;

test "external signer: echoes keyid and sig from subprocess" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = testing.allocator;

    // Inline `sh -c` script: ignore stdin entirely and emit a fixed
    // response. "AQID" = base64("\x01\x02\x03").
    const script =
        "cat >/dev/null; " ++
        "printf '{\"keyid\":\"test:abc\",\"sig_base64\":\"AQID\"}\\n'";

    // We parameterise the signer by binary path — but the protocol spawns
    // that path with no args. So we pass a tiny wrapper that re-execs sh -c.
    // Easier: drive the low-level runOnce() via a fake binary_path that is
    // actually a path to a throwaway shell script. For this test we just
    // shell out to sh via a temp file.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const script_path_rel = "signer.sh";
    {
        const f = try tmp.dir.createFile(testing.io, script_path_rel, .{ .permissions = .executable_file });
        defer f.close(testing.io);
        try f.writeStreamingAll(testing.io, "#!/bin/sh\n");
        try f.writeStreamingAll(testing.io, script);
        try f.writeStreamingAll(testing.io, "\n");
    }

    // Realpath the script so spawn can find it regardless of cwd.
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const script_abs = blk: {
        const f = try tmp.dir.openFile(testing.io, script_path_rel, .{});
        defer f.close(testing.io);
        const n = try f.realPath(testing.io, &path_buf);
        break :blk path_buf[0..n];
    };

    var ext = ExternalSigner.init(allocator, testing.io, script_abs);
    defer ext.deinit();
    const s = ext.asSigner();

    // keyid before any sign call → error.
    try testing.expectError(error.KeyIdNotKnownUntilFirstSign, s.keyid(allocator));

    const sig = try s.signDsse(allocator, "DSSEv1 4 test 0 ");
    defer allocator.free(sig);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, sig);

    // Now keyid() returns the cached value.
    const kid = try s.keyid(allocator);
    defer allocator.free(kid);
    try testing.expectEqualStrings("test:abc", kid);
}

test "external signer: non-zero exit surfaces ExternalSignerFailed" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = testing.allocator;

    const script =
        "cat >/dev/null; " ++
        "printf 'boom\\n' 1>&2; " ++
        "exit 1";

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const script_path_rel = "bad.sh";
    {
        const f = try tmp.dir.createFile(testing.io, script_path_rel, .{ .permissions = .executable_file });
        defer f.close(testing.io);
        try f.writeStreamingAll(testing.io, "#!/bin/sh\n");
        try f.writeStreamingAll(testing.io, script);
        try f.writeStreamingAll(testing.io, "\n");
    }

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const script_abs = blk: {
        const f = try tmp.dir.openFile(testing.io, script_path_rel, .{});
        defer f.close(testing.io);
        const n = try f.realPath(testing.io, &path_buf);
        break :blk path_buf[0..n];
    };

    var ext = ExternalSigner.init(allocator, testing.io, script_abs);
    defer ext.deinit();
    const s = ext.asSigner();

    try testing.expectError(error.ExternalSignerFailed, s.signDsse(allocator, "DSSEv1 4 test 0 "));
}
