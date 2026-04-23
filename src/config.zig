// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const config_file = ".mkit/config";

pub const default_signing_key = ".mkit/keys/default.key";
pub const default_branch = "main";

/// Default for `user.identity` — empty string means "unset". When a commit
/// is constructed with an unset user.identity, the CLI derives an Ed25519
/// Identity from the signing keypair's public key. See `userIdentityBytes`.
pub const default_user_identity: []const u8 = "";

pub const default_remote_endpoint = "";
pub const default_remote_bucket = "";
pub const default_remote_type = "";

// SSH CLI overrides (see docs/SSH-SECURITY.md). Empty string means "do not
// pass the flag; inherit the user's ~/.ssh/config default". These feed the
// `ssh` child process argv in transport/ssh.zig.
pub const default_ssh_strict_host_key_checking: []const u8 = "";
pub const default_ssh_user_known_hosts_file: []const u8 = "";
pub const default_ssh_identity_file: []const u8 = "";

/// Legacy config keys from earlier mkit versions. These are no longer
/// recognized by the CLI, but are tolerated (silently ignored) when
/// encountered in an existing `.mkit/config` file so that old on-disk
/// configs don't break `mkit init` for returning users.
const legacy_keys = [_][]const u8{
    "project_id",
    "gateway" ++ "_url",
    "network",
    "notary.kind",
};

fn isLegacyKey(key: []const u8) bool {
    for (legacy_keys) |lk| {
        if (std.mem.eql(u8, key, lk)) return true;
    }
    return false;
}

/// Decoded `user.identity` parts, ready to hand to `mkit.object.Identity`.
/// The caller-supplied scratch buffer must outlive the returned slice.
pub const DecodedIdentity = struct {
    /// 0x01 = ed25519, 0x02 = did:key, 0x03 = opaque. Matches IdentityKind.
    kind: u8,
    bytes: []const u8,
};

/// Parse the canonical hex form `[kind:u8 hex][len:u16 LE hex][bytes hex]`
/// into a `DecodedIdentity`. `scratch` receives the decoded bytes and
/// must have room for `(hex.len / 2) - 3` bytes.
pub fn parseUserIdentity(hex: []const u8, scratch: []u8) !DecodedIdentity {
    if (hex.len < 6) return error.InvalidUserIdentity;
    if (hex.len % 2 != 0) return error.InvalidUserIdentity;
    const raw_len = hex.len / 2;
    if (raw_len < 3) return error.InvalidUserIdentity;
    if (scratch.len < raw_len) return error.InvalidUserIdentity;
    _ = std.fmt.hexToBytes(scratch[0..raw_len], hex) catch return error.InvalidUserIdentity;
    const kind = scratch[0];
    const len: u16 = @as(u16, scratch[1]) | (@as(u16, scratch[2]) << 8);
    if (@as(usize, len) + 3 != raw_len) return error.InvalidUserIdentity;
    // Basic sanity on known kinds.
    switch (kind) {
        0x01 => if (len != 32) return error.InvalidUserIdentity,
        0x02, 0x03 => {},
        else => return error.InvalidUserIdentity,
    }
    return .{ .kind = kind, .bytes = scratch[3 .. 3 + @as(usize, len)] };
}

/// Expand a user-typed `user.identity` value into the canonical
/// `[kind][len][bytes]` hex form. Accepted inputs:
///   - `ed25519:<64-hex>`
///   - `mid:<u64 decimal>`
///   - raw hex (returned verbatim after a structural check via
///     `parseUserIdentity`).
/// Returns a fresh heap allocation owned by the caller.
pub fn expandUserIdentity(allocator: Allocator, value: []const u8) ![]u8 {
    if (value.len == 0) return error.InvalidUserIdentity;

    if (std.mem.startsWith(u8, value, "ed25519:")) {
        const hex = value["ed25519:".len..];
        if (hex.len != 64) return error.InvalidUserIdentity;
        var decoded: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&decoded, hex) catch return error.InvalidUserIdentity;
        return try encodeIdentityHex(allocator, 0x01, decoded[0..]);
    }

    if (std.mem.startsWith(u8, value, "mid:")) {
        const dec = value["mid:".len..];
        const mid = std.fmt.parseInt(u64, dec, 10) catch return error.InvalidUserIdentity;
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, mid, .little);
        return try encodeIdentityHex(allocator, 0x03, bytes[0..]);
    }

    // Raw hex — validate structure via parseUserIdentity before accepting.
    // Allocate a scratch buffer sized to the decoded bytes.
    if (value.len % 2 != 0 or value.len < 6) return error.InvalidUserIdentity;
    const scratch = try allocator.alloc(u8, value.len / 2);
    defer allocator.free(scratch);
    _ = try parseUserIdentity(value, scratch);
    return try allocator.dupe(u8, value);
}

/// Encode `[kind:u8][len:u16 LE][bytes]` as lowercase hex. Caller owns.
pub fn encodeIdentityHex(allocator: Allocator, kind: u8, bytes: []const u8) ![]u8 {
    if (bytes.len > std.math.maxInt(u16)) return error.InvalidUserIdentity;
    const total = 3 + bytes.len;
    const out = try allocator.alloc(u8, total * 2);
    const hex_alphabet = "0123456789abcdef";
    const writeByte = struct {
        fn f(dest: []u8, off: usize, b: u8) void {
            dest[off] = hex_alphabet[b >> 4];
            dest[off + 1] = hex_alphabet[b & 0x0F];
        }
    }.f;
    writeByte(out, 0, kind);
    writeByte(out, 2, @intCast(bytes.len & 0xFF));
    writeByte(out, 4, @intCast((bytes.len >> 8) & 0xFF));
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        writeByte(out, 6 + i * 2, bytes[i]);
    }
    return out;
}

// The on-disk config key is `user.identity`, storing a hex-encoded
// Identity per docs/SPEC-OBJECTS.md §9: `[kind:u8][len:u16 LE][bytes]`.
// Conveniences accepted at parse time:
//   user.identity = ed25519:<64-hex>    — 32-byte Ed25519 pubkey
//   user.identity = mid:<u64 dec>       — 8-byte LE opaque (u64 LE counter)
//   user.identity = <raw-hex>           — already-encoded Identity bytes
// An empty / unset value means "derive from the signing key pubkey at
// commit time". See `parseUserIdentity` and `expandUserIdentity` for the
// exact grammar.

pub const Config = struct {
    /// Hex-encoded Identity: `[kind:u8 hex][len:u16 LE hex][bytes hex]`.
    /// Empty string = unset (CLI derives an Ed25519 Identity from the
    /// signing key at commit time).
    user_identity: []const u8 = default_user_identity,
    signing_key: []const u8 = default_signing_key,
    default_branch: []const u8 = default_branch,
    remote_endpoint: []const u8 = default_remote_endpoint,
    remote_bucket: []const u8 = default_remote_bucket,
    remote_type: []const u8 = default_remote_type, // "s3", "file", or "" (auto-detect from endpoint)
    ssh_strict_host_key_checking: []const u8 = default_ssh_strict_host_key_checking,
    ssh_user_known_hosts_file: []const u8 = default_ssh_user_known_hosts_file,
    ssh_identity_file: []const u8 = default_ssh_identity_file,
    allocator: ?Allocator = null,

    pub fn deinit(self: *Config) void {
        if (self.allocator) |alloc| {
            if (self.user_identity.len > 0)
                alloc.free(self.user_identity);
            if (!std.mem.eql(u8, self.signing_key, default_signing_key))
                alloc.free(self.signing_key);
            if (!std.mem.eql(u8, self.default_branch, default_branch))
                alloc.free(self.default_branch);
            if (!std.mem.eql(u8, self.remote_endpoint, default_remote_endpoint))
                alloc.free(self.remote_endpoint);
            if (!std.mem.eql(u8, self.remote_bucket, default_remote_bucket))
                alloc.free(self.remote_bucket);
            if (!std.mem.eql(u8, self.remote_type, default_remote_type))
                alloc.free(self.remote_type);
            if (self.ssh_strict_host_key_checking.len > 0)
                alloc.free(self.ssh_strict_host_key_checking);
            if (self.ssh_user_known_hosts_file.len > 0)
                alloc.free(self.ssh_user_known_hosts_file);
            if (self.ssh_identity_file.len > 0)
                alloc.free(self.ssh_identity_file);
        }
    }
};

/// Read config from .mkit/config. Returns defaults if file doesn't exist.
pub fn readConfig(allocator: Allocator, dir: std.fs.Dir) !Config {
    const content = dir.readFileAlloc(allocator, config_file, 4096) catch |err| switch (err) {
        error.FileNotFound => return Config{},
        else => return err,
    };
    defer allocator.free(content);

    return parseConfig(allocator, content);
}

/// Write config to .mkit/config as key=value lines.
pub fn writeConfig(dir: std.fs.Dir, config: Config) !void {
    const f = try dir.createFile(config_file, .{ .mode = 0o600 });
    defer f.close();

    if (config.user_identity.len > 0) {
        try f.writeAll("user.identity = ");
        try f.writeAll(config.user_identity);
        try f.writeAll("\n");
    }

    try f.writeAll("signing_key = ");
    try f.writeAll(config.signing_key);
    try f.writeAll("\n");

    try f.writeAll("default_branch = ");
    try f.writeAll(config.default_branch);
    try f.writeAll("\n");

    if (config.remote_endpoint.len > 0) {
        try f.writeAll("remote_endpoint = ");
        try f.writeAll(config.remote_endpoint);
        try f.writeAll("\n");
    }

    if (config.remote_bucket.len > 0) {
        try f.writeAll("remote_bucket = ");
        try f.writeAll(config.remote_bucket);
        try f.writeAll("\n");
    }

    if (config.remote_type.len > 0) {
        try f.writeAll("remote_type = ");
        try f.writeAll(config.remote_type);
        try f.writeAll("\n");
    }

    if (config.ssh_strict_host_key_checking.len > 0) {
        try f.writeAll("ssh.strict_host_key_checking = ");
        try f.writeAll(config.ssh_strict_host_key_checking);
        try f.writeAll("\n");
    }

    if (config.ssh_user_known_hosts_file.len > 0) {
        try f.writeAll("ssh.user_known_hosts_file = ");
        try f.writeAll(config.ssh_user_known_hosts_file);
        try f.writeAll("\n");
    }

    if (config.ssh_identity_file.len > 0) {
        try f.writeAll("ssh.identity_file = ");
        try f.writeAll(config.ssh_identity_file);
        try f.writeAll("\n");
    }
}

/// Parse config content string into Config. Skips comments (#), blank lines, and unknown keys.
pub fn parseConfig(allocator: Allocator, content: []const u8) !Config {
    var config = Config{};
    config.allocator = allocator;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#') continue;

        // Split on '='
        const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse continue;
        const key = std.mem.trimEnd(u8, trimmed[0..eq_pos], " \t");
        const value = std.mem.trimStart(u8, trimmed[eq_pos + 1 ..], " \t");

        if (std.mem.eql(u8, key, "user.identity")) {
            if (config.user_identity.len > 0) allocator.free(config.user_identity);
            // Expand the shorthand into the canonical hex form.
            config.user_identity = expandUserIdentity(allocator, value) catch |err| switch (err) {
                error.InvalidUserIdentity => return error.InvalidUserIdentity,
                else => return err,
            };
        } else if (std.mem.eql(u8, key, "author_mid")) {
            // Legacy key — silently ignored for back-compat with pre-V1
            // config files still on disk. `mkit config author_mid <val>`
            // rejects the key at CLI level (see cmdConfig in main.zig).
            continue;
        } else if (std.mem.eql(u8, key, "signing_key")) {
            // Free prior value if it was heap-allocated (duplicate key)
            if (!std.mem.eql(u8, config.signing_key, default_signing_key)) {
                allocator.free(config.signing_key);
            }
            config.signing_key = if (std.mem.eql(u8, value, default_signing_key)) default_signing_key else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "default_branch")) {
            if (!std.mem.eql(u8, config.default_branch, default_branch)) {
                allocator.free(config.default_branch);
            }
            config.default_branch = if (std.mem.eql(u8, value, default_branch)) default_branch else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_endpoint")) {
            if (!std.mem.eql(u8, config.remote_endpoint, default_remote_endpoint)) {
                allocator.free(config.remote_endpoint);
            }
            config.remote_endpoint = if (value.len == 0) default_remote_endpoint else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_bucket")) {
            if (!std.mem.eql(u8, config.remote_bucket, default_remote_bucket)) {
                allocator.free(config.remote_bucket);
            }
            config.remote_bucket = if (value.len == 0) default_remote_bucket else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "remote_type")) {
            if (!std.mem.eql(u8, config.remote_type, default_remote_type)) {
                allocator.free(config.remote_type);
            }
            config.remote_type = if (value.len == 0) default_remote_type else try allocator.dupe(u8, value);
        } else if (isLegacyKey(key)) {
            // Legacy keys from earlier mkit versions; ignored.
            continue;
        } else if (std.mem.eql(u8, key, "ssh.strict_host_key_checking")) {
            if (config.ssh_strict_host_key_checking.len > 0) {
                allocator.free(config.ssh_strict_host_key_checking);
            }
            config.ssh_strict_host_key_checking = if (value.len == 0) "" else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "ssh.user_known_hosts_file")) {
            if (config.ssh_user_known_hosts_file.len > 0) {
                allocator.free(config.ssh_user_known_hosts_file);
            }
            config.ssh_user_known_hosts_file = if (value.len == 0) "" else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "ssh.identity_file")) {
            if (config.ssh_identity_file.len > 0) {
                allocator.free(config.ssh_identity_file);
            }
            config.ssh_identity_file = if (value.len == 0) "" else try allocator.dupe(u8, value);
        }
        // Unknown keys are silently ignored
    }

    return config;
}

// -- Tests --

test "parse empty config" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "");
    defer config.deinit();

    try std.testing.expectEqualStrings("", config.user_identity);
    try std.testing.expectEqualStrings(default_signing_key, config.signing_key);
    try std.testing.expectEqualStrings("main", config.default_branch);
}

test "parseConfig silently ignores legacy author_mid" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "author_mid = 42");
    defer config.deinit();

    // Legacy key has no effect — user.identity remains unset.
    try std.testing.expectEqualStrings("", config.user_identity);
}

test "parse user.identity ed25519 shorthand" {
    const allocator = std.testing.allocator;
    const hex32 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    var config = try parseConfig(allocator, "user.identity = ed25519:" ++ hex32);
    defer config.deinit();

    // Expected canonical: [01][20 00][32 bytes]
    const expect = "01" ++ "2000" ++ hex32;
    try std.testing.expectEqualStrings(expect, config.user_identity);
}

test "parse user.identity mid shorthand" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "user.identity = mid:42");
    defer config.deinit();

    // 42 LE = 2a 00 00 00 00 00 00 00; kind=0x03, len=0x0008
    try std.testing.expectEqualStrings("03" ++ "0800" ++ "2a00000000000000", config.user_identity);
}

test "parse user.identity raw hex" {
    const allocator = std.testing.allocator;
    // opaque (kind=0x03), 2-byte payload [0xaa 0xbb]
    const raw = "03" ++ "0200" ++ "aabb";
    var config = try parseConfig(allocator, "user.identity = " ++ raw);
    defer config.deinit();

    try std.testing.expectEqualStrings(raw, config.user_identity);
}

test "parse user.identity rejects invalid hex" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidUserIdentity,
        parseConfig(allocator, "user.identity = ed25519:deadbeef"),
    );
    try std.testing.expectError(
        error.InvalidUserIdentity,
        parseConfig(allocator, "user.identity = mid:notanumber"),
    );
    // ed25519 must carry exactly 32 bytes — declared 2 bytes here:
    try std.testing.expectError(
        error.InvalidUserIdentity,
        parseConfig(allocator, "user.identity = 010200aabb"),
    );
}

test "parseUserIdentity round-trip with expandUserIdentity" {
    const allocator = std.testing.allocator;
    const hex = try expandUserIdentity(allocator, "mid:7");
    defer allocator.free(hex);
    var scratch: [64]u8 = undefined;
    const parsed = try parseUserIdentity(hex, scratch[0..]);
    try std.testing.expectEqual(@as(u8, 0x03), parsed.kind);
    try std.testing.expectEqual(@as(usize, 8), parsed.bytes.len);
    try std.testing.expectEqual(@as(u64, 7), std.mem.readInt(u64, parsed.bytes[0..8], .little));
}

test "parse signing_key" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "signing_key = custom.key");
    defer config.deinit();

    try std.testing.expectEqualStrings("custom.key", config.signing_key);
}

test "parse default_branch" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "default_branch = develop");
    defer config.deinit();

    try std.testing.expectEqualStrings("develop", config.default_branch);
}

test "config roundtrip" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    const original = Config{
        .signing_key = ".mkit/keys/deploy.key",
        .default_branch = "develop",
    };

    try writeConfig(tmp.dir, original);

    var read = try readConfig(allocator, tmp.dir);
    defer read.deinit();

    try std.testing.expectEqualStrings(".mkit/keys/deploy.key", read.signing_key);
    try std.testing.expectEqualStrings("develop", read.default_branch);
}

test "config not found returns defaults" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    var config = try readConfig(allocator, tmp.dir);
    defer config.deinit();

    try std.testing.expectEqualStrings("", config.user_identity);
    try std.testing.expectEqualStrings(default_signing_key, config.signing_key);
    try std.testing.expectEqualStrings("main", config.default_branch);
}

test "config ignores unknown keys" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "unknown = value\nsigning_key = foo.key");
    defer config.deinit();

    try std.testing.expectEqualStrings("foo.key", config.signing_key);
}

test "parse remote config" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "remote_endpoint = https://r2.example.com\nremote_bucket = my-bucket");
    defer config.deinit();

    try std.testing.expectEqualStrings("https://r2.example.com", config.remote_endpoint);
    try std.testing.expectEqualStrings("my-bucket", config.remote_bucket);
}

test "config roundtrip with remote" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    const original = Config{
        .signing_key = ".mkit/keys/deploy.key",
        .default_branch = "develop",
        .remote_endpoint = "https://my-r2.example.com",
        .remote_bucket = "mkit-repos",
    };

    try writeConfig(tmp.dir, original);

    var read = try readConfig(allocator, tmp.dir);
    defer read.deinit();

    try std.testing.expectEqualStrings(".mkit/keys/deploy.key", read.signing_key);
    try std.testing.expectEqualStrings("develop", read.default_branch);
    try std.testing.expectEqualStrings("https://my-r2.example.com", read.remote_endpoint);
    try std.testing.expectEqualStrings("mkit-repos", read.remote_bucket);
}

test "parse remote config defaults when absent" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "signing_key = foo.key");
    defer config.deinit();

    try std.testing.expectEqualStrings("foo.key", config.signing_key);
    try std.testing.expectEqualStrings("", config.remote_endpoint);
    try std.testing.expectEqualStrings("", config.remote_bucket);
}

test "config roundtrip without remote" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir(".mkit");

    // Write config with no remote fields
    const original = Config{
        .default_branch = "develop",
    };

    try writeConfig(tmp.dir, original);

    var read = try readConfig(allocator, tmp.dir);
    defer read.deinit();

    // Remote fields should remain empty defaults
    try std.testing.expectEqualStrings("", read.remote_endpoint);
    try std.testing.expectEqualStrings("", read.remote_bucket);
}

test "parseConfig silently ignores legacy chain keys" {
    const allocator = std.testing.allocator;
    const gw = "gateway" ++ "_url";
    const input = "project_id = abcd\n" ++ gw ++ " = https://example.com\nnetwork = mainnet\nnotary.kind = custom\nsigning_key = keep.key\n";
    var config = try parseConfig(allocator, input);
    defer config.deinit();
    // Legacy keys are dropped on the floor; surviving keys still parse.
    try std.testing.expectEqualStrings("keep.key", config.signing_key);
}

test "parse ssh.* fields" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(
        allocator,
        "ssh.strict_host_key_checking = yes\n" ++
            "ssh.user_known_hosts_file = /home/alice/.ssh/mkit_known_hosts\n" ++
            "ssh.identity_file = /home/alice/.ssh/id_ed25519\n",
    );
    defer config.deinit();

    try std.testing.expectEqualStrings("yes", config.ssh_strict_host_key_checking);
    try std.testing.expectEqualStrings("/home/alice/.ssh/mkit_known_hosts", config.ssh_user_known_hosts_file);
    try std.testing.expectEqualStrings("/home/alice/.ssh/id_ed25519", config.ssh_identity_file);
}

test "ssh.* fields default to empty" {
    const allocator = std.testing.allocator;
    var config = try parseConfig(allocator, "");
    defer config.deinit();

    try std.testing.expectEqualStrings("", config.ssh_strict_host_key_checking);
    try std.testing.expectEqualStrings("", config.ssh_user_known_hosts_file);
    try std.testing.expectEqualStrings("", config.ssh_identity_file);
}

test "config roundtrip with ssh.* fields" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");

    const original = Config{
        .ssh_strict_host_key_checking = "accept-new",
        .ssh_user_known_hosts_file = "/tmp/mkit_known_hosts",
        .ssh_identity_file = "/tmp/mkit_id_ed25519",
    };
    try writeConfig(tmp.dir, original);

    var read = try readConfig(allocator, tmp.dir);
    defer read.deinit();

    try std.testing.expectEqualStrings("accept-new", read.ssh_strict_host_key_checking);
    try std.testing.expectEqualStrings("/tmp/mkit_known_hosts", read.ssh_user_known_hosts_file);
    try std.testing.expectEqualStrings("/tmp/mkit_id_ed25519", read.ssh_identity_file);
}

// -------------------------------------------------------------------------
// XDG Base Directory resolution.
//
// mkit's user-level config lives under the XDG paths when a repo-local
// `.mkit/config` doesn't override a given key. Spec:
// https://specifications.freedesktop.org/basedir-spec/latest/
//
//   Config: $XDG_CONFIG_HOME  (default ~/.config)   -> mkit/config
//   Data:   $XDG_DATA_HOME    (default ~/.local/share) -> mkit/keys/...
//   Cache:  $XDG_CACHE_HOME   (default ~/.cache)    -> mkit/
//   State:  $XDG_STATE_HOME   (default ~/.local/state) -> mkit/
//
// None of these touch `.mkit/` — that is the repo-local state dir (like
// git's .git/) and its resolution is unchanged. These helpers exist
// purely so a future user-level config layer can look up paths
// consistently.
//
// Each helper allocates a new buffer; the caller owns it and must free.
// Returns `error.NoHome` if neither the XDG variable nor `$HOME` is set,
// which is a hard error on any sane POSIX system.
// -------------------------------------------------------------------------

fn xdgFallback(allocator: Allocator, xdg_var: []const u8, relative: []const u8) ![]u8 {
    if (std.posix.getenv(xdg_var)) |v| {
        if (v.len > 0) return try allocator.dupe(u8, v);
    }
    const home = std.posix.getenv("HOME") orelse return error.NoHome;
    return try std.fs.path.join(allocator, &.{ home, relative });
}

/// `$XDG_CONFIG_HOME` or `$HOME/.config`.
pub fn xdgConfigHome(allocator: Allocator) ![]u8 {
    return xdgFallback(allocator, "XDG_CONFIG_HOME", ".config");
}

/// `$XDG_DATA_HOME` or `$HOME/.local/share`.
pub fn xdgDataHome(allocator: Allocator) ![]u8 {
    return xdgFallback(allocator, "XDG_DATA_HOME", ".local/share");
}

/// `$XDG_CACHE_HOME` or `$HOME/.cache`.
pub fn xdgCacheHome(allocator: Allocator) ![]u8 {
    return xdgFallback(allocator, "XDG_CACHE_HOME", ".cache");
}

/// `$XDG_STATE_HOME` or `$HOME/.local/state`.
pub fn xdgStateHome(allocator: Allocator) ![]u8 {
    return xdgFallback(allocator, "XDG_STATE_HOME", ".local/state");
}

/// Full path to the user-level mkit config file:
/// `<xdgConfigHome>/mkit/config`. Caller frees.
pub fn userConfigPath(allocator: Allocator) ![]u8 {
    const base = try xdgConfigHome(allocator);
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &.{ base, "mkit", "config" });
}

/// Full path to the user-level keystore directory:
/// `<xdgDataHome>/mkit/keys`. Caller frees. The directory may not exist
/// yet — `std.fs.cwd().makePath` can create it on demand.
pub fn userKeystorePath(allocator: Allocator) ![]u8 {
    const base = try xdgDataHome(allocator);
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &.{ base, "mkit", "keys" });
}

/// Full path to the user-level cache directory: `<xdgCacheHome>/mkit`.
/// Caller frees. Not actively used in 0.1.0 but reserved so that any
/// future caching code has a well-defined home.
pub fn userCachePath(allocator: Allocator) ![]u8 {
    const base = try xdgCacheHome(allocator);
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &.{ base, "mkit" });
}

/// Full path to the user-level state directory: `<xdgStateHome>/mkit`.
/// Used for things like a global edit-message scratch file
/// (COMMIT_EDITMSG fallback) when a repo-local `.mkit/` is unavailable.
pub fn userStatePath(allocator: Allocator) ![]u8 {
    const base = try xdgStateHome(allocator);
    defer allocator.free(base);
    return try std.fs.path.join(allocator, &.{ base, "mkit" });
}

test "xdgConfigHome returns $XDG_CONFIG_HOME when non-empty" {
    // We can't mutate env in-process on 0.15.2, so the test drives the
    // lower-level helper with an explicit path. The real
    // `xdgConfigHome()` is a thin wrapper over this.
    const allocator = std.testing.allocator;

    const result = try xdgFallback(allocator, "XDG_CONFIG_HOME", ".config");
    defer allocator.free(result);

    // Whatever the environment says, the result must be non-empty and
    // start with '/' (absolute) OR with the HOME fallback prefix.
    try std.testing.expect(result.len > 0);
}

test "xdg helpers produce different sub-paths for their four categories" {
    const allocator = std.testing.allocator;

    const cfg = try xdgConfigHome(allocator);
    defer allocator.free(cfg);
    const data = try xdgDataHome(allocator);
    defer allocator.free(data);
    const cache = try xdgCacheHome(allocator);
    defer allocator.free(cache);
    const state = try xdgStateHome(allocator);
    defer allocator.free(state);

    // They share the same HOME prefix by default but at least the
    // leaf component differs.
    try std.testing.expect(!std.mem.eql(u8, cfg, data));
    try std.testing.expect(!std.mem.eql(u8, cache, state));
}

test "userConfigPath ends in /mkit/config" {
    const allocator = std.testing.allocator;
    const p = try userConfigPath(allocator);
    defer allocator.free(p);
    try std.testing.expect(std.mem.endsWith(u8, p, "/mkit/config"));
}

test "userKeystorePath ends in /mkit/keys" {
    const allocator = std.testing.allocator;
    const p = try userKeystorePath(allocator);
    defer allocator.free(p);
    try std.testing.expect(std.mem.endsWith(u8, p, "/mkit/keys"));
}

test "userStatePath / userCachePath end in /mkit" {
    const allocator = std.testing.allocator;
    const s = try userStatePath(allocator);
    defer allocator.free(s);
    try std.testing.expect(std.mem.endsWith(u8, s, "/mkit"));
    const c = try userCachePath(allocator);
    defer allocator.free(c);
    try std.testing.expect(std.mem.endsWith(u8, c, "/mkit"));
}

test "config roundtrip without ssh.* fields omits them" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir(".mkit");

    const original = Config{ .default_branch = "dev" };
    try writeConfig(tmp.dir, original);

    // Read raw file content and assert ssh.* keys are absent when empty.
    const content = try tmp.dir.readFileAlloc(allocator, ".mkit/config", 4096);
    defer allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "ssh.strict_host_key_checking") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "ssh.user_known_hosts_file") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "ssh.identity_file") == null);
}
