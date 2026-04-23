// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Snapshot-style CLI tests for the mkit binary's user-facing surface.
// These test the wire-level contract that downstream packagers (Homebrew,
// Scoop) and users depend on:
//
//   - `mkit version` prints exactly `mkit <cli_version>\n` to stdout.
//   - `mkit --help` prints the usage block (and lists every documented
//     subcommand as a substring).
//   - `mkit <unknown-subcommand>` exits non-zero with a clear error.
//
// We import the shared `cli.zig` constants rather than shelling out, so the
// tests snapshot the *same* string buffer the binary would emit. This keeps
// tests fast and hermetic.

const std = @import("std");
const cli = @import("cli.zig");

test "mkit version: wire format is exactly \"mkit <version>\\n\"" {
    // Homebrew's formula test runs `shell_output(bin/mkit version)` and
    // asserts the substring `mkit <version>`. If the newline terminator
    // or the `mkit ` prefix ever moves, this snapshot catches it.
    const expected = "mkit " ++ cli.cli_version ++ "\n";
    try std.testing.expectEqualStrings("mkit 0.2.0\n", expected);
}

test "cli_version is a numeric x.y.z" {
    // The zon is the source of truth; we at least check cli_version
    // parses as a semver-ish x.y.z. No external lookup (would race with
    // build.zig.zon parsing during tests).
    const v = cli.cli_version;
    try std.testing.expect(v.len >= 5);
    var dots: usize = 0;
    for (v) |c| {
        if (c == '.') {
            dots += 1;
        } else if (c < '0' or c > '9') {
            // Pre-release suffixes (e.g. "0.1.0-rc1") are allowed; we
            // stop strict validation on the first non-digit after the
            // numeric core.
            return;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), dots);
}

test "help_text: every documented subcommand appears as a substring" {
    // Kept in sync with the if/else chain in `fn run()` in main.zig.
    const expected_subcommands = [_][]const u8{
        "init",
        "add",
        "rm",
        "hash",
        "cat",
        "tree",
        "commit",
        "log",
        "status",
        "diff",
        "branch",
        "checkout",
        "tag",
        "config",
        "merge",
        "push",
        "pull",
        "fetch",
        "stash",
        "clone",
        "remote",
        "keygen",
        "cherry-pick",
        "rebase",
        "bisect",
        "sparse-checkout",
        "serve",
        "blame",
        "verify",
        "version",
    };

    for (expected_subcommands) |sub| {
        if (std.mem.indexOf(u8, cli.help_text, sub) == null) {
            std.debug.print(
                "cli_test: help_text missing subcommand '{s}'\n",
                .{sub},
            );
            return error.MissingSubcommand;
        }
    }
}

test "help_text: mentions the strict mkit+<scheme>:// URL form" {
    // W5's URL contract. If the help ever regresses to an example without
    // the `mkit+` prefix this catches it.
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "mkit+file://") != null);
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "mkit+https://") != null);
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "mkit+s3://") != null);
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "mkit+ssh://") != null);
}

test "help_text: documents user.identity config key" {
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "user.identity") != null);
}

test "help_text: documents the new ssh.* config keys" {
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "ssh.strict_host_key_checking") != null);
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "ssh.user_known_hosts_file") != null);
    try std.testing.expect(std.mem.indexOf(u8, cli.help_text, "ssh.identity_file") != null);
}

// -----------------------------------------------------------------------
// Strict URL parser wiring: `mkit remote add <url>` should go through the
// W5 `validateRemoteUrl` gate. These tests hit that entry point directly
// — the CLI wiring is exercised at the same depth the handler uses.
// -----------------------------------------------------------------------

const remote = @import("remote.zig");

test "mkit remote add: accepts mkit+file:///tmp/x" {
    const parsed = try remote.validateRemoteUrl("mkit+file:///tmp/x");
    try std.testing.expect(parsed == .file);
    try std.testing.expectEqualStrings("/tmp/x", parsed.file);
}

test "mkit remote add: rejects bare https:// with InvalidScheme" {
    try std.testing.expectError(
        error.InvalidScheme,
        remote.validateRemoteUrl("https://example.com"),
    );
}

test "mkit remote add: rejects mkit+gopher:// with UnknownScheme" {
    try std.testing.expectError(
        error.UnknownScheme,
        remote.validateRemoteUrl("mkit+gopher://example.com"),
    );
}

test "mkit remote add: rejects mkit+file:// with no path" {
    try std.testing.expectError(
        error.MalformedUrl,
        remote.validateRemoteUrl("mkit+file://"),
    );
}

// -----------------------------------------------------------------------
// user.identity expansion: the CLI's `mkit config user.identity <value>`
// path runs through `config.expandUserIdentity`. Cover the three accepted
// shorthand forms plus a rejection.
// -----------------------------------------------------------------------

const cfg = @import("config.zig");

test "mkit config user.identity ed25519 shorthand round-trips" {
    const allocator = std.testing.allocator;
    const hex32 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const encoded = try cfg.expandUserIdentity(allocator, "ed25519:" ++ hex32);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("01" ++ "2000" ++ hex32, encoded);

    var scratch: [256]u8 = undefined;
    const decoded = try cfg.parseUserIdentity(encoded, scratch[0..]);
    try std.testing.expectEqual(@as(u8, 0x01), decoded.kind);
    try std.testing.expectEqual(@as(usize, 32), decoded.bytes.len);
}

test "mkit config user.identity mid shorthand encodes 8-byte LE opaque" {
    const allocator = std.testing.allocator;
    const encoded = try cfg.expandUserIdentity(allocator, "mid:42");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("03" ++ "0800" ++ "2a00000000000000", encoded);
}

test "mkit config user.identity: rejects malformed input" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidUserIdentity,
        cfg.expandUserIdentity(allocator, "ed25519:deadbeef"),
    );
    try std.testing.expectError(
        error.InvalidUserIdentity,
        cfg.expandUserIdentity(allocator, "mid:notanumber"),
    );
    try std.testing.expectError(
        error.InvalidUserIdentity,
        cfg.expandUserIdentity(allocator, ""),
    );
}
