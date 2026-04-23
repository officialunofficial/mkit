// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const mkit = @import("mkit");
const build_options = @import("build_options");

fn readExact(file: std.Io.File, io_cap: std.Io, buf: []u8) !usize {
    var off: usize = 0;
    while (off < buf.len) {
        const n = file.readStreaming(io_cap, &.{buf[off..]}) catch |e| return e;
        if (n == 0) break;
        off += n;
    }
    return off;
}

/// Re-export the shared CLI surface constants through the mkit module.
const cli = mkit.cli;
const exit = mkit.exit;

/// Re-export so the existing `cli_version` symbol in main.zig keeps
/// working for any callers (notably `printVersion` below).
pub const cli_version = cli.cli_version;

/// Module-level threaded Io, initialized at the top of main() so that any
/// CLI helper can reach for `io()` without plumbing it through every
/// function. Mirrors the pattern the task brief prescribes.
var g_threaded: std.Io.Threaded = undefined;
/// Preserved copy of the argv vector given to `main(Init.Minimal)` so
/// that `run()` can produce a `[][]const u8` without re-parsing.
var g_argv_vector: std.process.Args.Vector = undefined;

fn io() std.Io {
    return g_threaded.io();
}

/// Resolve the commit author `Identity`. If `config.user_identity` is set,
/// decode it into the caller-supplied `scratch` buffer (`scratch.len` MUST
/// be at least `user_identity.len / 2`). Otherwise derive an Ed25519
/// Identity from the signing key's public key, which is borrowed directly
/// and does NOT use scratch.
fn resolveAuthorIdentity(
    user_identity_hex: []const u8,
    scratch: []u8,
    pubkey: []const u8,
) !mkit.object.Identity {
    if (user_identity_hex.len == 0) {
        return mkit.object.Identity.ed25519Ref(pubkey);
    }
    const decoded = try mkit.config.parseUserIdentity(user_identity_hex, scratch);
    const kind: mkit.object.IdentityKind = switch (decoded.kind) {
        0x01 => .ed25519,
        0x02 => .did_key,
        0x03 => .@"opaque",
        else => return error.InvalidUserIdentity,
    };
    return .{ .kind = kind, .bytes = decoded.bytes };
}

/// Short human-readable Identity renderer. For 8-byte opaque identities
/// (interpreted as a u64 LE counter) returns the decimal value; otherwise
/// returns `"<kind>:<first-8-hex-chars>"`.
fn formatAuthorShort(buf: []u8, id: mkit.object.Identity) []const u8 {
    if (id.kind == .@"opaque" and id.bytes.len == 8) {
        const mid = std.mem.readInt(u64, id.bytes[0..8], .little);
        return std.fmt.bufPrint(buf, "{d}", .{mid}) catch "?";
    }
    const kind_name = switch (id.kind) {
        .ed25519 => "ed25519",
        .did_key => "did:key",
        .@"opaque" => "opaque",
    };
    const hex_alphabet = "0123456789abcdef";
    const take: usize = @min(id.bytes.len, 4);
    var tmp: [8]u8 = undefined;
    for (id.bytes[0..take], 0..) |b, i| {
        tmp[i * 2] = hex_alphabet[b >> 4];
        tmp[i * 2 + 1] = hex_alphabet[b & 0x0F];
    }
    const hex_len: usize = take * 2;
    return std.fmt.bufPrint(buf, "{s}:{s}", .{ kind_name, tmp[0..hex_len] }) catch "?";
}

/// Open `$EDITOR` on `.mkit/COMMIT_EDITMSG`, read the user's message
/// back, strip '#' comment lines, trim whitespace. Returns the final
/// commit message as an allocator-owned slice.
///
/// Errors:
///   - `error.NoEditor` — `$EDITOR` and `$VISUAL` are both unset.
///   - `error.EditorFailed` — editor exited with non-zero status.
///   - `error.EmptyCommitMessage` — after stripping, nothing is left.
///
/// Note: we deliberately do NOT default to `vi`. Failing loud tells the
/// user exactly what's missing; `export EDITOR=vi` is cheap to fix.
fn editCommitMessage(allocator: std.mem.Allocator, mkit_dir: std.Io.Dir) ![]u8 {
    const editor = mkit.term.posixGetenv("EDITOR") orelse mkit.term.posixGetenv("VISUAL") orelse return error.NoEditor;
    if (editor.len == 0) return error.NoEditor;

    // Write the template to .mkit/COMMIT_EDITMSG, overwriting any prior one.
    {
        const f = try mkit_dir.createFile(io(), "COMMIT_EDITMSG", .{ .truncate = true });
        defer f.close(io());
        try f.writeStreamingAll(io(), mkit.cli.commit_editmsg_template);
    }

    // Spawn the editor. Realpath so the child doesn't need to share cwd.
    // stdin/stdout/stderr inherited so interactive UIs (vim, nano) work.
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs_len = try mkit_dir.realPathFile(io(), "COMMIT_EDITMSG", &path_buf);
    const abs_path = path_buf[0..abs_len];

    var child = try std.process.spawn(io(), .{
        .argv = &.{ editor, abs_path },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io());
    switch (term) {
        .exited => |code| if (code != 0) return error.EditorFailed,
        else => return error.EditorFailed,
    }

    // Read the edited file back. Bounded at 1 MiB — commit messages are
    // small; anything larger is almost certainly a mistake.
    const raw = try mkit_dir.readFileAlloc(io(), "COMMIT_EDITMSG", allocator, .limited(1 * 1024 * 1024));
    defer allocator.free(raw);

    const cleaned = try mkit.cli.stripCommentsAndTrim(allocator, raw);
    if (cleaned.len == 0) {
        allocator.free(cleaned);
        return error.EmptyCommitMessage;
    }
    return cleaned;
}

pub fn main(init: std.process.Init.Minimal) !void {
    g_argv_vector = init.args.vector;
    if (build_options.use_jemalloc) {
        return bootstrap(std.heap.c_allocator, init);
    } else {
        var da: std.heap.DebugAllocator(.{}) = .init;
        defer {
            if (da.deinit() == .leak) {
                // In 0.16 writes take an Io; use the stderr file via a
                // short-lived Threaded. We are about to exit anyway, so
                // skip the diagnostic if that fails.
                const msg = "mkit: memory leak detected\n";
                _ = std.Io.File.stderr().writeStreamingAll(g_threaded.io(), msg) catch {};
                std.process.exit(exit.general_error);
            }
        }
        return bootstrap(da.allocator(), init);
    }
}

fn bootstrap(allocator: std.mem.Allocator, init: std.process.Init.Minimal) !void {
    g_threaded = .init(allocator, .{
        .argv0 = .init(init.args),
        .environ = init.environ,
    });
    defer g_threaded.deinit();
    return run(allocator, init);
}

fn run(allocator: std.mem.Allocator, init: std.process.Init.Minimal) !void {
    // Install SIGINT/SIGTERM shutdown flag + SIGPIPE ignore before any
    // subcommand dispatch. Idempotent; cheap; must happen before any
    // long-running operation (clone, push, pull) can start.
    mkit.signal.setupHandlers();

    // Build an arena to own argv slices — Args.toSlice requires an arena-style
    // allocator. Freeing is handled when the arena is torn down on `run` exit.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const args = try init.args.toSlice(arena_state.allocator());

    if (args.len < 2) {
        printUsage();
        return;
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "--help") or
        std.mem.eql(u8, command, "-h") or
        std.mem.eql(u8, command, "help"))
    {
        try printHelp();
        return;
    }

    if (std.mem.eql(u8, command, "init")) {
        try cmdInit();
    } else if (std.mem.eql(u8, command, "hash")) {
        try cmdHash(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "cat")) {
        try cmdCat(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "keygen")) {
        try cmdKeygen();
    } else if (std.mem.eql(u8, command, "verify")) {
        try cmdVerify(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "tree")) {
        try cmdTree(allocator);
    } else if (std.mem.eql(u8, command, "commit")) {
        try cmdCommit(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "log")) {
        try cmdLog(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "branch")) {
        try cmdBranch(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "checkout")) {
        try cmdCheckout(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "status")) {
        try cmdStatus(allocator);
    } else if (std.mem.eql(u8, command, "diff")) {
        try cmdDiff(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "tag")) {
        try cmdTag(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "config")) {
        try cmdConfig(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "push")) {
        try cmdPush(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "merge")) {
        try cmdMerge(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "pull")) {
        try cmdPull(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "clone")) {
        try cmdClone(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "remote")) {
        try cmdRemote(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "add")) {
        try cmdAdd(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "rm")) {
        try cmdRm(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "fetch")) {
        try cmdFetch(allocator);
    } else if (std.mem.eql(u8, command, "blame")) {
        try cmdBlame(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "stash")) {
        try cmdStash(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "cherry-pick")) {
        try cmdCherryPick(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "rebase")) {
        try cmdRebase(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "bisect")) {
        try cmdBisect(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "serve")) {
        try cmdServe(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "sparse-checkout")) {
        try cmdSparseCheckout(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version")) {
        try printVersion();
    } else {
        const stderr = std.Io.File.stderr();
        try stderr.writeStreamingAll(io(), "error: unknown command '");
        try stderr.writeStreamingAll(io(), command);
        try stderr.writeStreamingAll(io(), "' (run 'mkit --help' for a list of commands)\n");
        // Exit with sysexits(3) EX_USAGE (64) so CI scripts / shell one-liners
        // can distinguish "user typed the wrong thing" from a real failure.
        std.process.exit(exit.usage);
    }
}

/// Emit `mkit <version>\n` on stdout. Homebrew's formula test does
/// `assert_match "mkit 0.1.0", shell_output("#{bin}/mkit version")`, so the
/// wire format here must stay stable across cosmetic refactors.
fn printVersion() !void {
    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io(), "mkit ");
    try stdout.writeStreamingAll(io(), cli_version);
    try stdout.writeStreamingAll(io(), "\n");
}

fn printUsage() void {
    const stderr = std.Io.File.stderr();
    stderr.writeStreamingAll(io(), cli.help_text) catch {};
}

/// `mkit --help` / `mkit help` / `mkit -h` path — stdout, exit 0.
fn printHelp() !void {
    const stdout = std.Io.File.stdout();
    try stdout.writeStreamingAll(io(), cli.help_text);
}

fn cmdInit() !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.init(io(), cwd) catch |err| switch (err) {
        error.AlreadyInitialized => {
            try stderr.writeStreamingAll(io(), "error: already a mkit repository\n");
            return;
        },
        else => return err,
    };
    store.close();

    // Initialize refs and HEAD
    try mkit.refs.init(io(), cwd);

    // Create default config (if it doesn't already exist)
    const config_path = ".mkit/config";
    cwd.access(io(), config_path, .{}) catch {
        const cf = try cwd.createFile(io(), config_path, .{});
        defer cf.close(io());
        // user.identity intentionally unset — the CLI derives an Ed25519
        // Identity from the signing key at commit time. Users can override
        // via `mkit config user.identity <value>`.
        try cf.writeStreamingAll(io(), "signing_key = .mkit/keys/default.key\n");
        try cf.writeStreamingAll(io(), "default_branch = main\n");
    };

    try stdout.writeStreamingAll(io(), "initialized empty mkit repository in .mkit/\n");
    try stdout.writeStreamingAll(io(), "\nnext steps:\n");
    try stdout.writeStreamingAll(io(), "  mkit keygen           generate signing key\n");
    try stdout.writeStreamingAll(io(), "  mkit add .            stage files\n");
    try stdout.writeStreamingAll(io(), "  mkit commit -m \"msg\"  create first commit\n");
}

fn cmdHash(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit hash <file>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();
    ensureCleanWorktree(allocator, &store, cwd) catch {
        try stderr.writeStreamingAll(io(), "error: merge would overwrite local changes; commit or stash them first\n");
        return;
    };

    const file_path = args[0];
    const h = mkit.worktree.hashFile(allocator, io(), &store, cwd, file_path) catch |err| {
        try stderr.writeStreamingAll(io(), "error: cannot hash '");
        try stderr.writeStreamingAll(io(), file_path);
        try stderr.writeStreamingAll(io(), "': ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };

    const hex = mkit.hash.toHex(h);
    try stdout.writeStreamingAll(io(), &hex);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdCat(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit cat <hash>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const hash_str = args[0];
    const h = mkit.hash.fromHex(hash_str) catch {
        try stderr.writeStreamingAll(io(), "error: invalid hash '");
        try stderr.writeStreamingAll(io(), hash_str);
        try stderr.writeStreamingAll(io(), "'\n");
        return;
    };

    var obj = store.get(allocator, h) catch |err| switch (err) {
        error.ObjectNotFound => {
            try stderr.writeStreamingAll(io(), "error: object not found\n");
            return;
        },
        error.HashMismatch => {
            try stderr.writeStreamingAll(io(), "error: object corrupt (hash mismatch)\n");
            return;
        },
        else => return err,
    };
    defer obj.deinit(allocator);

    try mkit.format.printObject(stdout, io(), allocator, obj, h);
}

fn cmdTree(allocator: std.mem.Allocator) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
        return;
    };
    defer work_dir.close(io());

    const h = try mkit.worktree.buildTree(allocator, io(), &store, work_dir);
    const hex = mkit.hash.toHex(h);
    try stdout.writeStreamingAll(io(), &hex);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdAdd(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit add <path>...\n");
        try stderr.writeStreamingAll(io(), "       mkit add .          (stage all files)\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    var idx = try mkit.index.readIndex(allocator, io(), cwd);
    defer idx.deinit();

    for (args) |arg| {
        if (std.mem.eql(u8, arg, ".")) {
            var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
                try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
                return;
            };
            defer work_dir.close(io());
            try mkit.index.addAll(allocator, io(), &store, work_dir, &idx);
        } else {
            mkit.index.addFile(allocator, io(), &store, cwd, &idx, arg) catch |err| {
                try stderr.writeStreamingAll(io(), "error: cannot stage '");
                try stderr.writeStreamingAll(io(), arg);
                try stderr.writeStreamingAll(io(), "': ");
                var buf2: [256]u8 = undefined;
                const err_name = std.fmt.bufPrint(&buf2, "{s}", .{@errorName(err)}) catch "unknown";
                try stderr.writeStreamingAll(io(), err_name);
                try stderr.writeStreamingAll(io(), "\n");
                continue;
            };
        }
    }

    try mkit.index.writeIndex(io(), cwd, &idx);

    // Print summary
    var buf: [64]u8 = undefined;
    const count_str = std.fmt.bufPrint(&buf, "{d}", .{idx.stagedCount()}) catch "?";
    try stdout.writeStreamingAll(io(), "staged ");
    try stdout.writeStreamingAll(io(), count_str);
    try stdout.writeStreamingAll(io(), " file(s)\n");
}

fn cmdRm(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit rm <path>...\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    var idx = try mkit.index.readIndex(allocator, io(), cwd);
    defer idx.deinit();

    for (args) |arg| {
        try mkit.index.removeFile(&idx, allocator, arg);
        try stdout.writeStreamingAll(io(), "removed ");
        try stdout.writeStreamingAll(io(), arg);
        try stdout.writeStreamingAll(io(), "\n");
    }

    try mkit.index.writeIndex(io(), cwd, &idx);
}

fn cmdCommit(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    // Parse -m <message>
    var message: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-m") and i + 1 < args.len) {
            message = args[i + 1];
            i += 1;
        }
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Acquire .mkit/index.lock to serialize against any other mkit commit
    // / checkout / merge / rebase operating on this repo. See src/lock.zig.
    var mkit_dir = cwd.openDir(io(), ".mkit", .{}) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open .mkit directory\n");
        return;
    };
    defer mkit_dir.close(io());
    var repo_lock = mkit.lock.acquireDefault(io(), mkit_dir, "index.lock") catch |err| switch (err) {
        error.LockBusy => {
            try stderr.writeStreamingAll(io(), "error: another mkit process is running in this repository (.mkit/index.lock held)\n");
            return;
        },
        else => return err,
    };
    defer repo_lock.release();

    // If no -m was provided, open $EDITOR on .mkit/COMMIT_EDITMSG and
    // read the edited message back. Caller owns the returned buffer.
    // Editor prompt happens AFTER the repo lock is acquired so that
    // two concurrent `mkit commit` invocations don't both pop editors.
    var edit_buf: ?[]u8 = null;
    defer if (edit_buf) |b| allocator.free(b);
    if (message == null) {
        edit_buf = editCommitMessage(allocator, mkit_dir) catch |err| switch (err) {
            error.NoEditor => {
                try stderr.writeStreamingAll(io(), "error: no commit message supplied and $EDITOR is unset\n");
                try stderr.writeStreamingAll(io(), "       pass -m <message> or set EDITOR=<path-to-your-editor>\n");
                std.process.exit(exit.usage);
            },
            error.EditorFailed => {
                try stderr.writeStreamingAll(io(), "error: editor exited with non-zero status; aborting commit\n");
                std.process.exit(exit.general_error);
            },
            error.EmptyCommitMessage => {
                try stderr.writeStreamingAll(io(), "error: empty commit message; aborting\n");
                std.process.exit(exit.usage);
            },
            else => return err,
        };
        message = edit_buf.?;
    }

    var config = try readRepoConfig(allocator, cwd);
    defer config.deinit();

    const kp = loadSigningKey(allocator, cwd, config.signing_key) catch |err| switch (err) {
        error.FileNotFound => {
            try stderr.writeStreamingAll(io(), "error: no signing key found (run 'mkit keygen' first)\n");
            return;
        },
        error.InvalidKeyFile => {
            try stderr.writeStreamingAll(io(), "error: invalid key file (expected 32-byte seed)\n");
            return;
        },
        else => {
            try stderr.writeStreamingAll(io(), "error: invalid key seed\n");
            return;
        },
    };

    // Build tree: use index if it has staged entries, otherwise fall back to whole working dir
    var idx = try mkit.index.readIndex(allocator, io(), cwd);
    defer idx.deinit();

    // Get parent from HEAD
    const parent_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
    const head_tree = try resolveHeadTree(allocator, &store, cwd);
    const tree_hash = if (idx.entries.items.len > 0)
        mkit.index.buildCommitTreeFromIndex(allocator, &store, head_tree, &idx) catch |err| {
            try stderr.writeStreamingAll(io(), "error: could not build staged tree: ");
            var buf_tree: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf_tree, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        }
    else blk: {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
            return;
        };
        defer work_dir.close(io());
        break :blk try mkit.worktree.buildTree(allocator, io(), &store, work_dir);
    };

    var parents_buf: [1]mkit.hash.Hash = undefined;
    var parents: []mkit.hash.Hash = undefined;
    if (parent_hash) |ph| {
        parents_buf[0] = ph;
        parents = parents_buf[0..1];
    } else {
        parents = parents_buf[0..0];
    }

    // Get timestamp (u64 Unix seconds per SPEC-OBJECTS §5).
    const timestamp: u64 = @intCast(@max(std.Io.Clock.real.now(io()).toSeconds(), 0));

    var id_scratch: [1024]u8 = undefined;
    const author_id = resolveAuthorIdentity(config.user_identity, id_scratch[0..], kp.public_key[0..]) catch {
        try stderr.writeStreamingAll(io(), "error: invalid user.identity in config (run 'mkit config user.identity <value>')\n");
        return;
    };

    // Create commit (unsigned first, then sign)
    var commit = mkit.object.Commit{
        .tree_hash = tree_hash,
        .parents = parents,
        .author = author_id,
        .signer = kp.public_key,
        .message = message.?,
        .timestamp = timestamp,
        .message_hash = mkit.hash.hash(message.?),
        .content_digest = mkit.hash.zero, // computed at push time
        .signature = .{0} ** 64,
    };

    // Sign the commit
    commit.signature = mkit.sign.signCommit(allocator, commit, kp) catch {
        try stderr.writeStreamingAll(io(), "error: signing failed\n");
        return;
    };

    // Store the commit
    const commit_obj = mkit.object.Object{ .commit = commit };
    const commit_hash = try store.put(allocator, commit_obj);

    // Update HEAD
    try mkit.refs.updateHead(allocator, io(), cwd, commit_hash);

    // Clear the index after successful commit
    if (idx.entries.items.len > 0) {
        var empty_idx = mkit.index.Index.init(allocator);
        defer empty_idx.deinit();
        mkit.index.writeIndex(io(), cwd, &empty_idx) catch {};
    }

    // Print result
    const hex = mkit.hash.toHex(commit_hash);
    const tree_hex = mkit.hash.toHex(tree_hash);
    try stdout.writeStreamingAll(io(), "[");
    if (parent_hash == null) {
        try stdout.writeStreamingAll(io(), "root commit");
    } else {
        // Resolve current branch name from HEAD
        const head = mkit.refs.readHead(allocator, io(), cwd) catch null;
        if (head) |h| {
            switch (h) {
                .branch => |branch| {
                    defer allocator.free(branch);
                    try stdout.writeStreamingAll(io(), branch);
                },
                .detached => try stdout.writeStreamingAll(io(), "detached"),
            }
        } else {
            try stdout.writeStreamingAll(io(), "HEAD");
        }
    }
    try stdout.writeStreamingAll(io(), "] ");
    try stdout.writeStreamingAll(io(), &hex);
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "tree   ");
    try stdout.writeStreamingAll(io(), &tree_hex);
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "signer ");
    const signer_hex = mkit.hash.toHex(kp.public_key);
    try stdout.writeStreamingAll(io(), &signer_hex);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdLog(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    // Parse flags
    var oneline = false;
    var graph = false;
    var max_entries: usize = 50;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--oneline")) {
            oneline = true;
        } else if (std.mem.eql(u8, args[i], "--graph")) {
            graph = true;
        } else if (std.mem.eql(u8, args[i], "-n") and i + 1 < args.len) {
            max_entries = std.fmt.parseInt(usize, args[i + 1], 10) catch 50;
            i += 1;
        }
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
    if (head_hash == null) {
        try stderr.writeStreamingAll(io(), "no commits yet\n");
        return;
    }

    if (graph) {
        // Graph rendering with BFS traversal
        var graph_state = mkit.format.GraphState.init(allocator);
        defer graph_state.deinit();

        var visited = std.AutoHashMap(mkit.hash.Hash, void).init(allocator);
        defer visited.deinit();

        var queue: std.ArrayList(mkit.hash.Hash) = .empty;
        defer queue.deinit(allocator);
        try queue.append(allocator, head_hash.?);

        var count: usize = 0;
        var head_idx: usize = 0;

        while (head_idx < queue.items.len) {
            if (count >= max_entries) {
                try stdout.writeStreamingAll(io(), "... (truncated)\n");
                break;
            }

            const h = queue.items[head_idx];
            head_idx += 1;

            const gop = try visited.getOrPut(h);
            if (gop.found_existing) continue;

            var obj = store.get(allocator, h) catch {
                try stderr.writeStreamingAll(io(), "error: corrupt commit chain\n");
                return;
            };
            defer obj.deinit(allocator);

            if (obj != .commit) continue;

            const c = obj.commit;

            // Dupe parents for graph rendering (obj is deferred deinit)
            const parents_duped = try allocator.dupe(mkit.hash.Hash, c.parents);
            defer allocator.free(parents_duped);

            var lines = try mkit.format.graphRenderCommit(allocator, &graph_state, h, parents_duped);
            defer lines.deinit();

            // Print commit line with graph prefix
            try stdout.writeStreamingAll(io(), lines.commit_prefix);
            if (oneline) {
                const formatted = try mkit.format.formatCommitOneline(allocator, h, c);
                defer allocator.free(formatted);
                try stdout.writeStreamingAll(io(), formatted);
            } else {
                const hex = mkit.hash.toHex(h);
                try stdout.writeStreamingAll(io(), "commit ");
                try stdout.writeStreamingAll(io(), &hex);
                try stdout.writeStreamingAll(io(), "\n");
                // Print message with continuation prefix
                for (lines.post_lines) |post_line| {
                    try stdout.writeStreamingAll(io(), post_line);
                    try stdout.writeStreamingAll(io(), "  ");
                    try stdout.writeStreamingAll(io(), c.message);
                    try stdout.writeStreamingAll(io(), "\n");
                    break; // Only print message once
                }
                // Print remaining post lines
                if (lines.post_lines.len > 1) {
                    for (lines.post_lines[1..]) |post_line| {
                        try stdout.writeStreamingAll(io(), post_line);
                        try stdout.writeStreamingAll(io(), "\n");
                    }
                } else if (lines.post_lines.len == 0) {
                    try stdout.writeStreamingAll(io(), "\n");
                }
            }

            // Print post-commit graph lines (for oneline mode, or remaining lines)
            if (oneline) {
                for (lines.post_lines) |post_line| {
                    try stdout.writeStreamingAll(io(), post_line);
                    try stdout.writeStreamingAll(io(), "\n");
                }
            }

            // Enqueue parents
            for (parents_duped) |parent| {
                try queue.append(allocator, parent);
            }

            count += 1;
        }
    } else {
        // Linear log (original behavior)
        var current: ?mkit.hash.Hash = head_hash;
        var count: usize = 0;

        while (current) |h| {
            if (count >= max_entries) {
                try stdout.writeStreamingAll(io(), "... (truncated)\n");
                break;
            }

            var obj = store.get(allocator, h) catch {
                try stderr.writeStreamingAll(io(), "error: corrupt commit chain\n");
                return;
            };
            defer obj.deinit(allocator);

            if (obj != .commit) {
                try stderr.writeStreamingAll(io(), "error: non-commit object in history\n");
                return;
            }

            if (oneline) {
                const formatted = try mkit.format.formatCommitOneline(allocator, h, obj.commit);
                defer allocator.free(formatted);
                try stdout.writeStreamingAll(io(), formatted);
            } else {
                try mkit.format.printObject(stdout, io(), allocator, obj, h);
                try stdout.writeStreamingAll(io(), "\n");
            }

            const c = obj.commit;
            if (c.parents.len > 0) {
                current = c.parents[0];
            } else {
                current = null;
            }
            count += 1;
        }
    }
}

fn cmdBlame(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit blame <file>\n");
        return;
    }
    const path = args[0];

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
    if (head_hash == null) {
        try stderr.writeStreamingAll(io(), "no commits yet\n");
        return;
    }

    var result = mkit.blame.blameFile(allocator, &store, head_hash.?, path) catch |err| switch (err) {
        error.FileNotFound => {
            try stderr.writeStreamingAll(io(), "error: file '");
            try stderr.writeStreamingAll(io(), path);
            try stderr.writeStreamingAll(io(), "' not found in HEAD\n");
            return;
        },
        else => return err,
    };
    defer result.deinit();

    // Print each line: "<hash8> (<mid> <timestamp>) <text>"
    var buf: [256]u8 = undefined;
    for (result.lines) |line| {
        const hex = mkit.hash.toHex(line.commit_hash);
        const short_hash = hex[0..8];
        try stdout.writeStreamingAll(io(), short_hash);
        try stdout.writeStreamingAll(io(), " (");

        // Format author: for opaque 8-byte identities (interpreted as a u64 LE counter)
        // show the decoded u64; otherwise show "<kind>:<first-bytes>".
        const author_str = formatAuthorShort(&buf, line.author);
        try stdout.writeStreamingAll(io(), author_str);
        if (author_str.len < 4) {
            const pad_len = 4 - author_str.len;
            var pad: [4]u8 = .{' '} ** 4;
            try stdout.writeStreamingAll(io(), pad[0..pad_len]);
        }

        try stdout.writeStreamingAll(io(), " ");

        // Format timestamp as ISO date if non-zero
        const ts_str = std.fmt.bufPrint(&buf, "{d}", .{line.timestamp}) catch "?";
        try stdout.writeStreamingAll(io(), ts_str);

        try stdout.writeStreamingAll(io(), ") ");
        try stdout.writeStreamingAll(io(), line.text);
        try stdout.writeStreamingAll(io(), "\n");
    }
}

fn cmdBranch(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    // mkit branch -d <name>
    if (args.len >= 2 and std.mem.eql(u8, args[0], "-d")) {
        const branch_name = args[1];
        mkit.refs.deleteRefSafe(allocator, io(), cwd, branch_name) catch |err| switch (err) {
            error.RefNotFound => {
                try stderr.writeStreamingAll(io(), "error: branch '");
                try stderr.writeStreamingAll(io(), branch_name);
                try stderr.writeStreamingAll(io(), "' not found\n");
                return;
            },
            error.CannotDeleteCurrentBranch => {
                try stderr.writeStreamingAll(io(), "error: cannot delete branch '");
                try stderr.writeStreamingAll(io(), branch_name);
                try stderr.writeStreamingAll(io(), "' — it is the current branch\n");
                return;
            },
            else => return err,
        };
        try stdout.writeStreamingAll(io(), "deleted branch ");
        try stdout.writeStreamingAll(io(), branch_name);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit branch <name> — create branch at HEAD
    if (args.len >= 1) {
        const branch_name = args[0];
        const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
        if (head_hash == null) {
            try stderr.writeStreamingAll(io(), "error: no commits yet — cannot create branch\n");
            return;
        }
        // Check if branch already exists
        const existing = try mkit.refs.readRef(allocator, io(), cwd, branch_name);
        if (existing != null) {
            try stderr.writeStreamingAll(io(), "error: branch '");
            try stderr.writeStreamingAll(io(), branch_name);
            try stderr.writeStreamingAll(io(), "' already exists\n");
            return;
        }
        try mkit.refs.writeRef(io(), cwd, branch_name, head_hash.?);
        const hex = mkit.hash.toHex(head_hash.?);
        try stdout.writeStreamingAll(io(), "created branch ");
        try stdout.writeStreamingAll(io(), branch_name);
        try stdout.writeStreamingAll(io(), " at ");
        try stdout.writeStreamingAll(io(), hex[0..8]);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit branch — list branches
    const current_branch: ?[]const u8 = blk: {
        const head = mkit.refs.readHead(allocator, io(), cwd) catch break :blk null;
        switch (head) {
            .branch => |b| break :blk b,
            .detached => break :blk null,
        }
    };
    defer if (current_branch) |b| allocator.free(b);

    const ref_list = try mkit.refs.listRefs(allocator, io(), cwd);
    defer {
        for (ref_list) |ref| {
            allocator.free(ref.name);
        }
        allocator.free(ref_list);
    }

    if (ref_list.len == 0) {
        // Show current branch even if no ref file exists yet
        if (current_branch) |branch| {
            try stdout.writeStreamingAll(io(), "* ");
            try stdout.writeStreamingAll(io(), branch);
            try stdout.writeStreamingAll(io(), "\n");
        } else {
            try stderr.writeStreamingAll(io(), "no branches yet\n");
        }
        return;
    }

    // Check if current branch is already in the list
    var current_in_list = false;
    for (ref_list) |ref| {
        if (current_branch) |cb| {
            if (std.mem.eql(u8, ref.name, cb)) {
                current_in_list = true;
            }
        }
    }

    // If HEAD points to a branch not yet in the refs list, show it first
    if (current_branch != null and !current_in_list) {
        try stdout.writeStreamingAll(io(), "* ");
        try stdout.writeStreamingAll(io(), current_branch.?);
        try stdout.writeStreamingAll(io(), "\n");
    }

    for (ref_list) |ref| {
        const is_current = if (current_branch) |cb| std.mem.eql(u8, ref.name, cb) else false;
        if (is_current) {
            try stdout.writeStreamingAll(io(), "* ");
        } else {
            try stdout.writeStreamingAll(io(), "  ");
        }
        try stdout.writeStreamingAll(io(), ref.name);
        try stdout.writeStreamingAll(io(), "\n");
    }
}

fn cmdCheckout(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit checkout <branch>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Serialize against other commit/checkout/merge/rebase. See src/lock.zig.
    var mkit_dir = cwd.openDir(io(), ".mkit", .{}) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open .mkit directory\n");
        return;
    };
    defer mkit_dir.close(io());
    var repo_lock = mkit.lock.acquireDefault(io(), mkit_dir, "index.lock") catch |err| switch (err) {
        error.LockBusy => {
            try stderr.writeStreamingAll(io(), "error: another mkit process is running in this repository (.mkit/index.lock held)\n");
            return;
        },
        else => return err,
    };
    defer repo_lock.release();

    const branch_name = args[0];
    if (!mkit.protocol.validateRefName(branch_name)) {
        try stderr.writeStreamingAll(io(), "error: invalid branch name\n");
        return;
    }
    const branch_hash = try mkit.refs.readRef(allocator, io(), cwd, branch_name);
    if (branch_hash == null) {
        try stderr.writeStreamingAll(io(), "error: branch '");
        try stderr.writeStreamingAll(io(), branch_name);
        try stderr.writeStreamingAll(io(), "' not found\n");
        return;
    }
    ensureCleanWorktree(allocator, &store, cwd) catch {
        try stderr.writeStreamingAll(io(), "error: checkout would overwrite local changes; commit or stash them first\n");
        return;
    };

    // Load sparse checkout patterns
    const sparse = mkit.restore.loadSparseCheckout(allocator, io(), cwd) catch null;
    defer if (sparse) |s| mkit.restore.freeSparsePatterns(allocator, s);

    // Restore working directory from the branch's commit tree
    if (branch_hash) |bh| {
        var commit_obj = store.get(allocator, bh) catch |err| {
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), "error: could not read commit: ");
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        defer commit_obj.deinit(allocator);

        if (commit_obj == .commit) {
            var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
                try stderr.writeStreamingAll(io(), "error: could not open working directory for restore\n");
                return;
            };
            defer work_dir.close(io());
            mkit.restore.restoreTree(allocator, io(), &store, commit_obj.commit.tree_hash, work_dir, .{
                .sparse_patterns = sparse,
            }) catch |err| {
                var buf2: [256]u8 = undefined;
                const err_name = std.fmt.bufPrint(&buf2, "{s}", .{@errorName(err)}) catch "unknown";
                try stderr.writeStreamingAll(io(), "error: could not restore working directory: ");
                try stderr.writeStreamingAll(io(), err_name);
                try stderr.writeStreamingAll(io(), "\n");
                return;
            };
        }
    }

    try mkit.refs.writeHeadBranch(io(), cwd, branch_name);

    try stdout.writeStreamingAll(io(), "switched to branch '");
    try stdout.writeStreamingAll(io(), branch_name);
    try stdout.writeStreamingAll(io(), "'\n");
}

fn printDiffEntries(stdout: std.Io.File, entries: []const mkit.diff.DiffEntry) !void {
    for (entries) |entry| {
        const prefix: []const u8 = switch (entry.kind) {
            .added => "A  ",
            .removed => "D  ",
            .modified => "M  ",
            .mode_changed => "T  ",
        };
        try stdout.writeStreamingAll(io(), prefix);
        try stdout.writeStreamingAll(io(), entry.path);
        try stdout.writeStreamingAll(io(), "\n");
    }
}

fn resolveHeadTree(allocator: std.mem.Allocator, store: *mkit.store.ObjectStore, cwd: std.Io.Dir) !?mkit.hash.Hash {
    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
    if (head_hash) |hh| {
        var obj = try store.get(allocator, hh);
        defer obj.deinit(allocator);
        if (obj == .commit) return obj.commit.tree_hash;
    }
    return null;
}

fn cmdStatus(allocator: std.mem.Allocator) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const head_tree = try resolveHeadTree(allocator, &store, cwd);

    // Check if we have a staging index
    var idx = try mkit.index.readIndex(allocator, io(), cwd);
    defer idx.deinit();

    var has_output = false;

    if (idx.entries.items.len > 0) {
        // Show staged changes (index vs HEAD)
        const idx_tree = if (idx.stagedCount() > 0)
            try mkit.index.buildTreeFromIndex(allocator, &store, &idx)
        else
            null;

        var staged_diff = try mkit.diff.diffTrees(allocator, &store, head_tree, idx_tree);
        defer staged_diff.deinit();

        if (staged_diff.entries.len > 0) {
            try stdout.writeStreamingAll(io(), "Changes to be committed:\n");
            for (staged_diff.entries) |entry| {
                const prefix: []const u8 = switch (entry.kind) {
                    .added => "  A  ",
                    .removed => "  D  ",
                    .modified => "  M  ",
                    .mode_changed => "  T  ",
                };
                try stdout.writeStreamingAll(io(), prefix);
                try stdout.writeStreamingAll(io(), entry.path);
                try stdout.writeStreamingAll(io(), "\n");
            }
            has_output = true;
        }

        // Show explicitly removed files from index
        for (idx.entries.items) |entry| {
            if (entry.status == .removed) {
                if (!has_output) {
                    try stdout.writeStreamingAll(io(), "Changes to be committed:\n");
                }
                try stdout.writeStreamingAll(io(), "  D  ");
                try stdout.writeStreamingAll(io(), entry.path);
                try stdout.writeStreamingAll(io(), "\n");
                has_output = true;
            }
        }
    }

    // Show working tree changes (workdir vs HEAD) — the original behavior
    var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
        return;
    };
    defer work_dir.close(io());

    var result = try mkit.diff.statusDiff(allocator, io(), &store, head_tree, work_dir);
    defer result.deinit();

    if (result.entries.len > 0) {
        if (has_output) {
            try stdout.writeStreamingAll(io(), "\n");
        }
        if (idx.entries.items.len > 0) {
            try stdout.writeStreamingAll(io(), "Changes not staged for commit:\n");
            for (result.entries) |entry| {
                const prefix: []const u8 = switch (entry.kind) {
                    .added => "  A  ",
                    .removed => "  D  ",
                    .modified => "  M  ",
                    .mode_changed => "  T  ",
                };
                try stdout.writeStreamingAll(io(), prefix);
                try stdout.writeStreamingAll(io(), entry.path);
                try stdout.writeStreamingAll(io(), "\n");
            }
        } else {
            // No index — use original flat format
            try printDiffEntries(stdout, result.entries);
        }
        has_output = true;
    }

    if (!has_output) {
        try stdout.writeStreamingAll(io(), "nothing to commit, working tree clean\n");
    }
}

fn cmdDiff(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    if (args.len == 2) {
        // mkit diff <hash1> <hash2> — diff two trees
        const hash1_str = args[0];
        const hash2_str = args[1];

        const h1 = mkit.hash.fromHex(hash1_str) catch {
            try stderr.writeStreamingAll(io(), "error: invalid hash '");
            try stderr.writeStreamingAll(io(), hash1_str);
            try stderr.writeStreamingAll(io(), "'\n");
            return;
        };
        const h2 = mkit.hash.fromHex(hash2_str) catch {
            try stderr.writeStreamingAll(io(), "error: invalid hash '");
            try stderr.writeStreamingAll(io(), hash2_str);
            try stderr.writeStreamingAll(io(), "'\n");
            return;
        };

        // Resolve: if hash is a commit, use its tree_hash; if it's a tree, use directly
        const tree1 = try resolveTreeHash(allocator, &store, h1) orelse {
            try stderr.writeStreamingAll(io(), "error: first argument is not a tree or commit\n");
            return;
        };
        const tree2 = try resolveTreeHash(allocator, &store, h2) orelse {
            try stderr.writeStreamingAll(io(), "error: second argument is not a tree or commit\n");
            return;
        };

        var result = try mkit.diff.diffTrees(allocator, &store, tree1, tree2);
        defer result.deinit();

        if (result.entries.len == 0) {
            try stdout.writeStreamingAll(io(), "no differences\n");
            return;
        }

        try printDiffEntries(stdout, result.entries);
    } else if (args.len == 0) {
        // mkit diff (no args) — same as status: HEAD vs workdir
        const head_tree = try resolveHeadTree(allocator, &store, cwd);

        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
            return;
        };
        defer work_dir.close(io());

        var result = try mkit.diff.statusDiff(allocator, io(), &store, head_tree, work_dir);
        defer result.deinit();

        if (result.entries.len == 0) {
            try stdout.writeStreamingAll(io(), "no differences\n");
            return;
        }

        try printDiffEntries(stdout, result.entries);
    } else {
        try stderr.writeStreamingAll(io(), "usage: mkit diff [<hash1> <hash2>]\n");
    }
}

fn parseRemoteUrl(url: []const u8) ?struct { endpoint: []const u8, bucket: []const u8 } {
    const last_slash = std.mem.lastIndexOfScalar(u8, url, '/') orelse return null;
    const endpoint = url[0..last_slash];
    const bucket = url[last_slash + 1 ..];
    if (endpoint.len == 0 or bucket.len == 0) return null;
    return .{ .endpoint = endpoint, .bucket = bucket };
}

// ======================================================================// Transport dispatch
// ======================================================================
const TransportType = enum { file, s3, http, ssh };

/// Detect transport type from config. If remote_type is explicitly set, use it.
/// Otherwise auto-detect from remote_endpoint.
fn detectTransportType(config: mkit.config.Config) TransportType {
    if (config.remote_type.len > 0) {
        if (std.mem.eql(u8, config.remote_type, "file")) return .file;
        if (std.mem.eql(u8, config.remote_type, "s3")) return .s3;
        if (std.mem.eql(u8, config.remote_type, "http")) return .http;
        if (std.mem.eql(u8, config.remote_type, "ssh")) return .ssh;
    }
    if (config.remote_endpoint.len == 0) return .http;
    if (config.remote_endpoint[0] == '/' or
        std.mem.startsWith(u8, config.remote_endpoint, "file://"))
        return .file;
    // URLs ending with common S3 patterns use S3 transport
    if (std.mem.indexOf(u8, config.remote_endpoint, "r2.cloudflarestorage.com") != null or
        std.mem.indexOf(u8, config.remote_endpoint, "s3.amazonaws.com") != null or
        std.mem.indexOf(u8, config.remote_endpoint, "minio") != null)
        return .s3;
    // SSH: ssh:// prefix or SCP-style user@host:path
    if (std.mem.startsWith(u8, config.remote_endpoint, "ssh://")) return .ssh;
    if (std.mem.indexOfScalar(u8, config.remote_endpoint, '@') != null and
        std.mem.indexOfScalar(u8, config.remote_endpoint, ':') != null)
        return .ssh;
    // Default: plain HTTP (mkit VCS Worker)
    return .http;
}

/// Represents an opened transport with its backing storage.
/// Must call deinit() when done.
const OpenTransport = struct {
    transport: mkit.protocol.Transport,
    backing: union(enum) {
        file: *mkit.transport_file.FileTransport,
        s3: *mkit.transport_s3.S3Transport,
        http: *mkit.transport_http.HttpTransport,
        ssh: *mkit.transport_ssh.SshTransport,
    },
    allocator: std.mem.Allocator,

    fn deinit(self: *OpenTransport) void {
        switch (self.backing) {
            .file => |ft| {
                ft.deinit();
                self.allocator.destroy(ft);
            },
            .s3 => |s3t| {
                s3t.deinit();
                self.allocator.destroy(s3t);
            },
            .http => |ht| {
                ht.deinit();
                self.allocator.destroy(ht);
            },
            .ssh => |st| {
                st.deinit();
                self.allocator.destroy(st);
            },
        }
    }
};

/// Open a transport based on the config. Caller must call deinit on the result.
fn openTransport(allocator: std.mem.Allocator, config: mkit.config.Config) !OpenTransport {
    const transport_type = detectTransportType(config);

    switch (transport_type) {
        .file => {
            // For file transport, the endpoint is the path.
            // Strip "file://" prefix if present.
            var path = config.remote_endpoint;
            if (std.mem.startsWith(u8, path, "file://")) {
                path = path["file://".len..];
            }

            const ft = try allocator.create(mkit.transport_file.FileTransport);
            ft.* = mkit.transport_file.FileTransport.init(allocator, io(), path) catch |err| {
                allocator.destroy(ft);
                return err;
            };
            return .{
                .transport = ft.transport(),
                .backing = .{ .file = ft },
                .allocator = allocator,
            };
        },
        .s3 => {
            const s3_config = mkit.remote.RemoteConfig{
                .endpoint = config.remote_endpoint,
                .bucket = config.remote_bucket,
                .access_key_id = "",
                .secret_access_key = "",
                .region = "auto",
            };
            // Try to enrich from env vars
            var env_cfg = (try mkit.remote.configFromEnv(allocator)) orelse s3_config;
            // If env didn't provide endpoint/bucket, use config values
            if (env_cfg.endpoint.len == 0 or env_cfg.bucket.len == 0) {
                if (env_cfg.allocator != null) env_cfg.deinit();
                env_cfg = s3_config;
            }

            const s3 = try allocator.create(mkit.transport_s3.S3Transport);
            s3.* = mkit.transport_s3.S3Transport.init(allocator, io(), .{
                .endpoint = env_cfg.endpoint,
                .bucket = env_cfg.bucket,
                .access_key_id = env_cfg.access_key_id,
                .secret_access_key = env_cfg.secret_access_key,
                .region = env_cfg.region,
            });
            return .{
                .transport = s3.transport(),
                .backing = .{ .s3 = s3 },
                .allocator = allocator,
            };
        },
        .http => {
            // Plain HTTP transport for mkit VCS Worker
            // Endpoint is the base URL (e.g., "https://mkit-vcs.example.com/v1")
            const base_url = config.remote_endpoint;

            // API token from env
            const api_token: ?[]const u8 = mkit.term.posixGetenv("MKIT_API_TOKEN");

            const ht = try allocator.create(mkit.transport_http.HttpTransport);
            ht.* = mkit.transport_http.HttpTransport.init(allocator, io(), base_url, api_token);
            return .{
                .transport = ht.transport(),
                .backing = .{ .http = ht },
                .allocator = allocator,
            };
        },
        .ssh => {
            // Parse the SSH URL from the endpoint
            const parsed = mkit.protocol.parseUrl(config.remote_endpoint) catch return error.InvalidUrl;
            const ssh_url = switch (parsed) {
                .ssh => |s| s,
                else => return error.InvalidUrl,
            };
            const st = try allocator.create(mkit.transport_ssh.SshTransport);
            const ssh_options = mkit.transport_ssh.SshOptions{
                .strict_host_key_checking = config.ssh_strict_host_key_checking,
                .user_known_hosts_file = config.ssh_user_known_hosts_file,
                .identity_file = config.ssh_identity_file,
            };
            st.* = mkit.transport_ssh.SshTransport.initWithOptions(
                allocator,
                io(),
                ssh_url.user,
                ssh_url.host,
                ssh_url.port,
                ssh_url.path,
                ssh_options,
            ) catch |err| {
                allocator.destroy(st);
                return err;
            };
            return .{
                .transport = st.transport(),
                .backing = .{ .ssh = st },
                .allocator = allocator,
            };
        },
    }
}

fn cmdStash(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    if (args.len == 0) {
        // Default: save with "WIP" message
        mkit.stash.save(allocator, &store, io(), cwd, "WIP") catch |err| {
            try writeStashError(stderr, "save", err);
            return;
        };
        try stdout.writeStreamingAll(io(), "saved working directory to stash\n");
        return;
    }

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "save")) {
        // Parse -m <message>
        var message: []const u8 = "WIP";
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "-m") and i + 1 < args.len) {
                message = args[i + 1];
                i += 1;
            }
        }
        mkit.stash.save(allocator, &store, io(), cwd, message) catch |err| {
            try writeStashError(stderr, "save", err);
            return;
        };
        try stdout.writeStreamingAll(io(), "saved working directory to stash\n");
    } else if (std.mem.eql(u8, subcmd, "list")) {
        var stash_list = mkit.stash.list(allocator, io(), cwd) catch |err| {
            try writeStashError(stderr, "list", err);
            return;
        };
        defer stash_list.deinit();

        if (stash_list.entries.len == 0) {
            try stdout.writeStreamingAll(io(), "no stash entries\n");
            return;
        }

        for (stash_list.entries, 0..) |entry, i| {
            // Format: stash@{N}: <message>
            var idx_buf: [16]u8 = undefined;
            const idx_str = std.fmt.bufPrint(&idx_buf, "{d}", .{i}) catch "?";
            try stdout.writeStreamingAll(io(), "stash@{");
            try stdout.writeStreamingAll(io(), idx_str);
            try stdout.writeStreamingAll(io(), "}: ");
            try stdout.writeStreamingAll(io(), entry.message);
            try stdout.writeStreamingAll(io(), "\n");
        }
    } else if (std.mem.eql(u8, subcmd, "pop")) {
        const idx = if (args.len > 1) parseStashIndex(args[1]) else 0;
        mkit.stash.pop(allocator, io(), &store, cwd, idx) catch |err| {
            try writeStashError(stderr, "pop", err);
            return;
        };
        try stdout.writeStreamingAll(io(), "applied and dropped stash entry\n");
    } else if (std.mem.eql(u8, subcmd, "drop")) {
        const idx = if (args.len > 1) parseStashIndex(args[1]) else 0;
        mkit.stash.drop(allocator, io(), cwd, idx) catch |err| {
            try writeStashError(stderr, "drop", err);
            return;
        };
        try stdout.writeStreamingAll(io(), "dropped stash entry\n");
    } else if (std.mem.eql(u8, subcmd, "show")) {
        const idx = if (args.len > 1) parseStashIndex(args[1]) else 0;
        var diff_result = mkit.stash.show(allocator, io(), &store, cwd, idx) catch |err| {
            try writeStashError(stderr, "show", err);
            return;
        };
        defer diff_result.deinit();

        if (diff_result.entries.len == 0) {
            try stdout.writeStreamingAll(io(), "no changes in stash entry\n");
            return;
        }

        for (diff_result.entries) |entry| {
            const prefix = switch (entry.kind) {
                .added => "A  ",
                .removed => "D  ",
                .modified => "M  ",
                .mode_changed => "T  ",
            };
            try stdout.writeStreamingAll(io(), prefix);
            try stdout.writeStreamingAll(io(), entry.path);
            try stdout.writeStreamingAll(io(), "\n");
        }
    } else {
        try stderr.writeStreamingAll(io(), "usage: mkit stash [save|list|pop|drop|show]\n");
    }
}

fn parseStashIndex(arg: []const u8) usize {
    return std.fmt.parseInt(usize, arg, 10) catch 0;
}

fn writeStashError(stderr: std.Io.File, operation: []const u8, err: anyerror) !void {
    try stderr.writeStreamingAll(io(), "error: stash ");
    try stderr.writeStreamingAll(io(), operation);
    try stderr.writeStreamingAll(io(), " failed: ");
    var buf: [256]u8 = undefined;
    const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
    try stderr.writeStreamingAll(io(), err_name);
    try stderr.writeStreamingAll(io(), "\n");
}

fn readRepoConfig(allocator: std.mem.Allocator, cwd: std.Io.Dir) !mkit.config.Config {
    return mkit.config.readConfig(allocator, io(), cwd) catch mkit.config.Config{};
}

fn loadSigningKey(
    allocator: std.mem.Allocator,
    cwd: std.Io.Dir,
    key_path: []const u8,
) !mkit.sign.KeyPair {
    const seed = try cwd.readFileAlloc(io(), key_path, allocator, .limited(128));
    defer allocator.free(seed);
    if (seed.len != 32) return error.InvalidKeyFile;
    return mkit.sign.KeyPair.fromSeed(seed[0..32].*);
}

fn verifyPackDigest(expected: mkit.hash.Hash, bytes: []const u8) !void {
    const actual = mkit.hash.hash(bytes);
    if (!std.mem.eql(u8, &actual, &expected)) return error.PackDigestMismatch;
}

fn ensureCommitExists(
    allocator: std.mem.Allocator,
    store: *mkit.store.ObjectStore,
    commit_hash: mkit.hash.Hash,
) !void {
    var obj = try store.get(allocator, commit_hash);
    defer obj.deinit(allocator);
    if (obj != .commit) return error.NotACommit;
}

fn buildPackLocatorRef(
    buf: []u8,
    ref_name: []const u8,
    commit_hash: mkit.hash.Hash,
) ![]const u8 {
    const hex = mkit.hash.toHex(commit_hash);
    return std.fmt.bufPrint(buf, "{s}.{s}.pack", .{ ref_name, &hex });
}

fn readPackDigestForRef(
    t: mkit.protocol.Transport,
    allocator: std.mem.Allocator,
    ref_name: []const u8,
    commit_hash: mkit.hash.Hash,
) !?mkit.hash.Hash {
    var specific_buf: [512]u8 = undefined;
    const specific_ref = try buildPackLocatorRef(&specific_buf, ref_name, commit_hash);
    if (try t.readRef(allocator, specific_ref)) |digest| {
        return digest;
    }

    // Backward-compatible fallback for older remotes that still publish
    // branch-scoped pack companions.
    var legacy_buf: [512]u8 = undefined;
    const legacy_ref = try std.fmt.bufPrint(&legacy_buf, "{s}.pack", .{ref_name});
    return try t.readRef(allocator, legacy_ref);
}

fn ensureCleanWorktree(
    allocator: std.mem.Allocator,
    store: *mkit.store.ObjectStore,
    cwd: std.Io.Dir,
) !void {
    const head_tree = try resolveHeadTree(allocator, store, cwd);
    var work_dir = try cwd.openDir(io(), ".", .{ .iterate = true });
    defer work_dir.close(io());

    var diff = try mkit.diff.statusDiff(allocator, io(), store, head_tree, work_dir);
    defer diff.deinit();
    if (diff.entries.len > 0) return error.DirtyWorktree;
}

fn ensureDirectoryEmpty(dir: std.Io.Dir) !void {
    // Open with iterate flag — cwd() handle may lack iteration support on macOS
    var iterable = dir.openDir(io(), ".", .{ .iterate = true }) catch return error.DirectoryNotEmpty;
    defer iterable.close(io());
    var iter = iterable.iterate();
    while (try iter.next(io())) |_| {
        return error.DirectoryNotEmpty;
    }
}

fn resolveTreeHash(allocator: std.mem.Allocator, store: *mkit.store.ObjectStore, h: mkit.hash.Hash) !?mkit.hash.Hash {
    var obj = store.get(allocator, h) catch |err| switch (err) {
        error.ObjectNotFound => return null,
        else => return err,
    };
    defer obj.deinit(allocator);

    return switch (obj) {
        .commit => |c| c.tree_hash,
        .tree => h,
        else => null,
    };
}

fn cmdTag(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    // mkit tag -d <name>
    if (args.len >= 2 and std.mem.eql(u8, args[0], "-d")) {
        const tag_name = args[1];
        mkit.refs.deleteTag(io(), cwd, tag_name) catch |err| switch (err) {
            error.TagNotFound => {
                try stderr.writeStreamingAll(io(), "error: tag '");
                try stderr.writeStreamingAll(io(), tag_name);
                try stderr.writeStreamingAll(io(), "' not found\n");
                return;
            },
            else => return err,
        };
        try stdout.writeStreamingAll(io(), "deleted tag ");
        try stdout.writeStreamingAll(io(), tag_name);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit tag <name> <hash> — create tag at specific commit
    if (args.len >= 2) {
        const tag_name = args[0];
        const hash_str = args[1];
        const h = mkit.hash.fromHex(hash_str) catch {
            try stderr.writeStreamingAll(io(), "error: invalid hash '");
            try stderr.writeStreamingAll(io(), hash_str);
            try stderr.writeStreamingAll(io(), "'\n");
            return;
        };
        // Check if tag already exists
        const existing = try mkit.refs.readTag(allocator, io(), cwd, tag_name);
        if (existing != null) {
            try stderr.writeStreamingAll(io(), "error: tag '");
            try stderr.writeStreamingAll(io(), tag_name);
            try stderr.writeStreamingAll(io(), "' already exists\n");
            return;
        }
        try mkit.refs.writeTag(io(), cwd, tag_name, h);
        const hex = mkit.hash.toHex(h);
        try stdout.writeStreamingAll(io(), "created tag ");
        try stdout.writeStreamingAll(io(), tag_name);
        try stdout.writeStreamingAll(io(), " at ");
        try stdout.writeStreamingAll(io(), hex[0..8]);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit tag <name> — create tag at HEAD
    if (args.len == 1) {
        const tag_name = args[0];
        const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
        if (head_hash == null) {
            try stderr.writeStreamingAll(io(), "error: no commits yet — cannot create tag\n");
            return;
        }
        // Check if tag already exists
        const existing = try mkit.refs.readTag(allocator, io(), cwd, tag_name);
        if (existing != null) {
            try stderr.writeStreamingAll(io(), "error: tag '");
            try stderr.writeStreamingAll(io(), tag_name);
            try stderr.writeStreamingAll(io(), "' already exists\n");
            return;
        }
        try mkit.refs.writeTag(io(), cwd, tag_name, head_hash.?);
        const hex = mkit.hash.toHex(head_hash.?);
        try stdout.writeStreamingAll(io(), "created tag ");
        try stdout.writeStreamingAll(io(), tag_name);
        try stdout.writeStreamingAll(io(), " at ");
        try stdout.writeStreamingAll(io(), hex[0..8]);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit tag — list tags
    const tag_list = try mkit.refs.listTags(allocator, io(), cwd);
    defer {
        for (tag_list) |t| {
            allocator.free(t.name);
        }
        allocator.free(tag_list);
    }

    if (tag_list.len == 0) {
        try stderr.writeStreamingAll(io(), "no tags\n");
        return;
    }

    for (tag_list) |t| {
        try stdout.writeStreamingAll(io(), "  ");
        try stdout.writeStreamingAll(io(), t.name);
        if (t.hash) |h| {
            const hex = mkit.hash.toHex(h);
            try stdout.writeStreamingAll(io(), " ");
            try stdout.writeStreamingAll(io(), hex[0..8]);
        }
        try stdout.writeStreamingAll(io(), "\n");
    }
}

fn cmdConfig(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    // mkit config <key> <value> — set value
    if (args.len >= 2) {
        const key = args[0];
        const value = args[1];

        var config = try mkit.config.readConfig(allocator, io(), cwd);
        defer config.deinit();

        if (std.mem.eql(u8, key, "author_mid")) {
            try stderr.writeStreamingAll(io(), "error: unknown config key 'author_mid' (did you mean 'user.identity'?)\n");
            try stderr.writeStreamingAll(io(), "hint: run 'mkit config user.identity mid:<N>' for the 8-byte-LE opaque form\n");
            return;
        } else if (std.mem.eql(u8, key, "user.identity")) {
            if (config.user_identity.len > 0) {
                if (config.allocator) |alloc| alloc.free(config.user_identity);
            }
            if (value.len == 0) {
                config.user_identity = mkit.config.default_user_identity;
            } else {
                config.user_identity = mkit.config.expandUserIdentity(allocator, value) catch {
                    try stderr.writeStreamingAll(io(), "error: invalid user.identity value\n");
                    try stderr.writeStreamingAll(io(), "hint: accepted forms: ed25519:<64-hex>, mid:<u64>, or raw [kind][len][bytes] hex\n");
                    return;
                };
            }
        } else if (std.mem.eql(u8, key, "signing_key")) {
            // If current is not default, free it before replacing
            if (config.allocator) |alloc| {
                if (!std.mem.eql(u8, config.signing_key, mkit.config.default_signing_key)) {
                    alloc.free(config.signing_key);
                }
            }
            if (!std.mem.eql(u8, value, mkit.config.default_signing_key)) {
                config.signing_key = try allocator.dupe(u8, value);
            } else {
                config.signing_key = mkit.config.default_signing_key;
            }
        } else if (std.mem.eql(u8, key, "default_branch")) {
            // If current is not default, free it before replacing
            if (config.allocator) |alloc| {
                if (!std.mem.eql(u8, config.default_branch, mkit.config.default_branch)) {
                    alloc.free(config.default_branch);
                }
            }
            if (!std.mem.eql(u8, value, mkit.config.default_branch)) {
                config.default_branch = try allocator.dupe(u8, value);
            } else {
                config.default_branch = mkit.config.default_branch;
            }
        } else if (std.mem.eql(u8, key, "remote_endpoint")) {
            if (config.allocator) |alloc| {
                if (!std.mem.eql(u8, config.remote_endpoint, mkit.config.default_remote_endpoint)) {
                    alloc.free(config.remote_endpoint);
                }
            }
            if (value.len > 0) {
                config.remote_endpoint = try allocator.dupe(u8, value);
            } else {
                config.remote_endpoint = mkit.config.default_remote_endpoint;
            }
        } else if (std.mem.eql(u8, key, "remote_bucket")) {
            if (config.allocator) |alloc| {
                if (!std.mem.eql(u8, config.remote_bucket, mkit.config.default_remote_bucket)) {
                    alloc.free(config.remote_bucket);
                }
            }
            if (value.len > 0) {
                config.remote_bucket = try allocator.dupe(u8, value);
            } else {
                config.remote_bucket = mkit.config.default_remote_bucket;
            }
        } else if (std.mem.eql(u8, key, "remote_type")) {
            if (config.allocator) |alloc| {
                if (!std.mem.eql(u8, config.remote_type, mkit.config.default_remote_type)) {
                    alloc.free(config.remote_type);
                }
            }
            if (value.len > 0) {
                config.remote_type = try allocator.dupe(u8, value);
            } else {
                config.remote_type = mkit.config.default_remote_type;
            }
        } else if (std.mem.eql(u8, key, "ssh.strict_host_key_checking")) {
            if (config.allocator) |alloc| {
                if (config.ssh_strict_host_key_checking.len > 0)
                    alloc.free(config.ssh_strict_host_key_checking);
            }
            config.ssh_strict_host_key_checking = if (value.len == 0) "" else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "ssh.user_known_hosts_file")) {
            if (config.allocator) |alloc| {
                if (config.ssh_user_known_hosts_file.len > 0)
                    alloc.free(config.ssh_user_known_hosts_file);
            }
            config.ssh_user_known_hosts_file = if (value.len == 0) "" else try allocator.dupe(u8, value);
        } else if (std.mem.eql(u8, key, "ssh.identity_file")) {
            if (config.allocator) |alloc| {
                if (config.ssh_identity_file.len > 0)
                    alloc.free(config.ssh_identity_file);
            }
            config.ssh_identity_file = if (value.len == 0) "" else try allocator.dupe(u8, value);
        } else {
            try stderr.writeStreamingAll(io(), "error: unknown config key '");
            try stderr.writeStreamingAll(io(), key);
            try stderr.writeStreamingAll(io(), "'\n");
            try stderr.writeStreamingAll(io(), "valid keys: user.identity, signing_key, default_branch, remote_endpoint, remote_bucket, remote_type, ssh.strict_host_key_checking, ssh.user_known_hosts_file, ssh.identity_file\n");
            return;
        }

        try mkit.config.writeConfig(io(), cwd, config);
        try stdout.writeStreamingAll(io(), key);
        try stdout.writeStreamingAll(io(), " = ");
        try stdout.writeStreamingAll(io(), value);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    // mkit config — show all config
    var config = try mkit.config.readConfig(allocator, io(), cwd);
    defer config.deinit();

    try stdout.writeStreamingAll(io(), "user.identity = ");
    try stdout.writeStreamingAll(io(), if (config.user_identity.len > 0) config.user_identity else "(derived from signing key)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "signing_key = ");
    try stdout.writeStreamingAll(io(), config.signing_key);
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "default_branch = ");
    try stdout.writeStreamingAll(io(), config.default_branch);
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "remote_endpoint = ");
    try stdout.writeStreamingAll(io(), if (config.remote_endpoint.len > 0) config.remote_endpoint else "(not set)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "remote_bucket = ");
    try stdout.writeStreamingAll(io(), if (config.remote_bucket.len > 0) config.remote_bucket else "(not set)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "remote_type = ");
    try stdout.writeStreamingAll(io(), if (config.remote_type.len > 0) config.remote_type else "(auto)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "ssh.strict_host_key_checking = ");
    try stdout.writeStreamingAll(io(), if (config.ssh_strict_host_key_checking.len > 0) config.ssh_strict_host_key_checking else "(inherit)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "ssh.user_known_hosts_file = ");
    try stdout.writeStreamingAll(io(), if (config.ssh_user_known_hosts_file.len > 0) config.ssh_user_known_hosts_file else "(inherit)");
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "ssh.identity_file = ");
    try stdout.writeStreamingAll(io(), if (config.ssh_identity_file.len > 0) config.ssh_identity_file else "(inherit)");
    try stdout.writeStreamingAll(io(), "\n");
}

/// Push reachable objects + the current branch ref to the configured remote.
fn cmdPush(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    // Parse --dry-run.
    var dry_run = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--dry-run")) {
            dry_run = true;
        }
    }

    const cwd = std.Io.Dir.cwd();

    var config = mkit.config.readConfig(allocator, io(), cwd) catch mkit.config.Config{};
    defer config.deinit();

    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Resolve HEAD to a commit
    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd);
    if (head_hash == null) {
        try stderr.writeStreamingAll(io(), "error: no commits yet — nothing to push\n");
        return;
    }
    const tip_hash = head_hash.?;

    const head = mkit.refs.readHead(allocator, io(), cwd) catch null;
    var ref_name_buf: [256]u8 = undefined;
    var ref_name: []const u8 = "refs/heads/main";
    if (head) |h| {
        switch (h) {
            .branch => |branch| {
                defer allocator.free(branch);
                const written = std.fmt.bufPrint(&ref_name_buf, "refs/heads/{s}", .{branch}) catch "refs/heads/main";
                ref_name = written;
            },
            .detached => {},
        }
    }

    // Build pack companion ref name early so we can read it during negotiation.
    var pack_ref_buf: [512]u8 = undefined;
    const pack_ref_name = buildPackLocatorRef(&pack_ref_buf, ref_name, tip_hash) catch {
        try stderr.writeStreamingAll(io(), "error: ref name too long\n");
        return;
    };

    var remote_old_hash: ?mkit.hash.Hash = null;
    var remote_old_pack: ?mkit.hash.Hash = null;
    if (config.remote_endpoint.len > 0) {
        var transport_handle = openTransport(allocator, config) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to open transport: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        defer transport_handle.deinit();
        const t = transport_handle.transport;

        remote_old_hash = t.readRef(allocator, ref_name) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to read remote ref: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };

        // Read current pack companion for CAS precondition.
        remote_old_pack = t.readRef(allocator, pack_ref_name) catch null;

        if (remote_old_hash) |remote_tip| {
            if (std.mem.eql(u8, &remote_tip, &tip_hash)) {
                try stdout.writeStreamingAll(io(), "already up to date\n");
                return;
            }
            ensureCommitExists(allocator, &store, remote_tip) catch {
                try stderr.writeStreamingAll(io(), "error: remote ref points to a commit that is not present locally — run 'mkit pull' first\n");
                return;
            };
            const fast_forward = mkit.merge.isAncestor(allocator, &store, remote_tip, tip_hash) catch {
                try stderr.writeStreamingAll(io(), "error: failed to verify remote ancestry\n");
                return;
            };
            if (!fast_forward) {
                try stderr.writeStreamingAll(io(), "error: non-fast-forward push rejected — run 'mkit pull' first\n");
                return;
            }
        }
    }

    // Build packfile from reachable objects
    const pack_result = mkit.packfile.packReachable(allocator, &store, tip_hash) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to build packfile: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    defer allocator.free(pack_result.bytes);

    if (config.remote_endpoint.len > 0 and !dry_run) {
        // Transport-based push: upload pack + write ref + write .pack companion
        var transport_handle = openTransport(allocator, config) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to open transport: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        defer transport_handle.deinit();
        const t = transport_handle.transport;

        // 1. Upload packfile
        t.uploadPack(allocator, pack_result.bytes, pack_result.digest) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to upload pack: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };

        // 2. Publish a commit-specific pack locator before moving the branch tip.
        //    Use CAS precondition so the Worker doesn't reject with 428.
        const pack_condition: mkit.protocol.RefWriteCondition = if (remote_old_pack) |old|
            .{ .match = old }
        else
            .missing;
        t.updateRef(allocator, pack_ref_name, pack_condition, pack_result.digest) catch |err| switch (err) {
            error.RefConflict => {
                // Pack companion conflict is non-fatal — the pack itself is content-addressed.
                try stderr.writeStreamingAll(io(), "warning: pack companion ref conflict (non-fatal)\n");
            },
            else => {
                try stderr.writeStreamingAll(io(), "warning: could not write pack companion\n");
            },
        };

        // 3. CAS-update remote ref against the state we observed during push negotiation.
        const ref_condition: mkit.protocol.RefWriteCondition = if (remote_old_hash) |old|
            .{ .match = old }
        else
            .missing;
        t.updateRef(allocator, ref_name, ref_condition, tip_hash) catch |err| {
            if (err == error.RefConflict) {
                try stderr.writeStreamingAll(io(), "error: remote ref changed during push — retry after fetch/pull\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: failed to write remote ref: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };

        // Print success summary
        const tip_hex = mkit.hash.toHex(tip_hash);
        try stdout.writeStreamingAll(io(), "pushed ");
        try stdout.writeStreamingAll(io(), tip_hex[0..8]);
        try stdout.writeStreamingAll(io(), " -> ");
        try stdout.writeStreamingAll(io(), ref_name);
        try stdout.writeStreamingAll(io(), "\n");

        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{pack_result.bytes.len}) catch "?";
        try stdout.writeStreamingAll(io(), "packfile: ");
        try stdout.writeStreamingAll(io(), size_str);
        try stdout.writeStreamingAll(io(), " bytes\n");
    } else {
        // Dry-run or no remote configured: print a minimal summary.
        try stdout.writeStreamingAll(io(), "=== push summary (dry run) ===\n");

        const tip_hex = mkit.hash.toHex(tip_hash);
        try stdout.writeStreamingAll(io(), "commit: ");
        try stdout.writeStreamingAll(io(), tip_hex[0..16]);
        try stdout.writeStreamingAll(io(), "...\n");

        try stdout.writeStreamingAll(io(), "\nref update:\n");
        try stdout.writeStreamingAll(io(), "  ");
        try stdout.writeStreamingAll(io(), ref_name);
        try stdout.writeStreamingAll(io(), " ");
        if (remote_old_hash) |old| {
            const old_hex = mkit.hash.toHex(old);
            try stdout.writeStreamingAll(io(), old_hex[0..8]);
        } else {
            try stdout.writeStreamingAll(io(), "(new)");
        }
        try stdout.writeStreamingAll(io(), " -> ");
        const new_hex = mkit.hash.toHex(tip_hash);
        try stdout.writeStreamingAll(io(), new_hex[0..8]);
        try stdout.writeStreamingAll(io(), "\n");

        var size_buf: [20]u8 = undefined;
        const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{pack_result.bytes.len}) catch "?";
        try stdout.writeStreamingAll(io(), "\npackfile: ");
        try stdout.writeStreamingAll(io(), size_str);
        try stdout.writeStreamingAll(io(), " bytes\n");

        if (config.remote_endpoint.len == 0) {
            try stdout.writeStreamingAll(io(), "\nno remote configured — use 'mkit remote add <url>' to enable push\n");
        } else {
            try stdout.writeStreamingAll(io(), "\nremote update skipped (--dry-run)\n");
        }
    }
}

fn cmdMerge(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit merge <branch>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Serialize against other commit/checkout/merge/rebase. See src/lock.zig.
    var mkit_dir = cwd.openDir(io(), ".mkit", .{}) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open .mkit directory\n");
        return;
    };
    defer mkit_dir.close(io());
    var repo_lock = mkit.lock.acquireDefault(io(), mkit_dir, "index.lock") catch |err| switch (err) {
        error.LockBusy => {
            try stderr.writeStreamingAll(io(), "error: another mkit process is running in this repository (.mkit/index.lock held)\n");
            return;
        },
        else => return err,
    };
    defer repo_lock.release();

    const branch_name = args[0];

    // Resolve HEAD (ours)
    const ours_hash = try mkit.refs.resolveHead(allocator, io(), cwd) orelse {
        try stderr.writeStreamingAll(io(), "error: no commits on current branch\n");
        return;
    };

    // Resolve target branch (theirs)
    const theirs_hash = (try mkit.refs.readRef(allocator, io(), cwd, branch_name)) orelse {
        try stderr.writeStreamingAll(io(), "error: branch '");
        try stderr.writeStreamingAll(io(), branch_name);
        try stderr.writeStreamingAll(io(), "' not found\n");
        return;
    };

    // Already up to date?
    if (std.mem.eql(u8, &ours_hash, &theirs_hash)) {
        try stdout.writeStreamingAll(io(), "already up to date\n");
        return;
    }

    // Find merge base
    const base_hash = try mkit.merge.findMergeBase(allocator, &store, ours_hash, theirs_hash);

    // Fast-forward: if base == ours, theirs is ahead — just update HEAD
    if (base_hash) |bh| {
        if (std.mem.eql(u8, &bh, &ours_hash)) {
            // Restore working directory from theirs commit tree
            var theirs_obj = store.get(allocator, theirs_hash) catch |err| {
                var buf: [256]u8 = undefined;
                const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
                try stderr.writeStreamingAll(io(), "error: could not read commit: ");
                try stderr.writeStreamingAll(io(), err_name);
                try stderr.writeStreamingAll(io(), "\n");
                return;
            };
            defer theirs_obj.deinit(allocator);

            if (theirs_obj == .commit) {
                var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
                    try stderr.writeStreamingAll(io(), "warning: could not open working directory for restore\n");
                    return;
                };
                defer work_dir.close(io());
                mkit.restore.restoreTree(allocator, io(), &store, theirs_obj.commit.tree_hash, work_dir, .{}) catch {
                    try stderr.writeStreamingAll(io(), "error: failed to restore working directory\n");
                    return;
                };
            }

            try mkit.refs.updateHead(allocator, io(), cwd, theirs_hash);

            const hex = mkit.hash.toHex(theirs_hash);
            try stdout.writeStreamingAll(io(), "fast-forward ");
            try stdout.writeStreamingAll(io(), hex[0..8]);
            try stdout.writeStreamingAll(io(), "\n");
            return;
        }
    }

    // Load ours commit to get tree hash
    var ours_obj = store.get(allocator, ours_hash) catch {
        try stderr.writeStreamingAll(io(), "error: could not read HEAD commit\n");
        return;
    };
    defer ours_obj.deinit(allocator);
    if (ours_obj != .commit) {
        try stderr.writeStreamingAll(io(), "error: HEAD does not point to a commit\n");
        return;
    }
    const ours_tree = ours_obj.commit.tree_hash;

    // Load theirs commit to get tree hash
    var theirs_obj = store.get(allocator, theirs_hash) catch {
        try stderr.writeStreamingAll(io(), "error: could not read branch commit\n");
        return;
    };
    defer theirs_obj.deinit(allocator);
    if (theirs_obj != .commit) {
        try stderr.writeStreamingAll(io(), "error: branch does not point to a commit\n");
        return;
    }
    const theirs_tree = theirs_obj.commit.tree_hash;

    // Load base commit tree (null if no common ancestor)
    var base_tree: ?mkit.hash.Hash = null;
    if (base_hash) |bh| {
        var base_obj = store.get(allocator, bh) catch {
            try stderr.writeStreamingAll(io(), "error: could not read merge base commit\n");
            return;
        };
        defer base_obj.deinit(allocator);
        if (base_obj == .commit) {
            base_tree = base_obj.commit.tree_hash;
        }
    }

    // 3-way merge
    var result = try mkit.merge.mergeTrees(allocator, &store, base_tree, ours_tree, theirs_tree);
    defer result.deinit();

    if (result.hasConflicts()) {
        try stderr.writeStreamingAll(io(), "merge conflict:\n");
        for (result.conflicts) |c| {
            const kind_str: []const u8 = switch (c.kind) {
                .modify_modify => "both modified",
                .delete_modify => "delete/modify",
                .add_add => "both added",
            };
            try stderr.writeStreamingAll(io(), "  ");
            try stderr.writeStreamingAll(io(), c.path);
            try stderr.writeStreamingAll(io(), " (");
            try stderr.writeStreamingAll(io(), kind_str);
            try stderr.writeStreamingAll(io(), ")\n");
        }
        return;
    }

    var config = try readRepoConfig(allocator, cwd);
    defer config.deinit();

    const kp = loadSigningKey(allocator, cwd, config.signing_key) catch |err| switch (err) {
        error.FileNotFound => {
            try stderr.writeStreamingAll(io(), "error: no signing key found (run 'mkit keygen' first)\n");
            return;
        },
        error.InvalidKeyFile => {
            try stderr.writeStreamingAll(io(), "error: invalid key file (expected 32-byte seed)\n");
            return;
        },
        else => {
            try stderr.writeStreamingAll(io(), "error: invalid key seed\n");
            return;
        },
    };

    // Get timestamp (u64 Unix seconds per SPEC-OBJECTS §5).
    const timestamp: u64 = @intCast(@max(std.Io.Clock.real.now(io()).toSeconds(), 0));

    // Create merge commit (two parents)
    var merge_msg_buf: [512]u8 = undefined;
    const merge_msg = std.fmt.bufPrint(&merge_msg_buf, "Merge branch '{s}'", .{branch_name}) catch "Merge branch";

    var id_scratch: [1024]u8 = undefined;
    const author_id = resolveAuthorIdentity(config.user_identity, id_scratch[0..], kp.public_key[0..]) catch {
        try stderr.writeStreamingAll(io(), "error: invalid user.identity in config (run 'mkit config user.identity <value>')\n");
        return;
    };

    var parents_buf: [2]mkit.hash.Hash = .{ ours_hash, theirs_hash };
    var commit = mkit.object.Commit{
        .tree_hash = result.tree_hash,
        .parents = &parents_buf,
        .author = author_id,
        .signer = kp.public_key,
        .message = merge_msg,
        .timestamp = timestamp,
        .message_hash = mkit.hash.hash(merge_msg),
        .content_digest = mkit.hash.zero,
        .signature = .{0} ** 64,
    };

    commit.signature = mkit.sign.signCommit(allocator, commit, kp) catch {
        try stderr.writeStreamingAll(io(), "error: signing failed\n");
        return;
    };

    const commit_obj = mkit.object.Object{ .commit = commit };
    const commit_hash = try store.put(allocator, commit_obj);

    // Restore working directory from merged tree
    {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: could not open working directory for restore\n");
            return;
        };
        defer work_dir.close(io());
        mkit.restore.restoreTree(allocator, io(), &store, result.tree_hash, work_dir, .{}) catch |err| {
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), "error: could not restore merged working tree: ");
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
    }

    // Update HEAD after restore succeeds
    try mkit.refs.updateHead(allocator, io(), cwd, commit_hash);

    const hex = mkit.hash.toHex(commit_hash);
    try stdout.writeStreamingAll(io(), "merged '");
    try stdout.writeStreamingAll(io(), branch_name);
    try stdout.writeStreamingAll(io(), "' into HEAD\n");
    try stdout.writeStreamingAll(io(), "[merge] ");
    try stdout.writeStreamingAll(io(), &hex);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdKeygen() !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();

    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    cwd.createDirPath(io(), ".mkit/keys") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Set restrictive directory permissions (owner rwx only)
    {
        var d = cwd.openDir(io(), ".mkit/keys", .{}) catch null;
        if (d) |*dir| {
            _ = std.c.fchmod(dir.handle, 0o700);
            dir.close(io());
        }
    }

    const kp = mkit.sign.KeyPair.generate(io());

    const key_path = ".mkit/keys/default.key";
    if (cwd.openFile(io(), key_path, .{})) |f| {
        f.close(io());
        try stderr.writeStreamingAll(io(), "error: key already exists at .mkit/keys/default.key\n");
        try stderr.writeStreamingAll(io(), "       delete it first if you want to generate a new one\n");
        return;
    } else |_| {}

    const file = try cwd.createFile(io(), key_path, .{ .permissions = @enumFromInt(0o600) });
    defer file.close(io());
    try file.writeStreamingAll(io(), &kp.seed);

    const pub_hex = mkit.hash.toHex(kp.public_key);
    try stdout.writeStreamingAll(io(), "generated keypair\n");
    try stdout.writeStreamingAll(io(), "public key: ");
    try stdout.writeStreamingAll(io(), &pub_hex);
    try stdout.writeStreamingAll(io(), "\n");
    try stdout.writeStreamingAll(io(), "saved seed: .mkit/keys/default.key\n");
}

fn cmdVerify(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit verify <hash>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const hash_str = args[0];
    const h = mkit.hash.fromHex(hash_str) catch {
        try stderr.writeStreamingAll(io(), "error: invalid hash '");
        try stderr.writeStreamingAll(io(), hash_str);
        try stderr.writeStreamingAll(io(), "'\n");
        return;
    };

    var obj = store.get(allocator, h) catch |err| switch (err) {
        error.ObjectNotFound => {
            try stderr.writeStreamingAll(io(), "error: object not found\n");
            return;
        },
        error.HashMismatch => {
            try stderr.writeStreamingAll(io(), "error: object corrupt (hash mismatch)\n");
            return;
        },
        else => return err,
    };
    defer obj.deinit(allocator);

    switch (obj) {
        .commit => |c| {
            const valid = mkit.sign.verifyCommit(allocator, c) catch {
                try stderr.writeStreamingAll(io(), "error: verification failed\n");
                return;
            };
            if (valid) {
                const signer_hex = mkit.hash.toHex(c.signer);
                try stdout.writeStreamingAll(io(), "valid commit signature\n");
                try stdout.writeStreamingAll(io(), "signer: ");
                try stdout.writeStreamingAll(io(), &signer_hex);
                try stdout.writeStreamingAll(io(), "\n");
                var author_buf: [64]u8 = undefined;
                const author_str = formatAuthorShort(&author_buf, c.author);
                try stdout.writeStreamingAll(io(), "author: ");
                try stdout.writeStreamingAll(io(), author_str);
                try stdout.writeStreamingAll(io(), "\n");
            } else {
                try stderr.writeStreamingAll(io(), "invalid: signature verification failed\n");
            }
        },
        .remix => |r| {
            const valid = mkit.sign.verifyRemix(allocator, r) catch {
                try stderr.writeStreamingAll(io(), "error: verification failed\n");
                return;
            };
            if (valid) {
                const signer_hex = mkit.hash.toHex(r.signer);
                try stdout.writeStreamingAll(io(), "valid remix signature\n");
                try stdout.writeStreamingAll(io(), "signer: ");
                try stdout.writeStreamingAll(io(), &signer_hex);
                try stdout.writeStreamingAll(io(), "\n");
                var author_buf: [64]u8 = undefined;
                const author_str = formatAuthorShort(&author_buf, r.author);
                try stdout.writeStreamingAll(io(), "author: ");
                try stdout.writeStreamingAll(io(), author_str);
                try stdout.writeStreamingAll(io(), "\n");
            } else {
                try stderr.writeStreamingAll(io(), "invalid: signature verification failed\n");
            }
        },
        .blob => {
            try stderr.writeStreamingAll(io(), "error: blobs are not signed objects\n");
        },
        .tree => {
            try stderr.writeStreamingAll(io(), "error: trees are not signed objects\n");
        },
        .chunked_blob => {
            try stderr.writeStreamingAll(io(), "error: chunked blobs are not signed objects\n");
        },
        .delta => {
            try stderr.writeStreamingAll(io(), "error: deltas are not signed objects\n");
        },
    }
}

fn cmdRemote(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();

    // Verify we're in a mkit repo
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    // `mkit remote set <url>` and `mkit remote add <url>` are aliases —
    // both run the URL through the strict `mkit+<scheme>://` validator
    // and then persist the parsed form to .mkit/config.
    const is_set_or_add = args.len >= 2 and
        (std.mem.eql(u8, args[0], "set") or std.mem.eql(u8, args[0], "add"));

    if (is_set_or_add) {
        const url = args[1];

        // Strict `mkit+<scheme>://...` parser (W5). Anything else is a
        // hard reject — we never persist ambiguous URLs.
        const parsed = mkit.remote.validateRemoteUrl(url) catch |err| {
            try stderr.writeStreamingAll(io(), "error: invalid remote URL '");
            try stderr.writeStreamingAll(io(), url);
            try stderr.writeStreamingAll(io(), "': ");
            switch (err) {
                error.InvalidScheme => try stderr.writeStreamingAll(io(), "must start with 'mkit+<scheme>://'"),
                error.UnknownScheme => try stderr.writeStreamingAll(io(), "unknown scheme (expected file, https, s3, ssh, or memory)"),
                error.MalformedUrl => try stderr.writeStreamingAll(io(), "malformed URL (missing host, path, or field)"),
            }
            try stderr.writeStreamingAll(io(), "\n");
            try stderr.writeStreamingAll(io(), "hint: URL must start with mkit+<scheme>:// (e.g. mkit+https://, mkit+ssh://, mkit+file://, mkit+s3://)\n");
            return;
        };

        var config = try mkit.config.readConfig(allocator, io(), cwd);
        defer config.deinit();

        // Free old values if heap-allocated
        if (config.allocator) |alloc| {
            if (!std.mem.eql(u8, config.remote_endpoint, mkit.config.default_remote_endpoint)) {
                alloc.free(config.remote_endpoint);
            }
            if (!std.mem.eql(u8, config.remote_bucket, mkit.config.default_remote_bucket)) {
                alloc.free(config.remote_bucket);
            }
            if (!std.mem.eql(u8, config.remote_type, mkit.config.default_remote_type)) {
                alloc.free(config.remote_type);
            }
        }

        switch (parsed) {
            .file => |path| {
                config.remote_endpoint = try allocator.dupe(u8, path);
                config.remote_bucket = mkit.config.default_remote_bucket;
                config.remote_type = try allocator.dupe(u8, "file");
            },
            .s3 => |s| {
                config.remote_endpoint = try allocator.dupe(u8, s.bucket);
                config.remote_bucket = try allocator.dupe(u8, s.prefix);
                config.remote_type = try allocator.dupe(u8, "s3");
            },
            .https => {
                // Preserve the original URL so downstream HTTP transport
                // gets host:port/path unchanged.
                config.remote_endpoint = try allocator.dupe(u8, url);
                config.remote_bucket = mkit.config.default_remote_bucket;
                config.remote_type = try allocator.dupe(u8, "http");
            },
            .ssh => {
                config.remote_endpoint = try allocator.dupe(u8, url);
                config.remote_bucket = mkit.config.default_remote_bucket;
                config.remote_type = try allocator.dupe(u8, "ssh");
            },
            .memory => {
                config.remote_endpoint = try allocator.dupe(u8, url);
                config.remote_bucket = mkit.config.default_remote_bucket;
                config.remote_type = try allocator.dupe(u8, "memory");
            },
        }

        try mkit.config.writeConfig(io(), cwd, config);

        try stdout.writeStreamingAll(io(), "remote ");
        try stdout.writeStreamingAll(io(), args[0]);
        try stdout.writeStreamingAll(io(), "\n");
        try stdout.writeStreamingAll(io(), "  endpoint: ");
        try stdout.writeStreamingAll(io(), config.remote_endpoint);
        try stdout.writeStreamingAll(io(), "\n");
        if (config.remote_bucket.len > 0) {
            try stdout.writeStreamingAll(io(), "  bucket:   ");
            try stdout.writeStreamingAll(io(), config.remote_bucket);
            try stdout.writeStreamingAll(io(), "\n");
        }
        if (config.remote_type.len > 0) {
            try stdout.writeStreamingAll(io(), "  type:     ");
            try stdout.writeStreamingAll(io(), config.remote_type);
            try stdout.writeStreamingAll(io(), "\n");
        }
    } else if (args.len == 0) {
        // mkit remote — show current config
        var config = try mkit.config.readConfig(allocator, io(), cwd);
        defer config.deinit();

        if (config.remote_endpoint.len == 0) {
            try stdout.writeStreamingAll(io(), "no remote configured\n");
            try stdout.writeStreamingAll(io(), "use: mkit remote add <url>\n");
        } else {
            try stdout.writeStreamingAll(io(), "endpoint: ");
            try stdout.writeStreamingAll(io(), config.remote_endpoint);
            try stdout.writeStreamingAll(io(), "\n");
            if (config.remote_bucket.len > 0) {
                try stdout.writeStreamingAll(io(), "bucket:   ");
                try stdout.writeStreamingAll(io(), config.remote_bucket);
                try stdout.writeStreamingAll(io(), "\n");
            }
            if (config.remote_type.len > 0) {
                try stdout.writeStreamingAll(io(), "type:     ");
                try stdout.writeStreamingAll(io(), config.remote_type);
                try stdout.writeStreamingAll(io(), "\n");
            }
        }
    } else {
        try stderr.writeStreamingAll(io(), "usage: mkit remote [add|set <url>]\n");
        try stderr.writeStreamingAll(io(), "  URL must start with mkit+<scheme>://\n");
        try stderr.writeStreamingAll(io(), "  schemes: file, https, s3, ssh, memory\n");
    }
}

fn cmdPull(allocator: std.mem.Allocator, _: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    const cwd = std.Io.Dir.cwd();

    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Read remote config
    var config = try mkit.config.readConfig(allocator, io(), cwd);
    defer config.deinit();

    if (config.remote_endpoint.len == 0) {
        try stderr.writeStreamingAll(io(), "error: no remote configured (use 'mkit remote add <url>')\n");
        return;
    }

    // Get current branch
    const head = mkit.refs.readHead(allocator, io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: cannot read HEAD\n");
        return;
    };
    var branch_name: []const u8 = undefined;
    var branch_owned: bool = false;
    switch (head) {
        .branch => |b| {
            branch_name = b;
            branch_owned = true;
        },
        .detached => {
            try stderr.writeStreamingAll(io(), "error: cannot pull in detached HEAD state\n");
            return;
        },
    }
    defer if (branch_owned) allocator.free(branch_name);

    // Build ref name
    var ref_name_buf: [256]u8 = undefined;
    const ref_name = std.fmt.bufPrint(&ref_name_buf, "refs/heads/{s}", .{branch_name}) catch {
        try stderr.writeStreamingAll(io(), "error: branch name too long\n");
        return;
    };

    // Open transport
    var transport_handle = openTransport(allocator, config) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to open transport: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    defer transport_handle.deinit();
    const t = transport_handle.transport;

    // 1. Read remote ref
    const remote_hash = t.readRef(allocator, ref_name) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to read remote ref: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    } orelse {
        try stderr.writeStreamingAll(io(), "remote branch '");
        try stderr.writeStreamingAll(io(), branch_name);
        try stderr.writeStreamingAll(io(), "' not found\n");
        return;
    };

    // 2. Check if already up to date
    const local_hash = try mkit.refs.readRef(allocator, io(), cwd, branch_name);
    if (local_hash) |lh| {
        if (std.mem.eql(u8, &lh, &remote_hash)) {
            try stdout.writeStreamingAll(io(), "already up to date\n");
            return;
        }
    }

    // 3. Read the commit-specific pack locator to discover pack digest.
    const pack_digest = readPackDigestForRef(t, allocator, ref_name, remote_hash) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to read pack companion: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    } orelse {
        try stderr.writeStreamingAll(io(), "error: pack companion not found for ");
        try stderr.writeStreamingAll(io(), ref_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };

    // 4. Download pack
    const pack_bytes = t.downloadPack(allocator, pack_digest) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to download pack: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    defer allocator.free(pack_bytes);
    verifyPackDigest(pack_digest, pack_bytes) catch {
        try stderr.writeStreamingAll(io(), "error: downloaded pack failed digest verification\n");
        return;
    };

    // 5. Unpack into local store
    mkit.packfile.unpackInto(allocator, pack_bytes, &store) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to unpack: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    ensureCommitExists(allocator, &store, remote_hash) catch {
        try stderr.writeStreamingAll(io(), "error: downloaded pack does not contain the advertised remote commit\n");
        return;
    };

    if (local_hash) |lh| {
        const fast_forward = mkit.merge.isAncestor(allocator, &store, lh, remote_hash) catch {
            try stderr.writeStreamingAll(io(), "error: failed to verify pull ancestry\n");
            return;
        };
        if (!fast_forward) {
            try stderr.writeStreamingAll(io(), "error: non-fast-forward pull rejected — local branch has diverged\n");
            return;
        }
    }
    ensureCleanWorktree(allocator, &store, cwd) catch {
        try stderr.writeStreamingAll(io(), "error: pull would overwrite local changes; commit or stash them first\n");
        return;
    };

    // 6. Restore working directory from the remote commit's tree
    var commit_obj = store.get(allocator, remote_hash) catch |err| {
        try stderr.writeStreamingAll(io(), "error: could not read commit: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    defer commit_obj.deinit(allocator);

    if (commit_obj == .commit) {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
            return;
        };
        defer work_dir.close(io());
        mkit.restore.restoreTree(allocator, io(), &store, commit_obj.commit.tree_hash, work_dir, .{}) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to restore working directory: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            try stderr.writeStreamingAll(io(), "ref not updated — working directory may be inconsistent\n");
            return;
        };
    }

    // 7. Update local ref only after restore succeeds
    mkit.refs.writeRef(io(), cwd, branch_name, remote_hash) catch |err| {
        try stderr.writeStreamingAll(io(), "error: failed to update local ref: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };

    // Print success
    const remote_hex = mkit.hash.toHex(remote_hash);
    try stdout.writeStreamingAll(io(), "pulled ");
    try stdout.writeStreamingAll(io(), remote_hex[0..8]);
    try stdout.writeStreamingAll(io(), " -> ");
    try stdout.writeStreamingAll(io(), branch_name);
    try stdout.writeStreamingAll(io(), "\n");

    var size_buf: [20]u8 = undefined;
    const size_str = std.fmt.bufPrint(&size_buf, "{d}", .{pack_bytes.len}) catch "?";
    try stdout.writeStreamingAll(io(), "unpacked ");
    try stdout.writeStreamingAll(io(), size_str);
    try stdout.writeStreamingAll(io(), " bytes\n");
}

fn cmdClone(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit clone [--depth N] [--sparse ...] <url>\n");
        try stderr.writeStreamingAll(io(), "  examples:\n");
        try stderr.writeStreamingAll(io(), "    mkit clone https://account.r2.cloudflarestorage.com/bucket\n");
        try stderr.writeStreamingAll(io(), "    mkit clone s3://endpoint/bucket\n");
        try stderr.writeStreamingAll(io(), "    mkit clone file:///path/to/repo\n");
        try stderr.writeStreamingAll(io(), "    mkit clone /path/to/repo\n");
        try stderr.writeStreamingAll(io(), "    mkit clone --depth 1 <url>\n");
        try stderr.writeStreamingAll(io(), "    mkit clone --sparse src/ docs/ <url>\n");
        return;
    }

    // Parse --depth N, --sparse <patterns...>, and URL.
    // Convention: `mkit clone [--depth N] [--sparse pat1 pat2 ...] <url>`
    // The last non-flag arg is always the URL.
    var depth: ?u32 = null;
    var has_sparse = false;
    var positional: std.ArrayList([]const u8) = .empty;
    defer positional.deinit(allocator);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--depth") and i + 1 < args.len) {
            depth = std.fmt.parseInt(u32, args[i + 1], 10) catch null;
            i += 1;
        } else if (std.mem.eql(u8, args[i], "--sparse")) {
            has_sparse = true;
        } else if (!std.mem.startsWith(u8, args[i], "--")) {
            try positional.append(allocator, args[i]);
        }
    }

    // Last positional is URL; if --sparse, earlier positionals are patterns
    var url_arg: ?[]const u8 = null;
    var sparse_patterns: std.ArrayList([]const u8) = .empty;
    defer sparse_patterns.deinit(allocator);
    if (positional.items.len > 0) {
        url_arg = positional.items[positional.items.len - 1];
        if (has_sparse) {
            for (positional.items[0 .. positional.items.len - 1]) |p| {
                try sparse_patterns.append(allocator, p);
            }
        }
    }

    const url = url_arg orelse {
        try stderr.writeStreamingAll(io(), "error: missing URL argument\n");
        return;
    };

    const clone_params_base = struct {
        fn build(remote_endpoint: []const u8, remote_bucket: []const u8, remote_type: []const u8, d: ?u32, sp: []const []const u8) CloneParams {
            return .{
                .remote_endpoint = remote_endpoint,
                .remote_bucket = remote_bucket,
                .remote_type = remote_type,
                .depth = d,
                .sparse_patterns = if (sp.len > 0) sp else null,
            };
        }
    };

    // Parse the URL using protocol.parseUrl for scheme-aware dispatch
    const parsed = mkit.protocol.parseUrl(url) catch {
        // Fall back to legacy endpoint/bucket split
        const legacy = parseRemoteUrl(url) orelse {
            try stderr.writeStreamingAll(io(), "error: invalid remote URL\n");
            return;
        };
        // Build config from legacy parsing and proceed
        return cloneWithConfig(allocator, stdout, stderr, clone_params_base.build(
            legacy.endpoint,
            legacy.bucket,
            "",
            depth,
            sparse_patterns.items,
        ));
    };

    switch (parsed) {
        .file => |f| {
            return cloneWithConfig(allocator, stdout, stderr, clone_params_base.build(
                f.path,
                "",
                "file",
                depth,
                sparse_patterns.items,
            ));
        },
        .s3 => |s| {
            return cloneWithConfig(allocator, stdout, stderr, clone_params_base.build(
                s.endpoint,
                s.bucket,
                "s3",
                depth,
                sparse_patterns.items,
            ));
        },
        .http => |h| {
            return cloneWithConfig(allocator, stdout, stderr, clone_params_base.build(
                h.base_url,
                "",
                "http",
                depth,
                sparse_patterns.items,
            ));
        },
        .ssh => {
            // For SSH, store the full URL as the endpoint
            return cloneWithConfig(allocator, stdout, stderr, clone_params_base.build(
                url,
                "",
                "ssh",
                depth,
                sparse_patterns.items,
            ));
        },
    }
}

const CloneParams = struct {
    remote_endpoint: []const u8,
    remote_bucket: []const u8,
    remote_type: []const u8,
    depth: ?u32 = null,
    sparse_patterns: ?[]const []const u8 = null,
};

fn cloneWithConfig(
    allocator: std.mem.Allocator,
    stdout: std.Io.File,
    stderr: std.Io.File,
    params: CloneParams,
) !void {
    // Init local repo
    const cwd = std.Io.Dir.cwd();
    ensureDirectoryEmpty(cwd) catch {
        try stderr.writeStreamingAll(io(), "error: clone target directory must be empty\n");
        return;
    };
    var store = mkit.store.ObjectStore.init(io(), cwd) catch |err| switch (err) {
        error.AlreadyInitialized => {
            try stderr.writeStreamingAll(io(), "error: already a mkit repository\n");
            return;
        },
        else => return err,
    };
    // Keep store open for unpacking
    defer store.close();

    try mkit.refs.init(io(), cwd);

    // Save remote config
    var config = mkit.config.Config{};
    config.allocator = allocator;
    config.remote_endpoint = try allocator.dupe(u8, params.remote_endpoint);
    config.remote_bucket = try allocator.dupe(u8, params.remote_bucket);
    config.remote_type = if (params.remote_type.len > 0)
        try allocator.dupe(u8, params.remote_type)
    else
        mkit.config.default_remote_type;
    defer config.deinit();

    try mkit.config.writeConfig(io(), cwd, config);

    try stdout.writeStreamingAll(io(), "initialized mkit repository\n");
    try stdout.writeStreamingAll(io(), "remote: ");
    try stdout.writeStreamingAll(io(), params.remote_endpoint);
    if (params.remote_bucket.len > 0) {
        try stdout.writeStreamingAll(io(), "/");
        try stdout.writeStreamingAll(io(), params.remote_bucket);
    }
    try stdout.writeStreamingAll(io(), "\n");

    // Open transport and pull refs
    var transport_handle = openTransport(allocator, config) catch |err| {
        try stderr.writeStreamingAll(io(), "warning: could not connect to remote: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        try stdout.writeStreamingAll(io(), "(run 'mkit pull' to fetch remote content)\n");
        return;
    };
    defer transport_handle.deinit();
    const t = transport_handle.transport;

    // List remote refs
    const remote_refs = t.listRefs(allocator, "refs/heads/") catch |err| {
        try stderr.writeStreamingAll(io(), "warning: could not list remote refs: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        try stdout.writeStreamingAll(io(), "(run 'mkit pull' to fetch remote content)\n");
        return;
    };
    defer {
        for (remote_refs) |ref| allocator.free(ref.name);
        allocator.free(remote_refs);
    }

    if (remote_refs.len == 0) {
        try stdout.writeStreamingAll(io(), "(empty repository — no branches found)\n");
        return;
    }

    // For each ref, read the .pack companion and download the pack
    for (remote_refs) |ref| {
        if (!mkit.protocol.validateRefName(ref.name)) continue;
        // Build the full ref name for companion lookup
        var full_ref_buf: [256]u8 = undefined;
        const full_ref_name = std.fmt.bufPrint(&full_ref_buf, "refs/heads/{s}", .{ref.name}) catch continue;
        const pack_digest = readPackDigestForRef(t, allocator, full_ref_name, ref.hash) catch continue orelse continue;
        const pack_bytes = t.downloadPack(allocator, pack_digest) catch continue;
        defer allocator.free(pack_bytes);
        verifyPackDigest(pack_digest, pack_bytes) catch continue;

        mkit.packfile.unpackInto(allocator, pack_bytes, &store) catch continue;
        ensureCommitExists(allocator, &store, ref.hash) catch continue;

        // Set local ref
        mkit.refs.writeRef(io(), cwd, ref.name, ref.hash) catch continue;

        try stdout.writeStreamingAll(io(), "  fetched ");
        try stdout.writeStreamingAll(io(), ref.name);
        try stdout.writeStreamingAll(io(), "\n");
    }

    // Determine default branch: "main" if it exists, otherwise first ref
    var default_branch: ?[]const u8 = null;
    for (remote_refs) |ref| {
        if (std.mem.eql(u8, ref.name, "main")) {
            default_branch = "main";
            break;
        }
    }
    if (default_branch == null and remote_refs.len > 0) {
        default_branch = remote_refs[0].name;
    }

    // Write sparse checkout patterns if specified
    if (params.sparse_patterns) |patterns| {
        mkit.restore.writeSparseCheckout(io(), cwd, patterns) catch |err| {
            try stderr.writeStreamingAll(io(), "warning: failed to write sparse checkout: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
        };
    }

    // Checkout default branch
    if (default_branch) |db| {
        try mkit.refs.writeHeadBranch(io(), cwd, db);

        // Write shallow boundaries if --depth was specified
        if (params.depth) |d| {
            if (mkit.refs.readRef(allocator, io(), cwd, db) catch null) |tip_hash| {
                const boundaries = mkit.packfile.collectShallowBoundaries(allocator, &store, tip_hash, d) catch null;
                if (boundaries) |b| {
                    defer allocator.free(b);
                    mkit.refs.writeShallowBoundaries(io(), cwd, b) catch {};
                }
            }
        }

        // Load sparse checkout patterns for restore
        const sparse = mkit.restore.loadSparseCheckout(allocator, io(), cwd) catch null;
        defer if (sparse) |s| mkit.restore.freeSparsePatterns(allocator, s);

        // Restore working directory
        if (mkit.refs.readRef(allocator, io(), cwd, db) catch null) |tip_hash| {
            var commit_obj = store.get(allocator, tip_hash) catch {
                return;
            };
            defer commit_obj.deinit(allocator);

            if (commit_obj == .commit) {
                var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch return;
                defer work_dir.close(io());
                mkit.restore.restoreTree(allocator, io(), &store, commit_obj.commit.tree_hash, work_dir, .{
                    .sparse_patterns = sparse,
                }) catch |err| {
                    try stderr.writeStreamingAll(io(), "warning: failed to restore working directory: ");
                    var buf: [256]u8 = undefined;
                    const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
                    try stderr.writeStreamingAll(io(), err_name);
                    try stderr.writeStreamingAll(io(), "\n");
                };
            }
        }

        try stdout.writeStreamingAll(io(), "checked out ");
        try stdout.writeStreamingAll(io(), db);
        try stdout.writeStreamingAll(io(), "\n");
    }
}

fn cmdFetch(allocator: std.mem.Allocator) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();
    const cwd = std.Io.Dir.cwd();

    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    var config = try mkit.config.readConfig(allocator, io(), cwd);
    defer config.deinit();

    if (config.remote_endpoint.len == 0) {
        try stderr.writeStreamingAll(io(), "error: no remote configured (use 'mkit remote add <url>')\n");
        return;
    }

    var transport_handle = openTransport(allocator, config) catch {
        try stderr.writeStreamingAll(io(), "error: could not open transport\n");
        return;
    };
    defer transport_handle.deinit();
    const t = transport_handle.transport;

    const head = mkit.refs.readHead(allocator, io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: cannot read HEAD\n");
        return;
    };
    const branch_name: []const u8 = switch (head) {
        .branch => |b| b,
        .detached => {
            try stderr.writeStreamingAll(io(), "error: cannot fetch in detached HEAD state\n");
            return;
        },
    };
    defer allocator.free(branch_name);

    var ref_name_buf: [256]u8 = undefined;
    const ref_name = std.fmt.bufPrint(&ref_name_buf, "refs/heads/{s}", .{branch_name}) catch {
        try stderr.writeStreamingAll(io(), "error: branch name too long\n");
        return;
    };

    const remote_hash = t.readRef(allocator, ref_name) catch {
        try stderr.writeStreamingAll(io(), "error: could not read remote ref\n");
        return;
    } orelse {
        try stderr.writeStreamingAll(io(), "remote branch '");
        try stderr.writeStreamingAll(io(), branch_name);
        try stderr.writeStreamingAll(io(), "' not found\n");
        return;
    };

    if (store.exists(remote_hash)) {
        try stdout.writeStreamingAll(io(), "already up to date\n");
    } else {
        const pack_digest = readPackDigestForRef(t, allocator, ref_name, remote_hash) catch {
            try stderr.writeStreamingAll(io(), "error: could not read pack companion\n");
            return;
        } orelse {
            try stderr.writeStreamingAll(io(), "error: no pack companion found\n");
            return;
        };

        const pack_bytes = t.downloadPack(allocator, pack_digest) catch {
            try stderr.writeStreamingAll(io(), "error: could not download pack\n");
            return;
        };
        defer allocator.free(pack_bytes);
        verifyPackDigest(pack_digest, pack_bytes) catch {
            try stderr.writeStreamingAll(io(), "error: downloaded pack failed digest verification\n");
            return;
        };

        mkit.packfile.unpackInto(allocator, pack_bytes, &store) catch {
            try stderr.writeStreamingAll(io(), "error: could not unpack\n");
            return;
        };
        ensureCommitExists(allocator, &store, remote_hash) catch {
            try stderr.writeStreamingAll(io(), "error: downloaded pack does not contain the advertised remote commit\n");
            return;
        };

        const remote_hex = mkit.hash.toHex(remote_hash);
        try stdout.writeStreamingAll(io(), "fetched ");
        try stdout.writeStreamingAll(io(), remote_hex[0..8]);
        try stdout.writeStreamingAll(io(), " -> ");
        try stdout.writeStreamingAll(io(), branch_name);
        try stdout.writeStreamingAll(io(), "\n");
    }

    // Write remote-tracking ref
    cwd.createDirPath(io(), ".mkit/refs/remotes") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    cwd.createDirPath(io(), ".mkit/refs/remotes/origin") catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var remote_ref_buf: [256]u8 = undefined;
    const remote_ref_path = std.fmt.bufPrint(&remote_ref_buf, ".mkit/refs/remotes/origin/{s}", .{branch_name}) catch return;
    const hex = mkit.hash.toHex(remote_hash);
    const rf = cwd.createFile(io(), remote_ref_path, .{}) catch return;
    defer rf.close(io());
    rf.writeStreamingAll(io(), &hex) catch {};
    rf.writeStreamingAll(io(), "\n") catch {};
}

fn cmdCherryPick(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit cherry-pick <hash>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Resolve HEAD
    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd) orelse {
        try stderr.writeStreamingAll(io(), "error: no commits on current branch\n");
        return;
    };

    // Get HEAD commit's tree
    var head_obj = store.get(allocator, head_hash) catch {
        try stderr.writeStreamingAll(io(), "error: could not read HEAD commit\n");
        return;
    };
    defer head_obj.deinit(allocator);
    if (head_obj != .commit) {
        try stderr.writeStreamingAll(io(), "error: HEAD does not point to a commit\n");
        return;
    }
    const head_tree = head_obj.commit.tree_hash;

    // Parse target hash
    const hash_str = args[0];
    const target_hash = mkit.hash.fromHex(hash_str) catch {
        try stderr.writeStreamingAll(io(), "error: invalid hash '");
        try stderr.writeStreamingAll(io(), hash_str);
        try stderr.writeStreamingAll(io(), "'\n");
        return;
    };

    // Cherry-pick
    var result = mkit.cherry_pick.cherryPick(allocator, &store, target_hash, head_tree) catch |err| {
        try stderr.writeStreamingAll(io(), "error: cherry-pick failed: ");
        var buf: [256]u8 = undefined;
        const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
        try stderr.writeStreamingAll(io(), err_name);
        try stderr.writeStreamingAll(io(), "\n");
        return;
    };
    defer result.deinit();

    if (result.hasConflicts()) {
        try stderr.writeStreamingAll(io(), "cherry-pick conflict:\n");
        for (result.conflicts) |c| {
            const kind_str: []const u8 = switch (c.kind) {
                .modify_modify => "both modified",
                .delete_modify => "delete/modify",
                .add_add => "both added",
            };
            try stderr.writeStreamingAll(io(), "  ");
            try stderr.writeStreamingAll(io(), c.path);
            try stderr.writeStreamingAll(io(), " (");
            try stderr.writeStreamingAll(io(), kind_str);
            try stderr.writeStreamingAll(io(), ")\n");
        }
        return;
    }

    // Clean merge: create signed commit
    var config = try readRepoConfig(allocator, cwd);
    defer config.deinit();

    const kp = loadSigningKey(allocator, cwd, config.signing_key) catch |err| switch (err) {
        error.FileNotFound => {
            try stderr.writeStreamingAll(io(), "error: no signing key found (run 'mkit keygen' first)\n");
            return;
        },
        error.InvalidKeyFile => {
            try stderr.writeStreamingAll(io(), "error: invalid key file (expected 32-byte seed)\n");
            return;
        },
        else => {
            try stderr.writeStreamingAll(io(), "error: invalid key seed\n");
            return;
        },
    };

    const timestamp: u64 = @intCast(@max(std.Io.Clock.real.now(io()).toSeconds(), 0));

    var id_scratch: [1024]u8 = undefined;
    const author_id = resolveAuthorIdentity(config.user_identity, id_scratch[0..], kp.public_key[0..]) catch {
        try stderr.writeStreamingAll(io(), "error: invalid user.identity in config (run 'mkit config user.identity <value>')\n");
        return;
    };

    var parents_buf: [1]mkit.hash.Hash = .{head_hash};
    var commit = mkit.object.Commit{
        .tree_hash = result.tree_hash,
        .parents = &parents_buf,
        .author = author_id,
        .signer = kp.public_key,
        .message = result.original_message,
        .timestamp = timestamp,
        .message_hash = mkit.hash.hash(result.original_message),
        .content_digest = mkit.hash.zero,
        .signature = .{0} ** 64,
    };

    commit.signature = mkit.sign.signCommit(allocator, commit, kp) catch {
        try stderr.writeStreamingAll(io(), "error: signing failed\n");
        return;
    };

    const commit_obj = mkit.object.Object{ .commit = commit };
    const commit_hash = try store.put(allocator, commit_obj);

    // Restore working directory
    {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: could not open working directory for restore\n");
            return;
        };
        defer work_dir.close(io());
        mkit.restore.restoreTree(allocator, io(), &store, result.tree_hash, work_dir, .{}) catch |err| {
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), "error: could not restore working tree: ");
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
    }

    // Update HEAD
    try mkit.refs.updateHead(allocator, io(), cwd, commit_hash);

    const hex = mkit.hash.toHex(commit_hash);
    try stdout.writeStreamingAll(io(), "[cherry-pick] ");
    try stdout.writeStreamingAll(io(), &hex);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdRebase(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit rebase <branch>\n");
        try stderr.writeStreamingAll(io(), "       mkit rebase --continue\n");
        try stderr.writeStreamingAll(io(), "       mkit rebase --abort\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    // Serialize against other commit/checkout/merge/rebase. See src/lock.zig.
    var mkit_dir = cwd.openDir(io(), ".mkit", .{}) catch {
        try stderr.writeStreamingAll(io(), "error: cannot open .mkit directory\n");
        return;
    };
    defer mkit_dir.close(io());
    var repo_lock = mkit.lock.acquireDefault(io(), mkit_dir, "index.lock") catch |err| switch (err) {
        error.LockBusy => {
            try stderr.writeStreamingAll(io(), "error: another mkit process is running in this repository (.mkit/index.lock held)\n");
            return;
        },
        else => return err,
    };
    defer repo_lock.release();

    if (std.mem.eql(u8, args[0], "--abort")) {
        // Abort: restore original HEAD and clean up
        var state = mkit.rebase.readState(allocator, io(), cwd) catch |err| {
            if (err == error.NoRebaseInProgress) {
                try stderr.writeStreamingAll(io(), "error: no rebase in progress\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: could not read rebase state\n");
            return;
        };
        defer state.deinit();

        // Restore original HEAD (update branch ref and HEAD)
        mkit.refs.writeRef(io(), cwd, state.head_name, state.orig_head) catch {};
        mkit.refs.writeHeadBranch(io(), cwd, state.head_name) catch {};

        // Restore working tree
        var orig_obj = store.get(allocator, state.orig_head) catch {
            try stderr.writeStreamingAll(io(), "warning: could not read original commit\n");
            try mkit.rebase.cleanupRebase(io(), cwd);
            try stdout.writeStreamingAll(io(), "rebase aborted\n");
            return;
        };
        defer orig_obj.deinit(allocator);

        if (orig_obj == .commit) {
            var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
                try stderr.writeStreamingAll(io(), "warning: could not open working directory for restore\n");
                try mkit.rebase.cleanupRebase(io(), cwd);
                try stdout.writeStreamingAll(io(), "rebase aborted\n");
                return;
            };
            defer work_dir.close(io());
            mkit.restore.restoreTree(allocator, io(), &store, orig_obj.commit.tree_hash, work_dir, .{}) catch {};
        }

        try mkit.rebase.cleanupRebase(io(), cwd);
        try stdout.writeStreamingAll(io(), "rebase aborted\n");
        return;
    }

    if (std.mem.eql(u8, args[0], "--continue")) {
        // Continue: read state, build tree from working dir, create commit, advance
        var state = mkit.rebase.readState(allocator, io(), cwd) catch |err| {
            if (err == error.NoRebaseInProgress) {
                try stderr.writeStreamingAll(io(), "error: no rebase in progress\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: could not read rebase state\n");
            return;
        };
        defer state.deinit();

        if (state.todo.len == 0) {
            // All done
            mkit.refs.writeRef(io(), cwd, state.head_name, state.onto) catch {};
            mkit.refs.writeHeadBranch(io(), cwd, state.head_name) catch {};
            try mkit.rebase.cleanupRebase(io(), cwd);
            try stdout.writeStreamingAll(io(), "rebase complete\n");
            return;
        }

        var config = try readRepoConfig(allocator, cwd);
        defer config.deinit();

        const kp = loadSigningKey(allocator, cwd, config.signing_key) catch |err| switch (err) {
            error.FileNotFound => {
                try stderr.writeStreamingAll(io(), "error: no signing key found (run 'mkit keygen' first)\n");
                return;
            },
            error.InvalidKeyFile => {
                try stderr.writeStreamingAll(io(), "error: invalid key file (expected 32-byte seed)\n");
                return;
            },
            else => {
                try stderr.writeStreamingAll(io(), "error: invalid key seed\n");
                return;
            },
        };

        // Build tree from current working directory
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try stderr.writeStreamingAll(io(), "error: cannot open working directory\n");
            return;
        };
        defer work_dir.close(io());
        const tree_hash = try mkit.worktree.buildTree(allocator, io(), &store, work_dir);

        // Get the current HEAD (what we're building on)
        const current_head = try mkit.refs.resolveHead(allocator, io(), cwd) orelse state.onto;

        // Load original commit message
        const current_todo = state.todo[0];
        var orig_commit_obj = store.get(allocator, current_todo) catch {
            try stderr.writeStreamingAll(io(), "error: could not read original commit\n");
            return;
        };
        defer orig_commit_obj.deinit(allocator);
        const commit_message = if (orig_commit_obj == .commit)
            orig_commit_obj.commit.message
        else
            "rebase continue";

        const timestamp: u64 = @intCast(@max(std.Io.Clock.real.now(io()).toSeconds(), 0));

        var id_scratch: [1024]u8 = undefined;
        const author_id = resolveAuthorIdentity(config.user_identity, id_scratch[0..], kp.public_key[0..]) catch {
            try stderr.writeStreamingAll(io(), "error: invalid user.identity in config (run 'mkit config user.identity <value>')\n");
            return;
        };

        var parents_buf: [1]mkit.hash.Hash = .{current_head};
        var commit = mkit.object.Commit{
            .tree_hash = tree_hash,
            .parents = &parents_buf,
            .author = author_id,
            .signer = kp.public_key,
            .message = commit_message,
            .timestamp = timestamp,
            .message_hash = mkit.hash.hash(commit_message),
            .content_digest = mkit.hash.zero,
            .signature = .{0} ** 64,
        };

        commit.signature = mkit.sign.signCommit(allocator, commit, kp) catch {
            try stderr.writeStreamingAll(io(), "error: signing failed\n");
            return;
        };

        const commit_obj = mkit.object.Object{ .commit = commit };
        const commit_hash = try store.put(allocator, commit_obj);
        try mkit.refs.updateHead(allocator, io(), cwd, commit_hash);

        // Advance state: move current from todo to done
        const new_done = try allocator.alloc(mkit.hash.Hash, state.done.len + 1);
        @memcpy(new_done[0..state.done.len], state.done);
        new_done[state.done.len] = current_todo;
        allocator.free(state.done);
        state.done = new_done;

        const new_todo = try allocator.alloc(mkit.hash.Hash, state.todo.len - 1);
        if (state.todo.len > 1) {
            @memcpy(new_todo, state.todo[1..]);
        }
        allocator.free(state.todo);
        state.todo = new_todo;

        // Continue replaying remaining commits
        try rebaseReplay(allocator, &store, cwd, &state, config, kp, stdout, stderr);
        return;
    }

    // Start a new rebase: mkit rebase <branch>
    const branch_name = args[0];

    // Resolve HEAD
    const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd) orelse {
        try stderr.writeStreamingAll(io(), "error: no commits on current branch\n");
        return;
    };

    // Resolve target branch
    const onto_hash = (try mkit.refs.readRef(allocator, io(), cwd, branch_name)) orelse {
        try stderr.writeStreamingAll(io(), "error: branch '");
        try stderr.writeStreamingAll(io(), branch_name);
        try stderr.writeStreamingAll(io(), "' not found\n");
        return;
    };

    if (std.mem.eql(u8, &head_hash, &onto_hash)) {
        try stdout.writeStreamingAll(io(), "already up to date\n");
        return;
    }

    // Get current branch name
    const head = mkit.refs.readHead(allocator, io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: cannot read HEAD\n");
        return;
    };
    const current_branch: []const u8 = switch (head) {
        .branch => |b| b,
        .detached => {
            try stderr.writeStreamingAll(io(), "error: cannot rebase in detached HEAD state\n");
            return;
        },
    };
    defer allocator.free(current_branch);

    // Collect commits to replay
    const commits = mkit.rebase.collectCommitsToReplay(allocator, &store, head_hash, onto_hash) catch {
        try stderr.writeStreamingAll(io(), "error: could not collect commits to replay\n");
        return;
    };
    defer allocator.free(commits);

    if (commits.len == 0) {
        try stdout.writeStreamingAll(io(), "nothing to rebase\n");
        return;
    }

    // Write rebase state
    var state = mkit.rebase.RebaseState{
        .head_name = try allocator.dupe(u8, current_branch),
        .orig_head = head_hash,
        .onto = onto_hash,
        .todo = try allocator.dupe(mkit.hash.Hash, commits),
        .done = try allocator.alloc(mkit.hash.Hash, 0),
        .allocator = allocator,
    };
    defer state.deinit();

    try mkit.rebase.writeState(io(), cwd, state);

    // Point HEAD to onto
    try mkit.refs.updateHead(allocator, io(), cwd, onto_hash);

    var config = try readRepoConfig(allocator, cwd);
    defer config.deinit();

    const kp = loadSigningKey(allocator, cwd, config.signing_key) catch |err| switch (err) {
        error.FileNotFound => {
            try stderr.writeStreamingAll(io(), "error: no signing key found (run 'mkit keygen' first)\n");
            return;
        },
        error.InvalidKeyFile => {
            try stderr.writeStreamingAll(io(), "error: invalid key file (expected 32-byte seed)\n");
            return;
        },
        else => {
            try stderr.writeStreamingAll(io(), "error: invalid key seed\n");
            return;
        },
    };

    // Begin replaying
    try rebaseReplay(allocator, &store, cwd, &state, config, kp, stdout, stderr);
}

fn rebaseReplay(
    allocator: std.mem.Allocator,
    store: *mkit.store.ObjectStore,
    cwd: std.Io.Dir,
    state: *mkit.rebase.RebaseState,
    config: mkit.config.Config,
    kp: mkit.sign.KeyPair,
    stdout: std.Io.File,
    stderr: std.Io.File,
) !void {
    while (state.todo.len > 0) {
        const current_commit_hash = state.todo[0];

        // Get current HEAD tree
        const current_head = try mkit.refs.resolveHead(allocator, io(), cwd) orelse state.onto;
        var current_obj = store.get(allocator, current_head) catch {
            try stderr.writeStreamingAll(io(), "error: could not read current HEAD\n");
            return;
        };
        defer current_obj.deinit(allocator);
        if (current_obj != .commit) {
            try stderr.writeStreamingAll(io(), "error: HEAD does not point to a commit\n");
            return;
        }
        const current_tree = current_obj.commit.tree_hash;

        // Cherry-pick this commit
        var cp_result = mkit.cherry_pick.cherryPick(allocator, store, current_commit_hash, current_tree) catch |err| {
            try stderr.writeStreamingAll(io(), "error: cherry-pick failed during rebase: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        defer cp_result.deinit();

        if (cp_result.hasConflicts()) {
            // Save state and stop
            try mkit.rebase.writeState(io(), cwd, state.*);
            try stderr.writeStreamingAll(io(), "conflict while replaying ");
            const hash_hex = mkit.hash.toHex(current_commit_hash);
            try stderr.writeStreamingAll(io(), hash_hex[0..8]);
            try stderr.writeStreamingAll(io(), ":\n");
            for (cp_result.conflicts) |c| {
                const kind_str: []const u8 = switch (c.kind) {
                    .modify_modify => "both modified",
                    .delete_modify => "delete/modify",
                    .add_add => "both added",
                };
                try stderr.writeStreamingAll(io(), "  ");
                try stderr.writeStreamingAll(io(), c.path);
                try stderr.writeStreamingAll(io(), " (");
                try stderr.writeStreamingAll(io(), kind_str);
                try stderr.writeStreamingAll(io(), ")\n");
            }
            try stderr.writeStreamingAll(io(), "\nresolve conflicts and run 'mkit rebase --continue'\n");
            try stderr.writeStreamingAll(io(), "or run 'mkit rebase --abort' to cancel\n");
            return;
        }

        // Create signed commit
        const timestamp: u64 = @intCast(@max(std.Io.Clock.real.now(io()).toSeconds(), 0));

        var id_scratch: [1024]u8 = undefined;
        const author_id = resolveAuthorIdentity(config.user_identity, id_scratch[0..], kp.public_key[0..]) catch {
            try stderr.writeStreamingAll(io(), "error: invalid user.identity in config (run 'mkit config user.identity <value>')\n");
            return;
        };

        var parents_buf: [1]mkit.hash.Hash = .{current_head};
        var commit = mkit.object.Commit{
            .tree_hash = cp_result.tree_hash,
            .parents = &parents_buf,
            .author = author_id,
            .signer = kp.public_key,
            .message = cp_result.original_message,
            .timestamp = timestamp,
            .message_hash = mkit.hash.hash(cp_result.original_message),
            .content_digest = mkit.hash.zero,
            .signature = .{0} ** 64,
        };

        commit.signature = mkit.sign.signCommit(allocator, commit, kp) catch {
            try stderr.writeStreamingAll(io(), "error: signing failed during rebase\n");
            return;
        };

        const commit_obj = mkit.object.Object{ .commit = commit };
        const new_hash = try store.put(allocator, commit_obj);
        try mkit.refs.updateHead(allocator, io(), cwd, new_hash);

        const new_hex = mkit.hash.toHex(new_hash);
        try stdout.writeStreamingAll(io(), "  replayed ");
        try stdout.writeStreamingAll(io(), new_hex[0..8]);
        try stdout.writeStreamingAll(io(), "\n");

        // Advance state
        const new_done = try allocator.alloc(mkit.hash.Hash, state.done.len + 1);
        @memcpy(new_done[0..state.done.len], state.done);
        new_done[state.done.len] = current_commit_hash;
        allocator.free(state.done);
        state.done = new_done;

        const new_todo = try allocator.alloc(mkit.hash.Hash, state.todo.len - 1);
        if (state.todo.len > 1) {
            @memcpy(new_todo, state.todo[1..]);
        }
        allocator.free(state.todo);
        state.todo = new_todo;
    }

    // All done: update branch ref, restore tree, clean up
    const final_head = try mkit.refs.resolveHead(allocator, io(), cwd) orelse state.onto;
    mkit.refs.writeRef(io(), cwd, state.head_name, final_head) catch {};
    mkit.refs.writeHeadBranch(io(), cwd, state.head_name) catch {};

    // Restore working tree
    var final_obj = store.get(allocator, final_head) catch {
        try mkit.rebase.cleanupRebase(io(), cwd);
        try stdout.writeStreamingAll(io(), "rebase complete\n");
        return;
    };
    defer final_obj.deinit(allocator);

    if (final_obj == .commit) {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
            try mkit.rebase.cleanupRebase(io(), cwd);
            try stdout.writeStreamingAll(io(), "rebase complete\n");
            return;
        };
        defer work_dir.close(io());
        mkit.restore.restoreTree(allocator, io(), store, final_obj.commit.tree_hash, work_dir, .{}) catch {};
    }

    try mkit.rebase.cleanupRebase(io(), cwd);
    try stdout.writeStreamingAll(io(), "rebase complete\n");
}

fn cmdBisect(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit bisect <start|good|bad|reset>\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    defer store.close();

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "start")) {
        // Check if bisect already in progress
        if (mkit.bisect.isBisectInProgress(io(), cwd)) {
            try stderr.writeStreamingAll(io(), "error: bisect already in progress (use 'mkit bisect reset' first)\n");
            return;
        }

        const head_hash = try mkit.refs.resolveHead(allocator, io(), cwd) orelse {
            try stderr.writeStreamingAll(io(), "error: no commits yet\n");
            return;
        };

        // Get current branch
        const head = mkit.refs.readHead(allocator, io(), cwd) catch {
            try stderr.writeStreamingAll(io(), "error: cannot read HEAD\n");
            return;
        };
        const branch_name: ?[]const u8 = switch (head) {
            .branch => |b| b,
            .detached => null,
        };
        defer if (branch_name) |b| allocator.free(b);

        const state = mkit.bisect.BisectState{
            .orig_head = head_hash,
            .orig_branch = branch_name,
            .bad_hash = null,
            .good_hashes = try allocator.alloc(mkit.hash.Hash, 0),
            .allocator = allocator,
        };
        try mkit.bisect.writeState(io(), cwd, state);
        allocator.free(state.good_hashes);

        try stdout.writeStreamingAll(io(), "bisect started\n");
        try stdout.writeStreamingAll(io(), "use 'mkit bisect bad [hash]' and 'mkit bisect good [hash]' to mark commits\n");
        return;
    }

    if (std.mem.eql(u8, subcmd, "good")) {
        var state = mkit.bisect.readState(allocator, io(), cwd) catch |err| {
            if (err == error.NoBisectInProgress) {
                try stderr.writeStreamingAll(io(), "error: no bisect in progress (run 'mkit bisect start')\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: could not read bisect state\n");
            return;
        };
        defer state.deinit();

        // Parse optional hash arg, default to HEAD
        const good_hash = if (args.len > 1) blk: {
            break :blk mkit.hash.fromHex(args[1]) catch {
                try stderr.writeStreamingAll(io(), "error: invalid hash\n");
                return;
            };
        } else blk: {
            break :blk (try mkit.refs.resolveHead(allocator, io(), cwd)) orelse {
                try stderr.writeStreamingAll(io(), "error: no commits yet\n");
                return;
            };
        };

        // Add to good hashes
        const new_good = try allocator.alloc(mkit.hash.Hash, state.good_hashes.len + 1);
        @memcpy(new_good[0..state.good_hashes.len], state.good_hashes);
        new_good[state.good_hashes.len] = good_hash;
        allocator.free(state.good_hashes);
        state.good_hashes = new_good;

        try mkit.bisect.writeState(io(), cwd, state);

        const good_hex = mkit.hash.toHex(good_hash);
        try stdout.writeStreamingAll(io(), "marked ");
        try stdout.writeStreamingAll(io(), good_hex[0..8]);
        try stdout.writeStreamingAll(io(), " as good\n");

        // If we have both good and bad, compute midpoint
        if (state.bad_hash) |bad| {
            try bisectStep(allocator, &store, cwd, bad, state.good_hashes, stdout, stderr);
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "bad")) {
        var state = mkit.bisect.readState(allocator, io(), cwd) catch |err| {
            if (err == error.NoBisectInProgress) {
                try stderr.writeStreamingAll(io(), "error: no bisect in progress (run 'mkit bisect start')\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: could not read bisect state\n");
            return;
        };
        defer state.deinit();

        // Parse optional hash arg, default to HEAD
        const bad_hash = if (args.len > 1) blk: {
            break :blk mkit.hash.fromHex(args[1]) catch {
                try stderr.writeStreamingAll(io(), "error: invalid hash\n");
                return;
            };
        } else blk: {
            break :blk (try mkit.refs.resolveHead(allocator, io(), cwd)) orelse {
                try stderr.writeStreamingAll(io(), "error: no commits yet\n");
                return;
            };
        };

        state.bad_hash = bad_hash;
        try mkit.bisect.writeState(io(), cwd, state);

        const bad_hex = mkit.hash.toHex(bad_hash);
        try stdout.writeStreamingAll(io(), "marked ");
        try stdout.writeStreamingAll(io(), bad_hex[0..8]);
        try stdout.writeStreamingAll(io(), " as bad\n");

        // If we have both good and bad, compute midpoint
        if (state.good_hashes.len > 0) {
            try bisectStep(allocator, &store, cwd, bad_hash, state.good_hashes, stdout, stderr);
        }
        return;
    }

    if (std.mem.eql(u8, subcmd, "reset")) {
        var state = mkit.bisect.readState(allocator, io(), cwd) catch |err| {
            if (err == error.NoBisectInProgress) {
                try stderr.writeStreamingAll(io(), "error: no bisect in progress\n");
                return;
            }
            try stderr.writeStreamingAll(io(), "error: could not read bisect state\n");
            return;
        };
        defer state.deinit();

        // Restore original HEAD + branch
        if (state.orig_branch) |branch| {
            mkit.refs.writeRef(io(), cwd, branch, state.orig_head) catch {};
            mkit.refs.writeHeadBranch(io(), cwd, branch) catch {};
        } else {
            mkit.refs.updateHead(allocator, io(), cwd, state.orig_head) catch {};
        }

        // Restore working tree
        var orig_obj = store.get(allocator, state.orig_head) catch {
            try mkit.bisect.cleanupBisect(io(), cwd);
            try stdout.writeStreamingAll(io(), "bisect reset\n");
            return;
        };
        defer orig_obj.deinit(allocator);

        if (orig_obj == .commit) {
            var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch {
                try mkit.bisect.cleanupBisect(io(), cwd);
                try stdout.writeStreamingAll(io(), "bisect reset\n");
                return;
            };
            defer work_dir.close(io());
            mkit.restore.restoreTree(allocator, io(), &store, orig_obj.commit.tree_hash, work_dir, .{}) catch {};
        }

        try mkit.bisect.cleanupBisect(io(), cwd);
        try stdout.writeStreamingAll(io(), "bisect reset\n");
        return;
    }

    try stderr.writeStreamingAll(io(), "unknown bisect subcommand '");
    try stderr.writeStreamingAll(io(), subcmd);
    try stderr.writeStreamingAll(io(), "'\n");
    try stderr.writeStreamingAll(io(), "usage: mkit bisect <start|good|bad|reset>\n");
}

fn bisectStep(
    allocator: std.mem.Allocator,
    store: *mkit.store.ObjectStore,
    cwd: std.Io.Dir,
    bad: mkit.hash.Hash,
    good_hashes: []const mkit.hash.Hash,
    stdout: std.Io.File,
    stderr: std.Io.File,
) !void {
    const candidates = mkit.bisect.enumerateRange(allocator, store, bad, good_hashes) catch {
        try stderr.writeStreamingAll(io(), "error: could not enumerate bisect range\n");
        return;
    };
    defer allocator.free(candidates);

    if (candidates.len == 0) {
        try stdout.writeStreamingAll(io(), "bisect: no candidates found\n");
        return;
    }

    if (candidates.len == 1) {
        const found_hex = mkit.hash.toHex(candidates[0]);
        try stdout.writeStreamingAll(io(), "bisect: first bad commit is ");
        try stdout.writeStreamingAll(io(), &found_hex);
        try stdout.writeStreamingAll(io(), "\n");
        return;
    }

    const midpoint = mkit.bisect.pickMidpoint(candidates);
    const mid_hex = mkit.hash.toHex(midpoint);

    // Checkout midpoint (detached HEAD)
    try mkit.refs.updateHead(allocator, io(), cwd, midpoint);

    // Restore working tree
    var mid_obj = store.get(allocator, midpoint) catch {
        try stderr.writeStreamingAll(io(), "warning: could not read midpoint commit\n");
        return;
    };
    defer mid_obj.deinit(allocator);

    if (mid_obj == .commit) {
        var work_dir = cwd.openDir(io(), ".", .{ .iterate = true }) catch return;
        defer work_dir.close(io());
        mkit.restore.restoreTree(allocator, io(), store, mid_obj.commit.tree_hash, work_dir, .{}) catch {};
    }

    var count_buf: [20]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{candidates.len}) catch "?";
    try stdout.writeStreamingAll(io(), "bisecting: ");
    try stdout.writeStreamingAll(io(), count_str);
    try stdout.writeStreamingAll(io(), " commits remaining\n");
    try stdout.writeStreamingAll(io(), "testing ");
    try stdout.writeStreamingAll(io(), mid_hex[0..8]);
    try stdout.writeStreamingAll(io(), "\n");
}

fn cmdServe(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit serve <path>\n");
        return;
    }

    const path = args[0];

    // Open a FileTransport at the given path
    var ft = mkit.transport_file.FileTransport.init(allocator, io(), path) catch {
        try stderr.writeStreamingAll(io(), "error: could not open repository at '");
        try stderr.writeStreamingAll(io(), path);
        try stderr.writeStreamingAll(io(), "'\n");
        return;
    };
    defer ft.deinit();
    const transport = ft.transport();

    const stdin = std.Io.File.stdin();
    const stdout = std.Io.File.stdout();

    // -- OP_HELLO handshake (SPEC-TRANSPORT §7.4) --
    // First frame MUST be OP_HELLO. This pins the protocol version and binary
    // name so a renamed or legacy peer fails loud instead of silently
    // exchanging frames (red-team R-10).
    //
    // TODO(W5.5): apply a read deadline to this initial stdin.readAll to
    // bound the time spent waiting for a slow/misbehaving client. Zig 0.15.2
    // does not expose a portable per-handle read timeout; implementing this
    // requires raw fd poll() work, which is deferred to 0.2.0.
    {
        var hello_header: [5]u8 = undefined;
        const h_read = readExact(stdin, io(), &hello_header) catch return;
        if (h_read != 5) return;
        const hello_op = hello_header[0];
        const hello_len = std.mem.littleToNative(u32, @bitCast(hello_header[1..5].*));

        if (hello_op != mkit.transport_ssh.OP_HELLO) {
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "hello required") catch return;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch {};
            return;
        }
        if (hello_len > mkit.transport_ssh.MAX_PAYLOAD) return;

        const hello_payload = allocator.alloc(u8, hello_len) catch return;
        defer allocator.free(hello_payload);
        if (hello_len > 0) {
            const read = readExact(stdin, io(), hello_payload) catch return;
            if (read != hello_len) return;
        }

        const hello = mkit.transport_ssh.decodeHelloRequest(hello_payload) catch {
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "hello decode error") catch return;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch {};
            return;
        };

        if (!std.mem.eql(u8, hello.binary_name, mkit.transport_ssh.BINARY_NAME)) {
            try stderr.writeStreamingAll(io(), "serve: rejecting peer with binary_name='");
            try stderr.writeStreamingAll(io(), hello.binary_name);
            try stderr.writeStreamingAll(io(), "' (expected 'mkit')\n");
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "binary name mismatch") catch return;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch {};
            return;
        }

        if (hello.proto_version > mkit.transport_ssh.PROTO_VERSION) {
            try stderr.writeStreamingAll(io(), "serve: client advertises future proto_version\n");
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_UNSUPPORTED, "unsupported proto version") catch return;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch {};
            return;
        }

        if (hello.proto_version != mkit.transport_ssh.PROTO_VERSION) {
            // Older-than-v1: v1 is currently the floor. Reject loud.
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_UNSUPPORTED, "unsupported proto version") catch return;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch {};
            return;
        }

        const server_hello = mkit.transport_ssh.encodeHelloResponse(
            allocator,
            mkit.transport_ssh.PROTO_VERSION,
            mkit.transport_ssh.SERVER_VERSION,
        ) catch return;
        defer allocator.free(server_hello);
        const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, server_hello) catch return;
        defer allocator.free(resp);
        stdout.writeStreamingAll(io(), resp) catch return;
    }

    // Wire protocol loop: read request frames, dispatch, write response frames
    while (true) {
        // Read header: [1-byte opcode][4-byte LE length]
        var header: [5]u8 = undefined;
        const header_read = readExact(stdin, io(), &header) catch break;
        if (header_read != 5) break;

        const opcode = header[0];
        const payload_len = std.mem.littleToNative(u32, @bitCast(header[1..5].*));

        if (opcode == mkit.transport_ssh.OP_CLOSE) break;

        if (payload_len > mkit.transport_ssh.MAX_PAYLOAD) {
            const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "payload too large") catch break;
            defer allocator.free(resp);
            stdout.writeStreamingAll(io(), resp) catch break;
            continue;
        }

        // Read payload
        const payload = allocator.alloc(u8, payload_len) catch break;
        defer allocator.free(payload);
        if (payload_len > 0) {
            const payload_read = readExact(stdin, io(), payload) catch break;
            if (payload_read != payload_len) break;
        }

        // Dispatch by opcode
        switch (opcode) {
            mkit.transport_ssh.OP_UPLOAD_PACK => {
                const decoded = mkit.transport_ssh.decodeUploadPack(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                transport.uploadPack(allocator, decoded.data, decoded.digest) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "upload failed") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, "") catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            mkit.transport_ssh.OP_DOWNLOAD_PACK => {
                const digest = mkit.transport_ssh.decodeDownloadPack(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const data = transport.downloadPack(allocator, digest) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_NULL, "") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                defer allocator.free(data);
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, data) catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            mkit.transport_ssh.OP_PACK_EXISTS => {
                const digest = mkit.transport_ssh.decodePackExists(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const exists = transport.packExists(allocator, digest) catch false;
                const exists_byte: [1]u8 = .{if (exists) 1 else 0};
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, &exists_byte) catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            mkit.transport_ssh.OP_WRITE_REF => {
                const decoded = mkit.transport_ssh.decodeWriteRef(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                transport.writeRef(allocator, decoded.name, decoded.hash) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "write ref failed") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, "") catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            mkit.transport_ssh.OP_UPDATE_REF => {
                const decoded = mkit.transport_ssh.decodeUpdateRef(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                transport.updateRef(allocator, decoded.name, decoded.condition, decoded.hash) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "update ref failed") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, "") catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            mkit.transport_ssh.OP_READ_REF => {
                const ref_name = mkit.transport_ssh.decodeReadRef(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const maybe_hash = transport.readRef(allocator, ref_name) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "read ref failed") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                if (maybe_hash) |h| {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, &h) catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                } else {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_NULL, "") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                }
            },
            mkit.transport_ssh.OP_LIST_REFS => {
                const prefix = mkit.transport_ssh.decodeListRefs(payload) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "decode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                const refs = transport.listRefs(allocator, prefix) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "list refs failed") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                defer {
                    for (refs) |ref| allocator.free(ref.name);
                    allocator.free(refs);
                }
                const encoded = mkit.transport_ssh.encodeRefList(allocator, refs) catch {
                    const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "encode error") catch break;
                    defer allocator.free(resp);
                    stdout.writeStreamingAll(io(), resp) catch break;
                    continue;
                };
                defer allocator.free(encoded);
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_OK, encoded) catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
            else => {
                const resp = mkit.transport_ssh.encodeResponse(allocator, mkit.transport_ssh.STATUS_ERROR, "unknown opcode") catch break;
                defer allocator.free(resp);
                stdout.writeStreamingAll(io(), resp) catch break;
            },
        }
    }
}

fn cmdSparseCheckout(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const stdout = std.Io.File.stdout();
    const stderr = std.Io.File.stderr();

    if (args.len < 1) {
        try stderr.writeStreamingAll(io(), "usage: mkit sparse-checkout <set|list|disable>\n");
        try stderr.writeStreamingAll(io(), "       mkit sparse-checkout set <pattern>...\n");
        try stderr.writeStreamingAll(io(), "       mkit sparse-checkout list\n");
        try stderr.writeStreamingAll(io(), "       mkit sparse-checkout disable\n");
        return;
    }

    const cwd = std.Io.Dir.cwd();

    // Verify we're in a mkit repo
    var store = mkit.store.ObjectStore.open(io(), cwd) catch {
        try stderr.writeStreamingAll(io(), "error: not a mkit repository (run 'mkit init' first)\n");
        return;
    };
    store.close();

    const subcmd = args[0];

    if (std.mem.eql(u8, subcmd, "set")) {
        if (args.len < 2) {
            try stderr.writeStreamingAll(io(), "usage: mkit sparse-checkout set <pattern>...\n");
            return;
        }
        mkit.restore.writeSparseCheckout(io(), cwd, args[1..]) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to write sparse checkout: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        try stdout.writeStreamingAll(io(), "sparse checkout patterns updated\n");
    } else if (std.mem.eql(u8, subcmd, "list")) {
        const patterns = mkit.restore.loadSparseCheckout(allocator, io(), cwd) catch |err| {
            try stderr.writeStreamingAll(io(), "error: failed to load sparse checkout: ");
            var buf: [256]u8 = undefined;
            const err_name = std.fmt.bufPrint(&buf, "{s}", .{@errorName(err)}) catch "unknown";
            try stderr.writeStreamingAll(io(), err_name);
            try stderr.writeStreamingAll(io(), "\n");
            return;
        };
        if (patterns) |pats| {
            defer mkit.restore.freeSparsePatterns(allocator, pats);
            for (pats) |pat| {
                if (pat.negated) try stdout.writeStreamingAll(io(), "!");
                try stdout.writeStreamingAll(io(), pat.pattern);
                if (pat.dir_only) try stdout.writeStreamingAll(io(), "/");
                try stdout.writeStreamingAll(io(), "\n");
            }
        } else {
            try stdout.writeStreamingAll(io(), "no sparse checkout configured\n");
        }
    } else if (std.mem.eql(u8, subcmd, "disable")) {
        cwd.deleteFile(io(), ".mkit/sparse-checkout") catch |err| switch (err) {
            error.FileNotFound => {
                try stdout.writeStreamingAll(io(), "sparse checkout not configured\n");
                return;
            },
            else => {
                try stderr.writeStreamingAll(io(), "error: failed to remove sparse checkout file\n");
                return;
            },
        };
        try stdout.writeStreamingAll(io(), "sparse checkout disabled\n");
    } else {
        try stderr.writeStreamingAll(io(), "unknown sparse-checkout subcommand '");
        try stderr.writeStreamingAll(io(), subcmd);
        try stderr.writeStreamingAll(io(), "'\n");
        try stderr.writeStreamingAll(io(), "usage: mkit sparse-checkout <set|list|disable>\n");
    }
}
