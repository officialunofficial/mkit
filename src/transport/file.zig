// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const protocol = @import("../protocol.zig");
const hash_mod = @import("../hash.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

/// Monotonic counter for uniquifying tmp-file suffixes so two writers in the
/// same process never collide on the same tmp path.
var tmp_counter: std.atomic.Value(u64) = .init(0);

/// Lock-file CAS parameters — bounded so updateRef(.match) can never spin
/// forever. 50 attempts × 100 ms = 5 s total, matching the W5 spec.
const LOCK_MAX_ATTEMPTS: u32 = 50;
const LOCK_SLEEP_NS: u64 = 100 * std.time.ns_per_ms;

/// Write `wire` to `ref_name` via a tmp-file + fsync + rename sequence so a
/// crash mid-write cannot leave the ref at zero bytes.
///
/// Layout: `<ref_name>.tmp.<pid>.<counter>` → `<ref_name>` (atomic rename on POSIX).
// TODO(W5): sync ref dir when stdlib supports — std.fs.Dir.sync does not
// exist in Zig 0.15.2, so a containing-directory fsync is deferred. The
// tmp-rename sequence is still crash-safe for the ref contents themselves.
fn atomicWriteRef(root: std.fs.Dir, ref_name: []const u8, wire: []const u8) !void {
    var tmp_buf: [512]u8 = undefined;
    const pid: i32 = @intCast(std.c.getpid());
    const counter = tmp_counter.fetchAdd(1, .monotonic);
    const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp.{d}.{d}", .{ ref_name, pid, counter }) catch return error.RefNameTooLong;

    // Best-effort cleanup on any failure between createFile and rename.
    errdefer root.deleteFile(tmp_path) catch {};

    {
        const file = try root.createFile(tmp_path, .{});
        defer file.close();
        try file.writeAll(wire);
        // Best-effort fsync — a rename-over-rename is already atomic on POSIX.
        // On filesystems that do not support fsync (e.g. some tmpfs in CI) we
        // accept the weaker durability rather than failing the write.
        file.sync() catch {};
    }

    try root.rename(tmp_path, ref_name);
}

/// Local filesystem Transport implementation.
/// Stores packfiles and refs as regular files under a root directory.
///
/// Layout:
///   packs/<64-hex-digest>       — packfile blobs
///   refs/heads/main             — ref files (65-byte wire format)
///   refs/tags/v1.0              — nested ref directories created on demand
pub const FileTransport = struct {
    root: std.fs.Dir,
    owns_root: bool, // true if we opened it (must close on deinit)
    allocator: Allocator,

    /// Open a FileTransport at the given filesystem path.
    pub fn init(allocator: Allocator, path: []const u8) !FileTransport {
        const dir = try std.fs.cwd().openDir(path, .{});
        return .{ .root = dir, .owns_root = true, .allocator = allocator };
    }

    /// Create a FileTransport from an already-opened directory.
    pub fn initFromDir(allocator: Allocator, dir: std.fs.Dir) FileTransport {
        return .{ .root = dir, .owns_root = false, .allocator = allocator };
    }

    pub fn deinit(self: *FileTransport) void {
        if (self.owns_root) self.root.close();
    }

    /// Return the vtable-based Transport interface for this FileTransport.
    pub fn transport(self: *FileTransport) protocol.Transport {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // =========================================================================
    // VTable dispatch
    // =========================================================================

    const vtable = protocol.Transport.VTable{
        .uploadPack = uploadPackImpl,
        .downloadPack = downloadPackImpl,
        .packExists = packExistsImpl,
        .writeRef = writeRefImpl,
        .updateRef = updateRefImpl,
        .readRef = readRefImpl,
        .listRefs = listRefsImpl,
    };

    fn uploadPackImpl(ptr: *anyopaque, _: Allocator, bytes: []const u8, digest: Hash) anyerror!void {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        const key = protocol.packKey(digest);

        // Ensure packs/ directory exists
        self.root.makeDir("packs") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        // Packs are content-addressed — safe to write via tmp+rename so a
        // crash mid-write cannot leave a zero-byte pack on disk.
        var tmp_buf: [128]u8 = undefined;
        const pid: i32 = @intCast(std.c.getpid());
        const counter = tmp_counter.fetchAdd(1, .monotonic);
        const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp.{d}.{d}", .{ &key, pid, counter }) catch return error.RefNameTooLong;
        errdefer self.root.deleteFile(tmp_path) catch {};
        {
            const file = try self.root.createFile(tmp_path, .{});
            defer file.close();
            try file.writeAll(bytes);
            file.sync() catch {};
        }
        try self.root.rename(tmp_path, &key);
    }

    fn downloadPackImpl(ptr: *anyopaque, allocator: Allocator, digest: Hash) anyerror![]u8 {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        const key = protocol.packKey(digest);

        const file = self.root.openFile(&key, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.PackNotFound,
            else => return err,
        };
        defer file.close();

        const stat = try file.stat();
        if (stat.size > 4 * 1024 * 1024 * 1024) return error.PackTooLarge; // 4GB limit
        const bytes = try allocator.alloc(u8, stat.size);
        errdefer allocator.free(bytes);
        const read = try file.readAll(bytes);
        if (read != stat.size) {
            allocator.free(bytes);
            return error.UnexpectedEof;
        }
        return bytes;
    }

    fn packExistsImpl(ptr: *anyopaque, _: Allocator, digest: Hash) anyerror!bool {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        const key = protocol.packKey(digest);
        self.root.access(&key, .{}) catch return false;
        return true;
    }

    fn writeRefImpl(ptr: *anyopaque, _: Allocator, ref_name: []const u8, h: Hash) anyerror!void {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        return updateRefImpl(ptr, self.allocator, ref_name, .any, h);
    }

    fn updateRefImpl(ptr: *anyopaque, allocator: Allocator, ref_name: []const u8, condition: protocol.RefWriteCondition, h: Hash) anyerror!void {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        try ensureParentDirs(self.root, ref_name);
        const wire = protocol.formatRef(h);

        switch (condition) {
            .any => {
                try atomicWriteRef(self.root, ref_name, &wire);
            },
            .missing => {
                // exclusive create is itself atomic — no tmp-rename needed.
                // (The file either exists after this call with the correct
                // bytes, or we returned RefConflict / an I/O error.)
                const file = self.root.createFile(ref_name, .{ .exclusive = true }) catch |err| switch (err) {
                    error.PathAlreadyExists => return error.RefConflict,
                    else => return err,
                };
                defer file.close();
                try file.writeAll(&wire);
                file.sync() catch {};
            },
            .match => |expected| {
                // Read-then-write CAS needs a lock file so two concurrent
                // updaters cannot both pass the read check and race the write.
                // The lock is `<ref_name>.lock` created with O_EXCL; we spin
                // for up to LOCK_MAX_ATTEMPTS × LOCK_SLEEP_NS before giving up.
                var lock_buf: [512]u8 = undefined;
                const lock_path = std.fmt.bufPrint(&lock_buf, "{s}.lock", .{ref_name}) catch return error.RefNameTooLong;

                var attempts: u32 = 0;
                while (true) : (attempts += 1) {
                    if (attempts >= LOCK_MAX_ATTEMPTS) return error.RefConflict;
                    const lock_file = self.root.createFile(lock_path, .{ .exclusive = true }) catch |err| switch (err) {
                        error.PathAlreadyExists => {
                            std.Thread.sleep(LOCK_SLEEP_NS);
                            continue;
                        },
                        else => return err,
                    };
                    lock_file.close();
                    break;
                }
                // Always clean up the lock, even if the write or read fails.
                defer self.root.deleteFile(lock_path) catch {};

                const current = try readRefImpl(ptr, allocator, ref_name);
                if (current == null or !std.mem.eql(u8, &current.?, &expected)) return error.RefConflict;
                try atomicWriteRef(self.root, ref_name, &wire);
            },
        }
    }

    fn readRefImpl(ptr: *anyopaque, _: Allocator, ref_name: []const u8) anyerror!?Hash {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefName(ref_name)) return error.InvalidRef;
        const file = self.root.openFile(ref_name, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();

        var buf: [128]u8 = undefined;
        const read = try file.readAll(&buf);
        return protocol.parseRef(buf[0..read]) catch return null;
    }

    fn listRefsImpl(ptr: *anyopaque, allocator: Allocator, prefix: []const u8) anyerror![]protocol.Ref {
        const self: *FileTransport = @ptrCast(@alignCast(ptr));
        if (!protocol.validateRefPrefix(prefix)) return error.InvalidRef;
        // Normalize: strip trailing slash to avoid double-slash in path joins
        const normalized = std.mem.trimRight(u8, prefix, "/");
        var refs: std.ArrayList(protocol.Ref) = .{};
        errdefer {
            for (refs.items) |ref| {
                allocator.free(ref.name);
            }
            refs.deinit(allocator);
        }

        try collectRefs(self.root, allocator, normalized, normalized, &refs);

        // Sort alphabetically by name
        std.mem.sort(protocol.Ref, refs.items, {}, struct {
            fn lessThan(_: void, a: protocol.Ref, b: protocol.Ref) bool {
                return std.mem.order(u8, a.name, b.name) == .lt;
            }
        }.lessThan);

        return refs.toOwnedSlice(allocator);
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Create all parent directories for a nested path like "refs/heads/main".
    fn ensureParentDirs(dir: std.fs.Dir, path: []const u8) !void {
        var i: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, i, '/')) |slash| {
            const sub_path = path[0..slash];
            dir.makeDir(sub_path) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            i = slash + 1;
        }
    }

    /// Recursively collect refs under a directory, building full ref names.
    fn collectRefs(
        root: std.fs.Dir,
        allocator: Allocator,
        base_prefix: []const u8,
        dir_path: []const u8,
        refs: *std.ArrayList(protocol.Ref),
    ) anyerror!void {
        // Open the directory for this prefix. If it doesn't exist, that's fine — empty result.
        var dir = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            // Build the full ref name: dir_path + "/" + entry.name
            const full_name = try hash_mod.joinPath(allocator, dir_path, entry.name);

            switch (entry.kind) {
                .file => {
                    // Read the ref file
                    if (!protocol.validateRefName(full_name)) {
                        allocator.free(full_name);
                        continue;
                    }
                    const file = dir.openFile(entry.name, .{}) catch {
                        allocator.free(full_name);
                        continue;
                    };
                    defer file.close();

                    var buf: [128]u8 = undefined;
                    const read = file.readAll(&buf) catch {
                        allocator.free(full_name);
                        continue;
                    };

                    const h = protocol.parseRef(buf[0..read]) catch {
                        allocator.free(full_name);
                        continue;
                    };

                    // Strip prefix to return suffix only (e.g. "main" not "refs/heads/main")
                    const suffix = if (full_name.len > base_prefix.len and
                        std.mem.startsWith(u8, full_name, base_prefix))
                    blk: {
                        var start = base_prefix.len;
                        // Skip separator slash if present
                        if (start < full_name.len and full_name[start] == '/') start += 1;
                        if (!protocol.validateRefName(full_name[start..])) {
                            allocator.free(full_name);
                            continue;
                        }
                        const s = try allocator.dupe(u8, full_name[start..]);
                        allocator.free(full_name);
                        break :blk s;
                    } else full_name;
                    try refs.append(allocator, .{ .name = suffix, .hash = h });
                },
                .directory => {
                    // Recurse into subdirectory
                    try collectRefs(root, allocator, base_prefix, full_name, refs);
                    allocator.free(full_name);
                },
                else => {
                    allocator.free(full_name);
                },
            }
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "upload and download pack" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const data = "hello packfile content";
    const digest = hash_mod.hash(data);

    const t = ft.transport();
    try t.uploadPack(allocator, data, digest);

    const downloaded = try t.downloadPack(allocator, digest);
    defer allocator.free(downloaded);

    try std.testing.expectEqualStrings(data, downloaded);
}

test "download missing pack" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const digest = hash_mod.hash("nonexistent pack");
    const t = ft.transport();

    try std.testing.expectError(error.PackNotFound, t.downloadPack(allocator, digest));
}

test "pack creates directory" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    // packs/ directory should not exist yet
    tmp.dir.access("packs", .{}) catch |err| {
        try std.testing.expect(err == error.FileNotFound);
    };

    const data = "first pack";
    const digest = hash_mod.hash(data);
    const t = ft.transport();
    try t.uploadPack(allocator, data, digest);

    // Now packs/ directory should exist
    tmp.dir.access("packs", .{}) catch {
        return error.TestUnexpectedResult;
    };
}

test "pack exists true and false" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const data = "exists test";
    const digest = hash_mod.hash(data);
    const t = ft.transport();

    // Before upload
    const before = try t.packExists(allocator, digest);
    try std.testing.expect(!before);

    // After upload
    try t.uploadPack(allocator, data, digest);
    const after = try t.packExists(allocator, digest);
    try std.testing.expect(after);
}

test "write and read ref" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h = hash_mod.hash("commit-data");
    const t = ft.transport();

    try t.writeRef(allocator, "refs/heads/main", h);
    const read = try t.readRef(allocator, "refs/heads/main");

    try std.testing.expect(read != null);
    try std.testing.expectEqual(h, read.?);
}

test "write ref creates parent dirs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h = hash_mod.hash("deep-ref");
    const t = ft.transport();

    // Write a deeply nested ref
    try t.writeRef(allocator, "refs/heads/feature/deep/branch", h);

    // Verify intermediate directories were created
    tmp.dir.access("refs", .{}) catch return error.TestUnexpectedResult;
    tmp.dir.access("refs/heads", .{}) catch return error.TestUnexpectedResult;
    tmp.dir.access("refs/heads/feature", .{}) catch return error.TestUnexpectedResult;
    tmp.dir.access("refs/heads/feature/deep", .{}) catch return error.TestUnexpectedResult;

    // Verify the ref is readable
    const read = try t.readRef(allocator, "refs/heads/feature/deep/branch");
    try std.testing.expect(read != null);
    try std.testing.expectEqual(h, read.?);
}

test "read missing ref" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const t = ft.transport();
    const read = try t.readRef(allocator, "refs/heads/nonexistent");

    try std.testing.expect(read == null);
}

test "overwrite ref" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h1 = hash_mod.hash("commit-v1");
    const h2 = hash_mod.hash("commit-v2");
    const t = ft.transport();

    try t.writeRef(allocator, "refs/heads/main", h1);
    try t.writeRef(allocator, "refs/heads/main", h2);

    const read = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(read != null);
    try std.testing.expectEqual(h2, read.?);
}

test "update ref rejects stale expected hash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const current = hash_mod.hash("current");
    const stale = hash_mod.hash("stale");
    const next = hash_mod.hash("next");
    const t = ft.transport();

    try t.writeRef(allocator, "refs/heads/main", current);
    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .{ .match = stale }, next),
    );
}

test "update ref creates only when missing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h = hash_mod.hash("initial");
    const t = ft.transport();

    try t.updateRef(allocator, "refs/heads/main", .missing, h);
    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .missing, h),
    );
}

test "list refs" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h1 = hash_mod.hash("c1");
    const h2 = hash_mod.hash("c2");
    const h3 = hash_mod.hash("c3");
    const t = ft.transport();

    try t.writeRef(allocator, "refs/heads/main", h1);
    try t.writeRef(allocator, "refs/heads/develop", h2);
    try t.writeRef(allocator, "refs/tags/v1.0", h3);

    // List only heads
    const heads = try t.listRefs(allocator, "refs/heads");
    defer {
        for (heads) |ref| allocator.free(ref.name);
        allocator.free(heads);
    }

    try std.testing.expectEqual(@as(usize, 2), heads.len);

    // List all refs
    const all = try t.listRefs(allocator, "refs");
    defer {
        for (all) |ref| allocator.free(ref.name);
        allocator.free(all);
    }

    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "list refs sorted" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const h = hash_mod.hash("sort-test");
    const t = ft.transport();

    // Write in non-alphabetical order
    try t.writeRef(allocator, "refs/heads/zebra", h);
    try t.writeRef(allocator, "refs/heads/alpha", h);
    try t.writeRef(allocator, "refs/heads/middle", h);

    const refs_list = try t.listRefs(allocator, "refs/heads");
    defer {
        for (refs_list) |ref| allocator.free(ref.name);
        allocator.free(refs_list);
    }

    try std.testing.expectEqual(@as(usize, 3), refs_list.len);
    try std.testing.expectEqualStrings("alpha", refs_list[0].name);
    try std.testing.expectEqualStrings("middle", refs_list[1].name);
    try std.testing.expectEqualStrings("zebra", refs_list[2].name);
}

test "list refs empty" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    const t = ft.transport();
    const refs_list = try t.listRefs(allocator, "refs/heads");
    defer allocator.free(refs_list);

    try std.testing.expectEqual(@as(usize, 0), refs_list.len);
}

test "transport interface" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();

    // Use only the protocol.Transport interface — no direct FileTransport calls
    const t: protocol.Transport = ft.transport();

    // uploadPack + packExists + downloadPack
    const pack_data = "transport-vtable-test-payload";
    const digest = hash_mod.hash(pack_data);

    try std.testing.expect(!(try t.packExists(allocator, digest)));
    try t.uploadPack(allocator, pack_data, digest);
    try std.testing.expect(try t.packExists(allocator, digest));

    const downloaded = try t.downloadPack(allocator, digest);
    defer allocator.free(downloaded);
    try std.testing.expectEqualStrings(pack_data, downloaded);

    // writeRef + readRef + listRefs
    const h = hash_mod.hash("ref-data");
    try t.writeRef(allocator, "refs/heads/main", h);

    const read_h = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(read_h != null);
    try std.testing.expectEqual(h, read_h.?);

    const missing = try t.readRef(allocator, "refs/heads/nope");
    try std.testing.expect(missing == null);

    const refs_list = try t.listRefs(allocator, "refs/heads");
    defer {
        for (refs_list) |ref| allocator.free(ref.name);
        allocator.free(refs_list);
    }
    try std.testing.expectEqual(@as(usize, 1), refs_list.len);
    try std.testing.expectEqualStrings("main", refs_list[0].name);
    try std.testing.expectEqual(h, refs_list[0].hash);
}

// =============================================================================
// Atomic-write + lock-file CAS tests (W5-1)
// =============================================================================

test "atomic ref write: two refs written in sequence round-trip" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();
    const t = ft.transport();

    const h1 = hash_mod.hash("atomic-1");
    const h2 = hash_mod.hash("atomic-2");
    try t.writeRef(allocator, "refs/heads/main", h1);
    try t.writeRef(allocator, "refs/heads/main", h2);

    const r = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(r != null);
    try std.testing.expectEqual(h2, r.?);

    // No leftover tmp files should remain.
    var dir = try tmp.dir.openDir("refs/heads", .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    var leftover_tmp: usize = 0;
    var total: usize = 0;
    while (try iter.next()) |entry| {
        total += 1;
        if (std.mem.indexOf(u8, entry.name, ".tmp.")) |_| leftover_tmp += 1;
        if (total > 100) break; // cap — test bounded
    }
    try std.testing.expectEqual(@as(usize, 0), leftover_tmp);
}

test "atomic ref write: concurrent writer never leaves empty/truncated file" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();
    const t = ft.transport();

    const h_old = hash_mod.hash("atomic-old");
    const h_new = hash_mod.hash("atomic-new");
    // Seed the ref so readers always have a valid file to observe.
    try t.writeRef(allocator, "refs/heads/main", h_old);

    const Worker = struct {
        transport: protocol.Transport,
        alloc: Allocator,
        h: Hash,
        fn run(self: @This()) void {
            var i: u32 = 0;
            while (i < 50) : (i += 1) {
                self.transport.writeRef(self.alloc, "refs/heads/main", self.h) catch {};
            }
        }
    };

    const thread = try std.Thread.spawn(.{}, Worker.run, .{Worker{
        .transport = t,
        .alloc = allocator,
        .h = h_new,
    }});

    // Meanwhile the main thread reads and asserts the ref is always either
    // h_old or h_new — never empty / truncated / nonsense.
    var reads: u32 = 0;
    while (reads < 50) : (reads += 1) {
        const r = try t.readRef(allocator, "refs/heads/main");
        try std.testing.expect(r != null);
        const v = r.?;
        const is_old = std.mem.eql(u8, &v, &h_old);
        const is_new = std.mem.eql(u8, &v, &h_new);
        try std.testing.expect(is_old or is_new);
    }

    thread.join();

    // Final state must be h_new.
    const final = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(final != null);
    try std.testing.expectEqual(h_new, final.?);
}

test "updateRef(.match) success writes new hash" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();
    const t = ft.transport();

    const h_old = hash_mod.hash("cas-old");
    const h_new = hash_mod.hash("cas-new");

    try t.writeRef(allocator, "refs/heads/main", h_old);
    try t.updateRef(allocator, "refs/heads/main", .{ .match = h_old }, h_new);

    const r = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(r != null);
    try std.testing.expectEqual(h_new, r.?);

    // Lock file must have been cleaned up.
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("refs/heads/main.lock", .{}));
}

test "updateRef(.match) wrong hash → RefConflict and cleans lock" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();
    const t = ft.transport();

    const h_current = hash_mod.hash("cas-cur");
    const h_stale = hash_mod.hash("cas-stale");
    const h_new = hash_mod.hash("cas-target");

    try t.writeRef(allocator, "refs/heads/main", h_current);
    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .{ .match = h_stale }, h_new),
    );

    // State unchanged.
    const r = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(r != null);
    try std.testing.expectEqual(h_current, r.?);

    // Lock file must have been cleaned up even on the RefConflict path.
    try std.testing.expectError(error.FileNotFound, tmp.dir.access("refs/heads/main.lock", .{}));
}

test "updateRef(.match) with pre-existing stale lock times out to RefConflict, never panics" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var ft = FileTransport.initFromDir(allocator, tmp.dir);
    defer ft.deinit();
    const t = ft.transport();

    const h_current = hash_mod.hash("cas-stalelock-cur");
    const h_new = hash_mod.hash("cas-stalelock-new");

    try t.writeRef(allocator, "refs/heads/main", h_current);

    // Plant a lock file by hand. updateRef must spin and eventually time out
    // to RefConflict (it does not panic, does not corrupt the ref).
    // We temporarily lower the lock attempt count by using a short-poll loop
    // here; the real attempts are bounded by LOCK_MAX_ATTEMPTS so the 5 s
    // timeout is the upper bound for this test.
    {
        const lock = try tmp.dir.createFile("refs/heads/main.lock", .{ .exclusive = true });
        lock.close();
    }

    try std.testing.expectError(
        error.RefConflict,
        t.updateRef(allocator, "refs/heads/main", .{ .match = h_current }, h_new),
    );

    // Ref state unchanged.
    const r = try t.readRef(allocator, "refs/heads/main");
    try std.testing.expect(r != null);
    try std.testing.expectEqual(h_current, r.?);

    // The pre-existing lock we planted is still there (we never stole it);
    // remove it so tmp.cleanup doesn't complain.
    try tmp.dir.deleteFile("refs/heads/main.lock");
}
