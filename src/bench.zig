// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const mkit = struct {
    const hash = @import("hash.zig");
    const object = @import("object.zig");
    const serialize = @import("serialize.zig");
    const store = @import("store.zig");
    const sign = @import("sign.zig");
    const ignore = @import("ignore.zig");
    const diff = @import("diff.zig");
    const worktree = @import("worktree.zig");
    const refs = @import("refs.zig");
};

const doNotOptimizeAway = std.mem.doNotOptimizeAway;

// Why: std.time.Timer was removed in 0.16; monotonic wall-clock reads now
// go through the Io capability. We retain the same "start → read nanos"
// shape as the old Timer so callsites stay readable.
var bench_threaded: std.Io.Threaded = undefined;
var bench_io: std.Io = undefined;

const Timer = struct {
    start_ns: i96,

    fn start() error{TimerUnsupported}!Timer {
        return .{ .start_ns = std.Io.Clock.awake.now(bench_io).nanoseconds };
    }

    fn read(self: Timer) u64 {
        const now_ns = std.Io.Clock.awake.now(bench_io).nanoseconds;
        return @intCast(now_ns - self.start_ns);
    }
};

// Why: std.testing.tmpDir is @compileError'd outside `is_test` in 0.16,
// so the bench binary can no longer lean on it. Provide a minimal
// equivalent that creates a unique directory under `.zig-cache/bench-tmp/`
// using a seeded counter.
var tmp_counter: u64 = 0;
const BenchTmpDir = struct {
    dir: std.Io.Dir,
    parent: std.Io.Dir,
    sub_path: [32]u8,

    fn cleanup(self: *BenchTmpDir) void {
        self.dir.close(bench_io);
        self.parent.deleteTree(bench_io, &self.sub_path) catch {};
        self.parent.close(bench_io);
    }
};

fn benchTmpDir() BenchTmpDir {
    tmp_counter += 1;
    const seed = std.Io.Clock.awake.now(bench_io).nanoseconds;
    var sub_path: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&sub_path, "bench-{x:0>16}-{x:0>8}", .{ @as(u64, @truncate(@as(u96, @bitCast(seed)))), tmp_counter }) catch unreachable;

    const cwd = std.Io.Dir.cwd();
    var cache = cwd.createDirPathOpen(bench_io, ".zig-cache", .{}) catch @panic("bench: cannot open .zig-cache");
    defer cache.close(bench_io);
    var parent = cache.createDirPathOpen(bench_io, "bench-tmp", .{}) catch @panic("bench: cannot open .zig-cache/bench-tmp");
    const dir = parent.createDirPathOpen(bench_io, &sub_path, .{}) catch @panic("bench: cannot open bench tmp subdir");
    return .{ .dir = dir, .parent = parent, .sub_path = sub_path };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch &buf;
    std.Io.File.stdout().writeStreamingAll(bench_io, s) catch {};
}

fn printRow(name: []const u8, ns_per_op: u64, detail: []const u8) void {
    const us = @as(f64, @floatFromInt(ns_per_op)) / 1_000.0;
    if (us >= 1_000.0) {
        print("  {s:<40} {d:>8.2} ms   {s}\n", .{ name, us / 1_000.0, detail });
    } else {
        print("  {s:<40} {d:>8.2} us   {s}\n", .{ name, us, detail });
    }
}

fn fmtRate(buf: []u8, bytes: u64, ns: u64) []const u8 {
    const bps = @as(f64, @floatFromInt(bytes)) / (@as(f64, @floatFromInt(ns)) / 1e9);
    if (bps >= 1e9) {
        return std.fmt.bufPrint(buf, "{d:.1} GB/s", .{bps / 1e9}) catch "?";
    } else if (bps >= 1e6) {
        return std.fmt.bufPrint(buf, "{d:.1} MB/s", .{bps / 1e6}) catch "?";
    } else {
        return std.fmt.bufPrint(buf, "{d:.1} KB/s", .{bps / 1e3}) catch "?";
    }
}

fn fmtOps(buf: []u8, ops: u64, ns: u64) []const u8 {
    const ops_sec = @as(f64, @floatFromInt(ops)) / (@as(f64, @floatFromInt(ns)) / 1e9);
    if (ops_sec >= 1e6) {
        return std.fmt.bufPrint(buf, "{d:.1} M ops/s", .{ops_sec / 1e6}) catch "?";
    } else if (ops_sec >= 1e3) {
        return std.fmt.bufPrint(buf, "{d:.1} K ops/s", .{ops_sec / 1e3}) catch "?";
    } else {
        return std.fmt.bufPrint(buf, "{d:.0} ops/s", .{ops_sec}) catch "?";
    }
}

fn header(name: []const u8) void {
    print("\n  {s}\n  {s}\n", .{ name, "-" ** 68 });
}

// ---------------------------------------------------------------------------
// BLAKE3 hashing throughput
// ---------------------------------------------------------------------------

fn benchBlake3(comptime size: comptime_int, label: []const u8) void {
    const iters = comptime if (size >= 10_000_000) 10 else if (size >= 1_000_000) 100 else 1_000;
    const data = std.heap.page_allocator.alloc(u8, size) catch return;
    defer std.heap.page_allocator.free(data);
    @memset(data, 0xAA);

    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        doNotOptimizeAway(mkit.hash.hash(data));
    }
    const elapsed = timer.read();
    const total_bytes: u64 = @as(u64, size) * iters;
    var buf: [32]u8 = undefined;
    printRow(label, elapsed / iters, fmtRate(&buf, total_bytes, elapsed));
}

// ---------------------------------------------------------------------------
// Serialization roundtrip
// ---------------------------------------------------------------------------

fn benchSerialize() void {
    const alloc = std.heap.page_allocator;
    const iters: u64 = 10_000;

    var parents_buf = [_]mkit.hash.Hash{mkit.hash.hash("parent1")};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 42, .little);
    const commit = mkit.object.Object{ .commit = .{
        .tree_hash = mkit.hash.hash("tree"),
        .parents = &parents_buf,
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = .{0xAA} ** 32,
        .message = "feat(mkit): add benchmarks for performance validation",
        .timestamp = 1711300000,
        .message_hash = mkit.hash.hash("message"),
        .content_digest = mkit.hash.zero,
        .signature = .{0xBB} ** 64,
    } };

    // Serialize
    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        const bytes = mkit.serialize.serialize(alloc, commit) catch continue;
        doNotOptimizeAway(bytes.ptr);
        alloc.free(bytes);
    }
    var elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("serialize commit", elapsed / iters, fmtOps(&buf, iters, elapsed));

    // Deserialize
    const bytes = mkit.serialize.serialize(alloc, commit) catch return;
    defer alloc.free(bytes);

    timer = Timer.start() catch return;
    for (0..iters) |_| {
        var obj = mkit.serialize.deserialize(alloc, bytes) catch continue;
        doNotOptimizeAway(&obj);
        obj.deinit(alloc);
    }
    elapsed = timer.read();
    printRow("deserialize commit", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Tree serialization (100 entries)
// ---------------------------------------------------------------------------

fn benchSerializeTree() void {
    const alloc = std.heap.page_allocator;
    const iters: u64 = 5_000;
    const n = 100;

    var entries: [n]mkit.object.TreeEntry = undefined;
    var names: [n][16]u8 = undefined;
    for (0..n) |i| {
        const name = std.fmt.bufPrint(&names[i], "file_{d:0>4}.txt", .{i}) catch continue;
        entries[i] = .{ .name = name, .mode = .blob, .object_hash = mkit.hash.hash(name) };
    }
    const tree = mkit.object.Object{ .tree = .{ .entries = &entries } };

    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        const bytes = mkit.serialize.serialize(alloc, tree) catch continue;
        doNotOptimizeAway(bytes.ptr);
        alloc.free(bytes);
    }
    const elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("serialize tree (100 entries)", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Ed25519 sign + verify
// ---------------------------------------------------------------------------

fn benchSign() void {
    const alloc = std.heap.page_allocator;
    const iters: u64 = 1_000;
    const kp = mkit.sign.KeyPair.generate(bench_io);

    var parents = [_]mkit.hash.Hash{};
    var mid_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &mid_buf, 42, .little);
    var commit = mkit.object.Commit{
        .tree_hash = mkit.hash.hash("tree"),
        .parents = &parents,
        .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
        .signer = kp.public_key,
        .message = "bench commit",
        .timestamp = 1711300000,
        .signature = .{0} ** 64,
    };

    // Sign
    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        commit.signature = mkit.sign.signCommit(alloc, commit, kp) catch continue;
        doNotOptimizeAway(&commit.signature);
    }
    var elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("ed25519 sign commit", elapsed / iters, fmtOps(&buf, iters, elapsed));

    // Verify
    timer = Timer.start() catch return;
    for (0..iters) |_| {
        doNotOptimizeAway(mkit.sign.verifyCommit(alloc, commit) catch false);
    }
    elapsed = timer.read();
    printRow("ed25519 verify commit", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Object store I/O
// ---------------------------------------------------------------------------

fn benchStore() void {
    const alloc = std.heap.page_allocator;
    const iters: u64 = 1_000;

    var tmp = benchTmpDir();
    defer tmp.cleanup();
    var store = mkit.store.ObjectStore.init(bench_io, tmp.dir) catch return;
    defer store.close();

    // Put
    var hashes: [1_000]mkit.hash.Hash = undefined;
    var timer = Timer.start() catch return;
    for (0..iters) |i| {
        var data: [256]u8 = undefined;
        std.mem.writeInt(u64, data[0..8], @intCast(i), .little);
        @memset(data[8..], 0xBB);
        hashes[i] = store.put(alloc, mkit.object.Object{ .blob = .{ .data = &data } }) catch continue;
    }
    var elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("store put (256B blob)", elapsed / iters, fmtOps(&buf, iters, elapsed));

    // Get
    timer = Timer.start() catch return;
    for (0..iters) |i| {
        var obj = store.get(alloc, hashes[i]) catch continue;
        doNotOptimizeAway(obj.blob.data.ptr);
        obj.deinit(alloc);
    }
    elapsed = timer.read();
    printRow("store get (256B blob)", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Glob pattern matching
// ---------------------------------------------------------------------------

fn benchGlobMatch() void {
    const iters: u64 = 100_000;
    const patterns = [_][]const u8{ "*.zig", "*.log", "*.txt", "README.md", "src/*.zig" };
    const names = [_][]const u8{ "main.zig", "debug.log", "README.md", "build", "test.txt", "lib.zig", "Makefile", "data.bin" };

    var timer = Timer.start() catch return;
    var matches: u64 = 0;
    for (0..iters) |_| {
        for (patterns) |pat| {
            for (names) |name| {
                if (mkit.ignore.globMatch(pat, name)) matches += 1;
            }
        }
    }
    doNotOptimizeAway(matches);
    const elapsed = timer.read();
    const total = iters * patterns.len * names.len;
    var buf: [32]u8 = undefined;
    printRow("glob match (5x8 patterns)", elapsed / total, fmtOps(&buf, total, elapsed));
}

// ---------------------------------------------------------------------------
// Tree diff
// ---------------------------------------------------------------------------

fn benchDiff() void {
    const alloc = std.heap.page_allocator;
    const iters: u64 = 500;
    const n = 100;

    var tmp = benchTmpDir();
    defer tmp.cleanup();
    var store = mkit.store.ObjectStore.init(bench_io, tmp.dir) catch return;
    defer store.close();

    var old_entries: [n]mkit.object.TreeEntry = undefined;
    var old_names: [n][16]u8 = undefined;
    for (0..n) |i| {
        const name = std.fmt.bufPrint(&old_names[i], "file_{d:0>4}.txt", .{i}) catch continue;
        old_entries[i] = .{ .name = name, .mode = .blob, .object_hash = mkit.hash.hash(name) };
    }
    const old_hash = store.put(alloc, mkit.object.Object{ .tree = .{ .entries = &old_entries } }) catch return;

    var new_entries: [n]mkit.object.TreeEntry = undefined;
    var new_names: [n][16]u8 = undefined;
    for (0..n) |i| {
        const name = std.fmt.bufPrint(&new_names[i], "file_{d:0>4}.txt", .{i}) catch continue;
        new_entries[i] = .{
            .name = name,
            .mode = .blob,
            .object_hash = if (i % 10 == 0) mkit.hash.hash("modified") else mkit.hash.hash(name),
        };
    }
    const new_hash = store.put(alloc, mkit.object.Object{ .tree = .{ .entries = &new_entries } }) catch return;

    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        var res = mkit.diff.diffTrees(alloc, &store, old_hash, new_hash) catch continue;
        doNotOptimizeAway(res.entries.ptr);
        res.deinit();
    }
    const elapsed = timer.read();
    var buf2: [32]u8 = undefined;
    printRow("diff trees (100 entries, 10% changed)", elapsed / iters, fmtOps(&buf2, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Filesystem workflows: init, hash, tree, commit
// ---------------------------------------------------------------------------

fn benchInit() void {
    const iters: u64 = 100;

    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        var tmp = benchTmpDir();
        var st = mkit.store.ObjectStore.init(bench_io, tmp.dir) catch {
            tmp.cleanup();
            continue;
        };
        st.close();
        mkit.refs.init(bench_io, tmp.dir) catch {};
        tmp.cleanup();
    }
    const elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("mkit init (full repo setup)", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

fn benchHashFiles() void {
    const alloc = std.heap.page_allocator;
    const num_files = 100;
    const file_size = 4096;

    // Set up repo with files
    var tmp = benchTmpDir();
    defer tmp.cleanup();
    var store = mkit.store.ObjectStore.init(bench_io, tmp.dir) catch return;
    defer store.close();

    // Create files
    var file_names: [num_files][16]u8 = undefined;
    for (0..num_files) |i| {
        const name = std.fmt.bufPrint(&file_names[i], "file_{d:0>4}.txt", .{i}) catch continue;
        const f = tmp.dir.createFile(bench_io, name, .{}) catch continue;
        var data: [file_size]u8 = undefined;
        std.mem.writeInt(u64, data[0..8], @intCast(i), .little);
        @memset(data[8..], 0xCC);
        f.writeStreamingAll(bench_io, &data) catch {};
        f.close(bench_io);
    }

    // Benchmark: hash all files (read from disk + BLAKE3 + store to object db)
    const iters: u64 = 20;
    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        for (0..num_files) |i| {
            const name = std.fmt.bufPrint(&file_names[i], "file_{d:0>4}.txt", .{i}) catch continue;
            const file = tmp.dir.openFile(bench_io, name, .{}) catch continue;
            defer file.close(bench_io);
            const stat = file.stat(bench_io) catch continue;
            const data = alloc.alloc(u8, stat.size) catch continue;
            defer alloc.free(data);
            const read = file.readPositionalAll(bench_io, data, 0) catch continue;
            const blob = mkit.object.Object{ .blob = .{ .data = data[0..read] } };
            doNotOptimizeAway(store.put(alloc, blob) catch continue);
        }
    }
    const elapsed = timer.read();
    const total_files = iters * num_files;
    var buf: [32]u8 = undefined;
    const detail = fmtOps(&buf, total_files, elapsed);
    printRow("hash 100 x 4KB files (disk→store)", elapsed / iters, detail);
}

fn benchTreeSnapshot() void {
    const alloc = std.heap.page_allocator;
    const num_files = 50;

    // Set up a directory with files and subdirs
    var tmp = benchTmpDir();
    defer tmp.cleanup();

    var store_tmp = benchTmpDir();
    defer store_tmp.cleanup();
    var store = mkit.store.ObjectStore.init(bench_io, store_tmp.dir) catch return;
    defer store.close();

    // Create a realistic project structure
    tmp.dir.createDirPath(bench_io, "src") catch {};
    tmp.dir.createDirPath(bench_io, "tests") catch {};
    tmp.dir.createDirPath(bench_io, "docs") catch {};

    for (0..num_files) |i| {
        var name_buf: [32]u8 = undefined;
        const dir_prefix: []const u8 = if (i < 20) "src/" else if (i < 35) "tests/" else if (i < 45) "docs/" else "";
        const name = std.fmt.bufPrint(&name_buf, "{s}f_{d:0>3}.txt", .{ dir_prefix, i }) catch continue;
        const f = tmp.dir.createFile(bench_io, name, .{}) catch continue;
        var data: [1024]u8 = undefined;
        std.mem.writeInt(u64, data[0..8], @intCast(i), .little);
        @memset(data[8..], 0xDD);
        f.writeStreamingAll(bench_io, &data) catch {};
        f.close(bench_io);
    }

    // Benchmark: snapshot entire working directory
    const iters: u64 = 20;
    var timer = Timer.start() catch return;
    for (0..iters) |_| {
        var work_dir = tmp.dir.openDir(bench_io, ".", .{ .iterate = true }) catch continue;
        defer work_dir.close(bench_io);
        doNotOptimizeAway(mkit.worktree.buildTree(alloc, bench_io, &store, work_dir) catch continue);
    }
    const elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("tree snapshot (50 files, 3 dirs)", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

fn benchCommitWorkflow() void {
    const alloc = std.heap.page_allocator;

    // Full workflow: init → create files → build tree → sign commit → store → update ref
    const iters: u64 = 20;
    var timer = Timer.start() catch return;

    for (0..iters) |iter| {
        var tmp = benchTmpDir();

        var store = mkit.store.ObjectStore.init(bench_io, tmp.dir) catch {
            tmp.cleanup();
            continue;
        };
        mkit.refs.init(bench_io, tmp.dir) catch {
            store.close();
            tmp.cleanup();
            continue;
        };

        // Create 10 files
        for (0..10) |i| {
            var name_buf: [16]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "f_{d:0>2}.txt", .{i}) catch continue;
            const f = tmp.dir.createFile(bench_io, name, .{}) catch continue;
            var data: [512]u8 = undefined;
            std.mem.writeInt(u64, data[0..8], @as(u64, iter * 10 + i), .little);
            @memset(data[8..], 0xEE);
            f.writeStreamingAll(bench_io, &data) catch {};
            f.close(bench_io);
        }

        // Build tree
        var work_dir = tmp.dir.openDir(bench_io, ".", .{ .iterate = true }) catch {
            store.close();
            tmp.cleanup();
            continue;
        };
        const tree_hash = mkit.worktree.buildTree(alloc, bench_io, &store, work_dir) catch {
            work_dir.close(bench_io);
            store.close();
            tmp.cleanup();
            continue;
        };
        work_dir.close(bench_io);

        // Sign commit
        const kp = mkit.sign.KeyPair.generate(bench_io);
        var parents = [_]mkit.hash.Hash{};
        var mid_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &mid_buf, 42, .little);
        var commit = mkit.object.Commit{
            .tree_hash = tree_hash,
            .parents = &parents,
            .author = .{ .kind = .@"opaque", .bytes = mid_buf[0..] },
            .signer = kp.public_key,
            .message = "benchmark commit",
            .timestamp = 1711300000,
            .message_hash = mkit.hash.hash("benchmark commit"),
            .content_digest = mkit.hash.zero,
            .signature = .{0} ** 64,
        };
        commit.signature = mkit.sign.signCommit(alloc, commit, kp) catch {
            store.close();
            tmp.cleanup();
            continue;
        };

        // Store commit + update ref
        const commit_hash = store.put(alloc, mkit.object.Object{ .commit = commit }) catch {
            store.close();
            tmp.cleanup();
            continue;
        };
        mkit.refs.updateHead(alloc, bench_io, tmp.dir, commit_hash) catch {};
        doNotOptimizeAway(commit_hash);

        store.close();
        tmp.cleanup();
    }

    const elapsed = timer.read();
    var buf: [32]u8 = undefined;
    printRow("full commit (10 files → signed)", elapsed / iters, fmtOps(&buf, iters, elapsed));
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn main() !void {
    bench_threaded = .init(std.heap.page_allocator, .{});
    defer bench_threaded.deinit();
    bench_io = bench_threaded.io();

    const out = std.Io.File.stdout();
    try out.writeStreamingAll(bench_io, "\nmkit benchmarks (ReleaseFast)\n");
    try out.writeStreamingAll(bench_io, "========================================================================\n");

    header("BLAKE3 hashing");
    benchBlake3(1_024, "blake3 1 KB");
    benchBlake3(64 * 1_024, "blake3 64 KB");
    benchBlake3(1_024 * 1_024, "blake3 1 MB");
    benchBlake3(10 * 1_024 * 1_024, "blake3 10 MB");

    header("Serialization");
    benchSerialize();
    benchSerializeTree();

    header("Ed25519 cryptography");
    benchSign();

    header("Object store (filesystem)");
    benchStore();

    header("Pattern matching");
    benchGlobMatch();

    header("Tree diff");
    benchDiff();

    header("Filesystem workflows");
    benchInit();
    benchHashFiles();
    benchTreeSnapshot();
    benchCommitWorkflow();

    try out.writeStreamingAll(bench_io, "\n========================================================================\n\n");
}
