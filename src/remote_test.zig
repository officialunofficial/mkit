// SPDX-License-Identifier: MIT OR Apache-2.0
const std = @import("std");
const hash_mod = @import("hash.zig");
const refs_mod = @import("refs.zig");
const object = @import("object.zig");
const store_mod = @import("store.zig");
const serialize = @import("serialize.zig");
const packfile = @import("packfile.zig");
const sign = @import("sign.zig");
const worktree = @import("worktree.zig");
const protocol = @import("protocol.zig");
const transport_memory = @import("transport/memory.zig");
const th = @import("test_helpers.zig");
const Hash = hash_mod.Hash;
const Allocator = std.mem.Allocator;

// ============================================================================
// Test helpers
// ============================================================================

/// Build a simple tree with a single file, store everything, create a commit,
/// and return (commit_hash, tree_hash, blob_hash).
fn makeSimpleCommit(
    allocator: Allocator,
    store: *store_mod.ObjectStore,
    filename: []const u8,
    content: []const u8,
    parents: []const Hash,
    msg: []const u8,
) !struct { commit: Hash, tree: Hash, blob: Hash } {
    const blob_hash = try th.makeBlob(allocator, store, content);
    const entries = [_]object.TreeEntry{
        .{ .name = filename, .mode = .blob, .object_hash = blob_hash },
    };
    const tree_hash = try th.makeTree(allocator, store, &entries);
    const commit_hash = try th.makeCommit(allocator, store, tree_hash, parents, msg);
    return .{ .commit = commit_hash, .tree = tree_hash, .blob = blob_hash };
}

// ============================================================================
// Integration tests — using protocol.Transport via MemoryTransport
// ============================================================================

test "push then pull roundtrip" {
    const allocator = std.testing.allocator;

    // --- Source repo ---
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(std.testing.io, src_tmp.dir);
    defer src_store.close();

    // Create blob -> tree -> commit
    const src = try makeSimpleCommit(
        allocator,
        &src_store,
        "hello.txt",
        "hello world",
        &[_]Hash{},
        "initial commit",
    );

    // Pack reachable objects from commit
    const pack_result = try packfile.packReachable(allocator, &src_store, src.commit);
    defer allocator.free(pack_result.bytes);

    // --- Remote (MemoryTransport via protocol.Transport) ---
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    // Push: upload pack + write ref
    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);
    try t.writeRef(allocator, "refs/heads/main", src.commit);

    // --- Destination repo ---
    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(std.testing.io, dst_tmp.dir);
    defer dst_store.close();

    // Verify objects don't exist in destination yet
    try std.testing.expect(!dst_store.exists(src.commit));
    try std.testing.expect(!dst_store.exists(src.tree));
    try std.testing.expect(!dst_store.exists(src.blob));

    // Pull: read remote ref -> download pack -> unpack into store
    const remote_hash = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(src.commit, remote_hash);

    const pack_bytes = try t.downloadPack(allocator, pack_result.digest);
    defer allocator.free(pack_bytes);

    try packfile.unpackInto(allocator, pack_bytes, &dst_store);

    // Verify all objects are now in destination
    try std.testing.expect(dst_store.exists(src.commit));
    try std.testing.expect(dst_store.exists(src.tree));
    try std.testing.expect(dst_store.exists(src.blob));

    // Load commit from destination and verify tree matches
    var dst_commit = try dst_store.get(allocator, src.commit);
    defer dst_commit.deinit(allocator);
    try std.testing.expectEqual(src.tree, dst_commit.commit.tree_hash);

    // Verify blob content
    var dst_blob = try dst_store.get(allocator, src.blob);
    defer dst_blob.deinit(allocator);
    try std.testing.expectEqualStrings("hello world", dst_blob.blob.data);
}

test "push updates remote ref" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const src = try makeSimpleCommit(
        allocator,
        &store,
        "file.txt",
        "content",
        &[_]Hash{},
        "first",
    );

    const pack_result = try packfile.packReachable(allocator, &store, src.commit);
    defer allocator.free(pack_result.bytes);

    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);
    try t.writeRef(allocator, "refs/heads/main", src.commit);

    // Verify the remote ref points to the correct hash
    const ref_hash = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(src.commit, ref_hash);

    // Nonexistent ref returns null
    const missing = try t.readRef(allocator, "refs/heads/nonexistent");
    try std.testing.expectEqual(@as(?Hash, null), missing);
}

test "pull fast-forward" {
    const allocator = std.testing.allocator;

    // --- Create repo with A -> B ---
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(std.testing.io, src_tmp.dir);
    defer src_store.close();

    // Commit A
    const a = try makeSimpleCommit(
        allocator,
        &src_store,
        "file.txt",
        "version 1",
        &[_]Hash{},
        "commit A",
    );

    // Commit B (child of A)
    const b = try makeSimpleCommit(
        allocator,
        &src_store,
        "file.txt",
        "version 2",
        &[_]Hash{a.commit},
        "commit B",
    );

    // --- Set up local repo with commit A ---
    var local_tmp = std.testing.tmpDir(.{});
    defer local_tmp.cleanup();
    var local_store = try store_mod.ObjectStore.init(std.testing.io, local_tmp.dir);
    defer local_store.close();

    // Pack and unpack A into local
    const pack_a = try packfile.packReachable(allocator, &src_store, a.commit);
    defer allocator.free(pack_a.bytes);
    try packfile.unpackInto(allocator, pack_a.bytes, &local_store);

    // Set up local refs (.mkit already exists from ObjectStore.init)
    try refs_mod.init(local_tmp.dir);
    try refs_mod.writeRef(local_tmp.dir, "main", a.commit);

    // --- Remote has commit B ---
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const pack_b = try packfile.packReachable(allocator, &src_store, b.commit);
    defer allocator.free(pack_b.bytes);
    try t.uploadPack(allocator, pack_b.bytes, pack_b.digest);
    try t.writeRef(allocator, "refs/heads/main", b.commit);

    // --- Pull: read remote ref, download, unpack, advance local ref ---
    const remote_commit = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(b.commit, remote_commit);

    const downloaded = try t.downloadPack(allocator, pack_b.digest);
    defer allocator.free(downloaded);
    try packfile.unpackInto(allocator, downloaded, &local_store);

    // Advance local ref
    try refs_mod.writeRef(local_tmp.dir, "main", b.commit);

    // Verify local ref now points to B
    const local_ref = (try refs_mod.readRef(allocator, local_tmp.dir, "main")).?;
    try std.testing.expectEqual(b.commit, local_ref);

    // Verify B's commit is accessible with updated tree
    var pulled_commit = try local_store.get(allocator, b.commit);
    defer pulled_commit.deinit(allocator);
    try std.testing.expectEqual(b.tree, pulled_commit.commit.tree_hash);

    // Verify parent chain: B -> A
    try std.testing.expectEqual(@as(usize, 1), pulled_commit.commit.parents.len);
    try std.testing.expectEqual(a.commit, pulled_commit.commit.parents[0]);
}

test "push idempotent" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const src = try makeSimpleCommit(
        allocator,
        &store,
        "data.txt",
        "idempotent",
        &[_]Hash{},
        "idempotent push",
    );

    const pack_result = try packfile.packReachable(allocator, &store, src.commit);
    defer allocator.free(pack_result.bytes);

    // Push twice — should not error
    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);
    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);

    // Pack still exists
    try std.testing.expect(try t.packExists(allocator, pack_result.digest));

    // Download still works and matches original
    const downloaded = try t.downloadPack(allocator, pack_result.digest);
    defer allocator.free(downloaded);
    try std.testing.expectEqualSlices(u8, pack_result.bytes, downloaded);
}

test "clone from transport" {
    const allocator = std.testing.allocator;

    // --- Source repo with chain A -> B ---
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(std.testing.io, src_tmp.dir);
    defer src_store.close();

    const a = try makeSimpleCommit(
        allocator,
        &src_store,
        "readme.md",
        "# Project",
        &[_]Hash{},
        "initial",
    );

    const b = try makeSimpleCommit(
        allocator,
        &src_store,
        "readme.md",
        "# Project\nWith description.",
        &[_]Hash{a.commit},
        "add description",
    );

    // --- Push both commits to remote via Transport ---
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    // Pack commit B
    const pack_b = try packfile.packReachable(allocator, &src_store, b.commit);
    defer allocator.free(pack_b.bytes);
    try t.uploadPack(allocator, pack_b.bytes, pack_b.digest);

    // Remote ref points to B (tip of main)
    try t.writeRef(allocator, "refs/heads/main", b.commit);

    // --- Clone: init fresh repo, read remote ref, download packs, unpack ---
    var clone_tmp = std.testing.tmpDir(.{});
    defer clone_tmp.cleanup();
    var clone_store = try store_mod.ObjectStore.init(std.testing.io, clone_tmp.dir);
    defer clone_store.close();

    // Read remote ref
    const tip = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(b.commit, tip);

    // Download pack for tip commit; it should also carry A's history.
    const cloned_pack = try t.downloadPack(allocator, pack_b.digest);
    defer allocator.free(cloned_pack);
    try packfile.unpackInto(allocator, cloned_pack, &clone_store);

    // Set up local refs (.mkit already exists from ObjectStore.init)
    try refs_mod.init(clone_tmp.dir);
    try refs_mod.writeRef(clone_tmp.dir, "main", b.commit);

    // Verify: all objects from both commits are accessible from one pack
    try std.testing.expect(clone_store.exists(a.commit));
    try std.testing.expect(clone_store.exists(b.commit));
    try std.testing.expect(clone_store.exists(a.tree));
    try std.testing.expect(clone_store.exists(b.tree));
    try std.testing.expect(clone_store.exists(a.blob));
    try std.testing.expect(clone_store.exists(b.blob));

    // Verify local HEAD -> main -> B
    const local_main = (try refs_mod.readRef(allocator, clone_tmp.dir, "main")).?;
    try std.testing.expectEqual(b.commit, local_main);

    // Verify commit B's blob content
    var cloned_commit = try clone_store.get(allocator, b.commit);
    defer cloned_commit.deinit(allocator);
    var cloned_tree = try clone_store.get(allocator, cloned_commit.commit.tree_hash);
    defer cloned_tree.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), cloned_tree.tree.entries.len);
    var cloned_blob = try clone_store.get(allocator, cloned_tree.tree.entries[0].object_hash);
    defer cloned_blob.deinit(allocator);
    try std.testing.expectEqualStrings("# Project\nWith description.", cloned_blob.blob.data);
}

test "multiple branches" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    // Create commit on main
    const main_commit = try makeSimpleCommit(
        allocator,
        &store,
        "main.txt",
        "main content",
        &[_]Hash{},
        "main initial",
    );

    // Create a separate commit on dev (different file)
    const dev_commit = try makeSimpleCommit(
        allocator,
        &store,
        "dev.txt",
        "dev content",
        &[_]Hash{},
        "dev initial",
    );

    // Push main
    const pack_main = try packfile.packReachable(allocator, &store, main_commit.commit);
    defer allocator.free(pack_main.bytes);
    try t.uploadPack(allocator, pack_main.bytes, pack_main.digest);
    try t.writeRef(allocator, "refs/heads/main", main_commit.commit);

    // Push dev
    const pack_dev = try packfile.packReachable(allocator, &store, dev_commit.commit);
    defer allocator.free(pack_dev.bytes);
    try t.uploadPack(allocator, pack_dev.bytes, pack_dev.digest);
    try t.writeRef(allocator, "refs/heads/dev", dev_commit.commit);

    // List remote refs
    const remote_refs = try t.listRefs(allocator, "refs/heads/");
    defer {
        for (remote_refs) |ref| allocator.free(ref.name);
        allocator.free(remote_refs);
    }

    try std.testing.expectEqual(@as(usize, 2), remote_refs.len);
    // Sorted alphabetically: dev, main
    try std.testing.expectEqualStrings("dev", remote_refs[0].name);
    try std.testing.expectEqual(dev_commit.commit, remote_refs[0].hash);
    try std.testing.expectEqualStrings("main", remote_refs[1].name);
    try std.testing.expectEqual(main_commit.commit, remote_refs[1].hash);

    // Clone both branches into a fresh store
    var clone_tmp = std.testing.tmpDir(.{});
    defer clone_tmp.cleanup();
    var clone_store = try store_mod.ObjectStore.init(std.testing.io, clone_tmp.dir);
    defer clone_store.close();

    // Download and unpack main
    const dl_main = try t.downloadPack(allocator, pack_main.digest);
    defer allocator.free(dl_main);
    try packfile.unpackInto(allocator, dl_main, &clone_store);

    // Download and unpack dev
    const dl_dev = try t.downloadPack(allocator, pack_dev.digest);
    defer allocator.free(dl_dev);
    try packfile.unpackInto(allocator, dl_dev, &clone_store);

    // Verify trees for both branches are correct
    var main_obj = try clone_store.get(allocator, main_commit.commit);
    defer main_obj.deinit(allocator);
    var main_tree = try clone_store.get(allocator, main_obj.commit.tree_hash);
    defer main_tree.deinit(allocator);
    try std.testing.expectEqualStrings("main.txt", main_tree.tree.entries[0].name);

    var dev_obj = try clone_store.get(allocator, dev_commit.commit);
    defer dev_obj.deinit(allocator);
    var dev_tree = try clone_store.get(allocator, dev_obj.commit.tree_hash);
    defer dev_tree.deinit(allocator);
    try std.testing.expectEqualStrings("dev.txt", dev_tree.tree.entries[0].name);
}

test "packfile content-addressed" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    // Create a commit
    const src = try makeSimpleCommit(
        allocator,
        &store,
        "same.txt",
        "same content",
        &[_]Hash{},
        "same commit",
    );

    // Pack the same commit twice
    const pack1 = try packfile.packReachable(allocator, &store, src.commit);
    defer allocator.free(pack1.bytes);
    const pack2 = try packfile.packReachable(allocator, &store, src.commit);
    defer allocator.free(pack2.bytes);

    // Same tree -> same packfile bytes -> same digest
    try std.testing.expectEqualSlices(u8, pack1.bytes, pack2.bytes);
    try std.testing.expectEqual(pack1.digest, pack2.digest);

    // Upload both — idempotent, should not error
    try t.uploadPack(allocator, pack1.bytes, pack1.digest);
    try t.uploadPack(allocator, pack2.bytes, pack2.digest);

    // Pack exists and matches
    try std.testing.expect(try t.packExists(allocator, pack1.digest));
}

test "remote ref overwrite" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var store = try store_mod.ObjectStore.init(std.testing.io, tmp.dir);
    defer store.close();

    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    // Commit A
    const a = try makeSimpleCommit(
        allocator,
        &store,
        "file.txt",
        "v1",
        &[_]Hash{},
        "commit A",
    );

    // Commit B (child of A)
    const b = try makeSimpleCommit(
        allocator,
        &store,
        "file.txt",
        "v2",
        &[_]Hash{a.commit},
        "commit B",
    );

    // Write ref to A
    try t.writeRef(allocator, "refs/heads/main", a.commit);
    const first = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(a.commit, first);

    // Overwrite ref to B
    try t.writeRef(allocator, "refs/heads/main", b.commit);
    const second = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(b.commit, second);

    // Verify only one ref entry for "refs/heads/main" exists
    const refs_list = try t.listRefs(allocator, "refs/heads/");
    defer {
        for (refs_list) |ref| allocator.free(ref.name);
        allocator.free(refs_list);
    }
    try std.testing.expectEqual(@as(usize, 1), refs_list.len);
    try std.testing.expectEqualStrings("main", refs_list[0].name);
    try std.testing.expectEqual(b.commit, refs_list[0].hash);
}

// ============================================================================
// Transport unit tests (via MemoryTransport)
// ============================================================================

test "transport download nonexistent pack" {
    const allocator = std.testing.allocator;
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const fake_digest = hash_mod.hash("nonexistent");
    try std.testing.expectError(error.PackNotFound, t.downloadPack(allocator, fake_digest));
}

test "transport list refs empty" {
    const allocator = std.testing.allocator;
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const refs_list = try t.listRefs(allocator, "refs/heads/");
    defer allocator.free(refs_list);
    try std.testing.expectEqual(@as(usize, 0), refs_list.len);
}

test "transport packExists false for missing" {
    const allocator = std.testing.allocator;
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    try std.testing.expect(!try t.packExists(allocator, hash_mod.zero));
}

test "push with pack companion for pull discovery" {
    const allocator = std.testing.allocator;

    // --- Source repo ---
    var src_tmp = std.testing.tmpDir(.{});
    defer src_tmp.cleanup();
    var src_store = try store_mod.ObjectStore.init(std.testing.io, src_tmp.dir);
    defer src_store.close();

    const src = try makeSimpleCommit(
        allocator,
        &src_store,
        "hello.txt",
        "hello world",
        &[_]Hash{},
        "initial commit",
    );

    const pack_result = try packfile.packReachable(allocator, &src_store, src.commit);
    defer allocator.free(pack_result.bytes);

    // --- Remote ---
    var mem = transport_memory.MemoryTransport.init(allocator);
    defer mem.deinit();
    const t = mem.transport();

    const commit_hex = hash_mod.toHex(src.commit);
    var pack_ref_buf: [256]u8 = undefined;
    const pack_ref_name = try std.fmt.bufPrint(&pack_ref_buf, "refs/heads/main.{s}.pack", .{&commit_hex});

    // Push: upload pack + publish commit-specific companion + write ref
    try t.uploadPack(allocator, pack_result.bytes, pack_result.digest);
    try t.writeRef(allocator, pack_ref_name, pack_result.digest);
    try t.writeRef(allocator, "refs/heads/main", src.commit);

    // --- Pull using companion ---
    // Read ref
    const remote_hash = (try t.readRef(allocator, "refs/heads/main")).?;
    try std.testing.expectEqual(src.commit, remote_hash);

    // Read commit-specific companion to discover pack digest
    const pack_digest = (try t.readRef(allocator, pack_ref_name)).?;
    try std.testing.expectEqual(pack_result.digest, pack_digest);

    // Download and unpack
    const pack_bytes = try t.downloadPack(allocator, pack_digest);
    defer allocator.free(pack_bytes);

    var dst_tmp = std.testing.tmpDir(.{});
    defer dst_tmp.cleanup();
    var dst_store = try store_mod.ObjectStore.init(std.testing.io, dst_tmp.dir);
    defer dst_store.close();

    try packfile.unpackInto(allocator, pack_bytes, &dst_store);

    // Verify all objects transferred
    try std.testing.expect(dst_store.exists(src.commit));
    try std.testing.expect(dst_store.exists(src.tree));
    try std.testing.expect(dst_store.exists(src.blob));
}
