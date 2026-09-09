import { describe, expect, it } from "vitest";
import {
    buildTree,
    getBlob,
    getObject,
    loadTree,
    makeVersion,
    mkit,
    objectKey,
    putBlob,
    putObject,
    validateManifest,
    validatePath,
    MAX_FILE_BYTES,
    MAX_TOTAL_BYTES,
    type FileManifest,
    type ObjectStorage,
} from "./objects";

class MemoryObjects implements ObjectStorage {
    readonly objects = new Map<string, Uint8Array>();
    async get(key: string) {
        const value = this.objects.get(key);
        return value
            ? { size: value.length, arrayBuffer: async () => new Uint8Array(value).buffer }
            : null;
    }
    async put(key: string, value: Uint8Array) {
        this.objects.set(key, value.slice());
    }
}

describe("canonical workspace objects", () => {
    it("round-trips binary blobs and nested executable files with native Merkle tree IDs", async () => {
        const store = new MemoryObjects();
        const binary = new Uint8Array([0, 255, 128, 10]);
        const hash = await putBlob(store, binary);
        const files: FileManifest = {
            "src/run.sh": { hash, size: binary.length, mode: "exec" },
            __proto__: { hash, size: binary.length, mode: "blob" },
        };
        // An own __proto__ entry must survive without mutating the manifest object.
        Object.defineProperty(files, "__proto__", {
            value: { hash, size: binary.length, mode: "blob" },
            enumerable: true,
        });
        const treeHash = await buildTree(store, files);
        const treeBytes = await getObject(store, treeHash);
        expect(mkit.object_id(treeBytes)).toBe(treeHash);
        expect(mkit.blake3_hex(treeBytes)).not.toBe(treeHash);
        const loaded = await loadTree(store, treeHash);
        expect(loaded).toEqual(files);
        expect(Object.getPrototypeOf(loaded)).toBeNull();
        expect(await getBlob(store, loaded["src/run.sh"].hash)).toEqual(binary);
    });

    it("rejects valid substituted blobs and malformed bytes under a requested key", async () => {
        const store = new MemoryObjects();
        const hash = await putBlob(store, new Uint8Array([1]));
        const different = mkit.blob_encode(new Uint8Array([2]));
        store.objects.set(objectKey(hash), different.bytes);
        different.free();
        await expect(getBlob(store, hash)).rejects.toThrow("requested hash");
        store.objects.set(objectKey(hash), new Uint8Array([1, 2]));
        await expect(getBlob(store, hash)).rejects.toThrow();
    });

    it("rejects a non-blob object even when its hash is correct", async () => {
        const store = new MemoryObjects();
        const hash = await buildTree(store, {});
        await expect(getBlob(store, hash)).rejects.toThrow("not a blob");
    });

    it.each([
        "../escape",
        "/absolute",
        "a//b",
        "a/./b",
        "a\\b",
        ".mkit/config",
        "a/.GiT/config",
        "bad\nname",
        "a\u0000b",
        "a\u0085b",
        "a/CON",
        "trailing.",
        "\ud800",
    ])("rejects unsafe path %j", (path) => {
        expect(() => validatePath(path)).toThrow();
    });

    it("rejects file/directory collisions, oversized manifests, and false sizes before publishing a tree", async () => {
        const store = new MemoryObjects();
        const hash = await putBlob(store, new Uint8Array([1]));
        const file = { hash, size: 1, mode: "blob" as const };
        await expect(buildTree(store, { a: file, "a/b": file })).rejects.toThrow("conflicts");
        await expect(buildTree(store, { a: { ...file, size: 0 } })).rejects.toThrow(
            "size mismatch",
        );
        expect(store.objects.size).toBe(1);
        expect(() =>
            validateManifest(
                Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`f${i}`, file])),
            ),
        ).toThrow("256 files");
        expect(() =>
            validateManifest(
                Object.fromEntries(
                    Array.from({ length: MAX_TOTAL_BYTES / MAX_FILE_BYTES + 1 }, (_, i) => [
                        `f${i}`,
                        { ...file, size: MAX_FILE_BYTES },
                    ]),
                ),
            ),
        ).toThrow("4 MiB");
        await expect(putBlob(store, new Uint8Array(MAX_FILE_BYTES + 1))).rejects.toThrow("256 KiB");
    });

    it("rejects symlinks without following their target", async () => {
        const store = new MemoryObjects();
        const target = "1".repeat(64);
        const tree = mkit.tree_encode(JSON.stringify([["link", "symlink", target]]));
        const hash = await putObject(store, tree.bytes);
        tree.free();
        await expect(loadTree(store, hash)).rejects.toThrow("Symlinks");
    });

    it("writes signed source remixes then signed commits with their own ancestry", async () => {
        const store = new MemoryObjects();
        const seedHex = "01".repeat(32);
        const hash = await putBlob(store, new TextEncoder().encode("hello"));
        const manifest: FileManifest = { "hello.txt": { hash, size: 5, mode: "blob" } };
        const source = {
            kind: "demo" as const,
            repository: "lobby-v2",
            ref: "main",
            commitHash: "02".repeat(32),
        };
        const first = await makeVersion(store, {
            manifest,
            seedHex,
            message: "Remix demo",
            source,
        });
        const firstBytes = await getObject(store, first.hash);
        expect(mkit.remix_verify(firstBytes)).toBe(true);
        const decoded = mkit.remix_decode(firstBytes);
        try {
            expect(decoded.tree_hex).toBe(first.treeHash);
            expect(decoded.parent_count).toBe(0);
            const upstream = decoded.source(0)!;
            try {
                expect(upstream.commit_hash_hex).toBe(source.commitHash);
            } finally {
                upstream.free();
            }
        } finally {
            decoded.free();
        }
        const second = await makeVersion(store, {
            manifest,
            seedHex,
            message: "Finish task",
            parent: first.hash,
        });
        const nextBytes = await getObject(store, second.hash);
        expect(mkit.commit_verify(nextBytes)).toBe(true);
        const next = mkit.commit_decode(nextBytes);
        try {
            expect(next.parent(0)).toBe(first.hash);
            expect(next.signer_hex).toBe(first.signer);
            expect(next.message).toBe("Finish task");
        } finally {
            next.free();
        }
        expect(await loadTree(store, second.treeHash)).toEqual(manifest);
    });
});
