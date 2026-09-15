import { gzipSync } from "node:zlib";
import { describe, expect, it, vi } from "vitest";
import { importDemo } from "./source";
import {
    buildTree,
    getBlob,
    makeVersion,
    mkit,
    objectKey,
    putBlob,
    MAX_FILE_BYTES,
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

function repository(objects: MemoryObjects, head: string, compressed = false) {
    return {
        fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            const url =
                typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
            expect(url).toMatch(
                /^https:\/\/api\.mkit\.sh\/mkit\.repo\.v1\.RepoService\/(GetRef|GetObject)$/,
            );
            expect(init?.method).toBe("POST");
            const body = JSON.parse(String(init?.body)) as {
                room: string;
                objectId?: string;
                name?: string;
            };
            expect(body.room).toBe("lobby-v2");
            let result: object;
            if (url.endsWith("/GetRef")) {
                expect(body.name).toBe("main");
                result = { exists: true, objectId: Buffer.from(head, "hex").toString("base64") };
            } else {
                const hash = Buffer.from(body.objectId!, "base64").toString("hex");
                const bytes = objects.objects.get(objectKey(hash));
                result = bytes
                    ? { found: true, bytes: Buffer.from(bytes).toString("base64") }
                    : { found: false };
            }
            const json = JSON.stringify(result);
            return compressed
                ? new Response(new Uint8Array(gzipSync(json)).buffer)
                : Response.json(result);
        }),
    };
}

async function fixture() {
    const upstream = new MemoryObjects();
    const bytes = new Uint8Array([0, 128, 255, 32]);
    const hash = await putBlob(upstream, bytes);
    const manifest = { "src/file.bin": { hash, size: bytes.length, mode: "blob" as const } };
    const version = await makeVersion(upstream, {
        manifest,
        seedHex: "01".repeat(32),
        message: "demo",
    });
    return { upstream, manifest, version, bytes };
}

describe("demo repository import", () => {
    it("imports a file at the full 256 KiB limit", async () => {
        const upstream = new MemoryObjects();
        const bytes = new Uint8Array(MAX_FILE_BYTES).fill(255);
        const hash = await putBlob(upstream, bytes);
        const manifest = { "large.bin": { hash, size: bytes.length, mode: "blob" as const } };
        const version = await makeVersion(upstream, {
            manifest,
            seedHex: "01".repeat(32),
            message: "large file",
        });
        const target = new MemoryObjects();
        expect((await importDemo(repository(upstream, version.hash), target)).files).toEqual(
            manifest,
        );
        expect(await getBlob(target, hash)).toEqual(bytes);
    });

    it.each([false, true])(
        "imports a pinned, signed canonical tree with gzip=%s",
        async (compressed) => {
            const { upstream, manifest, version, bytes } = await fixture();
            const target = new MemoryObjects();
            const api = repository(upstream, version.hash, compressed);
            const result = await importDemo(api, target, {});
            expect(result.source).toEqual({
                kind: "demo",
                repository: "lobby-v2",
                ref: "main",
                commitHash: version.hash,
            });
            expect(result.files).toEqual(manifest);
            expect(await getBlob(target, manifest["src/file.bin"].hash)).toEqual(bytes);
            expect(target.objects.get(objectKey(version.hash))).toEqual(
                upstream.objects.get(objectKey(version.hash)),
            );
        },
    );

    it("does not reread a ref when a commit hash is explicitly pinned", async () => {
        const { upstream, version } = await fixture();
        const api = repository(upstream, version.hash);
        await importDemo(api, new MemoryObjects(), { commitHash: version.hash });
        expect(api.fetch.mock.calls.some(([input]) => String(input).endsWith("/GetRef"))).toBe(
            false,
        );
    });

    it("imports a signed remix as the source version", async () => {
        const { upstream, manifest, version } = await fixture();
        const remix = await makeVersion(upstream, {
            manifest,
            seedHex: "02".repeat(32),
            message: "upstream remix",
            source: { kind: "demo", repository: "lobby-v2", commitHash: version.hash },
        });
        const imported = await importDemo(repository(upstream, remix.hash), new MemoryObjects());
        expect(imported.source.commitHash).toBe(remix.hash);
        expect(imported.files).toEqual(manifest);
    });

    it("rejects a substituted valid commit instead of importing it under the requested ID", async () => {
        const { upstream, version } = await fixture();
        const other = await makeVersion(upstream, {
            manifest: {},
            seedHex: "01".repeat(32),
            message: "different",
        });
        upstream.objects.set(objectKey(version.hash), upstream.objects.get(objectKey(other.hash))!);
        const target = new MemoryObjects();
        await expect(importDemo(repository(upstream, version.hash), target)).rejects.toThrow(
            "requested hash",
        );
        expect(target.objects.size).toBe(0);
    });

    it("rejects an invalid signature even when the requested hash matches the malformed signed object", async () => {
        const { upstream, version } = await fixture();
        const bytes = upstream.objects.get(objectKey(version.hash))!.slice();
        bytes[bytes.length - 1] ^= 1;
        const badHash = mkit.object_id(bytes);
        upstream.objects.set(objectKey(badHash), bytes);
        await expect(
            importDemo(repository(upstream, badHash), new MemoryObjects()),
        ).rejects.toThrow("valid signed");
    });

    it("rejects a substituted blob even with a correctly signed source commit", async () => {
        const { upstream, version, manifest } = await fixture();
        const other = mkit.blob_encode(new Uint8Array([3]));
        upstream.objects.set(objectKey(manifest["src/file.bin"].hash), other.bytes);
        other.free();
        await expect(
            importDemo(repository(upstream, version.hash), new MemoryObjects()),
        ).rejects.toThrow("requested hash");
    });

    it("repairs only the missing canonical empty tree without inventing starter files", async () => {
        const upstream = new MemoryObjects();
        const version = await makeVersion(upstream, {
            manifest: {},
            seedHex: "01".repeat(32),
            message: "empty demo",
        });
        upstream.objects.delete(objectKey(version.treeHash));
        const target = new MemoryObjects();
        const result = await importDemo(repository(upstream, version.hash), target);
        expect(Object.keys(result.files)).toEqual([]);
        expect(await buildTree(target, {})).toBe(version.treeHash);
        const { upstream: nonempty, version: populated } = await fixture();
        nonempty.objects.delete(objectKey(populated.treeHash));
        await expect(
            importDemo(repository(nonempty, populated.hash), new MemoryObjects()),
        ).rejects.toThrow("Missing demo object");
    });

    it("rejects oversized compressed responses after decompression", async () => {
        const body = new Uint8Array(gzipSync(" ".repeat(800 * 1024))).buffer;
        const api = { fetch: vi.fn(async () => new Response(body)) };
        await expect(importDemo(api, new MemoryObjects())).rejects.toThrow("response exceeds");
    });
});
