import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { describe, expect, it, vi } from "vitest";
import { CONSUMER_BUNDLE_BYTES } from "./partial-wasm";
import {
    bundleObjectUrl,
    fetchPublicBundle,
    importPartialBundle,
    trustedBundleOrigin,
    validatePartialPrepare,
} from "./partial-source";
import { mkit } from "./mkit";
import type { ObjectStorage } from "./objects";

const GOLDEN = fileURLToPath(new NodeURL("../../../rust/tests/golden/partial_workspace/", import.meta.url));
const PLAIN = new Uint8Array(readFileSync(`${GOLDEN}plain_file.bin`));
const BASE = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
const PATHS = [["7368616c6c6f772e747874"]];
const DIGEST = mkit.blake3_hex(PLAIN);

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

describe("public partial bundle origin and prepare", () => {
    it("accepts a trusted HTTPS origin and rejects credentials, query, and http", () => {
        expect(trustedBundleOrigin(undefined)).toBeUndefined();
        expect(trustedBundleOrigin("https://bundles.example")).toBe("https://bundles.example");
        expect(() => trustedBundleOrigin("http://bundles.example")).toThrow(/HTTPS/);
        expect(() => trustedBundleOrigin("https://user:pass@bundles.example")).toThrow(/credentials/);
        expect(() => trustedBundleOrigin("https://bundles.example/?q=1")).toThrow(/query/);
        expect(() => trustedBundleOrigin("https://bundles.example/path")).toThrow(/path/);
    });

    it("rejects malformed selections before import", () => {
        expect(() =>
            validatePartialPrepare({
                kind: "partial-bundle",
                baseCommit: BASE,
                selectedPaths: PATHS.slice().reverse(),
                bundleDigest: DIGEST,
                extra: true,
            }),
        ).toThrow(/Unknown/);
        expect(() =>
            validatePartialPrepare({
                kind: "partial-bundle",
                baseCommit: BASE,
                selectedPaths: [PATHS[0], PATHS[0]],
                bundleDigest: DIGEST,
            }),
        ).toThrow(/ordered/);
        expect(() =>
            validatePartialPrepare({
                kind: "partial-bundle",
                baseCommit: "AA".repeat(32),
                selectedPaths: PATHS,
                bundleDigest: DIGEST,
            }),
        ).toThrow(/base commit/);
    });

    it("fetches only the digest URL without owner credentials and bounds size", async () => {
        const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            expect(String(input)).toBe(bundleObjectUrl("https://bundles.example", DIGEST));
            expect(init?.redirect).toBe("error");
            expect(JSON.stringify(init?.headers ?? {})).not.toMatch(/authorization/i);
            return new Response(PLAIN, { status: 200 });
        });
        await expect(fetchPublicBundle("https://bundles.example", DIGEST, fetcher)).resolves.toEqual(
            PLAIN,
        );
        const oversized = new Uint8Array(CONSUMER_BUNDLE_BYTES + 1);
        const big = vi.fn(async () => new Response(oversized, { status: 200 }));
        await expect(fetchPublicBundle("https://bundles.example", DIGEST, big)).rejects.toThrow(
            /too large/,
        );
        const redirect = vi.fn(async () => {
            throw new TypeError("redirect");
        });
        await expect(fetchPublicBundle("https://bundles.example", DIGEST, redirect)).rejects.toThrow(
            /redirect/,
        );
    });

    it("imports selected files through wasm without repository object URLs", async () => {
        const storage = new MemoryObjects();
        const fetcher = vi.fn(async (input: RequestInfo | URL) => {
            expect(String(input)).not.toMatch(/GetObject|GetRef|api\.mkit\.sh/);
            return new Response(PLAIN, { status: 200 });
        });
        const imported = await importPartialBundle(
            "https://bundles.example",
            storage,
            "ab".repeat(16),
            {
                kind: "partial-bundle",
                baseCommit: BASE,
                selectedPaths: PATHS,
                bundleDigest: DIGEST,
            },
            fetcher,
        );
        expect(imported.source.kind).toBe("partial-bundle");
        expect(imported.source.mode).toBe("public-partial-v1");
        expect(imported.files["shallow.txt"]?.mode).toBe("blob");
        expect(storage.objects.has(imported.bundleKey)).toBe(true);
        expect(fetcher).toHaveBeenCalledOnce();
    });

    it("rejects a corrupted digest before activating storage", async () => {
        const storage = new MemoryObjects();
        const fetcher = vi.fn(async () => new Response(PLAIN, { status: 200 }));
        await expect(
            importPartialBundle(
                "https://bundles.example",
                storage,
                "ab".repeat(16),
                {
                    kind: "partial-bundle",
                    baseCommit: BASE,
                    selectedPaths: PATHS,
                    bundleDigest: "ff".repeat(32),
                },
                fetcher,
            ),
        ).rejects.toThrow(/digest/);
        expect(storage.objects.size).toBe(0);
    });
});
