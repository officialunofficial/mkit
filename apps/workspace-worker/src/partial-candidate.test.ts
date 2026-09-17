import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { describe, expect, it } from "vitest";
import { fromHex, hex, mkit } from "./mkit";
import { putBlob, type ObjectStorage } from "./objects";
import { createPartialCandidate } from "./partial-candidate";
import { importPartialBundle } from "./partial-source";

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

describe("partial candidate export", () => {
    async function imported(storage = new MemoryObjects()) {
        return {
            storage,
            imported: await importPartialBundle(
                "https://bundles.example",
                storage,
                "ab".repeat(16),
                {
                    kind: "partial-bundle",
                    baseCommit: BASE,
                    selectedPaths: PATHS,
                    bundleDigest: DIGEST,
                },
                async () => new Response(PLAIN, { status: 200 }),
            ),
        };
    }

    it("reports no_changes when selected bytes are unchanged", async () => {
        const { storage, imported: value } = await imported();
        const result = await createPartialCandidate({
            workspaceId: "ab".repeat(16),
            objects: storage,
            bundle: PLAIN,
            baseCommit: BASE,
            selectedPaths: PATHS,
            original: value.files,
            current: value.files,
            seedHex: "41".repeat(32),
            agentPublicKey: hex(mkit.ed25519_pubkey_from_seed(Uint8Array.from({ length: 32 }, () => 0x41))),
            message: "save",
        });
        expect(result.status).toBe("no_changes");
    });

    it("signs an ordinary candidate parenting the supplied base", async () => {
        const { storage, imported: value } = await imported();
        const next = new TextEncoder().encode("wasm parity");
        const current = {
            "shallow.txt": {
                hash: await putBlob(storage, next),
                size: next.length,
                mode: "blob" as const,
            },
        };
        const seedHex = "41".repeat(32);
        const result = await createPartialCandidate({
            workspaceId: "ab".repeat(16),
            objects: storage,
            bundle: PLAIN,
            baseCommit: BASE,
            selectedPaths: PATHS,
            original: value.files,
            current,
            seedHex,
            agentPublicKey: hex(mkit.ed25519_pubkey_from_seed(fromHex(seedHex))),
            message: "partial edit",
        });
        expect(result.status).toBe("ready");
        if (result.status !== "ready") return;
        expect(result.candidate.baseCommit).toBe(BASE);
        expect(result.candidate.coverage).toBe("selected-only");
        expect(result.candidate.id).toMatch(/^[0-9a-f]{64}$/);
        const update = storage.objects.get(result.candidate.key);
        expect(update?.byteLength).toBeGreaterThan(32);
        expect(mkit.blake3_hex(update!)).toBe(result.candidate.digest);
    });
});
