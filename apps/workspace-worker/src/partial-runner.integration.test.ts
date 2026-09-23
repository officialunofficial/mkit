import { afterEach, describe, expect, it, vi } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { fromHex, hex, mkit } from "./mkit";
import { runAgent, type SessionSnapshot } from "./nanocodex";
import { getBlob, type ObjectStorage, type FileManifest } from "./objects";
import { importPartialBundle } from "./partial-source";
import { WorkspaceState } from "./workspace-state";
import { SandboxWorkspace } from "./sandbox-files";
import { runWorkspaceTask } from "./workspace-runner";
import type { WorkspaceTask } from "./contracts";

// Only the model and container transport are replaced. The runner, selected
// capture, descriptor-anchored Python helper, state and compiled wasm are real.
const sdk = vi.hoisted(() => ({ getSandbox: vi.fn() }));
vi.mock("@cloudflare/sandbox", () => ({ ...sdk, parseSSEStream: vi.fn() }));
vi.mock("./nanocodex", async () => ({
    runAgent: vi.fn(),
    GroqError: (await import("./groq/protocol")).GroqError,
}));
const execute = promisify(execFile);
const GOLDEN = fileURLToPath(new NodeURL("../../../rust/tests/golden/", import.meta.url));
const BUNDLE = new Uint8Array(readFileSync(`${GOLDEN}partial_workspace/plain_file.bin`));
const BASE = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
const PATHS = [["7368616c6c6f772e747874"]];
const DIGEST = mkit.blake3_hex(BUNDLE);
const context = {
    callId: "call",
    parentCallId: "",
    sessionId: "session",
    model: "model",
    signal: new AbortController().signal,
};
const directories: string[] = [];
afterEach(async () => {
    for (const directory of directories.splice(0)) await rm(directory, { recursive: true });
    vi.clearAllMocks();
});

class MemoryObjects implements ObjectStorage {
    readonly objects = new Map<string, Uint8Array>();
    afterPut?: (key: string) => void;
    afterGet?: (key: string) => void;
    async get(key: string) {
        const bytes = this.objects.get(key);
        this.afterGet?.(key);
        return bytes ? { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer } : null;
    }
    async put(key: string, bytes: Uint8Array) {
        this.objects.set(key, bytes.slice());
        this.afterPut?.(key);
    }
}

type MemoryStorage = {
    get(key: string): Promise<unknown>;
    put(writes: Record<string, unknown>): Promise<void>;
    transaction<T>(callback: (storage: MemoryStorage) => Promise<T>): Promise<T>;
};

async function harness() {
    const directory = await realpath(await mkdtemp(join(tmpdir(), "mkit-partial-runner-")));
    directories.push(directory);
    const root = join(directory, "project");
    const marker = join(directory, "generation");
    const objects = new MemoryObjects();
    const imported = await importPartialBundle("https://bundles.example", objects, "workspace", {
        kind: "partial-bundle", baseCommit: BASE, selectedPaths: PATHS, bundleDigest: DIGEST,
    }, async () => new Response(BUNDLE));
    const task: WorkspaceTask = { id: "task", status: "running", prompt: "edit selected", createdAt: 1 };
    const seed = "41".repeat(32);
    let now = 10;
    const data = new Map<string, unknown>([
        ["task", task], ["files", imported.files], ["generation", "one"], ["seed", seed],
        ["grant", { grant: { expiresAt: 100 } }],
        ["meta", { id: "workspace", head: null, updatedAt: 1,
            agentPublicKey: hex(mkit.ed25519_pubkey_from_seed(fromHex(seed))) }],
        ["partial", { mode: "public-partial-v1", baseCommit: BASE, selectedPaths: PATHS,
            bundleDigest: DIGEST, bundleKey: imported.bundleKey, original: imported.files }],
    ]);
    // External storage adapter: cloning matches Durable Object value semantics;
    // transaction rollback prevents a failed admission from leaking writes.
    const storage: MemoryStorage = {
        async get(key: string) { return structuredClone(data.get(key)); },
        async put(writes: Record<string, unknown>) {
            for (const [key, value] of Object.entries(writes)) data.set(key, structuredClone(value));
        },
        async transaction<T>(callback: (value: MemoryStorage) => Promise<T>): Promise<T> {
            const before = structuredClone(data);
            try { return await callback(storage); }
            catch (error) {
                data.clear();
                for (const [key, value] of before) data.set(key, value);
                throw error;
            }
        },
    };
    const state = new WorkspaceState(storage as unknown as DurableObjectStorage,
        objects as unknown as R2Bucket, () => now);
    const helperCalls: string[] = [];
    sdk.getSandbox.mockReturnValue({
        async exec(command: string) {
            helperCalls.push(command);
            try {
                const result = await execute("/bin/sh", ["-c", command
                    .replace("/usr/bin/python3", "python3")
                    .replaceAll("/workspace/project", root)
                    .replaceAll("/tmp/mkit-generation", marker)], { maxBuffer: 8 * 1024 * 1024 });
                return { ...result, exitCode: 0, success: true };
            } catch (error) {
                const failure = error as { stdout?: string; stderr?: string };
                return { stdout: failure.stdout ?? "", stderr: failure.stderr ?? "", exitCode: 1 };
            }
        },
    });
    const sandbox = new SandboxWorkspace({} as never, "workspace", objects);
    const publish = vi.fn();
    const env = { DIRECTORY: { getByName: () => ({ publish }) }, GROQ_API_KEY: "unused", GROQ_MODEL: "fixture" };
    const input = { state, sandbox, task, env: env as unknown as Env,
        serial: async <T>(fn: () => Promise<T>) => fn(), signal: new AbortController().signal };
    return { data, objects, root, state, input, publish, helperCalls, expire: () => { now = 100; } };
}

function answer(): Awaited<ReturnType<typeof runAgent>> {
    const snapshot: SessionSnapshot = { version: 1, model: "fixture", lineage_id: "lineage",
        prompt_cache_key: "cache", workspace: "/workspace/project", canonical_context: {}, history: [] };
    return { finalMessage: "done", snapshot, usage: { provider: "groq", model: "fixture",
        inputTokens: 0, outputTokens: 0, totalTokens: 0 } };
}

describe("partial task pipeline with real selected filesystem capture", () => {
    it("materializes, captures, signs and independently rebuilds the authenticated root", async () => {
        const h = await harness();
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.write_file.handler({ path: "shallow.txt", content: "runner replacement" }, context);
            return answer();
        });
        await runWorkspaceTask(h.input);
        const candidate = await h.state.candidate();
        expect(candidate).not.toBeNull();
        expect(h.data.get("task")).toMatchObject({ status: "completed", versionHash: candidate!.id });
        expect(h.helperCalls.some((call) => call.includes('"ignore":[]'))).toBe(true);
        const bytes = h.objects.objects.get(`objects/${candidate!.id}`)!;
        expect(mkit.commit_verify(bytes)).toBe(true);
        const commit = mkit.commit_decode(bytes);
        // Independent existing disclosure and Tree APIs, not partial-edit output:
        // all hidden sibling triples are retained from the authenticated root.
        const rootBytes = mkit.disclosure_payload_bytes(BASE,
            readFileSync(`${GOLDEN}disclosure/root_tree.bin`));
        const triples = JSON.parse(mkit.tree_decode(rootBytes)) as [string, string, string][];
        const replacement = mkit.blob_encode(new TextEncoder().encode("runner replacement"));
        const rebuilt = mkit.tree_encode(JSON.stringify(triples.map(([name, mode, id]) =>
            [name, mode, name === "shallow.txt" ? replacement.hash_hex : id])));
        try {
            expect(commit.parent_count).toBe(1);
            expect(commit.parent(0)).toBe(BASE);
            expect(commit.tree_hex).toBe(rebuilt.hash_hex);
            expect(candidate!.rootHex).toBe(rebuilt.hash_hex);
            const update = h.objects.objects.get(candidate!.key)!;
            expect(mkit.blake3_hex(update)).toBe(candidate!.digest);
            if (process.env.MKIT_PARTIAL_ORACLE_DIR)
                writeFileSync(join(process.env.MKIT_PARTIAL_ORACLE_DIR, "runner.mkwu"), update);
        } finally { commit.free(); replacement.free(); rebuilt.free(); }
        expect(h.publish).not.toHaveBeenCalled();
    });

    it("completes unchanged tasks without a signature, candidate or update artifact", async () => {
        const h = await harness();
        const originalKeys = [...h.objects.objects.keys()];
        vi.mocked(runAgent).mockResolvedValue(answer());
        await runWorkspaceTask(h.input);
        expect(h.data.get("task")).toMatchObject({ status: "completed" });
        expect((h.data.get("task") as WorkspaceTask).versionHash).toBeUndefined();
        expect(await h.state.candidate()).toBeNull();
        expect([...h.objects.objects.keys()]).toEqual(originalKeys);
        expect(h.publish).not.toHaveBeenCalled();
    });

    it("rejects ignored-name additions and retains the last coherent saved draft", async () => {
        const h = await harness();
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.write_file.handler({ path: "shallow.txt", content: "saved first" }, context);
            await mkdir(join(h.root, "target"));
            await writeFile(join(h.root, "target", "extra"), "unselected");
            return answer();
        });
        await runWorkspaceTask(h.input);
        expect(h.data.get("task")).toMatchObject({ status: "failed" });
        const files = h.data.get("files") as FileManifest;
        expect(Object.keys(files)).toEqual(["shallow.txt"]);
        expect(new TextDecoder().decode(await getBlob(h.objects, files["shallow.txt"]!.hash)))
            .toBe("saved first");
        expect(await h.state.candidate()).toBeNull();
        expect([...h.objects.objects.keys()].some((key) => key.includes("/update/"))).toBe(false);
    });

    it("rejects expired consent after the asynchronous bundle read without signing", async () => {
        const h = await harness();
        vi.mocked(runAgent).mockImplementation(async (options) => {
            await options.tools.write_file.handler({ path: "shallow.txt", content: "saved draft" }, context);
            return answer();
        });
        h.objects.afterGet = (key) => { if (key.includes("/bundle/")) h.expire(); };
        await runWorkspaceTask(h.input);
        expect(h.data.get("task")).toMatchObject({ status: "failed" });
        expect(await h.state.candidate()).toBeNull();
        expect([...h.objects.objects.keys()].some((key) => key.includes("/update/"))).toBe(false);
        // Base and draft storage contain Blobs only; no signed Commit was persisted.
        expect([...h.objects.objects.entries()].filter(([key]) => key.startsWith("objects/"))
            .every(([, bytes]) => { try { mkit.blob_decode(bytes); return true; } catch { return false; } }))
            .toBe(true);
    });

    for (const invalidation of ["expire", "revoke", "interrupted"] as const) {
        it(`does not admit a candidate after artifact persistence is ${invalidation}`, async () => {
            const h = await harness();
            vi.mocked(runAgent).mockImplementation(async (options) => {
                await options.tools.write_file.handler({ path: "shallow.txt", content: "saved draft" }, context);
                return answer();
            });
            h.objects.afterPut = (key) => {
                if (!key.includes("/update/")) return;
                if (invalidation === "expire") h.expire();
                else if (invalidation === "revoke") h.data.set("revoked", true);
                else throw new Error("interrupted after immutable write");
            };
            await runWorkspaceTask(h.input);
            expect(h.data.get("task")).toMatchObject({ status: "failed" });
            expect(await h.state.candidate()).toBeNull();
            expect(h.data.has("snapshot")).toBe(false);
            const files = h.data.get("files") as FileManifest;
            expect(new TextDecoder().decode(await getBlob(h.objects, files["shallow.txt"]!.hash)))
                .toBe("saved draft");
            // Immutable orphans are not durable readiness or successful completion.
            expect([...h.objects.objects.keys()].some((key) => key.includes("/update/"))).toBe(true);
            expect(h.publish).not.toHaveBeenCalled();
        });
    }
});
