import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import type { WorkspaceView } from "./contracts";

const sourceRoot = fileURLToPath(new NodeURL("./", import.meta.url));
let mf: Miniflare;

beforeAll(async () => {
    const bundle = await build({
        stdin: {
            resolveDir: sourceRoot,
            sourcefile: "workspace-state-harness.ts",
            loader: "ts",
            contents: `
      import { DurableObject } from 'cloudflare:workers';
      import { WorkspaceState } from './workspace-state';
      import { putBlob, loadTree, getBlob } from './objects';
      export class Harness extends DurableObject {
        constructor(ctx, env) { super(ctx, env); this.state = new WorkspaceState(ctx.storage, env.OBJECTS); }
        async fetch(request) {
          const input = await request.json();
          try {
            if (input.op === 'setup') { await this.ctx.storage.put(input.writes); return Response.json({ ok: true }); }
            if (input.op === 'apply') return await this.state.apply(input.auth, input.mutation);
            if (input.op === 'replay') return await this.state.replay(input.auth) ?? Response.json({ missing: true }, { status: 404 });
            if (input.op === 'view') return Response.json(await this.state.view(input.owner, input.version));
            if (input.op === 'files') return Response.json(await this.state.files(input.version));
            if (input.op === 'inspect') {
              const entries = await this.ctx.storage.list();
              return Response.json({ values: Object.fromEntries(entries), alarm: await this.ctx.storage.getAlarm() });
            }
            if (input.op === 'publish') {
              const bytes = new TextEncoder().encode(input.content);
              const hash = await putBlob(this.env.OBJECTS, bytes);
              const files = { [input.path]: { hash, size: bytes.length, mode: input.mode ?? 'blob' } };
              const mutation = await this.state.publishedVersion(files, input.message, input.remix);
              return await this.state.apply(input.auth, mutation);
            }
            if (input.op === 'roundtrip') {
              const version = await this.ctx.storage.get('version:' + input.version);
              const files = await loadTree(this.env.OBJECTS, version.treeHash);
              const content = {};
              for (const [path, file] of Object.entries(files)) content[path] = new TextDecoder().decode(await getBlob(this.env.OBJECTS, file.hash));
              return Response.json({ files, content, version });
            }
            throw new Error('Unknown test operation');
          } catch (error) { return Response.json({ error: error.message }, { status: error.status ?? 500 }); }
        }
        async alarm() {}
      }
      export default { fetch(request, env) {
        const id = env.STATE.idFromName(new URL(request.url).pathname);
        return env.STATE.get(id).fetch(request);
      } };
    `,
        },
        bundle: true,
        write: false,
        format: "esm",
        platform: "browser",
        target: "es2022",
        external: ["cloudflare:workers"],
        plugins: [
            {
                name: "mkit-wasm",
                setup(builder) {
                    builder.onResolve({ filter: /mkit_wasm_bg\.wasm$/ }, () => ({
                        path: "./mkit.wasm",
                        external: true,
                    }));
                },
            },
        ],
    });
    mf = new Miniflare(
        convertV4MiniflareOptions({
            name: "workspace-state-test",
            modulesRoot: "/",
            compatibilityDate: "2026-09-09",
            compatibilityFlags: ["nodejs_compat"],
            modules: [
                { type: "ESModule", path: "/state-test.mjs", contents: bundle.outputFiles[0].text },
                {
                    type: "CompiledWasm",
                    path: "/mkit.wasm",
                    contents: readFileSync(
                        fileURLToPath(
                            new NodeURL("../vendor/mkit-wasm/mkit_wasm_bg.wasm", import.meta.url),
                        ),
                    ),
                },
            ],
            durableObjects: { STATE: { className: "Harness", useSQLite: true } },
            r2Buckets: ["OBJECTS"],
        }),
    );
    await mf.ready;
}, 30_000);

afterAll(async () => {
    await mf?.dispose();
});

const hash = (character: string) => character.repeat(64);
const auth = (nonce: string, digest = "d") => ({
    publicKey: hash("1"),
    nonce: hash(nonce),
    digest: hash(digest),
    expiresAt: Date.now() + 60_000,
    body: {},
});
const summary = (id: string) => ({
    id,
    title: "Demo remix",
    ownerPublicKey: hash("1"),
    agentPublicKey: hash("2"),
    source: { kind: "demo", repository: "demo-repository", commitHash: hash("3"), ref: "main" },
    head: null,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    public: true,
});
async function request(id: string, input: Record<string, unknown>) {
    return mf.dispatchFetch(`http://localhost/${id}`, {
        method: "POST",
        body: JSON.stringify(input),
    });
}
async function setup(extra: Record<string, unknown> = {}) {
    const id = crypto.randomUUID();
    const meta = summary(id);
    const result = await request(id, {
        op: "setup",
        writes: { meta, files: {}, seed: hash("4"), activated: true, ...extra },
    });
    expect(result.status).toBe(200);
    return { id, meta };
}

describe("WorkspaceState on transactional SQLite Durable Object storage", () => {
    it("rolls back mutable writes, deletes, alarm and receipt when the transaction cannot produce a view", async () => {
        const { id, meta } = await setup({ draftMarker: "keep" });
        const result = await request(id, {
            op: "apply",
            auth: auth("a"),
            mutation: {
                writes: {
                    meta: { ...meta, title: "Must roll back" },
                    draftMarker: "replace",
                    temporary: "discard",
                },
                deletes: ["files"],
                alarm: Date.now() + 3_600_000,
            },
        });
        expect(result.status).toBe(404);
        const inspection = (await (await request(id, { op: "inspect" })).json()) as {
            values: Record<string, unknown>;
            alarm: number | null;
        };
        expect(inspection.values.meta).toEqual(meta);
        expect(inspection.values.files).toEqual({});
        expect(inspection.values.draftMarker).toBe("keep");
        expect(inspection.values).not.toHaveProperty("temporary");
        expect(Object.keys(inspection.values).some((key) => key.startsWith("receipt:"))).toBe(
            false,
        );
        expect(inspection.alarm).toBeNull();
        expect((await request(id, { op: "replay", auth: auth("a") })).status).toBe(404);
    });

    it("commits mutations with their replay receipt and does not repeat same-digest operations", async () => {
        const { id, meta } = await setup({ obsolete: "delete me" });
        const alarm = Date.now() + 3_600_000;
        const first = await request(id, {
            op: "apply",
            auth: auth("a"),
            mutation: {
                writes: {
                    meta: { ...meta, title: "Saved title" },
                    "message:0000000000001:first": {
                        id: "first",
                        role: "user",
                        text: "Only once",
                        createdAt: 1,
                    },
                },
                deletes: ["obsolete"],
                alarm,
                headers: { "X-Operation": "first" },
            },
        });
        expect(first.status).toBe(200);
        expect(first.headers.get("x-operation")).toBe("first");
        const body = (await first.json()) as WorkspaceView;
        const duplicate = await request(id, {
            op: "apply",
            auth: auth("a"),
            mutation: {
                writes: {
                    meta: { ...meta, title: "Should never be written" },
                    "message:0000000000002:duplicate": {
                        id: "duplicate",
                        role: "user",
                        text: "Wrong",
                        createdAt: 2,
                    },
                },
                alarm: alarm + 60_000,
            },
        });
        expect(duplicate.status).toBe(200);
        expect(await duplicate.json()).toEqual(body);
        expect(duplicate.headers.get("x-operation")).toBe("first");
        const replay = await request(id, { op: "replay", auth: auth("a") });
        expect(await replay.json()).toEqual(body);
        const inspection = (await (await request(id, { op: "inspect" })).json()) as {
            values: Record<string, unknown>;
            alarm: number;
        };
        expect(inspection.values.meta).toMatchObject({ title: "Saved title" });
        expect(inspection.values).not.toHaveProperty("obsolete");
        expect(
            Object.keys(inspection.values).filter((key) => key.startsWith("message:")),
        ).toHaveLength(1);
        expect(
            Object.keys(inspection.values).filter((key) => key.startsWith("receipt:")),
        ).toHaveLength(1);
        expect(inspection.alarm).toBe(alarm);
    });

    it("rejects reuse of the nonce with a different digest in both apply and replay", async () => {
        const { id, meta } = await setup();
        expect(
            (
                await request(id, {
                    op: "apply",
                    auth: auth("a"),
                    mutation: { writes: { meta: { ...meta, title: "Original" } } },
                })
            ).status,
        ).toBe(200);
        expect(
            (
                await request(id, {
                    op: "apply",
                    auth: auth("a", "e"),
                    mutation: { writes: { meta: { ...meta, title: "Attack" } } },
                })
            ).status,
        ).toBe(409);
        expect((await request(id, { op: "replay", auth: auth("a", "e") })).status).toBe(409);
        expect(await (await request(id, { op: "view", owner: true })).json()).toMatchObject({
            workspace: { title: "Original" },
        });
    });

    it("exposes public project state without owner conversation or running-task details", async () => {
        const task = { id: "task", prompt: "Private prompt", status: "running", createdAt: 1 };
        const message = {
            id: "message",
            role: "assistant",
            text: "Private conversation",
            createdAt: 1,
        };
        const { id } = await setup({ task, "message:0000000000001:message": message });
        const publicView = (await (
            await request(id, { op: "view", owner: false })
        ).json()) as WorkspaceView;
        expect(publicView).toMatchObject({ isOwner: false, messages: [], task: null });
        expect(JSON.stringify(publicView)).not.toContain("Private");
        const ownerView = (await (
            await request(id, { op: "view", owner: true })
        ).json()) as WorkspaceView;
        expect(ownerView).toMatchObject({ isOwner: true, messages: [message], task });
        expect(publicView.files).toEqual(ownerView.files);
        expect(publicView.workspace).toEqual(ownerView.workspace);
    });

    it("round-trips immutable manifests and signed versions while advancing the current head", async () => {
        const { id } = await setup();
        const initial = await request(id, {
            op: "publish",
            auth: auth("a"),
            path: "src/hello.txt",
            content: "Hello 🌱",
            mode: "exec",
            message: "Remix demo",
            remix: true,
        });
        expect(initial.status).toBe(200);
        const first = (await initial.json()) as WorkspaceView;
        const firstHash = first.workspace.head!;
        const updated = await request(id, {
            op: "publish",
            auth: auth("b"),
            path: "src/hello.txt",
            content: "Second version",
            mode: "blob",
            message: "Update greeting",
        });
        expect(updated.status).toBe(200);
        const second = (await updated.json()) as WorkspaceView;
        const secondHash = second.workspace.head!;
        expect(secondHash).not.toBe(firstHash);
        expect(second.versions).toHaveLength(2);
        expect(second.versions[0]).toMatchObject({
            hash: secondHash,
            parent: firstHash,
            message: "Update greeting",
        });
        const old = (await (
            await request(id, { op: "view", owner: false, version: firstHash })
        ).json()) as WorkspaceView;
        expect(old.files).toEqual([
            {
                path: "src/hello.txt",
                hash: first.files[0].hash,
                size: new TextEncoder().encode("Hello 🌱").length,
                mode: "exec",
            },
        ]);
        expect(old.workspace.head).toBe(secondHash);
        const firstObjects = (await (
            await request(id, { op: "roundtrip", version: firstHash })
        ).json()) as { files: unknown; content: unknown; version: unknown };
        expect(firstObjects.content).toEqual({ "src/hello.txt": "Hello 🌱" });
        expect(firstObjects.version).toMatchObject({
            hash: firstHash,
            parent: null,
            message: "Remix demo",
        });
        expect(await (await request(id, { op: "files", version: firstHash })).json()).toEqual(
            firstObjects.files,
        );
        const currentObjects = (await (
            await request(id, { op: "roundtrip", version: secondHash })
        ).json()) as { files: unknown; content: unknown };
        expect(currentObjects.content).toEqual({ "src/hello.txt": "Second version" });
        expect(await (await request(id, { op: "files" })).json()).toEqual(currentObjects.files);
    });

    it("can apply and replay an ordinary mutation after a long owner conversation", async () => {
        const messages = Object.fromEntries(
            Array.from({ length: 60 }, (_, index) => [
                `message:${String(index).padStart(13, "0")}:${index}`,
                {
                    id: String(index),
                    role: "assistant",
                    text: "漢".repeat(12_000),
                    createdAt: index,
                },
            ]),
        );
        const files = Object.fromEntries(
            Array.from({ length: 256 }, (_, index) => [
                `${"a".repeat(240)}/${"b".repeat(240)}/${"c".repeat(240)}/${index}-${"d".repeat(230)}`,
                { hash: hash("5"), size: 1, mode: "blob" },
            ]),
        );
        const history = Object.fromEntries(
            Array.from({ length: 50 }, (_, index) => [
                `history:${String(index).padStart(13, "0")}:${index}`,
                {
                    hash: String(index).padStart(64, "0"),
                    treeHash: hash("6"),
                    parent: null,
                    message: "y".repeat(4096),
                    signer: hash("2"),
                    createdAt: index,
                },
            ]),
        );
        const { id, meta } = await setup({ ...messages, ...history, files });
        const result = await request(id, {
            op: "apply",
            auth: auth("a"),
            mutation: { writes: { meta: { ...meta, title: "Still editable" } } },
        });
        if (result.status !== 200) throw new Error(await result.text());
        const body = (await result.json()) as WorkspaceView;
        expect(body.workspace.title).toBe("Still editable");
        expect(body.messages).toHaveLength(60);
        expect(body.files).toHaveLength(256);
        expect(body.versions).toHaveLength(50);
        expect(new TextEncoder().encode(JSON.stringify(body)).length).toBeGreaterThan(
            2 * 1024 * 1024,
        );
        const replay = await request(id, { op: "replay", auth: auth("a") });
        expect(replay.status).toBe(200);
        expect(await replay.json()).toEqual(body);
        const inspection = (await (await request(id, { op: "inspect" })).json()) as {
            values: Record<string, unknown>;
        };
        const receipt = inspection.values[`receipt:${hash("a")}`] as {
            parts: number;
            body?: unknown;
        };
        expect(receipt.body).toBeUndefined();
        expect(receipt.parts).toBeGreaterThan(1);
        const parts = Object.entries(inspection.values).filter(([key]) =>
            key.startsWith(`receipt-part:${hash("a")}:`),
        );
        expect(parts).toHaveLength(receipt.parts);
        for (const [, part] of parts) expect(String(part).length).toBeLessThanOrEqual(32 * 1024);
    });

    it("fails oversized replay responses atomically and leaves no partial receipt", async () => {
        const messages = Object.fromEntries(
            Array.from({ length: 60 }, (_, index) => [
                `message:${String(index).padStart(13, "0")}:${index}`,
                {
                    id: String(index),
                    role: "assistant",
                    text: "x".repeat(40_000),
                    createdAt: index,
                },
            ]),
        );
        const { id, meta } = await setup(messages);
        const result = await request(id, {
            op: "apply",
            auth: auth("a"),
            mutation: { writes: { meta: { ...meta, title: "Must roll back" } } },
        });
        expect(result.status).toBe(413);
        const inspection = (await (await request(id, { op: "inspect" })).json()) as {
            values: Record<string, unknown>;
        };
        expect(inspection.values.meta).toEqual(meta);
        expect(
            Object.keys(inspection.values).some(
                (key) => key.startsWith("receipt:") || key.startsWith("receipt-part:"),
            ),
        ).toBe(false);
    });

    it("continues to replay inline receipts written before chunking was introduced", async () => {
        const { id } = await setup();
        const body = await (await request(id, { op: "view", owner: true })).json();
        const operation = auth("a");
        await request(id, {
            op: "setup",
            writes: {
                [`receipt:${operation.nonce}`]: {
                    digest: operation.digest,
                    body,
                    headers: { "X-Operation": "legacy" },
                },
            },
        });
        const replay = await request(id, { op: "replay", auth: operation });
        expect(replay.status).toBe(200);
        expect(replay.headers.get("x-operation")).toBe("legacy");
        expect(await replay.json()).toEqual(body);
    });
});
