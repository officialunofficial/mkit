import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { encoder, fromHex, hex, mkit } from "./mkit";
import { grantMessage, type PreparedWorkspace, type WorkspaceView } from "./contracts";
import { putBlob, type FileManifest } from "./objects";

const ROOT = fileURLToPath(new NodeURL("./", import.meta.url));
const AUDIENCE = "https://mkit.sh";
let mf: Miniflare;

beforeAll(async () => {
    const mocks: Record<string, string> = {
        source: `
      import { putBlob } from ${JSON.stringify(`${ROOT}objects.ts`)};
      export async function importDemo(repository, objects) {
        const bytes = new TextEncoder().encode('# Demo project\\n');
        const files = Object.create(null);
        files['README.md'] = { hash: await putBlob(objects, bytes), size: bytes.length, mode: 'blob' };
        return { source: { kind: 'demo', repository: 'demo', commitHash: '0'.repeat(64), ref: 'main' }, files };
      }
    `,
        "sandbox-files": `
      export class SandboxWorkspace {
        files = {}; generation = ''; stopped = false;
        constructor(namespace, id, objects) { this.id = id; this.objects = objects; }
        async ensure(files, generation) { this.files = files; this.generation = generation; }
        async capture(generation) {
          if (generation !== this.generation) throw new Error('Stale generation');
          const pending = await this.objects.get('test/terminal-files/' + this.id);
          return pending ? await pending.json() : this.files;
        }
        async terminal() {
          const pair = new WebSocketPair(); pair[1].accept();
          pair[1].addEventListener('message', event => pair[1].send(event.data));
          return new Response(null, { status: 101, webSocket: pair[0] });
        }
        async stopTerminal() {
          this.stopped = true;
          await this.objects.put('test/terminal-stopped/' + this.id, 'yes');
          if (await this.objects.get('test/fail-terminal-stop/' + this.id)) throw new Error('Injected sandbox teardown failure');
        }
        async destroy() { this.stopped = true; }
      }
    `,
        "workspace-runner": `
      export async function runWorkspaceTask({ state, serial, signal, task }) {
        await serial(async () => {
          await state.storage.put('test:runnerStarted', true);
          if (task.prompt === 'Hold the command queue') {
            await new Promise(resolve => {
              signal.addEventListener('abort', resolve, { once: true });
              if (signal.aborted) resolve();
            });
            if (signal.aborted) await state.storage.put('test:runnerAborted', true);
          }
        });
        await serial(async () => {
          const current = await state.storage.get('task');
          if (signal.aborted || current.status === 'cancelled') {
            await state.storage.put('task', { ...current, status: 'cancelled', finishedAt: Date.now() });
          } else {
            const publication = await state.publishedVersion(await state.files(), 'Agent finished');
            await state.storage.put({ ...publication.writes,
              task: { ...current, status: 'completed', finishedAt: Date.now(), versionHash: publication.writes.meta.head },
              ...state.message('assistant', 'Private agent conversation'),
            });
          }
        });
      }
    `,
        sandbox: `import { DurableObject } from 'cloudflare:workers'; export class Sandbox extends DurableObject {}`,
    };
    const bundle = await build({
        stdin: {
            resolveDir: ROOT,
            sourcefile: "integration-harness.ts",
            loader: "ts",
            contents: `
      import worker from './index';
      import { Workspace } from './workspace';
      import { WorkspaceDirectory as DirectoryBase } from './directory';
      export class WorkspaceDirectory extends DirectoryBase {
        async fixture(writes) { await this.ctx.storage.put(writes); }
        async publishFixture(summaries) { for (const summary of summaries) await this.publish(summary); }
      }
      export { Sandbox } from '@cloudflare/sandbox';
      export class TestWorkspace extends Workspace {
        async fixture(writes) { await this.ctx.storage.put(writes); }
        async inspect() { return Object.fromEntries(await this.ctx.storage.list()); }
        async alarmNow() { return this.alarm(); }
      }
      export default { async fetch(request, env, ctx) {
        const path = new URL(request.url).pathname;
        if (path.startsWith('/__test/')) {
          const input = await request.json(); const stub = env.WORKSPACES.getByName(input.id);
          if (path === '/__test/directory') { await env.DIRECTORY.getByName('global').fixture(input.writes); return Response.json({ ok: true }); }
          if (path === '/__test/publish') { await env.DIRECTORY.getByName('global').publishFixture(input.summaries); return Response.json({ ok: true }); }
          if (path === '/__test/terminal-stopped') return Response.json({ stopped: !!(await env.OBJECTS.get('test/terminal-stopped/' + input.id)) });
          if (path === '/__test/fail-terminal-stop') { await env.OBJECTS.put('test/fail-terminal-stop/' + input.id, 'yes'); return Response.json({ ok: true }); }
          if (path === '/__test/fixture') { await stub.fixture(input.writes); return Response.json({ ok: true }); }
          if (path === '/__test/inspect') return Response.json(await stub.inspect());
          if (path === '/__test/alarm') { await stub.alarmNow(); return Response.json({ ok: true }); }
        }
        return worker.fetch(request, env, ctx);
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
                name: "controlled-external-systems",
                setup(builder) {
                    builder.onResolve(
                        { filter: /^\.\/(source|sandbox-files|workspace-runner)$/ },
                        (args) => ({ path: args.path.slice(2), namespace: "test-fixture" }),
                    );
                    builder.onResolve({ filter: /^@cloudflare\/sandbox$/ }, () => ({
                        path: "sandbox",
                        namespace: "test-fixture",
                    }));
                    builder.onLoad({ filter: /.*/, namespace: "test-fixture" }, (args) => ({
                        contents: mocks[args.path],
                        loader: "js",
                        resolveDir: ROOT,
                    }));
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
            name: "workspace-integration",
            modulesRoot: "/",
            compatibilityDate: "2026-09-09",
            compatibilityFlags: ["nodejs_compat"],
            modules: [
                {
                    type: "ESModule",
                    path: "/integration.mjs",
                    contents: bundle.outputFiles[0].text,
                },
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
            durableObjects: {
                WORKSPACES: { className: "TestWorkspace", useSQLite: true },
                DIRECTORY: { className: "WorkspaceDirectory", useSQLite: true },
                Sandbox: { className: "Sandbox", useSQLite: true },
            },
            r2Buckets: ["OBJECTS"],
            bindings: {
                AUTH_AUDIENCE: AUDIENCE,
                GROQ_MODEL: "openai/gpt-oss-120b",
                GROQ_API_KEY: "unused-test-key",
                MAX_DAILY_MODEL_REQUESTS: "900",
                MAX_DAILY_MODEL_TOKENS: "180000",
            },
        }),
    );
    await mf.ready;
}, 30_000);

afterAll(async () => {
    await mf?.dispose();
});

function identity() {
    const seed = hex(crypto.getRandomValues(new Uint8Array(32)));
    return { seed, publicKey: hex(mkit.ed25519_pubkey_from_seed(fromHex(seed))) };
}
function envelope(
    id: ReturnType<typeof identity>,
    repository: string,
    path: string,
    value: unknown,
    nonce = hex(crypto.getRandomValues(new Uint8Array(32))),
) {
    const body = JSON.stringify(value),
        digest = mkit.blake3_hex(encoder.encode(body));
    const now = Date.now(),
        expires = now + 300_000;
    const canonical = [
        "mkit-write:v2",
        AUDIENCE,
        repository,
        path,
        `body:${digest}`,
        String(now),
        String(expires),
        nonce,
    ].join("\n");
    return {
        method: "POST",
        body,
        headers: {
            "Content-Type": "application/json",
            Origin: AUDIENCE,
            "X-Envelope-Version": "2",
            "X-Audience": AUDIENCE,
            "X-Repository": repository,
            "X-Content-Commitment": `body:${digest}`,
            "X-Expires-At": String(expires),
            "X-Public-Key": id.publicKey,
            "X-Signature": hex(
                mkit.ed25519_sign(
                    fromHex(mkit.blake3_hex(encoder.encode(canonical))),
                    fromHex(id.seed),
                ),
            ),
            "X-Digest": digest,
            "X-Created-At": String(now),
            "Idempotency-Key": nonce,
        },
    };
}
async function signed(
    id: ReturnType<typeof identity>,
    repository: string,
    path: string,
    value: unknown,
) {
    return mf.dispatchFetch(AUDIENCE + path, envelope(id, repository, path, value));
}
async function prepare(owner = identity()) {
    const response = await signed(owner, "workspaces", "/api/workspaces/prepare", { kind: "demo" });
    if (response.status !== 200) throw new Error(await response.text());
    return { owner, prepared: (await response.json()) as PreparedWorkspace };
}
function activationEnvelope(owner: ReturnType<typeof identity>, prepared: PreparedWorkspace) {
    const signature = hex(
        mkit.ed25519_sign(
            fromHex(mkit.blake3_hex(encoder.encode(grantMessage(prepared.grant)))),
            fromHex(owner.seed),
        ),
    );
    const path = `/api/workspaces/${prepared.id}/activate`;
    return envelope(owner, prepared.id, path, {
        grant: prepared.grant,
        signature,
    });
}
async function activate(owner: ReturnType<typeof identity>, prepared: PreparedWorkspace, existingCookie?: string) {
    const cookie = existingCookie ?? (await signed(owner, "identity", "/api/workspaces/session", {})).headers.get("Set-Cookie")!.split(";")[0];
    const path = `/api/workspaces/${prepared.id}/activate`;
    const signedRequest = activationEnvelope(owner, prepared);
    const response = await mf.dispatchFetch(AUDIENCE + path, {
        ...signedRequest, headers: { ...signedRequest.headers, Cookie: cookie },
    });
    if (response.status !== 200) throw new Error(await response.text());
    return {
        view: (await response.json()) as WorkspaceView,
        cookie,
        setCookie: response.headers.get("set-cookie"),
    };
}
async function project() {
    const setup = await prepare();
    return { ...setup, ...(await activate(setup.owner, setup.prepared)) };
}
async function fixture(id: string, writes: Record<string, unknown>) {
    const response = await mf.dispatchFetch(AUDIENCE + "/__test/fixture", {
        method: "POST",
        body: JSON.stringify({ id, writes }),
    });
    expect(response.status).toBe(200);
}
async function inspect(id: string) {
    return (
        await mf.dispatchFetch(AUDIENCE + "/__test/inspect", {
            method: "POST",
            body: JSON.stringify({ id }),
        })
    ).json() as Promise<Record<string, unknown>>;
}
async function view(id: string, cookie?: string) {
    const response = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${id}`, {
        headers: cookie ? { Cookie: cookie } : {},
    });
    return response.json() as Promise<WorkspaceView>;
}
async function waitFor(id: string, predicate: (value: Record<string, unknown>) => boolean) {
    for (let attempt = 0; attempt < 100; attempt++) {
        const value = await inspect(id);
        if (predicate(value)) return value;
        await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error("Workspace did not reach expected state");
}

describe("workspace HTTP coordinator with real auth and storage", () => {
    it("creates an identity-scoped root session, replays it exactly, and cannot revive it after logout", async () => {
        const owner = identity(), path = "/api/workspaces/session";
        expect(await (await mf.dispatchFetch(AUDIENCE + path)).json()).toBeNull();
        const signedLogin = envelope(owner, "identity", path, {});
        const response = await mf.dispatchFetch(AUDIENCE + path, signedLogin);
        expect(response.status).toBe(200);
        const session = await response.json() as { id: string; publicKey: string; expiresAt: number };
        expect(session.publicKey).toBe(owner.publicKey);
        expect(session.expiresAt - Date.now()).toBeGreaterThan(6 * 86400000);
        expect(Object.keys(session).sort()).toEqual(["expiresAt", "id", "publicKey"]);
        const cookie = response.headers.get("Set-Cookie")!.split(";")[0];
        expect(response.headers.get("Set-Cookie")).toContain("Path=/; HttpOnly; SameSite=Strict; Max-Age=604800; Secure");
        const replay = await mf.dispatchFetch(AUDIENCE + path, signedLogin);
        expect(replay.headers.get("Set-Cookie")).toBe(response.headers.get("Set-Cookie"));
        expect(await replay.json()).toEqual(session);
        expect(await (await mf.dispatchFetch(AUDIENCE + path, { headers: { Cookie: cookie } })).json()).toEqual(session);
        expect((await signed(owner, "workspaces", path, {})).status).toBe(401);
        expect((await signed(owner, "identity", path, { seed: "must not be accepted" })).status).toBe(400);
        expect((await mf.dispatchFetch(AUDIENCE + path, { method: "DELETE", headers: { Cookie: cookie, Origin: "https://other.example" } })).status).toBe(403);
        expect((await mf.dispatchFetch(AUDIENCE + path, { method: "DELETE", headers: { Cookie: cookie, Origin: AUDIENCE } })).status).toBe(200);
        expect(await (await mf.dispatchFetch(AUDIENCE + path, { headers: { Cookie: cookie } })).json()).toBeNull();
        expect((await mf.dispatchFetch(AUDIENCE + path, signedLogin)).status).toBe(401);
    });

    it("shares one login across owned workspaces without rotating it, while cookies cannot authorize signed writes", async () => {
        const owner = identity();
        const login = await signed(owner, "identity", "/api/workspaces/session", {});
        const cookie = login.headers.get("Set-Cookie")!.split(";")[0];
        const one = (await prepare(owner)).prepared, two = (await prepare(owner)).prepared;
        const first = await activate(owner, one, cookie), second = await activate(owner, two, cookie);
        expect(first.setCookie).toBeNull();
        expect(second.setCookie).toBeNull();
        expect((await view(one.id, cookie)).isOwner).toBe(true);
        expect((await view(two.id, cookie)).isOwner).toBe(true);
        const renew = envelope(owner, one.id, `/api/workspaces/${one.id}/session`, {});
        const renewed = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${one.id}/session`, { ...renew, headers: { ...renew.headers, Cookie: cookie } });
        expect(renewed.status).toBe(200);
        expect(renewed.headers.get("Set-Cookie")).toBeNull();
        const stranger = await signed(identity(), "identity", "/api/workspaces/session", {});
        expect((await view(one.id, stranger.headers.get("Set-Cookie")!.split(";")[0])).isOwner).toBe(false);
        const token = cookie.split("=")[1];
        await fixture(one.id, { [`session:${mkit.blake3_hex(encoder.encode(token))}`]: Date.now() + 3600000 });
        expect((await view(one.id, `mkit_workspace=${token}`)).isOwner).toBe(false);
        const attempted = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${one.id}/file`, {
            method: "POST", headers: { Cookie: cookie, Origin: AUDIENCE, "Content-Type": "application/json" },
            body: JSON.stringify({ path: "README.md", content: "Unsigned overwrite", expectedHash: first.view.files[0].path }),
        });
        expect(attempted.status).toBe(401);
        expect((await view(one.id, cookie)).workspace.head).toBe(first.view.workspace.head);
        await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/session`, { method: "DELETE", headers: { Cookie: cookie, Origin: AUDIENCE } });
        expect((await view(one.id, cookie)).isOwner).toBe(false);
        expect((await view(two.id, cookie)).isOwner).toBe(false);
    });

    it("does not restore a logged-out session through late activation or activation replay", async () => {
        const { owner, prepared } = await prepare();
        const login = await signed(owner, "identity", "/api/workspaces/session", {});
        const cookie = login.headers.get("Set-Cookie")!.split(";")[0];
        const path = `/api/workspaces/${prepared.id}/activate`;
        const activation = activationEnvelope(owner, prepared);
        await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/session`, {
            method: "DELETE", headers: { Cookie: cookie, Origin: AUDIENCE },
        });
        // The signed request was prepared before logout but reaches activation afterward.
        for (const requestCookie of [cookie, cookie, undefined]) {
            const response = await mf.dispatchFetch(AUDIENCE + path, {
                ...activation,
                headers: { ...activation.headers, ...(requestCookie ? { Cookie: requestCookie } : {}) },
            });
            expect(response.status).toBe(200);
            expect(response.headers.get("Set-Cookie")).toBeNull();
            expect(await (await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/session`, {
                headers: { Cookie: cookie },
            })).json()).toBeNull();
            expect((await view(prepared.id, cookie)).isOwner).toBe(false);
        }
        const unsignedIn = (await prepare(owner)).prepared;
        const response = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${unsignedIn.id}/activate`, activationEnvelope(owner, unsignedIn),
        );
        expect(response.status).toBe(200);
        expect(response.headers.get("Set-Cookie")).toBeNull();
    });

    it("requires signed preparation and activation before exposing a public remix", async () => {
        expect(
            (
                await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/prepare`, {
                    method: "POST",
                    body: '{"kind":"demo"}',
                    headers: { "Content-Type": "application/json" },
                })
            ).status,
        ).toBe(401);
        const { owner, prepared } = await prepare();
        expect((await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}`)).status).toBe(
            404,
        );
        const wrong = identity();
        expect(
            (await signed(wrong, prepared.id, `/api/workspaces/${prepared.id}/activate`, {}))
                .status,
        ).toBe(403);
        const { view: active, cookie } = await activate(owner, prepared);
        expect(active).toMatchObject({
            isOwner: true,
            agentEnabled: true,
            workspace: { id: prepared.id, public: true, ownerPublicKey: owner.publicKey },
        });
        expect(active.versions).toHaveLength(1);
        expect((await view(prepared.id)).isOwner).toBe(false);
        expect((await view(prepared.id, cookie)).isOwner).toBe(true);
        const directory = (await (await mf.dispatchFetch(`${AUDIENCE}/api/workspaces`)).json()) as {
            workspaces: Array<{ id: string }>;
        };
        expect(directory.workspaces.some((item) => item.id === prepared.id)).toBe(true);
    });

    it("keeps task and chat private, rejects another identity, and revokes read sessions on logout", async () => {
        const { owner, prepared, cookie } = await project();
        await fixture(prepared.id, {
            task: { id: "task", prompt: "Owner-only prompt", status: "completed", createdAt: 1 },
            "message:0000000000001:private": {
                id: "private",
                role: "assistant",
                text: "Owner-only response",
                createdAt: 1,
            },
        });
        expect(await view(prepared.id)).toMatchObject({ isOwner: false, messages: [], task: null });
        expect(JSON.stringify(await view(prepared.id))).not.toContain("Owner-only");
        expect((await view(prepared.id, cookie)).messages).toHaveLength(1);
        expect(
            (await signed(identity(), prepared.id, `/api/workspaces/${prepared.id}/session`, {}))
                .status,
        ).toBe(403);
        expect(
            (
                await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/session`, {
                    method: "DELETE",
                    headers: { Cookie: cookie, Origin: "https://other.example" },
                })
            ).status,
        ).toBe(403);
        expect((await view(prepared.id, cookie)).isOwner).toBe(true);
        const logout = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/session`, {
            method: "DELETE",
            headers: { Cookie: cookie, Origin: AUDIENCE },
        });
        expect(logout.status).toBe(200);
        expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");
        expect(await view(prepared.id, cookie)).toMatchObject({
            isOwner: false,
            messages: [],
            task: null,
        });
        const renewed = await signed(
            owner,
            prepared.id,
            `/api/workspaces/${prepared.id}/session`,
            {},
        );
        expect(renewed.status).toBe(200);
    });

    it("rejects stale edits and makes saved files publicly readable and remixable", async () => {
        const { owner, prepared, view: initial } = await project();
        const original = (await (
            await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/file?path=README.md`)
        ).json()) as { hash: string };
        const saved = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/file`, {
            path: "README.md",
            expectedHash: original.hash,
            content: "Updated readme",
        });
        expect(saved.status).toBe(200);
        const latest = (await saved.json()) as WorkspaceView;
        expect(latest.workspace.head).not.toBe(initial.workspace.head);
        expect(
            (
                await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/file`, {
                    path: "README.md",
                    expectedHash: original.hash,
                    content: "Stale overwrite",
                })
            ).status,
        ).toBe(409);
        expect(
            await (
                await mf.dispatchFetch(
                    `${AUDIENCE}/api/workspaces/${prepared.id}/file?path=README.md`,
                )
            ).json(),
        ).toMatchObject({ content: "Updated readme" });
        const forkOwner = identity();
        const forkResponse = await signed(forkOwner, "workspaces", "/api/workspaces/prepare", {
            kind: "workspace",
            workspaceId: prepared.id,
        });
        expect(forkResponse.status).toBe(200);
        const fork = (await forkResponse.json()) as PreparedWorkspace;
        expect(fork.grant.source).toMatchObject({
            kind: "workspace",
            workspaceId: prepared.id,
            commitHash: latest.workspace.head,
        });
        await activate(forkOwner, fork);
        expect(
            await (
                await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${fork.id}/file?path=README.md`)
            ).json(),
        ).toMatchObject({ content: "Updated readme" });
    });

    it("detects same-size binary edits, additions, deletions and mode changes against saved HEAD", async () => {
        const { prepared, view: initial } = await project();
        const saved = (await inspect(prepared.id)).files as FileManifest;
        const bucket = await mf.getR2Bucket("OBJECTS");
        const before = { hash: await putBlob(bucket, new Uint8Array([0, 1])), size: 2, mode: "blob" as const };
        const after = { hash: await putBlob(bucket, new Uint8Array([0, 2])), size: 2, mode: "blob" as const };
        const base = { ...saved, "binary.dat": before, "gone.dat": before };
        const working = { "README.md": { ...saved["README.md"], mode: "exec" as const }, "binary.dat": after, "new.dat": after };
        await fixture(prepared.id, { [`manifest:${initial.workspace.head}`]: base, files: working });
        const changes = [
            { path: "binary.dat", status: "modified", beforeHash: before.hash, afterHash: after.hash },
            { path: "gone.dat", status: "deleted", beforeHash: before.hash, afterHash: null },
            { path: "new.dat", status: "added", beforeHash: null, afterHash: after.hash },
            { path: "README.md", status: "modified", beforeHash: saved["README.md"].hash, afterHash: saved["README.md"].hash },
        ].sort((a, b) => a.path.localeCompare(b.path));
        expect((await view(prepared.id)).changes).toEqual(changes);
        const historical = await (await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}?version=${initial.workspace.head}`)).json() as WorkspaceView;
        expect(historical.changes).toEqual(changes);
        expect(historical.files.find(file => file.path === "binary.dat")?.hash).toBe(before.hash);
        expect((await view(prepared.id)).files.find(file => file.path === "binary.dat")?.hash).toBe(after.hash);
    });

    it("checkpoints the complete terminal manifest and restores as a new child without losing history", async () => {
        const { owner, prepared, cookie, view: initial } = await project();
        const bucket = await mf.getR2Bucket("OBJECTS");
        const bytes = new Uint8Array([0, 255, 1]);
        const terminalFiles: FileManifest = {
            ...(await inspect(prepared.id)).files as FileManifest,
            "terminal.bin": { hash: await putBlob(bucket, bytes), size: bytes.length, mode: "blob" },
        };
        const terminal = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/terminal`, {
            headers: { Cookie: cookie, Origin: AUDIENCE, Upgrade: "websocket" },
        });
        expect(terminal.status).toBe(101);
        terminal.webSocket!.accept();
        await bucket.put(`test/terminal-files/${prepared.id}`, JSON.stringify(terminalFiles));
        const path = `/api/workspaces/${prepared.id}/versions`;
        const operation = envelope(owner, prepared.id, path, { message: "Capture terminal work" });
        const response = await mf.dispatchFetch(AUDIENCE + path, operation);
        expect(response.status).toBe(200);
        const checkpoint = await response.json() as WorkspaceView;
        expect(checkpoint.changes).toEqual([]);
        expect(checkpoint.versions).toHaveLength(2);
        expect(checkpoint.versions.find(version => version.hash === checkpoint.workspace.head)).toMatchObject({ parent: initial.workspace.head, message: "Capture terminal work" });
        expect((await inspect(prepared.id))[`manifest:${checkpoint.workspace.head}`]).toEqual(terminalFiles);
        expect(await bucket.get(`test/terminal-stopped/${prepared.id}`)).not.toBeNull();
        expect(await (await mf.dispatchFetch(AUDIENCE + path, operation)).json()).toEqual(checkpoint);
        const restored = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/restore`, { versionHash: initial.workspace.head });
        expect(restored.status).toBe(200);
        const result = await restored.json() as WorkspaceView;
        expect(result.versions).toHaveLength(3);
        expect(result.versions.find(version => version.hash === result.workspace.head)?.parent).toBe(checkpoint.workspace.head);
        expect(result.files).toEqual(initial.files);
        expect(result.changes).toEqual([]);
        expect((await inspect(prepared.id))[`manifest:${checkpoint.workspace.head}`]).toEqual(terminalFiles);
    });

    it("publishes browser edits together as one named version and rejects any conflicting batch atomically", async () => {
        const { owner, prepared, view: initial } = await project();
        const current = (await inspect(prepared.id)).files as FileManifest;
        const path = `/api/workspaces/${prepared.id}/versions`;
        const edits = [
            { path: "README.md", content: "Updated together", expectedHash: current["README.md"].hash },
            { path: "src/new.txt", content: "New file", expectedHash: null },
        ];
        const failed = await signed(owner, prepared.id, path, { message: "Conflict", edits: [edits[1], { ...edits[0], expectedHash: "f".repeat(64) }] });
        expect(failed.status).toBe(409);
        expect((await inspect(prepared.id)).files).toEqual(current);
        expect((await view(prepared.id)).workspace.head).toBe(initial.workspace.head);
        expect((await signed(owner, prepared.id, path, { message: "Duplicate", edits: [edits[1], edits[1]] })).status).toBe(400);
        expect((await signed(owner, prepared.id, path, { message: "   ", edits })).status).toBe(400);
        const response = await signed(owner, prepared.id, path, { message: "One coherent change", edits });
        expect(response.status).toBe(200);
        const result = await response.json() as WorkspaceView;
        expect(result.versions).toHaveLength(2);
        expect(result.versions.find(version => version.hash === result.workspace.head)).toMatchObject({ message: "One coherent change", parent: initial.workspace.head });
        expect(result.files.map(file => file.path)).toEqual(["README.md", "src/new.txt"]);
        expect(result.changes).toEqual([]);
        expect((await inspect(prepared.id))[`manifest:${initial.workspace.head}`]).toEqual(current);
        expect(await (await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/file?path=README.md`)).json()).toMatchObject({ content: "Updated together" });
    });

    it("bounds batch edits, supports larger multi-file bodies, and enforces version authorization", async () => {
        const { owner, prepared, cookie } = await project();
        const path = `/api/workspaces/${prepared.id}/versions`;
        const payload = { message: "Large batch", edits: [
            { path: "large-a.txt", content: "a".repeat(210000), expectedHash: null },
            { path: "constructor", content: "b".repeat(210000), expectedHash: null },
        ] };
        expect((await mf.dispatchFetch(AUDIENCE + path, {
            method: "POST", headers: { Cookie: cookie, Origin: AUDIENCE, "Content-Type": "application/json" }, body: JSON.stringify(payload),
        })).status).toBe(401);
        expect((await signed(identity(), prepared.id, path, payload)).status).toBe(403);
        expect((await signed(owner, prepared.id, path, { message: "Oversize", edits: [{ path: "too-big", content: "x".repeat(262145), expectedHash: null }] })).status).toBe(413);
        expect((await signed(owner, prepared.id, path, { message: "Invalid", edits: [{ path: "../escape", content: "x", expectedHash: null }] })).status).toBe(400);
        const response = await signed(owner, prepared.id, path, payload);
        expect(response.status).toBe(200);
        expect((await response.json() as WorkspaceView).files).toContainEqual({ path: "constructor", size: 210000, mode: "blob", hash: expect.stringMatching(/^[0-9a-f]{64}$/) });
        await fixture(prepared.id, { task: { id: "busy", prompt: "Working", status: "running", createdAt: Date.now() } });
        expect((await signed(owner, prepared.id, path, { message: "Busy" })).status).toBe(409);
        await fixture(prepared.id, { revoked: true });
        expect((await signed(owner, prepared.id, path, { message: "Revoked" })).status).toBe(403);
    });

    it("runs a queued task after the request ends and automatically publishes a version", async () => {
        const { owner, prepared, view: initial } = await project();
        const response = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/tasks`, {
            prompt: "Complete this task",
        });
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ task: { status: "queued" } });
        await waitFor(
            prepared.id,
            (value) => (value.task as { status?: string })?.status === "completed",
        );
        const current = await view(prepared.id);
        expect(current.workspace.head).not.toBe(initial.workspace.head);
        expect(current.versions).toHaveLength(2);
        expect(current.messages).toEqual([]);
        expect(current.task).toBeNull();
    });

    it("cancels a running task even while its command holds the serial queue", async () => {
        const { owner, prepared } = await project();
        expect(
            (
                await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/tasks`, {
                    prompt: "Hold the command queue",
                })
            ).status,
        ).toBe(200);
        await waitFor(prepared.id, (value) => value["test:runnerStarted"] === true);
        const cancellation = await signed(
            owner,
            prepared.id,
            `/api/workspaces/${prepared.id}/cancel`,
            {},
        );
        expect(cancellation.status).toBe(200);
        expect(await cancellation.json()).toMatchObject({ task: { status: "cancelled" } });
        const current = await inspect(prepared.id);
        expect(current.task).toMatchObject({ status: "cancelled" });
    }, 5000);

    it("does not cancel a newer task when an earlier cancellation is replayed", async () => {
        const { owner, prepared } = await project();
        const path = `/api/workspaces/${prepared.id}/cancel`;
        const originalCancellation = envelope(owner, prepared.id, path, {});
        expect((await mf.dispatchFetch(AUDIENCE + path, originalCancellation)).status).toBe(200);
        expect(
            (
                await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/tasks`, {
                    prompt: "Hold the command queue",
                })
            ).status,
        ).toBe(200);
        await waitFor(prepared.id, (value) => value["test:runnerStarted"] === true);
        try {
            const replay = await mf.dispatchFetch(AUDIENCE + path, originalCancellation);
            expect(replay.status).toBe(200);
            const state = await inspect(prepared.id);
            expect(state["test:runnerAborted"]).toBeUndefined();
            expect(state.task).toMatchObject({ status: "running" });
        } finally {
            await signed(owner, prepared.id, path, {});
        }
    }, 5000);

    it("returns an actionable allowance response when task admission is exhausted", async () => {
        const { owner, prepared } = await project();
        await mf.dispatchFetch(AUDIENCE + "/__test/directory", {
            method: "POST",
            body: JSON.stringify({
                id: prepared.id,
                writes: {
                    [`tasks:${Math.floor(Date.now() / 86400000)}:${owner.publicKey}`]: 12,
                },
            }),
        });
        const response = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/tasks`, {
            prompt: "Beyond daily allowance",
        });
        expect(response.status).toBe(429);
        expect(await response.json()).toMatchObject({
            error: expect.stringContaining("allowance"),
        });
        expect((await inspect(prepared.id)).task).toBeUndefined();
    });

    it("requires the owner session and same-origin WebSocket handshake for the terminal", async () => {
        const { prepared, cookie } = await project();
        const url = `${AUDIENCE}/api/workspaces/${prepared.id}/terminal`;
        expect(
            (await mf.dispatchFetch(url, { headers: { Upgrade: "websocket", Origin: AUDIENCE } }))
                .status,
        ).toBe(403);
        expect(
            (
                await mf.dispatchFetch(url, {
                    headers: {
                        Upgrade: "websocket",
                        Origin: "https://other.example",
                        Cookie: cookie,
                    },
                })
            ).status,
        ).toBe(403);
        expect(
            (await mf.dispatchFetch(url, { headers: { Origin: AUDIENCE, Cookie: cookie } })).status,
        ).toBe(426);
        const connection = await mf.dispatchFetch(url, {
            headers: { Upgrade: "websocket", Origin: AUDIENCE, Cookie: cookie },
        });
        expect(connection.status).toBe(101);
        const socket = connection.webSocket!;
        socket.accept();
        const echoed = new Promise<string>((resolve) =>
            socket.addEventListener("message", (event) => resolve(String(event.data)), {
                once: true,
            }),
        );
        socket.send("echo hello");
        expect(await echoed).toBe("echo hello");
        const closed = new Promise<void>((resolve) =>
            socket.addEventListener("close", () => resolve(), { once: true }),
        );
        expect(
            (
                await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/session`, {
                    method: "DELETE",
                    headers: { Origin: AUDIENCE, Cookie: cookie },
                })
            ).status,
        ).toBe(200);
        await mf.dispatchFetch(AUDIENCE + "/__test/alarm", { method: "POST", body: JSON.stringify({ id: prepared.id }) });
        await closed;
        expect(
            await (
                await mf.dispatchFetch(AUDIENCE + "/__test/terminal-stopped", {
                    method: "POST",
                    body: JSON.stringify({ id: prepared.id }),
                })
            ).json(),
        ).toEqual({ stopped: true });
    });

    it("stops the persistent terminal process when an oversized input frame is rejected", async () => {
        const { prepared, cookie } = await project();
        const connection = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${prepared.id}/terminal`,
            { headers: { Upgrade: "websocket", Origin: AUDIENCE, Cookie: cookie } },
        );
        const socket = connection.webSocket!;
        socket.accept();
        const closed = new Promise<void>((resolve) =>
            socket.addEventListener("close", () => resolve(), { once: true }),
        );
        socket.send("x".repeat(65_537));
        await closed;
        expect(
            await (
                await mf.dispatchFetch(AUDIENCE + "/__test/terminal-stopped", {
                    method: "POST",
                    body: JSON.stringify({ id: prepared.id }),
                })
            ).json(),
        ).toEqual({ stopped: true });
    });

    it("stops an open terminal when its agent grant expires", async () => {
        const { prepared, cookie, view: initial } = await project();
        const connection = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${prepared.id}/terminal`,
            { headers: { Upgrade: "websocket", Origin: AUDIENCE, Cookie: cookie } },
        );
        const socket = connection.webSocket!;
        socket.accept();
        const closed = new Promise<void>((resolve) =>
            socket.addEventListener("close", () => resolve(), { once: true }),
        );
        await fixture(prepared.id, {
            grant: {
                ...initial.grant,
                grant: { ...initial.grant!.grant, expiresAt: Date.now() - 1 },
            },
        });
        socket.send("must not execute");
        await closed;
        expect(
            await (
                await mf.dispatchFetch(AUDIENCE + "/__test/terminal-stopped", {
                    method: "POST",
                    body: JSON.stringify({ id: prepared.id }),
                })
            ).json(),
        ).toEqual({ stopped: true });
    });

    it("disables delegated access even if stopping the sandbox terminal fails", async () => {
        const { owner, prepared, cookie } = await project();
        const connection = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${prepared.id}/terminal`,
            { headers: { Upgrade: "websocket", Origin: AUDIENCE, Cookie: cookie } },
        );
        const socket = connection.webSocket!;
        socket.accept();
        try {
            await mf.dispatchFetch(AUDIENCE + "/__test/fail-terminal-stop", {
                method: "POST",
                body: JSON.stringify({ id: prepared.id }),
            });
            await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/revoke`, {});
            expect(await view(prepared.id, cookie)).toMatchObject({ agentEnabled: false });
            expect((await inspect(prepared.id)).revoked).toBe(true);
        } finally {
            socket.close();
        }
    });

    it("marks a crashed running task interrupted without replaying its command", async () => {
        const { prepared } = await project();
        await fixture(prepared.id, {
            task: { id: "crashed", prompt: "Never replay me", status: "running", createdAt: 1 },
        });
        const alarm = await mf.dispatchFetch(`${AUDIENCE}/__test/alarm`, {
            method: "POST",
            body: JSON.stringify({ id: prepared.id }),
        });
        expect(alarm.status).toBe(200);
        const result = await inspect(prepared.id);
        expect(result.task).toMatchObject({
            status: "failed",
            error: expect.stringContaining("restarted"),
        });
        expect(result["test:runnerStarted"]).toBeUndefined();
    });

    it("fails a queued task when authorization expires before it can start", async () => {
        const { prepared, view: initial } = await project();
        await fixture(prepared.id, {
            task: { id: "expired", prompt: "Do not execute", status: "queued", createdAt: 1 },
            grant: {
                ...initial.grant,
                grant: { ...initial.grant!.grant, expiresAt: Date.now() - 1 },
            },
        });
        const alarm = await mf.dispatchFetch(`${AUDIENCE}/__test/alarm`, {
            method: "POST",
            body: JSON.stringify({ id: prepared.id }),
        });
        expect(alarm.status).toBe(200);
        const result = await inspect(prepared.id);
        expect(result.task).toMatchObject({
            status: "failed",
            error: expect.stringContaining("authorization"),
        });
        expect(result["test:runnerStarted"]).toBeUndefined();
    });

    it("discovers the newest projects even after the directory contains more than 500 entries", async () => {
        const template = {
            title: "Public project",
            ownerPublicKey: "1".repeat(64),
            agentPublicKey: "2".repeat(64),
            source: { kind: "demo", repository: "demo", commitHash: "0".repeat(64) },
            head: "3".repeat(64),
            createdAt: 1,
            public: true,
        };
        const summaries = Array.from({ length: 501 }, (_, index) => ({
            ...template,
            id: index.toString(16).padStart(32, "0"),
            updatedAt: index,
        }));
        const newest = { ...template, id: "f".repeat(32), updatedAt: Date.now() + 1000 };
        const response = await mf.dispatchFetch(AUDIENCE + "/__test/publish", {
            method: "POST",
            body: JSON.stringify({ id: newest.id, summaries: [...summaries, newest] }),
        });
        expect(response.status).toBe(200);
        const directory = (await (await mf.dispatchFetch(`${AUDIENCE}/api/workspaces`)).json()) as {
            workspaces: Array<{ id: string }>;
        };
        expect(directory.workspaces[0]?.id).toBe(newest.id);
        expect(directory.workspaces).toHaveLength(50);
    });
});
