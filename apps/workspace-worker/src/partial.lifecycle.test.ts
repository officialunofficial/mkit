import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { encoder, fromHex, hex, mkit } from "./mkit";
import { grantMessage, type PreparedWorkspace, type WorkspaceView } from "./contracts";

const ROOT = fileURLToPath(new NodeURL("./", import.meta.url));
const GOLDEN = fileURLToPath(new NodeURL("../../../rust/tests/golden/partial_workspace/", import.meta.url));
const PLAIN = readFileSync(`${GOLDEN}plain_file.bin`);
const BASE = "17963c328bb4a65dfffb659125df822a5a8b0aaca309c245c569420e243f8d90";
const PATHS = [["7368616c6c6f772e747874"]];
const DIGEST = mkit.blake3_hex(PLAIN);
const AUDIENCE = "https://mkit.sh";
let mf: Miniflare;

beforeAll(async () => {
    const mocks: Record<string, string> = {
        "sandbox-files": `
      export class SandboxWorkspace {
        constructor(namespace, id, objects) { this.id = id; this.objects = objects; this.files = {}; this.generation = ''; }
        async ensure(files, generation) { this.files = files; this.generation = generation; }
        async capture() { return this.files; }
        async captureExact() { return this.files; }
        async terminal() {
          const pair = new WebSocketPair(); pair[1].accept();
          return new Response(null, { status: 101, webSocket: pair[0] });
        }
        async stopTerminal() {}
        async destroy() {}
      }
    `,
        sandbox: `import { DurableObject } from 'cloudflare:workers'; export class Sandbox extends DurableObject {}`,
        "workspace-runner": `export async function runWorkspaceTask() {}`,
    };
    const bundle = await build({
        stdin: {
            resolveDir: ROOT,
            sourcefile: "partial-lifecycle-harness.ts",
            loader: "ts",
            contents: `
      const plain = Uint8Array.from(atob(${JSON.stringify(Buffer.from(PLAIN).toString("base64"))}), c => c.charCodeAt(0));
      const origFetch = globalThis.fetch.bind(globalThis);
      globalThis.fetch = (input, init) => {
        const url = typeof input === 'string' ? input : input instanceof Request ? input.url : String(input);
        if (url.endsWith('.mkwb')) {
          if (!url.endsWith('/${DIGEST}.mkwb')) return Promise.resolve(new Response('missing', { status: 404 }));
          return Promise.resolve(new Response(plain, { status: 200 }));
        }
        return origFetch(input, init);
      };
      import worker from './index';
      import { Workspace } from './workspace';
      export class TestWorkspace extends Workspace {
        constructor(ctx, env) {
          const objects = new Proxy(env.OBJECTS, {
            get(target, key) {
              if (key === 'put') return async (...args) => {
                const result = await target.put(...args);
                if (String(args[0]).includes('/update/')) {
                  const fault = await ctx.storage.get('persistFault');
                  if (fault === 'revoke') await ctx.storage.put('revoked', true);
                  if (fault === 'expire') {
                    const signed = await ctx.storage.get('grant');
                    signed.grant.expiresAt = Date.now() - 1;
                    await ctx.storage.put('grant', signed);
                  }
                }
                return result;
              };
              const value = target[key];
              return typeof value === 'function' ? value.bind(target) : value;
            },
          });
          super(ctx, { ...env, OBJECTS: objects });
        }
        async fixture(writes) { await this.ctx.storage.put(writes); }
        async inspect() { return Object.fromEntries(await this.ctx.storage.list()); }
      }
      export { WorkspaceDirectory } from './directory';
      export { Sandbox } from '@cloudflare/sandbox';
      export default { async fetch(request, env, ctx) {
        const path = new URL(request.url).pathname;
        if (path.startsWith('/__test/')) {
          const input = await request.json();
          const stub = env.WORKSPACES.getByName(input.id);
          if (path === '/__test/inspect') return Response.json(await stub.inspect());
          if (path === '/__test/fixture') { await stub.fixture(input.writes); return Response.json({ ok: true }); }
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
                    builder.onResolve({ filter: /^\.\/(sandbox-files|workspace-runner)$/ }, (args) => ({
                        path: args.path.slice(2),
                        namespace: "test-fixture",
                    }));
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
            name: "partial-lifecycle",
            modulesRoot: "/",
            compatibilityDate: "2026-09-09",
            compatibilityFlags: ["nodejs_compat"],
            modules: [
                { type: "ESModule", path: "/lifecycle.mjs", contents: bundle.outputFiles[0].text },
                {
                    type: "CompiledWasm",
                    path: "/mkit.wasm",
                    contents: readFileSync(
                        fileURLToPath(new NodeURL("../vendor/mkit-wasm/mkit_wasm_bg.wasm", import.meta.url)),
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
                PUBLIC_PARTIAL_BUNDLE_ORIGIN: AUDIENCE,
                PUBLIC_PARTIAL_RESOURCE_OK: "1",
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
                mkit.ed25519_sign(fromHex(mkit.blake3_hex(encoder.encode(canonical))), fromHex(id.seed)),
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

describe("public partial lifecycle with real wasm import", () => {
    it.each(["none", "expire", "revoke"] as const)("admits a manual candidate only with fresh consent (%s)", async (fault) => {
        const owner = identity();
        const prepareRequest = envelope(owner, "workspaces", "/api/workspaces/prepare", {
            kind: "partial-bundle",
            baseCommit: BASE,
            selectedPaths: PATHS,
            bundleDigest: DIGEST,
        });
        const preparedResponse = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/prepare`, prepareRequest);
        expect(preparedResponse.status).toBe(200);
        const prepared = (await preparedResponse.json()) as PreparedWorkspace;
        const replay = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/prepare`, prepareRequest);
        expect(replay.status).toBe(200);
        expect(await replay.json()).toEqual(prepared);
        expect(prepared.grant.source.kind).toBe("partial-bundle");
        const cookie = (await signed(owner, "identity", "/api/workspaces/session", {})).headers
            .get("Set-Cookie")!
            .split(";")[0]!;
        const signature = hex(
            mkit.ed25519_sign(
                fromHex(mkit.blake3_hex(encoder.encode(grantMessage(prepared.grant)))),
                fromHex(owner.seed),
            ),
        );
        const activated = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/activate`, {
            ...envelope(owner, prepared.id, `/api/workspaces/${prepared.id}/activate`, {
                grant: prepared.grant,
                signature,
            }),
            headers: {
                ...envelope(owner, prepared.id, `/api/workspaces/${prepared.id}/activate`, {
                    grant: prepared.grant,
                    signature,
                }).headers,
                Cookie: cookie,
            },
        });
        expect(activated.status).toBe(200);
        const view = (await activated.json()) as WorkspaceView;
        expect(view.workspace.head).toBeNull();
        expect(view.coverage?.verification).toBe("selected-only");
        expect(view.candidateStatus).toBe("none");
        if (fault !== "none") {
            await mf.dispatchFetch(`${AUDIENCE}/__test/fixture`, {
                method: "POST",
                body: JSON.stringify({ id: prepared.id, writes: { persistFault: fault } }),
            });
        }
        const saved = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/file`, {
            path: "shallow.txt",
            content: "wasm parity",
            expectedHash: view.files[0]!.hash,
        });
        if (fault !== "none") {
            expect(saved.status).toBe(403);
            const inspected = await (await mf.dispatchFetch(`${AUDIENCE}/__test/inspect`, {
                method: "POST", body: JSON.stringify({ id: prepared.id }),
            })).json() as { candidate?: unknown; files: Record<string, { hash: string }> };
            expect(inspected.candidate).toBeUndefined();
            expect(inspected.files["shallow.txt"]!.hash).toBe(view.files[0]!.hash);
            const denied = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/partial-update`, {
                headers: { Cookie: cookie },
            });
            expect(denied.status).toBe(404); // No admitted candidate exists.
            const bucket = await mf.getR2Bucket("OBJECTS");
            expect((await bucket.list({ prefix: `partial/${prepared.id}/update/` })).objects).toHaveLength(1);
            return;
        }
        expect(saved.status).toBe(200);
        const savedView = (await saved.json()) as WorkspaceView;
        expect(savedView.candidateStatus).toBe("ready");
        const download = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${prepared.id}/partial-update`,
            { headers: { Cookie: cookie } },
        );
        expect(download.status).toBe(200);
        expect(download.headers.get("X-Mkit-Coverage")).toBe("selected-only");
        const mkwu = new Uint8Array(await download.arrayBuffer());
        expect(mkwu.byteLength).toBeGreaterThan(32);
        // Optional bridge to the Rust recipient oracle; no second wire decoder.
        if (process.env.MKIT_PARTIAL_ORACLE_DIR)
            writeFileSync(join(process.env.MKIT_PARTIAL_ORACLE_DIR, "download.mkwu"), mkwu);
        const inspect = (await (
            await mf.dispatchFetch(`${AUDIENCE}/__test/inspect`, {
                method: "POST",
                body: JSON.stringify({ id: prepared.id }),
            })
        ).json()) as { candidate: { id: string; baseCommit: string } };
        expect(inspect.candidate.baseCommit).toBe(BASE);
        const bucket = await mf.getR2Bucket("OBJECTS");
        const object = await bucket.get(`objects/${inspect.candidate.id}`);
        expect(object).not.toBeNull();
        const commitBytes = new Uint8Array(await object!.arrayBuffer());
        expect(mkit.commit_verify(commitBytes)).toBe(true);
        const decoded = mkit.commit_decode(commitBytes);
        try {
            expect(decoded.parent_count).toBe(1);
            expect(decoded.parent(0)).toBe(BASE);
        } finally {
            decoded.free();
        }
        const denied = await mf.dispatchFetch(
            `${AUDIENCE}/api/workspaces/${prepared.id}/partial-update`,
        );
        expect(denied.status).toBe(403);
        const otherCookie = (await signed(identity(), "identity", "/api/workspaces/session", {}))
            .headers.get("Set-Cookie")!.split(";")[0]!;
        const nonOwner = await mf.dispatchFetch(`${AUDIENCE}/api/workspaces/${prepared.id}/partial-update`, {
            headers: { Cookie: otherCookie },
        });
        expect(nonOwner.status).toBe(403);
        const pending = await signed(owner, prepared.id, `/api/workspaces/${prepared.id}/file`, {
            path: "shallow.txt",
            content: "again",
            expectedHash: savedView.files[0]!.hash,
        });
        expect(pending.status).toBe(409);
    });
});
