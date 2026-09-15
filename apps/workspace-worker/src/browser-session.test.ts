import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import {
    browserSessionCookie, requestBrowserSession, BROWSER_SESSION_TTL, type BrowserSession,
} from "./browser-session";
import { tokenDigest, type AuthenticatedOperation } from "./auth";

const NOW = 1_800_000_000_000;
const owner = "11".repeat(32);
let mf: Miniflare;

beforeAll(async () => {
    const bundle = await build({
        stdin: {
            resolveDir: fileURLToPath(new NodeURL("./", import.meta.url)),
            sourcefile: "browser-session-harness.ts", loader: "ts",
            contents: `
                import { DurableObject } from 'cloudflare:workers';
                import { BrowserSessions } from './browser-session';
                export class Harness extends DurableObject {
                    async fetch(request) {
                        const input = await request.json();
                        const sessions = new BrowserSessions(this.ctx.storage, () => input.now);
                        try {
                            if (input.op === 'create') return Response.json(await sessions.create(input.auth));
                            if (input.op === 'read') return Response.json(await sessions.read(input.id));
                            if (input.op === 'remove') { await sessions.remove(input.id); return Response.json({ok:true}); }
                            if (input.op === 'inspect') return Response.json(Object.fromEntries(await this.ctx.storage.list()));
                            if (input.op === 'create-fault') {
                                const storage = { transaction: callback => this.ctx.storage.transaction(async txn => {
                                    await callback(txn); throw new Error('Injected transaction failure');
                                }) };
                                await new BrowserSessions(storage, () => input.now).create(input.auth);
                            }
                            throw new Error('Unknown operation');
                        } catch (error) { return Response.json({error:error.message}, {status:error.status ?? 500}); }
                    }
                }
                export default { fetch(request, env) {
                    return env.SESSIONS.getByName(new URL(request.url).pathname).fetch(request);
                }};
            `,
        },
        bundle: true, write: false, format: "esm", platform: "browser", target: "es2022",
        external: ["cloudflare:workers"],
        plugins: [{ name: "mkit-wasm", setup(builder) {
            builder.onResolve({ filter: /mkit_wasm_bg\.wasm$/ }, () => ({ path: "./mkit.wasm", external: true }));
        } }],
    });
    mf = new Miniflare(convertV4MiniflareOptions({
        name: "browser-session-test", modulesRoot: "/",
        compatibilityDate: "2026-09-09", compatibilityFlags: ["nodejs_compat"],
        modules: [
            { type: "ESModule", path: "/session-test.mjs", contents: bundle.outputFiles[0].text },
            { type: "CompiledWasm", path: "/mkit.wasm", contents: readFileSync(fileURLToPath(new NodeURL("../vendor/mkit-wasm/mkit_wasm_bg.wasm", import.meta.url))) },
        ],
        durableObjects: { SESSIONS: { className: "Harness", useSQLite: true } },
    }));
    await mf.ready;
}, 30_000);

afterAll(async () => { await mf?.dispose(); });

function auth(index = 1): AuthenticatedOperation {
    return {
        publicKey: owner, nonce: index.toString(16).padStart(64, "0"),
        digest: (index + 100).toString(16).padStart(64, "0"), expiresAt: NOW + 60_000, body: {},
    };
}
function request(directory: string, input: Record<string, unknown>, now = NOW) {
    return mf.dispatchFetch(`http://localhost/${directory}`, { method: "POST", body: JSON.stringify({ ...input, now }) });
}
type Created = { session: BrowserSession; token: string };
async function create(directory: string, operation = auth()) {
    const response = await request(directory, { op: "create", auth: operation });
    expect(response.status).toBe(200);
    return await response.json() as Created;
}
async function inspect(directory: string) {
    return await (await request(directory, { op: "inspect" })).json() as Record<string, unknown>;
}

describe("browser sessions on transactional SQLite Durable Object storage", () => {
    it("persists only a digest-keyed session and a short-lived replay receipt", async () => {
        const directory = crypto.randomUUID();
        const created = await create(directory);
        expect(created.token).toMatch(/^[0-9a-f]{64}$/);
        expect(created.session).toEqual({ id: tokenDigest(created.token), publicKey: owner, expiresAt: NOW + BROWSER_SESSION_TTL });
        expect(created.session.id).not.toBe(created.token);
        expect(await (await request(directory, { op: "read", id: created.session.id })).json()).toEqual(created.session);
        const rows = await inspect(directory);
        expect(rows[`browser-session:${created.session.id}`]).not.toHaveProperty("token");
        const receipt = rows[`browser-login:${owner}:${auth().nonce}`];
        expect(receipt).toMatchObject({ token: created.token, digest: auth().digest, expiresAt: auth().expiresAt });
        expect(Object.keys(rows)).toHaveLength(4);
        const later = await request(directory, { op: "read", id: created.session.id }, auth().expiresAt);
        expect(await later.json()).toEqual(created.session);
        expect(JSON.stringify(await inspect(directory))).not.toContain(created.token);
    });

    it("returns the same bearer for exact concurrent retries without duplicate records", async () => {
        const directory = crypto.randomUUID();
        const results = await Promise.all([create(directory), create(directory)]);
        expect(results[0]).toEqual(results[1]);
        expect(Object.keys(await inspect(directory))).toHaveLength(4);
        const changed = { ...auth(), digest: "ff".repeat(32) };
        expect((await request(directory, { op: "create", auth: changed })).status).toBe(409);
        expect(Object.keys(await inspect(directory))).toHaveLength(4);
        const next = await create(directory, auth(2));
        expect(next.session.id).not.toBe(results[0].session.id);
    });

    it("logout cannot be undone by replaying its signed login, including after repeated logout", async () => {
        const directory = crypto.randomUUID();
        const created = await create(directory);
        await request(directory, { op: "remove", id: created.session.id });
        await request(directory, { op: "remove", id: created.session.id });
        expect(await (await request(directory, { op: "read", id: created.session.id })).json()).toBeNull();
        expect((await request(directory, { op: "create", auth: auth() })).status).toBe(401);
        expect(JSON.stringify(await inspect(directory))).not.toContain(created.token);
        const fresh = await create(directory, auth(2));
        expect(fresh.session.id).not.toBe(created.session.id);
    });

    it("expires sessions after seven days and rejects expired login requests before allocation", async () => {
        const directory = crypto.randomUUID();
        const created = await create(directory);
        const before = await request(directory, { op: "read", id: created.session.id }, created.session.expiresAt - 1);
        expect(await before.json()).toEqual(created.session);
        expect(await (await request(directory, { op: "read", id: created.session.id }, created.session.expiresAt)).json()).toBeNull();
        expect((await request(directory, { op: "create", auth: auth() }, created.session.expiresAt)).status).toBe(401);
        expect(await inspect(directory)).toEqual({});
        expect((await request(directory, { op: "create", auth: { ...auth(), expiresAt: NOW } })).status).toBe(401);
        expect((await request(directory, { op: "create", auth: { ...auth(), expiresAt: NOW + 330_001 } })).status).toBe(401);
        expect(await inspect(directory)).toEqual({});
    });

    it("rolls back the bearer receipt and session together on storage transaction failure", async () => {
        const directory = crypto.randomUUID();
        expect((await request(directory, { op: "create-fault", auth: auth() })).status).toBe(500);
        expect(await inspect(directory)).toEqual({});
        await create(directory);
    });

    it("prunes at most 32 expired index entries per call until a backlog is drained", async () => {
        const directory = crypto.randomUUID();
        for (let i = 1; i <= 40; i++) await create(directory, auth(i));
        expect(Object.keys(await inspect(directory))).toHaveLength(160);
        for (const remaining of [96, 32, 0]) {
            await request(directory, { op: "read", id: "00".repeat(32) }, NOW + BROWSER_SESSION_TTL);
            expect(Object.keys(await inspect(directory))).toHaveLength(remaining);
        }
    });
});

describe("host-only browser login cookies", () => {
    const token = "ab".repeat(32);
    const read = (cookie: string, url = "https://mkit.sh/create") => requestBrowserSession(new Request(url, { headers: { Cookie: cookie } }));

    it("uses a secure __Host cookie at Path=/ for seven days with no Domain attribute", () => {
        const cookie = browserSessionCookie(token);
        expect(cookie).toBe(`__Host-mkit_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800; Secure`);
        expect(cookie).not.toContain("Domain=");
        expect(browserSessionCookie("")).toContain("Max-Age=0; Secure");
        expect(() => browserSessionCookie("bad; injected=1")).toThrow();
        expect(read(`other=1; __Host-mkit_session=${token}; another=2`)).toBe(tokenDigest(token));
    });

    it("isolates the HTTP development cookie from the HTTPS cookie", () => {
        expect(browserSessionCookie(token, false)).toBe(`mkit_session_local=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`);
        expect(read(`mkit_session_local=${token}`, "http://localhost:8787/")).toBe(tokenDigest(token));
        expect(read(`mkit_session_local=${token}`)).toBeNull();
        expect(read(`__Host-mkit_session=${token}`, "http://localhost:8787/")).toBeNull();
    });

    it.each([
        "", "__Host-mkit_session=", "__Host-mkit_session=short", `prefix__Host-mkit_session=${token}`,
        `__Host-mkit_session=${"AA".repeat(32)}`, `__Host-mkit_session=${token}%00`,
        `__Host-mkit_session=${token}; __Host-mkit_session=${token}`, "other=" + "a".repeat(8192),
    ])("rejects invalid or ambiguous cookie %j", cookie => {
        expect(read(cookie)).toBeNull();
    });
});
