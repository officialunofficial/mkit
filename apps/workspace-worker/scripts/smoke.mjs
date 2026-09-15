/** Opt-in live smoke: creates a public remix and uses one real model task.
 * node scripts/smoke.mjs http://localhost:8788 [--agent]
 * Signs with an isolated test identity; WebAuthn is tested separately in the UI. */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import assert from "node:assert/strict";
import WebSocket from "ws";
import * as api from "../vendor/mkit-wasm/mkit_wasm.js";
api.initSync({
    module: await readFile(new URL("../vendor/mkit-wasm/mkit_wasm_bg.wasm", import.meta.url)),
});
const origin = process.argv[2] ?? "http://localhost:8788";
const saved = process.argv.includes("--resume")
    ? JSON.parse(await readFile(".wrangler/smoke-identity.json", "utf8"))
    : null;
const seed = saved ? Buffer.from(saved.seed, "hex") : randomBytes(32),
    pub = Buffer.from(api.ed25519_pubkey_from_seed(seed)).toString("hex");
const enc = new TextEncoder(),
    digest = (value) => api.blake3_hex(enc.encode(value));
let cookie = saved?.cookie ?? "";
let id = saved?.id;
async function request(path, value, repo = "workspaces") {
    const body = JSON.stringify(value),
        now = Date.now(),
        nonce = randomBytes(32).toString("hex"),
        hash = digest(body);
    const canonical = [
        "mkit-write:v2",
        origin,
        repo,
        `/api/workspaces${path}`,
        `body:${hash}`,
        String(now),
        String(now + 300000),
        nonce,
    ].join("\n");
    const response = await fetch(`${origin}/api/workspaces${path}`, {
        method: "POST",
        body,
        headers: {
            "Content-Type": "application/json",
            Origin: origin,
            Cookie: cookie,
            "X-Public-Key": pub,
            "X-Signature": Buffer.from(
                api.ed25519_sign(Buffer.from(digest(canonical), "hex"), seed),
            ).toString("hex"),
            "X-Digest": hash,
            "Idempotency-Key": nonce,
            "X-Created-At": String(now),
            "X-Expires-At": String(now + 300000),
            "X-Envelope-Version": "2",
            "X-Audience": origin,
            "X-Repository": repo,
            "X-Content-Commitment": `body:${hash}`,
        },
    });
    const result = await response.json();
    assert.equal(response.status, 200, JSON.stringify(result));
    cookie = response.headers.get("set-cookie")?.split(";")[0] ?? cookie;
    return result;
}
if (!saved) {
    const prepared = await request("/prepare", { kind: "demo" });
    const g = prepared.grant;
    id = prepared.id;
    const message = [
        "mkit-workspace-grant:v1",
        g.workspaceId,
        g.ownerPublicKey,
        g.agentPublicKey,
        g.source.kind,
        g.source.repository,
        g.source.commitHash,
        g.source.ref ?? "",
        g.source.workspaceId ?? "",
        g.permissions.join(","),
        String(g.createdAt),
        String(g.expiresAt),
    ].join("\n");
    const signature = Buffer.from(
        api.ed25519_sign(Buffer.from(digest(message), "hex"), seed),
    ).toString("hex");
    await request(`/${id}/activate`, { grant: g, signature }, id);
    console.log("Activated signed remix", id);
    await mkdir(".wrangler", { recursive: true });
    await writeFile(
        ".wrangler/smoke-identity.json",
        JSON.stringify({ origin, id, seed: seed.toString("hex"), cookie }),
        { mode: 0o600 },
    );
    await request(
        `/${id}/file`,
        { path: "smoke.txt", content: "Signed editor smoke\n", expectedHash: null },
        id,
    );
    const pubView = await (await fetch(`${origin}/api/workspaces/${id}`)).json();
    assert.equal(pubView.isOwner, false);
    assert.deepEqual(pubView.messages, []);
    assert.equal(pubView.versions.length, 2);
    console.log("Public file/version and private conversation checks passed");
}
if (!saved || process.argv.includes("--terminal")) {
    await new Promise((resolve, reject) => {
        const ws = new WebSocket(`${origin.replace(/^http/, "ws")}/api/workspaces/${id}/terminal`, {
            headers: { Origin: origin, Cookie: cookie },
        });
        let output = "",
            sent = false;
        const timer = setTimeout(() => {
            ws.terminate();
            reject(new Error("PTY timeout: " + output.slice(-400)));
        }, 120000);
        ws.on("error", reject);
        ws.on("message", (data, binary) => {
            if (binary) output += data.toString();
            if (!sent) {
                sent = true;
                ws.send(
                    Buffer.from(
                        "printf 'terminal-persisted\\n' > terminal.txt; printf 'PTY_SMOKE_%s\\n' OK\r",
                    ),
                );
            }
            if (output.includes("PTY_SMOKE_OK")) {
                clearTimeout(timer);
                ws.close();
                resolve();
            }
        });
    });
    console.log("Real container PTY executed a shell command");
}
if (process.argv.includes("--cancel")) await request(`/${id}/cancel`, {}, id);
if (process.argv.includes("--agent")) {
    await request(
        `/${id}/tasks`,
        {
            prompt: "Read smoke.txt and terminal.txt, then create sum.mjs exporting add(a,b). Run a Node assertion that add(2,3) is 5. Keep these files. Briefly report the test result.",
        },
        id,
    );
    console.log("Agent queued; no browser or WebSocket remains connected");
    for (let i = 0; i < 75; i++) {
        await new Promise((r) => setTimeout(r, 4000));
        const view = await (
            await fetch(`${origin}/api/workspaces/${id}`, { headers: { Cookie: cookie } })
        ).json();
        if (["completed", "failed", "cancelled"].includes(view.task?.status)) {
            assert.equal(view.task.status, "completed", JSON.stringify(view.task));
            assert.ok(view.files.some((f) => f.path === "sum.mjs"));
            assert.ok(view.files.some((f) => f.path === "terminal.txt"));
            console.log("Agent completed and signed version", view.task.versionHash);
            break;
        }
        if (i === 74) throw new Error("Agent task timed out");
    }
}
const logout = await fetch(`${origin}/api/workspaces/${id}/session`, {
    method: "DELETE",
    headers: { Origin: origin, Cookie: cookie },
});
assert.equal(logout.status, 200);
assert.equal(
    (await (await fetch(`${origin}/api/workspaces/${id}`, { headers: { Cookie: cookie } })).json())
        .isOwner,
    false,
);
console.log("Logout invalidated session. Smoke passed:", `${origin}/create?id=${id}`);
