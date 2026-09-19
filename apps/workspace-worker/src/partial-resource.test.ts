// Opt-in deployed-engine measurements, not a production memory guarantee.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { performance } from "node:perf_hooks";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions, Response as MiniflareResponse } from "miniflare";
import { describe, expect, it } from "vitest";

const fixtures = process.env.MKIT_PARTIAL_RESOURCE_DIR;
const root = fileURLToPath(new NodeURL("./", import.meta.url));
const worker = `
import { initSync } from '../vendor/mkit-wasm/mkit_wasm.js';
import wasmModule from '../vendor/mkit-wasm/mkit_wasm_bg.wasm';
import { mkit, hex, fromHex } from './mkit';
import { importPartialBundle } from './partial-source';
import { verifyPartialSnapshot } from './partial-wasm';
import { createPartialCandidate } from './partial-candidate';
import { getBlob, putBlob } from './objects';
const wasm = initSync({ module: wasmModule });
const memories = new Set([wasm.memory]);
const instantiate = WebAssembly.instantiate.bind(WebAssembly);
WebAssembly.instantiate = async (...args) => {
  const result = await instantiate(...args);
  const instance = result.instance ?? result;
  for (const value of Object.values(instance.exports))
    if (value instanceof WebAssembly.Memory) memories.add(value);
  return result;
};
const memory = () => ({ wasmBytes: wasm.memory.buffer.byteLength,
  runtimeWasmBytes: [...memories].map(value => value.buffer.byteLength) });
let saved;
export default { async fetch(request, env) {
  const stage = new URL(request.url).pathname.slice(1);
  const metadata = JSON.parse(env.METADATA);
  if (stage === 'baseline') {
    // Retain the real agent/tokenizer runtime footprint, but never call a model.
    const { runAgent } = await import('./nanocodex');
    await runAgent({ prompt: 'resource baseline', tools: {}, apiKey: 'local-fixture',
      signal: new AbortController().signal });
    return Response.json(memory());
  }
  if (stage === 'verify') {
    const bytes = new Uint8Array(await request.arrayBuffer());
    const limits = new URL(request.url).searchParams.get('limits');
    try {
      verifyPartialSnapshot(bytes, metadata.base, JSON.stringify(metadata.paths), limits);
      return Response.json({ accepted: true, wasmBytes: wasm.memory.buffer.byteLength });
    } catch (error) { return Response.json({ accepted: false, error: String(error) }); }
  }
  if (stage === 'import') {
    const bundle = new Uint8Array(await request.arrayBuffer());
    const requestData = { kind: 'partial-bundle', baseCommit: metadata.base,
      selectedPaths: metadata.paths, bundleDigest: metadata.digest };
    const imported = await importPartialBundle('https://fixture.invalid', env.OBJECTS,
      'resource-fixture', requestData, async () => new Response(bundle));
    saved = { bundle, imported };
    return Response.json({ ...memory(),
      files: Object.keys(imported.files).length, inputBytes: bundle.length });
  }
  if (stage === 'edit') {
    const current = {};
    for (const [path, file] of Object.entries(saved.imported.files)) {
      const bytes = await getBlob(env.OBJECTS, file.hash);
      // Distinct replacements must not defeat shared-representation caching.
      bytes[0] = (bytes[0] + Object.keys(current).length + 1) % 256;
      current[path] = { ...file, hash: await putBlob(env.OBJECTS, bytes) };
    }
    const result = await createPartialCandidate({ workspaceId: 'resource-fixture',
      objects: env.OBJECTS, bundle: saved.bundle, baseCommit: metadata.base,
      selectedPaths: metadata.paths, original: saved.imported.files, current,
      seedHex: '41'.repeat(32),
      agentPublicKey: hex(mkit.ed25519_pubkey_from_seed(fromHex('41'.repeat(32)))),
      message: 'Resource measurement', beforeSign: async () => {} });
    if (result.status !== 'ready') throw new Error('expected changed candidate');
    saved.candidate = result.candidate;
    return Response.json({ ...memory(), candidate: result.candidate.id });
  }
  if (stage === 'readback') {
    const stored = await env.OBJECTS.get(saved.candidate.key);
    const bytes = new Uint8Array(await stored.arrayBuffer());
    if (mkit.blake3_hex(bytes) !== saved.candidate.digest) throw new Error('readback mismatch');
    return Response.json({ ...memory(), updateBytes: bytes.length });
  }
  return new Response('missing', { status: 404 });
} };
`;

async function inspector(mf: Miniflare) {
    const endpoint = await mf.getInspectorURL();
    const socket = new WebSocket(new NodeURL("/core:user:resource", endpoint.href).href);
    await new Promise<void>((resolve, reject) => {
        socket.addEventListener("open", () => resolve(), { once: true });
        socket.addEventListener("error", () => reject(new Error("inspector connection failed")), { once: true });
    });
    let next = 0;
    const pending = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void }>();
    socket.addEventListener("message", (event) => {
        const response = JSON.parse(String(event.data));
        const request = pending.get(response.id);
        if (!request) return;
        pending.delete(response.id);
        if (response.error) request.reject(new Error(JSON.stringify(response.error)));
        else request.resolve(response.result ?? {});
    });
    return {
        call(method: string): Promise<Record<string, unknown>> {
            const id = ++next;
            return new Promise((resolve, reject) => {
                pending.set(id, { resolve, reject });
                socket.send(JSON.stringify({ id, method, params: {} }));
            });
        },
        close() { socket.close(); },
    };
}

describe.skipIf(!fixtures)("opt-in Workerd partial resource measurements", () => {
    for (const name of ["large", "many", "bundle_limit", "shared"]) {
        it(`${name}: import, edit, persist and read back with compiled wasm`, async () => {
            const metadata = JSON.parse(readFileSync(`${fixtures}/${name}.json`, "utf8"));
            const bytes = readFileSync(`${fixtures}/${name}.mkwb`);
            const built = await build({
                stdin: { contents: worker, resolveDir: root, sourcefile: "resource-harness.ts", loader: "ts" },
                bundle: true, write: false, format: "esm", platform: "browser", target: "es2022",
                plugins: [{ name: "wasm-module", setup(builder) {
                    builder.onResolve({ filter: /mkit_wasm_bg\.wasm$/ }, () => ({ path: "./mkit.wasm", external: true }));
                    builder.onResolve({ filter: /tiktoken_bg\.wasm$/ }, () => ({ path: "./tiktoken.wasm", external: true }));
                    builder.onResolve({ filter: /\/nanocodex\.wasm$/ }, () => ({ path: "./nanocodex.wasm", external: true }));
                } }],
            });
            const mf = new Miniflare(convertV4MiniflareOptions({
                name: "resource", compatibilityDate: "2026-09-09", inspectorPort: 0,
                compatibilityFlags: ["nodejs_compat"],
                modulesRoot: "/", modules: [
                    { type: "ESModule", path: "/resource.mjs", contents: built.outputFiles[0]!.text },
                    { type: "CompiledWasm", path: "/mkit.wasm", contents: readFileSync(`${root}../vendor/mkit-wasm/mkit_wasm_bg.wasm`) },
                    { type: "CompiledWasm", path: "/tiktoken.wasm", contents: readFileSync(`${root}../node_modules/tiktoken/lite/tiktoken_bg.wasm`) },
                    { type: "CompiledWasm", path: "/nanocodex.wasm", contents: readFileSync(`${root}../vendor/nanocodex.wasm`) },
                ],
                r2Buckets: ["OBJECTS"], bindings: { METADATA: JSON.stringify(metadata) },
                outboundService: async (request) => {
                    expect(request.url).toBe("https://api.groq.com/openai/v1/responses");
                    const item = { type: "message", id: "msg", role: "assistant", status: "completed",
                        content: [{ type: "output_text", text: "done", annotations: [] }] };
                    const events = [
                        { type: "response.created", response: { id: "fixture", status: "in_progress", output: [] } },
                        { type: "response.output_item.done", output_index: 0, item },
                        { type: "response.completed", response: { id: "fixture", status: "completed", output: [item],
                            usage: { input_tokens: 10, output_tokens: 1, total_tokens: 11 } } },
                    ];
                    return new MiniflareResponse(events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
                        { headers: { "content-type": "text/event-stream" } });
                },
            }));
            let cdp: Awaited<ReturnType<typeof inspector>> | undefined;
            try {
                await mf.ready;
                cdp = await inspector(mf);
                const samples: Record<string, unknown>[] = [];
                await cdp.call("Profiler.enable");
                await cdp.call("Profiler.start");
                for (const stage of ["baseline", "import", "edit", "readback"]) {
                    const started = performance.now();
                    const response = await mf.dispatchFetch(`https://fixture.invalid/${stage}`, stage === "import"
                        ? { method: "POST", body: bytes } : {});
                    expect(response.status, await response.clone().text()).toBe(200);
                    const output = await response.json();
                    const elapsedMs = performance.now() - started;
                    const heap = await cdp.call("Runtime.getHeapUsage").catch((error) => ({ unavailable: String(error) }));
                    samples.push({ stage, elapsedMs, ...output as object, heap });
                }
                const { profile } = await cdp.call("Profiler.stop") as { profile: {
                    startTime: number; endTime: number; samples?: number[]; timeDeltas?: number[];
                    nodes: { id: number; callFrame: { functionName: string } }[];
                } };
                const idle = new Set(profile.nodes.filter((node) => node.callFrame.functionName === "(idle)").map((node) => node.id));
                const nonIdleSampleMicroseconds = profile.samples?.reduce((total, sample, index) =>
                    total + (idle.has(sample) ? 0 : (profile.timeDeltas?.[index] ?? 0)), 0);
                writeFileSync(`${fixtures}/${name}.measurement.json`, JSON.stringify({ name, metadata, samples,
                    profiler: { elapsedMicroseconds: profile.endTime - profile.startTime,
                        sampleCount: profile.samples?.length, nonIdleSampleMicroseconds } }, null, 2));

                // Valid unchanged fixtures succeed at the actual cap; lowering the
                // corresponding cap by one must reject (not malformed-input rejection).
                if (name !== "shared") {
                    const limits = { max_selected_file_bytes: name === "many" ? 4 * 1024 : 256 * 1024,
                        max_total_selected_bytes: 1024 * 1024,
                        max_witness_bytes: 1024 * 1024, max_bundle_bytes: 4 * 1024 * 1024 };
                    const verify = async (active: typeof limits) => {
                        const response = await mf.dispatchFetch(`https://fixture.invalid/verify?limits=${encodeURIComponent(JSON.stringify(active))}`,
                            { method: "POST", body: bytes });
                        return response.json() as Promise<{ accepted: boolean; error?: string }>;
                    };
                    expect((await verify(limits)).accepted).toBe(true);
                    for (const field of ["max_selected_file_bytes", "max_total_selected_bytes", "max_witness_bytes"] as const) {
                        const result = await verify({ ...limits, [field]: limits[field] - 1 });
                        expect(result.accepted).toBe(false);
                        expect(result.error).toMatch(/limit|large|witness|bound/i);
                    }
                    if (name === "bundle_limit")
                        expect((await verify({ ...limits, max_bundle_bytes: limits.max_bundle_bytes - 1 })).accepted).toBe(false);
                }
            } finally {
                cdp?.close();
                await mf.dispose();
            }
        }, 300_000);
    }
});
