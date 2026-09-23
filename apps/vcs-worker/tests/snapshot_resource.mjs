// Opt-in local workerd sampling, never an exact isolate peak measurement.
// For wasm memory, append `globalThis.__mkit_wasm_memory=i.memory;` to the
// ignored worker-build index.js in disposable local output; rebuild afterward
// to remove this test-only exposure before any other artifact is used.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const Socket = process.env.MKIT_SNAPSHOT_WS_PACKAGE
  ? require(process.env.MKIT_SNAPSHOT_WS_PACKAGE) : WebSocket;
const endpoint = process.env.MKIT_SNAPSHOT_INSPECTOR_URL;
const workerName = process.env.MKIT_SNAPSHOT_WORKER_NAME ?? "mkit-vcs-managed-local-test";
if (!endpoint) throw new Error("set MKIT_SNAPSHOT_INSPECTOR_URL to workerd /json URL");
const targets = await (await fetch(endpoint + "/json")).json();
const target = targets.find((item) => item.id === `core:user:${workerName}`);
if (!target) throw new Error(`workerd inspector target core:user:${workerName} absent`);
const socket = new Socket(target.webSocketDebuggerUrl, { origin: "http://localhost:8791" });
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});
let next = 0;
let contextId;
const contexts = [];
const pending = new Map();
socket.addEventListener("message", (event) => {
  const result = JSON.parse(event.data);
  if (result.method === "Runtime.executionContextCreated") {
    contextId = result.params.context.id;
    contexts.push({ id: contextId, name: result.params.context.name,
      origin: result.params.context.origin });
  }
  const slot = pending.get(result.id);
  if (!slot) return;
  pending.delete(result.id);
  if (result.error) slot.reject(Error(JSON.stringify(result.error)));
  else slot.resolve(result.result);
});
function call(method, params = {}) {
  const id = ++next;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
const samples = [];
let running = true;
process.on("SIGINT", () => { running = false; });
await call("Runtime.enable");
await call("Profiler.enable");
await call("Profiler.start");
const started = Date.now();
while (running && Date.now() - started < 240_000) {
  try {
    const [heap, wasm] = await Promise.all([
      call("Runtime.getHeapUsage"),
      contextId ? call("Runtime.evaluate", { expression:
        "globalThis.__mkit_wasm_memory?.buffer.byteLength ?? null",
        contextId, returnByValue: true }) : Promise.resolve(null),
    ]);
    samples.push({ at: Date.now() - started, jsUsed: heap.usedSize,
      jsTotal: heap.totalSize, backing: heap.backingStorageSize,
      embedder: heap.embedderHeapUsedSize, wasmBytes: wasm?.result?.value ?? null });
  } catch (error) { console.error("sample error", String(error)); break; }
  await new Promise((resolve) => setTimeout(resolve, 100));
}
const profile = await call("Profiler.stop");
socket.close();
const maxima = Object.fromEntries(["jsUsed", "jsTotal", "backing", "embedder", "wasmBytes"]
  .map((key) => [key, Math.max(0, ...samples.map((sample) => sample[key] ?? 0))]));
console.log(JSON.stringify({ target: target.id, contexts, samples: samples.length,
  elapsedMs: Date.now() - started, maxima,
  profilerSamples: profile.profile?.samples?.length ?? 0,
  first: samples[0], last: samples.at(-1) }));
