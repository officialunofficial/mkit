// Local workerd only. Usage: node profile.mjs <HTTP port> <inspector port> <output dir>
import { writeFile } from 'node:fs/promises';
const { default: WebSocket } = await import(process.env.MKIT_PROBE_WS_MODULE ?? 'ws');
const [port, inspector, output] = process.argv.slice(2);
if (!port || !inspector || !output) throw Error('three arguments required');
const origin = `http://127.0.0.1:${port}`;
const targets = await (await fetch(`http://127.0.0.1:${inspector}/json/list`)).json();
const target = targets.find(t => t.webSocketDebuggerUrl);
const ws = new WebSocket(target.webSocketDebuggerUrl, { headers: { Origin: "https://devtools.devprod.cloudflare.dev" } });
await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
let seq = 0;
const pending = new Map();
ws.addEventListener('message', ev => {
  const msg = JSON.parse(ev.data);
  if (pending.has(msg.id)) { const { resolve, reject } = pending.get(msg.id); pending.delete(msg.id); msg.error ? reject(Error(JSON.stringify(msg.error))) : resolve(msg.result); }
});
function rpc(method, params = {}) { return new Promise((resolve, reject) => { const id = ++seq; pending.set(id, { resolve, reject }); ws.send(JSON.stringify({ id, method, params })); }); }
const headers = { 'content-type': 'application/json', 'x-repository': `ed25519-${'11'.repeat(32)}/cpu` };
// Warm the deployment guard before profiling; cold requests intentionally go live.
await (await fetch(`${origin}/mkit.transport.v1.TransportService/GetServerInfo`, { method: 'POST', headers, body: '{}' })).text();
console.log(await (await fetch(`${origin}/seed`)).text());
const request = () => fetch(`${origin}/mkit.transport.v1.TransportService/ListRefs`, { method: 'POST', headers, body: '{"pageSize":10000}' });
const warm = await (await request()).json();
if (!warm.refs?.length || !(warm.nextPageToken || warm.next_page_token)) throw Error(`probe did not exercise bounded snapshot paging: ${JSON.stringify(warm).slice(0,200)}`);
await rpc('Profiler.enable');
await rpc('Profiler.setSamplingInterval', { interval: 100 });
await rpc('Profiler.start');
const trials = 30;
let bytes = 0;
for (let i = 0; i < trials; i++) { const r = await request(); if (!r.ok) throw Error(await r.text()); bytes = (await r.arrayBuffer()).byteLength; }
const { profile } = await rpc('Profiler.stop');
await writeFile(`${output}/published-view.cpuprofile`, JSON.stringify(profile));
const frames = new Map(profile.nodes.map(n => [n.id, n.callFrame]));
let active = 0, wasm = 0;
for (let i = 0; i < profile.samples.length; i++) {
  const f = frames.get(profile.samples[i]);
  const delta = profile.timeDeltas[i];
  if (!['(idle)', '(program)', '(root)'].includes(f.functionName)) active += delta;
  if (f.url.startsWith('wasm:') || f.functionName.includes('wasm-function')) wasm += delta;
}
const result = { trials, refs_per_page: warm.refs.length, encoded_response_bytes: bytes, active_sample_ms_per_request: active / trials / 1000, wasm_sample_ms_per_request: wasm / trials / 1000, wall_ms_per_request: (profile.endTime - profile.startTime) / trials / 1000 };
console.log(JSON.stringify(result));
await writeFile(`${output}/published-view-cpu.json`, JSON.stringify(result, null, 2));
ws.terminate();
