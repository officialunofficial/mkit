// Local inspector only. Sampled retention evidence; never a complete peak claim.
// node isolate-sample.mjs <inspector port> <output.json> <stop-file>
import {writeFile, access} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
const [port, output, stop] = process.argv.slice(2);
if (!/^\d+$/.test(port || '') || !output || !stop) throw Error('three arguments required');
const {default: WebSocket} = await import(process.env.MKIT_PROBE_WS_MODULE ?? 'ws');
const deadline = Date.now() + 30 * 60 * 1000;
const clients = new Map(), samples = [], gaps = [];
async function client(target) {
  const socket = new WebSocket(target.webSocketDebuggerUrl,
    {headers: {Origin: 'https://devtools.devprod.cloudflare.dev'}});
  await Promise.race([new Promise((resolve, reject) => {
    socket.once('open', resolve); socket.once('error', reject);
  }), delay(3000).then(() => {throw Error('inspector connection timeout');})]);
  let serial = 0;
  const pending = new Map();
  socket.on('message', raw => {
    const message = JSON.parse(raw.toString());
    const waiter = pending.get(message.id);
    if (waiter) {pending.delete(message.id);clearTimeout(waiter.timer);
      message.error ? waiter.reject(Error(JSON.stringify(message.error))) : waiter.resolve(message.result);}
  });
  const rpc = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++serial;
    const timer = setTimeout(() => {pending.delete(id);reject(Error('inspector RPC timeout'));}, 3000);
    pending.set(id, {resolve, reject, timer});socket.send(JSON.stringify({id, method, params}));
  });
  const isolate = await rpc('Runtime.getIsolateId');
  return {socket, rpc, isolate: isolate.id, target: target.id};
}
try {
  while (Date.now() < deadline) {
    try {await access(stop);break;} catch {}
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`,
        {signal: AbortSignal.timeout(3000)})).json();
      const enabled = targets.filter(t => t.webSocketDebuggerUrl);
      if (enabled.length > 16) gaps.push({at: Date.now(), error: "target bound exceeded", targets: enabled.length});
      for (const target of enabled.slice(0, 16)) {
        let active = clients.get(target.id);
        if (!active) {active = await client(target);clients.set(target.id, active);}
        const started = Date.now();
        try {
          const heap = await active.rpc('Runtime.getHeapUsage');
          const memory = await active.rpc('Runtime.evaluate', {expression:
            'globalThis.__mkitLaunchMemory ? globalThis.__mkitLaunchMemory() : null',
            returnByValue: true, timeout: 1000});
          samples.push({started, finished: Date.now(), isolate: active.isolate,
            target: active.target, heap, wasm: memory.result?.value ?? null});
        } catch (error) {gaps.push({at: Date.now(), target: active.target, error: String(error)});}
      }
    } catch (error) {gaps.push({at: Date.now(), error: String(error)});}
    if (samples.length + gaps.length > 100000) throw Error('observation bound exceeded');
    await delay(250);
  }
} finally {
  for (const active of clients.values()) active.socket.terminate();
  await writeFile(output, JSON.stringify({scope: 'sampled local CDP isolate retention',
    completePeakCertificate: false, deadlineExceeded: Date.now() >= deadline, samples, gaps}, null, 2));
}
