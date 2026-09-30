#!/usr/bin/env node
// Test the built, test-faults Worker on the pinned wrangler/workerd runtime.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp, writeFile, open} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import net from 'node:net';
const root = resolve(import.meta.dirname, '..');
const scratch = await mkdtemp(join(process.env.TMPDIR, 'hook-runtime-'));
let calls = 0, closed = 0, redirected = 0;
const inspections = [];
const server = createServer((request, response) => {
  calls++;
  request.on('close', () => { closed++; });
  if (request.url === '/redirect-target') { redirected++; response.end('followed'); return; }
  let body = '';
  request.on('data', chunk => { body += chunk; });
  request.on('end', () => {
    if (request.url.startsWith('/inspect-')) {
      const json = JSON.parse(body);
      assert.equal(json.phase, 'INSPECT_PHASE_PRE_RECEIVE');
      assert.equal(json.inspectionId, 'inspection:runtime-probe');
      assert.deepEqual(json.objects, [{id:'IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=', size:'123', kind:'INSPECT_OBJECT_KIND_BLOB'}]);
      assert.equal(request.headers['x-mkit-hook-audience'], 'https://hook-probe.invalid');
      assert.ok(request.headers['x-mkit-hook-signature']);
      inspections.push({body, nonce:request.headers['x-mkit-hook-nonce']});
      response.writeHead(200, {'content-type':'application/json'});
      response.end(request.url === '/inspect-pass' ? '{"pass":{}}' : request.url === '/inspect-reject' ? '{"quarantine":{"reason":"policy"}}' : '{"defer":{"retryAfterMs":1}}');
      return;
    }
    assert.equal(body, '{ "probe": true }');
    assert.equal(request.headers['x-mkit-hook-audience'], 'https://hook-probe.invalid');
    if (request.url === '/redirect') { response.writeHead(302, {location:'/redirect-target'}); response.end(); }
    else if (request.url === '/oversize') { response.writeHead(200, {'content-type':'application/json'}); response.write('abcdef'); }
    else if (request.url === '/body') { response.writeHead(200, {'content-type':'application/json'}); response.flushHeaders(); }
    // Otherwise stall before headers; no JS timer keeps the fixture alive.
    response.on('close', () => { closed++; });
  });
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const fixture = `http://127.0.0.1:${server.address().port}`;
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = Number(process.env.VCS_CONFORMANCE_PORT || listener.address().port);
await new Promise(resolve => listener.close(resolve));
const config = join(scratch, 'wrangler.json');
await writeFile(config, JSON.stringify({name:'mkit-hook-runtime-probe', main:join(root,'apps/vcs-worker/tests/hook-fetch-probe/wrapper.mjs'), compatibility_date:'2026-09-09', build:{command:'true'}, vars:{HOOK_PROBE_ORIGIN:fixture}}));
const log = await open(join(scratch,'wrangler.log'), 'w');
const child = spawn('npx', ['--yes','wrangler@4.134.0','dev','--config',config,'--ip','127.0.0.1','--port',String(port),'--show-interactive-dev-session=false'], {cwd:root, detached:true, stdio:['ignore',log.fd,log.fd], env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
try {
  const origin = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let attempt = 0; attempt < 240; attempt++) {
    try { await fetch(`${origin}/__mkit_test/worker-sleep`, {signal:AbortSignal.timeout(2000)}); ready = true; break; }
    catch { await delay(250); }
  }
  assert.ok(ready, `wrangler did not start; see ${scratch}/wrangler.log`);
  const timer = await (await fetch(`${origin}/__mkit_test/worker-sleep`)).json();
  assert.equal(timer.slept, true); assert.equal(timer.timedOut, true); assert.equal(timer.activeTimers, 0);
  for (const mode of ['stall','body','cancel','oversize','redirect']) {
    const before = calls;
    const response = await fetch(`${origin}/__mkit_test/hook-fetch?mode=${mode}`, {signal:AbortSignal.timeout(5000)});
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.calls, 1, `${mode}: exactly one fetch`);
    assert.equal(result.aborted, 1, `${mode}: underlying signal aborted`);
    assert.equal(result.activeTimers, 0, `${mode}: no pending timer after completion`);
    assert.equal(calls - before, 1);
    if (['stall','body','cancel'].includes(mode)) assert.equal(result.timedOut, true);
    if (mode === 'oversize') { assert.equal(result.status, 200); assert.equal(result.bytes, 5); }
    if (mode === 'redirect') assert.equal(result.status, 302);
    console.log(`PASS WorkerSleep/FetchChannel ${mode}`);
  }
  assert.equal(redirected, 0);
  for (const [mode, verdict] of [['inspect-pass','pass'], ['inspect-reject','reject'], ['inspect-defer','unavailable']]) {
    const before = inspections.length;
    const response = await fetch(`${origin}/__mkit_test/hook-fetch?mode=${mode}`, {signal:AbortSignal.timeout(5000)});
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(result.verdicts, [verdict, verdict]);
    assert.equal(result.calls, 2);
    assert.equal(result.activeTimers, 0);
    assert.equal(inspections.length - before, 2);
    assert.equal(inspections[before].body, inspections[before + 1].body);
    assert.notEqual(inspections[before].nonce, inspections[before + 1].nonce);
    console.log(`PASS Worker RemoteInspector/FetchChannel ${mode}`);
  }
  assert.ok(closed >= 3, 'local fixture observed cancellation');
  console.log('PASS runtime timer expiry, cancellation cleanup, streamed cap and manual redirect');
} finally {
  try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await log.close();
  console.log(`Runtime evidence: ${scratch}`);
}
