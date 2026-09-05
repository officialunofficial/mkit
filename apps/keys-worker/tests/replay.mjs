// Run against a local keys Worker: node tests/replay.mjs http://localhost:8789
// Uses real Wasm signing and the real SQLite Durable Object adapter.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import init, * as wasm from '../../web/vendor/mkit-wasm/pkg/mkit_wasm.js';
await init({ module_or_path: await readFile(new URL('../../web/vendor/mkit-wasm/pkg/mkit_wasm_bg.wasm', import.meta.url)) });
const base = process.argv[2] ?? 'http://localhost:8789';
const seed = new Uint8Array(32).fill(19);
const hex = b => Buffer.from(b).toString('hex');
const pubkey = hex(wasm.ed25519_pubkey_from_seed(seed));
function operation(name, nonce = hex(crypto.getRandomValues(new Uint8Array(32))), audience = base, repository = 'keys') {
  const body = JSON.stringify({ name });
  const digest = wasm.blake3_hex(new TextEncoder().encode(body));
  const created = String(Date.now()), expires = String(Number(created) + 300000);
  const canonical = ['mkit-write:v2', audience, repository, '/mkit.keys.v1.Keys/SetName', `body:${digest}`, created, expires, nonce].join('\n');
  const signingDigest = Buffer.from(wasm.blake3_hex(new TextEncoder().encode(canonical)), 'hex');
  return { method: 'PUT', body, headers: { 'content-type': 'application/json', 'x-envelope-version': '2', 'x-audience': audience,
    'x-repository': repository, 'x-content-commitment': `body:${digest}`, 'x-digest': digest, 'x-created-at': created,
    'x-expires-at': expires, 'idempotency-key': nonce, 'x-public-key': pubkey, 'x-signature': hex(wasm.ed25519_sign(signingDigest, seed)) } };
}
const put = op => fetch(`${base}/name/${pubkey}`, op);
const resume = process.argv.indexOf('--resume');
if (resume !== -1) {
  const first = JSON.parse(await readFile(process.argv[resume + 1], 'utf8'));
  const replay = await fetch(`${base}/name/${pubkey.toUpperCase()}`, first);
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).name, 'first');
  assert.equal((await (await fetch(`${base}/name/${pubkey}`)).json()).name, 'second');
  console.log('replay record and later name survive Worker restart');
  process.exit(0);
}
const unknown = hex(wasm.ed25519_pubkey_from_seed(crypto.getRandomValues(new Uint8Array(32))));
assert.equal((await fetch(`${base}/name/${unknown}`)).status, 404, 'unset name is absent without any KV binding');
const missingBatch = await fetch(`${base}/resolve`, { method: 'POST', body: JSON.stringify({ pubkeys: [unknown] }) });
assert.equal(missingBatch.status, 200);
assert.deepEqual((await missingBatch.json()).names, {});
const first = operation('first'), second = operation('second');
assert.equal((await put(first)).status, 200);
assert.equal((await put(second)).status, 200);
const replay = await fetch(`${base}/name/${pubkey.toUpperCase()}`, first);
assert.equal(replay.status, 200);
assert.equal((await replay.json()).name, 'first');
assert.equal((await (await fetch(`${base}/name/${pubkey}`)).json()).name, 'second');
assert.notEqual((await put(operation('changed', first.headers['idempotency-key']))).status, 200);
assert.equal((await put(operation('wrong-audience', undefined, 'https://other.example'))).status, 401);
assert.equal((await put(operation('wrong-repository', undefined, base, 'other'))).status, 401);
const old = operation('legacy'); old.headers['x-envelope-version'] = '1';
assert.equal((await put(old)).status, 401);
const resolved = await fetch(`${base}/resolve`, { method: 'POST', body: JSON.stringify({ pubkeys: [pubkey] }) });
assert.equal((await resolved.json()).names[pubkey], 'second');
const prepare = process.argv.indexOf('--prepare');
if (prepare !== -1) await writeFile(process.argv[prepare + 1], JSON.stringify(first));
if (process.argv.includes('--fault')) {
  for (const boundary of ['after-name', 'after-result']) {
    const interrupted = operation(`third-${boundary}`);
    const before = await (await fetch(`${base}/name/${pubkey}`)).json();
    const failed = await put({ ...interrupted, headers: { ...interrupted.headers, 'x-mkit-test-fault': boundary } });
    assert.equal(failed.status, 500, 'injected failure must abort transaction');
    assert.deepEqual(await (await fetch(`${base}/name/${pubkey}`)).json(), before);
    const resumed = await put(interrupted);
    assert.equal(resumed.status, 200);
    assert.equal((await resumed.json()).name, `third-${boundary}`);
    assert.equal((await (await fetch(`${base}/name/${pubkey}`)).json()).name, `third-${boundary}`);
  }
}
console.log('keys replay, nonce conflict, destination isolation, legacy rejection and read consistency passed');
