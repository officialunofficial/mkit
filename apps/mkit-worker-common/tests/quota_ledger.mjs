// Local workerd regression for BOTH adapters; no deployment or test endpoint.
// node apps/mkit-worker-common/tests/quota_ledger.mjs repo|vcs|repo-rate http://localhost:PORT /tmp/PERSIST_DIRECTORY
// The Worker must use AUTH_AUDIENCE matching the URL and AUTH_REPOSITORY=default
// for VCS. A fresh signing key isolates the author; Repo also uses a fresh room.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import init, * as wasm from '../../web/vendor/mkit-wasm/pkg/mkit_wasm.js';

const [mode, base, storage] = process.argv.slice(2);
assert.ok(['repo', 'vcs', 'repo-rate'].includes(mode) && base && storage, 'expected repo|vcs|repo-rate, local base URL, persistence directory');
assert.ok(['localhost', '127.0.0.1', '[::1]'].includes(new URL(base).hostname), 'local Workers only');
await init({ module_or_path: await readFile(new URL('../../web/vendor/mkit-wasm/pkg/mkit_wasm_bg.wasm', import.meta.url)) });
const hex = bytes => Buffer.from(bytes).toString('hex');
const seed = crypto.getRandomValues(new Uint8Array(32));
const author = hex(wasm.ed25519_pubkey_from_seed(seed));
const repository = mode.startsWith('repo') ? `quota-${crypto.randomUUID()}` : 'default';
const prefix = mode.startsWith('repo') ? '/mkit.repo.v1.RepoService/' : '/mkit.transport.v1.TransportService/';
const name = `refs/heads/quota-${crypto.randomUUID()}`;
const id = value => Buffer.alloc(32, value % 256).toString('base64');
const target = mode.startsWith('repo') ? { room: repository, name } : { name };
function signedMethod(method, message, nonce = hex(crypto.getRandomValues(new Uint8Array(32)))) {
  const procedure = prefix + method;
  const body = JSON.stringify(message);
  const digest = wasm.blake3_hex(new TextEncoder().encode(body));
  const created = Date.now(), expires = created + 300000, commitment = `body:${digest}`;
  const canonical = ['mkit-write:v2', base, repository, procedure, commitment, created, expires, nonce].join('\n');
  const signature = hex(wasm.ed25519_sign(Buffer.from(wasm.blake3_hex(new TextEncoder().encode(canonical)), 'hex'), seed));
  return { procedure, body, headers: {
    'content-type': 'application/json', 'connect-protocol-version': '1', 'x-envelope-version': '2',
    'x-audience': base, 'x-repository': repository, 'x-content-commitment': commitment, 'x-digest': digest,
    'x-created-at': String(created), 'x-expires-at': String(expires), 'idempotency-key': nonce,
    'x-public-key': author, 'x-signature': signature,
  } };
}
const signed = (value, nonce) => signedMethod('UpdateRef', { ...target, newId: id(value), expectation: 'REF_EXPECTATION_ANY' }, nonce);
async function send(operation) {
  const response = await fetch(base + operation.procedure, { method: 'POST', body: operation.body, headers: operation.headers });
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: response.status, body };
}
function snapshot() {
  return JSON.parse(execFileSync('python3', [fileURLToPath(new URL('./read_auth_ledger.py', import.meta.url)), storage, author], { encoding: 'utf8' }));
}
const first = signed(1), accepted = await send(first);
assert.equal(accepted.status, 200, JSON.stringify(accepted));
if (mode === 'repo-rate') {
  // Compare ledger growth with actual admitted effects, not an assumed number
  // of successes in a timing window. Unique reaction targets make active=true
  // identify acceptance without depending on response ordering.
  const before = snapshot();
  const posts = Array.from({ length: 64 }, (_, i) => signedMethod('PostMessage', { room: repository, text: `rate test ${i}` }));
  const posted = await Promise.all(posts.map(send));
  for (const response of posted) assert.equal(response.status, 200, JSON.stringify(response));
  const admittedPosts = posted.filter(response => response.body.accepted).length;
  assert.ok(admittedPosts > 0 && admittedPosts < posts.length, 'fixture burst must exercise accepted and rate-limited posts');
  const afterPosts = snapshot();
  assert.equal(afterPosts.messages, admittedPosts);
  const reactions = Array.from({ length: 64 }, (_, i) => signedMethod('React', { room: repository, targetId: i.toString(16).padStart(64, '0'), emoji: '👍' }));
  const reacted = await Promise.all(reactions.map(send));
  for (const response of reacted) assert.equal(response.status, 200, JSON.stringify(response));
  const admittedReactions = reacted.filter(response => response.body.active).length;
  assert.ok(admittedReactions > 0 && admittedReactions < reactions.length, 'fixture burst must exercise accepted and rate-limited reactions');
  const afterReactions = snapshot();
  assert.equal(afterReactions.reactions, admittedReactions);
  const postIndex = posted.findIndex(response => response.body.accepted);
  const reactionIndex = reacted.findIndex(response => response.body.active);
  assert.deepEqual(await send(posts[postIndex]), posted[postIndex]);
  assert.deepEqual(await send(reactions[reactionIndex]), reacted[reactionIndex]);
  const afterReplay = snapshot();
  assert.deepEqual(afterReplay, afterReactions, 'admitted chat/reaction replays must not write state');
  const growth = [afterPosts.operations - before.operations, afterReactions.operations - afterPosts.operations];
  console.log(`repo rate: ${JSON.stringify({ growth, admittedPosts, admittedReactions, before, afterPosts, afterReactions })}`);
  assert.deepEqual(growth, [admittedPosts, admittedReactions], 'rate-limited chat/reaction nonces must not allocate replay rows');
  console.log('repo: only admitted chat/reaction effects reserve replay records; admitted retries retain their original results');
  process.exit(0);
}
for (let i = 2; i <= 300; i++) {
  const response = await send(signed(i));
  assert.equal(response.status, 200, `admitted operation ${i}: ${JSON.stringify(response)}`);
}
const before = snapshot();
assert.equal(before.quotaOps, 300);
for (let i = 0; i < 24; i++) {
  const rejected = await send(signed(301 + i));
  assert.equal(rejected.status, 429, `over-quota operation: ${JSON.stringify(rejected)}`);
}
// Exhaustion must not prevent an admitted operation from recovering its result.
for (const replay of await Promise.all(Array.from({ length: 8 }, () => send(first)))) assert.deepEqual(replay, accepted);
const conflict = await send(signed(250, first.headers['idempotency-key']));
assert.ok(conflict.status >= 400 && conflict.status !== 429, `nonce conflict must precede quota: ${JSON.stringify(conflict)}`);
const current = await send({ procedure: prefix + (mode.startsWith('repo') ? 'GetRef' : 'ReadRef'), body: JSON.stringify(target), headers: { 'content-type': 'application/json', 'connect-protocol-version': '1' } });
assert.equal(current.status, 200, JSON.stringify(current));
assert.equal(current.body.objectId, id(300), 'retries and rejected writes must not change the ref');
const after = snapshot();
assert.equal(after.quotaOps, 300);
console.log(`${mode}: ${JSON.stringify({ before, after })}`);
assert.equal(after.operations, before.operations, 'quota-rejected unique nonces must not allocate replay rows');
console.log(`${mode}: 300 admitted writes, 24 rejected nonces, exhausted-quota replay and nonce conflict passed`);
