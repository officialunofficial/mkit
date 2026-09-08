// Shared fixed wire vector, also verified by mkit-core's write_auth tests.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init, * as wasm from '../../web/vendor/mkit-wasm/pkg/mkit_wasm.js';
await init({ module_or_path: await readFile(new URL('../../web/vendor/mkit-wasm/pkg/mkit_wasm_bg.wasm', import.meta.url)) });
const vector = JSON.parse(await readFile(new URL('../../../rust/tests/golden/auth-v2/unary.json', import.meta.url), 'utf8'));
const canonical = ['mkit-write:v2', vector.audience, vector.repository, vector.procedure,
  vector.commitment, vector.created_at, vector.expires_at, vector.nonce].join('\n');
assert.equal(canonical, vector.canonical);
assert.equal(wasm.blake3_hex(new TextEncoder().encode(vector.body)), vector.body_digest);
assert.equal(wasm.blake3_hex(new TextEncoder().encode(canonical)), vector.signing_digest);
const digest = Buffer.from(vector.signing_digest, 'hex');
assert.equal(Buffer.from(wasm.ed25519_sign(digest, Buffer.from(vector.seed, 'hex'))).toString('hex'), vector.signature);
assert.ok(wasm.ed25519_verify(Buffer.from(vector.signature, 'hex'), digest, Buffer.from(vector.public_key, 'hex')));
console.log('shared Rust/JavaScript auth v2 golden passed');
