// Independent local auth-v2 signer; never prints the private key or envelope.
import assert from 'node:assert/strict';
import {createPrivateKey, createPublicKey, randomBytes, sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const [seed, run, audience, repository, procedure, body] = process.argv.slice(2);
function hash(bytes) {
  const result = spawnSync('b3sum', ['--no-names'], {input:bytes});
  assert.equal(result.status, 0);
  return result.stdout.toString().trim();
}
const derived = hash(Buffer.concat([Buffer.from('mkit-server-conformance signer\n'),
  Buffer.from(seed,'hex'), Buffer.from(run+'\nembedding.reference_fixture/repository-a')]));
const key = createPrivateKey({format:'der',type:'pkcs8',key:Buffer.concat([
  Buffer.from('302e020100300506032b657004220420','hex'),Buffer.from(derived,'hex')])});
const publicKey = createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('hex');
assert.equal(repository.split('/')[0], `ed25519-${publicKey}`);
const created = Date.now().toString(), expires = (Number(created)+60000).toString(), nonce=randomBytes(32).toString('hex');
const digest=hash(Buffer.from(body)), commitment=`body:${digest}`;
const canonical=['mkit-write:v2',audience,repository,procedure,commitment,created,expires,nonce].join('\n');
console.log(JSON.stringify({'X-Envelope-Version':'2','X-Audience':audience,'X-Repository':repository,
  'X-Public-Key':publicKey,'X-Signature':sign(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),key).toString('hex'),
  'X-Content-Commitment':commitment,'X-Digest':digest,'X-Created-At':created,'X-Expires-At':expires,'Idempotency-Key':nonce}));
