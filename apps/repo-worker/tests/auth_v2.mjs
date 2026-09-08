// Against a local Worker configured AUTH_AUDIENCE=http://localhost:8790.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init, * as wasm from '../../web/vendor/mkit-wasm/pkg/mkit_wasm.js';
await init({module_or_path: await readFile(new URL('../../web/vendor/mkit-wasm/pkg/mkit_wasm_bg.wasm',import.meta.url))});
const base=process.argv[2]??'http://localhost:8790';
const room=`auth-${crypto.randomUUID()}`;
const seed=crypto.getRandomValues(new Uint8Array(32));
const hex=b=>Buffer.from(b).toString('hex');
const pubkey=hex(wasm.ed25519_pubkey_from_seed(seed));
function signed(method,message,{nonce=hex(crypto.getRandomValues(new Uint8Array(32))),audience=base,repository=room,created=Date.now()}={}) {
 const procedure=`/mkit.repo.v1.RepoService/${method}`,body=JSON.stringify(message),digest=wasm.blake3_hex(new TextEncoder().encode(body));
 const expires=created+300000,commitment=`body:${digest}`;
 const canonical=['mkit-write:v2',audience,repository,procedure,commitment,created,expires,nonce].join('\n');
 const signature=hex(wasm.ed25519_sign(Buffer.from(wasm.blake3_hex(new TextEncoder().encode(canonical)),'hex'),seed));
 return {procedure,body,headers:{'content-type':'application/json','connect-protocol-version':'1','x-envelope-version':'2','x-audience':audience,'x-repository':repository,'x-content-commitment':commitment,'x-digest':digest,'x-created-at':String(created),'x-expires-at':String(expires),'idempotency-key':nonce,'x-public-key':pubkey,'x-signature':signature}};
}
async function send(op) { const r=await fetch(base+op.procedure,{method:'POST',body:op.body,headers:op.headers});const body=await r.json();return {status:r.status,body}; }
async function read(method,msg) {return send({procedure:`/mkit.repo.v1.RepoService/${method}`,body:JSON.stringify(msg),headers:{'content-type':'application/json','connect-protocol-version':'1'}});}
const name='refs/heads/auth',id=n=>Buffer.alloc(32,n).toString('base64');
const update=n=>({room,name,newId:id(n),expectation:'REF_EXPECTATION_ANY'});
const first=signed('UpdateRef',update(1)),second=signed('UpdateRef',update(2));
const a=await send(first);assert.equal(a.status,200,JSON.stringify(a));
assert.equal((await send(second)).status,200);
assert.deepEqual(await send(first),a);
assert.equal((await read('GetRef',{room,name})).body.objectId,id(2));
const concurrent=await Promise.all(Array.from({length:40},()=>send(first)));for(const r of concurrent)assert.deepEqual(r,a);
assert.notEqual((await send(signed('UpdateRef',update(3),{nonce:first.headers['idempotency-key']}))).status,200);
assert.equal((await send(signed('UpdateRef',update(3),{audience:'https://other.example'}))).status,401);
assert.equal((await send(signed('UpdateRef',update(3),{repository:'elsewhere'}))).status,401);
assert.equal((await send(signed('UpdateRef',update(3),{created:Date.now()-300001}))).status,401);
const old=signed('UpdateRef',update(3));old.headers['x-envelope-version']='1';assert.equal((await send(old)).status,401);
const bytes=Buffer.from(`object-${room}`),objectId=Buffer.from(wasm.blake3_hex(bytes),'hex').toString('base64');
const put=signed('PutObject',{room,objectId,bytes:bytes.toString('base64')});
const puts=await Promise.all(Array.from({length:12},()=>send(put)));for(const r of puts)assert.deepEqual(r,puts[0]);assert.equal(puts[0].status,200,JSON.stringify(puts));
assert.deepEqual(await send(put),puts[0]);
const post=signed('PostMessage',{room,text:'one logical message'});const posted=await send(post);assert.equal(posted.status,200,JSON.stringify(posted));
for(const r of await Promise.all(Array.from({length:8},()=>send(post))))assert.deepEqual(r,posted);
assert.equal((await read('ListMessages',{room})).body.messages.length,1);
const react=signed('React',{room,targetId:hex(Buffer.from(posted.body.messageId,'base64')),emoji:'👍'});const reacted=await send(react);assert.equal(reacted.status,200,JSON.stringify(reacted));
for(const r of await Promise.all(Array.from({length:8},()=>send(react))))assert.deepEqual(r,reacted);
assert.equal((await read('ListReactions',{room})).body.reactions.length,1);
console.log('repo v2: stable ref/object/chat/reaction replay, concurrency, nonce conflict, destination, expiry, v1 rejection passed');
