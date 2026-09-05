// Real local workerd integration: AUTH_AUDIENCE=http://localhost:8791,
// AUTH_REPOSITORY=default. Pass --fault with a test-faults build.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import init,* as wasm from '../../web/vendor/mkit-wasm/pkg/mkit_wasm.js';
await init({module_or_path:await readFile(new URL('../../web/vendor/mkit-wasm/pkg/mkit_wasm_bg.wasm',import.meta.url))});
const base=process.argv[2]??'http://localhost:8791',repository='default',seed=crypto.getRandomValues(new Uint8Array(32));
const hex=b=>Buffer.from(b).toString('hex'),b3=b=>wasm.blake3_hex(b),pubkey=hex(wasm.ed25519_pubkey_from_seed(seed));
const prefix='/mkit.transport.v1.TransportService/';
function signed(method,body,commitment,nonce=hex(crypto.getRandomValues(new Uint8Array(32)))) {
 const procedure=prefix+method,created=Date.now(),expires=created+300000,digest=b3(body);
 commitment??=`body:${digest}`;
 const canonical=['mkit-write:v2',base,repository,procedure,commitment,created,expires,nonce].join('\n');
 const signature=hex(wasm.ed25519_sign(Buffer.from(b3(new TextEncoder().encode(canonical)),'hex'),seed));
 return {procedure,body,headers:{'content-type':'application/json','connect-protocol-version':'1','x-envelope-version':'2','x-audience':base,'x-repository':repository,'x-content-commitment':commitment,'x-digest':digest,'x-created-at':String(created),'x-expires-at':String(expires),'idempotency-key':nonce,'x-public-key':pubkey,'x-signature':signature}};
}
const unary=(method,msg,nonce)=>signed(method,Buffer.from(JSON.stringify(msg)),undefined,nonce);
async function send(op) {const r=await fetch(base+op.procedure,{method:'POST',body:op.body,headers:op.headers});const text=await r.text();let body;try{body=JSON.parse(text);}catch{body=text;}return {status:r.status,body};}
async function read(name) {return send({procedure:prefix+'ReadRef',body:JSON.stringify({name}),headers:{'content-type':'application/json','connect-protocol-version':'1'}});}
const id=n=>Buffer.alloc(32,n).toString('base64'),name=`refs/heads/test-${crypto.randomUUID()}`;
const update=n=>({name,newId:id(n),expectation:'REF_EXPECTATION_ANY'});
const a=unary('UpdateRef',update(1)),b=unary('UpdateRef',update(2));
assert.equal((await send(a)).status,200);assert.equal((await send(b)).status,200);assert.equal((await send(a)).status,200);
assert.equal((await read(name)).body.objectId,id(2));
for(let batch=0;batch<20;batch++){for(const r of await Promise.all(Array.from({length:16},()=>send(a))))assert.equal(r.status,200,JSON.stringify(r));}
assert.notEqual((await send(unary('UpdateRef',update(3),a.headers['idempotency-key']))).status,200);
const packmap=`refs/packmap/test-${crypto.randomUUID()}`,head=process.argv.includes('--fault')?`refs/heads/__test_fail_once-${crypto.randomUUID()}`:`refs/heads/test-${crypto.randomUUID()}`;
const advance=unary('AdvanceRefs',{headRef:head,headExpectation:'REF_EXPECTATION_ANY',headNewId:id(4),packmapRef:packmap,packmapExpectation:'REF_EXPECTATION_MISSING',packmapNewId:id(5)});
if(process.argv.includes('--fault')) {
 const failed=await send(advance);assert.notEqual(failed.status,200,JSON.stringify(failed));
 assert.equal((await read(head)).body.exists??false,false);assert.equal((await read(packmap)).body.exists??false,false);
}
const result=await send(advance);assert.equal(result.status,200,JSON.stringify(result));assert.equal((await read(head)).body.objectId,id(4));assert.equal((await read(packmap)).body.objectId,id(5));assert.deepEqual(await send(advance),result);
function frame(msg){const bytes=Buffer.from(JSON.stringify(msg)),header=Buffer.alloc(5);header.writeUInt32BE(bytes.length,1);return Buffer.concat([header,bytes]);}
function stream(bytes,{claimedId=b3(bytes),length=bytes.length,actualId=claimedId,nonce}={}){
 const wireId=Buffer.from(actualId,'hex').toString('base64');
 const body=Buffer.concat([frame({header:{packId:wireId,totalBytes:String(length)}}),frame({chunk:{packId:wireId,offset:'0',data:bytes.toString('base64'),last:true}})]);
 const op=signed('UploadPack',body,`pack:${claimedId}:${length}`,nonce);op.headers['content-type']='application/connect+json';return op;
}
async function upload(op){const r=await fetch(base+op.procedure,{method:'POST',body:op.body,headers:op.headers});const bytes=Buffer.from(await r.arrayBuffer());if(r.status!==200)return {status:r.status,body:bytes.toString()};const frames=[];for(let p=0;p<bytes.length;){const flag=bytes[p],len=bytes.readUInt32BE(p+1);frames.push({flag,body:JSON.parse(bytes.subarray(p+5,p+5+len).toString())});p+=5+len;}return {status:r.status,frames};}
const pack=Buffer.from(`pack-${crypto.randomUUID()}`),put=stream(pack);const uploaded=await upload(put);assert.equal(uploaded.status,200,JSON.stringify(uploaded));assert.ok(!uploaded.frames.some(f=>f.body.error),JSON.stringify(uploaded));assert.deepEqual(await upload(put),uploaded);
const changed=stream(pack,{actualId:'ab'.repeat(32)});const rejected=await upload(changed);assert.ok(rejected.status!==200||rejected.frames.some(f=>f.body.error),JSON.stringify(rejected));
const wrongBytes=stream(Buffer.from('wrong'),{claimedId:b3(pack)});const invalid=await upload(wrongBytes);assert.ok(invalid.status!==200||invalid.frames.some(f=>f.body.error),JSON.stringify(invalid));
if(process.argv.includes('--fault')) {
 for(const stage of ['after-reserve','after-put']) {
  const op=stream(Buffer.from(`recover-${stage}-${crypto.randomUUID()}`));op.headers['x-mkit-test-fault']=stage;
  const failed=await upload(op);assert.ok(failed.status!==200||failed.frames.some(f=>f.body.error),JSON.stringify(failed));
  const resumed=await upload(op);assert.equal(resumed.status,200,JSON.stringify(resumed));assert.ok(!resumed.frames.some(f=>f.body.error),JSON.stringify(resumed));
  assert.deepEqual(await upload(op),resumed);
 }
}
if(process.argv.includes('--corrupt-ref')) {
 const corrupt='refs/heads/__corrupt';
 assert.notEqual((await read(corrupt)).status,200,'malformed stored ref must not be exposed as valid');
 assert.notEqual((await send(unary('UpdateRef',{name:corrupt,newId:id(9),expectation:'REF_EXPECTATION_MISSING'}))).status,200,'MISSING must not overwrite a malformed present ref');
}
console.log('vcs v2: ref replay, concurrent duplicate, nonce conflict, atomic advance, signed streaming content passed');
