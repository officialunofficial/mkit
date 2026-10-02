// Independent signed-hook/scanner receiver. No mkit or Worker test-fault API.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createPrivateKey, createPublicKey, randomBytes, sign, verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';

const hookOrigin = 'https://inspection.launch.invalid';
const serverAudience = 'https://vcs.launch.invalid';
const scannerPath = '/_mkit/scanner/pack';
const missing = '{"code":"not_found","message":"pack not found"}';
const privateKey = seed => createPrivateKey({format:'der', type:'pkcs8',
  key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), Buffer.alloc(32,seed)])});
const publicKey = key => createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const scannerKey = privateKey(0x33);
const foreignKey = privateKey(0x44);
const hookKey = createPublicKey(privateKey(0x55));
function hash(bytes) {
  const result = spawnSync('b3sum', ['--no-names'], {input:bytes, maxBuffer:1024});
  assert.equal(result.status,0, 'independent b3sum must succeed');
  const text = result.stdout.toString().trim();
  assert.match(text,/^[0-9a-f]{64}$/);
  return text;
}
function scannerHeaders(body, repository, options={}) {
  const digest = hash(body), now = Date.now(), nonce = randomBytes(32).toString('hex');
  const audience = options.audience || serverAudience, key = options.key || scannerKey;
  const commitment = 'body:' + digest;
  const canonical = ['mkit-write:v2',audience,repository,scannerPath,commitment,now,now+60000,nonce].join('\n');
  return {'content-type':'application/json','x-envelope-version':'2','x-audience':audience,
    'x-repository':repository,'x-public-key':publicKey(key),
    'x-signature':sign(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),key).toString('hex'),
    'x-digest':digest,'x-content-commitment':commitment,'x-created-at':String(now),
    'x-expires-at':String(now+60000),'idempotency-key':nonce};
}
const seenNonces = new Set();
function authenticate(headers, path, bytes) {
  const get = name => {assert.equal(typeof headers[name],'string',name); return headers[name];};
  assert.equal(get('x-mkit-hook-version'),'1');
  assert.equal(get('x-mkit-hook-audience'),hookOrigin);
  assert.equal(get('x-mkit-hook-key-id'),'launch-hook');
  const created = get('x-mkit-hook-created-at'), expires = get('x-mkit-hook-expires-at');
  assert.match(created,/^(0|[1-9][0-9]*)$/); assert.match(expires,/^(0|[1-9][0-9]*)$/);
  assert.ok(Number(created)<=Date.now()+30000 && Number(expires)>Date.now());
  assert.ok(Number(expires)-Number(created)>0 && Number(expires)-Number(created)<=300000);
  const nonce = get('x-mkit-hook-nonce'); assert.match(nonce,/^[0-9a-f]{64}$/);
  assert.ok(!seenNonces.has(nonce),'each hook attempt must have a fresh nonce');
  const digest = 'body:' + hash(bytes);
  assert.equal(get('x-mkit-hook-digest'),digest);
  const canonical = ['mkit-hook:v1','launch-hook',hookOrigin,path,digest,created,expires,nonce].join('\n');
  const signature = get('x-mkit-hook-signature'); assert.match(signature,/^[0-9a-f]{128}$/);
  assert.ok(verify(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),hookKey,Buffer.from(signature,'hex')));
  seenNonces.add(nonce);
  return {nonce,body_blake3:digest.slice(5),signature_verified:true};
}
function decodedFileSet(pack) {
  assert.ok(pack.length>=44 && pack.subarray(0,4).equals(Buffer.from('MKIT')));
  assert.equal(pack.readUInt32LE(4),1,'this lane deliberately produces only raw packs');
  assert.equal(hash(pack.subarray(0,-32)),pack.subarray(-32).toString('hex'),'pack trailer');
  const count = pack.readUInt32LE(8); assert.ok(count<=10000);
  const files = new Map(); let pos=12;
  for(let i=0;i<count;i++) {
    assert.ok(pos+5<=pack.length-32);
    const type = pack[pos], length=pack.readUInt32LE(pos+1); pos+=5;
    assert.equal(type,0,'unsupported delta/compression must not get an inferred PASS');
    assert.ok(length>=6 && pos+length<=pack.length-32);
    const object=pack.subarray(pos,pos+length); pos+=length;
    assert.ok(object.subarray(1,5).equals(Buffer.from('MKT1'))); assert.equal(object[5],1);
    if(object[0]===1) {
      assert.ok(length>=10); assert.equal(object.readUInt32LE(6),length-10);
      files.set(hash(object),{id:hash(object),size:String(length),kind:'INSPECT_OBJECT_KIND_BLOB'});
    } else assert.ok([2,3].includes(object[0]),'manifest coverage requires its independent BMT decoder');
  }
  assert.equal(pos,pack.length-32);
  return [...files.values()].sort((a,b)=>a.id.localeCompare(b.id));
}

if(process.argv.includes('--self-test')) {
  assert.equal(hash(Buffer.alloc(0)),'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');
  const body=Buffer.from('{ "exact": true }'), now=String(Date.now());
  const headers={'x-mkit-hook-version':'1','x-mkit-hook-audience':hookOrigin,'x-mkit-hook-key-id':'launch-hook',
    'x-mkit-hook-created-at':now,'x-mkit-hook-expires-at':String(Number(now)+60000),
    'x-mkit-hook-nonce':'ab'.repeat(32),'x-mkit-hook-digest':'body:'+hash(body)};
  const path='/mkit.server.hooks.v1.HooksService/Inspect';
  const canonical=['mkit-hook:v1','launch-hook',hookOrigin,path,'body:'+hash(body),now,headers['x-mkit-hook-expires-at'],headers['x-mkit-hook-nonce']].join('\n');
  headers['x-mkit-hook-signature']=sign(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),privateKey(0x55)).toString('hex');
  assert.throws(()=>authenticate(headers,path,Buffer.from('{}')));
  authenticate(headers,path,body); assert.throws(()=>authenticate(headers,path,body),'nonce reuse');
  const object=Buffer.from([1,...Buffer.from('MKT1'),1,1,0,0,0,99]);
  const header=Buffer.alloc(12); header.write('MKIT'); header.writeUInt32LE(1,4); header.writeUInt32LE(1,8);
  const frame=Buffer.alloc(5); frame.writeUInt32LE(object.length,1);
  const prefix=Buffer.concat([header,frame,object]);
  const pack=Buffer.concat([prefix,Buffer.from(hash(prefix),'hex')]);
  assert.deepEqual(decodedFileSet(pack),[{id:hash(object),size:'11',kind:'INSPECT_OBJECT_KIND_BLOB'}]);
  const corrupt=Buffer.from(pack); corrupt[20]^=1; assert.throws(()=>decodedFileSet(corrupt));
  console.log('PASS independent receiver exact signature/body, nonce and raw-pack decoder self-tests');
  process.exit(0);
}

const state={mode:process.env.INSPECTION_MODE, result:'RUNNING', hooks:[], scanner:[], failures:[],closed:0,redirected:0};
let savedAssignment;
async function collectBounded(response) {
  const reader=response.body.getReader(), segments=[];let length=0;
  try {
    while(true) {
      const {done,value}=await reader.read();if(done) break;
      length+=value.length;assert.ok(length<=1048576,'scanner response must stay within one MiB');
      segments.push(Buffer.from(value));
    }
    return Buffer.concat(segments);
  } catch(error) {await reader.cancel();throw error;}
  finally {reader.releaseLock();}
}
async function retrieve(request, repository, options={}) {
  assert.ok(state.scanner.length<1024,'bounded fixture scanner transcript');
  const body=Buffer.from(JSON.stringify(request)); assert.ok(body.length<=16384);
  const started=Date.now();
  const response=await fetch(process.env.INSPECTION_WORKER_ORIGIN+scannerPath,{method:'POST',
    headers:scannerHeaders(body,repository,options),body,signal:AbortSignal.timeout(35000)});
  const bytes=await collectBounded(response);
  state.scanner.push({status:response.status,bytes:bytes.length,elapsed_ms:Date.now()-started,
    label:options.label||'assigned range',content_range:response.headers.get('content-range')});
  return {response,bytes};
}
async function deny(request, repository, options) {
  const {response,bytes}=await retrieve(request,repository,options);
  assert.equal(response.status,404,options.label); assert.equal(bytes.toString(),missing,options.label);
  assert.equal(response.headers.get('cache-control'),null);
}
async function inspect(json, record) {
  assert.equal(json.phase,'INSPECT_PHASE_PRE_RECEIVE'); assert.ok(json.inspectionId);
  assert.equal(json.operation.audience,serverAudience); assert.ok(json.operation.repository);
  assert.equal(json.operation.procedure,'/mkit.transport.v1.TransportService/AdvanceRefs');
  assert.ok(Array.isArray(json.objects) && json.objects.length>0);
  const metadata=json.scannerRetrieval; assert.equal(metadata.endpointPath,scannerPath);
  assert.ok(metadata.capability && Number(metadata.expiresAtMs)>Date.now());
  assert.ok(metadata.packs.length>0 && metadata.packs.length<=7);
  const repository=json.operation.repository;
  const id=Buffer.from(metadata.packs[0].id,'base64').toString('hex');
  const base={capability:metadata.capability,pack_id:id,start:0,end_inclusive:0};
  savedAssignment={request:base,repository,expires:Number(metadata.expiresAtMs)};
  // Local receiver state never logs the capability or original signed body.
  record.repository=repository; record.refs=json.operation.refs; record.inspection_id=json.inspectionId;
  record.objects=json.objects; record.packs=metadata.packs; record.capability_expires_at_ms=metadata.expiresAtMs;
  if(state.mode==='reject') return {reject:{code:'permission_denied',message:'fixture rejects staged content'}};
  if(state.mode!=='pass') return null;
  await deny(base,repository,{key:foreignKey,label:'foreign scanner key'});
  await deny(base,repository,{audience:'https://wrong.launch.invalid',label:'wrong audience'});
  await deny(base,repository+'/foreign',{label:'wrong repository'});
  await deny({...base,capability:'r1.invalid'},repository,{label:'bad capability'});
  await deny({...base,pack_id:'ff'.repeat(32)},repository,{label:'unassigned pack'});
  await deny({...base,end_inclusive:Number(metadata.packs[0].length)},repository,{label:'out-of-pack range'});
  await deny({...base,end_inclusive:1048576},repository,{label:'over-one-MiB range'});
  const fileSet=new Map();
  for(const pack of metadata.packs) {
    const length=Number(pack.length); assert.ok(length>0 && length<=64*1048576);
    const segments=[];
    for(let start=0;start<length;start+=1048576) {
      const end=Math.min(length-1,start+1048575);
      const {response,bytes}=await retrieve({capability:metadata.capability,
        pack_id:Buffer.from(pack.id,'base64').toString('hex'),start,end_inclusive:end},repository);
      assert.equal(response.status,206,'assigned staged raw-pack range');
      assert.equal(response.headers.get('content-range'),`bytes ${start}-${end}/${length}`);
      assert.equal(bytes.length,end-start+1); segments.push(bytes);
    }
    const raw=Buffer.concat(segments); assert.equal(hash(raw),Buffer.from(pack.id,'base64').toString('hex'));
    for(const entry of decodedFileSet(raw)) fileSet.set(entry.id,entry);
  }
  const actual=json.objects.map(object=>({...object,id:Buffer.from(object.id,'base64').toString('hex')})).sort((a,b)=>a.id.localeCompare(b.id));
  assert.deepEqual(actual,[...fileSet.values()].sort((a,b)=>a.id.localeCompare(b.id)),'complete independently decoded file set');
  record.independent_exact_set=true; record.denial_cases=7;
  return {pass:{}};
}
const server=createServer(async(request,response)=>{
  response.on('close',()=>{state.closed++;});
  try {
    if(request.url==='/state') {response.end(JSON.stringify(state));return;}
    if(request.url==='/terminal-check') {
      assert.ok(savedAssignment);
      assert.ok(Date.now()<savedAssignment.expires,'consumed-ticket test must precede capability expiry');
      await deny(savedAssignment.request,savedAssignment.repository,{label:'consumed ticket'});
      response.end('{}');return;
    }
    if(request.url==='/redirect-target') {state.redirected++;response.end('{}');return;}
    assert.equal(request.method,'POST');
    const chunks=[];let length=0;
    for await(const chunk of request) {length+=chunk.length;assert.ok(length<=2097152);chunks.push(chunk);}
    assert.ok(state.hooks.length<128,'bounded fixture hook transcript');
    const bytes=Buffer.concat(chunks), record=authenticate(request.headers,request.url,bytes);
    state.hooks.push({...record,procedure:request.url});
    const json=JSON.parse(bytes);
    if(request.url.endsWith('/Inspect')) {
      const item=state.hooks.at(-1), answer=await inspect(json,item);
      if(state.mode==='redirect') {response.writeHead(302,{location:'/redirect-target'});response.end();return;}
      if(state.mode==='oversize') {response.writeHead(200,{'content-type':'application/json'});response.end(' '.repeat(1048577));return;}
      if(state.mode==='body') {response.writeHead(200,{'content-type':'application/json'});response.flushHeaders();return;}
      if(state.mode==='stall') return;
      response.writeHead(200,{'content-type':'application/json'});response.end(JSON.stringify(answer));return;
    }
    throw new Error('unconfigured hook role called');
  } catch(error) {
    // Sanitized assertion only: never serialize request bodies/capabilities.
    state.failures.push({name:error.name,message:error.message.split('\n')[0]});
    response.writeHead(503);response.end('{}');
  }
});
server.listen(0,'127.0.0.1',()=>writeFileSync(process.env.INSPECTION_READY_FILE,
  JSON.stringify({origin:`http://127.0.0.1:${server.address().port}`,scanner_public_key:publicKey(scannerKey)})));
