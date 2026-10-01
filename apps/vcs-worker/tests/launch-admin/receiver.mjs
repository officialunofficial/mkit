// Independent local admin signer and signed-purge receiver; no mkit test API.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createPrivateKey, createPublicKey, randomBytes, sign, verify} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {writeFileSync} from 'node:fs';
const audience = 'https://vcs.launch.invalid';
const hookAudience = 'https://purge.launch.invalid';
const prefix = '/mkit.server.admin.v1.AdminService/';
const key = seed => createPrivateKey({format:'der',type:'pkcs8',key:Buffer.concat([
  Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,seed)])});
const publicBytes = key => createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32);
function hash(bytes) {
  const result = spawnSync('b3sum',['--no-names'],{input:bytes,maxBuffer:1024});
  assert.equal(result.status,0);
  const text=result.stdout.toString().trim(); assert.match(text,/^[0-9a-f]{64}$/); return text;
}
const operator=key(0x77), audit=key(0x78), receipt=key(0x79), hook=key(0x55);
if(process.argv[2]==='keys') {
  const entry=(keyId,key,roles)=>({keyId,alg:'ed25519',publicKey:publicBytes(key).toString('hex'),roles});
  console.log(JSON.stringify({admin:{version:1,keys:[entry('operator',operator,['moderation','audit']),entry('auditor',audit,['audit'])]},
    receipt:{version:1,keys:[{keyId:hash(publicBytes(receipt)),alg:'ed25519',publicKey:publicBytes(receipt).toString('hex')}]}}));
} else if(process.argv[2]==='admin') {
  const [,, ,origin,method,json,role='operator',stream='false']=process.argv;
  const raw=Buffer.from(json); let body=raw;
  if(stream==='true') {const frame=Buffer.alloc(5);frame.writeUInt32BE(raw.length,1);body=Buffer.concat([frame,raw]);}
  const now=String(Date.now()),expiry=String(Number(now)+60000),nonce=randomBytes(32).toString('hex');
  const path=prefix+method,digest='body:'+hash(body);
  const canonical=['mkit-admin:v1',role,audience,path,digest,now,expiry,nonce].join('\n');
  const headers={'content-type':stream==='true'?'application/connect+json':'application/json','connect-protocol-version':'1',
    'x-mkit-admin-version':'1','x-mkit-admin-key-id':role,'x-mkit-admin-audience':audience,
    'x-mkit-admin-created-at':now,'x-mkit-admin-expires-at':expiry,'x-mkit-admin-nonce':nonce,
    'x-mkit-admin-digest':digest,'x-mkit-admin-signature':sign(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),role==='operator'?operator:audit).toString('hex')};
  const response=await fetch(origin+(process.env.ADMIN_PATH_PREFIX??'')+path,{method:'POST',headers,body,signal:AbortSignal.timeout(60000)});
  const bytes=Buffer.from(await response.arrayBuffer());assert.ok(bytes.length<=8*1024*1024);
  console.log(JSON.stringify({status:response.status,headers:Object.fromEntries(response.headers),body:bytes.toString('base64'),request_digest:digest,nonce}));
} else {
  const state={requests:[],failures:[],outage:false},nonces=new Set();
  const server=createServer(async(request,response)=>{
    try {
      if(request.url==='/state') {response.end(JSON.stringify(state));return;}
      if(request.url==='/outage/on'||request.url==='/outage/off') {state.outage=request.url.endsWith('on');response.end('{}');return;}
      assert.equal(request.method,'POST');assert.equal(request.url,'/mkit.server.hooks.v1.HooksService/CachePurge');
      const chunks=[];let size=0;for await(const chunk of request){size+=chunk.length;assert.ok(size<=1048576);chunks.push(chunk);}
      const body=Buffer.concat(chunks),get=name=>{assert.equal(typeof request.headers[name],'string');return request.headers[name];};
      assert.equal(get('x-mkit-hook-version'),'1');assert.equal(get('x-mkit-hook-key-id'),'launch-hook');
      assert.equal(get('x-mkit-hook-audience'),hookAudience);
      const created=get('x-mkit-hook-created-at'),expires=get('x-mkit-hook-expires-at'),nonce=get('x-mkit-hook-nonce');
      assert.ok(Number(created)<=Date.now()+30000&&Number(expires)>Date.now()&&Number(expires)-Number(created)<=300000);
      assert.match(nonce,/^[0-9a-f]{64}$/);assert.ok(!nonces.has(nonce));nonces.add(nonce);
      const digest='body:'+hash(body);assert.equal(get('x-mkit-hook-digest'),digest);
      const canonical=['mkit-hook:v1','launch-hook',hookAudience,request.url,digest,created,expires,nonce].join('\n');
      assert.ok(verify(null,Buffer.from(hash(Buffer.from(canonical)),'hex'),createPublicKey(hook),Buffer.from(get('x-mkit-hook-signature'),'hex')));
      state.requests.push({body:JSON.parse(body),nonce,signature_verified:true,outage:state.outage});
      assert.ok(state.requests.length<=1024);
      response.statusCode=state.outage?503:200;response.setHeader('content-type','application/json');response.end('{}');
    } catch(error) {state.failures.push(String(error));response.statusCode=500;response.end('{}');}
  });
  server.listen(0,'127.0.0.1',()=>writeFileSync(process.env.ADMIN_READY_FILE,JSON.stringify({origin:'http://127.0.0.1:'+server.address().port})));
}
