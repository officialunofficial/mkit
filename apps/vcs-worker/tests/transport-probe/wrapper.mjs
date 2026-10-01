// Local-only fixture: production Rust StubTransport talks to a real DO stream.
import Rust from './build/worker/shim.mjs';
import {DurableObject} from 'cloudflare:workers';
const delay=ms=>new Promise(r=>setTimeout(r,ms));
export class Reply extends DurableObject {
 async fetch(req) {
  const mode=new URL(req.url).pathname;
  if(mode==='/abort_header') await delay(300);
  const body=new ReadableStream({async start(c){
   await delay(mode==='/error_status'?100:300);
   if(mode==='/error_body'){c.error(new Error('local fixture body failure'));return;}
   c.enqueue(new TextEncoder().encode('complete'));c.close();
  }});
  return new Response(body,{status:mode==='/error_status'?503:200});
 }
}
function proxy(target,special){return new Proxy(target,{get(t,k){
 const result=special(t,k);if(result!==undefined)return result;
 const v=Reflect.get(t,k,t);return typeof v==='function'&&k!=='constructor'?v.bind(t):v;
}});}
export default {async fetch(req,env,ctx){
 const counters={active:0,peak:0,starts:0,eof:0,errors:0,cancel:0};const events=[];
 const observed=proxy(env,(e,key)=>key==='REFSTORE'?proxy(e.REFSTORE,(ns,k)=>k==='get'?id=>proxy(ns.get(id),(stub,method)=>method==='fetch'?async request=>{
  counters.starts++;counters.active++;counters.peak=Math.max(counters.peak,counters.active);
  events.push({at:Date.now(),event:'start',activeBefore:counters.active-1,phase:await request.clone().text()});let closed=false;
  const done=kind=>{if(closed)return;closed=true;counters.active--;counters[kind]++;events.push({at:Date.now(),event:kind});};
  try {
   const response=await stub.fetch(request);
   const reader=response.body.getReader();
   const body=new ReadableStream({async pull(c){try{const part=await reader.read();if(part.done){done('eof');c.close();}else c.enqueue(part.value);}catch(e){done('errors');c.error(e);}},async cancel(reason){try{await reader.cancel(reason);}finally{done('cancel');}}},{highWaterMark:0});
   return new Response(body,response);
  }catch(e){done('errors');throw e;}
 }:undefined):undefined):undefined);
 const response=await new Rust(ctx,observed).fetch(req);const result=await response.json();
 const atReturn={...counters};
 await delay(400);
 return Response.json({...result,atReturn,after:{...counters},events});
}};
