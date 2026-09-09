import assert from 'node:assert/strict';
import { Agent } from 'nanocodex/node';
import { WebSocketServer } from 'ws';
import { writeFile } from 'node:fs/promises';

// Scripted peer only: no provider credentials, network inference, or shell tools.
const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
await new Promise(resolve => server.once('listening', resolve));
const frames = [];
let called = 0;
let step = 0;
server.on('connection', socket => socket.on('message', bytes => {
  const frame = JSON.parse(String(bytes));
  frames.push(frame);
  const id = `probe-${frames.length}`;
  let output = [];
  if (frame.generate !== false) {
    step++;
    output = step === 1
      ? [{type:'function_call',call_id:'probe-call',name:'runtimeInfo',arguments:'{}'}]
      : [{type:'message',role:'assistant',content:[{type:'output_text',text:step === 2 ? 'tool completed' : 'follow-up completed'}]}];
  }
  socket.send(JSON.stringify({type:'response.completed',response:{id,status:'completed',output,usage:null}}));
}));
let agent;
const deadline = setTimeout(() => { console.error('Probe timed out'); process.exit(1); }, 15000);
try {
  agent = await Agent.create({
    apiKey:'local-fixture-only', websocketUrl:`ws://127.0.0.1:${server.address().port}`,
    toolMode:'direct', thinking:'low',
    instructions:'Use the supplied runtimeInfo tool.',
    tools:{runtimeInfo:{description:'Return fixture runtime',parameters:{type:'object',properties:{},additionalProperties:false},handler:()=>{called++;return {runtime:'fixture'};}}},
  });
  const first = agent.turn.prompt({input:'Call runtimeInfo.'});
  assert.equal((await first.result()).finalMessage, 'tool completed');
  first.dispose();
  assert.equal(called, 1);
  const second = agent.turn.prompt({input:'Confirm the previous result.'});
  assert.equal((await second.result()).finalMessage, 'follow-up completed');
  second.dispose();
  assert.ok(frames.some(f => f.input?.some(i=>i.type==='function_call_output' && i.call_id==='probe-call')));
  await writeFile(new URL('./frames.json',import.meta.url), JSON.stringify(frames,null,2));
  console.log(JSON.stringify({package:'nanocodex@0.5.0',provider:'scripted localhost fixture, NOT Groq',frames:frames.length,toolCalls:called,followUp:true,requestFields:Object.keys(frames.find(f=>f.generate!==false)),inputTypes:[...new Set(frames.flatMap(f=>(f.input??[]).map(i=>i.type)))]},null,2));
} finally {
  clearTimeout(deadline);
  if (agent) { await agent.session.shutdown(); agent.dispose(); }
  for (const socket of server.clients) socket.terminate();
  await new Promise(resolve=>server.close(resolve));
}
