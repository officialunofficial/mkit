import assert from 'node:assert/strict';
import { Agent } from 'nanocodex/node';
import { WebSocketServer } from 'ws';
import { createInterface } from 'node:readline';
import { mkdir, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
const input = createInterface({ input: process.stdin, terminal: false });
const key = await new Promise(resolve => input.once('line', resolve));
input.close(); process.stdin.pause();
const server = new WebSocketServer({host:'127.0.0.1',port:0});
await new Promise(resolve=>server.once('listening',resolve));
const workspace = new URL('./workspace/',import.meta.url);
await mkdir(workspace,{recursive:true});
let requests=0, writes=0, tests=0, testsPassed=false;
let failure;
server.on('connection', socket=>{
  const saved=new Map();
  let queue=Promise.resolve();
  socket.on('message', bytes=>{
    queue=queue.then(async()=>{
      const frame=JSON.parse(String(bytes));
      assert.equal(frame.type,'response.create');
      const parent=frame.previous_response_id ? saved.get(frame.previous_response_id) : {history:[],tools:[]};
      assert.ok(parent,'unknown continuation');
      const history=structuredClone(parent.history);
      let tools=parent.tools;
      for(const item of frame.input??[]) {
        if(item.type==='additional_tools') tools=item.tools;
        else { const copy={...item}; delete copy.id; history.push(copy); }
      }
      let response;
      if(frame.generate===false) response={id:`warmup-${saved.size}`,status:'completed',output:[],usage:null};
      else {
        assert.ok(++requests<=8,'request cap');
        const upstream=await fetch('https://api.groq.com/openai/v1/responses',{
          method:'POST',headers:{Authorization:`Bearer ${key}`,'Content-Type':'application/json'},
          body:JSON.stringify({model:'openai/gpt-oss-120b',input:history,tools,tool_choice:'auto',parallel_tool_calls:false,max_output_tokens:768,stream:false}),
          signal:AbortSignal.timeout(30000),
        });
        const body=await upstream.json();
        if(!upstream.ok) throw new Error(`Groq HTTP ${upstream.status}: ${JSON.stringify(body).replaceAll(key,'[REDACTED]')}`);
        response=body;
        console.log(JSON.stringify({request:requests,status:response.status,outputTypes:response.output?.map(i=>i.type),tokens:response.usage?.total_tokens}));
      }
      saved.set(response.id,{history:[...history,...response.output??[]],tools});
      socket.send(JSON.stringify({type:'response.completed',response}));
    }).catch(error=>{failure=error;console.error(error.message);socket.close(1011,'upstream failed');});
  });
});
let agent;
const deadline=setTimeout(()=>{console.error('Probe deadline exceeded');process.exit(1);},60000);
try {
  agent=await Agent.create({apiKey:'local-broker',websocketUrl:`ws://127.0.0.1:${server.address().port}`,toolMode:'direct',thinking:'low',
    instructions:'Create the requested file using write_file, run run_tests, and report success. Use only these tools. Keep responses brief.',
    tools:{
      write_file:{description:'Write sum.mjs in the test workspace.',parameters:{type:'object',properties:{content:{type:'string'}},required:['content'],additionalProperties:false},handler:async({content})=>{assert.ok(content.length<4000);await writeFile(new URL('sum.mjs',workspace),content);writes++;return 'Written sum.mjs';}},
      run_tests:{description:'Test the sum.mjs add export.',parameters:{type:'object',properties:{},additionalProperties:false},handler:()=>{tests++;try{const output=execFileSync(process.execPath,['--input-type=module','-e',"import {add} from './sum.mjs'; if(add(2,3)!==5 || add(-2,2)!==0) throw Error('incorrect sum'); console.log('2 tests passed')"],{cwd:workspace,encoding:'utf8',timeout:3000,maxBuffer:4096});testsPassed=true;return output;}catch{return 'Tests failed; repair the add export.';}}},
    }});
  const first=agent.turn.prompt({input:'Create sum.mjs exporting function add(a,b) returning their sum. Run the tests.'});
  const result=await first.result();first.dispose();
  assert.ok(writes>0&&tests>0&&testsPassed,'agent must write and pass tests');
  const second=agent.turn.prompt({input:'Without tools, which file did you just create and test?'});
  const followup=await second.result();second.dispose();
  assert.match(followup.finalMessage,/sum\.mjs/);
  if(failure) throw failure;
  console.log(JSON.stringify({passed:true,nanocodex:'0.5.0 unchanged',groqModel:'openai/gpt-oss-120b',requests,writes,tests,final:result.finalMessage,followup:followup.finalMessage}));
}finally{
  clearTimeout(deadline);
  if(agent){await agent.session.shutdown();agent.dispose();}
  for(const socket of server.clients)socket.terminate();
  await new Promise(resolve=>server.close(resolve));
}
