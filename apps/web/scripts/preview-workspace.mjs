// Local design fixture. Proxies a running web preview; never contacts workspace production APIs.
import http from 'node:http';
const upstream = process.env.WORKBENCH_UPSTREAM ?? 'http://localhost:4173';
const port = Number(process.env.WORKBENCH_PORT ?? 4180);
const owner = 'a1'.repeat(32), agent = 'b2'.repeat(32), id = 'd'.repeat(32);
const head = 'c3'.repeat(32), parent = 'd4'.repeat(32);
const now = Date.now();
const first = {
  'README.md': '# Fieldnotes\n\nA small place to collect ideas.\n\n## Run locally\n\nnpm install\nnpm run dev\n',
  'src/app.js': 'const notes = [];\n\nexport function addNote(text) {\n  notes.push({ text, createdAt: Date.now() });\n}\n\nexport function getNotes() {\n  return notes;\n}\n',
  'src/styles.css': ':root {\n  color-scheme: light dark;\n  font-family: system-ui, sans-serif;\n}\n',
  'package.json': '{\n  "name": "fieldnotes",\n  "scripts": { "dev": "vite" }\n}\n',
};
const saved = { ...first, 'src/app.js': 'const notes = [];\n\nexport function addNote(text) {\n  const trimmed = text.trim();\n  if (!trimmed) return;\n  notes.push({ text: trimmed, createdAt: Date.now() });\n}\n\nexport function getNotes() {\n  return [...notes].reverse();\n}\n', 'src/storage.js': 'export function saveNotes(notes) {\n  localStorage.setItem("notes", JSON.stringify(notes));\n}\n' };
const working = { ...saved, 'src/styles.css': ':root {\n  color-scheme: light dark;\n  font-family: system-ui, sans-serif;\n  line-height: 1.5;\n}\n\n.note {\n  padding: 12px;\n  border-bottom: 1px solid currentColor;\n}\n' };
function hash(content) { return Buffer.from(content).toString('hex').padEnd(64, '0').slice(-64); }
function files(values) { return Object.entries(values).map(([path, content]) => ({ path, hash: hash(content), size: Buffer.byteLength(content), mode: 'blob' })); }
const versions = [{hash:head,parent,treeHash:'e'.repeat(64),message:'Validate notes and show newest first',signer:agent,createdAt:now-17*60_000},{hash:parent,parent:null,treeHash:'f'.repeat(64),message:'Remix project',signer:agent,createdAt:now-48*60_000}];
const view = {workspace:{id,title:'Fieldnotes',ownerPublicKey:owner,agentPublicKey:agent,source:{kind:'demo',repository:'lobby-v2',commitHash:parent},head,createdAt:now-48*60_000,updatedAt:now-120_000,public:true},files:files(working),changes:[{path:'src/styles.css',status:'modified',beforeHash:hash(saved['src/styles.css']),afterHash:hash(working['src/styles.css'])}],versions,messages:[{id:'1',role:'user',text:'Trim empty notes and show the newest notes first.',createdAt:now-20*60_000},{id:'2',role:'assistant',text:'Updated the note helpers. Empty notes are ignored, input is trimmed, and the latest notes appear first without mutating the stored list.\n\nAdded a storage helper for the next step.',createdAt:now-17*60_000},{id:'3',role:'system',text:'Saved version: Validate notes and show newest first',createdAt:now-17*60_000}],task:{id:'task',prompt:'Trim empty notes',status:'completed',createdAt:now-20*60_000,finishedAt:now-17*60_000,versionHash:head},isOwner:true,grant:null,agentEnabled:true};
http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://localhost:${port}`);
    if (url.pathname.startsWith('/api/workspaces')) {
      response.setHeader('content-type', 'application/json'); response.setHeader('cache-control', 'no-store');
      if (request.method !== 'GET') { response.writeHead(405); response.end(JSON.stringify({error:'Design fixture: writes are tested in the component and worker suites.'})); return; }
      if (url.pathname.endsWith('/session')) { response.end(JSON.stringify({id:'design-preview',publicKey:owner,expiresAt:now+86_400_000})); return; }
      const version = url.searchParams.get('version');
      const content = version === parent ? first : version === head ? saved : working;
      if (url.pathname.endsWith('/file')) { const path = url.searchParams.get('path'); if (!(path in content)) {response.writeHead(404);response.end('{}');return} response.end(JSON.stringify({path,content:content[path],hash:hash(content[path]),editable:true})); return; }
      response.end(JSON.stringify(url.pathname === '/api/workspaces' ? {workspaces:[view.workspace]} : {...view,files:files(content)})); return;
    }
    const result = await fetch(new URL(request.url, upstream), { redirect:'manual' });
    response.writeHead(result.status, Object.fromEntries([...result.headers].filter(([name]) => !['content-encoding','content-length','transfer-encoding'].includes(name))));
    response.end(Buffer.from(await result.arrayBuffer()));
  } catch { response.writeHead(502); response.end('Start the web preview on port 4173 first.'); }
}).listen(port, '127.0.0.1', () => console.log(`Design fixture: http://localhost:${port}/create?id=${id}`));
