// Run a built Uno fixture directly, without Wrangler's local HTTP proxy.
// MKIT_MINIFLARE_MODULE pins the installed SDK; no automatic download.
import {readFileSync, writeFileSync, existsSync} from 'node:fs';
import {createRequire} from 'node:module';
import path from 'node:path';
const require = createRequire(import.meta.url);
if (!process.env.MKIT_MINIFLARE_MODULE) throw Error('set MKIT_MINIFLARE_MODULE to the pinned SDK entry point');
const {Miniflare, convertV4MiniflareOptions, Log, LogLevel} = require(process.env.MKIT_MINIFLARE_MODULE);
const [configPath, artifact, port, readyFile] = process.argv.slice(2);
if (!configPath || !artifact || !/^\d+$/.test(port ?? '') || !readyFile) throw Error('config, artifact, port and ready file required');
const c = JSON.parse(readFileSync(configPath));
const root = path.dirname(configPath);
const inspector = process.env.MKIT_LAUNCH_INSPECTOR_PORT;
if (inspector && !/^\d+$/.test(inspector)) throw Error('invalid inspector port');
const modules = [
  {path:c.main, type:'ESModule'},
  {path:path.join(artifact, 'worker/shim.mjs'), type:'ESModule'},
  {path:path.join(artifact, 'index.js'), type:'ESModule'},
  {path:path.join(artifact, 'index_bg.wasm'), type:'CompiledWasm'},
];
if (c.compatibility_flags?.includes('nodejs_als') && existsSync(path.join(root, 'memory.mjs'))) {
  modules.push({path:path.join(root, 'memory.mjs'), type:'ESModule'});
}
const runtime = new Miniflare(convertV4MiniflareOptions({
  host:'127.0.0.1', port:Number(port), ...(inspector ? {inspectorPort:Number(inspector)} : {}),
  log:new Log(LogLevel.DEBUG), resourcePersistencePath:path.join(root, 'state/v3'),
  workers:[{
    name:c.name, modulesRoot:'/', modules, compatibilityDate:c.compatibility_date,
    compatibilityFlags:c.compatibility_flags, bindings:c.vars,
    durableObjects:Object.fromEntries(c.durable_objects.bindings.map(b => [b.name, {className:b.class_name, useSQLite:true}])),
    r2Buckets:Object.fromEntries(c.r2_buckets.map(b => [b.binding, {id:b.bucket_name}])),
  }],
}));
try {
  const ready = await runtime.ready;
  writeFileSync(readyFile, JSON.stringify({origin:ready.origin}));
  await new Promise(resolve => {
    process.once('SIGTERM', resolve);
    process.once('SIGINT', resolve);
  });
} finally {
  await runtime.dispose();
}
