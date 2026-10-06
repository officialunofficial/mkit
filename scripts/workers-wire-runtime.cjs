// SPDX-License-Identifier: MIT OR Apache-2.0
// Serve the built Worker on a workerd socket, bypassing the dev HTTP proxy.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

// Use exactly the Wrangler/Miniflare selected by npx, as in runtime metadata.
const executable = process.env.PATH.split(path.delimiter)
  .map(directory => path.join(directory, 'wrangler')).find(file => fs.existsSync(file));
if (!executable) throw new Error('Wrangler is not on PATH');
const resolve = createRequire(fs.realpathSync(executable));
const { unstable_getMiniflareWorkerOptions } = resolve('wrangler');
const { Miniflare, convertV4MiniflareOptions, Log, LogLevel } = resolve('miniflare');
const [config, artifact, state, port, ...args] = process.argv.slice(2);
if (!config || !artifact || !state || !/^\d+$/.test(port || '')) {
  throw new Error('config, build directory, state directory and port required');
}
const { workerOptions, main, externalWorkers } = unstable_getMiniflareWorkerOptions(config);
for (let index = 0; index < args.length; index++) {
  const flag = args[index];
  if (flag === '--var') {
    const value = args[++index];
    const separator = value?.indexOf(':') ?? -1;
    if (separator < 1) throw new Error('--var requires NAME:value');
    workerOptions.bindings[value.slice(0, separator)] = value.slice(separator + 1);
  } else if (flag === '--compatibility-date' || flag.startsWith('--compatibility-date=')) {
    workerOptions.compatibilityDate = flag.includes('=') ? flag.split('=')[1] : args[++index];
    if (!workerOptions.compatibilityDate) throw new Error('--compatibility-date requires a date');
  } else {
    throw new Error(`Unsupported direct-runtime argument: ${flag}`);
  }
}
const modules = [
  { type: 'ESModule', path: path.resolve(main) },
  { type: 'ESModule', path: path.resolve(artifact, 'worker/shim.mjs') },
  { type: 'ESModule', path: path.resolve(artifact, 'index.js') },
  { type: 'CompiledWasm', path: path.resolve(artifact, 'index_bg.wasm') },
].filter((module, index, all) => all.findIndex(other => other.path === module.path) === index);
const runtime = new Miniflare(convertV4MiniflareOptions({
  host: '127.0.0.1', port: 0, log: new Log(LogLevel.DEBUG),
  resourcePersistencePath: path.resolve(state),
  workers: [{ ...workerOptions, modulesRoot: '/', modules,
    unsafeDirectSockets: [{ host: '127.0.0.1', port: Number(port) }] }, ...externalWorkers],
}));
async function serve() {
  try {
    const origin = await runtime.unsafeGetDirectURL(workerOptions.name);
    console.log(`DIRECT_READY ${origin}`);
    await new Promise(resolve => {
      process.once('SIGTERM', resolve);
      process.once('SIGINT', resolve);
    });
  } finally {
    await runtime.dispose();
  }
}
serve().catch(error => { console.error(error); process.exitCode = 1; });
