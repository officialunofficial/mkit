// SPDX-License-Identifier: MIT OR Apache-2.0
// Resolve from the Wrangler executable selected by npx, not a global install.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const executable = process.env.PATH.split(path.delimiter)
  .map(directory => path.join(directory, 'wrangler')).find(file => fs.existsSync(file));
if (!executable) throw new Error('Wrangler is not on PATH');
let directory = path.dirname(fs.realpathSync(executable));
while (!fs.existsSync(path.join(directory, 'package.json'))) {
  const parent = path.dirname(directory);
  if (parent === directory) throw new Error('Wrangler package manifest not found');
  directory = parent;
}
const manifest = require(path.join(directory, 'package.json'));
if (manifest.name !== 'wrangler') throw new Error('Selected executable is not Wrangler');
const resolve = createRequire(path.join(directory, 'package.json'));
const miniflare = resolve('miniflare/package.json');
const workerd = createRequire(resolve.resolve('miniflare/package.json'))('workerd/package.json');
const config = fs.readFileSync('apps/vcs-worker/wrangler.dev.jsonc', 'utf8');
const configuredDate = config.match(/"compatibility_date"\s*:\s*"([^"\s]+)"/)[1];
const overrides = (process.env.VCS_CONFORMANCE_WRANGLER_ARGS || '').split(/\s+/);
const index = overrides.indexOf('--compatibility-date');
const compatibilityDate = index >= 0 ? overrides[index + 1] :
  (overrides.find(value => value.startsWith('--compatibility-date='))?.split('=')[1] || configuredDate);
console.log(JSON.stringify({ wrangler: manifest.version, miniflare: miniflare.version,
  workerd: workerd.version, node: process.version, compatibility_date: compatibilityDate }, null, 2));
