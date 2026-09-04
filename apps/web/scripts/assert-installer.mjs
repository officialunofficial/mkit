#!/usr/bin/env node
// Post-build guard: fail the build if an installer asset did not ship.
// /install.sh backs both the direct `curl -sSfL https://mkit.sh/install.sh | sh`
// and the bare-domain `curl mkit.sh | sh` sniff (src/install-route.ts reads it
// via env.ASSETS). It is staged by scripts/stage-public.mjs BEFORE
// `waku build` collects static assets; if that step is skipped/reordered or
// an asset is pruned, the build still succeeds but the installer silently
// 404s. Run after `waku build`.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const distPublic = resolve(here, '..', 'dist', 'public')

const installers = [
  { file: 'install.sh', shebang: '#!/bin/sh' },
]

for (const { file, shebang } of installers) {
  const path = resolve(distPublic, file)
  if (!existsSync(path)) {
    console.error(`assert-installer: missing ${path} — did scripts/stage-public.mjs run before \`waku build\`?`)
    process.exit(1)
  }
  if (shebang) {
    const head = readFileSync(path, 'utf8').slice(0, 64)
    if (!head.startsWith(shebang)) {
      console.error(`assert-installer: ${path} does not start with ${JSON.stringify(shebang)} (first bytes: ${JSON.stringify(head)})`)
      process.exit(1)
    }
  }
}

console.log('assert-installer: ok (dist/public/install.sh shipped)')
