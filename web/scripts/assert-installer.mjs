#!/usr/bin/env node
// Post-build guard: fail the build if the installer asset did not ship. The
// homepage serves install.sh to `curl mkit.sh | sh` (src/install-route.ts) and
// at /install.sh; both depend on copy-install.mjs having staged the script into
// public/ BEFORE `waku build` collected static assets. If that step is skipped,
// reordered, or the asset is pruned, the build still succeeds but the installer
// silently 404s and `curl mkit.sh | sh` pipes the HTML homepage into a shell.
// Run after `waku build` in the build chain.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const installer = resolve(here, '..', 'dist', 'public', 'install.sh')

if (!existsSync(installer)) {
  console.error(`assert-installer: missing ${installer} — did scripts/copy-install.mjs run before \`waku build\`?`)
  process.exit(1)
}

const head = readFileSync(installer, 'utf8').slice(0, 64)
if (!head.startsWith('#!/bin/sh')) {
  console.error(`assert-installer: ${installer} is not a POSIX sh script (first bytes: ${JSON.stringify(head)})`)
  process.exit(1)
}

console.log('assert-installer: ok (dist/public/install.sh shipped)')
