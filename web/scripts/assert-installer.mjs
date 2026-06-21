#!/usr/bin/env node
// Post-build guard: fail the build if the installer asset did not ship. The
// /install.sh asset backs both the direct `curl -sSfL https://mkit.sh/install.sh | sh`
// and the bare-domain `curl mkit.sh | sh` sniff (src/install-route.ts reads it
// via env.ASSETS). It is staged by scripts/stage-public.mjs BEFORE `waku build`
// collects static assets; if that step is skipped/reordered or the asset is
// pruned, the build still succeeds but the installer silently 404s. Run after
// `waku build`.
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const installer = resolve(here, '..', 'dist', 'public', 'install.sh')

if (!existsSync(installer)) {
  console.error(`assert-installer: missing ${installer} — did scripts/stage-public.mjs run before \`waku build\`?`)
  process.exit(1)
}

const head = readFileSync(installer, 'utf8').slice(0, 64)
if (!head.startsWith('#!/bin/sh')) {
  console.error(`assert-installer: ${installer} is not a POSIX sh script (first bytes: ${JSON.stringify(head)})`)
  process.exit(1)
}

console.log('assert-installer: ok (dist/public/install.sh shipped)')
