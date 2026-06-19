#!/usr/bin/env node
// Post-build guard: fail the build if the installer asset did not ship.
// `curl -sSfL https://mkit.sh/install.sh | sh` is served as the static asset
// /install.sh, which depends on scripts/stage-public.mjs having staged the
// repo-root install.sh into public/ BEFORE `waku build` collected static
// assets. If that step is skipped, reordered, or the asset is pruned, the build
// still succeeds but /install.sh silently 404s. Run after `waku build`.
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
