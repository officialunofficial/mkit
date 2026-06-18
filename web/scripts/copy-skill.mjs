#!/usr/bin/env node
// Stage the canonical, repo-root SKILL.md into web/public/ so the demo site
// serves it at https://mkit.sh/SKILL.md. The repo-root file is the
// single source of truth; this generated copy is gitignored. Run before
// `waku build`/`waku dev` so Waku collects it as a static asset.
import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = resolve(here, '..', '..', 'SKILL.md') // repo root
const destDir = resolve(here, '..', 'public')
const dest = resolve(destDir, 'SKILL.md')

try {
  mkdirSync(destDir, { recursive: true })
  copyFileSync(src, dest)
  console.log(`copy-skill: ${src} -> ${dest}`)
} catch (err) {
  console.error(`copy-skill: failed to stage SKILL.md: ${err.message}`)
  process.exit(1)
}
