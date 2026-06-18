#!/usr/bin/env node
// Stage the canonical, repo-root install.sh into web/public/ so the demo site
// serves it at https://mkit.sh/install.sh. The repo-root file is the single
// source of truth (it is the same script shipped from the GitHub raw URL); this
// generated copy is gitignored. Run before `waku build`/`waku dev` so Waku
// collects it as a static asset.
import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const src = resolve(here, '..', '..', 'install.sh') // repo root
const destDir = resolve(here, '..', 'public')
const dest = resolve(destDir, 'install.sh')

try {
  mkdirSync(destDir, { recursive: true })
  copyFileSync(src, dest)
  console.log(`copy-install: ${src} -> ${dest}`)
} catch (err) {
  console.error(`copy-install: failed to stage install.sh: ${err.message}`)
  process.exit(1)
}
