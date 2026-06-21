#!/usr/bin/env node
// Stage canonical, repo-root files into web/public/ so the demo site serves
// them as static assets (e.g. https://mkit.sh/SKILL.md, https://mkit.sh/install.sh).
// The repo-root files are the single source of truth; these generated copies are
// gitignored. Run before `waku build`/`waku dev` so Waku collects them.
//
// Usage: node scripts/stage-public.mjs <file>...   (paths relative to repo root)
import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..', '..')
const publicDir = resolve(here, '..', 'public')

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('stage-public: no files given (usage: stage-public.mjs <file>...)')
  process.exit(1)
}

mkdirSync(publicDir, { recursive: true })
for (const file of files) {
  const src = resolve(repoRoot, file)
  const dest = resolve(publicDir, file)
  try {
    copyFileSync(src, dest)
    console.log(`stage-public: ${src} -> ${dest}`)
  } catch (err) {
    console.error(`stage-public: failed to stage ${file}: ${err.message}`)
    process.exit(1)
  }
}
