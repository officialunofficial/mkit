#!/usr/bin/env node
// Walk every static HTML file Waku's SSG step emits and fix React 19's invalid `<link rel="preload" as="stylesheet">`
// (the HTML spec only allows `as="style"` for stylesheets — `as="stylesheet"` is hardcoded in
// `react-dom-server.edge.production.js`, but every browser warns about it). The static HTML never reaches the Worker
// because the Cloudflare Assets binding serves it directly, so a runtime HTMLRewriter would never run; the rewrite
// has to happen at build time on the prerendered files themselves.
//
// Idempotent: re-running on already-patched HTML is a no-op (regex matches nothing).

import { readFileSync, readdirSync, writeFileSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '..', 'dist', 'public')

const NEEDLE = /(<link\s[^>]*rel="preload"[^>]*\bas=)"stylesheet"/g
let touched = 0
let scanned = 0

const walk = (dir) => {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry)
    if (statSync(path).isDirectory()) {
      walk(path)
      continue
    }
    if (!path.endsWith('.html')) continue
    scanned++
    const html = readFileSync(path, 'utf8')
    if (!NEEDLE.test(html)) continue
    NEEDLE.lastIndex = 0
    writeFileSync(path, html.replace(NEEDLE, '$1"style"'))
    touched++
  }
}

walk(root)
console.log(`fixed-preload: scanned ${scanned} html, rewrote ${touched}`)
