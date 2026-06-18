#!/usr/bin/env node
// Post-build guard: fail the build if static prerendering silently produced
// nothing. waku's SSG step swallows route-registration problems (e.g. the
// fsRouter glob-key mismatch introduced by the 1.0.0-beta.2 bump, #305) and
// happily reports success while emitting zero pages — which is exactly how a
// blank mkit.sh shipped. Run after `waku build` in the build chain.
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const publicDir = resolve(here, '..', 'dist', 'public')
const failures = []

// Every statically rendered page must exist as prerendered HTML with real
// content, plus its RSC payload for client navigation.
const pagesDir = resolve(here, '..', 'src', 'pages')
const pages = readdirSync(pagesDir)
  .filter((f) => /\.tsx$/.test(f) && !f.startsWith('_'))
  .map((f) => f.replace(/\.tsx$/, ''))

for (const page of pages) {
  const htmlPath = page === 'index' ? join(publicDir, 'index.html') : join(publicDir, page, 'index.html')
  const rscPath = join(publicDir, 'RSC', 'R', `${page === 'index' ? '_root' : page}.txt`)
  if (!existsSync(htmlPath)) {
    failures.push(`missing prerendered HTML: ${htmlPath}`)
  } else {
    const html = readFileSync(htmlPath, 'utf8')
    if (html.length < 1024 || !html.includes('<h1')) {
      failures.push(`prerendered HTML looks like an empty CSR shell (${html.length} bytes): ${htmlPath}`)
    }
  }
  if (!existsSync(rscPath)) {
    failures.push(`missing RSC payload: ${rscPath}`)
  }
}

if (failures.length) {
  console.error('assert-prerender: build output is broken —')
  for (const f of failures) console.error(`  - ${f}`)
  process.exit(1)
}
console.log(`assert-prerender: ok (${pages.length} pages prerendered with RSC payloads)`)
