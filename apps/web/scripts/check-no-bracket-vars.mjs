// Tailwind v4 removed the bare `[--var]` arbitrary-value shorthand: a class like `text-[--color-muted]`
// compiles to NOTHING — no error, no CSS — and the element silently renders unstyled. That bit us once
// (every muted/hairline utility in the app was a no-op until #338). Theme tokens must be consumed as
// the named utilities Tailwind generates from @theme: text-muted, border-hairline, bg-paper, …
// This guard runs as part of `bun run lint` (locally and in web.yml CI).
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

const PATTERN = /\[--[a-z]/
const offenders = []

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) walk(path)
    else if (/\.(tsx|ts|jsx|js)$/.test(entry.name)) {
      readFileSync(path, 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (PATTERN.test(line)) offenders.push(`${path}:${i + 1}: ${line.trim()}`)
        })
    }
  }
}

walk('src')

if (offenders.length > 0) {
  console.error('Dead Tailwind v4 bracket-var utilities found (these compile to no CSS at all):\n')
  for (const o of offenders) console.error(`  ${o}`)
  console.error('\nUse the named utilities generated from @theme tokens instead: text-muted, border-hairline, bg-paper, …')
  process.exit(1)
}
