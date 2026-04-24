#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const configPath = resolve(here, '..', 'dist', 'server', 'wrangler.json')

let raw
try {
  raw = readFileSync(configPath, 'utf8')
} catch (err) {
  console.error(`patch-worker-config: could not read ${configPath} (has 'waku build' run?): ${err.message}`)
  process.exit(1)
}

const config = JSON.parse(raw)
const today = new Date().toISOString().slice(0, 10)
const changes = []

if (config.compatibility_date !== today) {
  config.compatibility_date = today
  changes.push(`compatibility_date=${today}`)
}

const flags = new Set(Array.isArray(config.compatibility_flags) ? config.compatibility_flags : [])
flags.add('nodejs_als')
const hadNodejsCompat = flags.has('nodejs_compat')
flags.add('nodejs_compat')
config.compatibility_flags = [...flags]
if (!hadNodejsCompat) changes.push('nodejs_compat')

const existing = config.observability && typeof config.observability === 'object' ? config.observability : {}
const merged = { enabled: true, head_sampling_rate: 1, ...existing }
const obsChanged = JSON.stringify(config.observability) !== JSON.stringify(merged)
config.observability = merged
if (obsChanged) changes.push('observability')

writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`)
console.log(`patched ${configPath}: ${changes.length ? changes.join(', ') : 'no changes (already up-to-date)'}`)
