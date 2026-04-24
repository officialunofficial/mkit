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

// Custom Domain(s). Listed patterns are attached to the Worker as Cloudflare Custom Domains — Wrangler auto-creates
// the proxied DNS record and issues a cert on `wrangler deploy` as long as the zone is on the same account. Routes
// are idempotent: re-running the patcher on an already-routed deploy is a no-op.
const DESIRED_ROUTES = [{ pattern: 'mkit.makechain.net', custom_domain: true }]
const currentRoutes = Array.isArray(config.routes) ? config.routes : []
const hasRoute = (r) =>
  currentRoutes.some((c) => c && c.pattern === r.pattern && Boolean(c.custom_domain) === Boolean(r.custom_domain))
const missing = DESIRED_ROUTES.filter((r) => !hasRoute(r))
if (missing.length) {
  config.routes = [...currentRoutes, ...missing]
  changes.push(`routes+=${missing.map((r) => r.pattern).join(',')}`)
}

// Keep the `*.workers.dev` subdomain live alongside the Custom Domain so preview links and smoke tests that target
// `mkit-demo-web.<account>.workers.dev` keep working. Without this, Wrangler disables `workers.dev` the moment any
// route is declared.
if (config.workers_dev !== true) {
  config.workers_dev = true
  changes.push('workers_dev=true')
}
if (config.preview_urls !== true) {
  config.preview_urls = true
  changes.push('preview_urls=true')
}

writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`)
console.log(`patched ${configPath}: ${changes.length ? changes.join(', ') : 'no changes (already up-to-date)'}`)
