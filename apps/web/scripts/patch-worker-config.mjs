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
const COMPATIBILITY_DATE = '2026-05-31'
const changes = []

if (config.compatibility_date !== COMPATIBILITY_DATE) {
  config.compatibility_date = COMPATIBILITY_DATE
  changes.push(`compatibility_date=${COMPATIBILITY_DATE}`)
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
const DESIRED_ROUTES = [{ pattern: 'mkit.sh', custom_domain: true }]
const currentRoutes = Array.isArray(config.routes) ? config.routes : []
const hasRoute = (r) =>
  currentRoutes.some((c) => c && c.pattern === r.pattern && Boolean(c.custom_domain) === Boolean(r.custom_domain))
const missing = DESIRED_ROUTES.filter((r) => !hasRoute(r))
if (missing.length) {
  config.routes = [...currentRoutes, ...missing]
  changes.push(`routes+=${missing.map((r) => r.pattern).join(',')}`)
}

// Run the Worker BEFORE static assets for the bare-domain root so `curl mkit.sh | sh` can be intercepted by the
// User-Agent sniff in src/install-route.ts. Cloudflare's `run_worker_first` accepts a route list, so only `/` pays
// the worker-first cost — every other path (including /install.sh and the prerendered demo pages) keeps the fast
// asset-first path. Without this, `/` is served straight from the prerendered index.html and the Worker never runs.
if (config.assets && typeof config.assets === 'object') {
  const runFirst = new Set(Array.isArray(config.assets.run_worker_first) ? config.assets.run_worker_first : [])
  if (!runFirst.has('/')) {
    runFirst.add('/')
    config.assets.run_worker_first = [...runFirst]
    changes.push('assets.run_worker_first+=/')
  }
}

// Keep the `*.workers.dev` subdomain live alongside the Custom Domain so preview links and smoke tests that target
// `mkit-web.<account>.workers.dev` keep working. Without this, Wrangler disables `workers.dev` the moment any
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
