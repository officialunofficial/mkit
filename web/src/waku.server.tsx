import { fsRouter } from 'waku'
import adapter from 'waku/adapters/cloudflare'
import { installerMiddleware } from './install-route'
import { withSecurityHeaders } from './security-headers'

// fsRouter requires glob keys prefixed with the pages dir ("./pages/hash.tsx"),
// so the glob must NOT use the `base` option — waku 1.0.0-beta.2 silently skips
// every module whose key lacks the "pages/" prefix, which ships a blank site
// (zero routes, no prerender). scripts/assert-prerender.mjs fails the build if
// this ever regresses.
// `curl mkit.sh | sh` — the installer sniff is registered as a Cloudflare-
// adapter middleware (runs inside the live Hono handler, before the RSC page
// router) rather than a fetch wrapper, because the deployed Worker dispatches
// through `defaultExport.fetch` and never calls this object's `fetch`. Paired
// with `assets.run_worker_first: ["/"]` so the Worker receives `GET /`.
const server = adapter(fsRouter(import.meta.glob('./pages/**/*.{tsx,ts}')), {
  middlewareFns: [installerMiddleware],
})

export default {
  ...server,
  async fetch(req, ...args) {
    return withSecurityHeaders(await server.fetch(req, ...args))
  },
} satisfies typeof server
