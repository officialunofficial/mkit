import { fsRouter } from 'waku'
import adapter from 'waku/adapters/cloudflare'
import { installerMiddleware } from './install-route'
import { securityHeadersMiddleware } from './security-headers'

// fsRouter requires glob keys prefixed with the pages dir ("./pages/hash.tsx"),
// so the glob must NOT use the `base` option — waku 1.0.0-beta.2 silently skips
// every module whose key lacks the "pages/" prefix, which ships a blank site
// (zero routes, no prerender). scripts/assert-prerender.mjs fails the build if
// this ever regresses.
//
// Both middlewares run inside the adapter's live Hono handler (`defaultExport.fetch`),
// NOT as a top-level `fetch` wrapper — the deployed Worker never calls this
// object's `fetch`, so a wrapper only runs at build-time SSG. Order matters:
// securityHeaders is first → outermost, so it also stamps the installer sniff's
// short-circuit response. The installer needs `assets.run_worker_first: ["/"]`
// (patch-worker-config.mjs) so the Worker actually receives `GET /`.
const server = adapter(fsRouter(import.meta.glob('./pages/**/*.{tsx,ts}')), {
  middlewareFns: [securityHeadersMiddleware, installerMiddleware],
})

export default server
