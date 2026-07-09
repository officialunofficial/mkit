import { fsRouter } from 'waku'
import adapter from 'waku/adapters/cloudflare'
import { cacheHeadersMiddleware } from './cache-headers'
import { installerMiddleware } from './install-route'
import { redirectMiddleware } from './redirects'
import { securityHeadersMiddleware } from './security-headers'

// fsRouter requires glob keys prefixed with the pages dir ("./pages/hash.tsx"),
// so the glob must NOT use the `base` option — waku 1.0.0-beta.2 silently skips
// every module whose key lacks the "pages/" prefix, which ships a blank site
// (zero routes, no prerender). scripts/assert-prerender.mjs fails the build if
// this ever regresses.
//
// All middlewares run inside the adapter's live Hono handler (`defaultExport.fetch`),
// NOT as a top-level `fetch` wrapper — the deployed Worker never calls this
// object's `fetch`, so a wrapper only runs at build-time SSG. Order matters:
// securityHeaders is first → outermost, so it also stamps the installer sniff's
// and the legacy-redirect short-circuit responses. The installer needs
// `assets.run_worker_first: ["/"]` (patch-worker-config.mjs) so the Worker
// actually receives `GET /`; the redirects need no such entry — the deleted
// demo routes have no asset, so they already fall through to the Worker.
// cacheHeaders is last → innermost, wrapping only the actual RSC render, so it
// never overwrites the installer's `no-store` or a redirect's headers.
const server = adapter(fsRouter(import.meta.glob('./pages/**/*.{tsx,ts}')), {
  middlewareFns: [securityHeadersMiddleware, installerMiddleware, redirectMiddleware, cacheHeadersMiddleware],
})

export default server
