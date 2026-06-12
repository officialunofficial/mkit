import { fsRouter } from 'waku'
import adapter from 'waku/adapters/cloudflare'
import { withSecurityHeaders } from './security-headers'

// fsRouter requires glob keys prefixed with the pages dir ("./pages/hash.tsx"),
// so the glob must NOT use the `base` option — waku 1.0.0-beta.2 silently skips
// every module whose key lacks the "pages/" prefix, which ships a blank site
// (zero routes, no prerender). scripts/assert-prerender.mjs fails the build if
// this ever regresses.
const server = adapter(fsRouter(import.meta.glob('./pages/**/*.{tsx,ts}')))

export default {
  ...server,
  async fetch(req, ...args) {
    return withSecurityHeaders(await server.fetch(req, ...args))
  },
} satisfies typeof server
