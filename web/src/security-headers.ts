// Worker-side delivery of the security headers. The header VALUES are defined once
// in ./security-policy.ts (the single source of truth shared with the build-time
// `_headers` generator) — edit policy there, not here.
//
// Coverage note: this middleware only runs for routes the Worker actually handles —
// i.e. `/` (the sole `run_worker_first` route) and short-circuit responses like the
// installer sniff. Every prerendered page (/tree, /hash, …) is served directly by the
// Cloudflare Assets binding and bypasses the Worker, so those routes get their headers
// from public/_headers instead. The two paths are kept in sync via security-policy.ts.
import { SECURITY_HEADERS } from './security-policy'

export function withSecurityHeaders(response: Response): Response {
  const secured = new Response(response.body, response)
  for (const [name, value] of SECURITY_HEADERS) {
    secured.headers.set(name, value)
  }
  return secured
}

// Hono context shape we rely on — kept minimal so we don't couple to a Hono type
// import (matches the installer middleware's approach).
type ResponseContext = { res: Response }

/**
 * Cloudflare-adapter middleware that applies the security headers to every response on the LIVE request path.
 *
 * Must be wired via the adapter's `middlewareFns` option, not a top-level `fetch` override: Waku's Cloudflare adapter
 * dispatches the deployed Worker through `defaultExport.fetch` → its internal Hono app, so an exported-object `fetch`
 * wrapper is only reached by build-time SSG and never runs in prod (which is why these headers were silently absent
 * before). Registering it first in `middlewareFns` makes it the outermost wrapper, so it also covers short-circuit
 * responses like the installer sniff.
 */
export function securityHeadersMiddleware() {
  return async (c: ResponseContext, next: () => Promise<void>): Promise<void> => {
    await next()
    c.res = withSecurityHeaders(c.res)
  }
}
