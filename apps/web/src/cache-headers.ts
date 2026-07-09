// Cache-Control for the Worker-rendered homepage.
//
// `/` is the sole `run_worker_first` route (see waku.server.tsx / install-route.ts): every
// hit re-runs a full Waku RSC render even though the page is otherwise static. Cloudflare's
// native Workers Cache (`cache.enabled` in wrangler config — see patch-worker-config.mjs)
// sits in front of the Worker and honours whatever Cache-Control the response carries, so
// stamping one here turns repeat homepage hits into cache hits with zero Worker execution.
//
// The Worker version is part of the cache key by default (we do NOT set
// `cache.cross_version_cache`), so every deploy starts from a cold cache — a content change
// takes effect immediately and this TTL can be generous without risking stale HTML.
const CACHE_CONTROL = 'public, max-age=3600, stale-while-revalidate=300'

// Hono context shape we rely on — kept minimal so we don't couple to a Hono type import
// (matches install-route.ts / security-headers.ts's approach).
type CacheContext = { req: { raw: Request }; res: Response }

/**
 * Cloudflare-adapter middleware factory that stamps Cache-Control onto a genuine page render.
 *
 * Must be registered LAST in `waku.server.tsx`'s `middlewareFns` array — the innermost layer, closest to the RSC router
 * — so it only ever wraps the actual rendered-page response. The installer sniff and the legacy redirects both
 * short-circuit BEFORE calling `next()`, so this middleware's body never runs for those requests; it can't clobber the
 * installer's `Cache-Control: no-store` or a redirect's headers.
 *
 * Only stamps GET/HEAD 200 responses that don't already carry a `Cache-Control` header — a defensive guard, not a
 * load-bearing one, since every request that reaches here is already known to be a `/` browser hit.
 */
export function cacheHeadersMiddleware() {
  return async (c: CacheContext, next: () => Promise<void>): Promise<void> => {
    await next()
    const method = c.req.raw.method
    if ((method === 'GET' || method === 'HEAD') && c.res.status === 200 && !c.res.headers.has('Cache-Control')) {
      const cached = new Response(c.res.body, c.res)
      cached.headers.set('Cache-Control', CACHE_CONTROL)
      c.res = cached
    }
  }
}
