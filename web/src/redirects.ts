// Legacy-route redirects.
//
// The hash/sign/streaming/attest demos used to each have their own page; they
// are now tabs on `/demos` (see components/demos-tabs.tsx, which still keys off
// `#hash | #sign | #streaming | #attest`). The old pages were deleted, so those
// paths no longer prerender to a static asset — which means Cloudflare hands the
// request to the Worker's Hono app, where this middleware can 301 it to the new
// anchor instead of letting the RSC router 404. Permanent (301) because the old
// URLs are gone for good: search engines and any existing inbound links should
// learn the new location.

const REDIRECTS: Record<string, string> = {
  '/hash': '/demos#hash',
  '/sign': '/demos#sign',
  '/streaming': '/demos#streaming',
  '/attest': '/demos#attest',
}

/**
 * Target path for a deleted legacy route, or `null` if `pathname` is not one. A single trailing slash is tolerated so
 * `/sign/` resolves like `/sign` (the asset layer's `drop-trailing-slash` only normalises requests that hit an asset;
 * these paths have none).
 */
export function resolveRedirect(pathname: string): string | null {
  const path = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname
  return REDIRECTS[path] ?? null
}

// Hono context shape we rely on — kept minimal so we don't couple to a Hono
// type import (matches install-route.ts's approach).
type RedirectContext = { req: { raw: Request } }

/**
 * Cloudflare-adapter middleware factory that 301s the deleted demo routes to their `/demos#…` anchors.
 *
 * Like the installer sniff, this must be wired via the adapter's `middlewareFns` option (see waku.server.tsx): it runs
 * inside the deployed Worker's Hono app, before the RSC page router, so it intercepts a path that no longer has a
 * prerendered asset before that router answers 404. No `run_worker_first` entry is needed — a request with no matching
 * static asset already falls through to the Worker.
 */
export function redirectMiddleware() {
  return async (c: RedirectContext, next: () => Promise<void>): Promise<Response | void> => {
    const target = resolveRedirect(new URL(c.req.raw.url).pathname)
    if (target) return new Response(null, { status: 301, headers: { Location: target } })
    return next()
  }
}
