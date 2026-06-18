// Bare-domain installer sniff.
//
// SOTA installers are reachable from the project's own short domain — e.g.
// `curl claude.ai/install.sh | sh`, `sh.rustup.rs`, `curl deno.land/install.sh`.
// We serve the canonical repo-root install.sh as a static asset at
// `/install.sh` (staged by scripts/copy-install.mjs), and additionally let the
// bare domain work: `curl mkit.sh | sh`.
//
// The catch with the bare domain is that `/` must keep serving the HTML
// homepage to browsers. We disambiguate on the User-Agent: command-line
// fetchers (curl/wget/...) get the script, everything else falls through to
// Waku's router. We serve the script BODY directly — never a redirect —
// because bare `curl mkit.sh | sh` does not pass `-L` and would otherwise pipe
// a 3xx HTML body straight into `sh`.

// Match only command-line HTTP fetchers at the START of the UA string. Browsers
// send `Mozilla/...`; crawlers send their own product tokens — both fall
// through to the homepage, so SEO and normal navigation are untouched.
const CLI_FETCHER_UA = /^(curl|wget|fetch|libcurl|httpie)\b/i

type AssetsEnv = { ASSETS: { fetch: (req: Request | URL | string) => Promise<Response> } }

/**
 * If `req` is a command-line fetcher asking for the site root, return the
 * install script with shell-friendly headers. Otherwise return `null` so the
 * caller delegates to the normal page router.
 */
export async function tryServeInstaller(req: Request, env: AssetsEnv): Promise<Response | null> {
  if (req.method !== 'GET' && req.method !== 'HEAD') return null

  const url = new URL(req.url)
  if (url.pathname !== '/') return null

  const ua = req.headers.get('user-agent') ?? ''
  if (!CLI_FETCHER_UA.test(ua)) return null

  // Reuse the already-staged static asset so there is a single source of truth.
  const asset = await env.ASSETS.fetch(new URL('/install.sh', url))
  if (!asset.ok) return null

  const res = new Response(asset.body, asset)
  res.headers.set('Content-Type', 'text/x-shellscript; charset=utf-8')
  // `/` now varies by User-Agent (script for curl, HTML for browsers). Without
  // this, a shared cache could serve the script to a browser or vice versa.
  res.headers.set('Vary', 'User-Agent')
  res.headers.set('Cache-Control', 'public, max-age=600')
  return res
}

// Hono context shape we rely on — kept minimal so we don't couple to a Hono
// type import. `env` is the Cloudflare bindings object (carries ASSETS).
type InstallerContext = { req: { raw: Request }; env: AssetsEnv }

/**
 * Cloudflare-adapter middleware factory for the installer sniff.
 *
 * IMPORTANT: this must be wired via the adapter's `middlewareFns` option, not a
 * top-level `fetch` override. Waku's Cloudflare adapter invokes the deployed
 * Worker through its internal Hono app (`defaultExport.fetch` → `fetchFn`);
 * `middlewareFns` run inside that app, before the RSC page router. A `fetch`
 * wrapper on the exported object is only reached by build-time SSG, so it never
 * sees production requests.
 *
 * Pair with `assets.run_worker_first: ["/"]` in wrangler config so the Worker
 * actually receives `GET /` instead of Cloudflare serving the prerendered
 * homepage asset first.
 */
export function installerMiddleware() {
  return async (c: InstallerContext, next: () => Promise<void>): Promise<Response | void> => {
    const res = await tryServeInstaller(c.req.raw, c.env)
    if (res) return res
    return next()
  }
}
