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
// through to the homepage, so SEO and normal navigation are untouched. This
// allowlist is intentionally conservative (false positives would serve a shell
// script to a browser); the explicit `/install.sh` path is the guaranteed,
// UA-independent way to fetch the installer for any other client.
const CLI_FETCHER_UA = /^(curl|wget|fetch|libcurl|httpie|aria2)\b/i

type AssetsEnv = { ASSETS: { fetch: (req: Request | URL | string) => Promise<Response> } }

/**
 * If `req` is a command-line fetcher asking for the site root, return the install script. Otherwise return `null` so
 * the caller delegates to the normal page router.
 */
export async function tryServeInstaller(req: Request, env: AssetsEnv): Promise<Response | null> {
  if (req.method !== 'GET' && req.method !== 'HEAD') return null

  const url = new URL(req.url)
  if (url.pathname !== '/') return null

  const ua = req.headers.get('user-agent') ?? ''
  if (!CLI_FETCHER_UA.test(ua)) return null

  // Reuse the already-staged static asset so there is a single source of truth.
  // Any failure here (unbound ASSETS, fetch error, non-200) must NOT take `/`
  // down for browsers — `run_worker_first: ["/"]` routes every homepage request
  // through this middleware, so a throw would 500 the site. Fall through (null)
  // and let the normal homepage render instead.
  let asset: Response
  try {
    asset = await env.ASSETS.fetch(new URL('/install.sh', url))
  } catch {
    return null
  }
  if (!asset.ok) return null

  // Build the response from scratch instead of `new Response(asset.body, asset)`
  // so the asset's ETag / Content-Length / Content-Encoding don't leak through
  // and mismatch once we relabel the Content-Type.
  //
  // `no-store` — NOT `public` + `Vary: User-Agent`. This URL returns the script
  // to CLI fetchers and HTML to browsers, but Cloudflare and many proxies ignore
  // `Vary: User-Agent`, so a shared cache could hand the script to a browser or
  // the homepage to `curl … | sh`. The only safe answer is to never cache `/`.
  return new Response(asset.body, {
    status: 200,
    headers: {
      'Content-Type': 'text/x-shellscript; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  })
}

// Hono context shape we rely on — kept minimal so we don't couple to a Hono
// type import. `env` is the Cloudflare bindings object (carries ASSETS).
type InstallerContext = { req: { raw: Request }; env: AssetsEnv }

/**
 * Cloudflare-adapter middleware factory for the installer sniff.
 *
 * IMPORTANT: this must be wired via the adapter's `middlewareFns` option, not a top-level `fetch` override. Waku's
 * Cloudflare adapter invokes the deployed Worker through its internal Hono app (`defaultExport.fetch` → `fetchFn`);
 * `middlewareFns` run inside that app, before the RSC page router. A `fetch` wrapper on the exported object is only
 * reached by build-time SSG, so it never sees production requests.
 *
 * Pair with `assets.run_worker_first: ["/"]` in wrangler config so the Worker actually receives `GET /` instead of
 * Cloudflare serving the prerendered homepage asset first.
 */
export function installerMiddleware() {
  return async (c: InstallerContext, next: () => Promise<void>): Promise<Response | void> => {
    const res = await tryServeInstaller(c.req.raw, c.env)
    if (res) return res
    return next()
  }
}
