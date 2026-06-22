// Single source of truth for the site's HTTP security headers.
//
// Two delivery paths consume this module and MUST stay in sync — that's why the
// values live here once instead of being duplicated:
//   1. The live Worker request path (src/security-headers.ts → securityHeadersMiddleware),
//      which covers `/` (the only `run_worker_first` route) and any future
//      worker-served response.
//   2. The Cloudflare static-asset `_headers` file (public/_headers), which covers
//      EVERY route — including the prerendered demo pages (/tree, /hash, …) that are
//      served straight from the Assets binding and never reach the Worker. That file
//      is generated from these constants by scripts/gen-headers.mjs (run in the build
//      chain) so it can't drift from this source.
//
// This module is plain data + string builders with no imports, so it can be loaded
// both by the bundled Worker and by the Node build script.

/**
 * Content-Security-Policy directives.
 *
 * Tuned for this app's actual resource use (validated while it shipped as Report-Only): WASM via `wasm-unsafe-eval` +
 * `worker-src blob:`, the inline no-flash theme script and React 19 RSC inline bootstrap via `'unsafe-inline'`, Google
 * Fonts, and the Cloudflare Insights beacon. Cross-origin references to github.com / og.mkit.sh / etc. are only `<a
 * href>` navigations and `<meta>` OG tags, neither of which a fetch-directive blocks, so they need no allowance here.
 */
export const CSP_DIRECTIVES = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://static.cloudflareinsights.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' data: blob:",
  "connect-src 'self' https://cloudflareinsights.com",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
] as const

export const CONTENT_SECURITY_POLICY = CSP_DIRECTIVES.join('; ')

const PERMISSIONS_POLICY = [
  'accelerometer=()',
  'ambient-light-sensor=()',
  'autoplay=()',
  'camera=()',
  'display-capture=()',
  'encrypted-media=()',
  'fullscreen=(self)',
  'geolocation=()',
  'gyroscope=()',
  'magnetometer=()',
  'microphone=()',
  'payment=()',
  'picture-in-picture=()',
  'publickey-credentials-get=(self)',
  'screen-wake-lock=()',
  'serial=()',
  'usb=()',
  'xr-spatial-tracking=()',
].join(', ')

// HSTS: two years, include subdomains, and submit for the browser preload list.
// Only meaningful over HTTPS (mkit.sh is HTTPS-only behind Cloudflare), and
// browsers ignore it on plain HTTP, so it is safe to send everywhere.
const STRICT_TRANSPORT_SECURITY = 'max-age=63072000; includeSubDomains; preload'

/**
 * The full security-header set, as `[name, value]` pairs. Consumed by both the Worker middleware and the `_headers`
 * generator. CSP is sent ENFORCING (not Report-Only): there is no report-collection endpoint wired up, so Report-Only
 * was a no-op, and the directives above already match every resource the live demos load.
 */
export const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  ['Content-Security-Policy', CONTENT_SECURITY_POLICY],
  ['Strict-Transport-Security', STRICT_TRANSPORT_SECURITY],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'no-referrer'],
  ['Permissions-Policy', PERMISSIONS_POLICY],
] as const
