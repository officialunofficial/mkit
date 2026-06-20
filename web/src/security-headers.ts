const CONTENT_SECURITY_POLICY_REPORT_ONLY = [
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
].join('; ')

const SECURITY_HEADERS = [
  ['Content-Security-Policy-Report-Only', CONTENT_SECURITY_POLICY_REPORT_ONLY],
  ['X-Content-Type-Options', 'nosniff'],
  ['X-Frame-Options', 'DENY'],
  ['Referrer-Policy', 'no-referrer'],
  [
    'Permissions-Policy',
    [
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
    ].join(', '),
  ],
] as const

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
 * Cloudflare-adapter middleware that applies the security headers to every
 * response on the LIVE request path.
 *
 * Must be wired via the adapter's `middlewareFns` option, not a top-level
 * `fetch` override: Waku's Cloudflare adapter dispatches the deployed Worker
 * through `defaultExport.fetch` → its internal Hono app, so an exported-object
 * `fetch` wrapper is only reached by build-time SSG and never runs in prod
 * (which is why these headers were silently absent before). Registering it
 * first in `middlewareFns` makes it the outermost wrapper, so it also covers
 * short-circuit responses like the installer sniff.
 */
export function securityHeadersMiddleware() {
  return async (c: ResponseContext, next: () => Promise<void>): Promise<void> => {
    await next()
    c.res = withSecurityHeaders(c.res)
  }
}
