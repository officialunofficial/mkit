# ADR 0003 — Web security headers via static `_headers` plus worker middleware

- Status: Accepted
- Date: 2026-06-22
- Supersedes: n/a

## Context

The mkit web app (`mkit/web`) is a Cloudflare Worker that prerenders pages to
static assets. Prerendered pages are served directly by the Cloudflare Assets
binding and **bypass the worker** — so worker-only response middleware never
runs for those routes, and any security headers it sets are absent on the most
common (static) paths. Relying on middleware alone leaves prerendered routes
uncovered.

## Decision

- Ship a static [`public/_headers`](../../apps/web/public/_headers) file so the
  Assets binding applies security headers to **prerendered/static routes**,
  covering the paths the worker never sees.
- Keep the worker response middleware for dynamically served routes, so the two
  mechanisms together cover **all routes**.
- Add **HSTS** (`Strict-Transport-Security`) to the header set.
- Note the **CSP posture**: a Content-Security-Policy is set as part of the
  header set; it is tracked in `apps/web/src/security-headers.ts` so the static and
  middleware paths stay in agreement.

## Consequences

- Security headers (incl. HSTS) are present on every route regardless of whether
  the worker runs — the static-asset bypass no longer drops them.
- Two places define the header set (`public/_headers` and the worker
  middleware); they must be kept in sync, asserted by
  `apps/web/src/security-headers.test.ts`.
- HSTS commits the apex/subdomains to HTTPS-only for its `max-age`; a rollback
  to plain HTTP is not transparent within that window.
