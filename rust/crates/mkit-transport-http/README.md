# mkit-transport-http

HTTP/HTTPS transport for mkit, with rustls TLS, a JSON REST dialect, and
bounded body sizes.

Speaks a simple JSON REST dialect against a mkit VCS Worker (e.g. a
Cloudflare Worker + R2). User-facing URL shape: `mkit+https://<host>/<project>`
— the `mkit+` prefix is stripped before the inner `reqwest` call. Full
contract in `docs/SPEC-TRANSPORT.md` §5.1.

## Wire contract

- `POST /<project>/packs` — body is pack bytes, response is
  `{"key": "<64-hex>"}`. `ETag` on success = `MD5(body)` (advisory only; the
  client trusts the returned key).
- `GET  /<project>/packs/<key>` — response is pack bytes.
- `HEAD /<project>/packs/<key>` — existence check.
- `GET  /<project>/refs/<name>` — response is `{"hash": "<64-hex>"}` or
  `404`.
- `PUT  /<project>/refs/<name>` — body is `{"hash": "<hex>"}`, headers
  include `If-Match` / `If-None-Match` for CAS.
- `GET  /<project>/refs?prefix=<p>` — response is
  `{"refs":[{"name": ..., "hash": ...}]}`.

Auth: optional `MKIT_API_TOKEN` env var → `Authorization: Bearer <t>`.

Retry policy: every request is driven by `mkit_core::protocol::BackoffIterator`
— up to 5 attempts, classified by `is_retryable`. CAS writes (`412`/`409`)
never retry.

Blocking by design: the `Transport` trait is synchronous, so this crate uses
`reqwest::blocking`. Callers in an async context must run it on a blocking
thread pool.
