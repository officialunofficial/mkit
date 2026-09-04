# mkit-transport-http

**Legacy:** superseded by `mkit-transport-connect`, which is what
`mkit+https://`/`mkit+http://` actually dispatch to in `mkit-cli` &mdash;
`HttpTransport` here is never constructed by any shipped CLI path. Retained
only as the reference implementation of the `sparse-checkout`/`pack-shards`
extensions (SPEC-TRANSPORT §6-§7), which have no CLI or server consumer
either. See SPEC-TRANSPORT-CONNECT §8 for the removal-decision status.

HTTP/HTTPS transport for mkit, with rustls TLS, a JSON REST dialect, and
bounded body sizes.

Speaks a simple JSON REST dialect against a mkit VCS Worker (for example a
Cloudflare Worker and R2). User-facing URL shape: `mkit+https://<host>/<project>`
&mdash; the `mkit+` prefix is stripped before the inner `reqwest` call. Full
contract in `docs/specs/SPEC-TRANSPORT.md` §5.1.

## Wire contract

- `POST /<project>/packs` &mdash; body is pack bytes, response is
  `{"key": "<64-hex>"}`. `ETag` on success = `MD5(body)` (advisory only; the
  client trusts the returned key).
- `GET  /<project>/packs/<key>` &mdash; response is pack bytes.
- `HEAD /<project>/packs/<key>` &mdash; existence check.
- `GET  /<project>/refs/<name>` &mdash; response is `{"hash": "<64-hex>"}` or
  `404`.
- `PUT  /<project>/refs/<name>` &mdash; body is `{"hash": "<hex>"}`, headers
  include `If-Match` / `If-None-Match` for CAS.
- `GET  /<project>/refs?prefix=<p>` &mdash; response is
  `{"refs":[{"name": ..., "hash": ...}]}`.

Auth: optional `MKIT_API_TOKEN` env var → `Authorization: Bearer <t>`.

Retry policy: every request is driven by `mkit_core::protocol::BackoffIterator`
&mdash; up to 5 attempts, classified by `is_retryable`. CAS writes (`412`/`409`)
never retry.

Blocking by design: the `Transport` trait is synchronous, so this crate uses
`reqwest::blocking`. Callers in an async context must run it on a blocking
thread pool.
