# mkit-server-worker

Cloudflare Workers adapter for the runtime-agnostic mkit server: streaming
R2 blobs, Durable Object metadata, Connect dispatch and remote hooks over
service bindings.

HTTP object serving is Stage 2 and explicitly opt-in. The default build,
reference app dependency and shipped Stage 1 features omit `http-objects`.
Even with the feature, `WorkerConfig::http_mount` defaults to `None` and
`INDEXED_MODE` remains refused. A programmatic `WorkerHttpMountConfig`
provides indexed configuration, HTTP configuration and read-CORS options;
call `adapter::serve_with` with that configuration. Environment variables
cannot activate the mount. Production activation belongs to WP-4.18/5.2.

The feature-gated secret `URL_TOKEN_KEYS` uses the key-file grammar:
`active <64 hex seed>` and `retired <64 hex public key> <retired_at_ms>`.
`URL_TOKEN_TTL` is seconds, defaults to 900 and accepts 1–86400. Parsed keys
are copied into the pipeline only when a mount is configured. Active and
retained public keys cannot repeat ticket-key material. Service-binding
hooks have no signing key; signed hook, receipt and admin roles must keep
their own separation checks when introduced.

The mount uses the runtime's escaped URL directly, preserving an empty
trailing query. Objects dispatch by `/-/`; RPC service dispatch stays exact.
Range responses stream, repeated headers and Content-Length survive, and
HEAD suppresses the body on every status. Workers can combine repeated
challenge fields as an ordered challenge list. HTTP object serving uses
no shared cache lookup or insertion, including for private responses.

Read CORS defaults to `*`; `HttpMountOptions::cors_origins` provides exact
allowed-origin echo with `Vary: Origin` on every response and no credential
permission. OPTIONS requires no authentication or payment. The public
`/.well-known/mkit-url-token-keys.json` key document also uses read CORS,
requires no bearer/payment and caches publicly for 300 seconds. Invalid
URL diagnostics never print URL/query text.

For paid reads, supply `WorkerHttpMountConfig::read_runtime` with Worker
sleep and a spawner retaining work through the request's `wait_until`
lifetime. Missing retention fails closed when a reservation is required.
Optional `HttpObjectsConfig::redirect_public_refs` redirects only public
ref GET/HEAD without proofs after earlier checks, preserving the repository
prefix in a relative object URL; configured admission disables redirects.

The [local workerd probe](tests/http-mount-probe/README.md) exercises the real
streaming bridge and outer response policy without deployment or cloud bindings.
