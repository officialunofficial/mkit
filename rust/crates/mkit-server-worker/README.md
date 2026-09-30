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

Set `AUTHORITY_FENCE=true` and `AUTHORITY_KEYS` (secret) to enable namespace
fencing under Multi addressing and an Authority hook. Each key line is
`<key-id> <64 lowercase hex public key> <namespace[,namespace...]>`; keys must be
dedicated and differ from owner, hook, ticket and active/retired URL-token keys.
Every write allowance must include `authority_generation`. Fencing is off by
default; launch activation belongs to WP-4.18. The getter/setter and canonical
signed statement contract are SPEC-SERVER §6.2.1.

Once a namespace has persisted authority fencing, disabling the executor setting
refuses new writes for that namespace, including generation zero. Initial
activation may return `unavailable` with `Retry-After: 1` until its bounded lease
barrier completes. Repeating the signed target resumes durable progress; it does
not create a namespace or charge first-write creation. Restore must preserve the
authority mode and generation, then declare real lease-table recovery.
