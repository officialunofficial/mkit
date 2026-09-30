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
their own separation checks. Signed hook and admin keys are checked at startup.

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

## Launch purge and audit configuration

`ADMIN_KEYS` contains the SPEC-SERVER §16.3 public-key list as a Worker secret.
It defaults off and mounts only `ReadAuditLog`; manual `PurgeCache` is deferred
to WP-5.6a. Admin requests use a separate signed envelope and cannot authenticate
client writes. Operator keys must differ from ticket, token, hook and authority
keys. Persisted sharding/addressing checks run before operator dispatch.

For a global purger, build with `signed-http-hooks`, explicitly include
`cache-purge` in `HOOK_ROLES`, set an
HTTPS `HOOK_URL` and the `MKIT_HOOK_KEY` signing secret, and use `WORKERS_PLAN=paid`.
A purge-only role list does not enable Authorize, Admit or Outcome. Invalid or
unsigned purge configuration refuses startup. The signed sink must acknowledge
with an empty JSON object; retries keep the body/id and use fresh nonces. The
sink must map the audience to the configured snapshot deployment and purge the
actual custom keys, including all 16 snapshot buckets; selector strings alone
do not attach Cache-Tag headers to existing snapshot entries.

Automatic callers accept repository-scoped intents in the triggering state apply.
The colo-local Cache API deletes paths and all existing snapshot cache keys.
Namespace suspension consumers must use those repository intents; this foundation
does not expose namespace manual acceptance. Gated entrypoints keep Workers
Caching disabled. The existing snapshot seam strongly checks durable invalidation
before and after lookup/refill, so retained R2 bytes cannot resurrect an invalidated
snapshot. Root audit append and its relay watermark share the target SQL apply.
All Paid alarm heads share one external-operation allowance. Until WP-5.4
integrates generation-aware publication, an invalidated repository uses live
reads rather than accepting a refreshed snapshot. Future inspector callers in
RepoIndex must integrate that published/serving authority seam before enabling
inspection snapshots.

## In-process canonical object prefetch (WP-4.16c)

With `http-objects` and explicit indexed/HTTP configuration, construct the
request's pipeline using `adapter::embedding_pipeline(env, cfg, hooks,
&request_budget, ...)`, then call `pipeline.object_reader(repo, ReaderView::Public)`.
The optional final `snapshot_warm` argument exists with `published-view`; use
`false` for an ordinary request. Share the request's existing 9,000-call physical
`SliceBudget` with the constructor. The native equivalent is
`Pipeline::object_reader`; native and Worker adapters re-export `ReaderView`
and `ObjectReader`. This API uses the shared core and adds no HTTP mount or wire.

`Public` is anonymous: public repositories, published refs and membership.
`Owner(&request_meta)` requires a verified auth-v2 `ListRefs` envelope for this
repository's owner or valid write grant. It uses the existing auth stage at
construction and again per batch, including grant-epoch checks. Passing the view
variant alone confers no authority. Owners use live refs and membership;
publication holds and global denial still filter objects. Blocked IDs, anonymous reads of private repositories
and unreachable IDs return `None`, matching id-route absence.

Each call accepts at most **16 IDs**, preserves order and duplicates, and caps
core work at **8,500 calls** inside the request's physical allowance. It shares
one bounded reachability walk (with eligible positive-cache proofs) and one
set-based global-denial descriptor pass. Every store operation is charged;
authorization and external seams reserve calls conservatively. Exhausted call,
decode or denial-context budgets fail closed with `unavailable`. Canonical
response bytes, including duplicate IDs, also fit `http_decode_budget`.

`read_canonical` returns serialized Blob, Tree, Commit, Remix, Tag and
**ChunkedBlob manifest** bytes, never pack-only Delta encodings.
`object_sizes` returns indexed uncompressed content sizes: Blob payload length
and other objects' canonical serialized length. It performs **no requested-object
byte reads**. Authorization may read canonical commit/tree/tag/manifest
ancestors; one manifest authorizes all requested chunks, without a read per
chunk. The restriction also covers delta bases used to reconstruct ancestors.
If a requested ancestor would need expansion to prove another requested ID,
request their sizes in separate batches; an incomplete proof returns
`unavailable` rather than reading the requested ancestor or claiming absence.

Prefetch the commit, trees, manifests and selected chunks asynchronously, then
insert the returned bytes into the wasm-clean synchronous source:

```rust,ignore
let reader = pipeline.object_reader(repo, ReaderView::Public).await?;
let mut source = mkit_core::store::MemorySource::default();
for (id, bytes) in ids.iter().zip(reader.read_canonical(&ids).await?) {
    if let Some(bytes) = bytes { source.insert(*id, bytes)?; }
}
let bundle = mkit_core::verify::build_disclosure_from(
    &source, &commit, &[b"file.bin"], mkit_core::verify::Selector::Object,
)?;
let verified = mkit_core::verify::verify_disclosure(&commit, &bundle)?;
```

`MemorySource` verifies each read, including Merkle object identities. Core
`diff_trees` and related builders use the same source synchronously. Hosts bound
aggregate prefetched memory and retain request authorization; there is no
blocking or `block_on` bridge inside the async reader.
