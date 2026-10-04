# mkit-server-worker

Cloudflare Workers adapter for the runtime-agnostic mkit server: streaming
R2 blobs, Durable Object metadata, Connect dispatch and remote hooks over
service bindings.

`sql::SqlKvStore` implements the core `NamespaceStore` contract over the
synchronous `sql::SqlConn` trait. `do_sql::DoSqlConn` supplies the Durable
Object `SQLite` engine; native `SQLite` connections stay in the test host.
Worker relay budgets live in `relay`, and physical storage alerts live in
`telemetry::pressure`.

HTTP object serving is explicitly opt-in. The default build omits
`http-objects` and `WorkerConfig::http_mount` defaults to `None`. The Paid Workers
profile (`LAUNCH_PROFILE=paid-workers`, `INDEXED_MODE=true`, Multi/D34 and tickets)
activates the merged verification/extraction driver. `HTTP_OBJECTS=true` plus
complete dedicated `URL_TOKEN_KEYS` selects the HTTP mount when compiled with
`http-objects`. A programmatic `WorkerHttpMountConfig` also configures serving
and read-CORS options. See the [reference configuration](../../../apps/vcs-worker/README.md#paid-workers-launch-profile-wp-418--r-194).
Native serves proofs; release Worker `?proof=1` remains unsupported and its
ServerInfo does not advertise proof capability.

Ref-path file responses use the extension-derived Content-Type allowlist and
Content-Disposition filename from SPEC-HTTP-OBJECTS §5.1. Object-id file responses
remain `application/octet-stream`. Every byte-serving response retains nosniff
and the sandbox CSP.

`DEFAULT_REPO_VISIBILITY=public|private` defaults to `public` and supplies
`WorkerConfig::default_repo_visibility` when no explicit visibility is stored.
Visibility applies to Multi deployments with Owner write policy; Single/Open
deployments do not gate reads by repository visibility.
An explicit `SetRepoVisibility` wins. Changing the default changes every repository
without an explicit setting; set it when creating the deployment.
`SetRepoVisibility` runs the supplied Admission hook and records an Outcome like
other mutating RPCs; a hook must handle that procedure.

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
default; the Paid Workers launch validates its activation (WP-4.18). The getter/setter and canonical
signed statement contract are SPEC-SERVER §6.2.1.

Once a namespace has persisted authority fencing, disabling the executor setting
refuses new writes for that namespace, including generation zero. Initial
activation may return `unavailable` with `Retry-After: 1` until its bounded lease
barrier completes. Repeating the signed target resumes durable progress; it does
not create a namespace or charge first-write creation. Restore must preserve the
authority mode and generation, then declare real lease-table recovery.

## Launch purge and audit configuration

`ADMIN_KEYS` contains the SPEC-SERVER §16.3 public-key list as a Worker secret.
It defaults off. Admin plus complete takedown configuration exposes `Takedown`,
`GetTakedown`, `ListTakedowns`, streamed `ReadPreserved`, audited `SetLegalHold`,
`PurgeCache` and `ReadAuditLog` on the operator mount. All seven routes remain
unavailable without that configuration.
Every admin response uses `Cache-Control: no-store`; preserved bytes are
freshly verified and never buffered into replay. Admin requests use a separate signed envelope and cannot authenticate
client writes. Operator keys must differ from ticket, token, hook and authority
keys. Persisted sharding/addressing checks run before operator dispatch.

For a global purger, build with `signed-http-hooks`, explicitly include
`cache-purge` in `HOOK_ROLES`, set an
HTTPS `HOOK_URL` and the `MKIT_HOOK_KEY` signing secret, and use `WORKERS_PLAN=paid`.
A purge-only role list does not enable Authorize, Admit or Outcome. Invalid or
unsigned purge configuration refuses startup. The signed sink must acknowledge
with an empty JSON object; retries keep the body/id and use fresh nonces. The
sink must map the audience to the deployment and purge the actual custom keys;
selector strings alone do not attach Cache-Tag headers to existing cache entries.

Automatic callers accept repository-scoped intents in the triggering state apply.
The colo-local Cache API deletes the intent's exact URL paths.
Namespace suspension consumers must use those repository intents; this foundation
does not expose namespace manual acceptance. Gated entrypoints keep Workers
Caching disabled. Root audit append and its relay watermark share the target SQL
apply. All Paid alarm heads share one external-operation allowance and one
physical tick budget.

## Embedding (supported, 0.x)

The `pack-ruzstd` feature (enabled by the vcs-worker `launch` feature) relies on
a bounded-decode patch to ruzstd 0.9 that a git-dependency embedder must repeat
in its own workspace, because Cargo does not inherit dependency patches:

```toml
[patch.crates-io]
ruzstd = { git = "https://github.com/officialunofficial/mkit", tag = "v0.5.0" }
```

Upstream tracking: [KillingSpark/zstd-rs #124, "Refuse blocks that decode past
Block_Maximum_Size"](https://github.com/KillingSpark/zstd-rs/pull/124) is open. Keep the patch until a released
version includes the bound; the tracked PR does not establish released coverage.

This crate stays `publish = false`. Consume it as a git dependency pinned to the
release tag; breaking 0.x changes are called out in CHANGELOG.

| Public API | Use |
|---|---|
| `adapter::serve_with` / `fetch_with` | Constructed request or environment-parsed fetch with a custom `HookSet` |
| `adapter::ns_object_with` | Environment-configured DO with custom `OutcomeSink` |
| `embedding::NsObjectBuilder` | Combine explicit config, outcome factory and custom purge/local invalidation |
| `embedding::HookCapabilities`, `WorkerConfig::from_env_with_hooks` | Declare the supplied Admission, Authorizer role and OutcomeSink without a remote binding |
| `embedding::PurgeHooks`, `WorkerConfig::from_env_with_purge` | Supply an actual Paid in-process `PurgeSink` as the signed HTTPS alternative; complete preservation/admin still required |
| `durable_objects!(config_factory, sink_factory)` | Generate all five standard DO exports from the same config/sink factories |
| `adapter::WorkerConfig` | Programmatic `ref_policy`, `takedown_denial`, HTTP mount and `admin_on_public_path`; call `validate` after changes |
| `http_mount::WorkerHttpMountConfig::with_context` | Keep HTTP read settlement in the host fetch lifetime |
| `adapter::serve_admin_with` | Host-routed canonical admin request authenticated with `ADMIN_KEYS` |
| `ns_object::NsObject`, `classes::ShardClass` | Low-level DO request and alarm delegation |
| `mkit_server::pipeline::{HookSet, Authorizer, Admission, OutcomeSink}` | Custom admission/authorization and durable outcome contracts |

Use the same config factory on fetch and DO construction. For in-process hooks,
pass `HookCapabilities` to `from_env_with_hooks` (or `from_vars_with_hooks`) and
build the matching `HookSet` in `serve_with` and matching sink in `NsObjectBuilder`.
`fetch_with(req, env, capabilities, make_hooks)` accepts these capabilities before
parsing opt-ins. Use `serve_with` and a mount with `with_context` for paid HTTP
settlement. The supplied role metadata controls policy; actual pipeline construction
still refuses a default Admission for paid reads or an open Authority. Remote
inspection, scanner retrieval and cache-purge signing remain enforced for roles
that use those channels.

The shared config factory’s signed audience
is `WorkerConfig::audience`, the exact public origin, regardless of the URL of a
constructed request. Dispatch shares the caller isolate's CPU, memory and
subrequest limits. The [embedded example](../../../apps/embedded-worker/README.md)
transfers streamed `UploadPart` through an in-process request and isolated
service-binding hooks; its local conformance remains a distinct runtime gate.

Set `admin_on_public_path=false` and route canonical admin requests through
`serve_admin_with` to keep the public mount off. Operator authentication and
canonical signed paths are unchanged. `RefPolicy`/`RefRule` support signer and
fast-forward rules; no separate general no-delete knob exists. Preservation configuration validates at startup; the configured restricted
admin catalog uses the merged WP-5.6a-3 runtime. Global denial must stay enabled.

Reserved prefixes are `/mkit.transport.v1.TransportService/`,
`/mkit.server.admin.v1.AdminService/`, any mounted HTTP path containing `/-/`,
`/.well-known/mkit-*`, `/_mkit/`, and `/__mkit_test/` in test builds. A host may
use another prefix such as `/_uno/`; namespaces and repos cannot start with `_`.
The [feature and measured-size table](../../../apps/vcs-worker/README.md#embedding-api-supported-0x)
records exact release commands and keeps unexecuted measurements explicit.

## In-process canonical object prefetch (WP-4.16c)

With `http-objects` and explicit indexed/HTTP configuration, construct the
request's pipeline using `adapter::embedding_pipeline(env, cfg, hooks,
&request_budget)`, then call `pipeline.object_reader(repo, ReaderView::Public)`.
Share the request's existing 9,000-call physical
`SliceBudget` with the constructor. The native equivalent is
`Pipeline::object_reader`; native and Worker adapters re-export `ReaderView`
and `ObjectReader`. This API uses the shared core and adds no HTTP mount or wire.

`reader.issue_urls(&targets, ttl_s)` returns up to 16 optional signed tokens
(`IssuedUrl`), requiring `URL_TOKEN_KEYS`; denied or unreachable targets are absent.
It shares RPC minting and checks the published view even for Owner readers.
A TTL of 0 selects the configured default; larger requests are clamped.

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
decode or denial-context budgets fail closed: an Owner reader gets
`ResourceExhausted` (`object reader limit exceeded`), while a Public reader sees
an ID whose reachability cannot be proved within the caps as absent. Storage
failures remain `unavailable`. Canonical response bytes, including duplicate
IDs, also fit `http_decode_budget`.

`read_canonical` returns serialized Blob, Tree, Commit, Remix, Tag and
**ChunkedBlob manifest** bytes, never pack-only Delta encodings.
`object_metadata` returns verified object kind, canonical serialization length and
logical file length (Blob payload or ChunkedBlob total_size; absent for other kinds).
`read_canonical_with_limit` applies a caller byte cap to two separate counters:
cumulative ancestor/base decoding and ordered output, including duplicates.
It returns ResourceExhausted on exhaustion.
Use `object_metadata` to select `canonical_len` or `logical_len` explicitly.
Reservations and outcome types are imported from `mkit_server::store`;
storage codecs and key layouts live under its doc-hidden `adapter_spi`.
Worker configuration uses `WorkerConfig::from_vars` or `from_env`; nested
settings use constructors or `Default` followed by field assignment.

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
