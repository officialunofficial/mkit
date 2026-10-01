# mkit-server-worker

Cloudflare Workers adapter for the runtime-agnostic mkit server: streaming
R2 blobs, Durable Object metadata, Connect dispatch and remote hooks over
service bindings.

HTTP object serving is explicitly opt-in. The default build omits
`http-objects` and `WorkerConfig::http_mount` defaults to `None`. The Paid Uno
profile (`LAUNCH_PROFILE=uno`, `INDEXED_MODE=true`, Multi/D34 and tickets)
activates the merged verification/extraction driver. `HTTP_OBJECTS=true` plus
complete dedicated `URL_TOKEN_KEYS` selects the HTTP mount when compiled with
`http-objects`. A programmatic `WorkerHttpMountConfig` also configures serving
and read-CORS options. See the [reference configuration](../../../apps/vcs-worker/README.md#paid-uno-launch-profile-wp-418--r-194).
Native serves proofs; release Worker `?proof=1` remains unsupported and its
ServerInfo does not advertise proof capability.

Ref-path file responses use the extension-derived Content-Type allowlist and
Content-Disposition filename from SPEC-HTTP-OBJECTS §5.1. Object-id file responses
remain `application/octet-stream`. Every byte-serving response retains nosniff
and the sandbox CSP.

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
It defaults off. `ReadAuditLog` and configured `PurgeCache` use the operator
mount; takedown/catalog/retention operations await complete verified preservation
(WP-5.6a-3). Preservation core is merged. Admin requests use a separate signed envelope and cannot authenticate
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
All Paid alarm heads share one external-operation allowance and one physical
tick budget. Published snapshots require their generation-aware serving fence;
configured inspection keeps snapshot optimization disabled.

## Embedding (supported, 0.x)

This crate stays `publish = false`. Consume it as a git dependency pinned to the
release tag; breaking 0.x changes are called out in CHANGELOG.

| Public API | Use |
|---|---|
| `adapter::serve_with` / `fetch_with` | Constructed request or environment-parsed fetch with a custom `HookSet` |
| `adapter::ns_object_with` | Environment-configured DO with custom `OutcomeSink` |
| `embedding::NsObjectBuilder` | Combine explicit config, published snapshots, outcome factory and custom purge/local invalidation |
| `embedding::PurgeHooks`, `WorkerConfig::from_env_with_purge` | Supply an actual Paid in-process `PurgeSink` as the signed HTTPS alternative; complete preservation/admin still required |
| `durable_objects!(config_factory, sink_factory)` | Generate all five standard DO exports from the same config/sink factories |
| `adapter::WorkerConfig` | Programmatic `ref_policy`, `takedown_denial`, HTTP mount and `admin_on_public_path`; call `validate` after changes |
| `http_mount::WorkerHttpMountConfig::with_context` | Keep HTTP read settlement in the host fetch lifetime |
| `adapter::serve_admin_with` | Host-routed canonical admin request authenticated with `ADMIN_KEYS` |
| `ns_object::NsObject`, `classes::ShardClass` | Low-level DO request and alarm delegation |
| `mkit_server::pipeline::{HookSet, Authorizer, Admission, OutcomeSink}` | Custom admission/authorization and durable outcome contracts |

Use the same config factory on fetch and DO construction. Its signed audience
is `WorkerConfig::audience`, the exact public origin, regardless of the URL of a
constructed request. Dispatch shares the caller isolate's CPU, memory and
subrequest limits. The [embedded example](../../../apps/embedded-worker/README.md)
transfers streamed `UploadPart` through an in-process request and isolated
service-binding hooks; its local conformance remains a distinct runtime gate.

Set `admin_on_public_path=false` and route canonical admin requests through
`serve_admin_with` to keep the public mount off. Operator authentication and
canonical signed paths are unchanged. `RefPolicy`/`RefRule` support signer and
fast-forward rules; no separate general no-delete knob exists. Takedown denial
still refuses startup until the preservation prerequisite is wired.

Reserved prefixes are `/mkit.transport.v1.TransportService/`,
`/mkit.server.admin.v1.AdminService/`, any mounted HTTP path containing `/-/`,
`/.well-known/mkit-*`, `/_mkit/`, and `/__mkit_test/` in test builds. A host may
use another prefix such as `/_uno/`; namespaces and repos cannot start with `_`.
The [feature and measured-size table](../../../apps/vcs-worker/README.md#embedding-api-supported-0x)
records exact release commands and keeps unexecuted measurements explicit.
