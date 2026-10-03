<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# mkit vcs worker (reference `mkit.transport.v1` server)

The **reference deployment** of `mkit.transport.v1.TransportService`
(defined in
[`proto/mkit/transport/v1/transport.proto`](../../proto/mkit/transport/v1/transport.proto),
normatively specified in
[`docs/specs/SPEC-TRANSPORT-CONNECT.md`](../../docs/specs/SPEC-TRANSPORT-CONNECT.md))
on Cloudflare Workers: what an `mkit+https://` remote talks to.

One Worker deployment serves **one mkit repository** by default;
`ADDRESSING=multi` (below) serves every repository its namespace policy
admits. Since WP-M0-17 this
crate is a **thin deployment of
[`mkit-server-worker`](../../rust/crates/mkit-server-worker)**: it holds no
protocol logic and no generated code, only the `#[event(fetch)]` handler and
the `RefStore` Durable Object class, both of which call the adapter. The
request pipeline (auth, replay, quota, ref CAS, uploads, downloads) is
[`mkit-server`](../../rust/crates/mkit-server)'s, the same code the native
server runs.

For deployment and incident procedures, use the [Workers operator guide](../../docs/operations/workers.md).

## Architecture

```
  worker::Request ─┐
                   │  #[event(fetch)] (src/worker_impl.rs)
                   ▼  mkit_server_worker::adapter::fetch
       CORS preflight · Content-Length cap · config from vars
                   │
       http::Request<LimitedBody<worker::Body>>   (streamed, never buffered;
                   │                               deadline headers dropped)
                   ▼  mkit_server::connect::service(pipeline)
      AuthInterceptor (auth v2) → TransportService / grpc.health.v1.Health
                   │
                   ▼  mkit_server::pipeline::Pipeline
           ├── blobs: R2BlobStore ──▶ R2 bucket (binding STORAGE, keys packs/<hex>)
           │          streaming put, final byte withheld until BLAKE3 verifies
           └── meta:  DoNamespaceStore ──▶ RefStore Durable Object (binding REFSTORE,
                      one JSON call per       instance "root": the deployment's one
                      store operation)        namespace partition, SqlKvStore over
                   │                          Durable Object SQLite; refs, replay
                   ▼                          records and quota in one kv table)
       http::Response<ConnectRpcBody>
                   │  streamed frame by frame (a DownloadPack chunk ≤ 800 KiB)
                   ▼
              worker::Response
```

The Durable Object is a pure key-value store: it applies batches with their
preconditions (including `NotAfter` deadlines, on its own clock) and runs no
pipeline logic. CAS, the two-ref `AdvanceRefs` transaction, the replay
ledger and the quota are each one atomic batch planned by the pipeline.

## Backup and disaster recovery

For an incident within 30 days, use Cloudflare Durable Object point-in-time
restore (PITR) first. Each writable Durable Object also exports a portable
logical snapshot to the `BACKUPS` R2 binding after its first committed put and
then daily by default. The snapshot covers one partition and is written under
`backups/v1/<prefix>/<kind>/<partition-hash>/<time>-<digest>.kvlog`. The
`BACKUP_PREFIX` var can separate deployments sharing a bucket; its default is
this Worker's name, `mkit-vcs-worker`. Staging must set its own `BACKUP_PREFIX`.
The first export runs one interval after the first committed put, not at the
time of that put. `BACKUP_INTERVAL_MS=0` disables the timer; `BACKUP_MAX_BYTES`
defaults to 16 MiB and cannot exceed 24 MiB. A partition above that cap is
logged and remains covered by PITR until segmented export is implemented.
Unchanged partitions skip uploads until `BACKUP_FORCE_REUPLOAD_MS` (28 days
by default); keep that interval shorter than the bucket's lifecycle retention.

Before deploying, create a separate `mkit-vcs-backups` bucket and bind it as
`BACKUPS` (as in `wrangler.jsonc`). Install an R2 lifecycle rule for the
`backups/` prefix with a **35-day default retention**. Check the rule's prefix:
it must never cover `packs/` or any other content-addressed objects. This
bucket and lifecycle rule are manual deployment steps (WP-1.19 checklist).
The bucket MUST be private: disable r2.dev and custom domains, and use only
scoped tokens. Its jurisdiction must match `NAMESPACE_JURISDICTION` for data
residency. Snapshots contain private ref names, signer keys, tickets and replay
rows. Confirm the bucket's access policy before the first deployment.
Keep `WORKERS_PLAN=free` on a Free account.

Indexed serving selects the Paid Workers launch profile described below. Free
Workers cannot enable indexed mode. WP-4.18 has merged, validates the profile and activates the extraction driver;
test-faults indexed conformance is separate evidence and does not establish
the completed launch matrix.
The alarm budget is shared across handlers; see the
[Workers operator guide](../../docs/operations/workers.md).

For a backend move or recovery beyond PITR, the `.kvlog` partition snapshots
in R2 are the source of truth. The standalone `mkit-server` binary that
shipped `export`, `restore` and `backup` commands for a native SQLite
deployment was removed, so there is no supported restore tool today. A
snapshot older than auth v2's maximum 300,000 ms envelope validity cannot
revive a replayable write envelope, and owners must re-issue grants after
any restore.

Production Worker restore and PITR administration are deferred to WP-5.11b.
Logical in-place/Merge restore, segmented export above 16 MiB, index
reconciliation after restore, a post-restore replay fence and a GC hold at
least as long as backup retention are also deferred. The `test-faults` import
route exists only for local conformance and must not be enabled in deployment.

## Outcome delivery, CORS and logs

Kind 8 (terminal outcome delivery) calls its sink at most once per row and
stops a fire at the first failure or 5 s timeout. It is budgeted by
`WORKERS_PLAN` (unset means Free): at most 8 sink calls per alarm on Free
(relay 32 + backup 1 + outcome 8 + quota rollup at most 8 of the 50
subrequests) and 64 on Paid.
By default this deployment uses the local `NoOutcomes` sink; see "Remote hooks"
below to send outcomes to a hook Worker.

Browsers may send `Authorization`, `Payment-Authorization`,
`PAYMENT-SIGNATURE` and `Accept-Payment`, and every response exposes
`WWW-Authenticate`, `PAYMENT-REQUIRED`, `Payment-Receipt` and
`PAYMENT-RESPONSE`. A response with several `WWW-Authenticate` challenges
keeps all of them.

The Worker never logs request headers, and a test checks that credential
values do not reach its tracing. **Check the platform's invocation-log
capture (Workers Logs, Logpush, tail) at staging before accepting payment
credentials:** it is outside this code (D15).

## Remote hooks (`ADMISSION_HOOK`)

Authorization, admission and outcome delivery can run in a separate hook
Worker (SPEC-SERVER §§6-8), reached over a **service binding**, which is not
reachable from the public internet, so the requests are unsigned (SPEC-SERVER
§7.3). Configure:

- the `ADMISSION_HOOK` service binding (`wrangler.jsonc` has a commented
  `services` example);
- `HOOK_ROLES`: a comma list of `authorize`, `admit` and `outcome`. It has no
  default (a hook Worker may implement any subset; the reference mppx Worker
  answers only Admit and Outcome), and the binding and the var must come
  together: either one alone makes every RPC answer `unavailable` naming it;
- optionally `HOOK_TIMEOUT_MS` (default 5000, at most 30000; deliveries are
  bounded by 5 s regardless) and `AUTHORIZER_ROLE` (`check`, the default, or
  `authority`, with the `authorize` role).

**The hook Worker must have no public route**: disable its `workers.dev`
route and its preview URLs and give it no custom domain or route. The adapter
cannot check this, and an unsigned hook that is reachable from the internet
would accept forged requests. A remote admission replaces the built-in
per-signer abuse quota: the hook owns abuse control, and admit needs
`TICKET_KEYS`.

Authorize and Admit fail closed (retryable `unavailable`, nothing written);
Outcome delivery is retried by kind 8 until the hook answers 2xx. **Subrequest
budget:** each binding call is one subrequest (Cloudflare counts every request to a
Worker over a service binding toward the subrequest limit, and a request may make
at most 32 Worker invocations). On the fetch path Authorize adds
one per RPC (reads included) and Admit one more per admitted write, so at most
2 of a request's 50 (Free); alarms are bounded by the kind-8 budget above (at
most 8 Outcome calls per alarm on Free, within the 32 + 1 + 8 + 8 split).
Every hook call carries no `X-Mkit-Hook-*` headers. A custom business layer in
a Rust Worker uses `adapter::fetch_with` and `adapter::ns_object_with` with its
own `HookSet` and outcome sink instead of the vars.

A Cloudflare Queue outcome sink remains deferred (WP-3.9b). Signed HTTP hooks
are available with the opt-in below. Test it
locally with `scripts/vcs-worker-hooks.sh` (a stub hook Worker under
`tests/hook-stub` and `wrangler.hooks.jsonc`).

## Auth v2 and namespace admission

All writes (`UpdateRef`, `AdvanceRefs`, `BeginUpload`, `UploadPack`) require the
destination-bound [auth v2 contract](../../docs/specs/SPEC-TRANSPORT-CONNECT.md#auth-v2-contract),
verified by `mkit-server`'s auth stage. The signature binds audience,
repository, procedure, exact body or pack content, creation/expiry
timestamps, and a mandatory random nonce. Reads are unsigned. Configure
`AUTH_AUDIENCE` to the exact public origin (override it for local
development) and `AUTH_REPOSITORY`, default `default`; with either missing or
malformed, every RPC answers `unavailable` naming it.

For upload tickets, provision the `TICKET_KEYS` secret with `wrangler secret
put TICKET_KEYS` (WP-1.19). Its content has one `<key-id> <64 hex>` key per
line; the first signs and every listed key verifies. Blank lines and `#`
comments are allowed. `wrangler.dev.jsonc` carries a fake development key.
Without keys, `BeginUpload` answers `unimplemented`.

### Sharding (`SHARDING`)

`SHARDING` is `d34` by default (unset means `d34`; `wrangler.jsonc` sets it
explicitly): metadata is sharded per (repository, ref) and `ListRefs` reads the
eventual ref-name index. **Breaking change (WP-1.28c):** a deployment that
holds single-sharded data answers 503 to every RPC until `SHARDING="single"` is
pinned; there is no migration (R-123). Under Single addressing, quota becomes
per (signer, branch) by default.

### Multi-repository addressing (`ADDRESSING=multi`)

`ADDRESSING=multi` serves every repository the namespace policy admits:
each request's `X-Repository <ns>/<name>` header selects the repository and
`AUTH_REPOSITORY` is unused (the shipped `default` value is ignored). Multi
requires `TICKET_KEYS` — a signed write names its repository, and uploads
still need tickets — and writes are owner-only (STC §7.5): a signature may
write only inside its own key's `ed25519-` namespace.

Write grants (SPEC-WRITE-GRANTS) are off unless `GRANT_SCHEMES` is set, and
need `ADDRESSING=multi`; the grant audience is `AUTH_AUDIENCE`. `wrangler.jsonc`
ships no `GRANT_SCHEMES`.

- `GRANT_SCHEMES`: the accepted owner schemes, comma-separated
  (`ed25519`, `secp256k1-eip191`, `webauthn-p256`). Present but blank is an
  error, never "off".
- `WEBAUTHN_RPS`: `WebAuthn` relying parties, `id=origin[,origin...]` entries
  separated by `;` or newlines (split on the first `=`). `webauthn-p256`
  requires one. Blank entries and duplicate ids are refused.
- `UNSAFE_LOOPBACK_GRANTS`: honoured only in `__test-faults` builds (local
  conformance). In a release build, setting it makes every RPC answer
  `unavailable`; a loopback `AUTH_AUDIENCE` or relying party is never accepted
  in production (SPEC-WRITE-GRANTS §3.2).

Any invalid value, `webauthn-p256` without a relying party, a relying party
without `GRANT_SCHEMES`, or grants without multi addressing is a config error:
every RPC answers `unavailable` naming the var.

Like `SHARDING`, `ADDRESSING` is fixed for the deployment lifetime: the first
request records the mode in a root marker (`am 00`), and redeploying with the
other addressing over existing data is refused (`deployment addressing
mismatch`). Unmarked data is a `single` deployment's.

The guard probes `v` only in the root partition, so Single+D34 data written
before multi-repository serving landed is not detected; D34 is unreleased with
no deployments, so this is acceptable.

- `NAMESPACE_POLICY=allowlist` (the default) admits only the namespaces in
  `NAMESPACE_ALLOWLIST`: canonical namespaces (`ed25519-<64 hex>` or
  `0x<40 hex>`) separated by newlines or commas, `#` comments and blank
  entries ignored. A missing, malformed or empty allowlist refuses startup
  (every RPC answers `unavailable` naming the var).
- `NAMESPACE_POLICY=any` admits every self-certifying namespace, requires
  `NAMESPACE_ALLOWLIST` to be absent and requires `UNSAFE_OPEN_NAMESPACES=true`: without non-default admission (M3) any
  fresh key resets its namespace's quota, so the open policy is an explicit
  unsafe opt-in. The embedding host demo selects it deliberately. Under
  `any`, takedown discovery is incomplete; configured global denial and
  preservation still apply, and completion must report that limitation.

The four vars are documented in `wrangler.jsonc`; for a local Multi
deployment under `wrangler dev`, pass them as `--var` (the conformance
script's `--multi` phase does exactly that).

With default admission, the replay record, per-signer write quota (300 writes
and 128 MiB per hour) and effect commit in one batch. A remote Admit replaces
that quota: the server makes no internal admission charges, and the remote
hook owns abuse control. A retry returns its recorded result, including after
a newer ref update; a nonce reused for a different operation is
`invalid_argument`. An upload reserves its declared size once and publishes
the pack only after it verifies. Multi addressing enforces namespace admission,
owner-only writes and any configured grants or authority fence. Single
addressing retains its auth-v2 write policy.

### Known limitations

- **Pack size**: `MAX_PACK_BYTES` defaults to 1 GiB (1,073,741,824 bytes)
  and accepts 1..=4.995 GiB (5,363,340,410 bytes). Larger packs use multipart
  tickets; non-final parts are at least 8 MiB. The independent request-body
  cap remains 65 MiB, enforced with or without `Content-Length`; exceeding
  it answers HTTP 400 `resource_exhausted`. `UploadPack` and `DownloadPack`
  stream, with download chunks of at most 800 KiB.
- **Unary replies are one frame**: each paged `ListRefs` reply is held whole,
  about 45 bytes per ref, bounded by the configured page size (128 refs for
  the Paid Workers launch) and the 2 MiB reply cap. The
  conformance script's 1 MiB body-buffer bound covers the streaming RPCs
  only.
- **Client deadlines are not enforced**: `connect-timeout-ms` and
  `grpc-timeout` are dropped before dispatch, because connectrpc would read
  `Instant::now()`, which panics on wasm32.
- **Metadata routing**: D34 shards namespace, ref, repository-index and
  content-index partitions; `SHARDING=single` uses the root RefStore.
- **Storage cap**: each Durable Object's store stops accepting writes near
  the plan's limit, set by the `WORKERS_PLAN` var: `free` (1 GB, the
  default) or `paid` (10 GB). Set `paid` only on a Workers Paid account.
- **Not deployed**: it runs against `wrangler dev` only; `wrangler dev`
  cannot prove Durable Object placement, limits or point-in-time recovery.
- **No migration from the pre-port schema.** The pre-WP-M0-17 Worker kept
  `refs`, `write_quota` and `authenticated_operations` tables; the port
  starts from the `kv` table and ignores them (the Worker was never
  deployed; pre-production policy).

## Endpoints

ConnectRPC, `POST /mkit.transport.v1.TransportService/<Method>`, plus
`POST /grpc.health.v1.Health/Check` (unauthenticated; `SERVING` when R2 and
the Durable Object both answer their probe). Behavior is
SPEC-TRANSPORT-CONNECT's; the black-box wire suite checks it.

## Build, run and test

```sh
# the Worker bundle (the wrangler [build] command)
worker-build --release

# local dev server (workerd + R2/DO emulation)
wrangler dev -c wrangler.dev.jsonc --var AUTH_AUDIENCE:http://127.0.0.1:8787 \
  --var AUTH_REPOSITORY:default

# the M0 wire-conformance check, from the repo root: builds the Worker,
# starts wrangler dev on a fresh state directory, runs mkit-server-conformance
scripts/vcs-worker-conformance.sh
scripts/vcs-worker-conformance.sh --test-faults   # + clock skew, quota, growth
scripts/vcs-worker-conformance.sh --multi         # + the Multi-addressing wire cases
```

The logic's tests live with it: `cargo nextest run -p mkit-server -p
mkit-server-worker -p mkit-server-conformance --all-features` in `rust/`.
`cargo test --lib` here has nothing to test.

## Test hooks (`__test-faults`)

A `worker-build --dev --features __test-faults` build adds, and a release
build has none of:

- `x-mkit-test-fault: after-reserve | after-put | final-chunk`: an upload
  fails once per operation after its reservation, after the pack is
  published, or at the pack's withheld final byte; the retry passes.
- a batch writing a key that contains `__test_fail_once-` (e.g. a ref
  `refs/heads/__test_fail_once-<id>`) fails once inside the Durable Object,
  after its writes, proving they roll back.
- `x-mkit-test-clock-skew-ms`, `GET /__mkit_test/stats` (`{bytes, keys}` of
  the partition) and the `TEST_QUOTA_OPS`/`TEST_QUOTA_BYTES`/
  `TEST_QUOTA_WINDOW_MS` vars, for the wire suite.
- `GET /__mkit_test/snapshot`, `POST /__mkit_test/restore` and
  `GET /__mkit_test/restored-snapshot` export the default single-shard DO,
  import into a separate fresh test DO, and verify a wrangler-dev round trip.
  These routes do not compile into a production build.

Manual harnesses (need `apps/web/vendor/mkit-wasm/pkg`, see apps/web):
`node tests/auth_v2_golden.mjs`, and against a running test-faults Worker
with `AUTH_AUDIENCE=http://localhost:8791`, `node tests/auth_v2.mjs
http://localhost:8791 --fault`: concurrent replay, nonce conflict, atomic
two-ref rollback and retry, stream content binding, and interrupted
publication. `tests/auth_storage_fixture.py` seeds a corrupt ref, a stale
quota window and an expired replay record into a stopped local Durable
Object database for `auth_v2.mjs --corrupt-ref`.

## Deploy (not yet live)

The historical [staging template](staging/README.md) is inert. The single Workers
launch uses the [Workers operator guide](../../docs/operations/workers.md).
User-owned staging and launch acceptance remain unrun.

1. **Provision storage** (one-time): `wrangler r2 bucket create
   mkit-vcs-objects`. The RefStore Durable Object and its `v1` SQLite
   migration are created on first deploy.
2. Set `AUTH_AUDIENCE` to the published origin, and `WORKERS_PLAN` for the
   account.
3. **Deploy:** `wrangler deploy`, or a Cloudflare Workers Builds project at
   `apps/vcs-worker`.
4. **Pin a route** in `wrangler.jsonc` once a hostname is chosen.

[workers-rs]: https://github.com/cloudflare/workers-rs

## Signed HTTP hooks (WP-3.9c)

Build with `signed-http-hooks` to opt into the signed HTTPS channel. Set
`HOOK_URL` to an HTTPS origin with an optional base path, `HOOK_ROLES` to
`authorize,admit,outcome` (or a subset), and the `MKIT_HOOK_KEY` secret to
`<key-id> <64 hex seed>`, matching the native grammar. `HOOK_TIMEOUT_MS`
defaults to 5000 (1–30000); `HOOK_SIGNATURE_VALIDITY_MS` defaults to 60000
(1–300000). `AUTHORIZER_ROLE=authority` requires the authorize role.

HTTP and `ADMISSION_HOOK` are mutually exclusive. Userinfo, query strings
and fragments are refused. Calls sign the exact Connect JSON bytes for the
endpoint origin, never follow redirects or retry internally, and abort on
timeout/cancellation. Decisions fail closed; durable outcomes retain their
existing retry/acknowledgement and Free 1×8 alarm budget. The secret must
differ from every accepted ticket secret and configured role key. Custom
`fetch_with`/`serve_with` entry points retain their injected hooks.

Optional namespace fencing uses `AUTHORITY_FENCE=true` and `AUTHORITY_KEYS`
(secret), one `<key-id> <64 lowercase hex public key> <namespace[,namespace...]>`
line per dedicated deployment-authority key. It requires Multi addressing and
`AUTHORIZER_ROLE=authority`; every write allowance must carry the namespace's
`authority_generation`. SPEC-SERVER §6.2.1 defines signed setter statements and
completion. Default is off; launch activation is WP-4.18.

Once a namespace has persisted authority fencing, disabling the executor setting
refuses new writes for that namespace, including generation zero. Initial
activation may return `unavailable` with `Retry-After: 1` until its bounded lease
barrier completes. Repeating the signed target resumes durable progress; it does
not create a namespace or charge first-write creation. Restore must preserve the
authority mode and generation, then declare real lease-table recovery.

## Paid Workers launch profile (WP-4.18 / R-194)

Set `LAUNCH_PROFILE=paid-workers`, `WORKERS_PLAN=paid`, `INDEXED_MODE=true`,
`ADDRESSING=multi`, `SHARDING=d34` and `TICKET_KEYS`. The profile fixes
`RETENTION=permanent`, `STORAGE_LEASES=false` and `GC_ENABLED=false`; other
values are refused. Ticketed uploads use threshold zero. Namespace policy is
`allowlist` with a nonempty canonical `NAMESPACE_ALLOWLIST`, or `any` with
`UNSAFE_OPEN_NAMESPACES=true`. An unset profile retains the default deployment.

Features are optional within this profile, and each validates its complete
configuration before activation:

| Opt-in | Required configuration |
|---|---|
| HTTP objects / URL tokens | `HTTP_OBJECTS=true`, an `http-objects` build and dedicated `URL_TOKEN_KEYS`; retained signing keys follow the existing token grammar |
| Signed hooks | `signed-http-hooks` build, `HOOK_URL` HTTPS, `HOOK_ROLES` and dedicated `MKIT_HOOK_KEY`; optional timeout/validity use the existing bounds. Alternatively use the isolated nonpublic `ADMISSION_HOOK` binding; both channels together are refused |
| Inspection | Zero inspectors is valid. With inspection, up to four sync `fail_closed` inspectors; `HOOK_ROLES=inspect`, `INSPECT_MODE=sync`, `INSPECT_ON_UNAVAILABLE=fail_closed`, `SCANNER_RETRIEVAL=true`, `SCANNER_KEYS` and dedicated `SCANNER_RETRIEVAL_KEYS`. Async, publish-on-unavailable and clear deadlines are refused |
| Admin | Dedicated `ADMIN_KEYS` with signed requests, permitted roles, replay and gapless audit |
| Paid HTTP reads | `HTTP_ADMIT_READS=true` additionally requires `HTTP_OBJECTS=true` and the `admit` hook role; response completion retains the fetch request waitUntil lifetime plus durable reconcile |
| Takedown | `TAKEDOWN_ENABLED=true`, admin keys, separate preservation bucket, explicit retention, dedicated preservation signer and published key list under §14.7, plus configured cache-purge delivery (signed HTTPS or an embedder-supplied `PurgeSink`). Partial configuration is refused |

Extraction (WP-4.10b-2 / #1244) and scanner retrieval (R-193 / #1243) are
merged; this activation wires their release paths. Configured preservation
core and the WP-5.6a-3 restricted admin catalog are wired. The requested embedding host
embedded matrix passes locally; broader variants and actual
staging remain unrun. Local evidence does not certify deployed resources.
See the [Workers operator guide](../../docs/operations/workers.md) for deployed verification requirements.

Worker object-serving HTTP responses carry `X-Content-Type-Options: nosniff`
and `Content-Security-Policy: sandbox; default-src 'none'`. Object-id file
responses use `application/octet-stream`; the launch adopts #1246 and selects
ref-path file media types from the fixed extension allowlist in
[SPEC-HTTP-OBJECTS §5](../../docs/specs/SPEC-HTTP-OBJECTS.md). HTML and SVG remain
binary attachments. Successful ref-path file responses include
`Content-Disposition` with a sanitized ASCII `filename` and an octet-preserving,
percent-encoded `filename*`; HEAD and 206 ranges use the same policy. JSON is
an attachment; the listed image, text, and PDF extensions are inline. Other
extensions use binary attachments. The server does not sniff content. Non-file
objects and native proof routes retain their specified media types. The rule
does not add file headers to 304 or error responses.
HTTP `?proof=1`
remains unsupported on the Worker, which advertises no proof capability;
the native reference server advertises and serves proofs.

With admin plus complete takedown configuration, the Worker admin subset is `Takedown`,
`GetTakedown`, `ListTakedowns`, `ReadPreserved`, `SetLegalHold`, `PurgeCache`
and `ReadAuditLog`. All seven endpoints remain unavailable without admin plus
complete takedown configuration. `ReadPreserved` streams freshly verified bounded pieces
with `Cache-Control: no-store`; retries retain byte-free descriptors and recheck
authority, retention and ownership. Hold review operations and `Reinstate` remain unexposed.
The launch creates no inspection holds or publication Events; async inspection,
hold review, Events and Worker proofs are not implemented.

R-193 scanner retrieval mounts `POST /_mkit/scanner/pack`. `SCANNER_KEYS`
contains 1–32 distinct non-weak Ed25519 public keys, one per line.
`SCANNER_RETRIEVAL_KEYS` contains one `active <id> <64 hex>` line followed
by up to 15 `retained <id> <64 hex> <retired_at_ms>` lines. Its capability
and scanner auth-v2 signature authorize only assigned staged added-pack raw
bytes in ranges of at most 1 MiB. Missing, foreign, expired, replayed,
consumed-ticket and globally blocked requests uniformly answer 404.
The scanner decodes packs and manifests itself. External delta bases need
an independently authorized resolver or local scanner cache; retrieval never
grants access to earlier packs or public object URLs. Proof-prefetch concurrency
is at most six responses, with 512 KiB pages (up to 3 MiB raw data, within the
4 MiB bound); nested checks remain sequential under the shared 8,500-op budget.

## Embedding API (supported, 0.x)

The supported wasm embedding entrypoints below share the production adapter.
Merged WP-4.16c also provides `adapter::embedding_pipeline` and `Pipeline::object_reader` for bounded in-process canonical prefetch.
Breaking 0.x changes are called out in CHANGELOG. Runtime acceptance is
recorded separately in the launch evidence matrix.
The crate stays `publish = false`; consume it as a git dependency pinned to
an approved immutable commit until a release tag exists.

| Current API | Purpose and boundary |
|---|---|
| `adapter::serve_with(req, env, &cfg, make_hooks)` | Dispatch a constructed Worker request with an explicit `WorkerConfig` and custom hooks |
| `adapter::fetch_with(req, env, capabilities, make_hooks)` | Parse environment configuration before dispatching with custom hooks |
| `adapter::fetch_with_context(req, env, context)` | Retain the request context for configured paid HTTP response settlement; requires `http-objects` |
| `WorkerConfig` | Audience, addressing, sharding, keys, launch selection, and optional mounts; parsing validates complete environment configuration |
| `http_mount::WorkerHttpMountConfig::with_context(context)` | Attach the host fetch context to programmatic HTTP serving and settlement |
| `adapter::ns_object_with(state, &env, class, make_sink)` | Construct a DO with a custom Outcome sink and environment configuration |
| `ns_object::NsObject`, `classes::ShardClass` | Route DO requests and alarms using the correct one of the five shard classes |
| `mkit_server::pipeline::{HookSet, Authorizer, Admission, OutcomeSink}` | Implement business decisions and durable Outcome delivery outside the adapter |

Use `embedding::NsObjectBuilder::new(state, &env, class, config_result)` with
`build_with(make_sink)` for custom Outcome delivery. `with_purge(sink, local)`
also installs the actual `Arc<dyn PurgeSink>` and `LocalInvalidation` on durable
retries. Keep fetch and DO factories on the same configuration. For a takedown
environment, use `WorkerConfig::from_env_with_purge(env, PurgeHooks::new(sink,
local))` so the custom sink participates in startup validation and replaces the
signed HTTPS `cache-purge` requirement. Admin keys and complete preservation
remain mandatory. Preservation core and the WP-5.6a-3 restricted admin catalog are wired.
Custom purge delivery requires `WORKERS_PLAN=paid`; Free alarm calls are
already reserved. The custom sink must acknowledge all selected global cache variants; local
invalidation must charge the provided budget and return a resumable checkpoint.

`mkit_server_worker::durable_objects!(config_factory, sink_factory)` generates
RefStore, NsCoordinator, RefShard, RepoIndexShard and ContentIndexShard with
fetch/alarm delegation. `config_factory(&Env)` returns
`Result<WorkerConfig, ConfigError>`; `sink_factory(&Env, &WorkerConfig)` returns
the Outcome sink. `durable_objects!()` uses environment configuration and hooks.
Both the reference deployment and [embedded example](../embedded-worker/README.md)
use this macro. [#1259](https://github.com/officialunofficial/mkit/pull/1259)
records the scoped local embedding acceptance. Use the
[Workers operator guide](../../docs/operations/workers.md) for deployed checks.

Set `WorkerConfig::admin_on_public_path = false` to keep AdminService off public
fetch and call `adapter::serve_admin_with(req, env, &cfg)` on host-routed admin
requests. The canonical signed AdminService path and ADMIN_KEYS authentication
remain required. No keys means disabled in both modes. Programmatic
`WorkerConfig::ref_policy` accepts `mkit_server::policy::{RefPolicy, RefRule}`
for signer restrictions and fast-forward rules. A fast-forward-only
`refs/tags/*` rule requires indexed mode; it is not a separate no-delete policy.
There is no general no-delete knob. Programmatic `takedown_denial` requires the
same preservation foundation; configured takedown cannot disable global denial. `WorkerConfig::validate()` checks these changes
before store access; fetch and DO construction call it automatically.

The example transfers the incoming ReadableStream to a constructed request for
`serve_with`, including streamed `UploadPart`. Its envelope audience must equal
WorkerConfig's `AUTH_AUDIENCE` (the exact public origin) regardless of the
constructed request URL. In-process dispatch shares the caller's isolate CPU,
memory and subrequest limits. Attach the host Context with
`WorkerHttpMountConfig::with_context(context)` when enabling HTTP read settlement.
Reserved paths are `/mkit.transport.v1.TransportService/`,
`/mkit.server.admin.v1.AdminService/`, any path containing `/-/` when HTTP serving
is mounted, `/.well-known/mkit-*`, `/_mkit/`, and `/__mkit_test/` in test builds.
A host can choose another prefix such as `/_host/`. Namespaces and repository
names cannot begin with `_`.

The minimal launch profile enables `pack-ruzstd` to accept native compressed pushes.
Core publication semantics are mandatory. These historical measurements are pinned to
`43256803446f7f29a7fbf45d794afcfb78cea181`, before the final review fixes.
The historical size manifest on the feature branch records artifact hashes,
full emitted sizes, commands and deterministic gzip counts (mtime zero). Its SHA-256 is
`ef1d92a85fce5c665131d2a5616d6d358ffec26e7c9ba5061d340a7f8fd71375`.
Run each command from `apps/vcs-worker`. Final-head variant measurements and
remote packaging acceptance remain UNRUN; these rows certify only that
historical emitted files fit the recorded local 64 MiB guard.

| Variant | Exact release build command | Raw wasm bytes | gzip bytes | Limit/acceptance |
|---|---|---|---|---|
| Profile without optional HTTP or signed HTTPS | `worker-build --release --features pack-ruzstd` | 6,661,292 | 2,279,944 | 6,701,318 emitted bytes; local PASS |
| HTTP objects / tokens | `worker-build --release --features pack-ruzstd,http-objects` | 6,990,192 | 2,380,916 | 7,030,420 emitted bytes; local PASS |
| Signed HTTPS hooks | `worker-build --release --features pack-ruzstd,signed-http-hooks` | 6,665,414 | 2,282,338 | 6,705,440 emitted bytes; local PASS |
| HTTP plus signed HTTPS | `worker-build --release --features pack-ruzstd,http-objects,signed-http-hooks` | 6,993,827 | 2,383,298 | 7,034,055 emitted bytes; local PASS |

The distinct embedding acceptance host at `7527556d09c7753462f0449622d86ade0fb3b70e`
measured 6,934,119 raw / 2,370,989 gzip bytes (6,974,355 emitted bytes).
[#1259](https://github.com/officialunofficial/mkit/pull/1259) pins that distinct
host artifact and measured runtime scope separately.

The aggregate `launch` build enables `pack-ruzstd`, `http-objects` and
`signed-http-hooks`; runtime features remain configuration opt-ins. Record the
example's independent wasm32 build and actual release runtime evidence
separately, then follow the [operator guide](../../docs/operations/workers.md)
for deployed validation.

Cloudflare's [September 4, 2026 size-limit change](https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/)
sets a 64 MiB uncompressed bundle limit on Free and Paid plans. The bundle
includes the wasm and JavaScript shim, so the table's wasm size alone is not
full bundle acceptance. gzip is informational; there is no compressed-size
limit. No deploy or cloud-account call is required for these local measurements.

`python3 scripts/vcs-worker-launch-size.py --sha <40-character-HEAD>` runs all
four commands sequentially from the repository root and preserves each emitted
bundle plus its raw/gzip counts and file hashes in the owned `TMPDIR`.
`python3 scripts/vcs-worker-launch-admin-runtime.py --sha <40-character-HEAD>`
exercises the configured seven-operation release catalog, private preservation,
role checks and independent signed purge receiver for allowlist and any. Both
require a clean committed candidate; the admin probe also requires a private
`VCS_CONFORMANCE_PORT`. Their component results leave the full matrix unrun.

The explicit `launch` Cargo feature enables R-203’s bounded pure-Rust zstd
decoder for compressed native pushes. The default build keeps decoding off.
Native push → launch Worker → clone runtime evidence is recorded separately in
the launch matrix.
