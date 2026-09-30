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

Indexed serving selects the Paid Uno launch profile described below. Free
Workers cannot enable indexed mode. Phase 1 validates the profile and refuses
release activation until WP-4.10b-2's extraction driver is merged; test-faults
indexed conformance is separate evidence and does not activate a deployment.
The alarm budget is shared across handlers; see the
[launch budget audit](../../docs/plans/mkit-server/launch-budgets.md).

For a backend move or recovery beyond PITR, collect a complete, compatible
set of `.kvlog` partition snapshots from R2 into the native export directory
layout. Select exactly one object for each `<kind>/<partition-hash>/`, normally
the newest. These snapshots are per partition and do not form one consistent
cut. Keep the target offline, and run `mkit-server restore --meta
sqlite:<NEW PATH> --from <DIR> --sharding single|d34`. Restore accepts only a
new database, advances grant epochs by at least 2^32, re-keys relay rows from
the supplied watermarks and marks coordinators recovered. A native deployment can create a
consistent portable set directly with `mkit-server export --meta
sqlite:<PATH> --out <DIR>`; `mkit-server backup` is the physical in-place
recovery option. A snapshot older than auth v2's maximum 300,000 ms envelope
validity cannot revive a replayable write envelope.

Owners must re-issue grants after restore. Missing relay sources or coordinators
are refused by default. `--allow-incomplete` reconstructs missing sources;
missing coordinators additionally require `--epoch-at-least N` with N ≥ 2^32 (4294967296), above any epoch the lost coordinator could have issued. Review the
printed missing list. An older target can lack membership or index rows that
the source had already delivered and removed; index reconcile is required
before GA (R-116).

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
- `UNSAFE_LOOPBACK_GRANTS`: honoured only in `test-faults` builds (local
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
- `NAMESPACE_POLICY=any` admits every self-certifying namespace and requires
  `UNSAFE_OPEN_NAMESPACES=true`: without non-default admission (M3) any
  fresh key resets its namespace's quota, so the open policy is an explicit
  unsafe opt-in. The Uno Kit demo (UNO-420) selects it deliberately. Under
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
- **Unary replies are one frame**: a `ListRefs` reply is held whole, about
  45 bytes per ref (1.2 MB for 30,000 refs), until WP-1.27 pages it. The
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

## Test hooks (`test-faults`)

A `worker-build --dev --features test-faults` build adds, and a release
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

The historical [staging template](staging/README.md) is inert. The single Uno
launch uses the [staging definition](../../docs/plans/mkit-server/staging-uno.md)
and [operator runbook](../../docs/plans/mkit-server/launch-operations.md).
Their user-owned staging and release gates remain unrun.

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

## Paid Uno launch profile (WP-4.18 / R-194)

Set `LAUNCH_PROFILE=uno`, `WORKERS_PLAN=paid`, `INDEXED_MODE=true`,
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
| Inspection | Zero inspectors is valid. With inspection, up to four sync `fail_closed` inspectors, complete R-193 scanner allowlist and a dedicated retrieval key are required. Async, publish-on-unavailable and clear deadlines are refused |
| Admin | Dedicated `ADMIN_KEYS` with signed requests, permitted roles, replay and gapless audit |
| Takedown | `TAKEDOWN_ENABLED=true`, admin keys, separate preservation bucket, explicit retention, dedicated preservation signer and published key list under §14.7, plus signed HTTPS `cache-purge`. Partial configuration is refused |

Phase 1 fails closed for unavailable extraction (WP-4.10b-2), preservation
(WP-5.6a-2) and scanner retrieval (R-193). Phase 2 removes these refusals only
when their merged implementations pass the complete local launch matrix.
See the [conformance plan](../../docs/plans/mkit-server/launch-conformance.md)
and [itemized evidence](../../docs/plans/mkit-server/launch-evidence.md).

Worker object-byte HTTP responses always use `application/octet-stream`,
`X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox; default-src 'none'`. They never render
untrusted repository content as active browser content. HTTP `?proof=1`
remains unsupported on the Worker, which advertises no proof capability;
the native reference server advertises and serves proofs.

With admin and takedown configured, the Worker admin subset is `Takedown`,
`GetTakedown`, `ListTakedowns`, `ReadPreserved`, `SetLegalHold`, `PurgeCache`
and `ReadAuditLog`. Hold review operations and `Reinstate` remain unexposed.
The launch creates no inspection holds or publication Events; async inspection,
hold review, Events and Worker proofs are post-launch work (R-200).
