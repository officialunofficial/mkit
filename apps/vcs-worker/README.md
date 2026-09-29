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

Indexed mode is unavailable on Workers until WP-4.8. Workers Free cannot
serve indexed mode: its 50-subrequest limit is below the budget for a single
repository object-index lookup. Paid Workers use a relay budget of 32 targets
per tick and eight ticks per alarm; Free keeps its smaller relay budget.

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

## Auth v2 (open write, no allow-list)

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
  development opt-in (D27).

The four vars are documented in `wrangler.jsonc`; for a local Multi
deployment under `wrangler dev`, pass them as `--var` (the conformance
script's `--multi` phase does exactly that).

The replay record, the per-signer write quota (300 writes and 128 MiB per
hour) and the effect commit in one batch. A retry returns its recorded
result, including after a newer ref update; a nonce reused for a different
operation is `invalid_argument`. An upload reserves its declared size once
and publishes the pack only after it verifies. Any valid key can write: this
deployment implements no allow-list.

### Known limitations

- **Open write**: no allow-list; any valid key may advance any ref.
- **64 MiB pack cap**, a documented M1 stopgap (resumable parts replace it).
  `UploadPack` and `DownloadPack` bodies stream: an upload holds about one
  chunk in the isolate, and a download streams 800 KiB chunks. A request
  body over 65 MiB (the cap plus framing) is refused with HTTP 400
  `resource_exhausted`, with or without `Content-Length`.
- **Unary replies are one frame**: a `ListRefs` reply is held whole, about
  45 bytes per ref (1.2 MB for 30,000 refs), until WP-1.27 pages it. The
  conformance script's 1 MiB body-buffer bound covers the streaming RPCs
  only.
- **Client deadlines are not enforced**: `connect-timeout-ms` and
  `grpc-timeout` are dropped before dispatch, because connectrpc would read
  `Instant::now()`, which panics on wasm32.
- **One Durable Object** holds the whole repository's metadata; M1 shards it
  (D34).
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

1. **Provision storage** (one-time): `wrangler r2 bucket create
   mkit-vcs-objects`. The RefStore Durable Object and its `v1` SQLite
   migration are created on first deploy.
2. Set `AUTH_AUDIENCE` to the published origin, and `WORKERS_PLAN` for the
   account.
3. **Deploy:** `wrangler deploy`, or a Cloudflare Workers Builds project at
   `apps/vcs-worker`.
4. **Pin a route** in `wrangler.jsonc` once a hostname is chosen.

[workers-rs]: https://github.com/cloudflare/workers-rs
