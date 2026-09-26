<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# mkit vcs worker (reference `mkit.transport.v1` server)

The **reference deployment** of `mkit.transport.v1.TransportService`
(defined in
[`proto/mkit/transport/v1/transport.proto`](../../proto/mkit/transport/v1/transport.proto),
normatively specified in
[`docs/specs/SPEC-TRANSPORT-CONNECT.md`](../../docs/specs/SPEC-TRANSPORT-CONNECT.md))
on Cloudflare Workers: what an `mkit+https://` remote talks to.

One Worker deployment serves **one mkit repository**. Since WP-M0-17 this
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

## Auth v2 (open write, no allow-list)

All writes (`UpdateRef`, `AdvanceRefs`, `UploadPack`) require the
destination-bound [auth v2 contract](../../docs/specs/SPEC-TRANSPORT-CONNECT.md#auth-v2-contract),
verified by `mkit-server`'s auth stage. The signature binds audience,
repository, procedure, exact body or pack content, creation/expiry
timestamps, and a mandatory random nonce. Reads are unsigned. Configure
`AUTH_AUDIENCE` to the exact public origin (override it for local
development) and `AUTH_REPOSITORY`, default `default`; with either missing or
malformed, every RPC answers `unavailable` naming it.

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
