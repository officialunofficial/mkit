<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# mkit vcs worker (reference `mkit.transport.v1` server)

The **reference implementation** of `mkit.transport.v1.TransportService`
(defined in
[`proto/mkit/transport/v1/transport.proto`](../../proto/mkit/transport/v1/transport.proto),
normatively specified in
[`docs/specs/SPEC-TRANSPORT-CONNECT.md`](../../docs/specs/SPEC-TRANSPORT-CONNECT.md)):
a Rust Cloudflare Worker ([workers-rs]) speaking [ConnectRPC] over the
canonical mkit push/pull protocol. It is what an `mkit+https://` remote talks
to.

One Worker deployment serves **one mkit repository** — unlike
[`apps/repo-worker`](../repo-worker)'s anonymous-multiplayer `mkit.repo.v1`
demo (per-`room` instancing, open write, chat/reactions), this service has no
room concept, no chat surface, and gates writes behind a signed envelope (see
"Auth" below). It otherwise follows repo-worker's proven architecture almost
exactly — vendored buffa/connectrpc codegen, R2 for content-addressed
storage, a Durable Object for serial ref CAS, the `worker::Request`
↔ `http::Request` adapter, the `SendFuture` shim for `!Send` worker handles.
Read `apps/repo-worker/README.md` first if any of that is unfamiliar; this
document only calls out what differs.

## Architecture

```
  worker::Request ─┐
                   │  #[event(fetch)]  (src/worker_impl.rs)
                   ▼
       http::Request<Full<Bytes>>
                   │  ConnectRpcService::new(Router).with_interceptor(AuthInterceptor)
                   │  driven via tower::ServiceExt::oneshot
                   ▼
      TransportService impl (src/worker_impl/service.rs)
           ├── PackExists / UploadPack / DownloadPack ──▶ R2 bucket  (binding STORAGE)
           └── ListRefs / ReadRef / UpdateRef / AdvanceRefs ──▶ RefStore Durable Object (binding REFSTORE)
                   │                                              • ONE global instance ("root")
                   ▼                                              • SQLite refs(path, value)
       http::Response<ConnectRpcBody>                             • serial CAS, incl. the two-ref
                   │  collect body → Bytes                          AdvanceRefs transaction
                   ▼                                                (src/worker_impl/refstore.rs)
              worker::Response
```

## Auth (DEMO MODE — open write, no allow-list)

`UpdateRef` and `AdvanceRefs` require the SAME unary signed-write envelope
`apps/repo-worker` uses (byte-for-byte identical canonical-string
construction — see its README for the full spec); `PackExists`, `ReadRef`,
and `ListRefs` are open reads.

`UploadPack` is client-streaming, which the unary envelope can't cover: the
Connect interceptor that gates it (`Interceptor::intercept_streaming`) runs
**once at stream establishment, before any message has arrived** — there is
no request body yet to BLAKE3 and bind a signature to. This service therefore
verifies a **narrower streaming envelope** for `UploadPack`
(`src/envelope.rs`'s `verify_stream_envelope`): it binds the signature to
`(procedure, createdAt, idempotencyKey)` only, proving "a holder of this key
authorized an UploadPack call at this time" — not "…over these specific
bytes." That is a deliberate, narrower claim than the unary envelope makes,
not a content-integrity gap: the uploaded pack's integrity is separately and
**unconditionally** enforced inside the handler regardless of auth
(SPEC-TRANSPORT-CONNECT §6.1 — `BLAKE3(received bytes) == header.pack_id`, a
mismatch is rejected before anything is stored).

Both envelope kinds are open-write (same posture as repo-worker): any valid
Ed25519 key may write. A valid signature proves request integrity +
same-author, never authority.

### Known limitations

- **Replay within the freshness window** (±5 min) — same caveat as
  repo-worker; the idempotency key is signed but not deduplicated
  server-side.
- **Open write** — no allow-list; any valid key may advance any ref.
- **Whole-pack buffering, not incremental streaming.** `UploadPack`
  accumulates the entire pack in memory (bounded by `MAX_PACK_BYTES`, 64 MiB)
  before one R2 put; `DownloadPack` reads the whole pack from R2 before
  yielding it as a degenerate two-item stream (one `header`, one `chunk`
  carrying all the bytes). This satisfies the wire contract in
  SPEC-TRANSPORT-CONNECT §6 (ascending contiguous offsets ending in
  `last = true` — a single chunk is a valid, if minimal, instance of that)
  without attempting the owned-`futures_channel::mpsc`-bridge streaming
  design SPEC-TRANSPORT-CONNECT §6.3 describes for a future incremental
  implementation. That bridge's end-to-end HTTP delivery is explicitly
  flagged **unverified** in the spec (a `wrangler dev` test received zero
  bytes even after the bridge processed a real event); this reference server
  does not attempt it. Chunked pack transfer replacing whole-pack buffering
  is out of scope for the issue this crate implements (mkit#699) and is
  tracked separately (mkit#702).
- **The outer HTTP transport also buffers whole request/response bodies**
  (`src/worker_impl.rs`'s `serve_connect`, mirroring repo-worker's bridge
  exactly): even if a handler produced a truly incremental stream, the
  fetch-handler bridge collects the entire `ConnectRpcBody` before
  returning a `worker::Response`. A real incremental `DownloadPack` would
  additionally need `Response::from_stream` (or equivalent) in that bridge,
  which this reference server does not implement — see
  SPEC-TRANSPORT-CONNECT §6.3.
- **No end-to-end integration test yet.** This crate ships unit tests for
  its pure logic (envelope verification, ref-CAS decisions, pack-digest
  matching — `cargo test --lib`, host target) but no test drives the real
  generated Worker service against `wrangler dev` or a `workers-rs` local
  test harness the way mkit#699's "Testing Decisions" describes. `mkit
  push`/`fetch`/`clone` over `mkit+https://` still exercise
  `mkit-transport-http`'s fake-server fixture
  (`rust/crates/mkit-cli/tests/remote_dispatch_http.rs`), not this Worker —
  wiring a real CLI-side Connect client is mkit#701's scope, and the e2e
  harness depends on it.

## Endpoints

ConnectRPC, `POST /mkit.transport.v1.TransportService/<Method>`:

| RPC | Shape | Auth | Behaviour |
|---|---|---|---|
| `ListRefs` | unary | read | DO prefix scan → `{refs}`. |
| `ReadRef` | unary | read | DO read → `{exists, object_id}`. |
| `UpdateRef` | unary | write | Single-ref CAS (`ANY`/`MISSING`/`MATCH`) → empty body, or Connect `failed_precondition` on conflict. |
| `AdvanceRefs` | unary | write | Atomic two-ref CAS (head + packmap), evaluated inside one serial DO fetch → `{outcome}`. |
| `PackExists` | unary | read | R2 head → `{exists}`. |
| `UploadPack` | client-streaming | write (streaming envelope) | Verifies `header`-then-`chunk*` framing, offset contiguity, `BLAKE3(received) == pack_id`; idempotent content-addressed R2 put. |
| `DownloadPack` | server-streaming | read | R2 get → a 2-item `(header, chunk)` stream carrying the whole pack (see "Known limitations"); Connect `not_found` if absent. |

## RefStore Durable Object

**One global instance** (`env.durable_object("REFSTORE").id_from_name("root")`)
— this service has no per-room/per-project split; a Worker deployment IS one
repository. SQLite `refs(path TEXT PRIMARY KEY, value TEXT)`. Internal JSON
wire protocol (`POST /get | /update | /list | /advance`) — see
`src/worker_impl/wire.rs`. `AdvanceRefs` evaluates BOTH ref preconditions
before writing EITHER ref (packmap checked first, matching
`Transport::advance_refs`'s default precedence) — a true atomic transaction
inside the DO's single serial `fetch`, never the packmap-then-head fallback a
non-transactional backend would need.

## Build & run

```sh
# unit tests (host) — envelope verify + ref CAS conformance vectors
cargo test --lib

# compile to wasm32 (what worker-build runs under the hood)
cargo build --target wasm32-unknown-unknown

# full worker bundle (the wrangler [build] command): cdylib → wasm-opt → esbuild
worker-build --release

# local dev server (workerd + R2/DO emulation)
wrangler dev -c wrangler.dev.jsonc
```

`wrangler.jsonc` binds the R2 bucket `STORAGE`, the Durable Object `REFSTORE`
(SQLite migration `v1`), and `compatibility_date`. There is no production
route configured yet — see "Deploy" below.

## Layout

- `src/envelope.rs`, `src/refs.rs`, `src/hashing.rs` — pure,
  target-independent logic (the `#[cfg(test)]` modules carry the conformance
  vectors). Compiled on host *and* wasm.
- `src/worker_impl.rs` + `src/worker_impl/{auth,refstore,service,wire}.rs` —
  wasm32-only worker glue.
- `generated/` — vendored buffa/connectrpc codegen for
  `proto/mkit/transport/v1/transport.proto` (repo root, NOT app-local — this
  proto module is shared with any future `mkit serve` / native CLI client
  consumer, per SPEC-TRANSPORT-CONNECT §1). `build.rs` stages it into
  `$OUT_DIR`; set `MKIT_TRANSPORT_CODEGEN=1` to regenerate from the proto
  instead (requires protoc ≥ 27). After editing `transport.proto`, run
  `scripts/regen-transport-proto.sh` from the repo root and commit the
  refreshed `generated/`.

## Deploy (not yet live)

This reference server has not been deployed anywhere; it only runs against
`wrangler dev` locally today. To make it live:

1. **Provision storage** (one-time): `wrangler r2 bucket create
   mkit-vcs-objects`. The RefStore Durable Object + its `v1` SQLite migration
   are created automatically on first deploy.
2. **Deploy:** `wrangler deploy` (needs an authenticated wrangler /
   `CLOUDFLARE_API_TOKEN`), or wire a Cloudflare Workers Builds project at
   `apps/vcs-worker` — same mechanism as `apps/repo-worker` and `apps/web`.
3. **Pin a route** in `wrangler.jsonc` (`routes: [{ pattern, custom_domain:
   true }]`) once a production hostname is chosen, and update
   `mkit-transport-http`'s default endpoint / any client configuration to
   match.

[workers-rs]: https://github.com/cloudflare/workers-rs
[ConnectRPC]: https://connectrpc.com/
