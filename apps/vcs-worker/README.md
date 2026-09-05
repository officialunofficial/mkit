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

One Worker deployment serves **one mkit repository** &mdash; unlike
[`apps/repo-worker`](../repo-worker)'s anonymous-multiplayer `mkit.repo.v1`
demo (per-`room` instancing, open write, chat/reactions), this service has no
room concept, no chat surface, and gates writes behind a signed envelope (see
"Auth" below). It otherwise follows repo-worker's proven architecture almost
exactly &mdash; vendored buffa/connectrpc codegen, R2 for content-addressed
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

## Auth v2 (open write, no allow-list)

All writes require the destination-bound [auth v2 contract](../../docs/specs/SPEC-TRANSPORT-CONNECT.md#auth-v2-contract).
The signature binds audience, repository, procedure, exact body or pack content,
creation/expiry timestamps, and a mandatory random nonce. Configure `AUTH_AUDIENCE` to the exact public origin (and override it
for local development); VCS also requires `AUTH_REPOSITORY`, default `default`.
Repo requests use the decoded room as repository identity.

SQLite transactions couple nonce replay records, quota, and mutable effects.
Retries return their recorded result, including after a newer ref update, and
never toggle a reaction or allocate a second message sequence. Immutable R2
publication reserves quota once and resumes an interrupted conditional put.
A failed ledger or quota read fails closed. Ref/event broadcasts occur only
after the transaction commits. Any valid key can still write; this demo does
not implement an allow-list.

### Known limitations

- **Open write** &mdash; no allow-list; any valid key may advance any ref.
- **Whole-pack buffering, not incremental streaming.** `UploadPack`
  accumulates the entire pack in memory (bounded by `MAX_PACK_BYTES`, 64 MiB)
  before one R2 put; `DownloadPack` reads the whole pack from R2 before
  yielding it as a degenerate two-item stream (one `header`, one `chunk`
  carrying all the bytes). This satisfies the wire contract in
  SPEC-TRANSPORT-CONNECT §6 (ascending contiguous offsets ending in
  `last = true` &mdash; a single chunk is a valid, if minimal, instance of that)
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
  which this reference server does not implement &mdash; see
  SPEC-TRANSPORT-CONNECT §6.3.
- **End-to-end RPC surface &mdash; manually VERIFIED (2026-07-12) against local
  `wrangler dev`, TWICE, with two different clients.** Pass 1 drove every
  RPC against a real local `wrangler dev` instance (wrangler 4.110.0,
  `worker` 0.8.5, `connectrpc` 0.8.1) with real R2 and Durable Object
  emulation, using hand-crafted Connect requests (unary JSON for
  `ListRefs`/`ReadRef`/`PackExists`/`UpdateRef`/`AdvanceRefs`, enveloped
  `application/connect+json` framing for the streaming
  `UploadPack`/`DownloadPack`) signed with a real Ed25519 key through the
  exact canonical-string construction `envelope.rs` implements. This is
  real coverage of the wasm-specific glue no host-side `cargo test` can
  reach (the `SendFuture` shim, `Env::bucket`/`Env::durable_object`, the
  internal DO JSON wire protocol, the `AuthInterceptor` wiring) &mdash; see
  `apps/repo-worker/README.md`'s "WatchRefs / streaming" section for why
  this project verifies wasm-only Worker glue manually against `wrangler
  dev` rather than trying to automate it in CI.

  Pass 2 (same day, closing the gap the paragraph below used to describe)
  drove the SAME local `wrangler dev` instance with the REAL native
  `mkit` CLI binary &mdash; `mkit init` / `keygen` / `commit` / `config
  transport_auth envelope` / `push` / `clone` / `pull` &mdash; end to end, no
  hand-crafted requests: `mkit push -u` (first push: `UploadPack` ×2 and
  `AdvanceRefs`, signed with the new native envelope-signing
  `ConnectTransport` auth mode), a second `mkit push` (fast-forward,
  CAS-`Match` `AdvanceRefs`), `mkit clone` into a fresh directory
  (`ListRefs`, `ReadRef`, and `DownloadPack`, content byte-identical and the
  commit hash round-tripping exactly), and `mkit pull` picking up a third
  commit. Every RPC returned `200 OK`; `wrangler dev`'s own request log and
  a `ReadRef`/`ListRefs` cross-check confirm the pushed commit hash landed
  exactly. This pass exercises the FULL client stack the "newly-discovered
  gap" paragraph below used to flag as untested: the real
  `mkit-transport-connect::EnvelopeSigner` implementation, the real
  `mkit-cli` config/signer resolution, and this server's `AuthInterceptor`
  together, not a hand-rolled substitute for either side.

  Getting Pass 2 running surfaced (and this pass fixes) two bugs neither
  Pass 1 nor this crate's `cargo test --lib` could have caught, because
  neither a hand-crafted curl request nor a host-side unit test exercises
  them:
  - **`worker_impl.rs`'s HTTP bridge now strips `Connect-Timeout-Ms` /
    `grpc-timeout` before dispatch.** `connectrpc`'s server-side deadline
    parsing (`response.rs`) calls `std::time::Instant::now()`
    unconditionally when either header is present, which panics
    ("time not implemented on this platform") on `wasm32-unknown-unknown`
    &mdash; this target has no OS clock and `Instant`/`SystemTime` have no
    JS-Date fallback (unlike `worker::Date`, which this server already
    uses for its own envelope freshness check). A hand-crafted curl
    request never sends a deadline header, so Pass 1 never hit this; the
    real `ConnectTransport` (mkit#701) sets one on every call
    (`with_default_timeout`), so it panicked the whole Worker on the
    FIRST real RPC. This server now simply never enforces a
    client-asserted deadline &mdash; the documented behavior of an unconfigured
    `DeadlinePolicy` anyway &mdash; rather than crash.
  - **`service.rs`'s `ListRefs` now strips the request `prefix` off each
    returned ref name**, per `mkit_core::protocol::Transport::list_refs`'s
    contract ("returned names have `prefix` stripped", SPEC-REFS §4) &mdash;
    every other transport (file/S3/SSH/memory) already honors this. This
    server previously returned the untouched full path
    (`refs/heads/main`), which silently broke `mkit-cli`'s
    `remote_dispatch::fetch_objects_inner` (it computes each branch's
    packmap ref as `refs/mkit/packmap/<listed-name>`, so an unstripped
    name produced `refs/mkit/packmap/refs/heads/main` &mdash; never the real
    ref) &mdash; surfacing as "remote advertised branch 'refs/heads/main' but no
    pack map to reconstruct it" on `mkit clone`/`fetch`/`pull`, not as an
    auth or wire-shape error. Pass 1's hand-crafted requests only ever
    inspected the raw JSON response, so a full but unstripped name looked
    superficially fine.

  **What was NOT verified:** a real deployed Cloudflare Worker (this pass
  had no deploy authorization, same caveat as repo-worker's own WatchRefs
  verification), and the incremental-streaming `DownloadPack` bridge
  SPEC-TRANSPORT-CONNECT §6.3 flags as unresolved (this server
  deliberately doesn't attempt it &mdash; see above).
- **RESOLVED (2026-07-12): `mkit-transport-connect` can now authenticate a
  write against this server.** `ConnectTransport` gained an ADDITIONAL
  auth mode &mdash; `mkit_transport_connect::envelope::EnvelopeTransport`,
  native (BLAKE3 and Ed25519, no wasm/JS) &mdash; alongside its existing
  bearer-token mode (`mkit-transport-http`'s scheme, still used by #700's
  `mkit serve --http`, unchanged). `mkit-cli` wires it in via a new
  `transport_auth = envelope` config key (user-scoped, with explicit endpoint trust); when set, `mkit push`/`fetch`/`pull`/`clone` sign every
  write RPC (`UpdateRef`/`AdvanceRefs`/`UploadPack`) with the SAME Ed25519
  identity that already signs commits &mdash; resolved via the exact commit-
  signing signer resolution (`signer`/`signing_key`/`key.ed25519_ref`),
  reusing `mkit_attest::RepoKeySigner` / `mkit_keystore::KeySigner` rather
  than a parallel key path. See "End-to-end RPC surface" above for the
  live `mkit push`/`clone`/`pull` proof against this exact server. Details:
  `rust/crates/mkit-transport-connect/src/envelope.rs`,
  `rust/crates/mkit-cli/src/remote_dispatch/{mod.rs,envelope_signer.rs}`.
- No automated `cargo test` drives this end-to-end scenario (the manual
  verification above is not wired into CI) &mdash; this crate's automated tests
  remain the host-only unit tests for pure logic (envelope verification,
  ref-CAS decisions, pack-digest matching &mdash; `cargo test --lib`).

## Endpoints

ConnectRPC, `POST /mkit.transport.v1.TransportService/<Method>`:

| RPC | Shape | Auth | Behavior |
|---|---|---|---|
| `ListRefs` | unary | read | DO prefix scan → `{refs}`. |
| `ReadRef` | unary | read | DO read → `{exists, object_id}`. |
| `UpdateRef` | unary | write, quota-gated | Single-ref CAS (`ANY`/`MISSING`/`MATCH`) → empty body, or Connect `failed_precondition` on conflict. |
| `AdvanceRefs` | unary | write, quota-gated | Atomic two-ref CAS (head and packmap), evaluated inside one serial DO fetch → `{outcome}`. |
| `PackExists` | unary | read | R2 head → `{exists}`. |
| `UploadPack` | client-streaming | write (streaming envelope), quota-gated | Verifies `header`-then-`chunk*` framing, offset contiguity, `BLAKE3(received) == pack_id`; idempotent content-addressed R2 put. |
| `DownloadPack` | server-streaming | read | R2 get → a 2-item `(header, chunk)` stream carrying the whole pack (see "Known limitations"); Connect `not_found` if absent. |

## RefStore Durable Object

**One global instance** (`env.durable_object("REFSTORE").id_from_name("root")`)
&mdash; this service has no per-room/per-project split; a Worker deployment IS one
repository. SQLite `refs(path TEXT PRIMARY KEY, value TEXT)`. Internal JSON
wire protocol (`POST /get | /update | /list | /advance | /object`) &mdash; see
`src/worker_impl/wire.rs`. `AdvanceRefs` evaluates BOTH ref preconditions
before writing EITHER ref (packmap checked first, matching
`Transport::advance_refs`'s default precedence) &mdash; a true atomic transaction
inside the DO's single serial `fetch`, never the packmap-then-head fallback a
non-transactional backend would need. The per-key write-quota ledger
(`write_quota` table) lives here too &mdash; see "Auth v2" above.

## Build and run

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
route configured yet &mdash; see "Deploy" below.

## Layout

- `src/envelope.rs`, `src/refs.rs`, `src/hashing.rs` &mdash; pure,
  target-independent logic (the `#[cfg(test)]` modules carry the conformance
  vectors). Compiled on host *and* wasm.
- `src/worker_impl.rs` and `src/worker_impl/{auth,refstore,service,wire}.rs` &mdash;
  wasm32-only worker glue.
- `generated/` &mdash; vendored buffa/connectrpc codegen for
  `proto/mkit/transport/v1/transport.proto` (repo root, NOT app-local &mdash; this
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
   mkit-vcs-objects`. The RefStore Durable Object and its `v1` SQLite migration
   are created automatically on first deploy.
2. **Deploy:** `wrangler deploy` (needs an authenticated wrangler /
   `CLOUDFLARE_API_TOKEN`), or wire a Cloudflare Workers Builds project at
   `apps/vcs-worker` &mdash; same mechanism as `apps/repo-worker` and `apps/web`.
3. **Pin a route** in `wrangler.jsonc` (`routes: [{ pattern, custom_domain:
   true }]`) once a production hostname is chosen, and update
   `mkit-transport-http`'s default endpoint/any client configuration to
   match.

[workers-rs]: https://github.com/cloudflare/workers-rs
[ConnectRPC]: https://connectrpc.com/

## Auth v2 runtime regressions

Build with `worker-build --dev --features test-faults`, run a local Worker with
`AUTH_AUDIENCE=http://localhost:8791` and `AUTH_REPOSITORY=default`, then run
`node tests/auth_v2.mjs http://localhost:8791 --fault`. The script checks
concurrent replay, quota preservation, atomic two-ref rollback and retry,
stream content binding, and interrupted immutable publication. The test fault
hooks are absent unless the explicit `test-faults` feature is enabled.
