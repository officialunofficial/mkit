---
spec: SPEC-TRANSPORT-CONNECT
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 Connect servers and clients (reference Worker, `mkit serve`, native CLI transport)
---

# SPEC-TRANSPORT-CONNECT — mkit.transport.v1, the canonical Connect remote protocol

Status: **Draft** for mkit v1. This document has not yet had maintainer
sign-off on the RPC shapes it defines (the acceptance gate for the
issue that produced it); no server or client implements it yet.
Scope: the `mkit.transport.v1.TransportService` Connect service — its
proto shape, verb-to-trait mapping, CAS semantics, error-code mapping,
and pack-transfer streaming design — and how the three planned
deployment targets (reference Worker, `mkit serve`, native CLI client)
consume one generated codebase. It does not cover S3 multipart, the
`WatchRefs` live-feed migration, or any server/client implementation;
those are separate, later changes (§8).

Supersedes: [SPEC-TRANSPORT](SPEC-TRANSPORT.md) §5 ("HTTP transport").
Once a Connect server/client reach verb parity with the JSON REST
dialect §5 describes, `mkit-transport-http`'s bespoke dialect is
retired and SPEC-TRANSPORT §5 is deleted in favor of this document.
Until then, both describe real (or planned) wire behavior and neither
is authoritative over the other's transport.

Reference implementation: none yet. `apps/repo-worker` is the closest
existing analog (a Connect service on Cloudflare Workers) but
implements the unrelated `mkit.repo.v1.RepoService` anonymous-demo
contract, not this one; this document borrows its proven patterns
(§1, §7) without sharing its proto.

The proto lives at
[`proto/mkit/transport/v1/transport.proto`](../../proto/mkit/transport/v1/transport.proto).

---

## 1. Buf module and package layout

```
buf.yaml (repo root, v2, single module today)
└── proto/mkit/transport/v1/transport.proto   → mkit.transport.v1
```

This is deliberately the same "standalone single-module `buf.yaml`"
shape `apps/repo-worker/buf.yaml` used before the repo had any other
proto module registered with `buf`. A separate change (tracked as
mkit#677, "buf workspace + proto path restructure") folds this
module into a repo-root **three-module** `buf.yaml` workspace
alongside `rust/crates/mkit-rpc/proto` (`mkit.rpc.v1`) and
`apps/repo-worker/proto` (`mkit.repo.v1`); until that lands, `buf
lint` / `buf breaking` on this module are invoked from the repo root
using the `buf.yaml` this document ships.

`buf breaking` is configured with `breaking.use: [FILE]` from this
module's first commit onward, so every subsequent change to
`transport.proto` is checked against the immediately prior version —
there is no grace period after this document merges.

A follow-up (tracked as mkit#679) extracts `RefExpectation` and
`RefEntry` into a shared `mkit/common/v1/refs.proto` imported by
`mkit.rpc.v1.ssh`, `mkit.repo.v1`, and this package, once the buf
workspace exists to make a cross-module import resolvable. Until
then, `mkit.transport.v1.RefExpectation` and `RefEntry` are
byte-for-byte duplicates of the `mkit.rpc.v1.ssh` originals — the
same "duplicate now, wire numbers pinned, extract later" pattern
`mkit.repo.v1.RefExpectation` already uses (see the comment at
`apps/repo-worker/proto/mkit/repo/v1/repo.proto:38-40`).

---

## 2. Verb-to-RPC mapping

`TransportService` maps one-to-one onto the verbs of the
[`Transport`](../../rust/crates/mkit-core/src/protocol.rs) trait — the
same trait `mkit-transport-http`/`-s3`/`-ssh`/`-enc` implement today.

| `Transport` trait method | RPC | Shape |
|---|---|---|
| `list_refs(prefix)` | `ListRefs` | unary |
| `read_ref(name)` | `ReadRef` | unary |
| `update_ref(name, condition, hash)` | `UpdateRef` | unary |
| `write_ref(name, hash)` (default impl: `update_ref(.., Any, ..)`) | *(none — client calls `UpdateRef` with `expectation = REF_EXPECTATION_ANY`)* | — |
| `advance_refs(..)` | `AdvanceRefs` | unary |
| `pack_exists(key)` | `PackExists` | unary |
| `upload_pack(bytes, key)` | `UploadPack` | client-streaming |
| `download_pack(key)` | `DownloadPack` | server-streaming |
| `upload_blob(bytes, key)` (default impl: delegates to `upload_pack`) | *(none — client calls `UploadPack`)* | — |
| `download_blob(key)` (default impl: delegates to `download_pack`) | *(none — client calls `DownloadPack`)* | — |

`write_ref` and the blob verbs are `Transport`-trait-level default
methods that delegate to another trait method **before any transport
implementation runs** (see `protocol.rs`'s doc comments on each). The
wire therefore never distinguishes "pack" from "auxiliary blob," or
"unconditional write" from "CAS write with `expectation = ANY`" — a
Connect server implementing the seven wire RPCs above (§2's table)
gets every `Transport` trait verb for free through the client-side
default impls, exactly as every other transport already does.

Endpoints follow the standard Connect convention:
`POST /mkit.transport.v1.TransportService/<Method>`.

---

## 3. CAS semantics — `UpdateRef`

Identical in spirit to [SPEC-TRANSPORT §4.2.1](SPEC-TRANSPORT.md#421-updateref-cas-encoding)
and `mkit.repo.v1.RepoService.UpdateRef`, expressed as a Connect
unary call instead of an `SshFrame` or a JSON body:

| `RefWriteCondition` | `RefExpectation` | `expected_id` | Semantics |
|---|---|---|---|
| `Any` | `REF_EXPECTATION_ANY` | empty | Last-writer-wins. |
| `Missing` | `REF_EXPECTATION_MISSING` | empty | Create-only; the ref MUST NOT already exist. |
| `Match(h)` | `REF_EXPECTATION_MATCH` | 32-byte digest `h` | Current ref value MUST equal `h`. |

A conforming server MUST reject `REF_EXPECTATION_UNSPECIFIED` (the
proto zero value) with Connect code `invalid_argument` — mkit is
alpha (pre-1.0); there is no back-compat surface for a client that
omits `expectation`.

Unlike the SSH wire's `Error.details` (an opaque, not-client-consumed
carrier for the current ref value, per SPEC-TRANSPORT §4.2.1) and
`mkit.repo.v1.UpdateRefResponse.current_id` (which *is*
client-consumed), `UpdateRefResponse` on this service carries **no**
current-value field at all: a CAS failure is a Connect error
(`failed_precondition`), full stop. This is a deliberate
simplification, not an oversight — SPEC-TRANSPORT §7 already requires
callers to disambiguate a possibly-lost write with a follow-up
`read_ref` after any ambiguous failure (timeout, retry), so a second
value-carrying channel on the CAS-conflict path adds a field no
conforming client is allowed to trust as authoritative on its own.
`ReadRef` is the one source of truth for "what is the ref's current
value," called explicitly, every time.

`update_ref`'s trait doc requires: "callers retrying after a network
timeout MUST follow up with `read_ref` to disambiguate whether the
first attempt landed before treating `RefConflict` as a true
conflict." This document reuses that requirement unchanged.

---

## 4. Atomic two-ref advance — `AdvanceRefs`

`Transport::advance_refs` updates a branch's head ref and its packmap
ref together, each under its own CAS precondition, so the
delta-transfer invariant ("if `head_ref` resolves to `T`, the packmap
reconstructs `closure(T)`") never has a window where the two refs
disagree. `AdvanceRefsRequest` carries both preconditions in one
message so a transactional server backend can commit both writes
atomically in one round-trip:

```proto
message AdvanceRefsRequest {
  string head_ref = 1;
  RefExpectation head_expectation = 2;
  bytes head_expected_id = 3;
  bytes head_new_id = 4;

  string packmap_ref = 5;
  RefExpectation packmap_expectation = 6;
  bytes packmap_expected_id = 7;
  bytes packmap_new_id = 8;
}
```

`AdvanceRefsResponse.outcome` mirrors
[`AdvanceOutcome`](../../rust/crates/mkit-core/src/protocol.rs) exactly:

| `AdvanceOutcome` | `AdvanceOutcome` (proto) | Meaning |
|---|---|---|
| `Committed` | `ADVANCE_OUTCOME_COMMITTED` | Both refs updated. |
| `HeadConflict` | `ADVANCE_OUTCOME_HEAD_CONFLICT` | The head precondition failed; branch moved under the caller. |
| `PackmapConflict` | `ADVANCE_OUTCOME_PACKMAP_CONFLICT` | The packmap precondition failed; a concurrent pusher advanced the chain first. |

A conflict is carried as a **successful** RPC with `outcome !=
ADVANCE_OUTCOME_COMMITTED`, not a Connect error — unlike `UpdateRef`,
`advance_refs`'s Rust signature already returns a typed enum rather
than a boolean success/CAS-conflict split (see
`protocol.rs`'s `AdvanceOutcome`), so the wire follows the same shape
instead of forcing a three-way outcome through a two-way (success /
error) channel.

Per `Transport::supports_atomic_advance`'s doc comment, a server
backed by a transactional ref store (a single Durable Object
transaction, a database transaction) SHOULD commit both writes
atomically and MUST advertise this out-of-band to the client (the
Connect service itself carries no `supports_atomic_advance` RPC — a
deployment either documents its guarantee or a client configuration
flag records it, mirroring how `Transport::supports_atomic_advance()`
is a Rust-level trait method today, not a wire negotiation). A
non-transactional server MUST fall back to the same
packmap-then-head ordering the trait's default `advance_refs`
implementation uses, and MUST NOT advertise atomic support if it
uses that fallback.

---

## 5. Error taxonomy — `TransportError` to Connect code

Connect carries structured errors natively (a code plus a message),
so — unlike the SSH wire's hand-rolled `mkit.rpc.v1.Error` message,
needed because raw stdio framing has no ambient error channel — this
service defines **no** custom error message type. Every
[`TransportError`](../../rust/crates/mkit-core/src/protocol.rs) variant
maps onto a standard Connect code:

| `TransportError` | Connect code | Raised by |
|---|---|---|
| `PackNotFound` | `not_found` | `DownloadPack` before any chunk is sent; `PackExists` never raises this (it returns `exists = false` instead). |
| `AccessDenied` | `permission_denied` | Any RPC, when the deployment's auth layer (§7) rejects the caller. |
| `RefConflict` | `failed_precondition` | `UpdateRef` / the relevant half of `AdvanceRefs` on a CAS mismatch. |
| `InvalidRef` | `invalid_argument` | Any RPC taking a ref name that fails SPEC-REFS §3. |
| `ConnectionFailed` | *(not server-raised — client-observed transport failure, e.g. TCP reset, deadline exceeded)* | — |
| `ServerError{status}` | `unavailable` (5xx-equivalent) or `resource_exhausted` (429-equivalent) | Deployment-specific overload / backend failure. |
| `InvalidResponse` | *(not server-raised — client-observed: malformed frame, wrong message on a streamed oneof, digest mismatch on `DownloadPack`)* | — |
| `ProtocolError` | `invalid_argument` | A client-streaming call whose `header` is missing, arrives after a `chunk`, or whose declared/received byte counts disagree (§6). |
| `PayloadTooLarge` | `resource_exhausted` | `UploadPack` header `total_bytes` (or the observed stream length) exceeds the server's cap. |
| `InsecureScheme` | *(not applicable — URL-scheme concern, handled client-side before any RPC is made; see SPEC-TRANSPORT §3)* | — |
| `RemoteError(String)` | `unknown` (server-raised, deployment-specific advisory failure with no more specific code applies) — also the client-side **default** target for any Connect code this table does not otherwise list (`internal`, `aborted`, `unauthenticated`, …), matching the variant's existing "catch-all" contract in `protocol.rs`. | A deployment-specific backend failure that does not fit any row above. |

A conforming client's Connect-to-`TransportError` mapping is the
mechanical inverse of this table, with `RemoteError(String)` as the
fallback arm for any Connect code not otherwise listed — the mapping
is total in both directions, never a partial match. `is_retryable`
(SPEC-TRANSPORT §7) continues to apply unchanged once translated:
`unavailable` and `resource_exhausted` are retryable, everything else
is not.

---

## 6. Pack transfer streaming

`UploadPack` (client-streaming) and `DownloadPack` (server-streaming)
carry [`PackChunk`](../../proto/mkit/transport/v1/transport.proto),
which duplicates
[`mkit.rpc.v1.ssh.PackChunk`](../../rust/crates/mkit-rpc/proto/ssh.proto)'s
field layout exactly (`pack_id`, `offset`, `data`, `last` — same
numbers, same types). This is a deliberate wire-identical duplication,
not a new chunking format: the bytes a client streams over Connect are
parseable by anything that already speaks the SSH/enc `PackChunk`
shape.

### 6.1 `UploadPack` (client-streaming)

`UploadPackRequest` is a `oneof` of `header` (`UploadPackHeader{
pack_id, total_bytes }`) and `chunk` (`PackChunk`). The client MUST
send exactly one `header` message first, then zero or more `chunk`
messages in ascending contiguous `offset` order, ending with a
`chunk.last = true` message (an empty pack still sends one `last =
true` chunk with empty `data`, matching the SSH wire's convention).

The server MUST reject the stream — before returning
`UploadPackResponse`, and MUST NOT create or overwrite the destination
pack on rejection — if:

- the first message is not `header`;
- any `chunk.pack_id` does not match `header.pack_id`;
- any `chunk.offset` does not equal the running received-byte count;
- the stream ends without a `chunk.last = true` message;
- the received byte count does not equal `header.total_bytes`; or
- `BLAKE3(received bytes)` does not equal `header.pack_id`.

These are the same checks SPEC-TRANSPORT §4.2 already requires of the
SSH server's `UploadPack` handling, restated for a Connect stream
instead of an `SshFrame` sequence.

### 6.2 `DownloadPack` (server-streaming)

`DownloadPackResponse` is the receive-side mirror: a `oneof` of
`header` (`DownloadPackHeader{ total_bytes }`) and `chunk`
(`PackChunk`). The server sends exactly one `header` message first,
then a sequence of `chunk` messages ending with `chunk.last = true`.
If the requested `pack_id` is absent, the server returns
`not_found` before sending any message (never a zero-chunk stream).

### 6.3 Streaming on Cloudflare Workers — design answer and open risk

The reference Worker (§7.1) is the one deployment target where
Connect streaming has a known, previously-hit failure mode:
`apps/repo-worker/README.md` §"WatchRefs / streaming (fallback)"
documents that `worker::WebSocket::events()` returns a **borrowed**
`EventStream<'ws>`, which cannot satisfy a generated server-streaming
trait method's `'static + Send` `ServiceStream<T>` bound — that
constraint is why `mkit.repo.v1.RepoService.WatchRefs` is served over
a hand-rolled WebSocket instead of Connect server-streaming today.

`DownloadPack` faces the identical shape of problem (server-to-client
streaming on Workers), and the M2 Task 0 spike (mkit#697) prototyped
the design answer this document specifies: bridge the source of
events (there, a Durable Object `/watch` WebSocket; for `DownloadPack`,
a chunked read from R2/filesystem) into an **owned**
`futures_channel::mpsc` channel, drained by a
`wasm_bindgen_futures::spawn_local` task, so the channel's `Receiver`
— not the borrowed source stream — is what gets boxed into the
generated trait's `ServiceStream<PackChunk>`. Because the channel is
owned (no borrowed lifetime), it satisfies `'static + Send` with zero
`unsafe` code. A conforming reference-Worker implementation of
`DownloadPack` MUST use this bridge pattern (or an equivalent owned
intermediate channel) rather than attempting to box a borrowed stream
directly.

The spike also identified a companion requirement: a Worker's fetch
handler that buffers the entire response body before returning it
(`http_resp.into_body().collect().await.to_bytes()`, the pattern
`apps/repo-worker`'s unary path uses today) defeats streaming
end-to-end regardless of how the RPC handler itself produces chunks —
the response construction MUST use a true streaming response
(`Response::from_stream` or equivalent) instead of collect-then-return.

**Known risk, not yet resolved:** the spike verified the bridge
mechanically (the DO WebSocket opens, drains real events, and
translates them correctly inside `wasm_bindgen_futures::spawn_local`)
and verified `cargo check --target wasm32-unknown-unknown` compiles
clean, but did **not** verify client-visible delivery end-to-end over
HTTP — a test client received zero bytes even after the bridge
processed a real event, against a local `wrangler dev` run, with the
root cause (a `wrangler dev` limitation vs. a remaining adapter bug)
not isolated. This document specifies the bridge as the correct
*design*, informed by the mechanical proof; it does not claim the
design is proven to deliver bytes to a real client yet. The reference
Worker issue (mkit#699) and the streaming pack transfer issue
(mkit#702) MUST re-verify end-to-end delivery (ideally against a real
Cloudflare deployment, not only `wrangler dev`) before either is
considered done — a proto/spec review is not a substitute for that
runtime verification.

`mkit serve` (§7.2) and the native CLI client (§7.3) run outside
Workers (axum/hyper and Tokio respectively) and are not subject to the
non-`'static` `WebSocket::events()` constraint at all — the bridge
above is a Workers-specific workaround, not a general requirement of
this protocol.

---

## 7. Deployment targets

One proto, one generated codebase, three consumers — no per-target
dialect:

### 7.1 Reference Worker

A `connectrpc` + `workers-rs` service (mkit#699), reusing
`apps/repo-worker`'s proven patterns: vendored `generated/` staged by
`build.rs` (`MKIT_REPO_CODEGEN=1` to regenerate via `connectrpc-build`
against the canonical `proto/mkit/transport/v1/transport.proto`, no
protoc dependency on the default build path — Cloudflare Workers
Builds and CI images lack a protoc new enough for `edition = "2023"`),
R2 for pack/blob storage, and a Durable Object for ref CAS. Unlike
`repo-worker`'s open-write demo, this deployment is auth-gated
(bearer token or an allow-list — mkit#699 decides the exact
mechanism), matching the trust model `mkit-transport-http`'s
`MKIT_API_TOKEN` bearer scheme already assumes for a "real" VCS
Worker (SPEC-TRANSPORT §5.2).

### 7.2 `mkit serve`

The same generated `TransportService` trait, served over axum/hyper
(mkit#700) instead of `workers-rs` — `connectrpc` supports both
server backends from one generated trait, so the RPC handler logic is
shareable in principle even though the two deployments' storage
backends differ (R2 + DO vs. local filesystem + `flock`, per
[SPEC-WORKTREE](SPEC-WORKTREE.md)/[SPEC-CONCURRENCY](SPEC-CONCURRENCY.md)).
This gives the CLI's `serve` command an HTTP mode alongside its
existing SSH-frame stdio and `--listen-enc` modes
(`rust/crates/mkit-cli/src/commands/serve/mod.rs`).

### 7.3 Native CLI Connect client

A new, non-wasm Rust crate (mkit#701) mirroring
[`mkit-repo-client`](../../rust/crates/mkit-repo-client/Cargo.toml)'s
"zero-duplication" codegen approach: compiled directly from the
canonical `proto/mkit/transport/v1/transport.proto` via a
workspace-relative path in `build.rs`, never a hand-copied proto or a
hand-rolled URL builder. It differs from `mkit-repo-client` only in
target: native (Tokio, `connectrpc`'s HTTP/native-TLS client
transport) rather than wasm (Fetch API, `wasm-bindgen`), so it drops
the wasm-only dependencies (`wasm-bindgen`, `web-sys`,
`send_wrapper`) and enables `connectrpc`'s native client features
instead. This crate becomes the implementation behind the
`mkit+https://` scheme, retiring `mkit-transport-http`'s hand-rolled
JSON DTOs once it reaches verb parity (SPEC-TRANSPORT §5 is then
deleted). Retry/backoff for this transport is expected to move into a
shared Connect interceptor (mkit#703) that wraps the generated client,
rather than a fourth from-scratch backoff ladder — the same
`is_retryable` classification and `BackoffIterator` ladder
(SPEC-TRANSPORT §7) apply, just translated through §5's Connect-code
mapping instead of read directly off an HTTP status or `TransportError`.

---

## 8. Out of scope

This document specifies the proto and its consumption pattern only.
Explicitly deferred to sibling issues:

- The reference Worker implementation (mkit#699).
- `mkit serve`'s HTTP mode (mkit#700).
- The native CLI Connect client (mkit#701).
- Retiring `mkit-transport-http` and deleting SPEC-TRANSPORT §5 (waits
  on verb parity between the new client and the old dialect).
- The shared retry/backoff Connect interceptor (mkit#703).
- S3 multipart upload (unrelated transport; not superseded by this
  document at all).
- Migrating `mkit.repo.v1.WatchRefs` to real Connect server-streaming
  using the bridge pattern in §6.3 (a `mkit.repo.v1` change, not a
  `mkit.transport.v1` one — tracked separately).
- End-to-end runtime verification of the `DownloadPack` streaming
  bridge (§6.3's known risk) — this is a proto/design review gate, not
  a working-server acceptance gate.
- Generated TypeScript (`connect-es`) clients for this service (M2
  scope, tracked with mkit#706).

---

## 9. Version history

| Version | Status | Changes |
|---|---|---|
| `1` | draft | Initial `mkit.transport.v1` proto: 7 wire RPCs covering every `Transport` trait verb (§2), `PackChunk` reused byte-for-byte from `ssh.proto`, `RefExpectation`/`RefEntry` duplicated with pinned wire numbers pending mkit#679's shared-proto extraction. |

---

## 10. Test anchors

There is no runtime to test against yet (§8) — the acceptance gate
for this document is static, not behavioral:

- `buf lint` (`STANDARD` category) against `proto/mkit/transport/v1/transport.proto` — zero errors, zero lint exceptions.
- `buf breaking` initialized (`breaking.use: [FILE]` in `buf.yaml`, §1) as the baseline for every future change to this module.
- The proto compiles cleanly through the real `buffa`/`connectrpc-build` codegen path (not just `protoc`) — verified by generating and compiling the full client + server stub set (`TransportService`, `TransportServiceClient`, every request/response/`oneof` message) against `buffa 0.8.1` / `connectrpc 0.8` / `connectrpc-build 0.8`, mirroring the exact `include_generated!()` pattern `mkit-repo-client`/`apps/repo-worker` use.
- Explicit maintainer sign-off on the RPC shapes in this document, per the originating issue's Testing Decisions — not automated test coverage, since no server or client exists to test.

Once mkit#699/#700/#701 build real implementations against this
proto, each of those issues owns its own runtime test anchors
(integration tests against a real or locally-hosted server); this
document is not amended to list them.

---

## 11. Invariants

| Invariant | Enforced by |
|---|---|
| Every `Transport` trait verb has exactly one corresponding wire RPC, or is a documented client-side default-impl delegation with no independent wire shape. | §2's mapping table; `protocol.rs`'s default-impl doc comments. |
| `RefExpectation`'s wire numbers (`ANY=1`, `MISSING=2`, `MATCH=3`) never change, even after mkit#679 extracts a shared proto. | `buf breaking` (`FILE` category, §1); the `RefExpectation` doc comment matching `ssh.proto`'s "do NOT renumber" contract. |
| A rejected `UploadPack` stream never creates or overwrites the destination pack. | §6.1's server-side rejection checks, mirroring SPEC-TRANSPORT §4.2's SSH requirement. |
| `DownloadPack` never sends a partial stream silently — it either completes with `chunk.last = true` or fails the whole call before any message is sent. | §6.2. |
| Every `TransportError` variant a server can raise has exactly one Connect code it maps to; a client's inverse mapping is mechanical, not heuristic. | §5's table. |
| An `AdvanceRefs` conflict is a typed response value, never a Connect error. | §4 — matches `AdvanceOutcome`'s three-variant, no-error-variant shape in `protocol.rs`. |
| The `DownloadPack` Workers-streaming design is documented as unverified end-to-end until a sibling issue proves real client-visible delivery. | §6.3's "Known risk" paragraph; mkit#699/#702's re-verification requirement. |
