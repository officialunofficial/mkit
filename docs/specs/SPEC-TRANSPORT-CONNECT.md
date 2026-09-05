---
spec: SPEC-TRANSPORT-CONNECT
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 Connect servers and clients (reference Worker, `mkit serve`, native CLI transport)
---

# SPEC-TRANSPORT-CONNECT &mdash; mkit.transport.v1, the canonical Connect remote protocol

Status: **Draft** for mkit v1. This document has not yet had maintainer
sign-off on the RPC shapes it defines (the acceptance gate for the
issue that produced it). All three deployment targets §7 describes now
exist: the native CLI Connect client (§7.3, mkit#701) is implemented
and tested against a real (in-process, memory-backed) `TransportService`
server; `mkit serve`'s HTTP mode (§7.2, mkit#700) hosts the same
generated service over axum/hyper; and the reference Worker (§7.1,
mkit#699, `apps/vcs-worker`) hosts it over `workers-rs` against R2 +
a Durable Object. The client and the Worker have now been verified
talking to each other over a real local `mkit+https://`-equivalent
deployment (`wrangler dev`, loopback `mkit+http://`) &mdash; including real
`mkit push`/`clone`/`pull` &mdash; via `ConnectTransport`'s new envelope-signing
auth mode; see "Reference implementation" below and
`apps/vcs-worker/README.md` "Known limitations". A real DEPLOYED
Cloudflare Worker (not just `wrangler dev`) remains unverified.
Scope: the `mkit.transport.v1.TransportService` Connect service &mdash; its
proto shape, verb-to-trait mapping, CAS semantics, error-code mapping,
and pack-transfer streaming design &mdash; and how the three planned
deployment targets (reference Worker, `mkit serve`, native CLI client)
consume one generated codebase. It does not cover S3 multipart, the
`WatchRefs` live-feed migration, or any server/client implementation;
those are separate, later changes (§8).

Supersedes: [SPEC-TRANSPORT](SPEC-TRANSPORT.md) §5 ("HTTP transport") as
the ACTIVE implementation behind `mkit+https://`/`mkit+http://` in
`mkit-cli` &mdash; `mkit-transport-connect` is what `remote_dispatch` now
constructs for those schemes. SPEC-TRANSPORT §5 is not yet deleted: the
`mkit-transport-http` crate remains in the tree (unused by `mkit-cli`'s
dispatch) because its `sparse-checkout` and `pack-shards` extensions
(SPEC-TRANSPORT §5.6 and the `pack-shards` cargo feature) have no
`mkit.transport.v1` equivalent yet &mdash; full retirement waits on that gap
being resolved, not just core-verb parity.

Reference implementation: `mkit-transport-connect` (the native CLI
client, §7.3) against `mkit-transport-connect/tests/roundtrip.rs`'s
in-process server &mdash; real HTTP, real protobuf framing, real Connect
streaming, backed by `mkit-transport-memory` rather than R2/a Durable
Object; this is also the implementation `mkit serve --http` (§7.2)
hosts directly. [`apps/vcs-worker`](../../apps/vcs-worker) (mkit#699)
implements the unary and client-streaming RPCs
(`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`/`PackExists`/`UploadPack`)
against this proto over R2 and a Durable Object; `DownloadPack`
(server-streaming) conforms to the wire shape but whole-pack-buffers
rather than incrementally streaming &mdash; see its README "Known
limitations" &mdash; so §6.3's owned-mpsc-channel bridge and its unresolved
end-to-end delivery risk remain unverified by that implementation. Every
RPC has been manually verified against a real local `wrangler dev`
instance (real R2/DO emulation, real Ed25519-signed envelopes) &mdash; see
`apps/vcs-worker/README.md` "Known limitations" for the trial writeup,
including a SECOND pass driving the real `mkit` CLI (`push`/`clone`/
`pull`) end to end against this exact server through `ConnectTransport`'s
new envelope-signing auth mode (§7.3). `ConnectTransport` now supports
BOTH the bearer-token scheme (SPEC-TRANSPORT §5.2, unchanged, used by
`mkit serve --http`) and this server's Ed25519 write envelope (§7.1) as
independent, additive auth modes &mdash; see §7.3. No AUTOMATED test drives
this client/server pair yet (the `wrangler dev` verification above is
manual, matching `apps/vcs-worker`'s existing testing posture for
wasm-only glue) &mdash; that remains the open item on the testing axis.
`apps/repo-worker`
remains the closest OTHER existing analog (a Connect service on
Cloudflare Workers) but implements the unrelated `mkit.repo.v1.RepoService`
anonymous-demo contract, not this one; this document borrows its proven
patterns (§1, §7) without sharing its proto.

The proto lives at
[`proto/mkit/transport/v1/transport.proto`](../../proto/mkit/transport/v1/transport.proto).

---

## 1. Buf module and package layout

```
buf.yaml (repo root, v2, three-module workspace)
├── rust/crates/mkit-rpc/proto         → mkit.rpc.v1 (+ .signer, .ssh, .verify)
├── apps/repo-worker/proto             → mkit.repo.v1
└── proto/mkit/transport/v1/transport.proto   → mkit.transport.v1
```

This module shares the repo-root `buf.yaml` workspace (mkit#677, "buf
workspace + proto path restructure") alongside `rust/crates/mkit-rpc/proto`
(`mkit.rpc.v1`) and `apps/repo-worker/proto` (`mkit.repo.v1`). `buf
lint` / `buf breaking` run from the repo root against the whole
workspace &mdash; see `CONTRIBUTING.md`'s "Protobuf schemas (buf)" section.

`buf breaking` is configured with `breaking.use: [FILE]` from this
module's first commit onward, so every subsequent change to
`transport.proto` is checked against the immediately prior version &mdash;
there is no grace period after this document merges.

A follow-up (tracked as mkit#679) extracts `RefExpectation` and
`RefEntry` into a shared `mkit/common/v1/refs.proto` imported by
`mkit.rpc.v1.ssh`, `mkit.repo.v1`, and this package &mdash; the buf
workspace (§1) now makes that cross-module import resolvable. Until
that extraction lands, `mkit.transport.v1.RefExpectation` and
`RefEntry` are byte-for-byte duplicates of the `mkit.rpc.v1.ssh`
originals. `mkit.rpc.v1.ssh` and `mkit.repo.v1` have already completed
this extraction and both import the shared `mkit/common/v1/refs.proto`
definitions rather than duplicating them (see the comment at
`apps/repo-worker/proto/mkit/repo/v1/repo.proto:20-23`); `mkit.transport.v1`
is the one package still pending the same move.

---

## 2. Verb-to-RPC mapping

`TransportService` maps one-to-one onto the verbs of the
[`Transport`](../../rust/crates/mkit-core/src/protocol.rs) trait &mdash; the
same trait `mkit-transport-http`/`-s3`/`-ssh`/`-enc` implement today.

| `Transport` trait method | RPC | Shape |
|---|---|---|
| `list_refs(prefix)` | `ListRefs` | unary |
| `read_ref(name)` | `ReadRef` | unary |
| `update_ref(name, condition, hash)` | `UpdateRef` | unary |
| `write_ref(name, hash)` (default impl: `update_ref(.., Any, ..)`) | *(none &mdash; client calls `UpdateRef` with `expectation = REF_EXPECTATION_ANY`)* | &mdash; |
| `advance_refs(..)` | `AdvanceRefs` | unary |
| `pack_exists(key)` | `PackExists` | unary |
| `upload_pack(bytes, key)` | `UploadPack` | client-streaming |
| `download_pack(key)` | `DownloadPack` | server-streaming |
| `upload_blob(bytes, key)` (default impl: delegates to `upload_pack`) | *(none &mdash; client calls `UploadPack`)* | &mdash; |
| `download_blob(key)` (default impl: delegates to `download_pack`) | *(none &mdash; client calls `DownloadPack`)* | &mdash; |

`write_ref` and the blob verbs are `Transport`-trait-level default
methods that delegate to another trait method **before any transport
implementation runs** (see `protocol.rs`'s doc comments on each). The
wire therefore never distinguishes "pack" from "auxiliary blob," or
"unconditional write" from "CAS write with `expectation = ANY`" &mdash; a
Connect server implementing the seven wire RPCs above (§2's table)
gets every `Transport` trait verb for free through the client-side
default impls, exactly as every other transport already does.

Endpoints follow the standard Connect convention:
`POST /mkit.transport.v1.TransportService/<Method>`.

---

## 3. CAS semantics &mdash; `UpdateRef`

Identical in spirit to [SPEC-TRANSPORT §4.2.1](SPEC-TRANSPORT.md#421-updateref-cas-encoding)
and `mkit.repo.v1.RepoService.UpdateRef`, expressed as a Connect
unary call instead of an `SshFrame` or a JSON body:

| `RefWriteCondition` | `RefExpectation` | `expected_id` | Semantics |
|---|---|---|---|
| `Any` | `REF_EXPECTATION_ANY` | empty | Last-writer-wins. |
| `Missing` | `REF_EXPECTATION_MISSING` | empty | Create-only; the ref MUST NOT already exist. |
| `Match(h)` | `REF_EXPECTATION_MATCH` | 32-byte digest `h` | Current ref value MUST equal `h`. |

A conforming server MUST reject `REF_EXPECTATION_UNSPECIFIED` (the
proto zero value) with Connect code `invalid_argument` &mdash; mkit is
alpha (pre-1.0); there is no back-compat surface for a client that
omits `expectation`.

Unlike the SSH wire's `Error.details` (an opaque, not-client-consumed
carrier for the current ref value, per SPEC-TRANSPORT §4.2.1) and
`mkit.repo.v1.UpdateRefResponse.current_id` (which *is*
client-consumed), `UpdateRefResponse` on this service carries **no**
current-value field at all: a CAS failure is a Connect error
(`failed_precondition`), full stop. This is a deliberate
simplification, not an oversight &mdash; SPEC-TRANSPORT §7 already requires
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

## 4. Atomic two-ref advance &mdash; `AdvanceRefs`

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
ADVANCE_OUTCOME_COMMITTED`, not a Connect error &mdash; unlike `UpdateRef`,
`advance_refs`'s Rust signature already returns a typed enum rather
than a boolean success/CAS-conflict split (see
`protocol.rs`'s `AdvanceOutcome`), so the wire follows the same shape
instead of forcing a three-way outcome through a two-way (success /
error) channel.

Per `Transport::supports_atomic_advance`'s doc comment, a server
backed by a transactional ref store (a single Durable Object
transaction, a database transaction) SHOULD commit both writes
atomically and MUST advertise this out-of-band to the client (the
Connect service itself carries no `supports_atomic_advance` RPC &mdash; a
deployment either documents its guarantee or a client configuration
flag records it, mirroring how `Transport::supports_atomic_advance()`
is a Rust-level trait method today, not a wire negotiation). A
non-transactional server MUST fall back to the same
packmap-then-head ordering the trait's default `advance_refs`
implementation uses, and MUST NOT advertise atomic support if it
uses that fallback.

---

## 5. Error taxonomy &mdash; `TransportError` to Connect code

Connect carries structured errors natively (a code plus a message),
so &mdash; unlike the SSH wire's hand-rolled `mkit.rpc.v1.Error` message,
needed because raw stdio framing has no ambient error channel &mdash; this
service defines **no** custom error message type. Every
[`TransportError`](../../rust/crates/mkit-core/src/protocol.rs) variant
maps onto a standard Connect code:

| `TransportError` | Connect code | Raised by |
|---|---|---|
| `PackNotFound` | `not_found` | `DownloadPack` before any chunk is sent; `PackExists` never raises this (it returns `exists = false` instead). |
| `AccessDenied` | `permission_denied` | Any RPC, when the deployment's auth layer (§7) rejects the caller. |
| `RefConflict` | `failed_precondition` | `UpdateRef` / the relevant half of `AdvanceRefs` on a CAS mismatch. |
| `InvalidRef` | `invalid_argument` | Any RPC taking a ref name that fails SPEC-REFS §3. |
| `ConnectionFailed` | *(not server-raised &mdash; client-observed transport failure, for example TCP reset, deadline exceeded)* | &mdash; |
| `ServerError{status}` | `unavailable` (5xx-equivalent) or `resource_exhausted` (429-equivalent) | Deployment-specific overload / backend failure. |
| `InvalidResponse` | *(not server-raised &mdash; client-observed: malformed frame, wrong message on a streamed oneof, digest mismatch on `DownloadPack`)* | &mdash; |
| `ProtocolError` | `invalid_argument` | A client-streaming call whose `header` is missing, arrives after a `chunk`, or whose declared/received byte counts disagree (§6). |
| `PayloadTooLarge` | `resource_exhausted` | `UploadPack` header `total_bytes` (or the observed stream length) exceeds the server's cap. |
| `InsecureScheme` | *(not applicable &mdash; URL-scheme concern, handled client-side before any RPC is made; see SPEC-TRANSPORT §3)* | &mdash; |
| `RemoteError(String)` | `unknown` (server-raised, deployment-specific advisory failure with no more specific code applies) &mdash; also the client-side **default** target for any Connect code this table does not otherwise list (`internal`, `aborted`, `unauthenticated`, …), matching the variant's existing "catch-all" contract in `protocol.rs`. | A deployment-specific backend failure that does not fit any row above. |

A conforming client's Connect-to-`TransportError` mapping is the
mechanical inverse of this table, with `RemoteError(String)` as the
fallback arm for any Connect code not otherwise listed &mdash; the mapping
is total in both directions, never a partial match. `is_retryable`
(SPEC-TRANSPORT §7) continues to apply unchanged once translated:
`unavailable` and `resource_exhausted` are retryable, everything else
is not.

---

## 6. Pack transfer streaming

`UploadPack` (client-streaming) and `DownloadPack` (server-streaming)
carry [`PackChunk`](../../proto/mkit/transport/v1/transport.proto),
which duplicates
[`mkit.rpc.v1.ssh.PackChunk`](../../rust/crates/mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto)'s
field layout exactly (`pack_id`, `offset`, `data`, `last` &mdash; same
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

The server MUST reject the stream &mdash; before returning
`UploadPackResponse`, and MUST NOT create or overwrite the destination
pack on rejection &mdash; if:

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

### 6.3 Streaming on Cloudflare Workers &mdash; design answer and open risk

The reference Worker (§7.1) is the one deployment target where
Connect streaming has a known, previously-hit failure mode:
`apps/repo-worker/README.md` §"WatchRefs / streaming (issue #705, building on the #697 spike)"
documents that `worker::WebSocket::events()` returns a **borrowed**
`EventStream<'ws>`, which cannot satisfy a generated server-streaming
trait method's `'static + Send` `ServiceStream<T>` bound &mdash; that
constraint is why `mkit.repo.v1.RepoService.WatchRefs` is served over
a hand-rolled WebSocket instead of Connect server-streaming today.

`DownloadPack` faces the identical shape of problem (server-to-client
streaming on Workers), and the M2 Task 0 spike (mkit#697) prototyped
the design answer this document specifies: bridge the source of
events (there, a Durable Object `/watch` WebSocket; for `DownloadPack`,
a chunked read from R2/filesystem) into an **owned**
`futures_channel::mpsc` channel, drained by a
`wasm_bindgen_futures::spawn_local` task, so the channel's `Receiver`
&mdash; not the borrowed source stream &mdash; is what gets boxed into the
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
end-to-end regardless of how the RPC handler itself produces chunks &mdash;
the response construction MUST use a true streaming response
(`Response::from_stream` or equivalent) instead of collect-then-return.

**Known risk, not yet resolved:** the spike verified the bridge
mechanically (the DO WebSocket opens, drains real events, and
translates them correctly inside `wasm_bindgen_futures::spawn_local`)
and verified `cargo check --target wasm32-unknown-unknown` compiles
clean, but did **not** verify client-visible delivery end-to-end over
HTTP &mdash; a test client received zero bytes even after the bridge
processed a real event, against a local `wrangler dev` run, with the
root cause (a `wrangler dev` limitation vs. a remaining adapter bug)
not isolated. This document specifies the bridge as the correct
*design*, informed by the mechanical proof; it does not claim the
design is proven to deliver bytes to a real client yet. The reference
Worker issue (mkit#699) and the streaming pack transfer issue
(mkit#702) MUST re-verify end-to-end delivery (ideally against a real
Cloudflare deployment, not only `wrangler dev`) before either is
considered done &mdash; a proto/spec review is not a substitute for that
runtime verification.

`mkit serve` (§7.2) and the native CLI client (§7.3) run outside
Workers (axum/hyper and Tokio respectively) and are not subject to the
non-`'static` `WebSocket::events()` constraint at all &mdash; the bridge
above is a Workers-specific workaround, not a general requirement of
this protocol.

---

## 7. Deployment targets

One proto, one generated codebase, three consumers &mdash; no per-target
dialect:

### 7.1 Reference Worker

A `connectrpc` and `workers-rs` service
([`apps/vcs-worker`](../../apps/vcs-worker), mkit#699), reusing
`apps/repo-worker`'s proven patterns: vendored `generated/` staged by
`build.rs` (`MKIT_TRANSPORT_CODEGEN=1` to regenerate via
`connectrpc-build` against the canonical
`proto/mkit/transport/v1/transport.proto`, no protoc dependency on the
default build path &mdash; Cloudflare Workers Builds and CI images lack a
protoc new enough for `edition = "2023"`), R2 for pack storage, and a
single global Durable Object for ref CAS (one Worker deployment = one
repository &mdash; no per-project room split). Unlike `repo-worker`'s
open-write demo, all mutating procedures require the versioned signed-write
contract below. This verifies the writer's identity; it does not impose an
allow-list. The deployment config supplies `AUTH_AUDIENCE` (exact canonical
HTTP(S) origin) and `AUTH_REPOSITORY` (the single repository identity).
Repo Worker instead obtains the repository identity from the decoded room;
Keys Worker uses `keys`. Host or forwarded request headers MUST NOT establish
the server's trusted audience.

#### Auth v2 contract

All producers and verifiers MUST use the following eight newline-separated
UTF-8 fields, with no final newline:

```text
mkit-write:v2
<audience>
<repository>
<full procedure>
<content commitment>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

The signature is strict Ed25519 over the 32-byte BLAKE3 of those bytes. The
origin is the URL's lowercase ASCII HTTP(S) origin with no userinfo, path,
query, fragment, trailing dot, or default port. Repository and procedure are
nonempty printable ASCII fields; newlines and whitespace are rejected. The
shared `mkit_core::write_auth` validator enforces bounded canonical fields.
A unary commitment is `body:<64 lowercase hex BLAKE3 of exact request bytes>`.
An UploadPack commitment is `pack:<64 lowercase hex pack id>:<decimal byte count>`.
The streaming handler MUST compare both fields with the first UploadPack
header before reserving quota or reading chunks, and verify the actual byte
count and BLAKE3 before publishing the immutable object.

Required headers are `X-Envelope-Version: 2`, `X-Audience`, `X-Repository`,
`X-Content-Commitment`, `X-Created-At`, `X-Expires-At`, `Idempotency-Key`,
`X-Public-Key`, and `X-Signature`; unary requests additionally carry `X-Digest`
matching the body commitment. Nonces are 32 cryptographically random bytes
encoded as 64 lowercase hexadecimal characters, generated once per logical
operation and retained with timestamps across every transport retry.
The validity interval MUST be positive and at most 300,000 ms; sender clocks
may lead the server by at most 30,000 ms. Expired requests MUST be rejected,
including requests whose results remain cached. Missing or unsupported auth
versions MUST fail closed.

A valid signature alone is insufficient replay protection. Each service MUST
persist a nonce reservation scoped to audience/repository/signer, together
with the full authenticated operation fingerprint. Reusing a nonce for a
different operation MUST fail. Same-operation retries MUST return the saved
result and MUST NOT repeat mutable effects or charge quota again. Nonce,
quota, reference changes (including both AdvanceRefs writes), chat sequence,
and reaction toggles MUST commit in one explicit SQLite transaction. A
transaction failure rolls them all back; broadcasts occur only after commit.
Replay records MUST remain until the signed expiry has passed.

Immutable object publication uses a durable pending reservation that charges
quota once, followed by a conditional content-addressed R2 put and a durable
result finalization. An interruption after reservation or publication is
resumed by the same signed operation. Concurrent finalizers return the first
saved result. An unreachable ledger or failed quota read fails closed.

`AUTH_AUDIENCE` must be explicitly configured for every deployment and local
development origin.

### 7.2 `mkit serve`

The same generated `TransportService` trait, served over axum/hyper
(mkit#700) instead of `workers-rs` &mdash; `connectrpc` supports both
server backends from one generated trait, so the RPC handler logic is
shareable in principle even though the two deployments' storage
backends differ (R2 and DO vs. local filesystem and `flock`, per
[SPEC-WORKTREE](SPEC-WORKTREE.md)/[SPEC-CONCURRENCY](SPEC-CONCURRENCY.md)).
This gives the CLI's `serve` command an HTTP mode alongside its
existing SSH-frame stdio and `--listen-enc` modes
(`rust/crates/mkit-cli/src/commands/serve/mod.rs`).

### 7.3 Native CLI Connect client

**Implemented** (mkit#701):
[`mkit-transport-connect`](../../rust/crates/mkit-transport-connect/), a
non-wasm Rust crate mirroring
[`mkit-repo-client`](../../rust/crates/mkit-repo-client/Cargo.toml)'s
"zero-duplication" codegen approach: compiled directly from the
canonical `proto/mkit/transport/v1/transport.proto` via a
workspace-relative path in `build.rs`, never a hand-copied proto or a
hand-rolled URL builder. It differs from `mkit-repo-client` only in
target: native (Tokio, `connectrpc`'s HTTP/native-TLS client
transport, TLS trust via `webpki-roots`) rather than wasm (Fetch API,
`wasm-bindgen`), so it drops the wasm-only dependencies
(`wasm-bindgen`, `web-sys`, `send_wrapper`) and enables `connectrpc`'s
native client features instead. `ConnectTransport` bridges the
synchronous `Transport` trait to the async generated client via
`mkit_core::protocol::async_shim::Executor` (a dedicated tokio runtime
per instance), mirroring `mkit-transport-enc`'s `TokioExecutor`.

This crate is now the implementation `mkit-cli`'s `remote_dispatch`
constructs for the `mkit+https://` scheme (and loopback-only
`mkit+http://`), replacing `mkit-transport-http` there &mdash; see
`rust/crates/mkit-cli/src/remote_dispatch/mod.rs`. `mkit-transport-http`
itself is NOT deleted (its `sparse-checkout`/`pack-shards` extensions
have no `mkit.transport.v1` equivalent yet, §8), so SPEC-TRANSPORT §5 is
marked superseded rather than removed.

**Auth modes** (mkit#699 follow-up, closing the gap this document
originally flagged in "Reference implementation" above):
`ConnectTransport` supports two independent, additive write-auth modes &mdash;
a deployment can require either, both, or neither:

- **Bearer token** (unchanged, #700/#701): `MKIT_API_TOKEN`, read from
  the environment at `connect()` time, sent as `Authorization: Bearer
  <token>` on every call. This is `mkit-transport-http`'s scheme
  (SPEC-TRANSPORT §5.2) and is what `mkit serve --http` (§7.2) expects.
- **Ed25519 write envelope**: `EnvelopeTransport` signs the auth v2 contract
  in §7.1, with an exact request body commitment for unary writes and the
  declared pack id and length for streaming writes. `transport_auth = envelope`
  is user-scoped and repository-forbidden. The CLI requires exact user-scoped
  `trusted_remote_endpoint` approval before resolving the commit-signing
  Ed25519 identity, independently of bearer-token presence. Domain separation
  alone does not grant a repository permission to invoke ambient signing.

Verified live: real `mkit push`/`clone`/`pull` (envelope auth) against a
local `wrangler dev` instance of `apps/vcs-worker` &mdash; see
`apps/vcs-worker/README.md` "Known limitations".

One deliberate gap from full HTTP-transport parity: `ConnectTransport::
supports_atomic_advance()` defaults to `false` (opt in via
`with_atomic_advance(true)`), where `HttpTransport::
supports_atomic_advance()` always returned `true`. SPEC-TRANSPORT-CONNECT
§4 requires a client to only claim atomicity a deployment has actually
documented; since no reference Connect server (mkit#699) exists yet to
confirm a transactional `AdvanceRefs`, the safe default means pushes over
`mkit+https://` take the ordered (non-atomic) `advance_refs` fallback and
do not re-baseline/reset the packmap chain &mdash; `remote_dispatch::
push_branch`'s re-baseline gate already requires `supports_atomic_advance()
== true` before resetting (mkit#521), so this is a (temporary) loss of
the packmap-compaction optimization, not a correctness gap. Revisit once
mkit#699 ships a confirmed-transactional backend.

Every `Transport` method `ConnectTransport` implements is driven through
the same `mkit_core::protocol::retrying`/`BackoffIterator` ladder
`mkit-transport-http`/`-ssh`/`-enc` share (mkit#703, mkit#790): a
transient `ConnectionFailed` or the Connect codes §5 maps onto a
5xx/429-equivalent (`unavailable`, `resource_exhausted`) is retried per
SPEC-TRANSPORT §7's `is_retryable` classification, read off the
`TransportError` §5's client-side mapping produces rather than directly
off an HTTP status. Each retry re-issues the whole RPC from scratch
(including, for `DownloadPack`, a fresh stream) &mdash; nothing from a failed
prior attempt is reused. Mutating CAS ops (`UpdateRef`/`AdvanceRefs`) are
safe to retry unconditionally because `is_retryable` excludes
`TransportError::RefConflict`; a CAS conflict is never retried here &mdash; that
stays caller-level policy.

The regression tests
(`rust/crates/mkit-transport-connect/tests/roundtrip.rs`,
`tests/retry.rs`) drive every `Transport` verb &mdash; including multi-chunk
`UploadPack`/`DownloadPack` streaming, all three `AdvanceOutcome`
variants, and the retry ladder itself (a flaky in-process server that
fails the first N calls with a retryable error class, and a
non-retryable-error/ladder-exhaustion pair) &mdash; through a real in-process
`TransportService` server (memory-backed, not R2/DO), per this issue's
testing decision: a real server, not a mock standing in for one.

---

## 8. Out of scope

This document specifies the proto and its consumption pattern only.
Explicitly deferred to sibling issues:

- The reference Worker implementation (mkit#699).
- `mkit serve`'s HTTP mode (mkit#700).
- ~~The native CLI Connect client (mkit#701).~~ Implemented &mdash; see §7.3.
- Fully deleting `mkit-transport-http` and SPEC-TRANSPORT §5 (waits on a
  `mkit.transport.v1` equivalent for its `sparse-checkout`/`pack-shards`
  extensions, not just core-verb parity &mdash; see §7.3).
- ~~The shared retry/backoff Connect interceptor (mkit#703).~~ Implemented
  directly in `ConnectTransport` (mkit#790) &mdash; see §7.3.
- S3 multipart upload (unrelated transport; not superseded by this
  document at all).
- Migrating `mkit.repo.v1.WatchRefs` to real Connect server-streaming
  using the bridge pattern in §6.3 (a `mkit.repo.v1` change, not a
  `mkit.transport.v1` one &mdash; tracked separately).
- End-to-end runtime verification of the `DownloadPack` streaming
  bridge (§6.3's known risk) &mdash; this is a proto/design review gate, not
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

The acceptance gate for this document itself is static, not behavioral:

- `buf lint` (`STANDARD` category) against `proto/mkit/transport/v1/transport.proto` &mdash; zero errors, zero lint exceptions.
- `buf breaking` initialized (`breaking.use: [FILE]` in `buf.yaml`, §1) as the baseline for every future change to this module.
- The proto compiles cleanly through the real `buffa`/`connectrpc-build` codegen path (not just `protoc`) &mdash; verified by generating and compiling the full client and server stub set (`TransportService`, `TransportServiceClient`, every request/response/`oneof` message) against `buffa 0.9.1`/`connectrpc 0.9`/`connectrpc-build 0.9`, mirroring the exact `include_generated!()` pattern `mkit-repo-client`/`apps/repo-worker` use.
- Explicit maintainer sign-off on the RPC shapes in this document, per the originating issue's Testing Decisions.

mkit#699/#700/#701 each own their own runtime test anchors (integration
tests against a real or locally-hosted server); this document is not
amended to list them. mkit#701 (§7.3) is the first to land one:
`rust/crates/mkit-transport-connect/tests/roundtrip.rs` runs a real
in-process `TransportService` server and drives every `Transport` verb
through it via the generated client &mdash; see §7.3 for what it does and
does not prove (a memory-backed in-process server, not the R2/DO
reference Worker).

---

## 11. Invariants

| Invariant | Enforced by |
|---|---|
| Every `Transport` trait verb has exactly one corresponding wire RPC, or is a documented client-side default-impl delegation with no independent wire shape. | §2's mapping table; `protocol.rs`'s default-impl doc comments. |
| `RefExpectation`'s wire numbers (`ANY=1`, `MISSING=2`, `MATCH=3`) never change, even after mkit#679 extracts a shared proto. | `buf breaking` (`FILE` category, §1); the `RefExpectation` doc comment matching `ssh.proto`'s "do NOT renumber" contract. |
| A rejected `UploadPack` stream never creates or overwrites the destination pack. | §6.1's server-side rejection checks, mirroring SPEC-TRANSPORT §4.2's SSH requirement. |
| `DownloadPack` never sends a partial stream silently &mdash; it either completes with `chunk.last = true` or fails the whole call before any message is sent. | §6.2. |
| Every `TransportError` variant a server can raise has exactly one Connect code it maps to; a client's inverse mapping is mechanical, not heuristic. | §5's table. |
| An `AdvanceRefs` conflict is a typed response value, never a Connect error. | §4 &mdash; matches `AdvanceOutcome`'s three-variant, no-error-variant shape in `protocol.rs`. |
| The `DownloadPack` Workers-streaming design is documented as unverified end-to-end until a sibling issue proves real client-visible delivery. | §6.3's "Known risk" paragraph; mkit#699/#702's re-verification requirement. |
