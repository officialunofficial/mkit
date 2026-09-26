---
spec: SPEC-TRANSPORT-CONNECT
version: 2
status: draft-normative
audience: implementers of mkit.transport.v1 Connect servers and clients (reference Worker, `mkit-server`, native CLI transport)
---

# SPEC-TRANSPORT-CONNECT &mdash; mkit.transport.v1, the canonical Connect remote protocol

Status: **Draft**, version 2. Version 1 defined a single-repository
service: one deployment served one repository, and a valid auth v2
signature was enough to write. Version 2 is a semantic revision of the
same wire package. It adds multi-repository addressing (§7.4), namespace
and write policy (§7.5), `GetServerInfo` (§2.1), upload tickets and
resumable parts (§7.6), ref deletion (§7.8), the consistency and
paging rules of a sharded server (§7.9), admission challenges (§5.1),
and the per-RPC upload lifecycle (§7.7). `mkit.transport.v1` evolves
additively: v2 adds RPCs and fields and never renumbers or removes one,
so `buf breaking` stays green. The breaks are semantic only. mkit is
pre-production (CONTRIBUTING, "Pre-production compatibility policy"), so
v2 has no v1 compatibility machinery: no v1 reader, no negotiation, and
no fallback mode. The proto messages v2 names land with the M1
implementation, and the admission messages with the M3 implementation
(§8); until then the implementations described under
"Reference implementation" below implement the v1 surface only. §9
records the version history.

Scope: the `mkit.transport.v1.TransportService` Connect service &mdash; its
proto shape, verb-to-trait mapping, CAS semantics, error-code mapping,
pack-transfer streaming design, repository addressing, write
authorization policy, upload tickets, admission challenges, and read
consistency &mdash; and how
the deployment targets (reference Worker, `mkit-server`, native CLI
client) consume one generated codebase. It does not cover S3 multipart,
the `WatchRefs` live-feed migration, pricing or payment verification,
or any server/client implementation; those are separate changes (§8).
Write and read grants, epochs, signed reads, and private repositories
are [SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md)'s.

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
Object. The self-hosted server is `mkit-server` (§7.2), whose
`mkit-server-native/tests/client_e2e.rs` drives the same client against it
end to end; it replaced `mkit serve --http`, which the CLI no longer has.
[`apps/vcs-worker`](../../apps/vcs-worker) (mkit#699)
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
`mkit-server serve --auth bearer`) and this server's Ed25519 write envelope (§7.1) as
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
| *(none &mdash; deployment discovery, M1)* | `GetServerInfo` (§2.1) | unary |
| *(none &mdash; upload ticket, M1)* | `BeginUpload` (§7.6) | unary |
| *(none &mdash; one part of a ticketed upload, M1)* | `UploadPart` (§7.6) | client-streaming |
| *(none &mdash; completes a multipart upload, M1)* | `CompleteUpload` (§7.6) | unary |
| *(none &mdash; reads a namespace's grant epoch, M2)* | `GetGrantEpoch` ([SPEC-WRITE-GRANTS §5.3](SPEC-WRITE-GRANTS.md#53-rpcs)) | unary |
| *(none &mdash; raises a namespace's grant epoch, M2)* | `SetGrantEpoch` ([SPEC-WRITE-GRANTS §5.3](SPEC-WRITE-GRANTS.md#53-rpcs)) | unary |
| *(none &mdash; sets a repository's visibility, M2)* | `SetRepoVisibility` ([SPEC-WRITE-GRANTS §9.1](SPEC-WRITE-GRANTS.md#91-visibility)) | unary |
| *(none &mdash; mints a signed URL token, M2)* | `IssueObjectUrl` ([SPEC-WRITE-GRANTS §9.4](SPEC-WRITE-GRANTS.md#94-signed-url-tokens)) | unary |

`write_ref` and the blob verbs are `Transport`-trait-level default
methods that delegate to another trait method **before any transport
implementation runs** (see `protocol.rs`'s doc comments on each). The
wire therefore never distinguishes "pack" from "auxiliary blob," or
"unconditional write" from "CAS write with `expectation = ANY`" &mdash; a
Connect server implementing the seven wire RPCs above (§2's table)
gets every `Transport` trait verb for free through the client-side
default impls, exactly as every other transport already does.

The four rows marked "M1" are v2 additions. They have no `Transport`
trait verb: they are deployment discovery and the ticketed upload
protocol, which a client drives around the seven verb RPCs. Their proto
messages land with the M1 implementation (§8), additively. The four rows
marked "M2" are SPEC-WRITE-GRANTS additions for grant epochs, repository
visibility, and URL tokens; their proto messages land with the M2
implementation, additively.

Endpoints follow the standard Connect convention:
`POST /mkit.transport.v1.TransportService/<Method>`.

### 2.1 `GetServerInfo`

`GetServerInfo` tells a client what a deployment supports before the
client relies on it. The request is empty. It MAY carry `X-Repository`
(§7.4). The response MUST NOT depend on whether that repository exists,
so it is never an existence oracle (§7.4, isolation).

The call is unauthenticated: a server MUST answer it without auth v2
headers or a bearer token. The response MAY be cached with
`Cache-Control: private, max-age=<n>` where `n` is at most 60 seconds.

`GetServerInfoResponse` carries these fields:

| Field | Meaning |
|---|---|
| `protocol` | The wire package, `mkit.transport.v1`. |
| `spec_version` | This document's version, `2`. |
| `max_pack_bytes` | The largest pack the deployment accepts. A deployment MAY advertise a lower value in indexed mode than in opaque mode, for example on a runtime with tight CPU limits. |
| `part_size` | The part size for resumable uploads (§7.6): a power of two, at least 8 MiB. |
| `max_parts` | The largest number of parts in one upload (§7.6). |
| `max_list_refs_page_size` | The largest number of refs one `ListRefs` page returns (§7.9). |
| `begin_upload_threshold_bytes` | Packs smaller than this MAY skip `BeginUpload` (§7.6). It is `0` on every multi-repository deployment and whenever `admission` is true. On a single-repository deployment without admission, the value is deployment-defined. |
| `atomic_advance` | Whether `AdvanceRefs` commits the head and packmap atomically (§4). |
| `indexed_mode` | Whether the deployment decodes and verifies pushed packs before refs move. |
| `admission` | Whether the deployment runs an admission step that can challenge a request (§5.1). When it is true, `begin_upload_threshold_bytes` is `0`. |
| `receipt_public_key`, `receipt_key_id` | The key that signs storage receipts, and its key id. Empty until storage receipts are specified. |
| `grant_schemes` | The owner signature schemes the deployment accepts on grants and epoch statements ([SPEC-WRITE-GRANTS §4](SPEC-WRITE-GRANTS.md#4-owner-signature-schemes)). Empty on a deployment that accepts no grants. |
| `namespace_policy` | `allowlist`, `any`, or `single-repository` (§7.5). `single-repository` is advertised, never configured. |
| `index_fanout` | The fixed object-id-prefix fan-out of the deployment's repository index (§7.9). The default is 4096. |

A client MUST NOT assume atomic advance without `atomic_advance = true`
from this call. `atomic_advance` replaces the client-side opt-in of v1
(§7.3): a client reads it here instead of from local configuration.

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
atomically and MUST advertise this through `GetServerInfo`'s
`atomic_advance` field (§2.1). A non-transactional server MUST fall
back to the same packmap-then-head ordering the trait's default
`advance_refs` implementation uses, and MUST NOT advertise atomic support if it
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
| `AccessDenied` | `permission_denied`; a client also maps `unauthenticated` to `AccessDenied`. | Any RPC, when the deployment's write or namespace policy (§7.5) rejects an authenticated caller, or a ticket does not bind to the request (§7.6). |
| `RefConflict` | `failed_precondition` | `UpdateRef` on a CAS mismatch, including deletion of an absent ref (§7.8). `AdvanceRefs` reports its conflicts as typed outcomes (§4), never as this error. |
| `InvalidRef` | `invalid_argument` | Any RPC taking a ref name that fails SPEC-REFS §3, or (`ReadRef`, `UpdateRef`, either name of `AdvanceRefs`) a name outside `refs/`, which a server does not serve (SPEC-REFS §2); that message starts `ref name must start with refs/`. |
| `ConnectionFailed` | *(not server-raised &mdash; client-observed transport failure, for example TCP reset, deadline exceeded)* | &mdash; |
| `ServerError{status}` | `unavailable` (5xx-equivalent), `resource_exhausted` (429-equivalent), or `aborted` (a client maps it to `ServerError{status: 503}`) | Deployment-specific overload / backend failure; `aborted` also answers a retry of an operation that is still in flight (§7.1). |
| `InvalidResponse` | *(not server-raised &mdash; client-observed: malformed frame, wrong message on a streamed oneof, digest mismatch on `DownloadPack`)* | &mdash; |
| `ProtocolError` | `invalid_argument` | A client-streaming call whose `header` is missing, arrives after a `chunk`, or whose declared/received byte counts disagree (§6). |
| `PayloadTooLarge` | `resource_exhausted` | `UploadPack` header `total_bytes` (or the observed stream length) exceeds the server's cap. |
| `AdmissionRequired{challenges, description}` | `permission_denied`, sent with HTTP status 402 and exactly one `AdmissionChallenge` detail (§5.1). A client also maps any HTTP 402 response to this variant. | A unary RPC that the deployment's admission step challenges (§5.1). Never retried. |
| `InsecureScheme` | *(not applicable &mdash; URL-scheme concern, handled client-side before any RPC is made; see SPEC-TRANSPORT §3)* | &mdash; |
| `RemoteError(String)` | `unknown` (server-raised, deployment-specific advisory failure with no more specific code applies) &mdash; also the client-side **default** target for any Connect code this table does not otherwise list (`internal`, `data_loss`, …), matching the variant's existing "catch-all" contract in `protocol.rs`. | A deployment-specific backend failure that does not fit any row above. |

A conforming client's Connect-to-`TransportError` mapping is the
mechanical inverse of this table, with `RemoteError(String)` as the
fallback arm for any Connect code not otherwise listed &mdash; the mapping
is total in both directions, never a partial match. Before it applies
the table, a client checks for admission: an HTTP 402 response, or a
`permission_denied` error that carries an `AdmissionChallenge` detail,
maps to `AdmissionRequired`, never to `AccessDenied` (§5.1).
`is_retryable` (SPEC-TRANSPORT §7) continues to apply once translated:
`unavailable`, `resource_exhausted`, and `aborted` are retryable, and
everything else is not. `AdmissionRequired` is never retryable.

Authentication, authorization, addressing, ticket, and storage
failures map to these codes. The `Condition` column is what the server
observed. A v2 client maps `failed_precondition` on `BeginUpload`,
`UploadPart`, `CompleteUpload`, a ticketed `UploadPack`, or an
`AdvanceRefs` carrying `ticket_ids` to a ticket failure, which it
resolves by calling `BeginUpload` again, never to `RefConflict`.

| Condition | Connect code |
|---|---|
| On an RPC that requires auth v2: a missing, malformed, or expired envelope, a bad signature, a missing `X-Repository`, or an `X-Repository` that differs from the signed `<repository>` (§7.4) | `unauthenticated` |
| An authenticated principal that the namespace or write policy does not authorize (§7.5) | `permission_denied` |
| A ticket whose audience, repository, signer, `pack_id`, or byte count differs from the request (§7.6) | `permission_denied` |
| A malformed repository identity, or a missing `X-Repository` on an unsigned RPC to a multi-repository deployment (§7.4) | `invalid_argument` |
| A read RPC on a repository that does not exist (§7.4) | `not_found` |
| A signed read whose auth v2 envelope fails verification ([SPEC-WRITE-GRANTS §9.2](SPEC-WRITE-GRANTS.md#92-signed-reads)) | `unauthenticated` |
| A grant that does not authorize a write, including an epoch mismatch found at `apply` ([SPEC-WRITE-GRANTS §11](SPEC-WRITE-GRANTS.md#11-error-codes)) | `permission_denied` |
| Any unauthorized read of a private repository ([SPEC-WRITE-GRANTS §9.3](SPEC-WRITE-GRANTS.md#93-read-authorization)), indistinguishable from a missing repository | `not_found` |
| An expired, unknown, or missing ticket, or a ticket presented to an advance of a ref it does not name (§7.6) | `failed_precondition` |
| A part whose subtree hash or length differs from its commitment, or a completion whose merged root or total differs from the ticket (§7.6) | `invalid_argument` |
| A pack still under verification in indexed mode (§7.6) | `unavailable` |
| A missed commit deadline (`NotAfter`), a full shard, or outbox backpressure. Nothing commits, and a retry with the same nonce is safe. | `unavailable`, never `resource_exhausted` |
| A signed nonce already recorded with a different operation fingerprint (§7.1) | `invalid_argument` |
| A signed nonce whose operation is still `in_flight` (§7.1). The request never reaches admission. | `aborted` (retryable) |
| A new operation that the admission step challenges (§5.1) | `permission_denied` with HTTP status 402 and one `AdmissionChallenge` detail |
| A new operation that the admission step denies outright (§5.1) | `permission_denied`, with no `AdmissionChallenge` detail, with its default HTTP status 403, never 402 |

`failed_precondition` is a CAS conflict only on `UpdateRef`. On the
RPCs above, and on an `UploadPack` that needed a ticket and carried
none, it is a ticket failure (§7.6), which a client MUST NOT treat as a
ref conflict. No ticket failure is `resource_exhausted`,
because clients retry that code on the backoff ladder. For the same
reason, no admission challenge or denial is `resource_exhausted`.

### 5.1 Admission challenges

A server MAY refuse a request until the caller does something outside
this protocol. Examples are a payment, a quota top-up, or verifying an
email address. A plain `resource_exhausted` cannot express this,
because clients retry it on a backoff ladder. A plain
`permission_denied` cannot express it either, because it gives the
caller nothing to act on. An admission challenge is a
`permission_denied` error that tells the caller what to do.

mkit registers no challenge schemes and interprets none. Payment
protocols such as MPP (the Machine Payments Protocol) and x402 define
their own challenges, credentials, and receipts. This section defines
only how they travel through `mkit.transport.v1` and which headers a
client may attach in reply. Pricing, payment verification, and
settlement belong to the deployment.

**Error.** The server answers a challenged request with HTTP status
402 and a Connect error body whose code is `permission_denied`. The
body carries exactly one error detail of type
`mkit.transport.v1.AdmissionChallenge`:

```proto
message AdmissionChallenge {
  repeated Challenge challenges = 1; // 1 to 8 entries, in the server's order of preference
  string description = 2;            // text for a person; at most 512 bytes of UTF-8
}

message Challenge {
  string scheme = 1; // lowercase token: [a-z0-9][a-z0-9.-]{0,63}
  string value = 2;  // opaque to mkit; at most 8,192 bytes
}
```

The proto messages land additively with the M3 implementation (§8).
Each `Challenge` is opaque: `scheme` names the external protocol that
interprets `value`, and a challenge defined by another protocol can
travel unchanged in `value` (informative: a deployment can mirror each
`WWW-Authenticate: Payment` challenge it sends as one entry). A client
treats a detail that breaks these bounds, or a second
`AdmissionChallenge` detail, as `InvalidResponse`. No RPC response
message carries an admission result; a challenge is only ever this
error.

A client that predates this section maps the error to `AccessDenied`
and fails at once instead of retrying, because the code is
`permission_denied` (§5).

**Header pass-through.** The 402 response MAY also carry the raw
challenge headers of the payment protocols the deployment supports:
one or more `WWW-Authenticate: Payment …` fields (MPP) and a
`PAYMENT-REQUIRED` field (x402). The server passes them through as
the deployment's business layer produced them. mkit does not
interpret them.

**Unary RPCs only.** A challenge applies only to unary RPCs, because a
client-streaming RPC reports its status after the client has sent the
whole stream. `GetServerInfo` is never challenged (§2.1), and neither
is the part path (`UploadPart`, `CompleteUpload`, and a ticketed
`UploadPack`, §7.6), whose admission happened at `BeginUpload`. When
the deployment runs admission, `GetServerInfo` advertises
`admission = true` and `begin_upload_threshold_bytes = 0`, so
`BeginUpload` is mandatory for every upload (§7.6). §7.7 states which
RPC of an upload is admitted. Paid bulk downloads are served over
plain HTTP (informative: a forthcoming HTTP-serving specification),
where a 402 is an ordinary response.

**Ordering.** For an operation the deployment authenticates, the
server authenticates before it challenges. For a signed write it
checks the replay ledger and authorizes before admission, in the order
§7.1 fixes, so a retry of a committed operation returns its stored
result and never meets a new challenge. An anonymous operation, such
as a paid public read, MAY be challenged directly.

**No state on challenge.** A challenged request MUST NOT change any
state. The server creates no namespace or repository, reserves no
quota, allocates no ticket, and does not consume the replay nonce. It
never stores a challenge as a replay result (§7.1). A retry with the
same nonce is therefore evaluated as a new operation. A denial
allocates nothing either (§7.5).

**Admission input.** The admission step decides from the operation,
which carries (informative):

- the audience, repository, procedure, and the verified signer, or
  "anonymous";
- the namespace owner and the write authorization used (§7.5);
- `creates_namespace` and `creates_repo`;
- for `BeginUpload`, the `pack_id`, the declared byte count, and the
  bytes new to the repository (known only from membership);
- the idempotency key.

Two rules about this input are normative. The server MUST give the admission
step `creates_namespace` and `creates_repo` (§7.5). It MUST NOT give
the admission step the bytes new to the whole store, because a price
that depends on them would reveal whether other repositories hold the
content (§7.4, isolation). Those bytes are reported only in the
`Committed` outcome (§7.7). Quota scopes that span namespaces, such as
per payer or per signer across namespaces, cannot be atomic on a store
sharded by namespace; a deployment keeps them best-effort, reserves
and reconciles them, or keeps them in its own store (informative).

**Binding (informative).** Binding a challenge to one request, for
example an HMAC over the MPP challenge parameters, an `opaque` value,
or a `digest` over the unary `BeginUpload` body, is the deployment's
job. mkit supplies the fingerprint to bind: the repository, the
signer, the `pack_id`, and the byte count. A retry sends a
byte-identical signed body (§7.1), so a `digest` binding holds across
it.

**Bearer deployments.** A deployment that authenticates callers with
`Authorization: Bearer` MUST advertise `header="Payment-Authorization"`
in every MPP challenge it sends, so the payment credential never
displaces the bearer token.

**Caching.** A 402 response carries `Cache-Control: no-store`. A
response that carries a `Payment-Receipt` field (MPP) or a
`PAYMENT-RESPONSE` field (x402) passes that field through to the client
and carries `Cache-Control: private`.

**CORS.** A deployment that serves browsers exposes the challenge and
receipt headers (`Access-Control-Expose-Headers: WWW-Authenticate,
Payment-Receipt, PAYMENT-REQUIRED, PAYMENT-RESPONSE`) and allows the
credential request headers (`Payment-Authorization`,
`PAYMENT-SIGNATURE`, `Authorization`, and `Accept-Payment`). A preflight `OPTIONS`
request never requires payment.

**Redaction.** Servers and clients MUST keep payment credentials and
receipts out of logs, traces, error messages, and analytics. This
covers every header a client attaches from its admission helper,
`Payment-Receipt`, `PAYMENT-RESPONSE`, and the helper's output.

#### Client behavior

A client builds `AdmissionRequired{challenges, description}` from the
`AdmissionChallenge` detail. A 402 response without that detail, for
example one an intermediary produced, yields an `AdmissionRequired`
with no challenges and an empty description. In both cases the client
also keeps the response's `WWW-Authenticate` and `PAYMENT-REQUIRED`
fields for the helper. The client never parses a `problem+json` or
other non-Connect body, and never retries `AdmissionRequired`
automatically.

A client implementation must keep the HTTP status of an error
response, so that it still recognizes a raw 402 that carries no
Connect detail (informative; an M3 implementation requirement). The
`connectrpc` 0.9 client drops that status when it builds its error
(`client/mod.rs`, lines 2173&ndash;2255). Without a helper it fails the operation and shows the
description and the challenge schemes to the user.

**Admission helper.** A client MAY run a user-configured admission
helper, named by the user-scoped `admission_helper` key:

- Repository configuration MUST NOT set `admission_helper`.
  [SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md#2-per-key-audit)
  classifies it as UNSAFE.
- The client runs the helper only for a remote whose endpoint equals
  the user-scoped `trusted_remote_endpoint`
  ([SPEC-CONFIG-SECURITY §3.4](SPEC-CONFIG-SECURITY.md#34-runtime-credential-and-request-signing-gates)).
- The client runs the helper at most once per logical operation.

The client writes one JSON object to the helper's standard input and
closes it:

```json
{
  "origin": "https://vcs.example",
  "repository": "ed25519-<64 hex>/name",
  "procedure": "/mkit.transport.v1.TransportService/BeginUpload",
  "description": "text from the detail, or empty",
  "challenges": [{ "scheme": "…", "value": "…" }],
  "headers": {
    "www-authenticate": ["Payment id=\"…\", …"],
    "payment-required": ["…"]
  }
}
```

`origin` is the canonical origin of §7.1. `challenges` holds the
detail's entries, in order, and is empty when the 402 had no detail.
`headers` maps each lowercase header name to the list of that field's
values, in the order received; it holds only `www-authenticate` and
`payment-required`, and omits a name the response did not carry.

The helper answers with exit status 0 and one JSON object on standard
output that maps header names to string values:

```json
{ "Payment-Authorization": "Payment eyJ…" }
```

For an MPP challenge the helper returns `Authorization: Payment …`,
or `Payment-Authorization: Payment …` when the challenge sets
`header="Payment-Authorization"`. For an x402 challenge it returns
`PAYMENT-SIGNATURE` (informative). Any other exit status, output that
is not such an object, an empty object, a header name that is not an
HTTP token, two names that differ only in case, or a value that
contains a control character other than horizontal tab aborts the
operation. A header value longer than 8,192 bytes also aborts it.

**Header allowlist.** The client attaches a helper header only if its
name is on the remote's allowlist. Names compare case-insensitively.

- The default allowlist is `Payment-Authorization`,
  `PAYMENT-SIGNATURE`, and `Authorization`. `Authorization` is on it
  only when the client does not already send `Authorization` to that
  remote, that is, when no `MKIT_API_TOKEN` bearer token (§7.3) is
  configured for it.
- The user-scoped `remote.<name>.admission_headers` key adds header
  names to the allowlist of the remote `<name>`
  ([SPEC-CONFIG-SECURITY](SPEC-CONFIG-SECURITY.md#2-per-key-audit)).
- A helper header that is not on the allowlist, or that names a header
  the request already carries, fails the operation. The error names
  that header.

**Hard-reserved headers.** These names are never allowed, whatever the
configuration says. An `admission_headers` entry that names one has no
effect, and the client warns naming it:

- the auth v2 envelope headers `X-Public-Key`, `X-Signature`,
  `X-Digest`, `X-Created-At`, `X-Expires-At`, `X-Envelope-Version`,
  `X-Audience`, `X-Repository`, `X-Content-Commitment`; the write-grant
  header `X-Write-Grant`; `X-Mkit-Ref` (§7.9); every header beginning
  `X-Mkit-`; every `X-Forwarded-*` header;
- `Host`, every `Content-*` header, `Transfer-Encoding`, every
  `Connect-*` header, `Cookie`, `Idempotency-Key`, and `Authorization`
  when the client already sends it to that remote (§7.3);
- the hop-by-hop headers `Connection`, `Keep-Alive`, every `Proxy-*`
  header, `TE`, `Trailer`, and `Upgrade`.

A later mkit specification that defines a request header MUST name it
`X-Mkit-*` or add it to this list.

`mkit config` SHOULD refuse to write a reserved name into
`remote.<name>.admission_headers`. When a client loads such an entry,
it SHOULD warn with this fixed wording, where `<header>` is the entry
and `<name>` the remote:

```text
warning: ignoring reserved header `<header>` in remote.<name>.admission_headers (see SPEC-TRANSPORT-CONNECT §5.1)
```

**Retry.** With the allowed headers attached, the client sends the same
logical operation once more. While the auth v2 envelope is still valid
(at most 300 seconds, §7.1), it reuses the nonce, the timestamps, and
the signed body. After the envelope has expired, it signs a new
operation over the same request body. The helper headers are not part
of the auth v2 canonical string. They stay attached to every transport
retry of that attempt on the backoff ladder. A second challenge for the
same operation fails it; the client does not run the helper again.

**Receipts.** A client keeps a `Payment-Receipt` or `PAYMENT-RESPONSE`
field it receives out of logs and traces, and MAY report it to the
user.

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

`mkit-server` (§7.2) and the native CLI client (§7.3) run outside
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
single global Durable Object for ref CAS. That is a single-repository
deployment in §7.4's terms. A multi-repository deployment shards its
state instead: one namespace coordinator per namespace, one strongly
consistent ref shard per (repository, ref), and eventually consistent
repository index shards (§7.9). Unlike `repo-worker`'s
open-write demo, all mutating procedures require the versioned signed-write
contract below. This verifies the writer's identity. Write authorization,
which decides whether that identity may write to the repository, is §7.5.
The deployment config supplies `AUTH_AUDIENCE` (exact canonical
HTTP(S) origin) and, on a single-repository deployment, `AUTH_REPOSITORY`
(the configured repository identity, §7.4). Repo Worker instead obtains
the repository identity from the decoded room; Keys Worker uses `keys`.
Host or forwarded request headers MUST NOT establish the server's
trusted audience.

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
query, fragment, trailing dot, or default port. `<repository>` is the full
repository identity of §7.4, exactly as `X-Repository` carries it.
Repository and procedure are nonempty printable ASCII fields; newlines and whitespace are rejected. The
shared `mkit_core::write_auth` validator enforces bounded canonical fields.
A unary commitment is `body:<64 lowercase hex BLAKE3 of exact request bytes>`.
An UploadPack commitment is `pack:<64 lowercase hex pack id>:<decimal byte count>`.
An UploadPart commitment is `part:<ticket>:<index>:<subtree-hash>:<len>` (§7.6).
The streaming handler MUST compare both fields with the first UploadPack
header before reserving quota or reading chunks, and verify the actual byte
count and BLAKE3 before publishing the immutable object.

Required headers are `X-Envelope-Version: 2`, `X-Audience`, `X-Repository`,
`X-Content-Commitment`, `X-Created-At`, `X-Expires-At`, `Idempotency-Key`,
`X-Public-Key`, and `X-Signature`; unary requests additionally carry `X-Digest`
matching the body commitment. Nonces are 32 cryptographically random bytes
encoded as 64 lowercase hexadecimal characters, generated once per logical
operation and retained with timestamps across every transport retry.

A request MAY also carry `X-Write-Grant`, a grant that authorizes the
signer ([SPEC-WRITE-GRANTS §4.2](SPEC-WRITE-GRANTS.md#42-header-encoding)).
It is not a signed header: it is not part of the canonical string above,
and the signature does not bind it.

**Signed reads.** The same contract signs read RPCs
([SPEC-WRITE-GRANTS §9.2](SPEC-WRITE-GRANTS.md#92-signed-reads)):
`ListRefs`, `ReadRef`, `PackExists`, `DownloadPack` and `IssueObjectUrl`,
each with a `body:` commitment over the exact request body. A client
that has a signer for a remote MUST sign every read RPC to it. A request that carries any auth v2 header MUST verify in full, or it
is `unauthenticated`. A signed read is idempotent: the server checks the
validity window only, and records and looks up no replay entry, so the
replay rules below apply to writes only. `GetServerInfo`,
`GetGrantEpoch` and `SetGrantEpoch` stay unsigned.

The validity interval MUST be positive and at most 300,000 ms; sender clocks
may lead the server by at most 30,000 ms. Expired requests MUST be rejected,
including requests whose results remain cached. Missing or unsupported auth
versions MUST fail closed.

A valid signature alone is insufficient replay protection. Each service MUST
persist, for every signed write except the replay-exempt uploads of §7.6
(the part path: `UploadPart`, `CompleteUpload`, and a ticketed
`UploadPack`), a nonce record scoped to
audience/repository/signer, together with the full authenticated operation
fingerprint. Reusing a nonce for a different operation MUST fail.
Same-operation retries MUST return the saved result and MUST NOT repeat
mutable effects or charge quota again. Nonce, quota, reference changes
(including both AdvanceRefs writes), chat sequence, and reaction toggles MUST
commit in one explicit SQLite transaction. A transaction failure rolls them
all back; broadcasts occur only after commit. Replay records MUST remain until
the signed expiry has passed.

A server processes a signed write in this order:

1. **Authenticate.** Verify the signature and the validity window. This
   step writes no state.
2. **Look up the replay record** for (audience, repository, signer, nonce):
   - a stored fingerprint that differs from the request's is
     `invalid_argument`;
   - a `committed` operation returns its stored result;
   - an `in_flight` operation returns a retryable `aborted`, without
     reaching admission.

   Only a new operation continues. So a retry never presents a spent payment
   credential again, and one signer's result is never served to another.
3. **Authorize** the write (§7.5), then run **admission** (§5.1)
   (for `BeginUpload`, after the live-ticket check of §7.7). A
   challenge or a denial allocates nothing. Because the lookup precedes
   admission, a retry stays answerable after the caller has exhausted its
   budget.
4. **Reserve.** Insert the `in_flight` replay record.
5. **Apply** the operation's effects.
6. **Commit** the stored result.

For a unary write, steps 4 to 6 commit together in the one transaction
required above. §7.7 states what each RPC's apply writes. A challenge and a
`PendingVerification` answer (§7.6) are never stored as replay results: the
server leaves no record for the attempt, and removes any `in_flight` record it
inserted, so a retry with the same nonce is evaluated again from step 2.

**Signed reads** skip the replay ledger and this order's steps 2 and 4 to 6
("Signed reads" above): a read is idempotent, so the server checks only the
signature and the validity window.

An upload no longer resumes through its replay record. An interrupted upload
resumes through its ticket and part receipts (§7.6), under the per-RPC
lifecycle of §7.7. An unreachable ledger or failed quota read fails closed.

`AUTH_AUDIENCE` must be explicitly configured for every deployment and local
development origin.

### 7.2 `mkit-server` (native)

The same generated `TransportService` binding (`mkit-server`'s `connect`
module over its pipeline), served over axum/hyper by the `mkit-server`
binary ([`mkit-server-native`](../../rust/crates/mkit-server-native/))
instead of `workers-rs`: one handler implementation for both targets, over
different storage backends (R2 and Durable Objects on Workers; the
`.mkit` on-disk layout or `SQLite` metadata with filesystem or S3 blobs
natively, per [SPEC-WORKTREE](SPEC-WORKTREE.md)/[SPEC-CONCURRENCY](SPEC-CONCURRENCY.md)
for the on-disk layout). `mkit-server serve --listen <ADDR> --repo-root
<DIR>` is the self-hosted `mkit+https://` remote; the same process can
also serve `mkit+enc://` (`--listen-enc`, SPEC-TRANSPORT-ENC §6). Its
flags, authentication modes and limits are in the crate's README.

`mkit serve <path>` (the CLI) is only the `mkit+ssh://` forced-command
server, speaking the SSH-frame protocol on stdin/stdout. Its former HTTP
mode (`--http`, mkit#700) and encrypted listener (`--listen-enc`) moved to
`mkit-server`, and with them the axum-hosted `TransportServer` of
`mkit-transport-connect`'s former `server` feature.

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
  (SPEC-TRANSPORT §5.2) and is what `mkit-server serve --auth bearer`
  (§7.2) expects.
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
the packmap-compaction optimization, not a correctness gap. v2 closes
this gap on the wire: a v2 client reads `atomic_advance` from
`GetServerInfo` (§2.1) and drops the local opt-in.

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

### 7.4 Repository addressing

A deployment serves one repository or many. Every repository RPC names
its repository, so one client and one proto serve both kinds of
deployment.

**Grammar.** A repository identity is ASCII text with this grammar
(ABNF, [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234)):

```abnf
repository = namespace "/" name / name   ; bare name: single-repository deployments only
namespace  = ed25519-ns / address-ns
ed25519-ns = "ed25519-" 64HEXLC           ; owner: that Ed25519 public key
address-ns = "0x" 40HEXLC                 ; owner: a key whose derived address matches
name       = lead *99tail
lead       = %x61-7A / DIGIT              ; a-z 0-9
tail       = lead / "." / "_" / "-"
HEXLC      = DIGIT / %x61-66              ; 0-9 a-f
```

Namespaces are self-certifying: the namespace itself names its owner,
so a verifier needs no registry to find the owner. The `ed25519-` form
names an Ed25519 public key. The `0x` form names a 20-byte address;
[SPEC-WRITE-GRANTS §4.1](SPEC-WRITE-GRANTS.md#41-address-derivation)
defines how an owner key derives it.
No other namespace form exists, and a deployment MUST NOT resolve
other forms through a registry of its own.

Identities are lowercase only, so two spellings never name one
repository. A server MUST reject an identity that does not match the
grammar, including one with uppercase hexadecimal digits, with
`invalid_argument`. The longest identity is 173 bytes (`ed25519-`, 64
hexadecimal digits, `/`, and a 100-byte name). That fits within the
255 bytes the reference auth v2 validator allows for `<repository>`
(§7.1).

**Carriage.** A client MUST send the `X-Repository` header on every
repository RPC, read or write. The exceptions are `GetServerInfo`
(§2.1), which MAY carry the header, and the namespace RPCs
`GetGrantEpoch` and `SetGrantEpoch`, which carry none
([SPEC-WRITE-GRANTS §5.3](SPEC-WRITE-GRANTS.md#53-rpcs)). A server treats a request without
the header as the deployment kind below requires. On a signed request,
`X-Repository` MUST equal the signed `<repository>` field byte for
byte. Envelope verification
detects a mismatch, so a mismatch is `unauthenticated`. Host, path, and
forwarded headers MUST NOT select the repository.

**Single-repository deployments.** The deployment configures exactly
one repository identity. It MAY be a bare name. A request without
`X-Repository` resolves to that identity on unsigned RPCs; a signed
request without `X-Repository` is `unauthenticated` (§7.1). A request that carries any
other well-formed identity is `not_found`. The §7.1 reference Worker is
a single-repository deployment.

**Multi-repository deployments.** The deployment routes each RPC by
`X-Repository`. A missing header on an unsigned RPC and a bare name
are both `invalid_argument`, because only the `namespace "/" name` form is
valid here. A read RPC on a repository that does not exist is
`not_found`, the same as a missing pack or ref.

**Isolation.** Refs, pack membership, packmap chains, and replay
records are per repository. Quota and admission scope are set by the
deployment. They are not required to be per repository. A server MUST
NOT let an RPC on one repository read or change another repository's
state. A server MAY store identical immutable bytes once across
repositories, but `PackExists` and `DownloadPack` MUST answer only for
packs that are members of the named repository. Otherwise a caller
could learn another repository's contents. A server MUST NOT answer any
RPC by consulting another repository's membership: no response may act
as an existence oracle for content held elsewhere.

**Creation.** A repository comes into existence with its first
authorized write (§7.5). This service has no create-repository RPC.

**Client.** The path of the remote URL is the repository identity:
`mkit+https://host/<namespace>/<name>` names `<namespace>/<name>`. The
client trims leading and trailing `/` from the path. An empty path
names the bare identity `default`, so a single-repository deployment
reachable with an empty path configures `default`. A client MUST send
the same identity in `X-Repository` on every repository RPC, reads
included, and in the signed `<repository>` field on writes.

**ssh and enc (informative).** The ssh and enc transports carry no
`X-Repository`. For ssh the addressing input is the path argument of
`mkit serve <path>`, the forced command; for enc it is the root of the
`mkit-server serve --repo-root <DIR> --listen-enc <ADDR>` that accepted
the connection (SPEC-TRANSPORT-ENC §6). The on-disk layout under that
path is unchanged, and the frozen `mkit.rpc.v1.ssh` protocol is
untouched.

### 7.5 Namespace and write policy

A deployment applies a namespace policy and a write policy to every
signed write except the part path (§7.6). Together they decide whether an authenticated principal
may write to the repository in `X-Repository`.

**Namespace policy.** `namespace_policy` is one of:

- **`allowlist`**: the deployment lists the owner namespaces it
  serves. A write to any other namespace is `permission_denied`. This
  is the default for a stock multi-repository deployment.
- **`any`**: every self-certifying namespace is served. This is an
  explicit opt-in. Every new key is a new namespace, and each new
  namespace starts with a fresh default quota. A deployment under
  `any` MUST therefore configure a non-default admission step
  (§5.1). Without one it MUST refuse to start, unless the
  operator passes an explicit unsafe override (for example, an
  "unsafe open namespaces" setting; the exact spelling is up to the
  implementation).

A single-repository deployment advertises `single-repository` in
`GetServerInfo` (§2.1). `single-repository` is advertised, never
configured; it tells a client that bare names and a missing
`X-Repository` are accepted.

**Write policy.** `write_policy` is one of:

- **`open`**: any valid auth v2 signer may write. Only a
  single-repository deployment MAY run `open`. A stock
  multi-repository deployment MUST NOT run `open`.
- **`owner`**: a write needs authorization for the repository in
  `X-Repository`.

Under `owner`, a write to `<ns>/<name>` is authorized when any of
these holds:

1. `ns` has the `ed25519-` form and the auth v2 signer is that key.
2. A valid grant authorizes the signer
   ([SPEC-WRITE-GRANTS §6](SPEC-WRITE-GRANTS.md#6-server-policy) and
   [§7](SPEC-WRITE-GRANTS.md#7-verification-order)). Before the M2
   implementation, only rules 1 and 3 apply (informative).
3. A deployment-defined authority source authorizes the signer for the
   repository. An example is a ledger's delegated-key record, checked
   against verified state. The deployment MUST document the source and
   MUST fail closed when it cannot read that source.

An `0x` namespace owner cannot sign auth v2, which is Ed25519-only. So
an `0x` namespace takes writes only through grants or through a
deployment-defined authority source (informative). Reads of a private
repository are authorized by the same three rules with the `read`
capability, and an unauthorized one is `not_found`
([SPEC-WRITE-GRANTS §9](SPEC-WRITE-GRANTS.md#9-reads-and-private-repositories)).

**Order.** The server authorizes a write after authentication and
after the replay-record and saved-reply check §7.1 requires, and before
it allocates any quota, reservation, or replay record. A rejection
allocates nothing.

**Creation signals.** The authorization and admission steps see
whether the write creates a namespace and whether it creates a
repository (`creates_namespace` and `creates_repo`). §5.1 requires the
server to give both to its admission step.

### 7.6 Upload tickets and resumable parts

A ticket reserves an upload before the client sends any pack bytes. It
names the ref the upload will advance, so the ticket lives with that
ref's strongly consistent state (§7.9). Parts let a client upload a
large pack in pieces and resume after a failure, without the server
ever holding a whole part in memory.

**`BeginUpload`.** `BeginUpload(repository, ref, pack_id, bytes)` is a
unary, signed write with a `body:` commitment (§7.1). It returns one
of:

- `AlreadyPresent`: the pack is already a member of this repository.
- `Ticket{id, part_size, expires, token}`: a reservation and an upload
  session.

For the same signer, ref, and pack before an advance consumes the
ticket, `BeginUpload` returns the existing ticket: the same id and the
same upload session, never `AlreadyPresent`. Membership is eventually
consistent (§7.9), so a server MAY return a ticket for a pack that is
already a member. That costs only a re-upload.

**Ticket token.** `token` is an opaque, server-authenticated value that
binds the ticket id, audience, repository, signer, `pack_id`, `bytes`,
`part_size`, `expires`, and the id of the key that authenticates it.
The server verifies a token without consulting any strongly consistent
metadata. A client treats the token as opaque. How the server
authenticates tokens is deployment-defined (informative: a message
authentication code under a deployment secret, rotated by key id).

**Parts.** A client uploads a pack of more than `part_size` bytes in
parts. `UploadPart` is a client-streaming, signed RPC, like
`UploadPack`:

1. The first message is a header `{ticket_token, index}`.
2. The following messages carry the part's bytes in order.
3. The response is a part receipt.

The part's commitment is:

```text
part:<ticket>:<index>:<subtree-hash>:<len>
```

`<ticket>` is the ticket id. A ticket id is 64 lowercase hexadecimal
digits. `<index>` is the zero-based part index in
decimal. `<subtree-hash>` is the part's BLAKE3 subtree chaining value
as 64 lowercase hexadecimal digits. `<len>` is the part's byte count in
decimal. The signed headers commit to the whole part before the client
sends any byte of it.

Every part except the last is exactly `part_size` bytes, a power of two
of at least 8 MiB. The last part holds the rest and is not empty. An
upload has at most `max_parts` parts (§2.1). Part `i` covers pack bytes
from `i × part_size`. Its subtree hash is the BLAKE3 chaining value of
those bytes as a non-root subtree at that offset, so the server can
merge the part hashes into the pack's root hash. Parts merge by
BLAKE3's left-balanced tree rule.

For `UploadPart`, the header's token ticket id and index MUST equal the
commitment's `<ticket>` and `<index>`, and `<len>` MUST equal
`part_size` for every part but the last.

Golden vectors (informative;
[SPEC-CONVENTIONS §5](SPEC-CONVENTIONS.md#5-golden-vectors-and-conformance-tests)).
Vector inputs are not stored: input byte `i` is `i mod 251`.

- `rust/tests/golden/uploads/subtree-merge.json` pins, per vector, each
  part's index, offset, length and subtree chaining value, and the
  merged root, which equals the BLAKE3 hash of the whole input. The
  8 MiB vectors cover 2, 3, 5 and 8 parts, with short last parts of
  1, 1023, 1024, 1025 and `8 MiB − 1` bytes and one upload of only
  full parts. Vectors marked `"test_geometry": true` use 1 KiB and
  4 KiB parts, below the minimum part size; they are test-only
  geometry for deeper, unbalanced trees (2 to 17 parts).
  `rust/tests/golden/uploads/MANIFEST.txt` pins the file's BLAKE3.
- `rust/tests/golden/auth-v2/part.json` pins a signed `UploadPart`
  envelope: its `part:` commitment (the second part of the 8 MiB
  two-part vector), canonical string, signing digest and Ed25519
  signature.

`scripts/golden/blake3_subtree_ref.py` checks both files against an
independent pure-Python BLAKE3.

The server verifies the ticket token and the commitment before it reads
any data. It hashes the data as it streams it to storage and MUST NOT
need to hold a whole part in memory. A subtree hash or length that
differs from the commitment is `invalid_argument`. On success the
server returns a **part receipt**: an opaque, server-authenticated value
that binds the ticket id, index, subtree hash, length, and the storage
backend's tag for the part. A part needs no admission decision, because
admission happened at `BeginUpload`. Sending a part index again is
idempotent.

**Part path.** `UploadPart`, `CompleteUpload` and a ticketed `UploadPack`
form the part path. They record no replay entry. They are idempotent by content, so
the server checks only the validity window, the ticket token, and the
commitment. The part path does not run the Authorizer; authority is
checked at `BeginUpload` and again inside the `AdvanceRefs` apply, so a
revocation between them leaves only unreferenced bytes, reclaimed at
ticket expiry.

**Completion.** `CompleteUpload{ticket_token, receipts[]}` is a unary,
signed write with a `body:` commitment. The server verifies every
receipt and merges the subtree hashes into a root. It makes the pack
visible in storage only if the root equals `pack_id` and the lengths sum
to `bytes`. Otherwise it aborts the storage session and returns
`invalid_argument`. Completion does not make the pack a member of the
repository. Completing the same ticket again is idempotent: it returns the
same result and changes nothing.

**Resume.** Part receipts are the durable record of the parts a server
received, and the client keeps them. A client that lost receipts sends
the missing parts again. A client that calls `BeginUpload` again gets
the same ticket. The server offers no listing of received parts.

**Single-part packs.** A pack of at most `part_size` bytes uses
`UploadPack` with the ticket token in its header and the usual `pack:`
commitment. It sends no `part:` commitment and no `CompleteUpload`.

**Threshold.** A multi-repository deployment MUST advertise
`begin_upload_threshold_bytes = 0`: every upload needs a ticket, so
membership is always recorded in a ref shard. On a single-repository
deployment, packs under the threshold MAY skip `BeginUpload`; a stored
pack is a member. When the deployment runs admission, the threshold is
0. An upload that needs a ticket and carries none is
`failed_precondition`.

**Membership.** On a multi-repository deployment, a pack becomes a
member of the repository only at the `AdvanceRefs` apply that consumes
its ticket. `AdvanceRefs` gains a repeated `ticket_ids` field
naming the tickets it consumes. A ticket can be consumed only by an
advance of the ref it names; any other advance is `failed_precondition`.
A head-only `UpdateRef` consumes no tickets. Packlist nodes (`MKPL`) are
uploads like any other pack, and need tickets too.

**Binding.** The ticket's audience, repository, and signer MUST equal
the request's, and the ticket's `pack_id` and `bytes` MUST equal the
request's commitment. Otherwise the request is `permission_denied`.

**Errors.** An expired or unknown ticket, including a token that fails
verification, is `failed_precondition`. A ticket, signer, or
commitment mismatch is `permission_denied`. A bad part hash or length
is `invalid_argument`. No ticket failure is `resource_exhausted`,
because clients retry that code on the backoff ladder (§5).

**Expiry.** A ticket expires less than 7 days after `BeginUpload`. A
ticket that expires before an advance consumes it produces an `Expired`
outcome for its reservation, and its pack becomes eligible for garbage
collection.

**Retries.** A client that retries a signed request reuses its nonce and
timestamps while the envelope is valid (at most 300 seconds, §7.1).
After that it signs a new operation.

**Pending verification.** In indexed mode, an `AdvanceRefs` that
consumes a pack still under verification fails with `unavailable` and a
`PendingVerification{retry_after}` detail. The client polls until the
ticket expires, rather than following its normal backoff ladder, and
signs a new operation once the envelope lapses. This detail is reserved
here and becomes normative with indexed mode.

**Storage visibility (informative).** On every backend, the storage
commit is the point at which a pack becomes visible. On an object store
with multipart uploads, the server completes the multipart upload only
after the merged root verifies. Presigned direct-to-storage part
uploads are not allowed, because they would bypass verification before
completion.

### 7.7 Lifecycle per RPC

This section is normative. It fixes, for each RPC of a ticketed upload,
whether admission (§5.1) runs and what the RPC's apply writes. The
shards are those of §7.9: a strongly consistent shard per (repository,
ref), and eventually consistent repository index shards.

Every RPC carries its own nonce: `BeginUpload`, each `UploadPart`,
`CompleteUpload`, a ticketed `UploadPack`, and `AdvanceRefs` are
separate signed operations.

The server also runs admission on every other signed unary write:
`UpdateRef`, including deletion (§7.8), and an `AdvanceRefs` that
consumes no ticket. Allowing, challenging or denying it is deployment
policy.

| RPC | Admission | What its apply writes |
|---|---|---|
| `BeginUpload` (unary; names its target ref) | Yes | In the target ref's shard: the replay record, a reservation row, and the ticket. |
| `UploadPart`, `CompleteUpload`, and a ticketed `UploadPack` (the part path, §7.6) | No | Pack or part bytes only, authorized by the stateless ticket token. The part path writes nothing to a metadata shard. The ticket's audience, repository, and signer MUST equal the request's, and for a ticketed `UploadPack` its `pack_id` and byte count MUST equal the request's `pack:` commitment; otherwise the request is `permission_denied` (§7.6). |
| `AdvanceRefs` | No; it consumes tickets | In the same ref shard: the head and the packmap, the ref's membership additions, which the server propagates to the repository index shards at least once, and one `Committed` outcome for each ticket it consumes. Tickets are local to the ref shard, so there is no cross-shard handoff. |

- **Membership.** A pack becomes a member of the repository only at the
  apply of the `AdvanceRefs` that consumes its ticket. Until then,
  `BeginUpload` for the same signer, ref, and pack returns the existing
  ticket, never `AlreadyPresent` (§7.6). A `BeginUpload` that finds such
  a live ticket returns it after authorization and before admission: it
  runs no admission, creates no reservation, and is never challenged.
- **One outcome per reservation.** Every reservation that admission
  granted gets exactly one outcome: `Committed`, `Aborted`, or
  `Expired`. `Committed` reports the bytes stored, the bytes new to the
  repository, the bytes new to the store, and the refs advanced.
- **Aborted.** If the apply of an admitted RPC fails after
  `Allow{reservation}`, for example an `UpdateRef` compare-and-swap
  loss, an epoch mismatch or a replay race, or a ticket's pack is
  collected as garbage before an advance consumes it, the server
  records `Aborted` in a separate transaction.
- **Expired.** A ticket that expires before an `AdvanceRefs` consumes
  it produces `Expired` (§7.6).
- **Conflicts.** An `AdvanceRefs` that ends in a typed conflict (§4)
  consumes no ticket. Its tickets stay usable until they expire. A lost
  compare-and-swap on `AdvanceRefs` is such a conflict, not `Aborted`.

A deployment settles a payment on `Committed` and releases it on
`Aborted` or `Expired`, so an aborted upload settles nothing
(informative). How outcomes reach the deployment, through a
transactional outbox delivered at least once and keyed by reservation
id, is specified in SPEC-SERVER (forthcoming, informative).

### 7.8 Ref deletion

`UpdateRef` and `AdvanceRefs` gain an additive `delete` field.

- On `UpdateRef`, `delete` is valid only with `REF_EXPECTATION_MATCH`
  and an empty `new_id`. The server removes the ref if its current
  value equals `expected_id`.
- On `AdvanceRefs`, `delete` removes the branch head and its packmap
  together, under the same rules for each: both expectations are
  `MATCH`, and both new ids are empty. A conflict is a typed outcome
  (§4), as for any advance.
- A `delete` with any other expectation or a nonempty new id is
  `invalid_argument`.
- Deleting an absent ref is a CAS conflict: `failed_precondition` on
  `UpdateRef`.

The write policy authorizes deletion (§7.5). A grant authorizes
deletion only through its `delete` flag
([SPEC-WRITE-GRANTS §8](SPEC-WRITE-GRANTS.md#8-ref-scopes-and-packmap-coverage)).
A deployment MAY refuse deletion entirely with `permission_denied`.

This document requires no client command for deletion (informative: a
`push --delete` command is a separate change).

### 7.9 Consistency and paging

A multi-repository deployment keeps each ref's state in a strongly
consistent shard and its repository-wide indexes in eventually
consistent shards (§7.1). This section states what a client can rely
on.

**Strong.** `ReadRef` of a specific ref is strongly consistent, and so
is every write. Push compare-and-swap MUST use `ReadRef`. A deployment
MUST NOT serve `ReadRef` from a snapshot to a client that may push. A
client that may push signs its reads (§7.1), so a deployment MAY serve an
unsigned `ReadRef` from a snapshot and MUST serve a signed one from the
ref's strongly consistent state
([SPEC-WRITE-GRANTS §9.2](SPEC-WRITE-GRANTS.md#92-signed-reads)).

**Eventual.** `ListRefs` and pack membership (`PackExists`,
`DownloadPack`, and `AlreadyPresent` from `BeginUpload`) are eventually
consistent. They may lag a write by seconds. A lag MUST only cause one
of these:

- a re-upload, because `AlreadyPresent` was not returned;
- a retryable `unavailable` ("not yet visible");
- an older listing; or
- `not_found` (or `exists = false`) for a pack when the request carried
  no `X-Mkit-Ref`.

A lag never exposes another repository's data and never acts as an
existence oracle (§7.4).

**Read-your-writes for packs.** `PackExists` and `DownloadPack` MAY
carry an optional header naming a ref of the same repository whose
packmap listed the pack:

```text
X-Mkit-Ref: <refname>
```

The server then also resolves membership against that ref's strongly
consistent shard, which holds the membership additions the ref's
advances recorded. So a pusher sees its own advance at once, despite
index lag. The answer is always subject to the caller's view. A caller
without write access gets the published view, so a pack that an
advance still in quarantine added stays invisible through the header,
exactly as without it. The header never reveals another repository's
packs, or whether a ref exists in another repository. An unknown or
malformed ref name makes the header a no-op: the answer falls back to
the index and is never an error, which would act as an existence
oracle. A client SHOULD send the header when it fetches packs listed by
a packmap it just read. `X-Mkit-Ref` is not part of the auth v2
canonical string: changing it can only change which of the caller's
own permitted answers comes back, never widen the caller's view.

**Paging.** `ListRefs` is paginated through additive fields: the
request carries `page_size` and `page_token`, and the response carries
`next_page_token`. An empty `next_page_token` ends the listing. The
server MAY return fewer refs than `page_size`, and caps it at
`max_list_refs_page_size` (§2.1). Every encoded response page MUST be
at most 2 MiB, so a page always fits under the common 4 MiB default
client message limit. The pages concatenate to a listing in ref-name
order ([SPEC-REFS §4.1](SPEC-REFS.md#41-ordering-and-duplicates)).

**Advertised values.** `GetServerInfo` advertises `index_fanout` and
the `ListRefs` page bound (§2.1).

---

## 8. Out of scope

This document specifies the proto and its consumption pattern only.
Explicitly deferred to sibling issues:

- The reference Worker implementation (mkit#699).
- ~~`mkit serve`'s HTTP mode (mkit#700).~~ Implemented, then moved to the
  `mkit-server` binary &mdash; see §7.2.
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
- Implementing version 2 (M1): multi-repository routing, the namespace
  and write policies, sharded server metadata, `GetServerInfo`, upload
  tickets and resumable parts, ref deletion, and `ListRefs` paging, with
  the proto additions they need (mkit#1084, mkit#1090).
- Implementing write and read grants, epochs, signed reads, private
  repositories and URL tokens, specified in
  [SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) (M2; mkit#1085, mkit#1089).
- Implementing admission (M3, mkit#1086): the `AdmissionChallenge` and
  `Challenge` proto messages, the `AdmissionRequired` `TransportError`
  variant and the retryable mapping of `aborted` (§5), the server's
  admission step and outcomes (§5.1, §7.7), and the client's 402
  handling, `admission_helper`, and header allowlist (§5.1).
- the remote-hook contract and outcome guarantees: see [SPEC-SERVER](SPEC-SERVER.md).
- Pricing, payment verification, and settlement: deployment policy,
  never mkit's (§5.1).

---

## 9. Version history

| Version | Status | Changes |
|---|---|---|
| `2` | draft | §7.4 repository addressing; §7.5 namespace and write policy (owner key); `GetServerInfo` (§2.1); §7.6 upload tickets and resumable parts; §7.8 ref deletion; §7.9 consistency and `ListRefs` paging; error-code split between `unauthenticated` and `permission_denied` (§5) (mkit#1084, mkit#1090); SPEC-WRITE-GRANTS (mkit#1085): signed reads and `X-Write-Grant` (§7.1), the M2 RPC rows (§2), and grant cross-references. §5.1 admission challenges: HTTP 402 with `permission_denied` and an opaque challenge list, raw MPP/x402 header pass-through, the header-returning `admission_helper` with its allowlist and hard-reserved set; §7.1 replay lookup after authentication and before authorization and admission, with signed reads outside the ledger; retryable `aborted` for in-flight operations (§5); §7.7 lifecycle per RPC (mkit#1086). The M0 server implementation still resumes an interrupted `UploadPack` through its `in_flight` replay record until M1 tickets land. |
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
| No RPC on one repository reads or changes another repository's refs, pack membership, or replay records. | §7.4 isolation; the `X-Repository` carriage rule. |
| A write is authorized, or rejected with nothing allocated, before any quota or replay state is touched. | §7.5 order. |
| A retry of a committed signed write returns the stored result and never reaches admission; a retry of an in-flight one gets a retryable `aborted`. | §7.1 order: authenticate, look up, then authorize and admit. |
| A challenged or denied request changes no state, and no challenge or `PendingVerification` answer is stored as a replay result. | §5.1 "No state on challenge"; §7.1. |
| A challenge is HTTP 402 with `permission_denied`, only on a unary RPC, and is never retried automatically. | §5.1; §5; SPEC-TRANSPORT §7. |
| A client attaches only allowlisted helper headers and never a hard-reserved one, whatever the configuration says. | §5.1 header allowlist and hard-reserved headers. |
| Every admitted reservation gets exactly one outcome: `Committed`, `Aborted`, or `Expired`. | §7.7. |
| A stock multi-repository deployment never runs `write_policy = open`. | §7.5 write policy. |
| An `AdvanceRefs` conflict is a typed response value, never a Connect error. | §4 &mdash; matches `AdvanceOutcome`'s three-variant, no-error-variant shape in `protocol.rs`. |
| The `DownloadPack` Workers-streaming design is documented as unverified end-to-end until a sibling issue proves real client-visible delivery. | §6.3's "Known risk" paragraph; mkit#699/#702's re-verification requirement. |
