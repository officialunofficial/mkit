---
spec: SPEC-SERVER
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers and of deployment business logic behind the remote-hook contract
---

# SPEC-SERVER — server pipeline guarantees and the remote-hook contract

## 1. Scope and relation to SPEC-TRANSPORT-CONNECT

This specification defines server-internal pipeline guarantees, durable
outcomes, and the contract between a server and deployment business logic.
An independent hook implementation can use this contract and the
`mkit.server.hooks.v1` schema without using a server implementation.

[SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md), abbreviated STC,
defines the client-visible `mkit.transport.v1` wire contract. Its rules
remain authoritative for client authentication, replay handling,
authorization, admission challenges, upload tickets, and RPC lifecycle.
References to STC below add internal guarantees or describe hook messages;
they do not replace those wire rules.

MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and REQUIRED have the meanings
defined by [SPEC-CONVENTIONS §1](SPEC-CONVENTIONS.md#1-normative-keywords).
The encoding, domain-separator, and golden-vector conventions of that
specification apply throughout this document.

A server that runs remote hooks MUST implement §5–§8. A server without
remote hooks MUST still implement §2–§5. A deployment implements the
business decisions exposed by hooks; the server implements the pipeline,
validation, durable recording, and delivery guarantees specified here.

The contract does not define prices, payment verification, settlement
policy, moderation policy, or the deployment's account model.
[SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) remains authoritative for grants,
their verification, and the preconditions they carry into apply.

Sections 9–13 reserve the M5 contracts. Inspection in §6.4 is provisional:
the call shape is fixed, and M5 may add fields additively.

## 2. Pipeline order

The stages are numbered 0–9. An operation visits the stages applicable
to its RPC and configured hooks. The signed-write processing order is
as STC §7.1 requires; this list names server-internal extension points.

0. **Authenticate and look up replay.** Perform authentication and replay
   lookup as STC §7.1 requires. Only an operation that continues under
   that contract reaches the later decision stages.
1. **Identity.** Map the authenticated request to a principal: an
   anonymous caller, an authenticated signer, a bearer holder, an
   authenticated transport peer, or an SSH forced-command identity.
2. **Authorize.** Decide whether the principal may perform the operation,
   as STC §7.5 requires. Record the established owner and grant facts
   in the operation passed to admission.
3. **Admit.** Decide whether the deployment permits this operation now.
   Admission may allow, challenge, or deny it. Admission applies only
   to unary RPCs, as STC §5.1 requires.
4. **Replay reservation and streamed body.** Reserve replay state as STC
   §7.1 requires, and receive any applicable streamed body under the
   ticket and part rules STC §7.6 requires. Durably record a pending
   reservation when §5 requires it before the guarded apply.
5. **Pre-receive checks.** Run content verification and policy checks,
   including inspection configured to run synchronously before apply.
6. **Atomic apply.** Apply the operation with its preconditions and
   applicable outbox rows in the atomic unit specified by §3 and §5.
7. **Receipt signing.** Produce a receipt when the deployment enables
   receipt signing for the committed operation.
8. **Outcome delivery.** Deliver the durable outcome to the configured
   sink under §5 and, for remote hooks, §6.5 and §8.
9. **Asynchronous inspection and lease events.** Run configured
   asynchronous inspection and lease-policy events after apply.

Stages before stage 4 MUST NOT write server state. Admission may plan a
default quota reservation, but that reservation MUST be committed with
apply; admission itself MUST NOT commit it.

Stage 2 MUST run before any quota or replay record is allocated, as STC
§7.5 requires. A challenge or denial at stages 2–3 writes nothing, as
STC §5.1 requires. A pending reservation under §5 is therefore written
only after admission has returned an allowance with a reservation id.

Signed reads skip the replay ledger, as STC §7.1 requires. Their
identity, authorization, and optional admission decisions use the
applicable stages without allocating replay state.

Informative: stage 6 is the commit point for the operation's guarded
effects. Receipt signing and delivery may happen later. An outcome
delivery failure does not undo an already committed operation.

## 3. Per-RPC lifecycle

Each RPC's admission eligibility and apply effects are as STC §7.7
requires. The following rules specify the internal atomic boundaries;
they do not reproduce its lifecycle table.

- For `BeginUpload`, the replay record, reservation, and ticket MUST
  commit in one atomic unit in the target ref's shard, as STC §7.7
  requires. The successful apply replaces the pending reservation
  described in §5 with the ticket-backed reservation.
- For an `AdvanceRefs` that consumes tickets, the head, packmap,
  membership additions, and one `Committed` outcome per consumed ticket
  MUST commit in one atomic unit in the target ref's shard, as STC §7.7
  requires.
- For a directly admitted unary write, meaning `UpdateRef` including
  deletion or `AdvanceRefs` consuming no ticket, when admission grants
  a reservation the ref write and its
  `Committed` outcome MUST commit in one atomic unit. The successful
  apply replaces its pending reservation with that outcome.
- An `Aborted` outcome MUST be written in a separate atomic unit after
  a failed apply, as STC §7.7 requires. That unit replaces the pending
  reservation with `Aborted` when a pending reservation exists.
- An `AdvanceRefs` typed conflict consumes no ticket and records no
  outcome; its tickets remain usable until expiry, as STC §7.7 requires.
- A pack becomes a repository member only at the `AdvanceRefs` apply
  that consumes its ticket, as STC §7.7 requires.

The pending-reservation write precedes these guarded atomic units.
It does not move ticket creation or ref publication into admission.
Ticket eligibility, token checks, and part handling remain as STC
§7.6 requires.

## 4. Fail-closed rules

A conforming server MUST enforce these rules:

- Missing or unsupported authentication versions fail closed, as STC
  §7.1 requires.
- Authorize and Admit hook failures deny the operation under §8.
- A hook response that violates §6.6 is invalid and is handled under §8.
- A store failure MUST NOT be reported as success.
- An unknown scheduled-work kind MUST be retained, never discarded.
- Startup with `namespace_policy = any` and default admission MUST be
  refused unless explicitly overridden, as STC §7.5 requires.
- An outcome MUST NOT be dropped. It remains durable until acknowledged.

Unknown scheduled work remains available for a version that understands
it. Treating that work as successfully completed would discard an
obligation that the current server cannot interpret.

## 5. Outcomes and the outbox

Every reservation granted by admission MUST get exactly one terminal
outcome: `Committed`, `Aborted`, or `Expired`; a paid read instead uses
`ReadServed`. Repeated delivery of that outcome is not another terminal
outcome. The reservation id identifies the one durable result.

For every admitted RPC whose admission returns a reservation, the
server MUST durably record a pending reservation before attempting the
guarded apply. The pending record identifies the reservation and the
operation's authentication validity interval for reconciliation.

On a successful `BeginUpload` apply, the server MUST replace the
pending reservation with the ticket-backed reservation in that apply's
atomic unit. On a successful direct admitted write, it MUST replace
the pending reservation with `Committed` in the ref write's atomic unit.

If the guarded apply fails, the server MUST replace the pending
reservation with `Aborted` in a separate atomic unit. The failed apply
MUST NOT leave the operation's guarded effects committed.

The periodic reconcile pass MUST record `Aborted` with reason
`ABORT_REASON_ABANDONED` for a pending reservation whose operation's
authentication validity interval has passed without replacement.
The interval is the one STC §7.1 requires, bounded by 300,000 ms.
This rule covers a crash between recording the pending reservation
and recording either a successful apply result or an abort.

An unconsumed ticket that expires MUST produce `Expired`, as STC
§7.7 requires. The periodic reconcile pass MUST produce `Expired`
for a ticket-backed reservation with no outcome once its ticket has
expired. It MUST NOT classify that reservation as an abandoned pending
operation after a successful `BeginUpload`.

Replacement and reconciliation MUST preserve exactly one terminal
outcome across crashes and concurrent attempts. A reconcile pass MUST
NOT replace an existing terminal outcome. A committed reservation MUST
NOT later become `Aborted` or `Expired`.

Informative: recording a pending reservation costs an additional atomic
unit for each admitted write that has a reservation id. Default quota
admission without a reservation id does not pay this cost.

The server MUST retain an outcome until acknowledged. Delivery MUST
be at least once, using the reservation id as the idempotency key.
There is no ordering guarantee between reservations. A receiver MUST
treat a repeated outcome for the same reservation as the same result.

The durable outbox holds outcomes awaiting acknowledgement. Delivery
attempts and process restarts MUST NOT discard an unacknowledged row.
Acknowledging one reservation does not acknowledge another reservation.

A server MAY refuse new admitted writes with retryable `unavailable`
while its undelivered outcome backlog exceeds a configured bound.
It MUST NOT drop outcomes to relieve that backlog. Reads and writes
that do not run admission MUST be unaffected by this backpressure.

`new_to_store` bytes appear only in `Committed`, as STC §5.1 requires
for admission input. They MUST NOT be added to another hook input as
an admission pricing signal.

Informative: a deployment settles payment on `Committed` and releases
the reservation on `Aborted` or `Expired`. Settlement failures after
commit are deployment policy. `ReadServed` provides metering for paid
reads; the deployment defines the corresponding read settlement.

## 6. Remote hooks: mkit.server.hooks.v1

The service exchanges information about an operation and its decisions.
Hook implementations do not receive arbitrary client credentials or
object contents through this contract. The field definitions below
use schema names; JSON uses their lowerCamelCase equivalents.

### 6.1 Transport and codec

The hook service MUST use the Connect protocol with unary RPCs over
HTTPS, subject to the loopback exception below. Its service name is
`mkit.server.hooks.v1.HooksService`, with these full procedure paths:

| RPC | Connect path |
|---|---|
| Authorize | `/mkit.server.hooks.v1.HooksService/Authorize` |
| Admit | `/mkit.server.hooks.v1.HooksService/Admit` |
| Inspect | `/mkit.server.hooks.v1.HooksService/Inspect` |
| Outcome | `/mkit.server.hooks.v1.HooksService/Outcome` |

Hook servers MUST support the JSON codec, `application/json`. They
MAY also support the binary codec. The calling server MUST send JSON
unless configured otherwise.

The JSON codec MUST use the canonical protobuf JSON mapping:
lowerCamelCase field names, standard base64 for `bytes`, and JSON
strings for 64-bit integers. Symbolic enumeration values use their
schema names. Empty messages are JSON objects, for example `{}`.

Scalar fields use explicit presence. In particular, absence of
`new_to_repo_bytes` means unknown; a present value of zero means the
server knows that zero bytes are new to the repository.

A deployment MAY implement any subset of the four RPCs. The calling
server MUST call only the hooks it is configured to use. Configuration
of a subset does not change the semantics of a hook that is enabled.

Plain HTTP MUST be used only for loopback hosts. Redirects MUST NOT
be followed. Request authentication is specified in §7, independently
of the selected codec.

Informative end-to-end admission sequence:

1. A client sends a signed `BeginUpload` to the server.
2. The server performs the applicable early stages and calls `Admit`.
3. The hook returns `challenge`; the server answers the client as STC
   §5.1 requires, including its 402 admission response.
4. The client completes the deployment's external action and retries
   under the STC contract. The server calls `Admit` for the new attempt.
5. The hook returns `allow` with a reservation id. The server records
   the pending reservation, then applies `BeginUpload` to create a ticket.
6. Upload and a later ticket-consuming `AdvanceRefs` follow STC §7.7.
   The latter atomically records the applicable `Committed` outcome.
7. The server calls `Outcome` until the hook acknowledges it. The hook
   uses the reservation id to make its settlement idempotent.

### 6.2 Authorize

`AuthorizeRequest.operation` describes the authenticated operation
before admission. `Operation` has the following fields, also used by
Admit and Inspect:

| Field | Meaning |
|---|---|
| `audience` | The mkit server's canonical origin, distinct from the hook endpoint's signing audience in §7.1. |
| `repository` | The full repository identity, as STC §7.4 requires. |
| `procedure` | The full procedure path of the client RPC being evaluated. |
| `principal` | The identity established by the server at stage 1. |
| `idempotency_key` | The auth v2 nonce of a signed write; empty otherwise. |
| `refs` | The intended ref changes, in decision order. |
| `owner` | Whether the principal owns the namespace; established for Admit. |
| `grant` | The write grant used, if any, and its checked epoch; established for Admit. |

`owner` and `grant` report authorization facts; Authorize is the stage
that precedes their establishment. An absent grant means no write
grant was used. Grant verification and apply preconditions remain
as [SPEC-WRITE-GRANTS §7](SPEC-WRITE-GRANTS.md#7-verification-order)
requires.

`Principal.kind` identifies exactly one of these alternatives:

| Alternative | Meaning |
|---|---|
| `anonymous` | An `Anonymous` empty message; no authenticated credential identity. |
| `signer` | A `Signer` whose `ed25519_public_key` is the verified 32-byte auth v2 public key. |
| `bearer_holder` | A `BearerHolder` empty message; the bearer token itself is never sent. |
| `transport_peer` | A `TransportPeer` whose `ed25519_public_key` is the authenticated 32-byte peer key. |
| `ssh_forced_command` | An `SshForcedCommand` whose `ed25519_public_key` is 32 bytes, or empty when unknown. |

The hook receives the established principal, not a credential to verify
on the client's behalf. Request authenticity on the hook channel is
checked separately under §7.

Each `RefChange` describes one intended ref write:

| Field | Meaning |
|---|---|
| `name` | The full ref name. |
| `condition.any` | An `Unconditional` empty message: no expected-current-value condition. |
| `condition.missing` | A `MustNotExist` empty message: the ref must not exist. |
| `condition.expected` | A 32-byte id that the ref must currently hold. |
| `new` | The 32-byte new target, or empty when `delete` is true. |
| `delete` | Whether the change deletes the ref. |

The condition is a oneof, so its alternatives are mutually exclusive.
The hook's decision does not establish that the condition will still
hold when apply executes. The guarded apply evaluates the ref
precondition under the client RPC's STC contract.

`GrantUsed.grant_id` is the 32-byte id of the write grant used.
`GrantUsed.epoch` is its unsigned 64-bit namespace epoch at authorization.
Neither field carries the grant statement or its signature.

`AuthorizeResponse.result` selects `allow` or `deny`. `AuthorizeAllow`
is an empty message permitting the operation to continue. An allowance
does not itself perform admission or commit a write.

`Deny.code` is a Connect code name. For Authorize, the allowed names
are `permission_denied`, `not_found`, `unauthenticated`,
`resource_exhausted`, and `failed_precondition`. The server MUST treat
any other code as `permission_denied`.

`Deny.message` is public text for the client. It MUST be at most 512
bytes of UTF-8 and contain no control characters. If it breaks either
rule, the server MUST replace it with a generic public message.
Code fallback and message replacement are the specified sanitization
of a deliberate denial, not hook transport failures.

The same `Deny` message shape is used by Admit and Inspect. Client
admission denial handling remains as STC §5.1 requires; the Authorize
code allowlist does not redefine the code for an admission denial.

### 6.3 Admit

`AdmitRequest` supplies the operation after authorization and the
admission-specific fields:

| Field | Meaning |
|---|---|
| `operation` | The operation defined in §6.2, including established owner and grant facts. |
| `declared_bytes` | The unsigned byte count declared by the request; zero for ref writes. |
| `pack_id` | The 32-byte pack id for `BeginUpload`; empty otherwise. |
| `creates_namespace` | Whether the write creates its namespace. |
| `creates_repo` | Whether the write creates its repository. |
| `new_to_repo_bytes` | Bytes new to this repository, known from membership; absent when unknown. |

Creation signals and admission input are supplied as STC §5.1 requires.
In particular, `new_to_repo_bytes` does not mean bytes new to the whole
store. Presence MUST preserve the distinction between unknown and zero.

`AdmitResponse.decision` selects `allow`, `challenge`, or `deny`.
The response contains exactly one decision. No remote admission field
returns internal quota charges; a remote admission returns none.

`AdmitAllow.reservation_id` is REQUIRED and MUST satisfy §6.6. It
identifies the deployment reservation that the server records and uses
to key its terminal outcome. `AdmitAllow.response_headers` contains
the allowed receipt headers defined in §6.6.

`AdmitChallenge.challenges` contains the deployment's opaque challenges
in order of preference. Each `Challenge.scheme` names the external
protocol; its `value` carries the protocol's opaque challenge text.
`AdmitChallenge.description` is text for a person.

Challenge entries and description MUST satisfy the bounds STC §5.1
requires, checked at the hook boundary under §6.6.
`AdmitChallenge.response_headers` contains the allowed challenge
headers defined in §6.6. The server handles the client response,
caching, CORS, and redaction as STC §5.1 requires.

`Header.name` is an HTTP header name and `Header.value` is its value.
Repeated `Header` entries preserve repeated `WWW-Authenticate` fields.
Their names are compared case-insensitively for the allowlists.

An Admit `deny` is a deliberate admission denial using the `Deny`
message described in §6.2. It allocates no pending reservation.
A `challenge` likewise allocates no pending reservation.

Informative: the deployment chooses how a reservation represents a
payment authorization, quota hold, or another external obligation.
The reservation id lets the later outcome discharge that obligation
without exposing the deployment's internal account identifiers.

### 6.4 Inspect (provisional)

This section is provisional. Its call shape is fixed; M5 may add fields
additively. Inspection follows the configured fail-closed or publish
mode, with failure handling defined in §8.

`InspectRequest.operation` is the operation defined in §6.2.
`InspectRequest.objects` lists the objects selected for inspection.
Each `InspectObject.id` is a 32-byte object id; `InspectObject.size`
is its unsigned size in bytes.

Object bytes MUST NOT be sent in the Inspect request. The request
contains identifiers and sizes only. Informative: an inspector that
needs content fetches it out of band through the deployment's object
serving facilities.

`InspectResponse.verdict` selects one of these alternatives:

| Alternative | Meaning |
|---|---|
| `pass` | An `InspectPass` empty message: inspection permits the content. |
| `quarantine` | An `InspectQuarantine` message: the content should be quarantined under the configured inspection mode. |
| `reject` | A `Deny` message: inspection rejects the operation, subject to the configured mode. |

`InspectQuarantine.reason` explains the quarantine verdict. It is
inspection-policy text, not an object body. `reject.code` and
`reject.message` use the `Deny` shape described in §6.2, including
the public-message sanitation rule.

An asynchronous verdict cannot reverse a ref write already committed.
In publish mode, later inspection can lead to quarantine. The reserved
M5 sections define the published-view and quarantine contracts.

### 6.5 Outcome

`OutcomeRequest.outcome` contains the terminal result recorded under
§5. `OutcomeResponse` is empty; its successful Connect response
acknowledges delivery under §8.

The shared `Outcome` fields are:

| Field | Meaning |
|---|---|
| `reservation_id` | The reservation whose result this is; the delivery idempotency key. |
| `audience` | The mkit server's canonical origin. |
| `repository` | The full repository identity as STC §7.4 requires. |
| `occurred_unix_ms` | When the outcome occurred, as signed 64-bit Unix epoch milliseconds. |
| `kind` | Exactly one of `committed`, `aborted`, `expired`, or `read_served`. |

`Committed` records a successful operation:

| Field | Meaning |
|---|---|
| `bytes_stored` | The unsigned count of bytes stored by the operation. |
| `new_to_repo` | The unsigned count of bytes new to the repository. |
| `new_to_store` | The unsigned count of bytes new to the entire store. |
| `refs` | The refs committed by the operation, in decision order. |

Each `CommittedRef.name` is the ref name. `CommittedRef.new` is
the 32-byte committed target, or empty when `deleted` is true.
`CommittedRef.deleted` identifies a committed deletion.

`Aborted.reason` classifies why the reservation did not commit:

| Enum name | Number | Meaning |
|---|---|---|
| `ABORT_REASON_UNSPECIFIED` | 0 | No specific reason supplied. |
| `ABORT_REASON_REF_CONFLICT` | 1 | A lost compare-and-swap on an admitted operation. |
| `ABORT_REASON_EPOCH_MISMATCH` | 2 | The grant epoch no longer satisfies apply. |
| `ABORT_REASON_PACK_MISSING` | 3 | A required pack is missing. |
| `ABORT_REASON_REPLAY_RACE` | 4 | A replay reservation race prevents apply. |
| `ABORT_REASON_INTERNAL` | 5 | An internal apply failure. |
| `ABORT_REASON_ABANDONED` | 6 | Reconcile found a pending reservation after the operation's authentication validity interval, without a recorded result. |

The typed-conflict exception for ticket-consuming `AdvanceRefs` remains
as STC §7.7 requires. `ABORT_REASON_REF_CONFLICT` does not convert that
exception into an abort or consume its tickets.

`Aborted.detail` is operator text, at most 512 bytes. It MUST NOT be
shown to clients. An `Expired` empty message records an unconsumed
ticket's expiry; it has no additional fields.

`ReadServed.object` is the 32-byte id of the object served by a paid
read. `ReadServed.bytes_served` is the unsigned number of bytes served.
It reports delivery rather than new storage and carries no
`new_to_store` accounting.

Informative: an Outcome webhook has its own hook-channel audience and
nonce under §7.1. Its `outcome.audience` continues to identify the mkit
server. The hook nonce protects delivery authenticity; the reservation
id makes repeated deliveries of the logical outcome idempotent.

### 6.6 Limits and response validation

The server MUST validate hook responses before using them. A response
violating any limit in this section is invalid and MUST be handled
under §8. The specified `Deny` sanitation in §6.2 applies separately.

- A response body MUST be at most 65,536 bytes.
- Challenge entries MUST meet the bounds STC §5.1 requires.
  Informative: those bounds are 1–8 entries, scheme token
  `[a-z0-9][a-z0-9.-]{0,63}`, value at most 8,192 bytes, and
  description at most 512 bytes of UTF-8.
- On a Challenge, pass-through headers MUST be limited to
  `WWW-Authenticate`, which is repeatable, and `PAYMENT-REQUIRED`.
- On Allow, pass-through headers MUST be limited to `Payment-Receipt`
  and `PAYMENT-RESPONSE`.
- A response MUST carry at most eight pass-through headers. Each
  value MUST be at most 8,192 bytes of visible ASCII plus SP, meaning
  bytes in the inclusive range `0x20`–`0x7e`.
- Header names MUST be compared case-insensitively.
- A `reservation_id` MUST be 1–128 bytes drawn from `[A-Za-z0-9._:-]`.
- `AdmitResponse.allow.reservation_id` is REQUIRED.

The applicable response oneof MUST select a decision or verdict.
An absent decision does not constitute permission to continue.
These checks validate the hook contract before constructing any
client-visible response under STC.

## 7. Hook channel authentication

### 7.1 Signed requests

Every hook request, including Outcome delivered as a webhook, MUST
be signed with a deployment hook key, except on a channel configured
under §7.3. Signing covers the exact request body bytes sent on that
channel; it does not sign a reserialized representation.

The signature MUST be strict Ed25519 over the 32-byte BLAKE3 of the
following eight newline-separated UTF-8 fields, with no final newline:

```text
mkit-hook:v1
<key id>
<audience>
<full procedure>
body:<64 lowercase hex BLAKE3 of the exact request body bytes>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

`mkit-hook:v1` is the literal domain separator for this key use, as
[SPEC-CONVENTIONS §4](SPEC-CONVENTIONS.md#4-domain-separator-and-namespace-naming)
requires. A hook key MUST NOT be any key used for `mkit-write:v2`,
grants, or receipts. Distinct roles MUST use distinct keys.

`<key id>` identifies a key in §7.2's list. It MUST be 1–64 bytes of
`[A-Za-z0-9._-]` and is chosen by the deployment.

`<audience>` is the hook endpoint's canonical origin, using the same
origin rules as STC §7.1 requires for its audience. It is not the
`operation.audience` or `outcome.audience` carried inside the body.

`<full procedure>` is the exact Connect path from §6.1. A verifier
MUST bind verification to the procedure receiving the request.

`<nonce>` MUST be 32 random bytes encoded as 64 lowercase hex digits.
The created and expiry fields are decimal epoch milliseconds.
The validity interval MUST be positive and at most 300,000 ms.
The sender's clock MAY lead the receiver's clock by at most 30,000 ms.

All of the following headers are REQUIRED:

| Header | Value |
|---|---|
| `X-Mkit-Hook-Version` | `1` |
| `X-Mkit-Hook-Key-Id` | The key id. |
| `X-Mkit-Hook-Audience` | The canonical hook endpoint origin. |
| `X-Mkit-Hook-Created-At` | The created epoch milliseconds. |
| `X-Mkit-Hook-Expires-At` | The expiry epoch milliseconds. |
| `X-Mkit-Hook-Nonce` | The 64 lowercase hex nonce. |
| `X-Mkit-Hook-Digest` | `body:` followed by the 64 lowercase hex BLAKE3 of the exact request body. |
| `X-Mkit-Hook-Signature` | The Ed25519 signature as 128 lowercase hex digits. |

The header values MUST match the corresponding canonical fields.
The hook server MUST:

1. Verify the signature against the public key selected from its
   current key list by the supplied key id.
2. Check that the audience equals its own canonical origin.
3. Check the validity window, including the positive interval,
   maximum duration, permitted clock lead, and unexpired expiry.
4. Check that the supplied digest equals `body:` plus the BLAKE3 of
   the exact received request body bytes.
5. Reject replay of a nonce within the validity window.

Outcome processing MUST additionally be idempotent by `reservation_id`.
Repeated logical delivery does not permit nonce replay to bypass the
channel authentication check.

Informative: a fresh signed delivery attempt can carry the same
durable Outcome body with a fresh hook nonce and validity window.
Body whitespace and JSON field order affect its digest even when the
decoded protobuf message is the same.

### 7.2 Key list and rotation

The key list is a JSON document with this shape:

```json
{
  "version": 1,
  "keys": [
    {
      "keyId": "deployment-hook-1",
      "alg": "ed25519",
      "publicKey": "<64 lowercase hex>",
      "notBeforeMs": "<int64 string, optional>",
      "notAfterMs": "<int64 string, optional>"
    }
  ]
}
```

`version` identifies this key-list format. `keys` contains the
accepted keys. Each `keyId` follows §7.1; `alg` is `ed25519`;
`publicKey` is a 32-byte public key as 64 lowercase hex digits.

`notBeforeMs` and `notAfterMs` are optional decimal signed 64-bit
epoch-millisecond strings defining key validity bounds. An absent
bound does not impose that bound. The hook server MUST honour each
present bound and MUST reject a key id absent from its current list.

To rotate, the deployment publishes the new key alongside the old
key, switches signing to the new key, and retires the old key after
the longest request validity interval has passed.

The document is distributed out of band by default. A server MAY
serve it at `GET /.well-known/mkit-hook-keys.json`, unauthenticated,
with `Cache-Control: max-age=300`.

Informative: distribution of the list establishes which deployment
keys a hook trusts. The optional well-known endpoint publishes public
keys; its availability does not place a private signing key on the
hook server.

### 7.3 Service-binding channels

On a platform service binding that is not reachable from the public
internet, a deployment MAY disable request signing for that channel.
Everything in §6 still applies, including codec support, field
semantics, response validation, and limits.

Informative: a Workers service binding is one deployment example.
The exception is configured for the isolated channel; a webhook
delivery uses the signed-request contract in §7.1.

## 8. Per-hook failure behaviour

Authorize and Admit MUST fail closed. A transport error, timeout,
non-2xx status, Connect error other than Authorize's deliberate Deny,
or invalid response under §6.6 MUST deny the operation with retryable
`unavailable` and MUST write no state.

A deliberate `deny` in a 2xx hook response is not a hook failure.
It uses the decision semantics of §6.2 or §6.3. Authorize's Deny is
the response decision specified there; it does not exempt arbitrary
Connect transport errors from failure handling.

Timeouts are deployment configuration. Informative: a default hook
timeout is 5 seconds.

Outcome delivery MUST retry with exponential backoff and jitter until
acknowledged. It MUST never be dropped. Any 2xx Connect response to
Outcome is an acknowledgement. Transport errors, timeouts, and
non-2xx responses leave the outcome awaiting delivery.

Informative: an initial retry interval of 1 second, a factor of 2,
and a cap of 15 minutes are example settings. The §5 retention rule
continues to apply regardless of the number of attempts.

Inspect MUST follow the inspector's configured mode. In fail-closed
mode, inspection failure rejects the push. In publish mode, publication
proceeds and inspection can quarantine the content later.

## 9. Published view (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 10. Quarantine (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 11. Admin API and audit log (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 12. Custom backends, backup and migrations (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 13. Conformance scope (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 14. Version history

| Version | Status | Change |
|---|---|---|
| 1 | draft | Initial M3 pipeline, durable outcome and remote-hook contract; M5 sections reserved. |

## 15. Test anchors

The fixtures under `rust/tests/golden/server-hooks/` are the authoritative
pinned bytes, as [SPEC-CONVENTIONS §5](SPEC-CONVENTIONS.md#5-golden-vectors-and-conformance-tests)
requires. These anchors are informative descriptions of those bytes.

| Golden file | Contract pinned |
|---|---|
| `authorize.request.json` | Operation, signer principal, and intended ref changes (§6.2). |
| `authorize-allow.response.json` | Empty Authorize allowance (§6.2). |
| `authorize-deny.response.json` | Deliberate Authorize denial code and public message (§6.2). |
| `admit.request.json` | BeginUpload pack id, declared bytes, authorization facts, and repository-byte presence (§6.3). |
| `admit-allow.response.json` | Reservation id and allowed receipt pass-through (§6.3, §6.6). |
| `admit-challenge.response.json` | Opaque challenge and example payment challenge header (§6.3, §6.6). |
| `admit-deny.response.json` | Deliberate admission denial (§6.3). |
| `inspect.request.json` | Provisional inspection operation and object metadata (§6.4). |
| `inspect-pass.response.json` | Empty inspection pass verdict (§6.4). |
| `outcome-committed.request.json` | Committed byte accounting and refs (§5, §6.5). |
| `outcome-aborted.request.json` | Apply-failure abort reason and operator detail (§5, §6.5). |
| `outcome-abandoned.request.json` | Pending reservation reconciled with ABANDONED (§5, §6.5). |
| `outcome-expired.request.json` | Unconsumed ticket expiry (§5, §6.5). |
| `outcome-read-served.request.json` | Paid-read object and bytes served (§5, §6.5). |
| `outcome.response.json` | Empty Outcome acknowledgement (§6.5, §8). |
| `signature.json` | Admit and Outcome exact bodies, canonical signing strings, hashes, signatures, and full headers (§7.1). |
| `key-list.json` | Public test key distribution document (§7.2). |
| `MANIFEST.txt` | BLAKE3 hashes of the other golden files (SPEC-CONVENTIONS §5). |

Informative: the signature vectors contain a clearly labelled test seed.
It is public fixture material and is not a deployment signing key.
