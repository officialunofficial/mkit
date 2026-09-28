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
remote hooks MUST still implement §2–§5 and §10. Every configured inspector,
including an in-process inspector without a remote hook, is bound by §11.
A deployment implements the business decisions exposed by hooks; the server
implements the pipeline, validation, durable recording, and delivery
guarantees specified here.

The contract does not define prices, payment verification, settlement
policy, moderation policy, or the deployment's account model.
[SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) remains authoritative for grants,
their verification, and the preconditions they carry into apply.

Sections 10–11 define the published view and inspection. Sections 12–14
reserve the remaining M5 contracts. Inspection fields extend the original
hook shape additively.
For a branch, its head and packmap share one publication sequence even
when either is written through `UpdateRef` (§10.2).

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
2. **Authorize.** Apply namespace and write policy as STC §7.5 requires.
   Evaluate the built-in namespace policy and rules 1–2 before a remote
   hook. Configure that hook as `authority` or `check` under §6.2;
   neither role overrides a namespace-policy denial. Carry the owner
   and grant facts into both Authorize and Admit requests.
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

The pending record is the arbiter. Every replacement of a pending
reservation MUST be conditional, in the same atomic unit, on the
record still being pending. This applies to the guarded apply
(§3's `BeginUpload` and directly admitted write rules), the separate
`Aborted` record, and the reconcile pass. A guarded apply whose
condition fails MUST commit nothing; the client receives retryable
`unavailable`. Thus a late apply cannot commit after reconciliation
has recorded `Aborted`, and at most one replacement succeeds.

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
The server MUST NOT send hooks any client credential except the
admission credential headers specified in §6.3, and MUST NOT send object
contents through this contract. The field definitions below use schema names; JSON uses
their lowerCamelCase equivalents.

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
before admission. The deployment MUST configure remote Authorize in
one of these two roles:

- **`authority`:** the hook is the deployment-defined authority source
  of STC §7.5 rule 3. The built-in namespace policy (`allowlist`/`any`)
  MUST be evaluated first; a hook Allow MUST NOT override its denial.
  Rules 1–2 (owner key and grant) MUST be evaluated before the hook.
  If either authorizes, the hook MUST still be called and MAY deny.
- **`check`:** the built-in namespace and write policy MUST run first.
  The hook can only deny further; it MUST NOT authorize a write the
  built-in policy rejected.

These roles compose with authorization as STC §7.5 requires. Grant
verification and its failure handling remain as SPEC-WRITE-GRANTS
requires; remote Allow does not bypass them.

`Operation` has the following fields, also used by Admit and Inspect:

| Field | Meaning |
|---|---|
| `audience` | The mkit server's canonical origin, distinct from the hook endpoint's signing audience in §7.1. |
| `repository` | The full repository identity, as STC §7.4 requires. |
| `procedure` | The full procedure path of the client RPC being evaluated. |
| `principal` | The identity established by the server at stage 1. |
| `idempotency_key` | The auth v2 nonce of a signed write; empty otherwise. |
| `refs` | The intended ref changes, in decision order. |
| `owner` | Whether the principal owns the namespace under STC §7.5 rule 1; set on both Authorize and Admit requests. |
| `grant` | The write grant used under STC §7.5 rule 2, if any, and its checked epoch; set on both Authorize and Admit requests. |

`owner` and `grant` carry the result of STC §7.5 rules 1–2 on both
Authorize and Admit requests. An absent grant means no write grant
was used. Grant verification and apply preconditions remain
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

Authorize receives the established principal, not a credential to verify
on the client's behalf. Admit receives the admission credential headers
specified in §6.3. Request authenticity on the hook channel is checked
separately under §7.

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
permits the operation to continue. Its `writer_view` boolean lets an
`authority` hook classify a signed caller as a repository writer under
§10.1. A `check` hook MUST NOT confer writer status through this field.
An allowance does not itself perform admission, authorize a private read,
or commit a write.
For an otherwise authorized public read, an `authority` hook consulted
solely for writer-view classification cannot deny the read: a denial or
hook failure selects the reader view (§10.1).

`Deny.code` is a Connect code name. For Authorize, the allowed names
are exactly `permission_denied`, `not_found`, and `unauthenticated`.
The server MUST answer any other value as `permission_denied`.
`not_found` is honoured only on read procedures, where it hides a
private repository; on a write the server MUST answer it as
`permission_denied`.

`Deny.message` is public text for the client. It MUST be at most 512
bytes of UTF-8 and contain no control characters. If it breaks either
rule, the server MUST replace it with a generic public message.
Code fallback and message replacement are the specified sanitization
of a deliberate denial, not hook transport failures.

The same `Deny` message shape is used by Admit and Inspect. For either
hook's pre-commit denial, the server MUST answer `permission_denied` with HTTP 403,
never 402, whatever `Deny.code` says, as STC §5 requires for an
admission denial. The public-message sanitation rule above applies
to denials from all three hooks.

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
| `credential_headers` | Admission credential request headers under the forwarding rules below; empty on a first attempt without credentials. |

Creation signals and admission input are supplied as STC §5.1 requires.
In particular, `new_to_repo_bytes` does not mean bytes new to the whole
store. Presence MUST preserve the distinction between unknown and zero.

**Credential headers.** The server MUST forward in `credential_headers`
the request headers permitted from a client's admission helper by STC
§5.1 and selected by the forwarding rules below. It MUST NOT forward
any other request header.

The default forwarded names are `Payment-Authorization`,
`PAYMENT-SIGNATURE`, and `Authorization` under the rule below. Header
names MUST be compared case-insensitively. A deployment MAY configure
additional forwarded names, but configuration MUST NOT add
`Authorization`, and the server MUST NOT forward any STC §5.1
hard-reserved name, whatever its configuration.

`Authorization` is forwarded only when the request carries exactly one
`Authorization` field line whose value is the auth-scheme `Payment`
(RFC 9110 §11.1, compared case-insensitively), then one or more SP, then
a token68 (RFC 9110 §11.2), with no comma. In every other case,
including any other scheme, no `Authorization` entry is forwarded: an
`Authorization` field with another scheme is the client's own
authentication, and a bearer token MUST NOT be forwarded.

The server MUST send header names as received. Each forwarded name MUST
appear at most once in the request: a selected name that the request
carries more than once, or as a comma-joined value, is an admission
denial. Each value MUST consist only of visible ASCII, SP and HTAB. The
list MUST contain at most 8 entries, and each value MUST be at most
8,192 bytes. If a selected header breaks any of these rules, the server
MUST deny admission with `permission_denied` under STC §5's
admission-denial row, without calling Admit or writing any state.

An empty list means the request carried no admission credential. This
is the normal first attempt, which the hook typically answers with a
challenge.

These headers are payment credentials. The server and the hook MUST
keep them out of logs, traces, error messages, and analytics, as STC
§5.1 "Redaction" requires. Their channel protection is specified in §7:
signed requests over verified TLS (subject to §6.1's loopback exception),
or service-binding isolation under §7.3.

Informative: on a signed channel, the §7.1 `body:` digest signs the
request body, so admission credential headers carried in that body are
covered by the hook-channel signature. A §7.3 service-binding channel is
unsigned.

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
message described in §6.2 and the client response STC §5 requires.
It allocates no pending reservation.
A `challenge` likewise allocates no pending reservation.

Informative: the deployment chooses how a reservation represents a
payment authorization, quota hold, or another external obligation.
The reservation id lets the later outcome discharge that obligation
without exposing the deployment's internal account identifiers.

### 6.4 Inspect

Inspection follows §11, with the caller's published view defined in §10.
`publish` and `fail_closed` apply only to inspector unavailability, never
as an override of a deliberate verdict.

`InspectRequest.operation` is the operation defined in §6.2.
Across an inspector's batches, `InspectRequest.objects` MUST enumerate
the inspected set in §11.1; each call contains its assigned batch.
The listed objects are decoded pack entries in indexed mode, including
file objects newly reachable from previously added packs.
Each `InspectObject.id` is a 32-byte object id; `size` is its unsigned
object size in bytes. `kind` identifies `BLOB`, `CHUNKED_FILE` (the
ChunkedBlob manifest), or `CHUNK` under `InspectObjectKind`.

`InspectRequest.phase` MUST be `INSPECT_PHASE_PRE_RECEIVE` at stage 5 or
`INSPECT_PHASE_QUARANTINE` at stage 9. `inspection_id` MUST be nonempty
and identify the logical inspection under §11.3. New callers MUST send
explicit phases and kinds; `UNSPECIFIED` is retained for the original
additive wire shape, not permission to omit the inspected set.

Object bytes MUST NOT be sent in the Inspect request. Inspectors that
need bytes MUST fetch them through a deployment-private channel, never
through the public serving path, which serves only published content.
That private channel MUST be accessible only to authorized inspectors.

`InspectResponse.verdict` selects one alternative:

| Alternative | Meaning |
|---|---|
| `pass` | This inspector permits the inspected content. |
| `quarantine` | Hold an unpublished advance or suspend serving flagged content after publication (§11). |
| `reject` | Pre-receive denial, or an asynchronous hit requiring takedown (§11). |
| `defer` | Asynchronous re-poll with `retry_after_ms` (§11.3); invalid in pre-receive. |

`InspectQuarantine.reason` is inspection-policy text, at most 512 bytes
under §6.6, not an object body. A synchronous `reject` returns
`permission_denied` with HTTP 403, never 402, whatever `reject.code`
says. Its public message follows §6.2's sanitation rule. An asynchronous
`reject` cannot reject an already committed push or replace `Committed`.

`flagged_objects` contains raw 32-byte object ids and is meaningful only
with `reject` or `quarantine`. Each listed id MUST belong to the request's
inspected set. Invalid ids or a nonempty list on `pass` or `defer` make
the response invalid under §6.6. Every QUARANTINE-phase `reject` or
`quarantine` MUST identify at least one flagged object; otherwise the
response is invalid under §6.6. A PRE_RECEIVE verdict MAY leave the list
empty because it governs the entire push. §11.3 immediately suspends
serving flagged objects, and §14 defines the takedown rewrite mechanics.

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

Request limits, checked before calling Admit: forwarded
`credential_headers` MUST contain at most 8 entries, each value at most
8,192 bytes of visible ASCII, SP and HTAB, with each name at most once.
A request breaking them is an admission denial, as §6.3 specifies; it is
not a hook failure under §8.

The server MUST validate hook responses before using them. A response
violating any response limit below is invalid and MUST be handled under
§8. The specified `Deny` sanitation in §6.2 applies separately.

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
- A `reservation_id` MUST be unique per server audience across all
  operations. If the server finds an existing pending record or
  terminal outcome for the returned `reservation_id`, whether for a
  different operation or for a retry of the same one, it MUST treat the
  response as invalid under §8. A hook MUST return a fresh id for each
  allowance.
- `InspectQuarantine.reason` MUST be at most 512 bytes.
- Inspect responses MUST satisfy the phase and flagged-id rules of §6.4.

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

Informative: the audience is an origin, so hook services at different
paths on one origin share an audience. They SHOULD use distinct keys.

`<full procedure>` is the exact Connect path from §6.1. A verifier
MUST bind verification to the procedure receiving the request.

`<nonce>` MUST be 32 random bytes encoded as 64 lowercase hex digits.
The created and expiry fields are decimal epoch milliseconds. They
MUST contain only base-10 ASCII digits, with no sign and no leading
zeros; a single `0` is allowed.
The validity interval MUST be positive and at most 300,000 ms.
The sender's clock MAY lead the receiver's clock by at most 30,000 ms.

A hook server MUST reject a request whose `X-Mkit-Hook-Version` is
missing or is not `1`, or that lacks any required header, before
reading the body.

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

Hook responses are not signed. Their authenticity rests on TLS with
server-certificate verification, which the calling server MUST perform
(plain HTTP is permitted only to loopback, §6.1), or on the isolation
of a service binding (§7.3).

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
The exception is an otherwise authorized public read for which an
authority hook is consulted solely to classify the writer view (§6.2):
its denial or failure selects the reader view without an error.

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

Inspect transport errors, timeouts, non-2xx responses, Connect errors,
and invalid responses are inspector unavailability. They MUST follow
that inspector's `on_unavailable` setting under §11, except that a
request-size or §6.6-limit failure is never eligible for `publish`.
Deliberate verdicts MUST follow their phase-specific semantics regardless
of that setting.
Synchronous `fail_closed` unavailability returns retryable `unavailable`;
asynchronous unavailability never rejects the committed push.

## 9. Indexed mode

### 9.1 Scope and opt-in

Indexed mode is opt-in per deployment. A deployment advertises its
choice through `GetServerInfo.indexed_mode`, as
[STC §2.1](SPEC-TRANSPORT-CONNECT.md#21-getserverinfo) requires.
Clients use that discovery result when planning uploads and interpreting
verification responses.

Opaque mode is the default; packs are stored as opaque bytes. In that
mode, §9.2–§9.6 do not apply; of §9.8, only the effective
`max_pack_bytes` and the `max_delta_chain_depth = 0` advertisement
apply. The allowed-signer policy in
§9.7(a) applies in both modes because it depends only on the request's
authenticated signer. Fast-forward-only (§9.7(b)) requires indexed
mode. Upload commitments, authentication, tickets, and membership
still follow STC; opaque storage does not relax those wire guarantees.

An indexed deployment decodes pushed packs and indexes their objects
per repository. Verification precedes ref publication. Upload completion
by itself establishes neither repository membership nor permission to
serve an extracted object; those decisions follow STC §7.6–§7.7 and the
HTTP-serving contract respectively.

Informative: a deployment can verify inline or schedule verification
between upload and advance. These are two ways to implement the same
acceptance contract, not different client-visible integrity guarantees.
The asynchronous case is specified in §9.5.

### 9.2 Classification

On upload completion of a ticketed blob, an indexed server MUST classify
it by its first four bytes:

| First four bytes | Upload type |
|---|---|
| `MKIT` | Pack, encoded under [SPEC-PACKFILE §1](SPEC-PACKFILE.md#1-high-level-layout). |
| `MKPL` | Packlist node. |
| Any other value, including fewer than four bytes | Unknown upload type. |

The `MKIT` bytes identify a pack; `MKPL` identifies a packlist node.
Classification selects the validation path. Recognized magic does not
by itself establish that the rest of the upload is valid.

An unknown type MUST fail with `invalid_argument` and public message
`unknown upload type` at the `AdvanceRefs` that consumes its ticket,
or earlier under §9.5. No ref moves as a result of that failed advance.

Every pack listed by a consumed `MKPL` node MUST either already be a
member of the same repository or be ticketed and consumed in the same
`AdvanceRefs`. A membership-dependent miss follows the lag window in
§9.4; after that window, it fails with `invalid_argument` and public
message `packlist lists a pack that is not in this repository`.

Packlist nodes themselves need tickets, as STC §7.6's membership rule
requires. A node's upload is not evidence that its listed packs belong
to the repository. A globally stored pack is not a repository member
merely because the node names its id.

Informative: an advance can consume tickets for newly uploaded packs
and for the packlist node that lists them. Membership additions then
commit under the existing atomic lifecycle in §3 and STC §7.7.

### 9.3 Verification obligations

Before an `AdvanceRefs` that consumes a pack commits, the server MUST
have verified all of the following:

- **(a) Object identity.** Every object's id agrees with its content under
  [SPEC-OBJECTS §10](SPEC-OBJECTS.md#10-storage), including the
  type-specific identity rules referenced there.
- **(b) Signatures.** Every commit, remix, and tag signature reachable
  from the new tips verifies under
  [SPEC-SIGNING §3–§4a and §6](SPEC-SIGNING.md#6-verification-algorithm).
- **(c) Closure.** Every object reachable from the advanced head is in
  the consumed packs or is already a verified member of the same
  repository. A membership-dependent miss follows §9.4's lag window
  before it is a permanent `open closure` failure. Object references
  follow the corresponding object layouts in
  [SPEC-OBJECTS §4–§7](SPEC-OBJECTS.md#4-tree-0x02).
- **(d) Delta resolution.** Every delta resolves under §9.4 within the
  chain-depth limit advertised under §9.8.

Object identity is checked on the reconstructed object, not on an
unverified claim in an entry. A transport-level pack commitment does
not replace the object identity or signature checks.

Signature validity uses the signed fields and domain separators of
SPEC-SIGNING. It does not imply that the auth v2 signer is an allowed
signer for a particular ref; that separate policy is in §9.7.

The following failures MUST return `invalid_argument` with exactly
the public message shown (the `open closure` row follows §9.4's lag
rule):

| Verification failure | Public message |
|---|---|
| Object id does not match its content | `object hash mismatch` |
| Commit, remix, or tag signature does not verify | `bad signature` |
| Reachable object is absent from the permitted closure after §9.4's lag window | `open closure` |
| Delta chain exceeds the advertised cap | `delta chain too deep` |

These are permanent failures. Clients MUST NOT retry the rejected
upload as though polling or backoff could make its content valid.
An unresolved external delta base follows §9.4's distinct visibility
and replanning rules rather than being reported as an open closure.

Informative: verified repository members can supply already checked
objects for closure. This does not allow an unverified staged object
to stand in for a verified member, or permit a membership lookup in
another repository.

### 9.4 Repository-isolated membership checks

A delta base MUST resolve only from an earlier entry in the same pack,
as [SPEC-PACKFILE §4](SPEC-PACKFILE.md#4-ordering-rule) requires for
in-pack resolution, or from verified members of the same repository.
A server MUST NOT resolve a base from another repository or from the
global content store.

Whether a push is accepted or rejected, and its public error text,
MUST NOT depend on whether the object exists anywhere outside the
repository. This applies the isolation guarantee of
[STC §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing) to
verification as well as to ordinary membership queries.

Repository membership is eventually consistent under STC §7.9.
Every membership-dependent check MUST use the lag window below:
delta-base resolution, closure (§9.3(c)), and the packlist rule (§9.2).
Each check reads only the membership of the same repository.

For a membership-dependent miss, while the consuming ticket is younger
than the deployment's relay-lag bound, the server MUST return retryable
`unavailable` with public message `repository membership not yet visible`.
The same message applies to all three checks. This temporary response
is permitted only within that interval.

Once the consuming ticket is older than that bound, the server MUST
return the permanent error of the check that missed:

| Membership-dependent miss | Connect code | Exact public message |
|---|---|---|
| Unresolved delta base | `failed_precondition` | `delta base not available in this repository` |
| Reachable object absent from the permitted closure | `invalid_argument` | `open closure` |
| Packlist names a pack absent from the repository and not ticketed and consumed in the same advance | `invalid_argument` | `packlist lists a pack that is not in this repository` |

Each permanent response MUST be byte-identical whether the object or
pack exists in another repository or nowhere. The temporary response
also MUST NOT distinguish those cases. The server uses ticket age and
repository-scoped visibility, not a global-existence query, to select
the response.

A membership-lag `unavailable` MUST NOT be stored as a replay result
(STC §7.1). The server MUST leave no replay record for the attempt and
remove any `in_flight` record it inserted, so the same nonce can be
evaluated again as membership becomes visible.

Informative: the consuming ticket's age is a sound proxy because the
needed object or pack was written before the client fetched it, which
was before `BeginUpload`.

The relay-lag bound is deployment configuration. It bounds the
visibility retry interval; it is not a claim that an unresolved object
must exist elsewhere. It does not extend the ticket's expiry.

On the delta-base `failed_precondition`, a client MUST re-plan the upload once
as a self-contained pack with no external delta bases and retry with
a new signed operation (new nonce) with a new ticket, as STC §7.6
requires. A second failure does not start an unbounded series of
replans.

Informative: repository A and repository B may hold identical bytes.
A delta pushed to B cannot use A's membership to satisfy resolution.
Adding or deleting a copy in A cannot alter B's acceptance decision
or public error response.

### 9.5 Asynchronous verification

Verification MAY run asynchronously after upload completion. While a
consumed pack is still unverified, `AdvanceRefs` MUST fail with
`unavailable` and exactly one `PendingVerification` detail, as
[STC §7.6](SPEC-TRANSPORT-CONNECT.md#76-upload-tickets-and-resumable-parts)
requires. This answer MUST NOT be stored as a replay result, under
STC §7.1; a retry must be able to observe verification progress.

`PendingVerification.retry_after_ms` is the server's suggested poll
interval in milliseconds. The server SHOULD send at least 1,000.
STC §7.6 requires the client to clamp it to 1,000–60,000 milliseconds;
a missing or zero value means 1,000. The client polls until ticket
expiry, using that polling interval instead of its normal backoff
ladder.

A pending answer is not a committed advance. The existing ticket
lifecycle remains authoritative; upload completion, verification
progress, and a pending response do not themselves consume a ticket
or move refs.

A server MAY report an upload-local failure earlier than the advance,
for example on `CompleteUpload`, only when the consuming advance would
also report it and it depends on the uploaded bytes alone: an unknown
upload type, an object hash mismatch, a bad signature on an object the
advance would check under §9.3(b), or a delta chain too deep whose whole
chain is inside the pack. An earlier report
MUST use `invalid_argument` and the same public message as at advance;
it MUST NOT use `failed_precondition`, which STC §5 maps to a ticket
failure on upload RPCs. Membership-dependent failures (§9.4) MUST be
reported only on the consuming `AdvanceRefs`.

Asynchronous scheduling does not turn a permanent validation failure
into a successful completion of the advance.

Verification state is per `(repository, pack)`. A pack verified for
one repository is not thereby verified for another. Global byte
reuse does not carry repository membership or verification authority
from one repository into another.

A server MUST make verification progress resumable across restarts
without re-yielding unverified content. It MUST bind resumed reads to
an unchanged source object. A restart cannot combine a verified prefix
from one source version with a suffix from another version.

Informative: a checkpoint can retain the entry cursor and running
hash state. An entity-tag condition on range reads is one way to bind
subsequent reads to the unchanged source. This example does not
prescribe a storage provider or a checkpoint encoding.

Informative sequence for a successful asynchronous push:

1. The client obtains a ticket and finishes uploading the pack under
   STC §7.6. The server classifies it and schedules verification.
2. The client attempts `AdvanceRefs` with that ticket. Verification
   is pending, so the server returns `unavailable` with one
   `PendingVerification` detail and stores no replay result.
3. The client waits the clamped `retry_after_ms` and polls. It reuses
   the nonce while its envelope is valid. After the validity interval
   lapses, it signs a new operation over the request, under STC §7.1's
   300-second limit.
4. Verification finishes. A later attempt passes verification and
   the remaining policy and apply preconditions, then commits under
   STC §7.7. If the ticket expires first, the client stops polling it.

### 9.6 Extraction (D32)

At verified ingest, the server MUST extract the following file content
into a global content-addressed object store:

- Every plain blob whose file content is at least the deployment's
  extraction threshold. The default threshold is 65,536 bytes.
- Every chunked blob, reassembled once into one object keyed by its
  manifest id, regardless of the plain-blob threshold.

Plain blob content follows
[SPEC-OBJECTS §3](SPEC-OBJECTS.md#3-blob-0x01). Chunked-blob manifests
and their ordered chunks follow
[SPEC-OBJECTS §7](SPEC-OBJECTS.md#7-chunked-blob-0x05).
The extracted plain blob is keyed by its object id. The reassembled
chunked file is keyed by the manifest's object id, not by the id of
an individual chunk or a newly invented file hash.

Reassembly uses manifest order and the declared total size. Extraction
adds a serving copy; it MUST NOT remove chunks or other objects from
their packs. The packs remain available for clone and fetch.

Extraction is file-level deduplicated by object id across repositories.
The store can retain one serving copy for repositories that share the
same file object. Deduplication does not make that object a verified
member of every repository that mentions its id.

Serving is authorized per repository (the HTTP-serving specification).
Existence in the global content store MUST NOT be observable through
this transport protocol, as §9.4 requires. The extracted serving copy
MUST NOT become a delta-base resolution source.

Informative: deduplication may change the amount or timing of
server-side work. Protocol responses do not differ based on
deduplication. Deployments that treat timing as sensitive can disable
deduplication.

Informative: extracted objects are served with byte-range support
under the HTTP-serving specification. A range reads file bytes from
the serving copy without changing the pack representation used by
clone and fetch.

The extraction threshold is deployment configuration. It is not
advertised through `GetServerInfo`. It does not change object identity,
chunk layout, or the client's upload obligations.

### 9.7 Ref policy

A deployment MAY configure the following policies per ref-name pattern,
using the grammar of
[SPEC-WRITE-GRANTS §3.3](SPEC-WRITE-GRANTS.md#33-ref-scope-entries):

- **(a) Allowed-signer set.** Only the configured auth v2 signers may move
  matching refs.
- **(b) Fast-forward-only.** A matching ref may only move to a descendant
  of its current value.

Both policies are checked at pre-receive (§2 stage 5), after
verification in indexed mode. A policy violation MUST fail with
`permission_denied` and the corresponding public message:

| Policy violated | Public message |
|---|---|
| Allowed-signer set | `signer not allowed for this ref` |
| Fast-forward-only | `non-fast-forward update not allowed on this ref` |

The allowed-signer set applies in both modes to the authenticated
operation signer. Valid signatures on reachable commits do not
independently authorize that signer to move the ref. Grant and
namespace authorization remain subject to STC and SPEC-WRITE-GRANTS.

Fast-forward-only requires indexed mode because the server needs the
commit graph. An opaque-mode deployment MUST refuse to start with a
fast-forward-only rule configured.

Deletion of a fast-forward-only ref, including the deletion operations
in STC §7.8, MUST be refused with the same `permission_denied` and
`non-fast-forward update not allowed on this ref` message.

These are generic pre-receive policies. Attestation predicates,
attestation carriage, and attestation-gated refs are outside this
contract (D33).

### 9.8 Limits advertised

`GetServerInfo.max_pack_bytes` is the effective accepted pack-size
limit in the deployment's mode, as STC §2.1 requires. An indexed
deployment MAY advertise a lower limit than an opaque deployment.
Clients plan uploads against the advertised effective value.

`GetServerInfo.max_delta_chain_depth` is the delta-chain depth cap.
The default in indexed mode is 50. A chain deeper than the advertised
cap fails under §9.3, even if all its bases are visible in the repository.

When indexed mode is off, the server MUST advertise
`max_delta_chain_depth = 0`. That value indicates that the indexed
verification cap is inapplicable; it does not enable indexed validation
in an opaque deployment.

The pack-size and chain-depth limits are distinct. A pack below the
size limit can still exceed the chain-depth cap. Neither limit changes
repository-isolated resolution or permits global-existence disclosure.

## 10. Published view

### 10.1 Caller's view

A **caller's view** is the pair of visible ref values and visible repository
membership used to answer that request. View selection MUST NOT grant
read authorization or override repository privacy, suspension, or takedown.
In particular, a `write`-only grant does not imply `read` of a private
repository (SPEC-WRITE-GRANTS §6).

`caller_view` is `writer`, `reader`, or `anonymous`. A caller is a writer
only when its signed request establishes one of these for the repository:

- an owner key;
- a verified grant with `write` or `read,write` capability covering the
  repository, with any ref scope;
- an authenticated ssh/enc principal authorized to write; or
- an authority source's Authorize allowance with `writer_view = true`.

Writer classification is per repository, not per requested ref. A grant
restricted to one ref can establish the repository's writer view; it does
not authorize writes to other refs. SSH/enc uses the authenticated signed
transport identity under SPEC-WRITE-GRANTS §10.

With `write_policy = open`, any valid signed writer is a writer for this
purpose; §11.1 therefore forbids inspection with that policy. For a public
repository, the authority hook is consulted only for this classification:
its denial or failure gives the reader view, not a read error. A bearer
token by itself MUST NOT establish the writer view.

All other authorized callers receive the reader view. An unauthenticated
caller has `caller_view = anonymous` and receives the same published view
where public reads are allowed. An unsigned request receives the reader
view even if the caller possesses a write key. Clients with a signer MUST
sign reads to be seen as writers (SPEC-WRITE-GRANTS §9.2).

A writer sees live ref values and live repository membership, including
all pending advances in the repository. Readers and anonymous callers
see published ref values and published membership only. These rules
apply on every serving surface, including HTTP consumers of this
abstract view.

### 10.2 Per-ref clearance and publication

Each ref MUST have an ordered advance sequence. The branch head
`refs/heads/<x>` and `refs/mkit/packmap/<x>` share one sequence: every
successful `AdvanceRefs`, head-only `UpdateRef`, or packmap-only
`UpdateRef` appends an advance to that sequence. The advance value is
the live (head, packmap) pair, and the pair MUST be published together.
Other refs have their own sequences and target values. Failed writes do
not append advances. In indexed mode with an inspector configured, a
head-only `UpdateRef` MUST verify before apply that its unchanged packmap
reconstructs the new head's closure; a packmap-only `UpdateRef` MUST
verify the resulting pair too (§9.3; STC §4 defines the paired advance).
This extra check is unnecessary in opaque mode or without inspectors,
where the published view equals the live view.

Each advance has a clearance state:

| State | Meaning |
|---|---|
| `pending` | Inspection, dependency clearance, or both remain outstanding. |
| `cleared` | Its inspection obligations and membership dependencies permit publication. |
| `held` | A quarantine verdict awaits re-inspection or admin release. |
| `hit` | A rejection awaits takedown completion. |
| `resolved` | Takedown has completed and all non-hit obligations are satisfied; it no longer blocks the publication prefix. |

The published value MUST be the value at the largest sequence number
*k* for which every advance up to *k* is `cleared` or `resolved`.
Until the first such value exists, the ref is absent to readers. A later
pass MUST NOT skip an earlier `pending`, `held`, or `hit` advance. A
`resolved` advance uses the value subject to completed takedown, never
restores flagged content through its original value.

**Published membership** is repository membership added by a `cleared`
or `resolved` advance, subject to deletion, suspension, and takedown.
For a `resolved` advance, it is the post-takedown membership of
replacement packs, not the removed packs. §14 defines the rewrite
mechanics. Server-initiated takedown pack rewrites and packmap updates
are not advances: they take no advance sequence number and carry no new
inspection obligation. An advance blocked only on a taken-down pack
MUST be re-evaluated against the replacement packs.

When no inspector is configured, a single-repository unticketed upload
permitted by STC §7.6 has no inspection obligation: its membership is
published with its storage commit, preserving STC's immediate membership
rule. An inspection-enabled deployment cannot use that path (§11.1).
An advance *k* clears only when all of these conditions hold:

1. Its own inspection obligations pass under §11, or each receives its
   explicit unavailable-publish deadline or audited admin release.
2. Every pack on its packmap chain is already in published membership
   or is added by *k* itself. For a non-branch ref, every object in its
   reachable closure MUST be contained in at least one published pack,
   counting *k*'s additions in the same atomic clearance.
3. No flagged id in the repository occurs in its inspected set or its
   packs (§11.3).

Clearing *k* MUST atomically publish its added membership and update the
published ref pointer to the largest eligible prefix. Completion out of
order can make membership eligible, but MUST NOT expose a ref value
beyond that prefix. A branch's head and packmap MUST remain a pair in
both live and published views. Publishing membership MUST durably
schedule re-evaluation of every advance previously blocked on that
membership in any ref. The scheduled work MUST be retained until
completed and MUST run within a bounded time. The same rule applies when
takedown replacement packs become published.

A pack added by another advance that has not cleared or resolved blocks
clearance. `AlreadyPresent` establishes live membership, not published
membership. Thus branch B reusing a pack from pending branch A cannot
publish it; neither can a tag pointing at a commit whose containing pack
is pending. The advance's own additions qualify in the same atomic
clearance, so initial publication has no circular membership dependency.

Deletions MUST publish immediately under STC §7.8 and MUST NOT wait for
inspection. They establish a ref-value publication boundary: later
verdicts on older advances MUST NOT change or resurrect that ref value.
Those verdicts still govern membership the older advances added: a pass
publishes it, a hold keeps it unpublished, and a hit takes it down.
A recreated ref, or another ref reusing the packs, can clear when that
membership becomes published. Later ref values are evaluated from the
deletion boundary under the ordinary inspection and dependency rules.

The server MUST retain every `pending`, `held`, or `hit` advance value,
together with its packmap chain, closure packs, and any takedown
replacement packs. Retention lasts until the advance is `cleared`,
`resolved`, or superseded. A `hit` advance MUST remain until its §14
takedown completes, even if its ref value is superseded. §13 makes
these GC roots.

The published pointer MUST be written in the same apply for an advance
that starts `cleared` and has an eligible prefix. An advance starting
`held` leaves the previous published value in place.
Published equals live exactly while no advance on that ref is held or
pending (and no hit awaits resolution). A deployment with only
synchronous inspectors MUST still maintain the published view.

### 10.3 Every reader surface uses the published view

`ListRefs`, `ReadRef`, `PackExists`, `DownloadPack`, `X-Mkit-Ref`, snapshots,
URL tokens, HTTP object serving, and caches MUST answer from the caller's
view. A pending ref value or unpublished pack MUST behave exactly like
an absent value or pack: omit it from listings, return `exists = false`,
or return `not_found`, as the surface's ordinary absent response requires.
An existing published ref continues to return its previous published value.
Reader responses MUST NOT expose live targets, pending pack ids, or
inspection state through alternate metadata or errors.

Published packlist nodes and delta bases MUST NOT reference unpublished
or pending ids. Informative: when every ref is pending, a reader sees an
existing empty repository. This is an accepted consequence of the
published view.

`X-Mkit-Ref` MUST NOT widen this view (STC §7.9). Snapshots and reader
caches MUST be built only from published values and membership. Writer
responses containing pending content MUST NOT enter a reader-visible
cache. Index lag can delay publication but MUST NOT expose live membership
to readers. A public serving copy or global byte reuse is not evidence of
published membership in this repository.

URL tokens MUST resolve in the published view even when issued by a writer
(SPEC-WRITE-GRANTS §9.4). A token MUST NOT turn a pending object into a
published one. HTTP serving MUST use visible ref values and visible
membership from this section before returning object bytes or proofs.

`GetServerInfoResponse.async_inspection` MUST report whether any asynchronous
inspector is configured, independently of repository existence. Writers
MUST sign reads to see their pending or held content. A false value does
not exempt synchronous quarantine from that rule or from the published
view.

## 11. Quarantine and inspection

### 11.1 Configuration and inspected set

Each configured inspector, remote or in-process, has a phase, `sync` or
`async`, and an `on_unavailable` setting, `fail_closed` or `publish`.
These settings govern only unavailability (§8); they MUST NOT override
`reject`, `quarantine`, or `defer`. A deployment MUST refuse startup if
opaque mode or `write_policy = open` is combined with any inspector.
Opaque mode cannot enumerate pack objects; open writes let any signer
obtain the writer view (§10.1). An async inspector or an inspector with
`on_unavailable = publish` MUST configure
`inspection_clear_deadline_ms`; otherwise startup MUST be refused.

An inspection-enabled deployment MUST require ticketed uploads and
advertise `begin_upload_threshold_bytes = 0` (STC §7.6), including in
single-repository mode. This associates all added pack entries with an
advance. Storage completion alone MUST NOT establish published
membership.

A file object is a plain blob of any size, a ChunkedBlob manifest, or a
chunk. The inspected set of each advance MUST be the union of:

1. every file object reachable from the advanced ref value but not
   contained in the repository's published membership, including
   manifests, their chunks, and extracted objects; and
2. every file entry of every pack that the advance adds to repository
   membership, whether reachable or not.

The server MUST NOT permit any configuration to narrow this set by size,
extraction status, or reachability within an added pack. The same set
MUST be inspected in both phases. Duplicate object ids need only one
entry; a blob used both as a file and as a chunk is reported once as a
`BLOB`. Extraction creates a serving copy, not an exemption from
inspection. Commit, tag and remix messages and tree entry names are
not inspected; they remain a residual content channel.

An inspected set larger than `inspect_batch_max_objects` MUST be sent
in multiple Inspect calls of at most that many objects each. This named
parameter defaults to 10,000. Each inspector has a separate obligation
for each batch, and its advance-level obligation is satisfied only when
all its batches pass or each receives an explicit release under §11.3.
A failure caused by the request's own size or §6.6 limits MUST NOT be
eligible for unavailable-publish: its obligation remains `pending` and
the server MUST use compliant batches before clearance.

Rationale: inspecting all newly reachable file objects also covers
surplus file entries in added packs. §9.3(c) permits entries outside the
closure; a published whole-pack download could otherwise reveal them.
Packs MUST NOT be rejected merely for surplus entries.

### 11.2 Synchronous checks

At stage 5, the server MUST call each synchronous inspector with
`phase = INSPECT_PHASE_PRE_RECEIVE` before apply:

| Result | Effect |
|---|---|
| `pass` | Satisfy this inspector's obligation and continue. |
| `reject` | Reject with `permission_denied` (HTTP 403); do not commit the advance. |
| `quarantine` | Commit the push, but start the advance `held`. |
| Unavailable, `fail_closed` | Return retryable `unavailable`; do not commit the advance. |
| Unavailable, `publish` | Commit with this obligation `pending`, schedule a QUARANTINE-phase inspection of the same set, and apply its configured clear deadline under §11.3. |

`defer` is invalid in this phase. A reject from any synchronous
inspector MUST deny the operation even if another returned quarantine.
A pass by one inspector MUST NOT override another's quarantine or
rejection. A synchronous hold persists even with no asynchronous
inspector until QUARANTINE-phase re-inspection or admin release. The
server MUST schedule that re-inspection on an admin release request or
retry schedule. If no hold remains but async or unavailable-publish
obligations remain, the committed advance starts `pending`; otherwise
§10 determines clearance.

A synchronous `fail_closed` `unavailable` is excluded from replay
storage by STC §7.1. A retry therefore re-runs the pre-receive check.

### 11.3 Asynchronous checks and resolution

Stage 6 commits live ref values, added membership, obligations, and
durable scheduling in the same apply. Stage 9 calls MUST be scheduled
from the outbox or a timer, resumable across restarts, and retried with
backoff. `AdvanceRefs` succeeds and records its applicable `Committed`
outcomes under §3–§5; subsequent inspection MUST NOT change that outcome
to `Aborted`, `Expired`, or rejection of the committed push.

Each configured inspector gives each advance its own obligation, split
into batches under §11.1. Each logical call MUST use a stable, nonempty
`inspection_id`, unique within the deployment for its inspector,
advance, phase, and inspected batch. Retries MUST preserve the id and
batch; the inspector MUST handle them idempotently. Deliberate
re-inspection uses a new id and supersedes the old logical call. The
server MUST ignore verdicts for a superseded `inspection_id`. Hook
authentication uses a fresh envelope under §7 as needed; its nonce is
distinct from the inspection id.

Before publication, the advance state is derived from its obligations
with precedence `hit > held > pending > cleared`. A hit becomes
`resolved` only after takedown completes **and** every non-hit
obligation is satisfied; until then it blocks the publication prefix.
Publication of advance *k* occurs when *k* clears under §10.2. A
verdict arriving afterward is post-publication even if another advance
still blocks the ref pointer. It MUST NOT un-publish a ref value.

| QUARANTINE-phase result | Effect |
|---|---|
| `pass` | Satisfy this inspector's batch obligation; clear when all obligations and §10 dependencies permit. |
| `quarantine` | Before publication, hold until re-inspection or admin release. After publication, suspend serving the flagged content until review; release resumes serving. |
| `reject` | Before publication, record a hit and perform takedown; resolve only after takedown and other obligations complete. After publication, perform takedown without rewinding the published pointer. |
| `defer` | Re-poll after clamped `retry_after_ms`; leave the obligation outstanding. |
| Unavailable, `fail_closed` | Leave the obligation `pending` and retry. |
| Unavailable, `publish` | Satisfy this obligation only after its configured clear deadline; continue follow-up inspection. |

A post-publication `reject` records a separate takedown obligation while
the advance remains published. Once the rewrite completes, its state
becomes `resolved` and its published membership is the replacement set.
A post-publication `quarantine` records a separate serving suspension;
the advance remains published while that suspension is reviewed.

On a hit or any QUARANTINE-phase `quarantine`, before or after
publication, the server MUST immediately stop serving every flagged
object and every pack containing one to **all** callers, including
writers. This applies to `DownloadPack`, `PackExists`, HTTP, extracted
copies, and use as a delta base. Each surface MUST give the same
`not_found` or absent answer as for an absent object or pack. Serving
MUST stop before any rewrite. Writers retain access to the rest of
their pending content. Under namespace policy `any`, an owner can mint
grants freely; serving flagged content to writers would make quarantine
a distribution channel. A flagged id MUST block clearance of every
advance in the repository whose inspected set or packs contain it,
including a re-push. The server MUST re-evaluate all pending advances
in the repository when a flag is released or its takedown replacement
membership is published.

The server MUST clamp `retry_after_ms` to 1,000–60,000 milliseconds, with
an absent or zero value meaning 1,000, as with PendingVerification (§9.5).
A deferred verdict is not unavailability and MUST NOT trigger the
unavailable-publish deadline.

`inspection_clear_deadline_ms` is a REQUIRED nonnegative deployment
parameter for each asynchronous inspector and each inspector with
`on_unavailable = publish`. It is the elapsed time from the advance's
commit to the deadline at which continued eligible unavailability
permits clearance for that inspector. mkit specifies no default. The
deadline MUST survive restarts; reattempts MUST NOT reset it. A
request-size or §6.6-limit failure is never eligible (§11.1). A
deadline MUST NOT release a deliberate hold, hit, flagged-id block, or
dependency on another unpublished advance. Reaching it MUST NOT cancel
scheduled follow-up inspection; a later verdict still requires action.

A post-publication `quarantine` suspends serving under the rule above
until review. An admin release (§16) resumes serving; a later `reject`
becomes a takedown under §14. Neither verdict rewinds the pointer.
Removing an inspector with outstanding obligations MUST NOT silently
waive them. Only an audited admin action under §16 MAY waive them;
until then they remain outstanding. §14 defines takedown rewrite
mechanics, while §16 defines the admin release and audit contract.

## 12. Admin API and audit log (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 13. Custom backends, backup and migrations (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 14. Conformance scope (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 15. Version history

| Version | Status | Change |
|---|---|---|
| 1 | draft | Initial M3 pipeline, durable outcome and remote-hook contract; M5 sections reserved. Admission credential headers (§6.3); indexed mode (§9). Published view (§10), per-advance inspection and quarantine (§11), including surplus pack entries; additive Inspect phase/id/kind/defer/flagged ids and Authorize writer_view (§6). |

## 16. Test anchors

The fixtures under `rust/tests/golden/server-hooks/` are the authoritative
pinned bytes, as [SPEC-CONVENTIONS §5](SPEC-CONVENTIONS.md#5-golden-vectors-and-conformance-tests)
requires. These anchors are informative descriptions of those bytes.

| Golden file | Contract pinned |
|---|---|
| `authorize.request.json` | Operation, signer principal, and intended ref changes (§6.2). |
| `authorize-allow.response.json` | Empty Authorize allowance (§6.2). |
| `authorize-deny.response.json` | Deliberate Authorize denial code and public message (§6.2). |
| `admit.request.json` | BeginUpload pack id, declared bytes, authorization facts, repository-byte presence, and a fake admission credential header (§6.3). |
| `admit-first-attempt.request.json` | First-attempt Admit input with no credential headers (§6.3). |
| `admit-allow.response.json` | Reservation id and allowed receipt pass-through (§6.3, §6.6). |
| `admit-challenge.response.json` | Opaque challenge and example payment challenge header (§6.3, §6.6). |
| `admit-deny.response.json` | Deliberate admission denial (§6.3). |
| `inspect.request.json` | Legacy non-conforming pre-M5 example, retained to pin the additive wire shape (§6.4). |
| `inspect-pass.response.json` | Empty inspection pass verdict (§6.4). |
| `inspect-quarantine-phase.request.json` | Quarantine phase, stable inspection id, and blob/manifest/chunk metadata (§6.4, §11). |
| `inspect-quarantine.response.json` | Hold verdict and flagged object ids (§6.4, §11). |
| `inspect-reject-flagged.response.json` | Reject/hit verdict with flagged ids (§6.4, §11). |
| `inspect-defer.response.json` | Async retry-after suggestion (§6.4, §11.3). |
| `authorize-writer-view.response.json` | Authority-source writer classification (§6.2, §10.1). |
| `outcome-committed.request.json` | Committed byte accounting and refs (§5, §6.5). |
| `outcome-aborted.request.json` | Apply-failure abort reason and operator detail (§5, §6.5). |
| `outcome-abandoned.request.json` | Pending reservation reconciled with ABANDONED (§5, §6.5). |
| `outcome-expired.request.json` | Unconsumed ticket expiry (§5, §6.5). |
| `outcome-read-served.request.json` | Paid-read object and bytes served (§5, §6.5). |
| `outcome.response.json` | Empty Outcome acknowledgement (§6.5, §8). |
| `signature.json` | Admit body including credential headers and Outcome body, with exact bytes, canonical signing strings, hashes, signatures, and full headers (§7.1). |
| `key-list.json` | Public test key distribution document (§7.2). |
| `MANIFEST.txt` | BLAKE3 hashes of every other golden file, including both Admit attempts (SPEC-CONVENTIONS §5). |

Informative: the signature vectors contain a clearly labelled test seed.
It is public fixture material and is not a deployment signing key.

The indexed-mode detail fixtures under `rust/tests/golden/transport/`
pin STC §7.6 and SPEC-SERVER §9.5:

| Golden file | Contract pinned |
|---|---|
| `pending-verification.bin` | `PendingVerification` binary encoding with `retry_after_ms = 5000`. |
| `pending-verification.json` | Canonical protobuf JSON for that detail. |
| `pending-verification-error.json` | Full Connect `unavailable` error with exactly one typed detail. |
| `MANIFEST.txt` | BLAKE3 hashes of the transport golden files. |
