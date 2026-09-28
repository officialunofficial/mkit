---
spec: SPEC-SERVER
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers and of deployment business logic behind the remote-hook contract
---

# SPEC-SERVER — server pipeline guarantees and the remote-hook contract

## 1. Scope and relation to SPEC-TRANSPORT-CONNECT

This specification defines server-internal pipeline guarantees, durable
outcomes and lifecycle events, storage leases, server garbage collection,
and the contract between a server and deployment business logic.
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
Servers MUST also implement the applicable indexed-mode, storage-lease, and
server-GC requirements of §§9, 12, and 13. A deployment implements the
business decisions exposed by hooks; the server implements the pipeline,
validation, durable recording, and delivery guarantees specified here.

The contract does not define prices, payment verification, settlement
policy, moderation policy, or the deployment's account model.
[SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) remains authoritative for grants,
their verification, and the preconditions they carry into apply.

Sections 10–18 cover the M5 contracts: §§10–11 specify the published view
and inspection, §§12–13 specify storage leases, lifecycle events, and
server garbage collection, and §15 specifies storage receipts. The other M5
sections remain reserved. Inspection and receipt fields extend the original
hook and transport shapes additively.
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
7. **Storage receipt signing.** Produce the §15 storage receipt when the
   deployment enables receipt signing for the committed operation.
8. **Outcome delivery.** Deliver the durable outcome to the configured
   sink under §5 and, for remote hooks, §6.5 and §8.
9. **Asynchronous inspection and lifecycle events.** Run configured
   asynchronous inspection after apply. Storage-lease timers perform
   transition side effects and durably record configured events under §12; request
   enforcement evaluates storage leases independently of those timers.

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
effects. Storage receipt signing and delivery may happen later; §15 fixes
the statement bytes at apply. An outcome
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
- An outcome or lifecycle event MUST NOT be dropped. It remains durable
  until acknowledged.

Unknown scheduled work remains available for a version that understands
it. Treating that work as successfully completed would discard an
obligation that the current server cannot interpret.

## 5. Outcomes, lifecycle events and the outbox

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

For an admitted HTTP read with a reservation id, the server MUST durably
record a pending read before sending the first response byte. Its abandonment
deadline MUST be a deployment-configured bound measured from reservation
creation, independent of an authentication validity interval. The server MUST
stop sending by that deadline. Completion, including partial transmission,
MUST conditionally replace the pending read with `ReadServed` recording actual
body bytes sent; successful HEAD records zero. A failure before the first byte
MUST conditionally replace it with `Aborted(INTERNAL)`. Reconciliation MUST
run only after `deadline + read_reconcile_grace`, where
`read_reconcile_grace` is a named deployment parameter defaulting to 60 s.
A `ReadServed` arriving within that grace period MUST win over abandonment.
After the grace period, reconciliation MUST conditionally record
`Aborted(ABANDONED)` if the record remains pending. These replacements use
the same pending-record arbiter below.
[SPEC-HTTP-OBJECTS](SPEC-HTTP-OBJECTS.md) fixes read ordering and admission input.

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

The durable outbox holds outcomes and, when an Event sink is configured,
§12 lifecycle events awaiting acknowledgement. Events use `event_id`
as their idempotency key; event acknowledgement does not acknowledge an
outcome or another event. Delivery
attempts and process restarts MUST NOT discard an unacknowledged row.
Acknowledging one reservation does not acknowledge another reservation.

A server MAY refuse new admitted writes with retryable `unavailable`
while its combined undelivered outcome and event backlog exceeds a
configured bound. Events MUST count toward that bound. The server MUST
NOT drop outcomes or events to relieve that backlog. Reads and writes
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
| Event | `/mkit.server.hooks.v1.HooksService/Event` |

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

A deployment MAY implement any subset of the five RPCs. The calling
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

For plain HTTP reads, `procedure` MUST be `/mkit.http.v1/GetObject` or
`/mkit.http.v1/GetRefPath`, and `principal` MUST be `anonymous`, as
[SPEC-HTTP-OBJECTS](SPEC-HTTP-OBJECTS.md) requires. These are hook operation
identifiers, not additional Connect RPCs; HTTP admission follows that
specification rather than the unary-RPC eligibility rule of STC §5.1.

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
`AdmitAllow.external_ref` is an optional implementer-supplied reference
to its own contract or payment receipt. The server carries it beside the
reservation id in a later storage receipt (§15); it does not interpret it.
Writers can fetch and see this value through `GetReceipt` subject to
the advance-receipt ref-scope rule in §15.6.

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
| `ABORT_REASON_ABANDONED` | 6 | Reconcile found a pending reservation without a recorded result after the operation's authentication validity interval, or, for an HTTP read, after its deadline plus `read_reconcile_grace` (§5). |

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
- `AdmitAllow.external_ref`, when present, MUST be at most 256 bytes of
  visible ASCII (`0x21`–`0x7e`). The implementer MUST keep credentials,
  bearer tokens, and other secrets out of it: it is copied into a
  storage receipt visible through `GetReceipt` to authorized writers
  under §15.6, including its write-only grant ref-scope limit. An empty
  value is omitted from the receipt.
- `InspectQuarantine.reason` MUST be at most 512 bytes.
- Inspect responses MUST satisfy the phase and flagged-id rules of §6.4.

The applicable response oneof MUST select a decision or verdict.
An absent decision does not constitute permission to continue.
These checks validate the hook contract before constructing any
client-visible response under STC.

## 7. Hook channel authentication

### 7.1 Signed requests

Every hook request, including Outcome and Event delivered as webhooks, MUST
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
`operation.audience`, `outcome.audience`, or `event.audience` carried
inside the body.

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

Outcome processing MUST additionally be idempotent by `reservation_id`;
Event processing MUST be idempotent by `event_id`.
Repeated logical delivery does not permit nonce replay to bypass the
channel authentication check.

Informative: a fresh signed delivery attempt can carry the same
durable Outcome or Event body with a fresh hook nonce and validity window.
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

Outcome and Event delivery MUST retry with exponential backoff and
jitter until acknowledged. The server MUST NOT drop either. Any 2xx Connect
response to Outcome or Event is an acknowledgement. Transport errors,
timeouts, and non-2xx responses leave the outcome or event awaiting
delivery.

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
all pending advances in the repository, subject to the serving stop for
held content in §11.3. Readers and anonymous callers
see published ref values and published membership only. These rules
apply on every serving surface, including HTTP consumers of this
abstract view.

### 10.2 Per-ref clearance and publication

Each ref MUST have an ordered advance sequence. The branch head
`refs/heads/<x>` and `refs/mkit/packmap/<x>` share one sequence: every
successful `AdvanceRefs`, head-only `UpdateRef`, or packmap-only
`UpdateRef` appends an advance to that sequence. Sequence numbers start
at `1`; `0` selects the latest receipt in STC §2.2. The sequence MUST
NOT reset on ref deletion, recreation, or repository-level deletion.
The advance value is the live (head, packmap) pair, and the pair MUST
be published together.
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
| `held` | A quarantine verdict awaits re-inspection or admin release under §11.3; a hold on an already-flagged id is released only by admin review (§16). |
| `hit` | A rejection awaits takedown completion. |
| `resolved` | Takedown, non-hit obligations, and §10.2 membership dependencies are complete; it no longer blocks the publication prefix. |

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
   External delta bases used by its packs (§9.4) MUST already be in
   published membership; *k*'s additions do not satisfy that external
   dependency.
3. No flagged id in the repository occurs in its inspected set or its
   packs. Such an advance is `held` under §11.3, not merely `pending`.

A `hit` advance becomes `resolved` only when its §14 takedown is complete,
all non-hit obligations are satisfied, and condition 2 holds for its
post-takedown packmap chain and replacement packs. Its own replacement
packs can publish atomically with resolution; other packs and external
delta bases must already be in published membership.

Clearing *k* MUST atomically publish its added membership and update the
published ref pointer to the largest eligible prefix. Completion out of
order can make membership eligible, but MUST NOT expose a ref value
beyond that prefix. A branch's head and packmap MUST remain a pair in
both live and published views. Publishing membership MUST durably
schedule re-evaluation of every advance previously blocked on that
membership, including an external delta-base dependency, in any ref.
The scheduled work MUST be retained until completed and MUST run within
a bounded time. The same rule applies when takedown replacement packs
become published.

A pack added by another advance that has not cleared or resolved blocks
clearance. `AlreadyPresent` establishes live membership, not published
membership. Thus branch B reusing a pack from pending branch A cannot
publish it; neither can a tag pointing at a commit whose containing pack
is pending. The advance's own additions qualify in the same atomic
clearance, so initial publication has no circular membership dependency.

Deletions under STC §7.8 or lease deletion under §12 MUST publish
immediately and MUST NOT wait for inspection. They establish a ref-value
publication boundary: later
verdicts on older advances MUST NOT change or resurrect that ref value.
Those verdicts still govern membership the older advances added: a pass
publishes it, a hold keeps it unpublished, and a hit takes it down,
except that membership invalidated by a repository-level lease deletion
(§12.2) MUST NOT become visible again under any later verdict. Until its
verdict arrives, such surviving membership is retained as §13.2 roots it.
A recreated ref, or another ref reusing the packs, can clear when that
membership becomes published. Later ref values are evaluated from the
deletion boundary under the ordinary inspection and dependency rules.

While its repository membership generation remains valid (§12.2), the
server MUST retain every advance value strictly after the published
pointer through the live value, in any clearance state, together with
its packmap chain, closure packs, packs, and, transitively, the packs
supplying external delta bases (§9.4) its packs use. Retention lasts until the
published pointer reaches or passes the advance. A `hit` advance and
its takedown replacement packs MUST additionally be retained until its
§14 takedown completes, including when a deletion has moved the ref's
publication boundary past that advance. §13 makes these GC roots.

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
`AlreadyPresent` MUST NOT be answered for a pack containing an id hidden
by a flag or hold; the server MUST answer as if the pack were absent.

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
MUST sign reads to see their own pending content that is not held. Held
content is hidden from every caller, even when this field is false
because only synchronous inspectors are configured.

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
for each batch. Its advance-level obligation is satisfied only when
every batch passes or its unflagged objects count as passed and its
flagged objects are released or taken down under §11.3.
A failure caused by the request's own size or §6.6 limits MUST NOT be
eligible for unavailable-publish: its obligation remains `pending` and
the server MUST use compliant batches before clearance.

Rationale: the added-pack set extends inspection beyond newly reachable
file objects to surplus entries. §9.3(c) permits entries outside the
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

A `reject` or `quarantine` verdict satisfies that inspector's obligation
for the batch's unflagged objects: they count as passed by that inspector.
The flagged objects remain subject to the serving stop and review or
takedown below. Other inspectors' obligations are unaffected.

Before publication, the advance state is derived from its obligations
with precedence `hit > held > pending > cleared`. A hit becomes
`resolved` only after takedown completes, every non-hit obligation is
satisfied, and §10.2's membership-dependency condition holds; until then
it blocks the publication prefix.
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

On a hit or a `quarantine` in either phase, before or after publication,
the server MUST immediately stop serving every flagged object and every
pack containing one to **all** callers, including writers. If a
`quarantine` verdict carries no flagged ids, the server MUST
hide every pack and object added by that advance from every caller.
Writers still see the live ref value and the rest of their pending
content that is not held. The serving stop covers `DownloadPack`,
`PackExists`, snapshots, URL-token and HTTP responses, extracted copies,
server-side reader caches, and use as a delta base. Each surface MUST
give the same `not_found` or absent answer as for an absent object or
pack. The server MUST invalidate server-side cached copies at once and
MUST trigger a purge of shared caches through §16 or the deployment's
purge interface. Serving MUST stop before any rewrite. Informative:
removal from a shared cache takes effect within the deployment's purge
latency. Under namespace policy `any`, an owner can mint grants freely;
serving held content to writers would make quarantine a distribution
channel.

An advance whose inspected set or packs contain an id already flagged
in the repository MUST become `held`, with those ids as its flagged
objects, including on a re-push. Only admin review under §16 MAY release
this hold; an unavailable-publish deadline MUST NOT release it. The
server MUST re-evaluate all advances in the repository blocked on that
flag when it is released or its takedown replacement membership is
published. Releasing a flagged id releases the holds derived from it,
subject to their other obligations.

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
deadline MUST NOT release a deliberate hold, hit, flagged-id hold, or
dependency on another unpublished advance. Reaching it MUST NOT cancel
scheduled follow-up inspection; a later verdict still requires action.

A post-publication `quarantine` suspends serving under the rule above
until review. An admin release (§16) resumes serving; a later `reject`
becomes a takedown under §14. Neither verdict rewinds the pointer.
Removing an inspector with outstanding obligations MUST NOT silently
waive them. Only an audited admin action under §16 MAY waive them;
until then they remain outstanding. §14 defines takedown rewrite
mechanics, while §16 defines the admin release and audit contract.

## 12. Storage leases and lifecycle events

### 12.1 Terms and scope

Storage leases govern retention and access. They are unrelated to the
namespace epoch leases of
[SPEC-WRITE-GRANTS §5.4](SPEC-WRITE-GRANTS.md#54-epoch-leases-and-the-apply-check).
Lease terms, prices, and renewal endpoints belong to deployment policy.
mkit defines no default storage-lease durations. No storage lease means
permanent retention, subject to separate administrative policy.

A storage lease has `{expires_at_ms, grace_ms, suspension_ms}`.
`expires_at_ms` is an absolute Unix epoch time in milliseconds;
`grace_ms` and `suspension_ms` are nonnegative durations in milliseconds.
Policy MUST explicitly set all three terms when assigning a lease.
The server MUST reject terms whose state boundaries cannot be represented
without overflow; it MUST NOT silently substitute defaults.

Indexed deployments MUST support per-ref storage leases. The ref shard
holds the per-ref terms; the namespace coordinator holds the
repository-level default and propagates changes with `config_version`.
An explicit per-ref lease overrides that default while the repository
remains undeleted; otherwise the ref uses the repository default. Opaque
deployments support repository-level
storage leases only and MUST NOT accept per-ref terms.
A deleted repository-level lease deletes every ref in the repository,
including refs with explicit per-ref terms, and invalidates repository
membership under §12.2. Per-ref terms do not restore the deleted
repository generation.

Repository-level changes MUST become effective within one epoch lease
plus the configuration cache TTL. They MUST follow the visibility
completion rule of
[SPEC-WRITE-GRANTS §9.1](SPEC-WRITE-GRANTS.md#91-visibility): completion
requires leased shards to acknowledge the change or lose their leases,
and every other cached copy to expire or be invalidated.

### 12.2 State and request enforcement

For an undeleted lease, let `e = expires_at_ms`, `g = grace_ms`,
`s = suspension_ms`, and `now` be the storage backend's time. State is a
pure function of those terms and `now`:

| State | Time interval | Effect |
|---|---|---|
| `active` | `now < e` | Normal reads and writes. |
| `grace` | `e ≤ now < e + g` | Writes blocked; reads allowed. |
| `suspended` | `e + g ≤ now < e + g + s` | Reads and writes blocked. |
| `deleted` | `e + g + s ≤ now` | Terminal for this lease: remove the ref and its published pointer; objects await §13 GC. |

An absent lease has state `active` without a time limit. Zero-length
intervals are empty. The server MUST evaluate the effective storage-lease
state on every repository request after authorization succeeds; access
enforcement MUST NOT wait for a timer. An unauthorized caller MUST receive
the ordinary authorization denial, byte-identical whether the lease exists
or not. Repository-independent deployment discovery remains as STC
§2.1 requires: it MUST NOT resolve a repository or depend on its
storage-lease state.
An expired state MUST NOT be served as active from a stale state cache.
For branch deletion, head and packmap MUST be removed together, along
with the branch's published pointer. A storage-lease deletion is a
publication deletion boundary under §10, with the same published-view
effect as a ref deletion under STC §7.8; later verdicts MUST NOT restore
the old ref value. A repository-level deletion MUST remove every ref,
including those with explicit per-ref terms, and each published pointer.
Delayed removal MUST NOT make a logically deleted ref accessible or a
GC root; §13.2 defines which advance membership remains a separate root
after a per-ref deletion. Repository-level deletion MUST
immediately invalidate the repository's existing membership as a single
generation: reads and `AlreadyPresent` MUST see no old member, the
invalidated membership MUST NOT satisfy the §§9.2–9.4 checks or the §13.3
reliance rule, and a new lease MUST NOT restore old membership. A later verdict on an earlier
advance MUST NOT make that invalidated membership visible again. §13
later reclaims its data.

Renewal during `grace` or `suspended`, with terms placing the lease in
`active` at backend time, MUST restore `active`. `deleted` is terminal:
a new lease permits new writes only and MUST NOT restore removed refs,
published pointers, or the old lease's data. A late renewal MUST NOT
cancel deletion of the old lease merely because timer work is delayed.
A write to a ref whose own lease is `deleted` is not ref creation. It MUST
remain blocked until an administrator sets a new lease under §12.3.

Administrative suspension is a separate override, including applicable
repository, namespace, and takedown suspensions. The effective state MUST
be the more severe of storage-lease state and that override, in the order
`active < grace < suspended < deleted`. Payment renewal MUST NOT lift
an administrative or takedown suspension.

A write in `grace` MUST return `permission_denied` with exactly
`repository lease expired; writes blocked`. A per-ref `suspended` or
`deleted` state MUST hide that ref from readers; a write to that ref
MUST return `permission_denied` with exactly `lease suspended`.
Reads in a suspended or deleted repository MUST return `not_found` to
readers, without revealing repository existence; an authorized writer
reading that repository MUST instead receive `permission_denied` with
exactly `lease suspended`. Other writes blocked by suspension MUST
return that same permission error.
For a reader, the suspended-or-deleted repository's `not_found` MUST be
byte-identical to a nonexistent repository response in code, message,
details, and headers, as [SPEC-WRITE-GRANTS §9.3](SPEC-WRITE-GRANTS.md#93-read-authorization)
requires for private reads.
These storage-lease denials MUST NOT use `failed_precondition`, which
would cause clients to restart `BeginUpload`. Read responses and caches
MUST preserve the denial and MUST NOT expose suspended or deleted data
through a cached successful response. Signed URL reads remain subject
to these storage-lease checks and resolve only in the published view, as
[SPEC-WRITE-GRANTS §9.4](SPEC-WRITE-GRANTS.md#94-signed-url-tokens) requires.
Cache-purge wire details are reserved for §16.

Pack and object surfaces, including `PackExists`, `DownloadPack`, HTTP
object serving, and signed URL tokens, MUST enforce the
repository-level effective state. A per-ref `suspended` or `deleted`
state MUST hide that ref from `ReadRef`, `ListRefs`, and `X-Mkit-Ref`,
together with its published pointer, as required above. It MUST NOT hide
membership shared with other refs. Informative: deployments billing
storage per repository should use repository-level leases; per-ref
leases govern ref visibility, not byte availability.

### 12.3 Setting leases and transition work

`SetLease` assigns, replaces, or removes storage-lease terms for a
repository default or, in indexed mode, an individual ref. The server
MUST reject `SetLease` from any caller other than an administrator
authorized for that scope. This authority includes shortening a lease.
The server MUST evaluate shortened terms
without waiting for a timer, subject to §12.1's completion bound for
repository defaults. This includes transitions directly to suspension
or deletion.
Removing a repository default makes undeleted refs without per-ref
terms permanent. Removing per-ref terms restores the repository default,
or permanent retention if that default is absent. Both actions MUST NOT
resurrect a deleted lease. Every SetLease action MUST be audited.
Changes to terms or overrides issue a §15 lease storage receipt; an
`EXPIRY` transition does not. The admin API wire, authentication, and
audit-log details are reserved for §16; this section defines its
semantics only.

In indexed mode, the server MUST consult a deployment storage-lease
policy hook only when creating a ref with no lease record. The decision
MUST be one of explicit terms, inheritance of the repository default,
or explicit permanent retention. These last two are distinct: inheritance
follows later default changes, while explicit permanent retention does not.
In opaque mode, the hook MUST run at repository creation and MUST choose
repository-level terms or permanent retention; it MUST NOT set per-ref
terms.
Failure to obtain that policy decision MUST fail closed and MUST NOT
create a permanently retained ref by treating failure as an absent lease.
This is a policy obligation, not a remote-hook wire addition.
`AdmitAllow.lease` is deferred; admission does not assign lease terms
through the current hooks schema.

Timers MUST durably perform transition side effects and, when an Event
sink is configured, record one event for each transition due to expiry,
renewal, policy change, or administrative change. Work MUST survive
restart and MUST NOT record the same logical transition as distinct
events. Without an Event sink, no Event outbox row is required. Timer delay
never delays request enforcement. Expiry work MUST be conditional on
the applicable lease instance and terms, so old work cannot delete a
renewed ref. Once a lease is deleted, its pending deletion MUST target
only that lease's ref incarnation; a new lease MUST treat those old refs
as absent even before cleanup finishes. Delayed work MUST NOT delete a
ref created under the new lease.
Deletion side effects MUST use authoritative per-ref terms and the
coordinator's repository default at the current `config_version`, read
under a valid epoch lease. They MUST NOT use cached lease terms.

### 12.4 Event messages and delivery

`HooksService/Event(EventRequest)` delivers a lifecycle event.
`EventRequest.event` is REQUIRED; `EventResponse` is empty. The shared
`Event` fields are:

| Field | Meaning |
|---|---|
| `event_id = 1` | Idempotency key: MUST be 1–128 bytes of `[A-Za-z0-9._:-]` and unique per server audience. |
| `audience = 2` | The mkit server's canonical origin, distinct from the hook-channel signing audience. |
| `repository = 3` | Full repository identity under STC §7.4. |
| `occurred_unix_ms = 4` | Transition time as signed 64-bit Unix epoch milliseconds, independent of delivery time. |
| `sequence = 5` | Unsigned 64-bit sequence, strictly increasing per `(repository, scope)` for distinct events of every kind. |
| `kind` | Exactly one transition kind; `lease = 6` is defined here. Other kinds can extend the same envelope. |

`LeaseTransition` has these fields:

| Field | Meaning |
|---|---|
| `ref = 1` | Full ref name; empty means repository-level scope. |
| `from = 2`, `to = 3` | Previous and resulting effective lease states. |
| `lease_expires_unix_ms = 4` | Applicable storage lease's expiry; absent for permanent retention. |
| `cause = 5` | `EXPIRY`, `RENEWAL`, `POLICY`, or `ADMIN`. |

`LeaseState` numbers are `LEASE_STATE_UNSPECIFIED = 0`,
`LEASE_STATE_ACTIVE = 1`, `LEASE_STATE_GRACE = 2`,
`LEASE_STATE_SUSPENDED = 3`, and `LEASE_STATE_DELETED = 4`.
`LeaseCause` numbers are `LEASE_CAUSE_UNSPECIFIED = 0`,
`LEASE_CAUSE_EXPIRY = 1`, `LEASE_CAUSE_RENEWAL = 2`,
`LEASE_CAUSE_POLICY = 3`, and `LEASE_CAUSE_ADMIN = 4`.
Senders MUST populate every shared Event field and exactly one kind,
and MUST supply known, non-unspecified states and a non-unspecified
cause. Retries MUST retain the event id, sequence, scope, and body.
Sequences MUST NOT reset on restart, renewal, or ref recreation. Future
event kinds MUST share the same sequence space for their scope.

An Event MUST describe the scope whose own lease terms, administrative
override, or time-derived state changed. A repository-default change emits
one repository-scope event; refs inheriting that default MUST NOT emit
separate per-ref events, and receivers derive their effective state from
the repository transition.
An administrative override emits at the scope where it is set.

When an Event sink is configured, events MUST use the same durable outbox
as outcomes (§5), be delivered at least once, and remain retained until
acknowledged. Without a configured sink, no Event is recorded. Delivery
has no ordering guarantee. Receivers MUST deduplicate by `event_id` and use
`sequence` to order events within their scope; an older late delivery
MUST NOT roll back a newer state. Signing follows §7.1 and retry follows
§8. Events count toward §5's combined backlog bound.

The remote `CachePurge` contract is reserved for §16. A
deployment-internal cache-purge interface does not add a remote RPC.

## 13. Server garbage collection

### 13.1 Named parameters

| Parameter | Value or constraint | Meaning |
|---|---|---|
| `gc_grace` | Fixed: 7 d | Minimum time a repository candidate remains marked before removal. |
| `relay_lag_bound` | Deployment configuration, default: 60 s | Membership-visibility retry bound under §9.4; elapsed time does not replace the GC watermark. |
| `already_present_pin_window` | Minimum: the deployment's maximum ticket lifetime | Pack pin after an `AlreadyPresent` response. |
| `MAX_APPLY_WINDOW`, `margin` | Defined by SPEC-WRITE-GRANTS §1.1 (deployment parameters with defaults) | Commit-window parameters used in §13.3; this spec does not redefine them. |

The commit-deadline and `NotAfter` obligation on every write batch is
[SPEC-WRITE-GRANTS §5.5](SPEC-WRITE-GRANTS.md#55-commit-deadline).
The parameter definitions are in
[SPEC-WRITE-GRANTS §1.1](SPEC-WRITE-GRANTS.md#11-named-parameters).

### 13.2 Roots and liveness

Per-repository GC MUST include all of the following roots:

- Every live ref value, including each branch's packmap chain.
- Every published pointer, including its head and packmap.
- Every advance value strictly after the published pointer through and
  including the live value under §10, in any clearance state while its
  repository membership generation remains valid, with its packmap
  chain, indexed closure packs, and packs that advance added.
  It remains a root until the published pointer reaches or passes its
  advance position.
- Every `hit` advance's membership, packmap chain, closure packs, and
  replacement packs until §14 takedown completes: flagged bytes are
  preserved and replacements are durable. This remains a root behind
  a later value and after ref or storage-lease deletion.
- Every unexpired ticket's pack or packlist node.
- Every unexpired hold.
- Every takedown replacement pack (§14) not yet collected under §14's
  own rules.

Repository-level lease deletion invalidates the old membership generation:
pending advance membership in that generation is not a root and cannot
become visible again. A `hit` advance remains a separate root until
§14 takedown completes, including when its membership was invalidated.

An `AlreadyPresent` answer is planner use. If the pack contains any id
hidden in that repository by a flagged or held verdict under §11, the
server MUST answer as if the pack were absent and MUST NOT answer
`AlreadyPresent`. Otherwise, it MUST conditionally unmark and pin a
member that still exists and whose pack is not `deleting`. The pin MUST
be durable before the answer and protect its pack against repository
removal and byte deletion for `already_present_pin_window`, beginning at
the answer. Repeated answers extend protection to cover each answer's
window. Pins remain effective throughout the removal protocol. If the
conditional unmark and pin cannot succeed, the server MUST issue a ticket
or answer retryable `unavailable`; it MUST NOT answer `AlreadyPresent`.

Every pack and packlist node on a root's packmap chain MUST remain live
in both indexed and opaque modes: clients fail closed when a packmap
pack is missing. In indexed mode, a pack containing an object in a live
closure is live: GC MUST retain at least one containing pack for each
live object, specifically the pack the repository index uses to serve
that object, along with its index row and any extracted serving copy.
A non-branch advance's root also includes the packs that advance added.
For every retained pack, GC MUST also retain every pack supplying an
external delta base (§9.4) for an object in it, transitively. This
includes the packs of every advance retained by §10's publication rule,
regardless of that advance's clearance state. GC MUST retain the
corresponding repository membership and serving index rows while that
membership generation remains valid; an invalidated `hit` is preserved
under §14 instead.
Opaque mode cannot prove object closure; if a repository has any live
non-branch ref, GC MUST retain all its member packs. An opaque-mode
branch without a readable packmap chain MUST receive the same protection:
retain all member packs when the membership source is readable. An
unreadable membership source still aborts the run under §13.5.

A planned but unapplied write is a pending advance covered by the wait
phase below. An advance value between the published pointer and live
value can become published under §10 even when its clearance state is
`cleared` and it is no longer the live value. A lease-deleted ref is not
itself a root. After a per-ref deletion, surviving advance membership
awaiting a verdict under §10 remains a root; after a repository-level
deletion, its invalidated pending membership is not a root. `Hit`
membership awaiting §14 takedown remains a root across either deletion
boundary. Preservation-store bytes and blocklist rows MUST NOT
be collected by
server GC; their separate retention and purge rules are in §§14 and 16.

### 13.3 Per-repository mark, wait, re-check and drop

GC MUST perform these phases in order for each repository:

1. **Mark.** Compute the complete live set and mark only unreachable,
   unpinned candidates `gc_pending(since)`. `since` is the backend time
   at which this mark was established; `mark` below denotes that time.
   The mark clock and `now` in the wait phase MUST be within `margin`
   of every shard backend's clock; the coordinator clock is one suitable
   source. The decision that a lease-deleted ref is not a root MUST use
   authoritative per-ref terms and the coordinator default at the
   current `config_version`, read under a valid epoch lease, never cached
   terms. Apply §13.2's distinction between surviving advance membership
   after per-ref deletion and invalidated membership after repository-level
   deletion.
2. **Wait.** Removal MUST wait until all three conditions hold:
   `now > mark + MAX_APPLY_WINDOW + margin`; the namespace relay
   watermark has passed that point; and `since + gc_grace ≤ now`.
   The watermark is the namespace's completed-relay frontier, including
   outstanding work from active shards. A fixed sleep or a lagging
   index MUST NOT substitute for that frontier.
3. **Re-check.** Re-read the complete roots from strongly consistent
   ref shards. The shard list MUST be the union of the ref index read
   after the watermark condition holds and the coordinator's
   active-shard table, never the eventually consistent ref index alone.
   Re-check live refs, published pointers, all advance values between
   the published pointer and live value regardless of clearance state,
   surviving advance membership after per-ref deletion, `hit`
   advances, takedown replacement packs, unexpired tickets, holds,
   pins, object closure, and transitive external delta-base packs as
   applicable. Do not root invalidated pending membership after a
   repository-level deletion. Re-check authoritative
   per-ref lease terms and the coordinator default at the current
   `config_version` under a valid epoch lease, never from a cache.
   A candidate that became live or pinned, or whose mark changed,
   MUST NOT be removed.
4. **Drop.** Only after that re-check, remove the candidate's repository
   membership, associated repository index rows, and per-ref
   membership-addition records used by `X-Mkit-Ref`. Each removal MUST
   be guarded on the unchanged mark and last-change sequence so a
   concurrent unmark or new reference makes it fail without removal.
   Remove this repository's holder only after membership, index-row,
   and per-ref membership-addition removal is durable, and only if the
   repository no longer holds that member. Every holder removal,
   including orphan reconciliation, MUST be conditional on the holder's
   unchanged change sequence. Every holder write MUST advance that
   sequence, including a relay re-record of an existing holder. A
   re-added member therefore defeats a previously planned removal. GC
   MUST reconcile orphaned holders, which are safe but retain bytes
   unnecessarily.

A planner relying on a `gc_pending` member MUST clear its mark before
planning the use and MUST ensure the repository's holder exists. More
generally, a write that newly relies on an existing member MUST durably
clear that member's GC mark before the write commits and MUST ensure its
holder exists. New reliance means making a member reachable from a ref value
where it was not before, directly or transitively: every pack and packlist
node newly reachable from the new ref value, including through `prev` links
to existing packlist nodes, closure objects and the packs containing them,
and external delta bases (§§9.2–9.4). Any ref target counts, including a
head-only branch update, together with its closure (indexed mode) or its
packmap chain (opaque mode). In opaque mode, a write that introduces new
packmap nodes MUST apply this rule to every pack and node reachable from
them, including through `prev` links, except packs the same write uploaded
that were not already members; the server MUST decode those nodes as GC
does. If the mark cannot be cleared because the member is `deleting`, the
write MUST NOT rely on it and MUST answer retryable `unavailable` or cause a
re-upload. If the member is gone, the write MUST NOT rely on it and answers
as §9.4 answers a missing member; opaque mode uses the same responses.
A new mark restarts the wait. This rule and the commit deadlines cover
planned, unapplied advances without a cross-shard GC state precondition
on ref apply. Without this rule, GC cannot safely drop membership: the
drop guard sees changes only to the candidate member's own state, not a
new ref that relies on it. A planner encountering `deleting` MUST
return retryable `unavailable` or arrange a re-upload; it MUST NOT
report a permanent absence merely because deletion is in progress.
Informative: the detection mechanism and cost of finding newly relied-on
members belong to the server GC implementation.

### 13.4 Global byte deletion

Global pack or extracted-object bytes MUST be deleted only with zero
holders and zero live holds. An `AlreadyPresent` pin counts as a live
hold in this guard. Every path that writes or deduplicates bytes which
may later gain a holder MUST create a durable hold before relying on
those bytes. This includes ticket issue, upload completion, an
un-ticketed `UploadPack`, extracted-object deduplication, and
`AlreadyPresent`. The hold MUST remain until the path can no longer add
a holder and any committed membership is durably covered by holder
accounting. The ticket's hold MUST
be durable before ticket issue; the analogous hold for each other path
MUST be durable before its bytes are reused or it reports success.
A hold MUST be released only after its path can no longer add a holder,
allowing for clock skew. A ticket hold MUST remain through ticket
expiry plus `margin`, and longer if an in-flight path can still add a
holder.

Holder counts MUST conservatively cover holder additions still in
flight; an incomplete holder addition MUST prevent deletion. A hold
MUST continue protecting the bytes until the
holder is durably covered by holder accounting. This closes the relay
lag hole for a holder whose membership has committed but whose holder
record is still in flight.

Byte deletion MUST use a per-object guarded step: atomically verify the
object's last-change sequence, zero holders, and zero live holds while
entering `deleting`; then delete the bytes and clear the deletion state.
This global byte step has no separate object-level mark; the change
sequence invalidates a stale deletion attempt. Creating a hold while
the object is `deleting` MUST fail with retryable `unavailable`. A
re-upload or deduplication MUST NOT be accepted until `deleting` clears.
Crashes MUST leave this step retryable without exposing partially deleted
bytes as usable.
No cross-namespace watermark is required: holds and conservative holder
accounting protect holders still in flight across namespaces.

Content-index holders and holds are a normative obligation for packs
as well as extracted objects. Without pack holders and holds, GC MAY
drop unreachable repository membership after §13.3, but MUST NOT delete
pack bytes.

Informative: `gc_pending` and the `AlreadyPresent` pin are server state,
not wire fields.

### 13.5 Fail-closed collection

GC MUST abort the run on any unreadable root source, unreadable lease terms
or repository default, unreadable advance or clearance state, unknown
record kind, unreadable watermark or active-shard table, undecodable
packlist node, unreadable external delta-base pack, missing root or
referenced object, or truncated walk.
The opaque-mode branch fallback in §13.2 applies only when the complete
repository membership source is readable despite the branch's unreadable
packmap chain; it does not permit a partial membership walk.
It MUST NOT remove membership, index rows, holders, or bytes on the
strength of a partial root set or incomplete closure. These are the same
fail-closed principles as [SPEC-GC](SPEC-GC.md#fail-closed-requirement), applied to
server roots. A failure in the re-check MUST also abort removal; it
MUST NOT reuse the earlier mark's liveness verdict.

## 14. Takedown and redaction notices (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 15. Storage receipts

### 15.1 Meaning and issuance

A **storage receipt** is a server-signed statement of the live committed
advance or the storage-lease terms and effective state recorded at its
`issued_unix_ms`. It is evidence of that record at issue time, **not a
promise** of future retention or availability. An administrator can shorten
a lease (§12.3), and takedown can remove content (§14). The implementer
owns any payment receipt, price, availability contract, and the contents of
`external_ref`; mkit owns the storage receipt. An `external_ref` can link
the two without making the implementer's contract part of this predicate.

When receipt signing is enabled, the server MUST issue one advance storage
receipt for every committed `AdvanceRefs` or `UpdateRef` advance, including
deletion and an advance that later fails inspection. A conflict, failed
write, or disabled receipt signer MUST issue none. The advance storage
receipt attests the **live** committed advance only. It MUST NOT expose
the published value, pending/held/hit/cleared state, inspection verdict,
or any other publication or hold state. A signed reader-side ref-to-commit
binding is outside this contract. The receipt does not make content
visible to a reader, bypass §10's caller view, or alter §13's roots.

The server MUST issue a lease storage receipt for every committed change
to a scope's terms or administrative override, with cause `POLICY`,
`RENEWAL`, or `ADMIN` as in §12.4. It MUST NOT issue one for a
time-derived `EXPIRY` transition; §12.4 Events describe those. A lease
set by creation policy MUST appear in the creation advance's
`storage_lease`. A separate lease storage receipt is also issued if that
policy action changes the lease scope's terms. The §16
`SetLeaseResponse.receipt` field carries the lease storage receipt for
an administrative `SetLease` action; `SetSuspensionResponse.receipt`
carries one for an override change (§16).

Receipt statement bytes, including `issued_unix_ms`, `key_id`, and all
predicate fields, and the signing key identity MUST be fixed in the guarded
apply. That apply MUST also durably record a pending-signature row for
each receipt it issues. The server MUST finish pending signatures on its
own, without waiting for a client retry, then persist the **signed
envelope** and return those envelope bytes verbatim on replay and on
`GetReceipt` (STC §7.1). A request for a still-pending receipt MUST
return retryable `unavailable`.
Signing after apply MUST use the key fixed at apply even if rotation occurs
in between. If signing fails after a successful apply, the server MUST
return retryable `unavailable`; a same-nonce retry MUST complete or retrieve
the signed envelope for that committed result without applying a second
advance. Ed25519 signing is deterministic, so the same key and statement
bytes yield the same envelope. Removal of a compromised key does not rewrite
stored envelopes: replay MUST return the original envelope unchanged, and
clients reject it under §15.7. Individual receipts are never revoked;
a later §14 redaction notice signed by the same role key maps old to
replacement pack ids. Neither a receipt nor its retention is a server
GC root (§13).

Informative rationale: A paid-storage implementer can use the receipt as
evidence of what the server recorded, while its own contract defines any
promise and remedy. Stating a retention guarantee here would conflict
with administrator shortening and takedown. Limiting advance receipts to
the live writer view avoids exposing inspection or hold timing as a
detection-evasion signal.

### 15.2 Envelope, predicate, and subject

The receipt is a DSSE v1 envelope as in
[SPEC-ATTESTATIONS §4](SPEC-ATTESTATIONS.md#4-envelope-format):
`payloadType` MUST be exactly `application/vnd.in-toto+json`; the
payload MUST be a JCS-canonical in-toto Statement v1; and it MUST have
exactly one strict Ed25519 signature over the DSSE PAE. The entire
envelope JSON MUST be at most 65,536 bytes. Its `predicateType` MUST be
exactly
`https://github.com/officialunofficial/mkit/spec/predicate/storage-receipt/v1`.
The predicate MUST be a JSON object with `kind` equal to `advance` or
`lease`. Unknown or malformed fields fail receipt verification; a
producer MUST NOT put another kind in this predicate version. All u64
and i64 values in the predicate and key-list validity bounds MUST be
decimal strings, without a sign or leading zero for nonnegative values
(except `0`), so JS and wasm consumers retain exact integer values.

The 65,536-byte limit MUST be guaranteed before apply, never handled by
committing an advance and then dropping its receipt. An advance MUST
consume at most seven tickets; more than seven MUST be rejected with
`invalid_argument` before apply. Each consumed ticket contributes at
most one deployment reservation, and a ticketless write contributes at most one. A deployment
with a receipt-and-notice key configured MUST reject startup if its
canonical origin exceeds 2,048 UTF-8 bytes. The existing limits are
173 bytes for repository identity (STC §7.4), 512 bytes for a ref
(SPEC-REFS §3), 128 bytes for a reservation id (§6.6), and 256 bytes
for `external_ref` (§6.6). A conservative JCS statement bound, allowing
six JSON bytes per origin/repository/ref byte and two per visible-ASCII
`external_ref` byte, is
`6×2048 + 6×173 + 6×512 + 7×(64+20+32) +
7×(128+2×256+64) + 4096 = 26,234` bytes. The 4,096-byte remainder
covers all fixed fields, digest strings, punctuation, and decimal
integer strings; a lease statement has fewer variable entries.
Base64 and at most 1,024 bytes of DSSE envelope syntax give
`4×ceil(26,234/3)+1,024 = 36,004` bytes, below 65,536. Producers
MUST still check the encoded envelope before delivery and MUST refuse
any configuration or input that could violate this bound before apply.

The Statement MUST have exactly one subject. An advance subject MUST be
`{"name":"target","digest":{"blake3":"<target>"}}`, with no
`sha256`, in both opaque and indexed modes. `target` is 64 lowercase
hex digits. For a deletion, `target` and the subject digest are the
removed previous value; `deleted: true` says the new ref value is absent.
A lease subject MUST have `name: "scope"` and both `blake3` and
`sha256` digests of the **same** UTF-8 byte string
`<repository>\n<ref-or-empty>`, where an empty ref selects the
repository scope. For a namespace scope the byte string is
`<namespace>\n`; namespace identities have no repository-name suffix,
so the two forms cannot collide. The order and digest encoding follow
SPEC-ATTESTATIONS §4.2. A storage receipt is not an object attestation
and MUST NOT be pushed as one; a client MAY store it locally under
`.mkit/receipts/`, separate from `.mkit/attestations/`, without treating
it as an object GC root.

The shared receipt-and-notice role key signs both predicates. The
permanent domain for a storage receipt under that key is its exact
`predicateType`; §14 notices have a different `payloadType` and their
own predicate. A verifier MUST check both before interpreting signed
bytes. This gives each application of the shared key a distinct named
domain as [SPEC-CONVENTIONS §4](SPEC-CONVENTIONS.md#4-domain-separator-and-namespace-naming)
requires. DSSE's `DSSEv1` PAE prefix also separates these signatures
from non-DSSE signing protocols.

### 15.3 Advance predicate

For `kind: "advance"`, the predicate MUST contain these fields:

| Field | Meaning |
|---|---|
| `origin` | Server's canonical audience origin (STC §7.1). |
| `repository` | Full STC §7.4 repository identity. |
| `ref` | Full ref name advanced. For `AdvanceRefs`, the branch head. |
| `advance_sequence` | This ref's committed §10.2 sequence, a u64 decimal string starting at `1`. |
| `target` | New ref value as 64 lowercase hex; for deletion, the removed value. |
| `packmap` | Resulting paired packmap value as 64 lowercase hex for a branch; on branch deletion, the prior paired packmap value. Absent for other refs. |
| `previous` | Prior value as 64 lowercase hex; absent on creation. On deletion it equals `target`. |
| `deleted` | Boolean; true means the resulting ref value is absent. |
| `mode` | Exactly `opaque` or `indexed` at apply. |
| `closure_verified` | Boolean; true only when indexed closure was verified; false on deletion. |
| `added_packs` | Array of `{id, bytes}` for packs whose tickets this advance consumed, regardless of prior or hidden membership. `id` is 64 lowercase hex; `bytes` is a u64 decimal string. |
| `added_bytes` | Sum of `added_packs[].bytes`, a u64 decimal string. |
| `storage_lease` | Terms effective for this ref at apply, in the form below. |
| `reservations` | Array of `{id, external_ref?}` for deployment-supplied reservations associated with this advance. |
| `issued_unix_ms` | Signed i64 epoch milliseconds at issue, as a decimal string. |
| `key_id` | Key-list `keyId` of the signing key (§15.5). |

For a branch `UpdateRef` changing only one side of the pair, `packmap`
is the resulting live paired packmap; for a write directly to the
packmap ref, `ref` and `target` describe that requested ref and
`packmap` equals its resulting value. The branch head and
`refs/mkit/packmap/<x>` share one sequence; `GetReceipt` selects either
one through `refs/heads/<x>` (STC §2.2). `advance_sequence` MUST begin
at `1` and MUST NOT reset on ref deletion, recreation, or
repository-level deletion. On a deletion the old
head value is attested as `target`, and a branch's prior packmap value
remains in `packmap`, while `deleted` unambiguously records absence.
`closure_verified` MUST be false on deletion. An advance that consumes
no tickets MUST have an empty `added_packs` array; the server MUST NOT
filter consumed tickets by whether the pack was already a member or was
hidden by a hold or flag. Filtering would disclose that hidden state.
Informative: packs uploaded through an un-ticketed `UploadPack` never
appear in `added_packs`. The receipt's `previous` and paired
`packmap` are visible to the writer; they describe that writer's own committed write, not a reader view. An
advance with no deployment allowance has an empty `reservations`
array, even if it consumes tickets; a ticketless write that ran Admit
MUST include its deployment reservation. Entries in `added_packs` MUST
be in ascending id order with no duplicate id, and `reservations` MUST
be in ascending id
order with no duplicate id. A reservation id MUST be the deployment's
§6.3 allowance id; the server MUST NOT substitute a synthetic quota or
outcome id. `external_ref` MUST be copied only from that allowance and
MUST satisfy §6.6; an empty value MUST be omitted. Every writer of the
repository can fetch and see it through `GetReceipt`, subject to the
write-only grant ref-scope limit in §15.6. The implementer MUST keep
secrets out of it.

`storage_lease` MUST be either `{ "permanent": true }` or an object
with `scope` (`repository` or `ref`) and `expires_at_ms`, `grace_ms`,
and `suspension_ms` as decimal strings. The terms describe the
applicable recorded lease, including an inherited repository default;
they do not make a per-ref lease govern byte availability (§12.2).

An advance receipt MUST NOT contain `new_to_store`, physical or
deduplicated byte counts, or any other fact that exposes holdings of
other repositories (STC §5.1). It MUST NOT contain logical or
uncompressed byte counts, which opaque mode cannot establish. It MUST
NOT contain publication, hold, or inspection state. Informative: the
PRD's proposed logical/stored byte pair is replaced by `added_bytes`,
the sum of consumed-ticket pack sizes. It is not a claim about
physical storage or billing.

### 15.4 Lease predicate

For `kind: "lease"`, the predicate MUST contain `origin`, `scope`,
`terms`, `effective_state`, `cause`, `lease_version`,
`issued_unix_ms`, and `key_id`. `origin` is the canonical audience.
`scope` is either `{ "repository": "<full identity>", "ref": "<full ref or empty>" }`
or `{ "namespace": "<self-certifying namespace>" }`; an empty `ref`
means repository scope. `terms` is exactly one of finite terms
`{ "expires_at_ms": "<i64>", "grace_ms": "<u64>",
"suspension_ms": "<u64>" }`, `{ "permanent": true }`,
`{ "inherit": true }`, or `{ "not_applicable": true }`.
`inherit` records removal of explicit per-ref terms so that §12.1's
repository default governs; removing a repository default records
`permanent`. `not_applicable` is used only for a namespace-level
suspension override, which has no storage-lease terms. An override
change that leaves terms intact repeats those terms in the receipt.
`effective_state` is one of `active`, `grace`, `suspended`, or
`deleted`, after applying §12.2's administrative override at issue
time. `cause` is exactly `POLICY`, `RENEWAL`, or `ADMIN` (§12.4).
`lease_version` is a u64 decimal string, starting at `1` and increasing
by exactly `1` for every receipt-producing terms or override change at
that scope, including across restart, renewal, and ref recreation. The issued time and key
id have the same meaning as for an advance receipt. A repository
default change issues one repository-scope receipt, not a separate
receipt for each inheriting ref. A namespace override change issues one
namespace-scope receipt, not one per repository. A terms removal and a
namespace override change therefore both issue receipts.

### 15.5 Signing key, publication, and rotation

A deployment MUST use one receipt-and-notice Ed25519 role key for
storage receipts and §14 redaction notices. That role key MUST be
distinct from hook-channel, admin, URL-token, write, and upload MAC
keys. The key-list `keyId` is the 64-lowercase-hex BLAKE3 digest of
the raw 32-byte public key. The DSSE signature's `keyid` is exactly
`blake3:` followed by that `keyId`; predicate `key_id` and
`GetServerInfo.receipt_key_id` are exactly the unprefixed `keyId`.
`GetServerInfo.receipt_public_key` is the current signing key's raw
32-byte public key. Both info fields MUST be empty only when the
receipt-and-notice key is not configured. A deployment that enables
takedown MUST configure this key and publish its key list, or MUST
refuse startup (§14).

The deployment MUST publish `GET /.well-known/mkit-receipt-keys.json`
in the §7.2 key-list shape, with `version: 1`, `alg: "ed25519"`, and
the `keyId` convention above. It MUST return `Cache-Control: public,
max-age=300`, allow CORS from any origin, and require no bearer,
signed URL token, or payment. §14 notices use the same document.
During rotation the deployment MUST publish the new key in this list
at least 600 seconds before its first signature, covering two
300-second max-age periods. It MUST set
`notAfterMs` on the old key and MUST retain that retired key in the
list forever. A verifier MUST accept a listed key only when the signed
statement's issue time is within the
half-open interval `notBeforeMs ≤ issue_time < notAfterMs`, with
an absent bound open on that side. For storage receipts the issue time
is `issued_unix_ms`; for redaction notices it is `issuedAtMs` (§14).
A client with a TOFU pin refreshes the same-origin key list during
rotation, checks that it still includes its pinned key, and pins the
newly published key before accepting signatures under it. This
overlapping list is the continuity path for TOFU pins across rotation.
A newly listed key under a user-supplied trust root remains `unpinned`
until the user adds it to that root. A compromised key MUST
be removed from the list, thereby invalidating every receipt and notice it
signed. No transparency log or trusted compromise timestamp is
specified; a compromised signer can backdate its issue time.

### 15.6 Delivery, retrieval, and retention

The Connect receipt fields and `GetReceipt` wire are in STC §§2–4.
Its namespace lease selector derives the namespace from the signed
repository identity; it does not accept a caller-supplied different
namespace.
The receipt fields contain the complete envelope JSON bytes and are
empty for conflicts or when receipts are disabled. `GetReceipt` is a
signed read and MUST require the §10.1 writer view for the requested
repository; all other callers receive `not_found`, with no indication
whether a receipt exists. The SPEC-WRITE-GRANTS §9.3 read check MUST
precede this writer-view check; STC §2.2 fixes the complete order and
uniform error. A write-only grantee with a signed request has the writer
view and MAY fetch advance receipts only for refs within that grant's
ref scopes; a paired packmap maps to its branch for this check. An
out-of-scope advance receipt MUST receive the uniform `not_found` of
STC §2.2. Callers with `read` or `read,write` capability, owners, and
authorities are not subject to this grant-scope limit. The lease
selector MUST remain available to an otherwise authorized writer
while the repository is suspended or deleted, for receipts of that lease scope. The server MUST
retain the latest signed receipt for each ref, including its terminal
deletion receipt, while the repository exists, and the latest receipt
for each repository or ref lease scope while its repository identity remains
addressable, and each namespace lease scope while its namespace remains
addressable, including while the effective state is `suspended` or
`deleted`. This retention obligation begins when the pending signature
is complete. Lease receipts from repository- or namespace-level
takedowns and reinstatements are available through `GetReceipt` only;
the takedown and reinstatement admin responses carry no receipt. The advance selector MUST
enforce §12.2 suspension with `permission_denied` and public message
`lease suspended`; the lease selector remains available as above.
The server MAY retain older versions for a deployment-set
`receipt_retention` and MUST return `not_found` for a version it no
longer holds. This retention does not make receipts server GC roots.
SSH and enc clients receive no storage receipts in M5; their frozen
protos gain no receipt field. A future client integration is a separate
follow-up.

### 15.7 Client verification

Before storing a storage receipt, a client MUST:

1. Decode the envelope strictly, enforce the 65,536-byte cap, and
   check the exact `payloadType`, Statement type, and `predicateType`.
2. Verify the strict Ed25519 signature. A user-supplied trust root is
   pinned. When the user selects trust on first use (TOFU), the client
   MUST pin the accepted key on first use and treat it as pinned
   thereafter. Without that selection, a key learned only from
   `GetServerInfo` or the well-known URL MUST be reported and stored
   with status `unpinned`, not silently promoted to pinned.
3. Check that predicate `key_id` equals the body of the DSSE
   `blake3:` keyid, equals BLAKE3 of the selected public key, and
   that `issued_unix_ms` lies inside that listed key's validity window.
   The client MUST refresh the key list within its 300-second max-age.
   On an unknown `keyid`, it MUST refetch the list once, ignoring its
   cache, before deciding whether the key is listed. A pinned key absent from
   the current list fails verification even if its signature and
   issue-time window otherwise pass. The overlapping
   key list in §15.5 permits a client with a TOFU pin to pin the
   replacement key before the old key stops signing. A key newly
   published under a user-supplied root remains `unpinned` until the
   user adds it.
4. For an advance, check `origin`, `repository`, `ref`, `target`,
   `packmap`, and `previous` against the operation the client sent,
   wherever the operation supplies that value; an absent branch
   packmap or creation previous MUST remain absent. With an `ANY`
   update, the client has no sent previous value to compare. The
   `added_packs` ids and byte counts MUST equal the full set of tickets
   this advance consumed; none may be omitted because a pack was
   already present or hidden. For a
   deletion, the sent expected old value is its `target`.
5. Check `subject[0].digest.blake3` equals `target` for an advance;
   for a lease, check both digests against the canonical scope bytes.

If any check fails, the client MUST warn and MUST NOT store the
receipt. `unpinned` is a stored verification status, not a failed
signature check; clients MUST warn that it lacks a pinned trust root.
A receipt-verification failure MUST NOT turn an otherwise
committed push into an error unless the user explicitly opts in to
requiring a valid receipt. Clients MUST NOT log complete storage
receipts. Storage receipts are kept client-side and MUST NOT be pushed;
they are not object-GC roots. Client storage MUST use a
separate `.mkit/receipts/` store, never `.mkit/attestations/`.

Informative: the labelled vectors under `rust/tests/golden/receipts/`
pin canonical payload and envelope bytes, signature, subject binding,
key-list bytes, and four verification failures (§20).

## 16. Admin API and audit log (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 17. Custom backends, backup and migrations (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 18. Conformance scope (reserved, M5)

Reserved: this section is specified with M5 (see the version history).

## 19. Version history

| Version | Status | Change |
|---|---|---|
| 1 | draft | Additive M5 storage leases and lifecycle Event (§12), server GC (§13), and section renumbering (§§19–20); `GetServerInfo.leases` in STC §2.1. |
| 1 | draft | Storage receipts (§15): live advances and lease changes, shared receipt/notice key list, verifier rules and goldens; additive receipt fields and retrieval in STC, and `AdmitAllow.external_ref` (§6). |
| 1 | draft | Additive M5 published view (§10), per-advance inspection and quarantine (§11), including surplus pack entries; additive Inspect phase/id/kind/defer/flagged ids and Authorize writer_view (§6); `GetServerInfo.async_inspection` in STC §2.1. |
| 1 | draft | Initial M3 pipeline, durable outcome and remote-hook contract; M5 sections reserved. Admission credential headers (§6.3); indexed mode (§9). HTTP read reservations and procedure strings (WP-4.11), amended with `read_reconcile_grace = 60 s` default and `ReadServed` priority within grace (fix round 1). |

## 20. Test anchors

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
| `admit-allow-external-ref.response.json` | Optional implementer reference carried into a storage receipt (§6.3, §15). |
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
| `event-lease-grace.request.json` | Ref-level expiry into grace, sequence and lease terms (§12.4). |
| `event-lease-deleted.request.json` | Repository-level expiry into deletion (§12.4). |
| `event.response.json` | Empty Event acknowledgement (§12.4, §8). |
| `signature.json` | Admit body including credential headers, Outcome body, and Event body, with exact bytes, canonical signing strings, hashes, signatures, and full headers (§7.1). |
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

The storage-receipt fixtures under `rust/tests/golden/receipts/` pin §15:

| Golden file | Contract pinned |
|---|---|
| `advance-opaque.statement.json`, `advance-opaque.dsse.json` | Live opaque advance, blake3-only subject, reservation reference. |
| `advance-indexed.statement.json`, `advance-indexed.dsse.json` | Verified indexed advance and added membership. |
| `deletion.statement.json`, `deletion.dsse.json` | Deleted ref with prior target as subject. |
| `lease.statement.json`, `lease.dsse.json` | Lease change and two-digest scope subject. |
| `key-list.json` | Current and retired receipt-and-notice role keys. |
| `wrong-predicate.dsse.json`, `subject-mismatch.dsse.json`, `key-outside-window.dsse.json` | Distinct signed verification refusals. |
| `test-seed.json` | Public, labelled test-only Ed25519 seeds. |
| `MANIFEST.txt` | BLAKE3 hash of every other receipt fixture. |
