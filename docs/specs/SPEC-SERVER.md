---
spec: SPEC-SERVER
version: 1
status: draft-normative
audience: implementers of mkit.transport.v1 servers and of deployment business logic behind the remote-hook contract
---

# SPEC-SERVER — server pipeline guarantees and the remote-hook contract

## 1. Scope and relation to SPEC-TRANSPORT-CONNECT

**Protocol requirement.** This specification defines server acceptance guarantees, durable
outcomes and lifecycle events, storage leases, server garbage collection,
takedown and redaction notices, and the contract between a server and
deployment business logic.
An independent hook implementation can use this contract and the
`mkit.server.hooks.v1` schema without using a server implementation.

[SPEC-TRANSPORT-CONNECT](SPEC-TRANSPORT-CONNECT.md), abbreviated STC,
defines the client-visible `mkit.transport.v1` wire contract. Its rules
remain authoritative for client authentication, replay handling,
authorization, admission challenges, upload tickets, and RPC lifecycle.
References to STC below add observable safety guarantees or describe hook messages;
they do not replace those wire rules.

MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and REQUIRED have the meanings
defined by [SPEC-CONVENTIONS §1](SPEC-CONVENTIONS.md#1-normative-keywords).
The encoding, domain-separator, and golden-vector conventions of that
specification apply throughout this document.

A server that runs remote hooks MUST implement §5–§8. A server without
remote hooks MUST still implement §2–§5 and §10. Every configured inspector,
including an in-process inspector without a remote hook, is bound by §11.
Which of the indexed-mode, published-view, lifecycle, takedown, receipt and
admin sections (§§9–16) a server implements depends on its conformance
profile (§18). A deployment implements the
business decisions exposed by hooks; the server implements the pipeline,
validation, durable recording, and delivery guarantees specified here.

The contract does not define prices, payment verification, settlement
policy, moderation policy, or the deployment's account model.
[SPEC-WRITE-GRANTS](SPEC-WRITE-GRANTS.md) remains authoritative for grants,
their verification, and the preconditions they carry into apply.

Sections 10–18 cover the lifecycle contracts: §§10–11 specify the published view
and inspection, §§12–13 specify storage leases, lifecycle events, and
server garbage collection, §14 specifies takedown, §15 specifies storage
receipts, and §16 specifies administration. The other reserved sections remain
unspecified. Inspection, notice, and receipt fields extend the original hook
and transport shapes additively.
Section 16 applies to native and Workers deployments when an admin key
list is configured; without that list its routes are absent.
For a branch, its head and packmap share one publication sequence even
when either is written through `UpdateRef` (§10.2).

**Reference-server behavior. Current implementation profile.** This map describes the shipped core and
Workers adapter; §18 defines their conformance scope. Future full-profile rules
remain normative for implementations that adopt them. A future collector does
not weaken today's holder/hold safety, notice-key or admin contracts.

| Status | Behavior and contract |
|---|---|
| Implemented | Pipeline admission/outcomes (§§2–8), indexed verification/extraction (§9), paired publication and published reads (§10), and optional bounded synchronous inspection (§11, amended by §18). Publication verification retains its documented fail-closed limits. |
| Implemented, opt-in | Immediate takedown denial, verified preservation and durable discovery (§14, launch subset in §18); notice-key publication (§15.5); signed admin/replay, audit and purge (§16, restricted catalog in §18). Acceptance/preservation does not mean completed takedown. |
| Implemented safety groundwork | Content holders, pending-holder protection, extraction holds and deadlines derived from §13.4. Launch retains bytes permanently and runs no collector. |
| Retained, unintegrated groundwork | `store::inspection_mode`, `inspection_flags` and `inspection_holds`, plus reserved timer kind 14. Kept by owner decision; neither pipeline nor adapter installs these records or runs their continuations. Storage tests do not establish async-inspection support. |
| Future integration | Async inspection/holds/review (§§10–11), leases and lifecycle Events (§12), GC (§13), takedown rewrite/substitution/completion/notices (§14), and storage receipt issuance (§15). |
| Future deployment facilities | Edge caching and the exhaustive namespace catalog. Current purge delivery and known-holder/finite-root discovery remain implemented; discovery under open namespace policy remains incomplete (§18). |

The reference embedding fixture selects indexed mode, partitioned storage,
in-process hooks, and URL tokens, with takedown off and no inspection. Other
supported configurations require their own enforcement evidence.

### Storage adapter boundary

**Reference-server behavior.**

`mkit-server` defines the engine-neutral `NamespaceStore` contract. The
SQLite implementation (`mkit_server_worker::sql::{SqlConn, SqlKvStore}`),
physical storage-pressure telemetry, and Cloudflare relay plan budgets belong
to `mkit-server-worker`. Core has no `sql` feature or SQLite dependency.
The adapter move changes no statements, stored formats, or store semantics.

## 2. Pipeline order

**Protocol requirement.** A conforming server MUST preserve the observable
processing dependencies required by STC §7.1, including its replay
short-circuit, and the authorization and admission ordering in STC §7.5 and
§5.1. Authorization precedes quota or replay-record allocation; an admission
challenge or denial writes no RPC effects under those rules. A granted pending
reservation is recorded only after admission and before guarded acceptance
(§5). Signed reads skip the replay ledger. These requirements do not prescribe
a fixed set of execution stages. Stage numbers used below name the corresponding
semantic events, without requiring another server to use this orchestration.

**Reference-server behavior.** The reference extension points are numbered 0–9. An operation visits the stages applicable
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
   to unary RPCs, as STC §5.1 requires. Every mutating unary RPC runs it,
   including `SetRepoVisibility` in both its envelope and statement modes
   (§3).
4. **Replay reservation and streamed body.** Reserve replay state as STC
   §7.1 requires, and receive any applicable streamed body under the
   ticket and part rules STC §7.6 requires. Durably record a pending
   reservation when §5 requires it before the guarded apply.
5. **Pre-receive checks.** Run content verification and policy checks,
   including the built-in §14.2 blocklist check on every decoded pushed
   file object in indexed mode, whether or not an inspector is configured,
   and inspection configured to run synchronously before apply.
6. **Atomic apply.** Apply the operation with its preconditions and
   applicable outbox rows in the atomic unit specified by §3 and §5.
7. **Storage receipt signing.** Produce the §15 storage receipt when the
   deployment enables receipt signing for the committed operation.
8. **Outcome delivery.** Deliver the durable outcome to the configured
   sink under §5 and, for remote hooks, §6.5 and §8.
9. **Asynchronous inspection and lifecycle events.** Run configured
   asynchronous inspection after apply. Storage-lease background work performs
   transition side effects and durably records configured events under §12; request
   enforcement evaluates storage leases independently of that work.

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

**Protocol requirement.** Acceptance is the commit point for the operation's guarded
effects. Storage receipt signing and delivery may happen later; §15 fixes
the statement bytes at apply. An outcome
delivery failure does not undo an already committed operation.

## 3. Per-RPC lifecycle

**Protocol requirement.**

Each RPC's admission eligibility and apply effects are as STC §7.7
requires. The following rules specify the authoritative atomic boundaries;
they do not reproduce its lifecycle table.

- For `BeginUpload`, the replay record, reservation, and ticket MUST
  commit in one atomic unit, as STC §7.7
  requires. The successful apply replaces the pending reservation
  described in §5 with the ticket-backed reservation.
- For an `AdvanceRefs` that consumes tickets, the head, packmap,
  membership additions, and one `Committed` outcome per consumed ticket
  MUST commit in one atomic unit, as STC §7.7
  requires. A configured non-default Admission also admits the ref effects
  with zero bytes. Its separate reservation, when granted, MUST settle in
  that same unit, with zero byte totals. Pack reservations remain independent.
- For a directly admitted unary write, meaning `UpdateRef` including
  deletion and implicit pack consumption, or any `AdvanceRefs`, when admission grants
  a reservation the ref write and its
  `Committed` outcome MUST commit in one atomic unit. The successful
  apply replaces its pending reservation with that outcome.
- A `SetRepoVisibility` change goes through admission and outcomes like
  any other mutating RPC, in both modes. Admission runs after
  authorization (the envelope mode's owner or authority check; the
  statement mode has no authorizer call, its owner-signed statement being
  its own authorization) and after the replay lookup or the already-applied
  and not-newer statement checks, so a replay, an identical statement and a
  stale statement run no admission and record no outcome. It runs before any
  state change: a denial or challenge leaves no visibility row, listing
  index, replay record or reservation. Admission sees
  `procedure = /mkit.transport.v1.TransportService/SetRepoVisibility`,
  `declared_bytes = 0` and an empty `pack_id`; the statement mode has no
  signed envelope, so its `idempotency_key` is empty and its `owner` fact is
  true (the statement's signer is the namespace owner). When admission
  grants a reservation, the visibility row, its listing-index projection and
  the `Committed` outcome (no refs, no bytes) MUST commit in one atomic
  unit, replacing the pending reservation; a failed attempt records
  `Aborted` as below, and a reconciled abandonment is `ABANDONED`.
  Charges another admission returns for it are applied, in the same unit,
  to the quota scope each charge names. When the deployment also plans an
  automatic cache purge for the change, the purge, the audit and the outcome
  share one outbox update in that unit. The outcome-backlog bound (§5) is checked before admission, and only
  for an admission other than the default one (which never reserves); a
  refusal therefore strands no reservation. It is never applied to a real
  change from public to private: making a repository private MUST remain
  applicable while an outcome or purge sink is unavailable, so that change
  records its outcome even above the soft bound. A request that repeats the
  current value is not exempt. An `Allow`'s receipt headers are returned on
  the committed success only.
- An `Aborted` outcome MUST be written in a separate atomic unit after
  a definitely failed apply, as STC §7.7 requires. That unit replaces the pending
  reservation with `Aborted` when a pending reservation exists.
- An `AdvanceRefs` typed conflict consumes no ticket and records no ticket
  outcome; its tickets remain usable until expiry, as STC §7.7 requires.
  It MUST settle a separately granted ref reservation as `Aborted` with
  `REF_CONFLICT`, in the guarded conflict batch.
- A pack becomes a repository member only at the `AdvanceRefs` apply
  that consumes its ticket, as STC §7.7 requires.

The pending-reservation write precedes these guarded atomic units.
It does not move ticket creation or ref publication into admission.
Ticket eligibility, token checks, and part handling remain as STC
§7.6 requires.

### 3.1 Atomic acceptance

**Protocol requirement.** For an accepted signed ref write, a conforming
server MUST durably commit these effects in one atomic unit:

- the authoritative live ref effects, including both sides of a paired
  advance or deletion;
- the saved replay result and applicable quota effects;
- consumed ticket state and the corresponding repository membership additions;
- one terminal outcome for each consumed-ticket reservation and the outcome
  of a separately granted ref reservation, when applicable.

The same unit MUST retain durable responsibility for projections whose
indexes or counters may lag under their specified delivery rules. A failed
acceptance guard MUST commit none of that unit's effects. A typed ref conflict
is a separate guarded decision with its own replay and settlement rules (§3),
not an accepted ref write.

An observer MUST NOT see an accepted live ref effect without its durably
recorded replay result and terminal-outcome responsibility. Permitted replay
expiry and acknowledged-outcome pruning do not invalidate an earlier acceptance.
The earlier pending reservation does not itself establish acceptance.

Verification, decision, and acceptance MAY run in separate components within
one server's trust domain. Acceptance MUST bind to the exact verified frozen
bytes by pack ID and length. Every mutable fact relied on by verification or
the decision MUST be a guard in the atomic acceptance unit, including external
delta-base membership read under §9.4. Component placement does not relax that
unit or original-identity resolution of uncertain outcomes (§3.2).

**Reference-server behavior.** A portable decision retains exact scoped facts and
observation revisions through lowering. Checking guard categories alone does not
establish completeness: two ref names or absent membership keys remain distinct
even when they share a revision. An unconditional ref write needs no value guard
unless another rule depends on that value; admission may depend only on presence.
The published-source fence in §9.3 remains a separate check before each destination
apply attempt, rather than an atomic source-at-commit comparison.

**Reference-server behavior.** The portable ref decision answers every request
shape the wire admits: a single create/update, a single exact-match delete,
and any pair of valid ref names — canonical, unmatched, reversed, or
distinct — decided positionally under the first change's outcome class
(SPEC-TRANSPORT-CONNECT §4 makes the canonical packmap/head pairing
optional). Shapes the wire rejects or leaves to the implementation — a delete
whose expectation is not `MATCH` or whose new ID is nonempty
(SPEC-TRANSPORT-CONNECT §7.8), a repeated or malformed ref name, a partial
admission binding, and a request carrying more than two ref changes — keep the
reference server's generic per-ref CAS decision, and the portable decision
answers a typed refusal for them. The shape is judged before the portable
decision runs; every failure of the decision for an admitted shape is the
server's answer, never a silent fallback to the generic path.

**Reference-server behavior.** The portable ticketed decision answers the
signed `AdvanceRefs` form: a ref pair consumed with one or more upload
tickets — pending-reservation stability, replay precedence, ticket
validation in request order, authority-generation fencing, the embedded ref
decision, and the ticket-closure, reservation-settlement, storage-counting
and durable-outcome effects it composes (§6.3, §6.5, §9.3). The separate
defensive abort for a ticket whose pack never landed and a standalone
reservation settlement share the same portable rules. A ticketed request
that is unsigned or carries no replay binding, that was rejected before
planning, or that holds a fork barrier keeps the reference path. A stored row
that cannot be decoded is withheld from the decision rather than answered: an
earlier pending, replay, ticket or ref answer keeps its precedence, and the first
undecodable row the decision actually needs is the diagnostic.

The ticketed decision guards every ticket row it examined, including on a stored
conflict, the exact repository storage counter whenever the batch counts inline
(it fixes each pack's `new_to_repo`), the settled reservation rows, and the
authority observation when authority fencing applies. A ref that moved after
custom admission answers `aborted` "ref changed after admission; retry" with the
ref-conflict abort cause, exactly as the unticketed path does. A stored
fast-forward refusal decided on an `ANY` expectation commits only while the ref
still holds the value the check pinned. If the ref moves, the stored refusal
fails its guard, the write is re-planned, and the request ends as retryable write
contention; the client's retry is decided afresh. The membership rows that an
ancestry or closure check read live in the paged, sharded object index and stay
covered by the §9.4 lag window and the §14.2 blocklist commit window instead of a
batch comparison. A stored built-in refusal relies on the admission-time grant
and authority checks of the same request rather than on a batch comparison of
the grant epoch. The defensive abort of tickets whose pack is missing compares
the ticket rows it closes and every earlier ticket row that fixed its boundary.

**Reference-server behavior.** One fact has one class at every portable decision.
"Before a result is saved" covers the ref write, the ticketed advance and fork
acceptance; "after acceptance" covers fork advance, activation, completion and
clearance, which never change the saved result.

| Observed fact | Before a result is saved | After acceptance |
| --- | --- | --- |
| Authority fence not comparable atomically | Retryable: `Retry(Unavailable)`; fork acceptance `UnavailableInput` | Not observed |
| Authority or grant moved from the original binding | Permission denied, unstored | Withheld, result unchanged: `Defer`, code `ForkPermissionDenied` |
| Lifecycle unacquired | `UnavailableInput` | `UnavailableInput` |
| Lifecycle not active at the bound incarnation | Ref write and ticketed advance: `Retry(ChangedFacts)`. Fork acceptance: `DestinationNotEmpty`, because §9.9 requires an empty destination | Withheld, result unchanged: `Withhold(LifecycleUnavailable)`; clearance `Retain` |
| Supplier held | Retryable: `Retry(Unavailable)` | Not observed |
| Object or supplier denied | Permission denied "object blocked", unstored | Not observed |
| Member not yet visible | Retryable inside the original window: `Retry(MembershipNotVisible)`; after it, stored `invalid_argument` "open closure" | Not observed |
| Admitted ref changed | Retryable: `Retry(AdmittedRefChanged)`, `aborted` with the ref-conflict cause | Not observed |
| Source absent, unreadable, unpublished or unpaired | `not_found` "source not found", unstored | Not observed |
| Source pair differs from the captured pair | Retryable: `Retry(Unavailable)` | Not observed |

The rows are pinned by `fact_class_table_rows_for_ref_writes`,
`fact_class_table_rows_for_fork_decisions`, `source_fence_refusals_use_the_server_specification_answers`
and the `authority_unfenceable`, `authority_generation` and `destination_deleting`
rows of the fork acceptance fixtures.

### 3.2 Replay, durability, and recovery

**Protocol requirement.** A committed replay MUST answer with its saved result
without repeating any acceptance effect, quota charge, ticket consumption, or
terminal-outcome creation. Within the required retention period, response loss
or an uncertain storage outcome MUST resolve through the original operation
identity. A server MUST NOT report uncertainty as a definite abort unless
authoritative recovery proves that the acceptance did not commit. Cancellation
or a timeout alone is not that proof. Replay does not extend an envelope's
validity or the wire replay lifetime.

`Committed` means durable to the server's declared durability profile. The
server MUST declare its process, host, and storage or failover guarantees;
a volatile profile MUST identify itself and MUST NOT claim persistent
conformance. Several commits MAY share a durable log sync, but none may be
acknowledged before its own writes and required earlier dependencies are durable.
Reads, failed-guard results, publication, relay dispatch, and external outcome
delivery that depend on a commit MUST wait for that durability too. Holding
only the originating response is insufficient.

A server MUST separate atomic acceptance, durable acknowledgement, and
visibility. It MUST check current guards, ownership, and server-clock deadlines
at the final irrevocable acceptance point. Queue admission is not that point.
Waiting for durability MUST NOT extend authorization or permit a later unchecked
acceptance. A server relying on a bounded clock-to-commit span MUST preserve
that bound or provide an equivalent drain and fencing guarantee. A revocation
or ownership-transfer acknowledgement MUST cover already accepted writes so
they cannot emerge as new effects afterward.

Cancellation MUST leave the decision entirely before or entirely after
acceptance, never torn; once the accepted state is observed, cancellation MUST
NOT restore the prior state. Command ownership and recovery responsibility MUST
survive caller cancellation. Graceful shutdown MUST drain accepted commands or
retain their durable recovery responsibility. Restart MUST recover an atomic,
dependency-closed state containing every commit acknowledged within the declared
durability profile. A durability or ownership failure MUST stop successful
acknowledgement and dependent publication until safety is re-established.

### 3.3 Default admission

**Reference-server behavior.** mkit-server's default admission charges no
quota for a visibility change: it is owner-only, stores no object bytes,
and consumes no quota operation. It plans its namespace charge with the ref
and upload writes it aggregates. Other admission profiles may grant charges
under §3's atomic rules.

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

**Protocol requirement.**

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

If the guarded apply definitely fails, the server MUST replace the pending
reservation with `Aborted` in a separate atomic unit. The failed apply
MUST NOT leave the operation's guarded effects committed.

The server MUST eventually resolve a pending reservation whose operation's
authentication validity interval has passed without replacement by durably
recording `Aborted` with reason `ABORT_REASON_ABANDONED`.
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
§7.7 requires. The server MUST eventually record `Expired` for a ticket-backed
reservation with no outcome once its ticket has expired. It MUST NOT classify that reservation as an abandoned pending
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

**Reference-server behavior.** The reference server resolves abandoned and
expired reservations through periodic reconciliation. Recording a pending
reservation costs it an additional atomic unit per admitted write with a
reservation id; default quota admission without a reservation id avoids that
write. Other servers may use different recovery scheduling and storage while
preserving the terminal-resolution and atomicity requirements above.

**Protocol requirement.** The server MUST retain an outcome until acknowledged. Delivery MUST
be at least once, using the reservation id as the idempotency key.
There is no ordering guarantee between reservations. A receiver MUST
treat a repeated outcome for the same reservation as the same result.

The durable outbox holds outcomes and, when configured, §12 lifecycle
events and §16 cache purges awaiting acknowledgement. Events use `event_id`
as their idempotency key; event acknowledgement does not acknowledge an
outcome or another event. Delivery
attempts and process restarts MUST NOT discard an unacknowledged row.
Acknowledging one reservation does not acknowledge another reservation.

A server MAY refuse new admitted writes with retryable `unavailable`
while its combined undelivered outcome, event, and cache-purge backlog exceeds a
configured bound. Events and cache purges MUST count toward that bound. The server MUST
NOT drop outcomes, events, or cache purges to relieve that backlog. Reads and writes
that do not run admission MUST be unaffected by this backpressure.
The threshold is a soft snapshot check before admission. Concurrent admitted
operations may overshoot it by their in-flight terminal rows and encoded bytes.

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
| CachePurge | `/mkit.server.hooks.v1.HooksService/CachePurge` |

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

A deployment MAY implement any subset of the six RPCs. The calling
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

**Protocol requirement.**

`AuthorizeRequest.operation` describes the authenticated operation
before admission. The deployment MUST configure remote Authorize in
one of these two roles:

- **`authority`:** the hook is the deployment-defined authority source
  of STC §7.5 rule 3. The built-in namespace policy (`allowlist`/`any`)
  MUST be evaluated first; a hook Allow MUST NOT override its denial.
  In self-certifying mode, rules 1–2 (owner key and grant) MUST be evaluated before the hook.
  Authority namespace mode instead follows §6.2.2.
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
| `fork` | Present only for a fork (§9.9): the source repository, branch and expected tip, the source's visibility and visibility revision observed consistently (and checked again before construction starts), and the requested destination visibility. `operation.repository` is the destination. |
| `source_ref`, `source_head`, `source_packmap`, `source_generation`, `source_publication_sequence` | Present only for published-source `AdvanceRefs` (§9.3): the source branch and the pair, generation and published prefix captured from its authoritative row, in `operation.repository`. Intended destination writes still appear in `refs`; admission declares zero bytes. |

For `ListRepos`, `operation.repository` is an arbitrary caller-chosen selector
within the requested namespace, and its repository name need not exist. The
operation is **namespace-scoped**, as STC §7.10 requires. A repository-specific
read allowance MUST NOT imply permission to enumerate other private names.
Non-owner authority callers retain the public listing unless the deployment
explicitly enables namespace-wide authority listing (disabled by default) and
the hook Allow returns `writer_view = true` for the entire namespace.
Authority `permission_denied`/`not_found` denials select the public listing even
for the owner; hook failures fail closed. A Check hook cannot widen any listing
view and its denial or failure propagates.

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

### 6.2.1 Optional namespace authority-generation fence

**Protocol requirement.**

A server MAY implement authority fencing with an independent, monotonically
increasing unsigned 64-bit generation per namespace. After it acknowledges a
generation change, no acceptance relying on an older generation may commit.
Acceptance and every commit advancing a fork MUST compare the recorded authority
facts with the current generation. Fencing MUST NOT reuse grant epochs or make
them apply to external-authority writes.

**Reference-server behavior.** Fencing is disabled by default and requires the
Authority authorizer role and transactional storage.

**Protocol requirement.** The following rules apply when authority fencing is offered.

When enabled, every Authority allowance for a write MUST carry
`authority_generation`, including zero. Missing or invalid facts MUST fail
closed. Trusted Authority facts MUST survive admission, planning and retries;
the established owner and grant facts MUST remain intact. Final acceptance
MUST atomically compare those facts with the current authoritative generation. A mismatch MUST return
`permission_denied`, accept nothing, consume no tickets, and abort any admission
reservation. This covers ref advances/deletes, ticketless upload acceptance,
reserved `BeginUpload`, and authority envelope visibility writes. Upload tickets
MUST bind the generation; ticket-only uploads and multipart operations MUST
reject stale generations before staging additional bytes and before completion.
Private buffering does not establish accepted upload state. Completion,
authenticated part receipts, and verification markers MUST retain current
authority guards. A revoked stream MUST stage no subsequent write or succeed at
completion; an already in-flight write may leave unaccepted shared bytes.
Already accepted inspection/publication work is not cancelled by this fence.

**Reference-server behavior.** Client-frame validation is independent of
storage-write checkpoints. Each backend staging write checks the generation
before and after its await. These checkpoint counts and runtime scheduling
are implementation mechanisms, not a required orchestration.

**Protocol requirement.** The following wire rules apply when the authority RPCs are offered.
`GetAuthorityGeneration` and `SetAuthorityGeneration` are namespace-level RPCs
outside auth-v2 envelopes. A server whose authority shares its acceptance store
MAY omit these RPCs while implementing fencing. A server not offering them MUST
reject both with `unimplemented`, as a disabled deployment does. The
`mkit-authority-generation:v1` statement below authorizes only the wire setter;
it is not required for in-store authority changes. The setter
MUST authorize a bounded canonical statement using a configured, dedicated
Ed25519 deployment-authority key with explicit permission for the namespace;
a namespace-owner key alone MUST NOT authorize it. Keys MUST differ from hook,
accepted ticket, and active or retired URL-token keys.

The wire statement is `<base64url(bytes)>.<base64url(signature)>`, both unpadded
and canonical, at most 2,048 ASCII bytes. The signed UTF-8 bytes are exactly eight
LF-separated fields, without a final LF, in this order: literal
`mkit-authority-generation:v1`, key id (`[A-Za-z0-9._-]{1,64}`), canonical
namespace, generation, canonical deployment audience, created milliseconds,
expiry milliseconds, and nonce (64 lowercase hexadecimal characters). Decimal
integers MUST have canonical unsigned representation. The signature is strict
Ed25519 over BLAKE3 of those bytes. Expiry MUST exceed creation by at most
300,000 milliseconds; the statement MUST be unexpired and creation MUST be no
more than 30,000 milliseconds ahead of the verifier's clock. The key configuration
MUST reject weak or duplicate public keys and namespace-owner keys for any of
its permitted Ed25519 namespaces.

The target MUST equal the stored generation (idempotent completion retry), or
increase it by at most 1,024 without overflow. Rollback MUST be rejected. The
nonce binds the authorization, but is not a single-use token: repeated valid
statements for the same target MUST resume completion, including after restart.
A caller MAY refresh an expired statement for the same target. Reusing a nonce
cannot authorize a different target or namespace without a new signature.

A generation-change acknowledgement MUST establish a barrier after which no
older-generation acceptance can commit. Concurrent writes MUST either precede
that barrier or compare the new generation and refuse. Recovery and cached
authority evidence MUST preserve this guarantee. A pending setter MUST return
`unavailable` with a `Retry-After` header in delay-seconds. A completed replay
performs no new acceptance.

**Reference-server behavior.** The reference server serializes generation
changes with lease grants. Leases carry independent grant and authority
generations and acknowledgements; pushes precede acknowledgement. Completion
waits for every old lease to acknowledge or expire, including recovery holdoffs.
Independent durable scan checkpoints bound each request to eight pages of four
rows and four single-attempt pushes. Pending counts are conservative lower
bounds. Backend deadlines constrain the lease and apply window. These leases,
page sizes, checkpoints, and call bounds are implementation mechanisms.

**Protocol requirement.**

Under `namespace_policy = any`, `GetAuthorityGeneration` and
`SetAuthorityGeneration` MUST NOT require the namespace record: the deployment
key signs each statement, so a statement MAY precede the namespace's first
write. Under an allowlist the namespace MUST be listed.

**Protocol requirement.** The following rules apply when authority fencing is offered.
Namespace or repository creation MUST compare the same current authority
facts as other acceptance. A stale generation MUST create neither.

When `BeginUpload` finds an unexpired ticket for the same binding (ref, pack
and signer) issued under an older authority generation than the current
Authority allowance, the server MUST NOT answer `permission_denied`. It MUST,
in one atomic unit, close the old ticket, preserve open-ticket counts,
record its reservation's `Aborted` outcome with reason
`ABORT_REASON_EPOCH_MISMATCH` and procedure `BeginUpload`, and open the new
ticket and reservation under normal admission. The decision MUST compare the
old ticket, its binding, relevant counts and reservation, applicable membership
and verification state, and current generation. It MUST invalidate verification
state just as expiry would. Net-zero replacement MUST NOT consume additional open-ticket allowance or
refund the old reservation's admission charges. After commit, the server SHOULD
abort the old multipart session best effort. A lost acknowledgement or crash
leaves physical cleanup to backend lifecycle recovery.
Only an older generation is replaced: a
ticket from the same or a newer generation than the allowance still answers as
before (idempotent return or `permission_denied`), and a ticket issued before
fencing was enabled (no generation) is never replaced and answers
`permission_denied` until it expires. Racing consumption, expiry or a second
replacement fails a guard and re-plans or answers a retryable `aborted`.

Activation MUST durably establish fencing mode and initial generation zero
in one atomic unit, without registering a business namespace or suppressing
first-write admission and creation charges. Before the first fenced acceptance,
it MUST establish the generation-change barrier, including previously issued
authority evidence. Activation MAY return `unavailable` with `Retry-After: 1`
while pending. An executor with fencing disabled MUST refuse persisted fenced
state, including generation zero; it MUST NOT reinterpret it as unfenced.
Unfenced tickets MUST NOT become usable as fenced tickets. Ticket-only staging and completion MUST retain current authority guards across
backend work. Shared bytes or retained proof evidence MUST NOT let a stale ticket
create membership.

Recovery and portable restore MUST preserve authority mode and generation,
invalidate incomplete barrier observations, and refuse reconstruction or
rollback of missing authoritative fence state. Barrier progress MUST survive
executor replacement. A failed comparison MUST retain unresolved work; barrier
completion MUST revalidate the current authoritative state.

**Reference-server behavior.** The reference server stores separate grant and
authority barrier cursors and guards cursor saves and resets against the
observed generation and recovery state. Its setter has a conservative ceiling
of 43 metadata calls. Fencing mode and readiness are retained with lease-recovery
state; leased grants copy readiness only after the initial barrier.

**Protocol requirement.**

The authority service must stop delegate authorization, persist its target,
complete this barrier, then acknowledge revocation. Re-enrolling an identical
key requires fresh keys or incarnation/operation binding in that service.

### 6.2.2 Opt-in authority-owned namespaces

**Protocol requirement.**

A deployment MAY configure `namespace_mode = authority`. The default is
`self_certifying`, which retains STC §7.4's owner-key and owner-address grammar
and authorization rules. Authority mode MUST require Multi addressing,
an authority authorizer, the §6.2.1 authority-generation fence, and
`namespace_policy = any`. Startup MUST refuse any inconsistent combination;
the fence's auth-v2, transactional storage, and non-open hook prerequisites
still apply. Namespace mode is a deployment setting, never a request header.

Authority namespaces are opaque ASCII names of 1–72 bytes, matching
`[a-z0-9][a-z0-9._-]*`. The server MUST reject `root` and every name beginning
with `ed25519-` or `0x`, including otherwise valid self-certifying identities.
This accepts lowercase UUIDv7 names with dashes. A self-certifying deployment
MUST reject these opaque names at repository request and HTTP route boundaries.
Repository names and the maximum 173-byte identity length remain unchanged.
Owner-statement and grant codecs retain their self-certifying grammar; client
URL addressing accepts the union of both grammars
([SPEC-TRANSPORT-CONNECT §7.4](SPEC-TRANSPORT-CONNECT.md#74-repository-addressing)).

Registration: a namespace in authority mode is registered when its
authority generation has been durably established, which a verified `SetAuthorityGeneration`
statement (including generation 0) creates before any write. A write,
`BeginUpload` or visibility change for an unregistered namespace MUST be
refused with `permission_denied` (`namespace not registered`) before the
Authority hook, Admission or any store write, so a first write is always
fenced and no namespace can be squatted by a client. The check runs in
authorization under every supported storage arrangement, so no transport or
upload path reaches the hook, admission, or replay or charge recording for an
unregistered namespace. Registration status is not confidential: an
unsigned `GetAuthorityGeneration` already reveals a generation of 1 or more, and
a write probe can tell an unregistered namespace from one registered at 0. `GetAuthorityGeneration`
reports 0 for an unregistered namespace. The first accepted write still
reaches Admission with its creation facts and charges unchanged.

The deployment is the trust root. Ownership cannot be verified from the name
alone. Only the Authority hook authorizes writes or assigns the caller's writer
view. The server MUST NOT derive an owner key from an opaque name. Authorize
and Admit MUST receive `owner = false` and no grant; hook-returned owner/grant
claims MUST NOT manufacture either fact. The authority-generation allowance
still supplies the independent guarded write fence.

Owner-signed grants, grant-epoch operations, and visibility statements MUST be
refused with `permission_denied` and the uniform message
`owner statements are not supported in authority namespace mode` before owner
verification or repository-state access. This includes presented grant headers
on reads. `GetServerInfo.grant_schemes` MUST be empty in this mode. Signed
visibility envelopes continue to use Authority-hook authorization. URL-token,
admin, publication, and commit signatures retain their separate trust roles;
none provides ownership of an opaque namespace.

Dedicated authority keys MAY use exact opaque namespace scopes or `*` in
authority mode. A wildcard authorizes generation statements for every served
namespace; it grants no client write or read permission and bypasses no
namespace registration, statement audience, lifetime, signature, generation-step,
or lease-barrier check. Wildcards MUST be refused in self-certifying mode.
The 16-key bound and 1,024-namespace exact-scope bound remain. Authority keys
MUST remain separate from owner, hook, ticket, URL-token, admin, publication,
scanner, and history-token keys wherever those roles are configured.

In authority mode, a signed auth-v2 ListRefs envelope with an authority-hook
writer allowance MUST satisfy the writer authority required by owner-view
storage queries, object reads, and URL issuance. A reader allowance alone MUST
NOT satisfy it. Unauthorized principals MUST receive the same repository-absence
response for existing and missing repositories. The ordinary publication,
reachability, visibility, and denial checks remain. Namespace-wide private
listing still requires the explicit opt-in and a namespace-scoped hook writer
allowance.

**Reference-server behavior.** The listing opt-in is
`PipelineConfig::list_repos_authority_full`. Authority mode uses
`AuthorizerRole::Authority`. The writer allowance satisfies `repo_storage`,
`repo_storage_many`, `ReaderView::Owner` reads, and owner-view `issue_urls`;
batched counters return `None` for both missing and unauthorized repositories.

**Protocol requirement.**

Under `namespace_policy = any`, namespace discovery is not exhaustive.
Authority deployments MUST NOT claim complete deployment-wide takedown from
the namespace names or the available catalog. Embedders own account models,
keyrings, commit-signer policy, and any trusted landing-time storage.

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
| `new_to_repo_bytes` | Bytes new to this repository: zero when the upload's pack is already counted for the repository (§6.5.1), else its declared size; absent for an operation that adds no pack and when no admission hook is installed. A pre-admission observation: racing writes MAY both see the pack as new, and the committed counter (§6.5.1) is the authoritative value. |
| `credential_headers` | Admission credential request headers under the forwarding rules below; empty on a first attempt without credentials. |
| `fork` | Present only for a fork (§9.9): the source repository and the bytes the charge covers. Then `declared_bytes` and `new_to_repo_bytes` equal that count. |
| `resolved_ref_updates` | The effects a successful ref apply commits: each full name, new target or deletion, and `CREATE`, `REPLACE`, `DELETE`, or `NO_CHANGE`. Empty for operations without ref writes, including fork, and for the built-in default Admission. |

Creation signals and admission input are supplied as STC §5.1 requires.
In particular, `new_to_repo_bytes` does not mean bytes new to the whole
store. Presence MUST preserve the distinction between unknown and zero.

**Resolved ref effects.** The original request conditions remain in
`operation.refs`. `resolved_ref_updates` describes each working update in
planner order (packmap before head for an advance). When correlating request
conditions with resolved effects, consumers MUST match ref names. `CREATE` adds an absent
ref, `REPLACE` sets a present ref (including the same target), `DELETE`
removes a present ref, and `NO_CHANGE` deletes an already absent ref. The
server MUST fence each admitted effect in the same batch that applies it.
With custom Admission, duplicate destination ref names MUST be rejected
before invoking the hook or recording a reservation. Each admitted name
therefore represents exactly one ref's presence effect. The built-in default
retains its existing validation and accounting.
The public deletion API still requires `MATCH`; deleting an absent ref there
conflicts. `NO_CHANGE` represents the planner's absent-deletion case without
widening that request validation. Published-pair branch creation supplies both
destination refs as `CREATE`, with the captured head and packmap targets.
`MISSING` and `MATCH` bind presence through their CAS conditions; an update
whose CAS fails does not commit the advertised effect. For `ANY`, the
server observes presence before Admission and MUST retain that observation
through every planning retry. It guards presence, not the previous target.
Present-to-present target changes are permitted; a presence change MUST
abort the write and settle its granted ref reservation as `Aborted`, rather
than commit an effect Admission did not see. This fence does not detect an
absent-to-present-to-absent or present-to-absent-to-present cycle; the
successful batch still guarantees the admitted presence delta.

A configured non-default Admission MUST run for ticketed `AdvanceRefs` and
implicit consuming `UpdateRef`. Their ref admission has `declared_bytes = 0`,
no `pack_id`, and no `new_to_repo_bytes`; uploads retain their own byte
admission. A refusal or challenge MUST leave refs, tickets, membership, quota,
replay, and inline verification state unchanged. Custom ref Admission runs
after ticket binding and scheduled readiness checks, but before mutating
inline verification. Scheduled checks may schedule verification work and
return Pending before Admission, without allocating a ref reservation. A
ready call reaching Admission performs no such preparation writes. A granted inline reservation uses the existing
apply deadline; a failed or late proof MUST abort it. The built-in default keeps its existing skipped
paths and quota accounting, and adds no presence fence or operation charge.
Replay and existing-ticket answers continue to skip Admission.

Embedders MUST correlate resolved effects with their own reservation id and
deduplicate terminal deliveries by that id. Pack outcomes also carry ref
names; they do not constitute another ref reservation. `Aborted` has no ref
list, so the embedder retains its admitted effects until settlement.

Informative: the two newly admitted paths add one awaited hook call per
operation. A granted reservation also adds the existing pending-row atomic
unit and settlement reads/outbox work. Default Admission pays neither cost.

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
Repeated `Header` entries preserve `WWW-Authenticate` challenge order.
Servers SHOULD emit separate field lines; order-preserving combination
into a comma-separated challenge list on platforms that fold fields is
conforming under STC §5.1 and RFC 9110 §5.3. Clients and admission helpers
MUST parse these values as challenge lists (RFC 9110 §11.6.1).
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
The listed objects are indexed pack entries. The full profile includes
file objects newly reachable from previously added packs; the launch
profile uses the added-pack set specified in §11.1.
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
The optional additive `InspectRequest.scanner_retrieval = 5` carries only
the private retrieval metadata defined in §11.4; it contains no object bytes.

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
`InspectResponse.takedown_reason` is ignored on a PRE_RECEIVE
`reject`, which denies that push and MUST NOT initiate a global
takedown. On a QUARANTINE-phase `reject`, the field, when present,
MUST be a §14.6 token and becomes the notice reason; absent means
`policy`. An invalid token in that phase, or use with another verdict,
invalidates the response under §6.6.

### 6.5 Outcome

**Protocol requirement.**

`Committed` means **Sent, never Delivered**. It is the terminal result of
live apply, including when inspection or membership dependencies delay
publication. It MUST NOT later become `Aborted`. Delivery is reported by the
publication transition (§12.4), when the published prefix reaches that send.

`OutcomeRequest.outcome` contains the terminal result recorded under
§5. `OutcomeResponse` is empty; its successful Connect response
acknowledges delivery under §8.

For any configured outcome receiver, delivery runs from durable responsibility
**after commit**. Sink errors or timeouts never roll back that commit; the
refused row remains queued for retry. Delivery is at least once and **not
ordered**: later rows can overtake a refused row, which does not block the
rows behind it. Receivers deduplicate by `reservation_id` and retain the
highest per-repository `RepoStorageChanged.version` (§6.5.1).

**Reference-server behavior.** Persistent sink failure grows the outbox backlog. The core's
`OutboxBacklogCap` defaults to 100,000 rows and 64 MiB per outbox. Its
admission check refuses reservation-granting writes and admitted HTTP reads
when `rows > cap.rows || bytes > cap.bytes`; equality is still admitted.
Reservation-granting writes receive `unavailable` (HTTP 503), public message
`outbox backlog; retry`, with `Retry-After: 30`. Admitted HTTP-object reads
receive an empty HTTP 503 without that message or retry header. A real
public-to-private visibility change remains admitted above the cap;
same-value visibility requests are not exempt. This check does not undo
prior commits. Embedders should monitor `mkit_server_outbox_backlog`, with `unit=rows` and `unit=bytes`
labels per `shard_kind`, and restore the sink before the configured cap is
exceeded.

**Protocol requirement.** The shared `Outcome` fields are:

| Field | Meaning |
|---|---|
| `reservation_id` | The reservation whose result this is; the delivery idempotency key. |
| `audience` | The mkit server's canonical origin. |
| `repository` | The full repository identity as STC §7.4 requires. |
| `occurred_unix_ms` | When the outcome occurred, as signed 64-bit Unix epoch milliseconds. |
| `kind` | Exactly one of `committed`, `aborted`, `expired`, `read_served`, or `repo_storage_changed`. |
| `procedure` | Optional. The full Connect procedure path of the operation that produced the outcome (`UpdateRef`, `AdvanceRefs` including each consumed ticket's outcome, `BeginUpload` for an expired ticket, `UploadPack`, `SetRepoVisibility`, or an HTTP read). The server records it on the pending row and copies it to the terminal row, so an abandoned reservation names it too. Required for request outcomes, including expiry; absent for the `RepoStorageChanged` system event. A receiver treats an absent or unrecognized wire value as unspecified. A `SetRepoVisibility` `committed` carries no refs and zero bytes. |
| `visibility` | Optional. `public` or `private`: the visibility a `SetRepoVisibility` outcome set or attempted; present exactly when `procedure` is `SetRepoVisibility`. |

`Committed` records a successful operation:

| Field | Meaning |
|---|---|
| `bytes_stored` | The unsigned count of bytes stored by the operation. |
| `new_to_repo` | The unsigned count of pack bytes this write observed as new to the repository. An observation at acceptance; an asynchronously updated accounting projection may lag. It is not the accounting source: use `repo_storage_changed` (§6.5.1). |
| `new_to_store` | The unsigned count of bytes new to the entire store; in opaque mode, an upper bound: the declared pack bytes. |
| `refs` | The refs committed by the operation, in decision order. |

In opaque mode, `Committed.new_to_store` is an upper bound: the declared
pack bytes.

Each `CommittedRef.name` is the ref name. `CommittedRef.new` is
the 32-byte committed target, or empty when `deleted` is true.
`CommittedRef.deleted` identifies a committed deletion.

#### 6.5.1 Repository storage accounting

**Protocol requirement.**

The server keeps an exact, generic stored-bytes counter per repository of a
multi-repository deployment so an embedder can bill per owner by summing its
repositories. The basis is pack bytes: the sum of the sizes of the distinct
packs that are members of the repository. A pack shared by two repositories
counts once in each; nothing is deduplicated across repositories, and
physical garbage collection does not change the counter. Membership is never
removed, so the counter never decreases.

The repository counter MUST begin at zero with version zero when the repository
is registered. Missing authoritative accounting state MUST fail closed, never
produce a fabricated total. A pack MUST count exactly once per repository,
regardless of retries, concurrent consumption, or crashes. Consumption establishes
durable accounting responsibility even when inspection or publication is pending.
The counter MAY trail that responsibility through a durable projection, but MUST
converge to the exact distinct-member byte total. Every change increments
`version`. Physical cleanup and takedown do not reduce this membership total.

**Reference-server behavior.** The reference server keeps accounting at a
repository's registration authority. Local consumption updates it atomically;
remote consumption retains durable relay responsibility. Delivery compares a
counted-pack marker and updates the total and delivery watermark together, so
redelivery cannot count twice. Missing counter state stalls delivery rather than
losing its responsibility. Single-repository addressing retains no counter.

**Protocol requirement.**

Every counter change queues one `repo_storage_changed` outcome through the
ordinary outcome delivery (§5, §8). Its `reservation_id` is
`rs:<digest>:<version>`, unique per repository and version. `stored_bytes` is
the repository's absolute total after the change and `version` is monotonic per
repository. Delivery is at least once and MAY be out of order: a receiver
keeps the value with the highest `version` and ignores the rest. The outcome's
`procedure` is absent. Admission reservations MUST NOT use the reserved `rs:`
or `s:` prefixes.

**Reference-server behavior.** The embedding storage query returns the counter
and version after owner/grant and authorizer checks. Its batch form accepts at
most 100 repository names and preserves input order and duplicates. Missing and
unauthorized repositories return the same absence result; corrupt authorized
state remains a store error. Storage-change outcomes use reserved `rs:` ids and
the consumption plan's time, with queued delivery included in backlog telemetry.
These queries and batching limits are not public transport procedures.

**Protocol requirement.**

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
- The `s:` prefix is reserved for server-generated synthetic reservation ids;
  a hook MUST NOT return one.
- `AdmitResponse.allow.reservation_id` is REQUIRED.
- A `reservation_id` MUST be unique per server audience across all
  operations. If the server finds an existing pending record or
  terminal outcome for the returned `reservation_id`, whether for a
  different operation or for a retry of the same one, it MUST treat the
  response as invalid under §8. A hook MUST return a fresh id for each
  allowance. This uniqueness obligation lasts while the reservation row
  exists, including its pending and undelivered terminal states.
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

Every hook request, including Outcome, Event, and CachePurge delivery, MUST
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
grants, receipts, or administration (§16). Distinct roles MUST use distinct keys.
The DSSE `payloadType` `application/vnd.mkit.redaction-notice.v1+json`
is separately registered for §14.6 notices. It distinguishes those
messages from the §15 storage-receipt use of the shared receipt-and-notice
key; verifiers MUST check the exact type before interpreting a payload.

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
For remote `CachePurge`, that path is
`/mkit.server.hooks.v1.HooksService/CachePurge`.

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

Outcome, Event, and CachePurge delivery MUST retry with exponential backoff and
jitter until acknowledged. The server MUST NOT drop any of them. Any 2xx Connect
response to one of these procedures is an acknowledgement. Transport errors,
timeouts, and non-2xx responses leave the delivery awaiting
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

**Protocol requirement.**

Before an `AdvanceRefs` that consumes a pack commits, the server MUST
have verified all of the following:

- **(a) Object identity.** Every object's id agrees with its content under
  [SPEC-OBJECTS §10](SPEC-OBJECTS.md#10-storage), including the
  type-specific identity rules referenced there.
- **(b) Signatures.** Every commit, remix, and tag signature in the
  consumed packs verifies under
  [SPEC-SIGNING §3–§4a and §6](SPEC-SIGNING.md#6-verification-algorithm).
- **(c) Closure.** Every child referenced by an object in a consumed pack,
  and every advanced head, is in the consumed packs or is already a verified member of the same
  repository. A membership-dependent miss follows §9.4's lag window
  before it is a permanent `open closure` failure. Object references
  follow the corresponding object layouts in
  [SPEC-OBJECTS §4–§7](SPEC-OBJECTS.md#4-tree-0x02).
- **(d) Delta resolution.** Every delta resolves under §9.4 within the
  chain-depth limit advertised under §9.8.

An indexed server verifies (a)–(c) for every object in the packs an advance
consumes, not only objects reachable from the new tips.

An indexed server also applies (c) to a ticketless `AdvanceRefs` and to an
`UpdateRef` that is not a deletion and does not name a packmap ref: the new
head MUST be a commit, remix or tag that is a verified member of the same
repository. A miss follows §9.4's lag window, measured from the request's
signed `x-created-at` (clamped to the server's clock) because no ticket
exists, and is then the permanent `open closure` failure, byte-identical
whether or not the object exists in another repository. A capped lookup is
`object index limit exceeded`. Reconstructing the head follows §9.4's
delta-base rules. Opaque mode does not check the head. An indexed server
also requires a ticketless `AdvanceRefs` to pair `refs/heads/<x>` with
`refs/mkit/packmap/<x>`.

On the immediate path without inspectors, takedown or custom publication
verification, the server does not verify that the resulting packmap covers
the head's closure (§10.2). The publisher is responsible for coverage of
client-built pairs. Clients MUST NOT compose a branch-creation pair from
separate head and packmap reads; they SHOULD use the published-source form of
`AdvanceRefs` (STC §4) to branch from an existing published pair.

The published-source form creates both destination refs under `Missing`, in
the same repository, from one authoritative source publication row. The
server MUST bind the source ref, published head and packmap, membership
generation and publication sequence to the operation. It MUST authorize a
current source read before exposing its tip, including an expected-tip
mismatch. An absent, unpublished, unpaired or unreadable source MUST return
`not_found` with `source not found`; a readable source whose published head
differs from `expected_tip` MUST return `failed_precondition` with
`source tip changed`. Destination write authorization, ref policy, live
membership, denial, admission, quota, replay, receipts and outcomes follow
ordinary ticketless advances. The operation adds no bytes.

Before every destination acceptance attempt, the server MUST reauthorize the source and
compare its complete authoritative publication row with the captured row,
including the committed sequence and deletion boundary. A difference MUST
refuse apply (`source tip changed` when the expected-tip comparison fails;
otherwise retryable `unavailable`). A source change after this fence is
concurrent with creation: success MUST copy exactly the captured published
pair, never values selected by separate reads. This fence does not promise an atomic source-and-destination CAS. A completed replay returns its stored
advance result without selecting a new source pair.

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
| Object is absent from the permitted closure after §9.4's lag window | `open closure` |
| Delta chain exceeds the advertised cap | `delta chain too deep` |
| An object-index lookup limit is exceeded during closure or packlist checks | `object index limit exceeded` |

These are permanent failures. Clients MUST NOT retry the rejected
upload as though polling or backoff could make its content valid. The last
row is a per-lookup index cap and is also this error on the resumable
publication path.

**Reference-server behavior.** During publication verification the indexed
decode budget is charged over the whole packmap chain and reachable closure,
so it is history-scoped; it keeps its existing `invalid_argument` errors
(`object index limit exceeded` or `pack exceeds indexed decode budget` on the
canonical path, `pack exceeds indexed decode budget` on the resumable path,
whose budget is cumulative over the pair) until a separate amendment of this
input contract.

**Protocol requirement.** Running out of an
execution allowance, or of an implementation's retained-evidence capacity, is
not a verification failure of the content and is not in this table: §10.2
classifies it as `unavailable`.
An unresolved external delta base follows §9.4's distinct visibility
and replanning rules rather than being reported as an open closure.

Informative: verified repository members can supply already checked
objects for closure. This does not allow an unverified staged object
to stand in for a verified member, or permit a membership lookup in
another repository.

A verified member of the same repository MAY terminate the direct-child
integrity check without reconstructing that member's descendants again.
This permission does not waive published-membership dependencies or
resulting-pair coverage under §10.2, denial under §14.2, or configured ref
policy. Verification of every entry in the consumed packs, including entries
outside the advanced head's closure, remains required.

#### Direct-child closure edges

The direct-child integrity obligation uses the following matrix. Every consumed
object is included, even when it is not reachable from an advanced head.

| Source | Required children | Additional integrity obligation |
|---|---|---|
| Commit or remix | Tree, then every parent | None beyond child availability. |
| Tree | Every entry, preserving occurrences | Entry modes do not impose an additional child-kind refusal. |
| Tag | Target | The declared target type does not impose an additional child-kind refusal. |
| Chunked blob | Every chunk, preserving occurrences | Each child is a canonical, hash-correct Blob. Checked ordered payload sums never exceed the manifest total and the final sum equals it. |
| Blob or pack-only delta | None | Delta-base resolution is a separate obligation. |

Remix upstream source claims MUST NOT become same-repository closure edges.
Chunk occurrences count separately toward reassembled size, even when they
repeat an ID. This profile does not impose additional individual chunk lengths
from `chunk_size`. A missing child prevents successful closure; unavailable
acquisition or exhausted execution/evidence capacity MUST NOT be represented
as a complete missing set. A complete missing set includes every reached missing
ID and its reference occurrences. An unresolved child's unknown descendants
are not additional inferred missing IDs.

Verified same-repository members may terminate descent as described above.
Advanced heads still require Commit, Remix, or Tag kind. A later chunk use of
an already encountered ID still requires Blob integrity and occurrence length.
Tree/tag kind hints and gray-edge cycle detection MAY be reported as diagnostics;
they do not add content refusals to this profile. A traversal depth allowance
is an execution resource bound, with roots at depth zero. It is independent of
delta depth. The reached-ID ceiling includes verified frontier stops and permits
exactly 10,000,000 distinct IDs; exhaustion never establishes closure.

#### Local closure evidence pages

The following versioned byte contracts support retained closure evidence. They
are local algorithm evidence, not remote attestations or new transport messages.
A checksum does not authenticate a malicious host or checkpoint origin.
The caller retains pages privately until a complete result, acknowledges durable
retention before dependent progress, and reacquires pages by exact commitment.
Page loss requires replay or restart; it MUST NOT prove object absence.
Unsupported formats are rejected and verification restarts; there is no older
format reader. Reverification is the replacement for discarded local evidence.

Each page commitment carries its digest, role `Closure`, exact byte length, and
item count one. Each digest uses the SPEC-CONVENTIONS domain framing
`BLAKE3(le16(domain_length) || domain || page_bytes)`. Domains are:

- `mkit-closure-state:v1`: disposable visited-state journal pages.
- `mkit-closure-witness:v1`: relied-on repository membership observations.
- `mkit-closure-missing:v1`: complete missing-ID occurrence pages.
- `mkit-closure-heads:v1`: exact requested head sequence, with body
  `le64(count) || id[0] || ... || id[count-1]`, including duplicates.

All page integers below are little-endian. Optional values use a single byte
`0` for absent or `1` followed by the value; other tags are invalid. A page
reference is `digest[32] || le64(encoded_length)`; its role and item count are
implicit. Each page starts with version byte `1` and an optional previous-page
reference. Trailing bytes, unknown versions/tags, and invalid object kinds are
rejected. Decoders apply finite byte, item, allocation, and work allowances before
hashing or allocation. Linked pages are independently authenticated when read.

A membership record encodes, in order: repository ID `[32]`, incarnation `[32]`,
object ID `[32]`, object kind `u8`, canonical length `u64`, supplier pack ID `[32]`,
supplier length `u64`, supplier source binding `[32]`, canonical source binding
`[32]`, membership revision `[32]`, effective delta depth `u32`, published `u8`,
and held `u8`. Booleans are exactly `0` or `1`. A witness page contains one such
record after its header. Acceptance guards the exact relied-on facts and suppliers;
closure does not substitute these observations for live denial, inspection,
publication, or authorization evidence.

A state page contains, after its header: key `[32]`, object kind `u8`, canonical
length `u64`, optional verified Blob payload length `u64`, then state tag
`0` (gray), `1` (black), `2` (absent), or `3` followed by a membership record.
The member key, kind, and canonical length must match the containing state record.
An optional Blob payload length requires Blob kind and equals canonical length
minus the ten-byte canonical Blob prologue.
State pages are at most 1,024 bytes. There are 256 bucket heads, selected by the
first key byte; an update prepends a page. Lookups authenticate the newest record
for a key or exhaust that bucket chain. Only acknowledged heads are current.
Scanned records and page bytes consume cumulative work; pathological buckets
may exhaust it instead of yielding a conclusion. Resident journal metadata is
independent of the reached-ID count.

A missing page contains, after its header: missing object ID `[32]`, positive reason count
`u64`, then that many reasons. Each reason is optional source ID `[32]`, edge tag
`u8` (`0` head, `1` tree entry, `2` tree, `3` parent, `4` chunk, `5` tag target),
and occurrence ordinal `u64`. Source and edge kind are either both absent (a
head, with ordinal zero) or both present. Reasons are strictly ordered by
optional source ID, then edge tag, then ordinal; duplicates are rejected.
The final root follows links in ascending missing-ID
order, with one page per distinct ID. The complete result includes an exact count.
Empty sequences have count zero and the zero digest sentinel. Intermediate pages
or a truncated traversal MUST NOT be presented as a complete set or closure proof.

**Reference-server behavior.** The scheduled verifier may run up to eight durably checkpointed
Extract selection slices in one callback. Slices share the existing call
allowance, two-second elapsed cutoff and physical callback deadline; each keeps
its 16-step and batch-operation ceilings. Every boundary remains resumable and
repeats source and denial checks. This scheduling choice changes neither the
extraction threshold nor the conditions for Usable.

#### Local pair coverage checkpoint

A **local pair coverage checkpoint** retains an interrupted resulting-pair walk
so a scheduled verifier can resume it. Its domain is `mkit-pair-checkpoint:v1`,
checksummed with the same SPEC-CONVENTIONS framing
`BLAKE3(le16(domain_length) || domain || body)` appended as a trailing 32-byte
corruption check; the checksum is local corruption detection only and does not
authenticate the host or origin. An unsupported format version is rejected and
verification restarts. All integers are little-endian. The body is: version `u8`
`1`; repository `[32]`; view `[32]`; ruleset `u32`; profile `u8`; flags `u8`
(bit 0 head present, bit 1 packmap present, bit 2 branch, bit 3 honor-cleared,
bit 4 boundary seen; other bits invalid); head `[32]` if present; packmap `[32]`
if present; the eight limits (`u32` ×7 then `u64` work); phase `u8` (`0` chain,
`1` walk, `2` base); optional next packmap (`0`/`1` tag + `[32]`); optional base
cursor (tag + origin `[32]` + next `[32]` + depth `u32`); work used `u64`; then
counted `u32`-prefixed id lists — additions, chain, packs, visited,
dependencies, and suppliers, each sorted strictly ascending, then the queue in
walk order, disjoint from visited. Trailing bytes, unsorted or duplicate lists,
set-relation violations, and any mismatch with the expected pair, additions,
repository, view, ruleset, limits, or honor-cleared flag are rejected and the
walk restarts from the beginning.

### 9.4 Repository-isolated membership checks

A delta base MUST resolve only from an earlier entry in the same pack,
as [SPEC-PACKFILE §4](SPEC-PACKFILE.md#4-ordering-rule) requires for
in-pack resolution, or from verified members of the same repository.
A server MUST NOT resolve a base from another repository or from the
global content store.

The global blocklist in §14.2 is a denial check, not a membership or
delta-base source. Its lookup MAY deny an object in any repository, but
MUST NOT reveal whether that object is held in another repository.

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
`unavailable` with public message `repository membership not yet visible`
and exactly one `MembershipNotVisible` detail (`mkit.transport.v1`, an
empty message). The same message and detail apply to all three checks, and
the ref-policy fast-forward walk (§9.7) uses them too. The response adds
no HTTP status or `Retry-After`. This temporary response is permitted only
within that interval. A client SHOULD classify the condition by the detail;
it MAY fall back to the exact message for a server that predates the
detail. No permanent response carries the detail.

Once the consuming ticket is older than that bound, the server MUST
return the permanent error of the check that missed:

| Membership-dependent miss | Connect code | Exact public message |
|---|---|---|
| Unresolved delta base | `failed_precondition` | `delta base not available in this repository` |
| Object absent from the permitted closure | `invalid_argument` | `open closure` |
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

**Protocol requirement.** A server that verifies asynchronously MUST retain
restart-resumable progress. Verification evidence MUST remain bound to its
repository, uploaded content, and current authorization and denial facts.
Interrupted work MUST NOT expose unverified membership or lose durable recovery
responsibility. Checkpoint reuse MUST NOT waive current guards, expiry, or denial.
When denial is disabled, independent integrity, membership, and holder safety
obligations remain applicable.

**Reference-server behavior.** The reference verifier writes bounded inventory
pages with fresh business-clock plans and a ten-second backend deadline. It
guards checkpoints with their job and verification state. Entry provisional
writes precede or share the checkpoint that advances its cursor. Denial reads
precede frame and index writes in bounded waves of at most sixteen objects;
failed waves retain deterministic refusal order. Inline and scheduled paths
retain their final denial checks. Partial immutable pages stay unreachable until
staging is complete, and inventory sealing follows complete verification.

**Protocol requirement.**

Verification MAY run asynchronously after upload completion. While a
consumed pack is still unverified, `AdvanceRefs` MUST fail with
`unavailable` and exactly one `PendingVerification` detail, as
[STC §7.6](SPEC-TRANSPORT-CONNECT.md#76-upload-tickets-and-resumable-parts)
requires. This answer MUST NOT be stored as a replay result, under
STC §7.1; a retry must be able to observe verification progress.

A deployment MAY hold a pending ticketed advance before returning. The wait MUST release all attempt-local
observations and hold no lease, reservation, or guard. Its allowance MUST
end before both the request deadline and signed envelope expiry, with a
safety margin. Durable job readiness is only a wake signal: a woken request
MUST repeat the full normal advance path, including replay lookup and all
live authorization, admission, denial, CAS, and final guards. A timed-out
hold returns the original pending answer and typed hint. Cancellation adds
no durable continuation or replay result; a retry follows normal semantics.

**Reference-server behavior.** The reference implementation defaults the hold
to zero with a 2,000 ms maximum. It polls all consumed job rows in one batched
KV call every 100 ms. At the 2,000 ms cap it adds one ticket-resolution call
and at most nineteen job reads before the timeout, for twenty KV calls.
Each batch has at most seven rows. A woken attempt adds the ordinary advance
path's calls. The injected host deadline and envelope expiry leave a 250 ms
margin; less than 100 ms remaining disables the hold.

**Protocol requirement.** `PendingVerification.retry_after_ms` is the server's suggested poll
interval in milliseconds. The server SHOULD send at least 1,000, except when
bounded tiny-pack work is expected to finish sooner. For a
verification that is still progressing it SHOULD NOT send more than 5,000:
the hint is a poll interval, not a completion estimate, and a client
honours it in full up to the 60,000 clamp.
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

**Reference-server behavior.** The scheduled reference verifier answers
`PendingVerification` while a delta base is not yet a member inside the
membership lag window (§9.4), where an inline verifier answers
`repository membership not yet visible`: the pack is simply not verified
yet. The membership message applies to the closure, head and packlist
misses found when the advance checks the consumed set, and a base that is
still absent after the window is the permanent §9.4 answer, as inline.

**Reference-server behavior.** Before finalizing an early delta-base or
indexed decode-limit refusal, the scheduled verifier checks whole-source
integrity as required by SPEC-PACKFILE §§6.1 and 6.2. A corrupt trailer produces
`invalid_argument` with `object hash mismatch`, persisted as `Rejected`, just
as inline verification does. With valid integrity, the verifier retries the
failed entry using fresh membership facts. An absent base retains its lag-window
handling and non-persisted terminal result. Successful verification performs no
additional source reads.

The failure-only recheck reads at most one configured window per slice, capped
at 16 MiB and half the slice's resident allowance. Power-of-two windows are at
least 1 KiB. It checkpoints bounded BLAKE3 subtree frontiers and the trailer
under the existing job guard and source etag. No hasher memory image or
verification proof is serialized. A source change restarts the job. This
progress remains disposable and cannot publish indexes or mark a pack verified.
Successful job headers omit the optional recheck state, and the existing 16 KiB
header ceiling remains unchanged.

**Reference-server behavior.** Scheduled verification polling hints use the consumed job's
persisted timer with a 3,000 ms cap. Tiny decoded packs use a 100 ms floor and
preserve millisecond precision in the typed detail. Other phases round up to
whole seconds with a 1,000 ms floor. A missing job or a
wake not found within bounded inspection uses 1,000 ms. The HTTP Retry-After
header always rounds the detail up to whole seconds; neither value promises
completion. Clients retain STC's one-second polling clamp.

**Reference-server behavior.** Consecutive slices for one to three entries and at most 16 KiB of encoded and
decoded data, or canonical packlists of at most 256 bytes, MAY share one
handler's existing call allowance. Each intermediate
checkpoint MUST commit before the next slice begins, retaining durable recovery
work. The implementation caps consecutive slices at eight and checks a two-second
elapsed cutoff and the enclosing physical tick's deadline before starting
another slice. Extraction work and larger groups
retain their scheduled boundaries. A tiny AwaitDelivery checkpoint MAY trigger
one bounded discovery of its small source outbox through the registered relay
handler, under the same physical alarm limits. Target delivery, source cleanup,
and guarded wakeups retain their existing ordering and idempotence. Verification
still waits for required relay delivery before writing Verified.

**Reference-server behavior.** The scheduled implementation may run several Extract selection
steps within one bounded slice and guarded checkpoint, with a fixed 16-step
ceiling independent of the Worker clock. It may also decode a staged,
local, non-delta member frame in the call that consults its staged row
and walk several chunks per PREFLIGHT or UPLOAD slice under the same
ceilings. Staged non-delta frames in one pack may share a slice-local,
etag-bound transport window, capped at 4 MiB plus 240 bytes of canonical
and pack framing, or the configured window limit when smaller. Frames
outside that buffer retain the per-frame read path. Every chunk still
undergoes the same hash, size, and identity verification. When denial is
enabled, each chunk's own denial read stays per chunk while each source
pack's denial is read once per slice, after its last chunk and before the
part upload and the checkpoint commit. An external effect still
starts in a later slice. On entering the index-delivery wait, it checks after
300 ms and then once per second until delivery; the client-facing poll hint
still has its one-second floor.

**Protocol requirement.** Verification state is per `(repository, pack)`. A pack verified for
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

The fast-forward-only policy is checked at pre-receive (§2 stage 5),
after verification in indexed mode. The allowed-signer set needs no
verified content, so a server MAY check it earlier, before verification
and at `BeginUpload` (whose ticket is bound to the ref and the signer), and
the result MUST be the same. A policy violation MUST fail with
`permission_denied` and the corresponding public message:

| Policy violated | Public message |
|---|---|
| Allowed-signer set | `signer not allowed for this ref` |
| Fast-forward-only | `non-fast-forward update not allowed on this ref` |

The allowed-signer set applies in both modes to the authenticated
operation signer. Valid signatures on reachable commits do not
independently authorize that signer to move the ref. Grant and
namespace authorization remain subject to STC and SPEC-WRITE-GRANTS.

Every matching rule applies: allowed-signer sets of overlapping patterns
intersect, and any matching fast-forward-only rule binds. A matching
allowed-signer set with no auth v2 signer (a bearer, ssh or enc identity,
or none) denies. The namespace owner and authority-approved writers are
not exempt from either policy. Patterns never name a packmap ref
(SPEC-WRITE-GRANTS §3.3); a packmap ref is covered through its head
([SPEC-WRITE-GRANTS §8.3](SPEC-WRITE-GRANTS.md#83-packmap-coverage)), so an
allowed-signer set on `refs/heads/<x>` also governs `refs/mkit/packmap/<x>`,
and fast-forward-only is evaluated on the head alone.

Fast-forward-only requires indexed mode because the server needs the
commit graph. An opaque-mode deployment MUST refuse to start with a
fast-forward-only rule configured.

**Ancestry.** A new value descends from the current value when it equals
it or reaches it through the `parents` of commits and remixes; a remix's
`sources` are never followed, and a tag is a descendant only of itself.
The check reads only this repository's verified membership and the
objects staged by the advance (§9.4), never another repository or the
global content store. A deployment bounds the member commits one check
reads and the bytes it decodes. A check that cannot prove the ancestry
within those bounds fails closed as the policy's `permission_denied`. A
membership-dependent miss inside §9.4's lag window, with no other path to
the current value, is the retryable `unavailable`
`repository membership not yet visible` with its `MembershipNotVisible`
detail (§9.4) and is not stored; after the
window it is the policy denial. The window runs from the creation of the earliest consumed
ticket, or from the signed `x-created-at` (clamped to now)
when the write consumes no ticket. `REF_EXPECTATION_ANY` on a present
fast-forward-only ref is checked against the value the server observed and
commits as `MATCH` on that value; `MISSING` and `ANY` on an absent ref
create. The same check proves a `u`-only `MATCH`
([SPEC-WRITE-GRANTS §8.2](SPEC-WRITE-GRANTS.md#82-flags-per-change)) in
indexed mode; failing it is that grant's `write grant rejected: ref scope`.

Deletion of a fast-forward-only ref, including the deletion operations
in STC §7.8, MUST be refused with the same `permission_denied` and
`non-fast-forward update not allowed on this ref` message.

These are generic pre-receive policies. Attestation predicates,
attestation carriage, and attestation-gated refs are outside this
contract (D33).

### 9.8 Limits advertised

**Protocol requirement.**

`GetServerInfo.max_pack_bytes` is the effective accepted pack-size
limit in the deployment's mode, as STC §2.1 requires. An indexed
deployment MAY advertise a lower limit than an opaque deployment.
Clients plan uploads against the advertised effective value.

`GetServerInfo.max_delta_chain_depth` is the delta-chain depth cap.
A chain deeper than the advertised cap fails under §9.3, even if all its
bases are visible in the repository.

**Reference-server behavior.** The indexed default is 50.

The reference server resolves member chains with iterative descent and reverse
reconstruction. It retains at most the configured number of pending delta
metadata entries, plus one active member; call-stack use does not grow with
chain depth. Encoded frames and canonical bytes remain subject to the existing
source and decode budgets. This implementation preserves the checks, charging
order, and concurrent raw-member prefix/frame reads described above. Scheduled
extraction boxes each serial stage future to bound the storage carried through
enclosing slice futures, leaving stack space for frame decoding. This changes
neither the durable cursor nor the check and charging order.

**Protocol requirement.** When indexed mode is off, the server MUST advertise
`max_delta_chain_depth = 0`. That value indicates that the indexed
verification cap is inapplicable; it does not enable indexed validation
in an opaque deployment.

The pack-size and chain-depth limits are distinct. A pack below the
size limit can still exceed the chain-depth cap. Neither limit changes
repository-isolated resolution or permits global-existence disclosure.

An indexed advance that exceeds either pack limit fails with the exact
response below:

| Limit exceeded | Connect code | Exact public message |
|---|---|---|
| Indexed pack size | `invalid_argument` | `pack exceeds indexed max_pack_bytes` |
| Indexed decode budget | `invalid_argument` | `pack exceeds indexed decode budget` |

**Reference-server behavior.** Indexed canonical entries MUST NOT exceed 1,048,586 bytes, including object
framing. An oversized entry is refused at indexed verification with the
`invalid_argument` decode-limit message above; this limit and its refusal are
unchanged. Very large trees and chunk manifests can exceed it, so clients
should split very large flat directories into smaller subdirectories.

### 9.9 Fork

**Protocol requirement.** A server in indexed mode with multi-repository
addressing MAY offer a server-side fork. A fork inherits the current published
head `T` and paired packmap head `M` of one source branch into an empty
destination's membership, without creating a destination ref. The inherited
pack set contains the complete packmap chain, its listed packs, and the packs
that transitively supply their external delta bases. Packs are inherited whole,
including entries outside the closure of `T`.

A server that offers fork MUST build destination membership as staged state.
It MUST record guarded acceptance, including the terminal result, saved replay
result, and terminal outcome responsibility, in one atomic unit. Acceptance
MUST compare the recorded authority facts on which the operation relied. A
server that also offers authority fencing MUST compare those recorded facts
both at acceptance and at every commit that advances the fork. Stale authority
facts MUST prevent that commit; authority-generation mismatch has the
`permission_denied` class under §6.2.1.

The destination's staged membership MUST NOT become reader-visible, and the
server MUST NOT accept destination writes, before guarded acceptance. A failed
fork's destination MUST remain inert: retained construction state does not
authorize reads or writes. Making accepted fork membership reader-visible is
its published clearance. Neither construction nor clearance creates a ref.
A completed replay MUST return the saved result without repeating acceptance,
charges, outcome creation, or construction effects (§3.2).

**Protocol requirement.** For acceptance, the server MUST obtain a final source
proof after the last destination membership effect has been staged and before
the acceptance commits. That proof MUST establish that the source still
publishes the exact admitted head/packmap pair and membership generation, and
that every inherited pack remains published, readable by the forking principal,
and not denied. A proof obtained before the last staged membership effect is
insufficient.

The fork is ordered at that proof. A source move, unpublication, visibility
change, or denial committed before the proof MUST refuse the fork with the uniform missing-source answer:
`not_found` and `source not found`. A source change committed after the proof
is ordered after the fork and MUST NOT invalidate its acceptance. The source
proof and destination acceptance cannot be one atomic decision across
independent owners; this requirement bounds that consistency window at the
proof. It does not prescribe the owners' storage layout or construction method.

**Protocol requirement.** The source read MUST be authorized before revealing
its published tip or a tip mismatch. An absent, unreadable, unpublished, blocked,
superseded, or otherwise ineligible source MUST answer uniformly with
`not_found` and `source not found`. A readable source whose tip differs from
`expected_tip` MUST answer `failed_precondition` and `source tip changed`.
A capacity refusal MAY answer `resource_exhausted` and `fork too large` only
after source-read authorization. The destination MUST be unregistered, with no
refs or members, or belong to the same fork binding; otherwise the answer is
`failed_precondition` and `destination not empty`.

Destination write authorization MUST receive a consistent observation of the
source visibility and visibility revision. The server MUST revalidate that
observation after authorization and admission and before starting construction;
a change MUST answer `not_found` and `source not found`, releasing the
reservation. The initial authorized `expected_tip` mismatch above remains
distinct from a source change after admission. The authorization profile decides
whether source and destination visibility may differ. The requested destination visibility MUST agree with
any prior owner declaration for that name.

Admission MUST see the inherited byte charge in both `declared_bytes` and
`new_to_repo_bytes`. Quota charges MUST apply at most once within one admitted
construction attempt. Resuming a durably retained attempt for the same binding
MUST NOT charge again, and a separately granted joining reservation MUST
terminate as a replay race. A fork MUST NOT inherit more bytes than admission
permitted. A server MAY discard a definitely failed attempt that has established
neither an accepted destination nor a saved terminal fork result. A later request
for the same binding then begins a new admitted attempt and MAY charge again;
it is not a replay or continuation of the discarded attempt. Construction MUST
retain durable recovery responsibility and MUST NOT outlive its reservation without a
terminal disposition. An externally settled reservation MUST prevent further
construction and acceptance.

A pending fork answers `unavailable` and `fork in progress` with a `Retry-After`
hint. Both the original signed identity and a fresh signed request for the same
binding may resume it. A retained terminal failure MUST be replayed. Retrying a
discarded definitely failed attempt follows the new-admission exception above.
A completed result identifies the source, branch, tip, source publication sequence, packmap head,
pack count and bytes, copied index-entry count, sorted-pack-id digest, and
destination membership generation.

The fork MUST preserve repository isolation, immutable-object verification,
current denial, and complete takedown discovery for inherited members. It MAY
reuse structural evidence already established by the source, but that evidence
MUST NOT waive current denial or published-membership dependencies. Reused
evidence MUST remain bound to the inherited packmap chain and packs; removing
that binding requires fresh evidence. Inherited objects do not undergo a new
signer, ref-policy, or inspection decision. Later source changes do not alter
an accepted destination.

**Reference-server behavior.** The reference server currently exposes fork
through an embedding API rather than a Connect route. Its canonical signed
body has five LF-separated lines without a final LF: `mkit-fork:v1`, the source
repository, branch, 64-lowercase-hex expected tip, and `public` or `private`.
The auth-v2 procedure is `/mkit.server.v1/ForkRepo`; the body commitment binds
exactly those canonical bytes, and grants do not authorize it.
Its embedding dispatch authenticates, checks deployment compatibility, resolves
completed replay evidence, and then runs the embedding server's dispatch policy.
The public embedding guide and crate documentation define this API.

The reference fork driver lowers coordinator progress, accepted membership
activation, and final clearance through pure `mkit-primitives::fork` decisions.
The host retains proof acquisition, routing, atomic comparison, budgets, and
scheduling. These in-memory decisions add no wire or stored format. Their
required snapshots do not replace physical authority permissions or the final
source proof required above.

The reference implementation uses bounded resumable preparation with a 24-hour
construction lifetime. Registration installs a destination write barrier;
preparation copies indexes and holder evidence and stages the complete pack list
without installing membership. Guarded acceptance saves the result, replay and
terminal reservation responsibility together. Activation installs only accepted
membership and removes the write barrier when complete; registered failures
remain inert, while accepted work remains resumable without re-settlement.
Its limits remain 1,024 packs, 16,384 index rows, 8,000 working-set ids, 2,048
unresolved external-base ids (1,800 per pack), and 262,144 scanned source index
rows, with 600-call slices and bounded concurrent waves. These are reference
limits, not protocol limits; see the [operator guide](../operations/fork-waves.md).

The reference source proof captures exact source pair/policy observations and
monotonic eligibility versions before the complete inherited-pack proof pass,
then validates all captures after that pass. The capture includes source indexes,
the denial directory, and content-state versions for every registered subject.
This provides a coherent source point across resumed slices; changes refuse
uniformly as a missing source. A custom publication policy supplies a coherent,
non-repeating fork-eligibility version; its default refuses unaccepted forks.
Activation uses the retained accepted result and repeats current destination
denial checks; later source changes do not alter that result.

Every advancing coordinator commit compares recorded authority observations.
Physical activation compares a bound local permit, or direct authority guards
when colocated. Authority and epoch transitions freeze issuance and durably
invalidate registered local permits before publishing and acknowledging a move.
Index and directory mutation stamps use a backend-atomic checked increment in
existing write batches, without another ordinary-write storage round trip.
These are reference mechanisms, not additional protocol requirements.

When denial is enabled, the reference server retains a cleared structural set
and external-base evidence. Its witness flag enables later structural reuse;
current denial still applies. Without denial it omits that set, so a later
activation performs a fresh structural walk. Its `MAX_ADVANCE_ITEMS` limit of
4,096 can refuse that walk. Operators must follow the
[activation runbook](../operations/fork-waves.md#enabling-takedown-denial-after-running-with-it-off).

**Reference-server conformance evidence.** The destination gate, advancing fence,
and final source proof have reference implementations. Their implementation does
not itself certify conformance; the Tier-2 runner reports exercised assertions,
remaining declared skips, and failures separately.

## 10. Published view

### 10.1 Caller's view

**Protocol requirement.**

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

**Reference-server behavior.** Server-side object-reader embedders MAY share an additive per-session ledger
across calls. The ledger bounds storage call units, canonical decode work,
encoded pack-range reservations and canonical output bytes, including duplicate
outputs. Failed work MUST NOT refund consumed allowances. Read-path cap hits
MUST use `resource_exhausted` and the public message `object reader limit exceeded`,
except that IDs whose public reachability cannot be proved within the walk or
decode caps MUST remain uniformly absent (SPEC-HTTP-OBJECTS §4). Storage failures
remain `unavailable`. Existing per-call allowances and invocation call budgets
remain applicable. This embedding API does not change HTTP error mappings.

Embedders MAY opt into canonical/metadata batches of up to 45 ids; the default
is 16. This MUST NOT raise storage, row, byte, decode or output allowances or
change the 16-target URL issuance cap.

**Protocol requirement.** An operation MAY reuse verified locations and sealed inventory across its denial
and metadata consumers. Inventory batches MUST validate completion, entry digest,
type/length facts and reconstruction dependencies. Repeated target/pack denial
reads MAY be coalesced within one decision; final disclosure checks MUST
start fresh after independently loaded objects complete. A strongly empty denial
directory MUST NOT be cached across calls. Final access gates and external-base
membership/denial remain mandatory.

Informative: independent backend reads can run in bounded, prepaid waves while
results retain their original refusal order. Unknown or insufficient allowance
can retain serial admission. Continuation activation writes retain their
ordered boundary; the closing guarded apply remains the
validation cut before its pure closing reads.

**Reference-server behavior.** Independent reader I/O MAY run concurrently with one shared concurrency, transient
row and byte admission envelope across scans, membership groups and object loads.
Every wave MUST reserve page, row, byte and call allowances before dispatch, drain
all dispatched replies on failure, and process replies deterministically. Served
scan-prefix cursors, rotations and first-member pack ordering MUST remain intact.
Prepaid credits MUST belong to the dispatched wave and its inherited ledgers;
unrelated work or cancellation of another wave MUST NOT consume them.
Cancellation MUST release in-flight admission while retaining charged reservations.
Raw-load waves MUST NOT multiply the single-member transient payload allowance:
their combined encoded frames and canonical results MUST fit that allowance.
Retained earlier results remain subject to batch/output bounds; synchronous
decoder scratch and canonical conversion overlap only one member at a time.

**Protocol requirement.** A reader session MAY also retain bounded structural reachability proofs. These
MUST be privately bound to its reader/backend, full repository identity, view
and verified credential scope. A context change MUST discard proofs without
resetting allowances. Roots are captured during initialization, not at an atomic
repository-wide timestamp. Observing new commits before proof expiry requires a
new session. Root generations and derived proofs MUST expire within the configured
reachability lag and the request deadline. Hits and child expansion MUST NOT extend
that expiry. After reachability-lag expiry, the next batch captures fresh roots
without resetting allowances or the request deadline.

Only verified canonical decoding through the same repository/view may add local
history edges: commit/remix trees and parents, tree entries, tag targets and
manifest chunks. Foreign remix sources and reconstruction bases are not edges.
Queued objects and metadata MUST NOT establish child proofs. Expansion MUST
check the current stop predicate and reserve bounded edge/memo space before
allocation, declining memoization when it cannot fit. Reused proofs MUST retain
or revalidate stop-sensitive ancestry, including blocked/tombstoned manifests.

Structural evidence does not cache authorization, visibility, grant epochs,
member availability or takedown clearance. Every batch MUST retain the existing
live target, pack, dependency and gate checks, including metadata dependency
checks and uniform absence at proof caps. Writer proofs MUST NOT enter the shared
published reachability cache. Except for the authenticated continuation contract
below, session proofs MUST NOT survive the request or
broaden URL-token scope; URL issuance keeps its published-view preflight.

Selected-ref reader primitives MAY discover old commits using parent-directed
history, without descending into snapshot trees or file bodies. The traversal
mode MUST explicitly choose first-parent or all-parent history; all-parent
order is breadth-first in decoded parent order, with duplicate suppression.
Commit visits, queued merge frontier and tip-tag peeling MUST have independent
bounds. A cap MUST NOT silently switch traversal modes or emit a partial page.
Each helper captures one selected ref strongly in the authorized caller view;
this capture replaces session structural evidence without resetting any ledger
or extending its request deadline. It MUST NOT narrow the root set searched by
a subsequent general-ID fallback on an unscoped reader; that fallback retains
full ref discovery.
Tags MUST match their declared target kind.
A start commit is inclusive and skipped ancestors count toward the visit bound.
These primitives issue no continuation authority and persist no graph state.
The complete helper MUST share the existing per-call canonical decode allowance
across all nodes and reconstruction bases, in addition to its session ledger.
Ref capture, node loading and retained page/witness checks MUST share the same
I/O admission envelope. Denial proofs MAY consume the actual verified source
locations and sealed inventory without locating those targets again. Final
authorization and proof revalidation MUST precede the live inventory/descriptor
checks. Source guards MUST then start fresh after that work and all callbacks;
inventory facts MUST NOT establish additional traversal edges.

Selected-ref reader sessions MUST be explicitly opt-in. Selecting a ref narrows
only session canonical and metadata reads on that reader. The
session's root capture MUST read only the selected ref through the
authoritative anchor — the owner view's live ref, the public view's published
head — where a missing or empty publication ledger is uniformly absent, and
MUST capture the security digest after visibility-revision activation. The
retained checkpoint MUST be immutable: the selected ref, the raw publication
and ref values, the full publication, the security digest, the expiry and the
capture's identity generation. Selected sessions MUST NOT fall back to
all-ref root discovery, and MUST prove targets before locating them in either
view. Every proof reset, expiry, reader rebind or helper capture MUST
invalidate the checkpoint. Parent and tag-target history roles and decoded
commit/remix kind and timestamp MAY be recorded only while a checkpoint is
valid; they are structural evidence, never permission. Non-session reads and
URL issuance MUST keep the unscoped contract. This introduces no
stored-format change; activation reuses the existing visibility-revision
record.

Commit/path reader primitives MUST first prove the selected commit through
parents, then walk only the path trees. Components are exact decoded name bytes;
no case folding, Unicode normalization or symlink following is permitted. Empty
paths select the root tree. Intermediate entries MUST have tree mode and decode
as trees; leaf kind MUST agree with its entry mode. Symlink leaves return their
canonical blob and chunked-file leaves their canonical manifest, not logical
chunk bodies. An optional expected leaf ID mismatch MUST be uniformly absent
before loading that different leaf. Path depth has a separate hard bound.
An optional canonical path witness MAY return the commit and ancestor trees for
local inclusion proof construction. Those bytes MUST be charged as output and
all returned sources MUST be rechecked together before output. This witness is
acquisition data, never reusable authorization or continuation evidence.

All directed loads MUST use existing same-view membership, canonical hash checks,
source reconstruction and dependency rules. Only selected canonical local edges
may add evidence; inventory facts, foreign remix sources and delta bases MUST
NOT establish history/path edges. Live authority, ancestry stops, target/pack
and strong-denial checks precede edge use/output, including after body I/O and at
page boundaries. Public missing, orphan and discovery-cap results MUST remain
uniformly absent; owner caps remain typed and storage faults remain unavailable.
Output allowances MUST be reserved before copying the complete page or path
result, including any requested witness.
This additive embedding surface does not alter URL grammar or HTTP serving.

#### Authenticated history continuations

**Protocol requirement.** A server MAY offer authenticated selected-ref history
continuations across requests. A continuation MUST authenticate its scope and
history position, and MUST NOT confer permission. Its scope MUST distinguish
the backend, full repository identity, selected ref, reader or writer view, and
verified credential scope. An audience, signer, grant, or bound credential-header
change MUST invalidate it. A fresh request nonce or signature-verification time
alone MUST NOT change that credential scope.

Each redemption MUST authenticate current credentials and repeat applicable
visibility, authority, grant, membership, reconstruction, denial, and ancestry
checks before disclosing history. Earlier success MUST NOT cache authorization
or denial clearance. A public continuation MUST anchor to the authoritative
published value. Continuation evidence MUST NOT authorize an unrelated operation.
Authentication material used for continuations MUST remain independent of the
other configured key roles. A retired continuation key MUST NOT validate a token.
These requirements do not select an authentication algorithm or key-storage API.

A continuation MUST bind the selected ref and its authoritative publication
state, including sequence, deletion boundary, membership generation, and
published value. Redemption MUST atomically validate the bound ref and
publication state against authoritative state, together with the fixed expiry.
An observation of multiple values alone MUST NOT be assumed atomic. Missing or
incomplete authoritative evidence MUST fail closed. Ref append, rewind,
deletion/recreation, replacement, publication/incarnation changes, and intervening
visibility changes MUST invalidate the continuation even when values later
return to the same hash or visibility. Delayed projections MUST NOT restore
invalidated evidence. A ref change after successful atomic validation is
concurrent with that redemption and invalidates subsequent redemptions.

The server MUST preserve the requested traversal and canonical page order.
First-parent paging MUST remain distinct from all-parent traversal. Continuing a
timestamp-discovery walk MUST preserve the ordering semantics of
[SPEC-HISTORY-ORDER](SPEC-HISTORY-ORDER.md), including pending history and its
ordering keys. Evidence used to continue the walk MUST establish the selected
history's lineage, object kinds, and applicable timestamps. A disagreement with
verified history MUST refuse the page; imported state MUST NOT silently change
the requested order. Every returned object retains current source, integrity,
membership, reconstruction-dependency, authorization, and denial checks.

A continuation MUST have a fixed expiry bounded by the configured token lifetime
and any applicable write-grant expiry. Successors and replay MUST retain that
original expiry. Each page MUST carry a currently valid request envelope when
required; the issuing envelope's expiry and request-local proof lifetime MUST
NOT limit the continuation's own lifetime. Each redemption's evidence remains
subject to its own request deadline, permitted freshness interval, and token
expiry. Expiry reached during redemption MUST refuse disclosure. Redeeming a
token MUST NOT extend its expiry or a request deadline.

Invalid authenticity, scope, anchor, publication boundary, expiry, retired key,
or inaccessible state MUST return uniform absence in either view without
revealing cursor membership. Storage failures and resource refusals retain their
applicable classifications. Token values MUST NOT be logged or placed in URLs or headers;
they travel in request and response bodies. Request-body limits MUST be enforced
on received data rather than relying on a declared Content-Length.

A caller MAY replay a continuation within its scope and fixed expiry, including
to recover a lost response. The same token and page parameters MUST return the
same canonical page when every current check still permits it. Each redemption
MUST repeat those checks. The caller restarts at the selected ref when the token
expires or its bound anchor, credentials, or authority changes.

**Reference-server behavior.** The remainder of this subsection describes the
reference embedding API and its private continuation implementation. Other
conforming servers may use different token formats, cryptographic mechanisms,
storage, evidence retention, and validation operations while preserving the
observable requirements above.

See the [Workers embedding guide](../embedding/workers.md#one-reader-and-one-session-per-request)
for request composition and the [history paging measurements](../operations/history-paging.md)
for bounded fixture results.

As an explicit exception to request-local structural evidence, a server MAY
authenticate a selected-ref history cursor across requests. The continuation
MUST NOT confer permission. First-parent paging MUST remain distinct from
all-parent traversal; it MUST NOT silently narrow an all-parent log. A
continuation of an all-parent timestamp-discovery walk
([SPEC-HISTORY-ORDER](SPEC-HISTORY-ORDER.md)) MUST retain its sealed ordering
state in the token.

The reference embedding API exposes
`walk_history_page_in` and `walk_history_page_with_options_in`; selected-ref
sessions use `with_selected_ref`. Its opaque version-2 tokens use the following
private format, which other servers need not expose.

Version 2 is `<base64url(binary claims)>.<base64url(32-byte MAC)>`, with strict
unpadded encoding and a MAC string of exactly 43 characters. Claims are a
fixed-order little-endian encoding: version `0x02`; order (`0x00` first-parent,
`0x01` timestamp-discovery); purpose `mkit-history-continuation:v2`; backend
realm; full namespace/repository; selected ref; writer/public view; stable
verified principal/credential digest; strict anchor ID; the full authoritative
publication record (sequence, published prefix, deletion boundary, membership
generation and published pair) as its `Publication::encode` bytes; live
security digest; issuance time; original absolute expiry; an ordered witness
of 1–1,024 history nodes (each an ID plus a predecessor index: index 0 MUST be
the unique root, every other node's predecessor MUST name an earlier index,
and IDs MUST be unique); and, for timestamp-discovery only, the verbatim
SPEC-HISTORY-ORDER snapshot of the sealed reducer. A first-parent witness is a
linear chain and the last node is the cursor. Decoding rejects truncation,
trailing bytes, an unknown order, an empty or oversized witness, duplicate
witness IDs, a missing or misplaced root, forward predecessors, a malformed
snapshot, an unsealed or outstanding-selected reducer, and any pending ID
absent from the witness.

The credential digest includes the trusted auth audience, signer, grant and captured credential headers;
it excludes envelope nonce, fingerprint and verification time so a fresh signed
request can continue the same credential scope. The security digest binds the
repository record, visibility row including change time, monotonic visibility
revision, grant epoch, authority generation and deployment default visibility.
A first paging request activates the retained revision before capturing security
evidence. Once activated, every committed visibility write MUST increment it
atomically under its observed-value guard, even for a writer that does not issue
continuations; it MUST NOT reset on deletion/recreation. This
fences a public/private/public return even within one clock millisecond. Digests frame each component's
length to avoid concatenation ambiguity.

The reference MAC is keyed BLAKE3 with a key
derived using that exact purpose as its domain.

The source secret MUST be independent of URL, upload, scanner, hook, receipt,
authority, admin and client/owner keys. Reuse the deployment secret-management
pattern of URL tokens: dedicated secret binding/key file, zeroized owned source,
redacted diagnostics, and explicit key replacement. This MAC is symmetric:
there are no retained public verification keys. Rotation/retirement immediately
invalidates outstanding tokens. Deployment realms MUST distinguish backends
even when their repository names and auth audiences coincide.

MAC, format, expiry and stateless scope checks MUST precede sensitive reads.

Reference token parsing is bounded to a 65,536-byte decoded payload, an 87,426-byte token,
1,024 witness nodes, and the SPEC-HISTORY-ORDER §4 reducer bounds (256 pending
slots, 192 emitted IDs). Version 1 JSON claims are rejected at every deployment
boundary; a caller holding one restarts paging at the selected ref.

The token's order MUST equal the requested order
before any sensitive read. The server MUST authenticate current credentials and recheck visibility, epoch, grants and
authorizer before importing evidence. It MUST strongly read the selected ref
and authoritative publication fence, and compare them again at the closing
boundary. A write-free guarded apply defines the strict-ref validation cut:
it compares both the original publication record and live ref bytes and
checks the fixed expiry on the backend clock. It allocates no paging state.
The server MUST NOT assume that a multi-key read is atomic. Closing
security/anchor reads MAY reject subsequently observed changes, then live
object validation MUST complete immediately before disclosure, with no
intervening work that could stale its authorization or denial evidence.
Independent stores and hooks do not provide a simultaneous snapshot. Ref
changes after the validation cut are concurrent with that redemption and
invalidate later redemption of either the original token or its successor.
Public anchors use the authoritative published value, not an index projection.
A missing ledger or partial capture MUST NOT issue or redeem evidence.
Append, rewind, deletion/recreation, replacement and publication/incarnation
changes invalidate the continuation even when the ref returns to the same hash.
Delayed projections MUST NOT reinstate an invalidated continuation.

Issuance is memo-only. The caller seeds the walk at the selected tip peeled
through any tags to its commit/remix; the checkpoint keeps the unpeeled
anchor. Issuance revalidates the retained capture checkpoint &mdash; credential,
selected ref, anchor, security, and expiry &mdash; against
live state, and validates the caller's sealed walk against session evidence
alone. Every pending or emitted ID MUST be recorded in the session
memo on the selected ref: an emitted ID must be a proven commit/remix with its
decoded timestamp, and a pending ID must hold a recorded history edge whose
decoded timestamp, when known, supplies the reducer key. An outstanding selected candidate, an unsealed
walk, a pending ID that is off-ref or never read, an emitted ID that is not a
proven history object, or a supplied key that disagrees with the recorded
timestamp refuses issuance as uniform absence; invalid reader or walk state is
invalid input. The witness proves the pending IDs' lineage back to the
checkpoint tip; emitted IDs are not carried.

A timestamp-discovery redemption restores the sealed snapshot and emits the
next page in canonical order. Pending IDs whose priority keys the token does
not carry MUST obtain those keys before output selection; a key the token
carries MUST be rechecked against the live object at emission, and any disagreement refuses the page — carried state is
never reordered or amended. History state caps are explicit rather than
absent: frontier or emitted-set overflow, oversized witness and oversized
payload each report a typed history-state limit in both public and owner views.
A redemption NEVER extends expiry, mints no records, and pages a token it can
replay.

Tokens travel only inside request and response bodies — never in URL query
strings or headers — and MUST NOT be logged. The host enforces its separately
streamed request-body cap rather than trusting Content-Length alone.

Successors MUST inherit the original expiry. Initial expiry is bounded by the
configured token TTL and, when present, the write-grant expiry. The issuing
request envelope's expiry MUST NOT cap the token lifetime: every authenticated
page MUST supply a currently valid signed request envelope and repeat live
authorization and credential-scope checks. The request-local proof lag
and deadline MUST NOT cap the token's lifetime. Each page's own proofs MUST
still expire within its reachability lag, request deadline and token expiry.
Imported proofs MUST be confined to the paging operation and discarded on
success, failure or cancellation, preserving spent allowances and the original
request deadline; they MUST NOT authorize a later shared-session operation.
Expiry reached during redemption MUST also return uniform absence.
Every returned object retains current membership, actual source, reconstruction
dependencies, denial and authorizer checks. Custom ancestry descent stops MUST
be rechecked; neither empty denial results nor permission are carried in claims.
Invalid scope, MAC, anchor, boundary, expiry, retired key and inaccessible state
MUST return uniform absence for either view, without probing cursor membership.
Storage faults and owner resource exhaustion retain their existing classifications.

Reference issuance uses
`issue_history_continuation_in` and performs no object or storage proof calls;
it bounds supplied-ID memo lookups to 448 and witness traversals to 1,024.
Redemption hydrates pending keys within a six-call read envelope and reports
`HistoryStateLimit` for retained-state capacity exhaustion.

A caller MAY replay a continuation within its scope and fixed expiry, including
to retry a lost response. The same token and page parameters serve the same
canonical page when every live check still permits it. Each redemption MUST
repeat those checks; a previous success MUST NOT cache authority or denial.
History continuations allocate no replay or expiry records. Successors retain
the original expiry, including after replay. A caller restarts at the selected
ref when the token expires or its bound anchor or authority changes.

> **Informative: credential headers and continuation lifetime.** On a signed
> history read, the captured credential headers are part of a token's credential
> binding, both names and values: `Payment-Authorization`, `PAYMENT-SIGNATURE`
> and `Authorization`, plus the deployment's configured admission credential
> headers (a deployment-wide setting that only adds to the three built-in names). Capture records them before any admission judgment, so a header
> that admission would later ignore (for example a non-Payment `Authorization`)
> is still bound. A value that changes between pages, such as a renewed
> `Authorization`, `Payment-Authorization` or `PAYMENT-SIGNATURE` credential, changes the digest and ends the
> continuation: the next page is uniform absence and the client restarts from a
> fresh first page. Capture applies to every signed read under auth v2 and cannot be disabled
> per read, so integrators should keep these headers stable for a whole walk,
> or not send them on history reads; configuring no extra admission credential
> headers removes only the extras. An anonymous reader
> carries no credential digest. The token's fixed lifetime is the minimum of the
> token TTL and, when present, the write-grant expiry; successors never extend
> it, and each page still requires a fresh signed request and re-authorizes.

### 10.2 Per-ref clearance and publication

**Protocol requirement.**

Acceptance MAY precede reader-visible publication. A server deferring
publication MUST preserve the accepted decision and its durable recovery
responsibility while clearance remains outstanding. Acceptance and clearance
are distinct decisions, even when they commit together under this section.

Each ref MUST have an ordered advance sequence. The branch head
`refs/heads/<x>` and `refs/mkit/packmap/<x>` share one sequence: every
successful `AdvanceRefs`, head-only `UpdateRef`, or packmap-only
`UpdateRef` appends an advance to that sequence. Sequence numbers start
at `1`; `0` selects the latest committed advance in STC §2.2. The sequence MUST
NOT reset on ref deletion, recreation, or repository-level deletion.
The advance value is the live (head, packmap) pair, and the pair MUST
be published together.
Other refs have their own sequences and target values. Failed writes do
not append advances. In indexed mode with an inspector configured, a
head-only `UpdateRef` MUST verify before apply that its unchanged packmap
reconstructs the new head's closure; a packmap-only `UpdateRef` MUST
verify the resulting pair too (§9.3; STC §4 defines the paired advance).
The inspector-specific pair check is not imposed on the immediate path in
opaque mode or without inspectors, where the published view equals the live
view. Configured takedown or custom-policy verification and delayed
dependency publication still retain their applicable rules, including pair
coverage and published-membership dependencies.

An exact copy of a source's published pair introduces no new pair
inconsistency: on the immediate path its destination coverage is exactly
the source's. The published-source form of `AdvanceRefs` MUST NOT add a
pair-coverage walk on that path. Existing published pairs are not universally
coverage-verified. Where inspectors, takedown or custom publication
verification are configured, the destination retains the normal publication
checks in this section, including coverage and their existing limits.

Evidence computed against a publication state MUST be bound to that state. The
server MUST compare the publication state (its membership generation, sequence
and deletion boundary; the published prefix and value are re-derived at apply
and are not part of the binding) that verification,
inspection, policy and denial clearance were computed against with the state
the final atomic apply guards. On any difference it MUST obtain new evidence
for the replacement state or refuse with a retryable `unavailable`; it MUST NOT
re-read a newer publication row and guard only that row, which would validate
evidence derived from the older one. The binding is request-local and adds no
stored field.

**Protocol requirement.** Exhaustion of implementation execution capacity MUST
NOT be treated as malformed content or a missing closure member. A server MUST
retain valid recovery responsibility or refuse without publication using
`unavailable`. The same capacity cause MUST retain its classification throughout
preparation, dependency verification, and final clearance, including retries.
Explicit advertised input limits retain their specified errors. A server unable
to verify historical support within its supported limits MUST fail closed with
`unavailable`, document that limitation, and MUST NOT imply that an ordinary
retry necessarily resolves permanently unsupported work.

**Reference-server behavior.** Reference publication work shares one request
allowance across preparation, dependency checks and final-apply retries,
including snapshots, leases, checkpoints, commits, and failed dispatched calls.
Admission before preparation, hooks, inspectors, lease-read authority activation,
and full-partition prune recovery are outside this ledger. The implementation
reserves headroom for settlement and records permanently unsupported historical
capacity as a terminal stop rather than repeatedly rescheduling it.

**Protocol requirement.**

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

Clearing *k* MUST atomically publish its eligible added membership and update
the authoritative published ref pointer to the largest eligible prefix. That
unit MUST preserve the deletion boundary described below. Completion out of
order can make membership eligible, but MUST NOT expose a ref value beyond
that prefix. A branch's head and packmap MUST remain a pair in both live and
published views.

When a publication Event sink is configured (§12.4), a clearance that changes
the published pointer MUST record its corresponding transition and durable
delivery responsibility in that same atomic unit. Membership-only clearance
MUST NOT emit a publication transition. Correlation MUST identify the resulting
prefix value's originating operation, including when the pointer jumps over
several advances. External projections and deliveries MAY lag only as their
respective specifications permit. Event delivery MUST NOT disclose an undurable
clearance. Clearance and dependent disclosures retain §3.2's declared durability
guarantees.

Clearance MUST NOT re-execute acceptance, charge the accepted operation again,
consume its tickets again, create another acceptance terminal outcome, or settle
an acceptance reservation again. A publication Event is distinct from the
acceptance's terminal outcome. Recovery and repeated clearance MUST preserve
those distinctions even after acceptance replay evidence or acknowledged
outcome evidence has been pruned under its permitted rules. At-least-once
redelivery of the original outcome remains permitted; clearance MUST NOT create
a second terminal result or settlement responsibility.

A server MAY commit clearance in the acceptance's atomic unit when every
clearance condition already holds. That unit MUST guard every mutable fact
relied on for clearance: inspection and obligation state; applicable denial and
takedown evidence; the contiguous eligible prefix and external-supplier
membership; and the membership generation, deletion boundary, and other race
conditions required by this section. Denial evidence retains §14.2's specified
plan-time freshness and `NotAfter` bounds; this permission does not replace
those rules with an unbounded cached check. If a clearance guard fails, the
combined unit MUST commit nothing, or the server MAY re-plan acceptance with
separate clearance while retaining every acceptance guard. The observable
result of a combined unit MUST equal acceptance followed by clearance with no
intervening operation. Combining the decisions MUST NOT waive any condition
that would apply to separate clearance.

Publishing membership MUST durably
schedule re-evaluation of every advance previously blocked on that
membership, including an external delta-base dependency, in any ref.
The scheduled work MUST be retained until completed and MUST run within
a bounded time. The same rule applies when takedown replacement packs
become published.

**Reference-server behavior.** A retained periodic timer per blocked advance can satisfy this
scheduling requirement without an unbounded cross-ref reverse index. It must
survive restarts, recheck delayed membership projections without client traffic,
and remain scheduled while dependencies, inspection obligations, holds, hits,
or replacement dependencies remain outstanding. Timer completion is guarded
against concurrent obligation and generation changes; a timer cannot waive work.
A recheck may persist its witness position in the existing timer value and
continue within a bounded share of the whole alarm budget. The cursor must bind
the retained advance (including its complete dependency and obligation sets)
and the publication generation and deletion boundary. A change to that binding
restarts the check; an unrelated later advance or prefix movement need not.
Checkpointing and completion must atomically guard the current advance,
publication state and original timer value. A missing witness leaves the cursor
at that witness, never beyond it. Launch published-membership projections are
monotonic within a generation; mutable source-local witnesses are re-read in
full on each fire rather than trusted across checkpoints.

**Protocol requirement.** A pack added by another advance that has not cleared or resolved blocks
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

The published pointer MUST change in the same atomic unit as an advance
that starts `cleared` and has an eligible prefix. An advance starting
`held` leaves the previous published value in place.
Published equals live exactly while no advance on that ref is held or
pending (and no hit awaits resolution). A deployment with only
synchronous inspectors MUST still maintain the published view.

#### Resulting-pair coverage

Condition 2's coverage obligation decomposes into an exact implementer
checklist. For an advance writing the live (head, packmap) pair:

| Obligation | Requirement |
|------------|-------------|
| Chain packs | Every pack on the packmap chain is already in published membership or added by this advance. |
| Reachable closure | Every object reachable from the resulting head is contained in at least one chain pack; a non-branch ref's walk is unrestricted, while a branch head's members MUST locate inside chain packs only. |
| Head kind | A present head MUST be a history kind (Commit, Remix, or Tag); other kinds fail closed. |
| External delta suppliers | Delta bases outside the chain packs are recorded as external suppliers; they MUST already be in published membership and this advance's own additions MUST NOT satisfy them. |

The coverage requirement applies exactly when at least one verification regime
is configured (inspection obligations, takedown denial, or a custom
publication policy) and the write deletes none of its refs. A write that
deletes any ref is exempt. With none of those regimes configured, an immediate-path
write is exempt, including the published-source `AdvanceRefs` form — that form
gets no separate exemption: once any regime is configured the destination
retains coverage. Direct-child closure evidence never substitutes for
resulting-pair coverage.

Coverage evidence splits into *dependencies* — the packmap chain, the packs it
lists, and the packs located members resolve to — and *external suppliers* —
packs that supplied delta bases for covered members, merged with any cleared-set
suppliers at a fork boundary. Denial, inspection, and publication checks remain
separate guards: coverage alone never authorizes publication.

**Reference-server behavior.** The reference implementation bounds the chain,
listed packs, reachable members, dependencies, and supplier sets to 4,096 items
each and the fork cleared set to 8,000 objects, bounds retained verification
state to a fixed byte budget, and walks per slice under the scheduled
verifier's call ledger. Those numeric caps
are implementation mechanisms, not protocol promises.

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

### 10.4 Embedding composition

**Draft &mdash; pending architecture review.** These requirements may change.

**Protocol requirement.** A server profile MAY add namespaced local guards,
evidence, and durable responsibilities to an acceptance or published-clearance
decision. A server offering that profile MUST commit its covered additions with
the protocol decision in one atomic unit, or commit none of them. A failed
additional guard MUST NOT commit any effect of that decision or its covered
additions. A failed clearance guard leaves any earlier acceptance intact. An
extension MUST NOT waive authorization, denial, freshness, durability, or replay
requirements.

The profile MUST declare its covered decision classes and atomic domain,
including the protocol state and local responsibilities each decision covers.
Physical colocation, a shared process, or a shared storage provider MUST NOT
serve as proof of atomicity. Later remote delivery remains a separate effect;
its durable responsibility MAY belong to the decision's atomic unit.

For these additional guards, authority movement MUST return `permission_denied`;
a stale or consumed permit or incarnation MUST return `failed_precondition`;
retryable local contention MUST return `aborted`.

A committed replay MUST resolve the original accepted decision without
re-running its composition or creating another covered responsibility.
Clearance composition MUST NOT re-settle acceptance. A profile MUST distinguish
acceptance responsibilities from later clearance responsibilities. A profile
requiring recovery beyond ordinary retained evidence MUST declare and retain
that additional evidence without extending the wire replay lifetime.

Composition coverage is planned until a server exposes the composition seam.
The absence of that seam is not a declared implementation skip. This section
defines no programming-language API or physical storage layout.

## 11. Quarantine and inspection

### 11.1 Configuration and inspected set

**Protocol requirement.**

Each configured inspector, remote or in-process, has a phase, `sync` or
`async`, and an `on_unavailable` setting, `fail_closed` or `publish`.
These settings govern only unavailability (§8); they MUST NOT override
`reject`, `quarantine`, or `defer`. A deployment MUST refuse startup if
opaque mode or `write_policy = open` is combined with any inspector.
Opaque mode cannot enumerate pack objects; open writes let any signer
obtain the writer view (§10.1). The launch profile (§18) MUST accept only
`sync` inspectors with `on_unavailable = fail_closed`, and MUST refuse startup
with any other inspector setting or more than four inspectors. The following
async and unavailable-publish configuration rules apply to the full profile
(deferred, not implemented). An async inspector or an inspector with
`on_unavailable = publish` MUST configure
`inspection_clear_deadline_ms`; otherwise startup MUST be refused.

An inspection-enabled deployment MUST require ticketed uploads and
advertise `begin_upload_threshold_bytes = 0` (STC §7.6), including in
single-repository mode. This associates all added pack entries with an
advance. Storage completion alone MUST NOT establish published
membership.

**Full-profile inspected set (deferred, not implemented).** A file object is a
plain blob of any size, a ChunkedBlob manifest, or a chunk. The inspected
set of each advance MUST be the union of:

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

**Launch inspected set (R-200).** The launch profile MUST inspect exactly
the file-typed entries of the advance's added packs: every `Blob` and
`ChunkedBlob` entry, including surplus entries, with duplicate object ids
reported once. It MUST report `Blob` as `BLOB` and `ChunkedBlob` as
`CHUNKED_FILE`. Chunk-only blobs MAY therefore be reported as `BLOB`;
`CHUNK` MUST NOT be used in this profile. The scanner obtains chunk
membership by decoding manifests through the private byte-retrieval
channel (R-193), rather than through server-side role classification.

This set is complete for the launch profile because every membership addition
passes synchronous inspection before apply, including all file entries of every
consumed pack ticket. Existing membership was therefore already inspected,
even when asynchronous membership projection leaves publication pending. Newly reachable files
in such pending packs need not belong to the current advance's added packs;
they are covered by the earlier inspection. Upload completion or verification
alone establishes no membership, and ref deletion does not erase that coverage.
Enabling inspection over existing, unscanned content is unsupported in this
profile; an inspection deployment MUST start from an empty store. No durable
inspection-mode marker is introduced at launch; the marker and full-profile
activation rules are deferred and not implemented.

**Reference-server behavior.** The `store::inspection_*` modules are unintegrated
groundwork. Enumeration uses verified frame/checkpoint rows in pages of at most
1,000 rows per storage call without a tree walk, reference-page reads, or
object-store reads.

**Protocol requirement. Launch input bound.** A launch server MUST advertise
its positive whole-advance inspection bound as
`GetServerInfo.inspection_max_objects` when inspection is enabled, and omit
that optional field otherwise. It MUST refuse unsupported input before any
Inspect call or acceptance using `invalid_argument` and
`object index limit exceeded`, with ordinary entry-count-limit replay semantics
(STC §7.1). It MUST NOT classify this input limit as inspector unavailability
or make surplus entries alone invalid.

**Reference-server behavior.** The reference parameter `inspect_batch_max_objects`
defaults to 10,000 and cannot exceed that value. Each inspector receives one
complete batch. Before enumerating added-pack entries, the server MUST preflight the sum of
entry counts already recorded in their pack headers or verification jobs.
Pack entry counts are a conservative upper bound on the launch set,
including duplicate and non-file entries. An upper bound above the configured
limit MUST fail before any Inspect call or apply, with `invalid_argument`
and `object index limit exceeded`, following ordinary entry-count-limit replay
behavior (STC §7.1). It MUST NOT be reported as inspector unavailability.
This bound applies regardless of reachability; surplus entries alone remain
permitted. Inspection-disabled deployments retain their existing limits.

**Protocol requirement. Full-profile batching (deferred, not implemented).** The full profile has no
launch whole-set bound. An inspected set larger than
`inspect_batch_max_objects` MUST be sent
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

In the launch profile, `pass` continues; `reject` and `quarantine` both
MUST return `permission_denied` (HTTP 403) without committing. Unavailability
MUST return retryable `unavailable` without committing or storing replay.
A reject (including quarantine) from any inspector MUST dominate other
verdicts, including unavailability. `defer` remains invalid at PRE_RECEIVE.
Each logical call MUST use a stable inspection id for its inspector, advance,
phase and batch across retries, while each signed attempt uses a fresh nonce.
Requests contain object metadata only; scanner byte retrieval is a separate
private-channel capability (R-193).

The following synchronous hold and unavailable-publish behavior applies to
the full profile (deferred, not implemented):

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

**Protocol requirement.**

Full-profile semantics in this subsection are deferred and not implemented.

Stage 6 commits live ref values, added membership, obligations, and
durable scheduling in the same apply. Stage 9 calls MUST be scheduled
through durable background responsibility, resumable across restarts, and retried with
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

### 11.4 Private scanner pack retrieval (R-193, launch)

**Protocol requirement.**

A server offering launch inspection MAY enable a private scanner retrieval
channel. It MUST be disabled by default and MUST reject incomplete retrieval
configuration before exposing the route. Without enablement, the route MUST
NOT be mounted. It grants no
public-serving, write, admin, or preservation-read permission. Global denial
under §14 MUST remain authoritative when `takedown_denial` is enabled,
including for staged packs and trusted scanners. When it is disabled, retrieval
does not require denial-specific proofs under §14.2; credential, ticket,
lifetime, and range checks still apply.

**Reference-server behavior.** The reference retrieval channel requires its Paid
storage profile. The Workers adapter requires the Paid launch profile and valid
retrieval configuration at startup. With denial disabled it performs no reads of
block or independent-action state.

**Protocol requirement.**

An enabled PRE_RECEIVE call MUST include `scanner_retrieval`, an
`InspectRetrieval` message with the following fields:

| Field | Meaning |
|---|---|
| `endpoint_path = 1` | Origin-relative private path `/_mkit/scanner/pack`. |
| `capability = 2` | Opaque MAC-authenticated capability for this call. |
| `expires_at_ms = 3` | Exclusive unsigned Unix epoch-millisecond expiry. |
| `packs = 4` | Ordered added packs as `InspectPack { bytes id = 1; uint64 length = 2; }`; each id is 32 bytes and length is the raw staged pack length. |

The server MUST mint a fresh capability for every Inspect call, including
retries that preserve the same logical `inspection_id` (§11.2). It MUST
bind the server's canonical origin as audience, the inspection id, full
repository identity, ref and upload signer, exact ordered pack ids and
lengths, all corresponding upload ticket ids, mint/expiry times and a fresh
random nonce. Expiry MUST be no later than the hook timeout plus 1,000 ms
after minting, with an absolute maximum lifetime of 301,000 ms.
Outgoing hook signing continues to use §7's separate key and fresh nonce.

The versioned token is
`r1.<key-id>.<lowercase-hex JSON claims>.<64 lowercase-hex MAC>`.
The MAC is keyed BLAKE3 over the literal UTF-8 domain
`mkit-scanner-retrieval:v1\n` followed by the exact serialized claims bytes.
The retrieval MAC key MUST be a dedicated random 32-byte secret with
active/retained rotation. It MUST NOT be reused for another role. Startup
MUST refuse a collision with any configured role's secret or public key,
including the Ed25519 public key derived from a configured secret.

The scanner MUST send `POST /_mkit/scanner/pack` with a JSON body of at
most 16,384 bytes. The body names `capability` and `pack_id` (64 lowercase
hex digits), and MAY name unsigned `start` and `end_inclusive` together.
The request MUST carry a valid STC auth-v2 envelope signed by a key in
the deployment's dedicated scanner Ed25519 allowlist, with audience equal
to the server origin, repository equal to the capability's repository,
and signature binding the exact body bytes and route path. Scanner keys
MUST NOT be reused for another configured role; startup MUST refuse reuse.
The capability alone is insufficient authority, as is a scanner signature
without the matching capability.

The route MUST serve only the named bound pack's raw staged bytes, without
decoding entries or classifying objects. The scanner decodes packs itself,
verifies object ids against Inspect metadata, and derives chunk membership
by decoding manifests. A complete read of at most 1 MiB returns HTTP 200
with `application/octet-stream`. A valid bounded range of at most 1 MiB
returns HTTP 206 with that type and `Content-Range: bytes start-end/length`.
Larger packs require bounded ranges; invalid or oversized ranges MUST fail
uniformly as below. The route MUST emit no cache headers, MUST NOT use
Workers Caching, and MUST bound storage calls and resident response bytes.
Current global denial MUST be checked before disclosure; retained retrieval
authority does not cache denial clearance. The route MUST bound request work
and resident response bytes.

**Reference-server behavior.** Descriptor prefetch spans at most eight storage
partitions and 4 MiB of raw descriptors. Continuations and nested proofs remain
sequential under the request's shared 8,500-operation allowance. Prefetch grants
no cache-based authorization.

**Protocol requirement.**

Informative: an added pack may use an external delta base permitted by §9.4.
To decode that pack, the scanner needs an independently authorized resolver
or a retained local cache for the base. The retrieval capability remains
limited to the advance's raw added packs; it grants no authority to retrieve
external base objects or earlier packs.

At request time, the server MUST check BOTH that the capability is
unexpired and that every upload ticket bound to the requested pack still
exists, is open and unexpired, and matches its bound repository, ref,
signer, pack identity and length. Successful apply consumes the ticket;
terminal close or ticket expiry is an abort for this channel. Each makes
retrieval return `not_found`, even with an otherwise valid unexpired
capability. No new durable lifetime state or key tag is introduced.

A fail-closed attempt, including scanner unavailability or an invalid
verdict, leaves tickets open. Its capability intentionally remains usable
until capability expiry while those tickets remain open. A retry
re-inspects the same packs with the same inspection id and a fresh
capability. The scanner is a trusted role and the short expiry bounds
this retrieval window; returning from a failed attempt is not a terminal
ticket close.

Every retrieval failure MUST return the same HTTP 404 `not_found` answer,
including missing or incorrect capability, unknown or disallowed scanner
key, invalid signature, expiry, unknown or foreign pack, closed/consumed
or expired ticket, and, with denial enabled, an active global block. Storage or proof failure
MUST fail closed with the same answer. No error may disclose whether
the pack or ticket exists. Authorization and, when enabled, global-denial
checks MUST precede reading pack bytes.

## 12. Storage leases and lifecycle events

### 12.1 Terms and scope

**Protocol requirement.**

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

Indexed deployments in the full profile MUST support per-ref storage leases.
An indexed deployment MAY instead select the launch profile (§18), advertise
`leases = false`, retain content permanently and disable garbage collection.
That profile MUST NOT accept lease terms or advertise lease, GC or receipt
support that it does not implement. Leases, GC and receipts remain full-profile
requirements when applicable to its configuration.

For a deployment that supports leases, authoritative per-ref terms and
a repository-level default determine the effective lease.
An explicit per-ref lease overrides that default while the repository
remains undeleted; otherwise the ref uses the repository default. Opaque
deployments support repository-level
storage leases only and MUST NOT accept per-ref terms.
A deleted repository-level lease deletes every ref in the repository,
including refs with explicit per-ref terms, and invalidates repository
membership under §12.2. Per-ref terms do not restore the deleted
repository generation.

Repository-level changes MUST have a declared bounded completion interval.
Acknowledged completion MUST ensure that no stale cached authorization or lease
terms can authorize a later operation. Outstanding old authority must be revoked,
expired, or fenced before completion, as required by
[SPEC-WRITE-GRANTS §9.1](SPEC-WRITE-GRANTS.md#91-visibility).

**Reference-server behavior.** The reference completion interval is one epoch
lease plus the configuration cache TTL. It waits for lease acknowledgements or
expiry and invalidates or expires every other cached copy.

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
enforcement MUST NOT wait for background work. An unauthorized caller MUST receive
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
cancel deletion of the old lease merely because background work is delayed.
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
The remote cache-purge wire contract is in §16.7.

Pack and object surfaces, including `PackExists`, `DownloadPack`, HTTP
object serving, and signed URL tokens, MUST enforce the
repository-level effective state. A per-ref `suspended` or `deleted`
state MUST hide that ref from `ReadRef`, `ListRefs`, and `X-Mkit-Ref`,
together with its published pointer, as required above. It MUST NOT hide
membership shared with other refs. Informative: deployments billing
storage per repository should use repository-level leases; per-ref
leases govern ref visibility, not byte availability.

### 12.3 Setting leases and transition work

**Protocol requirement.**

`SetLease` assigns, replaces, or removes storage-lease terms for a
repository default or, in indexed mode, an individual ref. The server
MUST reject `SetLease` from any caller other than an administrator
authorized for that scope. This authority includes shortening a lease.
The server MUST evaluate shortened terms
without waiting for background work, subject to §12.1's completion bound for
repository defaults. This includes transitions directly to suspension
or deletion.
Removing a repository default makes undeleted refs without per-ref
terms permanent. Removing per-ref terms restores the repository default,
or permanent retention if that default is absent. Both actions MUST NOT
resurrect a deleted lease. Every SetLease action MUST be audited.
Changes to terms or overrides issue a §15 lease storage receipt; an
`EXPIRY` transition does not. The admin API wire, authentication, and
audit-log contract is in §16; this section defines the lease semantics.

In indexed deployments that support storage leases, the server MUST consult
a deployment storage-lease policy hook only when creating a ref with no lease
record. The launch profile with `leases = false` selects explicit permanent
retention by deployment configuration and MUST NOT invoke this hook or accept
lease terms. The decision
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

The server MUST durably perform transition side effects and, when an Event
sink is configured, record one event for each transition due to expiry,
renewal, policy change, or administrative change. Work MUST survive
restart and MUST NOT record the same logical transition as distinct
events. Without an Event sink, no Event outbox row is required. Delayed background work
never delays request enforcement. Expiry work MUST be conditional on
the applicable lease instance and terms, so old work cannot delete a
renewed ref. Once a lease is deleted, its pending deletion MUST target
only that lease's ref incarnation; a new lease MUST treat those old refs
as absent even before cleanup finishes. Delayed work MUST NOT delete a
ref created under the new lease.
Deletion side effects MUST use authoritative current per-ref terms and
repository defaults. They MUST NOT rely on stale cached lease terms.

### 12.4 Event messages and delivery

`HooksService/Event(EventRequest)` delivers a lifecycle event.
`EventRequest.event` is REQUIRED; `EventResponse` is empty. The shared
`Event` fields are:

| Field | Meaning |
|---|---|
| `event_id = 1` | Idempotency key: MUST be 1–128 bytes of `[A-Za-z0-9._:-]` and unique per server audience. |
| `audience = 2` | The mkit server's canonical origin, distinct from the hook-channel signing audience. |
| `repository = 3` | Full repository identity under STC §7.4; empty only for namespace scope. |
| `occurred_unix_ms = 4` | Transition time as signed 64-bit Unix epoch milliseconds, independent of delivery time. |
| `sequence = 5` | Unsigned 64-bit sequence, strictly increasing per repository/ref scope or namespace scope for distinct events of every kind. |
| `kind` | Exactly one transition kind; `lease = 6`, `publication = 7`, and `takedown = 8` are defined here. |
| `namespace = 9` | Namespace identity for a namespace-scoped override; empty otherwise. |

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
Senders MUST populate every shared Event field applicable to its scope
and exactly one kind. A namespace event MUST have `namespace` set
and `repository` empty; a repository/ref event MUST have
`repository` set and `namespace` empty. Senders MUST supply known,
non-unspecified states and a non-unspecified cause when the chosen kind
has those fields. Retries MUST retain the event id, sequence, scope,
and body.
For a namespace event, the sequence is strictly increasing per namespace;
for a repository or ref event, it is strictly increasing per
`(repository, scope)`. Sequences MUST NOT reset on restart, renewal, or ref recreation. Future
event kinds MUST share the same sequence space for their scope.

An Event MUST describe the scope whose own lease terms, administrative
override, or time-derived state changed. A repository-default change emits
one repository-scope event; refs inheriting that default MUST NOT emit
separate per-ref events, and receivers derive their effective state from
the repository transition.
An administrative override emits exactly one event at the scope where it is set.
For a namespace override that event has `namespace` set and `repository`
empty; it MUST NOT be duplicated once per repository. An admin-caused
lease transition uses `LEASE_CAUSE_ADMIN` (§16.5). A takedown suspension
emits only a `TakedownTransition`, never an additional `LeaseTransition`
with `LEASE_CAUSE_ADMIN`.
A namespace-level takedown MUST emit exactly one
`TakedownTransition` per namespace transition, with `Event.namespace`
set and `Event.repository` empty; it MUST NOT fan out per repository.
A content-level takedown MUST emit one transition per affected
repository. The transition carries takedown id,
`TakedownLevel` (`CONTENT = 1`, `REPOSITORY = 2`,
`NAMESPACE = 3`), `TakedownState` (`BLOCKED = 1`,
`COMPLETE = 2`, `REINSTATED = 3`), and the §14.6 reason token.
Unspecified enum values MUST NOT be emitted. A content `BLOCKED`
event MUST be recorded when the blocklist row is written, including
for each currently known affected repository. A newly discovered
holder MUST receive its own `BLOCKED` event before its
`COMPLETE` event. `COMPLETE` MUST be recorded at the applicable
per-repository or namespace completion. Repository- and
namespace-level overrides record `BLOCKED` when the override is set.
`REINSTATED` MUST be recorded when reinstatement completes, once per
affected repository for content level and once at the override's scope
for repository or namespace level.
These events obey the same outbox, deduplication, sequence, and
signing rules as lease transitions; §16 defines the global audit
record.

A `PublicationTransition` uses Event kind field `publication = 7`. It has:

| Field | Meaning |
|---|---|
| `ref = 1` | Full canonical ref name; a branch uses its head ref name. |
| `advance_sequence = 2` | Nonzero advance sequence from §10.2, distinct from the shared Event sequence. |
| `head = 3` | Raw 32-byte published head or non-branch target; empty for deletion. |
| `packmap = 4` | Raw 32-byte paired published packmap; empty for a non-branch ref or deletion. |
| `operation_id = 5` | Raw 32-byte logical write correlation, stable across retries; never credentials or a delivery nonce. |

A publication transition MUST be recorded in the same atomic unit
that changes the published pointer when a publication Event sink is
configured. Its ref, advance sequence, pair and operation correlation MUST
identify the resulting prefix value, including a deletion boundary. A pointer
jump over several cleared advances reports its resulting prefix; membership
clearance alone MUST NOT emit a publication transition. The pair is the
post-takedown pair for a resolved advance. The sender MUST durably retain
correlation with the originating operation through delayed clearance.
Publication events share the ref scope's Event sequence with lease events;
advance numbers MUST NOT be substituted for that shared sequence.

`Committed` means **Sent, never Delivered**: it records the live apply and is
terminal for its reservation. Delivered means that the published prefix has
reached the send's advance, as reported by publication. An Inspect Pass alone
is insufficient. Event and Outcome delivery may arrive in either order;
receivers MUST deduplicate events and MUST NOT regress state on a late Outcome
or Event. Durable recording of one logical event and at-least-once delivery
are distinct guarantees; delivery is not exactly once.

When an Event sink is configured, events MUST use the same durable outbox
as outcomes (§5), be delivered at least once, and remain retained until
acknowledged. Without a configured sink, no Event is recorded. Delivery
has no ordering guarantee. Receivers MUST deduplicate by `event_id` and use
`sequence` to order events within their scope; an older late delivery
MUST NOT roll back a newer state. Signing follows §7.1 and retry follows
§8. Events count toward §5's combined backlog bound.

The remote `CachePurge` contract is in §16.7. A
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

**Protocol requirement.**

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

A planned but unapplied write is covered by the safe-removal barrier below. An advance value between the published pointer and live
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

**Protocol requirement.** A server that offers GC MUST establish a complete,
authoritative root set under §13.2 and protect all retained, pinned, held, or
newly relied-on members before removal. It MUST account for in-flight accepted
writes and their outstanding projection responsibility. A delay or an eventually
consistent index alone MUST NOT establish completeness. GC MUST revalidate
current authoritative lease terms, roots, and candidate state before removal.
A concurrent new reference or changed candidate MUST defeat stale removal.

Repository membership, serving indexes, and ref-scoped membership evidence MUST
become durably absent before the repository releases its holder. Holder removal
MUST compare the unchanged holder identity or revision. Re-adding a member MUST
defeat an earlier planned removal. Incomplete discovery or recovery MUST retain
the candidate. A server MUST retain durable responsibility for unfinished cleanup.
These requirements do not prescribe an implementation's execution stages.

**Reference-server behavior.** The reference design uses mark, wait, re-check,
and drop. Marks carry a backend timestamp. It waits for the apply deadline plus
clock margin, the namespace's completed relay frontier, and `gc_grace`. Root
enumeration uses strongly consistent ref storage plus the union of the ref index
and active-storage registry. Re-checks include every root in §13.2, authoritative
lease terms, pending advances and replacement packs. Guarded deletion compares
the unchanged mark and last-change sequence; holder removal follows durable
membership and index removal and compares the holder change sequence. Orphan
holder reconciliation preserves that same guard. These timestamps, registries,
frontiers, and stored marks are mechanisms for the requirements above.

**Protocol requirement. GC reliance fence.** Every acceptance that newly
relies on an existing member MUST defeat a stale GC removal of that member.
No drop based on an earlier re-check may commit after such an acceptance
without re-checking its new reliance. The server MUST ensure the repository's
holder exists. Two conforming mechanisms are:

1. Clear each relied-on member's GC mark durably before acceptance commits and
   ensure its holder. A planner encountering an existing mark clears it before
   planning the use. A new mark restarts the required wait and re-check.
2. Maintain a per-repository reliance version. Every acceptance newly relying
   on existing members increments that version in its atomic unit. Every GC
   drop guards the version observed at its re-check. If the version changed,
   the drop MUST fail and re-mark before attempting removal again.

New reliance means making a member reachable from a ref value where it was not
before, directly or transitively: every pack and packlist node newly reachable
from the new value, including through `prev` links, closure objects and their
containing packs, and external delta bases (§§9.2–9.4). Any ref target counts,
including a head-only branch update, with its indexed closure or opaque packmap
chain. An opaque write introducing new packmap nodes MUST cover every pack and
node reachable from them, including through `prev` links, except packs the same
write uploaded that were not already members. It MUST decode those nodes as GC
does. The version mechanism does not require per-member mark writes, but MUST
protect every member this rule covers.

A write MUST NOT rely on a `deleting` member. It MUST return retryable
`unavailable` or arrange a re-upload, rather than report permanent absence merely
because deletion is in progress. A member already gone receives §9.4's missing
member response in either mode. The reliance fence and commit deadlines protect
planned, unapplied writes without prescribing a global transaction or execution
stages. The detection mechanism and cost of finding new reliance belong to the
server implementation.

**Reference-server behavior.** The per-member mark-clear and holder mechanism
satisfies this requirement; a reference server need not implement a reliance
version. This permission does not integrate currently deferred GC paths.

#### 13.3.1 Membership witness

**Protocol requirement.** A server MAY guard previously verified repository
membership with a constant-size witness consisting of the repository's
membership generation and removal version. Every event removing a member or
making it unusable for delta-base or closure reliance MUST increment the
removal version in the same atomic unit as that repository change. This
includes serving stops even when the underlying membership record remains.
Versions MUST NOT be reused within a generation. Every acceptance using the
witness MUST guard both unchanged values in its atomic unit, paired with the
reliance fence above. Additions alone do not require a removal-version change;
this witness is not a per-write state version.

The removal events are:

| Event | Required invalidation |
|---|---|
| Repository GC drops membership or its usable serving evidence (§13.3). | Increment the repository's removal version with removal. |
| A member enters `deleting` (§§13.3–13.4). | Increment the removal version with any repository transition that makes a still-retained member unusable. Global zero-holder, zero-hold byte deletion cannot have a usable retained member under §13.4's holder rules. |
| Inspection verdicts, flags, or holds stop serving or reliance (§§11.2–11.3), including quarantine without flagged ids. | Increment the removal version with the repository's serving stop, covering every affected pack and object even if membership remains stored. |
| Takedown replaces or removes old membership, packs, indexes, or now-unreachable manifest chunks (§14.4). | Increment the removal version with each repository change that removes usable membership. |
| Repository-level lease deletion (§12.2). | Invalidate the membership generation; a later lease cannot restore it. |
| Per-ref deletion, including a per-ref lease deletion (§§10.2, 12.2; STC §7.8). | Change neither membership generation nor removal version solely for ref deletion: shared membership survives. |

The witness proves that the previously verified members remain usable members
of that repository. It MUST NOT replace independent authorization, effective
lease-state, inspection-policy, or denial checks. In particular, repository or
namespace suspension (§12.2) and global block activation (§14.2) retain their
own required guards and freshness. A block's immediate serving stop (§14.3)
does not permit a stale denial proof: §14.2 defines which time-qualified proof
can still authorize a planned write and when it must be renewed. Repository
holds and flags that invalidate membership reliance still require the removal
version change above. These independent guards are required even when no
membership record changes.

### 13.4 Global byte deletion

Global pack or extracted-object bytes MUST be deleted only with zero
holders and zero live holds, except for the completed §14 takedown of
blocked bytes. That path MUST first durably remove or substitute every
affected holder and prevent new holders through the blocklist; it MAY
then delete the blocked extracted copy despite stale holder counts or
holds that cannot be released until relay delivery. For a superseded
pack, the exemption applies only to holders and holds of affected
repositories whose substitution is already durable. Any other holder
or hold blocks pack deletion until its repository is substituted or
its ordinary hold is released. The holder sweep and watermark proof in
§14.3 are required before using this exemption.
The §14 path is also exempt from §13.3's `gc_grace` wait for superseded
packs: those bytes are deleted at takedown completion, not seven days
later. All other §13 safety checks still apply.
An `AlreadyPresent` pin counts as a live
hold in the ordinary guard. Every path that writes or deduplicates bytes which
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

**Protocol requirement.**

GC MUST abort the run on any unreadable root source, unreadable lease terms
or repository default, unreadable advance or clearance state, unknown
record kind, unreadable completeness or in-flight-write evidence, undecodable
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

## 14. Takedown and redaction notices

### 14.1 Terms, levels and scope

A **takedown** is a durable denial of content or of a repository or
namespace, initiated by an authorized administrative action (§16) or an
inspector rejection (§11.3). A **tombstone** records that an object was
removed from a particular repository; it does not change the object's id.
A **redaction notice** is the signed account of that action (§14.6).

Content-level takedown is available only in indexed mode. It names 1–256
whole plain-blob ids or ChunkedBlob manifest ids; an individual byte range
cannot be removed. For a taken-down manifest, its chunks are removed from
a repository only when they are not **takedown-reachable** there after
substitution: reachable, without descending through any blocked or
taken-down manifest, from a live, published, or retained advance value
after substitution. This takedown's own hit membership, superseded
packs, holds, and replacement packs do not count as roots for this test. The chunks MUST NOT themselves be blocklisted on
account of that manifest.
Commits, trees, tags, and individual chunks cannot be taken down at
content level. Use a repository- or namespace-level takedown for such
content. In opaque mode, only these two levels are available. Informative:
commit and tag messages and tree entry names remain a residual content
channel even in indexed mode.

A repository- or namespace-level takedown is a §12 administrative
suspension override marked as a takedown. It reuses the existing lease
states, but payment renewal MUST NOT lift it. Reader answers, including
HTTP, MUST remain the byte-identical §12.2 `not_found`/404 answers; they
MUST NOT carry a notice or return 451. Authorized writers receive the
existing `lease suspended` public message and a §14.6 notice detail;
the message text is unchanged. A namespace override applies to every
repository in that namespace. §16 defines `Takedown` and the suspension
operation; §14 defines their serving and notice consequences.

Only an asynchronous QUARANTINE-phase inspector `reject` initiates an
automated global content takedown of its flagged ids in every namespace
holding them, including repositories unrelated to the rejected advance.
A synchronous PRE_RECEIVE `reject` denies only its push. A subsequent
reinstatement under §14.8 is the remedy for a mistaken hit. Informative:
one false-positive inspector verdict can make the same object unavailable
across many namespaces. The blocklist is keyed by object id; the same
bytes represented under a different id can evade that block.

### 14.2 Blocklist

**Protocol requirement.**

A deployment MAY disable global content denial. While disabled, denial checks
MUST report clear; holder, inventory, membership, index, and proof-structure
obligations remain applicable. Every operation that creates or activates a block
or denial action MUST refuse with `failed_precondition` and the exact public
message `takedown denial disabled` before any write.

**Reference-server behavior.** The `takedown_denial` configuration selects this
mode. When disabled, ingest and read paths skip block and denial-action storage
reads. Raw store writers require a capability obtained from a pipeline with
denial enabled. These API and I/O mechanisms do not constrain other servers.

**Protocol requirement.**

Enabling takedown on an existing store is a migration, not a configuration-only
change. Objects ingested with denial disabled MUST be checked on read once
denial is enabled. Holder, inventory, and proof structures require a backfill
before activation. The following blocklist checks and denial-specific
deduplication requirements apply when global content denial is enabled.

The server MUST maintain a strongly consistent global blocklist associating
each object id with its set of active actions. Each
action has a distinct `block_action_id`, source `takedown` or `manual`,
an optional `takedown_id`, a §14.6 reason token, and its `blockedAtMs`.
An action carrying a takedown id MUST have source `takedown`; a manual
action MUST NOT carry one. The object stays blocked while any action
remains; its blocklist entry is absent only when the set is empty. §16 defines
`AddBlock` and `RemoveBlock`. A manual block of an id with known holders
also starts a takedown action for those holders. `RemoveBlock` MUST
remove only a named manual action without a takedown id; only §14.8
reinstatement can lift a takedown action or undo its repository tombstones.

In indexed mode, stage 5 MUST check every decoded pushed file object
against the blocklist independent of configured inspectors. Extraction
deduplication and its holds, and the relay when recording a new holder,
MUST also check it. A newly recorded holder of a blocked object MUST
schedule takedown for that repository (§13.4). Extracted-object and HTTP
serving MUST read the blocklist at serve time with per-object strong
consistency. A blocked object MUST NOT be used as a delta base. These
checks enforce §11.3's serving stop before any repository rewrite.
Every blocklist check gating a membership, serving-index, or holder write
MUST be taken at or after that write's `plan_time`
(SPEC-WRITE-GRANTS §5.5). If synchronous
inspection occurs after an earlier check, the server MUST repeat the check
at plan time. A write planned before the blocklist action but applied
later remains bounded by `NotAfter` (§13.1); a write planned afterward
MUST observe the action or fail closed.
With denial enabled, `AlreadyPresent` and every other pack-deduplication path MUST answer
as if a pack were absent when it contains a blocked id or has been
superseded by a takedown. The resulting ticket forces indexed decode,
which rejects the blocked object with the error below. Deduplication
MUST NOT make a blocked or superseded pack reusable.

A push containing a blocklisted object MUST be rejected with
`permission_denied`, exact public message `object blocked`, and the
§14.6 detail with an empty repository and no rewrites. It MUST NOT
disclose whether a different repository holds the object. A blocklist
check failure MUST fail closed rather than treating the object as
unblocked. The blocklist is a denial source, never a deduplication,
serving, or membership source. Bytes from an `object blocked`
rejection remain subject to ordinary §13 GC; the rejection does not
authorize immediate byte deletion.

**Reference-server behavior.** The implementation reads the block entry and independent actions together with
`NamespaceStore::get_many`, including through borrowed stores. Each probe is
one store batch, charged one unit when budgeted; batch-capable backends can
serve it in one round trip. A member dependency check probes both the object
and its containing pack. This batching does not cache clearance or change the
fail-closed requirement.

### 14.3 Lifecycle and completion

**Protocol requirement.**

For each content takedown, the server MUST perform the following durable,
restart-resumable steps in order. A failed step leaves the serving stop
in force and MUST NOT report completion.

1. Record the blocklist action and immediately apply §11.3's serving
   stop to all callers and all serving surfaces. Invalidate local caches.
2. Copy canonical object bytes into the restricted preservation store
   (§14.7) and verify them against the id. For a ChunkedBlob, preserve
   and verify its manifest and every chunk against the manifest. An
   unreadable or mismatched source fails closed; later steps MUST NOT
   make unverified bytes available as a replacement.
3. For each holder repository, perform the rewrite and substitution in
   §14.4, then write its tombstones and ref notice flags and durably
   store its signed reader and writer notice sets (§14.6). Its old packs
   remain unavailable throughout.
   Durably enqueue that repository's purge as part of this completion;
   another repository's work MUST NOT delay this enqueue.
4. Mark the extracted serving copy and superseded packs for deletion.
   They remain unservable; actual deletion waits for step 6's proof.
5. Ensure a cache purge has been enqueued on **every** takedown,
   including a suspension, using §16's `CachePurge` delivery contract.
   Per-repository purges enqueued in step 3 need not wait for deletion
   of packs shared elsewhere. Shared-cache removal follows that
   interface's delivery latency.
6. Establish a safe-discovery barrier that covers every write which could
   have relied on clearance obtained before the block. The server MUST account
   for accepted writes and outstanding holder or index projection responsibility
   before enumerating affected repositories. A fixed delay alone MUST NOT prove
   that no affected holder remains. A later-discovered holder MUST receive the
   same takedown obligation.
7. Delete the extracted serving copy under §13.4's takedown exemption.
   Delete superseded pack bytes at the completion of their last affected
   repository under the `gc_grace` exemption, only when every holder
   and hold satisfies §13.4's affected-repository rule and step 6 has
   proved that no undiscovered holder can still rely on the pack. A
   pack lacking that proof remains blocked; deletion is retried when
   proof becomes available. Once proven, deletion MUST NOT wait for the
   ordinary seven-day grace.

Holder discovery MUST use authoritative holder evidence and a durable,
restart-resumable exhaustive sweep of every relevant namespace and repository.
Known holders alone MUST NOT establish completeness. The sweep MUST retain its
position and retry unreadable or incomplete enumeration and index observations.
Global completion MUST wait for exhaustive discovery, every affected repository,
and every outstanding effect covered by the safe-discovery barrier. It is used
for reporting and §16's audit log; it does not block an unrelated repository's
publication.

**Reference-server behavior.** The reference design's safety cut is takedown
time plus the maximum apply window and clock margin. It waits for time to pass
that cut and each namespace relay watermark to cover it. Discovery enumerates
the namespace registry and the union of repository and active-storage registries,
then checks named ids in bounded index reads and persists its cursor. This is
one implementation of complete discovery; its placement and relay frontiers
are not requirements on other conforming servers.

**Protocol requirement.**

A repository's takedown is **complete** once its affected values,
membership, indexes, tombstones, and notices are durable, its old packs
are unservable there, its cache purge is durably scheduled, and its safe-discovery barrier is
complete. A `hit` advance resolves on this
per-repository completion only when the post-takedown chain also passes
§10.2 condition 2 and its other obligations are met. The hit and
its replacement packs remain §13.2 roots until then, even across a
deletion boundary. A post-publication reject creates a separate
takedown obligation without rewinding the published pointer. It leaves
published membership as the replacement set after completion.

### 14.4 Rewrite, replacement and ref-value substitution

**Protocol requirement.**

For each affected repository, the server MUST rewrite every pack that
contains a taken-down object or whose delta chain passes through it,
including packs that use the object as an external base. It MUST remove
the object and make every surviving dependent entry independently
decodable. A delta needs rawification when its **direct** base is
excluded; an unchanged direct base can remain a delta after its own
safe rewrite. A packlist chain MUST be rebuilt to omit old packs and
reference actual replacement ids. New pack ids are content hashes of
the produced bytes, not fixed across implementations; the notice records
the ids actually written.

For a taken-down ChunkedBlob manifest, the rewrite MUST also remove
repository membership and serving indexes for each chunk no longer
takedown-reachable there (§14.1) after substitution. It MUST rewrite
or drop every pack containing such a chunk and substitute the affected
packmaps in the same scope below. A chunk still takedown-reachable
keeps its membership; §14.5's serving stop applies until the
repository takedown completes. Chunks remain outside the global
blocklist.

Before writing replacement bytes or reusing an existing replacement,
the server MUST create durable holds under §13.4. It MUST apply §13.3's
new-reliance rule to every newly relied-on member, using either conforming
reliance fence, and use a guarded write with `NotAfter`. An in-progress
`deleting` member produces retryable `unavailable`; a stale plan MUST
re-plan rather than publish a partial chain. The server MUST pair each
branch's unchanged head with its new packmap. It MUST substitute the
packmap in one guarded atomic unit in the live value, the published
value, and **every retained intermediate advance value** (§10.2).
Sequence numbers and inspection decisions MUST remain unchanged.

Replacement membership and serving index rows MUST become durable and
visible first. A guarded atomic unit then substitutes the ref
values and each affected ref's membership-addition records used by
`X-Mkit-Ref` (§13.3), and writes a tombstone per removed id and a
per-ref flag for every affected closure or packlist. Old packs MUST
remain unservable throughout this order; a reader between the two steps
MUST NOT receive blocked bytes.
Replacement packs inherit the published status of the packs they
replace. A `hit` advance's own replacement packs MAY publish atomically
with its resolution; packs supplied by other advances or external bases
still satisfy §10.2's dependency test. Publication of replacements MUST
durably schedule re-evaluation of blocked advances, including those
blocked on external bases. An advance blocked only on a removed pack
MUST be re-evaluated against its replacements. These server writes are
not advances: they take no sequence number and add no inspection duty.

### 14.5 Tombstones and caller answers

Before a repository's tombstone is written, every caller MUST receive
§11.3's ordinary absent, `not_found`, or 404 answer for blocked content,
including extracted copies, pack reads, HTTP, and delta-base lookup.
Afterward, an authorized caller who can see an affected ref value MUST
receive its active notices for that caller's view on `ReadRef` or
`ListRefs`; an absent or hidden ref MUST NOT reveal one. §14.6
defines the additive fields. A notice
flag is calculated for each affected ref at takedown time and followed
through subsequent ref moves until the affected value is no longer
visible. A returned notice MUST correspond to the returned value.

An `AdvanceRefs` whose permitted closure contains a tombstoned object
MUST use existing `invalid_argument` / `open closure` and attach the
applicable writer notice details. A tombstoned delta base MUST use existing
`failed_precondition` / `delta base not available in this repository`
with the applicable writer details, without §9.4's membership-lag window. The tombstone
check precedes that window. No new `failed_precondition` code is
introduced for a ticketed `AdvanceRefs`. A `DownloadPack` of a
superseded pack whose id appears in the `rewrites` of a notice for the
caller's view MUST return `not_found` with exactly those notices before
sending any stream message; otherwise it returns the ordinary plain
`not_found`. `PackExists`
MUST return `false`. The advance and delta-base details likewise require
an authorized writer in the affected repository. SSH and enc callers
receive the same plain error codes and messages without notice details.

HTTP 451 is permitted only for an id reachable by the published tree
walk when this repository has its tombstone. All preceding privacy,
authorization, unrelated membership, and reachability 404 checks still apply.
The tombstone is a candidate that lets a removed id pass the ordinary
membership-miss check solely to test published-tree reachability; it
does not restore membership or authorize serving bytes. A failed walk
remains 404.
In particular, reachability MUST NOT descend through a blocked or
tombstoned manifest. A chunk reachable only through such a manifest
returns 404, including before that manifest has a tombstone. The 451
check precedes 304 and Admission. §14.6 and
[SPEC-HTTP-OBJECTS §§3–4](SPEC-HTTP-OBJECTS.md#3-response-precedence)
define its response. Repository and namespace suspensions instead use
§12.2's byte-identical read denials, never 451.

A caller-selected view, including the writer view, MUST NOT bypass a
content takedown or administrative suspension. The strongly consistent
serve-time blocklist check stops extracted and HTTP serving immediately.
Every pack read after the blocklist write MUST prove that its indexed
entries contain no blocked id and that the pack has not been
superseded; otherwise that read returns §11.3's absent answer. A stale
holder index is not proof. Until a repository's takedown completes,
the serving stop also covers every chunk of a blocked manifest there;
the per-read proof fails for any pack containing such a chunk, even
though chunks are not blocklisted. The chunk-id set of a blocked
manifest MUST be recorded with its blocklist action when that action is
written, from the canonical manifest bytes. Whether a repository holds
the manifest is decided from that repository's own membership, not from
global holder rows. This proof makes the
repository-specific serving stop effective immediately, independent of
the holder sweep. Discovery
MUST NOT impose a deployment-wide pack outage. Informative: without
clone-with-holes support, a branch whose history contains a taken-down
object is unfetchable until its owner rewrites history.

### 14.6 Signed redaction notice

The server MUST sign separate reader and writer notice sets for each
affected (takedown, repository). A reader notice contains only objects
and rewrites concerning membership published at its issue time; a
writer notice covers the full affected live and retained membership.
If no published membership is affected, no reader notice is issued.
A repository- or namespace-level suspension has only a writer notice.
An ingest rejection uses a repository-empty writer notice per
blocklist action with no rewrites. Notices are signed at the takedown
or rewrite pass that creates their mappings. If a writer-only
replacement later becomes published, the server MUST sign a new reader
notice for its newly published mappings before exposing that ref value;
it MUST NOT reuse the writer notice for readers. Each is an immutable DSSE
JSON envelope with exactly one Ed25519 signature under the
receipt-and-notice key of §15. Its
`payloadType` is `application/vnd.mkit.redaction-notice.v1+json`; the
payload is JCS JSON, **not** an in-toto Statement. This distinct
`payloadType` is the notice signing domain. `keyId` is the lowercase
64-hex BLAKE3 digest of the raw public key; the DSSE `keyid` is
`blake3:<keyId>`. §15 defines key publication at
`/.well-known/mkit-receipt-keys.json` and retains retired keys forever
so old notices remain verifiable.

The payload is an object with exactly these fields:

| Field | Contract |
|---|---|
| `version` | Integer `1`. |
| `noticeId`, `takedownId` | `noticeId` is a random 128-bit value encoded as 32 lowercase hex digits, unique per signed notice; it MUST NOT be sequential. `takedownId` is the takedown's id, distinct from `block_action_id`, 1–128 bytes of `[A-Za-z0-9._:-]` under §6.6's reservation-id grammar, or empty only for a manual block's ingest notice. |
| `origin` | Canonical server origin, also the 451 blocking entity. |
| `repository` | Full repository identity, or empty only for an ingest rejection. |
| `view` | `reader` or `writer`. A reader notice is limited to published membership; an ingest or suspension notice is `writer`. |
| `objects` | Array of `{id,kind}`, sorted by id, with lowercase 64-hex id and kind `blob` or `chunked_blob`. Nonempty for content takedown and ingest rejection; empty for a repository or namespace suspension. |
| `reason` | One registered token below or a deployment token; never free text. |
| `takenDownAtMs`, `issuedAtMs` | Signed i64 Unix epoch milliseconds as decimal strings, as in §15 receipts; issuance is no earlier than the takedown. |
| `keyId` | Receipt-and-notice key id described above. |
| `rewrites` | Array of `{type,old,new}`, sorted by `type`, then `old`; `type` is `pack` or `packlist`, `old` is a lowercase 64-hex id, and `new` is a lowercase 64-hex id or empty when removed without replacement. Empty for ingest rejection. |

Registered reasons are `legal`, `policy`, `malware`, `abuse`, and
`manual`. A deployment token MUST use `x-` followed by 1–62 lowercase
ASCII letters, digits, dots, or hyphens. Deployments SHOULD map a
sensitive category to `legal` instead of disclosing it in a public
notice. §16's `reason_token` supplies this public token; its separate
`reason` is private audit text and MUST NOT enter a notice or Event.
No notice reason contains free text. Each encoded envelope MUST
be at most 262,144 bytes. A takedown MAY have several notices per
repository and view, ordered by `noticeId`. The server MUST partition
large object and rewrite sets into complete, bounded notices without
truncating either set; notice size MUST NOT make a takedown impossible
to complete. A second rewrite pass MUST add a new notice for its
new mappings. For a repository notice, `objects` and `rewrites`
MUST name only ids and packs affected in that repository, even if the
global takedown names more ids. Reader notices MUST further omit
pending-only ids and pack ids. An ingest notice names only submitted
blocked ids. A notice MUST NOT disclose another repository's membership.

The Connect detail is `mkit.transport.v1.RedactionNotice` and carries
only `bytes envelope = 1`, the exact DSSE envelope bytes. `ReadRef`
returns active notices for the caller's §10.1 view in
`redaction_notices = 3`. `ListRefs` returns
`ref_redactions = 3`, pairs of full ref name and notice, without
changing `RefEntry`; the pairs count toward STC §7.9's page byte bound.
The server MAY shorten a page to fit all of a returned ref's notices;
it MUST NOT silently omit a notice. If one ref plus its notices cannot
fit in a page, `ListRefs` MUST fail closed with `resource_exhausted`.
For a ref affected by several active notices, the server MUST include
each notice of the caller's view in ascending `noticeId` order;
duplicate pairs are forbidden. A reader MUST NOT receive a writer
notice. Reinstatement withdraws the affected active notices (§14.8).
A client MUST strictly decode the envelope, enforce the size bound and
exact `payloadType`, verify the Ed25519 signature against a pinned
trust root (§15.7), and check the expected origin, repository, and
`view`. The payload `keyId` MUST equal the body of the DSSE
`blake3:` keyid and BLAKE3 of the selected raw public key.
`issuedAtMs` MUST fall in that listed key's half-open validity
window (§15.5). The client MUST refresh the same-origin key list within
its 300-second max-age and refetch it once, ignoring its cache, on an
unknown keyid before
rejecting that key. A pinned key absent from the current list MUST fail
verification even if its signature and issue-time window pass. A key
learned only from `GetServerInfo` or the well-known URL is `unpinned`
and MUST NOT silently become trusted. During rotation, the client pins
the replacement key from the overlapping list before accepting its
signatures (§15.5).

HTTP 451 MUST use the newest applicable reader notice for the requested
id as the detail's canonical protobuf JSON body (greatest
`issuedAtMs`, then `noticeId`). It MUST NOT expose a writer notice.
`Content-Type` MUST be `application/json`, with
`Cache-Control: no-store` (or
`private, no-store` with a bearer gate). It MUST omit `ETag`, every
`X-Mkit-*` header, and `Content-Range`; HEAD omits the body. It MUST
include `Link: <origin>; rel="blocked-by"` as in
[RFC 7725](https://www.rfc-editor.org/rfc/rfc7725), and expose `Link`
through CORS. It MUST NOT include preserved bytes or free-text reasons.

### 14.7 Preservation store

**Protocol requirement.**

The preservation store MUST be a restricted storage keyspace separate
from serving and deduplication. It is reachable only through the audited
§16 `ReadPreserved` admin operation. It MUST NOT serve clients, supply a
delta base, satisfy deduplication, or be collected by §13 GC. The record
MUST include the verified canonical bytes (manifest and chunks for a
ChunkedBlob), takedown id, object ids, kinds and sizes, reason and time,
holders at completion, and per repository the affected old pack ids and
known advancing signer keys. The record remains accessible to authorized
admin review even when serving is stopped.

When takedown is enabled, `preservation_retention`, the §15
receipt-and-notice signing key, and the published §15.5 key list are
REQUIRED deployment configuration; startup without any of them MUST
be refused. mkit defines no default for `preservation_retention`.
`retain_until` is takedown time plus that duration.
A legal hold suspends timed purge until audited `SetLegalHold` release
under §16. The server MUST purge expired records without an active hold,
and the purge MUST be audited. Reinstatement marks the record
reinstated but retains it until retention ends.

### 14.8 Reinstatement

The §16 `Reinstate` operation MUST refuse with `failed_precondition`
if another active takedown still covers any requested id. Otherwise it
MUST perform a server-side rewrite from verified preserved bytes for
every id covered by that takedown in each affected repository. It MUST
restore each object and append a single-object pack for it. The rewrite
MUST cover the full §14.4 scope: live, published, and every retained
intermediate advance value, their packmaps and per-ref
membership-addition records, repository membership and serving indexes.
The new single-object packs inherit the published status of the packs
they replace. Replacement membership and indexes become durable first;
then the server compare-and-swaps each affected packmap with its head
and sequence unchanged under §13 holds, new-reliance, and `NotAfter`
rules. It MUST remove that takedown's blocklist action only after this
state is durable; any other active action continues to block the id.
In a repository, it MUST withdraw every active notice
only after every id that notice covers has been reinstated there; until
then its tombstones and notices remain active. On success it MUST delete
the corresponding tombstones and ref flags and audit the action. A
failed or partial reinstatement MUST leave denial in force; it MUST
NOT expose the object before all replacement state is durable.
For a ChunkedBlob, reinstatement MUST also restore every preserved chunk
whose repository membership was removed, using a separate single-object
pack for each needed chunk before the manifest can become reachable.
Chunks still takedown-reachable (§14.1) in that repository keep
their existing member pack. The guarded packmap and index update MUST
make the manifest and all its chunks usable together.
For a repository- or namespace-level takedown, reinstatement removes
the administrative suspension override under §12, withdraws its
per-repository notices, and is audited; no content pack rewrite is
needed unless a separate content takedown remains active.

### 14.9 Interaction with GC, restore and caches

**Protocol requirement.**

§13.2 retains hit membership, including invalidated membership, and
replacement packs until per-repository completion. §13.4 permits
deletion of blocked extracted bytes and
superseded packs after the substitution, without ordinary zero-holder
or `gc_grace` waits. Preservation records and active blocklist actions
follow §§14.2 and 14.7, not server GC.

A portable restore MUST replay every takedown and reinstatement
recorded after the snapshot time, in action order, before serving a
restored state. Active takedown and blocklist-action records MUST
persist independently of audit pruning and snapshot restore (§16).
They are the source for this replay.
Restoring an older content or repository index MUST NOT resurrect
tombstoned membership, an extracted copy, or a blocklist absence. An
incomplete or unreadable action record fails restore closed. Cached
walks and serving copies MUST honor the current blocklist and
tombstones immediately; every takedown enqueues §16 `CachePurge` as
§14.3 requires.

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
`packmap` are visible to every caller entitled to the receipt; they describe a committed write on that ref, not a reader view. An
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
until the user adds it to that root. A user-supplied trust root for an
origin disables TOFU continuity for that origin. A compromised key MUST
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
ref scopes; a paired packmap maps to its branch for this check. The same limit
applies to per-ref lease receipts; repository- and namespace-scope lease
receipts are not limited. An out-of-scope advance or per-ref lease
receipt MUST receive the uniform `not_found` of STC §2.2. The scope
check is part of authorization and runs before §12.2. Callers with `read` or `read,write` capability, owners, and
authorities are not subject to this grant-scope limit. The lease
selector MUST remain available to an otherwise authorized writer
while the repository is suspended or deleted, for receipts of that lease scope. The server MUST
retain the latest signed receipt for each ref, including its terminal
deletion receipt, while the repository exists, and the latest receipt
for each repository or ref lease scope while its repository identity remains
addressable, and each namespace lease scope while its namespace remains
addressable, including while the effective state is `suspended` or
`deleted`. This retention obligation begins when the pending signature
is complete. The server MUST keep the key fixed at apply until every
pending signature under it is complete. Disabling receipts stops new
pending rows but not the completion of existing ones; if the key itself
is removed, those receipts answer `not_found`. Lease receipts from repository- or namespace-level
takedowns and reinstatements are available through `GetReceipt` only;
the takedown and reinstatement admin responses carry no receipt. The advance selector MUST
enforce a §12.2 suspended or deleted effective state with `permission_denied` and public message
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

## 16. Admin API and audit log

### 16.1 Service, exposure and off-by-default

`mkit.server.admin.v1.AdminService` is the operator control plane. Its
procedures are Connect unary calls except `ReadPreserved` and
`ReadAuditLog`, which have one signed request and stream responses. The
service MUST be mounted only when a nonempty admin key list (§16.3) is
configured. An absent list disables every admin route; it MUST NOT
fall back to write, hook, grant, receipt, or bearer authentication.

A native deployment MUST expose the service on a listener separate from
the client transport listener, defaulting to loopback. The native client
listener MUST NOT serve admin paths. A Workers
deployment MUST expose the canonical
`/mkit.server.admin.v1.AdminService/<method>` paths, distinct from the
client transport service paths, behind the deployment's network
controls; it MUST NOT rewrite them before signature verification.
Admin procedures are exempt from the client RPC bearer gate.
A request carrying both `X-Mkit-Admin-*` and any auth-v2 envelope header
(`X-Public-Key`, `X-Signature`, `X-Digest`, `X-Created-At`,
`X-Expires-At`, `X-Envelope-Version`, `X-Audience`, `X-Repository`,
`X-Content-Commitment`, or `Idempotency-Key`), or `X-Write-Grant`, MUST be
rejected with `invalid_argument` before either identity is used. Admin
authorization is independent of repository visibility and of grants.
An `Authorization: Bearer` header is ignored for admin authentication.

Informative: the server holds public admin keys only. Private admin
keys belong offline or in a hardware security module. Informative: on
Workers the admin path shares the origin with client paths and is
protected by its signature. Deployments
provide their own operator UI; this version exposes no public audit or
preservation view. Repository owners learn about redaction through §14
notices and takedown lifecycle Events.

### 16.2 The `mkit-admin:v1` envelope

Every admin request MUST carry a strict Ed25519 signature over the
32-byte BLAKE3 digest of these eight newline-separated UTF-8 fields,
with no final newline:

```text
mkit-admin:v1
<key id>
<audience>
<full procedure>
body:<64 lowercase hex BLAKE3 of the exact request body bytes>
<created epoch milliseconds>
<expiry epoch milliseconds>
<nonce>
```

`mkit-admin:v1` is a permanent domain separator distinct from
`mkit-hook:v1` and `mkit-write:v2` under
[SPEC-CONVENTIONS §4](SPEC-CONVENTIONS.md#4-domain-separator-and-namespace-naming).
The key id follows §7.1's 1–64 byte `[A-Za-z0-9._-]` grammar.
The audience is the server's canonical origin under STC §7.1, even on
the separate admin listener or path; it MUST equal the configured
server origin. The procedure is the exact receiving Connect path,
`/mkit.server.admin.v1.AdminService/<method>`. The nonce is 32 random
bytes encoded as 64 lowercase hex digits. Times are unsigned decimal
epoch milliseconds with no sign or leading zero, except `0`. The
interval MUST be positive and at most 300,000 ms; the created time MAY
lead the backend clock by at most 30,000 ms and the expiry MUST be in
the future when accepted.

All eight headers below are REQUIRED, each exactly once. The server
MUST reject a missing or non-`1` version before reading the body and
MUST compare every supplied value to its canonical field:

| Header | Value |
|---|---|
| `X-Mkit-Admin-Version` | `1` |
| `X-Mkit-Admin-Key-Id` | Key id. |
| `X-Mkit-Admin-Audience` | Canonical server origin. |
| `X-Mkit-Admin-Created-At` | Created milliseconds. |
| `X-Mkit-Admin-Expires-At` | Expiry milliseconds. |
| `X-Mkit-Admin-Nonce` | Lowercase hex nonce. |
| `X-Mkit-Admin-Digest` | `body:` plus the exact-body BLAKE3 hex. |
| `X-Mkit-Admin-Signature` | Strict Ed25519 signature, 128 lowercase hex digits. |

The verifier MUST select a current public key by key id, check its
validity bounds, compare audience and procedure, check the time window
and exact-body digest, and verify the signature before treating a
request as authenticated. The digest covers the exact HTTP request body
as received, including the Connect envelope prefix for streaming
procedures and before decompression. Reserializing protobuf JSON does
not reconstruct those bytes. The admin service MUST support the JSON
codec and MAY support the binary codec. A streamed response has no
signing effect on its request. Responses are not signed; the caller MUST authenticate the
server through TLS, except for an isolated loopback channel.
An admin request body MUST be at most 1,048,576 bytes (1 MiB) on the
wire and at most 1 MiB after decompression; a larger body receives
`invalid_argument`. A validly signed
oversize request is an authenticated failure and MUST be audited.
This request cap does not bound streaming response bytes.

Malformed headers, unknown keys, expired envelopes, and invalid
signatures receive `unauthenticated`. They are unauthenticated attempts
for §16.6 even when they contain a plausible key id. A valid signature
for a key lacking the required role receives `permission_denied` and
is audited.

### 16.3 Admin key list, roles, rotation and separation

The configured admin key list has §7.2's JSON shape, with a REQUIRED
nonempty `roles` array on each key. `version` is `1`; `keyId`, `alg`,
`publicKey`, `notBeforeMs`, and `notAfterMs` have exactly §7.2's
grammar and meaning. Roles are `lease`, `moderation`, `grants`,
`audit`, and `all`; duplicate and unknown roles and duplicate key ids
MUST be rejected when loading the list.
Each key's roles apply deployment-wide, with no per-key scope in this
version; a matching role satisfies §12.3's authorization for that scope.
The `all` role grants every procedure. A deployment MAY have several
concurrent keys with different role sets. A key with only `lease` MUST
NOT gain moderation authority through `SetLease`.

| Procedures | Required role |
|---|---|
| `SetLease` with `RENEWAL` or `POLICY`; every action satisfies the `lease_role_min_notice` rule below | `lease` or `all` |
| `SetLease` with `ADMIN`; any resulting effective state, including earlier suspension or deletion | `moderation` or `all` |
| `SetSuspension`, `Takedown`, `GetTakedown`, `ListTakedowns`, `Reinstate`, `AddBlock`, `RemoveBlock`, `SetLegalHold`, `ReadPreserved` | `moderation` or `all` |
| `ReleaseHold`, `Reinspect`, `ReleaseFlag`, `ResumeServing`, `WaiveObligations`, `PurgeCache` | `moderation` or `all` |
| `RegisterSshGrant`, `RemoveSshGrant`, `ListSshGrants` | `grants` or `all` |
| `ReadAuditLog` | `audit` or `all` |

`lease_role_min_notice` is a deployment parameter with a default of
24 hours (86,400,000 ms). It MUST be a positive duration. The notice
rule applies to every `SetLease` whose cause is `RENEWAL` or `POLICY`,
whatever the caller's roles; `cause = ADMIN` requires `moderation` or
`all` and MAY produce any resulting state. The server MUST evaluate the
rule at apply, with the backend clock, over the **lease-derived** state
only (§12.1 terms and inheritance); overrides are not considered,
because `SetLease` cannot change them. For every affected scope, let
`S` be the first instant at or after apply when the lease-derived state
is `suspended` or `deleted`, and `D` the first such instant for
`deleted`, both before and after the change. The change is permitted
only if `S_new ≥ min(S_old, now + lease_role_min_notice)` and
`D_new ≥ min(D_old, now + lease_role_min_notice)`, where an absent
instant is infinite. A change can therefore always extend or renew a
lease, including while an override suspends the repository, but can
never bring suspension or deletion earlier than the notice. The rule
covers every `SetLease` action: setting terms, setting permanent,
removing terms, and changes to a repository default that affect
inheriting refs. A violation MUST return audited `permission_denied`
without applying any change.

An admin public key MUST be distinct from every key used for another
role, including hook, write authentication, grant, receipt and notice,
URL token, and message authentication. There is no threshold signing
in this version. Rotation uses overlapping `notBeforeMs` and
`notAfterMs` bounds: a deployment adds a new key, changes signers,
then retires the old key after its outstanding envelope validity and
replay records expire. Retiring a key MUST NOT erase audit entries.
The private key and the list are distributed through deployment
configuration, not through an unauthenticated discovery endpoint.

### 16.4 Replay and idempotency

**Protocol requirement.**

The server MUST maintain a durable replay ledger keyed by
`(audience, key id, nonce)` until at least the envelope expiry.
After envelope authentication, the server MUST first look up that key.
For the same key, digest, and procedure, a completed retry returns the
stored result, including its response or error, even if the key's roles
have since changed. A different digest or procedure returns
`invalid_argument`; an in-flight retry returns `aborted`. For a new
nonce, it MUST atomically reserve the key with the exact-body digest
and full procedure before checking roles or applying effects. It MUST
store an authenticated wrong-role denial as the terminal result and
audit it once. The stored result MUST survive restart. A retry cannot
substitute a later signature to change the original actor or label.

The launch `ReadPreserved` subset has the byte-free replay exception specified
in §18. An accepted `Takedown` whose durable denial activation is unfinished
returns retryable `unavailable` with the same takedown id while resuming its
cursor. Its nonce and operation results become completed only after every
requested denial is active, including after interrupted acceptance and recovery. Completed
results retain the stored-response and role-independent replay rule above.
Completed denial activation still returns `complete = false` for the remaining
launch takedown lifecycle (§18).
A nonce reservation that has not durably accepted an action still returns
`aborted`. All other procedures retain the rule above.

`Takedown`, `Reinstate`, `AddBlock`, `PurgeCache`, and a takedown-flagged
`SetSuspension` additionally require a client
`operation_id` of 1–128 bytes in `[A-Za-z0-9._:-]` (§6.6). Across
different nonces, the same operation id and identical logical request
MUST return the first operation's identity and result, including a
pending result; reuse for different content or procedure MUST return
`invalid_argument`. This ledger MUST persist for at least as long as
the audit log is retained. It prevents a caller retry after its
300-second signing window from starting a second rewrite or purge.
The role check MUST precede the `operation_id` lookup. An identical
logical request means the same full procedure and the same signed
request digest. `Takedown` and takedown-flagged `SetSuspension` share
this operation-id space; cross-procedure reuse is `invalid_argument`.

The server MUST commit an accepted action and its audit entry durably
before reporting success. A long-running action MAY report `complete`
as false; its id identifies follow-up status. A retried operation MUST
NOT append another action entry or repeat already committed effects.

### 16.5 Procedures

The following table names the request and response message for every
procedure. All nonempty repository identities follow STC §7.4; refs
follow SPEC-REFS §3, object and grant ids are 32 bytes, and reasons and
operator labels are bounded UTF-8 without controls (512 and 128 bytes
respectively). Invalid scope, enum, id, bound, or missing required
field is `invalid_argument`. A supplied `reason_token` in `Takedown`,
`AddBlock`, or `SetSuspension` MUST match §14.6 **Signed redaction
notice**. It is REQUIRED for `Takedown`, for `SetSuspension` when
`is_takedown` is true.
Otherwise it is optional; a manual block without a token records the
registered `manual` token, including when that block starts a
takedown. A `block_action_id` uses the §6.6 identifier grammar. The free-text `reason`
is private audit text and MUST NOT enter notices, Events, or any public
surface. A target absent after authentication is
`not_found`, unless the row says otherwise. Every authenticated call,
including a read or failed attempt, is audited under §16.6. The
listed error codes are in STC §5's Connect vocabulary; all procedures
also permit `unavailable` for a retryable backend failure and
`internal` for a failure that cannot safely be classified.

| Procedure: request → response | Required input and effect | Additional errors |
|---|---|---|
| `Takedown`: `TakedownRequest` → `TakedownResponse` | `operation_id`, non-UNSPECIFIED level, `reason_token`, reason and target; CONTENT takes 1–256 distinct blob or ChunkedBlob manifest ids in indexed mode, with no repository or namespace field. REPOSITORY takes one repository and NAMESPACE one namespace, with no object ids (§14 **Terms, levels and scope**). It starts §14 **Lifecycle and completion** and returns its id and completion state. A REPOSITORY or NAMESPACE takedown is equivalent to `SetSuspension{is_takedown = true}` for the override, takedown record, Event, and cache effects. Any lease receipt produced under §15 is available only through `GetReceipt`; this response carries none. | `failed_precondition` for content level in opaque mode or a target of the wrong object kind; `aborted` for concurrent work. |
| `GetTakedown`: `GetTakedownRequest` → `GetTakedownResponse` | `takedown_id`; returns the §14 lifecycle record without preserved bytes. | `not_found`. |
| `ListTakedowns`: `ListTakedownsRequest` → `ListTakedownsResponse` | Optional repository or namespace scope (absent means all), `page_size` 1–100 and opaque page token; returns records and next token. | `invalid_argument` for a foreign or malformed token. |
| `Reinstate`: `ReinstateRequest` → `ReinstateResponse` | `operation_id`, `takedown_id`, reason; performs §14 **Reinstatement** while preserving any legally held record. For repository or namespace reinstatement, any lease receipt produced under §15 is available only through `GetReceipt`; this response carries none. | `failed_precondition` if restoration is forbidden by another active takedown; `aborted` for concurrent work. |
| `AddBlock`: `AddBlockRequest` → `AddBlockResponse` | Object id, reason and `operation_id`, plus `reason_token` if it starts a takedown; adds a distinct manual action under §14 **Blocklist**, even if other actions already block the id, and returns the new `block_action_id`. A manual block with known holders starts the §14 takedown lifecycle; the response supplies its takedown id and completion state. | `aborted` for concurrent work. |
| `RemoveBlock`: `RemoveBlockRequest` → `RemoveBlockResponse` | `block_action_id` and reason; removes only that manual action with no takedown id under §14 **Blocklist** and reports `removed`. Other actions continue to block the id, and removing the action does not undo a takedown tombstone. | `failed_precondition` for a takedown-sourced action, which only §14 **Reinstatement** can lift. |
| `SetLegalHold`: `SetLegalHoldRequest` → `SetLegalHoldResponse` | Takedown id, `enabled`, reason; changes preservation legal hold under §14 **Preservation store**. | `failed_precondition` if disabling would violate an active hold. |
| `ReadPreserved`: `ReadPreservedRequest` → stream `ReadPreservedResponse` | Takedown id, object id and offset; returns ordered chunks with exact offsets and one `last`, solely from §14 **Preservation store**. | `not_found` if not preserved; `failed_precondition` if retention has ended. |
| `SetSuspension`: `SetSuspensionRequest` → `SetSuspensionResponse` | Exactly one repository or namespace scope, `suspended`, `is_takedown`, reason, and `reason_token` when `is_takedown` is true; sets the separate §12.2 override and returns its state. With `is_takedown = true`, `suspended` MUST be true and `operation_id` is required; the call starts a §14 **Lifecycle and completion** takedown record and returns its id and completion state. That override can be lifted only through §14 **Reinstatement**. `receipt` carries the §15 receipt when enabled and is empty otherwise. | `failed_precondition` for an attempted takedown bypass. |
| `SetLease`: `SetLeaseRequest` → `SetLeaseResponse` | Exactly one scope and action, non-UNSPECIFIED cause; applies §12.3. `receipt` MUST carry the §15 lease receipt when receipts are enabled and be empty otherwise. | `failed_precondition` for per-ref terms in opaque mode; audited `permission_denied` for ADMIN cause without `moderation` or `all`, or a §16.3 notice-rule violation on a `RENEWAL` or `POLICY` change. |
| `ReleaseHold`: `ReleaseHoldRequest` → `ReleaseHoldResponse` | Repository, inspector, inspection id, reason; overrides and satisfies that held prepublication obligation after review. It MUST schedule a new non-blocking QUARANTINE-phase re-inspection (§11.2) and return its `new_inspection_id`. A later reject becomes a takedown as for a postpublication verdict. This call MUST NOT release a hold whose verdict carries flagged ids. | `failed_precondition` for a hit or a hold whose verdict carries flagged ids; use `ReleaseFlag` for the latter. |
| `Reinspect`: `ReinspectRequest` → `ReinspectResponse` | Repository, inspector, old inspection id, reason; schedules deliberate re-inspection and returns a new id, superseding the old logical call (§11.3). It does not itself waive or release a hold. | `failed_precondition` for a completed hit. |
| `ReleaseFlag`: `ReleaseFlagRequest` → `ReleaseFlagResponse` | Repository, flagged object id, reason; admin review releases the flag and all holds derived solely from it, schedules §11.2 re-inspection on release, re-evaluates blocked advances (§11.3), and reports their count. It cannot undo a takedown. | `failed_precondition` for an active hit/takedown. |
| `ResumeServing`: `ResumeServingRequest` → `ResumeServingResponse` | Repository, inspector, inspection id, reason; after review releases the postpublication quarantine serving stop (§11.3), unless another hold or takedown still applies. | `failed_precondition` while another stop applies. |
| `WaiveObligations`: `WaiveObligationsRequest` → `WaiveObligationsResponse` | Repository, inspector, nonempty distinct `(ref, sequence)` targets with positive per-ref §10.2 sequences, and reason; explicitly waives only that inspector's outstanding obligations for those advances and re-evaluates clearance (§§10.2, 11.3). Inspector removal alone has no effect. | `failed_precondition` for hit, flag, or another inspector's obligation. |
| `RegisterSshGrant`: `RegisterSshGrantRequest` → `RegisterSshGrantResponse` | 32-byte principal and signed grant bytes; performs SPEC-WRITE-GRANTS §10 registration checks and returns the grant id. | `permission_denied` for a grant whose grantee differs from the principal; `failed_precondition` for a revoked epoch. |
| `RemoveSshGrant`: `RemoveSshGrantRequest` → `RemoveSshGrantResponse` | Principal and grant id; removes the registration and reports `removed`; existing grant revocation rules still apply. | `not_found` for an unknown principal. |
| `ListSshGrants`: `ListSshGrantsRequest` → `ListSshGrantsResponse` | Principal, `page_size` 1–100, opaque token; returns its registered grants and next token. | `invalid_argument` for a foreign or malformed token. |
| `PurgeCache`: `PurgeCacheRequest` → `PurgeCacheResponse` | `operation_id`, exactly one repository or namespace, optional paths/object ids/refs selection and reason; schedules a manual §16.7 purge and returns its `purge_id`. Empty selectors mean a whole-repository or whole-namespace purge. | `failed_precondition` if no purge interface or sink is configured. |
| `ReadAuditLog`: `ReadAuditLogRequest` → stream `ReadAuditLogResponse` | `from_seq` at least 1, `page_size` 1–100; streams pages of entries, next sequence, chain head and retained checkpoint (§16.6). | `invalid_argument` if the requested prefix was pruned. |

`SetLease` accepts `terms` or `remove` for a repository default,
and `terms`, `permanent`, or `remove` for a ref. `permanent` is an
explicit per-ref override distinct from inheritance. Terms require a
nonnegative grace and suspension duration and a valid expiry. The
server MUST allow shortening, evaluate the new effective state
without waiting for background work, and obey §12.1's repository completion
bound. Removing a default makes undeleted inheriting refs permanent;
removing per-ref terms restores the default or permanent retention if
none exists. Neither operation resurrects a deleted lease, ref,
pointer, or membership. A ref deleted by lease remains blocked until
an authorized `SetLease` assigns new terms. `RENEWAL` maps to
`LEASE_CAUSE_RENEWAL`, `POLICY` to `LEASE_CAUSE_POLICY`, and `ADMIN` to
`LEASE_CAUSE_ADMIN` in §12.4. A direct administrative suspension without
a takedown emits `ADMIN` at the scope where it is set. A takedown suspension or its
reinstatement emits only a `TakedownTransition`, never an additional
`ADMIN` `LeaseTransition` (§12.4). Lease receipts attest only a
committed live state under §15; an accepted request is no promise of
future retention.
The §16.3 `lease_role_min_notice` check applies to every `SetLease`
action and every affected inheriting ref. An earlier suspension or
deletion requires `moderation` or `all` with `cause = ADMIN`.

`RegisterSshGrant` MUST verify SPEC-WRITE-GRANTS §7 steps 1, 3, 4,
and 5, and MUST reject a grant whose grantee is not the transport
principal. Registration is server-side; no grant header is added to
ssh or enc. Grant listing and removal affect registrations, not the
owner-signed grant or namespace epoch.

### 16.6 Audit log

**Protocol requirement.**

The admin audit log is append-only and tamper-evident. Each entry has a
gapless unsigned `seq`, backend `recordedAtMs`, `actor`, optional
`operatorLabel`, `procedure`, lowercase `requestDigest`, `nonce`,
optional `operationId`, target identities, `result` (`code` and bounded
message), `details`, `prevHash`, and `entryHash`. An authenticated
request's actor is its admin key id and its procedure is the full
Connect path; its operator label is optional text in the signed body
and MUST NOT be used as authorization. Automatic actors are exactly
`system:inspector`, `system:timer`, or `system:relay`, with a stable
`system:<actor>/<action>` procedure and empty nonce and request digest. These
are event categories for inspection, lifecycle, and propagation work; they do
not require timers or a relay implementation. Targets MUST be
stable canonical identities, not content bytes. Messages and details
MUST each be at most 512 bytes of UTF-8; details MUST contain no
credentials, private keys, bearer tokens, preserved bytes, or object
content. The log has no update or delete API.

The canonical audit entry is a JSON object with lower-camel field
names matching `AuditEntry`, excluding `entryHash`; byte strings are
lowercase hex and integers are decimal JSON strings. Every entry MUST
contain `seq`, `recordedAtMs`, `actor`, `procedure`, `requestDigest`,
`nonce`, `targets`, `result`, `details`, and `prevHash`. The
`requestDigest` MUST include the `body:` prefix for an authenticated
request. System entries use empty strings for `requestDigest` and
`nonce`. Empty `targets` is `[]`; empty `details` and `result.message`
are `""`. The `result` object always contains `code` and `message`.
Success uses the audit-only code `ok`; failures use STC §5 codes.
`operatorLabel` and `operationId` are omitted when empty and included
otherwise. `prevHash` is the previous 32-byte hash or 32 zero bytes
for the first entry. For each entry the server MUST compute:

```text
entryHash = BLAKE3("mkit-admin-audit:v1" || JCS(entry including prevHash))
```

`mkit-admin-audit:v1` is a permanent hash domain under
SPEC-CONVENTIONS §4. The concatenation has no separator beyond the
literal domain bytes. The server MUST preserve sequence continuity
and verify the chain on export. The server MUST append every
authenticated call, successful or failed, with its result code, including
wrong-role and invalid-argument requests after identity verification.
Every takedown, reinstatement, block, legal hold, suspension, lease
change, release, re-inspection, waiver, grant change, and purge MUST
append an entry.
Automatic inspector hits, lifecycle transitions, propagation-discovered late-holder
takedowns, releases, and purges MUST also have system entries. An
unauthenticated attempt MUST go to metrics only, never the audit log;
otherwise unauthenticated callers could flood durable audit storage.

The log MUST be retained at least through the longest active
preservation retention under §14 **Preservation store**, including
legal holds. Background work MUST audit preservation-byte purge when retention
ends and no legal hold remains. Preservation bytes and blocklist entries remain outside
§13 GC; their retention and purge are governed by §14 **Preservation
store**, §14 **Blocklist**, and audited `SetLegalHold`, `RemoveBlock`,
and `Reinstate` calls here. Takedown and reinstatement action records
needed to replay after any restorable snapshot, and active blocklist
actions, MUST persist independently of audit-log pruning and survive
snapshot restore. Restore under §14.9 **Interaction with GC, restore and caches**
MUST read those action records and replay takedowns and reinstatements
recorded after the snapshot, in action order, before serving restored
state. Pruning an eligible audit prefix MUST keep
its final `(seq, entryHash)` as a checkpoint; the next retained
entry's `prevHash` MUST equal that hash. Pruning MUST NOT remove an
entry needed to verify an active preservation interval. Before any
pruning, the checkpoint is `(seq = 0, hash = 32 zero bytes)`; an empty
log also has that chain head.

Informative: an external, durable anchor of each exported chain head
is needed to detect truncation of the tail by an actor who controls the log.

`ReadAuditLog` is admin-only in v1. Each page MUST include the retained
checkpoint and a chain head `(chain_head_seq, chain_head)` from one
consistent snapshot, so an exporter can verify continuity and detect
truncation. Pages MUST be ordered by seq and `next_seq` MUST identify
the first entry not in the page. A request at the current head plus one
returns an empty page with the head; `from_seq <= checkpoint_seq`
returns `invalid_argument`. Reading the log is itself audited, after its
snapshot is fixed, so it cannot change the head reported by that read.

### 16.7 Remote cache purge

When a remote purge sink is configured, `HooksService/CachePurge`
delivers a `CachePurgeRequest` through §5's durable outbox, signed
under §7.1. The request has an audience-unique `purge_id` using
§6.6's reservation-id grammar; the mkit server audience, exactly one
of repository identity or namespace identity, a non-UNSPECIFIED trigger,
and optional origin-relative URL paths, 32-byte object ids, or full
ref names. A repository selector with no paths, ids, or refs requests a
whole-repository purge; the analogous namespace selector purges the
whole namespace. A namespace-scoped request is delivered once, unchanged;
the server MUST NOT expand it into per-repository requests, and the
receiver applies the namespace selector. URL paths are matched by exact path. Paths MUST begin
with `/`, contain no query or fragment, and
MUST NOT contain credentials. A delivery retry MUST retain the same
body and purge id but use a fresh hook signing nonce. The response is
empty. The receiver MUST deduplicate by `purge_id` and treat a repeat
as the same purge. Delivery is at least once, has no ordering guarantee,
is counted in §5's combined backlog, and remains pending until
acknowledged. Delivery failure follows §8's retry behavior.

The triggers are `TAKEDOWN`, `SUSPENSION`, `LEASE_DELETION`,
`VISIBILITY_CHANGE`, and `MANUAL`. A hit or quarantine serving stop
under §11.3, a §14 takedown, an administrative suspension, lease
deletion, and visibility change MUST invalidate server-side caches
immediately and request a shared-cache purge before stale bytes may
again be served. Where shared caches exist, the server MUST use the configured remote sink or the
deployment's internal purge interface. A deployment with shared caches
requiring invalidation MUST fail closed if neither is configured. A
deployment without shared caches still invalidates its server-side
caches and needs no remote sink. No remote outbox row is needed when no remote sink is
configured. A quarantine serving stop uses `SUSPENSION` and an
inspection hit uses `TAKEDOWN`. `PurgeCache` selects the `MANUAL` trigger and is audited;
automatic purges are audited with their system actor. §14
**Interaction with GC, restore and caches** governs takedown ordering.

## 17. Custom backends, backup and migrations (reserved, M5)

Stored formats are not yet a compatibility contract before 1.0; a store may
need a reset across versions.

Reserved: this section is specified with M5 (see the version history).

## 18. Conformance scope

**Protocol requirement.**

A server conforms to one of three profiles and advertises which through
`GetServerInfo` (STC §2.1). A client MUST NOT assume a feature of the full
profile unless the server advertises it.

**Core profile.** The server implements §2–§8 (a server without remote hooks
implements §2–§5) and:

- **Published view (§10).** It configures no inspector, so nothing is ever
  held or pending and every caller's view is the live view; §10 holds
  trivially. It MUST NOT accept inspector configuration (§11) and advertises
  `async_inspection = false`.
- **Storage leases (§12).** It enforces no storage leases and advertises
  `leases = false`. Content is retained permanently (§12.1). It MUST NOT
  accept lease terms.
- **Garbage collection (§13).** It deletes no repository content, so §13
  does not apply. Unreferenced upload bytes may accumulate until a full-profile
  server collects them.
- **Indexed mode (§9).** It does not offer indexed mode and advertises
  `indexed_mode = false`. Indexed deployments use the launch or full profile.
- **Takedown, receipts and admin (§14–§16).** It offers none of them: its
  receipt key fields are empty (§15.5), it issues no redaction notices, and it
  mounts no admin service (§16.1).

**Launch profile.** An indexed server MAY implement §§2–11, including
synchronous inspection and HTTP object serving without storage leases, while
advertising `leases = false`, retaining all repository content
permanently and disabling GC. It MUST refuse lease terms and issue no storage
receipts. Receipt key fields MUST follow §15.5: empty without a configured
receipt-and-notice key; populated when takedown requires that key. The lease, GC
and receipt-issuance requirements of §§12–13 and §15 do not apply to this profile;
§15.5 key publication still applies when takedown is enabled. Publication
Event sinks are excluded at launch. Inspection and
serving stops remain governed by §§10–11, subject to the launch amendments:
only synchronous, fail-closed inspection, with the whole-advance input bound
advertised as optional `inspection_max_objects` under §11.1.
Inspection is optional; configured inspection MUST enable scanner byte
retrieval following §11.4: a dedicated capability and
scanner-signed request, checked against current open upload tickets and
global denial, with no inline bytes or durable attempt-lifetime state.
The inspected set is every `Blob` and `ChunkedBlob` entry of the added packs,
surplus included and ids deduplicated, using `BLOB` and `CHUNKED_FILE` respectively;
chunk-only blobs MAY be `BLOB` and `CHUNK` is unused (§11.1). Earlier membership
was already inspected before its membership apply, including membership whose
publication is pending on asynchronous membership projection (§11.1). Enabling inspection
over existing, unscanned content is unsupported: inspection deployments MUST
start from an empty store.

**Reference-server behavior.** Inspection enumeration reads frame/checkpoint pages
of at most 1,000 rows, without a tree walk, reference pages, or object-store reads.

**Protocol requirement.**

Synchronous inspection covers added-pack file entries under §11.1. A ref-only
operation over previously admitted members does not require repeating that
inspection. This does not waive §10.2 publication dependencies,
resulting-pair requirements, or §14.2 pack-deduplication denial.
Implementations MUST document any historical-support limits of the enabled
publication verifier; the Workers operator guide does so for the Worker
adapter. Enabling inspection over an existing unscanned store remains
unsupported.
PRE_RECEIVE quarantine rejects with 403 and commits nothing. Startup MUST
refuse asynchronous or unavailable-publish inspectors and clear deadlines.

**Reference-server behavior.** The reference launch server permits at most four
inspectors, one batch each, and at most 10,000 inspected entries per advance.
Startup rejects a fifth inspector.

**Protocol requirement.**
The server MUST NOT create durable inspection continuations, outstanding
inspection obligations or inspection holds at launch. No durable inspection-mode marker is required:
disabling inspection stops only future scanning. Async inspection, holds,
quarantine suspension, inspection review procedures, complete full-profile
classification and unrestricted whole-set multi-batch inspection are deferred
and not implemented. The profile does not waive takedown
or admin requirements applicable to its configuration. The profile and its
permanent-retention/disabled-GC policy MUST be documented in deployment
capabilities. It MUST NOT claim full-profile conformance.

A deployment selects the launch profile explicitly. Namespace
policy is an allowlist, or open with explicit unsafe-open acknowledgment;
under open policy, takedown discovery is incomplete. HTTP serving/URL tokens,
remote hooks, inspection/retrieval, and admin/takedown are independent
opt-ins. Each MUST validate its complete configuration and key-role
separation at startup. Takedown MUST refuse activation without §14.7's
preservation store, explicit retention and preservation signing key, and a
configured purge sink; an embedder MAY provide a custom purge sink and local
invalidation. A server MUST NOT advertise proof serving it does not implement;
the shipped native and Worker HTTP handlers refuse permitted proof queries with
416 as specified by [SPEC-HTTP-OBJECTS §3](SPEC-HTTP-OBJECTS.md#3-response-precedence).
No new profile/proof wire field is implied. Selecting the profile, its configuration
names, platform requirements and deployment procedure belong to the
deployment's operator documentation; the Cloudflare Workers adapter's are in
[the Workers operator guide](../operations/workers.md).

**Full profile.** The server implements every section that applies to its
configuration, including §9–§16. An indexed deployment MUST support per-ref
storage leases (§12.1).

**Reference-server behavior.** After a committed timer write, the Worker adapter MUST retry a failed alarm
scheduling call at most twice inline. If scheduling still fails, it MUST return
the error instead of acknowledging the write and mark its alarm state unarmed
so the next activation checks the earliest durable timer again.

**Protocol requirement. Launch admin subset.** A launch deployment MAY explicitly offer the following
admin foundation without claiming the full §16 procedure set. It MUST state
its supported subset in its deployment documentation, and MUST NOT advertise
unimplemented operations. The remaining lease, GC, inspection and takedown
requirements follow the deployment's declared launch scope.

| Surface | Launch foundation |
|---|---|
| Signed admin framework (§16.1–§16.4) | Dedicated role keys, exact request signatures, durable nonce/result replay and persistent operation-id deduplication. Disabled unless keys are configured. |
| Audit (§16.6) | Gapless chain and ReadAuditLog, including authenticated reads/failures and automatic purge actions. |
| Purge (§16.7) | Automatic durable purge intents and signed retry delivery; serving fences remain authoritative before acknowledgement. |
| Manual PurgeCache | Optional asynchronous acceptance and audited completion below. |
| Other admin procedures | Supported only by completed launch work; never advertise unimplemented operations. |

**Reference-server behavior.** The adapter acceptance subset builds the embedding fixture with a locked
wasm dependency graph and exercises paid indexed publication, published reads,
URL tokens, supplied hooks and durable outcome retry with takedown off and no
inspection. A separate fault-enabled case verifies slice recovery. This subset
does not establish conformance for optional takedown or inspection; their
retained scenario harnesses and core tests remain necessary when enabled.

**Protocol requirement. Lean launch takedown.** A launch CONTENT `Takedown` names
one repository for canonical source validation and exactly one of 1–256 distinct
blob/manifest `object_ids` or one whole `pack_id` (admin schema field 9). This
request shape overrides §16.5's repository-free CONTENT shape for this subset.
An omitted level selects CONTENT; an omitted `reason_token` selects `manual`.
Supplied tokens MUST retain §14.6's grammar; reason remains private audit text.
Successful acceptance MUST durably bind the operation to verified immutable
action descriptors and activate every requested denial before returning success.
It returns `complete = false`; acceptance MUST NOT imply verified preservation,
holder discovery or repository/global completion. The pending record MUST retain
preservation work. Production takedown and `ReadPreserved` activation MUST be
available only when admin keys, the explicitly selected launch profile,
enabled takedown, indexed mode, and the complete §14.7
preservation configuration are valid. This includes the restricted
preservation store, explicit positive retention, receipt signing and
publication keys, and a configured cache-purge delivery (a signed remote hook,
or an embedder-supplied purge sink). Startup MUST refuse partial or
invalid configuration. The
preservation core, restricted admin catalog and §14.7 configuration are all
required for launch, as are the launch conformance gates. This implementation
does not waive §14's full completion requirements. The supported catalog is `Takedown`,
`PurgeCache`, `GetTakedown`, `ListTakedowns`, `ReadPreserved`, `SetLegalHold` and
`ReadAuditLog`. Inspection is sync-only: there are no launch inspection hits or holds.
The `ReleaseHold`, `Reinspect`, `ReleaseFlag`, `ResumeServing` and
`WaiveObligations` operations, reinstatement and signed notices are post-launch.
Future inspection hits MUST enter through durable intake and MUST NOT resolve
without their applicable real completion. Retained advances MUST NOT be rewound
or cleared by accepting a request or preserving bytes.

This profile permits an unresolved request after verified preservation while
§14.3's rewrite, substitution, tombstones, notices and physical serving deletion
remain unimplemented. It MUST retain immediate global denial and durable
acquisition/discovery responsibility. It MUST NOT report repository/global
completion, sign completion notices, or advertise those missing capabilities.
For §14.2 push rejection it MUST return `permission_denied` with public message
`object blocked`; the §14.6 signed-notice detail is omitted in this subset.
The full profile retains every §14 completion and signed-detail requirement.

Launch holder discovery MUST first read pack/extracted-object holder records
and then durably sweep all named ids. Finite Multi addressing MUST use the
complete configured namespace allowlist; Single addressing MUST sweep its sole
Root. Under `namespace_policy = any`, normal global denial and preservation
from the named repository MUST remain supported. Discovery MUST sweep provable
named-namespace and known-holder namespaces, but MUST NOT report discovery or
repository/global takedown completion under Any. Known holders MUST NOT
substitute for exhaustive roots. Each sweep MUST persist its discovery boundary
and progress, account for in-flight acceptance and outstanding projection effects,
and retry incomplete observations. Finishing a sweep alone does not establish
takedown completion.

**Reference-server behavior.** The launch reference implementation lacks an
exhaustive catalog under open namespace policy. Its finite-root sweep retains a
time cut and waits for relay watermarks before reading the union of repository
and active-storage registries. Indexed multi-repository storage and ticketed
uploads at threshold zero are its launch fixture selection, not protocol
placement requirements.

**Protocol requirement.**

The restricted §14.7 record MUST bind verified canonical ids, kinds, sizes and
bytes, including manifest order and every chunk, to the action and provenance.
Acquisition and discovery progress, currently known holders, affected old packs
and known signer metadata MUST be durable; missing final holders-at-completion
MUST remain explicitly incomplete. Admin status MUST distinguish acceptance,
pending acquisition, verified preservation, discovery progress, legal hold and
actual completion, without exposing bytes. Preservation success MUST NOT imply
discovery or takedown completion. The §14.7 retention, receipt-and-notice signing
key and published §15.5 key-list startup requirements remain mandatory even
though this profile issues no storage receipts or notices.
Retention purge MUST be audited and own only that action's preserved copy;
one action's purge MUST NOT delete another action's copy or remove denial.
Legal hold MUST guard timed purge. A purged copy or an expired copy without an
active hold MUST fail closed on read.

The existing v1 `TakedownRecord` reports `acquisition_pending`,
`preservation_verified`, `discovery_status`, `legal_hold` and
`preservation_purged` separately from `complete`. Discovery status is one of
`pending`, `in_progress`, `incomplete` or `complete`; an Any deployment MUST
NOT report `complete`. Verification is historical canonical verification,
not a promise of availability after purge or retention expiry. The launch
profile MUST report actual takedown `complete = false` while its completion
obligations remain unresolved.

For launch `ReadPreserved`, the nonce ledger MUST contain only a bounded,
byte-free result descriptor binding the request to its action/object/range or
terminal error. It MUST NOT cache preserved response bytes. A completed nonce
retry MUST NOT repeat workflow effects; each attempt to read bytes MUST perform
fresh current-key/role, retention/legal-hold and availability checks, and audit
its acceptance before any byte is emitted. This is an explicit exception to
§16.4's stored-response/unchanged-role retry rule. Each attempt MUST create a
fresh bounded stream and verify each emitted piece against the durably verified
copy before release; preflight verification followed by unchecked reads is
insufficient. Retention/hold and purge ownership MUST be checked before each
piece is emitted. Responses MUST have exact ordered offsets and exactly one `last`
only on success. Offset equal to size returns an empty final response; offset
greater than size is `invalid_argument`. Corruption, retention loss or backend
failure during streaming MUST terminate with a Connect error and be audited,
without preserved bytes in audit, logs or errors. An error MUST NOT emit `last`.

Manual `PurgeCache` MAY be supported independently: acceptance MUST atomically
commit its audit, replay result, and durable purge responsibility, return the purge id,
and expose completion through the audit log rather than synchronous delivery.

Automatic purge delivery MUST retain durable intent with the triggering state
change and audit responsibility. Delivery MUST NOT duplicate an audit entry for
the same source event. Audit records retain the source event's occurred time;
purge delivery MUST NOT depend on successful audit delivery.

**Reference-server behavior.** The reference server records purge intent,
delivery scheduling, and audit event in the source atomic unit. A relay target
commits audit append, source deduplication, and delivery-frontier advancement
together. Its audit chain follows arrival order.

**Protocol requirement.**

The mapping of profiles to conformance-suite cases is specified with M5.
Local Workers wire diagnostics retain recovered connection losses and report
existing retries as CI warnings. The harness connects directly to workerd
without changing the compiled Worker or suite assertions; see the [operator guide](../operations/workers.md#wire-connection-diagnostics).
This evidence does not change conformance verdicts, replay policy or the
client-visible error contract.

### 18.1 Protocol conformance tiers

**Protocol requirement.** Conformance applies to any server offering the
specified feature. Tier 1 uses only ordinary transport requests. Tier 2 uses
a versioned, test-only wire control interface to reach fault and recovery boundaries
and obtain typed, layout-independent atomic observations. The
[conformance runner and coverage table](../../rust/crates/mkit-server-conformance/README.md)
specify version 1 capability negotiation, HTTP binding, case names, and declared
skip semantics. Its HTTP binding is normative for black-box runs: servers under
test MUST implement the specified routes, and runners MUST drive them over HTTP.
An in-process trait MAY supplement that binding; no case may require the trait.
The conformance profile MUST declare optional features (transport writes, wire
authority getter/setter, authority fencing, fork, and the relay-lag bound) as well
as supported controls. Cases for an undeclared feature report `not applicable`
with its name. A declared skip instead records a known coverage gap in a declared
feature. Generation-race cases use the test-control authority bump, not the wire
setter. The protocol-defined pause boundaries are:

- `before_acceptance`: before the final guarded acceptance decision;
- `after_durable_acceptance_before_response`: after the complete accepted unit
  is durable, before the operation response is released;
- `after_response`: after that response is released;
- `before_published_clearance`: before the guarded decision that makes eligible
  membership and the published value reader-visible.

Boundary names identify observable decisions, not implementation steps. A
control binding MUST NOT claim support for a boundary it cannot reach. A control
request MAY select a protocol decision class, including `fork_acceptance`,
`fork_progress`, or `fork_source_proof`, and an occurrence to select an advancing
commit. For `fork_source_proof`, `before_acceptance` means after every
destination membership effect is staged, before the final source proof is
obtained. The binding MUST preserve that ordering when it advertises the
capability. The additional class `fork_destination_claim` selects the first
atomic decision excluding competing destination creation or writes.
`writer_authority_ready` selects ordinary signed write acceptance after reusable
write authority has been acquired; resumption MUST exercise that retained
authority. Bindings advertise these classes through
`decision.fork_destination_claim` and `decision.writer_authority_ready`.
Race cases use these boundaries to assert one winner without prescribing lease
representations or requiring a reverse ordering once writer authority is usable.
Source-change controls commit the selected source move,
unpublication, read-access revocation, or pack denial before returning; they
MUST NOT change the destination. This reaches each guarded decision without
naming engine steps. The runner may request graceful restart or host-supported
kill-style restart,
authority-generation changes, clock pinning or advancement, pause/resume, and
an atomic observation of typed protocol state. Unsupported operations require
declared skips with reasons. These controls MUST be disabled in production
builds and MUST NOT become public transport procedures. A skip does not establish
compliance with the asserted protocol rule.

**Reference-server behavior.** The optional NamespaceStore SPI suite tests
mkit-server adapters. Other conforming servers need not expose that API, its
key layouts, or its internal batch representation.

## 19. Version history

Informative: historical entries describe reference implementation changes as
well as protocol revisions. They do not make a reference storage layout or
scheduling mechanism a requirement on other conforming servers.

| Version | Status | Change |
|---|---|---|
| 1 | draft | Classify protocol guarantees independently of storage placement and orchestration. Specify atomic signed-ref acceptance, replay recovery and durability, guarded fork acceptance and its declared reference-server gaps, and protocol-defined tier-2 pause boundaries. No public wire shape changes. |
| 1 | draft | The membership-lag `unavailable` (§9.4, §9.7) carries an empty `MembershipNotVisible` detail; code, message and status are unchanged. Additive; no stored-format change. |
| 1 | draft | Fork job rounds (§9.9): a deployment without pack-level denial builds no cleared set (a later switch to denial takes a full first walk); the pre-admission plan is carried into the job when it fits one slice, after an equality check of the source pair; and independent pack units of planning and publication overlap in waves, the packmap head last. No wire, stored-row or response change. |
| 1 | draft | Embedded dispatch for a fork (§9.9): a typed in-process entry that authenticates, runs the deployment guard, recognises a completed replay with fail-closed evidence and runs the embedder's pre-dispatch policy before `fork_repo`. Additive API; no wire change, no stored-row change. |
| 1 | draft | Document scoped heavy extraction regression scheduling in §20; no runtime, wire, or conformance requirement change. |
| 1 | draft | Portable decision completeness (§3.1): a ticketed decision guards every ticket row it examined, the inline storage counter and the authority observation; a ref that moved after custom admission is a retryable ref conflict on the ticketed path too; a stored fast-forward refusal on an `ANY` expectation compares the pinned ref value; the fact-to-class table is published. Reference-server behavior only; no wire change, no stored-format change. |
| 1 | draft | Server-side fork (§9.9): a durable, resumable job that gives an empty destination the published membership of one source branch (packmap chain, listed packs and external-base packs), the cleared set and the flagged packmap head that bound later publication walks, and admission bound to the job. Additive: witness boundary flag (`m`/`pm` value of 20 bytes), `fj` and `fo` rows, timer kind 16, `Procedure::Fork`; the embedder-facing `ForkRequest` with its canonical signed body, `Pipeline::fork_repo`, the source-read and destination-write authorization, a hard-bound admission charge, and additive hook fields (`Operation.fork`, `AdmitRequest.fork`). No Connect wire change; no stored-row version change. |
| 1 | draft | Authority-generation setter and getter without a namespace record under `any`; authority-mode registration and the refusal of unregistered writes (§6.2.2); the `ag` guard on the fenced namespace-creation batch; one-batch replacement of a stale-generation upload ticket (§6.2.1). No wire change; no stored row changes. |
| 1 | draft | Opt-in authority-owned namespace grammar and trust model (§6.2.2), wildcard generation-key scopes, refused owner statements, and hook writer authority for owner-view operations. Default self-certifying deployments retain their behavior. |
| 1 | draft | Document retained local Workers wire connection-loss diagnostics (§18); no conformance, runtime or wire change. |
| 1 | draft | Bounded request-local reader graph proofs (§10.1): captured roots, fixed scope/expiry, decoded local edges and live security checks. No persisted cache, stored-row or wire change. |
| 1 | draft | Exact per-repository stored-bytes accounting (§6.5.1): a per-repository counter and counted-pack markers in the coordinator, counted exactly once per pack under D34 by the coordinator's relay hook; additive `Outcome.repo_storage_changed` (field 11) carrying the absolute total and a monotonic version; admission `new_to_repo_bytes` observes whether the pack is already counted. `Committed.new_to_repo` is documented as an observation. New stored rows `rb` and `rn`, and a new terminal reservation row state; no existing row changes. |
| 1 | draft | §10.2 binds publication evidence to the publication state it was computed against (generation, sequence and deletion boundary) and requires new evidence or a retryable refusal on any difference; execution-capacity exhaustion is `unavailable` with one request allowance across preparation, dependency visibility and final-apply retries, and unsupported historical capacity is a terminal stop. §9.3 distinguishes per-lookup index caps (permanent) from capacity. No stored-row or wire change. |
| 1 | draft | §17 no longer promises that rows written by 0.5.x keep decoding: stored formats are not a compatibility contract before 1.0. No behavior change. |
| 1 | draft | Clarifies publication verification: a verified member terminates only the direct-child check and waives no §10.2, §14.2 or ref-policy obligation (§9.3); the inspector pair-check shorthand is made precise (§10.2); synchronous inspection of ref-only operations and the duty to document historical-support limits (§18). No wire, stored-row or version change. |
| 1 | draft | Editorial: §18 states the launch profile deployment-neutrally and points to the Workers operator guide for the Worker-specific selection, bindings and purge configuration; the `store::inspection_*` modules are marked unintegrated groundwork and the deferred inspection, Event and proof work as not implemented. No behavior change. |
| 1 | draft | Additive object-reader session accounting and typed exhaustion. Existing public absence, advance messages and stored/wire formats are unchanged. |
| 1 | draft | `SetRepoVisibility` runs admission and records an outcome like other mutating RPCs, in envelope and statement modes (§2, §3). Additive optional `Outcome.procedure` and `Outcome.visibility` (fields 9 and 10) name the operation (§6.5); current pending and request-terminal reservation rows require `procedure`, so every request outcome, including a reconciled abandonment, names it. Incomplete stored rows are refused; storage-counter system events have no procedure. No row version changes. |
| 1 | draft | The production embedder's deprecated profile alias is removed; `paid-workers` is the only accepted value (§14, §18). |
| 1 | draft | Worker timer writes retry alarm scheduling twice inline, propagate exhaustion and retain cold-start repair. |
| 1 | draft | Namespace-scoped ListRepos authorization with an arbitrary repository selector; authority full listing requires explicit opt-in and writer view (§6.2; STC §7.10). |
| 1 | draft | Worker launch profile is `LAUNCH_PROFILE=paid-workers`; the production embedder's former profile value remains a deprecated alias with a startup warning. §18 accepts configured cache-purge delivery through the signed HTTPS hook or an embedder-supplied purge sink. |
| 1 | draft | Production takedown and `ReadPreserved` activation uses the configured admin, Paid Workers launch profile, takedown, indexed Paid and complete §14.7 preservation gate; startup refuses partial configuration. |
| 1 | draft | Bounded resumable publication rechecks retain a binding and witness position in the existing timer-12 value, guard checkpoints against obligation/generation changes, and preserve valid dependency limits. Unsupported pre-launch timer values require store reset (R-198 B1). |
| 1 | draft | R-190 restricted takedown administration (WP-5.6a-3): additive acquisition, verification, discovery, legal-hold and purge status fields in existing v1 TakedownRecord; signed audited reads and atomic holds, byte-free replay and freshly verified Connect streaming. No new protocol or wire version. |
| 1 | draft | R-190 lean launch preservation: finite allowlist/Single Root safety-cut sweeps; Any supports denial/preservation and incomplete known-namespace discovery pending the post-launch catalog. Pending, verified preservation and real completion stay distinct. Restricted ReadPreserved uses byte-free replay descriptors and fresh audited verified streams; full-profile and §14.7 key/list requirements remain. No schema fields or versions change in this amendment. |
| 1 | draft | R-193 additive Inspect retrieval metadata (§6.4, §11.4), private raw added-pack reads with dedicated MAC capability and scanner auth-v2 keys, bounded ranges, uniform not_found and global denial. Current open-ticket state plus short capability expiry defines lifetime; fail-closed attempts remain readable until expiry, and retries preserve inspection_id while minting fresh capabilities. Default-off and Paid-only; Worker activation requires the Paid Workers launch profile and complete valid retrieval settings. |
| 1 | draft | R-190 pending launch takedown: repository-local object or whole-pack input (additive admin `pack_id = 9`), independent immediate denial and unresolved preservation work; production activation awaits preservation. Manual PurgeCache accepts asynchronously with audited completion. |
| 1 | draft | R-200 launch inspection: sync/fail-closed only, at most four inspectors, positive whole-advance bound <=10,000 advertised as inspection_max_objects, conservative header/job-count refusal before enumeration with the existing index-limit error; one batch each and PRE_RECEIVE quarantine rejects. Inspect added-pack Blob/ChunkedBlob entries, surplus included, as BLOB/CHUNKED_FILE; chunk-only blobs MAY be BLOB, CHUNK unused. Earlier membership was synchronously inspected; activation requires an empty store. Enumerate frame/checkpoint pages of <=1,000 rows without inspection role reads. No durable continuation/marker; async, holds, quarantine, full classification and unrestricted multi-batch inspection deferred to WP-5.5c (§11, §18). |
| 1 | draft | Launch admin foundation subset: signed framework, gapless audit/ReadAuditLog and automatic purge delivery; manual PurgeCache deferred. Automatic audit uses committed source relay events and atomic root append/dedup/watermark. |
| 1 | draft | Launch profile permits indexed permanent retention with `leases = false` and GC disabled (§12.1, §18); publication transitions use Event field 7 with operation correlation, durable recording and at-least-once delivery (§12.4). Committed means Sent, never Delivered (§6.5; WP-5.4). |
| 1 | draft | Authority-ticket streams use bounded physical-byte checkpoints independent of client framing, retaining pre/post staging and final acceptance checks (§6.2.1; WP-2.16). |
| 1 | draft | Optional independent namespace authority generations, deployment-authority statements, lease completion and ticket fencing (§6.2.1; WP-2.16). |
| `1` (WP-3.13) | draft | §6.3 preserves repeated challenge order while allowing RFC 9110 combination on platforms that fold fields; mirrors STC §5.1. |
| 1 | draft | §9.7 clarifications: rules intersect, a packmap is covered through its head, a missing auth v2 signer denies, ancestry semantics and bounds, and the allowed-signer set MAY be checked before verification and at `BeginUpload`; §9.3 requires a ticketless indexed head to be a member commit, remix or tag (WP-4.17). |
| 1 | draft | Indexed ingestion verifies every consumed object, including unreachable entries; closure and packlist index caps have the `object index limit exceeded` error (§9.3; WP-4.7). Indexed pack-size and decode-budget errors are pinned in §9.8. |
| 1 | draft | §18 conformance scope: a core profile (§2–§8; no inspectors, storage leases, GC, indexed mode, takedown, receipts or admin service) and a full profile; §1 defers the §§9–16 obligations to the profile. |
| 1 | draft | Additive admin service, signed envelope, role-bearing key list, replay contract, audit log (§16), and remote CachePurge (§16.7); namespace-scoped Event (§12.4). |
| 1 | draft | §14 content, repository, and namespace takedown; signed notices, preservation and restore; additive transport notices and hook transition/reason. |
| 1 | draft | Storage receipts (§15): live advances and lease changes, shared receipt/notice key list, verifier rules and goldens; additive receipt fields and retrieval in STC, and `AdmitAllow.external_ref` (§6). |
| 1 | draft | Additive M5 published view (§10), per-advance inspection and quarantine (§11), including surplus pack entries; additive Inspect phase/id/kind/defer/flagged ids and Authorize writer_view (§6); `GetServerInfo.async_inspection` in STC §2.1. |
| 1 | draft | Additive M5 storage leases and lifecycle Event (§12), server GC (§13), and section renumbering (§§19–20); `GetServerInfo.leases` in STC §2.1. |
| 1 | draft | Initial M3 pipeline, durable outcome and remote-hook contract; M5 sections reserved. Admission credential headers (§6.3); indexed mode (§9). HTTP read reservations and procedure strings (WP-4.11), amended with `read_reconcile_grace = 60 s` default and `ReadServed` priority within grace (fix round 1). |

## 20. Test anchors

Informative: the heavy native indexed extraction regressions retain their
full fixtures and assertions in default and unchained CI runs. Exact-name
[nextest overrides](../../rust/.config/nextest.toml) serialize the 64 MiB
multipart threshold, compressed read-window, multipart lost-reply, and
fifty-delta cold-slice tests with a 300-second test ceiling. The
[contributor guide](../../CONTRIBUTING.md#scoped-slow-tests) explains the scope.
These test allowances do not change server runtime limits or conformance
requirements.

The fixtures under `rust/tests/golden/server-hooks/` are the authoritative
pinned bytes, as [SPEC-CONVENTIONS §5](SPEC-CONVENTIONS.md#5-golden-vectors-and-conformance-tests)
requires. These anchors are informative descriptions of those bytes.

`mkit-rpc::hooks_public::decode_every_golden_request` decodes every request
through the public hook types and checks protobuf and JSON round trips,
including equality with every field of the original JSON fixture. When adding
request vectors, update its exact request count alongside this table and
`scripts/check-server-hooks-goldens.sh`. Keep the field-preservation assertion:
round-tripping only the decoded message can miss fields discarded at decode.

| Golden file | Contract pinned |
|---|---|
| `authorize.request.json` | Operation, signer principal, and intended ref changes (§6.2). |
| `authorize-allow.response.json` | Empty Authorize allowance (§6.2). |
| `authorize-deny.response.json` | Deliberate Authorize denial code and public message (§6.2). |
| `admit.request.json` | BeginUpload pack id, declared bytes, authorization facts, repository-byte presence, and a fake admission credential header (§6.3). |
| `admit-first-attempt.request.json` | First-attempt Admit input with no credential headers (§6.3). |
| `authorize-fork.request.json` | A fork's operation: destination repository, source, branch, expected tip, source visibility and revision, and requested visibility (§6.2, §9.9). |
| `authorize-published-source.request.json` | A same-repository branch creation: destination Missing updates and captured source ref, pair, generation and published sequence (§6.2, §9.3). |
| `admit-fork.request.json` | A fork's Admit input: the source and the bytes the charge covers (§6.3, §9.9). |
| `admit-ref-writes.request.json` | Ref admission with CAS-bound create and replace effects (§6.3). |
| `admit-ref-deletions.request.json` | Ref admission with delete and absent-deletion effects (§6.3). |
| `admit-allow.response.json` | Reservation id and allowed receipt pass-through (§6.3, §6.6). |
| `admit-allow-external-ref.response.json` | Optional implementer reference carried into a storage receipt (§6.3, §15). |
| `admit-challenge.response.json` | Opaque challenge and example payment challenge header (§6.3, §6.6). |
| `admit-deny.response.json` | Deliberate admission denial (§6.3). |
| `inspect.request.json` | Legacy non-conforming pre-M5 example, retained to pin the additive wire shape (§6.4). |
| `inspect-pass.response.json` | Empty inspection pass verdict (§6.4). |
| `inspect-quarantine-phase.request.json` | Quarantine phase, stable inspection id, and blob/manifest/chunk metadata (§6.4, §11). |
| `inspect-quarantine.response.json` | Hold verdict and flagged object ids (§6.4, §11). |
| `inspect-reject-flagged.response.json` | Reject/hit verdict with flagged ids (§6.4, §11). |
| `event-takedown-blocked.request.json` | Content takedown blocked transition when the blocklist row is written (§12.4, §14). |
| `event-takedown.request.json` | Per-repository content takedown complete transition (§12.4, §14). |
| `event-takedown-namespace.request.json` | One namespace-scoped blocked transition with no repository fan-out (§12.4, §14). |
| `inspect-defer.response.json` | Async retry-after suggestion (§6.4, §11.3). |
| `authorize-writer-view.response.json` | Authority-source writer classification (§6.2, §10.1). |
| `outcome-committed.request.json` | Committed byte accounting and refs (§5, §6.5). |
| `outcome-visibility.request.json` | Committed repository visibility change with its procedure and visibility (§6.5). |
| `outcome-aborted.request.json` | Apply-failure abort reason and operator detail (§5, §6.5). |
| `outcome-abandoned.request.json` | Pending reservation reconciled with ABANDONED (§5, §6.5). |
| `outcome-expired.request.json` | Unconsumed ticket expiry (§5, §6.5). |
| `outcome-read-served.request.json` | Paid-read object and bytes served (§5, §6.5). |
| `outcome-repo-storage.request.json` | Repository stored-bytes change with absolute total and version (§6.5.1). |
| `outcome.response.json` | Empty Outcome acknowledgement (§6.5, §8). |
| `event-lease-grace.request.json` | Ref-level expiry into grace, sequence and lease terms (§12.4). |
| `event-lease-deleted.request.json` | Repository-level expiry into deletion (§12.4). |
| `event.response.json` | Empty Event acknowledgement (§12.4, §8). |
| `cache-purge.request.json` | Manual remote purge with target paths, object ids and refs (§16.7). |
| `cache-purge.response.json` | Empty purge acknowledgement (§16.7). |
| `signature.json` | Admit body including credential headers, Outcome, Event, and CachePurge bodies, with exact bytes, canonical signing strings, hashes, signatures, and full headers (§7.1). |
| `key-list.json` | Public test key distribution document (§7.2). |
| `MANIFEST.txt` | BLAKE3 hashes of every other golden file, including both Admit attempts (SPEC-CONVENTIONS §5). |

Informative: the signature vectors contain a clearly labelled test seed.
It is public fixture material and is not a deployment signing key.

[`rust/tests/golden/redaction/`](../../rust/tests/golden/redaction/)
pins the §14 JCS payloads and DSSE envelopes from a test seed for
reader and writer views, including a second rewrite pass. It pins
protobuf detail binary and canonical JSON, four baseline Connect error
bodies plus a reader-view superseded-pack error,
and reader and writer `ReadRef` and `ListRefs` responses. Its ingest
pair pins empty repository and rewrites; its key list pins the issue
window.
`MANIFEST.txt` pins BLAKE3 digests; `scripts/check-redaction-goldens.py`
verifies the signature and protobuf round trips. The HTTP 451 response
rows are in `rust/tests/golden/http-objects/response-cases.json`.

The fixtures under `rust/tests/golden/admin/` pin the §16 envelope,
role-bearing key list, representative admin procedures (including empty
lease and suspension receipts), and the three-entry audit chain. The
lease-key `ReleaseHold` signature receives the chained wrong-role denial;
the response fixture depicts an authorized moderator's call. Their
`MANIFEST.txt` pins each file's bytes.

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

## Public Rust API toward 0.6

**Reference-server behavior.**

The supported embedder surface is documented in the `mkit-server` crate docs.
The [Workers guide](../embedding/workers.md) and
[public reference](../../apps/embedded-worker/README.md) demonstrate composition;
they do not add protocol requirements. Hosts retain one reader and one
`ReaderSession` across sequential bounded request batches, report `used()` even
on failure, deduplicate outcomes durably and retain the highest storage version
under §6.5.1. Host pagination and continuation state remain outside the protocol.
Deployment configuration structs are non-exhaustive and constructed through
constructors, parsers or defaults. Storage layouts/codecs are adapter SPI under
`store::adapter_spi`; public storage traits and reservation/outcome types remain
the embedder contract. Call-budget defaults live in `limits`, and request and
purge slices share `budget::SliceBudget` without changing their accounting.
The Cargo fault-injection feature is internal (`__test-faults`); its wire test
capability retains the existing `test-faults` spelling. This API boundary does
not change wire behavior or stored bytes.

Trusted embedding queries use `reads::ReadAccess` or `Pipeline::read_access()`.
The [typed read guide](../embedding/typed-reads.md) lists accessors and migration paths.
These queries route through the configured shard map and never return encoded rows.
Callers retain repository authorization, their own policy journal, and final disclosure checks.
Existing authorized pipeline readers keep uniform absence and their final guards.
A visibility revision compares stored observations; it is not a monotonic policy journal.
Fork recovery trusts the Done job, which is committed atomically with its replay and reservation rows, and checks the caller's identity against it without authenticating an expired envelope.
A replay or reservation row that is still present must match the job; a row removed by outcome acknowledgement or replay expiry is accepted as absent.
The caller verifies current destination authority and its trusted retained landing evidence.
This additive surface changes no wire or stored format and requires no reset.
