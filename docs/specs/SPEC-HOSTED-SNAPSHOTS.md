---
spec: SPEC-HOSTED-SNAPSHOTS
version: 1
status: draft-normative
audience: implementers of the optional managed mkit hosting profile
---

# SPEC-HOSTED-SNAPSHOTS &mdash; owner-enrolled complete Snapshot indexes

Status: **Draft, normative** for the optional managed hosting profile. This
service-local protocol adds no generic transport method, portable object rule,
grant authority, subject read route, or default public Worker behavior. A
structural certificate says that the selected immutable raw-v1 packs contained
exactly a complete Snapshot rooted at a signed Commit/Remix at enrollment.
It is not authorization to disclose objects. The current ref, packmap,
policy and subject's live grant must be checked separately by a later private
consumer. A historical `ready` job response is never that current check.
Scope: owner enrollment wire, durable job fences, structural validation,
certificate indexes, and bounded cleanup. Private subject disclosure and
publication are outside this version.
Reference implementation: `apps/vcs-worker/src/worker_impl/snapshot_*.rs`
and `apps/vcs-worker/src/snapshot_wire.rs`.

## 1. Owner requests and replies

The five paths are `POST /mkit/host/v1/BeginSnapshot`, `ContinueSnapshot`,
`GetSnapshotJob`, `CancelSnapshot`, and `CleanupSnapshots`. They use the
[auth-v2 owner envelope](SPEC-SERVER-ACCESS.md) over the exact raw request
body and procedure path. The configured owner and a healthy persisted policy
MUST be checked before any job existence or nonce replay lookup. Every request
MUST be uncompressed `application/json` of at most 65,536 bytes. JSON has one
complete object, no duplicate or unknown fields, and an integer `version:1`.
Field order and whitespace need not be canonical because auth signs the raw
bytes. All IDs and pack keys are exactly 64 lowercase hex characters. All
u64 generation/revision fields use canonical decimal strings, including `0`;
leading zero, sign, exponent and overflow are invalid. A job ID is an
owner-supplied nonzero random 32-byte value, never an auth nonce.

| Method | Complete request fields after `version` |
|---|---|
| BeginSnapshot | `job_id`, `ref`, `expected_head`, `expected_packmap`, `selected_pack_keys` |
| ContinueSnapshot | `job_id`, `job_generation`, `expected_revision` |
| GetSnapshotJob | `job_id` |
| CancelSnapshot | `job_id`, `job_generation`, `expected_revision` |
| CleanupSnapshots | `expected_cleanup_revision`, `max_rows` |

Begin's `ref` is an existing valid `refs/heads/…` name of at most 1,024
bytes. `expected_head` is its live root. Its paired
`refs/mkit/packmap/…` ref must exist and equal `expected_packmap`, the
content key of a complete `MKPL` v1 tip blob. The owner supplies 1..128
strictly increasing, distinct selected pack keys. Begin captures those
exact values, the current policy generation, versions and a repository-wide
monotone job generation in one synchronous SQL transaction. It performs no
R2 I/O or premature tip membership claim. The first Continue fetches and
hash-checks the complete tip and proves that every selected key occurs in
the tip node itself; membership only in `prev` is unsupported.

Normal job replies are one JSON object with producer field order
`version,job_id,job_generation,revision,state,progress`. `progress` has
decimal-string `catalog_packs,catalog_entries,reached_objects,reached_bytes,
work_units,attempts,reserved_io_bytes,r2_operations`, in that order. State
is `catalog`, `walk`, `ready`, `cancelled`, `expired`, `failed`, or `cleaning`.
Begin starts at revision `"0"`; only an atomic successful semantic step
increments it. Get is a fresh read and never reserves a nonce. Cleanup's
200 body is exactly `version,cleanup_revision,affected_rows,has_more`, with
the two counters as decimal strings and `has_more` a Boolean. A successful
Cleanup increments its revision even when no row is eligible. `max_rows` is
an integer in 1..64 and counts actual business-state updates/deletions,
including idle expiry transitions, not constant ledger/meta bookkeeping.

An exact completed auth-v2 nonce replay within its TTL returns its saved
reply without new effects; a null/pending nonce returns 202 with
`{"version":1,"code":"in_progress","job_id":"<64hex>"}` and never
restarts I/O. This may outlive an attempt lease but not the auth TTL. New
progress needs a fresh signed nonce and current revision. A same-nonce
different fingerprint conflicts. The live owner/policy health check precedes
historical reply replay; a healthy policy-generation replacement may still
allow that effect-free historical reply, but it fences new progress. Cancel
may retire an old job under a new policy epoch for the same immutable owner.

Error bodies contain only `{"code":"…"}` plus LF, and all replies set
`Cache-Control: private, no-store`: 400 `invalid_argument`, 401
`unauthenticated`, 404 `not_found` after authentication, 405
`method_not_allowed`, 409 `conflict`, 413 `resource_exhausted` for body
bytes, 415 `unsupported_media_type`, 422 `unsupported_profile` for a
deliberate well-formed but excluded tip/pack profile, 429
`resource_exhausted` for hosted budgets, and 503 `unavailable` for unhealthy
config/schema or transient/corrupt storage. A refusal by a hosted resource
ceiling is not a declaration that the portable Snapshot is invalid.

## 2. Hosted profile and incremental proof

The initial hosted profile permits complete Snapshot objects in selected
immutable raw-v1 packs only. Each selected pack is at most 4 MiB, each
canonical object at most 2 MiB, each tip at most 64 KiB. The pack scanner
uses the core checked raw-v1 parser and cryptographic complete-pack key,
trailer, per-entry type-aware ID and canonical-object inspector. It retains
compact validated locators, not object bodies. The signed root, Tree
occurrences and chunk positions are traversed with the core's trusted
`SnapshotWalkRecord` step API. Parent/Remix historical sources are not part
of this Snapshot. Distinct object bytes contribute once to U/B, while every
Tree occurrence and manifest chunk position contributes to W and depth/layout
checks. A persisted work record is a bounded cursor, not an object fact:
bytes are re-inspected at every consumption. The owner cannot submit a
successor list or completion assertion.

One Continue advances at most the tip, one pack page of 64 entries, one
bounded walk page, or promotion. A walk step atomically consumes its
predecessor and enqueues every core successor, at most 64 page records plus
one continuation. It transactionally reconciles distinct IDs and canonical
lengths against the seen ledger before applying core accounting; stale or
duplicate apply has no effect. Completion requires empty frontier and indexed
anti-joins in both directions establishing exact equality of reached and
catalog IDs. Promotion rechecks the captured live ref/head/packmap, current
policy epoch, job generation/revision/attempt, identity and selected-key
digest. It swaps one current certificate pointer. An old index is retired
but survives while a bounded read lease pins it. Certificate/index locators
are authoritative after the seven-day job summary is purged; later private
consumers must not treat prunable job scratch as current logical membership.

## 3. Durable fences, I/O and cleanup

The service stores versioned RefStore-local SQL jobs, selected keys, compact
catalog locators, seen IDs, frontier cursors, current/retired certificate
indexes, read leases and a schema/identity sentinel. A wholly absent schema
may bootstrap only inside a successful authenticated Begin transaction.
Partial presence, wrong identity/version, unexpected row/checksum or
corruption fails closed and is not auto-repaired. Auth replay, semantic
revision and attempt sequence are distinct: each new admitted Continue
increments attempt sequence and a cumulative attempt counter, records its
scope/fingerprint and two-minute claim deadline, and durably reserves the
first known locator length or metadata HEAD before any await. HEAD is a
charged operation; a subsequent GET reserves its exact known length before
I/O and matches its ETag and length. Each later chunk is separately reserved
under the same live fence. Failed/crashed reservations are never refunded.
No SQL transaction, mutable borrow or Durable Object concurrency block spans
an R2 await. One shared heavy-operation permit per DO isolate prevents two
new large operations; saved and pending nonce replies bypass it.

On every read charge and final apply, the exact job generation, semantic
revision, attempt sequence, policy epoch, ref/head/packmap, selection digest,
claim deadline and signed request expiry are rechecked. A late result after
cancel, expiry, owner policy replacement, head/packmap movement, lease
timeout or a fresher attempt cannot apply or promote. Owner admin remains
responsive during an R2 wait. A cooperative 20-second deadline is checked
before/after awaits and before apply; uninterruptible synchronous work may
overrun it, so this is not a hard wall-clock promise.

Hosted independent ceilings: 2 live jobs/repository and 1/ref; 8 current
ready refs; 128 retained terminal summaries; 400,000 total catalog locator
rows; 1 GiB pinned raw pack bytes; 100,000 frontier rows and 32 MiB frontier
metadata/job; 100,000 distinct reached objects, 256 MiB reached canonical
bytes, Tree depth 128 and 1,000,000 work units. A Continue reserves at most
8 MiB R2 bytes and 66 R2 operations. At most 8,192 attempts, 2 GiB
cumulative pessimistically reserved read bytes and 540,672 operations are
admitted/job. These ceilings are independent; a valid portable Snapshot
may hit the repeated-pack/parent-read budget before a logical maximum.
Body and SQL rows remain bounded; no whole graph is materialized in a row.

Successful semantic progress extends a job's 24-hour idle deadline.
Cleanup first fences idle-expired live jobs with a fresh globally monotone
generation, releasing live slots without Continue. Cancel also allocates a
fresh generation. Terminal metadata lives seven days, independently of a
current or leased certificate index. Cleanup removes at most `max_rows`
eligible business rows per transaction, including expired leases, retired
unpinned catalog rows/indexes, and expired job children/summaries. There is
no unbounded cascade. `has_more` is an indexed existence check, not a full
remaining count. Global generation never resets after an old ID is purged;
reuse while a job or index still names it conflicts. Internal structural
read leases last at most five minutes, at most 64 physical rows in the
repository and 16 per certificate. A lease grants no subject authority; the
future consumer must check the live grant and policy before every private
read. No private read route is introduced here.

## 4. Security boundary

Only the configured owner can request enrollment or inspect job progress.
The exact selected-pack list and R2 locators are service-local state; neither
their presence nor `ready` grants access. The service never mutates ordinary
packs, historical refs, core objects or portable Snapshot rules. A complete
certificate is useful only while the current ref and packmap still match its
captured tuple. Revalidation is mandatory at later private disclosure and
publication boundaries.

## 5. Test anchors

The exact owner request/reply vectors under
`rust/tests/golden/hosted-snapshots/` pin the JSON and HTTP status contract.
`apps/vcs-worker/tests/managed_snapshots.py` exercises signed routes against
actual local workerd, R2 and SQLite, including a distinct reachable fixture
above 128 MiB. Core bounded-MKPL, raw-pack and Snapshot-walk tests pin
portable parsing and local inspected facts.

## 6. Invariants

| Invariant | Enforced by |
|---|---|
| An owner nonce replay performs no new I/O or state change. | Live owner/policy check then `Ledger::reserve` before a new Continue claim (§1, §3). |
| Every R2 call consumes durable pessimistic budget before invocation. | Fenced `Job::charge` transaction before HEAD, GET or range read (§3). |
| A stale async result never promotes. | Final generation/revision/attempt/policy/ref/expiry checks (§2, §3). |
| Reached and catalog IDs match exactly at promotion. | Indexed two-direction anti-joins plus aggregate counter reconciliation (§2). |
| A certificate cannot turn a grant into authority. | No c1 subject route; future private reader rechecks live grant and policy (§4). |
