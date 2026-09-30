## Authoritative approved split (2026-09-30)

The user approved [WP-4.10b-1](WP-4.10b-1.md), protection and bounded upload
prerequisites with Extract still fail-closed, followed by
[WP-4.10b-2](WP-4.10b-2.md), the extraction driver. Both share R-186. PR1's
production cap is 3,000 lines. PR2's 2,300-line amendment covers incremental
delta lookup/reconstruction and review/clippy fixes; the final 2,350-line cap
adds only isolated/parent checks and necessary fixes for Worker growth pruning
and the two native timer failures, with no new scope or code trimming. PR2 is based on PR1 and opens into
`feat/mkit-server` after PR1 merges. Neither PR is merged by the executor.

The original purpose and A/B requirements below define the complete package;
they are not a claim that PR1 finishes extraction. All executor checkpoint
sections below are historical. The [split checkpoint](WP-4.10b-split-proposal.md)
records the evidence behind the approved partition. Final budgets, gates and
scope are reported separately in each PR.

## Purpose

Workers extract large objects (Blobs ≥ 64 KiB and ChunkedBlobs) into the global object store in checkpointed alarm
slices. Holder rows are recorded through a content relay hook. This keeps native's invariant: `Verified` ⇒ extracted,
held, and holder recorded. That lifts 4.8's fail-closed Extract stub.

## A. Fixed (do not change)

- SPEC-SERVER §9.6 and §13.2–§13.4, and §14.2, including the late-holder takedown scheduling it requires.
- R-163 (the native extraction contract, `HolderV1`, chunk-only Blob exclusion) and R-171 (4.8's job, budgets and
  Paid-only rule).
- Verify before visible, and `AlreadyPresent` is advisory.
- Permanent retention (the launch profile) doesn't waive extraction protection or block checks.

## B. Decided (do not change)

- **B1. Checkpoints.** Versioned extraction checkpoints in the `vc` sub-4 rows. They hold:
  - selection facts;
  - the object/chunk cursor;
  - offsets;
  - the multipart session, parts and CVs;
  - cumulative charges;
  - holder-relay progress.

  Preserve consumed-set selection without the native staged map.
- **B2. The per-object protocol:**
  1. durable hold;
  2. verify and charge repository-local sources, on dedup and on a miss (the no-oracle rule from 4.10);
  3. root-checked completion;
  4. offsets sidecar;
  5. durable holder intent;
  6. renew the hold while awaiting delivery;
  7. then `Verify`.
- **B3. The content `RelayHook` on the target:**
  - atomically writes `HolderV1`;
  - bumps and guards `c`;
  - updates conservative counts;
  - releases the hold;
  - advances the relay watermark.

  Redelivery doesn't bump twice; a distinct re-record does. It checks the blocklist on holder delivery. **A late
  holder of a blocked object durably schedules takedown** through a durable seam, with a minimal launch consumer that
  records a takedown request for 5.6a.
- **B4. Multipart: bounded finalization.** Prefer R2 backend multipart, once root-check and publication semantics are
  validated, over re-reading every staged part into one final PUT. If backend multipart can't keep verify-before-visible,
  escalate.
- **B5. Budgets:**
  - Paid-only;
  - one verification fire;
  - 256 calls per slice;
  - a 48 MiB resident allowance;
  - count multipart operations, hook reads and retries;
  - recalculate the whole-alarm budget and record it in R-186.
- **B6. Protection:**
  - renew across the actual relay delay, beyond nominal lag and ticket expiry, whenever queued holder work can still
    apply;
  - replans need fresh block checks, guarded observations and `NotAfter`;
  - failures close.
- **B7. Exposure** stays default-off until 4.18. R-186 records it.

## C. Your decisions

Checkpoint encoding, module layout and metric names.

## D. Escalate (stop and report) if

- B4 can't keep verify-before-visible.
- The budget can't fit without raising the 256-call cap.
- Production code passes 3,000 lines. Then split off an additive multipart prerequisite.

## Tests (required)

The fact sheet's §8 extraction list, in full.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy and the worker build.
- `scripts/vcs-worker-conformance.sh` (the indexed/test-faults phase), with a free `VCS_CONFORMANCE_PORT`.

## Executor checkpoint: design, not implementation (2026-09-30)

The root ruling is `~/.cache/mkit-orch/scratchpad/prompts/RULING-4.10b-group-protection-codex.md`.
It reserves content pending-protection tag `gp` and optional timer kind 13
`CONTENT_TAKEDOWN_REQUEST`; R-186 remains this package's row. These reservations
do not describe implemented behavior.

### Consumed-set arbitration

Native `indexed/verify.rs` decodes already-Verified packs too. Its union therefore
includes their manifest/tree facts when selecting newly introduced objects.
`staged_owner` uses the first occurrence in ticket order; extraction only runs for
an owner whose `needs_index` is true. Both rules must survive Scheduled execution.
Recording only fresh packs or selecting each pack independently would be wrong.

The planned Scheduled creation transaction captures an ordered group of
pack/ticket/length/creation identities and each member's already-Verified status.
It guards every observed job and verification row, then claims all new jobs in
one batch. An unfinished member owned by a different group prevents *all* new
claims. After that group finishes, a later group may reuse its immutable facts.
This gives A+B versus B+C the same serialization boundary as native's Pending
verification lease, rather than creating A and C with mutually incompatible B.
Only creation of the group is atomic; subsequent work remains bounded per job.

Every group member contributes versioned vc sub-4 selection facts. Extract waits
for complete, validated facts from the whole group. The group must include reused
Verified members and preserve first-owner selection. Current producers' facts
must validate before use. Replaced/expired
identities invalidate unfinished work before extraction can switch groups.
Group aggregate extraction limits and duplicate ownership must use the union,
while every existing vc sub-6 source dependency remains available to publication.

### Protection and relay

TTL renewal alone cannot cover arbitrary queued delay: current holds expire within
24 hours and ticket cleanup can remove the job. Before an action can outlive TTL
protection, extraction will create a versioned `gp 00 object hold_id` marker in the
content shard, identifying the repository, source job and intent. Marker mutations
bump and guard `c`; any marker conservatively prevents collection. An initial
bounded existence scan suffices for GC, and malformed state fails closed.

The source checkpoint and holder relay enqueue must commit together. The target
hook will atomically write HolderV1, update conservative accounting, release the
TTL hold, remove the matching marker, and advance the watermark. It must still
apply valid queued work after ticket expiry, check the fresh blocklist, and record
a real durable takedown request for a late blocked holder. Watermark redelivery
does not re-bump; a distinct intent does. A crash before source intent creation
may leave conservative protection; cancellation cannot remove it on age alone.
Recovery must prove no surviving relay can still apply before releasing it.

### Multipart and budgets

Cloudflare's Workers API exposes create/resume/uploadPart/complete/abort. Complete
has no conditional-write options and makes the final object globally readable;
verification must finish before that call. Parts are selected by upload ID, part
number and returned ETag. ETags identify selected parts, not BLAKE3 integrity.
The backend path must keep private sessions bound to frozen object/group identity,
verify deterministic source bytes before each upload, persist CV/length/ETag
together, and validate exact geometry and merged root before completion. Duplicate
writers must not replace a selected slot with unverified or different bytes.
The existing R2 implementation instead rereads every staged part into a final PUT
and cannot supply bounded finalization for an arbitrarily large object.
Backend evidence: [Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/),
[multipart limits and ETags](https://developers.cloudflare.com/r2/objects/upload-objects/),
and installed workers-rs 0.8.5 `src/r2/mod.rs`.

All backend calls, hook reads, group retries and failed planning attempts count.
Verification retains one Paid-only fire, 256 calls and 48 MiB resident allowance.
Relay target limits must include hook work and shrink/retry reads before the
whole-alarm bound is recorded. Actual tests and measured bounds are outstanding.
Exposure remains off. No staging or deployment checks have run for this package.

### Remaining execution

Implement group arbitration/facts; source resolution and replay-safe charges;
bounded multipart; pending protection and target hook; expiry/crash recovery;
real Worker registration and budgets. Required regression coverage includes
native parity with reused packs, overlapping/partial groups, replacement and
expiry, every publication/sidecar/relay crash boundary, delayed delivery beyond
24 hours, stale GC/removal races, late block requests, and actual memory/call caps.
Then integrate other merged seams, run the full brief's gates, obtain two
independent reviews through the root, and open the PR. Nothing in this checkpoint
claims those implementation steps or checks are complete.

### Atomic-creation checkpoint

The first implementation step adds the ordered group DTO to jobs, preserves it
on source restart, and claims new jobs in a single transaction guarded on ticket,
job and verification observations plus `NotAfter`. An unfinished existing member
blocks creation of the rest of an overlapping group. Existing finished members
are captured with their already-Verified status. This is creation arbitration
only; selection facts and the extraction protocol remain
outstanding.

The new A+B/B+C regression first failed on the integrated baseline at the
assertion that C must remain unclaimed, then passed after the fix. Evidence is
under `~/.cache/mkit-test-tmp/wp-4-10b/group-{red,green}.log`. This focused result
does not establish complete native/Scheduled selection parity or production
readiness.

### Selection-fact checkpoint before additive multipart prerequisite (2026-09-30)

Decoded entries now persist versioned payload-free selection facts in vc sub-4:
Blob size, manifest size/chunk references, Tree child references, or Other.
Native selection remains unchanged; an independent fact-union regression compares
its result with native selection when manifest/tree context comes from reused
members. This is only a fact-capture foundation: group readiness, bounded union
selection, extraction and holder delivery are
still unfinished. `selection.rs` functions not yet used by the future driver may
produce temporary dead-code warnings at this checkpoint; no final gate claim.

Focused regression red (missing fact projection) then green, and all40 scheduled
job tests pass. Logs: selection-red.log, selection-green.log and
selection-job-suite.log in ~/.cache/mkit-test-tmp/wp-4-10b. No live handles remain.
Root allocated additive WP-4.10b-multipart/R192 (1500 production-line cap) as an
explicit prerequisite; parent scope and R186 remain complete extraction/relay.

### Restart scope (R-198) and approved upload callbacks

R-198 freezes the existing `gp`, `ct`, timer-13 and observed `RelayHook` surface.
Current producers' rows, including generic 96-effect relays, remain supported;
earlier unreleased persisted formats require a reset and have no migration or
reconstruction contract. GC has no deployment enabling surface and remains off.

The user approved internal upload callbacks on the existing `SliceExtension`:
begin with a complete trusted root/CV plan, verify one bounded part, complete
using the exact ordered receipts, and abort a private session. Default callbacks
perform no IO. The driver computes and persists part CVs incrementally before
beginning R-192's backend upload; no whole-object payload is retained. Completion
must match the root and every CV before visibility. Callback mismatch, part
replacement, abort and cold restart are required regressions. No trait, key tag,
timer kind, relay codec or wire format is added by this integration.

The resource ledger includes quota retry/pruning and expiry cleanup. Paid quota
fires cap at eight coordinator calls; R2 cleanup processes one page; Free expiry
closes tickets while recording deferred abort failures for bucket lifecycle
cleanup. These give Paid at most 889 calls and Free at most 49 per alarm, with
256 calls reserved for one verification fire. Ranged generic BlobStore reads
reserve two calls for R2's metadata check and byte fetch.


### Executor checkpoint: durable pending ownership foundation

Integrated merged multipart prerequisite39998d86 at b1a1aae2. `gp` stores a strict bounded version1 identity binding repository, canonical source partition, job ticket and relay intent. Guarded insertion bumps object `c`; identical retry does not bump, replacement identity refuses, block/deleting checks are fresh and NotAfter guarded. GC performs a bounded first-row existence check and conservatively refuses even malformed pending state after expiring ordinary holds. Stale GC plans lose their c guard. No age-based release API exists. Hook-atomic holder/gp/TTL/watermark delivery and source reconciliation remain unfinished; this foundation does not lift Extract's fail-closed stub. ContentIndex focused15 and key codec tests green; red TTL regression evidence retained in owncache pending-protection-red.log.


### Holder consumer prototype checkpoint

The declared RelayHook read/snapshot seam preserves old callbacks and NoHook get/apply behavior; target reads now combine rh and declared metadata in one get_many. A bounded prefix is selected before IO, deduplicating to at most8 keys (4MiB maximum raw corrupt snapshot). Pure shrinking reuses observations; CAS retries refill. This is a component bound, NOT a whole48MiB proof including Worker JSON/JS copies. The content hook has no store/client and uses exact c/holder/gp/hold/block/request/layout observations; holder/count/c, TTL+gp release, ct+timer13 and rh commit atomically. Transport lost reply/redelivery does not bump twice. Domain-bound identity now additionally includes object, hold and stable operation; ct validates this complete provenance. A blocked delivery after24h records a real versioned ct request. Timer13 materializes Ready and reschedules, retaining the request for5.6a; Ready never means takedown completed. Prototype50 relay tests green including original generic96 and Paid/Free whole-call fixtures, explicit2 routed methods, lost reply and late block/retained handoff. Worker/native registration, driver integration, comprehensive race/count/heap matrix and whole alarm proof remain unfinished.

### Bounded reference projection checkpoint

Integrated fence squash4d1c8fd4 at1c76515d. A valid 20,000-reference manifest
(canonical bytes below1MiB) reproduced a1,368,862-byte selection JSON value,
above512KiB: selection-paging-red.log contains the actual assertion failure.
Decode now emits vc sub4 version2 bound summaries and version3 reference pages,
128 references/page, preserving order and every identity. Each page repeats
owner/kind/count/full-reference digest and index; page keys bind owner/digest/
kind/count/index. Readers must validate all pages and the final digest before
selection effects; the group driver enforcing this is still unfinished.
Pages precede summaries and Decode completion; partial provisional writes replay
under the exact job guard. Reference projection allocation is released before
closure-child projection. Ninety largest page writes plus a512KiB job guard and
maximum1024-byte keys fit the existing1MiB batch contract (dedicated test).
This is a batch bound, not the final whole-slice/JS48MiB proof.

Three codec/large-reference tests pass (20,000-reference manifest,15,000-entry
legal Tree, maximum batch envelope). A30,000-reference manifest spanning several
page batches survives partial-write faults and a committed/lost page response;
all references and one entry count are retained without publishing Verified.
Logs selection-paging-{codecs,replay}.log retain exact runs. Local vc row writes
use ctx.store rather than routed Budgeted calls; SQL/CPU/memory work must still
be included in the final resource ledger. No256 outgoing-call failure is claimed
for those local writes. Extraction/selection-group freeze, source passes,
registration and whole-alarm gates remain unfinished; exposure is unchanged.

### Restart checkpoint and cap escalation

The driver and approved internal upload callbacks are saved, with two confirmed
acceptance failures retained. See [the measured checkpoint and split proposal](WP-4.10b-split-proposal.md)
for the current implementation, test results, unfinished requirements and the
requested partition. Earlier checkpoint sections describe their historical
state; none is a final completion or gate claim.
