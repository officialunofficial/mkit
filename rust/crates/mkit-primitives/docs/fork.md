# Guarded fork acceptance

This module implements the guarded acceptance contract in SPEC-SERVER §9.9.
The host owns inventory authentication, staging, acquisition, logical ordering,
and atomic persistence. None of the in-memory fact types has a wire encoding.
All public items inherit the module's ALPHA stability level.

## Atomic effects and source ordering

`ForkPlan::seal` validates complete immutable inventories rooted at the admitted
packmap pack. The inventories include the entire packmap chain, listed packs,
and transitive external-base suppliers, including surplus objects. A trusted
host authenticates these inventories and resolves each external supplier; the
plan does not establish pack verification by itself.

`decide_fork_acceptance` returns `AcceptFork`, `JoinIdentical`, `ReturnRecorded`,
or a guarded refusal. Missing required observations produce `UnavailableInput`;
they never mean absence. Contradictory facts produce `InvalidResponse`, and
execution exhaustion produces `ResourceLimit` without partial success.

The acceptance unit records the exact plan and terminal response, saves the
replay response, records durable terminal outcome responsibility, and settles
the exact pending reservation when admission granted one. Default admission
records authoritative absence instead of inventing a reservation. An applicable
already applied admission debit is retained;
acceptance never debits quota again. A charge-free allowance uses authoritative
quota absence; missing observations remain unavailable. It adds no visible member or destination
ref and does not enable writes. The later activation is published clearance;
it cannot repeat terminal settlement or replace the saved result.

The final source proof names one destination apply attempt and complete staging
revision. Its ordering point follows the last staged membership effect and
precedes acceptance. The host reacquires it for each retried apply attempt.
Every inherited pack is checked at that fence. Source changes ordered after
the fence do not invalidate acceptance: source facts are a separate ordering
requirement, not cross-owner atomic comparisons.

Run the packaged end-to-end example with
`cargo run -p mkit-primitives --example fork_acceptance`. It seals a plan and
calls the acceptance entry point with deterministic typed host observations.

## Guard matrix

Every fork decision returns a `decision::Guarded<D>`, the same wrapper the ref
and ticketed decisions use. Its `required_guards` are owned, typed
`RequiredGuard` values, one per acquired observation: the typed authority,
grant and repository (lifecycle) guards, and `RequiredGuard::Row` for the
fork-specific rows (job, emptiness, name, permission, admission, quota,
reservation, replay, the apply attempt, durable progress, authority and epoch
fences, the retained accepted result, the membership unit, the destination
clearance proof and the denial revision behind it). A `Row` carries the
observation revision and a commitment to every field of the fact value, so a
value that moved without a revision change still fails the comparison.
`ForkFacts::guards` (and the same method on the advance, activation, completion
and clearance facts) derives the live guards from freshly acquired facts, and
`decision::guards_hold` is the pure reference comparison. Compare every guard,
including its revision, with all effects in one atomic unit. Business expiry
and the proof deadline are `ValidThrough` guards. The final source proof is a
separate pre-apply `RequiredSourceFence::Fork`; `fork_source_proof` returns it.
Nothing here acquires or commits anything.

| Dependency | Exact required fact | Boundary and mutation evidence |
|---|---|---|
| Source publication | Complete captured generation, sequence, prefix, deletion boundary, head, and packmap | Final source fence; `semantic_fixtures_pin_decisions_and_stable_codes` |
| Source access | Principal, visibility, visibility revision, authorization revision, readable state | Final source fence; source access fixture mutations |
| Source lifecycle | Exact incarnation and active state | Final source fence; source incarnation fixture |
| Every inherited pack | Pack ID, source incarnation and generation, live membership revision, clearance, hold, denial revision, supersession, immutable descriptor and revision | Final source fence; `every_inherited_pack_including_transitive_suppliers_requires_live_full_proof` |
| Proof ordering | Exact apply attempt and complete staged revision; last effect < proof < acceptance | Explicit source fence; stale/early/late proof fixtures |
| Destination | Exact repository and new membership generation | Atomic snapshot and lifecycle observation mutation |
| Emptiness | Revision covering every ref and visible/staged member, including phantom additions; exact staged owner, count, and full staged-pack digest; writes disabled | Atomic comparison; `phantom_additions_cannot_hide_behind_previously_absent_rows` |
| Name | Registration absent or owned by this construction; declaration matches requested visibility | Atomic name observation; foreign/declaration fixtures |
| Permission | Exact operation, source visibility observation, requested destination visibility, create and write permission | Atomic permission observation; permission fixtures |
| Authority | Recorded mode and generation; atomic fencing capability when requested | Atomic authority observation; authority fixtures |
| Grant | Recorded grant identity and epoch or authoritative absence | Atomic grant observation; `original_grant_epoch_is_not_replaced_by_newer_permission` |
| Job and replay | Exact sealed plan, original attempt, staging progress, replay scope, fingerprint, and saved terminal result | Atomic job and replay observations; lost-reply and joining tests |
| Reservation | Exact request reservation, pending operation and destination, protected deadline | Atomic reservation observation and expiry; settled/wrong reservation fixtures |
| Admission and charge | Exact admitted plan, operation, reservation, inherited bytes in both charge fields, and already applied debit identity | Atomic admission and quota observations; charge fixtures |
| Quota | Exact debit bytes, counters, applicable ceilings, and observation revision | Atomic quota observation; quota fixtures |
| Lifecycle and validity | Destination absent or active in the exact generation; reservation and job protection still valid | Atomic lifecycle and inclusive business validity; expiry fixtures |

`every_atomic_guard_and_expiry_rejects_mutation` changes every destination
observation revision, repository, apply attempt, acceptance point, and validity
bound. A guard failure requires fresh facts and a new source proof, without
replacing the original authorization or admission with newer permission.

## Replay and recovery

Identical pending construction resumes without another debit. A fresh request
with its own joining admission settles only that joining reservation as a replay
race. Its settlement is guarded on that exact pending reservation; it cannot
release the original construction's reservation or holders.

A saved terminal result is checked against the exact plan and replay fingerprint.
It does not require a new source proof. Authoritative absence after replay or
reservation pruning does not re-create outcome responsibility. An externally
settled reservation prevents any further construction or acceptance.

Completed replay resolves consistent terminal evidence before any advancement
authority or grant check. It does not re-authorize the completed operation.
A fresh exact pending joining reservation settles as a replay race even when
the response was already cached.

`JoinIdentical` authorizes no durable construction progress. Its guards cover
joining and any joining settlement only. Reacquire the original owner facts and
redecide before each advancing commit; do not reuse joining guards to advance.

The caller validates the signed envelope at ingress. Its expiry is retained as
replay metadata; the primitive does not introduce a new commit-time envelope
expiry rule. Durable construction is protected by its job and reservation
deadlines. Nothing in this module copies, removes, or releases holders.

## Bounds and verification scope

`ForkLimits` has no unlimited default. Plan construction checks pack, branch,
edge, byte, index-entry, and work limits before scratch allocation or traversal.
Inventories must be canonical and distinct, and every dependency must be present
and reachable from the packmap root. Checked sums reject overflow. Scratch is
at most one `usize` and one byte per pack, reserved fallibly. The existing
sorted-pack digest streams through core's BLAKE3 implementation.

Decisions borrow observations, proofs, and the sealed response; the returned
guards are owned. Plan sealing
reserves one response branch string fallibly, bounded by the branch limit.
Host input memory and host-restored terminal records belong to the caller. Full-plan equality, branch comparisons, and proof checks have
an explicit finite work allowance. Every retained plan and terminal branch
is charged before returning a guarded decision, including refusal snapshots. Output contains one decision, at most one
acceptance or joining settlement, and a fixed number of owned guards (at most
fifteen for acceptance).
There is no hidden I/O, traversal callback, clock read, or runtime fan-out.

The semantic fixture inventory is read-only. The fuzz target is
`fork_acceptance` in the local fuzz package; stable tests replay the same body
with deterministic seeds. Bounds apply before hostile graph/proof processing.
Reference parity currently covers the existing sorted-pack digest and byte and
index-entry totals. Server adoption and independent tier-two activation parity
are separate integration work; this module removes no conformance skip and
changes no current server path, read cost, wire byte, or stored format.

Fork-specific types live in `fork` because the shared skeleton does not define
whole-pack inventories, fork results, authoritative all-members emptiness, or
fork job/replay/reservation states. They reuse the shared logical identities,
revisioned observations, authority, grants, lifecycle, and publication contracts.
