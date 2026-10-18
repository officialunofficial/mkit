# Fork progress and activation

Fork acceptance saves the terminal result, replay result, and outcome
responsibility and settles any applicable reservation. Published clearance
installs that accepted membership and eventually enables destination writes.
[SPEC-SERVER §9.9](../../../../../docs/specs/SPEC-SERVER.md#99-fork) defines
this boundary. Clearance never changes the saved result or settles again.

The progress and activation decisions consume authoritative host facts. They
perform no storage operations, traversal, scheduling, or clock reads. Every
public item inherits the fork module's ALPHA stability level. These facts have
no wire or stored encoding.

## Retained evidence and current checks

The host retains the exact accepted source pair, source membership generation,
full inherited pack set, destination, operation binding, byte charge, and
terminal result. The activation decision checks the saved result against that
retained binding. It does not authorize a different source or charge.

A source change after the final source proof is ordered after the fork. Do not
re-authorize the source or repeat the final source proof during activation.
Current destination denial and lifecycle checks still apply before visibility.
Their evidence is a trusted host fence, scoped to the pack, destination,
operation, and apply attempt. The host must acquire the real checks; making a
fact value does not prove that acquisition occurred.

Every advancing commit compares recorded authority facts when fencing is on.
That includes preparation checkpoints, acceptance, physical membership writes,
and completion. Logical observation tokens cover the complete authority mode
and generation, and the applicable grant epoch. Authoritative absence is a
value to compare; unavailable acquisition is never absence. A host whose
membership owner cannot atomically compare the coordinator authority must use
a commit-fenced permission with revocation draining or refuse that capability.
A preflight authority read alone does not discharge this requirement.

## Guard matrix

| Boundary | Required evidence and comparison |
| --- | --- |
| Preparation progress | Exact operation and destination, job observation and progress, recorded authority and applicable grant epoch, exact pending reservation when granted; construction eligibility sampled at phase start |
| Acceptance | All acceptance guards and the final ordered source proof; progress fencing applies to this commit too |
| Member installation | Exact accepted binding and result, selected inherited pack, exact job progress, current destination clearance fence, recorded authority permission at the physical commit, exact live and published witness observations, apply deadline |
| Identical replay | Complete identical live and published witnesses; neither a partial pair nor a foreign witness establishes completion |
| Completion | Exact accepted result and complete progress; operation-owned destination write barrier and current authority guarded with the final job transition |
| Failed construction | No advancement or visibility permission; retain the inert destination and its saved failure |

Every decision above returns a `decision::Guarded<D>` with owned, typed guards
(see the guard matrix in [fork acceptance](fork.md)). A preparation `Advance`
carries the construction expiry as a `ValidThrough` guard: eligibility is still
sampled when the phase starts, but a commit ordered after the original lifetime
now fails the comparison and the redecision answers `Expired`. An accepted
phase ignores the bound, so clearance outlives expiry. An activation `Install`
carries the proof deadline as a `ValidThrough` guard and guards the destination
denial revision the proof was acquired under (`ForkClearanceProof::denial_revision`),
so a denial change after the proof fails the comparison instead of installing a
denied pack. The host separately retains exact pending reservation comparisons,
authority fences, full job CAS, and physical apply deadlines.

After acceptance, reservation expiry, outcome acknowledgement, and permitted
replay pruning do not cancel recovery responsibility. Clearance remains
redriven until complete. A denial or lifecycle refusal withholds visibility
and preserves the accepted response. No progress or activation decision emits
an acceptance outcome, reservation settlement, ref update, quota debit, or
holder removal.

## Host lowering

The reference host retains its storage routing, budgets, bounded waves, and
proof acquisition. It compares the exact job row beside coordinator authority
and reservation guards. Membership installation preserves absent-row CAS and
byte-identical witness replay. A partial identical pair after a lost CAS
remains retryable; a foreign value refuses installation. The host never
rewrites a conflicting witness.

The destination write barrier remains until the final activation checkpoint.
Cleanup is scoped to the original binding and never removes another fork's
holders. Transient evidence cleanup does not authorize publication or repeat a
terminal outcome.

## Reference profile boundary

The current reference profile implements pack denial and sealed inventory
checks. Storage leases, repository suspension, and lifecycle deletion remain
future integration in SPEC-SERVER's profile map. Its authority shard leases are
writer permissions, not storage lifecycle state. The adapter therefore creates
no synthetic active-lifecycle observation. A host offering those additional
features must discharge their lifecycle checks before supplying clearance proof
and retain their required commit fences.

`ForkLifecycleProtection::Managed` binds the construction's repository
incarnation to a current revisioned lifecycle observation. Missing acquisition
returns `UnavailableInput`. Authoritative absence, deletion, or a different
incarnation withholds clearance (`Withhold(ForkWithheld::LifecycleUnavailable)`, code
`ForkLifecycleUnavailable`); it never refuses or changes the saved result. Both the
observation and its revision belong to the activation/completion guard snapshot.
`NotOffered` explicitly selects a profile without those transitions. Neither
profile can change the accepted result; an already completed replay needs no
new lifecycle authorization.

## Durable checkpoints and proposed completion

The progress revision names the original durable job row used by the
coordinator CAS. A membership decision checks that checkpoint and the selected
inherited pack; serial, wave, and head-last scheduling remain host duties.
Physical permits bind the immutable acceptance and operation, and the final
coordinator unit compares the original complete job row.

A host can finish several units within one slice before saving a new checkpoint.
Completion therefore supplies its proposed final cursor and part separately
from the original durable progress. The decision validates the proposed complete
count, digest, cursor, and part, then authorizes the owned barrier release under
the original job CAS. It does not claim that proposed progress was already durable.
