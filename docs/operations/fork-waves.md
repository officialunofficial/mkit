# Fork wave bounds and latency model

Fork work overlaps independent storage operations within existing units.
It does not overlap fork phases or cursor commits. Without pack-level denial it
also overlaps independent pack units of planning and publication, as described
under [plan and publish waves](#plan-and-publish-waves). The index copy overlaps
source partitions; see "Index copy waves".

## Calls and ordering

Destination emptiness checks use at most six scans with a limit of one row.
The first existing read exposes accounting depth before wave selection;
known remaining calls must cover `2 * layers + 1` debits per scan.
Unknown allowances keep scans serial, so later refusals cannot mask an earlier
I/O error in the fork driver.
Source index statistics use at most six concurrent calls, narrowing when the
remaining allowance cannot cover shared accounting ancestors. A zero-call
reservation exposes the inherited depth without spending calls or dispatching
I/O. Stats need one local debit, up to two per inherited layer, and one for an
opaque leaf; unknown allowances keep stats serial. Holder copies use four
distinct object IDs at a time
within a page, reducing the width when the remaining allowance cannot cover
all eight possible mutation attempts per ID (25 calls including the holder
read). An unknown inherited allowance keeps holder copies serial. The first
holder read reserves its existing call before the width is selected. Its
reservation exposes the number of accounting layers, without spending extra
calls. Each layer can debit two ledgers, and their ancestors can overlap.
The width uses a conservative `2 * layers + 1` debit multiplier, including an
opaque leaf, so shared ledgers cannot let a later holder starve an earlier one.
The actual calls remain charged once per existing ledger; this multiplier
only narrows scheduling. The metadata accessor is private and does not change
reader accounting or admission.
Repeated IDs start another wave, retaining the original calls
and avoiding new contention on the same object state.

Each wave drains its replies and consumes results in input order. A failure
can leave later operations in that wave completed, but does not start another
wave. Successful work keeps the same backend calls. An error can therefore
spend more calls than the serial loop's early return. No allowance is raised.

Read calls reserve credit before dispatch and do not charge that credit again.
Statistics reserve their exact slice calls before dispatch because stats do not
consume read credit. Holder mutations retain their existing per-call charges
before each backend dispatch: the number of retries and whether the source
holds the object are not known in advance. CAS retries still draw from the slice
budget. A copy wave takes only as many holders as the slice can still pay for
(six calls each, at most 64), so no holder reserve is held back for pages
without candidates.

A holder write completed before a failed page checkpoint is safe to
repeat: the destination holder already exists, so its count does not grow.
Blocked holder outcomes still map to `NotFound` in input order. Distinct IDs
have independent holder and object-state rows.

The fork loops have no separate elapsed slice cutoff. Their existing storage
call allowance, job expiry, and freshly stamped apply windows remain in force.

## Index copy waves

The copy phase reads up to six of the source's sixteen index partitions at a
time. The job row keeps one cursor per partition (`lanes`), so a wave takes the
next page of each of the first open partitions. The width follows the same
rule as the emptiness scans: the first read is reserved before the width is
chosen, the known remaining calls must cover `2 * layers + 1` debits per scan,
and an unknown allowance keeps the copy to one partition at a time. A wave also
narrows to the calls left in the slice, and once its pages are read it keeps only
the leading partitions whose writes the slice can still pay for (the first
always stays); the others, and a failure that belonged to one of them, wait for
the next wave.

A wave runs in three stages, each finishing for the whole wave before the next:
the scans, the index writes (at most six at once), then the holders. Replies are
consumed in partition order and the wave answers as the same partitions taken
one after another would: the first failing partition's error is the one
reported, and no partition after it is counted. The `copied == expected`,
`MAX_SCANNED_ROWS` and object-limit checks run over a running total in that
order. A wave that spends the slice keeps none of its progress: the cursors and
counts return to where the wave began, and the next slice repeats it. Every
write is a put of the same row or a holder write that only raises a sequence, so
the repeat is safe.

Pages hold 500 rows, or 256 where holders are copied. Holder candidates do not
bound the page: a wave copies at most 64 holders in all, in partition and key
order, and the lane records the source key of the last candidate it finished
(`held`; an empty mark means the rows are written and no candidate is done, for
a partition the wave had no holder room for). The page's rows are already written, so the next wave scans the same
page, skips the written rows, and continues after that key; the page is counted
and its cursor advances only when its last candidate is done. A repeat of a
holder write is safe for the reason above.

| Files | Copy rounds before / after | Copy calls | Slices for the whole fork |
| ---: | ---: | ---: | ---: |
| 500 | 35 / 9 | 35 / 35 | 1 / 1 |
| 3,000 | 112 / 15 | 112 / 58 | 1 / 1 |
| 10,000 | 340 / 35 | 340 / 177 | 3 / 1 |

Rounds are measured on a store that sleeps 30 ms per call and reports a known
read allowance (`tests/fork_copy_rounds.rs`); extraction is deployed at 64 KiB
and the files are small, so no holder is copied.

## Plan and publish waves

Without pack-level denial a pack's unit is a few fixed calls: planning reads the
pack's member row, its proof and its sealed head (at most eight calls); a
publication write proves destination denial, reads the destination's two rows,
and applies the guarded write (at most eight calls).
Both overlap up to six packs. The width is chosen before dispatch from the
store's known read allowance and the slice's remaining calls at
`2 * layers + 1` debits per call, the same conservative rule as the loops
above; an unknown allowance, or denial, keeps one pack at a time. A wave starts
only with at least a whole unit reserve (300 calls for planning, 60 for a
publication unit) in the slice. Replies are consumed in input order, so the
first failure in pack order is the reported one; packs before it are kept and
the discarded reads of later packs are repeated by the next wave or slice.

Planning merges each pack's facts in order (the packs it names, its external
bases) and a wave never plans a pack that an earlier pack of the same wave
adds: those are read by the next wave. A pack with external bases scans its
dependency rows serially while it is merged, as before.

Publication keeps the member and head order of the serial path with three
stages recorded in `job.part`: the members other than the head are written
together (`2`), proved again together (`3`), and then the head is written and
proved alone (`0`, `1`). The head's rows, whose flag says every other inherited
pack is a member, are therefore written last of all. A job in stage `2` or `3`
resumes under any driver: one that cannot run waves does the same stage one
pack at a time. A write that failed may leave later packs' rows of the same wave
written; a replay finds them identical and an unrelated row is never
overwritten.

When the plan fits one slice the request carries it into the job, which then
starts after its planning phase. The carry is refused as a moved tip unless the
source still publishes the same packmap head and membership generation.

## Retryable fork errors

The request and timer can drive the same job. If a publication guard loses,
the losing driver re-reads both destination rows. It continues only when both
are exactly the witness it intended to write. A foreign value gives
`destination not empty`, a terminal refusal. A partial identical pair or missing
rows requires another attempt. Acceptance proves the source after preparation.
Activation repeats destination denial proofs before and after each write and
retains absent guards and the apply deadline. A refusal after acceptance leaves
the saved result intact and clearance pending.

Every `ForkError::Unavailable` returned by a request's job step carries
`Retry-After: 1`. The Connect code stays `unavailable` and its default HTTP
status stays 503. Retry the same fork request after one second; persistent
configuration or stored-state errors require operator investigation.

| Message | Meaning |
| --- | --- |
| `fork publish raced` | A publication guard failed, and the re-read did not find the complete identical witness pair or a foreign value. |
| `fork publish deadline` | The publication apply window expired. |
| `fork copy deadline` | The index-copy apply window expired; these writes have no contention guard. |
| `fork commit deadline` | The job checkpoint apply window expired. |
| `fork start deadline` | The job-creation apply window expired. |
| `fork start contended` | Creation could not find a winning job after bounded retries. |
| `fork storage unavailable` | A backend operation failed. |
| `fork unavailable` | A proof returned a retryable server error. |
| `fork job missing` / `fork job corrupt` | The job row is absent or cannot be decoded. |
| `fork publish state` | The publication cursor has an invalid stage. |
| `fork shard map` | The shard map does not supply the required partitions. |
| `fork requires authority fence` | Namespace enforcement requires an authority fence. |
| `fork reservation` | The job's reservation is absent or inconsistent. |
| `fork registration read` / `fork set read` | A batch read returned the wrong number of rows. |
| `fork in progress` | The job needs another slice; the request already returns `Retry-After: 1`. |

The creation labels can also arise before the first step; this header rule
applies to errors from the step. `fork expired` is a terminal job failure, not
an instruction to keep retrying.

## Memory and security bounds

Six one-row emptiness replies retain at most 3 MiB of raw values plus keys.
Statistics hold six small scalar replies. Four holder mutations have at most
152 rows in their immediate read
sets and hold scans, below the existing 500-row copy scan and 1,000-row reader
envelope. Nested mutation retries do not accumulate responses.

The two per-pack write proofs use the existing `WRITE_PROOF_CONCURRENCY` of
four when known headroom covers all sixteen first-page calls, including
`2 * layers + 1` possible shared-ancestor debits per call. A zero-call reservation
provides that metadata; tight or unknown headroom retains serial reads.
Four maximum values total 2 MiB, within the existing 4 MiB proof bound.
Valid directory waves hold at most `4 * 64 * 33` pointer-value bytes.
The sixteen bounded pointer pages remain retained as before;
pointed-to descriptor reads and nested proofs remain serial.

Fork publication and upload admission still skip full pack denial proofs when
`takedown_denial` is false. The deployment gate and all final guards stay at
their existing boundaries. The wave scheduling itself leaves reader paths and hook inputs unchanged.
Pack-serving proofs retain their serial public entry point; upload admission
uses a private write entry point. The acceptance and source-evidence changes
below introduce new stored formats and public construction requirements; see
the breaking-change migration notes in CHANGELOG.md.

## Enabling takedown denial after running with it off

Enabling denial on an existing store is a migration, not a config flip.
[SPEC-SERVER §14.2](../specs/SPEC-SERVER.md#142-blocklist) requires holder,
inventory, and proof-structure backfill before activation, and checks of objects
ingested with denial off when they are read after activation. See also the
[Worker denial configuration](workers.md#embedding).

1. Stop admitting new fork jobs and drain or finish every in-flight fork before
   changing the mode. Deploy the same configuration to request pipelines and
   fork timers; use `ForkTimer::from_config` with the pipeline configuration.
   The job row does not record a denial mode, so changing it mid-job is unsafe.
2. Inventory destinations forked while denial was off. Those forks built no
   cleared set or recorded external-base set. Under denial, their first
   publication walk covers the full inherited object closure and discovers
   external bases itself; every reached pack receives the advance-time denial
   proof. See [SPEC-SERVER §9.9](../specs/SPEC-SERVER.md#99-fork).
3. Measure the closure that each destination's proposed publication must walk
   against `MAX_ADVANCE_ITEMS` (4,096), including inherited history and the new
   commit. The walk also bounds packmap, pack and dependency sets. Repository
   byte size or file count alone does not establish that it fits. There is no
   existing operator command or typed read that reports this publication-closure
   size or inventories destinations by their creation-time denial mode; operators
   need their own fork records and closure inspection. Do not assume an unknown
   closure fits.
4. A destination whose required walk exceeds 4,096 items cannot advance after
   switching: `Step::Capacity` is permanent, and retries do not shrink the walk.
   Plan to re-fork affected destinations into empty destinations after switching,
   with denial on, so the fork builds the cleared set. For new deployments or
   forks that may exceed this limit, fork with denial on from the start.

This runbook does not supply backfill or migration tooling and does not raise
the cap. Complete the §14.2 backfill before enabling denial; re-forking addresses
this fork publication limit, not the other activation prerequisites.

## Latency model

This model uses sixteen ref-index and object-index partitions. It assumes
every call in a loop costs 300 ms when cold or 40 ms when
warm. Independent calls in one wave finish together. It excludes unchanged
setup, location lookup, cursor writes, retries, and descriptor continuations.
The holder case has a source holder and succeeds without a CAS retry.
The holder model starts with a fresh 600-call slice and one inherited
reservation layer beneath the local counter. The debit multiplier is five:
seven waves of four IDs, ten of three, then three of two. Each holder has four
serial calls, so those twenty waves take eighty rounds. Less initial headroom
or more accounting layers narrows waves further. These are models, not
network timings.

| Loop | Calls | Serial rounds | Wave rounds | Cold before / after | Warm before / after |
| --- | ---: | ---: | ---: | ---: | ---: |
| Empty destination, refs and members | 32 | 32 | 6 | 9.60 s / 1.80 s | 1.28 s / 0.24 s |
| Empty destination, refs only | 16 | 16 | 3 | 4.80 s / 0.90 s | 0.64 s / 0.12 s |
| Source index statistics | 16 | 16 | 3 | 4.80 s / 0.90 s | 0.64 s / 0.12 s |
| Holder page, 64 distinct IDs | 256 | 256 | 80 | 76.80 s / 24.00 s | 10.24 s / 3.20 s |
| Pack denial directory | 16 | 16 | 4 | 4.80 s / 1.20 s | 0.64 s / 0.16 s |

Two full emptiness checks and one refs-only check total 80 calls: 24.00 s
becomes 4.50 s cold; 3.20 s becomes 0.60 s warm. Duplicate holder IDs reduce the modeled
concurrency benefit.

Closure expansion stays serial: budget exhaustion mid-wave would change
first-error precedence. Revisit with a validated reference-page bound if fork
closure time matters.

## Acceptance, settlement, and destination write protection

Preparation copies index entries and holder evidence and counts the inherited
packs. The durable job's complete pack list is staged membership; preparation
installs neither local membership nor published-member witnesses. `Accept`
proves the source packs after preparation, then compares the exact published
pair, generation, publication sequence, visibility declaration, and visibility
revision. Visibility setters retain a monotonic revision under sharded storage,
including without history tokens, so changes away and back remain detectable.
Observed source changes answer uniform absence. Before proving packs, the job
captures source pair and visibility rows, every source index partition's revision,
the sixteen directory revisions, and content-state versions for all registered
denial subjects, including subjects with no current descriptor. Only after the
complete proof pass does it validate the captured evidence. Monotonic versions
close changes away and back across slices; validation never resumes pack proofs.
After acceptance or a retained failure, the timer deletes transient `fq` evidence
in bounded pages, including while activation is stalled. Each page compares the
exact job and evidence rows, respects backend operation and byte headroom, and
shares the timer call budget. Row deletions are the durable progress cursor;
restart or an uncertain reply resumes from the remaining rows. `Done` and write
barrier clearance wait for reclamation to finish. These deletions
change neither the accepted decision nor membership.

Custom publication policies supply a durable, non-repeating `fork_version` for
changes to `pack_available`; the default refuses new or unaccepted forks.

The acceptance commit retains the accepted result with the complete pack set,
operation binding, destination, visibility, membership incarnation, byte charge,
and recorded authority observations. It atomically commits replay and the
reservation outcome. Publication uses this binding and current destination
denial checks. Later source changes do not revoke the accepted result. An
interruption or denial at clearance leaves that result intact and redrives the
job; it never charges or settles again.

The `fb` coordinator row blocks ordinary destination mutations from registration
through clearance. Each ordinary coordinator write and lease grant guards its
absence in the same apply. These keys join existing batched reads, adding no
round trip for repositories without forks. A usable old shard lease cannot
escape the barrier: its grant already committed the repository record, which
makes registration's absence guard lose. Registration wins only while no such
lease exists. `Done` atomically removes the barrier after every accepted member
has been installed; a failed registered fork retains the barrier permanently.

| Coordinator commit | Before | After |
|---|---|---|
| Launch | Job absent, quota guards, deadline | Also recorded authority rows and exact pending reservation |
| Plan, trees, walk | Job CAS and deadline | Also recorded authority rows and exact pending reservation |
| Register | Registry/visibility/authority guards, job CAS, deadline | Also barrier absence and exact pending reservation; installs the barrier atomically |
| Copy and count progress | Job CAS and deadline | Also recorded authority rows and exact pending reservation |
| Acceptance | No separate decision | Final source proof, barrier ownership, recorded authority rows, job CAS, pending reservation, replay absence, outcome guards, deadline |
| Activation progress | Job CAS and deadline | Recorded authority rows at coordinator checkpoints; local permit or colocated authority guards on physical membership; projects only the accepted binding |
| Done | Job CAS, deadline, replay and reservation settlement | Recorded authority rows, job CAS, barrier ownership, deadline; removes barrier and retains the saved result |
| Pre-acceptance refusal | Job CAS, reservation/outbox guards, deadline | Same terminal-abort path; registered failures retain their barrier |
| Proof metadata reclamation | No reclamation | Accepted or terminal job CAS, exact evidence rows, deadline; no authority guard because it changes no decision or membership |

The job, authority generation, grant epoch, barrier, replay, and reservation live
in the destination coordinator. Progress reads the job and both fence rows in
one `get_many`; authority guards add no storage call. After a precondition loss,
the next read observes the job and fence together: a moved fence aborts an
unaccepted attempt, while an unchanged fence retains normal CAS retry handling.

Physical membership installation uses a local permit bound to the job and its
recorded fence. Permit issuance is registered in the coordinator before local
installation. A generation or epoch move freezes issuance, durably drains the
registry and replaces local permits with revocation tombstones before publishing
and acknowledging the new fence. Interrupted drains resume from their checkpoint;
a late activation fails its local atomic guard. Colocated writes compare the
recorded authority rows directly in the physical membership apply.

Ordinary relay index delivery, native index installation, and fork activation
append backend-atomic `Write::Increment` mutations to their existing batches.
Directory registration does the same only for its first immutable pointer.
The default reference batch shapes retain their existing storage round trips.
The stamp consumes one operation: custom reserved-operation or hook budgets
at the batch cap can require another chunk. The ordinary index boundary probe
measures this case. Overflow or corrupt counter encoding refuses the complete
batch. Content-state sequences likewise
fail on overflow rather than wrap.

Low-level drivers use `ForkEnv::with_publication_policy` and
`ForkTimer::with_publication_policy` with the same policy as the pipeline.
Drain unaccepted work before replacing a policy whose version history cannot
be preserved. Stored fork, permit and proof formats have no legacy decoder;
reset existing stores when adopting this revision.

The serving pipeline offers fork only with sharded repository indexes. Low-level
admission and unaccepted recovery enforce the same source requirement, because
single-partition membership mutations do not maintain these proof revisions.
Single-partition ordinary writes keep their existing batches. Completed results
remain recoverable without a new source proof.

Permit rows retain a deadline. Coordinator recovery holds transitions until
previously issued apply windows have expired, even if restoration lost their
registry rows. Completed forks drain their permits after removing the write
barrier. Ordinary lease renewal and authority bootstrap add keys to existing
snapshots and batches; they add no storage round trip to ordinary writes.

## Portable progress and activation decisions

The fork driver supplies its retained binding, progress, exact authority
observations, and applicable reservation protection to the pure progress
decision. It lowers the decision alongside the existing job CAS. The selected
phase, bounded waves, slice allowance, and physical key routing stay in the host.

Membership activation supplies the exact accepted result and sorted inherited
inventory, current destination proof, and live/published witness pair. The
pure decision distinguishes an initial install, an identical replay, a foreign
witness, and a retryable partial pair after guard loss. Source changes after
acceptance do not change that result. The host retains the real denial and
lifecycle proof calls and every physical authority permission at membership
apply. It never substitutes a coordinator preflight for a physical commit guard.

The final completion decision validates the accepted result and completed
inventory before the coordinator atomically saves Done and removes the exact
operation-owned write barrier. Proof reclamation, which changes no decision,
finishes before that completion check. The decision creates no terminal outcome
or reservation settlement. Failed destinations remain inert, and no cleanup
removes holders.
