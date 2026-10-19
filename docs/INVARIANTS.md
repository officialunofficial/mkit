# Invariants

This enforcement index summarizes properties across the mkit monorepo. The
linked specs remain authoritative; these entries add code and regression-test
pointers, not a separate contract. Apply each entry only within its implemented
profile; storage-only groundwork is labeled explicitly. The
[SPEC-SERVER profile map](specs/SPEC-SERVER.md#1-scope-and-relation-to-spec-transport-connect)
distinguishes current enforcement from future integration.

## Pack locations preserve read checks and verify bytes before use

**Always:** issuing a pack location applies the same repository membership,
read authorization, denial, takedown, and inspection checks as streaming.
Locations require both discovery support and request opt-in, and expire within
an advertised finite bound. Clients fetch without transport credentials and
verify the pack content address and exact length before returning any bytes.

**Because:** an external pack host must not bypass repository policy or promote
unverified bytes into the read path. Issued URLs remain usable only until their
bounded expiry or an earlier purge.

**If violated:** callers can read hidden packs, leak transport credentials, or
consume corrupted external bytes. A deployment can promise a takedown deadline
it cannot enforce.

**Enforcement status:** `Pipeline::download` shares its read gate with location
issuance. `PackLocationConfig` validates provider lifetime, URL, and length.
The native channel uses a separate credential-free TLS client; the protocol
client verifies both commitments and falls back once without location opt-in.
The pack-location conformance profile exercises the external HTTP boundary.

## Cached imports and gc agree on object retention

**Always:** gc's final age check and unlink exclude bulk refresh/write on the
same store. A cached import refreshes every object in its stored history
closure, including chunk leaves, once per run before publication; missing
cached objects refuse publication. The strict per-object grace bound remains
required for writers outside gc's worktree locks.

**Because:** a stale candidate read or a skipped cached descendant must not
turn a successful reuse into a dangling ref.

**If violated:** gc can delete an object after its writer refreshed it, or
prune an old descendant hidden behind a map-cache hit.

**Enforcement status:** shared/exclusive locks on the immutable format file,
`ObjectStore::prune_if_old`, `BulkWriter::reuse_object`, and import-run memoization.
Deterministic sweep interleaving, killed-sweeper restart, read-only reuse and
cached chunk-closure refresh regressions cover the boundaries. SPEC-GC states
the remaining zero-grace and long-import restrictions.

## Primitive contracts keep trusted construction private

**Always:** only the owning primitive module can construct `VerifiedPack`,
`ClosureProof`, or `Guarded<D>`. Caller-supplied membership facts retain exact
repository, incarnation, source, supplier, and revision bindings. Missing input
is separate from authoritative absence. Source pre-apply fences remain separate
from destination atomic guards.

**Because:** type-safe composition must not promote unverified bytes or missing
facts into acceptance evidence.

**If violated:** callers could bypass verification, cross repository boundaries,
or apply effects without every required live comparison.

**Enforcement status:** the initial ALPHA skeleton has private fields and
compile-fail doctests. The closure entry point enforces its semantic checks with bounded state-machine
tests. Pack verification and decision entry points land with their owners.

## Compute completion order never chooses verification evidence

**Always:** caller-owned jobs bind the immutable source, repository, run,
ordinal, inputs, operation, and byte/work permits. Only library-created outputs
can return. Results and evidence merge in ordinal order; stale outputs change
no counters. Serial execution remains the default. Outstanding and completed
but unmerged work stays inside one shared resident ceiling.

**Because:** worker timing cannot select a different refusal, bypass delta-base
ordering, or release input/output memory before the driver consumes it.

**If violated:** a late completion could seal another run, an earlier malformed
entry could be hidden by a later parser failure, or worker ownership could
exceed the advertised memory bound.

**Enforced by:** `pack_verify::verify` raw-Blob admission escrows, dependency
barriers, opaque jobs/outputs, ordinal merge, drained checkpoints, schedule
parity tests, allocation probes, and the bounded compute-schedule fuzz oracle.


## Decoded leaf reuse preserves the eager verifier's accounting

**Always:** an objects-index page passes ordinary authentication and logical
work charging before owned records can be reused. The optional leaf cache
never suppresses a page emission or delays a retained-evidence charge. It
releases its bounded reservation before later decoder or edge growth can use
that capacity, at checkpoints, on deferred entry refusal and at completion.
The driver's inline size and checkpoint representation remain unchanged.

**Enforced by:** decoded-leaf authentication, capacity, pressure, refusal,
checkpoint and 0/1/2/4/8-job differential tests. Successful roots, page bytes,
fragments and logical work match the eager path; integrity drain keeps the
first deferred refusal behind final source integrity.

## All-entry verification shares one acquisition stream with integrity

**Always:** `VerifyDriver` hashes each acquired pack range while framing and
decoding entries. An uninterrupted successful run acquires exactly the pack
length, apart from separately requested canonical delta bases. Entry refusals
and authenticated external-base absence remain deferred behind final trailer
and whole-pack identity checks. The bounded state holds only the first entry
refusal; signature failures retain their separate decode-first precedence.
Unavailable input remains immediately retryable and never becomes absence.

**Because:** remote sources must not pay for a second integrity pass, and
provisional decoding must preserve the integrity-first refusal contract.

**If violated:** acquisition cost doubles, a corruption verdict changes with
execution strategy, or a provisional object could become trusted too early.

**Enforced by:** `VerifyDriver` deferred-refusal drain, the public acquisition
table and competing-fault regressions in `verify_onepass`, exact-boundary resume
tests, and the `verify_onepass_heap` allocation epoch. Only terminal
`Step::Complete` constructs a `VerifiedPack`.

## Portable closure completion requires every occurrence and retained page

**Always:** direct-child closure checks every supplied verified object and every
advanced head. Membership batches use only the requested repository incarnation.
Every chunk occurrence contributes its verified Blob payload length, including
surplus manifests and repeated IDs. A later use cannot bypass a new obligation.
Only acknowledged authenticated pages support visited-state and relied-on member
proofs. Resource exhaustion and acquisition loss never yield a complete result.

**Because:** head-only traversal misses surplus entries; ID deduplication alone
can skip file-integrity obligations or erase a supplier dependency.

**If violated:** an incomplete or corrupt consumed set could be accepted, or a
caller could publish a truncated missing set as a complete diagnostic.

**Enforced by:** `mkit_primitives::closure::ClosureWalker`, its independent seeded
graph oracle, protocol/adversarial tests, and closure transition fuzz replay.
Reference-server integration is separate; this primitive grants no visibility.
## Primitive framing authenticates before emitting provisional frames

**Always:** the framing driver checks the header, authenticates the trailer and
whole immutable source, and then decodes frames in wire order. Every response
matches its exact request, generation, source binding, range, and length.
`FramedPack` remains distinct from all-entry `VerifiedPack` evidence.

**Because:** valid frame geometry alone cannot establish canonical object
identity, delta validity, signatures, or repository authority.

**If violated:** a caller could admit corrupted bytes or promote a provisional
frame into trusted pack evidence.

**Enforcement:** `pack_verify::framing` owns private completion construction.
Its `integrity_precedes_framing_and_every_decoded_frame_is_provisional` and
`wrong_short_stale_missing_and_duplicate_replies_never_advance` tests pin the
integrity boundary and host response protocol.

## Primitive retained evidence never treats missing pages as absence

**Always:** an absence answer requires an authenticated route to the correct
leaf under the expected source, repository, ruleset, and root. The framing
driver blocks dependent progress until acknowledgment of the exact emitted
page commitment. Nested decoding shares cumulative work and allocation limits.

**Because:** externally retained bytes can disappear or change independently
of a machine's logical progress.

**If violated:** lost scratch could manufacture membership absence or complete
an operation whose evidence no longer exists.

**Enforcement:** `evidence::proof` tests
`pinned_empty_root_proves_absence_and_missing_page_never_does` and
`inclusion_and_before_between_after_absence_are_exactly_keyed` pin query-bound
absence. Framing's
`retention_applies_backpressure_and_acknowledgments_are_exact` pins repeated
retention events and refusal of wrong or duplicate acknowledgments. Page and
checkpoint decoders reject unsupported versions, malformed bounds, and trailing
bytes; checkpoint checksums grant no authority to resume.

## Differential conformance compares validated protocol decisions

**Always:** deterministic differential fixtures pin both servers' business clocks
and use fixed signing keys, nonces, and timestamps. Each replay fingerprint is
validated against its target's exact signed operation before normalization.
Reports preserve query order, multiplicity, and terminal responsibility counts.
Execution failures do not become passing equivalence results.

**Because:** different server origins and allocated identifiers can represent the
same protocol decision, while an invalid replay binding or repeated settlement
is a protocol difference.

**If violated:** normalization could hide corrupt replay records or duplicated
acceptance effects, and two broken servers could appear conforming.

**Enforcement:** the differential runner drives wire requests and typed HTTP
observations. Native two-host and mutation regressions run in the Cloud Build
workspace test gate. This checks decision equivalence; Tier 2 separately checks
crash, recovery, and concurrency behavior.

## Primitive cold resume binds cursor metadata before decoder progress

**Always:** Decode resume compares the validated core cursor's source length,
window size, position, payload total, version, entry count/index and expected
whole-pack identity with its outer envelope. It reserves restore memory first,
recovers every retained predecessor page, then authenticates the reacquired
window prefix. Cumulative work, evidence and historical memory peaks survive.

**Because:** an internally consistent cursor can still belong to a different
source or logical boundary, and a lost page cannot support dependent progress.

**If violated:** resumption could skip entries, substitute bytes or evidence,
or repeatedly reset the resource ceiling.

**Enforced by:** `pack_verify::framing::checkpoints::resume_tests` covers each
binding, every acknowledged entry, compressed cross-window frames, lost pages,
changed prefixes and exhausted restore/admission budgets. The framing fuzz
schedule compares cold restart with uninterrupted results and refusals.

## Conformance distinguishes absent features from implementation gaps

**Always:** cases for undeclared protocol features report not applicable with
feature names. A known gap in an offered feature needs a declared skip with a
reason. Tier-2 cases use the normative HTTP test-control binding, independently
of the server's language, layout, or orchestration.

**Because:** an optional feature is not an unimplemented requirement, and an
in-process API would prevent black-box conformance across implementations.

**If violated:** reports can hide protocol violations or require reference
orchestration from an independent server.

**Enforcement:** the conformance profile, report, and controlled-host tests pin
feature applicability, stale skip rejection, and enabled/disabled authority RPCs.
The native conformance CI job exercises both protocol tiers over loopback HTTP.

## Acceptance retains replay and terminal responsibility

**Always:** an accepted signed ref write retains its live effects, replay result,
applicable charge, ticket closure and repository membership additions, plus one
terminal responsibility per reservation, in its authoritative atomic unit.
Replaying its original identity does not repeat those effects. Cancellation and
response loss do not prove abort.

**Because:** another request can observe acceptance before its response arrives.
Recovery must resolve that same decision and settlement identity.

**If violated:** a retry could duplicate settlement or expose a ref whose
acceptance cannot be recovered.

**Enforcement:** SPEC-SERVER §3.1–§3.2 define the protocol requirement. The
conformance crate's two tiers cover wire replay and controlled acceptance
snapshots/restarts. The retained-memory reference test host declares process
kill recovery unsupported; persistent guarantees require a persistent host.

## Published clearance preserves acceptance and the eligible prefix

**Protocol requirement:** clearance atomically publishes eligible added
membership and the greatest contiguous eligible ref prefix, preserving the
head/packmap pair and deletion boundary. A configured publication Event and its
durable delivery responsibility belong to that pointer-changing unit. Clearance
never repeats acceptance charges, ticket consumption, terminal outcomes, or
settlement. Combined acceptance and clearance carry all guards of both decisions.

**Because:** readers may observe publication after acceptance and after restart.
A delayed verdict must not resurrect a deleted ref or create a second payment.

**If violated:** fail clearance or re-plan without exposing the ineligible
prefix; preserve the original acceptance and its settlement responsibility.

**Enforcement:** SPEC-SERVER §10.2 and the conformance coverage table define
portable snapshot, restart, prefix, deletion, and combined-race cases. Reference
publication storage and recheck tests enforce the implemented membership and
prefix rules. Configured lifecycle Events and asynchronous inspection holds
remain conditional requirements pending their integration.

## Membership witnesses pair removal invalidation with a reliance fence

**Protocol requirement:** a generation/removal-version witness guards retained
usable membership only when every removal or inspection serving stop invalidates
it atomically. Repository lease deletion invalidates the generation; per-ref
deletion preserves shared membership. Independent authorization, lease, and
denial checks retain their own freshness. New reliance defeats a stale GC drop
through per-member mark clearing or a guarded repository reliance version.

**Because:** unchanged membership records alone do not prove usable membership,
and a new ref may rely on a member without modifying that member's record.

**If violated:** reject or re-plan the stale acceptance or removal proposal;
never retain an accepted ref whose required member was removed by that race.

**Enforcement:** SPEC-SERVER §13.3 enumerates removal events and both reliance
mechanisms. The reference design uses per-member mark clearing. Portable GC and
inspection races are conditional on the server offering those features; retained
inspection storage groundwork alone does not implement them.

## Fork acceptance gates destination activation

**Protocol requirement:** a server offering fork stages membership without a
ref and records guarded acceptance, replay, and terminal outcome responsibility
in one atomic unit. Its destination is neither reader-visible nor writable
before that acceptance. Failure leaves the destination inert. With authority
fencing enabled, every advancing commit and acceptance compare the recorded
authority facts. Acceptance requires a final source proof after all destination
membership staging and before acceptance commits: the admitted published pair
and membership generation still match, and every inherited pack is published,
readable by the forking principal and not denied. The fork is ordered at that
proof; earlier source changes refuse uniformly as a missing source, and later
source changes do not invalidate acceptance.

**Because:** construction may survive a crash or continue after revocation;
partial construction must not grant repository access.

**Reference mechanism:** the job stages the inherited pack set before guarded
acceptance, settles its saved result once, and then activates membership.
Physical activation compares a partition-local permit, or direct authority guards
when colocated. A fence move freezes permit issuance and durably invalidates all
issued permits before acknowledgement. Source proof captures mutation versions,
proves every inherited pack, then validates those versions, so resumed slices
share one coherent source point. Portable conformance results remain separate
from this implementation description.

**Enforcement:** [SPEC-SERVER §9.9](specs/SPEC-SERVER.md#99-fork) defines the
conditional protocol requirements. The
[conformance coverage table](../rust/crates/mkit-server-conformance/README.md)
records exercised cases and remaining declared gaps; implementation alone does
not establish a passing conformance result.

## Typed pack evidence retains exact keys and live witness semantics

**Always:** exact pack index reads use only supplied packs, preserve present input
order and duplicates, and validate every frame against its supplied pack length.
At most 1,024 packs use eight 128-key reads through the caller's budgeted store.
Pack visibility reads decode both live witnesses; both must be unheld, match the
chosen membership generation, and be cleared unless the caller uses a writer view.
Corrupt rows, malformed replies, and exhausted budgets refuse the whole result.

**Because:** a generic member lookup may choose a different duplicate pack,
and one witness alone cannot prove confirmed lineage visibility.

**If violated:** callers could misattribute an object, accept a partial visibility
proof, or consume unbounded metadata work.

**Enforced by:** `ReadAccess::{object_index_in_packs, pack_witness}` and
`reads::tests` routing, frame-bound, batch, budget, and witness parity regressions.
These are trusted evidence APIs; authorization and final serving guards remain
at their existing boundaries. No wire or stored-format change.

## Optional performance measurements retain behavior and privacy

**Always:** `perf-metrics` collectors retain fixed-size numeric aggregates and
constant partition-kind, stage, operation, and stop-reason labels. They never
retain keys, credentials, names, object ids, values, or error details.
Default builds omit new timers, metadata, and log events. Enabled builds execute
the same checks, budgets, checkpoint writes, and reply bodies.

**Because:** measuring latency must not disclose private data or change a
security boundary, page boundary, scheduling decision, or resource allowance.

**If violated:** diagnostics could leak private repository data, distort timing,
or alter correctness while measuring it.

**Enforced by:** feature-gated collectors, fixed denial buckets, and native
verification instrumentation tests. Slice observations are scoped to each
future poll. Missing alarm or failure evidence stays unknown; telemetry never
guesses a disconnect or adds storage reads to recover diagnostic state.
Durations measure elapsed wall time; synchronous CPU requires profiling.
See [Performance measurements](operations/performance-metrics.md).

## Packmap advances preserve node bytes and live-ref leases

**Always:** native repository pushes in `mkit-sync` and protocol-client pushes
use the same pure planner. The CLI delegates repository push mechanics to sync.
New pack ids retain apply order. Full overlap permits a head-only advance;
partial overlap appends the full requested set. Resets clear the predecessor
but CAS against the live prior ref, even on a retry.

**Because:** deterministic nodes identify restarted pushes, and a reset must
still win its ref race before advertising the new closure.

**If violated:** retries could append redundant nodes, change content ids, or
replace a concurrent writer's packmap without its lease.

**Enforced by:** `transfer::packmap::plan_advance`, `mkit-sync::push`, the protocol
client push driver, and `packmap_planner`'s former-driver matrix and property
tests. Sync's native push regressions and the CLI push goldens pin pack ids,
ref moves, and output. Chain validation, reset authorization, upload, and
conflict handling remain driver boundaries. Connect repository operations use
`ClientSource`; other transports use `TransportSource`.

## Connect retries preserve identity and durable acknowledgements

**Always:** `mkit-client` owns Connect encoding and decoding. The host selects
credentials, grants, admission helpers, retry scheduling, and receipt storage.
Ambiguous writes retain their authenticated identity until expiry. A durable
part receipt is stored before progress or the next part. Fresh clients reuse
acknowledged parts only when destination, signer, ticket, pack, and geometry
match. Signing and exchange time consume the same attempt budget.

**Because:** retrying a logical write must not duplicate mutation or charge,
and a process restart must not discard an acknowledged upload part.

**If violated:** a retry could execute a second write, reuse another upload's
receipt, resend durable parts, or exceed the operation deadline.

**Enforced by:** `ClientSource` write recovery and caller-owned `ClientSession`,
host request policy, `NativeHttp` budgets, both-backend push and policy tests,
the multipart process-kill test, and native streaming and response compatibility
tests. Session locks release before host callbacks; receipt observation precedes
successful ticket cleanup.

## Native connection reuse never replays a started request

**Always:** reads and signed writes reuse at most one idle HTTP connection per
origin for ten seconds on the same current-thread runtime. Automatic connection
recovery uses only hyper's recovered, untouched request, before writing starts;
signed headers, nonce, and buffered or streamed body remain identical. Failures
after writing starts return to caller-owned recovery. Partial responses and
cancellation do not make an incomplete exchange eligible for reuse.

**Because:** connection reuse removes repeated TLS handshakes, while only an
untouched request establishes that no mutation could have reached the server.

**If violated:** a pooled retry could duplicate a write, change its identity,
reuse an expired connection, or expose bytes from an interrupted response.

**Enforced by:** `NativeHttp`'s bounded idle pool, hyper's pre-start cancellation
retry, native connection reuse/idle expiration/post-write disconnect/streamed
idle-close/partial-response tests, and the real HTTPS CLI latency comparison.

## Custom ref admission fences the committed presence delta

**Always:** a configured custom Admission sees every ref write's resolved
effect before mutation, including ticketed advances, published-pair creation, and implicit pack
consumption. CAS conditions bind conditional writes. Unconditional writes
carry the same presence observation across retries and guard it in the applying
batch; a changed presence aborts the write. Deleting an absent ref is
`NoChange`. Duplicate destination names are rejected before custom Admission,
so a single ref cannot advertise multiple effects. Default Admission retains
its existing accounting and paths.

**Because:** an embedder may reserve ref capacity separately from pack bytes.
The admitted presence delta must describe the successful apply exactly.

**If violated:** a ref could escape admission, a retry could commit an
unreserved create, or absent deletion could decrement a counter incorrectly.

**Enforced by:** `pipeline::resolve_ref_updates`, `plan::decide_refs`, the
shared pending-reservation outbox planner, and `pipeline::tests::ref_admission`.

## Request read scheduling retains ordered boundaries and exact reservations

**Always:** independent reads consume results in their original semantic order.
Every dispatched wave reserves its backend calls first and shares the existing
six-call admission envelope. Unknown or insufficient allowance keeps the serial
path. Ref listings refill a freed slot without waiting for a slower peer;
each dispatched scan owns its reservation. A failure stops refill, drains all
dispatched scans, and returns the earliest source error in source order.
Delta members stay serial between contiguous raw runs. Continuation
activation stays after authorization and anchor validation; closing reads stay
after the guarded apply. Final denial and membership checks stay after all
seam callbacks, with fresh per-phase state.

**Because:** fewer serial rounds must preserve the same authority, live serving
stop, response absence, and invocation resource bounds.

**If violated:** a budget refusal could mask an earlier error, a cached guard
could serve revoked content, or concurrent reads could exceed backend bounds.

**Enforced by:** reservation and precedence tests for inventory, dependency
reads, raw runs, lease reads, implicit packmap prologues, and continuations;
the round probe pins equal-or-lower call counts and the shared concurrency
limit. The waves introduce no durable state or restart step.

## Consecutive tiny verification slices preserve durable recovery

**Always:** tiny decoded packs share one handler's call allowance across at most
eight slices. Canonical packlists qualify by their 256-byte encoded-size bound;
ordinary packs require one to three frames and at most 16 KiB of encoded, decoded,
and external-base data. Effectful extraction keeps its separate slices. Each intermediate checkpoint atomically guards the job, verification
state, and original timer before the next slice begins. The original timer remains
until the final guarded reschedule; retries with a different physical timer key
retain single-slice scheduling. The physical tick's elapsed deadline, a two-second
handler cutoff, and the remaining-call check stop chaining. The deadline is
inherited without refreshing it, including after checkpoint I/O. External closure
lookups retain their full-slice reservation; bounded Decode facts only predict
resource cost and never replace fresh closure reads. Relay discovery runs only
after a durable AwaitDelivery checkpoint, with bounded source inspection and the
registered handler's existing physical alarm limits, hooks, order, and watermarks.

**Because:** removing alarm waits must preserve recovery after a lost commit reply
and must not grant another slice's worth of backend calls.

**If violated:** a crash could lose runnable work, concurrent verification could
commit stale progress, or inline delivery could bypass a hook or exceed an alarm
allowance.

**Enforced by:** `indexed::job::tiny`, `timers::inline_relay`, and the tiny-slice
fault, delivery, backlog, and physical-budget tests.

## Closure and index callbacks preserve per-slice replay semantics

**Always:** ClosureResolve and EmitIndex outside the tiny-pack path share one
callback allowance across at most eight durable slices, with separate settings
that accept one for single-slice scheduling. Every intermediate commit guards
the original timer and job. Each continuation re-reads its phase before work.
The physical deadline and two-second cutoff retain their original meanings.
Closure deletions and satisfying-pack dependencies commit with the checkpoint.
EmitIndex repeats its deadline, direct-batch denial checks, epoch-lease renewal,
relay enqueue, and newest outbox-sequence read in every slice. Replay can append
duplicate relay sequences; same-value index puts and target holder folding
retain at-least-once delivery semantics. AwaitDelivery waits for the newest
recorded sequence before verification advances.

**Because:** a callback that continues after a durable checkpoint must have the
same effects as the timer firing again immediately, including after lost replies.

**If violated:** replay could skip a dependency, lose runnable work, bypass a
fresh guard, exceed a call allowance, or publish before index delivery completes.

**Enforced by:** the durable-slice driver, phase callback crash, budget, phase
race and output-parity tests, EmitIndex relay replay tests, and the verification
probe in both denial modes. No wire or stored-format change.

## Consecutive Extract selection slices preserve durable recovery

**Always:** an Extract callback outside the tiny-pack path runs at most eight
durable selection slices,
sharing the existing call allowance, a two-second elapsed cutoff and the physical
tick deadline. Both ends of an intermediate slice must remain selection stages. Each next
slice checks its freshly read phase before work, so a concurrent restart or
advance cannot run another phase inside the selection callback.
Every intermediate checkpoint guards the original timer and job; the original
timer remains runnable after a crash or lost reply. Each slice repeats all source
and denial checks. Each slice retains its 16-step and batch-operation ceilings,
so a frozen clock permits at most 128 selection steps per callback.

**Because:** local selection should not require a physical alarm for every small
checkpoint, and sharing a callback must not refresh its resource allowance.

**If violated:** work could lose its timer after a crash, bypass a fresh guard,
or starve other timers with unbounded synchronous work.

**Enforced by:** `indexed::job::tiny` and the Extract callback crash, budget,
output-parity and pipeline-probe regressions. No stored-format change.

## Chained Extract selection preserves guarded slice boundaries

**Always:** only Extract selection stages run together inside a slice, and
PREFLIGHT/UPLOAD chunk walking chains only staged, local, non-delta member
frames that decode without a saved `member-frame` row. The
guarded checkpoint commits their progress once; effect stages begin in a later
slice and a part upload still ends its walk slice. Chaining stops before the
call, operation, step, or time budget is
exhausted. A failed later selection step or fused chunk leaves the preceding progress
checkpointable and retries that step on the next slice. A hard ceiling of 16
steps applies even when the Worker clock is frozen during synchronous CPU work;
the two-second elapsed check is a further limit across I/O. Each chunk's own
denial read stays per chunk; a source pack's denial is read once per slice,
after its last chunk and before the part upload and the commit.

**Because:** cutting alarm waits for small packs must preserve the durable
verification order and the Worker's per-invocation bounds.

**If violated:** a crash could skip an effect or lose selection progress, or
one alarm could exceed its storage or time limit, or a pack block landing
mid-slice could be uploaded past.

**Enforced by:** `indexed::job::extraction::may_chain` and
`may_chain_chunks`, their boundary tests, and
`indexed::extraction_chain_tests` and `extraction_budget_tests` crash-at-apply,
effect-stage and deferred-denial tests.

## Production verification retry telemetry exposes only fixed failure classes

**Always:** failed and raced verification timer fires emit only a typed,
fixed error class plus the proposed retry delay and attempt. Metric labels
contain only outcome and class; the event adds no identifiers or raw errors.
The existing guarded timer move, retry formula, and test-faults payload stay
unchanged.

**Because:** operators need to diagnose delayed verification without exposing
backend credentials or changing retry behavior.

**If violated:** backend error text could leak private data, or observations
could disagree with the timer's persisted retry plan.

**Enforced by:** `timers::failure_class`, the shared `timers::retry_plan`, and
`timers::telemetry_tests::verification_failures_emit_redacted_classes_and_retry_plan`.

## Published-source branch creation never composes separately read values

**Always:** a same-repository branch creation copies the head and packmap from
one authoritative published row. Before every destination apply it reauthorizes
the source and compares the complete captured row. A move after that fence is
concurrent; success still copies both original values. Both destination refs use
Missing. A committed replay returns the stored result without recapturing.

**Because:** source and destination branches can occupy different partitions,
and independently read head/packmap values can race. The immediate path preserves
the source's existing coverage without introducing a history walk; configured
publication checks retain their normal limits.

**If violated:** a branch can publish a mixed pair or a revoked source can be
read through an earlier authorization.

**Enforced by:** `pipeline::published_source`, the final `apply_loop` source
fence, and published-source copy, interleaving, replay and uniform-absence tests.

## In-process object reads retain id-route authority and bounded proofs

**Always:** canonical prefetch binds a repository and a verified view. Public
reads require anonymous published/public reachability; owner reads require a
current auth-v2 owner or write-grant envelope and writer authorization. Each
16-ID batch shares one bounded reachability walk and one authoritative global
denial descriptor pass, inside the 8,500-call core share. Indexed size queries
never load a requested object's bytes, including as a delta reconstruction base;
canonical ancestor reads may prove reachability. Size reads check each reconstruction
base object and selected pack using canonical resolution’s metadata selection and
depth/cycle bounds. Blocked ancestry retains prior proofs and leaves unproven IDs
absent. MemorySource verifies integrity
on every synchronous read, including Merkle object identities.

**Because:** embedders need manifests and proof inputs with HTTP's privacy and
takedown guarantees, without async blocking, per-chunk reads or per-ID scans.

**If violated:** a caller can obtain private, pending or blocked objects, exhaust
a Worker invocation through repeated proofs, or trust corrupted prefetched bytes.

**Enforced by:** `pipeline::object_reader`, shared `http_objects::reach::walk_many`,
`takedown::denial::object_denials`, budgeted stores and the indexed member-cache
read prohibition; reader presence/call-count/poisoned-frame/grant-revocation tests;
native HTTP disclosure byte parity; `store::memory` integrity tests.

## A selected-ref session never uses all-ref root discovery and its checkpoint never survives a proof reset

**Always:** session canonical and metadata reads on a `with_selected_ref`
reader root only at that ref's authoritative anchor — the owner view's live
ref, the public view's published head — never at all-ref discovery. The
immutable capture checkpoint (ref, raw publication/ref values, full
publication, post-activation security digest, expiry, identity generation) dies
with every proof reset, expiry, reader rebind, helper capture or revalidation
stop. Parent/tag-target roles and decoded commit/remix facts exist only under
a live checkpoint and are structural evidence, never permission.

**Because:** history continuation issuance must trust that the capture
it re-verifies is the exact anchor the session read from, and that lineage was
recorded under that capture only.

**If violated:** a session could silently broaden to unrelated refs, an
issuance fence could pass against a replaced anchor, or recorded history edges
could outlive the capture that authorized their interpretation.

**Enforced by:** `pipeline::read_proofs` checkpoint/lineage and reset funnel,
`pipeline::object_reader::selected` capture and fence; `selected_ref_tests`
single-ref capture/tag/unpeeled/off-ref/divergent-anchor/missing-ledger/ABA/
expiry/rebind/helper tests and `read_proofs` reset/lineage unit tests.

## History continuations carry verified state, never permission, and caps never truncate

**Always:** `issue_history_continuation_in` performs no object or storage
proof I/O — it validates the sealed `TimestampDiscovery` walk against session
memo evidence (recorded history edges and decoded timestamps) and re-fences
the retained capture checkpoint, so a version-2 token carries only
server-verified priority keys plus a bounded witness of pending lineage. A
redeemed token confers no permission: every served object is re-read live with
current membership, denial and authorizer checks, a carried key is rechecked
against the object at emission, and imported proofs die with the request.
The token's fixed lifetime is the minimum of its configured TTL and any
write-grant expiry; successors inherit its absolute expiry. The issuing request
envelope does not cap that lifetime: each authenticated page re-verifies its own
signed envelope and current writer authority. The request-local
proof window still bounds each page's evidence without capping the token.
History state caps — frontier, emitted set, witness, payload — fail as typed
`HistoryStateLimit` errors in both views, never as truncated output or
uniform absence.

**Because:** a continuation is the only place the server trusts carried
priority state across requests; if issuance re-read objects it would re-walk
page 1, if a token conferred permission a replayed or stale credential would
serve objects, and if a cap truncated silently the caller would lose history
entries without any signal to restart.
The fixed token lifetime lets a walk span multiple request-local proof windows.

**If violated:** issuance could re-walk page 1 per request, a forged or stale
token could widen visibility or skip denial, or a reducer cap could drop
commits silently, corrupting the caller's log while looking complete.

**Enforced by:** `pipeline::object_reader::history::continuation::issue`
memo-only validation and fences, `history_token` bounded v2 codec and
`HistoryStateLimit` mint/verify mapping, `read_proofs::restore_witness`
isolated proof scope; `timestamp_tests` no-object-I/O issuance, replay,
seed-window, cancellation, refusal and cap tests plus the `history_token`
codec bounds; continuation lifetime tests for advancing clocks and exact TTL,
fresh and expired request envelopes, and grant expiry.

## Private scanner retrieval requires current ticket and global-denial checks

**Always:** scanner byte reads require both a dedicated short-lived capability
and an allowlisted scanner auth-v2 signature over the exact private request.
Every ticket bound to the requested raw pack must still be open and unexpired
at request time. With `takedown_denial=true`, global denial must permit the
bytes; with it false, block/action reads and denial-specific descriptor proofs
are skipped. Credential, ticket, lifetime and range checks remain in both modes.
Apply consumption,
terminal close, ticket expiry or capability expiry yields the same `not_found`
as a missing pack. Fail-closed inspection leaves tickets open, so retrieval
intentionally survives that attempt only until capability expiry. Retries keep
the inspection id and mint a fresh capability.

**Because:** staged bytes are absent from the public serving view, and private
inspection authority must remain bounded without weakening global blocks or
introducing an existence oracle.

**If violated:** a scanner can read foreign, expired or blocked staged content,
or reveal whether a pack exists through error differences.

**Enforced by:** `rust/crates/mkit-server/src/scanner_retrieval/` capability,
current-ticket and denial checks with shared call/response bounds;
`rust/crates/mkit-server/src/takedown/denial.rs` prefetches at most eight
first descriptor pages with at most 4 MiB of raw descriptor values plus
bounded key, cursor and collection overhead; continuations and
nested inventory/chunk/action proofs remain sequential with their existing
bounds, and existing callers remain serial; core and native scanner retrieval
regression suites. Embedders configure and mount scanner retrieval explicitly.

## Ticketed pushes bind uploaded bytes to one paired advance

**Always:** a Connect push opens a signed ticket for each pack that needs one,
uploads that ticket's bytes, and commits at most seven distinct ticket ids in
an advance pairing `refs/heads/<branch>` with `refs/mkit/packmap/<branch>`.
Only the current data packs and current MKPL node contribute ids. Multipart
receipts are durable before the next part begins and remain until the advance
commits. An ambiguous advance retry retains its nonce until the envelope
lapses; polling renews before the worst-case retry ladder could cross expiry.

**Because:** a stale node ticket, early receipt deletion, or changed nonce
could make an otherwise complete push fail or replay a committed write.

**If violated:** a push can strand content, publish an incomplete closure, or
lose resumability after interruption.

**Enforced by:** `mkit-transport-connect/src/client.rs` ticket mapping, part
store and poll loop; `mkit-cli/src/remote_dispatch/packmap.rs` current commit
set; Connect client wire and CLI receipt-store tests; native FS end-to-end
ticketed upload and resume tests.

## Grant revocation fences every leased ref shard

**Always:** a grant epoch change reports success only after every leased
ref shard has acknowledged the new epoch or its old lease has expired.
Each granted write checks its epoch at authorization and again in its
atomic ref-shard apply, including after a failed apply is replanned.

**Because:** an owner must be able to treat a completed epoch update as
revocation of every older grant, even when a write was already in flight.

**If violated:** a stale grantee can commit after revocation has completed.

**Enforced by:** the grant-epoch and ref-scope wire suites and the pipeline's
epoch-lease tests.

## ListRefs pages make bounded forward progress

**Always:** a nonterminal ListRefs page contains at least one ref, its token
binds the repository and normalized prefix to the last emitted full name,
and every encoded page is at most 2 MiB. A failed bucket scan fails the
entire page with `unavailable`.

**Because:** clients reject repeated tokens and nonincreasing names; an
unbounded response exceeds the Connect client message limit.

**If violated:** a client loops or drops refs, or a partial merge appears to
be a complete listing.

**Enforced by:** `pipeline::list` property and large-list tests, the
`connect_dispatch` paging wire test, and the Connect encoded-length guard.

## Storage receipts attest recorded state without exposing inspection

**Always:** a storage receipt binds a committed live advance or lease change
to its issue-time terms and deployment role key. An advance receipt contains
only the writer's ref and consumed-ticket facts, never publication, hold, inspection,
or cross-repository physical-storage facts. Replays and later fetches return
the same signed bytes.

**Because:** changing the claim after commit defeats audit evidence, while
publication or physical-storage details can expose inspection decisions or
other repositories' holdings.

**If violated:** a writer can use receipts to evade detection, infer another
repository's packs, or receive contradictory evidence for one operation.

**Enforced by:** `rust/crates/mkit-server/tests/golden_receipts.rs` pins the
format, subject and key-window checks. Runtime issuance, replay and field
exclusion are specified in SPEC-SERVER §15 and await WP-5.8 implementation
and conformance coverage.

## Ticketed UploadPack writes no business metadata and requires a marker

**Always:** a ticketed UploadPack verifies the signed pack commitment and
ticket before reading bytes, streams the complete pack through a verifying
blob sink, and writes a content-addressed marker in the upload-marker
namespace after the pack commit. Only bounded authoritative generation/mode
reads are permitted; it writes no metadata row and makes no quota charge,
replay reservation, authorization, admission or `pre_receive` call.

**Because:** the marker proves that a holder of this ticket supplied and
verified these pack bytes. WP-1.10 requires it with the pack blob before
consuming the ticket, even when another repository already stored the pack.

**If violated:** an advance could attach a globally present pack without an
upload, or a ticketed stream could create business metadata or bypass revocation.

**Enforced by:** `mkit-server` pipeline tests `ticketed_upload_no_metadata_and_marker`,
`ticketed_upload_failures_leave_no_marker`, and `upload::marker::tests::golden_upload_marker_v1`;
wire cases `tickets.upload_pack_ticketed` and `repository.ticketed_upload_multi`.

## Git audit establishes correspondence without a signing key

**Always:** imported graph edges and translated unsigned fields are derived
from retained Git bytes and checked under the pinned public key. A head's
provenance claim must match its exact subject, ref, source and versions.

**Because:** valid signatures on unrelated twins do not authenticate a mutable
Git-to-mkit mapping cache.

**If violated:** swapped mappings or unrelated attestations can pass an audit.

**Enforced by:** `rust/crates/mkit-cli/tests/git_import_integration.rs` mapping
swap, unrelated attestation and private-key removal regressions; the full
45-test integration suite passes. Golden translated bytes remain unchanged.

## File equality survives valid representation changes

**Always:** different file object IDs compare by verified byte streams; modes
remain separate. Restaging identical content keeps the staged ID only when its
representation is valid for the new entry type; symlink targets use a single
Blob. Chunk failures remain errors, including after the first differing byte.

**Because:** an inline Blob, fixed-size manifest and CDC manifest may describe
the same bytes with different immutable object identities.

**If violated:** clean worktrees appear modified, restaging changes identity,
and merge or overwrite decisions depend on chunk boundaries. Retaining a chunked
file object for a symlink produces an index that cannot be committed.

**Enforced by:** core `worktree::blob::equality_tests`,
`ops::diff::tests::equal_content_different_chunk_layout_is_clean`, and
`rust/crates/mkit-cli/tests/content_representation_integration.rs`. Comparison
holds at most one chunk per side plus manifests; rename fingerprints are
memoized for one diff and confirmed by byte comparison.

## Requested transport identities are checked before effects

**Always:** fetched packs and metadata match their requested keys; shard
manifests name the requested pack before reconstruction. Sparse selections are
derived from canonical Tree witnesses verified against independently known IDs.

**Because:** internally valid content can still be a substituted response.

**If violated:** transports can publish unrequested objects or incomplete paths.

**Enforced by:** packmap substitution tests, HTTP/S3 shard suites, core sparse
v2 mutation/completeness tests and `rust/tests/golden/sparse/response_v2.bin`.

## Shard worker bounds do not delay an available quorum

**Always:** HTTP and S3 shard downloads collect completed responses while
admitting workers under the shared process-wide limit. Reaching quorum or the
failure threshold cancels outstanding work without waiting for redundant shards.

**Because:** bounded worker admission can otherwise block the collector even
after enough shard responses have arrived to reconstruct the pack.

**If violated:** slow redundant requests delay successful downloads until their
network timeouts expire.

**Enforced by:** HTTP and S3 `shard_quorum_does_not_wait_for_extra_worker_slots`
regressions, which gate redundant responses until after the quorum returns.

## Every ref mutation participates in its lock protocol

**Always:** local Any, Missing, Match and deletion take the same full-ref guard.
The order is registry, worktrees, history, then ref mutation locks; peers within
a class use canonical order. File transport serializes all condition variants
within its separate transport lock domain.
Ref lock filenames use a fixed-length digest of the complete ref identity,
including its namespace, so valid long ref names remain writable.

**Because:** an unconditional writer can invalidate a conditional writer's
observation just as another CAS writer can.

**If violated:** reported successful updates lose writes or expose invalid
history publication states.

**Enforced by:** core refs and file-transport contention regressions, CLI
history lifecycle and publication retry tests, and core long-ref mutation and
lock-identity regressions.

## History evidence binds ancestry, generation and context

**Always:** a trusted proof describes the canonical first-parent chain for the
expected repository, ref, tip and generation. Pending durable intents pin both
previous and target tips as GC roots even without the history feature enabled.

**Because:** a mutation journal is not an ancestry proof, and publication spans
multiple durable files.

**If violated:** rewinds, resets, ABA or interrupted writes can issue misleading
proofs or let GC remove objects needed to recover.

**Enforced by:** `history/ancestry.rs` chain/context/generation and six-boundary
failure tests, and core GC intent-root tests. Current descriptors establish
local trust only; snapshots/reconstruction cost O(chain length), capped at one
million leaves. Only canonical ancestry snapshots are supported.

## Staging selections are durable; stat caches are disposable

**Always:** current index data preserves path, mode, staged object and deletion
intent. Only checksummed v3 is accepted. Unknown, empty or corrupt index data
stops operations that rely on staging, including GC; it is never converted or
rebuilt from working files.

**Because:** HEAD and the working file cannot reconstruct a partial selection.

**If violated:** recovery silently replaces staged A with working B or garbage
collect the only copy of staged content.

**Enforced by:** current index checksum/round-trip and unsupported-version
rejection tests, current golden fixtures, and GC no-sweep-on-corruption coverage.

## Authenticated write effects and replay state commit together

**Always:** auth v2 verifies configured audience, decoded repository, procedure,
content commitment, times and nonce before effects. Retries keep their operation
identity. SQLite adapters commit mutable effects, quota and replay response in
one transaction; immutable publication records a recoverable reservation first.
New quota- or rate-limited operations pass admission before allocating a replay
record; admission rejection leaves replay storage unchanged. Permanent built-in
ref policy denials commit a guarded replay rejection, preserving a concurrent
winner; membership lag (`unavailable`) answers remain unstored. Existing
reservations and saved results remain retryable without another quota charge.

**Because:** signature validity alone cannot prevent cross-service replay or
repeating an effect after a crash.

**If violated:** a captured request can move a ref back, toggle a reaction twice,
restore an old name or charge duplicate upload quota.
Reserving rejected operations also lets throttled authors keep growing replay
storage after exhausting their write budget.

**Enforced by:** `mkit-server` ref policy permanent-denial, lag-retry and
concurrent replay winner tests; shared core canonical/context tests; Connect retry tests;
actual local Workers regressions in `apps/{repo-worker,keys-worker}/tests/`;
quota and rate admission in `apps/mkit-worker-common/tests/quota_ledger.mjs`;
web/spammer envelope tests. Keys failure injection after name and result writes
rolls back both; saved results survive a full Worker restart. Production builds
omit `test-faults`. Only auth v2 is accepted. Names use SQLite exclusively.

## Namespace quota charges and rollups

**Always:** an admitted default-quota write charges its fixed-window namespace
counter in the same batch as its write and signer charge. A ref shard guards its
local `qs` counter; a coordinator or Single partition guards its exact `qt`
total. The kind-5 rollup applies only the increase since that source's guarded
`qc` cumulative value, or re-baselines a decreased restored contribution, then installs an unguarded local `qv` view. A new shard seeds `qv` from the coordinator total read with its lease. A missing or
stale view permits writes only up to the local exact cap and increments a
fallback metric. Replays and admission-free ticket answers charge neither.

**Because:** a retry or crash after the coordinator apply must not count the
same shard usage twice, and a view refresh must not force every write to
re-plan. With scheduled rollups succeeding, the local estimate can lag other
active shards by at most their admission rate times three 60-second intervals (3R).

**If violated:** an author can exceed the namespace cap without a bounded
delay, or a retry double-charges and locks out valid writes.

**Enforced by:** `quota.rs` fixed-window math and batch planner, guarded
`timers::quota_rollup`, and the memory-store rollup/denial/rollover tests.

## Pending verification preserves the advance identity

**Always:** a typed pending `AdvanceRefs` response causes a clamped poll, not
a retry-ladder step. Every attempt keeps the same nonce, timestamps and
signature while the envelope remains valid; before the next poll it is renewed
when less than 30 s of validity remains (or the unary timeout, if longer). An
ambiguous retry retains its identity until the envelope actually lapses.
Polling ends before the consumed ticket expires.

**Because:** a pending answer is never stored for replay, and the next attempt
must observe verification progress without changing the logical operation.

**If violated:** an advance can fail after the ordinary retry ladder, use an
expired signature, or keep polling after its ticket is invalid.

**Enforced by:** `ConnectTransport::advance_refs_with_deadline` and its pending
response, renewal and deadline tests. The caller's real ticket deadline is
pending WP-1.17; until then the helper uses the seven-day maximum lifetime.

## External signer capabilities precede signing material

**Always:** the external signer returns compatible protocol, algorithm,
message-size and interaction capabilities before receiving SignRequest bytes.
The request uses a supported key form selected from that response, including
opaque handles for hardware signers with a configured default key.
All subprocess I/O retains frame and wall-clock bounds.

**Because:** advertising capabilities after signing cannot enforce them.

**If violated:** an incompatible signer can perform a request before rejection.

**Enforced by:** external signer no-sign-on-incompatible-handshake regressions,
opaque-handle request-frame and unsupported-key-form regressions, PIN/timeout
subprocess tests and the bundled file signer's end-to-end test.

## Dependabot ecosystem matches the lockfile format

**Always:** every directory with its own lockfile has a `.github/dependabot.yml`
update entry whose `package-ecosystem` matches that lockfile's format
(`cargo` for `Cargo.lock`, `bun` for `bun.lock`, `npm` for `package-lock.json`).
Every composite GitHub Action under `.github/actions/*/action.yml` has its
own `github-actions` entry, because a `directory: "/"` entry only scans
`.github/workflows/`.

**Because:** Dependabot edits only the manifest for the ecosystem it thinks
it is running. An `npm` entry pointed at a `bun`-only directory edits
`package.json` but never touches `bun.lock`. CI installs with
`bun install --frozen-lockfile`, which rejects a manifest whose lockfile did
not change with it.

**If violated:** every PR Dependabot opens for that directory fails CI on
the frozen-lockfile install step and gets closed unmerged, silently, on a
recurring weekly schedule. See `apps/web`'s Dependabot PRs #921, #922, #923,
#931, and #934 — all closed unmerged for exactly this reason before this
invariant was enforced.

**Enforced by:** `scripts/check-dependabot-coverage.sh`, run by the
"Meta: actionlint" workflow on any change to `.github/dependabot.yml`,
`.github/workflows/**`, or `.github/actions/**`.

## Single crypto-stack version across workspaces

**Always:** `ed25519-dalek` and `sha2` are pinned to the same
Cargo-semver-compatible version (for a `0.y.z` crate, `y` is the breaking
component; for `x.y.z` with `x >= 1`, `x` is) in every Cargo workspace that
declares them: `rust/`, `contrib/signers/`, and the `apps/*-worker`
standalone packages.

**Because:** several crates independently re-verify signatures/digests the
same byte-for-byte way another crate already does — `mkit-wasm`'s raw
Ed25519 exports vs. `mkit-core::sign`, and every `apps/*-worker`'s
write-envelope strict-verify vs. `mkit-core`'s own `verify_strict` call —
and the golden-vector and cross-impl-parity tests (e.g.
`mkit-wasm::ed25519::cross_impl_parity_with_dalek`,
`mkit-keystore`'s `*_matches_golden_vectors`) assert that stays true. A
drifted major/breaking version of the same crypto crate across workspaces
can silently diverge in wire-visible behavior (ed25519-dalek 2->3 dropped
the `std` feature and moved error types to `core::error::Error`; a future
bump could change verification semantics) with nothing forcing every
workspace to move together.

**If violated:** nothing fails to compile — each workspace has its own
lockfile, so two incompatible versions of the same crypto crate can coexist
silently. A behavior difference between them (a stricter/laxer signature
check, a different digest padding) would only surface as a hard-to-trace
cross-service inconsistency, not a build error.

**Enforced by:** `scripts/check-crypto-stack-version.sh`, run by the
"Meta: crypto-stack version" workflow on any change to a `Cargo.toml` under
`rust/`, `contrib/signers/`, or `apps/`.

## A live `mkit serve` is detectable by local worktree commands

**Always:** every live server process on a root holds a **shared** kernel
lock (`mkit_core::repo_lock::acquire_shared`) on `<common_dir>/serve.lock`
for its entire lifetime: `mkit serve <path>` (stdin SSH-frame, its only
mode) and any other server process embedding `mkit-server`'s filesystem
layout (which also holds `<common_dir>/server.lock` exclusively, so one
server serves a root at a time). Every command that acquires `worktree.lock`
or `worktrees.lock` immediately probes that same `serve.lock`
non-blocking-exclusive (`mkit_core::repo_lock::probe_exclusive`) and, if it
finds the lock busy, prints a warning to stderr naming the served root
before proceeding. Most commands do this through `mkit-cli`'s
`acquire_worktree_lock` / `acquire_worktrees_registry_lock`; the paths
that take `worktree.lock` directly (the `fetch`/`pull` phases in
`remote_dispatch` and `status`'s index refresh) call the same
`warn_if_served` probe (SPEC-CONCURRENCY §3.1). The one exclusive holder: at startup
`mkit serve` tries `serve.lock` exclusively without waiting, and only
while it holds it (no other server is up) sweeps the temp files crashed
uploads left in `packs/` (`.<hex>.tmp.<pid>.<seq>`, at least an hour
old), then takes it shared as above.

**Because:** `mkit-transport-file`'s only lock (`<root>/.mkit/refs/.lock`)
serializes file-transport instances against *each other*, not against
local worktree mutation or `gc` (SPEC-CONCURRENCY §3.1). Running `mkit
gc` or a worktree-mutating command directly against a root a live `mkit
serve` is also operating on is unsupported and uncoordinated; without
this invariant, nothing distinguishes that misuse from an ordinary,
safe invocation, and the failure (a `gc` sweep racing a concurrent
push's object write, or a lost ref update) surfaces only as
after-the-fact corruption with no diagnostic pointing at the cause.

**If violated:** a `gc` can silently sweep objects a concurrent `mkit
serve` client just uploaded, or a local commit/checkout can silently
lose a race against a client push — both without any warning ever
appearing, leaving an operator no reason to suspect the concurrent-serve
misconfiguration until data is already gone. This is detection only,
not coordination: a direct `mkit push mkit+file:///path` (bypassing
`mkit serve`) and a `serve` that starts *during* an already-in-flight
local critical section both remain undetected — see SPEC-CONCURRENCY
§3.1 for the full statement of what this warning does and does not
cover. Detection does not make a concurrent `gc` safe: SPEC-GC
("Concurrent writers and the grace window") states the condition a
writer outside gc's lock set must meet, which a dedup hit on an old
unreachable object does not meet today.

**Enforced by:** `mkit-cli/tests/serve_guard.rs`.

## Single commonware release train across every manifest and lockfile

**Always:** Commonware requirements use the same caret minimum (`2026.9.0`)
across manifests. Committed lockfiles select that baseline release train for
reproducible builds. Downstream consumers can select compatible 2026.x releases.
The latest-release compatibility probe updates its disposable lockfile separately.

**Because:** exact library requirements prevent downstream consumers from
selecting a newer compatible release. Reproducibility belongs in lockfiles.
Commonware-backed mkit wire encodings must retain their pinned bytes when the
resolved dependency changes.

**If violated:** an exact requirement can block downstream resolution, or a
compatible release can silently change mkit bytes without an encoder regression.

**Enforced by:** `scripts/check-crypto-stack-version.sh` audits the baseline
across manifests and committed lockfiles. The scheduled and manifest/lockfile PR
workflow **commonware-latest.yml** runs `scripts/check-commonware-latest.sh`:
it updates all resolved Commonware packages together, builds the consuming
crates with all features, and runs their normal tests, including golden vectors.
Build and test failures remain visible; the probe never restores an older pin.

## commonware `Strategy` cannot be spied on from outside commonware-parallel

**Always:** `crates/mkit-core/src/pack_shard.rs`'s test suite does not
attempt to assert that a caller-supplied `commonware_parallel::Strategy`
was *invoked* by the encode/decode core (only that a real, non-default
strategy compiles against the generic entry points and round-trips
correctly — see `round_trip_with_explicit_parallel_strategy`).

**Because:** commonware-parallel 2026.9.0 made `Strategy` impossible to
implement from outside the `commonware-parallel` crate itself:
`Strategy::manual` must return a `Manual<Self>`, and `Manual`'s fields are
private with no public constructor left (`Manual::new` was removed). The
`CountingStrategy` spy this test module used to define — an `impl
Strategy` that counted `fold_init` calls to prove the supplied strategy
was genuinely exercised, not merely accepted and discarded — can no
longer be written.

**If violated:** re-adding an external `impl Strategy` (e.g. to restore
the invocation-count assertion) will not compile against the pinned
commonware-parallel train; if it is somehow worked around, treat the
resulting test as unable to prove what its name claims.

**Enforced by:** `crates/mkit-core/src/pack_shard.rs`'s
`round_trip_with_explicit_parallel_strategy` (compiles + round-trips a
real `Rayon` strategy) as the remaining guard; the comment block above it
records why the invocation-count assertion cannot be rebuilt.

## Windows is not a build, test, or release target

**Always:** no workflow, action, `justfile` recipe, crate manifest, or
installer targets Windows — no `windows-latest` / `pc-windows-msvc` CI
runner, no `backend-windows-credential` / `windows-credential` keystore
feature, no `install.ps1` or Scoop packaging, and no
`[target.'cfg(windows)'.dependencies]` stanza in any `Cargo.toml`.
`BackendKind` has no Windows Credential Manager variant.

**Because:** commonware-runtime 2026.9.0's storage-sync path calls
`libc::sync()` on every non-Linux target (`rust/crates/mkit-transport-enc`
depends on `commonware-runtime` unconditionally, and `mkit-core`'s
dev-dependencies pull it in
too) — `libc::sync()` does not exist on `x86_64-pc-windows-msvc`, so the
workspace and its test suite no longer build there. Maintaining a Windows
CI/release leg that cannot actually build or test the workspace would ship
an untested binary, so Windows was dropped as a supported target (MKIT-6)
rather than worked around. Windows users run mkit under WSL, which uses
the Linux binary.

**If violated:** a reintroduced Windows CI leg goes red on every PR (the
workspace fails to build there); a reintroduced Windows release leg ships
a binary no test ever exercised; a reintroduced
`backend-windows-credential` feature reopens a semver-breaking
`BackendKind` variant on a published crate (`mkit-keystore`) without the
required major bump.

**Enforced by:** `scripts/check-no-windows-target.sh`, run by the
"Meta: actionlint" workflow on any change to the CI workflows, `justfile`,
crate manifests, `install.sh`, or the web app's installer-staging scripts.
`mkit-keystore`'s `windows_credential_backend_name_is_not_recognized` test
(`crates/mkit-keystore/src/lib.rs`) pins that `"windows-credential"` is an
unrecognized `BackendKind`/`KeyRef` backend string, not a fail-closed one.

## wasm32 dependency graphs contain no C-toolchain crates

**Always:** the `wasm32-unknown-unknown` normal-dependency graphs of
`mkit-wasm`, `apps/repo-worker`, and `mkit-server` contain none of `blst`,
`zstd-sys`, `commonware-runtime` or `commonware-storage`; `mkit-wasm`'s also
contains no `tokio`. Each crate depends on `mkit-core` with
`default-features = false`, which keeps `pack-zstd` (and so `zstd-sys`) out.
The same holds for `mkit-core` built with `--no-default-features
--features pack-ruzstd`, the pure-Rust decode-only zstd backend a Workers
build uses to read v2 packs: that graph must contain `ruzstd` and none of
the crates above. `mkit-wasm` stays raw-only (SPEC-DISCLOSURE §7.2), so
its graph must not contain `ruzstd` either until it opts in.

**Because:** none of those crates build for `wasm32-unknown-unknown`.
`mkit-wasm` ships to browsers, `apps/repo-worker` runs on Cloudflare
Workers, and `mkit-server` is the runtime-agnostic reference implementation
that supports wasm32 embedders. Cargo unifies features per
dependency graph, so one manifest line that re-enables a default feature
silently pulls a C library into every wasm build downstream.

**If violated:** the wasm32 builds fail, often only in a later, slower CI
job (wasm-pack, `worker-build`), or on a machine without the C toolchain
the native build happened to have. A wasm32 embedder could no longer build
the server at all.

**Enforced by:** `scripts/check-wasm-dep-graph.sh` (a `cargo tree` check
per crate, including the `mkit-core` `pack-ruzstd` graph, which must
contain `ruzstd`) and the `cargo check --target wasm32-unknown-unknown`
steps for `mkit-wasm` and `mkit-server`, all run by `just ci-scripts`
(part of `just ci`); cloudbuild/ci.yaml runs the script and the
`mkit-server` wasm32 build on `main` and PRs to it.

## The default `mkit` CLI is server-free

**Always:** the normal dependency graph of `mkit-cli` with its default
features, on every target, contains no `axum`, `mkit-server-native` (a removed crate, kept on the ban list),
`rusqlite` or `libsqlite3-sys`; it enables no hyper `server` feature, no
hyper-util `server*` feature and no connectrpc `server` or `axum` feature;
and it has `mkit-server` (the engine of `mkit serve`) with only the `ssh`
and `fs` features. `mkit serve` builds no async runtime: it runs the ssh
session under `futures::executor::block_on`, and its code names no tokio.
tokio itself is allowed: it is the runtime of the Connect and reqwest
*clients* in the default graph, and `mkit-server` uses only `tokio::sync`.

**Because:** the CLI is what every user installs (`cargo install
mkit-cli`, the release archives). The HTTP server, the
`SQLite` metadata store and their dependencies belong outside the CLI (the
`mkit-server` library and embedder storage adapters). A server stack in the CLI
graph grows the published crate's supply chain, its build time and its
binary, and invites serving code paths the CLI was never reviewed for.

**If violated:** the published `mkit` compiles an HTTP server, a C
`SQLite` build or a second async stack that no CLI command needs; the
release check (`scripts/check-release-artifact-features.sh`) then fails
only at release time, where this check fails at the PR.

**Enforced by:** `scripts/check-cli-baseline.sh` (a `cargo tree` model of
the graph plus a grep of `commands/serve/`), run by `just ci-scripts`
(part of `just ci`), `just ci-server` and cloudbuild/ci.yaml; the release build's real compiler artifacts are
checked by `scripts/check-release-artifact-features.sh` against
`scripts/release/mkit-packages.golden`.

## Every storage backend passes the storage-contract suite

**Always:** every `NamespaceStore` and `BlobStore` a server can be deployed
on passes `mkit-server-conformance`'s storage suite (`storage_suite!`),
including the durability cases (`dur.*`: cancellation mid-apply,
crash/restart without shutdown, portable export/import) and the `NotAfter`
commit-deadline cases (`kv.not_after_*`), and declares each case it skips,
for a capability the backend lacks (`StoreCapabilities`, or a reopen that
an in-memory `SQLite` database cannot do). A declared skip that starts
passing, or an undeclared one, fails the run.

**Because:** `mkit-server`'s pipeline is written once against the storage
traits (production server work §5.1) and trusts their contract: an atomic batch, a
missed deadline that writes nothing, a crash that leaves either the old or
the new state. A backend that bends one of these on a single path
(a partial batch on `SQLITE_FULL`, a blob visible before its final chunk)
corrupts refs or quota only in the deployment that uses it, where no
pipeline test looks.

**If violated:** a ref update half-applies or survives its own deadline,
replay or quota rows diverge from the effects they guard, or an upload is
readable before it is complete, on one backend only.

**Enforced by:** one test binary per backend in
`rust/crates/mkit-server-conformance/tests/`: `memory_backends.rs`
(full-capability and `RefsOnly` memory stores, `MemoryBlobStore`),
and `fs_backends.rs` (`FsLayoutStore`, `FsBlobStore`). The suite's own
mutation tests (`suite_selftest.rs`) prove each case fails the store bug it
targets. All run in the workspace nextest (`just ci`, cloudbuild/ci.yaml).

## M2 Connect surfaces remain explicit stubs until implementation

**Always:** `GetGrantEpoch`, `SetGrantEpoch`, `SetRepoVisibility` and
`IssueObjectUrl` return `unimplemented` ("not implemented yet") until
WP-2.8, WP-2.9 and WP-2.11 implement them. They write no state.

**Because:** their paths currently bypass auth-v2 `Procedure` dispatch.
WP-2.8 keeps both namespace epoch RPCs outside that path permanently, by
spec §5.3 (`grant_epoch_paths_are_permanently_outside_procedure`).
WP-2.9 and WP-2.11 must add mode-specific and signed-read authorization
before enabling their repository RPCs.

**If violated:** an unauthenticated repository RPC can mutate state or mint a token.

**Enforced by:** `mkit-server/tests/connect_dispatch.rs`'s `m2_*` tests
and the TODO and SECURITY comments in `connect/service.rs`. Implementing
WPs replace their stub assertions with behavior and auth tests.

## The native HTTP host passes the black-box wire suite

**Always:** the reference `mkit.transport.v1` implementation passes
`mkit-server-conformance`'s wire suite over HTTP through its in-process
`TestHost`, enabled by the `test-host` feature. The suite speaks raw Connect
with its own client, so it checks the wire independently of mkit's client library.

**Because:** HTTP bindings can change status codes, compression, streaming, or
limits even when the pipeline stays unchanged. A fixed black-box suite catches
changes that a permissive client might hide.

**If violated:** a deployment can answer with a different error code, drop a
precondition or limit, or buffer a stream where the spec requires streaming.

**Enforced by:** `rust/crates/mkit-server-conformance/tests/test_host.rs` and
`test_host_migrations.rs`, run with `--features test-host` by the Rust workflow's
`native-wire-conformance` job. `baseline_pipeline_memory.rs` separately exercises
the pipeline over memory stores and the store mutants each case must catch.

## Both zstd backends accept exactly one frame per entry

**Always:** a `0x03`/`0x04` entry's payload after `uncompressed_len` is
exactly one RFC 8878 Zstandard frame (SPEC-PACKFILE §3.3). The C backend
(`pack-zstd`) and the pure-Rust backend (`pack-ruzstd`) both reject a
skippable or legacy frame magic, a second concatenated frame and any
trailing byte, with `PackError::ZstdDecompress`. Both apply the same §3.3
bomb guards (claim ≤ `MAX_RAW_OBJECT_SIZE` before decoding, output bounded
to the claim, exact length re-check). Both paths reserve output fallibly
without zero-filling the claim; unpack charges the resident budget first.
The pure-Rust path reads out at most `claim + 1` bytes and never grows the
reserved output. Both decode windows are capped at 8 MiB independently of the
claim. The shared allocation-free preflight checks frame windows and encoded
block sizes before either decoder starts. The named `mkit-ruzstd` dependency
checks `min(Window_Size, 128 KiB)` before raw/RLE materialization and before
executing any compressed sequences. The fork is selected by a versioned path
dependency, retaining the import name
`ruzstd`. Published and independent-workspace consumers inherit the named
package without `[patch]` tables. Its separate
ring and block scratch have a fixed 28 MiB working allowance, including
transient old/new ring allocations during growth, outside the owned-payload
resident cap and the window reader's carry/output budget. Scheduled verification
reserves that scratch within its unchanged 48 MiB allowance by retaining a
1 MiB LRU (or one newest admitted larger base) and releasing the idle reader
window before nested delta-base decode. The physical window geometry and
entry admission formula remain unchanged. A post-entry cursor commits only
after delta verification succeeds; the next alarm resumes with the same hash
and etag checks. Member-chain copies drop after their dependency/byte charges
are staged. The pure-Rust path also
checks what `ruzstd` skips and the C decoder enforces: the declared
content size against the claim and the decoded length, the content
checksum, the reserved descriptor and sequence-mode bits, and the
per-block size bound for every window. When both features are on,
the C decoder serves reads.

**Because:** a pack must mean the same objects on a native build (C)
and a Workers isolate (`ruzstd`). A frame one runtime accepts and the
other rejects splits pushes, fetches and indexed state between them.

**If violated:** a push accepted on one runtime is rejected on the other,
or a runtime decodes bytes the spec forbids (a second frame's content).

The hand-written frame parsing assembles header fields in `u64`, never
`usize`, so it behaves the same on 32-bit wasm32 as on 64-bit native.

**Residual divergence (documented, not closed):** the two decoders agree
on the encoder frames covered by the differential proptest over
`PackWriter` output and C-encoded fixtures, and on the curated adversarial
table. On *malformed* frames they do not fully agree. Fail-closed on
`pack-ruzstd` (it rejects, C accepts): corrupt entropy-coded sections the C
one-shot decoder tolerates. Fail-open
(it accepts, C rejects) and both-accept-different-bytes cases also exist
for a small share of corrupted frames, in Huffman/FSE table internals
that no cheap check reaches; the reference `zstd` CLI rejects those
frames too. Over 850k mutated frames: 134 accepted only by `pack-ruzstd`,
2,580 accepted only by C, 4 accepted by both with different bytes, no
panics. This decoder-level difference remains documented; object ids are
content-derived. Integrity is unaffected: decoded bytes must parse as a canonical object and are stored
under their own content id, so no runtime can accept wrong content under
a given id. The divergence can only change which objects, if any, a
crafted pack yields on each runtime.

**Consumers MUST:** a server that accepts a pushed pack through
`pack-ruzstd` MUST NOT serve that pack's `0x03`/`0x04` frames verbatim to
other clients unless the reference (C) decoder decodes them to the same
bytes the server indexed (both decoders can accept a frame yet produce
different bytes). Otherwise it MUST serve server-derived bytes instead:
raw v1 entries, or frames the server re-encoded itself. No consumer may assume two runtimes derive the same
object set from the same client-supplied compressed frames. Owners:
WP-4.7 (indexed ingestion) and WP-4.8 (Workers verification), which
enable `pack-ruzstd` first.

**Enforced by:** `mkit_core::pack::zstd_tests` (`c_backend_enforces_one_frame`,
`ruzstd_enforces_one_frame`, `ruzstd_rejects_claims_before_or_at_the_cap`,
`ruzstd_rejects_huge_window_frame`,
`ruzstd_decodes_4_and_5_byte_literals_headers`,
`ruzstd_enforces_reserved_bits_and_block_size`, and under
`--all-features` the differential `backends_agree_on_adversarial_frames`,
`backends_agree_on_bit_flipped_frames`,
`backends_agree_on_reserved_sequence_mode_bits`,
`window_divergences_are_fail_closed`,
`backends_agree_on_committed_v2_fixtures` and
`ruzstd_matches_c_on_writer_output`), plus
`golden_pack::pack_v2_fixtures::pack_v2_fixtures_decode_without_c_zstd`
over `rust/tests/golden/pack-v2/`, the `pack-ruzstd`-only nextest run in
`just ci`, and `scripts/wasm-ruzstd-check.sh` (the same fixtures decoded
on a real wasm32 target by `mkit-core-wasm-check`, in `just ci-scripts`).

## Hosted workspaces separate public projects from owner execution

**Always:** workspace files and signed versions are public; conversation messages,
current task details, and PTY access require the owner's session. Writes require
an exact, unexpired auth-v2 signature. The browser uses a saved PRF passkey identity;
its signing seed never leaves the browser. The server holds a separate agent key
whose owner-signed grant must remain valid for new execution and version publication.

**Because:** public remixing must not disclose private prompts or give visitors
shell access under another person's delegated identity.

**If violated:** a public link can leak conversations or execute commands without
owner authorization; replaying a request can affect an unrelated later task.

**Enforced by:** `apps/workspace-worker/src/auth.test.ts`,
`apps/workspace-worker/src/workspace.integration.test.ts`, and the workspace client
identity tests under `apps/web/src/components/workspace/`.

## Hosted task completion publishes a recoverable signed version

**Always:** only a completed, currently authorized agent task publishes its new
signed version with its completed status and saved conversation snapshot. Failed
or cancelled tasks retain captured draft files without claiming completion.
Captures cannot overwrite another workspace generation. A worker restart does
not replay shell commands whose outcome is uncertain.

**Because:** the browser can close while the agent works, and container lifetime
is independent of the project's durable files and versions.

**If violated:** users lose completed work, see a completed task with no version,
or execute a command twice during recovery.

**Enforced by:** `apps/workspace-worker/src/workspace-state.test.ts`,
`apps/workspace-worker/src/workspace-runner.test.ts`, and
`apps/workspace-worker/src/sandbox-files.test.ts`.

## Browser login and signing authority have separate lifetimes

**Always:** one shared session query and Account region represent login on every page. A refresh can preserve the HttpOnly login cookie, but cannot recover or persist a signing seed. Locking signing preserves the login; sign-out revokes the server session and clears private query and mutation caches. Workspace reads remain disabled during logout, and late responses cannot replace another identity's state. Workspace activation never issues a login cookie.

**Because:** page navigation and cache reuse must not change identity or revive access after sign-out. Public recovery metadata is safe to persist; signing keys and private workspace state are not.

**Enforced by:** `apps/web/src/components/auth-provider.test.tsx`, workspace query/editor tests, `apps/workspace-worker/src/browser-session.test.ts`, workspace integration tests, and `bun run verify:auth` in `apps/web`.

## A workspace version saves one coherent project state

**Always:** a batch save checks every draft's expected file hash before publishing any edit or version. A conflict preserves browser edits and requires explicit review against current content. Terminal working changes and accepted drafts become one named version. Restore appends a new version and retains saved history.

**Because:** a project version must not silently combine stale edits or leave half a batch applied.

**Enforced by:** workspace worker version-edit integration tests, file-editor conflict tests, and workspace save orchestration tests.

## Browser drafts belong to the authenticated session

**Always:** drafts stay in memory, survive route remounts and signing locks, and clear on logout or session replacement. Explicit logout asks before discarding drafts. Current file query keys include content hashes so terminal captures cannot leave cached contents stale.

**Enforced by:** workspace draft-store, Account, auth-provider, and workspace query tests.

## BMT inclusion-proof bytes and sibling selection match commonware exactly

**Always:** `mkit_core::merkle::Proof`'s wire bytes (`u32 BE leaf_count ‖
varint(n) ‖ n × 32-byte digest`) and its level-major, self-duplicate- and
already-proven-sibling-omitting selection rule are byte-identical to
`commonware_storage::bmt::Proof` at the pinned `2026.9.0` train, for
single, range, and multi-leaf proofs alike — both directions: mkit
decodes and accepts upstream's proof bytes, and upstream decodes and
accepts mkit's.

**Because:** SPEC-MERKLE-OBJECTS §5.7 makes this byte-identity a
normative compatibility promise, so a commonware-based verifier (for
example, makechain) can decode and verify an mkit proof with the
upstream type directly, applying only mkit's outer type-domain wrap
(`wrap_id`) on top. mkit cannot depend on `commonware-storage`'s `bmt`
module directly for this (it drags in `commonware-cryptography`'s
unconditional `blst` C dependency, which does not build for
`wasm32-unknown-unknown` — see `merkle.rs`'s module docs and issue
#843), so the construction is vendored and the byte-identity claim has
no compiler to enforce it.

**If violated:** a proof mkit produces would fail to decode, or would
decode but fail to verify, against an otherwise-correct commonware-based
verifier (and vice versa) — silently breaking cross-implementation
verification with no local test failure, since every mkit-only
round-trip test would still pass.

**Enforced by:** `mkit_core::merkle::tests::proofs_match_commonware`
(native-only, dev-dependency on `commonware-storage`/`commonware-cryptography`),
which builds many randomised trees and single/range/multi position sets,
asserts mkit's encoded bytes equal upstream's `commonware_codec::Encode`
output, cross-decodes each side's bytes with the other's type, and
confirms both verifiers reject a mutated proof (flipped sibling byte,
dropped/added sibling, wrong `leaf_count`).

## Disclosure verification is against object ids only

**Always:** every check `mkit_core::verify` performs — a path step, a
chunk, a byte range — is stated against an authenticated object id
(a commit id, a step's `child_id`, a `ChunkedBlob`/chunk id). A v2
bundle carries a bare inner root on each step and chunk header; that
field is wrap-checked against the trusted id (`domain_digest(TYPE_DOMAIN,
inner_root) == expected_id`) **before** it is used for anything, then
cross-checked against the proof fold. No verification step ever treats
a bare inner root, a caller-claimed path string, or an unauthenticated
length/offset as a trust anchor.

**Because:** an inner root is not type-distinct (SPEC-MERKLE-OBJECTS §2),
so accepting one directly would let a `Tree` proof pass for a
`ChunkedBlob` id or vice versa; and a caller-claimed path or offset that
was never itself checked against a proof is exactly the kind of
unauthenticated metadata a disclosure bundle exists to replace with a
proof.

**If violated:** a verifier could be tricked into accepting content at
the wrong path, or into reporting an offset/length nothing in the bundle
actually proves — silently, since the disclosed bytes themselves might
still be genuine content from *somewhere* in the repository, just not at
the claimed location.

**Enforced by:** `mkit_core::verify::tests` (`verify_path_rejects_*`,
`verify_chunk_with_meta_bounds`, `commit_id_mismatch_is_rejected`) and
`rust/tests/golden/disclosure/`'s negative vectors (swapped steps, a
wrong-position proof, a forged `ChunkedBlob` meta pair) — SPEC-DISCLOSURE
§4 states this as a numbered MUST at every dispatch point.

## Declared disclosure inner roots wrap and match the proof fold

**Always:** for every v2 disclosure `Step` and chunk header,
`domain_digest(TYPE_DOMAIN, inner_root)` equals the parent Tree id or
ChunkedBlob leaf id, and the proof folds to exactly that declared
`inner_root`. Version byte `1` is rejected.

**Because:** a commonware-native verifier runs upstream
`verify_element_inclusion` / `verify_multi_inclusion` against the
declared root. Without wrap-check-first, a prover could substitute any
tree whose proof verifies against a forged root. Without the fold
cross-check, a bundle could declare a wrap-correct root while attaching
a proof built for a different tree.

**If violated:** an external verifier that trusted the field would
accept content from the wrong tree, or mkit and a commonware-native
verifier would disagree on the same bundle.

**Enforced by:** `rust/crates/mkit-core/tests/native_commonware_disclosure.rs`
(every accept golden verified with only bundle fields, upstream
`commonware_storage::bmt::Proof`, and `hash::domain_digest`; the three
v2 negatives fail at wrap or upstream verify) and
`rust/tests/golden/disclosure/neg_inner_root_forged.*`,
`neg_inner_root_fold_mismatch.*`, `neg_bundle_version_1.*`.

## Disclosed absolute offsets require a complete length-proof set

**Always:** `DisclosedPayload::Range::absolute_offset` is `Some(...)`
only when either the leaf is a plain `Blob` (nothing to sum) or the
disclosed chunk is index 0 (nothing precedes it), or `chunk_len_proofs`
verifiably covers exactly the index set `0..index` with no gaps and no
duplicates. Any other shape of `chunk_len_proofs` — a gap, a duplicate,
an index `>= index`, or one entry that fails to verify — is a typed
[`VerifyError::IncompleteLengthProofSet`], never a silent `None`. A
*non-empty* `chunk_len_proofs` on a chunk-index-0 range, or on a plain
`Blob` leaf, has nothing preceding it to describe and is rejected
outright as `VerifyError::UnexpectedLengthProofs`, never silently
ignored either.

**Because:** a partial or malformed length-proof set does not sum to a
value that means anything; treating it as "absent" (`None`) rather than
rejecting it outright would let a caller silently miss that an absolute
offset was *claimed but not actually provable*, rather than being told
plainly that the request failed. The chunk-0/plain-`Blob` case is the
same principle at its edge: an entry that describes nothing real is not
merely irrelevant, it is evidence of a malformed or lying builder.

**If violated:** an application relying on `absolute_offset` for, say,
byte-accurate DA-layer indexing could be handed a value derived from an
incomplete sum — or worse, silently receive `None` for a bundle that
*looked* like it was trying to prove one, masking a builder bug or a
malicious short-fill.

**Enforced by:** `mkit_core::verify::tests::incomplete_length_proof_set_is_rejected`
and `rust/tests/golden/disclosure/neg_incomplete_length_proof_set.*`;
`mkit_core::verify::tests::len_proofs_on_chunk0_are_rejected` and
`rust/tests/golden/disclosure/neg_len_proofs_on_chunk0.*` (SPEC-DISCLOSURE §4/§4.1).

## MKDS spans bind every chunk to one authenticated byte range

**Always:** an accepted MKDS container has one trusted commit, authenticated
path and leaf, a complete preceding length-proof set, and consecutive chunk
bundles. Its absolute boundaries come from verified canonical Blob content
lengths. The requested range starts in the first included chunk and ends in
the last, with no unnecessary last chunk. A malformed container returns its
first SPEC-DISCLOSURE §8.2 reason and no partial output bytes. A range-proof
builder checks untrusted boundary hints against the chunk bytes it reads and
does not read a chunk after the span.

**Because:** a chunk-size marker or unchecked hint is not a proof of a content
boundary, and combining individually valid bundles from different contexts
would not authenticate their concatenation as one requested range.

**If violated:** a caller can receive bytes at the wrong absolute offset or
from the wrong leaf, or accept an incomplete range as a valid disclosure.

**Enforced by:** `mkit_core::verify::span` and its unit tests,
`rust/crates/mkit-core/tests/golden_http_objects.rs` product/reference parity
and builder byte-identity checks, and `rust/crates/mkit-wasm/tests/verify.rs`
(WP-4.14a; SPEC-DISCLOSURE §8 and SPEC-HTTP-OBJECTS §5.2).

## Closure walks share one `children` function

**Always:** every reachability walk &mdash; store-backed
`reachable_objects` / `reachable_closure` / `reachable_snapshot`, the
store-less `verify_closure` BFS, the pull-based `verify_closure_streaming`
walk, push verification (`verify_push`), and push/fetch pack planning &mdash; takes
its edges from `ops::graph::children(obj, mode)`. The verifiers
(`verify_closure*` and `verify_push`) share one BFS, `verify::closure::walk`;
none keeps a walker of its own. Snapshot mode omits
commit/remix parents; history mode includes them; remix `sources` and
`Delta.base_hash` are never followed.

**Because:** a snapshot-vs-history disagreement, or a walker that
followed foreign remix sources, would let two "closures of the same
commit" disagree on the object set, so a DA-layer verifier and a push
could not be checking the same thing.

**If violated:** a history export verified in snapshot mode (or the
reverse) would silently drop or invent objects, and a wasm verifier
walking a hand-rolled map would accept a different set than
`reachable_objects`.

**Enforced by:** `mkit_core::ops::graph::tests::children_snapshot_omits_parents_history_includes_them`,
`reachable_snapshot_excludes_parent_commit`,
`mkit_core::verify::closure::tests::history_on_snapshot_reports_parent_missing`
/ `snapshot_on_history_reports_parent_unreferenced`, and
`mkit_core::verify::push::tests::history_vs_snapshot` /
`remix_sources_never_followed`.

## Streaming closure verification reads only reachable objects, each once

**Always:** `verify_closure_streaming` and `verify_push` queue and fetch each visited id at
most once (so repeated references do not grow the queue), fetch no id outside the selected snapshot/history closure, and drops an
object's bytes after extracting its child ids; it reports
`unreferenced_checked = false` because it cannot enumerate objects it never
requested.

**Because:** local closure verification must scale with the checked closure,
not with the size of the repository's unrelated object store, while a
duplicate or out-of-closure fetch would defeat the source's bounded,
pull-based contract.

**If violated:** a large local store can turn a small closure check into an
O(store-size) memory operation, or a buggy mode walk can silently inspect
foreign/unreachable objects and misrepresent what was verified.

**Enforced by:**
`mkit_core::verify::closure::tests::streaming_fetches_each_reachable_object_once_and_only`,
which uses a counting source that panics on unknown ids and checks the exact
snapshot/history fetch sets, and
`mkit_core::verify::push::tests::each_object_fetched_once_across_multiple_tips`
and `mkit_core::verify::closure::tests::repeated_child_ids_are_queued_once`.

## Push verification and delta bases resolve only within the pushing repository

**Always:** `verify_push` reads objects only through the `ObjectSource` its
caller supplies, and stops only at ids the caller's `known` accepts; a
`known` id is neither fetched nor descended. A server supplies a source
limited to the pushing repository's members plus the pushed objects, and
`known` holds only for objects whose whole closure (in the walk's mode) was
already verified in that repository. Every fetched object is re-hashed, and
every commit, remix and tag has its signature checked
(`sign::verify_object_signature`), before any ref moves. Likewise a delta's
external base comes only from the `pack::DeltaBaseSource` the decoder is
given: the local `ObjectStore` on a client, the repository's membership on a
server, never a global content store. A source that does not have a base
and a source that may not serve it give the same `DeltaBaseMissing` error;
an unverified source's bytes are re-derived, so a wrong object is never
used as a base.

A `known` tip is skipped whole, including the commit/remix/tag type check
`verify_push` applies to every fetched tip. Callers MUST type-check known
tips themselves (from their index) before moving a ref to one.

`decode_entries_with` is bounded by the caller's `DecodeLimits`: every
`0x03`/`0x04` claim and every delta's declared result length is charged
before it is materialised, and every external base from the
`DeltaBaseSource` as it is fetched. An entry or external base stays
resident only until the last delta that names it; an external base's
charge is then credited back. The budget is per call: a server sizes it
from its isolate limit and decode concurrency. `PackReader::read` instead
uses the separate peak resident cap below. Compressed and delta claims
accumulate under `DecodeLimits`; resident reservations are released on
last use. `ObjectStore` base admission charges before allocation through
the provided `DeltaBaseSource` method; existing sources default to charging
the bytes returned by `base()`.

**Because:** PRD §6.5 forbids existence oracles. If a push could close its
history, or resolve a delta, over objects held only by another repository or
the global store, the push's success would reveal that some other repository
holds those objects, and the repository would reference objects it never
held. A `known` that meant "exists somewhere" would skip verification of
content this repository never checked.

**If violated:** a pusher could probe for private content by pushing deltas
or commits over guessed ids, or land a ref whose history includes unverified,
unsigned or foreign objects.

**Enforced by:** `mkit_core::verify::push::tests` (`frontier_stop` and
`known_tip_is_noop`, whose source panics on any fetch past the frontier;
`unsigned_commit_rejected`, `forged_tag_rejected`, `remix_signature_checked`,
`wrong_bytes_for_id_is_corrupt`) and `mkit_core::pack::tests`
(`external_base_outside_source_is_delta_base_missing`,
`untrusted_source_returning_wrong_bytes_is_rejected`,
`decode_with_no_external_bases_matches_reader`,
`delta_bomb_is_rejected_before_any_delta_is_applied`,
`compressed_claims_are_charged_before_decompression`,
`external_bases_are_charged_against_the_budget`). The server-side wiring and
the cross-repository uniform-error conformance test belong to WP-4.7.

## Closure profile is raw-only

**Always:** a closure pack is SPEC-PACKFILE v1 with only `0x00` entries.
`PackWriter::new_raw_only` never compresses and rejects deltas.
`verify_closure_packs` treats any delta or compressed entry as
`VerifyError::ClosureProfileViolation` after a type scan that does not
decompress.

**Because:** `mkit-wasm` builds `mkit-core` with `default-features =
false` (no zstd). A compressed or delta pack would be unreadable there,
so the profile that a wasm verifier consumes has to be raw-only by
construction.

**If violated:** a native exporter could emit a v2 pack that a wasm
verifier rejects (or, without the type scan, tries to decompress and
hits the `pack-zstd` stub), splitting the verifier kit into two
incompatible carriers. The type scan still runs first when a build has
the `pack-ruzstd` decoder, so a compressed entry is a profile violation
there too, not a decoded object.

**Enforced by:** `mkit_core::pack::tests::raw_only_writer_emits_v1_raw_for_compressible_payload`,
`raw_only_writer_rejects_deltas`,
`mkit_core::verify::closure::tests::delta_pack_is_profile_violation`,
and `rust/tests/golden/closure/neg_delta_entry.*` /
`neg_compressed_entry.*`, and
`golden_pack::pack_v2_fixtures::closure_profile_still_rejects_compressed_entries`
(every feature combination, including a frame corrupted past decoding).

## Windowed pack entries stay provisional until complete verification

**Always:** `pack::window` yields the same entry values as `PackEntries` when
resource limits do not bind, and returns `Done` only after framing, the trailer,
and any expected whole-pack id pass. Drivers discard all staged entries on
any error, including entries yielded before a checkpoint.

**Binding.** `Done` means every entry yielded across the whole run chain (the original run and every resume
through its cursors) is an entry, in order, of the one pack whose bytes hash to the verified pack id: the trailer,
and `expected_pack_id` when set. A cursor from pack A used on a source that yields different bytes for any
not-yet-verified range fails with `PackfileCorrupted`, never `Done`. The reader does not re-read ranges it has
already verified. **Keeping the source immutable across resumes is the caller's job**;
for example, an object-store adapter can pin range reads to one object version. A source whose already-verified prefix changed after verification can still
reach `Done`, but only with entries of the verified pack.

A `None` checkpoint means keep the previous cursor. After a boundary-state `None` (the trailer phase), resuming re-reads at most one window plus the trailer; after a mid-entry `None`, it re-reads every window the unfinished entry spans.

**Because:** a streaming trailer check occurs after entries have been delivered;
completed-window CVs and the incremental current-window prefix commitment bind the
entries staged across resumes without re-reading completed ranges.

The live prefix state has two fixed-size BLAKE3 hasher slots and a window-relative
length bounded by 64 MiB. Each checkpoint absorbs only newly consumed bytes;
repeated checkpoints finalize that state without rereading the prefix. Callers
that never checkpoint do no prefix hashing. An inline once-cell preserves
concurrent read-only checkpoint calls. Advancing the reader moves its cached
incremental state forward and clears the boundary cache. Cold resume
authenticates the prefix once and reconstructs this state. Only the existing
explicit subtree commitments and prefix digest enter the cursor encoding.

The opt-in one-pass reader keeps acquired windows through carried-frame decode.
Its exact-boundary cursor instead retains explicit subtree frontiers through
the acquired end, the collected trailer, and a commitment to the unconsumed
suffix. Cold resume requests that suffix from the entry boundary and verifies
it without hashing it into the frontiers again. Integrity-only drain checkpoints
resume at the acquired end. Both forms keep private hash-library memory out of
their encodings. Exact checkpoint creation charges suffix hashing as work;
decoder reservations use the next frame's actual wire geometry and scratch
requirement before allocation.

**If violated:** malformed packs or mismatched cursor/source pairs can publish
partially verified data.

**Enforced by:** `rust/crates/mkit-core/src/pack/window/tests.rs` differential,
resume, cursor-binding, released-window, resource-budget, and trailer-split tests;
the `mkit-core-wasm-check` v2 differential harness. Caller staging rollback and
source immutability remain obligations of WP-4.7/4.8; the core reader does not store objects.

## Cursor metadata preserves validation and private state

**Always:** `WindowCursor::metadata` applies the existing cursor geometry and
frontier validation before returning copied bindings through read-only accessors.
Inspection leaves cursor bytes unchanged and exposes no constructor or mutable
cursor state.

**Because:** outer checkpoints must bind opaque reader progress without copying
the cursor grammar or bypassing its validation.

**If violated:** callers could restore progress under mismatched source geometry
or mistake a metadata snapshot for source authentication.

**Enforced by:** cursor metadata boundary/round-trip, fixed-byte and invalid-state
regressions in `pack/window/tests.rs`, plus private-field compile-fail rustdoc
examples. Source binding and final reader verification remain required.

## Pack exclusions preserve surviving objects and delta bases

**Always:** a pack rewrite drops every excluded entry and rawifies a surviving
delta only when its direct base is excluded. Surviving bytes and entry order
are preserved; an unchanged pack keeps its original bytes. Rewrites use the
existing `DecodeLimits` charged-payload accounting; the caller supplies
repository-scoped bases.

**Because:** deleting a delta base otherwise makes retained objects undecodable;
transitive rawification adds size without improving decodability.

**If violated:** a takedown can corrupt unrelated objects or reveal external
object membership.

**Enforced by:** `pack::rewrite::tests` (128 property cases, chains of depth 1–5,
external bases, duplicates, compressed fixtures and budget/error checks), plus
`mkit-core-wasm-check/tests/pack_rewrite.rs` and the hostile-length wasm harness.

## Repository addressing binds authentication and storage routing

**Always:** stage 0 validates `X-Repository` with the shared identity grammar
and stores its resolved identity on `Authenticated`. Every operation routes
refs and replay state through `ShardMap` using that repository. Multi ref reads
require a ref row in the named repository; Multi pack RPCs return
`unimplemented` before blob access until repository membership exists.

**Because:** ref keys contain only the repository name; namespace partitions
provide isolation, and global blob presence would reveal another repository's
contents. Auth v2 must bind the signature and replay scope to the routed identity.

**If violated:** a request can observe or mutate another repository's refs,
reuse its replay result, or learn whether it holds particular content.

**Enforced by:** server `repo::tests` (the BLAKE3-pinned repository grammar),
`pipeline::tests::single_repository_header_rules_preserve_04_requests_and_fail_at_stage_zero`,
native `tests/repository_routing.rs` over memory and SQLite (including the
same repository name in different namespaces and shared nonces), and the
conformance `repo.*` wire cases. Namespace authorization is WP-1.5; pack
membership is WP-1.10; WP-1.22 moved existence to the coordinator repository registry.

## Branch shards preserve atomic advances and registered repository state

**Always:** D34 accepts only matching `refs/heads/<x>` and
`refs/mkit/packmap/<x>` for `AdvanceRefs`, before storage or replay access,
and commits their effects and replay state in one ref partition. Multi writes
observe creation after replay lookup and commit coordinator registration only
after authorization and admission allow them, before committing refs. A
ref-shard repo-known marker is written with the ref batch.

**Because:** a store batch cannot span partitions. Registration before refs
makes a crash leave an empty registered repository; marker caching preserves
the two-call steady write path. Admission observations can race, while
`Operation::created` reports only creation actually committed by this write.

**If violated:** advances lose atomicity, challenges create repository state,
replays reach creation hooks, or committed refs become unreadable as an
unregistered repository.

**Enforced by:** pipeline pairing tests with the call-counting store and
native `tests/d34_creation.rs` over memory and SQLite in both sharding
modes; D34 mapping golden and property tests pin co-location and fixed fan-outs.

## Timer effects share the row's atomicity boundary

**Always:** a timer handler's batch commits in its timer partition only after
checking the original row value, together with deleting or rescheduling the row.
Unknown timer kinds remain stored. Native committed timer Puts notify inside the
blocking task, even if the awaiting request is canceled.

**Because:** alarm redelivery and concurrent ticks must not duplicate effects;
cancellation must not hide a durable timer from a driver.

**If violated:** effects can run twice or a committed timer can remain asleep.

**Enforced by:** `mkit-server/src/timers/tests.rs` race and atomicity tests.

## Epoch lease acknowledgements describe durable shard state

**Always:** outside a declared recovery hold-off, `ls.acked_epoch = n` only if
the shard's `el` durably holds epoch at least n, or every older-epoch write is
already past its backend deadline.
Live renewals preserve acknowledgement. Revocation pushes even to an absent
`el`, guards the observed shard value, then acknowledges in a separate guarded
coordinator batch. Every D34 ref batch guards `el` and starts with
`NotAfter(min(plan_time + MAX_APPLY_WINDOW, expires - margin, replay cap))`.
Creation and lease registration commit together only after authorization and
admission. D34 creates coordinator `nr`/`rr` records even with Single addressing,
so every leased shard has the records its guards and `config_version` require.
The Single sharding path continues reading and guarding `e` directly.
Safety requires `lease_margin_ms` to exceed the maximum skew between every
pipeline instance clock (grant, renewal and revoke), the sweep driver clock,
and every backend clock; this deployment assumption is documented, not checked
by `Pipeline::new`.

During declared recovery, a rebuilt missing `ls` row may acknowledge the current
epoch before a surviving old `el` is replaced. The persistent `lr` hold-off
prevents completion for `epoch_lease + margin`, so every surviving old write's
deadline has passed before revocation can complete.

**Because:** a coordinator acknowledgement before shard installation could
report completion while a delayed old-epoch batch can still commit. Expiry
alone is safe only because the storage backend checks its own clock atomically.

**If violated:** a revoked grant can mutate a ref after revocation completes,
or denied/challenged requests can allocate lease state.

**Enforced by:** `pipeline/lease.rs`, `pipeline/revocation.rs`, the pure write
planner, and native `tests/epoch_leases.rs` on memory and SQLite. The Rust
interleaving property test covers the protocol model; pipeline regressions
protect the implementation. `LeaseSweep` guards expired coordinator rows and
moves its timer atomically with each renewal. Recovery is declared with the
persistent `lr` marker; restore/rebuild procedures MUST call
`mark_lease_table_recovered` before serving writes (WP-1.29). Completion waits
`epoch_lease + margin` after that marker, independent of namespace creation time.

## Namespace and write policy decide before allocation and never read existence

**Always:** Multi writes pass the namespace policy and owner/authority policy
in the authorize stage, after replay lookup and creation observations, before
admission or any quota, reservation, replay, namespace or repository allocation.
Built-in policy never reads creation facts or repository existence. Namespace
and non-owner denials have the same public `permission_denied` message,
"write not permitted". Namespace denial never calls the authorizer. Authorize
and Admit both see the established owner and grant facts; authority hooks still
run for owners and may deny them. Single deployments retain open write behavior.

**Because:** unauthorized writes must not disclose repository existence or
allowlist contents, allocate state, or bypass a deployment namespace boundary.

**If violated:** denied callers can create storage state or infer other tenants'
repositories; an authority Allow can bypass a namespace restriction.

**Enforced by:** `Pipeline::new` validates policy combinations and D27 using
wasm-safe provided trait methods. `Pipeline::authorize` enforces STC §7.5 and
SPEC-SERVER §6.2. `pipeline::tests::policy` covers the policy/principal/hook matrix,
startup refusals, identical existing/missing repository denials, and empty
coordinator/ref shards after every denial. Wire `policy.*` cases pin owner,
non-owner and allowlist behavior. Grants and private reads remain M2.

## Ticket, reservation and outbox rows keep exactly one outcome per reservation

**Always:** a ticket has a reservation-derived id and a unique guarded `o` row.
Only a still-Ticketed or Pending row can become terminal. Directly admitted
writes first record Pending, then replace it with Committed or Aborted under
an equality guard; BeginUpload replaces Pending with Ticketed. A pending
apply's deadline precedes its reconcile timer, so a late apply cannot commit
after an Aborted(ABANDONED) replacement. Consumption commits its outcome
with ref publication and local membership; a missing pack with a present upload
marker records `Aborted(PACK_MISSING)` in a separate guarded batch before the
advance fails. A missing marker leaves the ticket open. Terminal outcomes stay
durable until acknowledgement, which deletes their delivery index and subtracts
the exact stored key/value byte count. Shared counters and sequence/backlog
values are guarded once per batch. A zero-to-positive backlog transition, including
one first created by a cache purge, atomically adds one kind-8 delivery kick;
delivery may repeat but never drops an unacked row.
A positive backlog keeps exactly one kind-8 row. Purge acknowledgement retains
an encoded zero backlog while that wake remains; producers reuse a present
backlog row, including zero, rather than insert another wake. Kind-8 atomically
deletes the zero row and its timer under the same backlog guard. Delivery decides completion
from the same backlog snapshot its acknowledgment batch guards; concurrent
appends either retain a rescheduled timer or fail that guard for re-planning.

**Because:** consumption and expiry race; delivery may repeat or crash. An
unguarded replacement could record two outcomes, erase a replacement ticket's
index or lose membership while publishing refs.

**If violated:** settlement can repeat, committed packs can disappear from
repository membership, and backlog/caps can undercount durable obligations.

**Enforced by:** `mkit-server/src/store/{tickets,outbox}.rs` pure planner tests,
strict `store/codec.rs` decodes, and `mkit-server-conformance/src/storage/kv_cases.rs`
creation, atomic publication, stale-ticket and acknowledgement cases over memory
and SQLite. WP-1.10 exercises consumption and the defensive abort over native
memory/SQLite and wire cases; the kind-2 expiry handler closes tickets with
one guarded `Expired` row and best-effort session abort. WP-3.3 enforces guarded
Pending reservations, ReadServed, reconciliation and backlog limits.
WP-3.13 corrects the kind-8 acknowledgment/completion window from #1219;
regular `timers/outcome_delivery.rs` regressions cover appends before and
after the guarded fresh read and complete empty-backlog acknowledgment.
## Relay delivery advances durable per-source watermarks before source cleanup

**Always:** relay rows for a source/target pair apply in sequence order. Each
batch guards the target's `rh` and advances it atomically with the row upserts,
deletes, and pre-delivery hook effects. Duplicates never apply a target batch. Source
cleanup guards each encoded row; draining the timer guards the originally
observed `os`, so a same-millisecond writer cannot lose its wake-up. Writers
stamp and chunk rows, and commit an immediate kind-3 timer with their outbox.
Target watermarks and the one `rs 00` scan row per source are never pruned;
watermarks are bounded by source shards.

**Always:** a key that is ever relay-deleted has exactly one producer. Its
source `os` sequence orders every upsert and delete. Identical upserts from
several producers remain valid for never-deleted keys, including object-index
`i` rows (R-130).

**Because:** one target `rh` per source deduplicates rows, but cannot order
conflicting operations from distinct sources on a deleted key.

**If violated:** a delayed upsert can resurrect a deleted ref-index row.

**Enforced by:** D34 ref-index routing from one ref shard, the disjoint
put/delete relay codec and outbox validation, and ordered relay delivery tests.

**Always:** during an active relay scan cycle, every undelivered row whose
sequence is at or below the durable cursor has a target in the cycle's
sorted, deduplicated blocked set. That set holds at most 32 targets. A cycle
ending at its observed `os` ignores newer rows until the next cycle. The
source atomically guards its previous scan state and commits the new state
with any queue-row deletions; a guard conflict retries. Reaching the cycle
end or the blocked-set cap starts the next fire at the head. Thus a target's
later row cannot advance `rh` past its earlier undelivered row: an earlier
row before the cursor blocks the target, and one after it is scanned first.
Only delivery failure blocks a target; reaching `max_targets` pauses before
the next target and resumes there on the next fire. Blocked targets are
retried at each cycle start. While fewer than `MAX_BLOCKED_TARGETS`
distinct failing targets precede it, every healthy target is eventually
delivered: every fire that sees a deliverable row delivers at least one,
delivered rows (including those past the checkpoint) are deleted in the
same guarded checkpoint, and fires that deliver nothing back off. No
closed-form fire bound is claimed; the relay throughput regressions pin
fire counts for representative schedules. A row appended mid-cycle waits
for the current cycle to finish. This can exceed `RELAY_LAG_BOUND_MS` in time;
WP-1.23c's `namespace_relay_watermark` must tolerate it. A target's later
row is never retried while its earlier row remains undelivered.
At the SQL soft capacity limit, only a valid, guarded `rs` checkpoint, with
any relay-row deletions, or a guarded kind-3 relay timer reschedule may use
the reserved space; ordinary puts still fail. The timer exception preserves
immediate rescheduling after progress on a full shard; without it the runner
would wait for the 5-second retry backoff.
After progress, the persisted relay continuation is strictly after the current
physical wake even when retry metadata retains an earlier handler due time.
The shared tick budget may request an earlier conservative alarm, but cannot
delay that continuation. The retry-progress and full-source relay tests enforce
this rule without changing tick allowances.

**Because:** target delivery and source cleanup cannot share a transaction.
A crash, overlapping timer fires, or a concurrent writer can occur between them.
Source-head scans alone would indefinitely hide a healthy target behind more
than one fire's inspection cap of permanently failing rows.

**If violated:** re-delivery overwrites newer index values, hook effects detach
from their membership writes, or newly queued rows lose their relay timer.
Restoring an older source requires raising `os` above every target's `rh` for
that source or re-keying it (R-102; WP-1.29).

**Enforced by:** `mkit-server/src/relay/tests.rs` crash, contention, ordering,
chunk-limit, wake-up and bounded-cycle fairness tests. Fires inspect up to four
times their row delivery budget, persist bounded cycle progress in `rs 00`, and
revisit blocked targets at the next cycle. Corruption stops delivery after its
decodable prefix.

<a id="object-index-visibility-follows-repository-membership-writer-gate-pending"></a>

## Object-index visibility follows repository membership

**Always:** index rows alone never grant repository membership. Indexed writers
finish index delivery before applying membership and refs; unfinished work
returns `PendingVerification` without a replay result. Identical pack entries
produce identical index values. Launch runs no orphan-row collector.

**Spec:** [SPEC-SERVER §§9.3–9.4](specs/SPEC-SERVER.md#93-verification-obligations)
and [§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [repository-scoped index lookups](../rust/crates/mkit-server/src/store/index.rs),
[indexed pipeline tests](../rust/crates/mkit-server/src/pipeline/tests/indexed.rs)
(`ticketed_good_push_commits_after_index_and_bad_pack_leaves_refs_unmoved`,
`begin_already_present_depends_on_membership_not_index_rows`).

## Pack reads consult only the named repository's membership

**Always:** Multi PackExists and DownloadPack authorize and check repository
existence, then consult the repository's membership index before opening a
blob. An optional X-Mkit-Ref checks only the same repository's ref shard;
invalid, unserved, unknown or overlong hints never cause a public error.
The hint is outside the auth v2 canonical string. Single's membership helper
accepts stored packs; Multi indexed reads and hints enforce the caller's current
live/published view and global denial.

**Because:** blobs may be shared globally, and index relay can lag a write.

**If violated:** pack reads expose another repository's content or make
malformed hints an existence oracle.

**Spec:** [SPEC-SERVER §§9.4, 10.3](specs/SPEC-SERVER.md#94-repository-isolated-membership-checks).
**Enforced by:** [pipeline pack reads](../rust/crates/mkit-server/src/pipeline/mod.rs)
and [indexed hint tests](../rust/crates/mkit-server/src/pipeline/tests/indexed.rs)
(`d34_ref_hint_obeys_pending_and_held_views_before_membership_relay`), plus Multi
wire membership cases.


## Every relay source is covered by an epoch lease

**Always:** a production batch that appends relay rows carries an epoch lease
on its source shard. Only ref shards are relay sources. The test-only `TestTimer`
kind may append a ref-index delete without a lease: it is compiled out of
release builds and can fire after the lease expires. A new relay source class
requires its own coordinator watermark design before it can append rows.
This binds WP-1.10 (#1188), 4.7, 4.8, 4.10, 5.3b, 5.6 and 5.7b. The namespace
watermark bounds every undelivered relay row's **commit time** from below;
consumers compare it against `T + MAX_APPLY_WINDOW + margin`.

**Because:** the coordinator keeps an `ls` row until the source outbox drains.
Without a lease, a new row could appear after the coordinator removed the
source, and the namespace minimum could pass an undelivered commit.

**If violated:** GC or takedown could complete before a relay row arrives.

**Enforced by:** lease guarded ref writes (including `AdvanceRefs`), the D34
apply-loop relay guard, `LeaseSweep` source scans, and real-path watermark
property tests. A new shard's first report can be stale-low, so the namespace
result can decrease even without recovery. It remains unavailable after
recovery until reconciliation.

## Fresh restore preserves epoch and relay safety

**Always:** logical restore imports into a newly empty store supplied by its
caller. It imports the root
sharding marker before other partitions, raises each restored namespace epoch
to `max(snapshot epoch + 2^32, --epoch-at-least)`, refusing overflow, and marks every
restored coordinator lease table recovered before traffic. It drops backup
state, kind-4 timers, old lease-sweep timers, reconciliation markers and relay
scan state. It resets imported `ls` maxima to zero and seeds expired `ls`
rows with sweep timers for restored ref shards that have relay backlog.
Before importing, it reads every
source `os` and every supplied target `rh[source]`. It discards restored
ref-shard epoch leases, forcing the first write to renew against the raised
coordinator epoch. For each source it sets
`floor = max(snapshot os, max supplied rh[source])`, re-keys each relay row
from `seq` to `seq + floor`, and sets `os` to `snapshot os + floor`, refusing
overflow.

**Because:** a Fresh target contains only supplied or explicitly reconstructed
partitions. A target
absent from the set has no high-water mark. Every restored relay row and the
source's next sequence therefore exceed every target's `rh[source]`. Missing
sources are refused or reconstructed at the supplied watermark; missing
coordinators require an explicit epoch floor and are marked recovered.
Relay rows carry upserts and deletes (R-134). Redelivering a row is
idempotent under `rh` ordering and the single-producer rule for relay-deleted
keys; gaps are harmless because delivery compares sequences only with `rh`.
The epoch jump prevents a grant issued and revoked after the snapshot from
becoming valid again. Owners must re-issue grants after restore. Already
delivered rows cannot be replayed from an older target's snapshot; index and
membership reconciliation is required before GA (R-116).

**If violated:** relay delivery can skip a required update, a restored grant
can regain authority through an unexpired old shard lease, or revocation can
complete while an old lease remains effective.

**Enforced by:** the native CLI refuses an existing database;
`mkit-server/src/store/restore.rs` checks every supplied target partition and
validates and transforms the supplied set before import. Tests
`missing_source_is_refused_or_reconstructed_above_target_watermark`,
`missing_coordinator_requires_both_flags_and_is_recovered_before_ref`,
`epoch_floor_and_overflow`, `older_target_cannot_recover_already_delivered_rows`,
and `fresh_restore_orders_root_and_rewrites_recovery_epoch_and_relay` enforce
the memory invariants; native `export_restore_roundtrip_and_usage_refusals`
enforces Fresh refusal and SQLite import.
`mkit-server/src/relay/deliver.rs` guards target upserts and `rh` together.
In-place and Merge restore require another proof and are deferred to WP-5.11b.

## Deployment discovery is public and repository-independent

**Always:** GetServerInfo is unauthenticated, never resolves a repository and
never reads the store. Its response depends only on deployment configuration,
hook defaults and store capabilities, with the upload threshold zero for
Multi addressing or admission.

**Because:** clients need capabilities before authenticating, and discovery
must never expose whether a repository exists (STC §2.1).

**If violated:** clients cannot discover bearer deployments or malformed and
unknown identities become a repository existence oracle.

**Enforced by:** pipeline `tests::info`, Connect dispatch discovery tests,
native `server_hardening` bearer/concurrency regression and wire cases
`info.shape_and_policy` and `info.ignores_repository_header` on Single, Multi,
native TestHost runners.

## Client repository addressing and capabilities remain stable

**Always:** the Connect client validates the literal remote path without repairing
its spelling and sends the resulting identity on every RPC. Signed writes bind
that same value. A transport caches its first capability discovery outcome and
claims atomic advance only for a validated v2 advertisement with an explicit
true value. Ref hints never enter the signed canonical string.

**Because:** routing must agree with authentication, and a push must not reset a
packmap based on an unsupported or changing atomicity assumption.

**If violated:** a client can address an unintended repository or strand a head
behind a packmap reset that was not committed atomically.

**Enforced by:** Connect `client::tests::url_identity_table_preserves_literal_paths`,
`envelope::tests::parity`, `tests/v2_client.rs` discovery and paging regressions,
and CLI `tests/remote_dispatch_connect.rs` header capture.

## Pack unpack bounds owned payload residency

**Always:** unpack charges decompressed payloads, delta targets and cached store
bases before allocation against `max(2 × MAX_RAW_OBJECT_SIZE, 16 × pack_len)`.
Raw wire payloads stay borrowed; a base is released after its final delta use.
Decompression writes into reserved capacity without initializing the claimed
size first. Raw staging skips positions after its earliest permanent failure;
transient worker admission failures are retried strictly in pack order.
Framing arithmetic rejects out-of-bounds lengths on native and wasm32 hosts.

**Because:** authenticated or malicious packs must not exhaust memory through
entry decompression or retained delta targets.

**If violated:** fetch, clone, pull or wasm pack verification can deny service.

**Enforced by:** `pack::tests` resident-peak, bomb, retention-equivalence and
maximum-wire-length regressions; live wasm framing tests in
`apps/web/src/lib/mkit.test.ts`.

<a id="inspection-clearance-bounds-every-reader-surface-specified-implementation-pending"></a>

## Inspection clearance bounds every reader surface

**Always:** readers use published refs and membership. Configured launch
inspection checks every added-pack file entry, including surplus entries,
before membership apply. Reject/quarantine cannot publish; unavailable results
cannot enter replay. Async inspection and durable holds are future integration.

**Spec:** [SPEC-SERVER §§10–11](specs/SPEC-SERVER.md#10-published-view), amended by
[§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [inspection regressions](../rust/crates/mkit-server/src/pipeline/tests/indexed/inspection.rs)
(`complete_set_deduplicates_and_every_inspector_receives_one_batch`,
`reject_dominates_unavailability_and_does_not_publish`,
`unavailable_has_no_replay_and_retry_reuses_inspection_id`), plus
[publication regressions](../rust/crates/mkit-server/src/store/publication_tests.rs).

<a id="takedown-denial-precedes-rewrites-specified-implementation-pending"></a>

## Takedown denial precedes rewrites

**Always:** accepted takedown actions deny independently before success. Launch
retains denial and acquisition/discovery responsibility after preservation;
rewrite, ref substitution, tombstones and completion notices are future work.

**Spec:** [SPEC-SERVER §§14.2–14.7](specs/SPEC-SERVER.md#142-blocklist) and the
[§18 launch subset](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [denial](../rust/crates/mkit-server/src/takedown/denial.rs) and
[activation regressions](../rust/crates/mkit-server/src/takedown/tests.rs)
(`interrupted_activation_replays_pending_until_every_denial_is_active`), plus
[preservation tests](../rust/crates/mkit-server/src/takedown/copy_tests.rs).

## Admin authority and audit continuity (launch foundations)

**Always:** configured admin routes verify exact signed requests and roles;
nonce and operation replay cannot start a second action. Authenticated results
and automatic purge actions extend a gapless audit chain. Unauthenticated
attempts do not enter that log. Only the §18 catalog is supported; leases,
inspection review and audit pruning remain future work.

**Spec:** [SPEC-SERVER §§16.1–16.7](specs/SPEC-SERVER.md#16-admin-api-and-audit-log)
and [§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [admin authentication](../rust/crates/mkit-server/src/admin/auth.rs),
[ledger](../rust/crates/mkit-server/src/admin/ledger.rs) and
[admin tests](../rust/crates/mkit-server/src/admin/tests.rs)
(`manual_purge_acceptance_is_durable_and_operation_replay_cannot_duplicate_work`,
`authenticated_denials_and_audit_reads_extend_gapless_chain`,
`forged_and_mixed_credentials_cannot_reserve_nonce_or_audit`), plus
[restricted catalog tests](../rust/crates/mkit-server/src/takedown/admin_tests.rs)
(`every_operation_is_signed_role_checked_replayed_and_audited`).

## BeginUpload decisions and replay share the write batch

**Always:** BeginUpload authorizes before returning a live ticket or membership
result. Those results skip admission and quota but persist a replay record.
A new ticket, its counters, expiry timer, Ticketed reservation, quota and replay
commit in the target ref shard's one guarded batch. D34 uses the common epoch
lease stages, el guard and capped deadline. Replay stores the complete token.

**Because:** repeat operations must allocate neither extra reservations nor cap
slots, and a retry must still return identical token bytes after consumption or
key rotation. Membership decisions in Multi may consult only the local repo row.

**If violated:** a denied request allocates state, racing opens exceed the caps,
retries charge admission again, or token results disappear with ticket rows.

**Enforced by:** `mkit-server/tests/golden_ticket_token.rs`
(`golden_ticket_token_v1`), `mkit-server/tests/begin_upload_codec.rs`, native
`tests/begin_upload.rs` (`lifecycle_*`, `caps_*`, `race_*`, `rejected_*`) over
memory and SQLite (Single and D34), and the wire `tickets.*` cases.
Kind-2 ticket expiry closes unconsumed tickets; current reconciliation and
terminal delivery are enforced by the [outcome timer](../rust/crates/mkit-server/src/timers/outcome_delivery.rs)
and [reservation reconciliation](../rust/crates/mkit-server/src/timers/reservation_reconcile.rs), under
[SPEC-SERVER §5](specs/SPEC-SERVER.md#5-outcomes-lifecycle-events-and-the-outbox).

## Ticketed advance publishes only completed uploads

**Always:** a ticketed advance checks the ticket row's repository, head ref,
signer and expiry, then the ticket-specific upload marker and pack blob. It
skips admission. A typed ref conflict preserves every ticket; a successful
advance closes each ticket and writes exactly one committed outcome and local
membership in the same guarded batch. The upload marker is checked before the
pack so a globally present pack cannot satisfy another ticket.

**Because:** an upload ticket alone does not prove bytes arrived, and a ref
conflict must remain correctable while the ticket is live.

**If violated:** a repository could claim another upload's pack, lose its
payment outcome, or strand usable tickets after a CAS conflict.

**Enforced by:** `mkit-server/src/pipeline/advance.rs`, native ticket advance
flow/race tests, and `mkit-server-conformance` ticket wire cases.

## Multipart completion authenticates every part before publication

**Always:** UploadPart verifies the ticket, signed commitment and geometry
before storing bytes. A part counts only after its subtree value matches.
CompleteUpload verifies every receipt, total length and merged BLAKE3 root
before making the pack visible. Both paths bypass metadata and admission;
success writes a content-addressed marker in the upload-marker namespace.

**Because:** an unauthenticated or incomplete part must not replace a good
part, publish a pack or create repository membership.

**If violated:** a forged receipt can publish unverified content, or an
upload can bypass BeginUpload's authorization and admission.

**Enforced by:** `upload::receipt::tests`, `pipeline::parts::tests`, and `pipeline::tests::begin_parts` (WP-1.11a).

## Filesystem multipart staging is separate from pack visibility

**Always:** a filesystem part appears under `server-uploads/<ticket-id>/<index>-<cv>` only after its subtree CV verifies. An invalid re-upload leaves the prior verified part intact. A durable per-index pointer selects the current verified file, so a crash during replacement preserves either the old or new receipt. Completion streams the selected part files through the verifying pack sink, so only an exact total and BLAKE3 root can publish a pack. A missing or stale part tag is invalid while the session exists; a completed session reports `SessionGone`. Sessions older than seven days plus one hour, measured from meta mtime, are swept at startup without touching younger sessions. FS part upload and completion each keep peak live heap growth below one quarter of an 8 MiB part in the shared suite; the memory reference backend buffers parts.

**Because:** receipts must identify durable, verified part bytes while crashes and retries cannot make incomplete bytes visible as packs.

**If violated:** a stale receipt could select replaced bytes, or a crash could expose a partial pack or discard a live session.

**Enforced by:** `mkit-server-conformance/src/storage/multipart.rs`, instantiated
by `tests/memory_backends.rs` and `tests/fs_backends.rs`; `mkit-server/src/fs/tests.rs`
ticket-layout, restart, replacement and seven-day sweep tests. The native HTTP
`TestHost` runs `Feature::Multipart` wire cases over `MemoryBlobStore` and
`MemoryKv`; filesystem multipart behavior is covered by the storage suite.

## Connect read authentication is scoped to one attempt

**Always:** a Connect client with a signer signs each repository read over
the exact HTTP request body, including streaming-request framing. Each retry
has fresh identity headers. Writes retain their logical-operation nonce, and
the grant header stays outside the signed canonical string. Discovery and
grant-epoch RPCs are never signed; grant-epoch RPCs carry no repository.

**Because:** read authentication selects the writer or private-reader view,
while replay protection applies only to writes. A grant is selected locally
and may change without changing the authenticated operation.

**If violated:** a private read can become anonymous, a retry can use an
expired identity, or a write can silently mint a new nonce.

**Enforced by:** the Connect procedure classification and envelope tests,
client retry tests, and `mkit_core::write_auth::verify_headers` checks over
captured request bodies.

## Implicit transport-identity membership is session-bound

**Always:** implicit (transport-identity) membership is granted only for
packs uploaded and verified in the same session and repository; the
packmap check only refuses. A session's pending set holds at most seven
distinct packs, dies with the session, and is consumed by that session's
next packmap write. A packmap is refused when its node's `prev` is
neither absent nor the packmap value the write replaces, so the
ssh/enc consuming write never adds a new non-member (values written
over Connect are not chain-validated, so this guarantee covers values
written over ssh/enc); it is also refused when its node or a listed pack is
neither pending nor already a member of the bound repository (a pending
packlist listed as a pack is refused: a packlist is a node, not a
pack), or when it lists more than 1,024 packs; the check never adds
membership for a pack it merely names, and no reservation or outcome
rows are created — there is no reservation to keep one outcome per.

**Because:** ssh and enc clients cannot carry signed upload tickets, so
the transport binds them to the session instead. Letting the packmap
check grant membership, or letting pending state outlive a session,
would let a client claim packs it never uploaded — the membership
oracle a ticket's signature otherwise prevents.

**If violated:** a writer could publish packmaps naming packs it did not
upload, minting membership without possession and breaking repository
isolation across sessions and repositories.

**Enforced by:** `mkit-server/src/pipeline/mod.rs`
`check_implicit_packmap` and `update_packmap_consuming` unit tests,
`mkit-server/src/ssh/tests.rs` pending/consume/reconnect/isolation
cases, and `mkit-cli/tests/serve_golden.rs` session-3 wire goldens.

## Private repositories are indistinguishable from missing ones

**Always:** an unauthorized read of a private repository answers the same
`not_found` — code, message, details and headers — as a missing
repository, from `ServerError::repository_not_found()`. A signed read
verifies its envelope in full before any repository lookup and never
creates or consumes a replay record.

**Because:** SPEC-WRITE-GRANTS §9.2/§9.3; private repositories must not be
enumerable, and reads must not spend replay capacity.

**If violated:** private repository existence leaks through an error
difference, or reads consume replay capacity.

**Enforced by:** `pipeline::authorize_read` and `policy::read::decide`;
the pipeline `private_repository_reads_return_the_missing_repository_error`
and `a_signed_read_writes_no_replay_rows` tests; the connect_dispatch and
wire `reads.private_not_found_byte_identical` cases.


## Scheduled verification checkpoints retain closure authority

**Always:** a scheduled job's guarded checkpoint and the deletion of a child
satisfied by a member pack commit together. The checkpoint retains that pack
for the consuming advance's membership recheck. Only a completed decode may
emit index rows, and Verified follows delivery and extraction. Rebuilding job
rows cannot downgrade an already Verified pack.

**Because:** a crash between deleting a child and recording its member would
lose the evidence needed to catch GC or generation changes. Async verification
must retain the same repository authority as inline verification.

**If violated:** an advance can accept an open closure, or storage damage can
turn a monotone verification result into a contradictory persisted rejection.

**Enforced by:** `mkit-server/src/indexed/job.rs` atomic closure checkpoints and
state guards; the job-driver crash sweeps, satisfying-member removal test,
Verified rebuild test, and Scheduled pipeline pending/delivery tests.

## Paid HTTP reads reserve durably and settle once

**Always:** a reservation-bearing HTTP read records Pending(Read) before
returning a body; transmission stops at the configured creation-based deadline.
Completion and reconciliation conditionally replace the same pending bytes.
Partial transmission records ReadServed(actual bytes handed to the stream),
and a zero-byte failure records Aborted(INTERNAL); HEAD succeeds with zero bytes.

**Because:** charging without a durable obligation loses accounting on a crash,
and independent terminal writes can charge one reservation twice.

**If violated:** a paid stream can escape accounting or create duplicate outcomes.

**Enforced by:** `pipeline/http_admission.rs`, `http_objects/paid.rs`,
`timers/reservation_reconcile.rs` and the focused `http_objects/paid_reads` tests.
With HTTP serving enabled, adapters must retain the injected spawner's tasks (WP-4.16).

## HTTP URL tokens bind before stored epoch access

**Always:** private HTTP reads precheck signatures before repository lookup,
then bind audience, repository, decoded target, expiry and lifetime before
reading the stored epoch. Public reads ignore every token result. A valid
private token still requires the Authorizer, and the caller stays anonymous.
Private immutable freshness never exceeds the token's remaining lifetime.

**Because:** early epoch access reveals extra state to invalid tokens, and
cache freshness beyond expiry extends a private authorization capability.

**If violated:** invalid tokens can probe stored state or private content can
remain fresh after the authorization expires.

**Enforced by:** `pipeline/http_tokens.rs`, `policy/read.rs` and counted-store
`http_objects/private_tokens` tests. With HTTP serving enabled, shared-cache bypass belongs
to the adapters in WP-4.16.

## Unsupported HTTP proofs stop before preparation and payment

**Always:** the shipped HTTP handlers validate proof query syntax and retain
normal repository/token authorization, published target resolution and takedown
checks. Permitted GET/HEAD proof requests then return 416 before proof-context
preparation, canonical representation metadata, validators, Admission,
reservations or response-stream setup. A conditional request cannot produce
304 for this unsupported representation. HEAD sends no body.

**Because:** unsupported representations must not consume payment or prepare
proofs that cannot be served, and private repository existence must remain
concealed. Generic disclosure formats, core builders and client verification
remain supported independently of HTTP serving.

**If violated:** disclosure of inaccessible content, wasted preparation work,
unsupported cache validation, or reservations for an unservable read.

**Enforced by:** SPEC-HTTP-OBJECTS §3, the HTTP `unsupported_proofs`,
`private_tokens`, `publication_access`, `takedown_denial` and `paid_reads` tests.

## Published refs and durable dependency work (WP-5.4)

**Always:** head and packmap publish together at the greatest contiguous cleared
prefix. Deletion preserves sequence boundaries. External delta dependencies,
including those of surplus entries, retain durable recheck work until satisfied;
own additions do not establish external-base publication. Reader authorization
precedes published-view selection.

**Spec:** [SPEC-SERVER §§10.1–10.3](specs/SPEC-SERVER.md#10-published-view) and
[§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [publication store](../rust/crates/mkit-server/src/store/publication.rs),
[publication regressions](../rust/crates/mkit-server/src/store/publication_tests.rs)
(`out_of_order_membership_does_not_skip_the_pointer`,
`deletion_and_recreation_preserve_sequence_and_old_membership`,
`own_additions_never_satisfy_an_external_delta_dependency`,
`d34_delayed_cross_ref_delta_relays_wake_durable_work_after_restart`), and
[HTTP publication access tests](../rust/crates/mkit-server/src/pipeline/tests/http_objects/publication_access.rs).
Async inspector scheduling and durable hold integration remain future work.

## Independent global denial and pending takedown intent (WP-5.6a-1)

**Always:** current V1 denial rows and each active V2 action deny independently.
Acceptance binds immutable verified descriptors and activates every denial before
returning success. Manifest chunks stop in repositories holding that manifest.
Purge responsibility commits with acceptance/activation and late-holder discovery;
failed delivery remains owned by durable timer work.

**Spec:** [SPEC-SERVER §§14.2, 14.7](specs/SPEC-SERVER.md#142-blocklist),
[§16.7](specs/SPEC-SERVER.md#167-remote-cache-purge) and
[§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [denial](../rust/crates/mkit-server/src/takedown/denial.rs),
[intent activation](../rust/crates/mkit-server/src/takedown/intent.rs),
[late-owner tests](../rust/crates/mkit-server/src/takedown/late_owner_tests.rs) and
[signed replay regressions](../rust/crates/mkit-server/src/takedown/tests.rs)
(`interrupted_activation_replays_pending_until_every_denial_is_active`,
`timer15_restart_finalizes_interrupted_signed_acceptance`).

## Lean preservation cannot imply completed takedown (WP-5.6a-2 contract)

**Always:** verified restricted copies do not establish final holders or completed
takedown. Discovery waits for the safety cut and relay watermark. Open namespace
policy never claims exhaustive discovery. Preserved reads freshly verify role,
retention and emitted pieces; replay contains no preserved bytes. Per-action
purge cannot delete another action's copy or lift denial.

**Spec:** [SPEC-SERVER §14.7](specs/SPEC-SERVER.md#147-preservation-store) and
[§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [copy tests](../rust/crates/mkit-server/src/takedown/copy_tests.rs),
[discovery regressions](../rust/crates/mkit-server/src/takedown/discovery_tests.rs)
(`finite_two_namespace_sweep_waits_for_undelivered_membership_then_unions_sources`,
`any_streams_one_namespace_candidate_and_never_claims_discovery_complete`), and
[admin regressions](../rust/crates/mkit-server/src/takedown/admin_tests.rs)
(`status_keeps_acquisition_verification_discovery_hold_and_completion_separate`,
`fresh_retry_roles_retention_and_ownership_never_replay_bytes`,
`signed_hold_commits_with_audit_and_nonce_and_blocks_actual_purge`).

## External authority revocation fences final acceptance

**Always:** with authority fencing enabled, a completed namespace generation
barrier prevents every older Authority allowance from accepting a new write.
Facts survive retries, visibility writes compare the coordinator generation,
and D34 writes guard generation-bearing leases and backend deadlines. Ticket
staging coalesces client frames in at most 256 KiB of private buffering and
checks the ticket's generation before and after every actual backend write,
plus receipt, completion and marker boundaries. Metadata work depends on
declared bytes, never the number of client frames. Durable
mode at generation zero prevents a disabled executor from accepting through a
fenced lease, fresh shard, visibility operation or ticket. Initial activation
finishes its barrier before granting ready leases and creates no accounting
namespace. Grant epochs remain independent. Generation/recovery-bound durable
cursors keep bounded completion progressing across cold executor instances;
recovery invalidates them while preserving the fence.
All-key stores inspect durable fence evidence even on disabled Single
executors; atomic all-key stores also guard the observed generation and mode
at acceptance. Single batches these reads into its existing read-ahead call.
Ref-only stores omit unsupported metadata reads and retain sequential ref
batches. Their capabilities cannot enable fencing; generation-bearing plans
on any incapable store refuse rather than dropping their protection.

**Because:** stopping future hook allowances cannot revoke an allowance already
paused between authorization and durable acceptance.

**If violated:** a revoked delegate can commit after revocation was acknowledged.

**Enforced by:** the atomic plan, visibility and ticket guards and shared lease
renewal/completion and the conformance memory-backend authority tests.
Deployment activation is
optional and requires an Authority hook with explicit generation facts.

## Pending holder work protects bytes beyond hold TTL

**Always:** any content-shard `gp` row for an object prevents collection.
Insertion guards and bumps `c`; the row does not expire by age. Identical
ownership retry does not bump, and changed ownership refuses.

**Because:** queued holder work may still apply after its ticket or ordinary
GC hold expires. Removing that protection can delete an object before its
durable holder arrives.

**Spec:** [SPEC-SERVER §13.4](specs/SPEC-SERVER.md#134-global-byte-deletion).
**Enforced by:** [content-index safety](../rust/crates/mkit-server/src/store/content_index.rs)
and [extraction holds](../rust/crates/mkit-server/src/indexed/extract.rs).
`ContentIndex::protect_pending_holder` uses guarded fresh
block/deleting observations and NotAfter. `collectable` checks one pending row
and its final plan guards `c`; unknown pending state closes collection. The
content relay hook atomically commits holder/count/c changes, ordinary hold and
exact pending-row release, and the watermark. A late blocked holder retains a
durable takedown request for WP-5.6a. No permissive release API is exposed.

Extraction verifies sources and enqueues/renews holders; takedown exposure requires admin
keys, `LAUNCH_PROFILE=paid-workers`, `TAKEDOWN_ENABLED=true`, indexed Paid mode and
complete §14.7 preservation configuration, with partial configuration refused
at startup.


### Scheduled extraction freezes closure and protects source lifetimes (WP-4.10b-2)

**Always:** extraction effects begin only after the complete consumed union has
passed closure and deterministic selection. Object counts and canonical-byte
reports deduplicate by ID. Peer reuse guards bounded job headers whose generation
binds immutable member-list bodies. A stale header or generation cannot authorize
reuse, replacement, cleanup or an extraction effect.

**Because:** a missing source can invalidate the entire push, and completed peer
member lists can be too large to fit raw CAS guards together. Header generations
prove the lifetime of immutable facts without buffering native's staged map.

**If violated:** a partial group can publish unwanted bytes or falsely report
Verified; large legitimate reused groups can become permanently unclaimable.

**Enforced by:** `indexed/checkpoint.rs`, `scheduled.rs` and `job/extraction.rs`;
`header_tests`, `scheduled_reclaim_tests` and native-oracle `extraction_tests`
cover header/body mutation, six groups with 256 members, union counts, closure lag,
replaced/expired tickets and canceled owners. Gone tombstones retain generations.

### Delta source reconstruction advances with bounded live memory (WP-4.10b-2)

**Always:** each unfinished extraction-source reconstruction alarm persists one
lookup prefix or one ancestry/decode step. Only a previous canonical accumulator
and one decoded frame are resident; descriptors and fragments use existing vc4.
Every decoded frame and accumulator matches its core object identity before upload, and
completed source charge advances atomically with the chunk cursor. Restart cannot
lose or double that charge. Extraction boxes each stage future at the serial
loop boundary so backend future storage does not accumulate in enclosing slice
futures. The 50-hop quota-boundary test retains a 512 KiB stack.

**Because:** a native-valid 50-hop source can exceed a single alarm's 256 calls
while fitting its 48 MiB live-memory allowance. Retrying a whole chain would stall.

**If violated:** a valid push never progresses, a replay changes quota accounting,
or unverified canonical content reaches the object store.

**Enforced by:** `job/extraction/member.rs` and the guarded `Stop::Yield` path.
`extraction_budget_tests` compares native results, per-alarm progress/calls and
restart midway through a 50-hop chain, including 250 KiB nodes and the exact
whole-source decode-budget boundary. `extraction_step_futures_stay_small` bounds
unpolled coroutine sizes with both ordinary and counted stores. These steps are
shared with wasm32; the native size guard complements the wasm32 build and
native HTTP wire-conformance checks. Apply validation retains 100 ops / 1 MiB.

## Launch inspection checks the complete bounded set before apply

**Always:** launch inspection uses at most four sync/fail-closed inspectors,
with one complete, deduplicated metadata batch per inspector. The set contains
every Blob and ChunkedBlob entry of the added packs, surplus included, reported
as BLOB and CHUNKED_FILE; chunk-only blobs remain BLOB and CHUNK is unused.
Inspection starts from an empty store; every consumed pack ticket's file entries
pass inspection before membership apply. Earlier membership remains covered even
when D34 relay lag delays publication or refs are deleted and recreated; upload
completion and verification alone add no membership. Added-pack entry counts preflight the positive
whole-advance bound (at most 10,000) before enumeration; oversize uses the
ordinary index-limit refusal before hooks/apply. Reject/quarantine dominates;
unavailable cannot commit or enter replay. With inspection disabled, existing
bytes and calls remain identical. No durable inspection continuation is created.

**Because:** whole-pack downloads expose surplus entries. Frame/checkpoint pages
of at most 1,000 rows enumerate the set without an inspection tree walk,
reference-page reads, object-store reads or role classification; inspection shares
the 1,000-call accounting contract. Scanners decode chunk membership through
R-193 private retrieval.

**If violated:** unscanned content can publish, retry can bypass inspection, or
an accepted request can exhaust its configured invocation budget.

**Spec:** [SPEC-SERVER §§11, 18](specs/SPEC-SERVER.md#11-quarantine-and-inspection).
**Enforced by:** [inspection code](../rust/crates/mkit-server/src/indexed/inspection.rs)
and [inspection tests](../rust/crates/mkit-server/src/pipeline/tests/indexed/inspection.rs).
The empty-store activation rule is a documented operator
precondition of the supported launch profile, not a runtime existing-content
check; there is no durable mode marker at launch. Inspector configuration,
input limits and verdicts are enforced by `Pipeline::with_inspectors`, `InspectionSet::preflight`,
header/frame checks and `Pipeline::inspect_advance` before apply. Request-local
accepted verification snapshots are checked before/after frame enumeration;
each pack's decoded-size sum must match its verified first-occurrence total.
Changed jobs or missing frames retain pending-verification behavior. Pipeline
acceptance tests cover verdict dominance, unavailable replay exclusion and
inspection-disabled identity. Budget assertion: 960 calls (300 verification,
256 ancestry, 256 shared pair closure/enumeration/dependencies, four Inspect,
144 other); <=16 frame pages plus two batched verification-snapshot reads
fit inside the pair allocation. The added-pack inspection set removes
the earlier role-reconstruction cost; see
[SPEC-SERVER §18](specs/SPEC-SERVER.md#18-conformance-scope).
Full classification, async holds and unrestricted multi-batch inspection remain
future integration; the durable marker is retained storage-only groundwork.

## HTTP file headers never interpolate raw filenames

**Always:** ordinary successful ref-path Blob/ChunkedBlob responses select media
and disposition only from the fixed extension allowlist. Extended filenames
are derived and fully percent-encoded outside RFC 5987 attr-char; the ASCII
fallback retains only alphanumerics and `._-` and is capped at 255 bytes.

**Because:** repository entry names may contain quotes, delimiters, control or
non-UTF-8 bytes. Their bytes must never become header syntax or active media.

**If violated:** a filename could inject response headers or enable active
content under the serving origin.

**Enforced by:** `http_objects/content_headers.rs`, success-only selection in
`pipeline/http.rs`, common pipeline tests, and shared `content-headers.json`
wire vectors on the native mount.

## Publication rechecks retain bounded progress

**Always:** timer 12 persists its next unchecked or unsatisfied routed witness position in
its existing row, bound to the full retained advance plus publication generation
and deletion boundary. Each fire makes at most 128 routed witness calls and
stops before the supplied timer budget is exhausted. Checkpoints and
completion guard the advance, publication state and original timer row together.
Local mutable witnesses are re-read each fire. Missing witnesses, outstanding
obligations, holds and hits never authorize completion.

**Because:** a valid D34 packmap may require more routed witness reads than one
alarm permits, and restarting every check can leave it permanently pending.

**If violated:** publication stalls, or stale progress skips a dependency after
an obligation or generation change.

**Enforced by:** `timers/publication_recheck.rs` and the publication recheck
regressions. No tag, timer kind, public protocol,
packmap limit or whole-alarm budget changes. Pre-launch timer codecs are reset,
not migrated (R-198 B1).

## Corrupt preservation sources have terminal audited checkpoints

**Always:** decoding or hash validation failure of a selected verified-member
source records a terminal source failure and an audit entry atomically. Denial
stays in force, the request remains unresolved, and a restart does not decode
that source again. Storage unavailability and resource exhaustion remain retryable.
Raw and compressed delta result headers are compared with immutable verified
decoded sizes before ordinary decode budgeting. Compressed prefix inspection
reads nine output bytes under the fixed window/block bounds, releases its decoder
before full decode, and does not reserve the advertised stream or result size.

**Because:** later storage corruption can invalidate historical verification;
retrying the same bad bytes cannot repair them and can monopolize Worker alarms.

**If violated:** a request can loop forever or falsely report preservation success.

**Enforced by:** preservation work corruption/restart and transient-I/O regressions;
`zstd_heap_bounds` measures the actual decoder on native and wasm32.

### Embedder URL token issuance (R-204)

- **Always:** reader URL batches share RPC read authorization, stored epoch,
  audience and TTL minting, and return tokens only for accessible published targets.
- **Because:** a verified reader envelope delegates in-process authority without
  creating a second token policy; HTTP URL tokens serve only the published view.
- **If violated:** an embedder could issue credentials under stale grant authority
  or reveal inaccessible content through batch presence.
- **Enforced:** `Pipeline::issue_url`, `ObjectReader::issue_urls` and its shared
  bounded reader preflight; parity, private, denial and pending-publication tests.

### Deployment default visibility (R-205)

- **Always:** every visibility read uses a stored visibility when present, and
  otherwise the deployment default, which is public unless configured.
- **Because:** first writes must honor private defaults, and an explicit owner
  setting must have identical precedence on every serving surface.
- **If violated:** an unset repository could leak through a path with a hard-coded
  public fallback, or a deployment change could override an owner's explicit setting.
- **Enforced:** `pipeline::repo_is_private` in the three strong visibility lookups; Connect,
  HTTP, URL issuance, readers and snapshots use those paths. No visibility cache.

## Restricted preserved reads and atomic operator holds (WP-5.6a-3)

**Always:** Get/List keep acquisition, verified preservation, discovery, legal
hold, purge and real completion separate. Any discovery never claims complete.
A signed hold change commits its core arbitration batch with the operator audit
and nonce result. ReadPreserved stores only a bounded action/object/offset
nonce descriptor. Every byte-reading retry checks current key and role and
commits an acceptance audit; every emitted piece freshly checks retention,
hold and purge ownership and verifies its immutable owner header and hash.
Only successful streams emit one last message; streaming failures append an
audit result before the Connect error. **Because:** replayed bytes, stale
retention checks or an unaudited hold can expose or destroy evidence.
**If violated:** a restricted copy leaks, legal hold loses arbitration or
verification is mistaken for real takedown completion. **Enforced by:**
`admin::Engine::handle_streamed`, `takedown::work::Work`'s admin operations,
the legal-hold planner and the signed catalog/streaming regression tests.
Production takedown activation requires admin keys, `LAUNCH_PROFILE=paid-workers`,
`TAKEDOWN_ENABLED=true`, indexed Paid mode and complete §14.7 preservation
configuration; startup refuses partial configuration.

## Native HTTPS extra trust

**Always:** Native Connect HTTPS retains the compiled Mozilla roots and verifies
both the certificate chain and hostname. `MKIT_SSL_CA_FILE` overrides the merged
`http.sslCAInfo` path; selected invalid files fail before any request dispatch.
**Because:** Extra local trust must authorize certificates explicitly without
silently downgrading verification or losing the normal public trust store.
**If violated:** A local trust option could admit an impersonated remote, or a
bad file could silently use another trust configuration.
**Enforcement:** `mkit-transport-connect::tls::client_config` builds rustls with
augmented roots and its standard verifier. Real TLS Connect/streaming tests
cover trusted CA, hostname mismatch and default refusal; subprocess tests cover
selection and CLI config layering. Browser clients keep browser-managed trust.

## Durable inspection mode and repository flags

**Status:** storage-only groundwork retained by owner decision. No pipeline or
adapter installs the marker or flags; launch's empty-store inspection rule is
an operator precondition, not activation of this storage API.

**Always (storage API):** mode activation is one-way and requires an empty store;
flag changes atomically bump the registry version, while identical installs do not.
**Spec:** [SPEC-SERVER §11](specs/SPEC-SERVER.md#11-quarantine-and-inspection) and the
[§18 integration boundary](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [inspection mode tests](../rust/crates/mkit-server/src/store/tests/inspection_mode.rs)
and [flag tests](../rust/crates/mkit-server/src/store/inspection_flags_tests.rs).

## Repository-wide inspection holds

**Status:** retained storage-only groundwork. Launch creates no inspection holds
or continuations; timer kind 14 remains reserved, with no runtime handler.

**Always (storage API):** cross-ref holds share the repository partition; release
removes only its own rows and fences delayed pages before removing the ref record.
**Spec:** [SPEC-SERVER §§10–11](specs/SPEC-SERVER.md#10-published-view) and
[§18](specs/SPEC-SERVER.md#18-conformance-scope).
**Enforced by:** [hold regressions](../rust/crates/mkit-server/src/store/inspection_holds_tests.rs)
(`repository_wide_cross_ref_holds_and_own_release_in_single_and_d34`,
`release_fences_delayed_pages_and_preserves_fallback_until_cleanup_in_single_and_d34`).

## Timestamp-priority history traversal is bounded and exact

**Always:** the shared `TimestampDiscovery` reducer emits all-parent history in
decreasing canonical `Commit.timestamp`/`Remix.timestamp` order with
retained-discovery ties — never a hash tiebreak, never a topological gate. The
pending frontier never exceeds 256 verbatim slots and the emitted set never
exceeds 192 ids; crossing either bound fails the operation with no partial
state. Dedup goes live with the first revisitable emission (a
multi-local-parent node, or any emission while candidates remain pending) and
records every later emission; decoded is not emitted, and parent enqueue
completes before any snapshot. Seeding closes at the first completed emission
so a late seed cannot descend into the unrecorded linear prefix.

**Because:** server issuance/redemption and embedder page loops must produce
byte-identical pages from the same state without re-walking the emitted
prefix; a skipped ancestor or duplicate emission is a conformance break, and
unbounded seen state cannot travel in a bounded token.

**If violated:** pages could repeat or drop commits, drift between
implementations, or grow a continuation token without bound.

**Enforced by:** `mkit-core::history_order` reference reducer and
[SPEC-HISTORY-ORDER](specs/SPEC-HISTORY-ORDER.md); fixture, page-boundary,
snapshot round-trip and explicit cap tests, plus proptest
split-vs-single-run equivalence.

## Denial waves preserve admission order

**Always:** with `PipelineConfig.takedown_denial=true`, a Decode batch's inventory
staging completes before its denial reads. Denial waves contain at most sixteen
reads, matching the staging batch cap; the shared reader admission envelope
remains six. Admitted readers reserve each wave's calls;
ordinary mutation stores keep dispatch-time charging, so later budget exhaustion
cannot mask an earlier object's denial. A wave whose all-or-nothing
reservation is refused issues no reads and reports unavailable (fail-closed;
the slice retries).
All responses in a wave finish before failures are examined in batch order.
No frame, candidate, or index row for the batch precedes successful denial
admission. EmitIndex and inline index writes use the same helper in their
existing put order before each direct apply. The earlier inline pre-staging
check uses the same waves at its existing boundary. Extract's per-chunk and
per-frame checks retain their existing serial boundaries.
Decode denial time records wave wall time, not summed call durations.

**Because:** staging must expose objects to a concurrent takedown before denial
admission, and response timing must not change blocked/unavailable precedence.

**If violated:** a concurrent block can escape admission or network timing can
select the outcome and misstate its cost.

**Enforced by:** Decode admission, direct index writes, the inline verifier's pre-staging check, and the shared denial-wave helper;
`inventory_stage_guard` covers a block landing during staging, and denial-wave
unit tests cover latency, call charges, reservations, and mixed failures.

## Disabled global denial performs no denial I/O

**Always:** when `PipelineConfig.takedown_denial=false`, ingest and read checks
report clear without reading block or denial-action rows. Holder, inventory,
membership, index, and proof-structure writes continue. Takedown writer paths
refuse with typed `failed_precondition` and `takedown denial disabled` before
any write. Raw block and denial-action writers require a capability that only
a pipeline with denial enabled can provide.

**Because:** skipping denial reads is safe only when every corresponding writer
is disabled. Keeping other rows supports normal ingest and a later migration
that backfills holder, inventory, and proof structures.

**If violated:** a block could become invisible to ingest or serving, or disabling
denial could lose holder and inventory information.

**Enforced by:** the shared denial read gate, `Pipeline::denial_capability`,
capability-bearing `ContentIndex` writers, and disabled-mode writer and ingest/read
regressions. [SPEC-SERVER §14.2](specs/SPEC-SERVER.md#142-blocklist) defines the
mode and activation migration.

## Native client headers and request budgets

**Always:** `NativeHttp` preserves supplied user-agent and gzip/identity-only
accept-encoding values, refuses unsupported or malformed negotiation before
connecting, and bounds each HTTP exchange through response receipt. Metadata
uses a 30-second default; UploadPack, UploadPart and DownloadPack use 300 seconds.
The two budgets can be configured independently.

**Because:** observer headers replace transport defaults, and metadata work
must not inherit a pack-transfer deadline.

**If violated:** host attempt policy could be silently replaced, unsupported
responses negotiated, or metadata connections held open for too long.

**Enforced by:** `mkit-sync::NativeHttp::send_typed`, `request_headers`, and the
`native_http` header-preservation, negotiation-refusal and timeout tests.

## Local build output stays isolated and opt-in

**Always:** local cache recipes give each workspace its own Cargo build directory
under `~/.cache/mkit/build/{workspace-path-hash}` (overridable by
`MKIT_BUILD_ROOT`). Never share `CARGO_TARGET_DIR` across worktrees. Tracked
TOML, Docker, and CI inputs never set `build-dir`; CI retains its own caches.
GC defaults to dry run and runs only `cargo clean` for clean, merged/gone linked
worktrees. It keeps main/current, detached, locked, and dirty checkouts and
refuses external, symlinked, or tracked target output and build directories
that overlap source checkouts. Neither output directory contains a registered
source checkout. Worktrees, branches, and source stay intact.

**Because:** shared compilation results save CPU without sharing Cargo's locked
output directories. A committed build-dir setting would redirect CI's caches;
a cleanup following external paths could remove another checkout's output.

**If violated:** parallel builds serialize, caches go cold, or cleanup deletes
unrelated output or source.

**Enforced by:** `scripts/local-build.py`,
`scripts/check-build-dir-authority.py`, and `scripts/tests/local-build.test.sh`
through `just check-local-build` and the existing local `just ci-scripts` gate.
No CI caching configuration changes. Stop concurrent edits before applying GC;
Git status is rechecked but editors do not participate in a shared lock.

## Complete ref listings retain bounded, strictly ordered state

**Always:** all three listing drivers use `mkit_core::ref_listing::RefListing`.
Names increase strictly within and across pages, including empty intervening
pages. Each nonempty cursor is at most 4 KiB and appears once. Cursor history
retains only BLAKE3 digests. A listing accepts at most 100,000 pages and charges
names, ref entries, digest history, and the active cursor to 128 MiB. A caller's
lower page limit still applies. Invalid state fails before the page is retained.

**Because:** a remote server controls page contents and continuation tokens.
Empty pages must not bypass resource limits or cursor-cycle detection.

**If violated:** a remote can exhaust memory, loop a listing, or expose duplicate
or inconsistent refs to a caller.

**Enforced by:** the shared accumulator, `Client::list_refs` page validation,
core budget/page-cap tests, and `shared_listing_adversaries` in each driver.

## Fetch checkpoints follow verified tracking publication

**Always:** a native fetch checkpoint binds its remote branch to a repository
identity and origin, and records only a fully applied, verified packmap chain.
Fetch publishes the tracking ref durably before the checkpoint under the same
worktree lock. An unchanged remote tip and head download nothing. Every listed
tip still passes locked closure verification; new nodes retain digest and
signature checks.
Missing local objects trigger full-chain recovery before publication.

**Because:** immutable packmap nodes permit skipping verified ancestors, but
an unpublished or differently addressed checkpoint cannot establish local safety.

**If violated:** fetch could skip new content, fail to restore missing objects,
or publish an unverified branch after a crash or concurrent operation.

**Enforced by:** `mkit-sync::fetch`, checksummed `checkpoint` records, bounded
`walk_pack_chain_until`, counting-source regressions on both backends, and crash,
concurrent-pull, identity-change, and signature-failure regressions.

## Sync source outcomes retain host scheduling evidence

**Always:** `RemoteSource` returns backend-neutral `SourceError`. Verification
and visibility waits, retry hints, payment challenges, signing failures, and raw
Connect code/message/details/status/headers survive the client adapter and
`SyncError::Source`. Classified core transport errors map explicitly. Sync
returns resumable outcomes without sleeping or retrying; refusal and transient
failure remain distinct. Observed signed clients compose without read callbacks.

**Because:** the host owns scheduling and admission policy, and deterministic
channel refusals must not become retryable connection failures.

**If violated:** hosts lose recovery evidence or retry terminal refusals, and
configured clients cannot be used through the sync adapter.

**Enforced by:** `mkit-sync` source adapter tests for both backends, remote
metadata/overload tests, and `observed_signed_client_composes_as_source`.
CLI transport display parity and the existing CLI golden suites retain output
and exit-code behavior. No authorization, wire, or stored-format boundary moves.


## Pending advance waits precede fresh guarded attempts

**Always:** an optional ticketed verification hold retains no attempt snapshot,
lease, reservation, or write gate. Its timer covers ticket resolution and job
polling, ends within two seconds and the host deadline and envelope expiry
minus 250 ms, and leaves the pending response unchanged on timeout. Usable
job rows only trigger a full new advance attempt.

**Because:** asynchronous readiness cannot authorize mutation or prolong a
signed request's validity. Cancellation must leave normal retries possible.

**If violated:** stale authorization could commit, concurrent requests could
stall, or an expired envelope could remain held.

**Enforced by:** `pipeline::pending_hold` and scheduled hold regressions for
expiry, elapsed budget, completion, cancellation, replay, and concurrent CAS.

## Client source writes keep policy and receipt durability in the host

**Always:** signed source writes use `mkit-client` per-RPC calls. The host
selects grants on each signed envelope and schedules typed failures through
`WriteRecovery`. Ticket-consuming writes never run admission recovery. Each
part receipt finishes caller-owned durable `put` before progress or the next
part. Fresh instances recover the open ticket and reuse only matching receipts.

**Because:** wire ownership belongs to the protocol client, while credential
trust, helpers, scheduling, and filesystem durability depend on the caller.

**If violated:** policy could authorize the wrong request, or a restart could
resend an acknowledged part or advance refs without its upload commitment.

**Enforced by:** request-policy seam tests and both-backend native push tests,
including multipart interruption and receipt reuse across fresh instances.

## Fork acceptance precedes membership installation

**Always:** the fork's durable pack list stages the complete inherited set,
including external-base suppliers. No membership witness is installed until
`Accept` records the accepted result with its replay and reservation outcome.
The same row binds the operation, destination, requested visibility, source pair,
membership generation, pack lengths, byte charge, and exact authority rows.
The final source pair, policy, and inherited-pack proofs follow preparation.
Activation repeats destination denial checks and never changes or settles the
saved result. An accepted job remains recoverable beyond the construction expiry.

**Because:** preparation is not permission to serve content, and a committed
receipt must survive interrupted clearance and later source changes.

**If violated:** readers could observe an unaccepted fork, an accepted result
could change after a lost reply, or a reservation could settle twice.

**Enforced by:** `fork::job`, `fork::accept`, `fork::publish`, and the fork engine
acceptance, settlement, membership-order, source-change, and lost-reply tests.
`fork::proof` captures source pair/policy rows, repository-index mutation
versions, directory revisions and every registered subject's content-state
version before proving packs. Validation follows the entire proof pass; a
changed version refuses uniformly. Versions never repeat, including after
removal and reinstallation. Custom publication policies must provide a coherent
`fork_version`; its default refuses new and unaccepted forks. Accepted and
retained failed jobs reclaim transient proof rows in bounded, restart-safe pages,
including while activation is stalled. Exact job and evidence guards prevent
stale capture checkpoints from resurrecting deleted rows.

## Physical fork activation is fenced before acknowledged moves

**Always:** membership installation atomically checks its recorded authority facts
when they share its partition. Otherwise it compares an expiring local permit
bound to the fork and recorded facts. Generation and epoch moves freeze issuance,
drain registered permits into local revocation tombstones, and publish the move
only after invalidation completes. Drain checkpoints survive interrupted work.

**Because:** a coordinator checkpoint after a physical membership write cannot
undo visibility granted by a stale write.

**Enforced by:** `fork::permit`, local activation guards, and the authority/epoch
transition paths. Repository-index mutations atomically increment `fv`; directory
registration increments `dv`; content mutations increment their existing state
sequence. `Write::Increment` adds these stamps without a writer snapshot or an
extra round trip for default reference batches. Custom reserved-operation budgets
at the batch cap can require another chunk; the ordinary verifier cost probe
measures those boundaries.

## Fork registration arbitrates with destination writers

**Always:** registration atomically requires the destination repository record
and fork barrier to be absent and installs both. Ordinary coordinator mutations
and lease grants guard barrier absence in their existing atomic batches. A usable
ref-shard lease implies an already registered repository: the coordinator commits
that record with the lease grant before the shard can install the lease. Since
repository registration is never deleted, a previously granted lease makes fork
registration refuse. Completion removes the barrier atomically with `Done`;
a failed registered destination retains it permanently.

**Because:** a preflight check alone cannot stop a writer that already captured
its snapshot, and delaying registration alone permits implicit creation.

**If violated:** a concurrent writer could change the destination during
construction or an unfinished fork could accept unrelated writes.

**Enforced by:** coordinator creation and lease-grant guards, the direct upload
planner, and the lease/registration and upload/claim race tests. The extra keys
join existing batch reads; ordinary writes add no storage round trip.

## A fork without denial builds no cleared set and carries its plan

**Always:** a fork on a deployment without pack-level takedown denial skips the
closure walk and builds no cleared set and no base-pack set, and still collects
the manifest set the holder copy needs. A destination flagged by such a fork has
no sets to load: if denial is enabled later, the first publication walk visits
every object and its advance-time proof covers every pack it reaches. A plan
computed before admission is carried into the job only when it fits one slice
and the source still publishes the same packmap head and membership generation;
otherwise the job plans for itself. Source pack proofs run after preparation
and before acceptance. Activation repeats destination denial proofs around each
membership write, and the packmap head's rows are written after every other
member's. Every advancing coordinator commit guards the recorded authority facts;
pre-acceptance progress also guards the exact pending reservation.

**Because:** nothing reads a cleared set without denial, and the set's walk cost
repeats inside a request; the plan's result is a function of the pair it read,
and the pair is read again before it is used.

**If violated:** a later switch to denial could skip an object the source never
proved, an admitted charge could differ from the pack set forked, or a reader
could see the head's flag without the packs it promises.

The supported pipeline and timer construction paths derive denial mode and
extraction settings from the same `PipelineConfig` through
`ForkEnv::from_config` and `ForkTimer::from_config`. Low-level public fields
remain caller-controlled; drain fork jobs before switching denial mode.

**Enforced by:** the fork engine tests for the denial-on full walk, the carried
pair check, the plan fallback, the publication stage order and the round probe.

## Published clearance does not settle acceptance

**Always:** `decide_clearance` recomputes the largest contiguous cleared or
resolved prefix and withholds a later value while an earlier advance is pending,
held, or hit. Own additions never satisfy an external supplier. A deletion moves
the boundary immediately and does not resurrect a component the deletion advance
does not carry. The decision has no reservation settlement and no terminal
acceptance result. `decide_accept_and_clear` returns the ticketed-advance
decision untouched and a clearance only when it applies, so the combined unit
equals acceptance then clearance. The reference profile declares lifecycle transitions
not offered and applies denial before this decision.

**Because:** clearance may run in the acceptance unit or later. Repeating
settlement would charge or consume the accepted operation twice.

**If violated:** a reader could see a ref past a blocked advance, an external
base could be treated as published because this advance added it, or recovery
could create a second outcome.

**Enforced by:** `mkit-primitives` clearance tests and the reference publication
prefix and deletion tests.

## Fork publication absorbs only exact witness replays

**Always:** after a publication absent guard fails, the driver reads both rows
again and accepts only the exact pair of witness bytes it intended to write.
Any foreign value refuses the fork; partial or missing identical rows remain
retryable. The accepted binding, live destination proofs, and local write guards
stay in place.

**Because:** request and timer drivers can publish the same unit concurrently.

**If violated:** an ordinary race could fail a request, or a foreign membership
could be accepted as this job's publication.

**Enforced by:** the publication guard-loss regressions for two drivers, foreign
rows, and partial witnesses. See the [retryable error table](operations/fork-waves.md#retryable-fork-errors).

## Fork waves retain checkpoint and failure order

**Always:** fork emptiness and statistics waves contain at most six operations;
holder waves contain at most four IDs. Repeated holder IDs run in
separate waves. Replies are drained and consumed in input order. Successful
units retain their storage call counts and existing slice limits. Reads reserve
credit before dispatch; variable holder retries charge each actual call.
Wave widths account conservatively for repeated debits across inherited
reservation layers, including shared ledger ancestors. Without denial, plan and
publication units of up to six distinct packs also overlap, with the same
widths, drains and input-order failure; the packmap head is written alone and
last. Write proofs overlap
directory reads only when known headroom covers all sixteen first pages;
otherwise they remain serial. Later sibling refusals must not reclassify an
earlier I/O error as a spent fork slice.

**Because:** completion order must not select a different refusal, and parallel
writes to the same object state would introduce avoidable CAS retries.

**If violated:** fork error precedence changes, slice accounting grows, or a
failed unit publishes partial progress.

**Enforced by:** the fork wave regressions and existing crash, resume, lifecycle,
and denial-gate tests. See [bounds and latency model](operations/fork-waves.md).

## Primitive fork acceptance separates terminal settlement from visibility

**Always:** `mkit-primitives::fork::decide_fork_acceptance` emits acceptance only
for a complete bounded full-inventory plan, an exactly bound protected
reservation and admission debit when granted/applicable, authoritative absence
otherwise, phantom-safe destination emptiness, and a final
source proof ordered after the last staged membership effect and before the
current acceptance attempt. Every relied-on destination fact and revision is
returned for one atomic comparison. Acceptance records terminal response,
replay, and outcome responsibility and settles the optional exact reservation
together.
It emits no visible membership, destination ref, or permission to write.

**Because:** construction, terminal acceptance, and published clearance have
different responsibilities. A sampled absence cannot exclude phantom additions;
a per-pack proof before the last staged effect cannot fence the full source.
A lost response or a later source move must not repeat a charge or outcome.

**If violated:** an unaccepted fork could become readable, an unauthorized or
changed plan could be accepted, or retries could settle another reservation.

**Enforced by:** the primitive's semantic fixtures, all-observation mutation
checks, phantom-addition and transitive-supplier tests, bounded hostile-fact
replay, and once-only terminal replay tests. This primitive is not yet adopted
by the reference server; its existing conformance gaps remain declared until
the activation integration passes the independent conformance suite.

## Portable auth checks preserve the core grammar and terminal replay rules

**Always:** auth-v2 envelope validation delegates raw canonical fields,
commitments, destination, time, and strict signatures to the core verifier.
Header inspection treats any declared signature trigger as envelope presence
and refuses partial or repeated fields. Repository addressing and an idempotency
key alone do not indicate a signature. A recorded rejection must use the permanent-code allowlist;
challenges and transient refusals cannot enter through that constructor.

**Because:** portable servers need one grammar, deterministic header treatment,
and final-result eligibility independent of token or storage representation.

**If violated:** implementations could disagree on signed bytes, interpret
ambiguous metadata differently, or retain a retryable refusal as permanent.

**Enforced by:** primitives raw-input parity, header and classifier matrices,
code fixtures, and stable seeded claims replay. Host adapters must inspect raw
multiplicities before collapsing headers, authenticate before replay lookup,
and keep signed reads outside their ledger. The reference adapter applies
these checks before repository routing in AuthV2 mode, preserves raw header
presence through verification, and retains the other authentication modes.
All write methods that emit unsigned client timestamps already require a full
envelope in AuthV2 mode; the visibility-statement exception emits no timestamps.

## Acceptance evidence does not confer acceptance authority

**Always:** portable evidence is bounded by explicit byte and record caps, binds
the exact frozen pack and operation, and carries only head and dependency facts.
Decoding never constructs verified packs, closure proofs, or guarded decisions.

**Because:** verifier and writer processes may share a trust domain while holding
different immutable pack records and live membership or denial observations.

**If violated:** substituted or replayed evidence could bypass acceptance guards,
or object-count-sized payloads could exhaust writer memory.

**Enforced by:** `AcceptanceEvidence::decode`, `check_binding`, `recheck_heads`,
and acceptance-evidence codec, binding, and signature regression tests. The host
authenticates origin and atomically checks live guards; the library does not.

## Authority moves drain fork membership permits

**Always:** an acknowledged authority or grant-epoch move leaves no old-generation
permit capable of installing membership. A drain freezes issuance, replaces
local tokens with tombstones, and publishes the fence only after its durable
registry is empty. A co-located install guards the recorded fence directly.

**Because:** a coordinator checkpoint cannot retract a membership effect that
already committed in another partition.

**If violated:** a delayed activation could install membership after revocation
completed, despite a later coordinator CAS failure.

**Enforced by:** local atomic permit guards, resumable transition drains,
recovery holdoffs, and the physical activation race regression.

## Fork clearance preserves the terminal acceptance

**Always:** with authority fencing, every advancing fork commit compares its
recorded authority facts. Before acceptance it also compares exact reservation
protection. After acceptance,
progress and membership activation retain the exact saved result and complete
inherited inventory; construction expiry and pruned settlement evidence do not
create a new terminal outcome. Destination writes remain blocked until complete
clearance. Later source movement cannot rewrite the accepted source pair.

**Because:** clearance may resume after the response, reservation acknowledgement,
or a crash. An advancing checkpoint cannot manufacture authorization or repeat
an accepted charge.

**If violated:** defer clearance without replacing the saved result. Refuse
foreign membership witnesses and retain a failed destination's inert state.

**Enforced by:** the pure fork progress, activation, and completion decisions,
full-snapshot mutation and hostile-fact tests, and reference fork driver lowering.
The host retains current destination proof acquisition, exact storage CAS, and
physical authority-permission enforcement.

## Portable ref decisions retain exact dependencies

**Always:** lowering preserves every exact dependency in a sealed ref decision,
including facts used only for a refusal. Plain ref writes that rely on separate
pack acceptance attach sealed bases and a complete host-supplied pack list before
lowering. Each relied-on pack has exact identity-and-length coverage; all basis
guards join the decision's checked, deduplicated requirements. Attachment keeps
effects and source fences unchanged and fails closed on repository mismatch or
contradictory expectations. Any accepted composed effects compare
those dependencies atomically. A separate source fence is repeated before each
apply attempt. Guard loss reacquires facts under the original binding.

**Because:** a guard category alone cannot distinguish two ref keys, and an
unconditional write can depend on presence through admission or policy.

**If violated:** fail lowering or retry decision without storing a terminal
answer. Never accept a partial guard projection.

**Enforcement:** portable decision mutation and omission tests cover exact
keys and categories. The server checks ref and publication projections before
committing its physical batch. Host policy acquisition and other effect groups
retain their existing boundaries; these checks do not assert that every host
policy path has moved into the portable module.

## Acceptance export binds sealed artifacts before carrying their facts

**Always:** in-process evidence export compares object-set roots, ruleset/profile
bindings, and repository identity. It verifies canonical signed heads and the
closure's original requested head sequence before sorting envelope records. It
authenticates every relied-on witness page and requires exact count and chain
termination before emitting bounded distinct supplier IDs.

**Because:** privately constructed artifacts from different operations or a partial
witness chain cannot jointly establish the facts carried to an acceptance writer.

**If violated:** substituted heads, truncated dependencies, or unrelated proofs
could be reported as facts from one verified operation.

**Enforcement status:** bounded export helper regressions, frozen closure-root
vectors, and a sealed-artifact export test cover head checks, witness-chain
authentication, budgets, binding, and real `VerifiedPack`/`ClosureProof` input.
Decision parity awaits the acceptance-decision lanes. No live guard or remote
authentication responsibility moves into this constructor.

## Scheduled entry refusals follow complete source integrity

**Always:** a scheduled early delta-base or indexed decode-limit refusal waits
for whole-source integrity. A corrupt trailer selects the same persisted hash
rejection as inline verification. Valid integrity triggers a fresh entry attempt;
missing membership remains subject to its original lag window and never becomes
a persisted content rejection. Successful decode performs no recheck reads.

**Because:** SPEC-PACKFILE §§6.1 and 6.2 require integrity-first refusal order
across verification strategies. An unavailable base cannot authenticate a trailer.

**If violated:** the same corrupt pack can produce different public refusals,
or a transient repository fact can permanently poison a valid pack.

**Enforced by:** the failure-only `indexed::job::integrity` frontier, the guarded
optional job progress, competing-fault tests across inline, scheduled, and
`VerifyDriver`, and the unchanged success-path read and verification round probes.
Only the original completed decode can proceed to index publication.


## Atomic force publication retains its planning dependencies

**Always:** every force write on an atomic-capable source compares its packmap
in the same atomic advance as the head, including empty and idempotent plans.
A dependent plan also compares the observed head. A changed chain must extend
the captured immutable node before its uploaded packs can be reused; otherwise
the push re-plans. Publication and re-planning share eight attempts per step.
Failed or invalid discovery must refuse force publication before uploading;
it cannot establish that concurrent clients cannot reset the chain.

**Because:** an unconditional head write or an append onto an unrelated reset
can lose the objects and delta bases the plan omitted. Separately read refs can
also straddle a reset back to the same content-addressed packmap value.

**If violated:** a successful force push could publish a head whose closure the
advertised chain cannot reconstruct. Retry exhaustion must leave the competing
writer's valid pair intact and return `PushError::PackmapContended`.

**Enforced by:** `mkit-sync::push::force`, both Connect backend race and retry
regressions in `mkit-sync/tests/push.rs`, HTTP atomic guard encoding tests, and
`formal/quint/advance`. Non-atomic transports retain their existing behavior;
the atomic-capable source must never lower these writes to an ordered fallback.
