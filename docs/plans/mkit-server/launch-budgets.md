# Paid launch budget audit (WP-4.18 / R-194)

Phase 1 records the current merged contracts and remaining integrated evidence.
It does not establish deployed CPU, memory, cost, or multicolocation behavior.
Phase 2 must pin this audit and runtime measurements to its immutable feature SHA.
The launch excludes async inspection, inspection holds, hold review operations,
publication Events, storage leases, GC, and Worker proofs. Native proofs remain
in the native request matrix. Permanent retention is the launch storage policy.

## Accounting boundaries

An incoming Worker request creates one 9,000-call `indexed::budget::SliceBudget`
and retains it through routed metadata, R2, content response lifetime, and
published-view cache/snapshot clients (`worker/src/adapter.rs`, `ns_client.rs`,
`r2.rs`, `published_view/runtime.rs`). `DoNamespaceStore::call` charges before
transport dispatch. `EnvBucket::bucket` charges each R2 operation; multipart
part dispatch uses the same retained allowance. A ranged pack read makes both
HEAD and GET requests, and both are charged. Hook channels currently use a
separate reserved allowance: the adapter reserves 1,000 calls for hooks and
response settlement. A hook exchange performs one Fetch or binding operation,
with no internal retry. The HTTPS channel covers headers and body with one
bounded timeout, manual redirects, and abort on cancellation. Phase 2 must
measure actual dispatcher totals, including hooks and settlement, rather than
reporting only the backend counter.

A Paid physical Durable Object alarm currently shares one 1,000-operation
`purge::SliceBudget` between every logical partition head. The alarm resets it
once at entry, never per head (`worker/src/ns_object.rs::alarm`). Local physical
DO SQLite reads, scans, and applies are not outgoing operations; routed DO
requests, R2 requests, cache operations, and remote hooks are outgoing work.
`SharedStore` charges before routed relay, rollup, and publication dependency
operations. Other handlers reserve their conservative external-call allowance
before firing. Rejected reservations retain the timer with Retry; purge work
retains its existing durable checkpoint. This is shared enforcement, but it
currently consumes the entire project alarm allowance without an explicit
headroom reserve and has progress risks described below.

## Current fixed units

| Work | Current bound/accounting | Phase 2 evidence required |
| --- | --- | --- |
| Verification kind 7 | 256 calls per slice, 48 MiB resident allowance, two 16 MiB windows; whole-alarm reservation 256 | Actual release extraction driver, repeated sources/dedup, all upload callbacks, crash/cursor retry, resident peak |
| Relay kind 3 | Paid up to 8 fires, 32 targets/fire, 2 target calls/target; up to 512; target retries and hook-before-apply reads use shared client | All due kinds together, interrupted replies, holder/audit before-apply reads, shared whole alarm maximum |
| Outcome kind 8 | Paid up to 4 fires of 16 rows, at most 64 sink calls reserved | Retained backlog/retry, frozen clock, no false acknowledgement on exhaustion |
| Quota rollup kind 5 | Paid 4 fires, 8 calls/fire; shared routed client also charges | CAS races/target exhaustion retain work; no full independent allowance per head |
| Ticket expiry kind 2 | 8 fires per partition tick; reserve 3 external calls/fire for multipart cleanup | Expiry and resumable verification cleanup together; backend abort call count |
| Reservation reconcile kind 9 | Local store work only | Pending response completion races and durable terminal arbiter |
| Snapshot kind 10 | One snapshot claim per physical alarm; reserve 3 external calls (coordinator read, R2 get, R2 put; removal uses fewer) | Sixteen heads, private/ineligible snapshot deletion, response/backup overlap |
| Backup kind 4 | Reserve 1 R2 put; snapshot alarm coordinator also limits overlap | All relevant head combinations and cold backup size |
| Publication dependency recheck kind 12 | One fire per logical partition tick; every routed witness page shares alarm counter | Must resolve starvation finding below before activation |
| Cache purge kind 14 | Enumeration, cache deletion, and signed sink delivery share allowance and existing checkpoints | Namespace catalog cold slices, repeated cursors, hooks failure, exact audit/preservation boundaries |
| Sync inspection request | Up to 4 inspectors; sequential calls; verification 300, ancestry 256, pair/enumeration/dependencies 256, hooks 4, other stages 144 = 960 declared units | Entire request including retries, physical transports, cancellation, R-193 retrieval |
| Atomic write | 100 preconditions+writes maximum; seven tickets; current D34 retained-publication batch 94 operations, ordinary publication 93 | Snapshot target-local additions reserve 3, pruning remains within cap, takedown/inspection guards together |

`mkit-server/src/indexed/job.rs::SliceLimits` defines the 256-call/48 MiB
verification limits. `store/outbox.rs` fixes seven tickets and the 94-operation
ledger. `pipeline/tests.rs` verifies real Single/D34 batches rather than a
constant-only model. The 960-unit inspection ledger is documented in
`pipeline/inspection.rs`, but a declared stage allocation alone cannot replace
whole physical dispatcher and retry measurements.

Ticket proof HEADs previously ran all seven ticket futures through `join_all`,
so seven outgoing responses could be active. `pipeline/advance.rs` now admits
at most six ticket proof futures; each marker HEAD completes before that
pack's HEAD begins. Its pending-response regression checks first-poll occupancy,
peak occupancy, every ticket result, and marker-before-pack ordering. The
unchanged implicit membership path uses a 16-future chunk limit in
`pipeline/implicit.rs`; it requires a six-slot bound before claiming the whole
writer/reuse matrix satisfies the outgoing limit. Sync inspectors and alarm
handlers are sequential, but phase 2 must also count R2 response body lifetimes
and spawned completion/settlement work.

## Unresolved deterministic findings

1. **Publication recheck can exhaust forever.** `indexed/publication.rs::verify_inner`
   reads a packmap node, inserts every `node.packs` into the dependency set,
   then inserts closure packs and external bases. Each dependency list accepts
   up to 4,096 items. D34 membership routing has 4,096 distinct prefixes
   (`pipeline/shard/d34.rs::membership`). `timers/publication_recheck.rs::dependencies`
   groups by shard and reads pages of eight keys. Thousands of distinct
   prefixes therefore require thousands of routed reads; worst-case two
   disjoint 4,096-item lists need 4,608 pages (3,584 groups of one plus 512
   groups containing nine items), exceeding the 1,000-call physical alarm cap.
   The existing comment's 8,192 is a safe looser bound.

   The dependency scan returns false at the first missing witness. Thus a
   large list can pass the initial request's bounded work because an early
   projected membership is missing; the request records Pending. Later,
   available projections can require more than an alarm's allowance, and the
   timer restarts from the beginning after every failure. Sync-only inspection
   does not remove this path: `store/publication.rs::append` schedules kind 12
   for every nonpublishable advance, including delayed cross-ref projections.
   With other due kinds, even a dependency set below 1,000 calls can starve.
   No current configuration limits packmap dependency count:
   `max_ancestry_commits` bounds ancestry checks; `decode_budget` and pack size
   limit bytes, not shard fanout. One small packmap node can name thousands of
   packs. A solution must bound accepted launch dependency work before commit
   and give it a usable shared alarm allocation, or use an already authorized
   owning contract for resumable progress. A new durable cursor/state is outside
   this work package. Activation cannot claim deterministic progress yet.

2. **Cold logical-head work has no physical alarm scan bound.**
   `sql/kv.rs::timer_heads` materializes every logical partition head without
   paging or a limit. `worker/src/ns_object.rs::alarm` calls a fresh default
   `TickBudget` for each head. That budget limits each logical tick to 512
   examined rows, 128 commits, 32 attempts/kind and 10,000 injected-clock ms,
   but a frozen clock and many logical heads do not bound the physical alarm's
   aggregate local rows or resident head vector. The shared outgoing allowance
   prevents excess external calls, but does not establish bounded cold local
   scans or fairness. Physical head enumeration and aggregate tick work need
   explicit bounded measurement/enforcement before final activation evidence.

3. **Release extraction/retrieval/preservation accounting awaits dependencies.**
   Kind 7 still uses `FailClosedExtraction` in the current release handler.
   `R2Extraction` reserves 8 begin, 3 part, 7 completion and 2 abort calls from
   the same per-slice counter, but its real release driver is phase 2 work.
   R-193 scanner retrieval and 5.6a-2 preservation are unavailable. Their
   requests and R2/body lifetimes must be added to the same dispatcher ledger
   after merge; no phase 1 PASS slot is implied.

## Required retained regressions and integrated runs

Run existing shared DO/R2 request-budget, inventory resident transport,
sixteen-head shared alarm/purge, real maximal seven-ticket batches, frozen-clock
relay/outcome/rollup, and the new pending ticket HEAD regression. Phase 2 adds
actual release wrangler runs with all opted-in features, multiple due kinds,
maximal dependency fanout, CAS retries, lost replies, stopped response bodies,
retained purge cursors, R-193 scanner scope, preservation and signed purge.
Pin commands/logs and measured outgoing peak, whole alarm calls, local examined
rows and resident work to exact SHAs in the launch evidence matrix. External
staging and platform measurements remain user-owned unrun evidence slots.
