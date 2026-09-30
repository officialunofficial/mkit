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

A Paid launch physical Durable Object alarm shares one 960-operation
`purge::SliceBudget` between every logical partition head, reserving 40 of the
unchanged 1,000-operation project envelope for dispatch and settlement.
Other Paid configurations retain the existing 1,000-operation allowance. The alarm resets it
once at entry, never per head (`worker/src/ns_object.rs::alarm`). Local physical
DO SQLite reads, scans, and applies are not outgoing operations; routed DO
requests, R2 requests, cache operations, and remote hooks are outgoing work.
`SharedStore` charges before routed relay, rollup, and publication dependency
operations. Other handlers reserve their conservative external-call allowance
before firing. Rejected reservations retain the timer with Retry; purge work
retains its existing durable checkpoint. Headroom does not replace measured
whole-dispatch evidence or resolve the progress risks described below.

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
| Cache purge kind 11 | Enumeration, cache deletion, and signed sink delivery share allowance and existing checkpoints | Namespace catalog cold slices, repeated cursors, hooks failure, exact audit/preservation boundaries |
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
peak occupancy, every ticket result, and marker-before-pack ordering. The implicit membership path also uses six-future chunks in
`pipeline/implicit.rs`; its regression drives the production packmap check
with seventeen pending membership responses and measures occupancy and completion. Sync inspectors and alarm
handlers are sequential, but phase 2 must also count R2 response body lifetimes
and spawned completion/settlement work.

## Deterministic findings and separate repairs

The two budget findings were assigned to separate repairs. Their component
checks do not certify the integrated launch matrix.

1. **Publication recheck progress: merged repair #1245.** Before the repair,
   valid D34 packmaps could require more than the 1,000-call physical alarm
   allowance, while every retry restarted at the first dependency. Each
   dependency list can contain 4,096 items; adversarial routing can require
   4,608 witness pages across two disjoint lists. The valid packmap limits and
   shared allowance are unchanged. [PR #1245](https://github.com/officialunofficial/mkit/pull/1245)
   merged at `d89c37fb968d39c180228678bc09c77a12002fc9`. Timer 12 now persists a
   guarded witness position in its existing value, checks at most 128 routed
   reads per fire, and invalidates progress when the guarded obligation,
   dependency or generation changes. Phase 2 must verify progress with the
   complete launch handler mix and pin actual release runtime evidence.

2. **Physical alarm scan and cold fairness: open repair #1247.** The audited
   base still materializes all logical heads with `timer_heads` and refreshes
   `TickBudget` per head. The user's ruling uses a bounded indexed raw window,
   a volatile rotating cursor, and persisted backoff in each retained timer
   row; no durable cursor. [PR #1247](https://github.com/officialunofficial/mkit/pull/1247)
   implements that ruling at `f07195914af704aa255f7430b5d93427f4d0c619` against
   base `cd680351bb499538c287b2197fcabd89c7783a95`. Windows contain at most 64 raw
   rows; one physical alarm shares 512 examined rows, 128 committed batches,
   32 attempts per kind and 10,000 injected-clock milliseconds. Failed and
   unknown kinds retain their payloads and original handler due times while
   a guarded move advances their physical due time, starting at five seconds
   and doubling to a ten-minute cap. Cold restarts therefore do not restore
   the same failing prefix. Component gates passed: 242 targeted module tests,
   18 native timer integration tests, native/wasm32 clippy and fmt, with two
   independent reviews. It is open and unmerged; merge it before phase 2 and
   measure the full handler mix on the integrated release Worker. Neither
   component success nor an open PR fills the launch evidence slots.

3. **Release extraction/retrieval/preservation accounting awaits dependencies.**
   WP-4.10b-2 (#1244) now supplies the real environment handler's
   `R2Extraction` driver (`worker/src/verify.rs::register_from_env_budgeted`).
   It reserves 8 begin, 3 part, 7 completion and 2 abort calls from the same
   256-call slice counter. The extraction state machine charges namespace
   and source reads against that counter; its 48 MiB resident limit stays
   unchanged. R-193 (#1243) now supplies scanner retrieval, whose global
   proof reads 4,096 descriptor shards and has one 8,500-call core
   allowance for denial/tickets/blob operations, nested under the Worker's
   9,000-call physical backend allowance. Each returned range is at most
   1 MiB; the ticket assignment is rechecked after reading bytes. Its first-page prefetch
   was eight simultaneous metadata calls (`takedown/denial.rs`); WP-4.18
   reduces this to six and retains measured cancellation/late-block/budget
   regressions. Nested descriptor proofs are serial while other prefetched
   responses remain pending. Release retrieval config and mount still require
   WP-4.18's profile activation. 5.6a-2 preservation remains unavailable.
   Full R2/body-lifetime dispatcher evidence remains phase 2 work.

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
