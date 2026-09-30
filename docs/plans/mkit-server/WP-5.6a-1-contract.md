# WP-5.6a-1 pending intent and denial contract (R-190)

**Status: PR1 implementation verified, activation off.** HTTP shared-chunk denial,
namespace-wide purge and packlist checkpoint recovery regressions pass. Workspace
and wasm32 clippy, scripts, docs/proto/goldens, CLI reverse dependencies, default
Worker conformance and two independent source reviews pass. The final whole-server
run completed all 2,550 tests: 2,549 passed; the existing native S3 synthetic-timer
fixture failed intermittently and passes alone and on unchanged parent `8bc30385`.
The security gate reports yanked `yoke-derive 0.8.3` in the unchanged interop
lockfile, reproduced on the byte-identical parent. These exceptions follow the
executor-common parent-failure procedure and remain recorded in the PR.
The [brief](briefs/WP-5.6a-1.md) remains the required contract; this layout is not
launch-readiness evidence. Production Rust additions are at most 2,794, including
eight review-added relay lines beyond the original 2,786 against base
`8bc30385`, below the 2,800 cap; tests/docs/proto/generated code are excluded.

Review fixed late-holder delivery's missing V2 observation: the guarded relay
snapshot now includes V1 and V2 denial and retains the real ct/timer-13 handoff.
The nine-key snapshot caps raw corrupt values at 4.5 MiB; backend calls are unchanged,
and ordinary batch validation/shrinking retains the 100-operation apply limit.
The V2 regression failed before the fix; the shared V1/V2 fixture passes afterward.

The staged core implements denial and audited intent; production takedown activation
awaits WP-5.6a-2 preservation and launch gates. Acceptance returns the existing
`{takedownId, complete:false}` response; preservation remains durably pending.

All metadata uses existing `b` subkeys. Exact current-producer V1 keys remain
`b 00 object:32`; no old-build migration, replacement tag or V1 removal occurs.

| Partition | Subkey after `b 00` | Contract |
|---|---|---|
| ContentShard(object) | `object:32 00 actions` | Strict V2 independent action set; content sequence guards activation. |
| ContentShard(owner) | `owner:32 00 chunks 00 page-action:32 page:u32BE` | Immutable hash-bound pages, sorted/unique within each page; descriptors pin `page_owner` and `page_action`. |
| ContentShard(object) | `ff denial-action-descriptors-v2-index 00 object:32` | Authoritative action descriptors; scan without reading every chunk page. |
| ContentShard(object) | `object:32 00 intent 00 request:32` | Immutable prepared descriptor, hash-bound by accepted request. |
| ContentShard(pack) | `pack:32 00 inventory 00 object:32` | Strict V1 immutable typed entry, delta base and reference-page descriptors. |
| ContentShard(pack) | `pack:32 00 inventory-parent 00 object:32` | Immutable manifest/tree descriptors; parent traversal checks its separate count/digest. |
| ContentShard(pack) | `pack:32 00 inventory-seal 00 object:32` | Exact 32-byte BLAKE3(object id plus typed entry bytes), committed with entry/header; batched presence uses these markers. |
| ContentShard(pack) | `pack:32 00 inventory-head` | Strict V1 length, entry and parent counts/XOR digests, complete seal. |
| Root | `ff intent-draft 00 request:32` / `ff request 00 request:32` | Strict V1 draft timestamp and accepted digest/action references, activation cursor and `preservation_pending:true`. |

Verified inventory precedes verified membership; proof streams metadata rather
than source packs. `sorted_pages:true` requires disjoint ordered page bounds;
page-local canonical inventory uses `false`, permits overlapping bounds and
counts page-unique chunks. Duplicates across pages retain denial-set semantics.
Whole-pack actions bind `pack_scope`/`pack_digest` to sealed inventory: file IDs
deny globally; chunk-only blobs retain the manifest's repository-specific stop.
Unknown/corrupt metadata and spent budgets fail closed. Timer 15 TAKEDOWN_WORK
retains responsibility for PR2 acquisition/discovery/retention; timer 11 handles
manual purge. Retention deletion must own each action's preserved copy.
The Worker invocation shares a 9,000-operation backend counter across DO/R2/cache,
snapshot guards and lazy phases; proof and intent counters nest within it.
Intent preparation/activation each cap at 4,000. The remaining 1,000 covers up to
two hooks and 64 immediate cache deletions; the admin exhaustion case measured
9,021 total storage calls including failure audit. Alarms independently cap 1,000.
Inventory scans eight rows (at most 4 MiB raw); worst-case JSON String capacity
is asserted below 12 MiB (11,188,096 bytes). Nested raw/decoded pages, 4 MiB proof
context, 4 MiB header scratch and a 1 MiB staging page derive a phase bound below
48 MiB. Million-chunk tests measure staging buffers at most 1 MiB and descriptors
below 32 KiB. Native publication's denial-only decode cap is 8 MiB. These component
bounds do not claim measured whole-Worker RSS or complete extraction-phase memory.
Global action/inventory traversal can exhaust the 9,000-operation budget and
return `unavailable` even for an unrelated read. The million-chunk regression
establishes page/allocation bounds, not outage-free handling of arbitrary
whole-pack geometry or deployment-wide action populations.

Future 5.5c hit intake must bind durable source identity/correlation to requests;
it is not implemented here. Base `8bc30385` includes merged 4.10b-1, so PR2 MUST
consume its actual `ct`/timer-13 handoff: Ready is availability, never completion;
transfer/acknowledgment requires durable owning workflow responsibility under the
brief's contract. This consumer is required PR2 scope, not an unmerged carry-forward.
