# WP-5.6a-1 pending intent and denial contract (R-190)

**Status: INCOMPLETE checkpoint.** HTTP helper/shared denial-budget wiring and
namespace-wide manual purge remain unfinished. Full gates, actual Worker
conformance and final independent reviews remain outstanding. The
[brief](briefs/WP-5.6a-1.md) remains the required contract; this layout is not
launch-readiness or complete every-surface enforcement evidence.

The staged core implements denial and audited intent; production takedown activation
awaits WP-5.6a-2 preservation and launch gates. Acceptance returns the existing
`{takedownId, complete:false}` response; preservation remains durably pending.

All metadata uses existing `b` subkeys. Exact current-producer V1 keys remain
`b 00 object:32`; no old-build migration, replacement tag or V1 removal occurs.

| Partition | Subkey after `b 00` | Contract |
|---|---|---|
| ContentShard(object) | `object:32 00 actions` | Strict V2 independent action set; content sequence guards activation. |
| ContentShard(owner) | `owner:32 00 chunks 00 page-action:32 page:u32BE` | Immutable verified pages; descriptors pin `page_owner` and `page_action`. |
| ContentShard(object) | `ff denial-action-descriptors-v2-index 00 object:32` | Authoritative action descriptors; scan without reading every chunk page. |
| ContentShard(object) | `object:32 00 intent 00 request:32` | Immutable prepared descriptor, hash-bound by accepted request. |
| ContentShard(pack) | `pack:32 00 inventory 00 object:32` | Strict V1 immutable typed entry, delta base and reference-page descriptors. |
| ContentShard(pack) | `pack:32 00 inventory-parent 00 object:32` | Immutable manifest/tree descriptors; current proofs validate full inventory. |
| ContentShard(pack) | `pack:32 00 inventory-head` | V1 length, unique count, XOR of BLAKE3(id plus entry bytes), complete seal. |
| Root | `ff intent-draft 00 request:32` / `ff request 00 request:32` | Strict V1 draft timestamp and accepted digest/action references, activation cursor and `preservation_pending:true`. |

Verified inventory precedes verified membership; proof streams bounded metadata
pages rather than buffering source packs. Action pages bind their source owner.
Unknown/corrupt metadata and spent budgets fail closed. Timer 15 TAKEDOWN_WORK
retains responsibility for PR2 acquisition/discovery/retention; timer 11 handles
manual purge. Retention deletion must own each action's preserved copy.
Request proof shares a 9,000-call counter; intent preparation/activation each cap
at 4,000 within that counter. Inventory scans request at most 32 rows (16 MiB of
raw values at the store maximum); total resident usage needs measured evidence.
The shared alarm cap is 1,000 operations, separate from Paid request limits.

Future 5.5c hit intake must bind durable source identity/correlation to requests;
it is not implemented here. The 4.10b-1 `ct`/timer-13 consumer remains a carry-forward
until merged: Ready is availability, never completion, and transfer/acknowledgment
requires durable owning workflow responsibility under the brief's handoff contract.

## Cap checkpoint

The approved 2,500 non-test-line cap is exceeded before PR1 completion. This is a
local committed checkpoint, without a push or PR. No required scope is deferred.
Focused intent, denial, admin purge and timer tests: 15 passed; formatting and
`just ci-security` passed. Retained regressions fail for HTTP serving a manifest
that shares a blocked chunk, and Worker namespace purge failing to complete.
HTTP helper wiring, bounded namespace enumeration, whole-request operation
accounting and measured resident-memory bounds remain required. Full local gates,
wasm32 clippy, actual Worker default conformance and final reviews remain unrun.
Both approved PRs remain required for launch; production activation stays off.
