# WP-4.8 takeover audit

Finished from the interrupted executor's worktree at `3fda91f5`, on
`mkit-server/wp-4-8-worker-async-verify`. A fresh fetch and merge of
`origin/feat/mkit-server` found WP-4.12 and WP-4.17 already present. Both
inherited base merges remain in the branch. The final base merge includes
WP-1.21/WP-1.19 (#1225), WP-1.27 (#1227) and WP-4.13/WP-4.15 (#1226),
retaining the adjacent invariant additions, all conformance cases and both
wrangler script phases. R-171 stays in numeric order within the table. The contract is [the brief](briefs/WP-4.8.md).

## Brief coverage

| Item | Implementation and evidence |
| --- | --- |
| B1 / D-1 | `pipeline::renew_for_relay` reuses the advance's coordinator read and `grant_batch`, then guards installation of `el`. No change to `ls` or `acked_epoch` semantics. Lease-renewal and lost-lease job tests. |
| B1 / D-2, D-3 | `vc` job, frame, owed-child and charged-base rows; kind-7 slice machine; local consumed-set closure checks. Job crash, closure, satisfying-pack and late-member tests. |
| B1 / D-4 | Additive core `last_frame` and `decode_entry_with`, golden metadata differential, frame-table differential with duplicates and depth. |
| B1 / D-5 | Paid only, 256 calls per kind-7 fire, one fire per alarm. Free registry and configuration refusal tests. |
| B1 / D-6 | Durable cumulative in-pack and distinct external-base accounting, separate Worker resident allocation allowance. Budget tests vary windows and entry caps. |
| B1 / D-7 | One-detail pending response; no replay row; same-nonce retry. Informative SPEC-SERVER §9.5 note. |
| B1 / D-8 | Authoritative advance enqueue. Completion enqueue omitted under the brief's first size cut; optional carry-forward. |
| B1 / D-9 | `SliceExtension` and fail-closed extraction phase. 64 KiB Blob cannot become Verified. |
| B2 | Checkpointed phases, etag binding, guarded job/state updates, index emission after `Done`, delivery before Verified. Terminal membership/platform outcomes stay outside Rejected. |
| B3 | Programmatic Inline/Scheduled mode; Scheduled advance never decodes the ticket inline. Missing or replacement job answers pending. |
| B4 | Release `INDEXED_MODE` refusal names WP-4.10b. Test builds require Paid + Multi + D34 + ticket keys. Default-feature Worker tests cover the release path, no kind 7 and unindexed server configuration. |
| B5 | Kind 2 guards removal of an unconsumed pack's `vs` and wakes kind 7; kind 7 pages `vc` cleanup and retains a member's `vs`. WP-5.3a must protect satisfying member packs of live jobs. |
| B6 | R-171, CHANGELOG, extraction hand-off and Scheduled ancestry integration. Worker ancestry is clamped to 64; history rows feed stage 5 after verification. |

## Required test coverage (§9 of the fact sheet)

All paths below are relative to `rust/crates/`.

| Required cases | Test location |
| --- | --- |
| Core frame metadata and entry decoding over goldens | `mkit-core/src/pack/window/tests.rs` |
| Frame-table versus `index_entries`, duplicates and in-pack depth | `mkit-server/src/indexed/job_tests.rs`: `the_frame_table_agrees_with_index_entries` |
| Multi-window completion, per-slice call budget | `a_multi_window_pack_verifies_in_bounded_slices` |
| Crash at every batch boundary | `a_crash_at_every_batch_boundary_resumes_to_the_same_result`; satisfying-member crash sweep added during takeover |
| Source etag change, moved prefix, cursor/source binding | Job source-change tests and core cursor-binding tests |
| CPU-kill replay, attempts and terminal outcome | `killed_slices_shrink_the_entry_cap_and_end_in_a_terminal_outcome_not_a_rejection` |
| External base lag, permanent miss, foreign repository isolation | External-base and byte-identical foreign-versus-absent job tests |
| Capped lookup and external depth | `a_capped_base_lookup_is_permanent_at_once`, `external_depth_over_the_cap_is_a_terminal_outcome_not_a_rejection` |
| Cumulative budget independent of slice boundaries | `the_decode_budget_is_the_same_wherever_the_slices_fall` |
| Rejected content failures, signature priority, in-pack depth | Content-failure and in-pack depth job tests; membership tests assert no Rejected |
| Pending detail, no replay and same nonce, missing job | `mkit-server/src/pipeline/tests/scheduled.rs` pending/commit test, plus job advance test |
| Co-consumed closure, lag and final recheck | Scheduled pipeline and job closure tests |
| Satisfying-pack removal, late member, MKPL cap, head type | Job advance tests |
| Advance operation counts | Scheduled Single comparison, existing 89/78 indexed plan tests and Scheduled D34 delivery case |
| Delivery before commit and pending while undelivered | Job delivery/lease test and D34 Scheduled pipeline test |
| Lease renewal and losing the source lease | Job renewal and lease-loss tests |
| Expired/consumed job cleanup | Job cleanup tests, kind-2 expiry tests |
| Extraction stub | `a_pack_needing_extraction_never_reaches_verified_here` |
| Worker etag, budget and Free refusal | `mkit-server-worker/src/verify.rs`, `adapter.rs`, job budget wrapper tests |
| Wrangler multi-window push and mid-pack failure | `indexed.async_verification_commits`, `scripts/vcs-worker-conformance.sh --test-faults --indexed`, port 8921 |
| Release inertness | Default-feature Worker suite, registry and server configuration tests |
| Scheduled fast-forward and u-only grants | Scheduled pipeline child/fork tests; 64-commit staging boundary and Worker clamp tests |
| Staging large-pack run | Human-owned WP-4.18 carry-forward; no deployment or cloud-account mutation performed |

## Gaps found during takeover

1. Closure deleted a satisfying child's row before committing its member-pack
   dependency. The crash sweep failed at apply 6. Deletions now share the
   guarded job checkpoint batch, with a bounded batch size.
2. A commit cap did not bound the calls of index lookups or delta reconstruction.
   Scheduled checks now allow 600 calls and ancestry 256, leaving 144 for other
   advance stages. Budget exhaustion fails closed. The Worker clamps a raised
   programmatic ancestry setting to 64.
3. Cleanup lacked guards against a replacement job and newly installed member.
   Cleanup now guards the observed job, absent ticket and absent membership;
   a short kind-2 verification read fails rather than silently dropping cleanup.
4. The existing ticket mismatch path only kicked the old timer. A fresh ticket
   now replaces the job by CAS, clears its terminal outcome and starts its own
   lag window; a failing regression demonstrated the previous behavior.
5. The resident allowance counted too little scratch memory. The default now
   reserves two windows, the LRU and eight entry-sized regions, giving a 1 MiB
   decoder/member-chain allowance. Member scratch resets each entry, and closure
   rows flush in bounded batches. A 2 MiB entry regression failed before this fix.
6. External accounting keyed only on object id, so equal bytes reached through
   two member locations were charged once. Location keys now bind object, pack
   and frame offset. A real two-member/delta-chain regression pins both entry
   caps 1 and 4096; zero-size object-keyed rows retain external depth.
7. Rebuilding a Verified pack's job could persist Rejected on storage damage.
   Verified now stays monotone; the trailer-damage regression failed before the fix.
8. The release Worker source guard also matched the uppercase ancestry constant
   name as transaction-control text. The adapter clamps directly to 64; the
   unchanged source guard and raised-cap regression both remain required.
9. A source restart retained provisional frame/history/base/child rows. A fake
   source carrying another signed commit was replaced by the valid source; the
   regression failed because the old frame survived successful verification.
   Decode now clears derived rows in guarded 90-row pages while kind is Unknown,
   before reading a fresh source. This also clears rows on ticket replacement.
10. Added the missing Scheduled `u`-only grant integration and the actual 64-commit
   staging boundary, alongside the inherited fast-forward-only child/fork test.

The PR body records final gate results, size accounting, executor decisions,
deviations and carry-forwards. Self-review consists of separate correctness/security
and brief/spec passes; the orchestrator notes prohibit spawning new agents.


## Size and implementation decisions

Production size is 2,800 added Rust source lines, excluding blank/comment lines,
test files and test modules, and the complete conformance test-harness crate.
Removed production lines are not subtracted. The completion enqueue remains the
brief's first size cut; the attempt counter and three-failure shrink remain.
Hash fields in the unshipped job DTO use strict fixed-size JSON byte arrays;
cursor bytes stay hex. No compatibility reader is added.

The one-window work unit means one new window of progress: resuming also reads
the current window, so a slice ordinarily feeds at most two windows. Entries
stop only at a checkpointable boundary. The default scratch allowance is a
stricter deployment limit than the fact sheet's proposed reader budget; it
reserves space for copies, decoding and cache overhead. The post-job advance's
late-member/head lookups are counted within its 600-call budget. The human-owned
staging run and completion enqueue remain the explicitly recorded gaps.

## Review rulings applied

External delta-base source packs, including chain intermediates, now persist in guarded `vc` sub-6 rows and join the advance's batched membership recheck. Base dependency misses retain the delta-base lag/permanent messages. WP-5.3a must protect these dependencies as well as closure-satisfying packs.

ClosureResolve and Recheck persist each examined id boundary. They reserve the full capped lookup allowance before an id, checkpoint successful progress when another lookup cannot fit, and end oversized single-id work with ticket-terminal ClosureCapped. Their durable attempts shrink work to one before terminating repeated interrupted passes. The kind-7 cap remains 256 calls.

The advance conservatively sums all co-consumed decoded totals, including duplicates across packs. This is stricter than Inline deduplication. Scheduled decode/depth error priority may also differ from Inline because it stops before Done. These explicit rulings replace blanket native-priority parity claims; both modes fail closed and membership failures never become Rejected.

Permanent regressions cover removal of an external source member after verification, the hot-closure replay loop, and the combined decode-budget overrun. R-171 also records the shared renewal path's authority-generation/acknowledgement handoff to WP-2.16.
