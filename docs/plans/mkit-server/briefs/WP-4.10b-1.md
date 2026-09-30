# WP-4.10b-1: protection and bounded upload prerequisites (R-186)

## Approved scope

The user approved this split on 2026-09-30 after the full Worker extraction
checkpoint could not finish within its 3,000-production-line cap. Both parts
share R-186; this is not a new protocol allocation. PR1 targets
`feat/mkit-server` on `mkit-server/wp-4-10b-1-protection`. Open the PR; do not merge.

PR1 delivers the protection, delivery and bounded upload prerequisites below.
The registered Worker verifier still uses `FailClosedExtraction`; required
objects end in `ExtractionUnavailable`. This part does not complete extraction
or enable indexed Workers. The original [WP-4.10b brief](WP-4.10b.md) remains the
full contract; [PR2](WP-4.10b-2.md) owns its unfinished driver requirements.

## Fixed contracts

- Preserve SPEC-SERVER §§9.6, 13.2–13.4 and 14.2, R-163 and R-171. A newly
  Verified pack cannot bypass extraction or verify-before-visible.
- Freeze `gp`, `ct`, timer kind 13 and the observed `RelayHook` seam. Add no trait,
  tag, timer, relay codec or wire format.
- R-198 forbids compatibility with earlier unreleased stores. Current producer
  rows, including generic 96-effect relay intents, must work.
- Indexed activation stays default-off until WP-4.18. Launch GC is off; there is
  no GC-enabling configuration path in the inspected launch profile. Do not add
  GC-only machinery; any future indexed GC startup path must refuse enablement.
- Count non-test production lines against the final base and report the method
  and total. PR1's cap is 3,000; escalate before passing it.

## Deliverables and brief checklist

1. **B1 prerequisites:** atomic consumed-group job creation, bounded payload-free
   frame/reference projection pages and opaque backend ETag capture. The full
   frozen selection and extraction checkpoint remain PR2 work.
2. **B2:** keep Extract fail-closed. Source verification/charging, reconstruction,
   root completion, offsets, holder enqueue/renewal and final Verify remain PR2.
3. **B3:** target holder delivery atomically writes HolderV1, guards/bumps `c`,
   updates conservative counts, releases the ordinary hold and exact pending
   ownership, and advances `rh`. Repeated delivery folds; distinct re-records
   bump. A late blocked holder records durable `ct` plus kind-13 retry work.
   Ready requests remain available to WP-5.6a; Ready never means takedown complete.
4. **B4 prerequisites:** retain the user-approved internal Rust callbacks on
   existing `SliceExtension`: `extraction_enabled` defaults false; `begin_object`,
   `put_object_part` and `complete_object` default to no result, and `abort_object`
   defaults to success. Existing implementors remain unchanged. The R2 adapter
   uses merged R-192 root-pinned multipart. This is internal Rust only.
5. **B5 prerequisites:** Paid-only verification, one 256-call verification fire,
   at most 100 operations per apply, byte-bounded projections and relay snapshots,
   actual routed hook reads/retries, and bounded expiry/quota/ranged-read costs.
   Record the measured budgets; do not describe these component bounds as the
   finished extraction phase's 48 MiB proof.
6. **B6 primitives:** `gp` never expires by age; pending ownership insertion uses
   fresh block/deleting observations, guarded `c` and NotAfter. Identical retry
   is idempotent; changed identity refuses. Target removal joins holder delivery
   atomically. Driver protection/renewal/restart safety remains PR2.
7. **B7:** release Worker registration remains fail-closed/default-off.

The callback adapter accepts a trusted plan bounded by the existing multipart
limits; R-192's verified sink and completion preserve root/CV checks before
publication. PR2 must compute that trusted root/CV plan incrementally and use the
intended 8 MiB part spool rather than a whole-object buffer, proving the complete
48 MiB allowance. Complete takes owned part receipts to avoid cloning the
maximum ETag list. Callback reservations are begin 8, part 3, complete 7 and
abort 2 calls before IO. Tests must cover CV mismatch, part replacement, abort
and a new adapter restarting mid-upload.

## Resource ledger and current limitations

The existing timer component ledger is Paid **889** calls: 512 relay, 256
verification, 64 outcomes, 32 quota, 1 backup and 24 expiry. Free is **49 of 50**: 32
relay, 8 outcomes, 8 quota and 1 backup; deferred expiry abort performs no external
IO. This is a component ledger. Newly merged purge, snapshot and admin consumers
share the alarm's **1,000** external-operation cap; 889 is not the total of all
merged alarm consumers. Free indexed verification is refused.

A generic ranged R2 read reserves both metadata and byte calls. Relay effects
fit current generic 96-effect rows together with bounded hook edits; exact batch
operation/byte checks, including guards, remain authoritative. The complete
extraction phase's retained payload, projections, receipts and Worker JSON/JS
allocation proof belongs to PR2.

## Gates and review

Run the common executor gates and original area gates: fmt; workspace/all-target
all-feature clippy; touched crates and reverse dependencies' all-feature nextest,
doctests and warning-free docs; wasm32 clippy and Worker build; `just ci-server`,
`ci-scripts` and `ci-security`. Run the **default** real Worker conformance phase
on an owned free `VCS_CONFORMANCE_PORT`. Indexed/test-faults extraction conformance
belongs to PR2. Perform both mandatory independent self-reviews and record their
findings/fixes, actual gate results and exact production count in the PR body.

## Carry-forwards

PR2 must resolve union count/byte parity, the legitimate full-member-list guard
limit and whole-group closure before effects. It owns native/Scheduled parity,
all extraction acceptance cases, whole-phase 48 MiB proof and default plus
indexed/test-faults real Worker conformance. WP-5.6a consumes retained takedown
requests; WP-4.18 owns activation. The executor merges neither PR.
