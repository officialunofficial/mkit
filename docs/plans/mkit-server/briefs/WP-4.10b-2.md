# WP-4.10b-2: bounded Worker extraction driver (R-186)

## Approved scope and sequencing

This is the user-approved follow-up to [PR1](WP-4.10b-1.md), sharing R-186.
Create its branch from PR1 and preserve the saved extraction checkpoint/tests;
open it into `feat/mkit-server` only after PR1 merges. Do not merge it. The
production cap is **2,000 non-test lines**, measured and reported against the
final base. Escalate before exceeding it or requiring another protocol surface.

The full [original WP-4.10b brief](WP-4.10b.md), R-198 restart ruling and frozen
group-protection ruling apply. PR1 remains fail-closed. This part completes the
driver before replacing that registration, while release activation remains
default-off until WP-4.18. No migration or compatibility for pre-launch stores.
Current producer rows, including generic 96-effect relays, must keep working.

## Required implementation

- Scan all consumed group facts, establish whole-group closure before any
  extraction effect, freeze deterministic native-equivalent selection and keep
  the first pack owner. Chunk-only blobs are excluded; later direct references
  in the same consumed union participate. Include reused Verified sources.
- Count **union** objects and canonical bytes, deduplicating across packs exactly
  as native does. Source-budget accounting remains repository-local, no-oracle
  and replay-safe on both dedup and misses; document its bounded behavior.
- Separate mutable job bodies from guarded headers **inside existing `vc`**
  storage. Headers carry state/generation; completed member lists are immutable
  facts. Every body change bumps generation; peer guards observe only bounded
  headers. These are required PR2 decisions, not claims that PR1 implements them.
  Preserve source lifetime, cancellation, replacement and restart correctness.
- Support the current producer case of six ready seven-pack groups, each with
  256 completed satisfying member packs, reused alongside a new pack. The old
  full peer guards total 1,371,337 bytes and cannot fit a 1,048,576-byte apply.
  Do not reject or stall that legitimate push or simply remove lifetime guards.
- Extract, reconstruct and reassemble staged/member/mixed chunks with exact
  offsets, including empty chunks and empty manifests. Root-check publication,
  write the offset sidecar, atomically enqueue the durable holder intent with
  progress, renew holds through real relay delay and ticket expiry, await target
  delivery, then permit Verify. Cancellation of a first owner must not allow its
  duplicate to become Verified without extracted content and protection.
- Use PR1's approved default-no-op internal `SliceExtension` callbacks and merged
  R-192 multipart. No new trait, tag, timer, codec, seam or wire format. Incremental
  root/CVs and bounded part receipts must preserve verify-before-visible, with
  no whole-object buffering beyond the 48 MiB allowance.
- Keep fresh block/deleting checks, exact guarded source and protection
  observations and NotAfter on replans. A lost lease closes effects safely;
  queued work must not lose protection when its source ticket expires.

## Bounded resource proof

Prove the **whole phase**, including projections, raw guards, retained receipt/CV
lists and Worker JSON/JS copies: at most 256 calls per verification fire, 48 MiB
resident allowance, 100 operations and the byte cap per apply. Preserve Free's
49-of-50-call component split/refusal and the shared merged Paid alarm cap of 1,000.
The PR1 889-call component ledger is not a complete merged alarm total.

Distinct consumed tickets for one pack and summed raw-guard byte limits need the
simplest correct bounded behavior, documented in the PR body. It must not
extract twice, lose protection, or stall/reject a legitimate push. Escalate with
a concrete current-producer example if safe bounded behavior is impossible.
GC stays off; add no GC-only machinery or unreleased-row compatibility.

## Tests, gates and completion

Complete the original fact sheet's extraction tests and native/Scheduled parity,
including union selection/reporting, Verified reuse, source charging on dedup,
empty/large fragments, every durable checkpoint replay, multipart lost replies,
CV mismatch/replacement/abort/restart, hold renewal beyond TTL/ticket expiry,
late blocked delivery, source lease loss, canceled owners, rejected group retry
and full-member-list bounded reuse. Keep genuine red regressions until fixed;
do not weaken them to claim completion.

Run the common and original area gates, wasm32 clippy and Worker build. Run both
default and indexed/test-faults real Worker conformance phases on an owned free
port. Perform both independent self-reviews and record every original A/B item,
executor decision/deviation, measured budgets, production count and gate result.
Definition of done is an open PR into `feat/mkit-server`; do not merge.
