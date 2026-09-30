# WP-4.10b: checkpoint and proposed split (2026-09-30)

Status: **historical checkpoint; the user approved this split on 2026-09-30.**
The authoritative scopes are [PR1](WP-4.10b-1.md) and [PR2](WP-4.10b-2.md), sharing
R-186, with caps of 3,000 and 2,000 production lines respectively. PR2 opens into
`feat/mkit-server` after PR1 merges. The measurements and validation below
belong to checkpoint `472d7a72`; they are not final PR1 gate or completion claims.
Statements below describing approval as outstanding record the original proposal.

## Measured size and reason to stop

Relative to merge base `4d1c8fd435b4552c8716a60b606280cf63434ace`, the checkpoint
contains 2,814 added and 58 removed non-test Rust physical lines: 2,872 changed
lines using the conservative added-plus-removed count. Test files and inline
`cfg(test)` blocks are excluded; comments and blank production lines are counted.
The added-only count is also reported so the counting convention is explicit.

The existing count-parity regression requires a bounded merge of current frame
rows (estimated 60–90 production lines). A whole-group closure barrier before
extraction effects is also required (estimated 65–80 lines). Together their
upper estimate crosses 3,000 using the conservative changed-line count, before
remediation of the confirmed guard-budget failure. Under added-only counting,
that upper estimate leaves only 16 lines for its remediation and resource proof.
These estimates are not measurements of
unwritten code; the 2,872-line checkpoint is measured. No production lines were
removed or reformatted merely to fit the cap.

## Concrete current-producer failures

1. `scheduled_duplicate_objects_keep_first_pack_owner_and_advance_counts` compares native and
   Scheduled reporting for the same consumed union. Scheduled sums per-pack
   entry counts and reports four objects where native reports three; canonical
   byte totals must also deduplicate. Selection and holder ownership alone do
   not satisfy count parity.
2. `completed_groups_with_full_member_lists_remain_claimable` runs the current
   verifier to produce six separate seven-pack completed groups. Each job has
   256 satisfying repository member packs. Reusing six ready sources alongside
   a new pack requires guarding their completed peers. The observed old job
   values total **1,371,337 bytes**, exceeding the **1,048,576-byte apply limit**.
   The complete attempted claim batch is **1,575,255 bytes**. The legitimate
   claim returns storage-unavailable and never creates the new
   pack's job. These are current producer rows, not historical or handwritten
   job fixtures. Dropping peer guards without an equivalent lifetime proof is
   unsafe; rejecting this push is not an acceptable bounded implementation.
3. Group reference projections are validated before selection, but full closure
   presence is not yet established before the first selected object's effects.
   An unstaged missing source currently waits indefinitely rather than producing
   native's closure error after the allowed lag. This is a source-review finding;
   the complete closure-barrier acceptance test remains to be added.

The canceled-first-owner failure was fixed: an absent fresh peer owner's ticket
prevents its surviving duplicate from becoming Verified without extraction.
The exact ticket observation is guarded. Queued work can still drain and renew
protection after its own ticket disappears. Its regression passes.

## Historical partition submitted for approval

**PR 1, protection and bounded upload integration:** retain the frozen gp/ct,
timer-13 and observed RelayHook foundations; current generic 96-effect relay
support; paged selection projections; compact opaque ETag capture; alarm quota,
expiry cleanup and ranged-read accounting; and default-compatible internal
SliceExtension upload callbacks plus R-192 adapter tests. Keep Extract
fail-closed. No claim that extraction is finished. Gate and review this coherent
partition before opening it into `feat/mkit-server`.

**PR 2, extraction driver:** move the driver, its checkpoint state, dispatch,
group ownership/reclamation and acceptance tests to a dependent follow-up.
Finish count parity, pre-effect group closure validation, and a bounded guard
strategy that supports the legitimate reuse case above. Prove restart and
cleanup safety before replacing any full raw guard with a smaller observation.
Complete the whole-phase 48 MiB proof, all brief tests and all required gates,
including wasm32 clippy and both default and indexed/test-faults real Worker
conformance on an independently chosen free port. Remain default-off until
4.18. Neither PR is to be merged by the executor.

The proposed partition needs approval because the restart prompt explicitly
says to split the driver out and escalate the proposal first if completion
would pass the 3,000-line cap. No additional trait, key tag, timer, wire format,
relay codec or R-row is requested here. Any later solution needing one must be
escalated separately. The checkpoint has not yet been rearranged into these PRs.

## Approved callback surface and bounded work

The existing `SliceExtension` now has default-disabled extraction and internal
`begin_object`, `put_object_part`, `complete_object`, and `abort_object`
callbacks. Existing implementors inherit no-op callbacks. R2Extraction uses the
merged R-192 verified multipart path. Reservations before IO are respectively
8, 3, 7 and 2 calls. Complete takes owned receipts, moving their tags rather
than cloning the maximum receipt vector. Part CVs are computed incrementally
and persisted separately from the small job checkpoint. No object payload is
buffered in its entirety; the current part spool is 8 MiB.

The callback regression covers an invalid CV list, a mismatching replacement
part, abort, and a new adapter resuming an existing upload. Incorrect root
completion remains private; publication requires the trusted root and every CV.
The former pre-upgrade rootless-object test was dropped under R-198. Current
producer generic relay rows remain covered.

Alarm accounting is Paid 889 calls (512 relay + 256 verification + 64 outcomes
+ 32 quota + 1 backup + 24 expiry) and Free 49 (32 relay + 8 outcomes + 8 quota
+ 1 backup). Indexed mode remains Paid-only. A generic ranged BlobStore read
reserves two calls for R2 metadata and bytes. Auxiliary driver writes validate
both operations and bytes against their exact job guard before applying;
operation count alone is insufficient. The entire phase's 48 MiB proof and the
legitimate multi-group summed-guard bound are not complete.

No GC enablement configuration or startup path exists in the inspected launch
profile. No GC-only machinery was added. Same-pack repeated ready tickets use
one pack's facts and ownership while all consumed ticket identities remain
validated; synthetic fresh duplicates remain Pending. These choices still need
the final comprehensive parity review after the blockers are fixed.

## Validation and remaining gates

Two independent reviewers examined correctness/bounds and brief/native parity.
Their findings produced the regressions above, plus fixes for oversized part
auxiliary batches, empty chunks, canceled ownership and rejected group reuse.
They did not approve completion.

Checkpoint checks: cargo fmt and server/Worker all-feature library clippy pass;
all 10 bounded multipart tests pass, including the upload callback regression.
The final focused extraction and group-reclaim
run reports **17 passed and 2 failed**, the count and guard regressions above;
the canceled-first-owner regression is among the passing tests.
Earlier ci-scripts, ci-security and spec-status
checks passed, but are not final gates for a future rearranged tree. Full
workspace tests/clippy, docs, ci-server, wasm32 clippy and real Worker conformance
are outstanding. The known red regressions are retained, not ignored or weakened.

Reproduction logs and the counting script are under
`~/.cache/mkit-test-tmp/wp-4-10b/`: `count-production.py`,
`checkpoint-upload-callbacks.log`, `checkpoint-lib-clippy.log`,
`checkpoint-extraction-review.log`, and `current-producer-group-guards-red.log`.
