# Executor prompt: launch review fixes B — index aggregation memory, pack cap, scanner retrieval on ticketless writes

Run locally in `/Users/vitormarthendalnunes/Documents/21.Uno/04.Mkit/mkit`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `~/.cache/mkit-orch/scratchpad/prompts/executor-common-external.md`;
- the external review, `/Users/vitormarthendalnunes/.cache/mkit-orch/scratchpad/research/FULL-REVIEW-e8164870.md`. Read the full entries for **1b-1, 4a-1 and 5-1**. It was pinned at `e8164870`;
  re-locate every line on the current base.

**Setup:**
- **Worktree:** `.claude/worktrees/fix-review-b`, from a fresh `origin/feat/mkit-server`.
- **Branch:** `mkit-server/fix-launch-review-b`.
- **PR title:** `fix(server): launch review fixes B (index memory bound, pack cap, ticketless scanner writes)`.
- **Cap:** 900 non-test Rust lines.

**Rule for every item:** reproduce first as a failing test (red), then fix it (green). An item that doesn't reproduce
is recorded as "not reproduced" with evidence and skipped.

## Items

1. **1b-1, High: aggregate object-index lookup memory** (`store/index.rs` `locate_many` / `scan_all`, the Worker
   `ns_client` and `wire` serialization; called from `indexed/scheduled.rs`).
   - **The fix:** bound the retained candidate bytes and the membership key and serialized request bytes **before
     allocation**. Join membership in bounded chunks, and return the existing cap / smaller-batch error when the
     aggregate bound is exceeded.
   - **The bound:** document it in bytes, and make sure it fits the Worker's 128 MB isolate with headroom (for example
     at most 16 MiB of retained index state per lookup). Key chunking alone isn't enough: account for the 256-ID
     candidate pool.
   - **Reproduction:** adapt the review's allocator probe (`~/.cache/mkit-test-tmp/review-full-1b/probe`) into a
     counting-allocator regression asserting a peak at or below the bound, plus a functional test that the smaller
     batches still verify correctly.
   - No new key, timer or protocol.
2. **4a-1, High: the current max_pack_bytes in Scheduled verification.** Reject a ticket whose bytes exceed the current
   `max_pack_bytes` at the start of Scheduled `check_inner` (before claiming or reusing a job), with the exact
   `invalid_argument` "pack exceeds indexed max_pack_bytes". Repeat the check before scheduled decode work. Make the
   native already-Verified remap return the same exact error.
   - **Tests:** a ticket issued under a larger cap, then a restart with a lower cap, for both a fresh job and a usable
     job.
3. **5-1, High (scanner retrieval enabled): ticketless ref writes.** With inspection plus scanner retrieval configured,
   a non-deletion `UpdateRef` or zero-ticket `AdvanceRefs` over already-published content currently fails with
   `internal("retrieval requires tickets")`. Support the empty added-pack case:
   - build an empty retrieval assignment (`token.rs` already allows zero packs) from the authenticated
     operation/ref/repo context, and make `inspect_advance` handle it coherently;
   - keep the §11.2 every-advance Inspect call semantics, with an empty object set and an empty-scope capability;
   - mint no authority over prior packs.
   - **Tests:** Single and D34 tag creation, a head-only update, a packmap-only update and a zero-ticket paired advance
     after an initial scanned publication.

## Coordination

- **4.18** (activation and adapter) and **the chore lane** (timers and tests) are in flight. This PR touches
  `store/index.rs`, `indexed/scheduled.rs`, `indexed/job.rs`, `pipeline/mod.rs` (inspection setup) and the Worker
  `ns_client.rs`/`wire.rs`. Keep the edits local, and merge the base before opening the PR.
- **Fix-review-A** runs in parallel. No overlap is expected.

## Gates

- the common gates;
- `just ci-server`;
- wasm32 clippy;
- the vcs-worker default conformance on a free port.

Do the self-review, then open the PR.
