# WP-1.23b amendment 1: durable relay scan state (answer to the R-103 question)

You are the WP-1.23b executor, continuing the stopped work.

**Where to work:**
- Worktree: `$REPO/.claude/worktrees/wp-1-23b`
- Branch: `mkit-server/wp-1-23b-membership-reads`
- Your commit: `0db295f3`

**Before continuing,** read the original prompt again,
`<local path>`,
and the common rules file it names.

**The decision is option A, with a bounded blocked set.** Narrowing R-103 (option B) is rejected: a single
permanently failing index shard must not stop relay delivery to every other shard. The contract below is
**Section B, fixed** and extends B.2.

**Definition of done:** an open PR. Work until the PR is open.
- Flaky gates and base conflicts are not stops.
- A failure that reproduces unchanged on the parent commit (the S3 `AlreadyPresent` vs `Created` assertion, and Worker
  conformance connection drops under load) is not a stop: record it with the parent-commit evidence and continue.
- Never end with uncommitted work, unpushed work, or no PR.

---

## B.2a Durable scan state

### State row (one per source partition)

- **Key:** `rs 00`, a new source-partition key.
  - Add `TAG_RELAY_SCAN = "rs"` to `store/keys.rs`, with a layout-table row, parse support, and the golden layout
    test.
  - It is never pruned, and there is one per source.
- **Value:** codec `RelayScanV1`, holding:
  - `cycle_end: u64`: the `os` value observed when the cycle started;
  - `cursor: u64`: the last `or` sequence inspected this cycle, or 0;
  - `blocked`: a sorted, deduplicated list of target `Partition`s, **at most `MAX_BLOCKED_TARGETS = 32`**.
- **Size:** the encoded value MUST stay under the store's value limit. Add a test at 32 maximum-size partitions.
  If it can't fit, reduce the cap and record the value (C).
- **Writes:** it is written in the same batch as the fire's row deletions, guarded by `Equals` on its previous value
  (or `Absent`).
  - A guard conflict makes the fire return `Retry`. It never overwrites.

### The invariant (state it in the module doc and in INVARIANTS)

> Every undelivered relay row with `seq ≤ cursor` has its target in `blocked`.

### One fire

1. **Load state.** If the row is absent, or `cursor ≥ cycle_end`, **start a new cycle:**
   - `cycle_end` = the current `os`;
   - `cursor` = 0;
   - `blocked` = empty.

   Rows added after `cycle_end` wait for the next cycle.
2. **Scan** `or` rows with `cursor < seq ≤ cycle_end`, in ascending seq, within the existing per-fire budgets:
   - `4 × max_rows` inspected rows;
   - `MAX_FIRE_BYTES`;
   - `max_targets`;
   - Worker calls.

   For each row:
   - **Target in `blocked`:** skip it (leave it in place).
   - **Otherwise, deliver it** in seq order under the existing rules.
     - On success, delete the row.
     - On failure (or being cut by `max_targets`), add the target to `blocked` and leave the row.
   - **Undecodable row:** deliver the decodable prefix, persist `cursor` = the seq just before the bad row, and return
     `Retry`. It is never skipped (the B.2 rule is unchanged).
3. **Advance `cursor`** to the last **inspected** seq. Never advance it past an uninspected row.
4. **Overflow:** if adding a target would exceed `MAX_BLOCKED_TARGETS`:
   - stop the scan at that row and leave the row in place;
   - persist `cursor = cycle_end`, which ends the cycle, so the next fire starts a new cycle from the head.

   This is safe: a fresh cycle has an empty `blocked` set and scans from the head, so the invariant holds trivially.
   Beyond the cap, targets further back can wait. That is the documented limit of the guarantee.
5. **Reaching `cycle_end`** ends the cycle. The next fire starts a new cycle from the head and retries the blocked
   targets.

### Order safety

A target's rows are delivered in ascending seq, and **no row of target T is delivered while an older T row is
undelivered**. This holds because, by the invariant:
- any undelivered older T row before `cursor` puts T in `blocked`;
- any older T row after `cursor` is reached first by the ascending scan.

State this argument in the module doc.

### Guarantee (replaces R-103's unqualified wording)

> A healthy target is delivered within a bounded number of fires, provided fewer than `MAX_BLOCKED_TARGETS` distinct
> failing targets have rows ahead of it. Every row is retried at least once per cycle.

## Tests (in addition to the brief's)

1. The exact schedule from your question: seq 1–512 target a permanently failing A, and seq 513 targets B. B is
   delivered within ⌈513 / (4 × max_rows)⌉ + 1 fires, and A's rows are retained and retried after the cycle ends.
2. **Order safety:**
   - T's rows at seq 1 and seq 600, with T failing only on the first attempt: the seq-1 row is never discarded, and
     `rh` never passes an undelivered T row;
   - a property test over random schedules (targets, failures, budgets) against a model that checks per-target order
     and eventual delivery of healthy targets.
3. **Overflow:** 33 distinct failing targets ahead of a healthy one.
   - The cycle resets, and nothing is lost or reordered.
   - Once the failing targets recover, every row is delivered.
4. **Crash between fires:** the state row and the deletions are atomic. Simulate a guard conflict and assert `Retry`
   with no lost rows.
5. `RelayScanV1` round-trips, and the size test.

## Plan

Add row **R-110**:

> WP-1.23b relay liveness. The source keeps a durable scan state (`rs 00`: cycle end, cursor, and at most 32 blocked
> targets), so a failing target's backlog cannot hide a healthy target beyond the per-fire inspection budget.
> - Guarantee: a healthy target is delivered while fewer than 32 distinct failing targets precede it.
> - Otherwise the cycle resets, and every row is retried at least once per cycle.
>
> This supersedes the R-103 wording.
