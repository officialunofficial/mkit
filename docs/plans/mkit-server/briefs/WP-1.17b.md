# WP-1.17b: split large pushes along first-parent history (client)

## Purpose

A Connect push whose new data needs more than the per-advance pack budget (6 data packs plus the MKPL node) no longer
fails with `PushTooLarge` after uploading 6 packs. The client splits it along the branch's first-parent history into
several advances. Each advance moves the branch to an intermediate first-parent commit whose closure fits. The split
is resumable and never widens overwrite authority.

## A. Fixed (do not change)

1. **STC §4 and §7.6–§7.7:**
   - an advance consumes at most 7 tickets, including the MKPL node;
   - membership is recorded at the consuming apply;
   - a conflict consumes nothing;
   - a live ticket is returned for the same (signer, ref, pack);
   - the lag window applies.
2. **R-142:**
   - the budget is six ticketed data packs plus the MKPL node;
   - `DeltaBaseUnavailable` re-plans as a self-contained plan, once.
3. **The seal-time gate stays** as a backstop.
4. **No transport, core or server API change.** Reuse 1.17/1.18's ticket threading, recovery, lag polling and part
   resume unchanged.
5. **Stage 1 servers refuse `u` without `f` on Match** ("update without force needs indexed mode"), and Missing
   needs `c`.

## B. Decided (do not change)

- **B1. Automatic, Connect-only (D1, D6).**
  - Split only when `limits.tickets_per_advance.is_some()` and the conservative estimate of **total** packs exceeds
    the budget, `min(tickets_per_advance, 7) - 1`.
  - Replace the literal `6` in the seal gate (`mod.rs` ~L1598) with that derived budget.
  - Otherwise behave exactly as today. No flag.
  - **ssh/enc are out of scope.** A session's 1 GiB budget and the 4 GiB pack split mean the mkit CLI can't reach
    #1210's 7-pack cap. Correct #1210's R-137 carry-forward in R-164 ("moot for mkit clients; reuse this split with a
    reconnect per step if the per-connection budget grows").
- **B2. Choosing the steps.**
  - **The chain:** walk tip's first parents back to the stop commit S: the first commit equal to the remote tip or
    one of its ancestors. With no remote tip, walk to the root or the shallow boundary.
    - Never enter a second-parent side.
    - Bound the walk, and cap steps at **1,000**, with a clean error and no advance.
  - **Cumulative bytes:** one forward pass seeded with `closure(S)` gives the cumulative raw bytes U(j) plus frame
    overhead.
  - **Cut points (D7):**
    - a guaranteed floor of 3 × the effective cap per step;
    - a greedy extension to the furthest j whose **real** plan (`estimate_pack_sizes`) fits in the budget, found by
      binary search down to the floor;
    - reuse the verified plan for upload, with no second delta encode.
  - **Determinism:** cut points are a pure function of (store, tip, remote head, limits), so a resumed push
    regenerates identical packs.
- **B3. A single oversize commit or merge (D3).**
  - Before publishing any step, run an **exact local dry seal** (the builder with a counting sink, no upload) for any
    unsplittable step whose estimate is over budget.
  - If it really needs more packs than the budget, fail **before step 1** with `PushTooLarge`, naming the commit
    (and its second parent, for a merge) and the count, with the "ask the operator to raise max_pack_bytes" hint.
  - A merge is always one step.
- **B4. Conditions per step.**
  - Step 1 uses the user's lease: Match(tracked), Missing, or Any.
  - Steps 2 and later always use **Match(c_{k-1})**, even under `--force`.
  - **Write the tracking ref after every committed step (D4):** add a per-step callback variant, and keep the
    existing `push_branch*` functions as wrappers. `push_all_with` writes tracking per step per branch.
- **B5. Grant pre-check (D8).**
  - Before any upload, check authority for **every** step's condition through the installed `GrantSource`, or the
    owner key.
  - When the server isn't in indexed mode, steps 2 and later require an `f`-carrying grant or the owner key.
  - Refuse early with a clear error that says nothing was published.
- **B6. Recovery per step.** `LandedThenRejected` continues. `TicketRejected` restarts once per step.
  `DeltaBaseUnavailable` re-plans the step as a full closure, once (D2). If that is over budget, fail with a clear
  error that reports the published prefix.
- **B7. Upload before advance, per step.** Never pre-upload several steps. Check shutdown between steps and inside
  every seal.
- **B8. Errors and UX.**
  - Any failure after step 1 reports the published prefix (the last committed commit) and that re-running resumes.
  - Progress on tty ("step k/N"); piped and `--quiet` output; `--json` includes the step count.
  - Update the `PushTooLarge` text.
- **B9. Out of scope (D5):** packmap-only staging advances, multi-have planning, and indexed-mode "delta chain too
  deep" retries. Record them as follow-ups in R-164.
- **B10. Docs.**
  - `docs/CLI.md`: splitting is automatic; intermediate states are published; Stage 2 hooks and receipts fire per
    step.
  - **R-164:** B1–B9.
  - A CHANGELOG line.

## C. Your decisions

- The internal module shape of `split.rs`, and the exact progress text.
- Chain-walk bound values other than the 1,000-step cap.

## D. Escalate (stop and report) if

- Determinism (B2) can't be achieved with the existing pack builder.
- The grant pre-check (B5) needs a `GrantSource` trait change.
- Production code passes 1,000 lines.

## Tests (required)

1. **Basic split:** extend the `TicketTransport` harness in `tests/push_ticket_recovery.rs` with many commits and a
   tiny cap. Expect N advances, each with at most 6 data tickets plus the node. The head after each step is a
   first-parent ancestor, and the final head is the tip. A fetch at each intermediate state reconstructs the closure.
2. **No-split regressions:**
   - an estimate within budget gives one advance;
   - `tickets_per_advance` None never splits;
   - the single-commit seventh-pack test is unchanged.
3. **Oversize:**
   - an oversize single commit or merge fails before any advance;
   - a dry seal that fits proceeds;
   - a small merge rides inside a step.
4. **Resume:** interrupt after step k. The tracking ref is `c_k`, and a re-run finishes with N advances in total,
   reusing live tickets or `AlreadyPresent` for the interrupted step.
5. **Concurrency:**
   - a concurrent push between steps gives `NonFastForwardPush`, reporting the prefix;
   - steps 2 and later send Match(prev) under `--force` and under Missing.
6. **Per-step recovery:** each B6 case.
7. **The grant pre-check:**
   - a `c`-only grant on a new branch and a `u`-without-`f` grant on a non-indexed server are refused before any
     upload;
   - the owner key and an `f` grant pass.
8. **Determinism:** the same inputs give identical cut points and pack keys.
9. **Bounds:**
   - a proptest shows the real sealed count is at most `estimate_pack_sizes`;
   - 3 × cap always fits in the budget.
10. **Limits:** the step cap and a shallow boundary.
11. **`push_all_with`:** tracking is written per step per branch.
12. **CLI output** snapshots: tty, piped, `--json` and `--quiet`.
13. **Native end-to-end** in `mkit-server-native` tests: a V2 server with a small `max_pack_bytes` and tickets gets a
    split push, and a clone verifies it.

## Gates

- The common gate set.
- `just ci-scripts`, including `check-cli-baseline.sh`.
- `cargo nextest run --locked -p mkit-cli -p mkit-core -p mkit-transport-connect -p mkit-server-native --all-features`.
- clippy and rustdoc.
