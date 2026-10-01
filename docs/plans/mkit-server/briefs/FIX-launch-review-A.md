# Executor prompt: launch review fixes A — takedown purge, admin replay, outcome wake, crypto pin

Run locally in `/Users/vitormarthendalnunes/Documents/21.Uno/04.Mkit/mkit`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `~/.cache/mkit-orch/scratchpad/prompts/executor-common-external.md`;
- the external review, `/Users/vitormarthendalnunes/.cache/mkit-orch/scratchpad/research/FULL-REVIEW-e8164870.md`. Read the full entries for **7a-2, 7b-1, 3-1 and 12-2**: claim, scenario, evidence,
  suggested fix. The review was pinned at `e8164870`; the base has moved since, so re-locate every line.

**Setup:**
- **Worktree:** `.claude/worktrees/fix-review-a`, from a fresh `origin/feat/mkit-server`.
- **Branch:** `mkit-server/fix-launch-review-a`.
- **PR title:** `fix(server): launch review fixes A (takedown purge, admin replay, outcome wake, sha2)`.
- **Cap:** 900 non-test Rust lines.

**Rule for every item:** reproduce it first as a failing test (red), then fix it (green). If an item doesn't reproduce
at the current base, don't fix it. Record "not reproduced" with evidence in the PR body, then continue with the rest.

## Items (decided: follow the review's suggested fix unless the code proves it wrong)

1. **7a-2, High: automatic cache purge on every takedown** (SPEC-SERVER §14.3 step 5, §16.7). On takedown acceptance
   and activation, and on late-owner intake, commit durable timer-11 CachePurge responsibility, with audit, in the
   same apply as the triggering state change, plus an immediate local invalidation call. Reuse the existing
   `plan_repository_purge` / `purge::plan_enqueue` machinery, with a stable takedown or action identity.
   - **Scope:** cover the denied objects and every repository the takedown knows about. As holder discovery finds
     more, purge those too, checkpointed in the existing timer-15 work.
   - **Manual PurgeCache** doesn't satisfy this.
   - **No new tag, timer kind or protocol.**
   - **Tests:** acceptance enqueues a purge, the sink receives it, it survives a restart, and late-owner intake
     purges too.
2. **7b-1, High: Takedown replay.** In `admin/ledger.rs` `finish_extension`, the fresh current-role recheck applies
   **only** to ReadPreserved (§16.4). An identical completed Takedown retry returns its stored response even after the
   key's roles changed.
   - **Tests:** the review's scenario; the ReadPreserved fresh-role denial still holds.
3. **3-1, High (paid reads): a missing kind-8 wake.** When `purge::plan_enqueue` takes the shared `oc` backlog from
   zero to positive, atomically schedule the existing kind-8 kick as well, preserving the zero-to-positive wake
   invariant (`INVARIANTS.md` around 1397).
   - **Tests:** purge first, then an outcome; purge completion; reconcile; restart. The outcome is delivered.
   - Check the op and alarm budgets.
4. **12-2, Medium (gate): sha2 alignment.** Align `mkit-server` dev-dependency `sha2` to 0.11 and adapt test usage.
   `bash scripts/check-crypto-stack-version.sh` exits 0.

## Coordination

- **4.18** is wiring a custom PurgeSink into the Worker DO builder and keeping activation closed. Touch only
  `mkit-server` core for item 1; keep Worker adapter edits minimal.
- **The chore lane** `chore/post-1247-repair` edits timer, relay and outbox tests. Keep item 3's code change local
  to `purge/mod.rs` and `outbox` where possible, and merge the base before opening the PR.

## Gates

- the common gates;
- `just ci-server`;
- wasm32 clippy;
- the crypto-stack script;
- the vcs-worker default conformance on a free port.

Do the self-review, then open the PR.
