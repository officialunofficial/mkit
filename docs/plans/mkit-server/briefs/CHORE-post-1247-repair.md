# Executor prompt: chore, repair the inherited base test and conformance failures (after #1247/#1248)

Run locally in `<repo>`.

**Definition of done:** an open PR into `feat/mkit-server`. Don't merge it.

**Read first:**
- `<local notes>`;
- **the failure list:** `~/.cache/mkit-test-tmp/wp-zstd-bound-review/baseline-findings.md`, with 14 named tests,
  their failure sites, a classification for each and the parent logs, plus the inherited Worker conformance failure
  `refs.many_refs_one_repository` (logs `vcs-*many-refs*.log` in `~/.cache/mkit-test-tmp/wp-zstd-bound/`);
- the PRs that likely caused them: #1247 (bounded timer alarm scan with persisted backoff: failing and unknown rows
  move their due time), #1248 (deterministic timer and growth conformance) and #1246 (content headers: the missing
  `content-headers.bin` golden);
- the ruling text for #1247, "RULING 4.18 cold alarm", in `<local notes>`.

**Setup:**
- **Worktree:** `.claude/worktrees/chore-post-1247`, from a fresh `origin/feat/mkit-server`.
- **Branch:** `chore/post-1247-repair`.
- **PR title:** `fix(server): repair inherited timer, job and fixture failures`.
- **Cap:** 600 non-test Rust lines.

## Decided

1. **Triage each failure as one of:**
   - **(a) a stale test expectation** of the pre-#1247 timer layout: for example, a test expects the old due-key row
     after backoff moved it;
   - **(b) a real product regression** introduced by #1247, #1248 or #1246;
   - **(c) a fixture or tooling artifact.**

   Show the evidence for each classification. **Don't assume the reviewer's "appears stale" labels**; verify them.
2. **For (a):** update the test to assert the **intended** #1247 behavior: a failing or unknown row is re-dated with
   capped backoff in the same row, never deleted, and still fires later. Never weaken a test to pass. Keep the
   original invariant: no lost wakeups, rows retained, retries happen.
3. **For (b):** fix the product code minimally, with a regression test. Watch especially:
   - `sql_soft_limit_reserves_space_for_guarded_relay_timer_reschedule` (Err(Full) on the guarded reschedule). The
     backoff write may need the reserved capacity.
   - The off-by-one wakeup (5100 vs 5101) and the "fires 0 rather than 1" relay cases. Backoff must never delay a
     **healthy** row or a just-progressed relay.
   - The indexed job tests that don't finish (cap set {2,4} instead of {1,2,4}), and the published-view
     dirty-work test.

   If a fix needs a protocol, key, timer-kind or budget change, stop and escalate.
4. **For (c):** regenerate or restore `content-headers.bin` from its source, so `golden_http_object_spans_via_wasm`
   passes, and confirm the golden generator includes it.
5. **`refs.many_refs_one_repository`** (Worker conformance, HTTP 500 / "Network connection lost"): diagnose it. Is it
   a real Worker failure under many refs (memory, CPU, subrequests, a timer or alarm interaction after #1247), or
   harness load? Fix it if it's real and in scope. Otherwise produce a precise diagnosis and escalate.

## Gates

- the full `mkit-server`, `mkit-server-native`, `mkit-server-worker` and `mkit-wasm` test suites, all green (that's
  the point of this PR);
- `just ci-server`;
- wasm32 clippy;
- the vcs-worker default conformance on a free port, including `many_refs`.

Record before and after for every named test. Do the self-review, then open the PR.

## Accepted user correction (external review 12-1)

Do not create `content-headers.bin`. Add `"content-headers"` to the metadata-table
skip list in `rust/crates/mkit-wasm/tests/verify.rs`, matching
`rust/crates/mkit-core/tests/golden_http_objects.rs`. This is a metadata table
with no proof binary.
