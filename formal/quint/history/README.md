# History publication and recovery (MKIT-20)

Tool pins (MKIT-17): quint 0.32.0, Java 21, Apalache 0.62.2 run directly on
the TLA+ that `quint compile` emits, and TLC from the `tlc2.TLC` class in that
Apalache jar (sha256 `079b6c23…6efaa8`). `quint compile` itself uses quint's
bundled Apalache (0.56.1) only to translate to TLA+; `quint verify` is not
used for any result below.

Quint models of first-parent ancestry publication, crash recovery and the
scrub schedule in [SPEC-HISTORY-PROOF §4](../../../docs/specs/SPEC-HISTORY-PROOF.md),
under the guards in [SPEC-CONCURRENCY §3.3/§4](../../../docs/specs/SPEC-CONCURRENCY.md).
Each model is aligned with `rust/crates/mkit-core/src/history/ancestry.rs`
(`advance`, `finish`, `recover`, `decide_chain`, `AncestrySnapshot::load`),
`refs.rs` (`RefMutation::{write,delete}`, `update_ref_with_ancestry`,
`delete_ref_with_ancestry`) and `refs/ancestry_state.rs` (`invalidate`,
`pending_roots`).

| File | Contents |
|---|---|
| `history.qnt` | `historyCore`: the publication/recovery state machine. `history` is the conforming instance plus scenario tests; `mut*` are mutants. |
| `scrub.qnt` | `scrubCore`: the §4.5 re-verification schedule. `scrub` is the conforming instance plus a test using the real constants; `scrubLossy`, `scrubClockBack` and `mut*` are variants. |
| `tlc/` | TLC wrappers that add a sound state `VIEW` to the compiled TLA+. |
| `check.sh` | Reruns every check below. |

## history.qnt

**Durable state:** `ref`, `transaction`, `pending-snapshot`,
`generations/<g>.snapshot`, `current`, object store. **Volatile state:** the
operation's program counter and its in-memory snapshot. `Crash` can fire
between any two durable steps and discards volatile state. Each durable step
(write+sync) is one action. §4.4 steps 1–3 are `decide`, which persists the
intent; steps 4, 5, 6, 7a and 7b are `FPending`, `FRef`, `FSnap`, `FCurrent`
and `FClear`. The actors are:

- `Advance`: finish any recorded intent, including the retry-of-intent early
  return, then CAS-check and decide.
- `Delete`: recover, check the expectation, invalidate `current`, then remove
  the ref.
- `RawWrite` / `RawDelete`: refuse a pending intent, invalidate `current`
  before changing the tip, and keep `current` on a true no-op write.
- `Gc`: roots are the ref plus the intent's previous and target refs.
- `WriteObject`: may add an object without its ancestors.
- `canServe`: `load`'s checks, evaluated as a state predicate because a load
  is a pure read.

A ghost `lineage[g]` records whether every ref value written since generation
`g` was minted fast-forwarded the previous one.

| Invariant | Meaning (spec) | Non-vacuity (checker falsifies) |
|---|---|---|
| `NoProofWhileIntent` | proofs withheld while an intent exists (§4.4) | `mutLoadIgnoresTx` |
| `CurrentMatchesRef` | with no intent, `current`'s snapshot has the live tip and its canonical whole chain (§3, §4.4) | `mutHealTipOnly` (recovery appends only the tip) |
| `ServedMatchesRef` | the same property for a served descriptor | holds even under `mutHealTipOnly`, because `load` re-walks the chain; `CanaryNeverServed` shows it is reachable |
| `GenerationFastForwardOnly`, `ServedGenerationFresh` | a generation is never reused across delete/recreate, reset/rewrite or raw ABA (§1) | `mutRawSkipsInvalidate`, `mutReuseGenOnRewrite` |
| `FastForwardRetainsGeneration` | a fast-forward of the live published tip keeps its generation (§1, §4.4 step 2) | `mutFreshGenOnFF` (every publish mints a fresh generation) |
| `FinishOnlyFromRecorded` | recovery proceeds only from the recorded previous or target ref (§4.4) | `mutFinishAnyRef` (recovery accepts any ref; needs a raw writer that steps over the intent) |
| `RecoveryEnabled`, `NeverFailsClosed` | when idle with an intent, recovery's precondition holds and its result satisfies the invariants, so the intent is always recoverable; divergence (fail closed) is unreachable through supported APIs | `mutRawIgnoresTx` (a raw writer steps over the intent, so recovery fails closed and the intent stays) |
| `IntentRootsRetained` | pending intent refs stay GC roots (§4.3); the intent's target chain is present (§4.2: missing ancestors fail before publication) | `mutGcIgnoresIntent`, `mutSkipVerify` |
| `IntentEventuallyCleared` (TLC, `tlc/MCL.tla`) | progress: an intent is always eventually removed by recovery, given fair callers and finitely many crashes (§4.4 "completes steps 4–7") | `mutRecoverSkipsPending` (recovery resumes at step 5 and errors at step 6 forever; every safety invariant still holds), `mutRawIgnoresTx` (fails closed forever) |

Each mutant is checked, by quint and by TLC, against the one invariant it is
meant to break, not against the `Safety` conjunction, so a mutant caught by an
unrelated conjunct would be reported as unexpected. TLC exit codes are also
matched exactly (12 for an invariant, 13 for a temporal property).

`mutWriteBeforeInvalidate` (a raw write moves the tip before removing
`current`) violates `CurrentMatchesRef` through a crash between the two
steps, so the crash placement exercises write ordering, not just guards.

`NoProofWhileIntent` restates `load`'s own intent check, so only a mutant
of that check can falsify it. The check is defence in depth here:
`mutLoadIgnoresTx` still satisfies `ServedMatchesRef` and
`ServedGenerationFresh`, because every state an intent leaves behind either
fails the tip/chain checks or already holds the complete target snapshot.

**Reachability canaries (each must be violated):** `CanaryNeverServed`,
`CanaryNoCrashRecovery`, `CanaryNoMultiCommitFF`, `CanaryNoRecreate`,
`CanaryNoGcDuringIntent`, `CanaryNoServedFF`.

**Scenario tests:** `boundary0Test`–`boundary4Test` crash a 1→3 fast-forward
after each persisted boundary, run GC, then retry. They require the intent to
be withheld and GC-rooted, and require the whole chain `[1,2,3]` in the
reused generation after recovery. `rawAbaTest` and `deleteRecreateTest`
require a fresh generation.

**Recovery progress.** TLC runs with `-deadlock`, but that hides nothing
here: `Gc` and `WriteObject` are enabled whenever no operation is in flight
and `Crash` whenever one is, so no state is a deadlock. A stuck protocol
would instead be a recovery that errors on every retry, leaving the intent
and withholding proofs forever. Safety invariants cannot see that
(`mutRecoverSkipsPending` passes all of them), so `tlc/MCL.tla` checks the
temporal property

    IntentEventuallyCleared == (calm /\ tx.present) ~> ~tx.present

under `WF(Progress)` (a started operation keeps taking steps),
`WF(RecoverAttempt)` (while an intent exists, some caller eventually runs
`advance` or `delete`, which recover first, §4.4 step 1) and finitely many
crashes. The last is a prophecy flag `calm` that may switch on once and then
forbids `Crash`; every behaviour with finitely many crashes is the projection
of one that switches it on after its last crash. Liveness under unboundedly
many crashes is not claimed: a crash can always interrupt recovery.

A liveness property was chosen over a bounded "completion is reachable"
witness because the failure mode of interest (retrying forever) is a cycle,
which reachability does not exclude. Non-vacuity: the property fails for
`mutRecoverSkipsPending` (lasso: crash after step 6, then recover → step 5 →
step 6 errors → recover …) and `mutRawIgnoresTx`; it fails without
`WF(RecoverAttempt)` (GC loops forever with the intent pending); and
`CanaryNoCalmIntent` shows intents do reach the crash-free suffix.

Two encoding pitfalls, both caught by the mutant: a crash must be selected by
name (`history.qnt` splits `step` into `noCrashStep` and `Crash` for this),
because an in-flight error has exactly the effect of a crash, so excluding
crashes by effect (`~Crash` on steps, or `<>[][~Crash]_vars`) also excludes
the failing retry and made TLC report the mutant as live.

`RecoveryEnabled` remains the safety-form companion: from every reachable
idle state with an intent, `finish`'s precondition holds.

**Bounds:** commits {1,2,3,4} in the first-parent forest 1←2←3, 1←4; at most
3 generations minted; one branch. TLC explores the whole reachable space of
this instance, at every depth (VIEW-reduced: 200,388 distinct states,
depth 37; the progress check has 400,776 with the `calm` flag). The VIEW
drops ghosts no guard reads and the state of dead generations; it is a
bisimulation quotient, so it is sound for the invariants and for
`IntentEventuallyCleared`, whose predicates and actions read only viewed
variables. Quint simulation runs 50,000 traces of up to 30 steps. Apalache
checks `Safety` to length 10 (length 12 did not finish within the 30-minute budget).

## scrub.qnt

The model tracks, per leaf, the publish and real time at which the leaf was
last read from the store. It covers:

- fast-forward publishes, using the window path or the full walk exactly as
  in `decide_chain`, including the `end <= prefix.len()` rollback guard;
- rewrites, which get a new generation;
- corrupt, missing or foreign-generation scrub state;
- optionally, lost scrub writes (`scrubLossy`) and a wall clock that steps
  backwards (`scrubClockBack`).

The constants are scaled: `MIN_WINDOW=2`, `LAP_FRACTION=3`, `MAX_AGE=3`
(real values 512, 64 and 604800), with chains of at most 16 leaves. The
scaling keeps `MIN_WINDOW >= LAP_FRACTION - 1`, as the real constants do
(512 >= 63); that relation is what limits a lap to `LAP_FRACTION + 1`
publishes. Each fast-forward adds at least one leaf, so a lap started at
`verified_through = vt` needs `vt + LAP_FRACTION` leaves; with 16, the lap
of every initial or rewritten chain (at most 13 leaves) runs to the end.
`realLapBoundTest` checks `lap <= 65` exhaustively for every
`verified_through` up to the 1,000,000-leaf cap, and `realLapTest` checks
sample values.

The first version of this model used `LAP_FRACTION=4` with a 14-leaf cap.
That scaling breaks the relation above: `vt = 11` gives a 6-publish lap, a
case the real constants cannot produce. `ActualPublishBound` held only
because the leaf cap cut every such lap short (with a 24-leaf cap, quint
finds the violation). The current constants hold with a 24-leaf cap too.

SPEC-HISTORY-PROOF §4.5 now states the corrected numbers (spec text fix in
this PR): a rotation takes `floor((vt-1)/window) + 1` fast-forward publishes,
at most **65**, not 64 (e.g. `vt = 32769`, `window = 512`: 64 window
publishes plus the full walk), and that bound holds only **when every
advisory `scrub` write lands**; a lost write leaves the old cursor, the same
window is re-read, and only the 7-day bound remains. The model's
`LAP_FRACTION + 1` is the scaled 65. §2.2's `inactive_peaks` field is a
wire-format detail of the inclusion proof (always 0 in mkit) and does not
touch publication, recovery or the scrub, so no model change was needed.

| Property | Result |
|---|---|
| `ActualPublishBound`: no leaf goes more than `LAP_FRACTION+1` (real 65) publishes unread, the corrected §4.5 bound | holds (TLC over the whole finite instance: any number of publishes, with the fast-forwards per generation bounded by the leaf cap; Apalache length 8); falsified by `mutWrapWithoutFull`; falsified by `scrubLossy`, as §4.5 now says |
| `TimeBound`: after a publish, every leaf was read within `MAX_AGE` (7 days) | holds, including with lost writes; falsified by `mutIgnoreAge` and by `scrubClockBack` (wall clock steps back, now stated in §4.5) |
| `InvalidForcesFull`: invalid, missing or foreign-generation scrub state always forces a full walk | holds; falsified by `mutTrustInvalid` |
| `SpecPublishBound`: the superseded "64 fast-forward publishes" | **violated**, kept as a regression witness for finding 1 |
| `WindowOnlyWhenFresh`: window only if "fewer than" 7 days elapsed | **violated** (finding 2, still open) |

## Commands and outcomes

```sh
./check.sh                           # quint + TLC: "all checks as expected" (5m53s)
APALACHE=1 ./check.sh   # adds Apalache 0.62.2, Safety to HISTORY_DEPTH (default 10)
# final runs: HISTORY_DEPTH=8, "all checks as expected" (10m44s); length 10 run separately
```

Tool locations default to `${FV_HOME:-$HOME/.local/share/mkit-fv}/apalache-0.62.2`
(`APALACHE_MC`, `TLA2TOOLS` override; TLC defaults to the Apalache jar).
`JAVA_HOME` defaults to `/usr/libexec/java_home -v 21`, then Homebrew's
`openjdk@21`. Heaps: TLC `-Xmx4g`, 4 workers (`TLC_HEAP`, `TLC_WORKERS`);
Apalache `JVM_ARGS=-Xmx4g`. Timings are on a shared 15-core M-series Mac
with other checkers running, 2026-09-26.

Results of the final run (`check.sh` output, abridged):

```text
quint test history (7 passing), scrub (realLapBoundTest, realLapTest)    ok
quint run history::Safety (50,000 traces x 30 steps)                      ok
quint run canaries x6, each mutant::its invariant x12                      violation
quint run mutLoadIgnoresTx::ServedMatchesRef / ServedGenerationFresh        ok
quint run mutRecoverSkipsPending::Safety                                  ok
quint run scrub/scrubLossy/scrubClockBack/mut* (16 steps)                 as in the table
tlc history::Safety                                   ok         200,388 distinct (VIEW), depth 37, 12s
tlc history::IntentEventuallyCleared                  ok         400,776 distinct (VIEW + calm), under 1 min
tlc history::IntentEventuallyCleared, no WF(RecoverAttempt)  liveness violation
tlc history::CanaryNoCalmIntent                       violation
tlc mutLoadIgnoresTx::NoProofWhileIntent              violation  (837 distinct)
tlc mutRawIgnoresTx::RecoveryEnabled                  violation  (477)
tlc mutRawIgnoresTx::NeverFailsClosed                 violation  (1,813)
tlc mutRawSkipsInvalidate::GenerationFastForwardOnly  violation  (6,801)
tlc mutRawSkipsInvalidate::ServedGenerationFresh      violation  (11,561)
tlc mutGcIgnoresIntent::IntentRootsRetained           violation  (107)
tlc mutHealTipOnly::CurrentMatchesRef                 violation  (52,411)
tlc mutReuseGenOnRewrite::GenerationFastForwardOnly   violation  (57,388)
tlc mutFreshGenOnFF::FastForwardRetainsGeneration     violation  (1,426)
tlc mutSkipVerify::IntentRootsRetained                violation  (35)
tlc mutFinishAnyRef::FinishOnlyFromRecorded           violation  (1,803)
tlc mutWriteBeforeInvalidate::CurrentMatchesRef       violation  (1,499)
tlc mutRecoverSkipsPending::Safety                    ok         148,902 distinct
tlc mutRecoverSkipsPending::IntentEventuallyCleared   liveness violation
tlc mutRawIgnoresTx::IntentEventuallyCleared          liveness violation
tlc scrubUnbounded::{ActualPublishBound,TimeBound,InvalidForcesFull}  ok  1,904 distinct each
tlc scrubUnbounded::SpecPublishBound                  violation  (init vt=7, three window publishes)
apalache history::Safety                        length 8   NoError   124s
apalache history::Safety                        length 10  NoError   471s (7m51s)
apalache history::Safety                        length 12  not finished: stopped after 36 min (over budget) while
                                                           checking step 12, no violation reported up to then
apalache history::CanaryNeverServed             length 7   violation  10s
apalache mutGcIgnoresIntent::IntentRootsRetained length 7  violation   8s
apalache mutFreshGenOnFF::FastForwardRetainsGeneration length 8  violation 11s
apalache mutSkipVerify::IntentRootsRetained     length 7   violation   7s
apalache mutFinishAnyRef::FinishOnlyFromRecorded length 7  violation   9s
apalache mutWriteBeforeInvalidate::CurrentMatchesRef length 7  violation 14s
apalache scrub::ActualPublishBound,TimeBound,InvalidForcesFull length 8  NoError 39s
apalache scrub::SpecPublishBound                length 8   violation   4s
apalache mutTrustInvalid::InvalidForcesFull     length 8   violation   3s
apalache scrubLossy::ActualPublishBound         length 8   violation   5s
```

Each Apalache run is `apalache-mc check --init=q_init --next=q_step
--inv=q_inv --length=N M.tla` on the output of `quint compile --target
tlaplus --main <module> --invariant <inv>`. Earlier results (Apalache
0.47.2, which predates the FoldSet soundness fixes; the models use `fold`)
are superseded by these. Bounded Apalache runs are not proofs; the TLC runs
are exhaustive for the finite instances described above, nothing more.

## Findings

Status against the SPEC-HISTORY-PROOF text on this branch (including the
§4.1/§4.5 spec text fixes in this PR).

1. **Scrub lap is 65 publishes, not 64.** Fixed in the spec: §4.5 now
   gives `floor((vt-1)/window) + 1`, at most 65. `window = max(512, vt/64)`,
   and the window path runs only while `cursor + window < verified_through`;
   65 occurs whenever `vt >= 32768` and `vt` is not a multiple of 64 (e.g.
   `vt = 32769` or `999999`); `realLapBoundTest` shows 65 is also the
   maximum. Minimal scaled counterexample to the old claim (TLC, Apalache,
   quint): a full verify with `vt=7`, `w=2`, then 3 window publishes cover
   `[0,6)`, and leaf 6 is not read again until the 4th publish.
2. **The 7-day boundary is off by one (open).** §4.5 permits the window path
   only when *fewer than* 604800 s have elapsed. The code uses the window
   path when `now - last_full_verify_unix <= 604800` (`stale` is
   `> SCRUB_MAX_AGE_SECS`), so at exactly 604800 s it takes the window path.
   Either the spec should say "at most" or the code should use `>=`.
3. **The publish bound depends on the scrub write landing.** Fixed in the
   spec: §4.5 now says the 65-publish bound does not hold when the advisory
   write is lost and only the 7-day bound applies. `write_scrub_state`'s
   result is discarded (`let _ =`), the write is not synced
   (`write_atomic(.., false)`), and a crash between `finish` and that write
   loses the advanced cursor (`scrubLossy` falsifies `ActualPublishBound`,
   keeps `TimeBound`).
4. **The time bound assumes a wall clock that never steps back.** Now stated
   in §4.5 (`saturating_sub` counts a future `last_full_verify_unix` as 0 s
   elapsed; `scrubClockBack`).
5. **§4.5's scrub encoding was out of date.** Fixed in the spec: §4.5 now
   has `"MKSC" || u8(2) || generation[32] || ...` (93 bytes) with the
   generation binding, and §4.1 lists `scrub`.
6. **The 7-day bound only applies when a publish happens.** Now stated in
   §4.5 ("evaluated only when a fast-forward publish runs"); `TimeBound` is
   stated at publish time. Served proofs do not depend on the scrub
   (`AncestrySnapshot::load` re-walks the chain).

The history state machine itself (§4.3–§4.4, deletion and recreate) showed
no safety or progress violation in the modelled instance.

## Limitations

- One branch; repository id and ref-name context checks are single-valued;
  checksums and corruption of history metadata are not modelled (the Rust
  tests `tampered_snapshot_and_transaction_fail_closed` cover them).
- GC is atomic with respect to publication. This assumes every branch-moving
  command holds a `worktree.lock` or `worktrees.lock` that GC also takes, per
  the SPEC-CONCURRENCY §4 table (the git bridge's import phase takes no
  `worktree.lock`, but writes only tags and remote-tracking refs; its branch
  fast-forward takes `worktree.lock`). GC's grace window is not modelled.
- Ref writes that bypass `RefMutation` (for example the file transport's own
  `refs/` tree, SPEC-CONCURRENCY §3.1) are outside the model.
  `mutRawSkipsInvalidate` shows such a writer could revive a generation
  through ABA if it ever shared a history-enabled common dir.
- Branch rename (§1: fresh generation) is not modelled separately; with one
  branch it is a delete of the old name plus a first publication of the new.
- The scrub model uses scaled constants (see above for why the scaling is
  faithful); with the real constants, the lap length is checked
  arithmetically (`realLapBoundTest`, exhaustive up to the 1,000,000-leaf cap).
- Object loss other than GC (bit rot, a torn write) is not modelled in
  `history.qnt`, so a published tip's chain stays present; `scrub.qnt` covers
  the schedule that re-reads it.
- `IntentEventuallyCleared` assumes fair callers and finitely many crashes;
  it is checked only in the finite instance and only by TLC (Apalache runs
  are safety only). It relies on the VIEW being a bisimulation quotient (see
  `tlc/MC.tla`); the unreduced instance exceeds 7,000,000 states at depth 27
  and was not run to completion.
- TLC from the Apalache jar prints a build-time-less version string (the
  current timestamp); the jar is identified by its sha256 above.
