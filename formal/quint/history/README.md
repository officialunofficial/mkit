# History publication and recovery (MKIT-20)

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

**Reachability canaries (each must be violated):** `CanaryNeverServed`,
`CanaryNoCrashRecovery`, `CanaryNoMultiCommitFF`, `CanaryNoRecreate`,
`CanaryNoGcDuringIntent`, `CanaryNoServedFF`.

**Scenario tests:** `boundary0Test`–`boundary4Test` crash a 1→3 fast-forward
after each persisted boundary, run GC, then retry. They require the intent to
be withheld and GC-rooted, and require the whole chain `[1,2,3]` in the
reused generation after recovery. `rawAbaTest` and `deleteRecreateTest`
require a fresh generation.

**Recovery liveness** is checked in safety form. `RecoveryEnabled` shows that
from every reachable idle state with an intent, `finish` is enabled. `finish`
is deterministic, and its remaining five durable steps lead to a state
satisfying all invariants with the intent removed; the boundary tests execute
this path. Liveness under an unbounded number of crashes is not claimed: a
crash can always interrupt recovery.

**Bounds:** commits {1,2,3,4} in the first-parent forest 1←2←3, 1←4; at most
3 generations minted; one branch. TLC explores the whole reachable space of
this instance, at every depth. Quint simulation runs traces of up to 30
steps. Apalache checks depth 10.

## scrub.qnt

The model tracks, per leaf, the publish and real time at which the leaf was
last read from the store. It covers:

- fast-forward publishes, using the window path or the full walk exactly as
  in `decide_chain`, including the `end <= prefix.len()` rollback guard;
- rewrites, which get a new generation;
- corrupt, missing or foreign-generation scrub state;
- optionally, lost scrub writes (`scrubLossy`) and a wall clock that steps
  backwards (`scrubClockBack`).

The constants are scaled: `MIN_WINDOW=2`, `LAP_FRACTION=4`, `MAX_AGE=3`
(real values 512, 64 and 604800), with chains of at most 14 leaves.
`realLapTest` evaluates the lap-length formula with the real constants.

| Property | Result |
|---|---|
| `ActualPublishBound`: no leaf goes more than `LAP_FRACTION+1` publishes unread | holds (TLC, unbounded publishes); falsified by `mutWrapWithoutFull` |
| `TimeBound`: after a publish, every leaf was read within `MAX_AGE` | holds, including with lost writes; falsified by `mutIgnoreAge` and `scrubClockBack` |
| `InvalidForcesFull`: invalid scrub state always forces a full walk | holds; falsified by `mutTrustInvalid` |
| `SpecPublishBound`: "at 64 fast-forward publishes" | **violated** (finding 1) |
| `WindowOnlyWhenFresh`: window only if "fewer than" 7 days elapsed | **violated** (finding 2) |

## Commands and outcomes

```sh
./check.sh              # quint typecheck/test/run and TLC: "all checks as expected" (~6 min)
APALACHE=1 ./check.sh   # adds Apalache 0.47.2 bounded runs
```

Individual commands (all run for MKIT-20, with the results shown):

```sh
quint test history.qnt --main history            # 7 passing
quint test scrub.qnt --main scrub                # realLapTest passing
quint run history.qnt --main history --invariant Safety \
  --max-steps 30 --max-samples 50000 --backend rust              # [ok]
quint run history.qnt --main <mutant> --invariant <inv> ...      # [violation], per table
quint compile --target tlaplus --main history --invariant Safety history.qnt > history.tla
java -cp /opt/fv/tla2tools.jar tlc2.TLC -deadlock -config tlc/MC.cfg tlc/MC.tla
  # No error: 9,903,627 states generated, 200,388 distinct (view) states, depth 37
apalache-mc check --init=q_init --next=q_step --inv=q_inv --length=10 history.tla
  # Apalache 0.47.2, Safety: "no error up to computation length 10" (25m35s,
  # before FastForwardRetainsGeneration was added; with it: length 8, 4m06s)
  # CanaryNeverServed violated at depth 6; mutGcIgnoresIntent violated at depth 3;
  # mutFreshGenOnFF at 7, mutSkipVerify at 2, mutFinishAnyRef at 5
apalache-mc check ... --length=8 scrub.tla   # ActualPublishBound,TimeBound,InvalidForcesFull: NoError (49s)
                                             # SpecPublishBound: violated at depth 4
                                             # mutTrustInvalid InvalidForcesFull: violated at depth 2
```

## Findings

1. **Scrub lap is 65 publishes, not 64.** `window = max(512, vt/64)`, and the
   window path runs only while `cursor + window < verified_through`, so a lap
   takes `floor((vt-1)/window) + 1` publishes. That is 65 whenever
   `vt >= 32768` and `vt` is not a multiple of 64, e.g. `vt = 32769` or
   `vt = 999999`. The minimal scaled counterexample (TLC and quint): a full
   verify with `vt=9` and `w=2`, then 4 window publishes cover `[0,8)`, and
   leaf 8 is not read again until the 5th publish.
2. **The 7-day boundary is off by one.** §4.5 permits the window path only
   when *fewer than* 604800 s have elapsed. The code uses the window path when
   `now - last_full_verify_unix <= 604800` (`stale` is `> SCRUB_MAX_AGE_SECS`),
   so at exactly 604800 s it takes the window path.
3. **The publish bound depends on the scrub write landing.**
   `write_scrub_state`'s result is discarded (`let _ =`), the write is not
   synced (`write_atomic(.., false)`), and a crash between `finish` and that
   write loses the advanced cursor, so the same window is re-read. In that case `ActualPublishBound` fails (`scrubLossy`); only the
   7-day bound holds.
4. **The time bound assumes a wall clock that never steps back.** With
   `saturating_sub`, a `last_full_verify_unix` in the future counts as 0 s
   elapsed, so a clock step-back delays the 7-day full walk
   (`scrubClockBack`).
5. **§4.5's scrub encoding is out of date** (doc drift). The spec has
   `"MKSC" || u8(1)` with no generation and a 61+32 layout; the code writes
   `MKSC\x02 || generation[32] || cursor || verified_through || last_full ||
   BLAKE3` (93 bytes) and discards state whose generation does not match.
   §4.1's layout also omits the `scrub` file.

The history state machine itself (§4.3–§4.4, deletion and recreate) showed
no violation.

## Limitations

- One branch; repository id and ref-name context checks are single-valued;
  checksums and corruption of history metadata are not modelled (the Rust
  tests `tampered_snapshot_and_transaction_fail_closed` cover them).
- GC is atomic with respect to publication. This assumes every branch-moving
  command holds a `worktree.lock` or `worktrees.lock` (`branch -d`/`-m`) that
  GC also takes, per the SPEC-CONCURRENCY §4 table. GC's grace window is not modelled.
- Ref writes that bypass `RefMutation` (for example the file transport's own
  `refs/` tree, SPEC-CONCURRENCY §3.1) are outside the model.
  `mutRawSkipsInvalidate` shows such a writer could revive a generation
  through ABA if it ever shared a history-enabled common dir.
- Branch rename (§1: fresh generation) is not modelled separately; with one
  branch it is a delete of the old name plus a first publication of the new.
- The scrub model uses scaled constants; the real-constant lap length is
  checked arithmetically only (`realLapTest`).
