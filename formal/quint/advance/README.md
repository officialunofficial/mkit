# Atomic advance and guarded force pushes

This Quint model checks the delta-transfer invariant: if the remote head
resolves to T, its packmap reconstructs closure(T), without missing delta
bases. It includes ordered and atomic writes, crashes, lost responses,
replay-ledger responses, packmap conflicts, head conflicts and bounded retries.

| File | Purpose |
| --- | --- |
| `advance.qnt` | State machine, safe instances, mutants and reachability canaries |
| `advance_test.qnt` | Deterministic races, recovery and mutant witnesses |
| `check.sh` | Typechecking, pinned tests, simulation, exhaustive TLC and bounded Apalache |

## Client and transport behavior

Non-force behavior is unchanged. A push reads the remote head, plans a
pack, chooses append or atomic re-baseline, and retries packmap conflicts
within `ATTEMPTS`. Head conflicts use the existing fresh head read to
disambiguate a lost successful response from a rejected push.

On an atomic transport a force push captures a strong packmap read before
reading the head and planning. These reads are separate model actions:
a concurrent writer may change either value between them. The ticket pre-plan
may read the head first; both guards still compare the resulting mixed-time pair
at publication. The model fixes packmap-first order and exercises the
identical-root case explicitly.

A head-only force push uses atomic advance with a same-value packmap write
and `Match` on the captured packmap. An appending force push can reuse its
plan only if the current packmap chain extends the chain it captured.
Otherwise it captures fresh refs and re-plans, using the existing shared
`ATTEMPTS` budget. Exhaustion reports contention, rather than restarting an
unbounded outer loop. Every newly built request gets its own bounded
transport retry ladder; a ladder re-issues the identical request.

A force plan that depends on the observed head also guards that head with
`Match`. The packmap guard remains required. This matters even when the
packmap value matches: an atomic writer can restore an identical earlier
content-addressed root after another writer introduced a different head.
The pinned ABA scenario explicitly restores the seed root `[0]`.

Append packs conservatively require every object in closure(planning head)
as a delta base. Consequently all atomic force plans in this model carry
the head guard. The client can retain `Any` for a self-contained pack that
does not depend on the observed head. HTTP substitutes `Match(observed
head)` because its atomic endpoint cannot encode `Any`; it uses the same
packmap guard and never the ordered force fallback. Ordered transports
retain their existing behavior.

Pack ids include the force plan's base. A re-plan creates a new immutable
pack instead of changing the contents of a pack already in the remote chain.
A reset back to the seed closure may restore the same packmap root, allowing
ABA interleavings. Uploads are assumed available; pack garbage collection
has its own model in `formal/quint/gc`.

## Invariants and non-vacuity

| Predicate | Requirement |
| --- | --- |
| `DeltaTransfer` | The packmap reconstructs the current head's closure |
| `SuccessSound` | A reported success held its tip on the head after starting |
| `ConflictHonest` | A NonFastForward report did not leave its own head write standing |
| `NoLostUpdate` | A guarded head write replaced its expected value |
| `NoLostSuccess` | With fast-forward pushers only, successful history remains reachable |
| `Progress` | No stuck pusher; CAS and ladder counters remain bounded |
| `All` | Every safety and progress predicate above |
| `Termination` | Under weak fairness every pusher eventually finishes or dies |

The mutants retain the old conflict handling, unsafe ordered resets,
unlocked head CAS, reversed write order, absent timeout and unbounded retry
ladder. `http1_gateNoAny` deliberately restores the old unsafe HTTP force
fallback and reset gate; it still must violate `DeltaTransfer`. Reachability
canaries require resets, appends, torn writes, conflicts, replay and lost
responses to remain possible.

The existing `read_ref` ambiguity remains: a landed write that another
pusher then builds on can report NonFastForward when its later fresh head
read sees the descendant. `WitnessLandedThenNff` pins this safe ambiguity;
`ConflictHonest` permits an overwritten write.

## Former findings and regression scenarios

Before the guard and re-plan changes, TLC finds `DeltaTransfer` violations
in all five original gap instances:

| Instance | Original race |
| --- | --- |
| `gapHttpAny2` | An ordered HTTP force head write follows an atomic reset |
| `gapNoopAny2` | A head-only force push follows a sideways lease reset |
| `gapAppendAny2` | An old delta pack is appended onto a reset chain |
| `gapTwoAny3` | Two force pushes interleave with a fast-forward reset |
| `gapAppendTwoAny3` | The same three-pusher race with a delta pack |

These instances now require `All` to hold in simulation and TLC, and in
bounded Apalache where configured. Deterministic tests require recovery
rather than merely preventing the bad write. `gapAbaAny3` additionally
requires safety when independent reads span a change and the identical old
packmap root is restored before the force write.

The additional ABA instance uses `abaStep` to start the restoring lease only
after the intermediate head exists. Every original instance keeps `step`.
Starting that lease earlier exposes a separate unchanged non-force limit:
a lease can name a future head, plan a head-only rewind against the old
head, and later succeed after an incompatible reset. The deterministic
`futureLeaseNonforce_test` retains that counterexample explicitly. This
force-push change does not claim to repair the future-lease case.

The baseline TLC witnesses use 182, 47, 70, 1211 and 1954 distinct states,
respectively, in the table's order. These are counterexample search counts,
not counts for the repaired state space.

## Running

```sh
./check.sh                       # typecheck, pinned tests, simulation and TLC
APALACHE=1 ./check.sh            # also run bounded Apalache checks
TLC=0 ./check.sh                 # skip TLC
QUINT=0 TLC=0 APALACHE=1 ./check.sh
```

The pinned toolchain is Quint 0.32.0, Apalache 0.62.2 and Java 21. TLC is
`tlc2.TLC` from the Apalache jar. `quint compile --target tlaplus` uses its
bundled transpiler; checks run directly through the pinned checker.

`FV_HOME` defaults to `$HOME/.local/share/mkit-fv`; `APALACHE_MC`,
`TLA2TOOLS` and `JAVA_HOME` can override tool locations. The script defaults
to two TLC workers. `TLC_HEAP` and `APALACHE_HEAP` default to 4g.
`TLC3=0` skips three-pusher exhaustive runs. `ONLY=<regex>` restricts TLC
and Apalache by `<module>::<invariant>`. `STEPS` defaults to 40 and `SAMPLES`
to 20000 for seeded simulation. `ADV_DEPTH` defaults to 8 for the original
safe bounded checks; force regression lengths are listed in `check.sh`.

TLC's safety VIEW drops only `lastAction`; neither guards nor safety or
progress predicates read it. Canaries that read it and temporal termination
checks run without that VIEW.
