# quint-advance: `advance_refs`, the retry ladder and the #521 gate

A Quint model of how mkit advances a branch on a remote (formal verification
effort, PR #1082). The advance writes the packmap with a CAS, then the head
with a CAS. The model covers crashes and connection loss between and after
those writes, lost responses, the transport retry ladder, the `read_ref`
disambiguation, concurrent pushers, and the re-baseline gate from PR #521.
The normative text is the spec on this branch: SPEC-TRANSPORT §7 and
SPEC-TRANSPORT-CONNECT §3, §4 and §7.1 to §7.3 as reconciled here.

| File | Contents |
|------|----------|
| `advance.qnt` | The model: module `advance`, then its instances, mutants and documented-gap witnesses |
| `advance_test.qnt` | Pinned interleavings: the SPEC behaviour, every mutant, both gaps |
| `check.sh` | Runs every check below and compares each result with the expected one |

## What is modelled, and where it lives in the code

| Model step | Code |
|---|---|
| `start`: read the remote head R, plan closure(tip) minus closure(R), take the head-only path if that is empty, run the re-baseline gate | `mkit-cli` `remote_dispatch::push_branch_with_limits` |
| `loop`: one iteration of the packmap CAS loop. It reads the packmap; if our pack is already chained it commits the head alone; otherwise it builds node = prior ++ [ours] (or [ours] on a reset) | `remote_dispatch::packmap::advance_packmap` (`PACKMAP_CAS_ATTEMPTS`) |
| `srvAdvAtomic`: packmap and head in one batch, with an optional replay ledger | `mkit-server` `Pipeline::apply_atomic` on an `atomic_multi_key` store; HTTP `/refs/advance` |
| `srvAdvFirst`, `srvAdvSecond`: packmap CAS, then head CAS, as two writes that are each durable | `Transport::advance_refs` default (file, S3, SSH, memory); `mkit-server` `plan_and_apply` on a non-atomic store; `HttpTransport::advance_refs_ordered` |
| `srvCrash`: the server or connection dies between the two ordered writes | the unary timeout (`ConnectTransport` `unary_timeout`) surfaces it as `ConnectionFailed` |
| `srvUpd`: `update_ref(head, cond, tip)` | `packmap::commit_head` |
| `lose`: the response is lost; the ladder re-issues the same request or gives up | `mkit_core::protocol::retrying`, `BackoffIterator`; `RetryIdentity` |
| `deliver`, `readHead`: map the outcome. On `HeadConflict` or `RefConflict`, run `read_ref(head)`: if it returns our tip the push landed, otherwise it is NonFastForward | `advance_packmap`, `commit_head`, `head_conflict` (SPEC-TRANSPORT §7) |
| `crash`: the pusher dies with an ordered advance half applied, or after the server applied a request | a local `mkit+file://` push that dies mid-advance |

Abstraction and bounds:

- Commits 0 to 6 form a fixed DAG: 1 and 2 are children of 0, 3 is a child
  of 1, 4 a child of 2, 5 a child of 3, and 6 a child of 4. An object is a commit, and
  closure(c) is c plus its ancestors.
- An append pack for a push planned against R carries closure(tip) minus
  closure(R). It is modelled as needing every object of closure(R) as a
  delta base, which is the most demanding case. A reset pack is
  self-contained.
- The packmap value is the chain of pack ids, oldest first. Node keys are
  content-addressed, so equal chains mean equal keys. Pack 0 is the seed
  push. Reconstruction folds the chain oldest first. A node whose bases are
  not yet reconstructable breaks the chain, and fetch then fails.
- Each pusher runs one push, and pusher tips are distinct.
- Pack uploads are always present. The model has no pack GC; that is
  covered by `formal/quint/gc`.
- `push_branch` reads the head and then probes the packmap. The model does
  both in one step. The probe only chooses between reset and append, and
  every write is re-validated by CAS afterwards.
- A request lost before the server applies it only uses up a ladder attempt,
  which `lose` already covers.
- A client crash is modelled only where it leaves remote state behind:
  `advSrv2` (half applied) and `resp` (applied, outcome unseen). A crash
  anywhere else behaves like a pusher that never takes another step.
- The replay ledger keeps one stored result per pusher, keyed by the nonce
  of its current logical call. Ledger expiry is not modelled.
- Explicit bounds: 2 pushers (the `*2` instances; `http1` has 1) or 3
  pushers (`*3`); `ATTEMPTS` = 3 loop iterations (the code allows 8);
  `LADDER` = 2 re-issues (the code allows 4); `THRESH` = 1, so every
  non-empty push asks to re-baseline and the gate alone decides.

## Invariants

| Name | Statement | Source |
|---|---|---|
| `DeltaTransfer` | If the head resolves to T, the packmap reconstructs closure(T), with no broken node | `Transport::advance_refs` doc (protocol.rs); SPEC-TRANSPORT-CONNECT §4 |
| `SuccessSound` | A push reported as success had its tip on the head after it started | SPEC-TRANSPORT §7 |
| `ConflictHonest` | A push reported NonFastForward never wrote the head, or its write has since been overwritten | SPEC-TRANSPORT §7 (`read_ref` before reporting a conflict) |
| `NoLostUpdate` | Every head write with `Match(e)` replaced exactly e | SPEC-REFS §5; concurrent pushers never lose an update (CAS level) |
| `NoLostSuccess` | When every pusher is a fast-forward (`Match(e)` with a tip descending from e), a push reported as success stays in closure(head). True by definition on instances with a force push or a non-fast-forward lease | concurrent pushers never lose an update (user level) |
| `NoStuckPusher`, `BoundedRetries` (together `Progress`) | A pusher mid-push always has a step; the loop and ladder counters stay in range | progress |
| `Termination` | `<>(every pusher is done or dead)` under weak fairness of `step` | progress; a TLC temporal property that `check.sh` (`live`) builds on the compiled TLA+ |

`Safety` = `DeltaTransfer`, `SuccessSound`, `ConflictHonest`,
`NoLostUpdate` and `NoLostSuccess`. `All` = `Safety` and `Progress`.

`Termination` is checked by TLC on every two-pusher safe instance (and
`http1`), without the VIEW, since TLC does not combine a VIEW with liveness
checking. On the three-pusher instances it rests on this argument:

- Every `loop` step that issues a call raises `attempts`, and `loop` stops
  at `ATTEMPTS` (`BoundedRetries`).
- Within one iteration, each call is re-issued only by `lose`, which lowers
  `ladder`, and `ladder` never goes below 0 (`BoundedRetries`).
- Every other step moves pc forward within the iteration:
  `advSrv`, `advSrv2`, `resp`, `readHead`, `done`.
- The only way back is `deliver` on `PackmapConflict`, which returns to
  `loop`, and that `loop` raises `attempts` again.

So a push takes at most about `ATTEMPTS * (LADDER + 1) * 4` steps. Every
run is finite, provided no pusher is stuck (`NoStuckPusher`). The
`noTimeout` mutant shows that `NoStuckPusher` and `Termination` are not
vacuous, and the `noLadderBound` mutant (a ladder that never runs out)
shows that `Termination` depends on the ladder bound.

## Instances and expected results

| Instance | Transport / store | Pushers (tip, head condition) | Expected |
|---|---|---|---|
| `ordered2`, `ordered3` | ordered | 1 Match(0), 2 Match(0) [, 3 Any] | `All` ok |
| `atomic2`, `atomic3` | atomic, no ledger | 1 Match(0), 2 Match(0) [, 3 Match(1)] | `All` ok |
| `ledger2`, `ledger3` | atomic + replay ledger | as atomic | `All` ok |
| `atomicAny3` | atomic | 1 Match(0), 2 Match(0), 3 Any | `All` ok |
| `http1` | HTTP (atomic; `Any` falls back to ordered) | 2 Any over head 1 | `All` ok |
| `forceFF2` | atomic | head 3; 1 Match(3) to 5 (fast-forward, re-baselines), 2 Any to 1 (head-only) | `All` ok |
| `noop2` | ordered | head 5; 1 Match(5) to 1, 2 Match(5) to 3 (both head-only) | `All` ok |
| `ledger2_oldConflict` | atomic + ledger, old client | | `All` ok. SPEC-TRANSPORT §7: "MAY skip the `read_ref` only when it knows the remote keeps that ledger" |
| `gapNoopAny2` | atomic | head 3; 1 Match(3) to 2 (not fast-forward), 2 Any to 1 (head-only) | `DeltaTransfer` violated: **finding F2** |
| `gapTwoAny3` | atomic | head 3; 3 Any to 4 (sideways), 1 Match(4) to 6 (fast-forward, re-baselines), 2 Any to 1 (head-only) | `DeltaTransfer` violated: **finding F2**, fast-forward leases only |
| `gapAppendAny2` | atomic | head 3; 1 Match(3) to 2 (not fast-forward), 2 Any to 5 (non-empty plan, appends) | `DeltaTransfer` violated: **finding F2**, appending variant |
| `gapAppendTwoAny3` | atomic | head 3; 3 Any to 4, 1 Match(4) to 6 (re-baselines), 2 Any to 5 (appends) | `DeltaTransfer` violated: **finding F2**, appending variant, fast-forward leases only |
| `gapHttpAny2` | HTTP | 1 Match(0) to 1 (re-baselines), 2 Any to 2 | `DeltaTransfer` violated: **finding F1** |

Mutants (non-vacuity). Each must violate the invariant named:

| Mutant | Fault | Violates |
|---|---|---|
| `ordered2_oldConflict`, `atomic2_oldConflict` | the pre-reconciliation client: a conflict means NonFastForward, with no `read_ref` | `ConflictHonest` (a spurious NonFastForward on a landed, re-issued write) |
| `ordered2_trustConflict` | a conflict means success, with no `read_ref` | `SuccessSound` |
| `ordered2_noGate` | pre-#521: re-baseline on a non-transactional advance | `DeltaTransfer` (stranded head) |
| `http1_gateNoAny` | the gate without its `Any` clause | `DeltaTransfer` |
| `ordered2_headFirst` | ordered advance writes the head before the packmap | `DeltaTransfer` |
| `noop2_splitCas` | server head CAS as an unlocked read, then write | `NoLostUpdate` |
| `ordered2_splitCas` | the same, on fast-forward pushers (pinned in `splitCasFF_test`) | `NoLostSuccess` (and `NoLostUpdate`) |
| `ordered2_noTimeout` | a server crash mid-request never reaches the client | `NoStuckPusher`, `Termination` |
| `ordered2_noLadderBound` | the retry ladder re-issues forever | `Termination` |

Canaries (reachability, each must be violated): `CanaryNoReset`,
`CanaryNoAppendSuccess`, `CanaryNoReissueAfterLanded`,
`CanaryNoDisambiguatedSuccess`, `CanaryNoNff`, `CanaryNoTornAdvance`,
`CanaryNoPackmapConflict`, `CanaryNoReplayed` and
`CanaryNoConcurrentSuccess`. `WitnessLandedThenNff` is also expected to be
violated; see "Residual ambiguity" below.

## Results

Recorded on 2026-09-27 in a clean environment. The default mode (quint test,
quint run and TLC, including `Termination`) is "all checks as expected" in
481 s. `APALACHE=1 QUINT=0 TLC=0 ./check.sh` gives 10 Apalache checks as
expected in 13m47s: `ordered2::All` 137 s, `atomic2::All` 96 s and
`ledger2::All` 90 s at length 8; `ordered2_oldConflict` at length 10 138 s;
`noGate` 19 s; `gapNoopAny2` 14 s; `gapHttpAny2` 27 s; `gapTwoAny3` 265 s;
`gapAppendAny2` 17 s; `noop2_splitCas` 11 s. A full `APALACHE=1 ./check.sh`
takes about 20 to 26 min.
Bounded does not mean proved. Each line below holds only within the bounds
in "Abstraction and bounds".

- **quint test**: all 15 pinned runs pass, across 11 test modules in
  `advance_test.qnt`.
- **quint run** (40 steps, 20000 samples, seed 0x1): `All` holds on every
  safe instance. Every mutant, gap witness and canary listed in `check.sh`
  is reached.
- **TLC** (exhaustive, `All` under the VIEW):

  | Instance | Distinct states | Time |
  |---|---|---|
  | `ordered2` | 12,677 | |
  | `atomic2` | 3,593 | |
  | `ledger2` | 1,545 | |
  | `http1` | 42 | |
  | `forceFF2` | 1,254 | |
  | `noop2` | 1,194 | |
  | `ledger2_oldConflict` | 1,329 | |
  | `ordered3` | 7,649,633 | 94 s |
  | `atomic3` | 1,366,702 | 18 s |
  | `ledger3` | 172,050 | 5 s |
  | `atomicAny3` | 2,254,898 | 30 s |

  Each of the 7 two-pusher runs (and `http1`) takes under 10 s. TLC reaches
  every mutant's violation, every gap witness, and the three canaries it
  checks.
- **TLC `Termination`** (temporal, weak fairness, no VIEW): holds on
  `ordered2` (27,345 distinct states), `atomic2` (7,491), `ledger2`
  (3,241), `http1` (59), `forceFF2` (2,597), `noop2` (2,507) and
  `ledger2_oldConflict` (2,827), each in under 20 s. Violated, as expected,
  by `ordered2_noTimeout` and `ordered2_noLadderBound`.
- **Apalache** (bounded symbolic, `apalache-mc` 0.62.2):
  - `All` holds on `ordered2` (136 s), `atomic2` (86 s) and `ledger2`
    (93 s), each for every run of length 8 or less.
  - Length 12 on `ordered2` alone ran past 35 minutes and was stopped, so
    the default is 8.
  - Violations found at the lengths of their pinned witnesses:

    | Instance | Invariant | Length | Time |
    |---|---|---|---|
    | `ordered2_oldConflict` | `ConflictHonest` | 10 | 154 s |
    | `ordered2_noGate` | `DeltaTransfer` | 8 | |
    | `gapNoopAny2` | `DeltaTransfer` | 5 | |
    | `gapHttpAny2` | `DeltaTransfer` | 7 | |
    | `gapTwoAny3` | `DeltaTransfer` | 8 | 320 s |
    | `gapAppendAny2` | `DeltaTransfer` | 6 | 16 s |
    | `noop2_splitCas` | `NoLostUpdate` | 7 | |

## Findings

**F1: an HTTP force push can be stranded by a concurrent re-baseline.**
Instance `gapHttpAny2`, pinned in `gapHttpAny_test`.

On `HttpTransport`, `supports_atomic_advance()` returns `true`, but an `Any`
condition falls back to the ordered two-PUT path. The #521 gate stops the
force push from resetting the chain itself, and the doc comment on
`HttpTransport::supports_atomic_advance` concludes that "force pushes take
the safe append path". That argument only considers the force push on its
own. The failing interleaving:

1. p2 (Any, tip 2) PUTs packmap [0, 2].
2. p1, a fast-forward push with `Match(0)`, re-baselines atomically: packmap
   `Match([0, 2])` becomes [1], and the head `Match(0)` still holds, so it
   moves to 1.
3. p2 PUTs head = 2.

The head is now 2, but the packmap reconstructs only closure(1).

The same ordered fallback also admits the appending shape of F2 (p2
re-reads a reset packmap after a `PackmapConflict` and appends onto it).

The CLI no longer constructs `HttpTransport` for push (`mkit+https` uses
`ConnectTransport`), so this is latent. It is reachable wherever
`push_branch` runs over a transport that reports atomic advance but falls
back to ordered writes for some calls.

**F2: a force push can be stranded by a concurrent re-baseline.**
Instances `gapNoopAny2`, `gapTwoAny3` (head-only) and `gapAppendAny2`,
`gapAppendTwoAny3` (appending), pinned in `gapNoopAny_test`,
`gapTwoAny_test` and `gapAppendAny_test`. This happens on a genuinely
atomic transport.

Head-only variant:

1. p2 force-pushes (Any) a tip that is already inside closure(R). Its plan
   is empty, so it takes `commit_head` only (the same holds for the
   idempotent short-cut in `advance_packmap`).
2. Before p2's head write, p1 re-baselines atomically to a tip whose
   closure does not contain p2's tip. p1's head condition `Match(3)` still
   holds.
3. p2's `Any` head write lands on top of the reset packmap.

`forceFF2` shows the same race is safe when p1 is a fast-forward push and
no other force push intervenes, because a fast-forward reset keeps
closure(old head). The unsafe case needs the reset closure to lose objects
that were in the head p2 planned against. That happens with a
`--force-with-lease` that is not a fast-forward (`gapNoopAny2`). It also
happens with fast-forward leases only (`gapTwoAny3`, pinned in
`gapTwoAny_test`):

1. p3 force-pushes the head sideways from 3 to 4.
2. p1 fast-forwards 4 to 6 with a reset.
3. p2, which planned its head-only `Any` write of 1 against head 3, lands
   it. Closure(1) is not inside closure(6).

Appending variant (`gapAppendAny2`): the force push has a non-empty plan,
so its pack needs closure(R) as delta bases (R = the head it planned
against).

1. p2 force-pushes (Any) 5 against head 3; the gate keeps it appending.
2. p1's lease `Match(3)` re-baselines atomically to 2: packmap [closure(2)].
3. p2's `advance_packmap` iteration reads the reset packmap, builds
   [closure(2), p2's pack] and commits: the packmap precondition is
   `Match` of the value it just read, and `Any` always holds.

The head is 5, but p2's pack needs closure(3), which the reset dropped:
fetch cannot resolve the chain. `gapAppendTwoAny3` reaches the same state
with fast-forward leases only (p3 force-pushes 3 to 4 first, p1
fast-forwards 4 to 6 with a reset). The loop's packmap re-read is what lets
it through: `advance_packmap` validates the re-read chain's integrity
(`resolve_pack_chain`), not that it still holds the pack's delta bases.

It is latent today: `ConnectTransport::supports_atomic_advance()` defaults
to false and the CLI never opts in (SPEC-TRANSPORT-CONNECT §7.3). It becomes
reachable when a v2 client reads `atomic_advance` from `GetServerInfo`, as
§7.3 plans.

SPEC-TRANSPORT-CONNECT §7.3 calls the missing reset "a (temporary) loss of
the packmap-compaction optimization, not a correctness gap". That is true
today. Enabling atomic advance adds F2 unless the gate also accounts for
concurrent `Any` writers. A fix has to cover both variants. For the
head-only write, send it as an `advance_refs` whose packmap precondition is
`Match` of a packmap value the client checked reconstructs the tip (a check
followed by a plain `update_ref` is racy). For the appending write, re-plan
(restart `push_branch`) when the re-read packmap is not an extension of the
chain the plan was made against, instead of appending onto it.

**Residual ambiguity of the `read_ref` rule (spec ambiguity, informational).**
Witness `WitnessLandedThenNff`, reachable in `ordered3` and `atomic3`.

SPEC-TRANSPORT §7 says what to do when `read_ref` returns the caller's
value. When it returns another value, the caller cannot tell "never landed"
from "landed, then another pusher built on it". The push is then reported
NonFastForward even though its commit is in the remote history. This is
safe: nothing is lost, and a fetch shows the commit. The spec does not say
it, though, and `ConflictHonest` is stated to allow it.

**Code status of the §7 disambiguation.** At the time of checking, the
working tree's `packmap.rs` has `head_conflict`, which runs `read_ref(head)`
on `HeadConflict` and `RefConflict`. This matches the model's SPEC client.
The `PackmapConflict` arm re-reads the packmap through the loop and takes
the idempotency short-cut (our keys anywhere in the chain), which is at
least as strong as §7's "a packmap that already holds the caller's node".
A reset takes no short-cut: it rewrites the same node and resolves through
`HeadConflict` and `read_ref` (pinned in `atomic_test`). The old behaviour
survives only as the `*_oldConflict` mutants.

## Running

```sh
./check.sh               # quint typecheck + test + run, then TLC
TLC=0 ./check.sh         # skip TLC
TLC3=0 ./check.sh        # skip the 3-pusher TLC runs (the longest ones)
APALACHE=1 ./check.sh    # add the bounded apalache-mc runs
```

Pins, the same as `formal/quint/refs` (from the verification toolchain review):

- quint 0.32.0.
- Apalache 0.62.2, run directly on the TLA+ that
  `quint compile --target tlaplus` produces. quint uses its bundled
  Apalache only to transpile.
- TLC is `tlc2.TLC` from the Apalache 0.62.2 jar.
- Java 21.

Tool locations default to `${FV_HOME:-$HOME/.local/share/mkit-fv}` and can
be overridden with `APALACHE_MC` and `TLA2TOOLS`. `JAVA_HOME` defaults to
`/usr/libexec/java_home -v 21`, then Homebrew's `openjdk@21`.

Knobs:

- Memory: `TLC_HEAP` (default 4g), `TLC_WORKERS` (default 2),
  `APALACHE_HEAP` (default 4g).
- `QUINT=0` skips `quint run`.
- `ONLY=<regex>` restricts TLC and Apalache to matching
  `<module>::<invariant>` checks.
- `STEPS` (default 40) and `SAMPLES` (default 20000) set the `quint run`
  depth and sample count.
- `ADV_DEPTH` (default 8) sets the Apalache length for the safe instances.

TLC runs `All` under a VIEW that drops only `lastAction`. That is sound for
`Safety`, `Progress` and their conjuncts, because no guard and none of them
reads `lastAction`. The canaries do read it, so they run without the VIEW.
