# quint-refs: ref CAS, lock order, server locks, served names

Quint models of mkit's ref concurrency (Linear MKIT-19, epic MKIT-17, PR
#1082), updated to the server-era specs on this branch: SPEC-REFS v3 and
SPEC-CONCURRENCY with `mkit-server`.

| File | What it models |
|------|----------------|
| `refs.qnt` | SPEC-REFS §5 CAS (Any / Missing / Match, deletes), §5.1 atomicity per lock domain (local `refs-<ref>.lock`, file-transport `RefLock`, memory `Mutex`), SPEC-CONCURRENCY §4 lock order and deadlock freedom, §3.2 recovery-log record/expire, §3.1 cross-domain gap |
| `refs_test.qnt` | Pinned interleavings for `refs.qnt`, mutants and witnesses included |
| `serve.qnt` | `serveLocks`: `serve.lock` (shared by `mkit serve` and `mkit-server`), `server.lock` (exclusive, `mkit-server`), the startup sweep of crashed uploads under an exclusive `serve.lock`, the worktree probe (SPEC-CONCURRENCY §2, §3.1). `servedNames`: SPEC-REFS v3 §2 served names and the §3 512-byte bound, as far as they affect safety |
| `serve_test.qnt` | Pinned interleavings for `serve.qnt` (`serve_test`, `served_test`) |
| `check.sh` | Runs every check below and compares each result with the expected one |

## What changed for the server-era specs

Source: `git diff e7257500 HEAD -- docs/specs/SPEC-CONCURRENCY.md docs/specs/SPEC-REFS.md`.

- **`serve.lock` / `server.lock`** (SPEC-CONCURRENCY §2 table, §3.1):
  every live server, `mkit serve` and `mkit-server serve`, holds
  `serve.lock` shared; `mkit-server` also holds `server.lock` exclusively.
  Modelled in `serveLocks` (invariants `ServeLockRW`, `OneMkitServer`,
  `UpServersHoldServeShared`, `NoMissedDetection`).
- **Startup sweep** (§3.1, "The one exclusive hold"): a starting
  `mkit serve` tries `serve.lock` exclusively without waiting, sweeps
  stale upload temp files in `packs/` only while it holds it, then drops it
  and takes the shared lock; busy means skip. Modelled against concurrent
  uploads of other servers, including a stalled streaming upload whose temp
  file is older than the age bound (`SweepAlone`, `NoLiveUploadSwept`).
- **Cross-domain gap now covers `mkit-server`** (§3.1): `mkit-server
  --meta fs-layout` writes refs through `FileTransport` under the same
  `<root>/.mkit/refs/.lock` (`FsLayoutStore::apply` ->
  `FileTransport::with_ref_lock`), so in `refs.qnt` a `file` op is a CAS
  from `mkit serve`, `mkit-server` or a `mkit+file://` push alike. The
  `WitnessCrossDomainGap` witness is still reachable, as documented.
- **Served names, SPEC-REFS v3 §2**, and the **512-byte bound, §3**:
  `servedNames` checks that a server refuses a name outside `refs/`, or
  one over the bound, on ReadRef / UpdateRef / both AdvanceRefs names,
  **before touching storage**, with an explicit error, never as absent;
  that a refused request writes nothing (no partial AdvanceRefs); and that
  a listing skips stored legacy refs (`<root>/main`, over-long names)
  (`RefuseBeforeStorage`, `ExplicitRefusal`, `RefusedWritesNothing`,
  `ListingServedOnly`). Names are abstract classes (served, outside
  `refs/`, over-long, grammar-invalid). **Which byte strings fall in which
  class is pure grammar, left to unit tests and conformance vectors**
  (`mkit_core::refs` tests; `mkit-server` `pipeline/tests.rs` and
  `ssh/tests.rs`), as are the derived local bounds (494 / 502 bytes) and
  prefix normalization (§4.2).
- **Memory transport**: `mkit-transport-memory`'s `update_ref` holds its
  `Mutex` across read-check-write, and SPEC-REFS §5.1 now says `atomic*`
  (in-process only). The former witness `WitnessMemMatchRace` is now the
  Safety conjunct `NoLostUpdateMem`; the old race survives as the
  `refs2_memNoMutex` mutant (also caught for Missing, which a HashMap
  cannot decide by O_EXCL).

## Running

```sh
./check.sh               # quint typecheck + test + run, then TLC
TLC=0 ./check.sh         # skip TLC
APALACHE=1 ./check.sh    # add the bounded apalache-mc runs
```

Pins (Polychrome review on MKIT-17): quint 0.32.0; Apalache 0.62.2 run
directly on the TLA+ that `quint compile --target tlaplus` produces (quint
uses its bundled Apalache only to transpile; `quint verify` is not used);
TLC is `tlc2.TLC` from the Apalache 0.62.2 jar; Java 21.

Tool locations default to `${FV_HOME:-$HOME/.local/share/mkit-fv}/apalache-0.62.2/`
and can be overridden with `APALACHE_MC` and `TLA2TOOLS`; `JAVA_HOME`
defaults to `/usr/libexec/java_home -v 21`, then Homebrew's `openjdk@21`.
Memory: `TLC_HEAP` (default 4g), `TLC_WORKERS` (2), `APALACHE_HEAP` (4g).
Other knobs: `QUINT=0` skips `quint run`; `ONLY=<regex>` restricts TLC and
Apalache to matching `<module>::<invariant>` checks; `STEPS` (quint run depth, 40), `SAMPLES` (20000),
`REFS_DEPTH` (Apalache length for refs2 Safety, 8), `SERVE_DEPTH` (12).

Each line of output is `<check>  <expected> (as expected)` or
`UNEXPECTED: ...`; the script exits 1 on any unexpected outcome. `ok` means
the invariant holds within the stated bound; `violation` means the checker
reached a mutant, canary or documented-gap witness, as it must.

## Checks and bounds

Bounded is not proved. Nothing here is a proof for unbounded processes,
refs or values.

| Checker | Instance | Bound | Result |
|---------|----------|-------|--------|
| `quint test` | `refs_test` (23 runs), `serve_test` (13), `served_test` (7) | pinned traces | all pass |
| `quint run` | `refs3`, `refs2` Safety | 20000 samples x 40 steps, seed 0x1 | ok |
| `quint run` | `serve2`, `serve3`, `served` Safety | same | ok |
| TLC | `serve2` Safety | exhaustive: 2 server slots (each may start as either binary), 1 local command, 3 uploaders | ok, 18,812 states |
| TLC | `serve3` Safety | exhaustive: 3 server slots | ok, 152,012 states |
| TLC | `served` Safety | exhaustive (one request at a time, 5 name classes, legacy files present or not) | ok, 66,064 states |
| TLC | `refs2` Safety, slice `domains` | exhaustive for 2 processes whose ops are local `updateRef`, `file` or `mem` on one ref (TLC `CONSTANT KINDS <- ...`, `REFS <- {0}`), CONSTRAINT `nextEntry <= 2`; VIEW drops only `lastAction` | ok, 3,418,713 states |
| TLC | `refs2` Safety, slice `chain` | same, ops `commit`, `amend`, `branch`, `checkout`, `gc` on one ref | ok, 3,538,512 states |
| Apalache 0.62.2 | `refs2` Safety (full op space) | length `REFS_DEPTH` = 8 (~22 min under load) | ok |
| Apalache 0.62.2 | `serve2` Safety, `served` Safety | length 12 / 8 | ok |

Every mutant and witness in the table below was reached by TLC and/or
Apalache as well as by its pinned `quint test` scenario (TLC state counts
to the counterexample: 53 to 2,422,421; Apalache lengths 2 to 9, the
shortest traces that can exhibit each).

Mutants and witnesses (each must be reached; `check.sh` lists every one):

| Instance | Must violate | What it shows |
|----------|--------------|---------------|
| `refs3_misorder` | `NoDeadlock`, `LockOrderRespected` | the §4 order is what prevents deadlock |
| `refs2_noRefLock` | `NoLostUpdateLocal` | pre-#637 lost update |
| `refs2_noFileLock` | `NoLostUpdateFile` | RefLock is needed |
| `refs2_gcSkipTrees` | `ExpireHoldsSuperset`, `NoRecordExpireInterleave` | §3.2 superset rule |
| `refs2_racyAcquire` | `LockOwnership` | broken flock |
| `refs2_memNoMutex` | `NoLostUpdateMem` | the v1 "NOT atomic" memory row |
| `refs3` | `WitnessCrossDomainGap` | documented §3.1 gap (local vs `mkit serve`/`mkit-server`, when the served root is the common dir) |
| `serve2_sweepUnlocked` | `SweepAlone`, `NoLiveUploadSwept` | the sweep needs the exclusive hold |
| `serve2_sweepUnderShared` | `SweepAlone`, `NoLiveUploadSwept` | a shared hold does not exclude other servers' uploads |
| `serve2_serverSkipsServe` | `UpServersHoldServeShared`, `NoMissedDetection`, `NoLiveUploadSwept` | `mkit-server` must hold `serve.lock` |
| `serve2_serverLockShared` | `OneMkitServer` | `server.lock` must be exclusive |
| `serve2_ftSlow` | `NoLiveUploadSwept` | ASSUMPTION: lockless `mkit+file://` uploads rely on the 1 h age bound |
| `serve2` | `WitnessUndetectedLateServer` | documented §3.1 gap: detection is one-directional |
| `served_checkAfterRead` | `RefuseBeforeStorage`, `ExplicitRefusal` | pre-v3 behaviour (answering `main` from storage / as absent) |
| `served_headCheckedLate` | `RefuseBeforeStorage`, `RefusedWritesNothing` | both AdvanceRefs names must be checked before the first write |
| `served_listNoSkip` | `ListingServedOnly` | legacy refs must be skipped in listings |

Canaries (`Canary*`, `Witness*` reachability) confirm the interesting
states are visited: a sweep removes a crashed upload's file, a start skips
its sweep, `mkit serve` and `mkit-server` share a root, a `mkit serve`
starts during a stalled upload, refusals of each kind are reached, and a
served AdvanceRefs succeeds.

The unsliced `refs2` space (8 kinds, 2 trees, 2 refs, 4 conditions, 2
values, 2 processes) passed 1.5 M distinct states at BFS depth 4 in 2
minutes with the queue still growing, so it does not fit the 30-minute /
4 GB budget: TLC covers it by the two slices above, quint run and Apalache
cover the whole space to their bounds.

## Abstractions

- Time is two ages, fresh and stale (older than `STALE_UPLOAD_AGE`, 1 h).
  A server's streaming upload can stall and go stale while live; only the
  lock protects it. A `FileTransport` upload is one `write_atomic` call and
  is assumed never stale while live (the age-bound assumption in the
  `lock_and_sweep` comment); `serve2_ftSlow` drops it.
- The probe's momentary exclusive hold is one atomic step; its other
  effects (a starting `mkit serve` skips its sweep, a starting server waits)
  are liveness only. Lock waits never time out (the 5 s timeout is
  abstracted, as in `refs.qnt`). Stop and crash are one action.
- `mkit-server --meta sqlite` keeps refs in SQLite (the R-81 marker makes
  `FileTransport` refuse ref writes on that root) and is not modelled;
  neither is `mkit-server`'s S3 spool sweep (under `server.lock`, used
  only by `mkit-server`).
- The git bridge locks (`git-<remote>.lock`, `git-import-key.lock`) that
  another track is adding to SPEC-CONCURRENCY §2/§4 are not in this model.

## Model-based conformance (MKIT-22)

`refs_mbt.qnt` (additive; `refs.qnt` is unchanged) instantiates `refs.qnt`
with `NO_FAULTS` for 2 (`refs_mbt2`) and 3 (`refs_mbt3`) processes and adds
the scheduler `stepLin`: a disk `readRef` is not scheduled while a process
of the other disk lock domain (local chain vs file transport) has read the
same ref and not committed. That removes exactly the documented §3.1
cross-domain gap, which the real, atomic API calls cannot reproduce, so every
trace is linearizable at the ref level and can be replayed. Generated traces
must satisfy `LinSafety` (`Safety` and `NoCrossDomainGap`); the
unrestricted `stepAll` must still reach the gap.

`formal/scripts/gen-refs-traces.sh` draws the ITF traces
(`quint run --mbt --out-itf`, one seed each, 60 steps), strips the
variables the harness does not read, and writes them to
`rust/crates/mkit-formal-conformance/tests/fixtures/formal_refs/`
(`CHECK=1` regenerates into a temp dir and diffs). The Rust test
`rust/crates/mkit-formal-conformance/tests/formal_refs_conformance.rs`
(`cargo test -p mkit-formal-conformance`, offline, normal CI) replays each
step against `mkit_core::refs`, `ops::recovery`, `FileTransport` and
`MemoryTransport` on a temp repo and compares, after every step, the disk
refs (through `refs::read_ref` and through `FileTransport`), the memory
refs, the recovery log, and every commit's outcome (`ok` / `conflict` /
`notfound`). The op-to-call mapping and what is not compared (lock steps,
the `history-mmr` ancestry path) are in that file's header.

| Check | Bound | Result |
|-------|-------|--------|
| `quint run refs_mbt2 --step stepLin` `LinSafety` | 2000 samples x 60 steps, seed 0x1 | ok |
| `quint run refs_mbt3 --step stepLin` `LinSafety` | 2000 samples x 60 steps, seed 0x1 | ok |
| `quint run refs_mbt3 --step stepLin` `LinSafety` (one-off, not in the script) | 20000 samples x 40 steps, seed 0x1, 9 min | ok |
| `quint run refs_mbt3 --step stepAll` `NoCrossDomainGap` | 20000 samples x 60 steps, seed 0x1 | violation (as it must) |
| Replay of 5 fixtures (`refs_mbt2` seeds 0xa, 0xf, 0x24; `refs_mbt3` seeds 0x1b, 0x21) | 300 steps, 41 commits | every step agrees |
| `harness_detects_adapter_faults` | 5 deliberate adapter bugs (one per domain, plus conditional delete and dropped record) | each caught |
| `harness_detects_a_tampered_trace` | flipped outcome, altered ref value | each caught at that state |

Bounded is not proved: the fixtures are 5 sampled traces, not every
interleaving.
