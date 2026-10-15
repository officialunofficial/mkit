# Verification slices and alarm callbacks

The deterministic `verification_pipeline_round_probe` drives scheduled
verification from a consumed pack to Usable. It compares single-slice Extract
callbacks with the default ceiling of eight. Fixtures contain 500 or 3,000 files
of 27 bytes, or three files above the extraction threshold as a control. Each
fixture also contains its tree and signed commit. The probe uses D34 sharding
with takedown denial enabled.

Run the probe from the repository root:

```sh
CARGO_BUILD_JOBS=3 just cargo-cached nextest run -p mkit-server \
  --all-features -j 3 verification_pipeline_round_probe --no-capture
```

The latency model charges 30 ms per dependent warm transport round and 100 ms
per alarm re-arm. Calls count storage-interface dispatches (`NamespaceStore`, `BlobStore`, and
`PackSink`), not SQL statements or adapter-internal RPCs. Local storage calls
have no modeled network latency.
This is a scheduling model, not a production stopwatch or a measurement of
synchronous CPU time. The injected business clock stays frozen during a callback
so the probe also exercises count-based bounds. Synthetic transport waits use
the paused Tokio clock; they do not advance that business clock. The model
therefore describes the count- and call-bounded schedule, with CPU time set to
zero. Separate clock-advancing regressions enforce elapsed and physical cutoffs.

A durable slice can visit several phases. Phase slice and callback counts
therefore overlap and must not be added. Storage calls and applies belong to the
phase active when they execute; a callback's re-arm belongs to its final active
phase. Re-arms count continuations before Usable; initial scheduling and the
later Watch maintenance timer are outside this interval. Extract substage rows
exclude shared checkpoint-load and guard overhead.
Zero rows mean the fixture never enters that stage. Stop counts distinguish
slice/chain exits from successful phase/step boundaries.

## Scheduling choice and bounds

Larger packs share the existing durable-slice driver with tiny packs for local
selection. Tiny packs continue to use only their existing `tiny_chain_slices`
setting, including when it is one. Both
the entry checkpoint and the proposed next checkpoint must remain in Extract
selection before the driver commits and continues. No inventory shortcut skips
selection. Decode, index emission, relay delivery, extraction effects, and the
Usable conditions retain their existing algorithms.

Every intermediate slice commits with the original timer and job guards before
another slice begins. The next slice also checks its freshly read checkpoint's
phase. A concurrent restart or advance to an effect stage ends the selection
callback before that phase does any work. The original timer remains until the final reschedule.
A crash before commit replays the slice; a crash or lost reply after commit
resumes its durable checkpoint. Deterministic auxiliary writes retain their
existing idempotence and guards. Every slice repeats source and denial checks.

One default callback shares the existing 256-call allowance and stops before another
slice when fewer than 128 calls remain. The driver never refreshes that budget.
The physical callback deadline and two-second elapsed cutoff also stop it.
Eight slices of at most sixteen selection steps bound synchronous work to 128
selection steps with a frozen clock, returning control to the timer dispatcher.
The existing per-slice operation ceiling and `MAX_BATCH_OPS` remain unchanged.
Chained steps carry at most 80 guard/write operations. The unconditional first
step retains its existing bound: a head reconstruction can carry 70 operations
and at most 18 source guards from the other six packs. The checkpoint adds at
most five operations, and timer fencing adds one for an intermediate commit or
four for the final reschedule. The wider first-step case uses at most 97 of the
100 operations; a chained commit uses at most 89.
No wire or stored format changes.

`SliceLimits::with_extract_chain_slices(1)` selects the original callback shape.
The default is eight; larger configured values clamp to eight. The separate
tiny-pack ceiling exclusively governs tiny packs and retains its existing meaning.

## Regression evidence

The probe pins the complete baseline table, compares non-Extract rows, and
requires at least four times fewer Extract callbacks for 3,000 files. It compares
durable verification output and extracted bytes. The extraction control also
compares content and offsets through the callback regression suite.

The callback tests inject interruption and lost replies at each new checkpoint,
resume through the retained timer, and compare the final result. They also check
the frozen-clock slice ceiling and a shared allowance that runs out mid-chain.
Existing slice-step, chunk, elapsed-cutoff, concurrent-guard, and extraction
regressions retain their assertions.

## Before and after

The baseline reproduces the single-slice callback scheduling at `b402c005` by
setting `extract_chain_slices` to one. The after run uses eight. All other
fixture settings match. Both runs fix the per-slice selection cap at 16; the
suite's one-step stress mode does not redefine this measurement. Each changed
cell shows before → after; a single value
is unchanged. The three complete baseline reports live beside the probe in
**verification_probe_data/** and are checked on every run.

For 3,000 files, Extract retains all 564 durable slices and 3,612 committed
applies. Callbacks fall from 564 to 71 (7.94 times fewer). The model drops from
56.3 seconds to 7.0 seconds, saving 49.3 seconds. The 500-file model saves
8.3 seconds, from 9.4 seconds to 1.1 seconds. The extraction control saves
one callback and 100 ms; its 117 warm rounds and extracted bytes are unchanged.
Every non-Extract row and every encoded object-index row matches exactly.

Decode and EmitIndex remain useful separate targets: for 3,000 files, Decode
uses 622 warm rounds and 20 callbacks (20.66 modeled seconds), while EmitIndex
uses 124 rounds and 47 callbacks (8.32 modeled seconds). This change does not
alter either stage.

### 500 files of 27 bytes

| Stage | Slices | Callbacks | Re-arms | Storage calls | Serial rounds | Committed applies | Modeled ms | Stop reasons |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Decode | 4 | 4 | 4 | 1624 | 113 | 556 | 3790 | {"slice:decode_boundary": 4} |
| ClosureResolve | 6 | 6 | 5 | 46 | 0 | 11 | 500 | {"phase_boundary": 1, "slice:phase_incomplete": 5} |
| EmitIndex | 8 | 8 | 7 | 191 | 44 | 52 | 2020 | {"phase_boundary": 1, "slice:phase_incomplete": 7} |
| AwaitDelivery | 2 | 2 | 2 | 25 | 4 | 6 | 320 | {"slice:durable_boundary": 1, "slice:pending_or_error": 1} |
| Extract | 95 | 95 → 12 | 94 → 11 | 5197 → 5114 | 0 | 604 | 9400 → 1100 | {"chain:no_progress": 1, "chain:steps": 94, "phase_boundary": 1, "slice:phase_incomplete": 94} |
| Extract/scan | 32 | 32 → 4 | 31 → 3 | 2079 | 0 | 541 | 3100 → 300 | {"chain:steps": 31, "slice:phase_incomplete": 31, "step_boundary": 472} |
| Extract/closure | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/dependencies | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/members | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/head | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 1} |
| Extract/select | 33 | 33 → 5 | 32 → 4 | 1571 | 0 | 32 | 3200 → 400 | {"chain:steps": 32, "slice:phase_incomplete": 32, "step_boundary": 471} |
| Extract/choose | 32 | 32 → 5 | 31 → 4 | 1067 | 0 | 31 | 3100 → 400 | {"chain:no_progress": 1, "chain:steps": 31, "slice:phase_incomplete": 31, "step_boundary": 471} |
| Extract/preflight | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/start | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/upload | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/complete | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/offsets | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/enqueue | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/delivery | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 | {"slice:terminal": 1} |

### 3,000 files of 27 bytes

| Stage | Slices | Callbacks | Re-arms | Storage calls | Serial rounds | Committed applies | Modeled ms | Stop reasons |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Decode | 20 | 20 | 20 | 9628 | 622 | 3295 | 20660 | {"slice:decode_boundary": 20} |
| ClosureResolve | 34 | 34 | 33 | 270 | 0 | 67 | 3300 | {"phase_boundary": 1, "slice:phase_incomplete": 33} |
| EmitIndex | 47 | 47 | 46 | 1051 | 124 | 248 | 8320 | {"phase_boundary": 1, "slice:phase_incomplete": 46} |
| AwaitDelivery | 2 | 2 | 2 | 23 | 2 | 5 | 260 | {"slice:durable_boundary": 1, "slice:pending_or_error": 1} |
| Extract | 564 | 564 → 71 | 563 → 70 | 31023 → 30530 | 0 | 3612 | 56300 → 7000 | {"chain:no_progress": 1, "chain:steps": 563, "phase_boundary": 1, "slice:phase_incomplete": 563} |
| Extract/scan | 188 | 188 → 24 | 187 → 23 | 12432 | 0 | 3236 | 18700 → 2300 | {"chain:steps": 187, "slice:phase_incomplete": 187, "step_boundary": 2816} |
| Extract/closure | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/dependencies | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/members | 2 | 2 → 1 | 1 → 0 | 3 | 0 | 1 | 100 → 0 | {"chain:steps": 1, "slice:phase_incomplete": 1, "step_boundary": 1} |
| Extract/head | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 1} |
| Extract/select | 188 | 188 → 24 | 187 → 23 | 9383 | 0 | 187 | 18700 → 2300 | {"chain:steps": 187, "slice:phase_incomplete": 187, "step_boundary": 2816} |
| Extract/choose | 189 | 189 → 25 | 188 → 24 | 6381 | 0 | 188 | 18800 → 2400 | {"chain:no_progress": 1, "chain:steps": 188, "slice:phase_incomplete": 188, "step_boundary": 2814} |
| Extract/preflight | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/start | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/upload | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/complete | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/offsets | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/enqueue | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/delivery | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 | {"slice:terminal": 1} |

### Control: three files of 70,002 bytes

| Stage | Slices | Callbacks | Re-arms | Storage calls | Serial rounds | Committed applies | Modeled ms | Stop reasons |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Decode | 4 | 4 | 4 | 76 | 29 | 25 | 1270 | {"slice:decode_boundary": 4} |
| ClosureResolve | 1 | 1 | 0 | 6 | 0 | 1 | 0 | {"phase_boundary": 1} |
| EmitIndex | 1 | 1 | 0 | 9 | 2 | 3 | 60 | {"phase_boundary": 1} |
| AwaitDelivery | 2 | 2 | 2 | 31 | 10 | 9 | 500 | {"slice:durable_boundary": 1, "slice:pending_or_error": 1} |
| Extract | 23 | 23 → 22 | 22 → 21 | 438 → 437 | 117 | 70 | 5710 → 5610 | {"chain:effect_stage": 21, "chain:no_progress": 1, "chain:steps": 1, "phase_boundary": 1, "slice:phase_incomplete": 22} |
| Extract/scan | 1 | 1 | 0 | 22 | 0 | 6 | 0 | {"step_boundary": 6} |
| Extract/closure | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/dependencies | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/members | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 2} |
| Extract/head | 1 | 1 | 0 | 1 | 0 | 0 | 0 | {"step_boundary": 1} |
| Extract/select | 2 | 2 → 1 | 1 → 0 | 24 | 0 | 4 | 100 → 0 | {"chain:steps": 1, "slice:phase_incomplete": 1, "step_boundary": 5} |
| Extract/choose | 4 | 4 | 3 | 17 | 0 | 3 | 300 | {"chain:effect_stage": 3, "chain:no_progress": 1, "slice:phase_incomplete": 3, "step_boundary": 2} |
| Extract/preflight | 6 | 6 | 6 | 93 | 42 | 21 | 1860 | {"chain:effect_stage": 6, "slice:phase_incomplete": 6} |
| Extract/start | 3 | 3 | 3 | 24 | 15 | 6 | 750 | {"chain:effect_stage": 3, "slice:phase_incomplete": 3} |
| Extract/upload | 0 | 0 | 0 | 0 | 0 | 0 | 0 | {} |
| Extract/complete | 3 | 3 | 3 | 39 | 24 | 6 | 1020 | {"chain:effect_stage": 3, "slice:phase_incomplete": 3} |
| Extract/offsets | 3 | 3 | 3 | 30 | 15 | 6 | 750 | {"chain:effect_stage": 3, "slice:phase_incomplete": 3} |
| Extract/enqueue | 3 | 3 | 3 | 30 | 15 | 6 | 750 | {"chain:effect_stage": 3, "slice:phase_incomplete": 3} |
| Extract/delivery | 3 | 3 | 0 | 9 | 0 | 3 | 0 | {"step_boundary": 3} |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 | {"slice:terminal": 1} |
