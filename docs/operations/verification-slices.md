# Verification slices and alarm callbacks

The deterministic `verification_pipeline_round_probe` drives scheduled
verification from a consumed pack to Usable. It compares single-slice callbacks
with the default ceilings of eight for ClosureResolve, EmitIndex, and Extract
selection. Fixtures contain 500 or 3,000 files of 27 bytes, or three files of
70,002 bytes above the extraction threshold as a control. Each fixture also
contains its tree and signed commit. The probe uses D34 sharding and runs with
takedown denial both on and off. Both variants share each encoded pack fixture.

Run the probe from the repository root:

```sh
CARGO_BUILD_JOBS=3 just cargo-cached nextest run -p mkit-server \
  --all-features -j 3 verification_pipeline_round_probe --no-capture
```

The latency model charges 30 ms per dependent warm transport round and 100 ms
per alarm re-arm. Calls count storage-interface dispatches (`NamespaceStore`,
`BlobStore`, and `PackSink`), not SQL statements or adapter-internal RPCs.
Local storage calls have no modeled network latency. This is a scheduling
model, not a production stopwatch or a measurement of synchronous CPU time.
The business clock stays frozen during a callback. Synthetic transport waits
use the paused Tokio clock and do not advance that business clock. Separate
clock-advancing regressions enforce elapsed and physical cutoffs.

A durable slice can visit several phases. Phase slice and callback counts
therefore overlap and must not be added except for the stated comparison of
ClosureResolve plus EmitIndex phase callbacks. Calls and applies belong to the
phase active when they execute; a callback's re-arm belongs to its final active
phase. Re-arms count continuations before Usable. Initial scheduling and the
later Watch maintenance timer are outside this interval. Full baseline reports,
including Extract substages and stop reasons, are pinned in
**verification_probe_data/** beside the probe. Denial-off reports have their
own files; the existing denial-on baseline files are unchanged.

## Scheduling choice and bounds

ClosureResolve, EmitIndex, and Extract selection outside the tiny-pack path
share the existing durable-slice driver. Each phase family has its own
`SliceLimits` setting: `with_closure_chain_slices`, `with_emit_chain_slices`,
and `with_extract_chain_slices`. A value of one restores single-slice callbacks
for that family. Defaults are eight; larger values clamp to eight. Tiny packs
continue to use only `tiny_chain_slices`, including when it is one.

Every intermediate slice commits with the original timer and job guards before
another slice begins. The next slice re-reads the checkpoint and checks its
phase before work. Extract continuations also require a selection stage. A
concurrent restart or phase advance ends the chain. Existing within-slice phase
transitions keep their existing order. The original timer remains runnable until
the final reschedule. A crash before commit replays the slice; a crash or lost
reply after commit resumes the durable checkpoint.

One callback shares the original 256-call allowance and never refreshes it.
Before continuing, the driver requires at least 128 remaining calls. External
closure lookup retains its larger full-slice reservation. Budgeted dispatches
also charge before I/O, including lease retries. The physical callback deadline
and two-second elapsed cutoff stop the driver, including after checkpoint I/O.
Eight durable slices bound synchronous work even when the clock is frozen.
The per-slice operation ceilings and `MAX_BATCH_OPS` do not change.

Each ClosureResolve slice settles at most 90 child rows. Deletions, the scan
cursor, and satisfying-pack dependencies commit together. A crash cannot delete
a child before recording its dependency. Each slice repeats its local-frame and
member lookups; no lookup result is cached across slices.

Each EmitIndex slice scans at most 64 frames. It retains the same sequence of
effects: each direct batch checks denial and applies same-value index puts with
`NotAfter`; relay rows renew the source epoch lease and commit under the existing
lease and sequence guards; the slice then reads `last_relay_seq` and checkpoints.
Nothing is hoisted or shared across slices. A crash after enqueue but before the
checkpoint can re-emit that page with new outbox sequences, exactly as in
single-slice mode. Index puts are identical, target holder intents fold, and
AwaitDelivery waits on the newest recorded sequence. EmitIndex itself emits
index rows; the holder regression separately exercises the shared relay hook.
The next slice starts only after the previous checkpoint commits and the timer
fence passes. Chaining adds no interleaving beyond the timer firing again
immediately. Enqueue and checkpoint remain separate applies.

Extract selection retains its existing 16-step ceiling: at most 128 steps per
callback. Chained steps carry at most 80 guard/write operations. A head
reconstruction's unconditional first step can carry 70 operations and at most
18 source guards from the other six packs. The checkpoint adds at most five
operations; timer fencing adds one for an intermediate commit or four for the
final reschedule. The wider first-step case uses at most 97 of 100 operations;
a chained selection commit uses at most 89. Effectful extraction retains its
existing scheduling and threshold semantics. No wire or stored-format change.

## Regression evidence

The phase callback regressions interrupt each intermediate commit before and
after apply, lose replies, resume through the retained timer, and compare durable
output and exact index bytes against single-slice scheduling. Each phase also
has a frozen-clock ceiling, shared-budget stop, and concurrent-restart test.
The EmitIndex relay replay test interrupts the second slice after enqueue and
before checkpoint, then proves that duplicate target puts match, AwaitDelivery
waits on the newest sequence, and Usable completes. The duplicate-holder test
proves that new relay sequences fold one protected intent into one holder.
Existing tiny-pack and Extract callback tests retain their assertions.

The probe compares durable verification output, every object-index shard, and
extracted bytes. Decode attribution is identical before and after, and every
callback's charged calls stay within its configured allowance. The 3,000-file
case requires at least four times fewer combined ClosureResolve and EmitIndex
phase callbacks in both denial modes. The existing fourfold Extract assertion
also remains. The original probe timeout stays unchanged.

## Before and after

Before sets the three non-tiny durable-slice ceilings to one; after sets them
to eight. The original Extract baseline remains available, so its existing
selection improvement is visible too. Each cell shows before → after when it
changes. Slices, committed output, extraction thresholds, and checks are
unchanged. Committed applies include relay delivery and cleanup, whose grouping
changes when several EmitIndex pages queue in one callback.

For 3,000 files in either denial mode, ClosureResolve plus EmitIndex phase
callbacks fall from 81 to 12 (6.75 times fewer), and re-arms fall from 79 to 10.
Their model falls from 11,620 ms to 3,640 ms. Some relay delivery shifts into
AwaitDelivery: including that phase gives 11,880 ms → 4,200 ms, a net saving of
7,680 ms. For 500 files, including AwaitDelivery gives 2,840 ms → 1,380 ms.
The control's closure, emission, and delivery costs stay unchanged.

### 500 files of 27 bytes, denial on

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 4 | 4 | 4 | 1624 | 113 | 556 | 3790 |
| ClosureResolve | 6 | 6 → 1 | 5 → 0 | 46 → 41 | 0 | 11 | 500 → 0 |
| EmitIndex | 8 | 8 → 2 | 7 → 1 | 191 → 89 | 44 → 8 | 52 → 22 | 2020 → 340 |
| AwaitDelivery | 2 | 2 | 2 | 25 → 49 | 4 → 28 | 6 → 18 | 320 → 1040 |
| Extract | 95 | 95 → 12 | 94 → 11 | 5197 → 5114 | 0 | 604 | 9400 → 1100 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

### 500 files of 27 bytes, denial off

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 1 | 1 | 1 | 1095 | 77 | 547 | 2410 |
| ClosureResolve | 6 | 6 → 1 | 5 → 0 | 46 → 41 | 0 | 11 | 500 → 0 |
| EmitIndex | 8 | 8 → 2 | 7 → 1 | 191 → 89 | 44 → 8 | 52 → 22 | 2020 → 340 |
| AwaitDelivery | 2 | 2 | 2 | 25 → 49 | 4 → 28 | 6 → 18 | 320 → 1040 |
| Extract | 95 | 95 → 12 | 94 → 11 | 5197 → 5114 | 0 | 604 | 9400 → 1100 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

### 3,000 files of 27 bytes, denial on

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 20 | 20 | 20 | 9628 | 622 | 3295 | 20660 |
| ClosureResolve | 34 | 34 → 5 | 33 → 4 | 270 → 241 | 0 | 67 | 3300 → 400 |
| EmitIndex | 47 | 47 → 7 | 46 → 6 | 1051 → 575 | 124 → 88 | 248 → 150 | 8320 → 3240 |
| AwaitDelivery | 2 | 2 | 2 | 23 → 33 | 2 → 12 | 5 → 10 | 260 → 560 |
| Extract | 564 | 564 → 71 | 563 → 70 | 31023 → 30530 | 0 | 3612 | 56300 → 7000 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

### 3,000 files of 27 bytes, denial off

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 4 | 4 | 4 | 6480 | 407 | 3246 | 12610 |
| ClosureResolve | 34 | 34 → 5 | 33 → 4 | 270 → 241 | 0 | 67 | 3300 → 400 |
| EmitIndex | 47 | 47 → 7 | 46 → 6 | 1051 → 575 | 124 → 88 | 248 → 150 | 8320 → 3240 |
| AwaitDelivery | 2 | 2 | 2 | 23 → 33 | 2 → 12 | 5 → 10 | 260 → 560 |
| Extract | 564 | 564 → 71 | 563 → 70 | 31023 → 30530 | 0 | 3612 | 56300 → 7000 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

### Control: three files of 70,002 bytes, denial on

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 4 | 4 | 4 | 76 | 29 | 25 | 1270 |
| ClosureResolve | 1 | 1 | 0 | 6 | 0 | 1 | 0 |
| EmitIndex | 1 | 1 | 0 | 9 | 2 | 3 | 60 |
| AwaitDelivery | 2 | 2 | 2 | 31 | 10 | 9 | 500 |
| Extract | 23 | 23 → 22 | 22 → 21 | 438 → 437 | 117 | 70 | 5710 → 5610 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

### Control: three files of 70,002 bytes, denial off

| Phase | Slices | Callbacks | Re-arms | Calls | Rounds | Applies | Modeled ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Decode | 4 | 4 | 4 | 71 | 25 | 25 | 1150 |
| ClosureResolve | 1 | 1 | 0 | 6 | 0 | 1 | 0 |
| EmitIndex | 1 | 1 | 0 | 9 | 2 | 3 | 60 |
| AwaitDelivery | 2 | 2 | 2 | 31 | 10 | 9 | 500 |
| Extract | 23 | 23 → 22 | 22 → 21 | 432 → 431 | 111 | 70 | 5530 → 5430 |
| Verify | 1 | 1 | 0 | 5 | 2 | 3 | 60 |

## Decode attribution and deferred reduction

The following calls and rounds are unchanged by chaining. Nested test-only
scopes attribute every Decode call exactly once; each table sums to its Decode
row above. Frame reads include local frame metadata and pack-window/etag reads.
Writes cover buffered row flushes. Checkpoint includes per-entry row-and-cursor applies, checkpoint loads, ticket
and attempt guards, Pending-state writes, and final rescheduling overhead.
The denial/holder bucket includes admission denial checks and external-base
holder resolution; these fixtures need no external bases.

| Files | Denial | Sub-step | Calls | Rounds |
| --- | --- | --- | ---: | ---: |
| 500 | on | inventory | 76 | 76 |
| 500 | on | denial/holder | 502 | 33 |
| 500 | on | frames | 510 | 4 |
| 500 | on | writes | 5 | 0 |
| 500 | on | checkpoint | 531 | 0 |
| 500 | off | inventory | 76 | 76 |
| 500 | off | denial/holder | 0 | 0 |
| 500 | off | frames | 504 | 1 |
| 500 | off | writes | 5 | 0 |
| 500 | off | checkpoint | 510 | 0 |
| 3000 | on | inventory | 402 | 402 |
| 3000 | on | denial/holder | 3002 | 197 |
| 3000 | on | frames | 3048 | 23 |
| 3000 | on | writes | 33 | 0 |
| 3000 | on | checkpoint | 3143 | 0 |
| 3000 | off | inventory | 400 | 400 |
| 3000 | off | denial/holder | 0 | 0 |
| 3000 | off | frames | 3016 | 7 |
| 3000 | off | writes | 33 | 0 |
| 3000 | off | checkpoint | 3031 | 0 |
| control | on | inventory | 18 | 18 |
| control | on | denial/holder | 5 | 4 |
| control | on | frames | 19 | 7 |
| control | on | writes | 0 | 0 |
| control | on | checkpoint | 34 | 0 |
| control | off | inventory | 18 | 18 |
| control | off | denial/holder | 0 | 0 |
| control | off | frames | 19 | 7 |
| control | off | writes | 0 | 0 |
| control | off | checkpoint | 34 | 0 |

No Decode algorithm changes. For 3,000 files with denial on, inventory accounts
for 402 of 622 rounds and denial for 197. Without denial, inventory accounts for
400 of 407 rounds. Inventory already reads the pack head and up to 16 independent
entries in one `get_many`, then commits a guarded apply. The apply depends on
that read, and denial must follow staging. Denial already overlaps independent
object reads in waves of up to 16.

A contained follow-up could group same-partition denial reads within an admitted
batch. It must retain all object/action/holder checks after staging and preserve
input-order failure handling. These waves already consume one modeled round per
16 objects; grouping collisions predicts zero warm-round savings for a full wave,
although it can reduce calls and occasionally a callback. No positive round
saving is established, so this change is deferred. Risks include short batch
replies, different failure precedence, and accidentally reading denial before
the staging commit. Reducing inventory's two dependent rounds would require a
separate staging design and a guard/freshness audit, outside this change.

## Charged remote calls per callback

These are verification-handler budget debits, grouped by the phase at callback
entry, not the storage-call totals above. Local outbox commits do not debit the
remote allowance. Relay delivery has its own existing allowance. All measured
callbacks assert at most 256 debits; the direct-emission stress regression also
spends denial calls until the continuation reserve stops the chain.

| Files | Denial | Entry phase | Before calls per callback (count) | After calls per callback (count) |
| --- | --- | --- | --- | --- |
| 500 | on | ClosureResolve | 0 (5), 2 (1) | 2 (1) |
| 500 | on | EmitIndex | 0 (7) | 0 (1) |
| 500 | on | Decode | 1 (1), 193 (2), 195 (1) | 1 (1), 193 (2), 195 (1) |
| 500 | off | ClosureResolve | 0 (5), 2 (1) | 2 (1) |
| 500 | off | EmitIndex | 0 (7) | 0 (1) |
| 500 | off | Decode | 77 (1) | 77 (1) |
| 3000 | on | ClosureResolve | 0 (33), 2 (1) | 0 (4), 2 (1) |
| 3000 | on | EmitIndex | 0 (46) | 0 (6) |
| 3000 | on | Decode | 8 (1), 39 (1), 99 (1), 193 (17) | 8 (1), 39 (1), 99 (1), 193 (17) |
| 3000 | off | ClosureResolve | 0 (33), 2 (1) | 0 (4), 2 (1) |
| 3000 | off | EmitIndex | 0 (46) | 0 (6) |
| 3000 | off | Decode | 7 (1), 16 (1), 191 (1), 193 (1) | 7 (1), 16 (1), 191 (1), 193 (1) |
| control | on | ClosureResolve | 2 (1) | 2 (1) |
| control | on | EmitIndex | none | none |
| control | on | Decode | 5 (3), 15 (1) | 5 (3), 15 (1) |
| control | off | ClosureResolve | 2 (1) | 2 (1) |
| control | off | EmitIndex | none | none |
| control | off | Decode | 4 (3), 13 (1) | 4 (3), 13 (1) |
