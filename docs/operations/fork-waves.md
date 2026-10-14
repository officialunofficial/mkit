# Fork wave bounds and latency model

Fork work overlaps independent storage operations within existing units.
It does not overlap fork phases, pack publication boundaries, or cursor commits.
The index copy overlaps source partitions; see "Index copy waves".

## Calls and ordering

Destination emptiness checks use at most six scans with a limit of one row.
The first existing read exposes accounting depth before wave selection;
known remaining calls must cover `2 * layers + 1` debits per scan.
Unknown allowances keep scans serial, so later refusals cannot mask an earlier
I/O error in the fork driver.
Source index statistics use at most six concurrent calls, narrowing when the
remaining allowance cannot cover shared accounting ancestors. A zero-call
reservation exposes the inherited depth without spending calls or dispatching
I/O. Stats need one local debit, up to two per inherited layer, and one for an
opaque leaf; unknown allowances keep stats serial. Holder copies use four
distinct object IDs at a time
within a page, reducing the width when the remaining allowance cannot cover
all eight possible mutation attempts per ID (25 calls including the holder
read). An unknown inherited allowance keeps holder copies serial. The first
holder read reserves its existing call before the width is selected. Its
reservation exposes the number of accounting layers, without spending extra
calls. Each layer can debit two ledgers, and their ancestors can overlap.
The width uses a conservative `2 * layers + 1` debit multiplier, including an
opaque leaf, so shared ledgers cannot let a later holder starve an earlier one.
The actual calls remain charged once per existing ledger; this multiplier
only narrows scheduling. The metadata accessor is private and does not change
reader accounting or admission.
Repeated IDs start another wave, retaining the original calls
and avoiding new contention on the same object state.

Each wave drains its replies and consumes results in input order. A failure
can leave later operations in that wave completed, but does not start another
wave. Successful work keeps the same backend calls. An error can therefore
spend more calls than the serial loop's early return. No allowance is raised.

Read calls reserve credit before dispatch and do not charge that credit again.
Statistics reserve their exact slice calls before dispatch because stats do not
consume read credit. Holder mutations retain their existing per-call charges
before each backend dispatch: the number of retries and whether the source
holds the object are not known in advance. CAS retries still draw from the slice
budget. A copy wave takes only as many holders as the slice can still pay for
(six calls each, at most 64), so no holder reserve is held back for pages
without candidates.

A holder write completed before a failed page checkpoint is safe to
repeat: the destination holder already exists, so its count does not grow.
Blocked holder outcomes still map to `NotFound` in input order. Distinct IDs
have independent holder and object-state rows.

The fork loops have no separate elapsed slice cutoff. Their existing storage
call allowance, job expiry, and freshly stamped apply windows remain in force.

## Index copy waves

The copy phase reads up to six of the source's sixteen index partitions at a
time. The job row keeps one cursor per partition (`lanes`), so a wave takes the
next page of each of the first open partitions. The width follows the same
rule as the emptiness scans: the first read is reserved before the width is
chosen, the known remaining calls must cover `2 * layers + 1` debits per scan,
and an unknown allowance keeps the copy to one partition at a time. A wave also
narrows to the calls left in the slice, and once its pages are read it keeps only
the leading partitions whose writes the slice can still pay for (the first
always stays); the others, and a failure that belonged to one of them, wait for
the next wave.

A wave runs in three stages, each finishing for the whole wave before the next:
the scans, the index writes (at most six at once), then the holders. Replies are
consumed in partition order and the wave answers as the same partitions taken
one after another would: the first failing partition's error is the one
reported, and no partition after it is counted. The `copied == expected`,
`MAX_SCANNED_ROWS` and object-limit checks run over a running total in that
order. A wave that spends the slice keeps none of its progress: the cursors and
counts return to where the wave began, and the next slice repeats it. Every
write is a put of the same row or a holder write that only raises a sequence, so
the repeat is safe.

Pages hold 500 rows, or 256 where holders are copied. Holder candidates do not
bound the page: a wave copies at most 64 holders in all, in partition and key
order, and the lane records the source key of the last candidate it finished
(`held`; an empty mark means the rows are written and no candidate is done, for
a partition the wave had no holder room for). The page's rows are already written, so the next wave scans the same
page, skips the written rows, and continues after that key; the page is counted
and its cursor advances only when its last candidate is done. A repeat of a
holder write is safe for the reason above.

| Files | Copy rounds before / after | Copy calls | Slices for the whole fork |
| ---: | ---: | ---: | ---: |
| 500 | 35 / 9 | 35 / 35 | 1 / 1 |
| 3,000 | 112 / 15 | 112 / 58 | 1 / 1 |
| 10,000 | 340 / 35 | 340 / 177 | 3 / 1 |

Rounds are measured on a store that sleeps 30 ms per call and reports a known
read allowance (`tests/fork_copy_rounds.rs`); extraction is deployed at 64 KiB
and the files are small, so no holder is copied.

## Memory and security bounds

Six one-row emptiness replies retain at most 3 MiB of raw values plus keys.
Statistics hold six small scalar replies. Four holder mutations have at most
152 rows in their immediate read
sets and hold scans, below the existing 500-row copy scan and 1,000-row reader
envelope. Nested mutation retries do not accumulate responses.

The two per-pack write proofs use the existing `WRITE_PROOF_CONCURRENCY` of
four when known headroom covers all sixteen first-page calls, including
`2 * layers + 1` possible shared-ancestor debits per call. A zero-call reservation
provides that metadata; tight or unknown headroom retains serial reads.
Four maximum values total 2 MiB, within the existing 4 MiB proof bound.
Valid directory waves hold at most `4 * 64 * 33` pointer-value bytes.
The sixteen bounded pointer pages remain retained as before;
pointed-to descriptor reads and nested proofs remain serial.

Fork publication and upload admission still skip full pack denial proofs when
`takedown_denial` is false. The deployment gate and all final guards stay at
their existing boundaries. Reader paths, hooks, outcomes, wire bytes, stored
formats, and public APIs do not change. Pack-serving proofs retain their serial
public entry point; upload admission uses a private write entry point. No store reset is required.

## Latency model

This model uses sixteen ref-index and object-index partitions. It assumes
every call in a loop costs 300 ms when cold or 40 ms when
warm. Independent calls in one wave finish together. It excludes unchanged
setup, location lookup, cursor writes, retries, and descriptor continuations.
The holder case has a source holder and succeeds without a CAS retry.
The holder model starts with a fresh 600-call slice and one inherited
reservation layer beneath the local counter. The debit multiplier is five:
seven waves of four IDs, ten of three, then three of two. Each holder has four
serial calls, so those twenty waves take eighty rounds. Less initial headroom
or more accounting layers narrows waves further. These are models, not
network timings.

| Loop | Calls | Serial rounds | Wave rounds | Cold before / after | Warm before / after |
| --- | ---: | ---: | ---: | ---: | ---: |
| Empty destination, refs and members | 32 | 32 | 6 | 9.60 s / 1.80 s | 1.28 s / 0.24 s |
| Empty destination, refs only | 16 | 16 | 3 | 4.80 s / 0.90 s | 0.64 s / 0.12 s |
| Source index statistics | 16 | 16 | 3 | 4.80 s / 0.90 s | 0.64 s / 0.12 s |
| Holder page, 64 distinct IDs | 256 | 256 | 80 | 76.80 s / 24.00 s | 10.24 s / 3.20 s |
| Pack denial directory | 16 | 16 | 4 | 4.80 s / 1.20 s | 0.64 s / 0.16 s |

Two full emptiness checks and one refs-only check total 80 calls: 24.00 s
becomes 4.50 s cold; 3.20 s becomes 0.60 s warm. Duplicate holder IDs reduce the modeled
concurrency benefit.

Closure expansion stays serial: budget exhaustion mid-wave would change
first-error precedence. Revisit with a validated reference-page bound if fork
closure time matters.
