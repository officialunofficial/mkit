# Request read rounds

The sequential-round probe uses a paused clock and the shared six-call read
admission. Each storage call costs one virtual latency unit. Round counts
measure dependencies, not elapsed production latency. The baseline is commit
`2e25d163`. The probe retains the existing shape ceilings and records every
row's before/after rounds and metadata-call delta.

Run from **rust/**:

```sh
cargo test -p mkit-server --features http-objects --lib embedder_read_shapes -- --nocapture
cargo test -p mkit-server --all-features --lib first_parent_ -- --nocapture
```

## Round and call deltas

Nested reads use one commit, eight files, and a nested directory. Flat reads
use four commits and six files. The longer history contains 52 commits and two
files, with one new pack per commit. Every ranged blob read still costs the
same conservative two call units; the table counts actual blob GETs separately.
Page1(10) activates the missing visibility revision on the first anonymous,
denial-off run. Subsequent page measurements reuse that durable revision.

| Denial | View | Shape | Rounds before | Rounds after | KV before | KV after | KV delta | GET before/after |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Off | Anonymous | Nested Show with sizes | 34 | 34 | 68 | 68 | +0 | 6/6 |
| Off | Anonymous | Nested Cat | 30 | 30 | 38 | 38 | +0 | 8/8 |
| Off | Anonymous | Nested Show | 24 | 24 | 37 | 37 | +0 | 6/6 |
| Off | Anonymous | Flat Show with sizes | 26 | 25 | 56 | 56 | +0 | 4/4 |
| Off | Anonymous | Short Log(5), four commits | 34 | 34 | 52 | 58 | +6 | 8/8 |
| Off | Anonymous | Log(5) | 42 | 42 | 64 | 72 | +8 | 10/10 |
| Off | Anonymous | Log(10) | 80 | 80 | 124 | 142 | +18 | 20/20 |
| Off | Anonymous | Page1(10) | 85 | 84 | 129 | 147 | +18 | 20/20 |
| Off | Anonymous | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| Off | Anonymous | Log(50) | 380 | 380 | 603 | 701 | +98 | 100/100 |
| Off | Anonymous | Page1(50) | 384 | 383 | 607 | 705 | +98 | 100/100 |
| Off | Anonymous | Canonical Log(10) | 73 | 73 | 86 | 86 | +0 | 20/20 |
| Off | Anonymous | Selected Log(10) | 73 | 73 | 73 | 73 | +0 | 20/20 |
| Off | Owner | Nested Show with sizes | 31 | 31 | 69 | 69 | +0 | 6/6 |
| Off | Owner | Nested Cat | 31 | 31 | 39 | 39 | +0 | 8/8 |
| Off | Owner | Nested Show | 22 | 22 | 38 | 38 | +0 | 6/6 |
| Off | Owner | Flat Show with sizes | 25 | 24 | 57 | 57 | +0 | 4/4 |
| Off | Owner | Short Log(5), four commits | 35 | 35 | 53 | 59 | +6 | 8/8 |
| Off | Owner | Log(5) | 43 | 43 | 65 | 73 | +8 | 10/10 |
| Off | Owner | Log(10) | 81 | 81 | 125 | 143 | +18 | 20/20 |
| Off | Owner | Page1(10) | 85 | 84 | 129 | 147 | +18 | 20/20 |
| Off | Owner | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| Off | Owner | Log(50) | 381 | 381 | 604 | 702 | +98 | 100/100 |
| Off | Owner | Page1(50) | 385 | 384 | 608 | 706 | +98 | 100/100 |
| Off | Owner | Canonical Log(10) | 64 | 64 | 87 | 87 | +0 | 20/20 |
| Off | Owner | Selected Log(10) | 74 | 74 | 74 | 74 | +0 | 20/20 |
| On | Anonymous | Nested Show with sizes | 49 | 49 | 135 | 135 | +0 | 6/6 |
| On | Anonymous | Nested Cat | 54 | 50 | 114 | 114 | +0 | 8/8 |
| On | Anonymous | Nested Show | 36 | 36 | 88 | 88 | +0 | 6/6 |
| On | Anonymous | Flat Show with sizes | 37 | 36 | 106 | 106 | +0 | 4/4 |
| On | Anonymous | Short Log(5), four commits | 73 | 60 | 156 | 162 | +6 | 8/8 |
| On | Anonymous | Log(5) | 90 | 73 | 190 | 198 | +8 | 10/10 |
| On | Anonymous | Log(10) | 173 | 139 | 360 | 378 | +18 | 20/20 |
| On | Anonymous | Page1(10) | 177 | 142 | 364 | 382 | +18 | 20/20 |
| On | Anonymous | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| On | Anonymous | Log(50) | 833 | 659 | 1719 | 1817 | +98 | 100/100 |
| On | Anonymous | Page1(50) | 837 | 662 | 1723 | 1821 | +98 | 100/100 |
| On | Anonymous | Canonical Log(10) | 113 | 113 | 256 | 256 | +0 | 20/20 |
| On | Anonymous | Selected Log(10) | 113 | 113 | 243 | 243 | +0 | 20/20 |
| On | Owner | Nested Show with sizes | 46 | 46 | 136 | 136 | +0 | 6/6 |
| On | Owner | Nested Cat | 55 | 51 | 115 | 115 | +0 | 8/8 |
| On | Owner | Nested Show | 34 | 34 | 89 | 89 | +0 | 6/6 |
| On | Owner | Flat Show with sizes | 36 | 35 | 107 | 107 | +0 | 4/4 |
| On | Owner | Short Log(5), four commits | 74 | 61 | 157 | 163 | +6 | 8/8 |
| On | Owner | Log(5) | 91 | 74 | 191 | 199 | +8 | 10/10 |
| On | Owner | Log(10) | 174 | 140 | 361 | 379 | +18 | 20/20 |
| On | Owner | Page1(10) | 178 | 143 | 365 | 383 | +18 | 20/20 |
| On | Owner | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| On | Owner | Log(50) | 834 | 660 | 1720 | 1818 | +98 | 100/100 |
| On | Owner | Page1(50) | 838 | 663 | 1724 | 1822 | +98 | 100/100 |
| On | Owner | Canonical Log(10) | 104 | 104 | 257 | 257 | +0 | 20/20 |
| On | Owner | Selected Log(10) | 114 | 114 | 244 | 244 | +0 | 20/20 |

The sole permitted metadata-call increase is first-parent successor warming:
two pure reads per consumed successor. Log(10) and Page1(10) add exactly 18
calls; the last result never warms its unused page-boundary parent. Paired probe
runs suppress only warming and assert that GETs and rounds do not increase.
Single-result pages add no warming calls. Other shapes retain equal or lower
call counts.

ListRefs replaces sixteen serial bucket scans with three prepaid waves.
Inventory waves preserve partition/chunk validation order. Fresh dependency
reads deduplicate IDs in first-seen order and use reserved waves; phase-cached
guards retain scalar accounting so cache hits do not consume backend call units.
Delta members stay serial between contiguous raw runs.

## Ordering and budgets

Authorization, proof binding, revalidation, and filtering remain before
location and inventory work. Directory/descriptor checks complete before
fresh dependency admission: a tight shared budget must still observe an earlier
malformed descriptor before spending calls on later dependencies. The regression
uses a 24-call budget and distinguishes `Unavailable` from `ResourceExhausted`.
Continuation activation stays serial. Its guarded closing apply remains the cut
before joined pure reads, and security absence/errors precede anchor errors.

Remaining-allowance hints never reserve or charge work. Unknown or insufficient
allowances retain serial admission. Every dispatched wave still reserves its
calls before dispatch, and all object-reader metadata/blob work uses the same
six-call envelope. Warming dispatches nothing when its optional reservation
does not fit; speculative failures grant no proof and retain no guard reply.
All original call, byte, operation, deadline, and wire limits remain in place.

## Conditional cold model

The cold model sets warm storage latency to 50 ms and first touches of RepoIndex
and ContentShard partitions to 300 or 500 ms. Blob reads remain warm. It reports
both fully cold partitions and initially warm source-pack content partitions.
These are synthetic assumptions, not evidence of actual backend activation.
Cold source-pack guards can remain on the critical path even after the parent's
partitions are warm. In the fully cold 300 ms case, anonymous Log(10) measured
9.75 s without warming and 10.30 s with warming. Retain warming only after the
embedder's cold/warm re-measure confirms a benefit for its actual read shape.
Warming is isolated from the other request-path changes for an independent
revert.
