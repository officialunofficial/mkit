# Request read rounds

**Reference-server behavior.** These fixture measurements describe the
reference server at the named commits. They are not protocol limits or
production latency claims. Rounds measure dependent virtual latency; metadata
calls measure API invocations. They are different units.

Run from **rust/**:

```sh
cargo test -p mkit-server --features http-objects --lib embedder_read_shapes -- --nocapture
cargo test -p mkit-server --all-features --lib first_parent_ -- --nocapture
```

## Historical snapshot: original baseline

The table below is the original snapshot introduced at
`05c0bc49eb044a98171eee8a87aa19ae3e9c0103`, measured against baseline
`2e25d163a2fc7d28227b78a7dd06bd3c9c432a85`. It is historical evidence,
not a statement of current results.

Nested reads use one commit, eight files, and a nested directory. Flat reads
use four commits and six files. The longer history contains 52 commits and two
files, with one new pack per commit. This historical model charged a ranged blob read two call
units; the table counts actual blob GETs separately. The current default models
one GET; `MKIT_BENCH_RANGED_HEAD=1` opts into HEAD plus GET.
Page1(10) activates the missing visibility revision on the first anonymous,
denial-off run. Subsequent page measurements reuse that durable revision.

| Denial | View | Shape | Rounds before | Rounds after | KV before | KV after | KV delta | GET before/after |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Off | Anonymous | Nested Show with sizes | 34 | 34 | 68 | 68 | +0 | 6/6 |
| Off | Anonymous | Nested Cat | 30 | 30 | 38 | 38 | +0 | 8/8 |
| Off | Anonymous | Nested Show | 24 | 24 | 37 | 37 | +0 | 6/6 |
| Off | Anonymous | Flat Show with sizes | 26 | 25 | 56 | 56 | +0 | 4/4 |
| Off | Anonymous | Short Log(5), four commits | 34 | 34 | 52 | 52 | +0 | 8/8 |
| Off | Anonymous | Log(5) | 42 | 42 | 64 | 64 | +0 | 10/10 |
| Off | Anonymous | Log(10) | 80 | 80 | 124 | 124 | +0 | 20/20 |
| Off | Anonymous | Page1(10) | 85 | 84 | 129 | 129 | +0 | 20/20 |
| Off | Anonymous | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| Off | Anonymous | Log(50) | 380 | 380 | 603 | 603 | +0 | 100/100 |
| Off | Anonymous | Page1(50) | 384 | 383 | 607 | 607 | +0 | 100/100 |
| Off | Anonymous | Canonical Log(10) | 73 | 73 | 86 | 86 | +0 | 20/20 |
| Off | Anonymous | Selected Log(10) | 73 | 73 | 73 | 73 | +0 | 20/20 |
| Off | Owner | Nested Show with sizes | 31 | 31 | 69 | 69 | +0 | 6/6 |
| Off | Owner | Nested Cat | 31 | 31 | 39 | 39 | +0 | 8/8 |
| Off | Owner | Nested Show | 22 | 22 | 38 | 38 | +0 | 6/6 |
| Off | Owner | Flat Show with sizes | 25 | 24 | 57 | 57 | +0 | 4/4 |
| Off | Owner | Short Log(5), four commits | 35 | 35 | 53 | 53 | +0 | 8/8 |
| Off | Owner | Log(5) | 43 | 43 | 65 | 65 | +0 | 10/10 |
| Off | Owner | Log(10) | 81 | 81 | 125 | 125 | +0 | 20/20 |
| Off | Owner | Page1(10) | 85 | 84 | 129 | 129 | +0 | 20/20 |
| Off | Owner | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| Off | Owner | Log(50) | 381 | 381 | 604 | 604 | +0 | 100/100 |
| Off | Owner | Page1(50) | 385 | 384 | 608 | 608 | +0 | 100/100 |
| Off | Owner | Canonical Log(10) | 64 | 64 | 87 | 87 | +0 | 20/20 |
| Off | Owner | Selected Log(10) | 74 | 74 | 74 | 74 | +0 | 20/20 |
| On | Anonymous | Nested Show with sizes | 49 | 49 | 135 | 135 | +0 | 6/6 |
| On | Anonymous | Nested Cat | 54 | 50 | 114 | 114 | +0 | 8/8 |
| On | Anonymous | Nested Show | 36 | 36 | 88 | 88 | +0 | 6/6 |
| On | Anonymous | Flat Show with sizes | 37 | 36 | 106 | 106 | +0 | 4/4 |
| On | Anonymous | Short Log(5), four commits | 73 | 60 | 156 | 156 | +0 | 8/8 |
| On | Anonymous | Log(5) | 90 | 73 | 190 | 190 | +0 | 10/10 |
| On | Anonymous | Log(10) | 173 | 139 | 360 | 360 | +0 | 20/20 |
| On | Anonymous | Page1(10) | 177 | 142 | 364 | 364 | +0 | 20/20 |
| On | Anonymous | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| On | Anonymous | Log(50) | 833 | 659 | 1719 | 1719 | +0 | 100/100 |
| On | Anonymous | Page1(50) | 837 | 662 | 1723 | 1723 | +0 | 100/100 |
| On | Anonymous | Canonical Log(10) | 113 | 113 | 256 | 256 | +0 | 20/20 |
| On | Anonymous | Selected Log(10) | 113 | 113 | 243 | 243 | +0 | 20/20 |
| On | Owner | Nested Show with sizes | 46 | 46 | 136 | 136 | +0 | 6/6 |
| On | Owner | Nested Cat | 55 | 51 | 115 | 115 | +0 | 8/8 |
| On | Owner | Nested Show | 34 | 34 | 89 | 89 | +0 | 6/6 |
| On | Owner | Flat Show with sizes | 36 | 35 | 107 | 107 | +0 | 4/4 |
| On | Owner | Short Log(5), four commits | 74 | 61 | 157 | 157 | +0 | 8/8 |
| On | Owner | Log(5) | 91 | 74 | 191 | 191 | +0 | 10/10 |
| On | Owner | Log(10) | 174 | 140 | 361 | 361 | +0 | 20/20 |
| On | Owner | Page1(10) | 178 | 143 | 365 | 365 | +0 | 20/20 |
| On | Owner | ListRefs | 17 | 4 | 17 | 17 | +0 | 0/0 |
| On | Owner | Log(50) | 834 | 660 | 1720 | 1720 | +0 | 100/100 |
| On | Owner | Page1(50) | 838 | 663 | 1724 | 1724 | +0 | 100/100 |
| On | Owner | Canonical Log(10) | 104 | 104 | 257 | 257 | +0 | 20/20 |
| On | Owner | Selected Log(10) | 114 | 114 | 244 | 244 | +0 | 20/20 |

Metadata calls are equal in every probe row; no shape's rounds increase. GETs are
unchanged.

ListRefs replaces sixteen serial bucket scans with three prepaid waves.
Inventory waves preserve partition/chunk validation order. Fresh dependency
reads deduplicate IDs in first-seen order and use reserved waves; phase-cached
guards retain scalar accounting so cache hits do not consume backend call units.
Delta members stay serial between contiguous raw runs.

## Current snapshot

Source: `2cccd133ebe5871a738415a021c189894c4337c5`. Fixture: 52 linear
commits, two root files, file 0 changed and a fresh pack per commit, with
reference branch-bucketed metadata addressing. Features: `mkit-server/http-objects`, default probe configuration.
Denial: off. Counting model: paused Tokio time, six-way read admission, 30 ms
virtual latency per call; rounds equal virtual elapsed time divided by that
latency. Metadata calls exclude blob calls. Ranged reads use one GET by default.
The selected and canonical probes follow first parents; ordinary Log uses the
history-walk API. Their counts are not interchangeable.

| View | API / shape | Dependent rounds | Metadata calls | Blob GETs |
| --- | --- | ---: | ---: | ---: |
| Anonymous | Selected-ref canonical reads, Log(10) | 43 | 33 | 20 |
| Owner | Selected-ref canonical reads, Log(10) | 44 | 34 | 20 |
| Anonymous | Canonical object reads, Log(10) | 43 | 46 | 20 |
| Owner | Canonical object reads, Log(10) | 44 | 47 | 20 |
| Anonymous | History walk, Log(10) | 66 | 64 | 20 |
| Owner | History walk, Log(10) | 67 | 65 | 20 |

The probe `embedder_read_shapes_report_rounds` prints these measured counters
separately from its retained historical constants. Re-run it at the source SHA
and retain the same environment and fixture when comparing results.

## Ordering and budgets

Authorization, proof binding, revalidation, and filtering remain before
location and inventory work. Directory/descriptor checks complete before
fresh dependency admission: a tight shared budget must still observe an earlier
malformed descriptor before spending calls on later dependencies. The regression
uses a 24-call budget and distinguishes `Unavailable` from `ResourceExhausted`.
Continuation activation stays serial. Its guarded closing apply remains the cut
before joined pure reads, and in the closing fence security absence/errors
precede anchor errors; the resumed prologue consumes the anchor first.

Remaining-allowance hints never reserve or charge work. Unknown or insufficient
allowances retain serial admission. Every dispatched wave still reserves its
calls before dispatch, and all object-reader metadata/blob work uses the same
six-call envelope.
All original call, byte, operation, deadline, and wire limits remain in place.

One accounting consequence is deliberate. A wave is prepaid, so when one
member of a wave fails or refuses, its already-dispatched siblings stay charged
(serial code would have stopped at the first failure), including the implicit
packmap prologue when a malformed packmap is refused; successful shapes are
unaffected.

## Deferred: pre-wake parent shards, pending production cold/warm split

An earlier revision of this change warmed each consumed first-parent
successor's RepoIndex and ContentShard partitions with two pure reads joined to
the preceding commit's validation tail (+2 metadata calls per consumed
successor: +18 on Log(10), +98 on Log(50)). It was removed because the model
cuts both ways. With warm storage at 50 ms and first touches at 300 or 500 ms
(synthetic assumptions, not evidence of real activation), anonymous Log(10),
denial off:

| First touch | Source-pack guards | Without | With |
| --- | --- | --- | --- |
| 300 ms | warm | 9.75 s | 8.05 s |
| 300 ms | cold | 9.75 s | 10.30 s |
| 500 ms | warm | 14.35 s | 11.65 s |
| 500 ms | cold | 14.35 s | 15.70 s |

It helps only when source-pack guards are already warm, is slower when
everything is cold, and shrinks the largest page that completes inside the
fixed call allowance by about 5% to 14%. Revisit with the production cold/warm
split. `first_parent_log_models_cold_first_touches` keeps the cold-model
harness for the unchanged walk.
