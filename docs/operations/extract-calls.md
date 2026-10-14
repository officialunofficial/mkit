# Extract pack-window calls

Extract shares a bounded pack buffer across the staged non-delta chunks of
one walk slice. It plans at most sixteen references, reads at the first
chunk's existing reader boundary, and decodes every chunk separately. The
planner stops at the chunk completing the current output part. The
buffer holds at most 4 MiB plus 240 bytes of frame headers, or the configured
window limit when smaller. This fits sixteen ingest chunks of 256 KiB,
including their canonical and frame headers. A different source pack or a
span exceeding the cap stops planning. A frame outside the buffer releases
it and uses the existing per-frame reader. No buffer survives a slice.

The read still uses the job's captured etag. Each chunk keeps its denial,
hash, size, and identity checks. Pack-denial checks still run before a part
upload and before the slice commits. Protection runs at slice start, and the
lease is renewed immediately before upload. External and delta members keep
their existing lookup and reconstruction path. There is no wire, API, or
stored-format change, and no store reset.

## Walk call model

The table counts charged remote storage and pack-window calls across both
PREFLIGHT and UPLOAD. It includes each stage's ending protect-only slice.
It excludes selection, object begin/complete, offsets, and relay delivery;
the test also prints those stages separately. Part boundaries end a slice
and can cause the same chunk to decode again next time. Chunk references,
rather than distinct objects, determine the work.

| Fixture | Walk slices, both passes | Before, denial on | Shared window, denial on | Before, denial off | Shared window, denial off |
|---|---:|---:|---:|---:|---:|
| 64 references, nearly 256 KiB each | 12 | 331 | 211 | 191 | 71 |
| 600 references, nearly 150 MiB | 114 | 3,155 | 2,031 | 1,807 | 683 |
| 4,096 references, nearly 1 GiB (arithmetic) | 768 | 21,499 | 13,819 | 12,287 | 4,607 |
| 1,800 references, 150 MiB, fourteen repeated chunks plus a tail | 264 | 8,855 | 5,481 | 4,957 | 1,583 |

| Fixture | Calls/reference before → shared, denial on | Calls/slice before → shared, denial on | Calls/reference before → shared, denial off | Calls/slice before → shared, denial off |
|---|---:|---:|---:|---:|
| 64 | 5.172 → 3.297 | 27.583 → 17.583 | 2.984 → 1.109 | 15.917 → 5.917 |
| 600 | 5.258 → 3.385 | 27.675 → 17.816 | 3.012 → 1.138 | 15.851 → 5.991 |
| 4,096 | 5.249 → 3.374 | 27.993 → 17.993 | 3.000 → 1.125 | 15.999 → 5.999 |
| 1,800 | 4.919 → 3.045 | 33.542 → 20.761 | 2.754 → 0.879 | 18.777 → 5.996 |

With denial on, each pass costs `D + W + 5S + F + R`: `D` frame
decodes, `W` walk slices (one deferred pack denial each), `S = W + 1`
including the ending step, `F = 1` for the first PREFLIGHT protection and
zero for UPLOAD, and `R` pack reads. Previously `R = D`; adjacent frames
now give `R = W`. With denial off, the existing denial skip removes `D + W`
and costs `5S + F + R`. Protection calls remain.

The original 600-reference fixture repeats content every 256 entries. Staged
rows select the first occurrence, so the read planner can encounter a pack
offset discontinuity. The arithmetic test models that fallback, without
changing the fixture. The separate unique-frame test proves sharing for
adjacent distinct frames. The production-shaped fixture reconstructs
150 MiB from about 1,800 references and a small set of distinct chunks.

## Latency model

These are call-wait estimates, not runtime measurements. At 45–61 ms per
charged call, the 600-reference fixture's two walks fall from 142–192 seconds
with denial on and per-frame reads to 31–42 seconds with shared reads and
denial off. The 1 GiB arithmetic fixture falls from 967–1,311 seconds to
207–281 seconds. The 1,800-reference fixture falls from 398–540 seconds to
71–97 seconds. Other push phases are unchanged.

For the observed large-file geometry, retain the observed slice counts as a
conservative input: 283 slices for 150 MiB and 1,752 for 1 GiB. Approximately
six calls per slice after sharing and the denial skip gives 1,698 and 10,512
calls, or 76–104 seconds and 473–641 seconds of charged-call wait. The old
8,829 and 59,134 calls model 397–539 seconds and 2,661–3,607 seconds at the
same latency range. Smaller slices caused by the two-second cutoff can now
reach the unchanged sixteen-step cap, so slice counts can fall further.

The observed total times were 603 and 3,021 seconds. The effective per-call
ratios do not isolate remote latency from CPU, local storage, or uploads.
Full Extract duration also includes part uploads, local work, and alarm gaps.
The retained evidence attributes about 64 and 352 seconds to ordinary and
outlier alarm gaps. Adding those unchanged gaps to the call-wait scenarios
gives 140–168 seconds and 825–993 seconds before additional local work and
part-upload costs. These are partial models, not end-to-end forecasts:
the telemetry does not separate the remaining costs.

## Regression evidence

The extraction budget tests cover exact read counts, a shared window over
a pack-part boundary and a chunk spanning an output-part boundary, an out-of-window fallback, the fixed byte cap,
and corruption inside a later frame. The corrupted chunk remains the first
failing cursor, even though its bytes arrived alongside earlier frames.
A planned span beyond the recorded pack length uses the per-frame path,
so a bad future offset cannot fail an earlier valid chunk.
Existing crash, lost-part-reply, protection, lease, and mid-slice pack-block
oracles retain their assertions. `MKIT_TEST_EXTRACT_CHAIN=1` exercises the
one-chunk path. Read-shape probes outside Extract retain their expectations.
