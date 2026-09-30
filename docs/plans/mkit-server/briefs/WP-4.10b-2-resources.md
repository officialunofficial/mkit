# WP-4.10b-2 resource and lifetime proof (R-186)

This is the extraction driver follow-up to WP-4.10b-1. It changes internal Rust
checkpoints inside existing `vc`; it adds no tag, timer kind, relay codec, wire
format, trait or cross-partition seam. Indexed mode remains release-default-off
until WP-4.18. Both parts share R-186.

## Incremental reconstruction acceptance

The user approved a **2,300 changed physical non-test Rust line** amendment solely for
incremental source lookup/reconstruction in existing vc4 and review/clippy fixes.
The original native-valid member source stalled synchronous reconstruction at
chunk 0; the new cursor preserves lookup, descent and ascent across alarms.
Each alarm examines one bounded index prefix or reconstructs one ancestry frame.
Descriptors and opaque lookup continuation live in vc4; only a bounded cursor,
level and cumulative byte charge enter the guarded header. No protocol surface
has changed.

Final cap audit at `406e0c39`: **2,301 changed physical production lines**,
comprising 2,221 added and 80 removed. The earlier 2,297 count omitted four
removed `cfg(test)` gates that enable production use of existing projection
helpers. Those deletions count; the unchanged 114 helper/import lines are
reported as reused existing code rather than newly added diff lines. This is
one line above the then-approved cap, so execution stopped without pushing or
opening the PR. The user subsequently approved **2,350 lines**, without code
trimming or new scope: additional headroom covers only isolated/parent checks
and necessary fixes of the Worker growth-pruning and two native timer failures.
No runtime resource limit or protocol surface was raised to accommodate it.

The remaining failure checks reproduced both native timer failures on clean
feature parent `bc114103`: filesystem paired runs were PASS/FAIL/PASS versus
parent PASS/PASS/FAIL; S3's earlier parent failure and subsequent passing reruns
show the same intermittent timer path. Worker ticket/outbox pruning also failed
on that clean parent's full growth phase (1,101 keys, bound 609), despite three
passing isolated parent runs. No production fix or trimming was made for these
pre-existing failures. The final complete Worker test-faults/indexed script
passed main 93, growth 2, quota 4 and indexed recovery 1; streamed buffering
peaked at 864,051 bytes, below 1 MiB. Native aggregate gate exceptions, exact
controls and other gate results are recorded in the PR body.

The 50-hop test uses actual producer-generated index rows and native as its oracle.
With 2 KiB source nodes it makes **101 durable reconstruction steps**, consuming
**2,306 observed / 2,318 charged calls** across extraction and final verification. The 250 KiB-node
case also makes **101 steps and 2,306 / 2,318 calls**: cumulative canonical source
size exceeds the entry allowance while the live accumulator remains bounded.
Every alarm stays within 256 calls and advances its durable reconstruction state.
A fresh handler resumes midway through descent without changing persisted rows.
Both reconstructed files, offsets and Scheduled outcome match native. A third
case sets the whole-source decode allowance one byte below the native charge;
both paths return the budget error after bounded progress.

Lookup examines at most eight raw index values at a time, preserves ordered
membership selection and the same-pack earlier-frame preference, and retains
bounded row, page-work and distinct membership-partition counters. Frames retain
existing index encodings. Ascent validates every canonical accumulator through
the core pack decoder's object identity rules, including Merkle-addressed bases,
plus actual depth and geometry. Fresh source authorization and object/pack denial
checks precede frame reads and checkpointed canonical-base reuse.
A single accumulator uses 128 KiB fragments;
ancestors are not held together in memory. Source-byte cost includes every decoded
member node and is charged atomically with the completed chunk cursor, once per
manifest occurrence. The upload pass reconstructs again without charging again.

Feature tip `8bc30385` (merged PR1 #1238, including duplicate-holder intent drain)
was merged in `b2285099`; the interop security lock update was merged in `64e1d683`.
The sync-inspection integration and global V2 denial/admin/inventory changes are
also merged through feature tip `bc114103`. Reviewed relay changes remain intact. Full final gate
results, the final line count and independent review findings are recorded in the
PR body. Staging heap/CPU evidence remains WP-4.18's activation responsibility.

## Whole alarm and verification calls

The real RefShard registration uses `R2Extraction` only for Paid Scheduled
indexed mode. A verification fire reserves **256 calls** from the merged alarm's
shared **1,000-call** counter before running. There is at most one kind-7 fire per
alarm. Stores, pack ranges and object uploads then consume its own 256-call
counter before doing IO. Exhaustion fails the current slice; its durable cursor
replays. The next alarm starts a new counter. Source lookup, lease renewal,
block/hold/protection reads and retries use the same slice counter.

Successful bounded work requests the next alarm without an artificial delay,
including incremental member lookup and reconstruction. The existing scheduler
still advances the timer key by at least one millisecond and permits only one
verification fire per alarm. Missing sources and undelivered holder intents keep
their backoff; pending delivery renews protection before waiting. Index emission
uses 64-row pages, leaving room for the merged per-object denial reads and keeping
even invalid 512 KiB raw values within the 48 MiB resident allowance. The full
group scan, closure barrier and union totals remain mandatory for small objects.

The frozen component ledger remains Paid **889** and Free **49**, including
24 paid expiry calls. This is not the merged alarm total: purge,
snapshot/admin and other merged consumers also reserve from the shared
1,000-call counter. They yield when their reservation cannot fit. Free retains
49 of 50 calls and refuses Scheduled indexed verification; the driver cannot be
registered there. No allowance or fire quota has increased.

The approved callbacks on existing `SliceExtension` default to no-op:
`extraction_enabled`, `begin_object`, `put_object_part`, `complete_object` and
`abort_object`. R2 reserves at most **8 / 3 / 7 / 2** calls respectively for the
four upload callbacks before their IO. Small object/root-bound completion
reserves six. The generic verification registration retains `FailClosedExtraction`;
the actual Worker environment registration uses the driver. Existing
implementors do not change.

## Whole extraction phase memory

The project's allowance is **48 MiB**, not the isolate's platform limit. These
bounds describe simultaneously live buffers, including raw storage rows and
Worker JS copies, rather than just the final object buffer. Heap/CPU measurements
on deployed staging remain an activation gate in WP-4.18.

- **Canonical reconstruction.** Reserve two windows W, the 8 MiB LRU and eight
  entry-sized regions E=(48 MiB-2W-8 MiB)/8. Default W=16 MiB gives E=1 MiB.
  Source frames are checked *before* range reads: encoded length is at most
  max(W,E)+128 bytes, decoded size is at most E, and actual dependency depth is
  bounded. Checkpointed ancestry is depth bounded. Member
  reconstruction retains only the previous canonical accumulator and the newly
  decoded frame, with ancestry descriptors outside the guarded header.
  Parsing, delta output, temporary bases, source object and R2 range copies fit
  the reserved regions. An encoded frame plus the other entry buffers leaves
  an entry-sized margin at default windows; bounded headers/body/metadata fit
  that margin. No original decoder windows survive into later upload phases.
- **Projection and payload reads.** At most eight raw KV values are fetched
  together (at most 4 MiB under the 512 KiB value cap), plus one transient SQL/JS
  row. Projection page geometry/digest and exact payload fragment lengths are
  validated. Payload fragments are normally 128 KiB, so eight valid fragments
  occupy 1 MiB. The sole assembled part is at most 8 MiB. Canonical source
  scratch, bounded headers and multipart metadata are included; this phase
  stays below 24 MiB. No whole file is assembled.
- **Preflight and upload.** A first bounded pass reconstructs and charges
  repository-local canonical sources, even on dedup. It computes part CVs and
  their merged root before opening a root-pinned R-192 session. A second pass
  reconstructs and verifies each part before passing it to R2. Native's charge
  convention is preserved, including repeated manifest chunk occurrences;
  replayed checkpoints cannot reset the group counter. At most 10,000 parts/CVs
  and a 1,024-byte session are permitted by the existing multipart limits.
- **Completion.** No part payload or original decoder window is retained.
  Receipts are fetched eight at a time, each at most 1,089 bytes, and moved into
  the callback. R-192's full bounded root/CV metadata is verified before backend
  completion. A conservative ledger at 10,000 maximum-sized receipts/ETags is
  10,890,000 receipt bytes + 0.8 MiB container space + 0.5 MiB CV capacity +
  10,240,000 Rust ETag bytes + 0.32 MiB tuples + two 2 MiB metadata buffers +
  20,480,000 UTF-16 JS ETag bytes: about **45.3 MiB**. Reserve another 1 MiB for
  JS objects/array and 0.5 MiB for headers, hydrated body and temporaries:
  **under 47 MiB**. The Worker SDK builds JS part objects directly; it does not
  serialize the entire part array into another JSON string. The callback moves
  receipt tags instead of duplicating another eleven MiB. CVs must match
  exact plan geometry, and oversized receipts are rejected before accumulation.
- **Offsets.** Manifest references are bounded by E. Offset rows are read in
  batches of eight and decoded as exact u64s; the output starts at zero,
  increases monotonically, and ends at the verified file length. The encoded
  sidecar and the one-MiB streaming pieces stay inside the reconstruction
  allowance. Empty chunks/empty manifests retain native's offsets.
- **Advance union reporting.** Completed exact groups reuse their frozen
  distinct-object count and canonical-byte total. Other current producer rows
  merge sorted frame streams with one 64-row raw page at a time, retaining only
  IDs and sizes from previous pages. The SQL lookahead is at most 65 raw rows,
  32.5 MiB, plus one transient JS row and small heads/guards: below 35 MiB.
  The DO/SQL adapter moves raw values into KV values, without cloning a whole
  page or retaining a complete JS row array.

A real 8 MiB+99-byte multipart driver test observes PREFLIGHT, UPLOAD and COMPLETE
using at most eight raw rows. Native-oracle tests cover charge stability, exact
union counts/bytes and duplicate-byte decode-budget boundaries. Corrupt checkpoint
counters, cursors and frame geometry fail closed before oversized allocation.

## Apply bounds and immutable job facts

All applies retain the existing **100-operation** and **1 MiB** caps. Auxiliary
writes split at the actual store's validated operation/byte limit, with the exact
owning header and NotAfter. Final checkpoint/protection/relay plans retain exact
observations and deadlines. Generic current 96-effect relays still work.

The vc0 header is versioned, bounded by **16 KiB**, and contains state, generation
and immutable body identity. Completed satisfying-member/MKPL lists are a separate
content-addressed vc4 body. Any header mutation advances generation; a body change
writes another immutable body and advances generation in the same apply. Cleanup
first CASes the header to a Gone tombstone and retains that generation forever.
It cannot erase a reused live generation or permit same-ticket ABA.

Peer reuse guards only peer headers. Seven ready groups each with six other
peers need at most 49 distinct observed headers; allowing seven rewritten
headers gives 56 x 16 KiB = **917,504 bytes**, leaving **131,072 bytes** for bounded
keys, tickets/state observations and timers. Exact Batch validation remains the
final check. The six-group/256-member fixture's 42 peer headers total **133,093
bytes**, and its new-job claim uses **160,271 bytes**. The complete immutable
bodies never enter peer guards. Maximum header fixtures measure 12,592 bytes
ordinarily and 13,465 bytes while extracting; their member body is 67,500 bytes.

Cleanup retains facts for a matching unfinished peer while its ticket is live or
an object is already started/draining. Ticketless pre-effect peers do not retain
each other forever. The Gone CAS guards peer headers and observed ticket presence
or absence, so a concurrent claim or revived ticket defeats stale cleanup.

## Group, closure and ticket decisions

Selection uses the complete ordered consumed union, with first-pack ownership,
chunk-only Blob exclusion, direct file references and already-Verified sources.
The group's closure, dependencies, satisfying members, packlists and head are
validated before the first hold/protection/upload effect. Missing unstaged content
waits only through its source owner's allowed membership lag, then reports
native's closure error. A genuinely later member can retry that pre-effect error.
Started objects retain their durable progress on terminal failure.

Distinct tickets naming the same pack are all validated and consumed normally.
Pack facts, extraction ownership and counts are deduplicated by pack ID; the
first consumed ticket owns extraction. The immutable native object union also
deduplicates canonical IDs and byte totals across different packs. External-base
charges retain R-171's conservative per-pack convention; extraction member-source
charges retain native's per-occurrence convention. Neither duplicate ticket can
cause a second extraction or release another ticket's protection.

The group charge identity excludes the changing immutable member-list body ID;
body observations still guard closure/freeze. Adding a satisfying member cannot
reset charges accumulated by another owner. Frozen source identity includes pack,
ticket, length, age, ETag, version and decoded facts. Exact header observations
prove its lifetime, including benign post-freeze member-list growth.

Fresh block/deleting checks precede effects. Lease renewal precedes protection,
part publication, object/root-bound commit and holder enqueue; a lost lease
fails closed. Queued holder delivery can drain beyond ticket expiry/ordinary TTL
under durable gp, while holds are renewed. Verify follows target holder delivery.
The frozen target hook handles duplicate delivery, conservative counts and late
blocked durable takedown requests; request execution remains WP-5.6a.

Launch retains permanent objects, has no GC-enabling path and keeps GC off.
No migration, old-build compatibility, GC machinery or new protocol foundation
is introduced.
