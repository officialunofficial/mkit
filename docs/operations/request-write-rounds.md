# Request write rounds

The write-round probe measures signed ref writes the way
`pipeline/tests/http_objects/read_rounds.rs` measures reads: every namespace
and blob call is recorded, tagged with a pipeline phase, and priced on a paused
clock — 30 ms per call warm, 300 ms for the first touch of each index or
content partition (and once for the blob store).
Rounds count dependent calls (overlapping delays coalesce), not elapsed
production latency; the numbers size mkit's share of an embedder's per-write
wall time and expose serial work.

`pipeline/tests/http_objects/write_rounds.rs` pins every cell exactly; the
AD1 effect-recording admission hook measures identically to the default hooks
(an in-memory hook adds no backend calls). Run from **rust/**:

```sh
cargo test -p mkit-server --all-features --lib write_rounds -- --nocapture
```

## Signed write shapes

Each cell is one request on a seeded repository (two published branches,
`refs/heads/main` and `refs/heads/two`, each with its packmap, all members
verified). `UpdateRef Match` moves `main` to the child commit inside the same
pack. Denial on sets `takedown_denial`; an "open closure" cell is the public
error the request ends with — a ticketless create cannot carry a packlist
under denial, so on the branch ops only `AdvanceRefs` with an explicit
packmap, or a `Match` move inside an existing packlist, can commit. `Tag
create` commits under denial because tag refs carry no packmap to prove.

| Shape | Shard | Denial | Outcome | KV | Blobs | Warm ms | Cold ms | Rounds |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| UpdateRef Match | Single | off | committed | 4 | 2 | 150 | 420 | 5 |
| UpdateRef Match | Single | on | committed | 48 | 2 | 1110 | 3270 | 37 |
| UpdateRef Match | D34 | off | committed | 4 | 2 | 150 | 960 | 5 |
| UpdateRef Match | D34 | on | committed | 50 | 2 | 1140 | 4650 | 38 |
| UpdateRef Missing | Single | off | committed | 4 | 2 | 150 | 420 | 5 |
| UpdateRef Missing | Single | on | open closure | 5 | 2 | 180 | 990 | 6 |
| UpdateRef Missing | D34 | off | committed | 7 | 2 | 240 | 1050 | 8 |
| UpdateRef Missing | D34 | on | open closure | 8 | 2 | 270 | 1620 | 9 |
| AdvanceRefs create | Single | off | committed | 4 | 2 | 150 | 420 | 5 |
| AdvanceRefs create | Single | on | committed | 48 | 2 | 1110 | 3270 | 37 |
| AdvanceRefs create | D34 | off | committed | 7 | 2 | 240 | 1050 | 8 |
| AdvanceRefs create | D34 | on | committed | 52 | 10 | 1350 | 5400 | 45 |
| AdvanceRefs source_ref | Single | off | committed | 8 | 2 | 270 | 540 | 9 |
| AdvanceRefs source_ref | Single | on | committed | 47 | 2 | 1080 | 3240 | 36 |
| AdvanceRefs source_ref | D34 | off | committed | 11 | 2 | 360 | 1170 | 12 |
| AdvanceRefs source_ref | D34 | on | committed | 52 | 8 | 1320 | 4830 | 44 |
| Tag create | Single | off | committed | 4 | 2 | 150 | 420 | 5 |
| Tag create | Single | on | committed | 38 | 6 | 870 | 3300 | 29 |
| Tag create | D34 | off | committed | 7 | 2 | 240 | 1050 | 8 |
| Tag create | D34 | on | committed | 46 | 6 | 1080 | 4590 | 36 |
| Ref delete | any | any | committed | 2 | 0 | 60 | 60 | 2 |

`PlanSnapshot` holds every fused read plus the mid-request checks the
classifier cannot separate; `GuardedApply` is every guarded batch, including
mid-request CAS writes, not only the final commit.

Denial off, a signed ref write is 4–7 KV calls and one batch: the fused
read-ahead, the object-index lookup and membership read, then the apply. The
embedder's plain writes are cheap in mkit's model — five dependent rounds,
150 ms warm on Single; D34 adds the coordinator lease and outbox for creates
(8 rounds, 240 ms), and `source_ref` runs 9–12 rounds (270–360 ms). All stay
well under half a second at a generous real per-call latency. The denial-on
row is where the rounds are.

## Embedder flow: upload, scheduled verify, ticketed advance

The embedder's shape end to end — `BeginUpload` + `UploadPack` session, a
tiny-slice scheduled verification (the SP2 settle), then the ticketed
`AdvanceRefs` for head + packmap. PW1's hold at 0 ms is the client-retry path;
at 1000 ms the first advance parks in the server hold while verification
settles. Steps are per-request or out-of-band (`settle` runs on timers).

| Shard | Denial | Hold | Step | KV | Blobs | Warm ms | Cold ms |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: |
| Single | off | 0 | upload | 13 | 6 | 570 | 840 |
| Single | off | 0 | advance (pending) | 5 | 2 | 210 | 210 |
| Single | off | 0 | settle (out of band) | 62 | 1 | 1890 | 2160 |
| Single | off | 0 | advance (commit) | 9 | 2 | 330 | 330 |
| Single | on | 0 | upload | 23 | 12 | 1050 | 1320 |
| Single | on | 0 | advance (pending) | 5 | 4 | 210 | 210 |
| Single | on | 0 | settle (out of band) | 90 | 2 | 2700 | 3510 |
| Single | on | 0 | advance (commit) | 54 | 4 | 1320 | 2400 |
| D34 | off | 0 | upload | 13 | 6 | 570 | 840 |
| D34 | off | 0 | advance (pending) | 5 | 2 | 210 | 210 |
| D34 | off | 0 | settle (out of band) | 97 | 1 | 2940 | 3750 |
| D34 | off | 0 | advance (commit) | 9 | 2 | 330 | 330 |
| D34 | on | 0 | upload | 23 | 12 | 1050 | 1320 |
| D34 | on | 0 | advance (pending) | 5 | 4 | 210 | 210 |
| D34 | on | 0 | settle (out of band) | 123 | 2 | 3720 | 5070 |
| D34 | on | 0 | advance (commit) | 54 | 4 | 1320 | 2400 |
| Single | off | 1000 | advance (parked) | 6 | 2 | 270 | 270 |
| Single | off | 1000 | advance (commit) | 10 | 2 | 360 | 360 |
| Single | on | 1000 | advance (parked) | 6 | 4 | 270 | 270 |
| Single | on | 1000 | advance (commit) | 55 | 4 | 1350 | 2430 |
| D34 | off | 1000 | advance (parked) | 6 | 2 | 270 | 270 |
| D34 | off | 1000 | advance (commit) | 10 | 2 | 360 | 360 |
| D34 | on | 1000 | advance (parked) | 6 | 4 | 270 | 270 |
| D34 | on | 1000 | advance (commit) | 55 | 4 | 1350 | 2430 |

Hold cells share the upload and settle rows of their 0 ms sibling. The hold's
own 1000 ms of parking is not backend time; the parked attempt costs one more
KV call than the client-retry answer.

End-to-end the embedder's write costs 89 KV calls on Single without denial —
only 27 of them on request paths (upload + both advances); the other 62 are the
out-of-band verification pump. With denial the request path nearly triples
(82 calls, 2580 ms warm modeled) because the committing advance pays the full
denial price. Against a reported multi-second per-write latency, mkit's
request-path model is ~1.1 s warm without denial and ~2.6 s with it; cold
first touches add ~0.3 s more without denial and ~1.4 s with it. Anything
beyond that needs numbers from the real store's per-call latency — the probe's
30 ms unit is deliberately conservative, and the dependent chains below are
what scale with it.

## Findings (measurement only — fixes belong to a follow-up lane)

Each entry lists what the probe observed and the modeled saving. Savings are
warm-model upper bounds for the serialized work, not predicted wall-clock.

1. **Denial turns a 4-call write into ~50.** The denied `UpdateRef Match` on
   Single spends 46 of 48 calls in `PlanSnapshot`: a ~19-call serial member /
   denial walk, a `vs` checkpoint write, a 16-shard directory proof, then a
   full snapshot re-read.
   - The member walk runs per closure hop: `i` index lookup, `m` membership,
     and two fused `b` denial reads per object — `verify_member_head`
     (`indexed/verify.rs:154`) → `member_object_inner` /
     `member_dependencies_clear` (`indexed/resolve.rs:601`,
     `resolve.rs:682-698`) → `denied()` → `ContentIndex::blocked`
     (`takedown/denial.rs:324`, `store/content_index.rs:765`). ~18 serial
     calls ≈ 540 ms warm before planning starts.
   - The repo proof scans all 16 deny-directory shards in waves of
     `WRITE_PROOF_CONCURRENCY = 4` (`takedown/denial.rs:477`,
     `denial.rs:503-524`, `takedown/directory.rs:114-159`), preceded by a
     serial `inventory::visit` per published pack
     (`denial.rs:630-633`). Empty directory: 16 scans / 4 rounds. With N
     entries the per-entry `descriptors()` reads stay serial
     (`directory.rs:215`). Raising the wave width is worth ≤3 rounds on an
     empty directory; the descriptor tail is the real serial cost.
   - After the proof the loop discards the read-ahead wholesale — "only fixed
     admission quota facts survive" — and `read_snapshot` re-fetches ~10 keys
     already read this request (`pipeline/mod.rs:4242-4255` vs the `read_ahead`
     set at `mod.rs:3285-3358`). Deliberate per §14.2, but the discard costs
     one fused call + one round; a narrower invalidation set is a candidate.
   - Estimated saving for `UpdateRef Match` Single/denial: the proof alone is
     ~22 calls ≈ 15 dependent rounds; overlapping the per-hop denial reads
     with the index lookups could cut roughly a third of the 37 rounds.

2. **Every upload-session RPC re-reads the authority fence pair.** One
   `BeginUpload` + `UploadPack` session issues seven identical serial
   `get_many(ag, lr)` calls — `check_ticket_generation` →
   `ensure_authority_activation` reads both rows per call site
   (`pipeline/authority.rs:37-42`, `authority.rs:61-96`), reached from the
   session claim checks (`pipeline/upload.rs:345-532`, `pipeline/parts.rs:120-248`).
   On Single with fencing disabled the read still runs and early-returns.
   ~180 ms warm per uploaded object; one read per request would save 6 calls
   and 6 rounds per session.

3. **A pending advance is not free.** The first ticketed `AdvanceRefs` that
   answers `pack verification pending` still does a `GuardedApply` writing the
   `vc` job rows and `w` timers per ticket before returning (5–6 KV calls).
   That is the scheduling write doing its job — but embedders counting a
   "pending" reply as cheap should note it costs a full plan+apply.

4. **The commit retry re-reads verify-job rows serially.** The retry's
   usability check does `get_many(vc,vs)` then `scan(vc)` ranges plus
   per-member `get` reads per ticket (`indexed/scheduled.rs:809-821`,
   `scheduled.rs:952-1012`, `scheduled.rs:200-228`) — ~6 serial calls ≈ 180 ms
   warm per ticket before the fused re-read.

5. **Duplicate whole-pack blob reads on the request path.** `Tag create`
   Single/denial fetches the target commit's pack **four times** and the
   packmap's pack twice in one request (6 `blob_get`s); `UpdateRef Match`
   fetches its pack twice. Separate stages each call `frame_bytes`
   (`indexed/resolve.rs:153`) or `pack_bytes` (`indexed/verify.rs:188`) with no
   per-request memo — `check_member_head_type`, the publication pair verify
   (`pipeline/mod.rs:4084-4099`), and the resume slice all re-decode the same
   frames. A request-scoped frame cache would cut tag-create denial to ~2
   gets, ~2 blob rounds.

6. **The publication-resume checkpoint writes `vs` mid-request.** Under
   denial, `verify_publication` resumes the packmap root's advance
   (`pipeline/mod.rs:4037-4056` → `indexed/publication/resume.rs:244-348`):
   read `vs`, run a traversal slice, then CAS `vs` back with retained
   progress — even when the slice completes and nothing remains pending. One
   extra guarded apply ≈ 1 round on every denial-on write that moves a branch.

7. **Source-ref and D34 paths re-read rows.** `AdvanceRefs source_ref` reads
   `(rr, rv, e)` twice and the publication row `pp` twice — once capturing the
   source (`pipeline/published_source.rs:81`) and again in planning
   (`pipeline/mod.rs:3290-3295`). On D34 under denial the coordinator lease
   runs `observe_lease` + `admit_lease` twice — once before planning and again
   inside the apply loop because `prove` forces re-admission
   (`pipeline/lease.rs:631`, `lease.rs:718`, `pipeline/mod.rs:4257-4275`) —
   4 coordinator calls ≈ 3 extra rounds on the D34 denial cells that lease
   (advances, creates and tag creates); a `Match` move inside an existing
   packlist takes no lease at all, and a `Missing` create rejected at plan
   pays only the first admission.

8. **The settle pump is serial per job.** Scheduled verification drives
   ~9-call checkpoint rounds per fired job — `scan(w)` claim, `vc`/`vs` reads,
   claim apply, slice work, checkpoint apply, reschedule
   (`timers/mod.rs:311-359`, `timers/mod.rs:170-242`) — plus a re-scan of the
   `w` prefix per pump tick. It is out of band, so it does not sit on the
   request's wall clock, but the same serial chain decides how soon the retry
   can commit: 62–123 calls and 1890–3720 modeled ms for this two-pack flow.

9. **Upload markers double blob writes and are re-checked per advance.** Each
   `upload()` writes the pack *and* an `UploadMarker` blob (begin/write/commit
   = 6 blob calls), and each ticketed advance then `blob_head`s every ticket's
   marker and pack — once when it answers pending, again on the commit retry.
   Blob-side: 12 calls to upload two small packs under denial, then 4 head
   calls per advance attempt.

10. **Admission hooks cost nothing on the wire.** The AD1 effect-recording
    hook measures call-for-call identical to the default hooks in all 48
    matrix cells — admission is in-memory and never touches storage.

## Caveats

- The 30 ms unit is a modeling constant, not a store benchmark; real savings
  scale with the deployment's per-call latency. Cold-modeled cells charge
  300 ms only for the first touch of each index or content partition and once
  for the blob store (`read_probe::partition_latency_ms`) — an upper bound
  when partitions stay warm across requests.
- The settle step is a fixed pump: twelve `run_due` ticks at 1 ms apart, so
  its call counts are for this two-pack flow, not a general settlement price.
- `PlanSnapshot` over-attributes: the probe tags by key class, so denial proof
  and resume work inside `plan_and_apply` all land there.
- Rounds measure the dependent chain under the paused clock, not wall time;
  two calls counted in one round still cost two backend invocations.
