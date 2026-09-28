## Purpose

Indexed mode (SPEC-SERVER §9) needs a repository-scoped answer to "which of these objects does this repository hold,
and where". The closure, delta-base and packlist checks all need it, and so do HTTP serving and the takedown sweep.

This WP builds:
- the storage layout;
- the deterministic row planner;
- the read APIs.

It has no production writer yet. Its writers arrive with WP-4.7 (native) and WP-4.8 (Workers). Test it with synthetic
rows, the way WP-1.23a was tested.

## A. Fixed (do not change)

1. **SPEC-SERVER §9:**
   - §9.1: indexed mode;
   - §9.2–9.4: membership checks that stay isolated to the repository, and the lag window;
   - §9.5: verification state per (repository, pack);
   - §9.8: the delta-chain cap.
2. **R-102:** relay rows carry upserts only. **R-110:** relay lag can exceed 60 s.
3. **The index fan-out is 4096**, using the top 12 bits of the id, the same as membership's d34 mapping.
4. **The advance batch has no room for per-object rows.** Index rows are delivered by their own relay rows or by direct
   writes, never inside the advance batch.

## B. Decided (do not change)

### B1. Key and value

- **Key:** `i 00 <repo> 00 <object:32> <pack:32>`.
- **Value:** a **write-once** compact binary value behind a version byte, not JSON. It holds:
  - frame offset;
  - frame length;
  - wire type;
  - decoded size;
  - an optional delta base;
  - chain depth.
- A pack that repeats an entry: the first occurrence wins.
- Add a golden for the key and value bytes, `parse` round trips, and an updated `RESERVED_TAGS` (`i` becomes used).

### B2. Validity comes from membership

- A row counts only if `m <repo> <pack>` exists for its pack.
- There is **no** per-row `pending`/`verified`/`extracted` state. Rows may be written early.

### B3. Several identical producers are allowed

- Relax the "each source/key must have exactly one producer" comment at `relay/deliver.rs:~49`, and record the
  relaxation in R-130.
- Identical values from different sources are safe under the `rh` dedup.

### B4. Routing

- Add `ShardMap::object_index(repo, &Hash) -> Partition` using the 12-bit prefix, and update the d34 golden.
- Don't refactor `content_shard`.

### B5. APIs

- **`plan_index_rows(...)`**:
  - groups rows by target;
  - chunks them to `MAX_RELAY_PUTS` and the byte limits;
  - writes directly when target == source;
  - is deterministic.
- **`contains_many` / `locate_many`**:
  - a bounded scan per object, plus one `get_many` over the distinct packs' membership rows, cached per call;
  - never crosses repositories.
- **`holds_any(repo, ids)`**: for the takedown sweep.

### B6. Out of scope

Record each of these in R-130:
- per-pack verification state: WP-4.7 and WP-4.8;
- frame offsets in mkit-core (`DecodedEntry` and the window reader's `Step::Entry` are `#[non_exhaustive]`, so the
  fields can be added): WP-4.7 and WP-4.8;
- a batched multi-range read on the Worker wire: WP-4.6.

### B7. Invariant for 4.7 and 4.8

A pack's index rows MUST be delivered before its advance commits. Until they are, the advance answers
`PendingVerification`. Otherwise, relay lag turns the §9.4 lag window into false permanent errors.

Put this in R-130 and in INVARIANTS.

### B8. Timer kinds (pre-assigned)

| Kind | Owner |
|---|---|
| 1–4 | taken |
| 5 | WP-1.26a quota rollup |
| 6 | WP-4.10a holder pump |
| 7 | WP-4.8 async verification |

Record this in R-130. WP-4.5 registers no timer.

### B9. Plan

Add row **R-130**:

> WP-4.5.
> - Write-once index rows `i <repo> <object> <pack>`; validity comes from pack membership, with no verified flag.
>   This amends the 4.5, 4.7 and 4.8 text.
> - Identical multi-producer relay upserts are allowed; this relaxes R-102's one-producer wording.
> - Invariant B7.
> - Frame offsets in core belong to 4.7 and 4.8.
> - The multi-range read is 4.6's.
> - Timer kinds: 5 is 1.26a, 6 is 4.10a, 7 is 4.8.
> - 4.6 risk: a first push touching all 4096 prefixes means about 128 Worker alarms of delivery.

## C. Your decisions

- The binary value layout within B1.
- Module layout.
- Test organisation.

## D. Escalate (stop and report) if

- Production changes exceed 1,500 lines. The fallback split is 4.5a (layout, codec, `ShardMap`, planner) and 4.5b
  (lookups, membership join, conformance).
- The B2 membership join can't be bounded per call.

## Tests (required)

1. Golden bytes for the key and codec, `parse` round trips, and `RESERVED_TAGS`.
2. The d34 mapping golden.
3. Repository isolation in both sharding modes.
4. The planner:
   - chunking limits;
   - a pack spanning all 4096 prefixes;
   - duplicate entries;
   - determinism.
5. Two identical producers, and redelivery with the `rh` dedup.
6. A row whose pack is not a member reads as absent, and becomes visible once the membership row lands.
7. The storage conformance suite on memory and SQLite.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance --all-features`
- the wasm32 check
