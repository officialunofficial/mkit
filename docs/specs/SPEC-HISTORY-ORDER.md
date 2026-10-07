---
spec: SPEC-HISTORY-ORDER
version: 1
status: draft-normative
audience: mkit-server history continuation issuance/redemption, embedder page walkers, and implementers of mkit-core::history_order
---

# SPEC-HISTORY-ORDER &mdash; bounded timestamp/discovery all-parent traversal

Status: **Draft-normative** for mkit v1. Server and embedder
implementations that page all-parent history across stateless
continuations MUST produce the orders and accept the bounds defined
here; an order that differs anywhere is non-conformant.
Scope: the `TimestampDiscovery` traversal order, its priority keys and
tie rules, dedup activation, the 256/192 bounds and their failure
modes, and the byte snapshot that carries reducer state between pages.
Selection of which ref, session, or objects feed the walk; proof and
token formats that wrap the snapshot; and every object I/O loop are
specified elsewhere ([SPEC-SERVER](SPEC-SERVER.md),
[SPEC-HTTP-OBJECTS](SPEC-HTTP-OBJECTS.md)).
Endianness: **little-endian** throughout. All ids are 32-byte BLAKE3
hashes ([SPEC-OBJECTS](SPEC-OBJECTS.md) §10).
Reference implementation: `rust/crates/mkit-core/src/history_order.rs`.
Authority: this file is the source of truth for the traversal order and
snapshot format. If code, docs, or tests disagree with this file, fix
the implementation or amend this spec in the same change.

---

## 1. Purpose

An embedder walks an all-parent `Log` by decoding one canonical object
per emitted commit; pages after the first must continue without
re-walking the emitted prefix and must produce byte-identical output on
the server and in the embedder. Breadth-first all-parent order cannot
resume from a bounded state, and a timestamp frontier alone either
repeats a shared ancestor (equal-time or skewed edges let it leave the
frontier before its other children are discovered) or skips one (a
cutoff cannot see unvisited skewed ancestors). The reducer defined here
keeps exactly the state needed for the exact order and refuses
explicitly when that state exceeds its bounds.

The order is deliberately peculiar: **decreasing canonical timestamps,
ties by retained discovery order**, named
`HistoryOrder::TimestampDiscovery`. It is not the server's
breadth-first `HistoryMode::AllParents`, and it is not the CLI's
`--date-order` (timestamp with a hash tiebreak under a topological
gate), neither of which this document or implementation replaces.

## 2. Definitions

- **Candidate**: an object id that may still be emitted. Each candidate
  occupies one **slot** in the **pending** list.
- **Priority key**: the candidate's canonical `Commit.timestamp` or
  `Remix.timestamp` `u64` field exactly as stored in the canonical
  object ([SPEC-OBJECTS](SPEC-OBJECTS.md) §5, §6). Keys MUST NOT come
  from any other field, from Git-style author/committer distinctions,
  or from the id itself.
- **Emitted set**: the bounded set of ids already emitted while dedup
  was live.
- **Selected**: the candidate popped by the reducer and not yet
  completed by its `emit` call.
- **Dedup live**: the state in which emissions are recorded into the
  emitted set and emitted-id candidates are suppressed.

## 3. Traversal contract

A conforming reducer MUST behave exactly as follows.

1. **Selection.** Pop the pending candidate with the greatest priority
   key. Among equal keys, the candidate at the earliest retained
   pending position wins. Hash or id comparisons MUST NOT break ties,
   and no topological constraint may delay an ancestor behind its
   descendants.
2. **Unknown keys.** A candidate MAY enter pending without a key. A
   sole remaining candidate MUST be selectable without one (there is no
   competitor); while multiple candidates pend, every unknown key MUST
   be obtained (a metadata decode, never an expansion) before output is
   selected, in pending order. Hydrating a key fills it in place: the
   slot keeps its pending position for ties. Duplicate slots for one id
   share the id's single canonical key.
3. **Emission and expansion.** On emitting a candidate, its caller
   lists all local commit/remix parents in canonical decoded order.
   Parents already in the emitted set MUST be omitted; the rest append
   to pending after all existing slots, so earlier equal-key candidates
   always outrank new discoveries and new equal-key parents keep their
   canonical parent order. Parent enqueue MUST complete even for the
   last output of a page before state is snapshotted &mdash; a decoded,
   queued parent is pending, not emitted.
4. **Dedup activation.** The emitted set goes live immediately before
   recording the first emission a later discovery could revisit: a node
   with more than one local parent (its branches may reconverge), or
   any emission while other candidates still pend (independently seeded
   histories can reconverge without a merge). The triggering node is
   itself recorded. From then on every emitted id MUST enter the set.
   Emissions before activation are linear-prefix descendants, cannot be
   revisited in an acyclic ancestry DAG, and MUST NOT be seeded.
5. **Suppression.** A popped candidate whose id is in the emitted set
   is discarded without decoding or expanding it. Dropping queued
   candidates already in the emitted set is permitted cleanup at any
   selection point; it MUST NOT remove a future unique emission.
6. **Edges.** Only local commit/remix parent links are traversed.
   Foreign remix sources, trees, blobs and delta bases MUST NOT be
   treated as history edges. A live descent stop MAY withhold an edge
   from the frontier; the withheld parent still counts toward the
   emitted node's local parent count in rule 4.
7. **Duplicate slots.** Pending slots are retained verbatim, including
   duplicate ids supplied by the caller's queue. Every retained slot
   counts toward the pending bound of §4; implementations MUST NOT
   coalesce, sort, or deduplicate slots at handoff or decode. This is
   the frozen duplicate-slot policy.
8. **Malformed input.** A node is never its own ancestor; a self-edge
   MUST NOT be queued. The reducer cannot detect malformed or
   inconsistent input generally: callers MUST feed an acyclic ancestry
   DAG with true canonical keys and the decoded node's true local
   parent list.
9. **Seeding.** Candidates enter pending only by caller seed or by
   parent discovery in rule 3. Every seed push MUST precede the walk's
   first completed emission; a conforming reducer MUST refuse a seed
   after that point, including after a snapshot decode (flag bit2 in §5
   persists the closed window). Pre-activation emissions are not
   recorded, so a later seed could otherwise descend into them unseen
   and force a re-emission.
10. **Done.** The walk completes when no pending candidate could emit;
    no continuation token is issued exactly in this state.

## 4. Bounds and failure

| Bound | Value | Scope |
|---|---:|---|
| Pending slots | 256 | Every retained slot, duplicates included |
| Emitted ids | 192 | Ids recorded while dedup is live |

Exceeding either bound MUST fail the operation explicitly; a
conforming reducer MUST NOT truncate the frontier, evict emitted ids,
repeat an emitted id, or emit a partial page or successor. After a
failed transition the reducer state is unchanged.

## 5. Snapshot encoding

Reducer state is carried between pages as this byte string (for
example, inside a continuation token's claims; the token format is out
of scope). A snapshot MAY capture an outstanding selected candidate;
resuming completes its `emit` before continuing.

```
offset  size      field          value
0       1         version        0x01
1       1         order          0x01 = timestamp-discovery
2       1         flags          bit0: dedup live; bit1: selected
                                 present; bit2: seed window closed
                                 (§3.9); remaining bits MUST be zero
3       2         pending_len    u16, <= 256
5       2         emitted_len    u16, <= 192
7       var       pending        per slot, in retained order:
                                 32-byte id, u8 key flag, then the
                                 u64 priority key iff flag = 0x01
var     0|32      selected       32-byte id iff flags bit1 set
var     var       emitted        emitted_len x 32-byte ids, strictly
                                 ascending byte order
```

A decoder MUST reject input that is truncated, has trailing bytes, an
unknown version or order byte, reserved flag bits set, a `key flag`
outside `0x00`/`0x01`, either count above its §4 bound, emitted ids not
strictly ascending, or a dedup flag that disagrees with the emitted
set (dedup is live exactly when the set is non-empty). A snapshot
produced by a conforming encoder is bit-for-bit reproducible:
`encode(decode(x)) = x`.

## 6. Out of scope (v1)

- Which objects feed the walk: ref selection, tag peeling, session and
  proof state, descent stops, and every I/O loop.
- The continuation token claims and MAC that wrap a snapshot, and any
  provenance/witness encoding (see
  [SPEC-SERVER](SPEC-SERVER.md) authenticated history continuations).
- Any other traversal order (first-parent, breadth-first, topological,
  CLI date order) and any second `HistoryOrder` variant.
- Unbounded or approximate seen sets (Bloom filters, hash prefixes);
  the bounds of §4 are the contract.

## 7. Version history

| Version | Released | Changes |
|---------|----------|---------|
| `0x01`  | v1 (draft) | First order and snapshot format. |

## 8. Test anchors

`mkit-core::history_order::tests` pins the conformance fixtures:
`equal_time_asymmetric_merge_matches_design` /
`equal_time_merge_page_state_matches_design` (whole order `M,A,B,X,C`
and pages `[M,A],[B,X],[C]` with frontier `[B,X]`, emitted `{M,A}`),
`clock_skew_shared_ancestor_suppressed` (`M,A,X,B`; `[M,A],[X,B]`),
`linear_chain_needs_no_lookahead`, `parent_newer_than_child_wins`,
`push_after_first_emission_refused` and
`push_between_select_and_emit_still_allowed`,
`duplicate_parent_ids_emit_once`,
`independent_seeds_converging_without_merge_dedup`,
`held_back_parent_still_counts_for_merge`,
`page_boundary_equivalence_every_size`, `paged_equals_single_run` and
`snapshot_round_trip_is_lossless` (proptest),
`emit_frontier_overflow_publishes_nothing`, `emitted_cap_at_192`,
`frontier_cap_counts_duplicate_slots`, and
`decode_rejects_malformed_snapshots`.

## 9. Invariants

| Invariant | Mechanism / error |
|---|---|
| Emitted ids never repeat | emitted set + suppression at pop and enqueue |
| Order is timestamp-desc, discovery-tie | selection rule §3.1; no id comparison anywhere |
| Frontier <= 256, emitted <= 192 | `FrontierFull`, `EmittedFull`, `LimitExceeded` |
| Decoded != emitted | `emit` is the only path into the emitted set |
| Parent enqueue precedes snapshot | `CandidateOutstanding` blocks `step` mid-step |
| Seeding precedes first emission | sealed latch (`WalkStarted`); snapshot bit2 |
| Snapshots round-trip bit-for-bit | strict decoder; canonical emitted order |
| Caps publish no partial state | both bounds checked before mutation |
