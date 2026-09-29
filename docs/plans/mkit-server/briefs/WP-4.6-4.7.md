## Purpose

This bundle delivers indexed mode on native, and the Worker infrastructure it needs.
- **Native, ticketed advance:** the server verifies every consumed pack inline before the advance commits:
  - identity, signatures, closure, delta resolution and chain depth (SPEC-SERVER §9.3);
  - the packlist (MKPL) rule, with the §9.4 membership-lag window;
  - it writes the pack's object-index rows, and records per-(repo, pack) verification state.
- **Workers:** they get the batched multi-range index read that lookups and the takedown sweep need, plus the relay
  primitives WP-4.8 will use for asynchronous verification.
- **Scope:** indexed mode stays optional. Opaque deployments are byte-for-byte unchanged.

## A. Fixed (do not change)

1. **SPEC-SERVER:**
   - §9.1: indexed mode; inline and scheduled verification share one acceptance contract.
   - §9.2: classification and the MKPL rule.
   - §9.3: the checks and their exact messages: `object hash mismatch`, `bad signature`, `open closure`,
     `delta chain too deep`.
   - §9.4: repository-isolated resolution and the lag window: `unavailable "repository membership not yet visible"`,
     then the permanent errors. It never discloses global existence.
   - §9.5: verification state per (repo, pack).
   - §9.8: the depth cap, default 50.
   - STC §7.6 and §7.7: tickets and `PendingVerification`, with `retry_after_ms` of at least 1,000.
2. **R-130 (WP-4.5), in full:**
   - write-once `i` rows, valid only through membership;
   - a pure `chain_depth` (in-pack hops; an external base counts as 1);
   - **index rows delivered before the advance commits**;
   - the lookup budgets;
   - the `holds_any` / §14.3 gap that this bundle closes;
   - the carry-forwards on capped lookups and the writer-skip decision.

   Also R-122: the MKPL rule and the lag window are indexed-only.
3. **The advance batch gets no per-object rows.** It stays at 86 on D34 and 77 on Single at n = 7, and later 88 and
   then 89 when 1.28b and 3.3 land.
4. **Timer kinds:** 1–5 are used, 6 is reserved, and 7 is WP-4.8's. 8 and 9 are planned for 3.3. **This bundle
   registers no new kind.**
5. **Replay:** `unavailable` answers are never stored. Advance errors returned before apply write no replay row.

## B. Decided (do not change)

### Part 1: WP-4.6

- **B1. `scan_many`.** A core `NamespaceStore` method with a default: sequential `scan` per range.
  - Signature:
    `RangeScan { start, end, after, limit }` (`#[non_exhaustive]`), and
    `scan_many(&self, p, ranges: &[RangeScan]) -> Vec<ScanPage>`.
  - It returns a **served prefix**: at least 1 page and at most `ranges.len()`. Unserved ranges are re-requested.
    Every page obeys `scan`'s rules.
  - `MAX_SCAN_RANGES` = 256.
- **B2. Worker.** Add `NsCall::ScanMany { ranges }` and `NsReply::Pages`, one round trip.
  - The DO serves ranges in order, under one combined `MAX_PAGE_ENTRIES` / `MAX_PAGE_BYTES` budget.
  - It stops only at a range boundary, and always serves the first range.
- **B3. The `scan_all` rewrite.**
  - Group pending ids by `object_index` partition, and issue one `scan_many` per distinct partition per round.
  - `MAX_LOOKUP_PAGES` now counts scan **calls**; re-document it.
  - Keep round-robin fairness across rounds, the per-id row cap, and the pack-order prefix admission with its 487
    membership reads.
  - Update the `holds_any` doc: its first round makes exactly one read per distinct index partition, which meets
    §14.3/R-133. Ids with more rows than one page need more rounds; note this for WP-5.6.
- **B4. Relay primitives (no production consumer until WP-4.8).**
  - `relay/enqueue.rs`: `enqueue_relay_rows(os, rows, now) -> Vec<Batch>` returns chained source batches. Each batch
    has `NotAfter`, an `os` guard and put, one kick, and row puts within `MAX_BATCH_OPS` and the batch bytes. A
    precondition loss re-plans the remainder.
  - `relay_delivered_through(store, source, seq) -> bool`, reusing #1187's `source_relay_state`.
- **B5. Worker relay budget, plan-aware.**
  - Paid: `max_targets` 32, `max_per_tick` 8, which keeps each alarm at 512 subrequests or fewer.
  - Free: unchanged.
- **B6. Metrics.**
  - `mkit_server_partition_bytes` is labeled by partition kind (`repo_index` vs `ref_index`).
  - `mkit_server_relay_lag_exceeded_total{source_kind}`.
  - A `mkit_server_relay_backlog_rows` gauge.
  - `mkit_server_index_lookup_capped_total{reason}`, emitted by callers.
  - A test that the 70% and 90% pressure alerts cover `RepoIndexShard`.
- **B7. Workers Free cannot run indexed mode:** its 50 subrequests are fewer than one lookup needs. Document this in
  the Worker README and in the R-row.

### Part 2: WP-4.7

- **B8. Configuration.**
  - `PipelineConfig.indexed: Option<IndexedConfig { max_delta_chain_depth: 50, relay_lag_bound_ms: RELAY_LAG_BOUND_MS, max_pack_bytes, decode_budget }>`,
    off by default.
  - **Startup refusals:** indexed mode requires auth v2, ticket keys, `effective_threshold() == 0`, and Multi
    addressing. The Worker refuses indexed mode until WP-4.8.
  - `server_info()` advertises `indexed_mode`, the depth cap, and the effective indexed `max_pack_bytes`. The default
    is 2 GiB, configurable, and at most the decode budget.
  - Add native flags.
  - Document that switching an existing opaque deployment to indexed is unsupported: member packs would have no `i`
    rows.
- **B9. Wiring.** A new `mkit-server/src/indexed/` module, with `classify`, `entries`, `resolve`, `verify` and
  `state`.
  - It is entered only for ticketed advances in indexed mode, right after `ticket_decision` succeeds, replacing the
    TODO at `advance.rs:~253`.
  - It must **not** use the generic `PreReceive` hook, which is user policy and belongs to WP-4.17.
- **B10. Classification** (§9.2) by the first 4 bytes:
  - `MKIT` is a pack;
  - `MKPL` is a packlist node;
  - anything else, including fewer than 4 bytes, is `invalid_argument "unknown upload type"`.
- **B11. Decode path (orchestrator decision; overrides "use the 4.8a windowed reader").**
  - Native decodes the whole pack with `decode_entries_with`, `VERIFIED=false` as defense in depth, from the
    content-addressed pack blob.
  - Additive `mkit-core` changes:
    - frame metadata on `DecodedEntry` (`frame_offset`, `frame_length`, `wire_type`, `delta_base`), captured from
      `last_payload_range`;
    - a public single-frame `pack::decode_frame_with(frame, version, bases, limits)` for reconstructing external bases.
  - `mkit-core` is published: these changes are additive only, and need a CHANGELOG line.
  - The windowed decoder is WP-4.8's, bound to this bundle by a differential test on `entries::index_entries`.
- **B12. Pure index entries.** `entries::index_entries(frames) -> Vec<IndexEntry>` is a pure function of the frame
  list:
  - `chain_depth` is 0 for raw, 1 for an external base, and 1 plus the in-pack base's depth otherwise;
  - the first occurrence of an object wins;
  - any in-pack chain above the cap is rejected early.

  **This is the purity test R-130 assigned to 4.8; do it here.**
- **B13. Resolver.**
  - Take `delta_base_hashes`, then resolve through batched `locate_many` calls of up to 256 ids. Split on the
    retryable caps down to one id.
  - Reconstruct each located base asynchronously from its member pack's frame: a ranged `BlobStore::get` of
    `frame_offset..+frame_length`, recursing on `delta_base`, with memoization.
  - Same-pack links are read by exact key with `get_many`, with no scan.
  - The **total** resolution depth is capped at `max_delta_chain_depth`, across external bases.
  - Depth follows the server's actual resolution, through `locate_many`'s deterministic first member pack. It may
    change as membership becomes visible; that is acceptable, because it depends only on the repository.
- **B14. Checks (§9.3), all inline** (orchestrator decision D1). Verify **every object in the consumed packs**, not
  only those reachable from the tips. Otherwise an unverified dangling object becomes a member and is later trusted.
  - **(a) Identity:** from the decode.
  - **(b) Signatures:** `verify_object_signature` on every commit, remix and tag.
  - **(c) Closure:** each `children(obj, History)` id must be staged (in any pack this advance consumes), or be a
    located member. Batch these through `locate_many`.
  - **Tips:** the new head must be staged or a member. Run
    `verify_push([head], History, staged_source, known = |id| !staged(id))` for the tip-type and reachability checks.
  - **Exact messages:** `invalid_argument` with `object hash mismatch`, `bad signature`, `open closure` or
    `delta chain too deep`.
- **B15. The lag window (§9.4).** It applies to an unresolved base, a closure miss, and an MKPL miss.
  - While `now − ticket.created_at_ms < relay_lag_bound_ms`, answer `unavailable "repository membership not yet visible"`.
  - After that, answer the permanent error:
    - `failed_precondition "delta base not available in this repository"`;
    - `invalid_argument "open closure"`;
    - `invalid_argument "packlist lists a pack that is not in this repository"`.
  - A base present only in another repository is treated exactly like a base present nowhere. Its answers are
    byte-identical, both inside and after the window.
- **B16. The MKPL rule.**
  - Decode the node. Every listed pack must be ticketed and consumed in this advance, or be a member.
  - Membership is checked through **one** new batched function in `store/read.rs`, beside `is_member`: first the ref
    shard's local `m` rows, then the membership partitions via `get_many`. It is the single place where §12.2's
    deleted-repository generation rule will plug in.
- **B17. Capped lookups (orchestrator decision D5).**
  - A capped delta base maps to the permanent `failed_precondition "delta base not available in this repository"`.
    The client re-plans once, self-contained.
  - A capped closure or MKPL lookup maps to `invalid_argument "object index limit exceeded"`.
  - Both increment `index_lookup_capped_total{reason}` and log at error level.
- **B18. Direct index delivery on native (orchestrator decision D3).**
  - Before the advance commits, upsert every entry's `i` row synchronously, directly to each target partition, with
    `plan_index_rows`'s direct batches used for every target.
  - Rows are write-once and identical, so plain puts are safe.
  - **No writer skip:** write every entry's row (D6).
  - A failure part-way answers `PendingVerification`; the retry is idempotent.
- **B19. Verification state (§9.5).**
  - A new key class `vs 00 <repo> 00 <pack>` in the ref shard, the ticket's partition. Add it to `RESERVED_TAGS`,
    `parse` and the goldens.
  - The value `VerificationV1` is one of `Pending { lease_until_ms }`, `Verified { pack_len, verified_at_ms }`, or
    `Rejected { code, message }`. `Rejected` is for content-only failures.
  - Writes go in their own 3-op batches (`NotAfter`, guard, put), never in the advance batch.
  - `Verified` is monotone, so the advance needs no guard on it.
  - A `Verified` pack is not re-indexed; closure and signatures always run on the current consumed set. A conflict or CAS loss keeps `vs`.
  - A live `Pending` lease held by a concurrent verifier answers `PendingVerification`.
  - Lifetime: GC (WP-5.3a) removes `vs` with the local `m` row. Note for WP-1.14: its kind-2 expiry handler also deletes
    an expired, unconsumed ticket's `vs` row.
- **B20. `PendingVerification` builder.**
  - `indexed::pending(retry_after_ms)` returns `ServerError::unavailable("pack verification pending")`, with exactly
    one `PendingVerification` detail (`retry_after_ms` at least 1,000), HTTP 503 and `Retry-After`.
  - It must match the existing golden.
  - Enable the conformance case at `wire/mod.rs:~220`.
- **B21. Invariants on the advance side:**
  - `plan_consumption` is unchanged;
  - verification consumes nothing;
  - `AlreadyPresent` stays membership-only (add a regression test);
  - ticketless `AdvanceRefs` and `UpdateRef` in indexed mode are unchanged (the "head must be a member" rule is
    WP-4.17's; note it).
- **B22. Spec and plan.** SPEC-SERVER §9.3 gains:
  - "An indexed server verifies (a)–(c) for every object in the packs an advance consumes, not only objects reachable
    from the new tips."
  - A table row: "an object-index lookup limit exceeded during closure or packlist checks: `invalid_argument`,
    `object index limit exceeded`".

  Add a SPEC-SERVER version-history row. Also:
  - **R-147 (4.6):** B1–B7, and B4's consumer being 4.8.
  - **R-148 (4.7):**
    - B8–B21;
    - the decisions D1/D2/D3/D5/D6;
    - 4.8's differential test obligation against `index_entries`;
    - the 4.10 extraction seam (the verified-object list);
    - the WP-1.14 `vs` note;
    - the 4.12 serving rule for a capped id (non-retryable).
  - A CHANGELOG line per WP, plus one for the `mkit-core` API additions.

## C. Your decisions

- Module layout inside `indexed/`, and the shape of the `IndexedConfig` flags.
- The `vs` lease duration (document it).
- Whether `staged_source` wraps the decoded entries or a map.
- Worker DO dispatch details for `ScanMany`.

## D. Escalate (stop and report) if

- The advance batch grows, or a check can't run without adding ops to it.
- `mkit-core` needs a **breaking** change.
- Opaque-mode responses or batches would change.
- Production code passes 3,000 lines. Cut in this order:
  1. B4 (enqueue and delivered-through) moves to WP-4.8;
  2. B19's `Pending` lease concurrency (native simply re-verifies).

  Then open the PR, listing what was cut.

## Tests (required)

**Part 1:**
1. **`scan_many`:** the default implementation; served prefix; empty and continuation pages; a forged cursor
   rejected; the reply budget respected. Add these as `idx_scan_many_*` storage conformance cases on memory, SQLite,
   FS and the Worker loopback.
2. **`scan_all`:** calls are at most the number of distinct partitions per round; every existing `index.rs` test
   passes unchanged; `holds_any` makes one read per partition.
3. **Enqueue:** chaining, precondition re-plan, and delivered-through.
4. **Worker host tests:**
   - `ScanMany` over the real JSON wire;
   - a relay drain of 4,096 targets counting alarms and calls, on paid and on free;
   - the partition-kind label.

**Part 2:**
5. **Pure functions:** `index_entries` purity and depth; classification, including fewer than 4 bytes.
6. **Resolver:**
   - recursion and memoization;
   - the total-depth cap across external bases;
   - a base present only in another repository is unresolved.
7. **Errors:** every mapping and exact message; the lag-window boundary on `created_at_ms`.
8. **Codecs:** the `vs` codec golden, `parse` and `RESERVED_TAGS`; the pending detail bytes match the golden.
9. **Budget:** the advance op count is unchanged in indexed mode (86 on D34, 77 on Single).
10. **Native wire / in-process:**
    - acceptance: a good push; `AlreadyPresent` stays membership-only; `GetServerInfo` advertises the indexed fields;
    - rejections, with refs unmoved: a forged signature; an open closure, including a **dangling unreachable object**
      in a consumed pack (D1); a hash mismatch; an unknown upload type;
    - MKPL: a packlist that lists a foreign pack gets the lag window, then the permanent error;
    - **a thin delta whose base exists only in repository A**, pushed to repository B: its rejection is byte-identical
      to one whose base exists nowhere, inside and after the window;
    - delta chain too deep, both in-pack and across an external base;
    - a capped closure lookup gives `object index limit exceeded`;
    - `PendingVerification` from a concurrent lease: one detail, no replay row, and the retry succeeds;
    - opaque mode is unchanged;
    - the Worker refuses indexed mode.

## Gates

- `just ci-server`, `just ci-scripts` and `just ci-security`
- `cargo nextest run --locked -p mkit-core -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`
- the wasm32 check for `mkit-core` and `mkit-server`, and the worker build
- `scripts/vcs-worker-conformance.sh` (default phase)
