## Purpose

This WP makes ListRefs page correctly on every deployment:
- an opaque page token;
- `page_size` honored, with absent or 0 meaning the maximum (R-105);
- the advertised `max_list_refs_page_size` enforced;
- a 2 MiB encoded response cap.

The merge engine is built over a `BucketSource` abstraction, so 1.28b can plug in the 16 D34 ref-index buckets and
WP-1.21 can plug in snapshots. This WP ships single sharding, which is one source.

## A. Fixed (do not change)

1. **STC §7.9 and SPEC-REFS §4:**
   - lag produces only an older listing;
   - a response is at most 2 MiB encoded;
   - the prefix component-boundary rule and ordering.
2. **R-105:** an absent or 0 `page_size` means `max_list_refs_page_size`. WP-1.28 adds that sentence to STC §7.9.
3. **The WP-1.16 client** (merged):
   - requires strictly increasing names within and across pages;
   - treats **any** repeated token as a cycle;
   - caps a listing at 128 MiB and 100,000 pages.
4. **The D34 ref-index fan-out is 16.** It uses the existing `D34Shards::ref_index` bucket function and is **not**
   `index_fanout`, which is the 4096-way object-id fan-out. It is never advertised.

## B. Decided (do not change)

- **B1. Token v1.**
  - Contents: a version byte, a hash binding the repository and the normalized prefix, and the last emitted full ref
    name.
  - It is opaque bytes in the core and base64url at the Connect layer.
  - A malformed, oversized, other-repository or other-prefix token → `invalid_argument` "invalid page token".
  - There is no MAC; authorization runs on every page.
  - **Never embed store `Cursor`s.**
- **B2. Page size.**
  - N = `page_size`, where absent or 0 means the maximum. N is capped at `max_list_refs_page_size`.
  - The encoded `ListRefsResponse` is at most 2 MiB, measured by encoded length with headroom.
  - Every page emits **at least one name**, so the cursor strictly increases.
- **B3. Merge engine: a `BucketSource` trait, one scan per source.**
  - Each source scans `[max(prefix start, key(last)+0x00), prefix end)` with a per-source limit
    L ≈ min(N, 2·⌈N/sources⌉+8).
  - The boundary is the smallest last-fetched key among the sources that still have rows.
  - Emit the merged rows up to the boundary, stopping at N or at the byte cap.
  - A read error on any source fails the page with retryable `unavailable`. **Never** return a partial merge.
  - Scans run sequentially, or at most 4 concurrently. Your choice (C); document it.
  - Single sharding is one source over the `r` rows.
- **B4. Prefix handling:** `list_scan_prefix` plus `strip_listed_prefix`, keeping the SPEC-REFS rules.
- **B5. Connect.** Honor `page_token` and `page_size`, replacing the "unimplemented" paths and TODOs. Remove the TODO at
  `info.rs:~91`. Keep a full-listing loop for ssh and for tests.
- **B6. STC §7.9.**
  - Add the R-105 sentence.
  - Add: "a malformed or foreign page token is `invalid_argument`".
  - Add a version-history row.
- **B7. Conformance.** `list.large_response_within_limit` must follow page tokens: with the cap enforced, 10,000 refs
  no longer fit in one page. Add paging wire cases:
  - token round trip;
  - bad tokens;
  - `page_size` absent, 0 and above the cap;
  - the byte cap.
- **B8. Plan.** Add row **R-123**:

  > WP-1.28 split: 1.28a is the paging engine; 1.28b is the ref-name index, relay deletes and D34 ListRefs, after
  > WP-1.10; 1.28c is the D34 default flip plus client tolerance.
  >
  > Decisions:
  > - The ref-index fan-out is 16 and is not advertised.
  > - Index rows are `x 00 <repo> 00 <name>` (live values; M5 reserves a published-index class).
  > - Deletes are relayed by an optional `deletes` field on `RelayV1`, changed in place because nothing is deployed.
  > - The single→d34 migration promised in R-93/R-94 is dropped (nothing is published or deployed); a mismatched
  >   existing database is still refused.
  > - The ticket cap stays at 7 (WP-1.10's real advance budget of 9n+21 leaves room for two index relay rows).
  > - GC's shard list misses ticket-only and deleted-ref shards; WP-5.3a must cover them.
  > - The client's `PackmapMissing` on a stale listing is fixed in 1.28c.
  > - 1.28b owns the relay-delay fault that 1.27 needs.

  Update the registry: split 1.28 into 1.28a (depends on 1.2), 1.28b (1.28a, 1.10, 1.23) and 1.28c (1.28b, 1.8).
  1.21 depends on 1.28b; 1.27 depends on 1.28c.

## C. Your decisions

- Sequential or bounded-concurrent scans.
- The token encoding details inside B1.
- Module layout and test organisation.

## D. Escalate (stop and report) if

- The encoded-size cap can't be enforced without buffering beyond one page.
- Production changes exceed 1,500 lines.

## Tests (required)

1. **Token:** round trip; rejection of malformed, other-repository and other-prefix tokens.
2. **`page_size`:** 0, absent, and above the cap.
3. **Property test** over random ref sets, page sizes and byte budgets. Assert:
   - the concatenated pages equal the sorted full listing;
   - names are strictly increasing and no token repeats;
   - every page is at most 2 MiB encoded.

   Run it with **a multi-source `BucketSource` test double of 16 sources** as well as with single sharding.
4. **Concurrent inserts and deletes between pages:** refs present throughout appear exactly once.
5. **A listing over 32 MiB** (about 61,000 refs with 512-byte names), with the cap at 10,000, so the byte cap is
   exercised.
6. **Prefix boundaries:** `feat` vs `featx`, the empty prefix, a trailing `/`, and `nope/`.
7. **Two-repository isolation.**
8. **Wire:** the B7 cases.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-conformance -p mkit-transport-connect --all-features`
- the wasm32 check and the worker build
- `scripts/vcs-worker-conformance.sh` (default phase)
