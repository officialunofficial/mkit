## Purpose

`?proof=1` serves verifiable Object, MKDP and MKDS proof bundles over HTTP through the **same** validator, cap,
admission and settlement path as ordinary content, so proofs can never bypass payment. This covers native and core.
**WP-4.14b-2** (the Workers `ObjectSource` prefetch) follows after 4.10b.

## A. Fixed (do not change)

- SPEC-HTTP-OBJECTS §5.2, §3 and §7.
- R-161 (4.14a builder, `plan_range_proof`), R-169, R-177 and R-178.
- Proof commits must be published-reachable, and paths must match the leaf. Failures are a uniform 404 **before**
  validators and payment.

## B. Decided (do not change)

- **B1. The seam.** Change the flow to **prepare/select → common validators and caps → common admission →
  build/body**. The current early-return proof branch goes away.
  - The exact encoded GET length and the size cap are established before admission, without building.
  - Build only after admission. A build failure after reservation aborts.
- **B2. Representations:**
  - canonical Object bundles;
  - MKDP for single-chunk and plain-Blob ranges;
  - MKDS for cross-chunk ranges;
  - the proof ETag, cache and metadata rows;
  - `Accept-Ranges: none`;
  - always 200;
  - HTTP `Range` and `If-Range` are ignored.
- **B3. Status mapping:**
  - syntax errors are **400**;
  - content bounds, unsupported selectors, inclusive-length overflow and proof caps are **416**.

  Amend the plan and breakdown where they differ.
- **B4. Refactors and plan:**
  - share the duplicated prefix builder (R-161's `build_prefix` refactor);
  - make merged 4.13 an explicit dependency in the plan;
  - add 4.10b as 4.14b-2's dependency;
  - add registry rows 4.14b-1 and 4.14b-2.
- **B5. Accuracy notes** for Uno in R-187:
  - MKDP and MKDS verification uses `mkit-core`/`mkit-wasm`, not `mkit-attest` (that one handles DSSE);
  - a manifest proof alone doesn't verify separately fetched file bytes.

## C. Your decisions

Seam type shapes and module layout.

## D. Escalate (stop and report) if

- The encoded length can't be computed before admission without building the proof.
- Production code passes 2,000 lines.

## Tests (required)

The fact sheet's §8 proofs list, except the Worker prefetch items.

## Gates

- The common gate set, plus `just ci-server`.
- `cargo nextest run --locked -p mkit-core -p mkit-server -p mkit-server-native --all-features`.
- The wasm32 check with `http-objects`.
