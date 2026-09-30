## Purpose

Workers extract large objects (Blobs ≥ 64 KiB and ChunkedBlobs) into the global object store in checkpointed alarm
slices. Holder rows are recorded through a content relay hook. This keeps native's invariant: `Verified` ⇒ extracted,
held, and holder recorded. That lifts 4.8's fail-closed Extract stub.

## A. Fixed (do not change)

- SPEC-SERVER §9.6 and §13.2–§13.4, and §14.2, including the late-holder takedown scheduling it requires.
- R-163 (the native extraction contract, `HolderV1`, chunk-only Blob exclusion) and R-171 (4.8's job, budgets and
  Paid-only rule).
- Verify before visible, and `AlreadyPresent` is advisory.
- Permanent retention (the launch profile) doesn't waive extraction protection or block checks.

## B. Decided (do not change)

- **B1. Checkpoints.** Versioned extraction checkpoints in the `vc` sub-4 rows. They hold:
  - selection facts;
  - the object/chunk cursor;
  - offsets;
  - the multipart session, parts and CVs;
  - cumulative charges;
  - holder-relay progress.

  Preserve consumed-set selection without the native staged map.
- **B2. The per-object protocol:**
  1. durable hold;
  2. verify and charge repository-local sources, on dedup and on a miss (the no-oracle rule from 4.10);
  3. root-checked completion;
  4. offsets sidecar;
  5. durable holder intent;
  6. renew the hold while awaiting delivery;
  7. then `Verify`.
- **B3. The content `RelayHook` on the target:**
  - atomically writes `HolderV1`;
  - bumps and guards `c`;
  - updates conservative counts;
  - releases the hold;
  - advances the relay watermark.

  Redelivery doesn't bump twice; a distinct re-record does. It checks the blocklist on holder delivery. **A late
  holder of a blocked object durably schedules takedown** through a durable seam, with a minimal launch consumer that
  records a takedown request for 5.6a.
- **B4. Multipart: bounded finalization.** Prefer R2 backend multipart, once root-check and publication semantics are
  validated, over re-reading every staged part into one final PUT. If backend multipart can't keep verify-before-visible,
  escalate.
- **B5. Budgets:**
  - Paid-only;
  - one verification fire;
  - 256 calls per slice;
  - a 48 MiB resident allowance;
  - count multipart operations, hook reads and retries;
  - recalculate the whole-alarm budget and record it in R-186.
- **B6. Protection:**
  - renew across the actual relay delay, beyond nominal lag and ticket expiry, whenever queued holder work can still
    apply;
  - replans need fresh block checks, guarded observations and `NotAfter`;
  - failures close.
- **B7. Exposure** stays default-off until 4.18. R-186 records it.

## C. Your decisions

Checkpoint encoding, module layout and metric names.

## D. Escalate (stop and report) if

- B4 can't keep verify-before-visible.
- The budget can't fit without raising the 256-call cap.
- Production code passes 3,000 lines. Then split off an additive multipart prerequisite.

## Tests (required)

The fact sheet's §8 extraction list, in full.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy and the worker build.
- `scripts/vcs-worker-conformance.sh` (the indexed/test-faults phase), with a free `VCS_CONFORMANCE_PORT`.
