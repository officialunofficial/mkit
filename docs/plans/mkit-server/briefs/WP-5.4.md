## Purpose

mkit tracks, per ref, the **published** (head, packmap) pair: the contiguous prefix of advances whose content has
cleared. Readers see only published values, and writers see live ones. This is the foundation for inspection (5.5c)
and for the embedding host's Sent → Delivered states.

## A. Fixed (do not change)

1. **SPEC-SERVER §10** (published view: advance sequences, clearance, caller views) and **§12.1** as amended below.
   Where the breakdown differs, the spec wins.
2. **Caller-view classification never grants private-read permission.**
3. **The advance op budget.** Seven-ticket advances leave about 11 batch operations of headroom. Stay within the
   budget, and re-derive and assert the new count.
4. **Existing read contracts:** paging, tokens, and the uniform `not_found`.

## B. Decided (do not change)

- **B1. Spec amendments, in this PR:**
  - **The launch profile.** Amend SPEC-SERVER §12.1 and §18 so an indexed deployment MAY run with `leases = false`,
    permanent retention and GC disabled, advertised as such. Leases, GC and receipts remain the full-profile
    requirements. Add a version-history row.
  - **The publication signal.** Specify the publication transition Event (the Event proto's field 7). It carries the
    ref, the advance sequence, the (head, packmap) pair and an operation correlation. Its semantics: durable
    recording plus at-least-once delivery, and correct "exactly-once events" wording to that. WP-5.15 delivers it;
    this PR only specifies it.
  - "Committed means Sent, never Delivered" is recorded in the Outcome docs.
- **B2. Storage, in the RefShard:**
  - persistent advance sequences that never reset;
  - retained values;
  - obligations (the hook for 5.5c);
  - deletion boundaries;
  - the paired published (head, packmap);
  - coverage of head-only and packmap-only `UpdateRef`, other refs, and pair-closure verification.
- **B3. The greatest contiguous cleared-or-resolved prefix.** Membership clears separately: out-of-order clearance
  may publish membership while the pointer stays behind. Cross-ref reuse and external delta bases require published
  membership plus durable wake-ups.
- **B4. With no inspector configured,** every advance clears at apply, so published equals live. Behaviour stays
  byte-identical to today, and a test asserts it.
- **B5. Caller views and reads:**
  - writers see live refs and membership; readers see published values;
  - pending content is writer-visible; **held content is unavailable to everyone** (holds come with 5.5c; add the
    seam now);
  - switch every read surface to the view:
    - ListRefs, ReadRef, PackExists and DownloadPack;
    - `X-Mkit-Ref`;
    - snapshots (replace their inputs before removing 1.21's refusal);
    - URL tokens;
    - HTTP bytes and proofs;
    - caches.
- **B6. D34:**
  - authoritative membership, pointer and relay work commits together in the RefShard;
  - separate published RepoIndex and RefIndex projections;
  - versioned clearance witnesses;
  - delayed or reordered relays may reduce visibility, never expose pending data.
- **B7. Exposure:** the view is always on. It's a no-op without an inspector, per B4. No new flags.
- **B8. Docs:** R-182, a CHANGELOG line, and the registry note that 5.4's deps are now explicit (per PLAN-launch).

## C. Your decisions

Key layouts (documented and added to `keys.rs`, `parse` and goldens), witness encoding and module layout.

## D. Escalate (stop and report) if

- The advance budget can't absorb the pointer and sequence writes.
- A read surface can't serve published values without a Durable Object round-trip regression.
- Production code passes 3,000 lines. Then split into storage/clearance, and read surfaces/snapshots.

## Tests (required)

The fact sheet's required tests that apply to the published view:
- every read surface and caller type;
- held-byte absence for writers, via the seam;
- out-of-order clearance and cross-ref/delta dependencies;
- deletion and recreation;
- reordered relays and stale snapshots;
- an apply budget assertion;
- **B4's no-inspector identity test.**

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy.
- `scripts/vcs-worker-conformance.sh` default phase, with a free `VCS_CONFORMANCE_PORT`.
