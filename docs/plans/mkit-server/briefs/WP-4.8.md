## Purpose

Workers can verify consumed packs asynchronously in checkpointed, budgeted alarm slices, with the same answers as
native inline verification. That removes one prerequisite for indexed mode on Workers. Indexed mode stays refused
until 4.10b.

## A. Fixed (do not change)

1. **SPEC-SERVER §9.3–§9.8:** verification obligations, pending answers and the lag window. **SPEC-PACKFILE §11:**
   entries are provisional until `Done`.
2. **R-130:** delivery before commit. **R-148:** membership-dependent failures are never persisted as `Rejected`.
   **R-163:** `Verified` ⇒ extracted.
3. **The advance batch is unchanged:** 89 ops on D34, 78 on Single.
4. **Stage 1:** inert.
5. **Worker Free** can't run indexed mode (R-147). The Free-plan split is fixed.

## B. Decided (do not change)

- **B1.** All the fact sheet's recommendations D-1 to D-9 are accepted:
  - **D-1:** a narrow `lease::renew_for_relay` seam, used only by kind 7. **Escalate** if it changes `ls` or
    `acked_epoch` semantics beyond mirroring the advance's install.
  - **D-2:** the `vc` job row.
  - **D-3:** closure in slices plus a local advance check.
  - **D-4:** the additive `mkit-core` `last_frame()` and `decode_entry_with`.
  - **D-5:** Paid only, 256 subrequests, one kind-7 fire per alarm; Free refuses indexed mode.
  - **D-6:** a deterministic cumulative `decode_budget` plus a Worker resident cap.
  - **D-7:** `PendingVerification`, plus an informative SPEC-SERVER §9.5 line.
  - **D-8:** both the completion hook and the advance fallback.
  - **D-9:** the Extract stub fails closed.
- **B2.** The slice model, the `vc` layout, `VerifyJobV1` and the phases, as in fact sheet §2.1. Content failures and
  the index emission after `Done`, as §2.1–§2.3.
- **B3.** `IndexedConfig.verification: {Inline (default), Scheduled}`, programmatic only. The advance checks, as §2.2.
- **B4. Stage 1 inertness (fact sheet §8):**
  - in non-test-faults builds, `INDEXED_MODE` is still refused, with the message "requires WP-4.10b";
  - under test-faults it's allowed only with `WORKERS_PLAN=paid`;
  - kind 7 is registered only then;
  - add the listed inertness tests.
- **B5. Kind 2 self-cleaning of `vc`/`vs`** (it takes over R-148's carry-forward). 5.3a gets a carry-forward: don't
  collect satisfying member packs of live jobs.
- **B6. R-171:** B1–B5, the 4.10b hand-off (the Extract phase and `SliceExtension`), and the 4.17 carry-forward (a
  Worker ancestry cap of at most 64). A CHANGELOG line, including the `mkit-core` additions.

## C. Your decisions

Module layout, the LRU size, the attempt/backoff constants within B1, and harness shapes.

## D. Escalate (stop and report) if

- D-1's lease seam needs semantic changes.
- The windowed reader can't expose frame metadata additively.
- Production code passes 2,800 lines. Cut in this order:
  1. the completion-hook enqueue;
  2. the ×3 attempt shrink;
  3. then split the Worker wiring into a 4.8-2 PR.

## Tests (required)

The fact sheet's §9 list, in full.

## Gates

As in the fact sheet §9 "Gates", with `VCS_CONFORMANCE_PORT` set to a free port.
