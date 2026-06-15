# MMB-P Phase 1 — measurement findings (issue #349)

Goal: quantify the proof-size win that "pyramid bagging" (a non-zero
`inactive_peaks` boundary) would give mkit, to decide whether MMB-P is
worth adopting. Reproduce with:

```sh
cargo run --release --example mmbp_proof_size -p mkit-core --features history-mmr
```

## Correction to the original plan

The #349 plan proposed measuring the **sparse-checkout bitmap** first.
Reading the code shows that's **not applicable**: sparse-checkout
transmits the **full bitmap** (`SparseProof { bitmap_bytes }`) and verifies
by **recomputing the root** — it does **not** use per-element inclusion
proofs (the wire format even calls per-bit proofs a "future" slot). Pyramid
bagging only shrinks *inclusion proofs*, so it gives sparse-checkout **zero
benefit as built**. The only mkit consumer of real MMR inclusion proofs is
`history-mmr` (`CommitHistory::prove` / `verify_inclusion`), which hardcodes
`inactive_peaks = 0`. So the experiment measures history.

## Result: active-leaf inclusion-proof digests vs. inactivity floor

`floor%` = fraction of oldest leaves treated as pruned/inactive (the GC
boundary). `avg_digests` averaged over 64 active leaves; bytes ≈ digests×32.

**N = 1,000,000 leaves** (7 peaks):

| floor% | inactive_peaks | avg digests | vs floor-0 | ≈ bytes | reduction |
|-------:|---------------:|------------:|-----------:|--------:|----------:|
| 0   | 0 | 23.92 | —      | 766 | —    |
| 50  | 0 | 22.81 | −1.11  | 730 | 5%   |
| 90  | 2 | 19.91 | −4.02  | 637 | 17%  |
| 99  | 4 | 16.72 | −7.20  | 535 | 30%  |
| 99.9| 4 | 13.38 | −10.55 | 428 | 44%  |

(N = 1k and 100k show the same shape — see the example output.)

## Interpretation

1. **The win is real but conditional on aggressive pruning.** Pyramid
   bagging shrinks active-leaf proofs ~**30% at 99% pruned** and ~**44% at
   99.9% pruned** — matching the blog's 33%/50% claims. But at ≤50%
   inactivity (the realistic state of a lightly-pruned history) it is
   **0–5%**, and at an **unpruned** history (floor 0, mkit today) it is
   **0%**. This is the `V ≈ U` caveat, quantified.
2. **The win requires a GC floor that does not exist yet.** mkit has no
   history pruning (SPEC-GC), so `inactive_peaks` is always 0 and the
   benefit is nil today.
3. **Absolute proof size is already tiny.** Even the unoptimised proof is
   ≤25 digests (~0.8 KB). The pyramid saving is ~7–10 digests (~0.2–0.3 KB)
   and only at extreme pruning. Unless history proofs are sent at high
   volume, the absolute payoff is marginal.
4. **Adoption is cheap *when* it's warranted.** It is a ~1-line change:
   `prove`/`root` take `inactive_peaks = Family::inactive_peaks(size, floor)`
   instead of `0`, where `floor` is the GC watermark — plus the floor
   becomes a producer/verifier agreement parameter (same desync risk as
   `Bagging`; reuse the `HISTORY_BAGGING` single-source pattern), and any
   non-zero value is a root/proof **format break** (version bump + migration).
5. **MMB family swap is orthogonal** and untouched here — it's an
   append/compactness win, not a proof-size win.

## Recommendation

**Defer (low ROI).** Keep MMR + `ForwardFold` + `inactive_peaks = 0`. The
relative win is genuine but (a) gated on aggressive history GC that doesn't
exist, and (b) marginal in absolute bytes (sub-1 KB proofs). Re-open this
evaluation **only** alongside SPEC-GC, at which point this measurement and
the ~1-line wiring are ready. Sparse-checkout would need a per-bit-proof
redesign before pyramid applies at all — out of scope for this win.

The `mmbp_proof_size` example is kept as a reusable measurement so the
decision can be re-checked once a real prune watermark exists.
