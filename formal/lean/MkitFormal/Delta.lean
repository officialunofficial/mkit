import MkitFormal.DeltaModel
import MkitFormal.DeltaProofs
import MkitFormal.DeltaRunning
import MkitFormal.DeltaCanaries

/-!
# SPEC-DELTA (Linear MKIT-25)

* `MkitFormal.DeltaModel` — executable model of `docs/specs/SPEC-DELTA.md`
  (§2 header, §3 COPY/INSERT encoding, §4 `apply`, §5 writer model).
* `MkitFormal.DeltaProofs` — decode ∘ encode = id, canonicity, no
  out-of-bounds reads, soundness / completeness of `apply`, writer round trip.
* `MkitFormal.DeltaRunning` — error kind of decoded in-base streams
  (overrun vs underrun) and the per-opcode running-count bound (§2, §10).
* `MkitFormal.DeltaCanaries` — non-vacuity witnesses (mutants).
* `MkitFormal.DeltaDifftest` — the `delta_difftest` executable
  (`scripts/difftest-delta.sh`), differential test against `delta.rs`.
-/
