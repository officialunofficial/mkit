import MkitFormal.DeltaProofs

/-!
# SPEC-DELTA running-count theorems (MKIT-25)

§2 / §10: "The running emitted-byte count NEVER exceeds `result_len` (the v1
reader enforces this per-opcode, not only at end-of-stream)".

* `run_decoded` / `apply_decoded`: for a stream that decodes, targets this
  base and keeps its COPYs inside it, `apply` returns exactly one of `ok`,
  `resultLenOverrun` (the instructions emit more than `result_len`, §8
  vector 8) or `resultLenUnderrun` (fewer). The overrun kind is reported
  whenever the total exceeds `result_len`, which is only possible because the
  check fires on the first opcode that overshoots.
* `runT`: `run` instrumented with the emitted-byte count at every loop
  iteration, with the per-opcode overrun check switchable (`ovr`).
  `runT_fst` proves the instrumented loop computes `run` (for `ovr = true`),
  and `runT_bounded` proves every recorded count is `≤ result_len`.
  Canary `runT_noOverrun_exceeds` (in `DeltaCanaries`) shows the bound fails
  once the check is dropped.
-/

namespace MkitFormal.Delta

/-! ## Error kind of a decoded, in-base stream -/

/-- Outcome of the §4 loop on a decoded, in-base stream, from the total output
`o` and the declared `result_len`. -/
def lenVerdict (o : Bytes) (rl : Nat) : Except Err Bytes :=
  if o.length = rl then .ok o
  else if rl < o.length then .error .resultLenOverrun
  else .error .resultLenUnderrun

theorem run_decoded (base : Bytes) (rl : Nat) :
    ∀ (r out : Bytes) (is : List Instr), decodeInstrs r = .ok is →
      is.all (Instr.inBase base.length) = true → out.length ≤ rl →
      run base rl r out = lenVerdict (out ++ exec base is) rl
  | [], out, is, h, _, _ => by
    simp [decodeInstrs] at h; subst h
    rw [run]; simp only [exec, List.append_nil, lenVerdict]
    split <;> rename_i h1
    · rfl
    · have : ¬ rl < out.length := by omega
      simp [this]
  | op :: rest, out, is, h, hin, hle => by
    rw [decodeInstrs] at h
    rw [run]
    by_cases hc : 128 ≤ op.toNat
    · simp only [hc, if_true] at h ⊢
      by_cases hr : op.toNat ≠ 128
      · simp [hr] at h
      · simp only [hr, if_false] at h ⊢
        split at h
        · rename_i o l ho hl2
          have := readLE_len hl2
          simp at this
          have hlen6 : ¬ rest.length < 6 := by omega
          simp only [hlen6, if_false]
          by_cases hz : l = 0
          · simp [hz] at h
          · simp only [hz, if_false] at h ⊢
            cases hd : decodeInstrs (rest.drop 6) with
            | error e => simp [hd, Except.map] at h
            | ok is' =>
              simp [hd, Except.map] at h
              subst h
              simp only [List.all_cons, Bool.and_eq_true, Instr.inBase, decide_eq_true_eq] at hin
              obtain ⟨hb, hin'⟩ := hin
              have hcl : ((base.drop o).take l).length = l := by simp; omega
              have hnb : ¬ base.length < o + l := by omega
              simp only [hnb, if_false]
              by_cases hov : rl < out.length + l
              · simp only [hov, if_true, lenVerdict, exec, execInstr, List.length_append, hcl]
                have h1 : (out.length + (l + (exec base is').length) = rl) = False := by
                  simp; omega
                have h2 : rl < out.length + (l + (exec base is').length) := by omega
                simp [h1, h2]
              · simp only [hov, if_false]
                rw [slice?_eq hb]
                simp only
                rw [run_decoded base rl _ _ is' hd hin' (by simp; omega)]
                simp [exec, execInstr]
        · simp at h
    · simp only [hc, if_false] at h ⊢
      by_cases h0 : op.toNat = 0
      · simp [h0] at h
      · by_cases hls : rest.length < op.toNat
        · simp [h0, hls] at h
        · simp only [h0, hls, if_false] at h ⊢
          cases hd : decodeInstrs (rest.drop op.toNat) with
          | error e => simp [hd, Except.map] at h
          | ok is' =>
            simp [hd, Except.map] at h
            subst h
            simp only [List.all_cons, Bool.and_eq_true] at hin
            have htl : (rest.take op.toNat).length = op.toNat := by simp; omega
            by_cases hov : rl < out.length + op.toNat
            · simp only [hov, if_true, lenVerdict, exec, execInstr, List.length_append, htl]
              have h1 : (out.length + (op.toNat + (exec base is').length) = rl) = False := by
                simp; omega
              have h2 : rl < out.length + (op.toNat + (exec base is').length) := by omega
              simp [h1, h2]
            · simp only [hov, if_false]
              rw [slice?_eq (by simp; omega)]
              simp only [List.drop_zero]
              rw [run_decoded base rl _ _ is' hd hin.2 (by simp; omega)]
              simp [exec, execInstr]
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- For a stream that decodes, targets this base (§2) and keeps its COPYs
inside it (§2), `apply` accepts iff the output has exactly `result_len` bytes,
and otherwise reports `resultLenOverrun` when the instructions emit more
(§8 vector 8) and `resultLenUnderrun` when they emit fewer. -/
theorem apply_decoded (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (hb : d.baseLen = base.length) (hin : d.instrs.all (Instr.inBase base.length) = true) :
    apply base s = lenVerdict (exec base d.instrs) d.resultLen := by
  match s, hd with
  | v :: rest, hd =>
    simp only [decode] at hd
    by_cases hv : v ≠ 0x01
    · simp [hv] at hd
    · simp only [hv, if_false] at hd
      split at hd
      · rename_i bl rl hbl hrl
        cases hdi : decodeInstrs (rest.drop 8) with
        | error e => simp [hdi, Except.map] at hd
        | ok is =>
          simp [hdi, Except.map] at hd
          subst hd
          have := readLE_len hrl
          simp at this hb
          simp only [Decidable.not_not] at hv
          subst hv
          unfold apply
          simp only [headerLen, List.length_cons, show ¬ rest.length + 1 < 9 by omega, if_false,
            hbl, hrl, hb, ne_eq, not_true_eq_false]
          simpa using run_decoded base rl _ [] is hdi hin (by simp)
      · simp at hd

/-- §8 vector 8: instructions that emit more than `result_len` bytes are
rejected as `ResultLenOverrun` (not only as an end-of-stream mismatch). -/
theorem apply_overrun (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (hb : d.baseLen = base.length) (hin : d.instrs.all (Instr.inBase base.length) = true)
    (hgt : d.resultLen < (exec base d.instrs).length) :
    apply base s = .error .resultLenOverrun := by
  rw [apply_decoded base s d hd hb hin, lenVerdict]
  simp [show (exec base d.instrs).length ≠ d.resultLen by omega, hgt]

/-- §2: instructions that emit fewer than `result_len` bytes are rejected as
`ResultLenUnderrun` at end-of-stream. -/
theorem apply_underrun (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (hb : d.baseLen = base.length) (hin : d.instrs.all (Instr.inBase base.length) = true)
    (hlt : (exec base d.instrs).length < d.resultLen) :
    apply base s = .error .resultLenUnderrun := by
  rw [apply_decoded base s d hd hb hin, lenVerdict]
  simp [show (exec base d.instrs).length ≠ d.resultLen by omega,
    show ¬ d.resultLen < (exec base d.instrs).length by omega]

/-! ## The running emitted-byte count (instrumented loop) -/

/-- Prepend the emitted-byte count of the current iteration to a trace. -/
def tcons (n : Nat) (p : Except Err Bytes × List Nat) : Except Err Bytes × List Nat :=
  (p.1, n :: p.2)

/-- `run` with the emitted-byte count `out.length` recorded at the head of
every loop iteration (including the final end-of-stream test). `ovr := false`
drops the per-opcode overrun check (the `noOverrun` mutant). -/
def runT (ovr : Bool) (base : Bytes) (rl : Nat) :
    Bytes → Bytes → Except Err Bytes × List Nat
  | [], out => (if out.length = rl then .ok out else .error .resultLenUnderrun, [out.length])
  | op :: rest, out => tcons out.length <|
    if 128 ≤ op.toNat then
      if op.toNat ≠ 128 then (.error .reservedOpcodeBits, [])
      else if rest.length < 6 then (.error .eof, [])
      else
        match readLE 4 rest, readLE 2 (rest.drop 4) with
        | some off, some len =>
          if len = 0 then (.error .zeroLengthCopy, [])
          else if base.length < off + len then (.error .copyPastBase, [])
          else if ovr ∧ rl < out.length + len then (.error .resultLenOverrun, [])
          else
            match slice? base off len with
            | some chunk => runT ovr base rl (rest.drop 6) (out ++ chunk)
            | none => (.error .oob, [])
        | _, _ => (.error .oob, [])
    else if op.toNat = 0 then (.error .zeroOpcode, [])
    else if rest.length < op.toNat then (.error .eof, [])
    else if ovr ∧ rl < out.length + op.toNat then (.error .resultLenOverrun, [])
    else
      match slice? rest 0 op.toNat with
      | some lit => runT ovr base rl (rest.drop op.toNat) (out ++ lit)
      | none => (.error .oob, [])
termination_by r _ => r.length
decreasing_by all_goals simp; omega

/-- The instrumented loop computes exactly `run`. -/
theorem runT_fst (base : Bytes) (rl : Nat) :
    ∀ (r out : Bytes), (runT true base rl r out).1 = run base rl r out
  | [], out => by rw [runT, run]
  | op :: rest, out => by
    rw [runT, run]
    simp only [tcons, Bool.true_eq, true_and]
    split
    · split
      · rfl
      · split
        · rfl
        · split
          · split
            · rfl
            · split
              · rfl
              · split
                · rfl
                · split
                  · exact runT_fst base rl _ _
                  · rfl
          · rfl
    · split
      · rfl
      · split
        · rfl
        · split
          · rfl
          · split
            · exact runT_fst base rl _ _
            · rfl
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- §2 / §10: starting within `result_len`, the emitted-byte count at every
iteration of the loop stays `≤ result_len`, whatever the stream. -/
theorem runT_bounded (base : Bytes) (rl : Nat) :
    ∀ (r out : Bytes), out.length ≤ rl → ∀ n ∈ (runT true base rl r out).2, n ≤ rl
  | [], out, hle => by
    rw [runT]; simpa using hle
  | op :: rest, out, hle => by
    rw [runT]
    simp only [tcons, Bool.true_eq, true_and, List.mem_cons]
    intro n hn
    rcases hn with hn | hn
    · omega
    · revert n
      split
      · split
        · simp
        · split
          · simp
          · split
            · rename_i o l _ _
              split
              · simp
              · split
                · simp
                · split
                  · simp
                  · rename_i hno
                    split
                    · rename_i chunk hs
                      have hcl : chunk.length = l := by
                        simp [slice?] at hs; obtain ⟨h1, rfl⟩ := hs; simp; omega
                      exact runT_bounded base rl _ _ (by simp; omega)
                    · simp
            · simp
      · split
        · simp
        · split
          · simp
          · split
            · simp
            · rename_i hno
              split
              · rename_i lit hs
                have hcl : lit.length = op.toNat := by
                  simp [slice?] at hs; obtain ⟨h1, rfl⟩ := hs; simp; omega
                exact runT_bounded base rl _ _ (by simp; omega)
              · simp
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- `apply` runs the instrumented loop from an empty output: for any stream
whose header parses and targets this base, `apply` is `runT`'s result, and its
running count never exceeds the declared `result_len`. -/
theorem apply_running_le (base rest : Bytes) (bl rl : Nat)
    (hbl : readLE 4 rest = some bl) (hrl : readLE 4 (rest.drop 4) = some rl)
    (hb : bl = base.length) :
    apply base (0x01 :: rest) = (runT true base rl (rest.drop 8) []).1 ∧
      ∀ n ∈ (runT true base rl (rest.drop 8) []).2, n ≤ rl := by
  refine ⟨?_, runT_bounded base rl _ [] (by simp)⟩
  have := readLE_len hrl
  simp at this
  rw [runT_fst]
  unfold apply
  simp [headerLen, show ¬ rest.length + 1 < 9 by omega, hbl, hrl, hb]

end MkitFormal.Delta
