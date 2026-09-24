import MkitFormal.DeltaProofs

/-!
# Non-vacuity witnesses for the SPEC-DELTA theorems (MKIT-25)

Each check of §2/§4 is dropped in turn from a mutant of `run`/`apply`
(`Mut`); for every mutant a concrete stream makes the corresponding theorem
of `MkitFormal.DeltaProofs` false, while the real `apply` rejects the same
stream with the §8 error. Likewise the `wf` hypothesis of `decode_encode`,
the reserved-bit check behind `encode_decode`, and the byte re-verification
of the writer model behind `apply_encodeWith` are each shown load-bearing.

The only §4 check without a canary here is the per-opcode `result_len`
overrun check: dropping it changes the error *kind* (`resultLenUnderrun`
at end of stream instead of `resultLenOverrun`) but not acceptance, so it is
covered by the differential test (which compares error kinds), see
`overrun_kind_only`.
-/

namespace MkitFormal.Delta.Canaries

open MkitFormal.Delta

/-- Which check the mutant omits. -/
inductive Mut where
  | noInsertEof
  | noCopyBound
  | noFinalLen
  | noOverrun
  | noBaseLen
  deriving DecidableEq, Repr

/-- `run` with one check removed. -/
def runMut (m : Mut) (base : Bytes) (rl : Nat) : Bytes → Bytes → Except Err Bytes
  | [], out => if m = .noFinalLen ∨ out.length = rl then .ok out else .error .resultLenUnderrun
  | op :: rest, out =>
    if 128 ≤ op.toNat then
      if op.toNat ≠ 128 then .error .reservedOpcodeBits
      else if rest.length < 6 then .error .eof
      else
        match readLE 4 rest, readLE 2 (rest.drop 4) with
        | some off, some len =>
          if len = 0 then .error .zeroLengthCopy
          else if m ≠ .noCopyBound ∧ base.length < off + len then .error .copyPastBase
          else if m ≠ .noOverrun ∧ rl < out.length + len then .error .resultLenOverrun
          else
            match slice? base off len with
            | some chunk => runMut m base rl (rest.drop 6) (out ++ chunk)
            | none => .error .oob
        | _, _ => .error .oob
    else if op.toNat = 0 then .error .zeroOpcode
    else if m ≠ .noInsertEof ∧ rest.length < op.toNat then .error .eof
    else if m ≠ .noOverrun ∧ rl < out.length + op.toNat then .error .resultLenOverrun
    else
      match slice? rest 0 op.toNat with
      | some lit => runMut m base rl (rest.drop op.toNat) (out ++ lit)
      | none => .error .oob
termination_by r _ => r.length
decreasing_by all_goals simp; omega

def applyMut (m : Mut) (base s : Bytes) : Except Err Bytes :=
  if s.length < headerLen then .error .eof
  else
    match s with
    | [] => .error .oob
    | v :: rest =>
      if v ≠ 0x01 then .error .unsupportedVersion
      else
        match readLE 4 rest, readLE 4 (rest.drop 4) with
        | some bl, some rl =>
          if m ≠ .noBaseLen ∧ bl ≠ base.length then .error .baseLenMismatch
          else runMut m base rl (rest.drop 8) []
        | _, _ => .error .oob

/-! ## `apply_ne_oob` can fail -/

/-- INSERT(5) with one literal byte left. -/
def sTruncIns : Bytes := [1, 0, 0, 0, 0, 5, 0, 0, 0, 5, 97]

theorem noInsertEof_reads_oob : applyMut .noInsertEof [] sTruncIns = .error .oob := by
  simp [applyMut, runMut, sTruncIns, readLE, headerLen, slice?]

theorem apply_sTruncIns : apply [] sTruncIns = .error .eof := by
  simp [apply, run, sTruncIns, readLE, headerLen]

/-- COPY(2, 2) against a 3-byte base. -/
def sCopyPast : Bytes := [1, 3, 0, 0, 0, 2, 0, 0, 0, 0x80, 2, 0, 0, 0, 2, 0]

theorem noCopyBound_reads_oob : applyMut .noCopyBound [1, 2, 3] sCopyPast = .error .oob := by
  simp [applyMut, runMut, sCopyPast, readLE, headerLen, slice?]

theorem apply_sCopyPast : apply [1, 2, 3] sCopyPast = .error .copyPastBase := by
  simp [apply, run, sCopyPast, readLE, headerLen]

/-- `apply_rejects_copy_oob`'s premise holds for `sCopyPast`. -/
theorem sCopyPast_decodes : decode sCopyPast = .ok ⟨3, 2, [.copy 2 2]⟩ := by
  simp [decode, decodeInstrs, sCopyPast, readLE, Except.map]

/-! ## `apply_rejects_len_mismatch` / `apply_ok_length` can fail -/

/-- `result_len = 5` but a single 1-byte INSERT. -/
def sShort : Bytes := [1, 0, 0, 0, 0, 5, 0, 0, 0, 1, 7]

theorem noFinalLen_accepts_short : applyMut .noFinalLen [] sShort = .ok [7] := by
  simp [applyMut, runMut, sShort, readLE, headerLen, slice?]

theorem apply_sShort : apply [] sShort = .error .resultLenUnderrun := by
  simp [apply, run, sShort, readLE, headerLen, slice?]

/-! ## `apply_sound`'s `baseLen` conjunct can fail -/

/-- Declares `base_len = 1` but is applied to the empty base. -/
def sWrongBase : Bytes := [1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 7]

theorem noBaseLen_accepts : applyMut .noBaseLen [] sWrongBase = .ok [7] := by
  simp [applyMut, runMut, sWrongBase, readLE, headerLen, slice?]

theorem apply_sWrongBase : apply [] sWrongBase = .error .baseLenMismatch := by
  simp [apply, sWrongBase, readLE, headerLen]

/-! ## The overrun check only changes the error kind -/

/-- `result_len = 1`, INSERT of 2 bytes. -/
def sLong : Bytes := [1, 0, 0, 0, 0, 1, 0, 0, 0, 2, 7, 8]

theorem overrun_kind_only :
    apply [] sLong = .error .resultLenOverrun ∧
      applyMut .noOverrun [] sLong = .error .resultLenUnderrun := by
  constructor
  · simp [apply, run, sLong, readLE, headerLen]
  · simp [applyMut, runMut, sLong, readLE, headerLen, slice?]

/-! ## `decode_encode` needs `wf` -/

theorem decode_encode_needs_wf :
    decode (encode ⟨0, 1, [.copy (2 ^ 32) 1]⟩) = .ok ⟨0, 1, [.copy 0 1]⟩ := by
  simp [encode, encInstrs, encInstr, leBytes, decode, decodeInstrs, readLE, Except.map]

theorem decode_encode_needs_wf' : decode (encode ⟨0, 0, [.insert []]⟩) = .error .zeroOpcode := by
  simp [encode, encInstrs, encInstr, leBytes, decode, decodeInstrs, readLE, Except.map]

/-! ## `encode_decode` (canonicity) needs the reserved-bit check -/

/-- A lax decoder treating every opcode `≥ 0x80` as COPY. -/
def decodeLax : Bytes → Except Err (List Instr)
  | [] => .ok []
  | op :: rest =>
    if 128 ≤ op.toNat then
      match readLE 4 rest, readLE 2 (rest.drop 4) with
      | some off, some len =>
        if len = 0 then .error .zeroLengthCopy
        else (decodeLax (rest.drop 6)).map (.copy off len :: ·)
      | _, _ => .error .eof
    else if op.toNat = 0 then .error .zeroOpcode
    else if rest.length < op.toNat then .error .eof
    else (decodeLax (rest.drop op.toNat)).map (.insert (rest.take op.toNat) :: ·)
termination_by r => r.length
decreasing_by all_goals simp; omega

theorem decodeLax_not_canonical :
    decodeLax [0x81, 0, 0, 0, 0, 1, 0] = .ok [.copy 0 1] ∧
      encInstrs [.copy 0 1] = [0x80, 0, 0, 0, 0, 1, 0] := by
  constructor
  · simp [decodeLax, readLE, Except.map]
  · simp [encInstrs, encInstr, leBytes]

theorem decodeInstrs_reserved : decodeInstrs [0x81, 0, 0, 0, 0, 1, 0] = .error .reservedOpcodeBits := by
  simp [decodeInstrs]

/-! ## The writer's byte re-verification is load-bearing -/

/-- `validCopy` without the byte comparison: trusts the oracle. -/
def encodeTrusting (prop : Nat → Option (Nat × Nat)) (base target : Bytes) (i : Nat)
    (buf : Bytes) : List Instr :=
  if h : i < target.length then
    match prop i with
    | some (o, l) =>
      if hv : 0 < l ∧ l < 2 ^ 16 ∧ o < 2 ^ 32 ∧ o + l ≤ base.length ∧ i + l ≤ target.length then
        flush buf ++ .copy o l :: encodeTrusting prop base target (i + l) []
      else encodeTrusting prop base target (i + 1) (buf ++ [target[i]])
    | none => encodeTrusting prop base target (i + 1) (buf ++ [target[i]])
  else flush buf
termination_by target.length - i
decreasing_by all_goals (try have := hv.1); all_goals omega

/-- A lying oracle breaks the round trip of the trusting writer … -/
theorem trusting_roundtrip_fails :
    apply [1] (encode ⟨1, 1, encodeTrusting (fun _ => some (0, 1)) [1] [2] 0 []⟩) = .ok [1] := by
  simp [encodeTrusting, flush, encode, encInstrs, encInstr, leBytes, apply, run, readLE,
    headerLen, slice?]

/-- … but not of the verifying writer (instance of `apply_encodeWith`). -/
theorem verifying_roundtrip :
    apply [1] (encode (encodeWith (fun _ => some (0, 1)) [1] [2])) = .ok [2] :=
  apply_encodeWith _ _ _ (by decide) (by decide)

end MkitFormal.Delta.Canaries
