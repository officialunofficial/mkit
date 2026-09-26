import MkitFormal.DeltaModel

/-!
# SPEC-DELTA theorems (MKIT-25)

* `topBit_iff`, `reservedBits_iff`: the model's `128 ≤ op` / `op ≠ 128` tests
  are exactly `op & 0x80 != 0` / `op & 0x7F != 0` of §3 and `delta.rs`.
* `decode_encode` / `encode_decode`: the §2/§3 encoding of well-formed
  instruction lists is a bijection onto the streams `decode` accepts.
* `apply_ne_oob`: no stream makes `apply` read past the delta buffer or the
  base (§8 vector 15, §10 "cannot ... read out of bounds").
* `apply_sound`: an accepted stream decodes, targets this base (§2), has every
  COPY inside the base (§2), and the output is exactly `result_len` bytes and
  equals the instruction-list semantics. Corollaries `apply_rejects_copy_oob`
  and `apply_rejects_len_mismatch`.
* `apply_complete` and `apply_encodeWith` (round trip): `apply` reconstructs
  the target from the stream of any oracle-driven writer (§5), including the
  all-INSERT writer and the model of the Rust writer.
-/

namespace MkitFormal.Delta

/-! ## Opcode bit tests -/

set_option maxRecDepth 20000 in
private theorem opTable : ∀ i : Fin 256,
    ((UInt8.ofNat i.val &&& 0x80) ≠ 0 ↔ 128 ≤ i.val) ∧
    (128 ≤ i.val → ((UInt8.ofNat i.val &&& 0x7F) ≠ 0 ↔ i.val ≠ 128)) := by
  decide

/-- §3: "top bit set" is `128 ≤ op`. -/
theorem topBit_iff (op : UInt8) : (op &&& 0x80) ≠ 0 ↔ 128 ≤ op.toNat := by
  simpa using (opTable ⟨op.toNat, op.toNat_lt⟩).1

/-- §3.1: for a COPY opcode, "reserved low bits set" is `op ≠ 0x80`. -/
theorem reservedBits_iff (op : UInt8) (h : 128 ≤ op.toNat) :
    (op &&& 0x7F) ≠ 0 ↔ op.toNat ≠ 128 := by
  simpa using (opTable ⟨op.toNat, op.toNat_lt⟩).2 h

/-! ## Fixed-width integers -/

theorem p4 : (256 : Nat) ^ 4 = 2 ^ 32 := rfl
theorem p2 : (256 : Nat) ^ 2 = 2 ^ 16 := rfl

@[simp] theorem length_leBytes (k v : Nat) : (leBytes k v).length = k := by
  induction k generalizing v <;> simp [leBytes, *]

theorem readLE_leBytes (k v : Nat) (r : Bytes) :
    readLE k (leBytes k v ++ r) = some (v % 256 ^ k) := by
  induction k generalizing v with
  | zero => simp [readLE, Nat.mod_one]
  | succ k ih =>
    simp only [leBytes, List.cons_append, readLE, ih, Option.map_some]
    congr 1
    rw [Nat.pow_succ, Nat.mul_comm _ 256, Nat.mod_mul]
    simp

theorem readLE_len {k : Nat} {r : Bytes} {v : Nat} (h : readLE k r = some v) :
    k ≤ r.length := by
  induction k generalizing r v with
  | zero => simp
  | succ k ih =>
    cases r with
    | nil => simp [readLE] at h
    | cons b r =>
      simp only [readLE, Option.map_eq_some_iff] at h
      obtain ⟨w, hw, -⟩ := h
      have := ih hw
      simp; omega

theorem readLE_some {k : Nat} {r : Bytes} (h : k ≤ r.length) : ∃ v, readLE k r = some v := by
  induction k generalizing r with
  | zero => exact ⟨0, rfl⟩
  | succ k ih =>
    cases r with
    | nil => simp at h
    | cons b r =>
      obtain ⟨w, hw⟩ := ih (r := r) (by simp at h; omega)
      exact ⟨b.toNat + 256 * w, by simp [readLE, hw]⟩

theorem readLE_lt {k : Nat} {r : Bytes} {v : Nat} (h : readLE k r = some v) : v < 256 ^ k := by
  induction k generalizing r v with
  | zero => simp [readLE] at h; omega
  | succ k ih =>
    cases r with
    | nil => simp [readLE] at h
    | cons b r =>
      simp only [readLE, Option.map_eq_some_iff] at h
      obtain ⟨w, hw, rfl⟩ := h
      have h1 := ih hw
      have h2 := b.toNat_lt
      rw [Nat.pow_succ]
      have : 256 * w + 256 ≤ 256 ^ k * 256 := by
        rw [Nat.mul_comm (256 ^ k)]; exact Nat.mul_le_mul_left _ h1
      omega

/-- Reading back is canonical: the bytes are exactly the encoding of the value. -/
theorem leBytes_readLE {k : Nat} {r : Bytes} {v : Nat} (h : readLE k r = some v) :
    leBytes k v ++ r.drop k = r := by
  induction k generalizing r v with
  | zero => simp [leBytes]
  | succ k ih =>
    cases r with
    | nil => simp [readLE] at h
    | cons b r =>
      simp only [readLE, Option.map_eq_some_iff] at h
      obtain ⟨w, hw, rfl⟩ := h
      have hb := b.toNat_lt
      have e1 : (b.toNat + 256 * w) % 256 = b.toNat := by omega
      have e2 : (b.toNat + 256 * w) / 256 = w := by omega
      simp only [leBytes, e1, e2, List.drop_succ_cons, List.cons_append, ih hw,
        UInt8.ofNat_toNat]

theorem slice?_eq {r : Bytes} {i n : Nat} (h : i + n ≤ r.length) :
    slice? r i n = some ((r.drop i).take n) := by
  simp [slice?, h]

/-! ## decode ∘ encode = id -/

theorem decodeInstrs_encInstrs :
    ∀ is : List Instr, is.all Instr.wf = true → decodeInstrs (encInstrs is) = .ok is
  | [], _ => by simp [encInstrs, decodeInstrs]
  | .copy o l :: is, h => by
    simp only [List.all_cons, Bool.and_eq_true, Instr.wf, decide_eq_true_eq] at h
    obtain ⟨⟨⟨ho, hl0⟩, hl⟩, hs⟩ := h
    have ih := decodeInstrs_encInstrs is hs
    have d4 : (leBytes 4 o ++ leBytes 2 l ++ encInstrs is).drop 4 =
        leBytes 2 l ++ encInstrs is := by
      rw [List.append_assoc, List.drop_left' (by simp)]
    have d6 : (leBytes 4 o ++ leBytes 2 l ++ encInstrs is).drop 6 = encInstrs is := by
      rw [List.drop_left' (by simp)]
    simp only [encInstrs, encInstr, List.cons_append]
    rw [decodeInstrs]
    simp only [show (0x80 : UInt8).toNat = 128 from rfl, Nat.le_refl, if_true, ne_eq,
      not_true_eq_false, if_false]
    rw [d4, d6, List.append_assoc, readLE_leBytes, readLE_leBytes, ih]
    have : o % 256 ^ 4 = o := Nat.mod_eq_of_lt (by rw [p4]; omega)
    have : l % 256 ^ 2 = l := Nat.mod_eq_of_lt (by rw [p2]; omega)
    simp [*, Except.map] <;> omega
  | .insert lit :: is, h => by
    simp only [List.all_cons, Bool.and_eq_true, Instr.wf, decide_eq_true_eq] at h
    obtain ⟨⟨h0, h1⟩, hs⟩ := h
    have ih := decodeInstrs_encInstrs is hs
    have hop : (UInt8.ofNat lit.length).toNat = lit.length := by
      simp; omega
    simp only [encInstrs, encInstr, List.cons_append]
    rw [decodeInstrs]
    simp only [hop, List.length_append, List.drop_left, List.take_left]
    rw [ih]
    have : ¬ 128 ≤ lit.length := by omega
    have : lit.length ≠ 0 := by omega
    have : ¬ lit.length + (encInstrs is).length < lit.length := by omega
    simp [*, Except.map] <;> omega

theorem decode_encode (d : Delta) (h : d.wf = true) : decode (encode d) = .ok d := by
  obtain ⟨bl, rl, is⟩ := d
  simp only [Delta.wf, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨hb, hr⟩, hs⟩ := h
  simp only [encode, decode, ne_eq, not_true_eq_false, if_false]
  rw [readLE_leBytes, List.drop_left' (by simp), readLE_leBytes,
    ← List.append_assoc, List.drop_left' (by simp), decodeInstrs_encInstrs is hs]
  simp [Nat.mod_eq_of_lt hb, Nat.mod_eq_of_lt hr, Except.map]

/-! ## encode ∘ decode = id (the encoding is canonical) -/

theorem encInstrs_decodeInstrs :
    ∀ (r : Bytes) (is : List Instr), decodeInstrs r = .ok is →
      encInstrs is = r ∧ is.all Instr.wf = true
  | [], is, h => by
    simp [decodeInstrs] at h; subst h; simp [encInstrs]
  | op :: rest, is, h => by
    rw [decodeInstrs] at h
    by_cases hc : 128 ≤ op.toNat
    · simp only [hc, if_true] at h
      by_cases hr : op.toNat ≠ 128
      · simp [hr] at h
      · simp only [hr, if_false] at h
        split at h
        · rename_i off len h4 h2
          by_cases hz : len = 0
          · simp [hz] at h
          · simp only [hz, if_false] at h
            cases hd : decodeInstrs (rest.drop 6) with
            | error e => simp [hd, Except.map] at h
            | ok is' =>
              simp [hd, Except.map] at h
              subst h
              obtain ⟨ih1, ih2⟩ := encInstrs_decodeInstrs (rest.drop 6) is' hd
              have e4 := leBytes_readLE h4
              have e2 := leBytes_readLE h2
              have l4 := readLE_lt h4
              have l2 := readLE_lt h2
              have hop : op = 0x80 := by
                apply UInt8.toNat_inj.mp; simp only [Decidable.not_not] at hr; exact hr
              refine ⟨?_, ?_⟩
              · simp only [encInstrs, encInstr, hop, List.cons_append, ih1]
                congr 1
                rw [List.append_assoc, List.drop_drop] at *
                rw [e2, e4]
              · simp [Instr.wf, ih2]; omega
        · simp at h
    · simp only [hc, if_false] at h
      by_cases h0 : op.toNat = 0
      · simp [h0] at h
      · by_cases hl : rest.length < op.toNat
        · simp [h0, hl] at h
        · simp only [h0, hl, if_false] at h
          cases hd : decodeInstrs (rest.drop op.toNat) with
          | error e => simp [hd, Except.map] at h
          | ok is' =>
            simp [hd, Except.map] at h
            subst h
            obtain ⟨ih1, ih2⟩ := encInstrs_decodeInstrs _ is' hd
            refine ⟨?_, ?_⟩
            · have hlen : (rest.take op.toNat).length = op.toNat := by simp; omega
              simp only [encInstrs, encInstr, hlen, UInt8.ofNat_toNat, List.cons_append, ih1,
                List.take_append_drop]
            · simp [Instr.wf, ih2]; omega
termination_by r => r.length
decreasing_by all_goals simp; omega

theorem encode_decode (s : Bytes) (d : Delta) (h : decode s = .ok d) :
    encode d = s ∧ d.wf = true := by
  match s, h with
  | v :: rest, h =>
    simp only [decode] at h
    by_cases hv : v ≠ 0x01
    · simp [hv] at h
    · simp only [hv, if_false] at h
      simp only [Decidable.not_not] at hv
      split at h
      · rename_i bl rl hb hr
        cases hd : decodeInstrs (rest.drop 8) with
        | error e => simp [hd, Except.map] at h
        | ok is =>
          simp [hd, Except.map] at h
          subst h
          obtain ⟨h1, h2⟩ := encInstrs_decodeInstrs _ _ hd
          have eb := leBytes_readLE hb
          have er := leBytes_readLE hr
          have lb := readLE_lt hb
          have lr := readLE_lt hr
          refine ⟨?_, ?_⟩
          · simp only [encode, hv, h1]
            congr 1
            rw [List.drop_drop] at er
            rw [er, eb]
          · simp [Delta.wf, h2]; omega
      · simp at h

/-! ## No read past the delta buffer or the base -/

theorem run_ne_oob (base : Bytes) (rl : Nat) :
    ∀ (r out : Bytes), run base rl r out ≠ .error .oob
  | [], out => by
    rw [run]; split <;> simp
  | op :: rest, out => by
    rw [run]
    split
    · split
      · simp
      · split
        · simp
        · rename_i hlen
          obtain ⟨o, ho⟩ := readLE_some (k := 4) (r := rest) (by omega)
          obtain ⟨l, hl⟩ := readLE_some (k := 2) (r := rest.drop 4) (by simp; omega)
          simp only [ho, hl]
          split
          · simp
          · split
            · simp
            · rename_i hb
              split
              · simp
              · rw [slice?_eq (by omega)]
                exact run_ne_oob base rl _ _
    · split
      · simp
      · split
        · simp
        · split
          · simp
          · rw [slice?_eq (by simp; omega)]
            exact run_ne_oob base rl _ _
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- §8 vector 15 / §10: for every base and every byte string, `apply` never
performs an out-of-bounds read of the stream or of the base. -/
theorem apply_ne_oob (base s : Bytes) : apply base s ≠ .error .oob := by
  unfold apply
  split
  · simp
  · rename_i hs
    split
    · simp [headerLen] at hs
    · rename_i v rest
      split
      · simp
      · simp only [headerLen, List.length_cons] at hs
        obtain ⟨b, hb⟩ := readLE_some (k := 4) (r := rest) (by omega)
        obtain ⟨r, hr⟩ := readLE_some (k := 4) (r := rest.drop 4) (by simp; omega)
        simp only [hb, hr]
        split
        · simp
        · exact run_ne_oob _ _ _ _

/-! ## Soundness: what an accepted stream guarantees -/

theorem exec_append (base : Bytes) (a b : List Instr) :
    exec base (a ++ b) = exec base a ++ exec base b := by
  induction a <;> simp [exec, *]

theorem run_sound (base : Bytes) (rl : Nat) :
    ∀ (r out res : Bytes), run base rl r out = .ok res →
      ∃ is, decodeInstrs r = .ok is ∧ is.all (Instr.inBase base.length) = true ∧
        res = out ++ exec base is ∧ res.length = rl
  | [], out, res, h => by
    rw [run] at h
    split at h
    · simp at h; subst h
      exact ⟨[], by simp [decodeInstrs], by simp, by simp [exec], by assumption⟩
    · simp at h
  | op :: rest, out, res, h => by
    rw [run] at h
    split at h
    · rename_i hc
      split at h
      · simp at h
      · rename_i hr
        split at h
        · simp at h
        · split at h
          · rename_i o l ho hl
            split at h
            · simp at h
            · rename_i hz
              split at h
              · simp at h
              · rename_i hb
                split at h
                · simp at h
                · rw [slice?_eq (by omega)] at h
                  simp only at h
                  obtain ⟨is, hd, hin, he, hlen⟩ := run_sound base rl _ _ _ h
                  refine ⟨.copy o l :: is, ?_, ?_, ?_, hlen⟩
                  · rw [decodeInstrs]; simp [hc, hr, ho, hl, hz, hd, Except.map]
                  · simp [Instr.inBase, hin]; omega
                  · simp [he, exec, execInstr]
          · simp at h
    · rename_i hc
      split at h
      · simp at h
      · rename_i h0
        split at h
        · simp at h
        · rename_i hl
          split at h
          · simp at h
          · rw [slice?_eq (by simp; omega)] at h
            simp only at h
            obtain ⟨is, hd, hin, he, hlen⟩ := run_sound base rl _ _ _ h
            refine ⟨.insert (rest.take op.toNat) :: is, ?_, ?_, ?_, hlen⟩
            · rw [decodeInstrs]; simp [hc, h0, hl, hd, Except.map]
            · simp [Instr.inBase, hin]
            · simp [he, exec, execInstr]
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- An accepted stream decodes to a delta whose `base_len` is the supplied
base's length (§2), whose COPYs all lie inside the base (§2), whose output is
exactly `result_len` bytes (§2) and equals the instruction-list semantics. -/
theorem apply_sound (base s res : Bytes) (h : apply base s = .ok res) :
    ∃ d, decode s = .ok d ∧ d.baseLen = base.length ∧
      d.instrs.all (Instr.inBase base.length) = true ∧
      res = exec base d.instrs ∧ res.length = d.resultLen := by
  unfold apply at h
  split at h
  · simp at h
  · split at h
    · simp at h
    · rename_i v rest
      split at h
      · simp at h
      · rename_i hv
        split at h
        · rename_i bl rl hb hr
          split at h
          · simp at h
          · rename_i hbl
            obtain ⟨is, hd, hin, he, hlen⟩ := run_sound base rl _ _ _ h
            refine ⟨⟨bl, rl, is⟩, ?_, by simpa using hbl, hin, by simpa using he, hlen⟩
            simp [decode, hv, hb, hr, hd, Except.map]
        · simp at h

theorem decode_det {s : Bytes} {d d' : Delta} (h : decode s = .ok d) (h' : decode s = .ok d') :
    d = d' := by
  rw [h] at h'; cases h'; rfl

/-- §2: any stream containing a COPY outside the base is rejected. -/
theorem apply_rejects_copy_oob (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (o l : Nat) (hmem : Instr.copy o l ∈ d.instrs) (hout : base.length < o + l) :
    ∃ e, apply base s = .error e := by
  cases ha : apply base s with
  | error e => exact ⟨e, rfl⟩
  | ok res =>
    obtain ⟨d', hd', -, hin, -, -⟩ := apply_sound base s res ha
    rw [decode_det hd hd'] at hmem
    have := List.all_eq_true.mp hin _ hmem
    simp [Instr.inBase] at this; omega

/-- §2: any stream whose instructions do not produce exactly `result_len`
bytes is rejected. -/
theorem apply_rejects_len_mismatch (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (hne : (exec base d.instrs).length ≠ d.resultLen) : ∃ e, apply base s = .error e := by
  cases ha : apply base s with
  | error e => exact ⟨e, rfl⟩
  | ok res =>
    obtain ⟨d', hd', -, -, he, hl⟩ := apply_sound base s res ha
    rw [← decode_det hd hd'] at he hl
    subst he; exact absurd hl hne

/-- An accepted stream's output length is the declared `result_len`. -/
theorem apply_ok_length (base s res : Bytes) (h : apply base s = .ok res) :
    ∃ d, decode s = .ok d ∧ res.length = d.resultLen := by
  obtain ⟨d, hd, -, -, -, hl⟩ := apply_sound base s res h
  exact ⟨d, hd, hl⟩

/-! ## Completeness and round trip -/

theorem run_complete (base : Bytes) (rl : Nat) :
    ∀ (r out : Bytes) (is : List Instr), decodeInstrs r = .ok is →
      is.all (Instr.inBase base.length) = true → (out ++ exec base is).length = rl →
      run base rl r out = .ok (out ++ exec base is)
  | [], out, is, h, _, hl => by
    simp [decodeInstrs] at h; subst h
    simp [exec] at hl
    rw [run]; simp [exec, hl]
  | op :: rest, out, is, h, hin, hl => by
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
              simp only [exec, execInstr, List.length_append] at hl
              have hcl : ((base.drop o).take l).length = l := by simp; omega
              have hnb : ¬ base.length < o + l := by omega
              have hno : ¬ rl < out.length + l := by omega
              simp only [hnb, hno, if_false]
              rw [slice?_eq hb]
              simp only
              rw [run_complete base rl _ _ is' hd hin' (by simp; omega)]
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
            simp only [exec, execInstr, List.length_append] at hl
            have htl : (rest.take op.toNat).length = op.toNat := by simp; omega
            have hno : ¬ rl < out.length + op.toNat := by omega
            simp only [hno, if_false]
            rw [slice?_eq (by simp; omega)]
            simp only [List.drop_zero]
            rw [run_complete base rl _ _ is' hd hin.2 (by simp; omega)]
            simp [exec, execInstr]
termination_by r => r.length
decreasing_by all_goals simp; omega

/-- Every stream that decodes, targets this base, keeps its COPYs inside the
base and produces exactly `result_len` bytes is accepted. With `apply_sound`
this characterises `apply` exactly. -/
theorem apply_complete (base s : Bytes) (d : Delta) (hd : decode s = .ok d)
    (hb : d.baseLen = base.length) (hin : d.instrs.all (Instr.inBase base.length) = true)
    (hl : (exec base d.instrs).length = d.resultLen) :
    apply base s = .ok (exec base d.instrs) := by
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
          simp at this hb hl
          simp only [Decidable.not_not] at hv
          subst hv
          unfold apply
          simp only [headerLen, List.length_cons, show ¬ rest.length + 1 < 9 by omega, if_false,
            hbl, hrl, hb, ne_eq, not_true_eq_false]
          simpa using run_complete base rl _ [] is hdi hin (by simpa using hl)
      · simp at hd

/-! ### The writer model -/

theorem flush_spec (base : Bytes) (n : Nat) (buf : Bytes) (h : buf.length ≤ 127) :
    (flush buf).all Instr.wf = true ∧ (flush buf).all (Instr.inBase n) = true ∧
      exec base (flush buf) = buf := by
  unfold flush
  split
  · simp_all [exec]
  · rename_i hne
    have : 0 < buf.length := List.length_pos_iff.mpr hne
    simp [Instr.wf, Instr.inBase, exec, execInstr]; omega

/-- Invariant of the writer: well-formed, inside the base, and producing the
pending literal followed by the rest of the target. -/
def IsEnc (base target : Bytes) (i : Nat) (buf : Bytes) (is : List Instr) : Prop :=
  is.all Instr.wf = true ∧ is.all (Instr.inBase base.length) = true ∧
    exec base is = buf ++ target.drop i

theorem encodeFrom_spec (prop : Nat → Option (Nat × Nat)) (base target : Bytes)
    (i : Nat) (buf : Bytes) (hbuf : buf.length < 127) :
      (encodeFrom prop base target i buf).all Instr.wf = true ∧
        (encodeFrom prop base target i buf).all (Instr.inBase base.length) = true ∧
        exec base (encodeFrom prop base target i buf) = buf ++ target.drop i := by
  -- literal step shared by both "no copy" branches
  have lit : ∀ (h : i < target.length),
      IsEnc base target i buf
        (if (buf ++ [target[i]]).length = 127 then
          .insert (buf ++ [target[i]]) :: encodeFrom prop base target (i + 1) []
         else encodeFrom prop base target (i + 1) (buf ++ [target[i]])) := by
    intro h
    have hd : target.drop i = target[i] :: target.drop (i + 1) := List.drop_eq_getElem_cons h
    unfold IsEnc
    split
    · rename_i h127
      obtain ⟨a, b, c⟩ := encodeFrom_spec prop base target (i + 1) [] (by simp)
      simp only [List.all_cons, a, b, Bool.and_true, Instr.wf, Instr.inBase, exec, execInstr, c,
        hd, h127]
      simp
    · rename_i h127
      obtain ⟨a, b, c⟩ := encodeFrom_spec prop base target (i + 1) (buf ++ [target[i]])
        (by simp at h127 ⊢; omega)
      exact ⟨a, b, by rw [c, hd]; simp⟩
  unfold encodeFrom
  split
  · rename_i h
    split
    · rename_i o l _
      split
      · rename_i hv
        obtain ⟨hl0, hl, ho, hb, ht, heq⟩ := hv
        obtain ⟨f1, f2, f3⟩ := flush_spec base base.length buf (by omega)
        obtain ⟨a, b, c⟩ := encodeFrom_spec prop base target (i + l) [] (by simp)
        simp only [List.all_append, f1, f2, List.all_cons, a, b, Bool.and_true, Bool.true_and,
          Instr.wf, Instr.inBase, exec_append, f3, exec, execInstr, c, heq]
        refine ⟨by simp; omega, by simp; omega, ?_⟩
        simp only [List.nil_append]
        congr 1
        rw [← @List.drop_drop _ l i target, List.take_append_drop]
      · exact lit h
    · exact lit h
  · rename_i h
    obtain ⟨f1, f2, f3⟩ := flush_spec base base.length buf (by omega)
    refine ⟨f1, f2, ?_⟩
    rw [f3, List.drop_eq_nil_of_le (by omega)]; simp
termination_by target.length - i
decreasing_by all_goals omega

theorem encodeWith_wf (prop : Nat → Option (Nat × Nat)) (base target : Bytes)
    (hb : base.length < 2 ^ 32) (ht : target.length < 2 ^ 32) :
    (encodeWith prop base target).wf = true := by
  obtain ⟨a, -, -⟩ := encodeFrom_spec prop base target 0 [] (by simp)
  simp [encodeWith, Delta.wf, a, hb, ht]

/-- Round trip (§5): for any match oracle, applying the encoded stream of the
writer model to the base reconstructs the target exactly. -/
theorem apply_encodeWith (prop : Nat → Option (Nat × Nat)) (base target : Bytes)
    (hb : base.length < 2 ^ 32) (ht : target.length < 2 ^ 32) :
    apply base (encode (encodeWith prop base target)) = .ok target := by
  obtain ⟨-, b, c⟩ := encodeFrom_spec prop base target 0 [] (by simp)
  have hd := decode_encode _ (encodeWith_wf prop base target hb ht)
  have := apply_complete base _ _ hd rfl b (by simp [encodeWith, c])
  simpa [encodeWith, c] using this

/-- The all-INSERT writer of §5 round-trips. -/
theorem apply_encodeInsertOnly (base target : Bytes)
    (hb : base.length < 2 ^ 32) (ht : target.length < 2 ^ 32) :
    apply base (encode (encodeInsertOnly base target)) = .ok target :=
  apply_encodeWith _ base target hb ht

/-- The model of the Rust writer round-trips (independently of the oracle's
correctness: its proposals are re-verified). -/
theorem apply_encodeRust (base target : Bytes)
    (hb : base.length < 2 ^ 32) (ht : target.length < 2 ^ 32) :
    apply base (encode (encodeRust base target)) = .ok target :=
  apply_encodeWith _ base target hb ht

end MkitFormal.Delta
