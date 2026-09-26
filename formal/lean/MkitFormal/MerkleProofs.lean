import MkitFormal.MerkleModel

/-!
# SPEC-MERKLE-OBJECTS theorems (Linear MKIT-24)

For every leaf count `n` and position `i < n` (no bound on `n`):

* `prove_eq_sibsAux`: the table-indexed §5.3 selection (`prove`, as Rust
  indexes `levels[level][index]`) equals the recursive sibling list.
* `complete` / `complete_id` / `complete_chunk`: §5.4 completeness.
* `sound` / `sound_id`, `unique_proof`: §5.4 soundness (binding) and
  non-malleability under the explicit injectivity hypotheses `NodeInj`,
  `LeafInj`, `FinInj`, `WrapInj`; `cross_kind_rejected` (§2 type binding);
  `empty_tree_no_proof` (§4 / §5.4 zero-leaf case).
* `foldUp_length`, `extra_sibling_rejected`: every sibling is consumed
  exactly once (§5.4).
* `selPath_length_le`, `halvings_eq_levelsInTree`, `proof_length_le_maxLevels`,
  `selPath_bounds`: sibling count / position bounds (§5.2, §5.3).
* `selMulti_singleton`: the multi-position selection specialises to `selPath`.
* §5.4 multi / range: `reconstructMulti_nil` (zero positions),
  `reconstructMulti_dup` (repeated position), `reconstructMulti_oob`,
  `verifyChunksMulti_pos0` / `verifyChunksRange_pos0` (§5.5);
  `reconstructMulti_singleton` (a one-element multi-proof verifies exactly
  like `reconstruct`), hence `complete_multi_singleton` /
  `sound_multi_singleton`. General multi/range completeness and soundness
  are not proved (bounded `#guard` replays + difftest only).
-/

namespace MkitFormal.Merkle

variable {D : Type}

/-! ## Hypotheses (never axioms) -/

/-- `H(a ‖ b)` is injective on 64-byte inputs (collision resistance). -/
def NodeInj (h : Hasher D) : Prop := ∀ a b a' b', h.node a b = h.node a' b' → a = a' ∧ b = b'
/-- `H(be32 i ‖ x)` is injective in `x` for each position `i`. -/
def LeafInj (h : Hasher D) : Prop := ∀ i x y, h.leaf i x = h.leaf i y → x = y
/-- `H(be32 n ‖ x)` is jointly injective. Idealised: concretely `be32` makes it
injective only for `n < 2^32`, which the `u32` `leaf_count` guarantees. -/
def FinInj (h : Hasher D) : Prop := ∀ n m x y, h.fin n x = h.fin m y → n = m ∧ x = y
/-- `domain_digest(TYPE_DOMAIN k, r)` is jointly injective in `(k, r)`. -/
def WrapInj (h : Hasher D) : Prop := ∀ k k' r r', h.wrap k r = h.wrap k' r' → k = k' ∧ r = r'

/-! ## Structure lemmas -/

theorem getD_pairUp [Inhabited D] (h : Hasher D) :
    ∀ (l : List D) (q : Nat), q < (l.length + 1) / 2 →
      (pairUp h l).getD q default =
        h.node (l.getD (2 * q) default)
          (if 2 * q + 1 < l.length then l.getD (2 * q + 1) default else l.getD (2 * q) default)
  | [], q, hq => by simp at hq
  | [a], q, hq => by
    have : q = 0 := by simp at hq; omega
    subst this; simp [pairUp]
  | a :: b :: rest, 0, _ => by simp [pairUp]
  | a :: b :: rest, q + 1, hq => by
    have ih := getD_pairUp h rest q (by simp at hq; omega)
    have e1 : 2 * (q + 1) = 2 * q + 1 + 1 := by omega
    have e2 : 2 * (q + 1) + 1 = 2 * q + 1 + 1 + 1 := by omega
    simp only [pairUp, List.getD_cons_succ, e1, List.length_cons] at ih ⊢
    rw [ih]
    have : (2 * q + 1 + 1 + 1 < rest.length + 1 + 1) ↔ (2 * q + 1 < rest.length) := by omega
    simp [this]

variable [Inhabited D]

theorem top_eq_of_le (h : Hasher D) (lv : List D) (hl : lv.length ≤ 1) :
    top h lv = lv.getD 0 default := by
  rw [top]; simp [hl]

theorem top_eq_pairUp (h : Hasher D) (lv : List D) (hl : ¬ lv.length ≤ 1) :
    top h lv = top h (pairUp h lv) := by
  rw [top]; simp [hl]

theorem sibIndex_eq_self {s p : Nat} : sibIndex s p = p ↔ (p % 2 = 0 ∧ s ≤ p + 1) := by
  unfold sibIndex; split <;> (try split) <;> omega


theorem selPath_shift (s : Nat) : ∀ p lvl,
    selPath s p (lvl + 1) = (selPath s p lvl).map (fun e => (e.1 + 1, e.2)) := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl
    rw [selPath.eq_def s p (lvl + 1), selPath.eq_def s p lvl]
    split
    · simp
    · rw [ih ((s + 1) / 2) (by omega) (p / 2) (lvl + 1)]
      split <;> simp

theorem lookup_levels_zero (h : Hasher D) (lv : List D) (k : Nat) :
    lookup (levels h lv) (0, k) = lv.getD k default := by
  rw [levels]; split <;> simp [lookup]

theorem lookup_levels_succ (h : Hasher D) (lv : List D) (hl : ¬ lv.length ≤ 1) (l k : Nat) :
    lookup (levels h lv) (l + 1, k) = lookup (levels h (pairUp h lv)) (l, k) := by
  conv => lhs; rw [levels]
  simp [hl, lookup]

/-- The table-indexed selection (`prove`) equals the recursive sibling list. -/
theorem selPath_lookup (h : Hasher D) (n : Nat) : ∀ (lv : List D) (p : Nat), lv.length = n →
    (selPath n p 0).map (lookup (levels h lv)) = sibsAux h lv p := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro lv p hn
    rw [selPath, sibsAux]
    subst hn
    split
    · simp
    · rename_i hl
      rw [selPath_shift, List.map_append, List.map_map]
      have hfun : (lookup (levels h lv) ∘ fun e : Nat × Nat => (e.1 + 1, e.2)) =
          lookup (levels h (pairUp h lv)) := by
        funext e; simp [Function.comp, lookup_levels_succ h lv hl]
      rw [hfun, ih ((lv.length + 1) / 2) (by omega) (pairUp h lv) (p / 2) (length_pairUp h lv)]
      split <;> simp [lookup_levels_zero]

omit [Inhabited D] in
theorem level0_length (h : Hasher D) (leaves : List D) (hne : leaves ≠ []) :
    (level0 h leaves).length = leaves.length := by
  unfold level0; split
  · contradiction
  · simp

theorem level0_getD (h : Hasher D) (leaves : List D) (i : Nat) (hi : i < leaves.length) :
    (level0 h leaves).getD i default = h.leaf i (leaves.getD i default) := by
  unfold level0; split
  · simp at hi
  · simp [List.getD_eq_getElem?_getD, hi]

theorem prove_eq_sibsAux (h : Hasher D) (leaves : List D) (i : Nat) (hne : leaves ≠ []) :
    (prove h leaves i).siblings = sibsAux h (level0 h leaves) i := by
  simp only [prove]
  rw [← level0_length h leaves hne]
  exact selPath_lookup h _ _ i rfl

/-! ## Completeness (§5.4) -/

theorem foldUp_complete (h : Hasher D) (n : Nat) : ∀ (lv : List D) (p : Nat),
    lv.length = n → p < n →
      foldUp h n p (lv.getD p default) (sibsAux h lv p) = some (top h lv) := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro lv p hn hp
    subst hn
    rw [foldUp.eq_def, sibsAux]
    by_cases hl : lv.length ≤ 1
    · have : p = 0 := by omega
      subst this
      simp [hl, top_eq_of_le h lv hl]
    · simp only [hl, if_false]
      rw [top_eq_pairUp h lv hl]
      have hlen := length_pairUp h lv
      have ih' := ih ((lv.length + 1) / 2) (by omega) (pairUp h lv) (p / 2) hlen (by omega)
      have hq := getD_pairUp h lv (p / 2) (by omega)
      by_cases hdup : p % 2 = 0 ∧ lv.length ≤ p + 1
      · have hs : sibIndex lv.length p = p := sibIndex_eq_self.mpr hdup
        simp only [hdup, and_self, if_true, hs, List.nil_append]
        rw [← ih']
        congr 1
        rw [hq]
        have e : 2 * (p / 2) = p := by omega
        have h1 : ¬ (p + 1 < lv.length) := by omega
        simp [e, h1]
      · have hs : sibIndex lv.length p ≠ p := fun e => hdup (sibIndex_eq_self.mp e)
        simp only [hdup, if_false, hs, List.singleton_append]
        rw [← ih']
        congr 1
        rw [hq]
        unfold sibIndex
        by_cases hev : p % 2 = 0
        · have h1 : p + 1 < lv.length := by omega
          have e : 2 * (p / 2) = p := by omega
          simp [hev, h1, e]
        · have e : 2 * (p / 2) = p - 1 := by omega
          have e2 : p - 1 + 1 = p := by omega
          simp [hev, e, e2, hp]

/-! ## Conditional unfolding lemmas (also used to evaluate concrete cases) -/

section Unfold
omit [Inhabited D]
variable (h : Hasher D) {s p lvl : Nat} {c x : D} {sibs rest : List D}

theorem foldUp_base (hs : s ≤ 1) :
    foldUp h s p c sibs = if sibs.isEmpty then some c else none := by
  rw [foldUp.eq_def]; simp [hs]

theorem foldUp_dup (hs : ¬ s ≤ 1) (hd : p % 2 = 0 ∧ s ≤ p + 1) :
    foldUp h s p c sibs = foldUp h ((s + 1) / 2) (p / 2) (h.node c c) sibs := by
  rw [foldUp.eq_def]; simp [hs, hd]

theorem foldUp_nil (hs : ¬ s ≤ 1) (hd : ¬ (p % 2 = 0 ∧ s ≤ p + 1)) :
    foldUp h s p c [] = none := by
  rw [foldUp.eq_def]; simp only [hs, hd, if_false]

theorem foldUp_cons (hs : ¬ s ≤ 1) (hd : ¬ (p % 2 = 0 ∧ s ≤ p + 1)) :
    foldUp h s p c (x :: rest) =
      foldUp h ((s + 1) / 2) (p / 2) (if p % 2 = 0 then h.node c x else h.node x c) rest := by
  rw [foldUp.eq_def]; simp only [hs, hd, if_false]

theorem selPath_base (hs : s ≤ 1) : selPath s p lvl = [] := by
  rw [selPath]; simp [hs]

theorem selPath_step (hs : ¬ s ≤ 1) :
    selPath s p lvl = (if sibIndex s p = p then [] else [(lvl, sibIndex s p)]) ++
      selPath ((s + 1) / 2) (p / 2) (lvl + 1) := by
  rw [selPath]; simp [hs]

theorem levels_base {lv : List D} (hl : lv.length ≤ 1) : levels h lv = [lv] := by
  rw [levels]; simp [hl]

theorem levels_step {lv : List D} (hl : ¬ lv.length ≤ 1) :
    levels h lv = lv :: levels h (pairUp h lv) := by
  rw [levels]; simp [hl]

end Unfold

/-! ## Soundness / binding (§5.4, §6) -/

/-- The parent of position `p` pairs `lv[p]` with its §5.3 sibling. -/
theorem getD_pairUp_sib (h : Hasher D) (lv : List D) (p : Nat) (hp : p < lv.length) :
    (pairUp h lv).getD (p / 2) default =
      if p % 2 = 0 then h.node (lv.getD p default) (lv.getD (sibIndex lv.length p) default)
      else h.node (lv.getD (sibIndex lv.length p) default) (lv.getD p default) := by
  rw [getD_pairUp h lv (p / 2) (by omega)]
  unfold sibIndex
  by_cases hev : p % 2 = 0
  · have e : 2 * (p / 2) = p := by omega
    by_cases h1 : p + 1 < lv.length <;> simp [hev, h1, e]
  · have e : 2 * (p / 2) = p - 1 := by omega
    have e2 : p - 1 + 1 = p := by omega
    simp [hev, e, e2, hp]

theorem foldUp_sound (h : Hasher D) (hN : NodeInj h) (n : Nat) :
    ∀ (lv : List D) (p : Nat) (c : D) (sibs : List D), lv.length = n → p < n →
      foldUp h n p c sibs = some (top h lv) →
        c = lv.getD p default ∧ sibs = sibsAux h lv p := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro lv p c sibs hn hp hf
    subst hn
    rw [foldUp.eq_def] at hf
    rw [sibsAux]
    by_cases hl : lv.length ≤ 1
    · have : p = 0 := by omega
      subst this
      cases sibs with
      | nil => simp_all [top_eq_of_le h lv hl]
      | cons _ _ => simp [hl] at hf
    · simp only [hl, if_false] at hf ⊢
      rw [top_eq_pairUp h lv hl] at hf
      have hlen := length_pairUp h lv
      have hq := getD_pairUp_sib h lv p hp
      by_cases hdup : p % 2 = 0 ∧ lv.length ≤ p + 1
      · have hs : sibIndex lv.length p = p := sibIndex_eq_self.mpr hdup
        simp only [hdup, and_self, if_true] at hf
        obtain ⟨h1, h2⟩ := ih _ (by omega) (pairUp h lv) (p / 2) _ sibs hlen (by omega) hf
        rw [hq, hs] at h1
        simp only [hdup.1, if_true] at h1
        exact ⟨(hN _ _ _ _ h1).1, by simp [hs, h2]⟩
      · have hs : sibIndex lv.length p ≠ p := fun e => hdup (sibIndex_eq_self.mp e)
        simp only [hdup, if_false] at hf
        cases sibs with
        | nil => simp at hf
        | cons x rest =>
          simp only at hf
          obtain ⟨h1, h2⟩ := ih _ (by omega) (pairUp h lv) (p / 2) _ rest hlen (by omega) hf
          rw [hq] at h1
          by_cases hev : p % 2 = 0
          · simp only [hev, if_true] at h1
            obtain ⟨e1, e2⟩ := hN _ _ _ _ h1
            exact ⟨e1, by simp [hs, e2, h2]⟩
          · simp only [hev, if_false] at h1
            obtain ⟨e1, e2⟩ := hN _ _ _ _ h1
            exact ⟨e2, by simp [hs, e1, h2]⟩

/-- Completeness of §5.4 for every `n` and every `i < n`. -/
theorem complete [DecidableEq D] (h : Hasher D) (leaves : List D) (i : Nat)
    (hi : i < leaves.length) :
    verifyRoot h (prove h leaves i) (leaves.getD i default) i (innerRoot h leaves) = true := by
  have hne : leaves ≠ [] := by intro e; simp [e] at hi
  have hlen := level0_length h leaves hne
  have hc := foldUp_complete h leaves.length (level0 h leaves) i hlen hi
  rw [level0_getD h leaves i hi, ← prove_eq_sibsAux h leaves i hne] at hc
  simp [verifyRoot, reconstruct, prove, hi, innerRoot] at hc ⊢
  simp [hc]

/-- §5.4 completeness against the object id (§2). -/
theorem complete_id [DecidableEq D] (h : Hasher D) (k : Kind) (leaves : List D) (i : Nat)
    (hi : i < leaves.length) :
    verifyId h k (prove h leaves i) (leaves.getD i default) i (objectId h k leaves) = true := by
  have hc := complete h leaves i hi
  simp only [verifyRoot, beq_iff_eq] at hc
  simp only [verifyId, hc, objectId, Option.map_some]
  simp

/-- §5.5: every chunk position (`i ≥ 1`) of a ChunkedBlob verifies. -/
theorem complete_chunk [DecidableEq D] (h : Hasher D) (leaves : List D) (i : Nat)
    (hi : i < leaves.length) (h1 : 1 ≤ i) :
    verifyChunk h (prove h leaves i) (leaves.getD i default) i (objectId h .chunked leaves)
      = true := by
  have := complete_id h .chunked leaves i hi
  unfold verifyChunk; rw [this]
  have : i ≠ 0 := by omega
  simp [this]

/-- §5.4 soundness / binding: a proof that verifies for `(i, x)` against
`innerRoot leaves` forces the right leaf count, an in-range position,
`x = leaves[i]`, and the unique sibling list `prove` would generate. -/
theorem sound [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h) (hF : FinInj h)
    (pf : Proof D) (x : D) (i : Nat) (leaves : List D)
    (hv : verifyRoot h pf x i (innerRoot h leaves) = true) :
    pf.leafCount = leaves.length ∧ i < leaves.length ∧ x = leaves.getD i default ∧
      pf.siblings = (prove h leaves i).siblings := by
  simp only [verifyRoot, reconstruct, beq_iff_eq] at hv
  split at hv
  · rename_i hi
    cases hf : foldUp h pf.leafCount i (h.leaf i x) pf.siblings with
    | none => simp [hf] at hv
    | some v =>
      simp only [hf, Option.map_some, Option.some.injEq, innerRoot] at hv
      obtain ⟨hn, hv⟩ := hF _ _ _ _ hv
      have hi' : i < leaves.length := hn ▸ hi
      have hne : leaves ≠ [] := by intro e; simp [e] at hi'
      rw [hv, hn] at hf
      obtain ⟨e1, e2⟩ := foldUp_sound h hN _ (level0 h leaves) i _ _
        (level0_length h leaves hne) hi' hf
      rw [level0_getD h leaves i hi'] at e1
      exact ⟨hn, hi', hL _ _ _ e1, by rw [e2, prove_eq_sibsAux h leaves i hne]⟩
  · simp at hv

/-- Non-malleability: a verifying proof is exactly the generated one. -/
theorem unique_proof [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h)
    (hF : FinInj h) (pf : Proof D) (x : D) (i : Nat) (leaves : List D)
    (hv : verifyRoot h pf x i (innerRoot h leaves) = true) :
    pf.leafCount = (prove h leaves i).leafCount ∧ pf.siblings = (prove h leaves i).siblings := by
  obtain ⟨e1, -, -, e4⟩ := sound h hN hL hF pf x i leaves hv
  exact ⟨e1, e4⟩

/-- §5.4 normative (id-based) soundness, including the claimed kind (§2). -/
theorem sound_id [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h)
    (hF : FinInj h) (hW : WrapInj h) (k k' : Kind) (pf : Proof D) (x : D) (i : Nat)
    (leaves : List D) (hv : verifyId h k pf x i (objectId h k' leaves) = true) :
    k = k' ∧ pf.leafCount = leaves.length ∧ i < leaves.length ∧ x = leaves.getD i default := by
  simp only [verifyId, beq_iff_eq, objectId] at hv
  cases hr : reconstruct h pf x i with
  | none => simp [hr] at hv
  | some r =>
    simp only [hr, Option.map_some, Option.some.injEq] at hv
    obtain ⟨hk, hr'⟩ := hW _ _ _ _ hv
    have hv' : verifyRoot h pf x i (innerRoot h leaves) = true := by
      simp [verifyRoot, hr, hr']
    obtain ⟨e1, e2, e3, -⟩ := sound h hN hL hF pf x i leaves hv'
    exact ⟨hk, e1, e2, e3⟩

/-- §2: a proof never verifies against another kind's id. -/
theorem cross_kind_rejected [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h)
    (hF : FinInj h) (hW : WrapInj h) (k k' : Kind) (hk : k ≠ k') (pf : Proof D) (x : D)
    (i : Nat) (leaves : List D) : verifyId h k pf x i (objectId h k' leaves) = false := by
  cases hv : verifyId h k pf x i (objectId h k' leaves) with
  | false => rfl
  | true => exact absurd (sound_id h hN hL hF hW k k' pf x i leaves hv).1 hk

/-- §4 / §5.4: nothing verifies against the empty object (no leaves). -/
theorem empty_tree_no_proof [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h)
    (hF : FinInj h) (pf : Proof D) (x : D) (i : Nat) :
    verifyRoot h pf x i (innerRoot h []) = false := by
  cases hv : verifyRoot h pf x i (innerRoot h []) with
  | false => rfl
  | true => have := (sound h hN hL hF pf x i [] hv).2.1; simp at this

omit [Inhabited D] in
/-- §5.5: a chunk proof at position 0 (the metadata leaf) is rejected. -/
theorem chunk_pos0_rejected [DecidableEq D] (h : Hasher D) (pf : Proof D) (x id : D) :
    verifyChunk h pf x 0 id = false := by
  simp [verifyChunk]

/-! ## Exact sibling consumption (§5.4) -/

omit [Inhabited D] in
theorem foldUp_length (h : Hasher D) (s : Nat) :
    ∀ (p lvl : Nat) (c : D) (sibs : List D) (r : D),
      foldUp h s p c sibs = some r → sibs.length = (selPath s p lvl).length := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl c sibs r hf
    rw [foldUp.eq_def] at hf
    rw [selPath]
    by_cases hl : s ≤ 1
    · cases sibs <;> simp_all
    · simp only [hl, if_false, List.length_append] at hf ⊢
      by_cases hdup : p % 2 = 0 ∧ s ≤ p + 1
      · have hs : sibIndex s p = p := sibIndex_eq_self.mpr hdup
        simp only [hdup, and_self, if_true] at hf
        simp [hs, ih _ (by omega) _ (lvl + 1) _ _ _ hf]
      · have hs : sibIndex s p ≠ p := fun e => hdup (sibIndex_eq_self.mp e)
        simp only [hdup, if_false] at hf
        cases sibs with
        | nil => simp at hf
        | cons x rest =>
          simp only at hf
          simp [hs, ih _ (by omega) _ (lvl + 1) _ _ _ hf]; omega

omit [Inhabited D] in
/-- Too many or too few siblings are rejected: any accepted proof carries
exactly the §5.3 count. -/
theorem accepted_length (h : Hasher D) (pf : Proof D) (x : D) (i : Nat) (r : D)
    (hr : reconstruct h pf x i = some r) :
    pf.siblings.length = (selPath pf.leafCount i 0).length := by
  unfold reconstruct at hr
  split at hr
  · cases hf : foldUp h pf.leafCount i (h.leaf i x) pf.siblings with
    | none => simp [hf] at hr
    | some v => exact foldUp_length h _ _ _ _ _ _ hf
  · simp at hr

theorem extra_sibling_rejected [DecidableEq D] (h : Hasher D) (leaves : List D) (i : Nat)
    (x y root : D) :
    verifyRoot h ⟨leaves.length, (prove h leaves i).siblings ++ [y]⟩ x i root = false := by
  cases hv : verifyRoot h ⟨leaves.length, (prove h leaves i).siblings ++ [y]⟩ x i root with
  | false => rfl
  | true =>
    simp only [verifyRoot, beq_iff_eq] at hv
    have := accepted_length h _ x i root hv
    simp [prove] at this

theorem dropped_sibling_rejected [DecidableEq D] (h : Hasher D) (leaves : List D) (i : Nat)
    (x root : D) (hne : (prove h leaves i).siblings ≠ []) :
    verifyRoot h ⟨leaves.length, (prove h leaves i).siblings.dropLast⟩ x i root = false := by
  cases hv : verifyRoot h ⟨leaves.length, (prove h leaves i).siblings.dropLast⟩ x i root with
  | false => rfl
  | true =>
    simp only [verifyRoot, beq_iff_eq] at hv
    have := accepted_length h _ x i root hv
    have hpos : 0 < (prove h leaves i).siblings.length := List.length_pos_iff.mpr hne
    simp [prove] at this hpos
    omega

/-! ## Sibling count and position bounds (§5.2, §5.3) -/

omit [Inhabited D] in
theorem selPath_length_le (s : Nat) : ∀ p lvl, (selPath s p lvl).length ≤ halvings s := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl
    rw [selPath, halvings]
    split
    · simp
    · have := ih ((s + 1) / 2) (by omega) (p / 2) (lvl + 1)
      split <;> simp <;> omega

/-- `halvings n` (the verifier's `while level_size > 1` loop count) equals
`levels_in_tree(n) - 1` (the builder's loop count) for every `n`. -/
theorem halvings_eq_levelsInTree (n : Nat) : halvings n = levelsInTree n - 1 := by
  unfold levelsInTree
  induction n using Nat.strongRecOn with
  | _ n ih =>
    rw [halvings]
    split
    · have : n - 1 = 0 := by omega
      rw [this, bitLen]; simp
    · rw [ih ((n + 1) / 2) (by omega), bitLen.eq_def (n - 1)]
      have e : (n + 1) / 2 - 1 = (n - 1) / 2 := by omega
      simp [e]; omega

theorem bitLen_le (k : Nat) : ∀ x, x < 2 ^ k → bitLen x ≤ k := by
  induction k with
  | zero => intro x hx; have : x = 0 := by simp at hx; omega
            subst this; simp [bitLen]
  | succ k ih =>
    intro x hx
    rw [bitLen]
    split
    · omega
    · have := ih (x / 2) (by rw [Nat.pow_succ] at hx; omega)
      omega

/-- §5.2 `MAX_LEVELS`: for any `u32` leaf count, a single-leaf proof has at
most `levels_in_tree(n) - 1 ≤ 32` siblings. -/
theorem proof_length_le_maxLevels (h : Hasher D) (leaves : List D) (i : Nat)
    (hn : leaves.length ≤ 2 ^ 32) :
    (prove h leaves i).siblings.length ≤ levelsInTree leaves.length - 1 ∧
      levelsInTree leaves.length - 1 ≤ maxLevels := by
  have h1 := selPath_length_le leaves.length i 0
  rw [halvings_eq_levelsInTree] at h1
  refine ⟨by simpa [prove] using h1, ?_⟩
  have := bitLen_le 32 (leaves.length - 1) (by omega)
  simp [levelsInTree, maxLevels]; omega

/-- Level size and proven position after `l` fold steps. -/
def sizeAt : Nat → Nat → Nat
  | s, 0 => s
  | s, l + 1 => sizeAt ((s + 1) / 2) l

def posAt : Nat → Nat → Nat
  | p, 0 => p
  | p, l + 1 => posAt (p / 2) l

omit [Inhabited D] in
/-- §5.3 position bounds: each wire sibling `(level, index)` lies on a real
fold level, is a real node of that level, is not the proven node itself,
and shares its parent. -/
theorem selPath_bounds (s : Nat) : ∀ p lvl, p < s → ∀ e ∈ selPath s p lvl,
    ∃ l, e.1 = lvl + l ∧ l < halvings s ∧ e.2 < sizeAt s l ∧ e.2 ≠ posAt p l ∧
      e.2 / 2 = posAt p l / 2 := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl hp e he
    rw [selPath] at he
    split at he
    · simp at he
    · rename_i hl
      rcases List.mem_append.mp he with he | he
      · split at he
        · simp at he
        · rename_i hs
          simp at he; subst he
          refine ⟨0, by simp, by rw [halvings]; simp [hl], ?_, by simpa [posAt] using hs, ?_⟩
          · simp [sizeAt]; unfold sibIndex; split <;> (try split) <;> omega
          · simp [posAt]; unfold sibIndex; split <;> (try split) <;> omega
      · obtain ⟨l, h1, h2, h3, h4, h5⟩ := ih ((s + 1) / 2) (by omega) (p / 2) (lvl + 1)
          (by omega) e he
        refine ⟨l + 1, by omega, ?_, by simpa [sizeAt] using h3, by simpa [posAt] using h4,
          by simpa [posAt] using h5⟩
        rw [halvings]; simp [hl]; omega

omit [Inhabited D] in
theorem selPath_level_ge (s : Nat) : ∀ p lvl, ∀ e ∈ selPath s p lvl, lvl ≤ e.1 := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl e he
    rw [selPath] at he
    split at he
    · simp at he
    · rcases List.mem_append.mp he with he | he
      · split at he <;> simp at he; subst he; simp
      · have := ih ((s + 1) / 2) (by omega) (p / 2) (lvl + 1) e he; omega

omit [Inhabited D] in
/-- §5.3 ordering: level-major bottom-up, at most one sibling per level. -/
theorem selPath_levels_increasing (s : Nat) :
    ∀ p lvl, (selPath s p lvl).Pairwise (fun a b => a.1 < b.1) := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl
    rw [selPath]
    split
    · simp
    · rw [List.pairwise_append]
      refine ⟨by split <;> simp, ih _ (by omega) _ _, ?_⟩
      intro a ha b hb
      have := selPath_level_ge _ _ _ b hb
      split at ha <;> simp at ha; subst ha; simp; omega

omit [Inhabited D] in
/-- The general multi-position §5.3 selection agrees with `selPath` on a
single position (`BmtTree::proof` is a one-element `multi_proof`). -/
theorem selMulti_singleton (s : Nat) : ∀ p lvl, selMulti s [p] lvl = selPath s p lvl := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p lvl
    rw [selMulti, selPath]
    split
    · rfl
    · rename_i hl
      have hd : dedupSorted [p / 2] = [p / 2] := by simp [dedupSorted]
      simp only [List.map_cons, List.map_nil, hd, ih ((s + 1) / 2) (by omega)]
      split <;> simp_all

/-! ## §5.4 multi-leaf / range verification -/

omit [Inhabited D] in
/-- §5.4: a proof over zero positions is rejected, whatever the proof
(including `leaf_count = 0, siblings = []` against the empty Tree). -/
theorem reconstructMulti_nil (h : Hasher D) (pf : Proof D) : reconstructMulti h pf [] = none := by
  simp [reconstructMulti]

omit [Inhabited D] in
/-- §5.4: a repeated position is rejected. -/
theorem reconstructMulti_dup (h : Hasher D) (pf : Proof D) (elems : List (D × Nat))
    (hd : ¬ (elems.map (·.2)).Nodup) : reconstructMulti h pf elems = none := by
  unfold reconstructMulti
  split
  · rfl
  · split
    · rfl
    · simp [hd]

omit [Inhabited D] in
/-- §5.4: an out-of-range position is rejected. -/
theorem reconstructMulti_oob (h : Hasher D) (pf : Proof D) (elems : List (D × Nat))
    (e : D × Nat) (he : e ∈ elems) (hoob : pf.leafCount ≤ e.2) :
    reconstructMulti h pf elems = none := by
  unfold reconstructMulti
  have hne : elems.isEmpty = false := by
    cases elems with
    | nil => simp at he
    | cons _ _ => rfl
  have hany : elems.any (fun e => decide (pf.leafCount ≤ e.2)) = true :=
    List.any_eq_true.mpr ⟨e, he, by simpa using hoob⟩
  simp [hne, hany]

omit [Inhabited D] in
/-- §5.5: a chunk multi-proof covering position 0 is rejected. -/
theorem verifyChunksMulti_pos0 [DecidableEq D] (h : Hasher D) (pf : Proof D)
    (elems : List (D × Nat)) (x : D) (hx : (x, 0) ∈ elems) (id : D) :
    verifyChunksMulti h pf elems id = false := by
  have : elems.any (·.2 == 0) = true := List.any_eq_true.mpr ⟨(x, 0), hx, by simp⟩
  simp [verifyChunksMulti, this]

omit [Inhabited D] in
/-- §5.5: a chunk range proof starting at position 0 is rejected. -/
theorem verifyChunksRange_pos0 [DecidableEq D] (h : Hasher D) (pf : Proof D)
    (leaves : List D) (id : D) : verifyChunksRange h pf 0 leaves id = false := by
  simp [verifyChunksRange]

omit [Inhabited D] in
/-- The multi fold on one proven node is the single-leaf fold (`foldUp`),
including exact sibling consumption. -/
theorem foldMulti_single (h : Hasher D) (s : Nat) : ∀ (p : Nat) (d : D) (sibs : List D),
    ((foldMulti h s [(p, d)] sibs).bind fun r =>
      match r with
      | ([(_, d')], []) => some d'
      | _ => none) = foldUp h s p d sibs := by
  induction s using Nat.strongRecOn with
  | _ s ih =>
    intro p d sibs
    rw [foldMulti]
    split
    · rename_i hs
      rw [foldUp_base h hs]; cases sibs <;> simp
    · rename_i hs
      simp only [multiStep, alone]
      by_cases hd : p % 2 = 0 ∧ s ≤ p + 1
      · rw [foldUp_dup h hs hd]
        simp only [hd, and_self, if_true]
        exact ih _ (by omega) _ _ _
      · cases sibs with
        | nil => rw [foldUp_nil h hs hd]; simp [hd]
        | cons x rest =>
          rw [foldUp_cons h hs hd]
          simp only [hd, if_false]
          exact ih _ (by omega) _ _ _

omit [Inhabited D] in
/-- A one-element multi-proof verifies exactly like a single-leaf proof
(`BmtTree::proof` is a one-element `multi_proof`), so `complete` / `sound`
carry over to it. -/
theorem reconstructMulti_singleton (h : Hasher D) (pf : Proof D) (x : D) (i : Nat) :
    reconstructMulti h pf [(x, i)] = reconstruct h pf x i := by
  unfold reconstructMulti reconstruct
  by_cases hi : i < pf.leafCount
  · have hn : ¬ pf.leafCount ≤ i := by omega
    simp only [List.isEmpty_cons, List.any_cons, List.any_nil, hn, decide_false,
      Bool.or_false, List.map_cons, List.map_nil, List.nodup_cons, List.not_mem_nil,
      not_false_eq_true, List.nodup_nil, and_self, decide_true, Bool.not_true,
      Bool.false_eq_true, if_false, hi, if_true]
    have hs : List.mergeSort [(i, h.leaf i x)] (fun a b => decide (a.1 ≤ b.1)) =
        [(i, h.leaf i x)] := by simp
    rw [hs]
    have := foldMulti_single h pf.leafCount i (h.leaf i x) pf.siblings
    cases hf : foldMulti h pf.leafCount [(i, h.leaf i x)] pf.siblings with
    | none => rw [hf] at this; simp at this; rw [← this]; rfl
    | some r =>
      rw [hf] at this
      obtain ⟨l, sb⟩ := r
      match l, sb with
      | [(_, d')], [] => simp at this; rw [← this]; rfl
      | [], _ => simp at this; rw [← this]; rfl
      | [_], _ :: _ => simp at this; rw [← this]; rfl
      | _ :: _ :: _, _ => simp at this; rw [← this]; rfl
  · have hn : pf.leafCount ≤ i := by omega
    simp [hn, hi]

/-- Singleton multi-proof completeness, via `complete`. -/
theorem complete_multi_singleton [DecidableEq D] (h : Hasher D) (k : Kind) (leaves : List D)
    (i : Nat) (hi : i < leaves.length) :
    verifyMultiId h k (prove h leaves i) [(leaves.getD i default, i)] (objectId h k leaves)
      = true := by
  have := complete_id h k leaves i hi
  simpa [verifyMultiId, verifyId, reconstructMulti_singleton] using this

/-- Singleton multi-proof soundness, via `sound_id`. -/
theorem sound_multi_singleton [DecidableEq D] (h : Hasher D) (hN : NodeInj h) (hL : LeafInj h)
    (hF : FinInj h) (hW : WrapInj h) (k k' : Kind) (pf : Proof D) (x : D) (i : Nat)
    (leaves : List D) (hv : verifyMultiId h k pf [(x, i)] (objectId h k' leaves) = true) :
    k = k' ∧ pf.leafCount = leaves.length ∧ i < leaves.length ∧ x = leaves.getD i default := by
  apply sound_id h hN hL hF hW k k' pf x i leaves
  simpa [verifyMultiId, verifyId, reconstructMulti_singleton] using hv

end MkitFormal.Merkle
