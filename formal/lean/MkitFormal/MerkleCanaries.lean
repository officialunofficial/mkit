import MkitFormal.MerkleProofs

/-!
# Non-vacuity witnesses for the SPEC-MERKLE-OBJECTS theorems (MKIT-24)

* `termHasher` is a free term algebra: it satisfies every injectivity
  hypothesis, so `sound` / `sound_id` / `cross_kind_rejected` are not
  vacuously true.
* `*_needed` theorems exhibit hashers violating one hypothesis for which
  the corresponding conclusion fails: each hypothesis is load-bearing.
* `mutant*` theorems show that plausible bugs in the verifier (§5.4) and
  in the sibling selection (§5.3) break completeness, i.e. the checked
  properties can fail.
-/

namespace MkitFormal.Merkle.Canaries

open MkitFormal.Merkle

/-- Free hash terms: every hasher field is a distinct constructor. -/
inductive Tm where
  | base (n : Nat)
  | e
  | lf (i : Nat) (x : Tm)
  | nd (a b : Tm)
  | fn (n : Nat) (x : Tm)
  | wr (k : Kind) (x : Tm)
  deriving DecidableEq, Repr, Inhabited

def termHasher : Hasher Tm :=
  ⟨.e, .lf, .nd, .fn, .wr⟩

theorem termHasher_inj :
    NodeInj termHasher ∧ LeafInj termHasher ∧ FinInj termHasher ∧ WrapInj termHasher := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> intros _ _ _ _ <;> (try intro _) <;>
    simp_all [termHasher]

/-- `n` distinct leaf digests. -/
def ls : Nat → List Tm
  | 0 => []
  | n + 1 => ls n ++ [.base n]

/-- `sound` fires on a hasher meeting all its hypotheses. -/
theorem sound_nonvacuous (pf : Proof Tm) (x : Tm) (i : Nat) (L : List Tm)
    (hv : verifyRoot termHasher pf x i (innerRoot termHasher L) = true) :
    i < L.length ∧ x = L.getD i default :=
  let ⟨hN, hL, hF, _⟩ := termHasher_inj
  let ⟨_, h2, h3, _⟩ := sound termHasher hN hL hF pf x i L hv
  ⟨h2, h3⟩

/-- … and `complete` produces such proofs, so the hypothesis of
`sound_nonvacuous` is reachable (n = 5, i = 4: odd trailing node at level 0
and level 1). -/
theorem complete_witness :
    verifyRoot termHasher (prove termHasher (ls 5) 4) (.base 4) 4 (innerRoot termHasher (ls 5))
      = true :=
  complete termHasher (ls 5) 4 (by decide)

/-! ## Each injectivity hypothesis is load-bearing -/

def constLeaf : Hasher Tm := { termHasher with leaf := fun _ _ => .base 0 }
def constNode : Hasher Tm := { termHasher with node := fun _ _ => .base 0 }
def unboundFin : Hasher Tm := { termHasher with fin := fun _ x => .fn 0 x }
def unboundWrap : Hasher Tm := { termHasher with wrap := fun _ x => .wr .tree x }

/-- Evaluation lemma set for concrete cases (conditional unfolding only). -/
macro "eval_merkle" : tactic => `(tactic|
  simp [verifyRoot, verifyId, verifyChunk, reconstruct, prove, objectId, innerRoot, level0,
    lookup, sibIndex, ls, termHasher, constLeaf, constNode, unboundFin, unboundWrap, pairUp,
    foldUp_base, foldUp_dup, foldUp_nil, foldUp_cons, top_eq_of_le, top_eq_pairUp,
    selPath_base, selPath_step, levels_base, levels_step, List.mapIdx_cons, List.mapIdx_nil])

/-- Without `LeafInj` a wrong leaf verifies (n = 1). -/
theorem leafInj_needed :
    verifyRoot constLeaf ⟨1, []⟩ (.base 7) 0 (innerRoot constLeaf (ls 1)) = true ∧
      Tm.base 7 ≠ (ls 1).getD 0 default := by
  eval_merkle

/-- Without `NodeInj` a wrong leaf with a junk sibling verifies (n = 2). -/
theorem nodeInj_needed :
    verifyRoot constNode ⟨2, [.base 99]⟩ (.base 7) 0 (innerRoot constNode (ls 2)) = true ∧
      Tm.base 7 ≠ (ls 2).getD 0 default := by
  eval_merkle

/-- Without the §1.1 step-3 `leaf_count` binding (`FinInj`), a proof claiming
4 leaves verifies against a 3-leaf root (the odd-node duplication
malleability the finalize step exists to defeat). -/
theorem finInj_needed :
    verifyRoot unboundFin
      ⟨4, [.lf 1 (.base 1), .nd (.lf 2 (.base 2)) (.lf 2 (.base 2))]⟩ (.base 0) 0
      (innerRoot unboundFin (ls 3)) = true ∧ 4 ≠ (ls 3).length := by
  eval_merkle

/-- Without the §2 type-domain wrap (`WrapInj`), a Tree's proof verifies as a
ChunkedBlob chunk proof. -/
theorem wrapInj_needed :
    verifyChunk unboundWrap (prove unboundWrap (ls 3) 1) (.base 1) 1
      (objectId unboundWrap .tree (ls 3)) = true := by
  eval_merkle

/-! ## Mutants: the checked properties can fail -/

/-- Verifier mutant, fuel-bounded (fuel ≥ number of levels). `noSwap`: always
`H(c ‖ sib)` (drops §5.4's odd-position order). `v1Dup`: consume a wire
sibling at the odd trailing node (the §5.8 provisional behaviour) instead of
`H(c ‖ c)`. -/
def foldUpMut (noSwap v1Dup : Bool) (h : Hasher Tm) :
    Nat → Nat → Nat → Tm → List Tm → Option Tm
  | 0, _, _, _, _ => none
  | fuel + 1, s, p, c, sibs =>
    if s ≤ 1 then (if sibs.isEmpty then some c else none)
    else if !v1Dup && p % 2 = 0 && s ≤ p + 1 then
      foldUpMut noSwap v1Dup h fuel ((s + 1) / 2) (p / 2) (h.node c c) sibs
    else match sibs with
      | [] => none
      | x :: rest =>
        foldUpMut noSwap v1Dup h fuel ((s + 1) / 2) (p / 2)
          (if p % 2 = 0 || noSwap then h.node c x else h.node x c) rest

/-- Mutant verification of the generated proof for leaf `i` of `ls n`. -/
def verifyMut (noSwap v1Dup : Bool) (n i : Nat) : Bool :=
  (foldUpMut noSwap v1Dup termHasher (n + 1) n i (termHasher.leaf i (.base i))
      (prove termHasher (ls n) i).siblings).map (termHasher.fin n)
    == some (innerRoot termHasher (ls n))

theorem mutant_control : verifyMut false false 3 2 = true := by
  simp [verifyMut, foldUpMut]; eval_merkle

theorem mutant_noSwap_incomplete : verifyMut true false 2 1 = false := by
  simp [verifyMut, foldUpMut]; eval_merkle

theorem mutant_v1Dup_incomplete : verifyMut false true 3 2 = false := by
  simp [verifyMut, foldUpMut]; eval_merkle

/-- Selection mutant (§5.8 provisional): emit the odd trailing node's own
duplicate. The v2 verifier rejects the resulting proof. -/
theorem mutant_v1_selection_rejected :
    verifyRoot termHasher
      ⟨3, [.lf 2 (.base 2), .nd (.lf 0 (.base 0)) (.lf 1 (.base 1))]⟩ (.base 2) 2
      (innerRoot termHasher (ls 3)) = false := by
  eval_merkle

/-! Bounded executable replays through the compiled code path (evaluated at
build time; a failure is a build error). -/

#guard (List.range 41).all fun n => (List.range n).all fun i => verifyMut false false n i
#guard !((List.range 17).all fun n => (List.range n).all fun i => verifyMut true false n i)
#guard !((List.range 17).all fun n => (List.range n).all fun i => verifyMut false true n i)
#guard (List.range 41).all fun n => (List.range n).all fun i =>
  selMulti n [i] 0 == selPath n i 0

/-! ### Multi-leaf / range (§5.3, §5.4): bounded replays and mutants

General multi/range completeness is not proved (only the singleton case,
`complete_multi_singleton`); these replays check it exhaustively for small
trees through the compiled model. -/

/-- Non-empty subsets of `0..n` as ascending lists. -/
def subsets (n : Nat) : List (List Nat) :=
  ((List.range (2 ^ n)).drop 1).map fun m => (List.range n).filter fun i => m.testBit i

/-- Honest multi-proof of `P` over `ls n`, verified against the Tree id with
the elements given in `order` (Rust sorts internally, so any order works). -/
def multiOk (n : Nat) (P order : List Nat) : Bool :=
  verifyMultiId termHasher .tree (proveMulti termHasher (ls n) P)
    (order.map fun i => (Tm.base i, i)) (objectId termHasher .tree (ls n))

-- Every non-empty subset of every tree up to 9 leaves, ascending and reversed.
#guard (List.range 10).all fun n => (subsets n).all fun P => multiOk n P P && multiOk n P P.reverse
-- Every range of every tree up to 24 leaves verifies as a range proof …
#guard (List.range 25).all fun n => (List.range n).all fun a => (List.range (n - a)).all fun k =>
  verifyRangeId termHasher .tree (proveMulti termHasher (ls n) ((List.range (k + 1)).map (a + ·)))
    a ((List.range (k + 1)).map fun j => Tm.base (a + j)) (objectId termHasher .tree (ls n))
-- … and `siblings_required_for_range_proof` equals the §5.3 set rule.
#guard (List.range 49).all fun n => (List.range n).all fun a => (List.range (n - a)).all fun k =>
  selRange n a (a + k) 0 == selMulti n ((List.range (k + 1)).map (a + ·)) 0
-- §5.4 MUSTs on concrete inputs: repeated, zero and out-of-range positions.
#guard !multiOk 4 [1, 2] [1, 2, 2]
#guard !verifyMultiId termHasher .tree ⟨0, []⟩ [] (objectId termHasher .tree [])
#guard !multiOk 4 [1, 2] [1, 4]
-- Mutant (selection): not omitting an already-proven sibling (§5.3 second
-- bullet) yields proofs the verifier rejects (exact consumption).
#guard !((subsets 4).all fun P =>
  verifyMultiId termHasher .tree
    ⟨4, ((selMulti 4 P 0) ++ (P.filterMap fun p =>
        if sibIndex 4 p ∈ P ∧ sibIndex 4 p ≠ p then some (0, sibIndex 4 p) else none)).map
      (lookup (levels termHasher (level0 termHasher (ls 4))))⟩
    (P.map fun i => (Tm.base i, i)) (objectId termHasher .tree (ls 4)))
-- Mutant (verifier): skipping the sort makes descending inputs fail.
#guard !((subsets 4).all fun P =>
  let pf := proveMulti termHasher (ls 4) P
  let cur := P.reverse.map fun i => (i, termHasher.leaf i (Tm.base i))
  match foldMulti termHasher 4 cur pf.siblings with
  | some ([(_, d)], []) => termHasher.fin 4 d == innerRoot termHasher (ls 4)
  | _ => false)

end MkitFormal.Merkle.Canaries
