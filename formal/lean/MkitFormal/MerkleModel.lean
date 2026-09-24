/-!
# SPEC-MERKLE-OBJECTS model (Linear MKIT-24)

An executable model of `docs/specs/SPEC-MERKLE-OBJECTS.md` (version 2):

* §1.1 BMT construction (position-hash, fold with odd-node duplication,
  finalize with `leaf_count`), §2 identity wrap, §4 empty objects;
* §5.1 proof struct, §5.3 sibling selection (single-position `selPath`,
  the general multi-position `selMulti`, the range form `selRange`), §5.4
  single-leaf, multi-leaf and range verification, §5.5 chunk position
  semantics.

The model is parameterised over an abstract `Hasher`. Cryptographic
assumptions (injectivity of the node / leaf / finalize / wrap hashes) are
explicit hypotheses of the theorems in `MkitFormal.MerkleProofs`, never
axioms; `MkitFormal.MerkleCanaries` holds the non-vacuity witnesses. The
executable functions mirror
`rust/crates/mkit-core/src/merkle.rs` (`build_bmt`,
`siblings_required_for_multi_proof`, `siblings_required_for_range_proof`,
`BmtTree::multi_proof`, `Proof::reconstruct_element_root`,
`reconstruct_multi_root`, `reconstruct_range_root`, `verify_chunk`,
`verify_chunks_multi`, `verify_chunks_range`), and
`MkitFormal.MerkleDifftest` replays Rust-exported vectors against them.
-/

namespace MkitFormal.Merkle

/-- The two merkelized object kinds, keying the §2 type-domain wrap. -/
inductive Kind where
  | tree
  | chunked
  deriving DecidableEq, Repr, Inhabited

/-- Abstract hash oracle. Concretely (§1.1, §2) every field is BLAKE3:
`empty = H("")`, `leaf i x = H(be32 i ‖ x)`, `node a b = H(a ‖ b)`,
`fin n x = H(be32 n ‖ x)`, `wrap k r = domain_digest(TYPE_DOMAIN k, r)`. -/
structure Hasher (D : Type) where
  empty : D
  leaf : Nat → D → D
  node : D → D → D
  fin : Nat → D → D
  wrap : Kind → D → D

/-- §5.1 `Proof { leaf_count, siblings }` (wire encoding §5.2 not modelled). -/
structure Proof (D : Type) where
  leafCount : Nat
  siblings : List D
  deriving Repr

variable {D : Type}

/-! ## §1.1 construction -/

/-- One fold step (§1.1 step 2): pair adjacent nodes, duplicating an odd
trailing node (`H(left ‖ left)`). -/
def pairUp (h : Hasher D) : List D → List D
  | [] => []
  | [a] => [h.node a a]
  | a :: b :: rest => h.node a b :: pairUp h rest

theorem length_pairUp (h : Hasher D) :
    ∀ l : List D, (pairUp h l).length = (l.length + 1) / 2
  | [] => by simp [pairUp]
  | [_] => by simp [pairUp]
  | _ :: _ :: rest => by
    simp only [pairUp, List.length_cons, length_pairUp h rest]; omega

variable [Inhabited D]

/-- The single pre-finalize node: fold until one node remains. -/
def top (h : Hasher D) (lv : List D) : D :=
  if lv.length ≤ 1 then lv.getD 0 default else top h (pairUp h lv)
termination_by lv.length
decreasing_by rw [length_pairUp]; omega

/-- Level 0 (§1.1 step 1): position-hashed leaves, or `[H("")]` when `N = 0`. -/
def level0 (h : Hasher D) (leaves : List D) : List D :=
  match leaves with
  | [] => [h.empty]
  | _ => leaves.mapIdx (fun i x => h.leaf i x)

/-- Finalized (bare, pre-wrap) root (§1.1 step 3): `H(be32(N) ‖ folded)`. -/
def innerRoot (h : Hasher D) (leaves : List D) : D :=
  h.fin leaves.length (top h (level0 h leaves))

/-- §2 object id: `domain_digest(TYPE_DOMAIN, tree_root)`. -/
def objectId (h : Hasher D) (k : Kind) (leaves : List D) : D :=
  h.wrap k (innerRoot h leaves)

/-- Every level from level 0 up to the single pre-finalize node, as
`build_bmt` keeps them (`levels[0]` … `levels[last]`). -/
def levels (h : Hasher D) (lv : List D) : List (List D) :=
  if lv.length ≤ 1 then [lv] else lv :: levels h (pairUp h lv)
termination_by lv.length
decreasing_by rw [length_pairUp]; omega

/-- `levels[level][index]` (default when out of range). -/
def lookup (tbl : List (List D)) (e : Nat × Nat) : D :=
  (tbl.getD e.1 []).getD e.2 default

/-! ## §5.3 sibling selection -/

/-- `levels_in_tree` (§5.3): `32 - clz32(n.saturating_sub(1)) + 1`.
`clz32 x = 32 - bitLen x` for `x < 2^32`, so this is `bitLen (n - 1) + 1`
(`Nat` subtraction saturates like `saturating_sub`). -/
def bitLen (x : Nat) : Nat :=
  if x = 0 then 0 else bitLen (x / 2) + 1
termination_by x
decreasing_by omega

def levelsInTree (n : Nat) : Nat := bitLen (n - 1) + 1

/-- `MAX_LEVELS = u32::BITS` (§5.2). -/
def maxLevels : Nat := 32

/-- Number of fold steps from a level of size `s` down to one node. -/
def halvings (s : Nat) : Nat :=
  if s ≤ 1 then 0 else halvings ((s + 1) / 2) + 1
termination_by s
decreasing_by omega

/-- Sibling index of `p` in a level of size `s` (§5.3 first bullet): `p + 1`
for even `p` with a real right neighbour, `p` itself for the odd trailing
node, `p - 1` for odd `p`. -/
def sibIndex (s p : Nat) : Nat :=
  if p % 2 = 0 then (if p + 1 < s then p + 1 else p) else p - 1

/-- §5.3 for a single proven position: the wire siblings' `(level, index)`,
level-major bottom-up, starting at level `lvl` with a level of size `s`.
Self-duplicates are omitted. -/
def selPath (s p lvl : Nat) : List (Nat × Nat) :=
  if s ≤ 1 then []
  else (if sibIndex s p = p then [] else [(lvl, sibIndex s p)]) ++
    selPath ((s + 1) / 2) (p / 2) (lvl + 1)
termination_by s
decreasing_by omega

/-- Deduplicate an ascending list (adjacent duplicates). -/
def dedupSorted : List Nat → List Nat
  | a :: b :: rest => if a = b then dedupSorted (b :: rest) else a :: dedupSorted (b :: rest)
  | l => l

/-- §5.3 for a set `P` of proven positions (ascending, deduplicated), as in
`siblings_required_for_multi_proof`: a sibling is omitted when it is the
node's own duplicate or itself in `P`; `P` then advances to `{p / 2}`. -/
def selMulti (s : Nat) (P : List Nat) (lvl : Nat) : List (Nat × Nat) :=
  if s ≤ 1 then []
  else P.filterMap (fun p =>
      let q := sibIndex s p
      if q = p ∨ q ∈ P then none else some (lvl, q)) ++
    selMulti ((s + 1) / 2) (dedupSorted (P.map (· / 2))) (lvl + 1)
termination_by s
decreasing_by omega

/-- Proof generation (`BmtTree::proof`): look the §5.3-selected positions
up in the level table. Callers must pass `i < leaves.length`. -/
def prove (h : Hasher D) (leaves : List D) (i : Nat) : Proof D :=
  ⟨leaves.length, (selPath leaves.length i 0).map (lookup (levels h (level0 h leaves)))⟩

/-- Multi-position proof generation (`BmtTree::multi_proof`). -/
def proveMulti (h : Hasher D) (leaves : List D) (P : List Nat) : Proof D :=
  ⟨leaves.length, (selMulti leaves.length P 0).map (lookup (levels h (level0 h leaves)))⟩

/-- The same single-leaf sibling list, computed recursively on the level
list (used by the proofs; `prove_eq_sibsAux` shows it equals `prove`). -/
def sibsAux (h : Hasher D) (lv : List D) (p : Nat) : List D :=
  if lv.length ≤ 1 then []
  else (if sibIndex lv.length p = p then [] else [lv.getD (sibIndex lv.length p) default]) ++
    sibsAux h (pairUp h lv) (p / 2)
termination_by lv.length
decreasing_by rw [length_pairUp]; omega

/-! ## §5.4 single-leaf verification -/

/-- Fold `c` (at position `p` of a level of size `s`) up through `sibs`:
even `p` → `H(c ‖ sib)`, odd `p` → `H(sib ‖ c)`, odd trailing node →
`H(c ‖ c)` without consuming a sibling. Every sibling must be consumed
exactly once (`none` on too few or too many). -/
def foldUp (h : Hasher D) (s p : Nat) (c : D) (sibs : List D) : Option D :=
  if s ≤ 1 then (if sibs.isEmpty then some c else none)
  else if p % 2 = 0 ∧ s ≤ p + 1 then foldUp h ((s + 1) / 2) (p / 2) (h.node c c) sibs
  else match sibs with
    | [] => none
    | x :: rest =>
      foldUp h ((s + 1) / 2) (p / 2) (if p % 2 = 0 then h.node c x else h.node x c) rest
termination_by s
decreasing_by all_goals omega

/-- `reconstruct_element_root`: position check, position-hash, fold, finalize. -/
def reconstruct (h : Hasher D) (pf : Proof D) (leaf : D) (pos : Nat) : Option D :=
  if pos < pf.leafCount then
    (foldUp h pf.leafCount pos (h.leaf pos leaf) pf.siblings).map (h.fin pf.leafCount)
  else none

/-- Verification against a bare root (the commonware-parity check). -/
def verifyRoot [DecidableEq D] (h : Hasher D) (pf : Proof D) (leaf : D) (pos : Nat)
    (root : D) : Bool :=
  reconstruct h pf leaf pos == some root

/-- §5.4 normative verification: wrap the folded value with the claimed
kind's domain and compare to the trusted object id. -/
def verifyId [DecidableEq D] (h : Hasher D) (k : Kind) (pf : Proof D) (leaf : D) (pos : Nat)
    (id : D) : Bool :=
  (reconstruct h pf leaf pos).map (h.wrap k) == some id

/-- §5.5 `verify_chunk`: chunk proofs reject position 0 (the metadata leaf). -/
def verifyChunk [DecidableEq D] (h : Hasher D) (pf : Proof D) (chunk : D) (pos : Nat)
    (id : D) : Bool :=
  pos != 0 && verifyId h .chunked pf chunk pos id

/-! ## §5.3 range selection, §5.4 multi-leaf and range verification -/

/-- `siblings_required_for_range_proof` for `start..=end` (non-empty, in
range): per level, the left sibling of an odd `start` and the real right
sibling of an even `end`. §5.3 states one rule for any position set, so
this must equal `selMulti` on `[start, end]` (checked by `#guard` and the
difftest). -/
def selRange (s a b lvl : Nat) : List (Nat × Nat) :=
  if s ≤ 1 then []
  else (if a % 2 = 1 then [(lvl, a - 1)] else []) ++
    (if b % 2 = 0 ∧ b + 1 < s then [(lvl, b + 1)] else []) ++
    selRange ((s + 1) / 2) (a / 2) (b / 2) (lvl + 1)
termination_by s
decreasing_by omega

/-- Parent of a proven node at `p` whose pair-mate is not proven: the odd
trailing node folds as `H(d ‖ d)` without consuming a sibling, otherwise
one wire sibling is consumed (`H(d ‖ sib)` for even `p`, `H(sib ‖ d)` for
odd `p`). -/
def alone (h : Hasher D) (s p : Nat) (d : D) (sibs : List D) : Option (D × List D) :=
  if p % 2 = 0 ∧ s ≤ p + 1 then some (h.node d d, sibs)
  else match sibs with
    | [] => none
    | x :: rest => some (if p % 2 = 0 then h.node d x else h.node x d, rest)

/-- One level of `reconstruct_multi_root` over the proven nodes `cur`
(ascending by position): pair-mates both proven combine directly (the
§5.3 "already in `P`" omission), others go through `alone`. Returns the
next level's proven nodes and the unconsumed siblings. -/
def multiStep (h : Hasher D) (s : Nat) :
    List (Nat × D) → List D → Option (List (Nat × D) × List D)
  | [], sibs => some ([], sibs)
  | (p, d) :: rest, sibs =>
    match rest with
    | (q, e) :: rest' =>
      if p % 2 = 0 ∧ q = p + 1 then
        (multiStep h s rest' sibs).map fun r => ((p / 2, h.node d e) :: r.1, r.2)
      else do
        let (c, sibs') ← alone h s p d sibs
        let r ← multiStep h s ((q, e) :: rest') sibs'
        pure ((p / 2, c) :: r.1, r.2)
    | [] => do
      let (c, sibs') ← alone h s p d sibs
      pure ([(p / 2, c)], sibs')
termination_by l => l.length

/-- Fold every level (the `levels_in_tree - 1` loop; `halvings_eq_levelsInTree`). -/
def foldMulti (h : Hasher D) (s : Nat) (cur : List (Nat × D)) (sibs : List D) :
    Option (List (Nat × D) × List D) :=
  if s ≤ 1 then some (cur, sibs)
  else (multiStep h s cur sibs).bind fun r => foldMulti h ((s + 1) / 2) r.1 r.2
termination_by s
decreasing_by omega

/-- §5.4 multi-leaf reconstruction (`reconstruct_multi_root`) over
`(leaf, position)` elements in any order: zero positions, an out-of-range
position and a repeated position are all rejected (§5.4 MUSTs); every
sibling must be consumed and exactly one node must remain. -/
def reconstructMulti (h : Hasher D) (pf : Proof D) (elems : List (D × Nat)) : Option D :=
  if elems.isEmpty then none
  else if elems.any (fun e => pf.leafCount ≤ e.2) then none
  else if !(elems.map (·.2)).Nodup then none
  else
    let sorted := (elems.map fun e => (e.2, h.leaf e.2 e.1)).mergeSort (fun a b => a.1 ≤ b.1)
    match foldMulti h pf.leafCount sorted pf.siblings with
    | some ([(_, d)], []) => some (h.fin pf.leafCount d)
    | _ => none

/-- `reconstruct_range_root`: the contiguous leaves `start, start+1, …`
(an empty range is rejected as zero positions). -/
def reconstructRange (h : Hasher D) (pf : Proof D) (start : Nat) (leaves : List D) : Option D :=
  reconstructMulti h pf (leaves.mapIdx fun i x => (x, start + i))

/-- §5.4 id-based multi verification (`verify_tree_entries_multi`), and
§5.5 `verify_chunks_multi` (any position 0 rejected). -/
def verifyMultiId [DecidableEq D] (h : Hasher D) (k : Kind) (pf : Proof D)
    (elems : List (D × Nat)) (id : D) : Bool :=
  (reconstructMulti h pf elems).map (h.wrap k) == some id

def verifyChunksMulti [DecidableEq D] (h : Hasher D) (pf : Proof D) (elems : List (D × Nat))
    (id : D) : Bool :=
  !(elems.any (·.2 == 0)) && verifyMultiId h .chunked pf elems id

/-- `verify_tree_entries_range` / `verify_chunks_range` (`start = 0` rejected). -/
def verifyRangeId [DecidableEq D] (h : Hasher D) (k : Kind) (pf : Proof D) (start : Nat)
    (leaves : List D) (id : D) : Bool :=
  (reconstructRange h pf start leaves).map (h.wrap k) == some id

def verifyChunksRange [DecidableEq D] (h : Hasher D) (pf : Proof D) (start : Nat)
    (leaves : List D) (id : D) : Bool :=
  start != 0 && verifyRangeId h .chunked pf start leaves id

end MkitFormal.Merkle
