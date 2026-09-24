import MkitFormal.MerkleModel
import Std.Data.HashMap

/-!
# Differential test: Lean BMT model vs `merkle.rs` (MKIT-24)

Reads the vectors written by
`rust/crates/mkit-core/tests/formal_merkle_vectors.rs` and, for every tree,
instantiates the model's `Hasher` with the exported BLAKE3 oracle table
(an evaluation missing from the table becomes a distinct symbolic term, so
it can never collide with a real digest). It then checks that the model
reproduces, bit for bit:

* the finalized root and object id (§1.1, §2, §4);
* per single-leaf proof: `leaf_count`, the §5.3 `(level, index)` sibling
  positions, the sibling digests, the id-based verdict (§5.4; `verifyChunk`
  with the §5.5 position-0 rule for ChunkedBlobs) and bare-root acceptance;
* per wrong-position replay: Rust's (rejecting) verdict;
* per multi-leaf proof: `leaf_count`, `selMulti` positions and digests, and
  the multi verdict (`reconstructMulti`; §5.5 position 0 for chunks);
* per range proof: `selRange` and `selMulti` positions, digests, verdict,
  and the verdict for the same leaves claimed one position to the right;
* per `ADV` line (tampered `leaf_count` / siblings, reordered, repeated or
  zero positions, the §5.4 all-default proof against the empty Tree): the
  model's verdict equals Rust's.

Usage: `merkle_difftest <vectors.txt> [--mutant | --mutant-verify]`.
`--mutant` swaps in the §5.8 provisional selection (self-duplicates
emitted); `--mutant-verify` lets the model's multi/range verifier ignore
leftover siblings (drops §5.4 "every sibling consumed exactly once"). Each
must be detected: mismatches reported, exit 1.
-/

namespace MkitFormal.Merkle.Difftest

open MkitFormal.Merkle

structure Oracle where
  leaf : Std.HashMap (Nat × String) String := {}
  node : Std.HashMap (String × String) String := {}
  fin : Std.HashMap (Nat × String) String := {}
  wrap : Std.HashMap (String × String) String := {}

def kindName : Kind → String
  | .tree => "tree"
  | .chunked => "chunked"

/-- Oracle-backed hasher; a missing entry evaluates to a symbolic term. -/
def hasher (o : Oracle) (empty : String) : Hasher String where
  empty := empty
  leaf i x := o.leaf.getD (i, x) s!"?L({i},{x})"
  node a b := o.node.getD (a, b) s!"?N({a},{b})"
  fin n x := o.fin.getD (n, x) s!"?F({n},{x})"
  wrap k x := o.wrap.getD (kindName k, x) s!"?W({kindName k},{x})"

/-- `reconstructMulti` with the exact-consumption check removed (mutant). -/
def reconstructMultiLoose (h : Hasher String) (pf : Proof String)
    (elems : List (String × Nat)) : Option String :=
  if elems.isEmpty then none
  else if elems.any (fun e => pf.leafCount ≤ e.2) then none
  else if !(elems.map (·.2)).Nodup then none
  else
    let sorted := (elems.map fun e => (e.2, h.leaf e.2 e.1)).mergeSort (fun a b => a.1 ≤ b.1)
    match foldMulti h pf.leafCount sorted pf.siblings with
    | some ([(_, d)], _) => some (h.fin pf.leafCount d)
    | _ => none

/-- §5.8 provisional selection (mutant): also emits the self-duplicate. -/
def selPathV1 (s p lvl : Nat) : List (Nat × Nat) :=
  if s ≤ 1 then []
  else (lvl, sibIndex s p) :: selPathV1 ((s + 1) / 2) (p / 2) (lvl + 1)
termination_by s
decreasing_by omega

structure Tree where
  name : String := ""
  kind : Kind := .tree
  n : Nat := 0
  empty : String := ""
  leaves : List String := []
  oracle : Oracle := {}
  root : String := ""
  id : String := ""
  /-- Rust single-leaf proofs by position, for the wrong-position replays. -/
  singles : Std.HashMap Nat (List String) := {}
  /-- The last range proof, for the shifted-range replay. -/
  lastRange : Proof String := ⟨0, []⟩

structure Stats where
  trees : Nat := 0
  checks : Nat := 0
  singles : Nat := 0
  multis : Nat := 0
  ranges : Nat := 0
  wrongs : Nat := 0
  advs : Nat := 0
  advAccepted : Nat := 0
  failures : Array String := #[]

def csv (s : String) : List String := if s == "-" then [] else s.splitOn ","

def parsePos (s : String) : Option (Nat × Nat) :=
  match s.splitOn ":" with
  | [l, k] => do pure (← l.toNat?, ← k.toNat?)
  | _ => none

def check (st : Stats) (ok : Bool) (msg : Thunk String) : Stats :=
  let st := { st with checks := st.checks + 1 }
  if ok then st else { st with failures := st.failures.push msg.get }

def fmtPos (l : List (Nat × Nat)) : String :=
  ",".intercalate (l.map fun (a, b) => s!"{a}:{b}")

/-- Model verdict for elements `(leaf, pos)` under the tree's kind (§5.4 id
comparison, §5.5 position-0 rule for chunks). `loose` = verifier mutant. -/
def multiVerdict (loose : Bool) (t : Tree) (pf : Proof String) (elems : List (String × Nat)) :
    Bool :=
  let h := hasher t.oracle t.empty
  let r := (if loose then reconstructMultiLoose h pf elems else reconstructMulti h pf elems)
  let ok := r.map (h.wrap t.kind) == some t.id
  match t.kind with
  | .tree => ok
  | .chunked => !(elems.any (·.2 == 0)) && ok

/-- Range verdict (`verify_*_range`; chunk ranges may not start at 0). -/
def rangeVerdict (loose : Bool) (t : Tree) (pf : Proof String) (start : Nat)
    (leaves : List String) : Bool :=
  !(t.kind == .chunked && start == 0) &&
    multiVerdict loose t pf (leaves.mapIdx fun i x => (x, start + i))

def runProof (mutant loose : Bool) (t : Tree) (st : Stats) (w : List String) : Tree × Stats := Id.run do
  let h := hasher t.oracle t.empty
  match w with
  | [tag, posS, lcS, sibposS, sibsS, accS] =>
    let pos := (csv posS).filterMap String.toNat?
    let lc := lcS.toNat!
    let sibpos := (csv sibposS).filterMap parsePos
    let sibs := csv sibsS
    let acc := accS == "1"
    let ctx := s!"{t.name} {tag} {posS}"
    let mut st := check st (lc == t.n) s!"{ctx}: leaf_count {lc} ≠ {t.n}"
    if tag == "single" then
      let i := pos.headD 0
      let sel := if mutant then selPathV1 t.n i 0 else selPath t.n i 0
      st := check st (sel == sibpos)
        s!"{ctx}: §5.3 selection lean={fmtPos sel} rust={fmtPos sibpos}"
      st := check st ((prove h t.leaves i).siblings == sibs) s!"{ctx}: sibling digests differ"
      let pf : Proof String := ⟨lc, sibs⟩
      let leaf := t.leaves.getD i ""
      let v := match t.kind with
        | .tree => verifyId h .tree pf leaf i t.id
        | .chunked => verifyChunk h pf leaf i t.id
      st := check st (v == acc) s!"{ctx}: verdict lean={v} rust={acc}"
      st := check st (verifyRoot h pf leaf i t.root) s!"{ctx}: bare-root fold rejected"
      st := { st with singles := st.singles + 1 }
      return ({ t with singles := t.singles.insert i sibs }, st)
    else if tag == "range" then
      let a := pos.headD 0
      let b := pos.getD 1 0
      let P := (List.range (b + 1 - a)).map (a + ·)
      st := check st (selRange t.n a b 0 == sibpos)
        s!"{ctx}: §5.3 range selection lean={fmtPos (selRange t.n a b 0)} rust={fmtPos sibpos}"
      st := check st (selMulti t.n P 0 == sibpos)
        s!"{ctx}: §5.3 set rule on range lean={fmtPos (selMulti t.n P 0)} rust={fmtPos sibpos}"
      st := check st ((proveMulti h t.leaves P).siblings == sibs) s!"{ctx}: range digests differ"
      let pf : Proof String := ⟨lc, sibs⟩
      let v := rangeVerdict loose t pf a ((t.leaves.drop a).take (b + 1 - a))
      st := check st (v == acc) s!"{ctx}: range verdict lean={v} rust={acc}"
      return ({ t with lastRange := pf }, { st with ranges := st.ranges + 1 })
    else
      let sel := selMulti t.n pos 0
      st := check st (sel == sibpos)
        s!"{ctx}: §5.3 multi selection lean={fmtPos sel} rust={fmtPos sibpos}"
      st := check st ((proveMulti h t.leaves pos).siblings == sibs)
        s!"{ctx}: multi sibling digests differ"
      -- §5.4/§5.5: honest multi proofs verify, except chunk proofs covering 0.
      let expect := !(t.kind == .chunked && pos.contains 0)
      st := check st (acc == expect) s!"{ctx}: rust multi verdict {acc}, expected {expect}"
      let v := multiVerdict loose t ⟨lc, sibs⟩ (pos.map fun i => (t.leaves.getD i "", i))
      st := check st (v == acc) s!"{ctx}: multi verdict lean={v} rust={acc}"
      return (t, { st with multis := st.multis + 1 })
  | _ => return (t, { st with failures := st.failures.push s!"{t.name}: bad PROOF line" })

def runWrong (t : Tree) (st : Stats) (w : List String) : Stats :=
  let h := hasher t.oracle t.empty
  match w with
  | [iS, jS, badS] =>
    let i := iS.toNat!
    let j := jS.toNat!
    let pf : Proof String := ⟨t.n, t.singles.getD i []⟩
    let leaf := t.leaves.getD i ""
    let v := match t.kind with
      | .tree => verifyId h .tree pf leaf j t.id
      | .chunked => verifyChunk h pf leaf j t.id
    let st := check st (v == (badS == "1"))
      s!"{t.name} wrongpos {i}->{j}: lean={v} rust={badS}"
    { st with wrongs := st.wrongs + 1 }
  | _ => { st with failures := st.failures.push s!"{t.name}: bad WRONGPOS line" }

/-- `ADV <mode> <positions> <leaf_count> <siblings> <verdict>`: the model's
verdict on an adversarial proof/claim (honest leaves) must equal Rust's. -/
def runAdv (loose : Bool) (t : Tree) (st : Stats) (w : List String) : Stats :=
  let h := hasher t.oracle t.empty
  match w with
  | [mode, posS, lcS, sibsS, accS] =>
    let pos := (csv posS).filterMap String.toNat?
    let pf : Proof String := ⟨lcS.toNat!, csv sibsS⟩
    let acc := accS == "1"
    let v := match mode with
      | "single" =>
        let i := pos.headD 0
        let leaf := t.leaves.getD i ""
        match t.kind with
        | .tree => verifyId h .tree pf leaf i t.id
        | .chunked => verifyChunk h pf leaf i t.id
      | "range" =>
        let a := pos.headD 0
        let k := pos.getD 1 0
        rangeVerdict loose t pf a ((t.leaves.drop a).take k)
      | _ => multiVerdict loose t pf (pos.map fun i => (t.leaves.getD i "", i))
    let st := check st (v == acc)
      s!"{t.name} ADV {mode} {posS} lc={lcS} |sibs|={pf.siblings.length}: lean={v} rust={acc}"
    { st with advs := st.advs + 1, advAccepted := st.advAccepted + (if acc then 1 else 0) }
  | _ => { st with failures := st.failures.push s!"{t.name}: bad ADV line" }

/-- `SHIFTRANGE <start> <count> <verdict>`: the last range proof's leaves
claimed at `start + 1`. -/
def runShift (loose : Bool) (t : Tree) (st : Stats) (w : List String) : Stats :=
  match w with
  | [aS, kS, accS] =>
    let a := aS.toNat!
    let v := rangeVerdict loose t t.lastRange (a + 1) ((t.leaves.drop a).take kS.toNat!)
    let st := check st (v == (accS == "1")) s!"{t.name} SHIFTRANGE {a}: lean={v} rust={accS}"
    { st with wrongs := st.wrongs + 1 }
  | _ => { st with failures := st.failures.push s!"{t.name}: bad SHIFTRANGE line" }

def finishTree (t : Tree) (st : Stats) : Stats :=
  let h := hasher t.oracle t.empty
  let st := check st (innerRoot h t.leaves == t.root) s!"{t.name}: §1.1 root differs"
  { st with trees := st.trees + 1 }

def run (mutant loose : Bool) (lines : Array String) : Stats := Id.run do
  let mut st : Stats := {}
  let mut t : Tree := {}
  for line in lines do
    match line.splitOn " " with
    | ["TREE", name, kind, n] =>
      t := { name, kind := if kind == "chunked" then .chunked else .tree, n := n.toNat! }
    | ["EMPTY", e] => t := { t with empty := e }
    | "LEAVES" :: ls => t := { t with leaves := ls.filter (· ≠ "") }
    | ["L", i, x, o] =>
      t := { t with oracle := { t.oracle with leaf := t.oracle.leaf.insert (i.toNat!, x) o } }
    | ["N", a, b, o] =>
      t := { t with oracle := { t.oracle with node := t.oracle.node.insert (a, b) o } }
    | ["F", n, x, o] =>
      t := { t with oracle := { t.oracle with fin := t.oracle.fin.insert (n.toNat!, x) o } }
    | ["W", k, x, o] =>
      t := { t with oracle := { t.oracle with wrap := t.oracle.wrap.insert (k, x) o } }
    | ["ROOT", r] =>
      t := { t with root := r }
      st := finishTree t st
    | ["ID", r] =>
      t := { t with id := r }
      st := check st (objectId (hasher t.oracle t.empty) t.kind t.leaves == r)
        s!"{t.name}: §2 id differs"
    | "PROOF" :: rest =>
      let (t', st') := runProof mutant loose t st rest
      t := t'
      st := st'
    | "WRONGPOS" :: rest => st := runWrong t st rest
    | "ADV" :: rest => st := runAdv loose t st rest
    | "SHIFTRANGE" :: rest => st := runShift loose t st rest
    | ["END"] => t := {}
    | _ => pure ()
  return st

end MkitFormal.Merkle.Difftest

open MkitFormal.Merkle.Difftest in
def main (args : List String) : IO UInt32 := do
  match args with
  | path :: flags =>
    let mutant := flags.contains "--mutant"
    let loose := flags.contains "--mutant-verify"
    let lines ← IO.FS.lines path
    unless lines.size > 0 && lines[0]!.startsWith "MKIT-MERKLE-VECTORS 1" do
      IO.eprintln s!"{path}: not a MKIT-MERKLE-VECTORS 1 file"
      return 2
    let st := run mutant loose lines
    let tag := if mutant then " (mutant)" else if loose then " (mutant-verify)" else ""
    IO.println s!"merkle_difftest{tag}: trees={st.trees} single={st.singles} \
      multi={st.multis} range={st.ranges} wrongpos={st.wrongs} \
      adv={st.advs} (rust-accepted {st.advAccepted}) checks={st.checks} \
      failures={st.failures.size}"
    for f in st.failures.toList.take 10 do
      IO.println s!"  MISMATCH {f}"
    if st.trees == 0 || st.singles == 0 || st.multis == 0 || st.ranges == 0 || st.advs == 0 then
      IO.eprintln "no cases checked"
      return 2
    return if st.failures.isEmpty then 0 else 1
  | [] =>
    IO.eprintln "usage: merkle_difftest <vectors.txt> [--mutant | --mutant-verify]"
    return 2
