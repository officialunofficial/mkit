/-!
# SPEC-DELTA model (Linear MKIT-25)

An executable model of `docs/specs/SPEC-DELTA.md` (version 1):

* §2 stream header (`stream_version`, `u32 LE base_len`, `u32 LE result_len`);
* §3 instruction encoding (`COPY` = `0x80 ‖ u32 LE offset ‖ u16 LE length`,
  `INSERT` = `len ‖ literal`, `1 ≤ len ≤ 127`); there are no varints in v1,
  every integer is fixed-width little-endian;
* §4 reconstruction (`apply`), mirroring the order of checks of
  `rust/crates/mkit-core/src/delta.rs::decode` so that the error *kind* is
  comparable in the differential test;
* §5 a writer model (`encodeWith`), parameterised by a match oracle whose
  proposals are re-verified byte-for-byte (the Rust writer's hash index is one
  such oracle, see `rustOracle`).

Streams, bases and outputs are `List UInt8`. `apply` reads the stream as the
unread suffix and performs every read through the partial accessors `readLE`
and `slice?`; a failed read yields the model-only error `Err.oob`, which
stands for a Rust slice-index panic. `MkitFormal.DeltaProofs.apply_ne_oob`
proves it is unreachable, i.e. no instruction reads past the delta buffer or
the base.
-/

namespace MkitFormal.Delta

abbrev Bytes := List UInt8

/-- §2/§4 error kinds. `eof` = `MkitError::UnexpectedEof`,
`unsupportedVersion` = `MkitError::UnsupportedObjectVersion`, the rest are the
`DeltaCorruption` variants. `oob` is model-only (an unguarded read). -/
inductive Err where
  | eof
  | unsupportedVersion
  | baseLenMismatch
  | reservedOpcodeBits
  | zeroOpcode
  | zeroLengthCopy
  | copyPastBase
  | resultLenOverrun
  | resultLenUnderrun
  | oob
  deriving DecidableEq, Repr, Inhabited

/-- §3 instructions. -/
inductive Instr where
  | copy (off len : Nat)
  | insert (lit : Bytes)
  deriving DecidableEq, Repr, Inhabited

/-- A decoded §2 stream: header fields plus instructions. -/
structure Delta where
  baseLen : Nat
  resultLen : Nat
  instrs : List Instr
  deriving DecidableEq, Repr, Inhabited

/-! ## Encoding (§2, §3) -/

/-- `k`-byte little-endian encoding of `v` (low bytes first; `v` is taken
mod `256^k`). -/
def leBytes : Nat → Nat → Bytes
  | 0, _ => []
  | k + 1, v => UInt8.ofNat (v % 256) :: leBytes k (v / 256)

/-- §3.1 / §3.2. -/
def encInstr : Instr → Bytes
  | .copy o l => 0x80 :: (leBytes 4 o ++ leBytes 2 l)
  | .insert lit => UInt8.ofNat lit.length :: lit

def encInstrs : List Instr → Bytes
  | [] => []
  | i :: is => encInstr i ++ encInstrs is

/-- §2 header followed by the instructions. -/
def encode (d : Delta) : Bytes :=
  0x01 :: (leBytes 4 d.baseLen ++ (leBytes 4 d.resultLen ++ encInstrs d.instrs))

/-- Writer-side well-formedness (§3, §7): `COPY` fields fit their widths and
`length ≥ 1`; `INSERT` literals are 1..127 bytes. -/
def Instr.wf : Instr → Bool
  | .copy o l => decide (o < 2 ^ 32) && decide (0 < l) && decide (l < 2 ^ 16)
  | .insert lit => decide (0 < lit.length) && decide (lit.length ≤ 127)

def Delta.wf (d : Delta) : Bool :=
  decide (d.baseLen < 2 ^ 32) && decide (d.resultLen < 2 ^ 32) && d.instrs.all Instr.wf

/-- §2: `COPY(offset, length)` satisfies `offset + length ≤ base_len`. -/
def Instr.inBase (n : Nat) : Instr → Bool
  | .copy o l => decide (o + l ≤ n)
  | .insert _ => true

/-! ## Semantics of an instruction list -/

def execInstr (base : Bytes) : Instr → Bytes
  | .copy o l => (base.drop o).take l
  | .insert lit => lit

def exec (base : Bytes) : List Instr → Bytes
  | [] => []
  | i :: is => execInstr base i ++ exec base is

/-! ## Guarded reads -/

/-- Read a `k`-byte little-endian integer from the front of `r`; `none` iff
fewer than `k` bytes remain (an out-of-bounds read). -/
def readLE : Nat → Bytes → Option Nat
  | 0, _ => some 0
  | _ + 1, [] => none
  | k + 1, b :: r => (readLE k r).map (b.toNat + 256 * ·)

/-- `r[i .. i+n]`, or `none` when that range is out of bounds (Rust: panic). -/
def slice? (r : Bytes) (i n : Nat) : Option Bytes :=
  if i + n ≤ r.length then some ((r.drop i).take n) else none

/-! ## Syntactic decoding (§2, §3) -/

/-- Parse an instruction stream without a base. Rejects the §3 degenerate /
reserved encodings and truncation. -/
def decodeInstrs : Bytes → Except Err (List Instr)
  | [] => .ok []
  | op :: rest =>
    if 128 ≤ op.toNat then
      if op.toNat ≠ 128 then .error .reservedOpcodeBits
      else
        match readLE 4 rest, readLE 2 (rest.drop 4) with
        | some off, some len =>
          if len = 0 then .error .zeroLengthCopy
          else (decodeInstrs (rest.drop 6)).map (.copy off len :: ·)
        | _, _ => .error .eof
    else if op.toNat = 0 then .error .zeroOpcode
    else if rest.length < op.toNat then .error .eof
    else (decodeInstrs (rest.drop op.toNat)).map (.insert (rest.take op.toNat) :: ·)
termination_by r => r.length
decreasing_by all_goals simp; omega

def decode : Bytes → Except Err Delta
  | v :: rest =>
    if v ≠ 0x01 then .error .unsupportedVersion
    else
      match readLE 4 rest, readLE 4 (rest.drop 4) with
      | some bl, some rl => (decodeInstrs (rest.drop 8)).map (⟨bl, rl, ·⟩)
      | _, _ => .error .eof
  | [] => .error .eof

/-! ## Reconstruction (§4) -/

/-- The §4 loop over the unread suffix `r` of the stream, with `out` the bytes
emitted so far and `rl` the declared `result_len`. Order of checks follows the
§4 pseudo-code and `delta.rs::decode`. -/
def run (base : Bytes) (rl : Nat) : Bytes → Bytes → Except Err Bytes
  | [], out => if out.length = rl then .ok out else .error .resultLenUnderrun
  | op :: rest, out =>
    if 128 ≤ op.toNat then
      -- COPY (`op & 0x80 != 0`, see `DeltaProofs.topBit_iff`)
      if op.toNat ≠ 128 then .error .reservedOpcodeBits
      else if rest.length < 6 then .error .eof
      else
        match readLE 4 rest, readLE 2 (rest.drop 4) with
        | some off, some len =>
          if len = 0 then .error .zeroLengthCopy
          else if base.length < off + len then .error .copyPastBase
          else if rl < out.length + len then .error .resultLenOverrun
          else
            match slice? base off len with
            | some chunk => run base rl (rest.drop 6) (out ++ chunk)
            | none => .error .oob
        | _, _ => .error .oob
    else if op.toNat = 0 then .error .zeroOpcode
    else if rest.length < op.toNat then .error .eof
    else if rl < out.length + op.toNat then .error .resultLenOverrun
    else
      match slice? rest 0 op.toNat with
      | some lit => run base rl (rest.drop op.toNat) (out ++ lit)
      | none => .error .oob
termination_by r _ => r.length
decreasing_by all_goals simp; omega

def headerLen : Nat := 9

/-- §4 `apply(base, stream)`. -/
def apply (base s : Bytes) : Except Err Bytes :=
  if s.length < headerLen then .error .eof
  else
    match s with
    | [] => .error .oob
    | v :: rest =>
      if v ≠ 0x01 then .error .unsupportedVersion
      else
        match readLE 4 rest, readLE 4 (rest.drop 4) with
        | some bl, some rl =>
          if bl ≠ base.length then .error .baseLenMismatch
          else run base rl (rest.drop 8) []
        | _, _ => .error .oob

/-! ## Writer model (§5, informative) -/

def flush (buf : Bytes) : List Instr :=
  if buf = [] then [] else [.insert buf]

/-- A proposed `COPY(o, l)` at target position `i` is taken only if it is
well-formed, inside the base and the target, and the bytes really match. -/
def validCopy (base target : Bytes) (i o l : Nat) : Prop :=
  0 < l ∧ l < 2 ^ 16 ∧ o < 2 ^ 32 ∧ o + l ≤ base.length ∧ i + l ≤ target.length ∧
    (base.drop o).take l = (target.drop i).take l

instance (base target : Bytes) (i o l : Nat) : Decidable (validCopy base target i o l) := by
  unfold validCopy; infer_instance

/-- Greedy writer: at target position `i` ask the oracle `prop` for a match;
take it if valid (flushing the pending literal `buf`), otherwise append
`target[i]` to `buf`, flushing at 127 bytes. -/
def encodeFrom (prop : Nat → Option (Nat × Nat)) (base target : Bytes) (i : Nat)
    (buf : Bytes) : List Instr :=
  if h : i < target.length then
    match prop i with
    | some (o, l) =>
      if hv : validCopy base target i o l then
        flush buf ++ .copy o l :: encodeFrom prop base target (i + l) []
      else
        let buf' := buf ++ [target[i]]
        if buf'.length = 127 then .insert buf' :: encodeFrom prop base target (i + 1) []
        else encodeFrom prop base target (i + 1) buf'
    | none =>
      let buf' := buf ++ [target[i]]
      if buf'.length = 127 then .insert buf' :: encodeFrom prop base target (i + 1) []
      else encodeFrom prop base target (i + 1) buf'
  else flush buf
termination_by target.length - i
decreasing_by all_goals (try have := hv.1); all_goals omega

def encodeWith (prop : Nat → Option (Nat × Nat)) (base target : Bytes) : Delta :=
  ⟨base.length, target.length, encodeFrom prop base target 0 []⟩

/-- The trivial all-INSERT writer of §5. -/
def encodeInsertOnly (base target : Bytes) : Delta := encodeWith (fun _ => none) base target

/-! ## The Rust writer as an oracle (executable, for the differential test)

`delta.rs::encode` indexes every aligned 16-byte base block by hash (first
occurrence wins), and at target position `ti` (with a full 16-byte window)
looks the window up, re-checks the bytes, and extends greedily while
`base_pos + len < base.len()`, `ti + len < result.len()`, the bytes agree and
`len < u16::MAX`. Modulo 64-bit collisions of `block_hash` (which only turn a
match into literals), that is the oracle below. -/

def blockSize : Nat := 16

/-- First aligned base block equal to `target[ti .. ti+16]`, extended greedily. -/
def rustOracle (base target : Array UInt8) (ti : Nat) : Option (Nat × Nat) :=
  if ti + blockSize ≤ target.size then
    let nb := base.size / blockSize
    let eqBlock (j : Nat) : Bool :=
      (List.range blockSize).all fun k => base[j * blockSize + k]! == target[ti + k]!
    match (List.range nb).find? eqBlock with
    | none => none
    | some j =>
      let bp := j * blockSize
      let rec extend (fuel ml : Nat) : Nat :=
        match fuel with
        | 0 => ml
        | fuel + 1 =>
          if bp + ml < base.size && ti + ml < target.size &&
              base[bp + ml]! == target[ti + ml]! && ml < 65535 then
            extend fuel (ml + 1)
          else ml
      some (bp, extend 65535 blockSize)
  else none

def encodeRust (base target : Bytes) : Delta :=
  encodeWith (rustOracle base.toArray target.toArray) base target

end MkitFormal.Delta
