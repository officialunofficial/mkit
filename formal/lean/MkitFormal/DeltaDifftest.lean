import MkitFormal.DeltaCanaries

/-!
# Differential test: `delta.rs` vs the SPEC-DELTA model (MKIT-25)

Replays the vectors written by
`rust/crates/mkit-core/tests/formal_delta_vectors.rs` (see
`scripts/difftest-delta.sh`). Per case (`CASE … END`) it checks

* every `A` line: the model's `apply` agrees with Rust's `delta::decode` on
  acceptance, output bytes and error kind (§4, §8);
* the Rust writer's stream `ENC`: `apply base ENC = ok TARGET`, `decode ENC`
  succeeds with a well-formed delta that re-encodes byte-identically
  (`encode_decode`), and equals the model of the Rust writer
  (`encodeRust`, §5);
* the model's all-INSERT writer round-trips (executes `apply_encodeInsertOnly`;
  targets up to 4 KiB).

Usage: `delta_difftest VECTORS [--mutant noInsertEof|noCopyBound|noFinalLen|noOverrun|noBaseLen]`.
With `--mutant`, `apply` is replaced by the corresponding
`Canaries.applyMut`, and the run is expected to report disagreements.
-/

namespace MkitFormal.Delta.Difftest

open MkitFormal.Delta MkitFormal.Delta.Canaries

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def parseHex (s : String) : Option Bytes :=
  if s = "-" then some []
  else
    let rec go : List Char → Option (List UInt8)
      | [] => some []
      | a :: b :: rest => do
        let x ← hexVal a
        let y ← hexVal b
        let r ← go rest
        pure (UInt8.ofNat (16 * x + y) :: r)
      | [_] => none
    go s.toList

def hexStr (b : Bytes) : String :=
  if b.isEmpty then "-"
  else
    let d := "0123456789abcdef".toList
    String.mk (b.flatMap fun x => [d[x.toNat / 16]!, d[x.toNat % 16]!])

def errName : Err → String
  | .eof => "eof"
  | .unsupportedVersion => "unsupported_version"
  | .baseLenMismatch => "base_len_mismatch"
  | .reservedOpcodeBits => "reserved_opcode_bits"
  | .zeroOpcode => "zero_opcode"
  | .zeroLengthCopy => "zero_length_copy"
  | .copyPastBase => "copy_past_base"
  | .resultLenOverrun => "result_len_overrun"
  | .resultLenUnderrun => "result_len_underrun"
  | .oob => "oob"

def verdict : Except Err Bytes → String
  | .ok b => s!"OK {hexStr b}"
  | .error e => s!"ERR {errName e}"

def parseMut : String → Option Mut
  | "noInsertEof" => some .noInsertEof
  | "noCopyBound" => some .noCopyBound
  | "noFinalLen" => some .noFinalLen
  | "noOverrun" => some .noOverrun
  | "noBaseLen" => some .noBaseLen
  | _ => none

structure St where
  name : String := ""
  base : Bytes := []
  target : Bytes := []
  enc : Bytes := []
  cases : Nat := 0
  applies : Nat := 0
  accepted : Nat := 0
  failures : Array String := #[]

def fail (st : St) (msg : String) : St :=
  { st with failures := st.failures.push s!"{st.name}: {msg}" }

def endCase (st : St) : St := Id.run do
  let mut st := st
  if verdict (apply st.base st.enc) != verdict (.ok st.target) then
    st := fail st "apply base ENC ≠ ok TARGET"
  match decode st.enc with
  | .ok d =>
    if !d.wf then st := fail st "decode ENC not well-formed"
    if encode d != st.enc then st := fail st "encode (decode ENC) ≠ ENC"
  | .error e => st := fail st s!"decode ENC failed: {errName e}"
  if encode (encodeRust st.base st.target) != st.enc then
    st := fail st "model of the Rust writer disagrees with ENC"
  -- (quadratic in the list model; skipped for the 64 KiB+ golden cases)
  if st.target.length ≤ 4096 &&
      verdict (apply st.base (encode (encodeInsertOnly st.base st.target))) !=
      verdict (.ok st.target) then
    st := fail st "all-INSERT writer round trip failed"
  return { st with cases := st.cases + 1 }

def step (app : Bytes → Bytes → Except Err Bytes) (st : St) (line : String) : St :=
  let w := (line.splitOn " ").filter (· ≠ "")
  let hex (s : String) (k : Bytes → St) : St :=
    match parseHex s with
    | some b => k b
    | none => fail st s!"bad hex in: {line.take 80}"
  match w with
  | ["CASE", n] => { st with name := n }
  | ["BASE", h] => hex h fun b => { st with base := b }
  | ["TARGET", h] => hex h fun b => { st with target := b }
  | ["ENC", h] => hex h fun b => { st with enc := b }
  | ["END"] => endCase st
  | "A" :: tag :: b :: s :: rest =>
    let expect := " ".intercalate rest
    let baseOf (k : Bytes → St) : St := if b = "=" then k st.base else hex b k
    baseOf fun base => hex s fun strm =>
      let got := app base strm
      let st := { st with applies := st.applies + 1,
                          accepted := st.accepted + (match got with | .ok _ => 1 | _ => 0) }
      if verdict got = expect then st
      else fail st s!"A {tag}: lean {(verdict got).take 60} rust {expect.take 60}"
  | [] => st
  | _ =>
    if line.startsWith "MKIT-DELTA-VECTORS" then st else fail st s!"bad line: {line.take 80}"

end MkitFormal.Delta.Difftest

open MkitFormal.Delta MkitFormal.Delta.Difftest in
def main (args : List String) : IO UInt32 := do
  let (path, app, label) ← match args with
    | [p] => pure (p, apply, "model")
    | [p, "--mutant", m] =>
      match parseMut m with
      | some mu => pure (p, Canaries.applyMut mu, s!"mutant {m}")
      | none => throw <| IO.userError s!"unknown mutant {m}"
    | _ => throw <| IO.userError "usage: delta_difftest VECTORS [--mutant NAME]"
  let lines ← IO.FS.lines path
  let st := lines.foldl (step app) {}
  IO.println s!"delta_difftest ({label}): {st.cases} cases, {st.applies} streams \
    ({st.accepted} accepted), {st.failures.size} disagreement(s)"
  for f in st.failures.toList.take 10 do
    IO.println s!"  {f}"
  return if st.failures.isEmpty && st.cases > 0 then 0 else 1
