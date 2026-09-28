import Lake
open Lake DSL

-- mkit formal models (Lean 4 core only; no Mathlib). See README.md.
package mkit_formal where
  leanOptions := #[⟨`autoImplicit, false⟩]

@[default_target]
lean_lib MkitFormal where

-- Differential test: replays Rust-exported BMT vectors against the Lean model
-- of SPEC-MERKLE-OBJECTS §1/§5 (see scripts/difftest-merkle.sh).
lean_exe merkle_difftest where
  root := `MkitFormal.MerkleDifftest

-- Differential test: replays Rust-exported delta vectors against the Lean
-- model of SPEC-DELTA §2-§5 (see scripts/difftest-delta.sh).
lean_exe delta_difftest where
  root := `MkitFormal.DeltaDifftest
