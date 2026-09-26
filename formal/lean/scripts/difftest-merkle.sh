#!/usr/bin/env bash
# Reproduce every MKIT-24 check: build the Lean package (proofs + canaries,
# no `sorry`), audit axioms, export Rust vectors, run the Lean differential
# test, then confirm the canaries are caught (two model mutants, two corrupted
# Rust verdicts). Needs Lean 4.23.0 (`LAKE`, default `lake`) and cargo.
# Env: MKIT_FORMAL_SEED, MKIT_FORMAL_TREES (forwarded to the exporter).
set -euo pipefail
pkg=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$pkg/../.." && pwd)
LAKE=${LAKE:-lake}
out=${MKIT_FORMAL_MERKLE_OUT:-$pkg/.lake/difftest/merkle_vectors.txt}
fails=0
note() { printf '%-52s %s\n' "$1" "$2"; }

cd "$pkg"
if grep -rnw sorry MkitFormal/Merkle*.lean; then
  note "no sorry in MkitFormal/Merkle*.lean" "FAIL"; fails=$((fails + 1))
fi
"$LAKE" build MkitFormal.Merkle merkle_difftest >/dev/null
note "lake build (proofs, canaries, #guard replays)" "ok"
axioms=$("$LAKE" env lean scripts/merkle_axioms.lean)
if grep -Eq 'sorryAx|ofReduceBool' <<<"$axioms" ||
   grep -v "depends on axioms: \[propext\(, Classical.choice\)\?\(, Quot.sound\)\?\]" <<<"$axioms" | grep -q .; then
  printf '%s\n' "$axioms"; note "axiom audit" "FAIL"; fails=$((fails + 1))
else
  note "axiom audit ($(wc -l <<<"$axioms") theorems)" "ok"
fi

mkdir -p "$(dirname "$out")"
(cd "$repo/rust" && MKIT_FORMAL_MERKLE_OUT=$out \
  cargo test -q -p mkit-core --test formal_merkle_vectors -- --ignored >/dev/null)
note "rust export -> ${out#"$repo"/}" "ok"

bin=$pkg/.lake/build/bin/merkle_difftest
if "$bin" "$out"; then note "difftest" "ok"; else note "difftest" "FAIL"; fails=$((fails + 1)); fi

# Canaries: each model mutant and each corrupted Rust verdict must be caught.
canary() { # name, then the command that must FAIL
  local name=$1; shift
  if "$@" >/dev/null; then
    note "canary: $name" "FAIL (not detected)"; fails=$((fails + 1))
  else
    note "canary: $name" "ok"
  fi
}
canary "--mutant (§5.8 selection) detected" "$bin" "$out" --mutant
canary "--mutant-verify (no exact consumption) detected" "$bin" "$out" --mutant-verify
bad=$(dirname "$out")/merkle_vectors.corrupt.txt
# Flip the first accepted single-leaf verdict …
awk '!done && /^PROOF single/ && $NF == "1" { $NF = "0"; done = 1 } { print }' "$out" >"$bad"
canary "corrupted Rust single verdict detected" "$bin" "$bad"
# … and the first rejected adversarial (tampered) verdict.
awk '!done && /^ADV / && $NF == "0" { $NF = "1"; done = 1 } { print }' "$out" >"$bad"
canary "corrupted Rust ADV verdict detected" "$bin" "$bad"

[[ $fails == 0 ]] || { echo "$fails check(s) failed"; exit 1; }
echo "all MKIT-24 merkle checks passed"
