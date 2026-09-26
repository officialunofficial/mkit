#!/usr/bin/env bash
# Reproduce every MKIT-25 check: build the Lean SPEC-DELTA model (proofs +
# canaries, no `sorry`), audit axioms, export Rust vectors, run the Lean
# differential test, then confirm the canaries are caught (each `--mutant`
# reader and a corrupted Rust verdict). Needs Lean 4.23.0 (`LAKE`, default
# `lake`) and cargo.
# Env: MKIT_FORMAL_SEED, MKIT_FORMAL_DELTA_CASES (forwarded to the exporter).
set -euo pipefail
pkg=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$pkg/../.." && pwd)
LAKE=${LAKE:-lake}
out=${MKIT_FORMAL_DELTA_OUT:-$pkg/.lake/difftest/delta_vectors.txt}
fails=0
note() { printf '%-52s %s\n' "$1" "$2"; }

cd "$pkg"
if grep -rnw sorry MkitFormal/Delta*.lean; then
  note "no sorry in MkitFormal/Delta*.lean" "FAIL"; fails=$((fails + 1))
fi
"$LAKE" build MkitFormal.Delta delta_difftest >/dev/null
note "lake build (proofs, canaries, difftest exe)" "ok"
axioms=$("$LAKE" env lean MkitFormal/DeltaAxioms.lean)
if grep -Eq 'sorryAx|ofReduceBool' <<<"$axioms" ||
   grep -v "depends on axioms: \[propext\(, Classical.choice\)\?\(, Quot.sound\)\?\]" <<<"$axioms" |
   grep -v "does not depend on any axioms" | grep -q .; then
  printf '%s\n' "$axioms"; note "axiom audit" "FAIL"; fails=$((fails + 1))
else
  note "axiom audit ($(wc -l <<<"$axioms") theorems)" "ok"
fi

mkdir -p "$(dirname "$out")"
(cd "$repo/rust" && MKIT_FORMAL_DELTA_OUT=$out \
  cargo test -q -p mkit-core --test formal_delta_vectors -- --ignored >/dev/null)
note "rust export -> ${out#"$repo"/}" "ok"

bin=$pkg/.lake/build/bin/delta_difftest
if "$bin" "$out"; then note "difftest" "ok"; else note "difftest" "FAIL"; fails=$((fails + 1)); fi

# Canaries 1-5: each reader mutant (one §4 check dropped) must disagree.
for m in noInsertEof noCopyBound noFinalLen noOverrun noBaseLen; do
  if "$bin" "$out" --mutant "$m" >/dev/null; then
    note "canary: --mutant $m detected" "FAIL (not detected)"; fails=$((fails + 1))
  else
    note "canary: --mutant $m detected" "ok"
  fi
done
# Canary 6: flip the first Rust rejection into an acceptance of the target.
bad=$(dirname "$out")/delta_vectors.corrupt.txt
awk '!done && /^A / && $(NF-1) == "ERR" { $(NF-1) = "OK"; $NF = "00"; done = 1 } { print }' \
  "$out" >"$bad"
if "$bin" "$bad" >/dev/null; then
  note "canary: corrupted Rust verdict detected" "FAIL (not detected)"; fails=$((fails + 1))
else
  note "canary: corrupted Rust verdict detected" "ok"
fi

[[ $fails == 0 ]] || { echo "$fails check(s) failed"; exit 1; }
echo "all MKIT-25 delta checks passed"
