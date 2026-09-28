#!/usr/bin/env bash
# Regenerate the ITF fixtures of the refs model-based conformance test
# (Linear MKIT-22, epic MKIT-17).
#
#   formal/scripts/gen-refs-traces.sh          regenerate the checked-in fixtures
#   CHECK=1 formal/scripts/gen-refs-traces.sh  regenerate into a temp dir and
#                                              diff against the checked-in ones
#
# Model: formal/quint/refs/refs_mbt.qnt (instances refs_mbt2 / refs_mbt3 of
# refs.qnt with NO_FAULTS and the linearizable scheduler `stepLin`; see that
# file's header). Replayed by
#   rust/crates/mkit-formal-conformance/tests/formal_refs_conformance.rs
# (`cargo test -p mkit-formal-conformance`), which runs offline on the
# checked-in fixtures; quint is needed only to regenerate them.
#
# Each fixture is the ITF trace `quint run --mbt --out-itf` wrote for one
# (instance, seed), post-processed with jq: variables the harness does not
# read (owner, procs, faults, lostRecords, recordDuringExpire and the
# mbt::* metadata) are dropped, the remaining ones lose their
# `refsLin::refs::` qualifier, `#meta` is replaced by a deterministic one
# (quint's carries a wall-clock timestamp), and each state is one line.
# The result is still ITF (a trace may carry any subset of the variables).
#
# Pins (MKIT-17): quint 0.32.0 (rust backend). Another version may draw
# different traces for the same seed: CHECK=1 then reports a diff, which is
# not a conformance failure (regenerate and review).
#
# Every line printed is "<check>  <expected outcome> (as expected)" or
# "UNEXPECTED: ..."; the script exits 1 on any unexpected outcome.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
MODEL_DIR=$REPO/formal/quint/refs
FIXTURES=${FIXTURES:-$REPO/rust/crates/mkit-formal-conformance/tests/fixtures/formal_refs}
STEPS=${STEPS:-60}
SAMPLES=${SAMPLES:-2000}
# instance:seed. Seeds were picked (greedy set cover over seeds 0x1..0x28 of
# both instances, quint 0.32.0, STEPS=60) so that together the traces reach
# every op kind's commit, every CAS outcome (ok / conflict / notfound) in
# every lock domain that has it, a conditional delete, a recovery record
# and a gc expire (the Rust test asserts that coverage).
TRACES=${TRACES:-"refs_mbt2:0xa refs_mbt2:0xf refs_mbt2:0x24 refs_mbt3:0x1b refs_mbt3:0x21"}

command -v quint >/dev/null || { echo "gen-refs-traces.sh: quint not on PATH" >&2; exit 2; }
command -v jq >/dev/null || { echo "gen-refs-traces.sh: jq not on PATH" >&2; exit 2; }
QV=$(quint --version)
[[ $QV == 0.32.0 ]] || echo "gen-refs-traces.sh: warning: quint $QV, fixtures were pinned with 0.32.0" >&2

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fails=0
note() { printf '%-64s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }

cd "$MODEL_DIR"
quint typecheck refs_mbt.qnt >/dev/null && note "typecheck refs_mbt.qnt" "ok (as expected)" ||
  bad "typecheck refs_mbt.qnt" failed

# qrun: $1 main, $2 step, $3 invariant, $4 expect ok|violation.
qrun() {
  local out rc=0
  out=$(quint run refs_mbt.qnt --main "$1" --init initLin --step "$2" --invariant "$3" \
    --max-steps "$STEPS" --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $4 == violation && $out == *"[violation]"* ]]; then
    note "run $1 --step $2 $3" "$4 (as expected)"
  else bad "run $1 --step $2 $3" "wanted $4, rc=$rc"; fi
}
# The generator's own safety net: traces drawn with stepLin satisfy Safety
# and never show the cross-domain gap; without the restriction the gap is
# reached (so the restriction is what removes it, and it is not vacuous).
qrun refs_mbt2 stepLin LinSafety ok
qrun refs_mbt3 stepLin LinSafety ok
SAMPLES=${GAP_SAMPLES:-20000} qrun refs_mbt3 stepAll NoCrossDomainGap violation

OUT=$FIXTURES
[[ ${CHECK:-0} == 1 ]] && OUT=$WORK/fixtures
mkdir -p "$OUT"
for t in $TRACES; do
  main=${t%%:*}
  seed=${t#*:}
  name="$main-seed$seed.itf.json"
  raw="$WORK/raw-$name"
  rc=0
  quint run refs_mbt.qnt --main "$main" --init initLin --step stepLin --invariant LinSafety \
    --mbt --max-steps "$STEPS" --max-samples 1 --backend rust --seed="$seed" \
    --out-itf "$raw" >/dev/null 2>&1 || rc=$?
  if [[ $rc != 0 || ! -s $raw ]]; then bad "trace $main seed $seed" "quint run rc=$rc"; continue; fi
  jq -r --arg main "$main" --arg seed "$seed" --arg steps "$STEPS" --arg quint "$QV" '
    def keep: "^refsLin::refs::(disk|mem|lastAction|recLog|nextEntry|violations)$";
    def short: sub("^refsLin::refs::"; "");
    {
      format: "ITF",
      "format-description": "https://apalache-mc.org/docs/adr/015adr-trace.html",
      source: "formal/quint/refs/refs_mbt.qnt",
      main: $main, init: "initLin", step: "stepLin", invariant: "LinSafety",
      seed: $seed, "max-steps": ($steps | tonumber), quint: $quint,
      generator: "formal/scripts/gen-refs-traces.sh"
    } as $meta
    | ([.vars[] | select(test(keep)) | short] | unique) as $vars
    | [.states[] | with_entries(select(.key == "#meta" or (.key | test(keep))) | .key |= short)] as $states
    | "{\"#meta\":\($meta | tojson),\n\"vars\":\($vars | tojson),\n\"states\":[\n"
      + ($states | map(tojson) | join(",\n")) + "\n]}"
  ' "$raw" > "$OUT/$name"
  note "trace $main seed $seed ($(jq '.states | length' "$OUT/$name") states)" "ok (as expected)"
done

if [[ ${CHECK:-0} == 1 ]]; then
  if diff -r "$FIXTURES" "$OUT" >/dev/null; then note "fixtures reproduce byte-for-byte" "ok (as expected)"
  else bad "fixtures reproduce byte-for-byte" "diff -r $FIXTURES <regenerated> differs"; fi
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
