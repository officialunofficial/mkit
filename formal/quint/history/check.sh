#!/usr/bin/env bash
# Reproduce every MKIT-20 history check: `./check.sh` (quint + TLC, ~7 min),
# `APALACHE=1 ./check.sh` adds bounded Apalache runs (history depth
# ${HISTORY_DEPTH:-10} takes ~26 min). Needs quint 0.32, java and
# ${TLA2TOOLS:-/opt/fv/tla2tools.jar}; Apalache from ${APALACHE_MC:-/opt/fv/apalache/bin/apalache-mc}.
set -euo pipefail
cd "$(dirname "$0")"
TLA2TOOLS=${TLA2TOOLS:-/opt/fv/tla2tools.jar}
APALACHE_MC=${APALACHE_MC:-/opt/fv/apalache/bin/apalache-mc}
APA_JAR=$(dirname "$APALACHE_MC")/../lib/apalache.jar
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
fails=0
note() { printf '%-58s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }

# quint run: $1 file, $2 module, $3 invariant, $4 expect ok|violation
qrun() {
  local out rc=0
  out=$(quint run "$1" --main "$2" --invariant "$3" --max-steps "${5:-30}" \
    --max-samples "${6:-50000}" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 ]] || [[ $4 == violation && $out == *"[violation]"* ]]; then
    note "run $2::$3" "$4 (as expected)"
  else bad "run $2::$3" "wanted $4, rc=$rc"; fi
}
# compile $2 of $1 with invariants $3 to $4.tla (module renamed to $4)
tla() {
  quint compile --target tlaplus --main "$2" --invariant "$3" "$1" 2>/dev/null |
    sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE $4/" > "$5/$4.tla"
  (cd "$5" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
}
# TLC: $1 dir, $2 wrapper module, $3 expect ok|violation
tlc() {
  local rc=0
  (cd "$1" && java -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC -workers auto \
    -deadlock -config "$2.cfg" "$2.tla" > tlc.out 2>&1) || rc=$?
  local stats; stats=$(grep -E 'distinct states found' "$1/tlc.out" | tail -1 || true)
  if [[ $3 == ok && $rc == 0 ]] || [[ $3 == violation && $rc == 12 ]]; then
    note "tlc $1" "$3 (as expected) ${stats%%,*}"
  else bad "tlc $1" "wanted $3, rc=$rc"; fi
}

quint typecheck history.qnt && quint typecheck scrub.qnt
quint test history.qnt --main history --max-samples 1 >/dev/null && note "test history" ok
quint test scrub.qnt --main scrub >/dev/null && note "test scrub (real 512/64 lap)" ok

# ---- history.qnt ------------------------------------------------------------
qrun history.qnt history Safety ok
for c in CanaryNeverServed CanaryNoCrashRecovery CanaryNoMultiCommitFF \
  CanaryNoRecreate CanaryNoGcDuringIntent CanaryNoServedFF; do
  qrun history.qnt history "$c" violation
done
for m in mutLoadIgnoresTx:NoProofWhileIntent mutRawIgnoresTx:RecoveryEnabled \
  mutRawIgnoresTx:NeverFailsClosed mutRawSkipsInvalidate:GenerationFastForwardOnly \
  mutRawSkipsInvalidate:ServedGenerationFresh mutGcIgnoresIntent:IntentRootsRetained \
  mutHealTipOnly:CurrentMatchesRef mutReuseGenOnRewrite:GenerationFastForwardOnly; do
  qrun history.qnt "${m%%:*}" "${m##*:}" violation
done
# ---- scrub.qnt ----------------------------------------------------------------
for i in ActualPublishBound TimeBound InvalidForcesFull; do qrun scrub.qnt scrub "$i" ok 14; done
qrun scrub.qnt scrubLossy TimeBound ok 14
qrun scrub.qnt scrubLossy InvalidForcesFull ok 14
qrun scrub.qnt scrubClockBack ActualPublishBound ok 14
for c in CanaryNoWindow CanaryNoLapFull; do qrun scrub.qnt scrub "$c" violation 14; done
qrun scrub.qnt mutIgnoreAge TimeBound violation 14
qrun scrub.qnt mutWrapWithoutFull ActualPublishBound violation 14
# findings: spec claims the implementation does not meet
qrun scrub.qnt scrub SpecPublishBound violation 14
qrun scrub.qnt scrub WindowOnlyWhenFresh violation 14
qrun scrub.qnt scrubLossy ActualPublishBound violation 14
qrun scrub.qnt scrubClockBack TimeBound violation 14

# ---- TLC: exhaustive over the finite instances -----------------------------
for m in history mutLoadIgnoresTx mutRawSkipsInvalidate mutHealTipOnly mutGcIgnoresIntent \
  mutRawIgnoresTx mutReuseGenOnRewrite; do
  d="$WORK/tlc-$m"; mkdir -p "$d"
  tla history.qnt "$m" Safety history "$d"
  sed "s/history_historyCore_/${m}_historyCore_/g" tlc/MC.tla > "$d/MC.tla"
  cp tlc/MC.cfg "$d/"
  [[ $m == history ]] && tlc "$d" MC ok || tlc "$d" MC violation
done
d="$WORK/tlc-scrub"; mkdir -p "$d"
tla scrub.qnt scrubUnbounded ActualPublishBound,TimeBound,InvalidForcesFull scrubUnbounded "$d"
cp tlc/MCS.tla tlc/MCS.cfg "$d/"; tlc "$d" MCS ok
d="$WORK/tlc-scrub-spec"; mkdir -p "$d"
tla scrub.qnt scrubUnbounded SpecPublishBound scrubUnbounded "$d"
cp tlc/MCS.tla tlc/MCS.cfg "$d/"; tlc "$d" MCS violation

# ---- Apalache: bounded symbolic ------------------------------------------------
if [[ ${APALACHE:-0} == 1 ]]; then
  apa() { # $1 file $2 module $3 invariant $4 length $5 expect
    local d="$WORK/apa-$2-$3" rc=0; mkdir -p "$d"
    tla "$1" "$2" "$3" M "$d"
    (cd "$d" && "$APALACHE_MC" check --init=q_init --next=q_step --inv=q_inv \
      --length="$4" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
    if [[ $5 == ok && $rc == 0 ]] || [[ $5 == violation && $rc == 12 ]]; then
      note "apalache $2::$3 (length $4)" "$5 (as expected)"
    else bad "apalache $2::$3 (length $4)" "wanted $5, rc=$rc"; fi
  }
  apa history.qnt history Safety "${HISTORY_DEPTH:-10}" ok
  apa history.qnt history CanaryNeverServed 7 violation
  apa history.qnt mutGcIgnoresIntent IntentRootsRetained 7 violation
  apa scrub.qnt scrub ActualPublishBound,TimeBound,InvalidForcesFull 8 ok
  apa scrub.qnt scrub SpecPublishBound 8 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
