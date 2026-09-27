#!/usr/bin/env bash
# Reproduce every history check (MKIT-20, pins from MKIT-17):
#   ./check.sh               quint typecheck/test/run + TLC safety and progress
#   APALACHE=1 ./check.sh    adds bounded Apalache runs on the compiled TLA+
#                            (history depth ${HISTORY_DEPTH:-10}; see README for timings)
# Pins: quint 0.32.0, Java 21, Apalache 0.62.2 (run directly on the TLA+ that
# `quint compile` emits, never through `quint verify`), and TLC from the
# tlc2.TLC class inside that Apalache jar. Tool locations default to
# ${FV_HOME:-$HOME/.local/share/mkit-fv}/apalache-0.62.2 and can be overridden
# with APALACHE_MC and TLA2TOOLS. Heaps: TLC ${TLC_HEAP:-4g} with
# ${TLC_WORKERS:-4} workers, Apalache JVM_ARGS (default -Xmx4g).
set -euo pipefail
cd "$(dirname "$0")"
FV_HOME=${FV_HOME:-$HOME/.local/share/mkit-fv}
APALACHE_MC=${APALACHE_MC:-$FV_HOME/apalache-0.62.2/bin/apalache-mc}
APA_JAR=$(dirname "$APALACHE_MC")/../lib/apalache.jar
TLA2TOOLS=${TLA2TOOLS:-$APA_JAR}
TLC_HEAP=${TLC_HEAP:-4g}
TLC_WORKERS=${TLC_WORKERS:-4}
export JVM_ARGS=${JVM_ARGS:--Xmx4g}
# JAVA_HOME: caller's, else macOS java_home -v 21, else a Homebrew openjdk@21
# (keg-only, so java_home does not list it unless it has been symlinked).
if [[ -z ${JAVA_HOME:-} && -x /usr/libexec/java_home ]]; then
  JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null || true)
fi
if [[ -z ${JAVA_HOME:-} ]] && command -v brew >/dev/null; then
  JAVA_HOME=$(brew --prefix openjdk@21 2>/dev/null || true)
  [[ -x $JAVA_HOME/bin/java ]] || JAVA_HOME=
fi
if [[ -n ${JAVA_HOME:-} ]]; then export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"; fi
java -version 2>&1 | grep -q '"21' ||
  { echo "check.sh: needs Java 21 (set JAVA_HOME)" >&2; exit 2; }
for f in "$APA_JAR" "$TLA2TOOLS"; do
  [[ -f $f ]] || { echo "check.sh: missing $f (set FV_HOME, APALACHE_MC or TLA2TOOLS)" >&2; exit 2; }
done
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
trap 'echo "check.sh: aborted at line $LINENO (unexpected error)" >&2' ERR
fails=0
note() { printf '%-66s %s\n' "$1" "$2"; }
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
# compile module $2 of $1 with invariants $3 into $5/$4.tla (module renamed to $4)
# `quint compile` starts quint's bundled Apalache server on a fixed port, so a
# concurrent quint on the same machine can make it fail; retry a few times.
tla() {
  local try
  for try in 1 2 3 4 5; do
    { quint compile --target tlaplus --main "$2" --invariant "$3" "$1" 2>"$5/compile.err" |
      sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE $4/" > "$5/$4.tla"; } || true
    grep -q '^====' "$5/$4.tla" && break
    sleep $((try * 5))
  done
  grep -q '^====' "$5/$4.tla" ||
    { echo "check.sh: quint compile of $2 failed (see $5/compile.err)" >&2; return 1; }
  (cd "$5" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
}
# TLC: $1 dir, $2 wrapper module, $3 cfg, $4 expect ok|violation|liveness, $5 label.
# TLC exits 12 on a safety violation and 13 on a temporal (liveness) violation;
# each expectation accepts only its own code, so a mutant caught for the wrong
# reason is reported as unexpected.
tlc() {
  local rc=0
  (cd "$1" && java -Xmx"$TLC_HEAP" -XX:+UseParallelGC -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "$TLC_WORKERS" -deadlock -config "$3" "$2.tla" > "tlc-$3.out" 2>&1) || rc=$?
  local stats; stats=$(grep -E 'distinct states found' "$1/tlc-$3.out" | tail -1 |
    sed -E 's/^([0-9]+) states generated, ([0-9]+) distinct.*/\2 distinct/' || true)
  if [[ $4 == ok && $rc == 0 ]] || [[ $4 == violation && $rc == 12 ]] ||
    [[ $4 == liveness && $rc == 13 ]]; then
    note "tlc $5" "$4 (as expected) $stats"
  else bad "tlc $5" "wanted $4, rc=$rc"; fi
}
# Stage the history wrappers for module $1 (compiled with invariant $2) in $3.
stage_history() {
  mkdir -p "$3"
  tla history.qnt "$1" "$2" history "$3"
  for f in MC.tla MCL.tla; do
    sed "s/history_historyCore_/${1}_historyCore_/g" "tlc/$f" > "$3/$f"
  done
  cp tlc/MC.cfg tlc/MCL.cfg tlc/MCL-nofair.cfg tlc/MCL-canary.cfg "$3/"
}

quint typecheck history.qnt && quint typecheck scrub.qnt
quint test history.qnt --main history --max-samples 1 >/dev/null && note "test history" ok
quint test scrub.qnt --main scrub >/dev/null && note "test scrub (real 512/64 lap)" ok

# Each mutant paired with the one invariant it must break (non-vacuity).
MUTANTS=(mutLoadIgnoresTx:NoProofWhileIntent mutRawIgnoresTx:RecoveryEnabled
  mutRawIgnoresTx:NeverFailsClosed mutRawSkipsInvalidate:GenerationFastForwardOnly
  mutRawSkipsInvalidate:ServedGenerationFresh mutGcIgnoresIntent:IntentRootsRetained
  mutHealTipOnly:CurrentMatchesRef mutReuseGenOnRewrite:GenerationFastForwardOnly
  mutFreshGenOnFF:FastForwardRetainsGeneration mutSkipVerify:IntentRootsRetained
  mutFinishAnyRef:FinishOnlyFromRecorded mutWriteBeforeInvalidate:CurrentMatchesRef)

# ---- history.qnt: quint simulation --------------------------------------------
qrun history.qnt history Safety ok
for c in CanaryNeverServed CanaryNoCrashRecovery CanaryNoMultiCommitFF \
  CanaryNoRecreate CanaryNoGcDuringIntent CanaryNoServedFF; do
  qrun history.qnt history "$c" violation
done
for m in "${MUTANTS[@]}"; do qrun history.qnt "${m%%:*}" "${m##*:}" violation; done
# load's intent check is defence in depth: served descriptors stay correct without it
qrun history.qnt mutLoadIgnoresTx ServedMatchesRef ok
qrun history.qnt mutLoadIgnoresTx ServedGenerationFresh ok
# the stuck-recovery mutant is invisible to every safety invariant
qrun history.qnt mutRecoverSkipsPending Safety ok

# ---- scrub.qnt: quint simulation ------------------------------------------------
for i in ActualPublishBound TimeBound InvalidForcesFull; do qrun scrub.qnt scrub "$i" ok 16; done
qrun scrub.qnt scrubLossy TimeBound ok 16
qrun scrub.qnt scrubLossy InvalidForcesFull ok 16
qrun scrub.qnt scrubClockBack ActualPublishBound ok 16
for c in CanaryNoWindow CanaryNoLapFull; do qrun scrub.qnt scrub "$c" violation 16; done
qrun scrub.qnt mutIgnoreAge TimeBound violation 16
qrun scrub.qnt mutWrapWithoutFull ActualPublishBound violation 16
qrun scrub.qnt mutTrustInvalid InvalidForcesFull violation 16
# finding 2 (MKIT-57, fixed): window path only when fewer than MAX_AGE elapsed;
# the pre-fix `>` comparison is the mutant that must break it
qrun scrub.qnt scrub WindowOnlyWhenFresh ok 16
qrun scrub.qnt mutAgeInclusive WindowOnlyWhenFresh violation 16
# findings: bounds the implementation does not meet
qrun scrub.qnt scrub SpecPublishBound violation 16     # a lap is 65 publishes, not 64
qrun scrub.qnt scrubLossy ActualPublishBound violation 16  # lost advisory scrub write
qrun scrub.qnt scrubClockBack TimeBound violation 16

# ---- TLC: exhaustive over the finite instances -----------------------------------
d="$WORK/tlc-history"; stage_history history Safety "$d"
tlc "$d" MC MC.cfg ok "history::Safety"
tlc "$d" MCL MCL.cfg ok "history::IntentEventuallyCleared"
tlc "$d" MCL MCL-nofair.cfg liveness "history::IntentEventuallyCleared (no recover fairness)"
tlc "$d" MCL MCL-canary.cfg violation "history::CanaryNoCalmIntent"
for m in "${MUTANTS[@]}"; do
  mod=${m%%:*} inv=${m##*:}
  d="$WORK/tlc-$mod-$inv"; stage_history "$mod" "$inv" "$d"
  tlc "$d" MC MC.cfg violation "$mod::$inv"
done
d="$WORK/tlc-mutRecoverSkipsPending"; stage_history mutRecoverSkipsPending Safety "$d"
tlc "$d" MC MC.cfg ok "mutRecoverSkipsPending::Safety"
tlc "$d" MCL MCL.cfg liveness "mutRecoverSkipsPending::IntentEventuallyCleared"
d="$WORK/tlc-mutRawIgnoresTx-live"; stage_history mutRawIgnoresTx Safety "$d"
tlc "$d" MCL MCL.cfg liveness "mutRawIgnoresTx::IntentEventuallyCleared"

for i in ActualPublishBound TimeBound InvalidForcesFull; do
  d="$WORK/tlc-scrub-$i"; mkdir -p "$d"
  tla scrub.qnt scrubUnbounded "$i" scrubUnbounded "$d"
  cp tlc/MCS.tla tlc/MCS.cfg "$d/"; tlc "$d" MCS MCS.cfg ok "scrubUnbounded::$i"
done
d="$WORK/tlc-scrub-spec"; mkdir -p "$d"
tla scrub.qnt scrubUnbounded SpecPublishBound scrubUnbounded "$d"
cp tlc/MCS.tla tlc/MCS.cfg "$d/"; tlc "$d" MCS MCS.cfg violation "scrubUnbounded::SpecPublishBound"

# ---- Apalache 0.62.2: bounded symbolic, directly on the compiled TLA+ ------------
if [[ ${APALACHE:-0} == 1 ]]; then
  apa() { # $1 file $2 module $3 invariant $4 length $5 expect
    local d="$WORK/apa-$2-$3" rc=0 t0=$SECONDS; mkdir -p "$d"
    tla "$1" "$2" "$3" M "$d"
    (cd "$d" && "$APALACHE_MC" check --init=q_init --next=q_step --inv=q_inv \
      --length="$4" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
    local dt=$((SECONDS - t0))
    if [[ $5 == ok && $rc == 0 ]] || [[ $5 == violation && $rc == 12 ]]; then
      note "apalache $2::$3 (length $4)" "$5 (as expected, ${dt}s)"
    else bad "apalache $2::$3 (length $4)" "wanted $5, rc=$rc"; fi
  }
  apa history.qnt history Safety "${HISTORY_DEPTH:-10}" ok
  apa history.qnt history CanaryNeverServed 7 violation
  apa history.qnt mutGcIgnoresIntent IntentRootsRetained 7 violation
  apa history.qnt mutFreshGenOnFF FastForwardRetainsGeneration 8 violation
  apa history.qnt mutSkipVerify IntentRootsRetained 7 violation
  apa history.qnt mutFinishAnyRef FinishOnlyFromRecorded 7 violation
  apa history.qnt mutWriteBeforeInvalidate CurrentMatchesRef 7 violation
  apa scrub.qnt scrub ActualPublishBound,TimeBound,InvalidForcesFull,WindowOnlyWhenFresh 8 ok
  apa scrub.qnt mutAgeInclusive WindowOnlyWhenFresh 8 violation
  apa scrub.qnt scrub SpecPublishBound 8 violation
  apa scrub.qnt mutTrustInvalid InvalidForcesFull 8 violation
  apa scrub.qnt scrubLossy ActualPublishBound 8 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
