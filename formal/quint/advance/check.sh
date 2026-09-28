#!/usr/bin/env bash
# Reproduce every quint-advance check (MKIT-27 / MKIT-17): advance.qnt, the
# advance_refs model (packmap CAS then head CAS, crashes and lost responses,
# the retry ladder, the read_ref disambiguation, concurrent pushers, the
# #521 re-baseline gate).
#
#   ./check.sh               quint typecheck + test + run, then TLC
#   TLC=0 ./check.sh         skip TLC
#   APALACHE=1 ./check.sh    add bounded apalache-mc runs on the compiled TLA+
#   QUINT=0 skips `quint run`; ONLY=<regex> restricts TLC/Apalache to
#   matching "<module>::<invariant>" checks.
#
# Pins (MKIT-17 review): quint 0.32.0, Apalache 0.62.2 run directly on the
# compiled TLA+ (not `quint verify`), TLC = tlc2.TLC from the Apalache 0.62.2
# jar, Java 21. Tool locations (override any of them):
#   FV_HOME     ${FV_HOME:-$HOME/.local/share/mkit-fv}
#   APALACHE_MC $FV_HOME/apalache-0.62.2/bin/apalache-mc
#   TLA2TOOLS   $FV_HOME/apalache-0.62.2/lib/apalache.jar   (holds tlc2.TLC)
#   JAVA_HOME   else `/usr/libexec/java_home -v 21`, else Homebrew's openjdk@21
# Memory: TLC -Xmx${TLC_HEAP:-4g}, ${TLC_WORKERS:-2} workers; Apalache
# JVM_ARGS=-Xmx${APALACHE_HEAP:-4g}.
#
# Every line printed is "<check>  <expected outcome> (as expected)" or
# "UNEXPECTED: ...". `ok` = the invariant holds (within the stated bound);
# `violation` = a mutant, canary or documented-gap witness the checker must
# reach (non-vacuity, or a finding). The script exits 1 on any unexpected
# outcome.
set -euo pipefail
cd "$(dirname "$0")"
HERE=$PWD

FV_HOME=${FV_HOME:-$HOME/.local/share/mkit-fv}
APALACHE_MC=${APALACHE_MC:-$FV_HOME/apalache-0.62.2/bin/apalache-mc}
TLA2TOOLS=${TLA2TOOLS:-$FV_HOME/apalache-0.62.2/lib/apalache.jar}
APA_JAR=$(dirname "$APALACHE_MC")/../lib/apalache.jar
if [[ -z ${JAVA_HOME:-} ]]; then
  JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null || true)
  [[ -z $JAVA_HOME && -d /opt/homebrew/opt/openjdk@21 ]] && JAVA_HOME=/opt/homebrew/opt/openjdk@21
fi
if [[ -n ${JAVA_HOME:-} ]]; then export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"; fi
export JVM_ARGS="${JVM_ARGS:--Xmx${APALACHE_HEAP:-4g}}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
trap 'echo "check.sh: aborted at line $LINENO (unexpected error)" >&2' ERR
fails=0
note() { printf '%-64s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }
STEPS=${STEPS:-40}
SAMPLES=${SAMPLES:-20000}
F=advance.qnt

# quint run: $1 module, $2 invariant, $3 expect ok|violation
qrun() {
  [[ ${QUINT:-1} == 1 ]] || return 0
  local out rc=0
  out=$(quint run "$F" --main "$1" --invariant "$2" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $3 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $3 == violation && $out == *"[violation]"* ]]; then
    note "run $1::$2" "$3 (as expected)"
  else bad "run $1::$2" "wanted $3, rc=$rc"; fi
}

# Compile module $1 with invariant $2 into $3/M.tla (module renamed M).
# quint compile translates through its bundled Apalache server (transpiling
# only; checking is done by the pinned apalache-mc / TLC); run it inside $3 so
# its _apalache-out lands there.
# The transpiler runs quint's bundled Apalache server, which concurrent
# checks on the same machine share; retry a failed transpile (3 tries) and
# fail the check, not the script, if it keeps failing.
compile() {
  mkdir -p "$3"
  local try out
  for try in 1 2 3; do
    if out=$(cd "$3" && quint compile --target tlaplus --main "$1" --invariant "$2" "$HERE/$F" 2>"$3/compile.err") &&
       [[ $out == *"MODULE"* ]]; then
      printf '%s\n' "$out" | sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE M/" > "$3/M.tla"
      (cd "$3" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
        tla2sany/StandardModules/Variants.tla)
      return 0
    fi
    sleep $((try * 5))
  done
  return 1
}

# Apalache (bounded symbolic, apalache-mc directly): $1 module, $2 invariant,
# $3 length, $4 expect.
apa() {
  [[ -n ${ONLY:-} && ! "$1::$2" =~ $ONLY ]] && return 0
  local d="$WORK/apa-$1-$2-$3" rc=0 t0=$SECONDS
  compile "$1" "$2" "$d" || { bad "apalache $1::$2 (length $3)" "quint compile failed"; tail -5 "$d/compile.err" >&2; return 0; }
  (cd "$d" && "$APALACHE_MC" check --init=q_init --next=q_step --inv=q_inv \
    --length="$3" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 ]] || [[ $4 == violation && $rc == 12 ]]; then
    note "apalache $1::$2 (length $3)" "$4 (as expected) $((SECONDS - t0))s"
  else bad "apalache $1::$2 (length $3)" "wanted $4, rc=$rc"; tail -5 "$d/apa.out" >&2; fi
}

# TLC, exhaustive over the reachable states: $1 module, $2 invariant,
# $3 expect, $4 "view" to drop lastAction (sound for Safety, Progress and
# their conjuncts: no guard and none of them reads lastAction; NOT for the
# canaries that read it), else "".
tlc() {
  local rc=0 P t0=$SECONDS
  [[ -n ${ONLY:-} && ! "$1::$2" =~ $ONLY ]] && return 0
  local d="$WORK/tlc-$1-$2"
  compile "$1" "$2" "$d" || { bad "tlc $1::$2" "quint compile failed"; tail -5 "$d/compile.err" >&2; return 0; }
  # quint prefixes each name with <main>_<module>_ (read off q_init).
  P=$(sed -n 's/^q_init == \(.*_\)init$/\1/p' "$d/M.tla")
  {
    echo "---- MODULE MC ----"
    echo "EXTENDS M"
    if [[ $4 == view ]]; then
      echo "View == << @hd, @pm, @ps, @stored, @landed, @wrote, @overwritten, @lostUpdate >>"
    fi
    echo "===="
  } | sed "s/@/${P}/g" > "$d/MC.tla"
  {
    printf 'INIT q_init\nNEXT q_step\nINVARIANT q_inv\nCHECK_DEADLOCK FALSE\n'
    if [[ $4 == view ]]; then echo "VIEW View"; fi
  } > "$d/MC.cfg"
  (cd "$d" && java -XX:+UseParallelGC -Xmx${TLC_HEAP:-4g} -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "${TLC_WORKERS:-2}" -config MC.cfg MC.tla > tlc.out 2>&1) || rc=$?
  local stats; stats=$(grep -oE '[0-9]+ distinct states found' "$d/tlc.out" | tail -1 || true)
  if [[ $3 == ok && $rc == 0 ]] || [[ $3 == violation && $rc == 12 ]]; then
    note "tlc $1::$2" "$3 (as expected) ${stats:+$stats, }$((SECONDS - t0))s"
  else bad "tlc $1::$2" "wanted $3, rc=$rc"; tail -5 "$d/tlc.out" >&2; fi
}

# TLC temporal check of Termination (every pusher reaches done or dead) under
# weak fairness of the whole step relation: $1 module, $2 expect ok|violation.
# No VIEW (TLC does not combine VIEW with liveness checking). A liveness
# violation is TLC exit code 13.
live() {
  local rc=0 P t0=$SECONDS
  [[ -n ${ONLY:-} && ! "$1::Termination" =~ $ONLY ]] && return 0
  local d="$WORK/live-$1"
  compile "$1" All "$d" || { bad "tlc $1::Termination" "quint compile failed"; tail -5 "$d/compile.err" >&2; return 0; }
  P=$(sed -n 's/^q_init == \(.*_\)init$/\1/p' "$d/M.tla")
  {
    echo "---- MODULE MC ----"
    echo "EXTENDS M"
    echo "Vars == << @hd, @pm, @ps, @stored, @landed, @wrote, @overwritten, @lostUpdate, @lastAction >>"
    echo "Spec == q_init /\\ [][q_step]_Vars /\\ WF_Vars(q_step)"
    echo "Termination == <>(\\A i \\in @PIDS : @ps[i][\"pc\"] \\in {\"done\", \"dead\"})"
    echo "===="
  } | sed "s/@/${P}/g" > "$d/MC.tla"
  printf 'SPECIFICATION Spec\nPROPERTY Termination\nCHECK_DEADLOCK FALSE\n' > "$d/MC.cfg"
  (cd "$d" && java -XX:+UseParallelGC -Xmx${TLC_HEAP:-4g} -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "${TLC_WORKERS:-2}" -config MC.cfg MC.tla > tlc.out 2>&1) || rc=$?
  local stats; stats=$(grep -oE '[0-9]+ distinct states found' "$d/tlc.out" | tail -1 || true)
  if [[ $2 == ok && $rc == 0 ]] && grep -q "Finished checking temporal properties" "$d/tlc.out" ||
     [[ $2 == violation && $rc == 13 ]]; then
    note "tlc $1::Termination" "$2 (as expected) ${stats:+$stats, }$((SECONDS - t0))s"
  else bad "tlc $1::Termination" "wanted $2, rc=$rc"; tail -5 "$d/tlc.out" >&2; fi
}

# ---- typecheck + deterministic scenarios ------------------------------------
quint typecheck advance.qnt && quint typecheck advance_test.qnt
for m in ordered_test ordered_oldConflict_test ledger_test atomic_test noGate_test \
  splitCas_test gapNoopAny_test gapHttpAny_test gapTwoAny_test gapAppendAny_test splitCasFF_test; do
  quint test advance_test.qnt --main "$m" >/dev/null && note "test $m" ok || bad "test $m" failed
done

# Instances (advance.qnt, bottom): SAFE = Safety and Progress must hold.
SAFE2="ordered2 atomic2 ledger2 http1 forceFF2 noop2 ledger2_oldConflict"
SAFE3="ordered3 atomic3 ledger3 atomicAny3"

# ---- quint run: random simulation --------------------------------------------
for m in $SAFE2 $SAFE3; do qrun "$m" All ok; done
# Documented gaps (findings F1, F2 in README.md): DeltaTransfer is violated.
qrun gapHttpAny2 DeltaTransfer violation
qrun gapNoopAny2 DeltaTransfer violation
qrun gapAppendAny2 DeltaTransfer violation
qrun gapAppendTwoAny3 DeltaTransfer violation
# Mutants.
qrun ordered2_oldConflict ConflictHonest violation
qrun atomic2_oldConflict ConflictHonest violation
qrun ordered2_trustConflict SuccessSound violation
qrun ordered2_noGate DeltaTransfer violation
qrun http1_gateNoAny DeltaTransfer violation
qrun ordered2_headFirst DeltaTransfer violation
qrun ordered2_noTimeout NoStuckPusher violation
qrun ordered2_splitCas NoLostSuccess violation
# noop2_splitCas needs a 6-step pinned interleaving that random simulation
# does not hit at this budget: splitCas_test pins it, and TLC finds it below.
# Canaries (reachability).
for c in CanaryNoReset CanaryNoReissueAfterLanded CanaryNoDisambiguatedSuccess CanaryNoNff \
  CanaryNoPackmapConflict; do qrun atomic2 "$c" violation; done
for c in CanaryNoAppendSuccess CanaryNoTornAdvance CanaryNoReissueAfterLanded \
  CanaryNoDisambiguatedSuccess CanaryNoPackmapConflict; do qrun ordered2 "$c" violation; done
qrun ledger2 CanaryNoReplayed violation
qrun ordered3 CanaryNoConcurrentSuccess violation
# Residual ambiguity of the read_ref rule (documented, README.md): a landed
# push whose tip another pusher then built on is reported NonFastForward.
qrun ordered3 WitnessLandedThenNff violation
qrun atomic3 WitnessLandedThenNff violation

# ---- TLC: exhaustive ---------------------------------------------------------
if [[ ${TLC:-1} == 1 ]]; then
  for m in $SAFE2; do tlc "$m" All ok view; done
  tlc gapHttpAny2 DeltaTransfer violation view
  tlc gapNoopAny2 DeltaTransfer violation view
  tlc ordered2_oldConflict ConflictHonest violation view
  tlc atomic2_oldConflict ConflictHonest violation view
  tlc ordered2_trustConflict SuccessSound violation view
  tlc ordered2_noGate DeltaTransfer violation view
  tlc http1_gateNoAny DeltaTransfer violation view
  tlc ordered2_headFirst DeltaTransfer violation view
  tlc noop2_splitCas NoLostUpdate violation view
  tlc ordered2_noTimeout NoStuckPusher violation view
  tlc ordered2_splitCas NoLostSuccess violation view
  tlc gapAppendAny2 DeltaTransfer violation view
  # Termination as a TLC temporal property (weak fairness, no VIEW).
  for m in $SAFE2; do live "$m" ok; done
  live ordered2_noTimeout violation
  live ordered2_noLadderBound violation
  # Canaries need lastAction: no VIEW.
  tlc ordered2 CanaryNoTornAdvance violation ""
  tlc atomic2 CanaryNoReissueAfterLanded violation ""
  tlc ordered2 CanaryNoDisambiguatedSuccess violation ""
  # 3 pushers, exhaustive (see README.md for the measured state counts).
  if [[ ${TLC3:-1} == 1 ]]; then
    for m in $SAFE3; do tlc "$m" All ok view; done
    tlc gapTwoAny3 DeltaTransfer violation view
    tlc gapAppendTwoAny3 DeltaTransfer violation view
  fi
fi

# ---- Apalache: bounded symbolic ----------------------------------------------
if [[ ${APALACHE:-0} == 1 ]]; then
  D=${ADV_DEPTH:-8}   # length 12 on ordered2 alone exceeds 35 min
  for m in ordered2 atomic2 ledger2; do apa "$m" All "$D" ok; done
  apa ordered2_oldConflict ConflictHonest 10 violation   # the pinned 10-step witness
  apa ordered2_noGate DeltaTransfer 8 violation
  apa gapNoopAny2 DeltaTransfer 5 violation
  apa gapHttpAny2 DeltaTransfer 7 violation
  apa gapTwoAny3 DeltaTransfer 8 violation
  apa gapAppendAny2 DeltaTransfer 6 violation   # the pinned 6-step witness
  apa noop2_splitCas NoLostUpdate 7 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
