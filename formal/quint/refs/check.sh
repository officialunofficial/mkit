#!/usr/bin/env bash
# Reproduce every quint-refs check (MKIT-17 / MKIT-19): refs.qnt (ref CAS and
# lock order) and serve.qnt (serve.lock / server.lock, the startup upload
# sweep, the served-name rule).
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
# reach (non-vacuity). The script exits 1 on any unexpected outcome.
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

# quint run: $1 file, $2 module, $3 invariant, $4 expect ok|violation
qrun() {
  [[ ${QUINT:-1} == 1 ]] || return 0
  local out rc=0
  out=$(quint run "$1" --main "$2" --invariant "$3" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $4 == violation && $out == *"[violation]"* ]]; then
    note "run $2::$3" "$4 (as expected)"
  else bad "run $2::$3" "wanted $4, rc=$rc"; fi
}

# Compile module $2 of $1 with invariant $3 into $4/M.tla (module renamed M).
# quint compile translates through its bundled Apalache server (transpiling
# only; checking is done by the pinned apalache-mc / TLC); run it inside $4 so
# its _apalache-out lands there.
compile() {
  mkdir -p "$4"
  (cd "$4" && quint compile --target tlaplus --main "$2" --invariant "$3" "$HERE/$1" 2>/dev/null) |
    sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE M/" > "$4/M.tla"
  (cd "$4" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
}

# Apalache (bounded symbolic, apalache-mc directly): $1 file, $2 module,
# $3 invariant, $4 length, $5 expect.
apa() {
  [[ -n ${ONLY:-} && ! "$2::$3" =~ $ONLY ]] && return 0
  local d="$WORK/apa-$2-$3-$4" rc=0
  compile "$1" "$2" "$3" "$d"
  (cd "$d" && "$APALACHE_MC" check --init=q_init --next=q_step --inv=q_inv \
    --length="$4" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
  if [[ $5 == ok && $rc == 0 ]] || [[ $5 == violation && $rc == 12 ]]; then
    note "apalache $2::$3 (length $4)" "$5 (as expected)"
  else bad "apalache $2::$3 (length $4)" "wanted $5, rc=$rc"; tail -5 "$d/apa.out" >&2; fi
}

# TLC (exhaustive over the reachable states, or under CONSTRAINT $6):
# $1 file, $2 module, $3 invariant, $4 expect, $5 VIEW expression (or ""),
# $6 CONSTRAINT expression (or ""), optional $7 extra MC definitions and $8
# extra cfg lines (e.g. `CONSTANT @KINDS <- SliceKinds`, TLC's operator
# substitution, to check a slice of the op space), $9 the slice's name.
# `@` is the name prefix.
tlc() {
  local e7=${7:-} e8=${8:-} slice=${9:-} rc=0 P
  [[ -n ${ONLY:-} && ! "$2::$3" =~ $ONLY ]] && return 0
  local d="$WORK/tlc-$2-$3-${slice:-all}"
  compile "$1" "$2" "$3" "$d"
  # quint prefixes each name with <main>_<module>_ (read off q_init).
  P=$(sed -n 's/^q_init == \(.*_\)init$/\1/p' "$d/M.tla")
  {
    echo "---- MODULE MC ----"
    echo "EXTENDS M"
    if [[ -n $5 ]]; then echo "View == $5"; fi
    if [[ -n $6 ]]; then echo "Constr == $6"; fi
    if [[ -n $e7 ]]; then printf '%s\n' "$e7"; fi
    echo "===="
  } | sed "s/@/${P}/g" > "$d/MC.tla"
  {
    printf 'INIT q_init\nNEXT q_step\nINVARIANT q_inv\nCHECK_DEADLOCK FALSE\n'
    if [[ -n $5 ]]; then echo "VIEW View"; fi
    if [[ -n $6 ]]; then echo "CONSTRAINT Constr"; fi
    if [[ -n $e8 ]]; then printf '%s\n' "$e8"; fi
  } | sed "s/@/${P}/g" > "$d/MC.cfg"
  (cd "$d" && java -XX:+UseParallelGC -Xmx${TLC_HEAP:-4g} -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "${TLC_WORKERS:-2}" -config MC.cfg MC.tla > tlc.out 2>&1) || rc=$?
  local stats; stats=$(grep -oE '[0-9]+ distinct states found' "$d/tlc.out" | tail -1 || true)
  if [[ $4 == ok && $rc == 0 ]] || [[ $4 == violation && $rc == 12 ]]; then
    note "tlc $2::$3${slice:+ [slice $slice]}${6:+ (constrained)}" "$4 (as expected) $stats"
  else bad "tlc $2::$3" "wanted $4, rc=$rc"; tail -5 "$d/tlc.out" >&2; fi
}

# ---- typecheck + deterministic scenarios ------------------------------------
quint typecheck refs.qnt && quint typecheck serve.qnt
quint typecheck refs_test.qnt && quint typecheck serve_test.qnt
quint test refs_test.qnt --main refs_test >/dev/null && note "test refs_test" ok || bad "test refs_test" failed
quint test serve_test.qnt --main serve_test >/dev/null && note "test serve_test" ok || bad "test serve_test" failed
quint test serve_test.qnt --main served_test >/dev/null && note "test served_test" ok || bad "test served_test" failed

# ---- refs.qnt: random simulation --------------------------------------------
qrun refs.qnt refs3 Safety ok
qrun refs.qnt refs2 Safety ok
for w in WitnessCrossDomainGap WitnessMatchConflict WitnessConditionalDelete \
  WitnessGcExpires WitnessTwoLocksContended; do
  qrun refs.qnt refs3 "$w" violation
done
qrun refs.qnt refs3_misorder NoDeadlock violation
qrun refs.qnt refs3_misorder LockOrderRespected violation
qrun refs.qnt refs2_noRefLock NoLostUpdateLocal violation
qrun refs.qnt refs2_noFileLock NoLostUpdateFile violation
qrun refs.qnt refs2_gcSkipTrees ExpireHoldsSuperset violation
qrun refs.qnt refs2_racyAcquire LockOwnership violation
qrun refs.qnt refs2_memNoMutex NoLostUpdateMem violation

# ---- serve.qnt: random simulation -------------------------------------------
qrun serve.qnt serve2 Safety ok
qrun serve.qnt serve3 Safety ok
for c in CanaryNoOrphanSwept CanaryNoSkippedSweep CanaryNoServeAndServer \
  CanaryNoStartDuringStalledUpload WitnessUndetectedLateServer; do
  qrun serve.qnt serve2 "$c" violation
done
qrun serve.qnt serve2_sweepUnlocked SweepAlone violation
qrun serve.qnt serve2_sweepUnderShared SweepAlone violation
qrun serve.qnt serve2_serverSkipsServe UpServersHoldServeShared violation
qrun serve.qnt serve2_serverSkipsServe NoMissedDetection violation
qrun serve.qnt serve2_serverLockShared OneMkitServer violation
qrun serve.qnt served Safety ok
for c in CanaryNoOutsideRefusal CanaryNoLongRefusal CanaryNoLegacySkipped CanaryNoAdvance; do
  qrun serve.qnt served "$c" violation
done
qrun serve.qnt served_checkAfterRead RefuseBeforeStorage violation
qrun serve.qnt served_checkAfterRead ExplicitRefusal violation
qrun serve.qnt served_headCheckedLate RefusedWritesNothing violation
qrun serve.qnt served_listNoSkip ListingServedOnly violation
# NoLiveUploadSwept's mutants need a 5-step pinned interleaving that random
# simulation rarely hits: serve_test.qnt pins them, and TLC finds them below.

# ---- TLC: exhaustive (serve.qnt) / constrained (refs.qnt) --------------------
if [[ ${TLC:-1} == 1 ]]; then
  # serve.qnt is finite: exhaustive, no VIEW, no CONSTRAINT.
  tlc serve.qnt serve2 Safety ok "" ""
  tlc serve.qnt serve3 Safety ok "" ""
  tlc serve.qnt serve2_sweepUnlocked NoLiveUploadSwept violation "" ""
  tlc serve.qnt serve2_sweepUnderShared NoLiveUploadSwept violation "" ""
  tlc serve.qnt serve2_serverSkipsServe NoLiveUploadSwept violation "" ""
  tlc serve.qnt serve2_serverLockShared OneMkitServer violation "" ""
  tlc serve.qnt serve2_ftSlow NoLiveUploadSwept violation "" ""
  tlc serve.qnt serve2 CanaryNoStartDuringStalledUpload violation "" ""
  tlc serve.qnt served Safety ok "" ""
  tlc serve.qnt served_checkAfterRead RefuseBeforeStorage violation "" ""
  tlc serve.qnt served_headCheckedLate RefusedWritesNothing violation "" ""
  tlc serve.qnt served_listNoSkip ListingServedOnly violation "" ""
  # refs.qnt: recLog / nextEntry grow without bound and the full op space
  # (8 kinds x trees x refs x conditions x values) of two processes exceeds a
  # 30-minute / 4 GB budget (measured: > 1.5 M distinct states at depth 4).
  # TLC therefore runs exhaustive SLICES: TLC operator substitution
  # (`CONSTANT @KINDS <- ...`) narrows the kinds and refs `begin` may pick;
  # both processes, every interleaving, CONSTRAINT nextEntry <= 2 (at most
  # one recovery record). The VIEW drops only lastAction, which no guard or
  # Safety conjunct reads (sound for Safety, not for lastAction canaries).
  RV='<< @disk, @mem, @owner, @procs, @recLog, @nextEntry, @faults, @violations, @lostRecords, @recordDuringExpire >>'
  RC='@nextEntry <= 2'
  # Slice "domains": the three §5.1 lock domains on one ref: local updateRef
  # (refs-<ref>.lock), file (RefLock: mkit serve / mkit-server / mkit+file://)
  # and mem (Mutex).
  DOMD=$'SliceKinds == {"updateRef", "file", "mem"}\nSliceRefs == {0}'
  DOMC=$'CONSTANT @KINDS <- SliceKinds\nCONSTANT @REFS <- SliceRefs'
  tlc refs.qnt refs2 Safety ok "$RV" "$RC" "$DOMD" "$DOMC" domains
  tlc refs.qnt refs2 WitnessCrossDomainGap violation "$RV" "$RC" "$DOMD" "$DOMC" domains
  tlc refs.qnt refs2_memNoMutex NoLostUpdateMem violation "$RV" "$RC" "$DOMD" "$DOMC" domains
  tlc refs.qnt refs2_noFileLock NoLostUpdateFile violation "$RV" "$RC" "$DOMD" "$DOMC" domains
  tlc refs.qnt refs2_noRefLock NoLostUpdateLocal violation "$RV" "$RC" "$DOMD" "$DOMC" domains
  # Slice "chain": the §4 lock chain and §3.2 record/expire, one ref.
  CHD=$'SliceKinds == {"commit", "amend", "branch", "checkout", "gc"}\nSliceRefs == {0}'
  tlc refs.qnt refs2 Safety ok "$RV" "$RC" "$CHD" "$DOMC" chain
  tlc refs.qnt refs2_misorder NoDeadlock violation "$RV" "$RC" "$CHD" "$DOMC" chain
  tlc refs.qnt refs2_gcSkipTrees NoRecordExpireInterleave violation "$RV" "$RC" "$CHD" "$DOMC" chain
fi

# ---- Apalache: bounded symbolic ----------------------------------------------
if [[ ${APALACHE:-0} == 1 ]]; then
  D=${REFS_DEPTH:-8}
  S=${SERVE_DEPTH:-12}
  apa refs.qnt refs2 Safety "$D" ok
  apa refs.qnt refs2_memNoMutex NoLostUpdateMem 6 violation
  apa refs.qnt refs2_noRefLock NoLostUpdateLocal 8 violation   # 2 begins, 2 acquires, 2 reads, 2 commits
  apa refs.qnt refs2 WitnessCrossDomainGap 9 violation     # shortest witness: 9 steps
  apa serve.qnt serve2 Safety "$S" ok
  apa serve.qnt serve2_sweepUnlocked NoLiveUploadSwept 6 violation
  apa serve.qnt serve2_sweepUnderShared NoLiveUploadSwept 7 violation
  apa serve.qnt serve2_serverSkipsServe NoLiveUploadSwept 6 violation
  apa serve.qnt serve2_serverLockShared OneMkitServer 2 violation
  apa serve.qnt serve2_ftSlow NoLiveUploadSwept 4 violation
  apa serve.qnt served Safety 8 ok
  apa serve.qnt served_headCheckedLate RefusedWritesNothing 4 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
