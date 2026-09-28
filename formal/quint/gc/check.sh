#!/usr/bin/env bash
# Reproduce every gc check (MKIT-21, MKIT-17). Each line of output is one
# check with its expected outcome; anything else counts as UNEXPECTED and the
# script exits 1.
#
#   ./check.sh               quint typecheck + test + run (minutes)
#   APALACHE=1 ./check.sh    + bounded Apalache on the compiled TLA+
#   TLC=1 ./check.sh         + exhaustive TLC on the finite instances
#   ONLY=ci ./check.sh       only the ContentIndex model (contentIndex.qnt)
#   ONLY=gc ./check.sh       only the repository gc model (gc.qnt)
#   SEL='regex' ...          only the run/apalache/tlc checks whose
#                            "module::invariant" matches (quint test still runs)
#
# Pins (MKIT-17): quint 0.32.0, Apalache 0.62.2 run directly on the TLA+ that
# `quint compile` emits, TLC = the tlc2.TLC class inside that Apalache jar,
# Java 21. Tool locations (all overridable):
#   FV_HOME     ${FV_HOME:-$HOME/.local/share/mkit-fv}
#   APALACHE_MC $FV_HOME/apalache-0.62.2/bin/apalache-mc
#   TLA2TOOLS   the apalache.jar next to APALACHE_MC (contains tlc2.TLC)
#   JAVA_HOME   `/usr/libexec/java_home -v 21` when unset (macOS), then
#               Homebrew's openjdk@21; also used by `quint compile`
# Memory: TLC_HEAP (default 4g), APA_HEAP (default 4g), TLC_WORKERS (2).
set -euo pipefail
cd "$(dirname "$0")"

FV_HOME=${FV_HOME:-$HOME/.local/share/mkit-fv}
APALACHE_MC=${APALACHE_MC:-$FV_HOME/apalache-0.62.2/bin/apalache-mc}
TLA2TOOLS=${TLA2TOOLS:-$(dirname "$APALACHE_MC")/../lib/apalache.jar}
APA_JAR=$(dirname "$APALACHE_MC")/../lib/apalache.jar
# Java 21: $JAVA_HOME, else `java_home -v 21` (macOS), else Homebrew's
# keg-only openjdk@21 (not registered with java_home), else java on PATH.
if [[ -z ${JAVA_HOME:-} && -x /usr/libexec/java_home ]]; then
  JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null || true)
fi
for j in /opt/homebrew/opt/openjdk@21 /usr/local/opt/openjdk@21; do
  if [[ -z ${JAVA_HOME:-} && -x $j/bin/java ]]; then JAVA_HOME=$j; fi
done
if [[ -n ${JAVA_HOME:-} ]]; then export JAVA_HOME PATH="$JAVA_HOME/bin:$PATH"; fi
java -version >/dev/null 2>&1 || { echo "check.sh: no Java 21 found (set JAVA_HOME)" >&2; exit 2; }
TLC_HEAP=${TLC_HEAP:-4g}
APA_HEAP=${APA_HEAP:-4g}
STEPS=${STEPS:-30}
SAMPLES=${SAMPLES:-20000}
ONLY=${ONLY:-all}

fails=0
note() { printf '%-64s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# FILE and CORE select the model: gc.qnt/gcCore or contentIndex.qnt/ciCore.
FILE=gc.qnt CORE=gcCore

# quint run: $1 module, $2 invariant, $3 expect ok|violation
qrun() {
  if [[ -n ${SEL:-} && ! "$1::$2" =~ $SEL ]]; then return 0; fi
  local out rc=0
  out=$(quint run "$FILE" --main "$1" --invariant "$2" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $3 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $3 == violation && $out == *"[violation]"* ]]; then
    note "run $1::$2" "$3 (as expected)"
  else bad "run $1::$2" "wanted $3, rc=$rc"; fi
}

# Compile module $1 with invariant $3 to $2/M.tla. Definitions keep their
# names, prefixed `$1_$CORE_`, so checkers are pointed at the named invariant
# itself (`--invariant` keeps it from being pruned as unused).
compile() {
  mkdir -p "$2"
  quint compile --target tlaplus --main "$1" --invariant "$3" "$FILE" 2>/dev/null |
    sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE M/" > "$2/M.tla"
  (cd "$2" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
}

# Apalache (bounded symbolic, direct on the compiled TLA+): $1 module,
# $2 invariant, $3 length, $4 expect. The run checks only $2, by name
# (Apalache numbers the conjuncts of $2 as state invariants 0, 1, ...), so a
# reported violation is a violation of $2.
apa() {
  if [[ -n ${SEL:-} && ! "$1::$2" =~ $SEL ]]; then return 0; fi
  local d="$WORK/apa-$1-$2-$3" rc=0 inv="$1_${CORE}_$2" t0=$SECONDS
  compile "$1" "$d" "$2"
  (cd "$d" && JVM_ARGS="-Xmx$APA_HEAP" "$APALACHE_MC" check --init=q_init \
    --next=q_step --inv="$inv" --length="$3" --out-dir="$d/out" M.tla \
    > apa.out 2>&1) || rc=$?
  local dt="$((SECONDS - t0))s"
  if [[ $4 == ok && $rc == 0 ]] && grep -q 'The outcome is: NoError' "$d/apa.out"; then
    note "apalache $1::$2 (length $3)" "ok (as expected) $dt"
  elif [[ $4 == violation && $rc == 12 ]] &&
       grep -q "Set an invariant to $inv" "$d/apa.out" &&
       grep -Eq 'state invariant [0-9]+ violated' "$d/apa.out"; then
    note "apalache $1::$2 (length $3)" "violation (as expected) $dt"
  else bad "apalache $1::$2 (length $3)" "wanted $4, rc=$rc $dt (log: kept in $d)"
       trap - EXIT; fi
}

# TLC (exhaustive over the finite instance): $1 module, $2 invariant,
# $3 expect; optional $4 a CONSTRAINT with `@` for the variable prefix.
# A violation must be reported for the named invariant $2 itself.
# gc.qnt runs use a VIEW that drops only history no guard and no Safety or
# Progress conjunct reads (counters, lastAction, gc scratch outside the phase
# that reads it, mtimes of absent objects, pushStart outside "wrote"): sound
# for Safety, Progress and their conjuncts, NOT for the canaries (those are
# checked by quint run and Apalache). Deadlock checking is off: Corrupt/Repair
# are always enabled, so it could never fire; Progress states it instead.
tlc() {
  if [[ -n ${SEL:-} && ! "$1::$2" =~ $SEL ]]; then return 0; fi
  local d="$WORK/tlc-$1-$2-${4:+c}" rc=0 P="$1_${CORE}_" t0=$SECONDS view=""
  compile "$1" "$d" "$2"
  if [[ $CORE == gcCore ]]; then
    view="View == << ${P}clock, ${P}present, [o \\in ${P}present |-> ${P}mtime[o]],
  ${P}refs, ${P}corrupt, ${P}rlog, ${P}nextSeq, ${P}lockHolder, ${P}prodPhase,
  ${P}prodTarget, ${P}gcPhase, IF ${P}gcPhase = \"idle\" THEN 0 ELSE ${P}gcNow,
  IF ${P}gcPhase = \"expRead\" THEN << ${P}gcKept, ${P}gcDropAny >> ELSE << {}, FALSE >>,
  IF ${P}gcPhase = \"sweep\" THEN << ${P}gcLive, ${P}gcTodo, ${P}markedUnreadable >>
    ELSE << {}, {}, FALSE >>,
  ${P}pushPhase, IF ${P}pushPhase = \"wrote\" THEN ${P}pushStart ELSE 0,
  ${P}ghostRecs, ${P}livePruned, ${P}sweptUnreadable >>"
  fi
  printf -- '---- MODULE MC ----\nEXTENDS M\n%s\nConstr == %s\n====\n' \
    "$view" "${4:-TRUE}" > "$d/MC.tla"
  sed -i.bak "s/@/${P}/g" "$d/MC.tla"
  { printf 'INIT q_init\nNEXT q_step\nINVARIANT %s\nCONSTRAINT Constr\nCHECK_DEADLOCK FALSE\n' "$P$2"
    if [[ -n $view ]]; then printf 'VIEW View\n'; fi; } > "$d/MC.cfg"
  (cd "$d" && java -XX:+UseParallelGC -Xmx"$TLC_HEAP" -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "${TLC_WORKERS:-2}" -metadir "$d/states" -config MC.cfg MC.tla \
    > tlc.out 2>&1) || rc=$?
  local dt="$((SECONDS - t0))s" n
  n=$(grep -o '[0-9,]* distinct states found' "$d/tlc.out" | tail -1 || true)
  if [[ $3 == ok && $rc == 0 ]] && grep -q 'No error has been found' "$d/tlc.out"; then
    note "tlc $1::$2${4:+ (constrained)}" "ok (as expected) $n, $dt"
  elif [[ $3 == violation && $rc == 12 ]] &&
       grep -q "Invariant $P$2 is violated" "$d/tlc.out"; then
    note "tlc $1::$2${4:+ (constrained)}" "violation (as expected) $n, $dt"
  else bad "tlc $1::$2" "wanted $3, rc=$rc $dt (log: kept in $d)"; trap - EXIT; fi
}

# =============================================================================
# gc.qnt: repository gc, recovery log, locks, concurrent writers
# =============================================================================
if [[ $ONLY == all || $ONLY == gc ]]; then
FILE=gc.qnt CORE=gcCore
quint typecheck "$FILE"
for m in gc gcPushFast gcPushRawFreshen gcPushFastFreshen gcPushBounded mutBoundedLax \
         gcTagRoot gcTagClosure; do
  quint test "$FILE" --main "$m" >/dev/null && note "test $m" ok || bad "test $m" failed
done

# ---- supported deployment: all invariants hold ------------------------------
qrun gc All ok
for c in CanaryNoPrune CanaryNoAbort CanaryNoExpire CanaryNoPrunedRecord; do
  qrun gc "$c" violation
done
qrun gcGrace0 All ok                         # --grace-secs 0: locks alone suffice
qrun gcGrace0 CanaryNoPrune violation
# ---- later root publish of an abandoned tip (tag/attest/update-ref) ----------
qrun gcTagRoot NoDangling violation          # FINDING: root-only re-check under the lock
qrun gcTagClosure All ok                     # closure re-check: safe
qrun gcTagClosure CanaryNoYoungOverPruned violation  # the hazard state is reached
qrun gcTagRoot CanaryNoTagPublished violation
# ---- GC vs concurrent push (SPEC-CONCURRENCY §3.1) ---------------------------
qrun gcPushRaw NoDangling violation          # push slower than the grace window
qrun gcPushRawFreshen NoDangling violation   # ... even with mtime freshening
qrun gcPushFast NoDangling violation         # fast push, dedup keeps old mtime
qrun gcPushFastFreshen All ok                # fast push + freshen-on-dedup: safe
qrun gcPushBounded All ok                    # exact mtime assumption: safe
qrun gcPushBounded CanaryNoPruneDuringPush violation   # the safe modes are not vacuous:
qrun gcPushFastFreshen CanaryNoPruneDuringPush violation  # gc prunes mid-push and
qrun gcPushBounded CanaryNoPushPublished violation     # the push still publishes
qrun gcPushBounded CanaryNoPrunedPushPublished violation
qrun gcPushFastFreshen CanaryNoPrunedPushPublished violation
for m in gcPushRaw gcPushRawFreshen gcPushFast; do qrun "$m" NoLivePruned violation; done
for m in gcPushFastFreshen gcPushBounded; do qrun "$m" NoLivePruned ok; done
# ---- mutants (non-vacuity), each against the invariant it must break ----------
qrun mutNoLock SupersededRetained violation
qrun mutNoLock LockExclusion violation
qrun mutNoLockGrace0 NoDangling violation    # grace 0 is safe only because of the locks
qrun mutNoLockGrace0 NoLivePruned violation
qrun mutLenient UnreadableAborts violation
qrun mutLenient NoLivePruned violation
qrun mutNoRecord SupersededRetained violation
qrun mutNoKeepLast SupersededRetained violation
qrun mutLeakLock NoLeakedLock violation      # progress
qrun mutStuckPush NoStuckPush violation      # progress
# mutBoundedLax (mtime >= T - GRACE) is caught by `boundaryLossTest`, Apalache
# and TLC; quint run's random ticks rarely hit the exact boundary.

if [[ ${APALACHE:-0} == 1 ]]; then
  D=${GC_DEPTH:-8}
  apa gc All "$D" ok
  apa gcGrace0 All "$D" ok
  apa gcTagClosure All "$D" ok
  apa gcPushFastFreshen All "$D" ok
  apa gcPushBounded All "$D" ok
  apa gc CanaryNoPrune 6 violation
  apa gc CanaryNoExpire 10 violation
  # gcTagRoot::NoDangling needs 16 steps (gc must sweep all 7 objects and
  # finish before the tag can take the lock); a length-12 run found nothing in
  # 19 min. It is covered by tagAfterGraceTest, quint run and TLC.
  apa gcTagClosure CanaryNoYoungOverPruned 11 violation
  apa gcPushFast NoDangling 8 violation
  apa gcPushRawFreshen NoDangling 8 violation
  apa gcPushFast NoLivePruned 8 violation
  apa gcPushBounded CanaryNoPruneDuringPush 8 violation
  apa gcPushBounded CanaryNoPrunedPushPublished 10 violation
  apa gcPushFastFreshen CanaryNoPrunedPushPublished 9 violation
  apa mutNoLock LockExclusion 4 violation
  apa mutNoLock SupersededRetained 12 violation
  apa mutNoLockGrace0 NoDangling 8 violation
  apa mutLenient NoLivePruned 7 violation
  apa mutBoundedLax NoDangling 8 violation
  apa mutLenient UnreadableAborts 7 violation
  apa mutNoRecord SupersededRetained 3 violation
  apa mutNoKeepLast SupersededRetained 7 violation
  apa mutLeakLock NoLeakedLock 3 violation
  apa mutStuckPush NoStuckPush 4 violation
fi

if [[ ${TLC:-0} == 1 ]]; then
  # gc and gcGrace0 run unconstrained (~20M distinct states each). The
  # instances with a writer were OOM-killed at ~40M states unconstrained, so
  # they are bounded to keep one TLC within a 4 GB heap: NC = at most two
  # producer rewrites and no corrupt root source (corruption only makes gc
  # abort; the fail-closed checks run unconstrained in gc, mutLenient and in
  # Apalache/quint run).
  NC='@nextSeq <= 2 /\ @corrupt = {}'
  tlc gc All ok
  tlc gcGrace0 All ok
  tlc gcTagClosure All ok "$NC"
  tlc gcPushBounded All ok "$NC"
  tlc gcPushFastFreshen All ok "$NC"
  tlc mutLenient NoLivePruned violation
  tlc mutLenient UnreadableAborts violation
  tlc mutNoLock SupersededRetained violation
  tlc mutNoLock LockExclusion violation
  tlc mutNoRecord SupersededRetained violation
  tlc mutNoKeepLast SupersededRetained violation
  tlc mutLeakLock NoLeakedLock violation
  tlc mutStuckPush NoStuckPush violation "$NC"
  tlc mutBoundedLax NoDangling violation "$NC"
  tlc gcPushFast NoDangling violation "$NC"
  tlc gcTagRoot NoDangling violation "$NC"
fi
fi

# =============================================================================
# contentIndex.qnt: server ContentIndex GC ordering (R-64) vs an upload
# =============================================================================
if [[ $ONLY == all || $ONLY == ci ]]; then
FILE=contentIndex.qnt CORE=ciCore
quint typecheck "$FILE"
for m in ciHoldFirst ciBytesFirst; do
  quint test "$FILE" --main "$m" >/dev/null && note "test $m" ok || bad "test $m" failed
done
qrun ciHoldFirst All ok
qrun ciShortTtlGrace All ok
for c in CanaryNoDelete CanaryNoPublish CanaryNoDeleteThenPublish CanaryNoHolder; do
  qrun ciHoldFirst "$c" violation
done
qrun ciBytesFirst NoReachableLoss violation   # dedup/write before the hold
qrun ciShortTtl NoReachableLoss violation     # APPLY_WINDOW + RELAY_LAG = max(TTL, GRACE)
qrun ciMutNoDeletingGuard NoReachableLoss violation
qrun ciMutNoSeqGuard NoLiveDelete violation
qrun ciMutNoResume DeletingClears violation
qrun ciMutNoGiveUp UploadCanStep violation
if [[ ${APALACHE:-0} == 1 ]]; then
  apa ciHoldFirst All 16 ok
  apa ciShortTtlGrace All 16 ok
  apa ciBytesFirst NoReachableLoss 10 violation
  apa ciShortTtl NoReachableLoss 10 violation
  apa ciMutNoDeletingGuard NoReachableLoss 10 violation
  apa ciMutNoSeqGuard NoLiveDelete 10 violation
  apa ciMutNoResume DeletingClears 10 violation
  apa ciMutNoGiveUp UploadCanStep 10 violation
  apa ciHoldFirst CanaryNoDeleteThenPublish 12 violation
fi
if [[ ${TLC:-0} == 1 ]]; then
  tlc ciHoldFirst All ok
  tlc ciShortTtlGrace All ok
  tlc ciBytesFirst NoReachableLoss violation
  tlc ciShortTtl NoReachableLoss violation
  tlc ciMutNoDeletingGuard NoReachableLoss violation
  tlc ciMutNoSeqGuard NoLiveDelete violation
  tlc ciMutNoResume DeletingClears violation
  tlc ciMutNoGiveUp UploadCanStep violation
fi
fi

[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
