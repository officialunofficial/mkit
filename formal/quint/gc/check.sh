#!/usr/bin/env bash
# Reproduce every MKIT-21 gc check: `./check.sh` (quint test + quint run),
# `APALACHE=1 ./check.sh` adds bounded Apalache runs (safe instances to length
# ${GC_DEPTH:-10}). Needs quint 0.32, java, unzip and Apalache 0.47.2 at
# ${APALACHE_MC:-/opt/fv/apalache/bin/apalache-mc}.
set -euo pipefail
cd "$(dirname "$0")"
fails=0
note() { printf '%-58s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }
STEPS=${STEPS:-30}
SAMPLES=${SAMPLES:-20000}

# quint run: $1 module, $2 invariant, $3 expect ok|violation
qrun() {
  local out rc=0
  out=$(quint run gc.qnt --main "$1" --invariant "$2" --max-steps "$STEPS" \
    --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $3 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $3 == violation && $out == *"[violation]"* ]]; then
    note "run $1::$2" "$3 (as expected)"
  else bad "run $1::$2" "wanted $3, rc=$rc"; fi
}
# Apalache (bounded symbolic): compile $1 with invariant $2 to TLA+ and run
# apalache-mc directly (no shared quint-verify server); $3 depth, $4 expect.
APALACHE_MC=${APALACHE_MC:-/opt/fv/apalache/bin/apalache-mc}
APA_JAR=$(dirname "$APALACHE_MC")/../lib/apalache.jar
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
apa() {
  local d="$WORK/apa-$1-$2-$3" rc=0; mkdir -p "$d"
  quint compile --target tlaplus --main "$1" --invariant "$2" gc.qnt 2>/dev/null |
    sed -n '/^-* MODULE/,$p' | sed "1s/MODULE [A-Za-z0-9_]*/MODULE M/" > "$d/M.tla"
  (cd "$d" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
  (cd "$d" && "$APALACHE_MC" check --init=q_init --next=q_step --inv=q_inv \
    --length="$3" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 ]] || [[ $4 == violation && $rc == 12 ]]; then
    note "apalache $1::$2 (length $3)" "$4 (as expected)"
  else bad "apalache $1::$2 (length $3)" "wanted $4, rc=$rc"; fi
}

quint typecheck gc.qnt
for m in gc gcPushFast gcPushRawFreshen; do
  quint test gc.qnt --main "$m" >/dev/null && note "test $m" ok || bad "test $m" failed
done

# ---- supported deployment: all invariants hold ------------------------------
qrun gc Safety ok
for c in CanaryNoPrune CanaryNoAbort CanaryNoExpire CanaryNoPrunedRecord; do
  qrun gc "$c" violation
done
qrun gcGrace0 Safety ok                      # --grace-secs 0: locks alone suffice
qrun gcGrace0 CanaryNoPrune violation
# ---- GC vs concurrent push (SPEC-CONCURRENCY §3.1) ---------------------------
qrun gcPushRaw NoDangling violation          # push slower than the grace window
qrun gcPushRawFreshen NoDangling violation   # ... even with mtime freshening
qrun gcPushFast NoDangling violation         # fast push, dedup keeps old mtime
qrun gcPushFastFreshen Safety ok             # fast push + freshen-on-dedup: safe
qrun gcPushBounded Safety ok                 # exact mtime assumption: safe
qrun gcPushBounded CanaryNoPruneDuringPush violation   # the safe modes are not vacuous:
qrun gcPushFastFreshen CanaryNoPruneDuringPush violation  # gc prunes mid-push and
qrun gcPushBounded CanaryNoPushPublished violation     # the push still publishes
# The race also deletes an object that is live at deletion time: the push
# publishes between gc's mark and its sweep reaching the object.
for m in gcPushRaw gcPushRawFreshen gcPushFast; do qrun "$m" NoLivePruned violation; done
for m in gcPushFastFreshen gcPushBounded; do qrun "$m" NoLivePruned ok; done
# ---- mutants (non-vacuity) ---------------------------------------------------
qrun mutNoLock SupersededRetained violation
qrun mutNoLock LockExclusion violation
qrun mutLenient UnreadableAborts violation
qrun mutLenient NoLivePruned violation
qrun mutNoRecord SupersededRetained violation
qrun mutNoKeepLast SupersededRetained violation

# ---- Apalache: bounded symbolic ------------------------------------------------
if [[ ${APALACHE:-0} == 1 ]]; then
  D=${GC_DEPTH:-10}
  apa gc Safety "$D" ok
  apa gcGrace0 Safety "$D" ok
  apa gcPushFastFreshen Safety "$D" ok
  apa gcPushBounded Safety "$D" ok
  apa gc CanaryNoPrune 6 violation
  apa gc CanaryNoExpire 7 violation
  apa gcPushFast NoDangling 8 violation
  apa gcPushRawFreshen NoDangling 8 violation
  apa gcPushFast NoLivePruned 8 violation
  apa gcPushBounded CanaryNoPruneDuringPush 8 violation
  apa mutNoLock LockExclusion 4 violation
  apa mutNoLock SupersededRetained 12 violation
  apa mutLenient NoLivePruned 7 violation
  apa mutLenient UnreadableAborts 7 violation
  apa mutNoRecord SupersededRetained 3 violation
  apa mutNoKeepLast SupersededRetained 7 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
