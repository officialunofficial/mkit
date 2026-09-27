#!/usr/bin/env bash
# Reproduce every quint-transport check (MKIT-26 / MKIT-17): identity.qnt
# (requested transport identities checked before effects), shards.qnt (shard
# quorum under the process-wide worker bound, cancellation, progress) and
# threshold.qnt (SPEC-RELEASE-THRESHOLD t-of-n aggregation and rotation).
#
#   ./check.sh               quint typecheck + test + run, then TLC (safety + progress)
#   TLC=0 ./check.sh         skip TLC
#   APALACHE=1 ./check.sh    add bounded apalache-mc runs on the compiled TLA+
#   QUINT=0 skips `quint run`; ONLY=<regex> restricts TLC/Apalache to
#   matching "<module>::<property>" checks.
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
# "UNEXPECTED: ...". `ok` = the property holds (within the stated bound);
# `violation` = a mutant, canary or documented-gap witness the checker must
# reach (non-vacuity); `liveness` = TLC must report a temporal violation
# (exit 13), so a mutant caught by a safety or deadlock error instead is
# reported as unexpected. The script exits 1 on any unexpected outcome.
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
note() { printf '%-72s %s\n' "$1" "$2"; }
bad() { note "$1" "UNEXPECTED: $2"; fails=$((fails + 1)); }
STEPS=${STEPS:-40}
SAMPLES=${SAMPLES:-20000}

# quint run: $1 file, $2 module, $3 invariant, $4 expect ok|violation, [$5 steps]
qrun() {
  [[ ${QUINT:-1} == 1 ]] || return 0
  local out rc=0
  out=$(quint run "$1" --main "$2" --invariant "$3" --max-steps "${5:-$STEPS}" \
    --max-samples "$SAMPLES" --backend rust --seed=0x1 2>&1) || rc=$?
  if [[ $4 == ok && $rc == 0 && $out == *"[ok]"* ]] ||
     [[ $4 == violation && $out == *"[violation]"* ]]; then
    note "run $2::$3" "$4 (as expected)"
  else bad "run $2::$3" "wanted $4, rc=$rc"; fi
}

# quint test: $1 file, $2 module
qtest() {
  if quint test "$1" --main "$2" >/dev/null 2>&1; then note "test $2" ok
  else bad "test $2" failed; fi
}

# Compile module $2 of $1 with invariant $3 into $4/M.tla (module renamed M).
# quint compile translates through its bundled Apalache server (transpiling
# only; checking is done by the pinned apalache-mc / TLC); run it inside $4 so
# its _apalache-out lands there. The server is shared by concurrent agents, so
# a failed compile is retried.
compile() {
  mkdir -p "$4"
  local try
  for try in 1 2 3; do
    (cd "$4" && quint compile --target tlaplus --main "$2" --invariant "$3" "$HERE/$1" \
      2>"$4/compile.err") | sed -n '/^-* MODULE/,$p' |
      sed "1s/MODULE [A-Za-z0-9_]*/MODULE M/" > "$4/M.tla" || true
    grep -q '^====' "$4/M.tla" && break
    sleep $((try * 5))
  done
  grep -q '^====' "$4/M.tla" ||
    { echo "check.sh: quint compile of $2 failed (see $4/compile.err)" >&2; return 1; }
  (cd "$4" && unzip -o -j -q "$APA_JAR" tla2sany/StandardModules/Apalache.tla \
    tla2sany/StandardModules/Variants.tla)
}

# quint prefixes each name with <main>_<module>_ (read off q_init).
prefix() { sed -n 's/^q_init == \(.*_\)init$/\1/p' "$1/M.tla"; }
# The compiled state variables, as a TLA+ tuple body.
vars_of() {
  awk '/^VARIABLE/{v=1; next} v && /^  [A-Za-z_][A-Za-z0-9_]*$/{gsub(/ /,""); print; v=0}' "$1/M.tla" |
    paste -sd, - | sed 's/,/, /g'
}

# Apalache (bounded symbolic, apalache-mc directly): $1 file, $2 module,
# $3 invariant, $4 length, $5 expect.
apa() {
  [[ -n ${ONLY:-} && ! "$2::$3" =~ $ONLY ]] && return 0
  local d="$WORK/apa-$2-$3-$4" rc=0
  compile "$1" "$2" "$3" "$d"
  # The models have terminal states (a fetch ends, a download returns), so
  # deadlock checking is off, and a `violation` must be the invariant's.
  (cd "$d" && "$APALACHE_MC" check --no-deadlock --init=q_init --next=q_step --inv=q_inv \
    --length="$4" --out-dir="$d/out" M.tla > apa.out 2>&1) || rc=$?
  if [[ $5 == ok && $rc == 0 ]] ||
     { [[ $5 == violation && $rc == 12 ]] && grep -q 'state invariant 0 violated' "$d/apa.out"; }; then
    note "apalache $2::$3 (length $4)" "$5 (as expected)"
  else bad "apalache $2::$3 (length $4)" "wanted $5, rc=$rc"; tail -5 "$d/apa.out" >&2; fi
}

# TLC run in $1 on MC.tla with config $2; $3 expect ok|violation|liveness; $4 label.
run_tlc() {
  local rc=0
  (cd "$1" && java -XX:+UseParallelGC -Xmx${TLC_HEAP:-4g} -cp "$TLA2TOOLS" tlc2.TLC \
    -workers "${TLC_WORKERS:-2}" -config "$2" MC.tla > "tlc-$2.out" 2>&1) || rc=$?
  local stats; stats=$(grep -oE '[0-9]+ distinct states found' "$1/tlc-$2.out" | tail -1 || true)
  if [[ $3 == ok && $rc == 0 ]] || [[ $3 == violation && $rc == 12 ]] ||
     [[ $3 == liveness && $rc == 13 ]]; then
    note "tlc $4" "$3 (as expected) $stats"
  else bad "tlc $4" "wanted $3, rc=$rc"; tail -5 "$1/tlc-$2.out" >&2; fi
}

# TLC safety, exhaustive over the reachable states: $1 file, $2 module,
# $3 invariant, $4 expect, optional $5 CONSTRAINT expression and $6 VIEW
# expression (`@` = prefix).
tlc() {
  [[ -n ${ONLY:-} && ! "$2::$3" =~ $ONLY ]] && return 0
  local d="$WORK/tlc-$2-$3" P
  compile "$1" "$2" "$3" "$d"
  P=$(prefix "$d")
  { echo "---- MODULE MC ----"; echo "EXTENDS M"
    [[ -n ${5:-} ]] && echo "Constr == $5"
    [[ -n ${6:-} ]] && echo "View == $6"
    echo "===="; } | sed "s/@/${P}/g" > "$d/MC.tla"
  { printf 'INIT q_init\nNEXT q_step\nINVARIANT q_inv\nCHECK_DEADLOCK FALSE\n'
    [[ -n ${5:-} ]] && echo "CONSTRAINT Constr"
    [[ -n ${6:-} ]] && echo "VIEW View"; true; } > "$d/MC.cfg"
  run_tlc "$d" MC.cfg "$4" "$2::$3${5:+ (constrained: $5)}"
}

# TLC progress for shards.qnt: $1 module, $2 property (P1 | P2 | P2NoForeignFairness
# | P2Corrupt), $3 expect. Fairness is stated explicitly per property below.
#   P1  INVARIANTS.md form: once `minimum_shards` Ok results have been sent to
#       the collector, it decides. Fairness: WF(collector) ONLY: no worker,
#       straggler or timeout is assumed to make progress, so the collector
#       must not need a slot to receive what has already arrived.
#   P2  MKIT-26 form: when at least `minimum_shards` shards are honest and
#       prompt, and fewer than MAX_SHARD_WORKERS are stalled, the download
#       ends Ok. Fairness: WF(collector), WF(finish(i)) and WF(release(i)) for
#       every index (prompt workers answer, threads exit), WF(foreignRelease)
#       (other downloads' stragglers time out). NOT on timeout(i): a stalled
#       own shard may stall forever, which is exactly what must not delay us.
#   P2NoForeignFairness  canary: P2 without WF(foreignRelease) must fail
#       (every slot held forever by other downloads).
#   P2Corrupt  P2's conclusion when corrupted shards may answer: documented gap.
#   P2AnyStall P2 without the stall bound: documented bound (stalled own shards
#       holding every slot the download can get delay it until they time out).
tlcl() {
  [[ -n ${ONLY:-} && ! "$1::$2" =~ $ONLY ]] && return 0
  local d="$WORK/tlcl-$1-$2" P V
  compile shards.qnt "$1" ProgressTerms "$d"
  P=$(prefix "$d"); V=$(vars_of "$d")
  local workers='(\A i \in @IDX: WF_Vars(@finish(i)) /\ WF_Vars(@release(i)))'
  local fair_all="WF_Vars(@collector) /\\ WF_Vars(@foreignRelease) /\\ $workers"
  local fair_nf="WF_Vars(@collector) /\\ $workers"
  local spec prop
  case $2 in
    P1) spec='WF_Vars(@collector)'
        prop='@QuorumArrived ~> @Decided' ;;
    P2) spec=$fair_all
        prop='@HonestQuorumAvailable => <>@DecidedOk' ;;
    P2NoForeignFairness) spec=$fair_nf
        prop='@HonestQuorumAvailable => <>@DecidedOk' ;;
    P2Corrupt) spec=$fair_all
        prop='@QuorumAvailable => <>@DecidedOk' ;;
    P2AnyStall) spec=$fair_all
        prop='@HonestQuorumAnyStall => <>@DecidedOk' ;;
  esac
  { echo "---- MODULE MC ----"; echo "EXTENDS M"
    echo "Vars == << $V >>"
    echo "Spec == q_init /\\ [][q_step]_Vars /\\ $spec"
    echo "Prop == $prop"
    echo "===="; } | sed "s/@/${P}/g" > "$d/MC.tla"
  printf 'SPECIFICATION Spec\nPROPERTY Prop\nCHECK_DEADLOCK FALSE\n' > "$d/MC.cfg"
  run_tlc "$d" MC.cfg "$3" "$1::$2"
}

# ---- typecheck + deterministic scenarios ------------------------------------
for f in identity shards threshold; do
  quint typecheck $f.qnt && quint typecheck ${f}_test.qnt
done
qtest identity_test.qnt identity_test
qtest identity_test.qnt identity_mutants_test
qtest shards_test.qnt shards_test
qtest shards_test.qnt shards_blocking_test
qtest shards_test.qnt shards_noCancel_test
qtest shards_test.qnt shards_bad_test
qtest threshold_test.qnt threshold_test

# ---- identity.qnt: random simulation ----------------------------------------
qrun identity.qnt identity Safety ok 10
for c in CanaryNoPublish CanaryNoShardPublish CanaryNoMonoPublish \
  CanaryNoSubstitutionRejected CanaryNoReject; do
  qrun identity.qnt identity "$c" violation 10
done
qrun identity.qnt identity_nodeNoVerify NodeMatchesRequest violation 10
qrun identity.qnt identity_nodeNoVerify PublishedWithinRequestedClosure violation 10
qrun identity.qnt identity_noManifestPrecheck ShardsOnlyForRequestedManifest violation 10
qrun identity.qnt identity_noManifestChecks ReconstructOnlyForRequested violation 10
qrun identity.qnt identity_noPostDecodeCheck ShardPathReturnsRequested violation 10
qrun identity.qnt identity_consumerNoVerify PackMatchesRequest violation 10
qrun identity.qnt identity_noPackChecks PackMatchesRequest violation 10
# defence in depth: each layer alone keeps publication correct
qrun identity.qnt identity_noManifestPrecheck ReconstructOnlyForRequested ok 10
qrun identity.qnt identity_noPostDecodeCheck PackMatchesRequest ok 10
qrun identity.qnt identity_consumerNoVerify ShardPathReturnsRequested ok 10

# ---- shards.qnt: random simulation ------------------------------------------
qrun shards.qnt shards Safety ok
qrun shards.qnt shards_wide Safety ok
qrun shards.qnt shards_tight Safety ok
qrun shards.qnt shards_bad Safety ok
qrun shards.qnt shards_recvBlocking Safety ok        # its defect is progress only (TLC P2)
for c in CanaryNoOk CanaryNoNotFound CanaryNoFullPoolWithResults \
  CanaryNoOkWithStraggler CanaryNoOkUnderForeign; do
  qrun shards.qnt shards "$c" violation
done
qrun shards.qnt shards_blocking QuorumNotBlockedByAdmission violation
qrun shards.qnt shards_noCancel NoAttemptAfterDecision violation
qrun shards.qnt shards_noGroupCancel NoAttemptAfterDecision violation
qrun shards.qnt shards_noSlotCheck SlotBound violation
qrun shards.qnt shards_earlyQuorum OkHasQuorum violation
qrun shards.qnt shards_noFailureThreshold NoDisconnect violation
qrun shards.qnt shards_offByOne NoFalseNotFound violation
qrun shards.qnt shards_offByOne NotFoundPastThreshold violation
qrun shards.qnt shards DecodeFailsOnlyWithoutHonestQuorum ok
qrun shards.qnt shards_bad DecodeFailsOnlyWithoutHonestQuorum violation   # FINDING

# ---- threshold.qnt: random simulation ---------------------------------------
qrun threshold.qnt thr Safety ok 12
qrun threshold.qnt thr4 Safety ok 16
for c in CanaryNoRelease CanaryNoReleaseAfterRotation CanaryNoCompromiseSign \
  CanaryNoGarbageSurvived CanaryNoStaleAggregate; do
  qrun threshold.qnt thr "$c" violation 12
done
qrun threshold.qnt thr_asImpl AggregateCompleteness violation 12    # FINDING
qrun threshold.qnt thr_asImpl NoForgery ok 12
qrun threshold.qnt thr_asImpl AggregateFromOneShareSet ok 12
qrun threshold.qnt thr_filterAnyEpoch AggregateCompleteness violation 12
qrun threshold.qnt thr_noRefresh AggregateFromOneShareSet violation 12
qrun threshold.qnt thr_noRefresh NoForgery violation 12
qrun threshold.qnt thr_noRefresh AcceptedOnlyFromShareSetQuorum violation 12
qrun threshold.qnt thr_verifierIgnoresMsg AcceptedOnlyFromShareSetQuorum violation 12
qrun threshold.qnt thr_retainOld AcceptedOnlyFromShareSetQuorum ok 12   # sound, from ONE (old) share set
qrun threshold.qnt thr_retainOld NoForgery violation 12            # ASSUMPTION witness
qrun threshold.qnt thr_verifierIgnoresMsg NoForgery violation 12
qrun threshold.qnt thr_t1 NoForgery violation 12

# ---- TLC --------------------------------------------------------------------
if [[ ${TLC:-1} == 1 ]]; then
  # identity.qnt and shards.qnt are finite: exhaustive, no VIEW, no CONSTRAINT.
  tlc identity.qnt identity Safety ok
  tlc identity.qnt identity_nodeNoVerify NodeMatchesRequest violation
  tlc identity.qnt identity_nodeNoVerify PublishedWithinRequestedClosure violation
  tlc identity.qnt identity_noManifestPrecheck ShardsOnlyForRequestedManifest violation
  tlc identity.qnt identity_noManifestPrecheck ReconstructOnlyForRequested ok
  tlc identity.qnt identity_noManifestChecks ReconstructOnlyForRequested violation
  tlc identity.qnt identity_noPostDecodeCheck ShardPathReturnsRequested violation
  tlc identity.qnt identity_noPostDecodeCheck PackMatchesRequest ok
  tlc identity.qnt identity_consumerNoVerify PackMatchesRequest violation
  tlc identity.qnt identity_consumerNoVerify ShardPathReturnsRequested ok
  tlc identity.qnt identity_noPackChecks PackMatchesRequest violation

  tlc shards.qnt shards Safety ok
  tlc shards.qnt shards_wide Safety ok
  tlc shards.qnt shards_tight Safety ok
  tlc shards.qnt shards_bad Safety ok
  tlc shards.qnt shards_recvBlocking Safety ok
  tlc shards.qnt shards_blocking QuorumNotBlockedByAdmission violation
  tlc shards.qnt shards_noCancel NoAttemptAfterDecision violation
  tlc shards.qnt shards_noGroupCancel NoAttemptAfterDecision violation
  tlc shards.qnt shards_noSlotCheck SlotBound violation
  tlc shards.qnt shards_earlyQuorum OkHasQuorum violation
  tlc shards.qnt shards_noFailureThreshold NoDisconnect violation
  tlc shards.qnt shards_offByOne NoFalseNotFound violation
  tlc shards.qnt shards_offByOne NotFoundPastThreshold violation
  tlc shards.qnt shards_bad DecodeFailsOnlyWithoutHonestQuorum violation
  tlc shards.qnt shards DecodeFailsOnlyWithoutHonestQuorum ok
  # progress (temporal; fairness per property, see tlcl above)
  tlcl shards P1 ok
  tlcl shards P2 ok
  tlcl shards_wide P1 ok
  tlcl shards_wide P2 ok
  tlcl shards_blocking P1 liveness
  tlcl shards_recvBlocking P2 liveness
  tlcl shards P2NoForeignFairness liveness
  tlcl shards_bad P2 ok
  tlcl shards_bad P2Corrupt liveness                   # FINDING (progress form)
  tlcl shards_tight P2 ok
  tlcl shards_tight P2AnyStall liveness                # documented bound
  tlcl shards P2AnyStall ok                            # N=2,K=1: at most one stall, 2 slots

  # threshold.qnt: the pool of posted partials is a subset of a 15-element
  # universe (3 holders x 2 epochs "rel" + "evil", 3 garbage); unconstrained,
  # thr exceeded 7.3 M distinct states in 5 minutes without finishing. TLC
  # therefore explores every behaviour whose pool holds at most POOL_BOUND
  # partials (default 4: every mutant/witness needs at most 3). The VIEW
  # drops only lastAction, which no guard or invariant reads.
  TC="Cardinality(@pool) <= ${POOL_BOUND:-4}"
  TV='<< @cur, @pool, @known, @compromisedNow, @sigs, @recoveredMixed, @incomplete, @rotatedWithSig, @staleRecovered, @faults >>'
  tlc threshold.qnt thr Safety ok "$TC" "$TV"
  tlc threshold.qnt thr_asImpl AggregateCompleteness violation "$TC" "$TV"
  tlc threshold.qnt thr_asImpl NoForgery ok "$TC" "$TV"
  tlc threshold.qnt thr_filterAnyEpoch AggregateCompleteness violation "$TC" "$TV"
  tlc threshold.qnt thr_noRefresh AggregateFromOneShareSet violation "$TC" "$TV"
  tlc threshold.qnt thr_noRefresh NoForgery violation "$TC" "$TV"
  tlc threshold.qnt thr_noRefresh AcceptedOnlyFromShareSetQuorum violation "$TC" "$TV"
  tlc threshold.qnt thr_verifierIgnoresMsg AcceptedOnlyFromShareSetQuorum violation "$TC" "$TV"
  tlc threshold.qnt thr_retainOld NoForgery violation "$TC" "$TV"
  tlc threshold.qnt thr_retainOld AggregateFromOneShareSet ok "$TC" "$TV"
  tlc threshold.qnt thr_verifierIgnoresMsg NoForgery violation "$TC" "$TV"
  tlc threshold.qnt thr_t1 NoForgery violation "$TC" "$TV"
fi

# ---- Apalache: bounded symbolic ----------------------------------------------
if [[ ${APALACHE:-0} == 1 ]]; then
  I=${IDENTITY_DEPTH:-6}
  S=${SHARDS_DEPTH:-14}
  H=${THRESHOLD_DEPTH:-8}
  apa identity.qnt identity Safety "$I" ok
  apa identity.qnt identity_noManifestPrecheck ShardsOnlyForRequestedManifest 3 violation
  apa identity.qnt identity_noManifestChecks ReconstructOnlyForRequested 3 violation
  apa identity.qnt identity_noPostDecodeCheck ShardPathReturnsRequested 3 violation
  apa identity.qnt identity_consumerNoVerify PackMatchesRequest 4 violation
  apa identity.qnt identity_nodeNoVerify PublishedWithinRequestedClosure 4 violation
  apa shards.qnt shards Safety "$S" ok
  apa shards.qnt shards_blocking QuorumNotBlockedByAdmission 4 violation
  apa shards.qnt shards_noCancel NoAttemptAfterDecision 9 violation
  apa shards.qnt shards_noGroupCancel NoAttemptAfterDecision 9 violation
  apa shards.qnt shards_offByOne NoFalseNotFound 3 violation
  apa shards.qnt shards_bad DecodeFailsOnlyWithoutHonestQuorum 6 violation
  apa threshold.qnt thr Safety "$H" ok
  apa threshold.qnt thr4 Safety "${THR4_DEPTH:-6}" ok
  apa threshold.qnt thr_asImpl AggregateCompleteness 4 violation
  apa threshold.qnt thr_noRefresh NoForgery 6 violation
  apa threshold.qnt thr_retainOld NoForgery 7 violation
  apa threshold.qnt thr_verifierIgnoresMsg NoForgery 4 violation
  apa threshold.qnt thr_verifierIgnoresMsg AcceptedOnlyFromShareSetQuorum 4 violation
  apa threshold.qnt thr_noRefresh AcceptedOnlyFromShareSetQuorum 6 violation
fi
[[ $fails == 0 ]] && echo "all checks as expected" || { echo "$fails unexpected"; exit 1; }
