---- MODULE MCL ----
\* TLC progress check for history.qnt (compiled as history.tla; check.sh
\* renames the prefixes for mutants). Safety alone cannot see a stuck
\* protocol: Gc/WriteObject (idle) and Crash (in flight) are always enabled,
\* so the instance never deadlocks and `-deadlock` hides nothing, but a
\* recovery that errors on every retry would keep the intent, and so withhold
\* proofs, forever. IntentEventuallyCleared rules that out under:
\*   WF(Progress)        an operation that has started keeps taking steps;
\*   WF(RecoverAttempt)  while an intent exists, some caller eventually runs a
\*                       supported history operation (advance or delete),
\*                       which recovers first (SPEC-HISTORY-PROOF §4.4 step 1);
\*   finitely many crashes (with unboundedly many, a crash can always
\*                       interrupt recovery).
\* The last is encoded with a prophecy-style flag `calm`, which may switch on
\* once and afterwards forbids Crash, and the property is stated for calm
\* states: every behaviour with finitely many crashes is the projection of one
\* that switches `calm` on after its last crash.
\* The VIEW extends MC.tla's by `calm`. MC's VIEW drops only ghosts that no
\* guard reads and the state of dead generations, so view-equivalent states
\* have the same enabled steps to view-equivalent successors; every predicate
\* and action used below depends only on viewed variables, so the quotient
\* graph preserves this property. (Without a VIEW the instance has more than
\* 7,000,000 distinct states at depth 27 and did not finish in the budget.)
EXTENDS MC
VARIABLE calm
Vars == << history_historyCore_pc, history_historyCore_pending, history_historyCore_tx,
           history_historyCore_memChain, history_historyCore_ref, history_historyCore_snaps,
           history_historyCore_current, history_historyCore_store, history_historyCore_after,
           history_historyCore_opTarget, history_historyCore_opExpect,
           history_historyCore_nextGen, history_historyCore_lineage, history_historyCore_ev,
           calm >>
LView == << View, calm >>
\* q_step is exactly noCrashStep \/ Crash (history.qnt `step`). Crash is
\* selected by name: an in-flight error has the same effect as a crash, so
\* excluding crashes by their effect (~Crash as a predicate on steps) would
\* also forbid those errors and hide a recovery that fails forever.
Next == \/ history_historyCore_noCrashStep /\ calm' \in IF calm THEN {TRUE} ELSE BOOLEAN
        \/ ~calm /\ history_historyCore_Crash /\ calm' \in BOOLEAN
Progress == /\ \/ history_historyCore_FPending \/ history_historyCore_FRef
               \/ history_historyCore_FSnap \/ history_historyCore_FCurrent
               \/ history_historyCore_FClear \/ history_historyCore_AdvanceCont
               \/ history_historyCore_DelInval \/ history_historyCore_DelRef
               \/ history_historyCore_RawWriteRef
            /\ calm' = calm
RecoverAttempt ==
  /\ history_historyCore_tx.present
  /\ \E t \in history_historyCore_COMMITS, e \in history_historyCore_EXPECTS:
       history_historyCore_Advance(t, e) \/ history_historyCore_Delete(e)
  /\ calm' = calm
Init == q_init /\ calm = FALSE
Spec == Init /\ [][Next]_Vars /\ WF_Vars(Progress) /\ WF_Vars(RecoverAttempt)
\* Canary spec: no fairness for recovery callers (must be violated).
SpecNoRecoverFairness == Init /\ [][Next]_Vars /\ WF_Vars(Progress)
IntentEventuallyCleared ==
  (calm /\ history_historyCore_tx.present) ~> ~history_historyCore_tx.present
\* Canary property: an intent survives into a crash-free suffix (must be
\* violated), so IntentEventuallyCleared is not vacuously about states that
\* never carry an intent.
CanaryNoCalmIntent == [](calm => ~history_historyCore_tx.present)
====
