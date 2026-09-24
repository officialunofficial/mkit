---- MODULE MC ----
\* TLC wrapper for history.qnt (`quint compile --target tlaplus --main history`,
\* saved as history.tla). The VIEW drops witness-only ghosts and the state of
\* dead generations: no transition reads snaps/lineage of a generation that is
\* neither `current` nor the intent's, and neither ever becomes live again
\* (tx.gen is always `current` or a fresh id). Sound for q_inv (Safety).
EXTENDS history
Live(g) == g = history_historyCore_current
           \/ (history_historyCore_tx.present /\ g = history_historyCore_tx.gen)
View == << history_historyCore_ref, history_historyCore_tx, history_historyCore_pending,
           [g \in history_historyCore_GENS |->
              IF Live(g) THEN history_historyCore_snaps[g] ELSE history_historyCore_NOSNAP],
           history_historyCore_current, history_historyCore_store,
           history_historyCore_pc, history_historyCore_after, history_historyCore_opTarget,
           history_historyCore_opExpect, history_historyCore_memChain, history_historyCore_nextGen,
           [g \in history_historyCore_GENS |->
              IF Live(g) THEN history_historyCore_lineage[g] ELSE history_historyCore_LIN0],
           history_historyCore_ev.failedClosed, history_historyCore_ev.gcLostIntent >>
====
