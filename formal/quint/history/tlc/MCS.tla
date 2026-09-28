---- MODULE MCS ----
\* TLC wrapper for scrub.qnt (`--main scrubUnbounded`, saved as
\* scrubUnbounded.tla). Future behaviour depends only on relative ages and
\* elapsed time, capped above every threshold they are compared against, so
\* this finite VIEW covers unboundedly many publishes. Sound for q_inv.
EXTENDS scrubUnbounded
Cap(x, c) == IF x > c THEN c ELSE x
View == << scrubUnbounded_scrubCore_chainLen,
           scrubUnbounded_scrubCore_scrub.valid, scrubUnbounded_scrubCore_scrub.cursor,
           scrubUnbounded_scrubCore_scrub.vt,
           Cap(scrubUnbounded_scrubCore_wall - scrubUnbounded_scrubCore_scrub.lastFull,
               scrubUnbounded_scrubCore_MAX_AGE + 1),
           [i \in scrubUnbounded_scrubCore_LEAVES |->
              IF i < scrubUnbounded_scrubCore_chainLen
              THEN Cap(scrubUnbounded_scrubCore_pubs - scrubUnbounded_scrubCore_lastPub[i],
                       scrubUnbounded_scrubCore_LAP_FRACTION + 2)
              ELSE 0],
           [i \in scrubUnbounded_scrubCore_LEAVES |->
              IF i < scrubUnbounded_scrubCore_chainLen
              THEN Cap(scrubUnbounded_scrubCore_real - scrubUnbounded_scrubCore_lastReal[i],
                       scrubUnbounded_scrubCore_MAX_AGE + 1)
              ELSE 0],
           scrubUnbounded_scrubCore_lastMode, scrubUnbounded_scrubCore_lastScrubValid >>
====
