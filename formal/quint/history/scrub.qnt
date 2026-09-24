// -*- mode: Bluespec; -*-
// Scrub schedule for fast-forward publication (MKIT-20).
//
// Models docs/specs/SPEC-HISTORY-PROOF.md §4.5 as implemented by
// `decide_chain` / `advance` / `ScrubState` in
// rust/crates/mkit-core/src/history/ancestry.rs, for one branch. Only the
// verification SCHEDULE is modelled: the published chain is identical on
// every path (history.qnt covers publication and recovery). Constants are
// scaled down (see README.md); `realLap` below checks the real constants.

module scrubCore {
  // ---- switches -------------------------------------------------------------
  const LOSSY_SCRUB_WRITES: bool  // crash before / ignored error in `let _ = write_scrub_state`
  const CLOCK_STEPS_BACK: bool    // wall clock may step backwards
  const BUG_IGNORE_AGE: bool      // mutant: no 7-day staleness check
  const BUG_WRAP_WITHOUT_FULL: bool  // mutant: lap end wraps without full walk
  const BUG_TRUST_INVALID: bool   // mutant: corrupt/foreign state read as valid
  const MAXPUB: int               // publish-count bound (simulation)

  // ---- scaled parameters (real: 512, 64, 604800) ------------------------------
  pure val MIN_WINDOW = 2
  pure val LAP_FRACTION = 4
  pure val MAX_AGE = 3
  pure val MAXLEN = 14            // chain-length bound
  pure val LEAVES = 0.to(MAXLEN - 1)

  pure def min(a: int, b: int): int = if (a < b) a else b
  pure def max(a: int, b: int): int = if (a > b) a else b
  pure def window(vt: int): int = max(MIN_WINDOW, vt / LAP_FRACTION)
  pure def satSub(a: int, b: int): int = if (a > b) a - b else 0

  type Scrub = { valid: bool, cursor: int, vt: int, lastFull: int }

  var chainLen: int
  var scrub: Scrub               // on-disk `scrub` (valid = parses, checksum and
                                 // generation binding match)
  var wall: int                  // now_unix()
  var real: int                  // monotonic real time (ghost)
  var pubs: int                  // publishes of this chain (ghost)
  var lastPub: int -> int        // per leaf: publish that last read it
  var lastReal: int -> int       // per leaf: real time it was last read
  var lastMode: str              // "init" | "window" | "full"
  var lastElapsed: int           // wall - lastFull seen by the last FF publish
  var lastScrubValid: bool

  // Full first-parent walk: every leaf of the new chain is read.
  action publishFull(len: int, writeOk: bool, w: int, p: int, r: int): bool = all {
    chainLen' = len,
    scrub' = if (writeOk) { valid: true, cursor: 0, vt: len, lastFull: w }
             else scrub,
    lastPub' = LEAVES.mapBy(i => if (i < len) p else lastPub.get(i)),
    lastReal' = LEAVES.mapBy(i => if (i < len) r else lastReal.get(i)),
    lastMode' = "full",
  }

  action init = all {
    nondet len = 1.to(MAXLEN - 3).oneOf()
    all {
      chainLen' = len,
      scrub' = { valid: true, cursor: 0, vt: len, lastFull: 0 },
      wall' = 0, real' = 0, pubs' = 0,
      lastPub' = LEAVES.mapBy(i => 0), lastReal' = LEAVES.mapBy(i => 0),
      lastMode' = "init", lastElapsed' = 0, lastScrubValid' = true,
    }
  }

  // A fast-forward publish of k new leaves after dt time (§4.4 step 2, §4.5).
  action FastForward(k: int, dt: int, skew: int, writeOk: bool): bool = {
    val newLen = chainLen + k
    val elapsed = satSub(wall + dt + skew, scrub.lastFull)
    val stale = (not(scrub.valid) and not(BUG_TRUST_INVALID))
                or (not(BUG_IGNORE_AGE) and elapsed > MAX_AGE)
    val w = window(scrub.vt)
    val end = min(scrub.cursor + w, scrub.vt)
    // `end < verified_through` and the rollback guard `end <= prefix.len()`
    val windowPath = not(stale) and end < scrub.vt and end <= chainLen
    val wrapPath = BUG_WRAP_WITHOUT_FULL and not(stale) and not(windowPath)
    val w1 = wall + dt + skew
    val r1 = real + dt
    val p1 = pubs + 1
    all {
      newLen <= MAXLEN, pubs < MAXPUB,
      wall' = w1, real' = r1, pubs' = p1,
      lastElapsed' = elapsed, lastScrubValid' = scrub.valid,
      if (windowPath) all {
        chainLen' = newLen,
        scrub' = if (writeOk) { ...scrub, cursor: end } else scrub,
        // window [cursor, end) plus the freshly walked suffix
        lastPub' = LEAVES.mapBy(i =>
          if ((scrub.cursor <= i and i < end) or (chainLen <= i and i < newLen)) p1
          else lastPub.get(i)),
        lastReal' = LEAVES.mapBy(i =>
          if ((scrub.cursor <= i and i < end) or (chainLen <= i and i < newLen)) r1
          else lastReal.get(i)),
        lastMode' = "window",
      } else if (wrapPath) all {
        chainLen' = newLen,
        scrub' = if (writeOk) { ...scrub, cursor: 0 } else scrub,
        lastPub' = LEAVES.mapBy(i => if (chainLen <= i and i < newLen) p1 else lastPub.get(i)),
        lastReal' = LEAVES.mapBy(i => if (chainLen <= i and i < newLen) r1 else lastReal.get(i)),
        lastMode' = "window",
      } else publishFull(newLen, writeOk, w1, p1, r1),
    }
  }

  // Rewrite/reset: new generation, full walk. A lost scrub write leaves the
  // old generation's state, which the generation binding discards.
  action Rewrite(len: int, dt: int, writeOk: bool): bool = all {
    pubs < MAXPUB,
    wall' = wall + dt, real' = real + dt, pubs' = pubs + 1,
    lastElapsed' = 0, lastScrubValid' = scrub.valid,
    chainLen' = len,
    scrub' = if (writeOk) { valid: true, cursor: 0, vt: len, lastFull: wall + dt }
             else { ...scrub, valid: false },
    lastPub' = LEAVES.mapBy(i => if (i < len) pubs + 1 else lastPub.get(i)),
    lastReal' = LEAVES.mapBy(i => if (i < len) real + dt else lastReal.get(i)),
    lastMode' = "full",
  }

  // Missing / torn / bit-rotted scrub file.
  action CorruptScrub = all {
    scrub.valid,
    scrub' = { ...scrub, valid: false },
    chainLen' = chainLen, wall' = wall, real' = real, pubs' = pubs,
    lastPub' = lastPub, lastReal' = lastReal, lastMode' = lastMode,
    lastElapsed' = lastElapsed, lastScrubValid' = lastScrubValid,
  }

  action step = {
    nondet k = 1.to(2).oneOf()
    nondet dt = 0.to(2).oneOf()
    nondet skew = (if (CLOCK_STEPS_BACK) Set(0, -3) else Set(0)).oneOf()
    nondet writeOk = (if (LOSSY_SCRUB_WRITES) Set(true, false) else Set(true)).oneOf()
    nondet len = 1.to(MAXLEN - 3).oneOf()
    any { FastForward(k, dt, skew, writeOk), Rewrite(len, dt, writeOk), CorruptScrub }
  }

  // ---- properties -------------------------------------------------------------
  pure def leavesOf(n: int): Set[int] = LEAVES.filter(i => i < n)
  // How many publishes a leaf has gone unread.
  def age(i: int): int = pubs - lastPub.get(i)

  // §4.5 claim: every leaf is re-read at least once every LAP_FRACTION
  // (real: 64) fast-forward publishes.
  val SpecPublishBound = leavesOf(chainLen).forall(i => age(i) <= LAP_FRACTION - 1)
  // What the implementation guarantees: a lap is at most LAP_FRACTION + 1
  // publishes (LAP_FRACTION windows, then the full walk).
  val ActualPublishBound = leavesOf(chainLen).forall(i => age(i) <= LAP_FRACTION)
  // §4.5: right after a publish, every leaf was read within MAX_AGE (7 days)
  // of real time.
  val TimeBound = lastMode != "init" implies
    leavesOf(chainLen).forall(i => real - lastReal.get(i) <= MAX_AGE)
  // §4.5: the window path requires FEWER than MAX_AGE seconds elapsed.
  val WindowOnlyWhenFresh = lastMode == "window" implies lastElapsed < MAX_AGE
  // §4.5: missing/corrupt/foreign-generation state always forces a full walk.
  val InvalidForcesFull = (lastMode == "window") implies lastScrubValid

  // ---- canaries (must be violated) ----------------------------------------------
  val CanaryNoWindow = lastMode != "window"
  val CanaryNoLapFull = not(lastMode == "full" and lastScrubValid and lastElapsed <= MAX_AGE)
}

module scrub {
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = false, MAXPUB = 12).*

  // Real constants (512, 64): publishes per lap, i.e. the longest gap between
  // two reads of one leaf, is floor((vt - 1) / w) + 1 for vt > w.
  pure def realWindow(vt: int): int = if (vt / 64 > 512) vt / 64 else 512
  pure def realLap(vt: int): int = (vt - 1) / realWindow(vt) + 1
  run realLapTest = all {
    assert(realLap(64 * 512) == 64),
    assert(realLap(64 * 512 + 1) == 65),      // 32769 leaves: 65 publishes
    assert(realLap(64 * 512 + 63) == 65),
    assert(realLap(64 * 1000 + 63) == 65),
    assert(realLap(999999) == 65),            // just under the 1,000,000 cap
    assert(realLap(1000000) == 64),
    assert(realLap(1000) == 2),
    assert(realLap(64 * 512 - 1) == 64),
  }
}
module scrubLossy {
  import scrubCore(LOSSY_SCRUB_WRITES = true, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = false, MAXPUB = 12).*
}
module scrubClockBack {
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = true,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = false, MAXPUB = 12).*
}
module mutIgnoreAge {        // violates TimeBound
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = true, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = false, MAXPUB = 12).*
}
module mutWrapWithoutFull {  // violates ActualPublishBound
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = true,
                   BUG_TRUST_INVALID = false, MAXPUB = 12).*
}
module mutTrustInvalid {     // violates InvalidForcesFull
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = true, MAXPUB = 12).*
}
// Unbounded publish count, for TLC with the relative-age VIEW in README.md.
module scrubUnbounded {
  import scrubCore(LOSSY_SCRUB_WRITES = false, CLOCK_STEPS_BACK = false,
                   BUG_IGNORE_AGE = false, BUG_WRAP_WITHOUT_FULL = false,
                   BUG_TRUST_INVALID = false, MAXPUB = 1000000000).*
}
