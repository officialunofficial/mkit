// Loose-store gc versus a BulkWriter write or cached-object reuse.
// One object is sufficient to expose the split metadata-read/unlink race.
// The full retention-root graph and worktree locks remain in gc.qnt.
module sweepCore {
  const MUTANT: str        // "none", "staleCheck", "noLock", "noRefresh"
  const GRACE: int
  const PUBLISH_MODE: str  // "fast" (< GRACE after refresh) or "raw"
  pure val MAXT = 5
  pure def age(now: int, at: int): int = if (now > at) now - at else 0

  var clock: int
  var present: bool
  var mtime: int
  var published: bool
  var gcPhase: str         // idle -> read -> candidate -> locked -> checked -> unlinked -> idle
  var gcNow: int
  var gcLive: bool
  var checkedOld: bool
  var lockHolder: str      // "none", "gc" exclusive, "writer" shared
  var writerPhase: str    // idle -> locked -> touched -> ready -> done
  var refreshedAt: int
  var recentPruned: bool
  var livePruned: bool
  var pruned: bool
  var crashedBefore: bool
  var crashedAfter: bool

  action init = all {
    clock' = 0, present' = true, mtime' = 0, published' = false,
    gcPhase' = "idle", gcNow' = 0, gcLive' = false, checkedOld' = false,
    lockHolder' = "none", writerPhase' = "idle", refreshedAt' = 0,
    recentPruned' = false, livePruned' = false, pruned' = false,
    crashedBefore' = false, crashedAfter' = false,
  }
  action keepStore = all { present' = present, mtime' = mtime, published' = published }
  action keepGc = all {
    gcPhase' = gcPhase, gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
  }
  action keepWriter = all { writerPhase' = writerPhase, refreshedAt' = refreshedAt }
  action keepHistory = all {
    recentPruned' = recentPruned, livePruned' = livePruned, pruned' = pruned,
    crashedBefore' = crashedBefore, crashedAfter' = crashedAfter,
  }
  action Tick = all {
    clock < MAXT, clock' = clock + 1,
    keepStore, keepGc, keepWriter, keepHistory, lockHolder' = lockHolder,
  }

  // One shared lock spans the existing-file read and refresh, or new write.
  // A map-cache hit uses this same path, at most once per object per run.
  action WriterBegin = all {
    writerPhase == "idle", lockHolder == "none",
    writerPhase' = "locked", lockHolder' = "writer", refreshedAt' = refreshedAt,
    clock' = clock, keepStore, keepGc, keepHistory,
  }
  action WriterTouch = all {
    writerPhase == "locked",
    present' = true,
    mtime' = if (not(present) or MUTANT != "noRefresh") clock else mtime,
    writerPhase' = "touched", refreshedAt' = clock,
    lockHolder' = lockHolder, clock' = clock, published' = published, keepGc, keepHistory,
  }
  action WriterRelease = all {
    writerPhase == "touched",
    writerPhase' = "ready", lockHolder' = "none", refreshedAt' = refreshedAt,
    clock' = clock, keepStore, keepGc, keepHistory,
  }
  def publishEnabled: bool = writerPhase == "ready" and
    (PUBLISH_MODE == "raw" or clock - refreshedAt < GRACE)
  action WriterPublish = all {
    publishEnabled,
    published' = true, writerPhase' = "done", refreshedAt' = refreshedAt,
    present' = present, mtime' = mtime, clock' = clock, lockHolder' = lockHolder,
    keepGc, keepHistory,
  }
  action WriterAbort = all {
    writerPhase == "ready", not(publishEnabled),
    writerPhase' = "done", refreshedAt' = refreshedAt,
    clock' = clock, keepStore, keepGc, keepHistory, lockHolder' = lockHolder,
  }

  action GcBegin = all {
    gcPhase == "idle",
    gcPhase' = "read", gcNow' = clock, gcLive' = published, checkedOld' = false,
    clock' = clock, keepStore, keepWriter, keepHistory, lockHolder' = lockHolder,
  }
  def old: bool = present and not(gcLive) and age(gcNow, mtime) >= GRACE
  // The initial unlocked metadata read is only a candidate filter.
  action GcRead = all {
    gcPhase == "read",
    gcPhase' = if (old) "candidate" else "idle", checkedOld' = old,
    gcNow' = gcNow, gcLive' = gcLive,
    clock' = clock, keepStore, keepWriter, keepHistory, lockHolder' = lockHolder,
  }
  action GcLock = all {
    gcPhase == "candidate", lockHolder == "none",
    gcPhase' = "locked", lockHolder' = if (MUTANT == "noLock") "none" else "gc",
    gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
    clock' = clock, keepStore, keepWriter, keepHistory,
  }
  // Busy lock or an unreadable final metadata result: keep the object.
  action GcKeep = all {
    gcPhase == "candidate" or gcPhase == "locked",
    gcPhase' = "idle", lockHolder' = if (lockHolder == "gc") "none" else lockHolder,
    gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
    clock' = clock, keepStore, keepWriter, keepHistory,
  }
  action GcCheck = all {
    gcPhase == "locked",
    gcPhase' = "checked",
    checkedOld' = if (MUTANT == "staleCheck") checkedOld else old,
    gcNow' = gcNow, gcLive' = gcLive,
    clock' = clock, keepStore, keepWriter, keepHistory, lockHolder' = lockHolder,
  }
  // Final re-stat and unlink share the exclusive lock. No path is renamed.
  action GcUnlink = all {
    gcPhase == "checked",
    present' = if (checkedOld) false else present,
    recentPruned' = if (checkedOld and present and age(clock, mtime) < GRACE) true else recentPruned,
    livePruned' = if (checkedOld and present and published) true else livePruned,
    pruned' = if (checkedOld and present) true else pruned,
    gcPhase' = "unlinked", lockHolder' = lockHolder,
    gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
    mtime' = mtime, published' = published, clock' = clock, keepWriter,
    crashedBefore' = crashedBefore, crashedAfter' = crashedAfter,
  }
  action GcFinish = all {
    gcPhase == "unlinked",
    gcPhase' = "idle", lockHolder' = if (lockHolder == "gc") "none" else lockHolder,
    gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
    clock' = clock, keepStore, keepWriter, keepHistory,
  }
  // Process death releases the kernel lock. Before unlink the canonical
  // object survives; after unlink only an old unmarked object was removed.
  action GcCrash = all {
    gcPhase != "idle",
    gcPhase' = "idle", lockHolder' = if (lockHolder == "gc") "none" else lockHolder,
    gcNow' = gcNow, gcLive' = gcLive, checkedOld' = checkedOld,
    crashedBefore' = if (gcPhase == "checked" and present) true else crashedBefore,
    crashedAfter' = if (gcPhase == "unlinked" and not(present)) true else crashedAfter,
    recentPruned' = recentPruned, livePruned' = livePruned, pruned' = pruned,
    clock' = clock, keepStore, keepWriter,
  }
  action WriterCrash = all {
    writerPhase == "locked" or writerPhase == "touched",
    writerPhase' = "done", refreshedAt' = refreshedAt, lockHolder' = "none",
    clock' = clock, keepStore, keepGc, keepHistory,
  }
  action step = any {
    Tick, WriterBegin, WriterTouch, WriterRelease, WriterPublish, WriterAbort,
    GcBegin, GcRead, GcLock, GcKeep, GcCheck, GcUnlink, GcFinish, GcCrash, WriterCrash,
  }

  val NoDangling = published implies present
  val NoRecentPruned = not(recentPruned)
  val NoLivePruned = not(livePruned)
  val NoLeakedLock =
    (lockHolder == "gc" implies (gcPhase == "locked" or gcPhase == "checked" or gcPhase == "unlinked")) and
    (lockHolder == "writer" implies (writerPhase == "locked" or writerPhase == "touched"))
  val All = NoDangling and NoRecentPruned and NoLivePruned and NoLeakedLock
  val CanaryNoPrune = not(pruned)
  val CanaryNoPublishAfterPrune = not(pruned and published)
  val CanaryNoCrashBefore = not(crashedBefore)
  val CanaryNoCrashAfter = not(crashedAfter)
}

module sweepFixed {
  import sweepCore(MUTANT = "none", GRACE = 2, PUBLISH_MODE = "fast").*

  run refreshBetweenReadAndUnlinkTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead)
      .then(WriterBegin).then(WriterTouch).then(WriterRelease)
      .then(GcLock).then(GcCheck).then(GcUnlink).then(WriterPublish)
      .expect(present and published and All)
  run crashBeforeUnlinkTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead).then(GcLock).then(GcCheck)
      .then(GcCrash).expect(present and lockHolder == "none" and All)
      .then(WriterBegin).then(WriterTouch).then(WriterRelease).then(WriterPublish)
      .expect(present and published and All)
  run crashAfterUnlinkTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead).then(GcLock).then(GcCheck)
      .then(GcUnlink).then(GcCrash)
      .expect(not(present) and lockHolder == "none" and All)
      .then(WriterBegin).then(WriterTouch).then(WriterRelease).then(WriterPublish)
      .expect(present and published and All)
  run writerContentionKeepsTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead)
      .then(WriterBegin).then(GcKeep).then(WriterTouch).then(WriterRelease).then(WriterPublish)
      .expect(present and published and All)
}
module sweepSplit {
  import sweepCore(MUTANT = "staleCheck", GRACE = 2, PUBLISH_MODE = "fast").*
  run staleReadLossTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead)
      .then(WriterBegin).then(WriterTouch).then(WriterRelease)
      .then(GcLock).then(GcCheck).then(GcUnlink).then(WriterPublish)
      .expect(not(NoDangling) and not(NoRecentPruned))
}
module sweepNoLock {
  import sweepCore(MUTANT = "noLock", GRACE = 2, PUBLISH_MODE = "fast").*
  run refreshAfterFinalCheckTest =
    init.then(Tick).then(Tick).then(GcBegin).then(GcRead).then(GcLock).then(GcCheck)
      .then(WriterBegin).then(WriterTouch).then(WriterRelease).then(GcUnlink).then(WriterPublish)
      .expect(not(NoDangling) and not(NoRecentPruned))
}
module sweepNoRefresh {
  import sweepCore(MUTANT = "noRefresh", GRACE = 2, PUBLISH_MODE = "fast").*
  run cacheHitLossTest =
    init.then(Tick).then(Tick).then(WriterBegin).then(WriterTouch).then(WriterRelease)
      .then(GcBegin).then(GcRead).then(GcLock).then(GcCheck).then(GcUnlink).then(WriterPublish)
      .expect(not(NoDangling) and NoRecentPruned)
}
module sweepSlow {
  import sweepCore(MUTANT = "none", GRACE = 2, PUBLISH_MODE = "raw").*
  run graceExpiredTest =
    init.then(WriterBegin).then(WriterTouch).then(WriterRelease).then(Tick).then(Tick)
      .then(GcBegin).then(GcRead).then(GcLock).then(GcCheck).then(GcUnlink).then(WriterPublish)
      .expect(not(NoDangling) and NoRecentPruned)
}
module sweepGrace0 {
  import sweepCore(MUTANT = "none", GRACE = 0, PUBLISH_MODE = "raw").*
  run zeroGraceLossTest =
    init.then(WriterBegin).then(WriterTouch).then(WriterRelease)
      .then(GcBegin).then(GcRead).then(GcLock).then(GcCheck).then(GcUnlink).then(WriterPublish)
      .expect(not(NoDangling) and NoRecentPruned)
}
