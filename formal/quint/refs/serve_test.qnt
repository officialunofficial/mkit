// -*- mode: Bluespec; -*-
// Deterministic scenarios for serve.qnt. MUTANT scenarios show an invariant
// can fail (non-vacuity); WITNESS scenarios reach a documented gap.
module serve_test {
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false,
               serverLockShared: false, ftSlow: false }).* from "./serve"


  action initWith(o: Set[str]): bool = initFixed(SFAULTS_NONE, o)
  pure def withF(f: str): SFaults =
    { sweepUnlocked: f == "sweepUnlocked", sweepUnderShared: f == "sweepUnderShared",
      serverSkipsServe: f == "serverSkipsServe", serverLockShared: f == "serverLockShared",
      ftSlow: f == "ftSlow" }

  // A lone `mkit serve` gets serve.lock exclusively, sweeps the stale
  // orphan (not the fresh one), drops it and serves under the shared lock.
  run loneServeSweepsTest =
    initWith(Set("fresh", "stale"))
      .then(startServe("s1"))
      .expect(and { serveEx == "s1", spc.get("s1") == "sweep" })
      .then(sweep("s1")).then(drop("s1")).then(takeShared("s1"))
      .expect(and { Safety, orphans == Set("fresh"), sweptOrphan, serveSh == Set("s1") })

  // The race the exclusive hold closes: `mkit-server` is up with a stalled
  // streaming upload (its temp file is older than the age bound); a new
  // `mkit serve` finds serve.lock busy and skips the sweep.
  run stalledServerUploadSurvivesTest =
    initWith(Set("stale"))
      .then(startServer("s1")).then(takeShared("s1"))
      .then(beginUpload("s1")).then(age("s1"))
      .then(startServe("s2"))
      .expect(and { lastAction.outcome == "skipSweep", spc.get("s2") == "wantShared" })
      .then(takeShared("s2"))
      .expect(and { Safety, upload.get("s1") == "stale", orphans == Set("stale"),
                    serveSh == Set("s1", "s2") })
      .then(finishUpload("s1"))
      .expect(Safety)

  // A starting server blocks on the shared lock while a `mkit serve` sweeps.
  run serverWaitsForSweepTest =
    initWith(Set())
      .then(startServe("s1"))
      .then(startServer("s2"))
      .expect(serveEx == "s1")                 // takeShared(s2) disabled: exclusive holder in
      .then(sweep("s1")).then(drop("s1")).then(takeShared("s2")).then(takeShared("s1"))
      .expect(and { Safety, serveSh == Set("s1", "s2"), serverLock == Set("s2") })

  // server.lock: a second mkit-server cannot start while one is live, and
  // can once it stops (crash releases the kernel lock).
  run oneMkitServerTest =
    initWith(Set())
      .then(startServer("s1"))
      .expect(serverLock == Set("s1"))         // startServer(s2) disabled: server.lock held
      .then(takeShared("s1")).then(stop("s1")).then(startServer("s2"))
      .expect(and { Safety, serverLock == Set("s2") })

  // A crash mid-upload leaves an orphan; the next lone `mkit serve` sweeps
  // it once stale.
  run crashedUploadSweptLaterTest =
    initWith(Set())
      .then(startServer("s1")).then(takeShared("s1")).then(beginUpload("s1"))
      .then(stop("s1"))
      .expect(orphans == Set("fresh"))
      .then(ageOrphan).then(startServe("s2")).then(sweep("s2"))
      .expect(and { Safety, orphans == Set(), sweptOrphan })

  // A lockless FileTransport writer (mkit+file:// push) is protected only by
  // the age bound: its one-shot write never goes stale here, so the sweep
  // leaves it alone.
  run fileTransportUploadKeptTest =
    initWith(Set())
      .then(beginUpload(FT))                   // age(FT) is disabled without ftSlow
      .then(startServe("s1")).then(sweep("s1"))
      .expect(and { Safety, upload.get(FT) == "fresh" })

  // Detection: a local command probing while a server is up is warned.
  run probeWarnsTest =
    initWith(Set())
      .then(startServe("s1")).then(sweep("s1")).then(drop("s1")).then(takeShared("s1"))
      .then(localBegin("w"))
      .expect(and { Safety, warned.get("w") })

  // WITNESS (SPEC-CONCURRENCY §3.1 "Detection is one-directional"): a server
  // that starts during a local critical section is not detected by it.
  run lateServerUndetectedWitnessTest =
    initWith(Set())
      .then(localBegin("w"))
      .expect(not(warned.get("w")))
      .then(startServer("s1")).then(takeShared("s1"))
      .expect(and { Safety, not(WitnessUndetectedLateServer) })

  // MUTANT sweepUnlocked: a starting `mkit serve` sweeps although mkit-server
  // is up with a stalled upload, deleting its live temp file.
  run mutantSweepUnlockedTest =
    initFixed(withF("sweepUnlocked"), Set())
      .then(startServer("s1")).then(takeShared("s1"))
      .then(beginUpload("s1")).then(age("s1"))
      .then(startServe("s2"))
      .expect(not(SweepAlone))
      .then(sweep("s2"))
      .expect(and { not(NoLiveUploadSwept), upload.get("s1") == "lost" })

  // MUTANT serverSkipsServe: mkit-server up without serve.lock -> a
  // starting `mkit serve` gets it exclusively and sweeps the stalled upload;
  // a local probe misses the server.
  run mutantServerSkipsServeTest =
    initFixed(withF("serverSkipsServe"), Set())
      .then(startServer("s1"))
      .expect(not(UpServersHoldServeShared))
      .then(localBegin("w"))
      .expect(not(NoMissedDetection))
      .then(beginUpload("s1")).then(age("s1"))
      .then(startServe("s2")).then(sweep("s2"))
      .expect(not(NoLiveUploadSwept))

  // MUTANT serverLockShared: two mkit-servers on one root.
  run mutantServerLockSharedTest =
    initFixed(withF("serverLockShared"), Set()).then(startServer("s1")).then(startServer("s2"))
      .expect(not(OneMkitServer))

  // MUTANT sweepUnderShared: sweeping under the SHARED lock does not exclude
  // another server's stalled upload.
  run mutantSweepUnderSharedTest =
    initFixed(withF("sweepUnderShared"), Set())
      .then(startServer("s1")).then(takeShared("s1"))
      .then(beginUpload("s1")).then(age("s1"))
      .then(startServe("s2")).then(takeShared("s2"))
      .expect(not(SweepAlone))
      .then(sweep("s2"))
      .expect(not(NoLiveUploadSwept))

  // ASSUMPTION WITNESS: a FileTransport write outliving the 1 h age bound
  // (nothing locks it) would be swept by a lone `mkit serve`.
  run ftSlowWitnessTest =
    initFixed(withF("ftSlow"), Set())
      .then(beginUpload(FT)).then(age(FT))
      .then(startServe("s1"))
      .expect(SweepAlone)
      .then(sweep("s1"))
      .expect(not(NoLiveUploadSwept))
}

module served_test {
  import servedNames(FAULTS = { checkAfterRead: false, headCheckedLate: false, listNoSkip: false }).* from "./serve"

  // ReadRef("main") with a legacy <root>/main present: refused by name,
  // storage untouched, never "absent" nor the legacy value.
  run readMainRefusedTest =
    initFixed(SNFAULTS_NONE, 1, 0).then(recv("ReadRef", "M", "M")).then(check)
      .expect(and { phase == "reply", reply == "outsideRefs" })
      .then(answer).expect(Safety)

  // AdvanceRefs with a valid packmap and an over-long head: refused as too
  // long before the packmap is written.
  run advanceLongHeadRefusedTest =
    initFixed(SNFAULTS_NONE, 0, 0).then(recv("AdvanceRefs", "P", "L")).then(check)
      .expect(and { reply == "tooLong", store.get("P") == 1, wrote == Set() })
      .then(answer).expect(Safety)

  // A served AdvanceRefs writes packmap then head.
  run advanceOkTest =
    initFixed(SNFAULTS_NONE, 0, 0).then(recv("AdvanceRefs", "P", "A")).then(check).then(storage1).then(storage2)
      .expect(and { reply == "ok", store.get("P") == 2, store.get("A") == 2 })
      .then(answer).expect(Safety)

  // The listing skips a legacy over-long ref and the <root>/main file.
  run listingSkipsLegacyTest =
    initFixed(SNFAULTS_NONE, 1, 1).then(recv("ListRefs", "A", "A")).then(storage1)
      .expect(and { listed == Set("A", "P"), Safety })

  // MUTANT checkAfterRead (pre-v3 behaviour): ReadRef("main") answers from
  // storage ("absent" when no legacy file).
  run mutantCheckAfterReadTest =
    initFixed({ ...SNFAULTS_NONE, checkAfterRead: true }, 0, 0).then(recv("ReadRef", "M", "M")).then(storage1)
      .expect(and { reply == "absent", not(RefuseBeforeStorage), not(ExplicitRefusal) })

  // MUTANT headCheckedLate: packmap written, then the head refused -> a
  // refused request left a partial write.
  run mutantHeadCheckedLateTest =
    initFixed({ ...SNFAULTS_NONE, headCheckedLate: true }, 0, 0).then(recv("AdvanceRefs", "P", "M")).then(check).then(storage1).then(storage2)
      .expect(and { reply == "outsideRefs", store.get("P") == 2, not(RefusedWritesNothing),
                    not(RefuseBeforeStorage) })

  // MUTANT listNoSkip: the listing returns the legacy files.
  run mutantListNoSkipTest =
    initFixed({ ...SNFAULTS_NONE, listNoSkip: true }, 1, 1).then(recv("ListRefs", "A", "A")).then(storage1)
      .expect(not(ListingServedOnly))
}
