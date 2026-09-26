// -*- mode: Bluespec; -*-
// Deterministic scenarios for refs.qnt: each run pins one interleaving and
// checks the expected outcome. Scenarios marked MUTANT / WITNESS demonstrate
// that the corresponding invariant in refs.qnt can fail (non-vacuity) or that
// a documented gap is reachable.
module refs_test {
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).* from "./refs"

  pure def op(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    { kind: kind, tree: t, ref: r, cond: c, value: v, del: d }

  pure val SAFE_INIT = NO_FAULTS

  action beginOp(p: Proc, o: Op): bool = begin(p, o, false)

  // Two local conditional writers from DIFFERENT worktrees (no shared
  // worktree.lock) race Match(1) -> 2 on refs/heads/a. refs-<ref>.lock
  // blocks the second; it then observes 2 and conflicts (SPEC-REFS §5.1,
  // test vector 5 exactly-one-winner).
  run localMatchExactlyOneWinnerTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("commit", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // blocked on refs-<a>.lock
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "conflict" })

  // #658: rename's delete_ref_if_matches vs a concurrent Match advance.
  run renameDeleteVsCommitTest =
    initFixed(SAFE_INIT, 1, ABSENT, ABSENT)
      .then(beginOp("p1", op("branch", 0, 0, Match(1), 1, true)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(beginOp("p2", op("commit", 0, 0, Match(1), 2, false)))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))            // history lock held by p1
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == ABSENT, lastAction.outcome == "conflict" })

  // An unconditional (Any) write cannot slip into a Match critical section.
  run anyWaitsForMatchTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("updateRef", 1, 0, Any, 1, false)))
      .then(acquire("p2"))
      .expect(not(canMove("p2")))
      .then(commitRef("p1"))
      .expect(and { Safety, disk.get(0) == 2 })

  // Missing is decided by O_EXCL on the actual file: at most one winner even
  // WITHOUT the ref lock (SPEC-REFS §8 ".missing succeeds at most once").
  run missingAtomicEvenWithoutLockTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, ABSENT, ABSENT, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Missing, 1, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Missing, 2, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 1, lastAction.outcome == "conflict" })

  // MUTANT (pre-#637): no refs-<ref>.lock -> Match lost update; NoLostUpdateLocal fails.
  run mutantNoRefLockLostUpdateTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("updateRef", 1, 0, Match(1), 1, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { not(NoLostUpdateLocal), lastAction.outcome == "ok" })

  // File transport: RefLock serialises two Match CAS on the same root.
  run fileMatchSerialisedTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(acquire("p1"))
      .expect(not(canMove("p2")))
      .then(readRef("p1")).then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "conflict" })

  // MUTANT: file transport without RefLock -> NoLostUpdateFile fails.
  run mutantNoFileLockTest =
    initFixed({ ...NO_FAULTS, noFileLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("file", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 1, false)))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(not(NoLostUpdateFile))

  // WITNESS (documented, SPEC-REFS §5.1/§8): memory-transport .match race.
  run memMatchRaceWitnessTest =
    initFixed(SAFE_INIT, ABSENT, ABSENT, 1)
      .then(beginOp("p1", op("mem", 0, 0, Match(1), 2, false)))
      .then(beginOp("p2", op("mem", 0, 0, Match(1), 1, false)))
      .then(readRef("p1")).then(readRef("p2"))
      .then(commitRef("p1")).then(commitRef("p2"))
      .expect(and { Safety, not(WitnessMemMatchRace) })

  // WITNESS — DOCUMENTED GAP (SPEC-CONCURRENCY §3.1): a local Match write
  // under refs-<ref>.lock and a file-transport write under RefLock hit the
  // same file with no common lock. Safety (per-domain) still holds.
  run crossDomainGapWitnessTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("commit", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(readRef("p1"))
      .then(beginOp("p2", op("file", 0, 0, Match(1), 2, false)))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .then(commitRef("p1"))
      .expect(and { Safety, not(WitnessCrossDomainGap), lastAction.outcome == "ok" })

  // Under §4 order a reversed plan is not even startable.
  run reversedPlanRejectedTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(begin("p1", op("gc", 0, 0, Any, 1, false), true).fail())

  // MUTANT: gc taking its worktree locks in reverse -> deadlock with a
  // canonical gc (SPEC-CONCURRENCY §4). NoDeadlock and LockOrderRespected fail.
  run mutantMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("gc", 0, 0, Any, 1, false), false))
      .then(begin("p2", op("gc", 0, 0, Any, 1, false), true))
      .then(acquire("p1"))                  // p1: worktrees.lock
      .then(acquire("p2")).then(acquire("p2")) // p2: worktree.lock(1), worktree.lock(0)
      .expect(not(canMove("p1")))
      .expect(not(canMove("p2")))
      .expect(and { not(NoDeadlock), not(LockOrderRespected) })

  // MUTANT: commit taking refs-<ref> before worktree.lock (in-chain reversal).
  run mutantCommitMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("commit", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("commit", 0, 0, Match(1), 2, false), true))
      .then(acquire("p1"))                        // p1: worktree.lock(0)
      .then(acquire("p2")).then(acquire("p2"))    // p2: refs-a, history-a
      .expect(not(NoDeadlock))

  // MUTANT: a pure 3-cycle (no 2-cycle) — exercises the 3-cycle clause of
  // NoDeadlock. p1 holds wt(main) wants refs-a; p2 (reversed) holds refs-a
  // wants wt(1); p3 (reversed gc) holds wt(1) wants wt(main).
  run mutantThreeCycleDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("updateRef", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("updateRef", 1, 0, Match(1), 2, false), true))
      .then(begin("p3", op("gc", 0, 0, Any, 1, false), true))
      .then(acquire("p1")).then(acquire("p2")).then(acquire("p3"))
      .expect(and {
        not(NoDeadlock),
        not(PROCS.exists(a => PROCS.exists(b => waitsFor(a, b) and waitsFor(b, a)))),
        not(canMove("p1")), not(canMove("p2")), not(canMove("p3")),
      })

  // §3.2: while gc holds every worktree.lock, a producer cannot record.
  run gcExcludesRecordTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("gc", 0, 0, Any, 1, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .then(expireRead("p1"))
      .then(beginOp("p2", op("amend", 1, 0, Match(1), 2, false)))
      .expect(not(canMove("p2")))
      .then(expireWrite("p1")).then(release("p1"))
      .then(acquire("p2")).then(record("p2")).then(acquire("p2")).then(acquire("p2"))
      .expect(and { Safety, recLog == Set(1) })

  // MUTANT: gc expiring under worktrees.lock only -> record interleaves and
  // the entry is lost. NoRecordExpireInterleave and ExpireHoldsSuperset fail.
  run mutantGcSkipTreesTest =
    initFixed({ ...NO_FAULTS, gcSkipTrees: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("gc", 0, 0, Any, 1, false)))
      .then(acquire("p1")).then(expireRead("p1"))
      .then(beginOp("p2", op("amend", 1, 0, Match(1), 2, false)))
      .then(acquire("p2")).then(record("p2")).then(acquire("p2")).then(acquire("p2"))
      .expect(not(ExpireHoldsSuperset))
      .then(expireWrite("p1"))
      .expect(and { not(NoRecordExpireInterleave), lostRecords == Set(1) })

  // SPEC-REFS §5.1 mixed-mutation contract: an unconditional delete
  // (branch -d, delete_ref) waits for a Match in flight on the same ref.
  run deleteWaitsForMatchTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("branch", 0, 0, Any, 1, true)))
      .then(acquire("p2")).then(acquire("p2"))
      .expect(not(canMove("p2")))            // blocked on refs-<a>.lock
      .then(commitRef("p1")).then(release("p1"))
      .then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .expect(and { Safety, disk.get(0) == ABSENT, lastAction.outcome == "ok" })

  // MUTANT (pre-#637): the same unconditional delete lands inside the Match
  // window; the Match then resurrects the deleted ref. NoLostUpdateLocal fails.
  run mutantNoRefLockDeleteTest =
    initFixed({ ...NO_FAULTS, noRefLock: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(readRef("p1"))
      .then(beginOp("p2", op("branch", 0, 0, Any, 1, true)))
      .then(acquire("p2")).then(acquire("p2")).then(readRef("p2")).then(commitRef("p2"))
      .then(commitRef("p1"))
      .expect(and { not(NoLostUpdateLocal), disk.get(0) == 2 })

  // MUTANT: a broken (non-exclusive) kernel lock lets two processes hold
  // worktree.lock(main) at once. LockOwnership fails.
  run mutantRacyAcquireTest =
    initFixed({ ...NO_FAULTS, racyAcquire: true }, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 0, 0, Any, 2, false)))
      .then(beginOp("p2", op("updateRef", 0, 1, Any, 2, false)))
      .then(acquire("p1")).then(acquire("p2"))
      .expect(not(LockOwnership))

  // amend records under its worktree.lock alone (commit.rs: "Record it
  // BEFORE moving the branch (under the worktree lock)"), before it takes the
  // history and ref locks — so a record can land while another process holds
  // those, and gc's worktree.lock superset still excludes it.
  run amendRecordsBeforeRefLocksTest =
    initFixed(SAFE_INIT, 1, 1, ABSENT)
      .then(beginOp("p1", op("updateRef", 1, 0, Match(1), 2, false)))
      .then(acquire("p1")).then(acquire("p1"))  // wt(1), refs-a
      .then(beginOp("p2", op("amend", 0, 0, Match(1), 2, false)))
      .then(acquire("p2"))                      // wt(main)
      .expect(procs.get("p2").pc == "record")
      .then(record("p2")).then(acquire("p2"))   // history-a
      .expect(not(canMove("p2")))               // refs-a held by p1
      .expect(and { Safety, recLog == Set(1) })

  // checkout -b takes all four §4 classes in order; a gc started later
  // blocks on worktrees.lock, and one started first blocks the checkout.
  run checkoutFourLockChainTest =
    initFixed(SAFE_INIT, ABSENT, 1, ABSENT)
      .then(beginOp("p1", op("checkout", 1, 0, Missing, 2, false)))
      .then(acquire("p1")).then(acquire("p1")).then(acquire("p1")).then(acquire("p1"))
      .expect(and { LockOrderRespected, owner.get(0) == "p1", owner.get(2) == "p1",
                    owner.get(3) == "p1", owner.get(5) == "p1" })
      .then(beginOp("p2", op("gc", 0, 0, Any, 1, false)))
      .expect(not(canMove("p2")))
      .then(readRef("p1")).then(commitRef("p1"))
      .expect(and { Safety, disk.get(0) == 2, lastAction.outcome == "ok" })

  // MUTANT: a reversed checkout -b (refs-a first) against a canonical commit
  // holding wt(main) and waiting for refs-a -> 2-cycle via different classes.
  run mutantCheckoutMisorderDeadlockTest =
    initFixed({ ...NO_FAULTS, misorder: true }, 1, 1, ABSENT)
      .then(begin("p1", op("commit", 0, 0, Match(1), 2, false), false))
      .then(begin("p2", op("checkout", 0, 0, Any, 2, false), true))
      .then(acquire("p1"))                        // p1: wt(main)
      .then(acquire("p2")).then(acquire("p2"))    // p2: refs-a, history-a
      .expect(and { not(NoDeadlock), not(LockOrderRespected) })
}
