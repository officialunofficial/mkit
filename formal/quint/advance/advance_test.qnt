// -*- mode: Bluespec; -*-
// Pinned interleavings for advance.qnt. Each run fixes one interleaving and
// checks its outcome; MUTANT / GAP runs show an invariant failing
// (non-vacuity) or a documented gap (a finding) being reachable.
//
// Pusher ids are 1 and 2; tips and conditions are in each module's import.

// Ordered store (packmap then head), SPEC client. p1: 0 -> 1, p2: 0 -> 2.
module ordered_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  // A landed advance whose response is lost: the ladder re-issues it, the
  // re-issue's packmap precondition fails on our own node, the loop finds
  // our pack chained and commits the head alone, that RefConflict is our own
  // landed write, and read_ref(head) == tip reports success (SPEC-TRANSPORT
  // §7 as reconciled).
  run reissuedLandedAdvanceIsSuccessTest =
    init
      .then(start(1)).then(loop(1))
      .then(srvAdvFirst(1)).then(srvAdvSecond(1))
      .expect(and { hd == 1, pm == [0, 1], ps.get(1).resp == "Committed" })
      .then(lose(1))                          // response lost, ladder re-issues
      .then(srvAdvFirst(1))
      .expect(ps.get(1).resp == "PackmapConflict")
      .then(deliver(1)).then(loop(1))         // our pack is chained: head only
      .expect(ps.get(1).pc == "updSrv")
      .then(srvUpd(1))
      .expect(ps.get(1).resp == "conflict")   // Match(0) vs our own tip 1
      .then(deliver(1)).then(readHead(1))
      .expect(and { ps.get(1).report == "success", All })

  // Torn ordered advance (crash between packmap and head): the head stays,
  // the packmap is a superset, DeltaTransfer holds; the re-issue completes.
  run tornAdvanceThenReissueTest =
    init
      .then(start(1)).then(loop(1))
      .then(srvAdvFirst(1)).then(srvCrash(1))
      .expect(and { hd == 0, pm == [0, 1], DeltaTransfer })
      .then(lose(1)).then(srvAdvFirst(1))
      .expect(ps.get(1).resp == "PackmapConflict")
      .then(deliver(1)).then(loop(1)).then(srvUpd(1))
      .expect(ps.get(1).resp == "ok")
      .then(deliver(1))
      .expect(and { hd == 1, ps.get(1).report == "success", All })

  // Genuine race: p2 read the packmap before p1's advance (PackmapConflict),
  // re-reads, appends onto p1's node, loses the head CAS, reads the head
  // (1 != 2) and reports NonFastForward. The packmap is a superset.
  run genuineConflictIsNffTest =
    init
      .then(start(1)).then(start(2))
      .then(loop(2))                                         // p2 reads [0]
      .then(loop(1)).then(srvAdvFirst(1)).then(srvAdvSecond(1)).then(deliver(1))
      .then(srvAdvFirst(2))
      .expect(ps.get(2).resp == "PackmapConflict")
      .then(deliver(2)).then(loop(2)).then(srvAdvFirst(2)).then(srvAdvSecond(2))
      .expect(and { ps.get(2).resp == "HeadConflict", pm == [0, 1, 2], hd == 1 })
      .then(deliver(2)).then(readHead(2))
      .expect(and { ps.get(1).report == "success", ps.get(2).report == "nff", All })

  // The gate: on an ordered store a push never re-baselines.
  run gateKeepsOrderedAppendingTest =
    init.then(start(2)).expect(not(ps.get(2).reset))
}

// The pre-reconciliation client (conflict => NonFastForward, no read_ref).
module ordered_oldConflict_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: true, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  // MUTANT: the same re-issue as reissuedLandedAdvanceIsSuccessTest is
  // reported NonFastForward although the head holds our tip.
  run oldClientSpuriousNffTest =
    init
      .then(start(1)).then(loop(1))
      .then(srvAdvFirst(1)).then(srvAdvSecond(1))
      .then(lose(1)).then(srvAdvFirst(1))
      .then(deliver(1)).then(loop(1)).then(srvUpd(1)).then(deliver(1))
      .expect(and { hd == 1, ps.get(1).report == "nff", not(ConflictHonest) })
}

// Atomic store with the replay ledger: the re-issue gets the stored result.
module ledger_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = true, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: true, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  // Even the old client is honest here: the re-issue answers Committed.
  run ledgerReplaysCommittedTest =
    init
      .then(start(1)).then(loop(1)).then(srvAdvAtomic(1))
      .expect(and { ps.get(1).reset, pm == [1], hd == 1 })
      .then(lose(1)).then(srvAdvAtomic(1))
      .expect(and { lastAction.what == "replayed", ps.get(1).resp == "Committed" })
      .then(deliver(1))
      .expect(and { ps.get(1).report == "success", All })
}

// Atomic store, no ledger: a landed re-baseline re-issued.
module atomic_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  // A reset skips the idempotency short-cut: the loop rebuilds node [1],
  // whose packmap Match([1]) holds, and the head precondition fails on our
  // own tip; read_ref disambiguates to success.
  run reissuedResetIsSuccessTest =
    init
      .then(start(1)).then(loop(1)).then(srvAdvAtomic(1))
      .then(lose(1)).then(srvAdvAtomic(1))
      .expect(ps.get(1).resp == "PackmapConflict")
      .then(deliver(1)).then(loop(1)).then(srvAdvAtomic(1))
      .expect(ps.get(1).resp == "HeadConflict")
      .then(deliver(1)).then(readHead(1))
      .expect(and { ps.get(1).report == "success", All })

  // An atomic conflict writes nothing: p2's reset loses the head CAS and
  // leaves p1's packmap alone.
  run atomicConflictWritesNothingTest =
    init
      .then(start(1)).then(start(2))
      .then(loop(1)).then(srvAdvAtomic(1))
      .then(loop(2)).then(srvAdvAtomic(2))
      .expect(and { ps.get(2).resp == "HeadConflict", pm == [1], hd == 1, All })
}

// MUTANT: pre-#521 (no transactional-advance gate) on an ordered store.
module noGate_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: true, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  // #521: p2 re-baselines; p1 pushed first; p2's reset packmap PUT lands
  // (Match([0, 1])) and its head PUT loses: head 1, packmap closure(2).
  run strandedHeadTest =
    init
      .then(start(1)).then(start(2))
      .expect(ps.get(2).reset)
      .then(loop(1)).then(srvAdvFirst(1)).then(srvAdvSecond(1))
      .then(loop(2)).then(srvAdvFirst(2)).then(srvAdvSecond(2))
      .expect(and { pm == [2], hd == 1, ps.get(2).resp == "HeadConflict", not(DeltaTransfer) })
}

// MUTANT: server head CAS as an unlocked read-then-write.
module splitCas_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 5 }, 2 -> { tip: 3, cond: 5 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 5, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: true, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run lostUpdateTest =
    init
      .then(start(1)).then(start(2))
      .expect(and { ps.get(1).pc == "updSrv", ps.get(2).pc == "updSrv" })   // no-op plans
      .then(srvUpd(1)).then(srvUpd(2))                                   // both read 5
      .then(srvUpd2(1))
      .expect(and { hd == 1, NoLostUpdate })
      .then(srvUpd2(2))                                                  // p2 overwrites 1 blind
      .expect(and { hd == 3, not(NoLostUpdate) })
}

// GAP F2: head-only force push after a non-fast-forward lease re-baseline.
module gapNoopAny_test {
  import advance(PUSHERS = Map(1 -> { tip: 2, cond: 3 }, 2 -> { tip: 1, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run forceAfterRebaselineStrandsTest =
    init
      .then(start(2))                          // plans against head 3: empty, head-only
      .then(start(1)).then(loop(1)).then(srvAdvAtomic(1))
      .expect(and { ps.get(1).reset, pm == [1], hd == 2, DeltaTransfer })
      .then(srvUpd(2))                         // Any: head 2 -> 1
      .expect(and { hd == 1, pm == [1], not(DeltaTransfer) })
}

// GAP F1: HTTP Any fallback interleaved with a fast-forward re-baseline.
module gapHttpAny_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = true, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run anyFallbackVsRebaselineStrandsTest =
    init
      .then(start(1)).then(start(2))
      .expect(and { ps.get(1).reset, not(ps.get(2).reset) })   // gate: Any appends
      .then(loop(2)).then(srvAdvFirst(2))                      // packmap PUT [0, 2]
      .then(loop(1)).then(srvAdvAtomic(1))                     // reset Match([0, 2]), head Match(0)
      .expect(and { pm == [1], hd == 1, DeltaTransfer })
      .then(srvAdvSecond(2))                                   // head PUT Any: 2
      .expect(and { hd == 2, pm == [1], not(DeltaTransfer) })
}

// GAP F2 with fast-forward leases only (two force pushers).
module gapTwoAny_test {
  import advance(PUSHERS = Map(1 -> { tip: 6, cond: 4 }, 2 -> { tip: 1, cond: -1 }, 3 -> { tip: 4, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run twoForcePushesAndFastForwardRebaselineStrandTest =
    init
      .then(start(2))                                  // head 3: tip 1 is covered, head-only
      .then(start(3)).then(loop(3)).then(srvAdvAtomic(3))
      .expect(and { hd == 4, pm == [0, 3], DeltaTransfer })   // force push sideways, appended
      .then(start(1)).then(loop(1)).then(srvAdvAtomic(1))
      .expect(and { ps.get(1).reset, hd == 6, pm == [1], DeltaTransfer })  // fast-forward reset
      .then(srvUpd(2))
      .expect(and { hd == 1, not(DeltaTransfer) })
}

// GAP F2, appending variant: a force push with a non-empty plan re-reads a
// packmap another pusher has just reset, appends its pack (whose delta bases
// the reset dropped) and commits under Any.
module gapAppendAny_test {
  import advance(PUSHERS = Map(1 -> { tip: 2, cond: 3 }, 2 -> { tip: 5, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run forceAppendAfterRebaselineStrandsTest =
    init
      .then(start(2))                          // plans {5} against head 3; Any: append
      .expect(and { ps.get(2).pc == "loop", not(ps.get(2).reset) })
      .then(start(1)).then(loop(1)).then(srvAdvAtomic(1))
      .expect(and { ps.get(1).reset, pm == [1], hd == 2, DeltaTransfer })
      .then(loop(2))                           // re-reads the reset packmap [1]
      .expect(ps.get(2).node == [1, 2])
      .then(srvAdvAtomic(2))                   // packmap Match([1]) and Any both hold
      .expect(and { ps.get(2).resp == "Committed", hd == 5, pm == [1, 2], not(DeltaTransfer) })
}

// MUTANT: the unlocked head CAS loses a fast-forward push's reported success.
module splitCasFF_test {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 2, LADDER = 1,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: true, headFirst: false, noTimeout: false, noLadderBound: false }).* from "./advance"

  run lostSuccessTest =
    init
      .then(start(2)).then(loop(2)).then(srvAdvFirst(2)).then(srvCrash(2))   // packmap [0, 2], head lost
      .then(lose(2)).then(srvAdvFirst(2)).then(deliver(2))                   // PackmapConflict
      .then(loop(2))                                                          // our pack chained: head only
      .then(srvUpd(2))                                                        // server reads head 0
      .then(start(1)).then(loop(1)).then(srvAdvFirst(1)).then(srvAdvSecond(1)).then(deliver(1))
      .expect(and { hd == 1, ps.get(1).report == "success", NoLostSuccess })
      .then(srvUpd2(2))                                                       // blind write of 2 over 1
      .expect(and { hd == 2, not(NoLostSuccess), not(NoLostUpdate) })
}
