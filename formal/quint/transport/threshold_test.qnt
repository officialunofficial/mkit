// -*- mode: Bluespec; -*-
// Pinned interleavings for threshold.qnt (run by check.sh: `quint test`).
module threshold_test {
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).* from "./threshold"
  import quorum.* from "./threshold"

  pure val AS_IMPL: TFaults = { ...FAULTS, noFilter: true }
  pure val RETAIN: TFaults = { ...FAULTS, retainOld: true }
  pure val NO_REFRESH: TFaults = { ...FAULTS, noRefresh: true }
  pure def p(h: int, e: int, m: str, v: bool): Partial = { h: h, e: e, m: m, valid: v }

  // Threshold arithmetic: the code (N3f1) vs the spec's ceil(2n/3).
  run quorumTableTest = all {
    assert(n3f1Quorum(4) == 3 and n3f1Quorum(7) == 5),       // the spec's examples agree
    assert(n3f1Quorum(3) == 3 and specQuorum(3) == 2),       // FINDING: n = 3
    assert(n3f1Quorum(6) == 5 and specQuorum(6) == 4),       // FINDING: n = 6
    assert(not(SpecFormulaMatchesCode)),
    assert(CodeQuorumAtLeastSpec and NoSingleSigner),
  }

  // Two honest partials, a garbage partial under index 0 first in input
  // order: the verifying coordinator drops it and recovers.
  run filteredCoordinatorRecoversTest =
    initWith(FAULTS).then(honestSign(1)).then(honestSign(2)).then(advGarbage(0, "rel"))
      .then(aggregate("rel", Map(0 -> p(0, 0, "rel", false), 1 -> p(1, 0, "rel", true),
                                 2 -> p(2, 0, "rel", true)), true))
      .expect(accepts("rel") and Safety)

  // FINDING witness: `aggregate` without partial verification keeps the two
  // LOWEST indices, {0 (garbage), 1}, and fails although {1, 2} is a quorum.
  run unfilteredAggregateIncompleteTest =
    initWith(AS_IMPL).then(honestSign(1)).then(honestSign(2)).then(advGarbage(0, "rel"))
      .then(aggregate("rel", Map(0 -> p(0, 0, "rel", false), 1 -> p(1, 0, "rel", true),
                                 2 -> p(2, 0, "rel", true)), true))
      .expect(not(accepts("rel")) and not(AggregateCompleteness))

  // Rotation: epoch-0 partial of holder 0 and epoch-1 partial of holder 1
  // never combine.
  run mixedEpochsNeverCombineTest =
    initWith(FAULTS).then(honestSign(0)).then(rotate).then(honestSign(1))
      .then(aggregate("rel", Map(0 -> p(0, 0, "rel", true), 1 -> p(1, 1, "rel", true)), false))
      .expect(not(accepts("rel")) and Safety)

  // ...unless resharing reuses the polynomial (mutant).
  run noRefreshCombinesTest =
    initWith(NO_REFRESH).then(compromise(0)).then(advSign(0, 0, "evil")).then(rotate)
      .then(compromise(1)).then(advSign(1, 1, "evil"))
      .then(aggregate("evil", Map(0 -> p(0, 0, "evil", true), 1 -> p(1, 1, "evil", true)), false))
      .expect(not(NoForgery) and not(AggregateFromOneShareSet)
              and not(AcceptedOnlyFromShareSetQuorum))

  // ASSUMPTION witness: a rotated-out share that is not erased. One holder
  // compromised per share set, but holder 1's retained epoch-0 share plus
  // holder 0's epoch-0 share are a threshold of the OLD set, whose signature
  // verifies under the unchanged cohort key.
  run retainedOldSharesForgeTest =
    initWith(RETAIN).then(compromise(0)).then(rotate).then(compromise(1))
      .then(advSign(0, 0, "evil")).then(advSign(1, 0, "evil"))
      .then(aggregate("evil", Map(0 -> p(0, 0, "evil", true), 1 -> p(1, 0, "evil", true)), false))
      .expect(not(NoForgery) and AggregateFromOneShareSet)

  // Witness: partials of a rotated-out share set still recover a verifying
  // signature after rotation (nothing binds an epoch). Sound, since the old
  // holders did sign "rel", but "from the CURRENT share set" is not enforced.
  run staleShareSetStillVerifiesTest =
    initWith(FAULTS).then(honestSign(0)).then(honestSign(1)).then(rotate)
      .then(aggregate("rel", Map(0 -> p(0, 0, "rel", true), 1 -> p(1, 0, "rel", true)), false))
      .expect(accepts("rel") and not(CanaryNoStaleAggregate) and Safety)

  // With erasure, the same adversary holds (0, 0) and (1, 1) only.
  run erasedOldSharesTest =
    initWith(FAULTS).then(compromise(0)).then(rotate).then(compromise(1))
      .expect(known == Set((0, 0), (1, 1)) and Safety)
}
