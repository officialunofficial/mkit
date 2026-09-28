// -*- mode: Bluespec; -*-
// Pinned interleavings for shards.qnt (run by check.sh: `quint test`).
module shards_test {
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).* from "./shards"

  // One slot is held by another download's straggler and shard 0 stalls:
  // the collector still admits shard 1 and 2 in the remaining slot as it
  // frees, and decides Ok while shard 0 is still running (no waiting for the
  // redundant stalled request).
  run quorumPastStallUnderForeignTest =
    initWith(Map(0 -> "slow", 1 -> "ok", 2 -> "ok"), 1, FAULTS)
      .then(admit)                         // shard 0 takes the last free slot
      .expect(free == 0)
      .then(foreignRelease)
      .then(admit)                         // shard 1
      .then(finish(1)).then(release(1))
      .then(admit)                         // shard 2
      .then(receive(1)).then(finish(2)).then(receive(2))
      .expect(result == "ok" and ws.get(0) == "run" and cancelled and Safety)

  // With a full pool and results queued, the collector keeps receiving.
  run receivesWhilePoolFullTest =
    initWith(Map(0 -> "ok", 1 -> "ok", 2 -> "fail"), 0, FAULTS)
      .then(admit).then(admit)
      .then(finish(0)).then(finish(1))
      .expect(free == 0 and nextIdx < TOTAL and canReceive)
      .then(receive(0)).then(receive(1))
      .expect(result == "ok" and nextIdx == 2 and Safety)

  // extra_shards + 1 failures return PackNotFound, never earlier.
  run notFoundAtThresholdTest =
    initWith(Map(0 -> "fail", 1 -> "fail", 2 -> "ok"), 0, FAULTS)
      .then(admit).then(admit)
      .then(finish(0)).then(receive(0))
      .expect(result == "pending")
      .then(finish(1)).then(receive(1))
      .expect(result == "notfound" and failures == 2 and Safety)

  // After the decision a straggler sends an error without a new request.
  run cancelledWorkerMakesNoRequestTest =
    quorumPastStallUnderForeignTest
      .then(timeout(0))
      .expect(out.get(0) == "err" and not(attemptAfterDecision))
}

module shards_blocking_test {
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: true, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).* from "./shards"

  // Blocking admission: two results have arrived, but the collector is
  // blocked admitting shard 2 until a slot frees.
  run quorumBlockedByAdmissionTest =
    initWith(Map(0 -> "ok", 1 -> "ok", 2 -> "slow"), 0, FAULTS)
      .then(admit).then(admit)
      .then(finish(0)).then(finish(1))
      .expect(arrived == 2 and not(canReceive) and not(QuorumNotBlockedByAdmission))
}

module shards_noCancel_test {
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: true, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).* from "./shards"

  run attemptAfterDecisionTest =
    initWith(Map(0 -> "ok", 1 -> "ok", 2 -> "ok"), 0, FAULTS)
      .then(admit).then(admit).then(finish(0)).then(release(0)).then(admit)
      .then(finish(1)).then(receive(0)).then(receive(1))
      .expect(result == "ok")
      .then(finish(2))
      .expect(not(NoAttemptAfterDecision))
}

module shards_bad_test {
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow", "bad"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).* from "./shards"

  // FINDING witness: a corrupted shard answers first and is counted toward
  // the quorum; the decode then fails the download although shards 1 and 2
  // (a full quorum) are valid.
  run corruptShardDefeatsQuorumTest =
    initWith(Map(0 -> "bad", 1 -> "ok", 2 -> "ok"), 0, FAULTS)
      .then(admit).then(admit)
      .then(finish(0)).then(receive(0))
      .then(finish(1)).then(receive(1))
      .expect(result == "invalid" and okCount == 2 and Safety
              and not(DecodeFailsOnlyWithoutHonestQuorum))
}
