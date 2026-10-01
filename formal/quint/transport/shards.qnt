// -*- mode: Bluespec; -*-
// Shard quorum collection under the process-wide worker bound (transport model,
// epic verification toolchain, workstream quint-transport).
//
// Models `mkit_core::pack_shard::download::download_shards` as called by the
// HTTP (`HttpTransport::download_pack_via_shards`) and S3
// (`S3Transport::download_pack_via_shards`) transports, and the decode that
// follows (`decode_downloaded_pack`), as of this branch:
//   - one collector admits one worker per shard index, in index order, with a
//     NON-BLOCKING `WorkerSlot::try_acquire` against the process-wide bound
//     `MAX_SHARD_WORKERS` (shared with every other download in the process,
//     including detached stragglers of downloads that already returned);
//   - between admissions it drains its own result channel (`try_recv`), and
//     when it can neither receive nor admit it waits on the channel with a
//     10 ms timeout and then retries admission, because a slot freed by
//     ANOTHER request does not wake this receiver;
//   - an `Ok(shard)` result counts toward the quorum, `minimum_shards`
//     results return `Ok`; an `Err` counts as a failure and
//     `extra_shards + 1` failures return `PackNotFound`
//     (SPEC-PACK-SHARDS §5 "HTTP transport");
//   - returning drops the `DownloadGroup`, which cancels every outstanding
//     worker: a worker checks the token before every request attempt and
//     every body read (`Cancellation::check`), so it makes no new request
//     after the decision, but a read already blocked on the network runs
//     until the per-request timeout (`SHARD_REQUEST_TIMEOUT`);
//   - a worker holds its slot from admission until its thread exits, which
//     is after it has sent its result;
//   - the collected shards are then decoded: every shard's BLAKE3 is checked
//     against the manifest (§4.2 step 2c) and ANY mismatch fails the whole
//     download with `InvalidResponse` (§3).
// INVARIANTS.md "Shard worker bounds do not delay an available quorum".
//
// Abstractions (explicit):
//   - Each shard index has a fixed behaviour chosen by the environment at
//     init: "ok" (a valid shard, served promptly), "fail" (a prompt error:
//     404, 5xx after retries, ...), "slow" (the request stalls; it only ends
//     by timing out, as a failure) or "bad" (a prompt `200` whose bytes do
//     not match the manifest: a corrupted or substituted shard). Retries
//     are folded into the single outcome.
//   - Other downloads in the process are abstracted to `foreign` held slots
//     that are released one at a time (their stragglers timing out).
//   - Time, the 10 ms poll and the timeouts are abstracted: "eventually" is
//     expressed by fairness in the TLC progress checks (tlc/ wrappers in
//     check.sh), never by a clock.
//   - The Reed-Solomon decode is abstracted to "all collected shards are
//     valid" (the manifest's shard hashes and commitment were already bound
//     to the requested key; identity.qnt models that part).
//
// Checks: ./check.sh (README.md lists each command and its expected outcome).
module shardCore {
  // Mutation switches (non-vacuity only).
  type SFaults = {
    blockingAdmission: bool,  // admit every worker with a BLOCKING acquire before collecting
    recvBlocking: bool,       // wait on the own channel with no timeout (no admission retry)
    noCancel: bool,           // workers ignore the cancellation token
    noGroupCancel: bool,      // returning does not cancel the DownloadGroup (token never set)
    thresholdOffByOne: bool,  // `failures >= extra` instead of `failures > extra`
    noSlotCheck: bool,        // admission ignores the process-wide bound (review mutant)
    earlyQuorum: bool,        // decide on `minimum_shards - 1` Ok results (review mutant)
    noFailureThreshold: bool, // never return PackNotFound (review mutant)
  }

  const MIN: int          // minimum_shards (N)
  const EXTRA: int        // extra_shards (K)
  const MAXW: int         // MAX_SHARD_WORKERS (process-wide)
  const KINDS: Set[str]   // shard behaviours the environment may choose from
  const FAULTS: SFaults

  pure val TOTAL: int = MIN + EXTRA
  pure val IDX: Set[int] = 0.to(TOTAL - 1)
  pure val NOFAULTS: SFaults = {
    blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false,
    thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false,
  }

  // --------------------------------------------------------------- state
  var kind: int -> str        // per shard: ok | fail | slow | bad (fixed after init)
  var foreign: int            // slots held by other downloads' workers
  var ws: int -> str          // per shard worker: idle | run | sent | done
  var out: int -> str         // what the worker sent: "" | shard | err
  var nextIdx: int               // next index to admit
  var chan: Set[int]          // results sent but not yet received
  var succ: Set[int]          // collected Ok(shard) results
  var failures: int
  var result: str             // pending | ok | invalid | notfound | disconnected
  var cancelled: bool         // the DownloadGroup's token
  var parked: bool            // recvBlocking mutant: collector blocked in recv()
  // ghosts
  var attemptAfterDecision: bool  // a worker made a request after the collector decided
  var faults: SFaults
  var lastAction: str

  def own: int = IDX.filter(i => ws.get(i) == "run" or ws.get(i) == "sent").size()
  def free: int = MAXW - foreign - own
  def pending: bool = result == "pending"
  pure def countWhere(m: int -> str, v: str): int = IDX.filter(i => m.get(i) == v).size()
  def okCount: int = countWhere(kind, "ok")
  def badCount: int = countWhere(kind, "bad")
  def slowCount: int = countWhere(kind, "slow")
  // Shards whose worker returns Ok(shard): the transport does not hash-check
  // before counting (SPEC-PACK-SHARDS §4.2 step 2c runs in the decode).
  def okResponses: int = IDX.filter(i => kind.get(i) == "ok" or kind.get(i) == "bad").size()
  // Ok results already delivered to the collector (collected or queued).
  def arrived: int = succ.size() + chan.filter(i => out.get(i) == "shard").size()
  def canReceive: bool = pending and chan != Set() and (not(faults.blockingAdmission) or nextIdx == TOTAL)

  // --------------------------------------------------------------- init
  action initWith(k: int -> str, f: int, fl: SFaults): bool = all {
    kind' = k, foreign' = f,
    ws' = IDX.mapBy(_ => "idle"), out' = IDX.mapBy(_ => ""),
    nextIdx' = 0, chan' = Set(), succ' = Set(), failures' = 0,
    result' = "pending", cancelled' = false, parked' = false,
    attemptAfterDecision' = false, faults' = fl, lastAction' = "init",
  }
  action init = {
    nondet k = IDX.setOfMaps(KINDS).oneOf()
    nondet f = 0.to(MAXW).oneOf()
    initWith(k, f, FAULTS)
  }

  // --------------------------------------------------------------- collector
  // Admission: `WorkerSlot::try_acquire` succeeded; spawn the worker.
  action admit: bool = all {
    pending, not(parked), nextIdx < TOTAL, (free > 0 or faults.noSlotCheck),
    ws' = ws.set(nextIdx, "run"), nextIdx' = nextIdx + 1,
    kind' = kind, foreign' = foreign, out' = out, chan' = chan, succ' = succ,
    failures' = failures, result' = result, cancelled' = cancelled, parked' = parked,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "admit",
  }

  // `try_recv` / `recv_timeout` returned result `i`.
  action receive(i: int): bool = all {
    canReceive, i.in(chan),
    val isShard = out.get(i) == "shard"
    val succ2 = if (isShard) succ.union(Set(i)) else succ
    val fail2 = if (isShard) failures else failures + 1
    val quorum = succ2.size() == (if (faults.earlyQuorum) MIN - 1 else MIN)
    val tooMany = if (faults.thresholdOffByOne) fail2 >= EXTRA else fail2 > EXTRA
    // decode_downloaded_pack: any collected shard with a mismatching hash
    // fails the whole decode (ShardHashMismatch -> InvalidResponse).
    val decoded = if (succ2.forall(j => kind.get(j) == "ok")) "ok" else "invalid"
    val res = if (quorum) decoded else if (tooMany and not(faults.noFailureThreshold)) "notfound" else "pending"
    all {
      chan' = chan.exclude(Set(i)), succ' = succ2, failures' = fail2, result' = res,
      cancelled' = (cancelled or (res != "pending" and not(faults.noGroupCancel))), parked' = false,
      kind' = kind, foreign' = foreign, ws' = ws, out' = out, nextIdx' = nextIdx,
      attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "receive",
    }
  }

  // recvBlocking mutant only: nothing queued and no free slot, so the
  // collector blocks in `recv()`; only its own results can wake it.
  action park: bool = all {
    faults.recvBlocking, pending, not(parked), chan == Set(), nextIdx < TOTAL, free == 0,
    parked' = true,
    kind' = kind, foreign' = foreign, ws' = ws, out' = out, nextIdx' = nextIdx, chan' = chan,
    succ' = succ, failures' = failures, result' = result, cancelled' = cancelled,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "park",
  }

  // Every sender dropped with nothing queued: `Disconnected` ->
  // ConnectionFailed.
  action disconnect: bool = all {
    pending, nextIdx == TOTAL, chan == Set(), IDX.forall(i => ws.get(i) == "done"),
    result' = "disconnected", cancelled' = true,
    kind' = kind, foreign' = foreign, ws' = ws, out' = out, nextIdx' = nextIdx, chan' = chan,
    succ' = succ, failures' = failures, parked' = parked,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "disconnect",
  }

  action collector: bool = any { admit, park, disconnect, { nondet i = IDX.oneOf() receive(i) } }

  // --------------------------------------------------------------- workers
  // A prompt worker (ok / fail / bad) finishes and sends its result. After
  // the decision it observes the token at its next attempt / read and sends
  // an error without another request; the noCancel mutant makes one.
  action finish(i: int): bool = all {
    ws.get(i) == "run", kind.get(i) != "slow",
    val stop = cancelled and not(faults.noCancel)
    val o = if (stop) "err" else if (kind.get(i) == "ok" or kind.get(i) == "bad") "shard" else "err"
    all {
      ws' = ws.set(i, "sent"), out' = out.set(i, o),
      // After the collector returned the receiver is gone: the send fails.
      chan' = if (pending) chan.union(Set(i)) else chan,
      // Ghost: the worker made a request although the collector had already
      // returned (whatever the reason the token did not stop it).
      attemptAfterDecision' = (attemptAfterDecision or (not(pending) and not(stop))),
      kind' = kind, foreign' = foreign, nextIdx' = nextIdx, succ' = succ, failures' = failures,
      result' = result, cancelled' = cancelled, parked' = parked, faults' = faults,
      lastAction' = "finish",
    }
  }

  // A stalled request times out (SHARD_REQUEST_TIMEOUT); retries are folded
  // in, so the worker reports a failure.
  action timeout(i: int): bool = all {
    ws.get(i) == "run", kind.get(i) == "slow",
    ws' = ws.set(i, "sent"), out' = out.set(i, "err"),
    chan' = if (pending) chan.union(Set(i)) else chan,
    kind' = kind, foreign' = foreign, nextIdx' = nextIdx, succ' = succ, failures' = failures,
    result' = result, cancelled' = cancelled, parked' = parked,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "timeout",
  }

  // The worker thread exits: `_slot` drops, freeing the slot.
  action release(i: int): bool = all {
    ws.get(i) == "sent",
    ws' = ws.set(i, "done"),
    kind' = kind, foreign' = foreign, out' = out, nextIdx' = nextIdx, chan' = chan, succ' = succ,
    failures' = failures, result' = result, cancelled' = cancelled, parked' = parked,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "release",
  }

  // Another download's straggler exits. Its completion does not wake us.
  action foreignRelease: bool = all {
    foreign > 0, foreign' = foreign - 1,
    kind' = kind, ws' = ws, out' = out, nextIdx' = nextIdx, chan' = chan, succ' = succ,
    failures' = failures, result' = result, cancelled' = cancelled, parked' = parked,
    attemptAfterDecision' = attemptAfterDecision, faults' = faults, lastAction' = "foreignRelease",
  }

  action worker: bool = {
    nondet i = IDX.oneOf()
    any { finish(i), timeout(i), release(i) }
  }

  action step = any { collector, worker, foreignRelease }

  // --------------------------------------------------------------- safety
  // The process-wide bound is never exceeded.
  val SlotBound: bool = free >= 0
  // Ok / invalid only once exactly `minimum_shards` Ok results were collected.
  val OkHasQuorum: bool = (result == "ok" or result == "invalid") implies succ.size() == MIN
  // PackNotFound only past the failure threshold (extra_shards + 1 failures).
  val NotFoundPastThreshold: bool = result == "notfound" implies failures > EXTRA
  // Never PackNotFound while `minimum_shards` shards would answer Ok.
  val NoFalseNotFound: bool = result == "notfound" implies okResponses < MIN
  // The collector always reaches a decision before the channel disconnects.
  val NoDisconnect: bool = result != "disconnected"
  // After the decision no worker starts another request (cancellation).
  val NoAttemptAfterDecision: bool = not(attemptAfterDecision)
  // INVARIANTS.md: admission never stops the collector from receiving a
  // quorum that has already arrived.
  val QuorumNotBlockedByAdmission: bool =
    not(pending and arrived >= MIN and not(canReceive))
  val Safety: bool = and {
    SlotBound, OkHasQuorum, NotFoundPastThreshold, NoFalseNotFound, NoDisconnect,
    NoAttemptAfterDecision, QuorumNotBlockedByAdmission,
  }

  // DOCUMENTED GAP (see README "Findings"): a corrupted or substituted shard
  // is counted toward the quorum before its hash is checked, and one such
  // shard among the first `minimum_shards` fails the download even when
  // `minimum_shards` valid shards were available.
  val DecodeFailsOnlyWithoutHonestQuorum: bool = result == "invalid" implies okCount < MIN

  // --------------------------------------------------------------- progress
  // State predicates of the TLC progress properties (check.sh `tlcl`, where
  // the fairness of each property is stated). Temporal operators are not in
  // this file: `quint run` cannot check them.
  //   P1: QuorumArrived ~> Decided                       (WF collector only)
  //   P2: HonestQuorumAvailable => <>DecidedOk           (see check.sh)
  val QuorumArrived: bool = pending and arrived >= MIN
  val Decided: bool = not(pending)
  val DecidedOk: bool = result == "ok"
  // At least `minimum_shards` shards are valid and prompt, none is corrupted,
  // and stalled own shards cannot occupy every process-wide slot.
  val HonestQuorumAvailable: bool = okCount >= MIN and badCount == 0 and slowCount < MAXW
  // The same when corrupted shards may also answer (documented gap).
  val QuorumAvailable: bool = okCount >= MIN and slowCount < MAXW
  // The same without the stall bound (documented bound: stalled own shards
  // holding every slot this download can get make the quorum wait for their
  // timeouts).
  val HonestQuorumAnyStall: bool = okCount >= MIN and badCount == 0
  // Compile anchor: `quint compile` keeps only what the named invariant uses,
  // so the TLC progress wrappers compile this (always Safety) instead.
  val ProgressTerms: bool =
    Safety and Set(QuorumArrived, Decided, DecidedOk, HonestQuorumAvailable, QuorumAvailable,
        HonestQuorumAnyStall).size() >= 1

  // --------------------------------------------------------------- canaries
  val CanaryNoOk: bool = result != "ok"
  val CanaryNoNotFound: bool = result != "notfound"
  // Reachable: the pool is full, admission is pending, and results are queued.
  val CanaryNoFullPoolWithResults: bool = not(pending and free == 0 and nextIdx < TOTAL and chan != Set())
  // Reachable: the decision does not wait for a stalled redundant worker.
  val CanaryNoOkWithStraggler: bool = not(result == "ok" and IDX.exists(i => ws.get(i) == "run"))
  // Reachable: a foreign straggler holds a slot while we decide Ok.
  val CanaryNoOkUnderForeign: bool = not(result == "ok" and foreign > 0)
}

// KINDS: honest environment (no corrupted shard) unless named *_bad.
module shards {            // N=2, K=1, 2 process-wide workers: 3 shards, pool < shards
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_wide {       // N=3, K=2, 3 workers (TLC safety; quint run)
  import shardCore(MIN = 3, EXTRA = 2, MAXW = 3, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_tight {      // N=1, K=2, 2 workers: two stalled shards can hold both slots
  import shardCore(MIN = 1, EXTRA = 2, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_bad {        // corrupted shards allowed: DecodeFailsOnlyWithoutHonestQuorum gap
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow", "bad"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_blocking {   // QuorumNotBlockedByAdmission (and progress P1)
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: true, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_recvBlocking {  // progress P2 only (safety holds)
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: true, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_noCancel {   // NoAttemptAfterDecision
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: true, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_noGroupCancel {  // NoAttemptAfterDecision: the collector returns without cancelling
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: true, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_offByOne {   // NoFalseNotFound, NotFoundPastThreshold
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: true, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_noSlotCheck {  // SlotBound (review mutant)
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: true, earlyQuorum: false, noFailureThreshold: false }).*
}
module shards_earlyQuorum {  // OkHasQuorum (review mutant)
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: true, noFailureThreshold: false }).*
}
module shards_noFailureThreshold {  // NoDisconnect (review mutant)
  import shardCore(MIN = 2, EXTRA = 1, MAXW = 2, KINDS = Set("ok", "fail", "slow"),
    FAULTS = { blockingAdmission: false, recvBlocking: false, noCancel: false, noGroupCancel: false, thresholdOffByOne: false, noSlotCheck: false, earlyQuorum: false, noFailureThreshold: true }).*
}
