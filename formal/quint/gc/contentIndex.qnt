// -*- mode: Bluespec; -*-
// Server-side GC primitive: the ContentIndex GC ordering (R-64 steps 1-4)
// against a concurrent upload that dedups or writes the same blob.
//
// Models rust/crates/mkit-server/src/store/content_index.rs (module docs
// "GC ordering (R-64)", `add_hold`, `add_holder`, `release_hold`,
// `collectable`, `commit_collect`, `finish_collect`, `mutate`) and
// rust/crates/mkit-server/src/fs/blob.rs (`FsPackSink::publish`: an upload
// renames over the destination, so a dedup is `AlreadyPresent` and a new
// blob is `Created`; `delete` is idempotent). There is no normative spec
// yet: SPEC-SERVER's server-GC section is WP-5.1a and the GC driver
// (roots re-check, relay watermark) is WP-5.3a/b. Nothing in the tree calls
// `collectable`/`commit_collect` yet, so this model states the contract a
// caller must meet; it does not check a shipped code path.
//
// One object O. Its bytes are a blob in the pack store; a ref-shard apply
// makes it reachable (`published`); the relay later records a holder row and
// releases the upload's hold in the same batch.
//
// Actors:
//   upload : add_hold, write/dedup the bytes, apply (NotAfter deadline), in
//            the order UPLOAD_ORDER; gives up (release_hold) past the deadline.
//   relay  : add_holder releasing the hold, within RELAY_LAG of the apply.
//   gc     : collectable (plan) -> commit_collect (mark `deleting`) -> delete
//            bytes -> finish_collect; may crash after the mark and resume.
//
// Bounds: clock 0..MAXT = 7, one object, one upload, one hold id.

module ciCore {
  // "holdFirst": add_hold, then write/dedup, then apply (the order the
  //              add_hold doc requires, "taken before the ref-shard apply",
  //              strengthened to "before relying on the bytes")
  // "bytesFirst": write/dedup, then add_hold, then apply
  const UPLOAD_ORDER: str
  const GRACE: int      // collectable grace on the state row's last change
  const TTL: int        // hold lifetime (MAX_HOLD_TTL_MS caps it)
  const APPLY_WINDOW: int  // MAX_APPLY_WINDOW: apply NotAfter hold time + this
  const RELAY_LAG: int     // relay records the holder within this of the apply
  // "none" | "noDeletingGuard" (add_hold ignores `deleting`)
  //        | "noSeqGuard" (commit_collect ignores the Equals guard)
  //        | "noResume" (a crashed gc's `deleting` mark is never resumed)
  //        | "noGiveUp" (an upload past its deadline cannot release its hold)
  const MUTANT: str

  pure val MAXT = 7
  type State = { seq: int, changed: int, holders: int, deleting: bool }

  var clock: int
  var bytes: bool              // blob present in the pack store
  var st: State                // ContentIndex state row `c`
  var holdExp: int             // hold row expiry; -1 = no row
  var published: bool          // a ref makes O reachable
  var upPhase: str             // "idle" | "held" | "bytes" | "ready" | "applied" | "done"
  var holdAt: int
  var applyAt: int
  var gcPhase: str             // "idle" | "planned" | "marked" | "deleted"
  var planSeq: int
  // ghosts
  var lostLive: bool           // bytes deleted while reachable, held or in a holder row
  var deletedAny: bool          // gc deleted the bytes at least once

  def holdLive(now: int): bool = holdExp > now
  // `mutate`: bump seq, changed = max(changed, now), prune an expired hold.
  def bump(s: State): State = { ...s, seq: s.seq + 1, changed: if (clock > s.changed) clock else s.changed }
  def prunedHold: int = if (holdExp >= 0 and holdExp <= clock) -1 else holdExp

  action init = all {
    clock' = 0,
    bytes' = true,             // an old unreferenced blob: the dedup target
    st' = { seq: 0, changed: 0, holders: 0, deleting: false },
    holdExp' = -1,
    published' = false,
    upPhase' = "idle", holdAt' = 0, applyAt' = 0,
    gcPhase' = "idle", planSeq' = 0,
    lostLive' = false, deletedAny' = false,
  }

  action keepUp = all { upPhase' = upPhase, holdAt' = holdAt, applyAt' = applyAt }
  action keepGc = all { gcPhase' = gcPhase, planSeq' = planSeq }
  action keepGhost = all { lostLive' = lostLive, deletedAny' = deletedAny }

  // Environment. The relay-lag bound is an assumption on time.
  action Tick = all {
    clock < MAXT,
    upPhase == "applied" implies clock + 1 <= applyAt + RELAY_LAG,
    clock' = clock + 1,
    bytes' = bytes, st' = st, holdExp' = holdExp, published' = published,
    keepUp, keepGc, keepGhost,
  }

  // ---- upload -------------------------------------------------------------------
  def holdStep: bool = if (UPLOAD_ORDER == "holdFirst") upPhase == "idle" else upPhase == "bytes"
  def bytesStep: bool = if (UPLOAD_ORDER == "holdFirst") upPhase == "held" else upPhase == "idle"
  // add_hold: refused (retryable Unavailable, no write) while `deleting`.
  action UpHold = all {
    holdStep,
    not(st.deleting) or MUTANT == "noDeletingGuard",
    holdExp' = if (prunedHold > clock + TTL) prunedHold else clock + TTL,
    st' = bump(st),
    holdAt' = clock,
    upPhase' = if (UPLOAD_ORDER == "holdFirst") "held" else "ready",
    applyAt' = applyAt,
    clock' = clock, bytes' = bytes, published' = published, keepGc, keepGhost,
  }
  // BlobStore begin/write/commit: AlreadyPresent if the blob exists, else
  // Created. The index is not touched.
  action UpBytes = all {
    bytesStep,
    bytes' = true,
    upPhase' = if (UPLOAD_ORDER == "holdFirst") "ready" else "bytes",
    holdAt' = holdAt, applyAt' = applyAt,
    clock' = clock, st' = st, holdExp' = holdExp, published' = published, keepGc, keepGhost,
  }
  // Ref-shard apply with NotAfter = hold time + APPLY_WINDOW.
  action UpApply = all {
    upApplyEnabled,
    published' = true,
    upPhase' = "applied", applyAt' = clock, holdAt' = holdAt,
    clock' = clock, bytes' = bytes, st' = st, holdExp' = holdExp, keepGc, keepGhost,
  }
  // Deadline passed before the apply: release_hold (a mutation) and stop.
  def upApplyEnabled: bool = upPhase == "ready" and clock <= holdAt + APPLY_WINDOW
  def upGiveUpEnabled: bool =
    (upPhase == "ready" or upPhase == "held") and clock > holdAt + APPLY_WINDOW
    and MUTANT != "noGiveUp"
  action UpGiveUp = all {
    upGiveUpEnabled,
    holdExp' = -1, st' = bump(st),
    upPhase' = "done", holdAt' = holdAt, applyAt' = applyAt,
    clock' = clock, bytes' = bytes, published' = published, keepGc, keepGhost,
  }
  // Relay: add_holder releasing the hold in the same batch; refused while deleting.
  action RelayHolder = all {
    upPhase == "applied",
    not(st.deleting),
    st' = { ...bump(st), holders: st.holders + 1 },
    holdExp' = -1,
    upPhase' = "done", holdAt' = holdAt, applyAt' = applyAt,
    clock' = clock, bytes' = bytes, published' = published, keepGc, keepGhost,
  }

  // ---- gc ---------------------------------------------------------------------------
  def collectable: bool =
    not(st.deleting) and st.holders == 0 and clock - st.changed >= GRACE and not(holdLive(clock))
  action GcPlan = all {
    gcPhase == "idle", not(st.deleting), collectable,
    gcPhase' = "planned", planSeq' = st.seq,
    clock' = clock, bytes' = bytes, st' = st, holdExp' = holdExp, published' = published,
    keepUp, keepGhost,
  }
  // commit_collect: batch guarded by Equals on the state row it read.
  def commitOk: bool = st.seq == planSeq or MUTANT == "noSeqGuard"
  action GcCommit = all {
    gcPhase == "planned",
    gcPhase' = if (commitOk) "marked" else "idle",
    st' = if (commitOk) { ...bump(st), deleting: true } else st,
    holdExp' = if (commitOk) prunedHold else holdExp,
    planSeq' = planSeq,
    clock' = clock, bytes' = bytes, published' = published, keepUp, keepGhost,
  }
  action GcDelete = all {
    gcPhase == "marked",
    bytes' = false,
    lostLive' = if (bytes and (published or st.holders > 0 or holdLive(clock))) true else lostLive,
    deletedAny' = true,
    gcPhase' = "deleted", planSeq' = planSeq,
    clock' = clock, st' = st, holdExp' = holdExp, published' = published, keepUp,
  }
  action GcFinish = all {
    gcPhase == "deleted",
    st' = { ...bump(st), deleting: false },
    holdExp' = prunedHold,
    gcPhase' = "idle", planSeq' = planSeq,
    clock' = clock, bytes' = bytes, published' = published, keepUp, keepGhost,
  }
  // A gc that stops after the mark; a later run finds `deleting` and resumes
  // at the delete (module docs, step 4).
  action GcCrash = all {
    gcPhase == "marked" or gcPhase == "deleted",
    gcPhase' = "idle", planSeq' = planSeq,
    clock' = clock, bytes' = bytes, st' = st, holdExp' = holdExp, published' = published,
    keepUp, keepGhost,
  }
  def gcResumeEnabled: bool = gcPhase == "idle" and st.deleting and MUTANT != "noResume"
  action GcResume = all {
    gcResumeEnabled,
    gcPhase' = "marked", planSeq' = planSeq,
    clock' = clock, bytes' = bytes, st' = st, holdExp' = holdExp, published' = published,
    keepUp, keepGhost,
  }

  action step = any {
    Tick, UpHold, UpBytes, UpApply, UpGiveUp, RelayHolder,
    GcPlan, GcCommit, GcDelete, GcFinish, GcCrash, GcResume,
  }

  // ---- invariants -----------------------------------------------------------------
  // A reachable object's bytes are present.
  val NoReachableLoss = published implies bytes
  // GC never deletes bytes that are reachable, held, or in a holder row.
  val NoLiveDelete = not(lostLive)
  val Safety = NoReachableLoss and NoLiveDelete
  // Progress (the deadlock check is off: runs legitimately end at MAXT).
  // A `deleting` mark always has a gc step that moves it towards clearing,
  // and an in-flight upload always has a step of its own, or waits only on
  // such a mark.
  val DeletingClears =
    st.deleting implies (gcPhase == "marked" or gcPhase == "deleted" or gcResumeEnabled)
  def upCanStep: bool =
    if (upPhase == "idle" or upPhase == "done") true
    else if (upPhase == "applied") not(st.deleting)
    else if (holdStep) not(st.deleting) or MUTANT == "noDeletingGuard"
    else if (bytesStep) true
    else upApplyEnabled or upGiveUpEnabled
  val UploadCanStep = upCanStep or st.deleting
  val Progress = DeletingClears and UploadCanStep
  val All = Safety and Progress

  // ---- canaries (each must be violated) ----------------------------------------
  val CanaryNoDelete = not(deletedAny)
  val CanaryNoPublish = not(published)
  // gc deletes the old blob and the upload still publishes (re-creating the
  // bytes after its refused hold is retried): the race the ordering must win.
  val CanaryNoDeleteThenPublish = not(deletedAny and published)
  val CanaryNoHolder = st.holders == 0
}

module ciHoldFirst {        // hold before relying on the bytes: safe
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "none").*

  // gc marks the old blob; the upload's hold is refused until gc finishes,
  // then the upload re-creates the bytes and publishes.
  run gcFirstTest =
    init.then(Tick).then(Tick).then(GcPlan).then(GcCommit)
      .expect(st.deleting)
      .then(GcDelete).then(GcFinish)
      .then(UpHold).then(UpBytes).then(UpApply).then(RelayHolder)
      .expect(bytes and published and st.holders == 1 and Safety
              and not(CanaryNoDelete))
  // A plan made before the hold fails its Equals guard.
  run staleplanTest =
    init.then(Tick).then(Tick).then(GcPlan).then(UpHold).then(GcCommit)
      .expect(gcPhase == "idle" and not(st.deleting))
}
module ciBytesFirst {       // bytes (dedup or write) before the hold: unsafe
  import ciCore(UPLOAD_ORDER = "bytesFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "none").*

  // The upload dedups against the old blob, a whole gc cycle runs, then the
  // hold succeeds (no longer deleting) and the apply publishes a lost object.
  run dedupThenCollectTest =
    init.then(Tick).then(Tick).then(UpBytes)
      .then(GcPlan).then(GcCommit).then(GcDelete).then(GcFinish)
      .then(UpHold).then(UpApply)
      .expect(published and not(bytes) and not(NoReachableLoss) and NoLiveDelete)
}
// From the hold, gc is kept off the object until max(hold expiry, last
// change + GRACE); the apply is a ref-shard write and does not bump the
// state row. So the relay must record the holder before that:
// APPLY_WINDOW + RELAY_LAG < max(TTL, GRACE).
module ciShortTtl {         // TTL = GRACE = APPLY_WINDOW + RELAY_LAG: violates NoReachableLoss
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 2, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "none").*
}
module ciShortTtlGrace {    // the same TTL with GRACE = 3 > APPLY_WINDOW + RELAY_LAG: safe
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 3, TTL = 2, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "none").*
}
module ciMutNoDeletingGuard {
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "noDeletingGuard").*
}
module ciMutNoSeqGuard {
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "noSeqGuard").*
}
module ciMutNoResume {      // violates DeletingClears
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "noResume").*
}
module ciMutNoGiveUp {      // violates UploadCanStep
  import ciCore(UPLOAD_ORDER = "holdFirst", GRACE = 2, TTL = 3, APPLY_WINDOW = 1,
    RELAY_LAG = 1, MUTANT = "noGiveUp").*
}
