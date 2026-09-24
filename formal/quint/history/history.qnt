// -*- mode: Bluespec; -*-
// First-parent history publication and crash recovery (MKIT-20).
//
// Models docs/specs/SPEC-HISTORY-PROOF.md §4.3-§4.4 for ONE branch under the
// guards of SPEC-CONCURRENCY §3.3/§4, aligned with
// rust/crates/mkit-core/src/history/ancestry.rs (`advance`, `finish`,
// `recover`, `AncestrySnapshot::load`) and refs.rs / refs/ancestry_state.rs
// (`RefMutation::{write,delete}`, `invalidate`, `pending_roots`).
//
// Abstractions (see README.md in this directory for bounds and commands):
// - Both history and mutation locks are held for a whole operation, so
//   guarded operations, raw writers and readers are serialized; each
//   durable step (write+sync) is one atomic action. `pc` and the other
//   volatile variables are lost by `Crash`, which may fire between ANY two
//   durable steps. Files already synced survive.
// - Commits are a fixed first-parent forest; objects are content-addressed
//   and immutable, so a snapshot is (tip, chain) and "verified" means every
//   chain object is present in `store`.
// - Generations are fresh ids from a counter (the 32 random bytes).
// - Repository id / ref-name context checks are single-valued here.
// - GC runs atomically while no operation holds the ref locks (the
//   worktree-lock containment of SPEC-CONCURRENCY §4); a crash can still
//   leave an intent behind for GC to see.

module historyCore {
  // ---- mutants: every switch is false in the conforming model ----------
  const BUG_LOAD_IGNORES_TX: bool       // reader serves while an intent exists
  const BUG_RAW_IGNORES_TX: bool        // raw writer steps over an intent
  const BUG_RAW_SKIPS_INVALIDATE: bool  // raw write/delete keeps `current`
  const BUG_GC_IGNORES_INTENT: bool     // GC drops pending intent roots
  const BUG_HEAL_TIP_ONLY: bool         // recovery appends only the tip
  const BUG_REUSE_GEN_ON_REWRITE: bool  // non-FF keeps the old generation
  const BUG_FRESH_GEN_ON_FF: bool       // FF mints a fresh generation
  const BUG_SKIP_VERIFY: bool           // intent persisted without ancestors
  const BUG_FINISH_ANY_REF: bool        // recovery accepts any ref value
  const BUG_WRITE_BEFORE_INVALIDATE: bool  // raw write moves the ref first

  // ---- commit universe ----------------------------------------------------
  // First-parent forest: 1 <- 2 <- 3 and 1 <- 4 (a fork). 0 is "no ref".
  pure val NONE = 0
  pure val ANY = -1
  pure val COMMITS = Set(1, 2, 3, 4)
  pure val CHAIN: int -> List[int] =
    Map(0 -> [], 1 -> [1], 2 -> [1, 2], 3 -> [1, 2, 3], 4 -> [1, 4])
  pure def chainOf(c: int): List[int] = CHAIN.get(c)
  pure val CHAINSET: int -> Set[int] =
    Map(0 -> Set(), 1 -> Set(1), 2 -> Set(1, 2), 3 -> Set(1, 2, 3), 4 -> Set(1, 4))
  pure def elems(c: int): Set[int] = CHAINSET.get(c)
  // `a` is on the first-parent chain of `b` (ancestor-or-equal).
  pure def fpAncestor(a: int, b: int): bool = elems(b).contains(a)
  // Lineage summary of the ref values written since a generation was minted.
  // `ok` means every value was present and extended the previous one: no
  // delete, rewind, reset or ABA. Kept incrementally (O(1)) for Apalache.
  type Lin = { ok: bool, first: int, last: int, empty: bool }
  pure val LIN0: Lin = { ok: true, first: 0, last: 0, empty: true }
  pure def linAppend(l: Lin, v: int): Lin =
    { ok: l.ok and v != NONE and (l.empty or fpAncestor(l.last, v)),
      first: if (l.empty) v else l.first, last: v, empty: false }

  // Generation ids 1..MAXGEN (bound on fresh generations).
  pure val MAXGEN = 3
  pure val GENS = 1.to(MAXGEN)
  pure val EXPECTS = Set(ANY, NONE).union(COMMITS)

  type Snap = { present: bool, gen: int, tip: int, chain: List[int] }
  type Tx = { present: bool, prev: int, prevGen: int, target: int, gen: int }
  type Events = { failedClosed: bool, crashTx: bool, recovered: bool,
                  ffMulti: bool, deleted: bool, recreated: bool, gcWithTx: bool,
                  gcLostIntent: bool }

  pure val NOSNAP: Snap = { present: false, gen: 0, tip: 0, chain: [] }
  pure val NOTX: Tx = { present: false, prev: 0, prevGen: 0, target: 0, gen: 0 }
  pure val NOEV: Events = { failedClosed: false, crashTx: false, recovered: false,
                            ffMulti: false, deleted: false, recreated: false,
                            gcWithTx: false, gcLostIntent: false }

  // ---- durable state (§4.1) ------------------------------------------------
  var ref: int                  // refs/heads/<b>; 0 = missing
  var tx: Tx                    // `transaction` (§4.3)
  var pending: Snap             // `pending-snapshot`
  var snaps: int -> Snap        // `generations/<g>.snapshot`
  var current: int              // `current` generation pointer; 0 = absent
  var store: Set[int]           // object store
  // ---- volatile (lost on crash) --------------------------------------------
  var pc: str
  var after: str                // continuation after `finish`
  var opTarget: int
  var opExpect: int
  var memChain: List[int]       // snapshot built in memory for `finish`
  // ---- ghosts --------------------------------------------------------------
  var nextGen: int
  var lineage: int -> Lin      // ref values written since each gen was minted
  var ev: Events

  def cur: Snap = if (current == NONE) NOSNAP else snaps.get(current)

  // ---- frame helpers -------------------------------------------------------
  action keepDurable = all {
    ref' = ref, tx' = tx, pending' = pending, snaps' = snaps,
    current' = current, store' = store,
  }
  action keepGhost = all {
    nextGen' = nextGen, lineage' = lineage, ev' = ev,
  }
  action resetVolatile = all {
    pc' = "idle", after' = "none", opTarget' = NONE, opExpect' = ANY, memChain' = [],
  }
  // Operation returns an error with no durable effect.
  action opError = all { keepDurable, keepGhost, resetVolatile }
  // A ref write/delete, also appended to every minted generation's lineage.
  action writeRefGhost(v: int): bool = all {
    ref' = v,
    lineage' = GENS.mapBy(g => if (g < nextGen) linAppend(lineage.get(g), v)
                               else lineage.get(g)),
  }

  action init = all {
    ref' = NONE, tx' = NOTX, pending' = NOSNAP, snaps' = GENS.mapBy(g => NOSNAP),
    current' = NONE, store' = COMMITS,
    pc' = "idle", after' = "none", opTarget' = NONE, opExpect' = ANY, memChain' = [],
    nextGen' = 1, lineage' = GENS.mapBy(g => LIN0), ev' = NOEV,
  }

  // ---- §4.4 steps 1-3: decide chain/generation, persist intent -------------
  // `advance` after any recorded transaction is finished.
  action decide(t: int, exp: int): bool = {
    val condOk = exp == ANY or ref == exp
    // read_current_descriptor: `current` naming a missing snapshot errors.
    val corrupt = current != NONE and not(cur.present)
    val compatible = cur.present and cur.tip == ref
    val noop = compatible and cur.tip == t
    // Missing ancestors fail before publication (§4.2).
    val verified = BUG_SKIP_VERIFY or elems(t).subseteq(store)
    // §1/§4.4 step 2: a fast-forward of the live published tip keeps it.
    val ff = compatible and fpAncestor(cur.tip, t) and not(BUG_FRESH_GEN_ON_FF)
    val reuse = ff or (BUG_REUSE_GEN_ON_REWRITE and compatible)
    if (not(condOk) or corrupt or noop or not(verified)) opError
    else if (reuse) all {
      tx' = { present: true, prev: ref, prevGen: current, target: t, gen: current },
      ref' = ref, pending' = pending, snaps' = snaps, current' = current, store' = store,
      pc' = "f_pending", after' = "none", opTarget' = t, opExpect' = exp,
      memChain' = chainOf(t),
      nextGen' = nextGen, lineage' = lineage,
      ev' = { ...ev, ffMulti: ev.ffMulti or chainOf(t).length() >= cur.chain.length() + 2 },
    }
    else all {
      nextGen <= MAXGEN,  // bound
      tx' = { present: true, prev: ref, prevGen: if (compatible) current else NONE,
              target: t, gen: nextGen },
      ref' = ref, pending' = pending, snaps' = snaps, current' = current, store' = store,
      pc' = "f_pending", after' = "none", opTarget' = t, opExpect' = exp,
      memChain' = chainOf(t),
      nextGen' = nextGen + 1,
      lineage' = lineage.set(nextGen, LIN0),
      ev' = { ...ev, recreated: ev.recreated or ev.deleted },
    }
  }

  // ---- `finish` entry for a recorded transaction (recovery, §4.4) ----------
  // Accepts only the recorded previous or target ref and rebuilds the ENTIRE
  // target chain from verified objects; otherwise fails closed (intent kept).
  action startFinish(k: str, t: int, exp: int): bool = {
    val ok = (BUG_FINISH_ANY_REF or ref == tx.prev or ref == tx.target)
             and elems(tx.target).subseteq(store)
    val rebuilt =
      if (BUG_HEAL_TIP_ONLY and tx.prevGen != NONE and snaps.get(tx.prevGen).present)
        snaps.get(tx.prevGen).chain.append(tx.target)
      else chainOf(tx.target)
    if (ok) all {
      keepDurable,
      pc' = "f_pending", after' = k, opTarget' = t, opExpect' = exp, memChain' = rebuilt,
      keepGhost,
    }
    else all {
      keepDurable, resetVolatile,
      nextGen' = nextGen, lineage' = lineage,
      ev' = { ...ev, failedClosed: true },
    }
  }

  // step 4: write+sync pending-snapshot
  action FPending = all {
    pc == "f_pending",
    pending' = { present: true, gen: tx.gen, tip: tx.target, chain: memChain },
    ref' = ref, tx' = tx, snaps' = snaps, current' = current, store' = store,
    pc' = "f_ref", after' = after, opTarget' = opTarget, opExpect' = opExpect,
    memChain' = memChain,
    keepGhost,
  }
  // step 5: publish target ref with the already-held guard
  action FRef = all {
    pc == "f_ref",
    writeRefGhost(tx.target),
    tx' = tx, pending' = pending, snaps' = snaps, current' = current, store' = store,
    pc' = "f_snap", after' = after, opTarget' = opTarget, opExpect' = opExpect,
    memChain' = memChain,
    nextGen' = nextGen, ev' = ev,
  }
  // step 6: rename pending into generations/<gen>.snapshot, sync dirs
  action FSnap = all {
    pc == "f_snap",
    if (pending.present) all {
      snaps' = snaps.set(tx.gen, pending), pending' = NOSNAP,
      ref' = ref, tx' = tx, current' = current, store' = store,
      pc' = "f_current", after' = after, opTarget' = opTarget, opExpect' = opExpect,
      memChain' = memChain,
      keepGhost,
    } else opError,
  }
  // step 7a: atomically publish `current`
  action FCurrent = all {
    pc == "f_current",
    current' = tx.gen,
    ref' = ref, tx' = tx, pending' = pending, snaps' = snaps, store' = store,
    pc' = "f_clear", after' = after, opTarget' = opTarget, opExpect' = opExpect,
    memChain' = memChain,
    keepGhost,
  }
  // step 7b: remove `transaction`, then run the caller's continuation.
  action FClear = {
    // `advance`: retry_of_intent (Any / Missing / Match) returns early.
    val retry = opTarget == tx.target and (opExpect == ANY or opExpect == tx.prev)
    val nextPc =
      if (after == "advance") (if (retry) "idle" else "adv_cont")
      else if (after == "delete") "del_inval"
      else "idle"
    all {
      pc == "f_clear",
      tx' = NOTX,
      ref' = ref, pending' = pending, snaps' = snaps, current' = current, store' = store,
      pc' = nextPc, after' = "none",
      opTarget' = if (nextPc == "adv_cont") opTarget else NONE,
      opExpect' = if (nextPc == "idle") ANY else opExpect,
      memChain' = [],
      nextGen' = nextGen, lineage' = lineage,
      ev' = { ...ev, recovered: ev.recovered or ev.crashTx },
    }
  }

  // ---- entry points ----------------------------------------------------------
  // refs::update_ref_with_ancestry -> ancestry::advance
  action Advance(t: int, exp: int): bool = all {
    pc == "idle",
    if (tx.present) startFinish("advance", t, exp) else decide(t, exp),
  }
  action AdvanceCont = all { pc == "adv_cont", decide(opTarget, opExpect) }

  // refs::delete_ref_with_ancestry: recover, then RefMutation::delete
  action Delete(exp: int): bool = all {
    pc == "idle",
    if (tx.present) startFinish("delete", NONE, exp)
    else all {
      keepDurable, keepGhost,
      pc' = "del_inval", after' = "none", opTarget' = NONE, opExpect' = exp, memChain' = [],
    },
  }
  // refs::delete_ref / RemoteRefs etc.: RefMutation::delete without recovery
  action RawDelete(exp: int): bool = all {
    pc == "idle",
    if (tx.present and not(BUG_RAW_IGNORES_TX)) opError
    else all {
      keepDurable, keepGhost,
      pc' = "del_inval", after' = "none", opTarget' = NONE, opExpect' = exp, memChain' = [],
    },
  }
  // RefMutation::delete: check expected, invalidate/sync `current` ...
  action DelInval = all {
    pc == "del_inval",
    if (opExpect != ANY and ref != opExpect) opError
    else all {
      current' = if (BUG_RAW_SKIPS_INVALIDATE) current else NONE,
      ref' = ref, tx' = tx, pending' = pending, snaps' = snaps, store' = store,
      pc' = "del_ref", after' = "none", opTarget' = NONE, opExpect' = opExpect,
      memChain' = [],
      keepGhost,
    },
  }
  // ... then remove/sync the ref (NotFound if already missing).
  action DelRef = all {
    pc == "del_ref",
    if (ref == NONE) opError
    else all {
      writeRefGhost(NONE),
      tx' = tx, pending' = pending, snaps' = snaps, current' = current, store' = store,
      resetVolatile,
      nextGen' = nextGen, ev' = { ...ev, deleted: true },
    },
  }

  // RefMutation::write (update_ref / write_ref / builds without history-mmr)
  action RawWrite(v: int, exp: int): bool = all {
    pc == "idle",
    val condOk = exp == ANY or ref == exp
    val blocked = tx.present and not(BUG_RAW_IGNORES_TX)
    if (not(condOk) or blocked) opError
    else if (ref == v) all {
      // true no-op write preserves a matching snapshot
      writeRefGhost(v),
      tx' = tx, pending' = pending, snaps' = snaps, current' = current, store' = store,
      resetVolatile,
      nextGen' = nextGen, ev' = ev,
    }
    else if (BUG_WRITE_BEFORE_INVALIDATE) all {
      // mutant: tip first; a crash before the invalidation keeps `current`
      writeRefGhost(v),
      current' = current, tx' = tx, pending' = pending, snaps' = snaps, store' = store,
      pc' = "raw_write", after' = "none", opTarget' = v, opExpect' = exp, memChain' = [],
      nextGen' = nextGen, ev' = ev,
    }
    else all {
      // invalidate: remove/sync `current` before the tip changes
      current' = if (BUG_RAW_SKIPS_INVALIDATE) current else NONE,
      ref' = ref, tx' = tx, pending' = pending, snaps' = snaps, store' = store,
      pc' = "raw_write", after' = "none", opTarget' = v, opExpect' = exp, memChain' = [],
      keepGhost,
    },
  }
  action RawWriteRef = all {
    pc == "raw_write",
    if (BUG_WRITE_BEFORE_INVALIDATE) all {
      current' = NONE, ref' = ref, lineage' = lineage,
      tx' = tx, pending' = pending, snaps' = snaps, store' = store,
      resetVolatile, nextGen' = nextGen, ev' = ev,
    } else all {
      writeRefGhost(opTarget),
      tx' = tx, pending' = pending, snaps' = snaps, current' = current, store' = store,
      resetVolatile,
      nextGen' = nextGen, ev' = ev,
    },
  }

  // AncestrySnapshot::load under both locks (§3). A pure read, so it is a
  // state predicate: `canServe` holds exactly when a load issued now (no
  // operation in flight, i.e. locks free) returns a trusted descriptor for
  // `current`, from which proofs are served.
  def canServe: bool =
    pc == "idle"
    and (BUG_LOAD_IGNORES_TX or not(tx.present))
    and cur.present and cur.tip == ref
    and cur.chain == chainOf(cur.tip)      // reconstructs the chain from
    and elems(cur.tip).subseteq(store)     // verified local objects

  // GC: roots are the ref plus pending intent roots (§4.3).
  action Gc = {
    val intent = if (tx.present and not(BUG_GC_IGNORES_INTENT)) Set(tx.prev, tx.target)
                 else Set()
    val keep = Set(ref).union(intent).fold(Set(), (acc, r) => acc.union(elems(r)))
    all {
      pc == "idle",
      store' = store.intersect(keep),
      ref' = ref, tx' = tx, pending' = pending, snaps' = snaps, current' = current,
      resetVolatile,
      nextGen' = nextGen, lineage' = lineage,
      ev' = { ...ev, gcWithTx: ev.gcWithTx or tx.present,
              gcLostIntent: ev.gcLostIntent or (tx.present and
                not(store.intersect(elems(tx.prev).union(elems(tx.target)))
                    .subseteq(keep))) },
    }
  }
  // commit/fetch writes one object (possibly without its ancestors).
  action WriteObject(c: int): bool = all {
    pc == "idle",
    store' = store.union(Set(c)),
    ref' = ref, tx' = tx, pending' = pending, snaps' = snaps, current' = current,
    resetVolatile, keepGhost,
  }
  // Power loss / process death between durable steps.
  action Crash = all {
    pc != "idle",
    keepDurable, resetVolatile,
    nextGen' = nextGen, lineage' = lineage,
    ev' = { ...ev, crashTx: ev.crashTx or tx.present },
  }

  action step = {
    nondet t = COMMITS.oneOf()
    nondet e = EXPECTS.oneOf()
    any {
      Advance(t, e), AdvanceCont, FPending, FRef, FSnap, FCurrent, FClear,
      Delete(e), RawDelete(e), DelInval, DelRef, RawWrite(t, e), RawWriteRef,
      Gc, WriteObject(t), Crash,
    }
  }

  // ---- invariants -----------------------------------------------------------
  // §4.4: proofs MUST be withheld while an intent exists.
  val NoProofWhileIntent = canServe implies not(tx.present)
  // A served descriptor describes the live ref, with its canonical (whole)
  // first-parent chain. (Load re-checks this itself; see CurrentMatchesRef
  // for the durable-state version that does not rely on the re-check.)
  val ServedMatchesRef = canServe implies
    (cur.tip == ref and cur.chain == chainOf(ref))
  // Durable: without an intent, `current` always matches the live ref.
  val CurrentMatchesRef = (not(tx.present) and current != NONE) implies
    (cur.present and cur.tip == ref and cur.chain == chainOf(ref))
  // §1: generations are never reused across delete/recreate, rewrite or ABA:
  // every ref value since the published generation was minted was a
  // first-parent fast-forward of the previous one.
  val GenerationFastForwardOnly = (not(tx.present) and current != NONE) implies
    (not(lineage.get(current).empty) and lineage.get(current).ok)
  val ServedGenerationFresh = canServe implies lineage.get(current).ok
  // §1: "First-parent fast-forwards retain the generation" (the converse of
  // the above). `prevGen` is recorded only for a compatible published tip.
  val FastForwardRetainsGeneration =
    (tx.present and tx.prevGen != NONE and fpAncestor(tx.prev, tx.target))
      implies tx.gen == tx.prevGen
  // §4.4: finish proceeds only from the recorded previous or target ref.
  val FinishOnlyFromRecorded =
    (Set("f_pending", "f_ref").contains(pc) implies (ref == tx.prev or ref == tx.target))
    and (Set("f_snap", "f_current", "f_clear").contains(pc) implies ref == tx.target)
  // §4.3: pending intent refs stay GC roots (their whole chains survive).
  // (A raw writer may leave `prev` naming an already-missing object, so the
  // property is "GC never removes" rather than "prev's chain is present".)
  val IntentRootsRetained = not(ev.gcLostIntent)
    and (tx.present implies elems(tx.target).subseteq(store))
  // Recovery is always possible and yields a valid publication: from any
  // idle state with an intent, `finish` is enabled, deterministic, and its
  // 5 remaining durable steps produce ref = snapshot tip = target, the
  // canonical chain, and a fast-forward-only lineage. Divergence (fail
  // closed) is unreachable through the supported APIs.
  val RecoveryEnabled = (tx.present and pc == "idle") implies
    ((ref == tx.prev or ref == tx.target)
     and elems(tx.target).subseteq(store)
     and linAppend(lineage.get(tx.gen), tx.target).ok)
  val NeverFailsClosed = not(ev.failedClosed)

  val Safety = NoProofWhileIntent and ServedMatchesRef and CurrentMatchesRef
    and GenerationFastForwardOnly and ServedGenerationFresh and FastForwardRetainsGeneration
    and FinishOnlyFromRecorded
    and IntentRootsRetained and RecoveryEnabled and NeverFailsClosed

  // ---- canaries: each MUST be violated (reachability witnesses) ----------------
  val CanaryNeverServed = not(canServe)
  val CanaryNoCrashRecovery = not(ev.recovered)
  val CanaryNoMultiCommitFF = not(ev.ffMulti)
  val CanaryNoRecreate = not(ev.recreated)
  val CanaryNoGcDuringIntent = not(ev.gcWithTx)
  // served a reused generation after a multi-commit fast-forward
  val CanaryNoServedFF = not(canServe and lineage.get(current).first != ref)
}

// Conforming model.
module history {
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*

  // Scenario tests mirroring ancestry.rs
  // `every_publication_boundary_recovers_the_whole_fast_forward`.
  action finishStep = any { FPending, FRef, FSnap, FCurrent, FClear }
  run publishOne = init.then(Advance(1, ANY)).then(5.reps(_ => finishStep))
  // Crash after the intent plus k of steps 4, 5, 6, 7a; GC runs; recovery via a
  // retried advance restores the WHOLE 1 -> 3 fast-forward in generation 1.
  run boundary(k: int): bool =
    publishOne
      .expect(canServe and current == 1 and cur.chain == [1])
      .then((k + 1).reps(i => if (i == 0) Advance(3, ANY) else finishStep))
      .then(Crash)
      .expect(tx.present and not(canServe) and tx.gen == 1)
      .then(Gc)
      .expect(Set(1, 2, 3).subseteq(store))
      .then(Advance(3, ANY))
      .then(5.reps(_ => finishStep))
      .expect(not(tx.present) and pc == "idle" and canServe and current == 1
              and ref == 3 and cur.chain == [1, 2, 3])
  run boundary0Test = boundary(0)
  run boundary1Test = boundary(1)
  run boundary2Test = boundary(2)
  run boundary3Test = boundary(3)
  run boundary4Test = boundary(4)
  // Raw ABA (3 -> 4 -> 3) never revives generation 1; the next publish mints 2.
  run rawAbaTest =
    publishOne.then(Advance(3, ANY)).then(5.reps(_ => finishStep))
      .then(RawWrite(4, ANY)).then(RawWriteRef)
      .then(RawWrite(3, ANY)).then(RawWriteRef)
      .expect(current == NONE and not(canServe))
      .then(Advance(3, ANY)).then(5.reps(_ => finishStep))
      .expect(canServe and current == 2)
  // Delete/recreate mints a fresh generation; archived snapshot 1 remains.
  run deleteRecreateTest =
    publishOne.then(Delete(ANY)).then(DelInval).then(DelRef)
      .expect(ref == NONE and current == NONE and snaps.get(1).present)
      .then(Advance(1, NONE)).then(5.reps(_ => finishStep))
      .expect(canServe and current == 2)
}

// Mutants: each must violate the named invariant (non-vacuity).
module mutLoadIgnoresTx {   // violates NoProofWhileIntent
  import historyCore(
    BUG_LOAD_IGNORES_TX = true, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutRawIgnoresTx {    // violates RecoveryEnabled / NeverFailsClosed
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = true,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutRawSkipsInvalidate {  // violates GenerationFastForwardOnly (ABA)
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = true, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutGcIgnoresIntent {  // violates IntentRootsRetained
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = true,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutHealTipOnly {     // violates CurrentMatchesRef
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = true, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutReuseGenOnRewrite {  // violates GenerationFastForwardOnly
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = true,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutFreshGenOnFF {    // violates FastForwardRetainsGeneration
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = true, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
module mutSkipVerify {      // violates IntentRootsRetained (§4.2 missing ancestors)
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = true, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
// Needs a raw writer that steps over the intent to create the divergence.
module mutFinishAnyRef {    // violates FinishOnlyFromRecorded
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = true,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = true,
    BUG_WRITE_BEFORE_INVALIDATE = false
  ).*
}
// §4.4 deletion / refs.rs `RefMutation::write`: invalidate BEFORE the tip moves.
module mutWriteBeforeInvalidate {  // violates CurrentMatchesRef (crash between)
  import historyCore(
    BUG_LOAD_IGNORES_TX = false, BUG_RAW_IGNORES_TX = false,
    BUG_RAW_SKIPS_INVALIDATE = false, BUG_GC_IGNORES_INTENT = false,
    BUG_HEAL_TIP_ONLY = false, BUG_REUSE_GEN_ON_REWRITE = false,
    BUG_FRESH_GEN_ON_FF = false, BUG_SKIP_VERIFY = false, BUG_FINISH_ANY_REF = false,
    BUG_WRITE_BEFORE_INVALIDATE = true
  ).*
}
