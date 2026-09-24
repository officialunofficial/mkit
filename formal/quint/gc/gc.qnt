// -*- mode: Bluespec; -*-
// Garbage collection, retention roots and the recovery log (Linear MKIT-21).
//
// Models docs/specs/SPEC-GC.md ("Retention roots", "Fail-closed requirement",
// "Recovery log (Part 2)", "Invariants") under the lock sets of
// docs/specs/SPEC-CONCURRENCY.md §3.1, §3.2 and §4, aligned with
// rust/crates/mkit-core/src/ops/gc.rs (`collect_roots`, `live_objects`,
// `run_gc`), ops/recovery.rs (`record`, `expire`, `is_retained`) and
// rust/crates/mkit-cli/src/commands/gc.rs (lock set, `now`, expire → run_gc).
//
// Actors (each step is one atomic filesystem effect):
//   gc      : lock (worktrees.lock + every worktree.lock, §4; then read `now`)
//             → expireRead → expireWrite (recovery::expire is read-filter-
//             rewrite) → mark (collect_roots + closure, fail closed) → sweep
//             one object per step (run_gc loop) → done (release).
//   producer: amend/reset/rebase moving `main` (SPEC-GC "Recovery log"): under
//             its tree's worktree.lock, write the new tip's objects → record the
//             superseded tip → move the ref → release.
//   push    : a file-transport push (SPEC-CONCURRENCY §3.1): writes the tip's
//             objects, later publishes ref `pushed`. It takes NONE of gc's
//             locks, so it interleaves freely with a gc run.
//   env     : a root source (ref file / recovery log) becomes unreadable or is
//             repaired; the discrete clock advances.
//
// Abstractions:
// - Fixed object DAG; an object is present in the loose store with an on-disk
//   mtime. Writes are content-addressed: writing an already-present object is a
//   dedup hit that leaves its mtime untouched (store.rs `ObjectStore::write`,
//   `final_path.exists()` branch) unless FRESHEN models refresh-on-dedup.
// - Root sources: refs main/tag/pushed (HEAD, branches, tags, remotes, index,
//   stash, op state, attestations and history intents all behave like a ref
//   here) and the recovery log.
// - MAX_REACHABLE truncation and ObjectNotFound are the same fail-closed abort
//   as an unreadable source and are not modelled separately.
// - gc's `now` is read once after the locks (commands/gc.rs); each object's
//   mtime is read when the sweep reaches it (gc.rs `store.object_metadata`).
//
// Bounds (explicit): 7 objects, 3 refs + recovery log, 1 producer, 1 push,
// clock 0..MAXT = 6, GRACE = 2 (0 in gcGrace0), RETAIN = 2, KEEP_LAST = 1,
// at most MAXSEQ = 3 recovery records. Commands: see check.sh / README.md.

module gcCore {
  // PUSH_MODE: "none"    no push concurrent with gc (the supported deployment,
  //                      SPEC-CONCURRENCY §3.1)
  //            "raw"     push of arbitrary duration
  //            "fast"    push publishes < GRACE after writing its objects
  //            "bounded" push publishes only while EVERY object its tip reaches
  //                      has on-disk mtime > publish time - GRACE
  //                      (the exact timing assumption, `pushTimingOk`)
  const PUSH_MODE: str
  const FRESHEN: bool          // dedup hit refreshes mtime (store.rs does NOT)
  const GRACE: int             // object grace window (default 14 d; `--grace-secs`)
  // Mutants (all false in conforming instances), for non-vacuity only.
  const BUG_NO_LOCK: bool      // gc does not exclude producers' worktree.lock
  const BUG_LENIENT: bool      // gc skips unreadable sources instead of aborting
  const BUG_NO_RECORD: bool    // producer moves the ref without recording
  const BUG_NO_KEEP_LAST: bool // expire ignores the keep-last floor

  // ---- constants -------------------------------------------------------------
  pure val NONE = -1
  pure val RETAIN = 2          // recovery-log grace (default 90 d, recovery.rs)
  // KEEP_LAST = 1 (default 50): "among the most recent 1" = no newer entry.
  pure val MAXT = 6
  pure val MAXSEQ = 3
  // Object DAG (SPEC-GC closure walk: commit -> tree + parents, tree -> entries).
  //   0, 1, 5 leaves; 2 = C0 -> {0}; 3 = C1 -> {C0, 1};
  //   4 = C1' (amend of C1) -> {C0, 1}; 6 = P (push tip) -> {C1, 5}.
  //   Object 5 starts as an old orphan (mtime 0), 4 and 6 start absent.
  pure val OBJS = 0.to(6)
  pure val EDGES: int -> Set[int] =
    Map(0 -> Set(), 1 -> Set(), 2 -> Set(0), 3 -> Set(2, 1), 4 -> Set(2, 1),
        5 -> Set(), 6 -> Set(3, 5))
  // Reflexive-transitive closure of EDGES per object, tabulated for the SMT
  // backend; `closTableTest` checks it against the EDGES fixpoint.
  pure val CLOS: int -> Set[int] =
    Map(0 -> Set(0), 1 -> Set(1), 2 -> Set(2, 0), 3 -> Set(3, 2, 1, 0),
        4 -> Set(4, 2, 1, 0), 5 -> Set(5), 6 -> Set(6, 3, 2, 1, 0, 5))
  pure def closure(s: Set[int]): Set[int] = s.fold(Set(), (a, o) => a.union(CLOS.get(o)))
  pure def edgeClosure(s: Set[int]): Set[int] =
    OBJS.fold(s, (acc, _i) => acc.fold(acc, (a, o) => a.union(EDGES.get(o))))
  pure val PROD_TARGETS = Set(2, 3, 4)   // reset to C0 / back to C1 / amend to C1'
  pure val PUSH_TIP = 6
  pure val REFS = Set("main", "tag", "pushed")
  pure val SOURCES = Set("main", "tag", "pushed", "rlog")
  // saturating_sub, as in gc.rs / recovery.rs
  pure def age(now: int, t: int): int = if (now > t) now - t else 0

  type LogEntry = { seq: int, ts: int, obj: int }

  // ---- state -----------------------------------------------------------------
  var clock: int
  var present: Set[int]        // loose object store
  var mtime: int -> int        // on-disk mtime (stale once pruned)
  var refs: str -> int         // NONE = unset (all-zero hash, never a root)
  var corrupt: Set[str]        // root sources that currently cannot be read
  var rlog: Set[LogEntry]      // .mkit/recovery-log
  var nextSeq: int
  var lockHolder: str          // "none" | "gc" | "prod"  (worktree.lock)
  var prodPhase: str           // "idle" | "wrote" | "recorded"
  var prodTarget: int
  var gcPhase: str             // "idle" | "locked" | "expRead" | "expired" | "sweep"
  var gcNow: int
  var gcKept: Set[LogEntry]    // expire snapshot: entries to keep
  var gcDropAny: bool          // expire snapshot dropped something
  var gcLive: Set[int]         // live_objects
  var gcTodo: Set[int]         // iter_object_hashes not yet visited
  var pushPhase: str           // "idle" | "wrote" | "done"
  var pushStart: int
  // ghosts
  var ghostRecs: Set[LogEntry] // every record ever appended (never expired)
  var livePruned: bool         // gc deleted an object reachable from the true roots
  var sweptUnreadable: bool    // gc deleted after marking with an unreadable source
  var markedUnreadable: bool
  var prunes: int
  var aborts: int
  var expiredAny: bool
  var lastAction: { name: str, arg: int }

  // True root set (SPEC-GC "Retention roots"): every set ref plus every
  // recovery-log hash, whether or not gc can currently read the source.
  def refRoots(srcs: Set[str]): Set[int] =
    srcs.filter(r => REFS.contains(r) and refs.get(r) != NONE).map(r => refs.get(r))
  def logRoots: Set[int] = rlog.map(e => e.obj)
  def live: Set[int] = closure(refRoots(REFS).union(logRoots))

  action init = all {
    clock' = 0,
    present' = Set(0, 1, 2, 3, 5),
    mtime' = OBJS.mapBy(_o => 0),
    refs' = Map("main" -> 3, "tag" -> 2, "pushed" -> NONE),
    corrupt' = Set(),
    rlog' = Set(),
    nextSeq' = 0,
    lockHolder' = "none",
    prodPhase' = "idle",
    prodTarget' = NONE,
    gcPhase' = "idle",
    gcNow' = 0,
    gcKept' = Set(),
    gcDropAny' = false,
    gcLive' = Set(),
    gcTodo' = Set(),
    pushPhase' = "idle",
    pushStart' = 0,
    ghostRecs' = Set(),
    livePruned' = false,
    sweptUnreadable' = false,
    markedUnreadable' = false,
    prunes' = 0,
    aborts' = 0,
    expiredAny' = false,
    lastAction' = { name: "init", arg: NONE },
  }

  // ---- frame helpers ---------------------------------------------------------
  action keepGc = all {
    gcPhase' = gcPhase, gcNow' = gcNow, gcKept' = gcKept, gcDropAny' = gcDropAny,
    gcLive' = gcLive, gcTodo' = gcTodo, livePruned' = livePruned,
    sweptUnreadable' = sweptUnreadable, markedUnreadable' = markedUnreadable,
    prunes' = prunes, aborts' = aborts, expiredAny' = expiredAny,
  }
  action keepProd = all { prodPhase' = prodPhase, prodTarget' = prodTarget }
  action keepPush = all { pushPhase' = pushPhase, pushStart' = pushStart }
  action keepLog = all { rlog' = rlog, nextSeq' = nextSeq, ghostRecs' = ghostRecs }
  action keepStore = all { present' = present, mtime' = mtime }

  // Content-addressed write of `os` at the current clock: a new object gets
  // mtime = clock; a dedup hit keeps its old mtime unless FRESHEN.
  action writeObjs(os: Set[int]): bool = all {
    present' = present.union(os),
    mtime' = OBJS.mapBy(o =>
      if (os.contains(o) and (not(present.contains(o)) or FRESHEN)) clock
      else mtime.get(o)),
  }

  // ---- environment -------------------------------------------------------------
  action Tick(d: int): bool = all {
    d >= 1, clock + d <= MAXT,
    clock' = clock + d,
    keepStore, refs' = refs, corrupt' = corrupt, lockHolder' = lockHolder,
    keepLog, keepGc, keepProd, keepPush,
    lastAction' = { name: "tick", arg: d },
  }
  action Corrupt(s: str): bool = all {
    not(corrupt.contains(s)),
    corrupt' = corrupt.union(Set(s)),
    clock' = clock, keepStore, refs' = refs, lockHolder' = lockHolder,
    keepLog, keepGc, keepProd, keepPush,
    lastAction' = { name: "corrupt", arg: NONE },
  }
  action Repair(s: str): bool = all {
    corrupt.contains(s),
    corrupt' = corrupt.exclude(Set(s)),
    clock' = clock, keepStore, refs' = refs, lockHolder' = lockHolder,
    keepLog, keepGc, keepProd, keepPush,
    lastAction' = { name: "repair", arg: NONE },
  }

  // ---- producer: amend / reset / rebase (SPEC-GC "Recovery log", §3.2, §4) -----
  action ProdBegin(t: int): bool = all {
    prodPhase == "idle",
    lockHolder == "none" or (BUG_NO_LOCK and lockHolder == "gc"),
    t != refs.get("main"),
    nextSeq < MAXSEQ,
    writeObjs(CLOS.get(t)),                 // new tip + everything it references
    prodPhase' = "wrote", prodTarget' = t,
    lockHolder' = if (lockHolder == "none") "prod" else lockHolder,
    clock' = clock, refs' = refs, corrupt' = corrupt,
    keepLog, keepGc, keepPush,
    lastAction' = { name: "prod write", arg: t },
  }
  // recovery::record: durable append of the superseded tip, before the ref moves.
  def newRec: LogEntry = { seq: nextSeq, ts: clock, obj: refs.get("main") }
  action ProdRecord = all {
    prodPhase == "wrote",
    prodPhase' = "recorded", prodTarget' = prodTarget,
    rlog' = if (BUG_NO_RECORD) rlog else rlog.union(Set(newRec)),
    ghostRecs' = ghostRecs.union(Set(newRec)),
    nextSeq' = nextSeq + 1,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    lockHolder' = lockHolder,
    keepGc, keepPush,
    lastAction' = { name: "prod record", arg: refs.get("main") },
  }
  action ProdMove = all {
    prodPhase == "recorded",
    refs' = refs.set("main", prodTarget),
    corrupt' = corrupt.exclude(Set("main")),   // the ref file is rewritten
    prodPhase' = "idle", prodTarget' = NONE,
    lockHolder' = if (lockHolder == "prod") "none" else lockHolder,
    clock' = clock, keepStore,
    keepLog, keepGc, keepPush,
    lastAction' = { name: "prod move main", arg: prodTarget },
  }

  // ---- push through the file transport (SPEC-CONCURRENCY §3.1): no gc lock ------
  action PushWrite = all {
    PUSH_MODE != "none",
    pushPhase == "idle",
    writeObjs(CLOS.get(PUSH_TIP)),
    pushPhase' = "wrote", pushStart' = clock,
    clock' = clock, refs' = refs, corrupt' = corrupt, lockHolder' = lockHolder,
    keepLog, keepGc, keepProd,
    lastAction' = { name: "push write objects", arg: PUSH_TIP },
  }
  // Timing assumption evaluated at the publish instant `clock`.
  def pushTimingOk: bool =
    if (PUSH_MODE == "fast") clock - pushStart < GRACE
    else if (PUSH_MODE == "bounded")
      CLOS.get(PUSH_TIP).forall(o => clock - mtime.get(o) < GRACE)
    else true
  action PushPublish = all {
    pushPhase == "wrote",
    pushTimingOk,
    refs' = refs.set("pushed", PUSH_TIP),
    corrupt' = corrupt.exclude(Set("pushed")),
    pushPhase' = "done", pushStart' = pushStart,
    clock' = clock, keepStore, lockHolder' = lockHolder,
    keepLog, keepGc, keepProd,
    lastAction' = { name: "push publish", arg: PUSH_TIP },
  }
  // A push that misses its deadline gives up without publishing.
  action PushAbort = all {
    pushPhase == "wrote",
    not(pushTimingOk),
    pushPhase' = "done", pushStart' = pushStart,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    lockHolder' = lockHolder,
    keepLog, keepGc, keepProd,
    lastAction' = { name: "push abort", arg: PUSH_TIP },
  }

  // ---- gc (commands/gc.rs → recovery::expire → ops::gc::run_gc) ---------------
  def gcRelease: str = if (lockHolder == "gc") "none" else lockHolder
  action GcLock = all {
    gcPhase == "idle",
    lockHolder == "none" or (BUG_NO_LOCK and lockHolder == "prod"),
    lockHolder' = if (lockHolder == "none") "gc" else lockHolder,
    gcPhase' = "locked", gcNow' = clock,
    gcKept' = gcKept, gcDropAny' = gcDropAny, gcLive' = gcLive, gcTodo' = gcTodo,
    livePruned' = livePruned, sweptUnreadable' = sweptUnreadable,
    markedUnreadable' = false, prunes' = prunes, aborts' = aborts,
    expiredAny' = expiredAny,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    keepLog, keepProd, keepPush,
    lastAction' = { name: "gc lock", arg: clock },
  }
  // recovery.rs `is_retained`: age <= grace OR among the last keep_last (= 1).
  def retained(e: LogEntry, log: Set[LogEntry]): bool =
    age(gcNow, e.ts) <= RETAIN or
    (not(BUG_NO_KEEP_LAST) and not(log.exists(x => x.seq > e.seq)))
  // expire, read half; `read_all` is strict, so an unreadable log aborts gc.
  def expAborts: bool = corrupt.contains("rlog") and not(BUG_LENIENT)
  action GcExpireRead = all {
    gcPhase == "locked",
    gcPhase' = if (expAborts) "idle" else "expRead",
    aborts' = if (expAborts) aborts + 1 else aborts,
    lockHolder' = if (expAborts) gcRelease else lockHolder,
    gcKept' = rlog.filter(e => retained(e, rlog)),
    gcDropAny' = rlog.exists(e => not(retained(e, rlog))),
    lastAction' = { name: if (expAborts) "gc abort (expire)" else "gc expire read", arg: NONE },
    gcNow' = gcNow, gcLive' = gcLive, gcTodo' = gcTodo,
    livePruned' = livePruned, sweptUnreadable' = sweptUnreadable,
    markedUnreadable' = markedUnreadable, prunes' = prunes, expiredAny' = expiredAny,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    keepLog, keepProd, keepPush,
  }
  // expire, write half: atomic rewrite with the snapshot's kept entries, only
  // when the snapshot dropped something (recovery.rs `if pruned == 0`).
  action GcExpireWrite = all {
    gcPhase == "expRead",
    gcPhase' = "expired",
    rlog' = if (gcDropAny) gcKept else rlog,
    expiredAny' = if (gcDropAny) true else expiredAny,
    nextSeq' = nextSeq, ghostRecs' = ghostRecs,
    gcNow' = gcNow, gcKept' = gcKept, gcDropAny' = gcDropAny, gcLive' = gcLive,
    gcTodo' = gcTodo, livePruned' = livePruned, sweptUnreadable' = sweptUnreadable,
    markedUnreadable' = markedUnreadable, prunes' = prunes, aborts' = aborts,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    lockHolder' = lockHolder,
    keepProd, keepPush,
    lastAction' = { name: "gc expire write", arg: NONE },
  }
  // live_objects = closure(collect_roots) (strict: any unreadable source
  // aborts), then iter_object_hashes. The lenient mutant skips such sources.
  def readableSrcs: Set[str] = SOURCES.exclude(corrupt)
  def gcViewRoots: Set[int] =
    refRoots(readableSrcs).union(if (readableSrcs.contains("rlog")) logRoots else Set())
  def markAborts: bool = corrupt != Set() and not(BUG_LENIENT)
  action GcMark = all {
    gcPhase == "expired",
    gcPhase' = if (markAborts) "idle" else "sweep",
    aborts' = if (markAborts) aborts + 1 else aborts,
    lockHolder' = if (markAborts) gcRelease else lockHolder,
    gcLive' = closure(gcViewRoots),
    gcTodo' = if (markAborts) Set() else present,
    markedUnreadable' = corrupt != Set(),
    lastAction' = { name: if (markAborts) "gc abort (collect_roots)" else "gc mark", arg: NONE },
    gcNow' = gcNow, gcKept' = gcKept, gcDropAny' = gcDropAny,
    livePruned' = livePruned, sweptUnreadable' = sweptUnreadable,
    prunes' = prunes, expiredAny' = expiredAny,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    keepLog, keepProd, keepPush,
  }
  // run_gc loop body for one listed hash: keep if live, or if younger than the
  // grace window (mtime read now); else delete.
  def sweepDel(o: int): bool =
    present.contains(o) and not(gcLive.contains(o)) and age(gcNow, mtime.get(o)) >= GRACE
  action GcSweep(o: int): bool = all {
    gcPhase == "sweep",
    gcTodo.contains(o),
    gcTodo' = gcTodo.exclude(Set(o)),
    present' = if (sweepDel(o)) present.exclude(Set(o)) else present,
    prunes' = if (sweepDel(o)) prunes + 1 else prunes,
    // if-form: Apalache reads `x' := a \/ b` as `(x' := a) \/ b`
    livePruned' = if (sweepDel(o) and live.contains(o)) true else livePruned,
    sweptUnreadable' = if (sweepDel(o) and markedUnreadable) true else sweptUnreadable,
    lastAction' = { name: if (sweepDel(o)) "gc prune" else "gc keep", arg: o },
    gcPhase' = gcPhase, gcNow' = gcNow, gcKept' = gcKept, gcDropAny' = gcDropAny,
    gcLive' = gcLive, markedUnreadable' = markedUnreadable, aborts' = aborts,
    expiredAny' = expiredAny,
    clock' = clock, mtime' = mtime, refs' = refs, corrupt' = corrupt,
    lockHolder' = lockHolder,
    keepLog, keepProd, keepPush,
  }
  action GcDone = all {
    gcPhase == "sweep",
    gcTodo == Set(),
    gcPhase' = "idle", lockHolder' = gcRelease,
    gcNow' = gcNow, gcKept' = gcKept, gcDropAny' = gcDropAny, gcLive' = gcLive,
    gcTodo' = gcTodo, livePruned' = livePruned, sweptUnreadable' = sweptUnreadable,
    markedUnreadable' = markedUnreadable, prunes' = prunes, aborts' = aborts,
    expiredAny' = expiredAny,
    clock' = clock, keepStore, refs' = refs, corrupt' = corrupt,
    keepLog, keepProd, keepPush,
    lastAction' = { name: "gc done", arg: NONE },
  }

  action step = any {
    nondet d = oneOf(1.to(MAXT)) Tick(d),
    nondet s = oneOf(SOURCES) any { Corrupt(s), Repair(s) },
    nondet t = oneOf(PROD_TARGETS) ProdBegin(t),
    ProdRecord,
    ProdMove,
    PushWrite,
    PushPublish,
    PushAbort,
    GcLock,
    GcExpireRead,
    GcExpireWrite,
    GcMark,
    nondet o = oneOf(OBJS) GcSweep(o),
    GcDone,
  }

  // ---- invariants ----------------------------------------------------------------
  // SPEC-GC "No live object is ever pruned": gc never deletes an object that is
  // reachable from the true root set at the moment of deletion.
  val NoLivePruned = not(livePruned)
  // Observable form: every object reachable from a root is present (no ref or
  // recovery entry dangles). Also catches an object deleted while unreachable
  // that a concurrent writer then makes reachable (the §3.1 push race).
  val NoDangling = live.subseteq(present)
  // SPEC-GC "Fail-closed requirement": never prune against a partial root set.
  val UnreadableAborts = not(sweptUnreadable)
  // SPEC-GC "A superseded tip stays recoverable until the retention policy
  // expires it": each record still inside the policy (age <= RETAIN at the
  // current clock, or the newest ever appended) is in the log, fully present.
  val SupersededRetained = ghostRecs.forall(g =>
    (age(clock, g.ts) <= RETAIN or not(ghostRecs.exists(x => x.seq > g.seq)))
      implies (rlog.contains(g) and CLOS.get(g.obj).subseteq(present)))
  // SPEC-CONCURRENCY §3.2: gc's lock set contains the producer's worktree.lock,
  // so a producer mid-rewrite and an active gc run never coexist.
  val LockExclusion = not(prodPhase != "idle" and gcPhase != "idle")
  val Safety = NoLivePruned and NoDangling and UnreadableAborts
               and SupersededRetained and LockExclusion

  // ---- canaries: each MUST be violated (reachability witnesses) ---------------
  val CanaryNoPrune = prunes == 0
  val CanaryNoAbort = aborts == 0
  val CanaryNoExpire = not(expiredAny)
  val CanaryNoPrunedRecord = not(ghostRecs.exists(g => not(CLOS.get(g.obj).subseteq(present))))
  val CanaryNoPushPublished = refs.get("pushed") == NONE
  // gc deleted something in a run that overlapped an in-flight push
  val CanaryNoPruneDuringPush = not(pushPhase == "wrote" and prunes > 0)
}

// ---- conforming instances --------------------------------------------------
// Supported deployment: no push concurrent with gc (SPEC-CONCURRENCY §3.1).
module gc {
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*

  run closTableTest = init.expect(OBJS.forall(o => CLOS.get(o) == edgeClosure(Set(o))))
  // reset C1 -> C0 (records C1), amend C0 -> C1' (records C0); after RETAIN the
  // older entry expires (the newer is kept by keep-last) and gc prunes C1 and
  // the old orphan 5, keeping everything live.
  run resetExpirePruneTest =
    init
      .then(ProdBegin(2)).then(ProdRecord).then(ProdMove)
      .expect(refs.get("main") == 2 and rlog.size() == 1)
      .then(ProdBegin(4)).then(ProdRecord).then(ProdMove)
      .then(Tick(3))
      .then(GcLock).then(GcExpireRead).then(GcExpireWrite)
      .expect(rlog.map(e => e.obj) == Set(2))
      .then(GcMark)
      .then(GcSweep(0)).then(GcSweep(1)).then(GcSweep(2)).then(GcSweep(3))
      .then(GcSweep(4)).then(GcSweep(5)).then(GcDone)
      .expect(present == Set(0, 1, 2, 4) and prunes == 2 and Safety)
  // An unreadable tag makes collect_roots fail: gc aborts, nothing deleted.
  run unreadableAbortsTest =
    init.then(Corrupt("tag")).then(Tick(3))
      .then(GcLock).then(GcExpireRead).then(GcExpireWrite).then(GcMark)
      .expect(gcPhase == "idle" and lockHolder == "none" and aborts == 1
              and present == Set(0, 1, 2, 3, 5))
}
// `--grace-secs 0` in the supported deployment: the locks alone keep it safe.
module gcGrace0 {
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 0, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}
// Push may run concurrently with gc (outside the supported deployment).
module gcPushRaw {
  import gcCore(PUSH_MODE = "raw", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}
module gcPushRawFreshen {
  import gcCore(PUSH_MODE = "raw", FRESHEN = true, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*

  // Slow push: fresh objects written at t=0, published at t=2 >= GRACE; a gc
  // with now=2 prunes the not-yet-referenced tip in between.
  run slowPushLossTest =
    init.then(PushWrite).then(Tick(2))
      .then(GcLock).then(GcExpireRead).then(GcExpireWrite).then(GcMark)
      .then(GcSweep(6))
      .expect(not(present.contains(6)))
      .then(PushPublish)
      .expect(not(NoDangling) and NoLivePruned)
}
module gcPushFast {         // push publishes within GRACE; store as implemented
  import gcCore(PUSH_MODE = "fast", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*

  // Zero-duration push still loses data: object 5 is an old orphan, the push's
  // write of 5 is a dedup hit that keeps mtime 0, gc (now = 2) prunes it
  // between the push's object write and its ref publish.
  run fastPushDedupLossTest =
    init.then(Tick(2)).then(PushWrite)
      .then(GcLock).then(GcExpireRead).then(GcExpireWrite).then(GcMark)
      .then(GcSweep(5))
      .expect(not(present.contains(5)))
      .then(PushPublish)
      .expect(not(NoDangling) and NoLivePruned)
}
module gcPushFastFreshen {  // push publishes within GRACE, dedup refreshes mtime
  import gcCore(PUSH_MODE = "fast", FRESHEN = true, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}
module gcPushBounded {      // exact on-disk-mtime timing assumption
  import gcCore(PUSH_MODE = "bounded", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}

// ---- mutants (non-vacuity) -------------------------------------------------
module mutNoLock {          // violates SupersededRetained, LockExclusion
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = true,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}
module mutLenient {         // violates UnreadableAborts, NoLivePruned
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = true, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = false).*
}
module mutNoRecord {        // violates SupersededRetained
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = true, BUG_NO_KEEP_LAST = false).*
}
module mutNoKeepLast {      // violates SupersededRetained
  import gcCore(PUSH_MODE = "none", FRESHEN = false, GRACE = 2, BUG_NO_LOCK = false,
    BUG_LENIENT = false, BUG_NO_RECORD = false, BUG_NO_KEEP_LAST = true).*
}
