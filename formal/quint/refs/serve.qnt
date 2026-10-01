// -*- mode: Bluespec; -*-
// Server-era root locks and the served-name rule (verification toolchain / ref concurrency model,
// workstream quint-refs). Companion of refs.qnt, which keeps the ref CAS and
// lock-order model; the ref writes a server makes are refs.qnt's `file` ops.
//
// Module `serveLocks` models SPEC-CONCURRENCY §2 (lock inventory rows
// `serve.lock`) and §3.1 ("MKIT-11/#655 turned this from silent into
// detected"), as of this branch:
//   - every live server process on a root, `mkit serve` (ssh-frame) and
//     `mkit-server serve`, holds `serve.lock` SHARED for its whole lifetime;
//   - `mkit-server` also holds `server.lock` EXCLUSIVELY (one per root),
//     taken without waiting before `serve.lock` (mkit-server-native
//     `server::lock_root`: busy -> exit CONFIG_ERROR);
//   - a starting `mkit serve` tries `serve.lock` EXCLUSIVELY without waiting
//     and, only while it holds it, sweeps the temp files crashed uploads left
//     in `packs/` (`FsBlobStore::sweep_stale_uploads`, files at least
//     STALE_UPLOAD_AGE = 1 h old), then drops it and takes the shared lock;
//     busy -> skip the sweep (mkit-cli `serve::lock_and_sweep`);
//   - `worktree.lock` / `worktrees.lock` acquisition probes `serve.lock`
//     non-blocking-exclusive and warns (never refuses) when it is busy.
// Safety modelled: server.lock exclusion, serve.lock reader/writer
// exclusion, the sweep never deleting a live upload's temp file (the startup
// sweep vs a concurrent upload), and the probe never missing a live server.
//
// Abstractions (explicit):
//   - Time is abstracted to "fresh" / "stale" (older than STALE_UPLOAD_AGE).
//     A live server upload is a streaming upload that can STALL, so its temp
//     file may go stale while live; only the lock protects it. A
//     `FileTransport` writer (`mkit push mkit+file://`, no lock at all)
//     writes its temp file in one go (`write_atomic`), so it is assumed never
//     to be stale while live: that is the age-bound assumption the code
//     comment in `lock_and_sweep` states; the `ftSlow` instance drops it and
//     shows the sweep would then delete a live upload (documented assumption,
//     not a bug; see README).
//   - The probe's momentary exclusive hold is one atomic step. Its only
//     other effect (a starting `mkit serve` then skips its sweep, or a
//     starting server's shared acquire waits) is liveness, not safety.
//   - Lock waits block forever (the 5 s repo_lock timeout is abstracted).
//   - Stopping and crashing are one action (the kernel drops every lock).
//   - `mkit-server`'s own S3 spool sweep (under server.lock) is not
//     modelled: only mkit-server uses that directory.
//
// Module `servedNames` models SPEC-REFS v3 §2 "Served names" and the §3
// 512-byte bound as far as they affect safety: a server refuses a name
// outside `refs/` (or over 512 bytes) on ReadRef / UpdateRef / both names of
// AdvanceRefs BEFORE touching storage, with an explicit error, never as
// absent, and a refused request writes nothing (AdvanceRefs writes packmap
// then head, so a late check of the head would leave a partial write). A
// listing skips stored refs outside `refs/` or over the bound. Which byte
// strings pass the §3 grammar is left to unit tests and conformance vectors
// (`mkit_core::refs` tests, `mkit-server` `pipeline/tests.rs`,
// `ssh/tests.rs`); names here are abstract classes.
//
// Checks: ./check.sh (README.md lists each command and its expected outcome).
module serveLocks {
  type Srv = str

  // Mutation switches (non-vacuity only) and one assumption switch.
  type SFaults = {
    sweepUnlocked: bool,     // `mkit serve` sweeps without the exclusive serve.lock
    sweepUnderShared: bool,  // ... sweeps after taking serve.lock SHARED
    serverSkipsServe: bool,  // `mkit-server` holds server.lock but not serve.lock
    serverLockShared: bool,  // server.lock not exclusive
    ftSlow: bool,            // ASSUMPTION OFF: a lockless FileTransport upload can outlive the age bound
  }

  const SRVS: Set[Srv]
  const LOCALS: Set[str]
  const FAULTS: SFaults

  pure val FREE: str = ""
  pure val FT: str = "ft"  // the lockless FileTransport writer (mkit push mkit+file://)
  pure val SFAULTS_NONE: SFaults = {
    sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false,
    serverLockShared: false, ftSlow: false,
  }

  // --------------------------------------------------------------- state
  var kind: Srv -> str        // "serve" (mkit serve) | "server" (mkit-server) | "" while down
  var spc: Srv -> str         // down | sweep | drop | wantShared | up | upSweep
  var serveEx: str            // exclusive holder of serve.lock, FREE if none
  var serveSh: Set[Srv]       // shared holders of serve.lock
  var serverLock: Set[Srv]    // holders of server.lock (at most one unless mutated)
  var upload: str -> str      // per uploader (SRVS + FT): none | fresh | stale | lost
  var orphans: Set[str]       // ages of temp files crashed uploads left: fresh | stale
  var lpc: str -> str         // local worktree command: idle | critical
  var warned: str -> bool     // its serve.lock probe found the lock busy
  // ghosts
  var sweptLive: bool         // a sweep deleted the temp file of a live upload
  var sweptOrphan: bool       // a sweep deleted a crashed upload's temp file (canary)
  var missedDetection: bool   // a probe found serve.lock free while a server was up
  var lastAction: { name: str, who: str, outcome: str }
  var faults: SFaults         // constant after init (FAULTS; tests pin their own)

  pure def uploaders(ss: Set[Srv]): Set[str] = ss.union(Set(FT))

  // Deterministic initial state (tests and trace replay).
  action initFixed(f: SFaults, o: Set[str]): bool = all {
    kind' = SRVS.mapBy(_ => ""), spc' = SRVS.mapBy(_ => "down"),
    serveEx' = FREE, serveSh' = Set(), serverLock' = Set(),
    upload' = uploaders(SRVS).mapBy(_ => "none"), orphans' = o,
    lpc' = LOCALS.mapBy(_ => "idle"), warned' = LOCALS.mapBy(_ => false),
    sweptLive' = false, sweptOrphan' = false, missedDetection' = false,
    lastAction' = { name: "init", who: "", outcome: "" },
    faults' = f,
  }

  action init = {
   nondet o = Set(Set(), Set("fresh"), Set("stale"), Set("fresh", "stale")).oneOf()
   all {
    faults' = FAULTS,
    kind' = SRVS.mapBy(_ => ""),
    spc' = SRVS.mapBy(_ => "down"),
    serveEx' = FREE,
    serveSh' = Set(),
    serverLock' = Set(),
    upload' = uploaders(SRVS).mapBy(_ => "none"),
    orphans' = o,
    lpc' = LOCALS.mapBy(_ => "idle"),
    warned' = LOCALS.mapBy(_ => false),
    sweptLive' = false,
    sweptOrphan' = false,
    missedDetection' = false,
    lastAction' = { name: "init", who: "", outcome: "" },
   }
  }

  action keepServers = all {
    faults' = faults,
    kind' = kind, spc' = spc, serveEx' = serveEx, serveSh' = serveSh, serverLock' = serverLock,
  }
  action keepFiles = all {
    upload' = upload, orphans' = orphans, sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
  }
  action keepLocals = all { lpc' = lpc, warned' = warned, missedDetection' = missedDetection }

  def serveLockFree: bool = serveEx == FREE and serveSh == Set()

  // `mkit serve` start: repo_lock::acquire(serve.lock, Duration::ZERO), i.e.
  // a non-blocking exclusive try. Held -> sweep; busy -> skip to shared.
  action startServe(s: Srv): bool = {
    val got = serveLockFree
    all {
      spc.get(s) == "down",
      kind' = kind.set(s, "serve"),
      serveEx' = if (got and not(faults.sweepUnlocked) and not(faults.sweepUnderShared)) s else serveEx,
      spc' = spc.set(s,
        if (faults.sweepUnlocked) "sweep"
        else if (faults.sweepUnderShared) "wantShared"
        else if (got) "sweep" else "wantShared"),
      serveSh' = serveSh, serverLock' = serverLock, faults' = faults,
      keepFiles, keepLocals,
      lastAction' = { name: "startServe", who: s,
                      outcome: if (got or faults.sweepUnlocked) "sweep" else "skipSweep" },
    }
  }

  // FsBlobStore::sweep_stale_uploads: remove every stale upload temp file.
  // A live upload whose temp file is stale (stalled) loses it.
  action sweep(s: Srv): bool = {
   val liveStale = uploaders(SRVS).exists(o => upload.get(o) == "stale")
   val staleOrphan = orphans.contains("stale")
   all {
    spc.get(s) == "sweep" or spc.get(s) == "upSweep",
    sweptLive' = (sweptLive or liveStale),
    sweptOrphan' = (sweptOrphan or staleOrphan),
    upload' = uploaders(SRVS).mapBy(o => if (upload.get(o) == "stale") "lost" else upload.get(o)),
    orphans' = orphans.exclude(Set("stale")),
    spc' = spc.set(s, if (spc.get(s) == "upSweep") "up" else "drop"),
    kind' = kind, serveEx' = serveEx, serveSh' = serveSh, serverLock' = serverLock, faults' = faults,
    keepLocals,
    lastAction' = { name: "sweep", who: s, outcome: "" },
   }
  }

  // drop(exclusive): release the exclusive hold before taking the shared one.
  action drop(s: Srv): bool = all {
    spc.get(s) == "drop",
    serveEx' = if (serveEx == s) FREE else serveEx,
    spc' = spc.set(s, "wantShared"),
    kind' = kind, serveSh' = serveSh, serverLock' = serverLock, faults' = faults,
    keepFiles, keepLocals,
    lastAction' = { name: "drop", who: s, outcome: "" },
  }

  // `mkit-server serve` start: server.lock exclusively without waiting
  // (busy -> the process exits; no state change, so not a step here).
  action startServer(s: Srv): bool = all {
    spc.get(s) == "down",
    faults.serverLockShared or serverLock == Set(),
    kind' = kind.set(s, "server"),
    serverLock' = serverLock.union(Set(s)),
    spc' = spc.set(s, if (faults.serverSkipsServe) "up" else "wantShared"),
    serveEx' = serveEx, serveSh' = serveSh, faults' = faults,
    keepFiles, keepLocals,
    lastAction' = { name: "startServer", who: s, outcome: "" },
  }

  // repo_lock::acquire_shared(serve.lock): blocks while an exclusive holder
  // (a sweeping `mkit serve`) is in.
  action takeShared(s: Srv): bool = all {
    spc.get(s) == "wantShared",
    serveEx == FREE,
    serveSh' = serveSh.union(Set(s)),
    spc' = spc.set(s,
      if (faults.sweepUnderShared and kind.get(s) == "serve") "upSweep" else "up"),
    kind' = kind, serveEx' = serveEx, serverLock' = serverLock, faults' = faults,
    keepFiles, keepLocals,
    lastAction' = { name: "takeShared", who: s, outcome: "" },
  }

  // Exit or crash, at any phase: the kernel drops every lock; an upload in
  // flight leaves its temp file behind as an orphan.
  action stop(s: Srv): bool = {
    val u = upload.get(s)
    all {
      spc.get(s) != "down",
      spc' = spc.set(s, "down"),
      kind' = kind.set(s, ""),
      serveEx' = if (serveEx == s) FREE else serveEx,
      serveSh' = serveSh.exclude(Set(s)),
      serverLock' = serverLock.exclude(Set(s)),
      upload' = upload.set(s, "none"),
      orphans' = if (u == "fresh" or u == "stale") orphans.union(Set(u)) else orphans,
      sweptLive' = sweptLive, sweptOrphan' = sweptOrphan, faults' = faults,
      keepLocals,
      lastAction' = { name: "stop", who: s, outcome: u },
    }
  }

  // A pack upload starts writing its temp file: by an up server (streaming,
  // ssh-frame or HTTP) or by a lockless FileTransport writer.
  action beginUpload(o: str): bool = all {
    upload.get(o) == "none",
    // (an `if`, not `or`: TLC explores each disjunct of an action, and spc has no FT entry)
    if (o == FT) true else (spc.get(o) == "up" or spc.get(o) == "upSweep"),
    upload' = upload.set(o, "fresh"),
    orphans' = orphans, sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
    keepServers, keepLocals,
    lastAction' = { name: "beginUpload", who: o, outcome: "" },
  }

  // The upload renames its temp file over the blob (or finds it deleted).
  action finishUpload(o: str): bool = all {
    upload.get(o) != "none",
    upload' = upload.set(o, "none"),
    orphans' = orphans, sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
    keepServers, keepLocals,
    lastAction' = { name: "finishUpload", who: o, outcome: upload.get(o) },
  }

  // The FileTransport writer's process crashes mid-write.
  action crashFT = {
    val u = upload.get(FT)
    all {
      u == "fresh" or u == "stale",
      upload' = upload.set(FT, "none"),
      orphans' = orphans.union(Set(u)),
      sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
      keepServers, keepLocals,
      lastAction' = { name: "crashFT", who: FT, outcome: u },
    }
  }

  // Time passes past STALE_UPLOAD_AGE for a temp file that is not being
  // rewritten: an orphan, or a stalled server upload. A FileTransport write
  // is one `write_atomic` call, never stale while live (unless ftSlow).
  action age(o: str): bool = all {
    upload.get(o) == "fresh",
    o != FT or faults.ftSlow,
    upload' = upload.set(o, "stale"),
    orphans' = orphans, sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
    keepServers, keepLocals,
    lastAction' = { name: "age", who: o, outcome: "" },
  }
  action ageOrphan = all {
    orphans.contains("fresh"),
    orphans' = orphans.exclude(Set("fresh")).union(Set("stale")),
    upload' = upload, sweptLive' = sweptLive, sweptOrphan' = sweptOrphan,
    keepServers, keepLocals,
    lastAction' = { name: "ageOrphan", who: "", outcome: "" },
  }

  // A local worktree command takes worktree.lock / worktrees.lock, then
  // probes serve.lock non-blocking-exclusive (warn_if_served), then runs its
  // critical section. It proceeds either way.
  action localBegin(l: str): bool = {
    val busy = not(serveLockFree)
    val anyUp = SRVS.exists(s => spc.get(s) == "up" or spc.get(s) == "upSweep")
    all {
      lpc.get(l) == "idle",
      lpc' = lpc.set(l, "critical"),
      warned' = warned.set(l, busy),
      missedDetection' = (missedDetection or (not(busy) and anyUp)),
      keepServers, keepFiles,
      lastAction' = { name: "localBegin", who: l, outcome: if (busy) "warned" else "silent" },
    }
  }
  action localEnd(l: str): bool = all {
    lpc.get(l) == "critical",
    lpc' = lpc.set(l, "idle"),
    warned' = warned.set(l, false),
    missedDetection' = missedDetection,
    keepServers, keepFiles,
    lastAction' = { name: "localEnd", who: l, outcome: "" },
  }

  action step = {
    nondet s = SRVS.oneOf()
    nondet o = uploaders(SRVS).oneOf()
    nondet l = LOCALS.oneOf()
    any {
      startServe(s), startServer(s), sweep(s), drop(s), takeShared(s), stop(s),
      beginUpload(o), finishUpload(o), crashFT, age(o), ageOrphan,
      localBegin(l), localEnd(l),
    }
  }

  // ---------------------------------------------------------- invariants
  def isUp(s: Srv): bool = spc.get(s) == "up" or spc.get(s) == "upSweep"

  // Kernel reader/writer lock: an exclusive holder excludes every shared one.
  val ServeLockRW: bool = serveEx != FREE implies serveSh == Set()
  // SPEC-CONCURRENCY §3.1: "one `mkit-server` serves a root at a time".
  val OneMkitServer: bool =
    SRVS.filter(s => kind.get(s) == "server" and spc.get(s) != "down").size() <= 1
  // §2/§3.1: every live server holds serve.lock shared for its whole life.
  val UpServersHoldServeShared: bool = SRVS.forall(s => isUp(s) implies serveSh.contains(s))
  // §3.1: the sweep runs only while its process holds serve.lock
  // exclusively, "so no other server is up".
  val SweepAlone: bool = SRVS.forall(s => spc.get(s) == "sweep" or spc.get(s) == "upSweep" implies and {
    serveEx == s,
    SRVS.forall(t => t != s implies not(isUp(t))),
  })
  // The startup sweep never deletes the temp file of an upload in flight.
  val NoLiveUploadSwept: bool = not(sweptLive)
  // §3.1 detection: while any server is up, a worktree probe finds serve.lock busy.
  val NoMissedDetection: bool = not(missedDetection)

  val Safety: bool = and {
    ServeLockRW, OneMkitServer, UpServersHoldServeShared, SweepAlone,
    NoLiveUploadSwept, NoMissedDetection,
  }

  // ------------------------------------------ canaries (expected FALSE)
  // The sweep does remove a crashed upload's temp file.
  val CanaryNoOrphanSwept: bool = not(sweptOrphan)
  // A starting `mkit serve` finds the lock busy and skips its sweep.
  val CanaryNoSkippedSweep: bool =
    not(lastAction.name == "startServe" and lastAction.outcome == "skipSweep")
  // `mkit serve` and `mkit-server` share one root at once.
  val CanaryNoServeAndServer: bool =
    not(SRVS.exists(a => SRVS.exists(b =>
      isUp(a) and isUp(b) and kind.get(a) == "serve" and kind.get(b) == "server")))
  // A stalled server upload (stale temp file) exists while a `mkit serve`
  // starts: the case only the lock protects.
  val CanaryNoStartDuringStalledUpload: bool =
    not(lastAction.name == "startServe" and SRVS.exists(t => upload.get(t) == "stale"))
  // WITNESS of the documented one-directional gap (§3.1 "Residual gaps"): a
  // local command whose probe found no server is still in its critical
  // section when a server comes up. Expected reachable.
  val WitnessUndetectedLateServer: bool =
    not(LOCALS.exists(l => lpc.get(l) == "critical" and not(warned.get(l)))
        and SRVS.exists(s => isUp(s)))
}

// ======================================================================
module servedNames {
  // Abstract name classes (SPEC-REFS v3 §2, §3):
  //   "A" refs/heads/a           served
  //   "P" refs/mkit/packmap/a    served (pushed with branch a)
  //   "M" main                   grammar-valid, outside refs/ (pre-0.5 `mkit serve`
  //                              stored it as <root>/main)
  //   "L" refs/heads/<513 bytes> under refs/, over the 512-byte bound
  //   "X" grammar-invalid        refused as §3 says
  type SNFaults = {
    checkAfterRead: bool,   // ReadRef consults storage before the name check
    headCheckedLate: bool,  // AdvanceRefs checks the head name only after writing the packmap
    listNoSkip: bool,       // listing returns stored refs outside refs/ or over the bound
  }
  const FAULTS: SNFaults

  pure val NAMES: Set[str] = Set("A", "P", "M", "L", "X")
  pure val SERVED: Set[str] = Set("A", "P")
  pure val ABSENT: int = 0
  pure val SNFAULTS_NONE: SNFaults = { checkAfterRead: false, headCheckedLate: false, listNoSkip: false }

  // The explicit refusal a name draws (pipeline `check_ref_name`,
  // ssh `check_name`): too long first, then grammar, then outside refs/.
  pure def refusal(n: str): str =
    if (n == "L") "tooLong" else if (n == "X") "invalid" else if (n == "M") "outsideRefs" else ""

  // Request: verb ReadRef | UpdateRef | AdvanceRefs | ListRefs; for
  // AdvanceRefs n1 = packmap, n2 = head (packmap written first).
  // ListRefs prefix: "refs" | "none" (the empty prefix) | "main".
  type Req = { verb: str, n1: str, n2: str, value: int, prefix: str }

  var store: str -> int         // on-disk / stored refs, legacy files included
  var req: Req
  var phase: str                // idle | check | storage1 | storage2 | reply
  var wrote: Set[str]           // names this request wrote
  var reply: str                // "" | ok | absent | value | tooLong | invalid | outsideRefs
  var listed: Set[str]
  // ghosts
  var touchedRefused: bool      // storage step while the request holds a refused name
  var badReply: bool            // a refusable name answered other than by its refusal
  var refusedButWrote: bool     // an explicit refusal after this request wrote something
  var badListing: bool          // a listing returned a name the server does not serve
  var faults: SNFaults          // constant after init

  pure val NOREQ: Req = { verb: "", n1: "A", n2: "A", value: 0, prefix: "refs" }

  // Deterministic initial state: A and P hold 1; legacy M / L files per m, l.
  action initFixed(f: SNFaults, m: int, l: int): bool = all {
    faults' = f,
    store' = Map("A" -> 1, "P" -> 1, "M" -> m, "L" -> l, "X" -> 0),
    req' = NOREQ, phase' = "idle", wrote' = Set(), reply' = "", listed' = Set(),
    touchedRefused' = false, badReply' = false, refusedButWrote' = false, badListing' = false,
  }

  // Receive a fixed request (tests; `receive` below is the nondeterministic one).
  action recv(verb: str, n1: str, n2: str): bool = all {
    phase == "idle",
    req' = { verb: verb, n1: n1, n2: n2, value: 2, prefix: "refs" },
    phase' = if (verb == "ReadRef" and faults.checkAfterRead) "storage1"
             else if (verb == "ListRefs") "storage1" else "check",
    wrote' = Set(), reply' = "", listed' = Set(), store' = store, keepGhosts,
  }

  action init = {
   nondet a = Set(0, 1).oneOf()
   nondet p = Set(0, 1).oneOf()
   nondet m = Set(0, 1).oneOf()   // a legacy <root>/main file may exist
   nondet l = Set(0, 1).oneOf()   // a legacy over-long ref may exist
   all {
    faults' = FAULTS,
    store' = Map("A" -> a, "P" -> p, "M" -> m, "L" -> l, "X" -> 0),
    req' = NOREQ, phase' = "idle", wrote' = Set(), reply' = "", listed' = Set(),
    touchedRefused' = false, badReply' = false, refusedButWrote' = false, badListing' = false,
   }
  }

  def reqNames(r: Req): Set[str] =
    if (r.verb == "AdvanceRefs") Set(r.n1, r.n2)
    else if (r.verb == "ListRefs") Set()
    else Set(r.n1)
  def refused(r: Req): bool = reqNames(r).exists(n => refusal(n) != "")
  // The refusal of the first refused name in check order (AdvanceRefs
  // checks head, then packmap: pipeline `advance_refs`).
  def firstRefusal(r: Req): str =
    if (r.verb == "AdvanceRefs")
      (if (refusal(r.n2) != "") refusal(r.n2) else refusal(r.n1))
    else refusal(r.n1)

  action keepGhosts = all {
    faults' = faults,
    touchedRefused' = touchedRefused, badReply' = badReply,
    refusedButWrote' = refusedButWrote, badListing' = badListing,
  }

  action receive = {
    nondet verb = Set("ReadRef", "UpdateRef", "AdvanceRefs", "ListRefs").oneOf()
    nondet n1 = NAMES.oneOf()
    nondet n2 = NAMES.oneOf()
    nondet v = Set(1, 2).oneOf()
    nondet pre = Set("refs", "none", "main").oneOf()
    all {
      phase == "idle",
      req' = { verb: verb, n1: n1, n2: n2, value: v, prefix: pre },
      phase' = if (verb == "ReadRef" and faults.checkAfterRead) "storage1"
               else if (verb == "ListRefs") "storage1" else "check",
      wrote' = Set(), reply' = "", listed' = Set(),
      store' = store, keepGhosts,
    }
  }

  // The name check. Under headCheckedLate the head (n2) of AdvanceRefs is
  // not checked here.
  action check = {
    val names = if (req.verb == "AdvanceRefs" and faults.headCheckedLate) Set(req.n1) else reqNames(req)
    val r = names.exists(n => refusal(n) != "")
    all {
      phase == "check",
      phase' = if (r) "reply" else "storage1",
      reply' = if (r) (if (req.verb == "AdvanceRefs" and not(faults.headCheckedLate)) firstRefusal(req)
                        else refusal(req.n1)) else "",
      refusedButWrote' = (refusedButWrote or (r and wrote != Set())),
      store' = store, req' = req, wrote' = wrote, listed' = listed,
      touchedRefused' = touchedRefused, badReply' = badReply, badListing' = badListing, faults' = faults,
    }
  }

  // First storage step: read (ReadRef), write (UpdateRef, Any condition
  // stands for every condition: refusal does not depend on it), the packmap
  // write of AdvanceRefs, or the listing scan.
  action storage1 = {
    val lateRefusal = req.verb == "ReadRef" and faults.checkAfterRead and refused(req)
    val listing =
      if (req.prefix != "refs" and req.prefix != "none") Set()  // a prefix outside refs/ lists nothing
      else NAMES.filter(n => store.get(n) != ABSENT and
                             (faults.listNoSkip or SERVED.contains(n)))
    all {
      phase == "storage1",
      touchedRefused' = (touchedRefused or refused(req)),
      store' = if (req.verb == "UpdateRef" or req.verb == "AdvanceRefs") store.set(req.n1, req.value) else store,
      wrote' = if (req.verb == "UpdateRef" or req.verb == "AdvanceRefs") Set(req.n1) else Set(),
      listed' = if (req.verb == "ListRefs") listing else Set(),
      badListing' = (badListing or (req.verb == "ListRefs" and listing.exists(n => not(SERVED.contains(n))))),
      // checkAfterRead: the legacy behaviour answers from storage (the
      // pre-0.5 file, or "absent").
      reply' = if (req.verb == "ReadRef") (if (store.get(req.n1) == ABSENT) "absent" else "value")
               else if (req.verb == "AdvanceRefs") "" else "ok",
      badReply' = (badReply or lateRefusal),
      phase' = if (req.verb == "AdvanceRefs") "storage2" else "reply",
      req' = req, refusedButWrote' = refusedButWrote, faults' = faults,
    }
  }

  // AdvanceRefs second write (the head), after its (possibly late) check.
  action storage2 = {
    val late = faults.headCheckedLate and refusal(req.n2) != ""
    all {
      phase == "storage2",
      store' = if (late) store else store.set(req.n2, req.value),
      wrote' = if (late) wrote else wrote.union(Set(req.n2)),
      reply' = if (late) refusal(req.n2) else "ok",
      refusedButWrote' = (refusedButWrote or late),
      touchedRefused' = (touchedRefused or refused(req)),
      phase' = "reply",
      req' = req, listed' = listed, badReply' = badReply, badListing' = badListing, faults' = faults,
    }
  }

  action answer = all {
    phase == "reply",
    phase' = "idle",
    badReply' = (badReply or (refused(req) and reply != firstRefusal(req)
                              and not(faults.headCheckedLate))),
    store' = store, req' = req, wrote' = wrote, reply' = reply, listed' = listed,
    touchedRefused' = touchedRefused, refusedButWrote' = refusedButWrote, badListing' = badListing,
    faults' = faults,
  }

  action step = any { receive, check, storage1, storage2, answer }

  // SPEC-REFS §2: refuse "before touching storage".
  val RefuseBeforeStorage: bool = not(touchedRefused)
  // §2/§3: the explicit error (outsideRefs / tooLong / invalid), "MUST NOT
  // answer such a name as absent".
  val ExplicitRefusal: bool = not(badReply)
  // A refused request leaves storage unchanged (no partial AdvanceRefs).
  val RefusedWritesNothing: bool = not(refusedButWrote)
  // §2 / §3: a listing serves only refs/ names within the bound, and skips
  // (does not fail on) stored ones that are not.
  val ListingServedOnly: bool = not(badListing)
  val Safety: bool = and { RefuseBeforeStorage, ExplicitRefusal, RefusedWritesNothing, ListingServedOnly }

  // Canaries (expected FALSE): the interesting cases are reached.
  val CanaryNoOutsideRefusal: bool = not(phase == "reply" and reply == "outsideRefs" and store.get("M") != ABSENT)
  val CanaryNoLongRefusal: bool = not(phase == "reply" and reply == "tooLong" and req.verb == "AdvanceRefs")
  val CanaryNoLegacySkipped: bool =
    not(phase == "reply" and req.verb == "ListRefs" and store.get("L") != ABSENT and store.get("M") != ABSENT
        and listed.contains("A"))
  val CanaryNoAdvance: bool = not(phase == "reply" and req.verb == "AdvanceRefs" and reply == "ok")
}

// ------------------------------------------------------------ instances
// SFaults literal: { sweepUnlocked, sweepUnderShared, serverSkipsServe, serverLockShared, ftSlow }.
module serve2 {       // 2 server slots (each may start as either binary), 1 local command
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false, serverLockShared: false, ftSlow: false }).*
}
module serve3 {       // 3 server slots (quint run only)
  import serveLocks(SRVS = Set("s1", "s2", "s3"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false, serverLockShared: false, ftSlow: false }).*
}
module serve2_sweepUnlocked {     // SweepAlone, NoLiveUploadSwept
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: true, sweepUnderShared: false, serverSkipsServe: false, serverLockShared: false, ftSlow: false }).*
}
module serve2_sweepUnderShared {  // SweepAlone, NoLiveUploadSwept
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: true, serverSkipsServe: false, serverLockShared: false, ftSlow: false }).*
}
module serve2_serverSkipsServe {  // UpServersHoldServeShared, NoLiveUploadSwept, NoMissedDetection
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: true, serverLockShared: false, ftSlow: false }).*
}
module serve2_serverLockShared {  // OneMkitServer
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false, serverLockShared: true, ftSlow: false }).*
}
module serve2_ftSlow {            // ASSUMPTION WITNESS: NoLiveUploadSwept (lockless FileTransport)
  import serveLocks(SRVS = Set("s1", "s2"), LOCALS = Set("w"),
    FAULTS = { sweepUnlocked: false, sweepUnderShared: false, serverSkipsServe: false, serverLockShared: false, ftSlow: true }).*
}
// SNFaults literal: { checkAfterRead, headCheckedLate, listNoSkip }.
module served {
  import servedNames(FAULTS = { checkAfterRead: false, headCheckedLate: false, listNoSkip: false }).*
}
module served_checkAfterRead {    // RefuseBeforeStorage, ExplicitRefusal
  import servedNames(FAULTS = { checkAfterRead: true, headCheckedLate: false, listNoSkip: false }).*
}
module served_headCheckedLate {   // RefuseBeforeStorage, RefusedWritesNothing
  import servedNames(FAULTS = { checkAfterRead: false, headCheckedLate: true, listNoSkip: false }).*
}
module served_listNoSkip {        // ListingServedOnly
  import servedNames(FAULTS = { checkAfterRead: false, headCheckedLate: false, listNoSkip: true }).*
}
