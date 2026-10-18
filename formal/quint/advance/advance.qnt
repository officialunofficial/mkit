// -*- mode: Bluespec; -*-
// advance_refs: delta-transfer safety, guarded force pushes and bounded retries.
//
// What is modelled:
//   - Non-force pushes plan against the remote head, append a delta pack or
//     re-baseline when atomic advance is supported, and use the existing
//     packmap CAS loop and head-conflict disambiguation.
//   - Force pushes on atomic transports first capture a strong packmap read,
//     then read the head and plan. These are separate actions, allowing a
//     concurrent reset between the reads. Head-only writes use a same-value
//     packmap Match in an atomic advance. Appends reuse a plan only while the
//     current chain extends the captured chain; otherwise they re-plan.
//   - A plan that depends on the observed head also uses Match(observed head),
//     alongside the required packmap guard. This covers identical-root ABA:
//     another pusher can restore an earlier content-addressed packmap root.
//     Every append pack here adversarially requires every ancestor of its
//     planning head as a delta base, so every atomic force plan uses this
//     head guard. Self-contained force packs may retain Any in the client;
//     the model conservatively chooses the base-dependent case instead.
//   - HTTP's atomic endpoint encodes a force head condition as Match of the
//     head read during planning. It never uses the ordered force fallback.
//   - Re-plans and packmap CAS attempts share ATTEMPTS. The transport retry
//     ladder re-issues the identical guarded request up to LADDER times.
//     Lost responses, crashes and replay-ledger responses are explicit.
//   - Ordered transports retain their existing packmap-then-head behavior.
//
// Abstraction:
//   - Commits 0..6 have a fixed DAG: 1 and 2 descend from 0; 3 from 1; 4
//     from 2; 5 from 3; 6 from 4. Objects are commits and closure is ancestry.
//   - Pack 0 is the initial self-contained closure. Non-force pack i belongs
//     to pusher i. A force plan's immutable pack id includes its planning
//     head, so a re-plan cannot alter an already published pack's contents.
//   - The packmap is an oldest-first list of pack ids; reconstruction fails
//     if a pack's delta bases are absent. A reset to the initial closure can
//     restore the identical root [0], explicitly modelling root ABA.
//   - Uploads are content-addressed and available; pack GC is modelled in
//     formal/quint/gc. Each pusher runs one logical push with a distinct tip.
//   - Non-force head and packmap-probe reads stay combined, as before. Force
//     reads are separate because their relationship is part of the proof.
//   - A request lost before server processing only consumes ladder budget;
//     lost-response steps already cover this. A dead pusher stops its own
//     requests, also modelling a local writer or server crash. Replay-ledger
//     expiry is outside this model.
//
// Invariants (./check.sh, README.md):
//   DeltaTransfer   : if head resolves to T, the packmap reconstructs
//                     closure(T) (protocol.rs `advance_refs` doc;
//                     SPEC-TRANSPORT-CONNECT §4).
//   SuccessSound    : a push reported as success had its tip on the head
//                     after it started.
//   ConflictHonest  : a push reported NonFastForward never wrote the head, or
//                     its write was overwritten since (SPEC-TRANSPORT §7: the
//                     read_ref disambiguation).
//   NoLostUpdate    : every head write with Match(e) replaced exactly e
//                     (concurrent pushers never lose an update, CAS level).
//   NoLostSuccess   : with fast-forward pushers only, a push reported as
//                     success stays in closure(head) (user level).
//   Progress        : NoStuckPusher (a pusher mid-push always has a step) and
//                     BoundedRetries (loop and ladder counters stay in range).
//   Termination     : <>(every pusher done or dead) under weak fairness of
//                     `step`; a TLC temporal property built by check.sh
//                     (`live`), on the two-pusher instances.
module advance {
  // ---------------------------------------------------------------- types
  // SPEC-REFS §5 conditions a push can put on the head, as an int so the
  // instances below can name them: -1 = Any (force push), e >= 0 = Match(e)
  // (fast-forward push / --force-with-lease). The packmap condition is always
  // Match(prior) here: the seed push created the packmap.
  type Cond = int

  type Cfg = { tip: int, cond: Cond }

  type Faults = {
    oldConflict: bool,   // pre-reconciliation client: HeadConflict / RefConflict => NonFastForward, no read_ref
    trustConflict: bool, // HeadConflict / RefConflict => success without read_ref
    noGate: bool,        // pre-#521: re-baseline ignores supports_atomic_advance
    gateNoAny: bool,     // old HTTP force path: ordered fallback and unsafe reset
    splitCas: bool,      // server head CAS as read-then-write without a lock
    headFirst: bool,     // ordered advance writes the head BEFORE the packmap
    noTimeout: bool,     // a server crash mid-request never surfaces to the client
    noLadderBound: bool, // the retry ladder re-issues forever (no attempt limit)
  }

  // pc: idle | planForce | loop | advSrv | advSrv2 | updSrv | updSrv2 | resp | readHead
  //     | done | dead | hung
  //   advSrv  : advance_refs request at the server, not yet applied
  //   advSrv2 : ordered path, first write done, second pending
  //   updSrv  : update_ref (commit_head) at the server
  //   updSrv2 : splitCas mutant only, value read, write pending
  //   resp    : response in flight (resp == "lost" after a server crash)
  //   hung    : noTimeout mutant only
  type P = {
    pc: str,
    base: int,          // remote head R read at push start
    reset: bool,        // this push re-baselines (frozen before the loop)
    node: List[int],    // packmap value being written
    pmExp: List[int],   // packmap Match(prior)
    plannedPm: List[int], // strong packmap read captured before the force plan
    attempts: int,      // advance_packmap loop iterations used
    ladder: int,        // re-issues left in the current call's ladder
    call: str,          // "adv" | "upd"
    resp: str,          // Committed | PackmapConflict | HeadConflict | ok | conflict | lost
    report: str,        // "" | success | nff | contended | error
    srvRead: int,       // splitCas only
  }

  type Action = { name: str, p: int, what: str }

  // ------------------------------------------------------------ constants
  const PUSHERS: int -> Cfg     // pusher id (>= 1) -> tip and head condition
  const MODE: str               // "atomic" | "ordered"
  const LEDGER: bool            // auth v2 replay ledger (atomic stores only)
  const ANY_FALLBACK: bool      // HTTP: encode force head as Match(observed head)
  const INIT_HEAD: int
  const THRESH: int             // re-baseline when chain depth + 1 > THRESH
  const ATTEMPTS: int           // PACKMAP_CAS_ATTEMPTS (code: 8)
  const LADDER: int             // re-issues after the first attempt (code: 4)
  const FAULTS: Faults

  pure val NO_FAULTS: Faults = {
    oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false,
    splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false,
  }

  // Commit DAG: closure(c) = c and its ancestors.
  pure val CLOS: int -> Set[int] = Map(
    0 -> Set(0),
    1 -> Set(0, 1),
    2 -> Set(0, 2),
    3 -> Set(0, 1, 3),
    4 -> Set(0, 2, 4),
    5 -> Set(0, 1, 3, 5),
    6 -> Set(0, 2, 4, 6),
  )

  pure val ANY: Cond = -1
  pure def holds(c: Cond, h: int): bool = c == ANY or c == h

  pure def inList(l: List[int], x: int): bool = l.foldl(false, (acc, y) => acc or y == x)

  val PIDS: Set[int] = PUSHERS.keys()
  def tipOf(i: int): int = PUSHERS.get(i).tip
  def condOf(i: int): Cond = PUSHERS.get(i).cond

  // ------------------------------------------------------------------ state
  var hd: int                     // the head ref refs/heads/<b>
  var pm: List[int]
  var ps: int -> P
  var stored: int -> str          // replay ledger: stored result of pusher's current call
  var landed: Set[int]            // head held tip_i at some point after i started
  var wrote: Set[int]             // i's own request wrote tip_i to the head
  var overwritten: Set[int]       // i in wrote, and the head has since moved off tip_i
  var lostUpdate: bool            // a Match(e) head write replaced a value != e
  var lastAction: Action

  // A pack's contents; pack 0 is the seed push of INIT_HEAD.
  def packOf(k: int): { objs: Set[int], bases: Set[int] } =
    if (k == 0) { objs: CLOS.get(INIT_HEAD), bases: Set() }
    else if (k >= 10) {
      // Replanning creates a different immutable content-addressed pack.
      // A previously appended pack must retain the bases of its own plan.
      val owner = k / 10 - 1
      val base = k % 10
      { objs: CLOS.get(tipOf(owner)).exclude(CLOS.get(base)), bases: CLOS.get(base) }
    }
    else {
      val st = ps.get(k)
      val tipC = CLOS.get(tipOf(k))
      if (st.reset) { objs: tipC, bases: Set() }
      else { objs: tipC.exclude(CLOS.get(st.base)), bases: CLOS.get(st.base) }
    }

  // Fold the chain oldest first (fetch order, SPEC-PACKFILE §4).
  def recon(chain: List[int]): { ok: bool, s: Set[int] } =
    chain.foldl({ ok: true, s: CLOS.get(INIT_HEAD).exclude(CLOS.get(INIT_HEAD)) }, (acc, k) => {
      val pk = packOf(k)
      if (pk.bases.subseteq(acc.s)) { ok: acc.ok, s: acc.s.union(pk.objs) }
      else { ok: false, s: acc.s }
    })

  // ------------------------------------------------------------------- init
  pure val IDLE: P = {
    pc: "idle", base: -1, reset: false, node: List(), pmExp: List(), plannedPm: List(), attempts: 0,
    ladder: 0, call: "", resp: "", report: "", srvRead: -1,
  }

  action init = all {
    hd' = INIT_HEAD,
    pm' = List(0),
    ps' = PIDS.mapBy(_ => IDLE),
    stored' = PIDS.mapBy(_ => ""),
    landed' = Set(),
    wrote' = Set(),
    overwritten' = Set(),
    lostUpdate' = false,
    lastAction' = { name: "init", p: 0, what: "" },
  }

  // ---------------------------------------------------------------- helpers
  action keepHead = all {
    hd' = hd, landed' = landed, wrote' = wrote, overwritten' = overwritten,
    lostUpdate' = lostUpdate,
  }

  // Pusher i's request writes tip_i to the head under `c`; `seen` is the
  // value the server's CAS decided on (the current head, except splitCas).
  action writeHead(i: int, seen: int): bool = {
    val v = tipOf(i)
    // the server's CAS decided Match(e) on `seen` (== e); the write
    // replaces hd, which differs from e only if the CAS was not atomic
    val blind = requestCond(i) != ANY and requestCond(i) != hd
    all {
      hd' = v,
      landed' = landed.union(PIDS.filter(j => ps.get(j).pc != "idle" and tipOf(j) == v)),
      wrote' = wrote.union(Set(i)),
      overwritten' = overwritten.union(wrote.filter(j => tipOf(j) != v)),
      lostUpdate' = if (blind) true else lostUpdate,
    }
  }

  action setP(i: int, st: P): bool = ps' = ps.set(i, st)

  def guardedForce(i: int): bool = MODE == "atomic" and condOf(i) == ANY and not(FAULTS.gateNoAny)
  def effAtomic(i: int): bool = MODE == "atomic" and not(ANY_FALLBACK and condOf(i) == ANY and FAULTS.gateNoAny)
  def requestCond(i: int): Cond =
    if (guardedForce(i)) ps.get(i).base else condOf(i)
  pure def extendsChain(current: List[int], prior: List[int]): bool =
    current.length() >= prior.length() and current.slice(0, prior.length()) == prior

  def packId(i: int): int = if (guardedForce(i)) 10 * (i + 1) + ps.get(i).base else i

  // --------------------------------------------------------------- actions
  // Non-force: read R and probe packmap. Force: capture packmap before planning.
  action start(i: int): bool = {
    val st = ps.get(i)
    val tip = tipOf(i)
    val empty = CLOS.get(tip).subseteq(CLOS.get(hd))
    val reset = pm.length() + 1 > THRESH
      and (MODE == "atomic" or FAULTS.noGate)
      and (condOf(i) != ANY or FAULTS.gateNoAny)
    all {
      st.pc == "idle",
      hd' = hd, wrote' = wrote, overwritten' = overwritten, lostUpdate' = lostUpdate,
      landed' = if (hd == tip) landed.union(Set(i)) else landed,
      pm' = pm,
      if (guardedForce(i)) all {
        setP(i, { ...st, pc: "planForce", plannedPm: pm }),
        stored' = stored,
      }
      else if (empty)
        // no-op plan: commit_head only (fresh call, fresh nonce)
        all {
          setP(i, { ...st, pc: "updSrv", base: hd, call: "upd", ladder: LADDER }),
          stored' = stored.set(i, ""),
        }
      else all {
        setP(i, { ...st, pc: "loop", base: hd, reset: reset }),
        stored' = stored,
      },
      lastAction' = { name: "start", p: i, what: if (empty) "noop" else if (reset) "reset" else "append" },
    }
  }

  // The strong packmap read precedes this head read. They are separate
  // steps: a reset between them must also be caught by the packmap guard.
  action planForce(i: int): bool = {
    val st = ps.get(i)
    val empty = CLOS.get(tipOf(i)).subseteq(CLOS.get(hd))
    all {
      st.pc == "planForce",
      hd' = hd, wrote' = wrote, overwritten' = overwritten, lostUpdate' = lostUpdate, pm' = pm,
      landed' = if (hd == tipOf(i)) landed.union(Set(i)) else landed,
      stored' = stored.set(i, ""),
      if (st.attempts >= ATTEMPTS)
        setP(i, { ...st, pc: "done", report: "contended" })
      else if (empty)
        setP(i, { ...st, pc: "advSrv", base: hd, reset: false, call: "adv",
                  node: st.plannedPm, pmExp: st.plannedPm, ladder: LADDER,
                  attempts: st.attempts + 1 })
      else setP(i, { ...st, pc: "loop", base: hd, reset: false }),
      lastAction' = { name: "planForce", p: i, what: if (empty) "noop" else "append" },
    }
  }

  // advance_packmap: one iteration of the CAS loop.
  action loop(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "loop",
      keepHead, pm' = pm,
      stored' = stored.set(i, ""),
      if (st.attempts >= ATTEMPTS)
        all {
          setP(i, { ...st, pc: "done", report: "contended" }),
          lastAction' = { name: "loop", p: i, what: "contended" },
        }
      else if (guardedForce(i) and not(extendsChain(pm, st.plannedPm)))
        // The old plan's delta bases may have been dropped. Re-read and
        // re-plan, sharing the CAS budget rather than starting a new one.
        all {
          setP(i, { ...st, pc: "idle", attempts: st.attempts + 1 }),
          lastAction' = { name: "loop", p: i, what: "replan" },
        }
      else if (not(st.reset) and inList(pm, packId(i)))
        // idempotency: our pack is already chained, only the head remains
        all {
          setP(i, { ...st, pc: if (guardedForce(i)) "advSrv" else "updSrv",
                    call: if (guardedForce(i)) "adv" else "upd", node: pm, pmExp: pm,
                    ladder: LADDER, attempts: st.attempts + 1 }),
          lastAction' = { name: "loop", p: i, what: "commitHead" },
        }
      else
        all {
          setP(i, { ...st, pc: "advSrv", call: "adv", ladder: LADDER,
                    attempts: st.attempts + 1, pmExp: pm,
                    node: if (st.reset) (if (tipOf(i) == INIT_HEAD) List(0) else List(i)) else pm.append(packId(i)) }),
          lastAction' = { name: "loop", p: i, what: "advance" },
        },
    }
  }

  // Server: advance_refs, atomic batch (with the replay ledger if LEDGER).
  action srvAdvAtomic(i: int): bool = {
    val st = ps.get(i)
    val out =
      if (LEDGER and stored.get(i) != "") stored.get(i)
      else if (pm != st.pmExp) "PackmapConflict"
      else if (not(holds(requestCond(i), hd))) "HeadConflict"
      else "Committed"
    val applies = out == "Committed" and not(LEDGER and stored.get(i) != "")
    all {
      st.pc == "advSrv", effAtomic(i),
      if (applies) all { writeHead(i, hd), pm' = st.node } else all { keepHead, pm' = pm },
      stored' = if (LEDGER) stored.set(i, out) else stored,
      setP(i, { ...st, pc: "resp", resp: out }),
      lastAction' = { name: "srvAdv", p: i, what: if (LEDGER and stored.get(i) != "") "replayed" else out },
    }
  }

  // Server: ordered advance, first write (packmap; head under headFirst).
  action srvAdvFirst(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "advSrv", not(effAtomic(i)),
      stored' = stored,
      if (not(FAULTS.headFirst))
        if (pm != st.pmExp)
          all { keepHead, pm' = pm, setP(i, { ...st, pc: "resp", resp: "PackmapConflict" }),
                lastAction' = { name: "srvAdvFirst", p: i, what: "PackmapConflict" } }
        else
          all { keepHead, pm' = st.node, setP(i, { ...st, pc: "advSrv2" }),
                lastAction' = { name: "srvAdvFirst", p: i, what: "packmap" } }
      else
        if (not(holds(requestCond(i), hd)))
          all { keepHead, pm' = pm, setP(i, { ...st, pc: "resp", resp: "HeadConflict" }),
                lastAction' = { name: "srvAdvFirst", p: i, what: "HeadConflict" } }
        else
          all { writeHead(i, hd), pm' = pm, setP(i, { ...st, pc: "advSrv2" }),
                lastAction' = { name: "srvAdvFirst", p: i, what: "head" } },
    }
  }

  // Server: ordered advance, second write.
  action srvAdvSecond(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "advSrv2",
      stored' = stored,
      if (not(FAULTS.headFirst))
        if (not(holds(requestCond(i), hd)))
          all { keepHead, pm' = pm, setP(i, { ...st, pc: "resp", resp: "HeadConflict" }),
                lastAction' = { name: "srvAdvSecond", p: i, what: "HeadConflict" } }
        else
          all { writeHead(i, hd), pm' = pm, setP(i, { ...st, pc: "resp", resp: "Committed" }),
                lastAction' = { name: "srvAdvSecond", p: i, what: "Committed" } }
      else
        if (pm != st.pmExp)
          all { keepHead, pm' = pm, setP(i, { ...st, pc: "resp", resp: "PackmapConflict" }),
                lastAction' = { name: "srvAdvSecond", p: i, what: "PackmapConflict" } }
        else
          all { keepHead, pm' = st.node, setP(i, { ...st, pc: "resp", resp: "Committed" }),
                lastAction' = { name: "srvAdvSecond", p: i, what: "Committed" } },
    }
  }

  // Server crash / connection loss between the two ordered writes: the
  // client sees a transport error (the unary timeout), not an outcome.
  action srvCrash(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "advSrv2",
      keepHead, pm' = pm, stored' = stored,
      setP(i, { ...st, pc: if (FAULTS.noTimeout) "hung" else "resp", resp: "lost" }),
      lastAction' = { name: "srvCrash", p: i, what: "" },
    }
  }

  // Server: update_ref(head, cond, tip) (commit_head).
  action srvUpd(i: int): bool = {
    val st = ps.get(i)
    val replayed = LEDGER and stored.get(i) != ""
    val ok = holds(requestCond(i), hd)
    all {
      st.pc == "updSrv",
      pm' = pm,
      if (replayed)
        all { keepHead, stored' = stored, setP(i, { ...st, pc: "resp", resp: stored.get(i) }),
              lastAction' = { name: "srvUpd", p: i, what: "replayed" } }
      else if (FAULTS.splitCas)
        all { keepHead, stored' = stored, setP(i, { ...st, pc: "updSrv2", srvRead: hd }),
              lastAction' = { name: "srvUpd", p: i, what: "read" } }
      else all {
        if (ok) writeHead(i, hd) else keepHead,
        stored' = if (LEDGER) stored.set(i, if (ok) "ok" else "conflict") else stored,
        setP(i, { ...st, pc: "resp", resp: if (ok) "ok" else "conflict" }),
        lastAction' = { name: "srvUpd", p: i, what: if (ok) "ok" else "conflict" },
      },
    }
  }

  // splitCas mutant: the write, decided on the value read earlier.
  action srvUpd2(i: int): bool = {
    val st = ps.get(i)
    val ok = holds(condOf(i), st.srvRead)
    all {
      st.pc == "updSrv2",
      pm' = pm, stored' = stored,
      if (ok) writeHead(i, st.srvRead) else keepHead,
      setP(i, { ...st, pc: "resp", resp: if (ok) "ok" else "conflict" }),
      lastAction' = { name: "srvUpd2", p: i, what: if (ok) "ok" else "conflict" },
    }
  }

  // The client receives the response.
  action deliver(i: int): bool = {
    val st = ps.get(i)
    val conflict = st.resp == "HeadConflict" or st.resp == "conflict"
    all {
      st.pc == "resp", st.resp != "lost",
      keepHead, pm' = pm, stored' = stored,
      if (st.resp == "Committed" or st.resp == "ok")
        setP(i, { ...st, pc: "done", report: "success" })
      else if (st.resp == "PackmapConflict")
        setP(i, { ...st, pc: "loop" })
      else if (guardedForce(i))
        setP(i, { ...st, pc: "idle" })
      else if (FAULTS.oldConflict)
        setP(i, { ...st, pc: "done", report: "nff" })
      else if (FAULTS.trustConflict)
        setP(i, { ...st, pc: "done", report: "success" })
      else
        setP(i, { ...st, pc: "readHead" }),
      lastAction' = { name: "deliver", p: i, what: st.resp },
    }
  }

  // The response is lost (or the server crashed): the retry ladder re-issues
  // the same request, or gives up with a transport error.
  action lose(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "resp",
      keepHead, pm' = pm, stored' = stored,
      if (st.ladder > 0)
        all {
          setP(i, { ...st, pc: if (st.call == "adv") "advSrv" else "updSrv",
                    ladder: if (FAULTS.noLadderBound) st.ladder else st.ladder - 1, resp: "" }),
          lastAction' = { name: "reissue", p: i, what: st.resp },
        }
      else
        all {
          setP(i, { ...st, pc: "done", report: "error" }),
          lastAction' = { name: "ladderExhausted", p: i, what: st.resp },
        },
    }
  }

  // SPEC-TRANSPORT §7: read_ref(head) before reporting a conflict.
  action readHead(i: int): bool = {
    val st = ps.get(i)
    val landedNow = hd == tipOf(i)
    all {
      st.pc == "readHead",
      keepHead, pm' = pm, stored' = stored,
      setP(i, { ...st, pc: "done", report: if (landedNow) "success" else "nff" }),
      lastAction' = { name: "readHead", p: i, what: if (landedNow) "success" else "nff" },
    }
  }

  // The pusher's process dies. Only where it leaves remote state behind: with
  // an ordered advance half applied (a local file-transport push dying
  // between its two writes), or after the server applied a request whose
  // outcome it never sees. A death anywhere else stops the pusher before
  // its next remote effect, which a pusher that simply never takes another
  // step already covers (no invariant needs a pusher to move).
  action crash(i: int): bool = {
    val st = ps.get(i)
    all {
      st.pc == "advSrv2" or st.pc == "resp",
      keepHead, pm' = pm, stored' = stored,
      setP(i, { ...st, pc: "dead" }),
      lastAction' = { name: "crash", p: i, what: st.pc },
    }
  }

  def terminal(i: int): bool = Set("done", "dead", "hung").contains(ps.get(i).pc)

  action quiet = all {
    PIDS.forall(i => terminal(i)),
    keepHead, pm' = pm, ps' = ps, stored' = stored,
    lastAction' = { name: "quiet", p: 0, what: "" },
  }

  action pusherStep = {
    nondet i = PIDS.filter(j => not(terminal(j))).oneOf()
    any {
      start(i), planForce(i), loop(i), srvAdvAtomic(i), srvAdvFirst(i), srvAdvSecond(i),
      srvCrash(i), srvUpd(i), srvUpd2(i), deliver(i), lose(i), readHead(i), crash(i),
    }
  }

  action step = any { pusherStep, quiet }

  // ------------------------------------------------------------ invariants
  // The delta-transfer invariant (protocol.rs `Transport::advance_refs`;
  // SPEC-TRANSPORT-CONNECT §4): if the head resolves to T, the packmap
  // reconstructs closure(T).
  val DeltaTransfer: bool = {
    val r = recon(pm)
    r.ok and CLOS.get(hd).subseteq(r.s)
  }
  // A success report means the head held the pushed tip after the push began.
  val SuccessSound: bool = PIDS.forall(i => ps.get(i).report == "success" implies landed.contains(i))
  // SPEC-TRANSPORT §7: a NonFastForward report is never a landed write that
  // still stands.
  val ConflictHonest: bool =
    PIDS.forall(i => ps.get(i).report == "nff" implies (not(wrote.contains(i)) or overwritten.contains(i)))
  // Concurrent pushers never lose an update: a Match(e) head write replaces e.
  val NoLostUpdate: bool = not(lostUpdate)
  // The user-level reading of "never lose an update": when every pusher is a
  // fast-forward (a Match(e) push of a descendant of e, so no push may
  // legitimately drop another's commit), a push reported as success stays in
  // the history of the head. Vacuous (true) on instances with a force push
  // or a non-fast-forward lease.
  val FF_ONLY: bool = PIDS.forall(j => condOf(j) != ANY and CLOS.get(tipOf(j)).contains(condOf(j)))
  val NoLostSuccess: bool =
    FF_ONLY implies PIDS.forall(i => ps.get(i).report == "success" implies CLOS.get(hd).contains(tipOf(i)))

  val Safety: bool = DeltaTransfer and SuccessSound and ConflictHonest and NoLostUpdate and NoLostSuccess

  // ------------------------------------------------------------ progress
  // State predicates (every run is finite: see README.md). Only the noTimeout
  // mutant has a pusher with no step.
  val NoStuckPusher: bool = PIDS.forall(i => ps.get(i).pc != "hung")
  val BoundedRetries: bool = PIDS.forall(i => and {
    ps.get(i).attempts <= ATTEMPTS, ps.get(i).ladder >= 0, ps.get(i).ladder <= LADDER,
  })
  val Progress: bool = NoStuckPusher and BoundedRetries
  val All: bool = Safety and Progress

  // ------------------------------------------ canaries (each MUST be violated)
  val CanaryNoReset: bool = not(PIDS.exists(i => ps.get(i).reset and ps.get(i).report == "success"))
  val CanaryNoAppendSuccess: bool = not(PIDS.exists(i => not(ps.get(i).reset) and ps.get(i).report == "success" and inList(pm, packId(i))))
  val CanaryNoReissueAfterLanded: bool = not(lastAction.name == "reissue" and wrote.contains(lastAction.p))
  val CanaryNoDisambiguatedSuccess: bool = not(lastAction.name == "readHead" and lastAction.what == "success")
  val CanaryNoNff: bool = not(PIDS.exists(i => ps.get(i).report == "nff"))
  val CanaryNoTornAdvance: bool = not(lastAction.name == "srvCrash")
  val CanaryNoPackmapConflict: bool = not(lastAction.name == "deliver" and lastAction.what == "PackmapConflict")
  val CanaryNoConcurrentSuccess: bool = PIDS.filter(i => ps.get(i).report == "success").size() < 2
  val CanaryNoReplayed: bool = not(lastAction.what == "replayed")
  // Residual ambiguity of §7's read_ref rule (expected reachable, documented):
  // a push whose head write landed and was then built on by another pusher
  // reads a different head and is reported NonFastForward.
  val WitnessLandedThenNff: bool = not(PIDS.exists(i => ps.get(i).report == "nff" and wrote.contains(i)))
}

// ------------------------------------------------------------ instances
// FAULTS literal: { oldConflict, trustConflict, noGate, gateNoAny, splitCas,
// headFirst, noTimeout, noLadderBound }. Two pushers (TLC / Apalache) unless named *3.
// THRESH = 1: every non-empty push wants to re-baseline, so the gate decides.

// ordered store (file / S3 / SSH / memory transports; mkit-server on a
// non-atomic store): p1 fast-forwards 0 -> 1, p2 races 0 -> 2.
module ordered2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// + a force pusher (Any) whose tip 3 builds on p1's 1.
module ordered3 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }, 3 -> { tip: 3, cond: -1 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// atomic store without the replay ledger (mkit-server Open / Bearer on an
// atomic_multi_key store): resets allowed.
module atomic2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module atomic3 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }, 3 -> { tip: 3, cond: 1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module ledger3 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }, 3 -> { tip: 3, cond: 1 }),
                 MODE = "atomic", LEDGER = true, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// A force pusher (Any) on a genuinely atomic transport, racing two
// fast-forward re-baselines: expected safe (compare F1 / F2).
module atomicAny3 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }, 3 -> { tip: 3, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// atomic store with the auth v2 replay ledger (mkit-server AuthV2).
module ledger2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = true, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// HTTP atomic advance substitutes Match(observed head) for Any. The mutant
// below preserves the old ordered fallback to demonstrate its failure.
module http1 {
  import advance(PUSHERS = Map(2 -> { tip: 2, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = true, INIT_HEAD = 1, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// Force push (Any) racing a fast-forward re-baseline on an atomic transport
// (Connect with atomic_advance): head 3; p1 fast-forwards 3 -> 5 with a
// reset; p2 force-pushes 1 (an ancestor: empty plan, head-only write).
// Expected safe: closure(1) is inside closure(5).
module forceFF2 {
  import advance(PUSHERS = Map(1 -> { tip: 5, cond: 3 }, 2 -> { tip: 1, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// Head-only force push racing a sideways lease reset. The packmap guard
// rejects the stale request, then the shared budget permits a fresh plan.
module gapNoopAny2 {
  import advance(PUSHERS = Map(1 -> { tip: 2, cond: 3 }, 2 -> { tip: 1, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// Head-only force push racing another force push and a fast-forward reset.
module gapTwoAny3 {
  import advance(PUSHERS = Map(1 -> { tip: 6, cond: 4 }, 2 -> { tip: 1, cond: -1 }, 3 -> { tip: 4, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// HTTP force advance remains atomic with both packmap and observed-head
// guards. The former ordered fallback cannot split around p1's reset.
module gapHttpAny2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = true, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}

// A force delta plan races a sideways lease reset. The replacement chain
// does not extend its captured chain, so the old delta plan is discarded.
module gapAppendAny2 {
  import advance(PUSHERS = Map(1 -> { tip: 2, cond: 3 }, 2 -> { tip: 5, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// The appending variant with fast-forward leases only: as gapTwoAny3, but p2
// force-pushes 5 (a child of 3, non-empty plan) instead of rewinding to 1.
module gapAppendTwoAny3 {
  import advance(PUSHERS = Map(1 -> { tip: 6, cond: 4 }, 2 -> { tip: 5, cond: -1 }, 3 -> { tip: 4, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}

// ----------------------------------------------------- mutants (non-vacuity)
// The pre-reconciliation client: conflict => NonFastForward, no read_ref.
module ordered2_oldConflict {  // ConflictHonest
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: true, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module atomic2_oldConflict {   // ConflictHonest
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: true, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// With the replay ledger the old client is honest (SPEC-TRANSPORT §7 "MAY
// skip the read_ref only when it knows the remote keeps that ledger").
module ledger2_oldConflict {   // ConflictHonest holds
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = true, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: true, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module ordered2_trustConflict { // SuccessSound
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: true, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// pre-#521: re-baseline on a non-transactional advance.
module ordered2_noGate {       // DeltaTransfer
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: true, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// The gate without its `Any` clause, on HTTP's Any fallback.
module http1_gateNoAny {       // DeltaTransfer
  import advance(PUSHERS = Map(2 -> { tip: 2, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = true, INIT_HEAD = 1, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: true, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module ordered2_headFirst {    // DeltaTransfer
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: true, noTimeout: false, noLadderBound: false }).*
}
// Two head-only pushes (both no-op plans: tips 1, 3 are in closure(5)).
module noop2_splitCas {        // NoLostUpdate
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 5 }, 2 -> { tip: 3, cond: 5 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 5, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: true, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// The same unlocked head CAS on fast-forward pushers: p2's re-issued
// commit_head overwrites p1's reported success (NoLostSuccess).
module ordered2_splitCas {     // NoLostSuccess (and NoLostUpdate)
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: true, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module noop2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 5 }, 2 -> { tip: 3, cond: 5 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 5, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
module ordered2_noTimeout {    // NoStuckPusher
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: true, noLadderBound: false }).*
}
// The ladder without its attempt limit: a response lost on every re-issue
// re-issues forever (Termination, checked by TLC as a temporal property).
module ordered2_noLadderBound { // Termination
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "ordered", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2,
                 FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: true }).*
}

// A reset to the initial closure may restore the identical content-addressed
// root. The force head guard must still reject a plan made against head 6.
module gapAbaAny3 {
  import advance(PUSHERS = Map(1 -> { tip: 6, cond: 3 }, 2 -> { tip: 4, cond: -1 }, 3 -> { tip: 3, cond: 6 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 4, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
