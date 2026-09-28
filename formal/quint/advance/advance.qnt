// -*- mode: Bluespec; -*-
// advance_refs model for mkit (Linear MKIT-27, epic MKIT-17, PR #1082).
//
// What is modelled (branch claude/kind-brahmagupta-esqhc0; spec text as
// reconciled on this branch is normative):
//
//   Client (mkit-cli `remote_dispatch::push_branch_with_limits` and
//   `remote_dispatch::packmap::{advance_packmap, commit_head, head_conflict}`):
//     - push_branch reads the remote head R, plans closure(tip) \ closure(R)
//       (deltas against bases in closure(R)); an empty plan takes the
//       head-only `commit_head` path;
//     - the #406/#521 re-baseline gate: reset the packmap chain to one
//       self-contained node ONLY when the chain would pass the threshold AND
//       `supports_atomic_advance()` AND the head condition is not `Any`;
//     - advance_packmap's CAS loop (PACKMAP_CAS_ATTEMPTS): read packmap,
//       idempotency short-cut (our pack already in the chain -> commit_head),
//       build node = prior ++ [ours] (or [ours] on a reset), advance_refs with
//       packmap Match(prior) and the push's head condition;
//     - outcome handling per SPEC-TRANSPORT §7 as reconciled on this branch:
//       PackmapConflict -> re-read the packmap (the loop), HeadConflict or
//       commit_head's RefConflict -> read_ref(head); head == tip means the
//       write landed (success), else NonFastForwardPush.
//   Transport retry ladder (SPEC-TRANSPORT §7, `mkit_core::protocol::
//   retrying`; SPEC-TRANSPORT-CONNECT §7.3): a lost response (timeout,
//   connection loss, server crash) re-issues the SAME request, carrying the
//   same conditions, up to LADDER more times; then the call fails with an
//   error. With the auth v2 replay ledger (SPEC-TRANSPORT-CONNECT §7.1,
//   `RetryIdentity`), a re-issue within one call's ladder gets the stored
//   result of the committed attempt.
//   Server / store:
//     - "atomic": one batch for packmap + head (mkit-server pipeline
//       `apply_atomic` on an `atomic_multi_key` store; HTTP `/refs/advance`;
//       SPEC-TRANSPORT-CONNECT §4 "SHOULD commit both writes atomically");
//     - "ordered": packmap CAS then head CAS as two separately-durable writes
//       (`Transport::advance_refs` default: FileTransport, S3, SSH, memory;
//       mkit-server `plan_and_apply` on a non-atomic store; SPEC-TRANSPORT-
//       CONNECT §4 "MUST fall back to the same packmap-then-head ordering").
//       A crash / connection loss can land between the two writes.
//     - ANY_FALLBACK: the HTTP transport's atomic endpoint cannot express
//       `Any`, so an advance with an `Any` condition falls back to the ordered
//       path (`HttpTransport::advance_refs_impl`) although the transport still
//       reports `supports_atomic_advance() == true`.
//
// Abstraction (explicit):
//   - Commits 0..6 with a fixed DAG: 1, 2 children of 0; 3 child of 1; 4 child
//     of 2; 5 child of 3; 6 child of 4. An object = a commit; closure(c) = ancestors of c.
//   - A pack = (objs, bases): an append pack for a push planned against R
//     carries closure(tip) \ closure(R) and (adversarially) needs every object
//     of closure(R) as a delta base; a reset pack is self-contained. Pack
//     uploads (content-addressed, idempotent, SPEC-TRANSPORT §7) are always
//     present: no pack GC here (that is SPEC-GC's model, formal/quint/gc).
//   - A packmap value = the chain of pack ids, oldest first (node keys are
//     content addressed, so equal chains = equal node keys). Pack 0 = the
//     seed push that created the branch. Reconstructing a chain folds it
//     oldest first; a node whose delta bases are not yet reconstructable
//     breaks the chain (fetch fails).
//   - Each pusher runs one push; its tip is distinct from the other pushers'.
//   - push_branch's two reads (head, then the packmap probe) are one step:
//     the probe only chooses reset vs append, and every write is then
//     re-validated by CAS, so splitting them adds interleavings of the
//     choice only, not of any write.
//   - A request lost BEFORE the server processed it is not a separate step:
//     it only burns a ladder attempt, which the lost-response step already
//     covers.
//   - The server keeps running a request after the client dies; a dead
//     pusher here stops everything of its own, which also covers the local
//     file transport (the client IS the writer) and a server crash.
//   - The replay ledger keeps one stored result per pusher (its current
//     logical call's nonce); its expiry is not modelled.
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
    gateNoAny: bool,     // the gate's `Any` clause dropped (HTTP Any fallback)
    splitCas: bool,      // server head CAS as read-then-write without a lock
    headFirst: bool,     // ordered advance writes the head BEFORE the packmap
    noTimeout: bool,     // a server crash mid-request never surfaces to the client
    noLadderBound: bool, // the retry ladder re-issues forever (no attempt limit)
  }

  // pc: idle | loop | advSrv | advSrv2 | updSrv | updSrv2 | resp | readHead
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
  const ANY_FALLBACK: bool      // HTTP: `Any` forces the ordered path
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
    pc: "idle", base: -1, reset: false, node: List(), pmExp: List(), attempts: 0,
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
    val blind = condOf(i) != ANY and condOf(i) != hd
    all {
      hd' = v,
      landed' = landed.union(PIDS.filter(j => ps.get(j).pc != "idle" and tipOf(j) == v)),
      wrote' = wrote.union(Set(i)),
      overwritten' = overwritten.union(wrote.filter(j => tipOf(j) != v)),
      lostUpdate' = if (blind) true else lostUpdate,
    }
  }

  action setP(i: int, st: P): bool = ps' = ps.set(i, st)

  def effAtomic(i: int): bool = MODE == "atomic" and not(ANY_FALLBACK and condOf(i) == ANY)

  // --------------------------------------------------------------- actions
  // push_branch: read R (and probe the packmap), plan, decide reset.
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
      if (empty)
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
      else if (not(st.reset) and inList(pm, i))
        // idempotency: our pack is already chained, only the head remains
        all {
          setP(i, { ...st, pc: "updSrv", call: "upd", ladder: LADDER, attempts: st.attempts + 1 }),
          lastAction' = { name: "loop", p: i, what: "commitHead" },
        }
      else
        all {
          setP(i, { ...st, pc: "advSrv", call: "adv", ladder: LADDER,
                    attempts: st.attempts + 1, pmExp: pm,
                    node: if (st.reset) List(i) else pm.append(i) }),
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
      else if (not(holds(condOf(i), hd))) "HeadConflict"
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
        if (not(holds(condOf(i), hd)))
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
        if (not(holds(condOf(i), hd)))
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
    val ok = holds(condOf(i), hd)
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
      start(i), loop(i), srvAdvAtomic(i), srvAdvFirst(i), srvAdvSecond(i),
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
  val CanaryNoAppendSuccess: bool = not(PIDS.exists(i => not(ps.get(i).reset) and ps.get(i).report == "success" and inList(pm, i)))
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
// atomic store with the auth v2 replay ledger (vcs-worker / mkit-server AuthV2).
module ledger2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: 0 }),
                 MODE = "atomic", LEDGER = true, ANY_FALLBACK = false, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// HTTP `/refs/advance`: atomic, but `Any` falls back to ordered. One force
// pusher over head 1 with tip 2 (not a descendant): the gate's `Any` clause
// keeps it appending (see http1_gateNoAny).
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
// FINDING F2 (documented gap, DeltaTransfer expected violated): as forceFF2
// but p1 is a NON-fast-forward --force-with-lease (3 -> 2, Match(3)). p2's
// head-only Any write lands after p1's atomic reset: head 1, packmap
// reconstructs only closure(2).
module gapNoopAny2 {
  import advance(PUSHERS = Map(1 -> { tip: 2, cond: 3 }, 2 -> { tip: 1, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// FINDING F2, fast-forward leases only: p3 force-pushes 3 -> 4 (sideways),
// p1 fast-forwards 4 -> 6 with a reset, then p2's head-only Any write of 1
// (planned against head 3) lands: head 1, packmap closure(6).
module gapTwoAny3 {
  import advance(PUSHERS = Map(1 -> { tip: 6, cond: 4 }, 2 -> { tip: 1, cond: -1 }, 3 -> { tip: 4, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = false, INIT_HEAD = 3, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}
// FINDING F1 (documented gap, DeltaTransfer expected violated): HTTP. p1
// fast-forwards 0 -> 1 with an (atomic) re-baseline; p2 force-pushes 2 (Any),
// which falls back to the ordered two-PUT path. p1's reset commits between
// p2's packmap PUT and p2's head PUT: head 2, packmap reconstructs closure(1).
module gapHttpAny2 {
  import advance(PUSHERS = Map(1 -> { tip: 1, cond: 0 }, 2 -> { tip: 2, cond: -1 }),
                 MODE = "atomic", LEDGER = false, ANY_FALLBACK = true, INIT_HEAD = 0, THRESH = 1,
                 ATTEMPTS = 3, LADDER = 2, FAULTS = { oldConflict: false, trustConflict: false, noGate: false, gateNoAny: false, splitCas: false, headFirst: false, noTimeout: false, noLadderBound: false }).*
}

// FINDING F2, appending variant (DeltaTransfer expected violated): p2
// force-pushes 5 (Any) with a NON-empty plan against head 3 (its pack needs
// closure(3) as bases); p1's non-fast-forward lease re-baselines to [closure(2)];
// p2's loop re-reads the reset packmap, appends its pack onto it and commits
// under Any: head 5, and the chain [closure(2), p2] cannot resolve p2's bases.
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
