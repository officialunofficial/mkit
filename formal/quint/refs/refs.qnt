// -*- mode: Bluespec; -*-
// Ref CAS and lock-order model for mkit (Linear MKIT-19, workstream quint-refs).
//
// Models:
//   - SPEC-REFS §5 updateRef conditions Any / Missing / Match(H) and deletes
//     (unconditional `delete_ref`, conditional `delete_ref_if_matches`).
//   - SPEC-REFS §5.1 atomicity matrix for the three in-repo lock domains:
//       local : direct on-disk mutation under `refs-<ref>.lock` (refs.rs RefMutation)
//       file  : file transport under `<root>/.mkit/refs/.lock` (RefLock)
//       mem   : in-process memory transport, NO lock; `.match` is a
//               read-then-write race per the normative matrix.
//   - SPEC-CONCURRENCY §2 lock inventory, §4 global order
//       worktrees.lock ≺ worktree.lock(s) ≺ refs-history-<b>.lock ≺ refs-<ref>.lock
//     and in-class canonical order (main tree first, then ids; refs lexicographic).
//   - SPEC-CONCURRENCY §3.2 recovery-log record/expire synchronisation by
//     lock-superset containment (no dedicated lock).
//   - SPEC-CONCURRENCY §3.1: the file-transport RefLock is a separate domain
//     that writes the SAME ref files as the local chain; the cross-domain race
//     is a documented, unresolved gap (witnessed below, not a bug).
//
// Each process runs one operation at a time as explicit steps
//   begin → acquire* → [record] → readRef → commitRef → release      (ref writers)
//   begin → acquire* → expireRead → expireWrite → release            (gc)
// so a read-check-write can be interleaved with other processes' steps.
// `commitRef` checks Match against the value seen at `readRef` (TOCTOU window
// that the lock is supposed to close); Missing is decided on the actual file
// (O_EXCL / create_new, SPEC-REFS §5.1), unconditional delete fails NotFound on
// the actual file.
//
// Lock waits block forever (the 5 s repo_lock timeout, SPEC-CONCURRENCY §4
// last paragraph, is abstracted away: "SHOULD NOT rely on the timeout").
//
// Every step sets `lastAction` (step label + parameters + outcome) so traces
// can be replayed against the Rust implementation (ITF conformance).
//
// Code/spec drift (recorded as findings, not modelled): the Rust memory
// transport holds a Mutex across its read-check-write, so it is stronger than
// SPEC-REFS §5.1 says; this model follows the spec.
//
// Bounds (explicit): 3 processes (refs3) or 2 (refs2, Apalache), 2 worktrees
// (0 = main, 1 = linked id), 2 branch refs (0 = refs/heads/a ≺ 1 =
// refs/heads/b), hash values {1, 2}, 0 = ref absent, lock plans ≤ 3 locks.
// Multi-ref commands (branch -m, batched remote writes) publish one ref at a
// time (SPEC-CONCURRENCY §4 last sentence of the order paragraph), so each
// publication is one single-ref op here.
//
// Checks (see refs_test.qnt for pinned scenarios):
//   quint test refs_test.qnt
//   quint run refs.qnt --main refs3 --invariant Safety --max-samples 100000 --max-steps 40
//   quint run refs.qnt --main refs3 --invariant WitnessCrossDomainGap   # expect violation
//   quint run refs.qnt --main refs2_noRefLock --invariant NoLostUpdateLocal   # mutant: expect violation
//   quint compile --target tlaplus --main refs2 --invariant Safety refs.qnt > refs2.tla
//   apalache-mc check --init=q_init --next=q_step --inv=refs2_refs_Safety --length=8 refs2.tla
// Mutant modules (each must violate the invariant named next to it) are at
// the end of this file.
module refs {
  // ---------------------------------------------------------------- types
  type Proc = str

  // SPEC-REFS §5: condition := .any | .missing | .match(H)
  type Cond = Any | Missing | Match(int)

  // Lock ids. For the local chain the integer order IS the SPEC-CONCURRENCY §4
  // total order, including the canonical in-class order:
  //   0 worktrees.lock
  //   1 worktree.lock(main)      2 worktree.lock(linked id 1)
  //   3 refs-history-<a>.lock    4 refs-history-<b>.lock
  //   5 refs-<refs/heads/a>.lock 6 refs-<refs/heads/b>.lock
  //   7 <root>/.mkit/refs/.lock  (file-transport RefLock; separate domain,
  //     never composed with 0..6 — §3.1, §4 "not composed")
  type Lock = int

  // An operation request. `kind` selects the lock plan / command path.
  //   commit    : worktree.lock(tree) ≺ history(ref) ≺ refs-<ref>   (commit/merge/...)
  //   amend     : as commit, plus recovery::record before moving the ref
  //   updateRef : worktree.lock(tree) ≺ refs-<ref>                  (history-less path)
  //   branch    : worktrees.lock ≺ history(ref) ≺ refs-<ref>        (branch -d/-m, checkout guard)
  //   gc        : worktrees.lock ≺ worktree.lock(0) ≺ worktree.lock(1), then recovery::expire
  //   file      : file-transport RefLock only (mkit serve / mkit+file:// push)
  //   mem       : memory transport, no lock
  // `del` = delete instead of write (branch only): Any = delete_ref,
  // Match(e) = delete_ref_if_matches(e).
  type Op = { kind: str, tree: int, ref: int, cond: Cond, value: int, del: bool }

  type PState = {
    pc: str,            // idle | acquire | record | read | commit | expireRead | expireWrite | release
    op: Op,
    plan: List[Lock],   // locks to take, in this process's acquisition order
    nHeld: int,         // plan[0..nHeld) are held
    observed: int,      // value seen by readRef
    pending: Set[str],  // lock domains that wrote this ref since our readRef
    snapshot: Set[int], // recovery-log contents seen by expireRead
    outcome: str,       // "" | ok | conflict | notfound
  }

  // Mutation switches used ONLY to show the invariants are non-vacuous.
  type Faults = {
    misorder: bool,     // a process may take its plan in reverse (violates §4)
    noRefLock: bool,    // local writers skip refs-<ref>.lock (pre-#637 behaviour)
    noFileLock: bool,   // file transport skips RefLock
    gcSkipTrees: bool,  // gc expires holding only worktrees.lock (violates §3.2)
    racyAcquire: bool,  // acquire ignores exclusivity (a broken flock; violates §2)
  }

  type Violation = { writer: str, by: str }

  // Step label for trace replay. `lock` = lock taken by `acquire`, else -1.
  type Action = { name: str, proc: Proc, op: Op, rev: bool, lock: int, outcome: str }

  // --------------------------------------------------------------- bounds
  const PROCS: Set[Proc]  // instantiated below: 3 procs (refs3*) or 2 procs (refs2*)
  const FAULTS: Faults    // NO_FAULTS for the real model; mutants only for non-vacuity
  pure val TREES: Set[int] = Set(0, 1)
  pure val REFS: Set[int] = Set(0, 1)
  pure val VALUES: Set[int] = Set(1, 2)
  pure val ABSENT: int = 0
  pure val KINDS: Set[str] = Set("commit", "amend", "updateRef", "branch", "gc", "file", "mem")
  pure val LOCKS: Set[Lock] = 0.to(7)
  pure val FREE: Proc = ""
  pure val PLAN_IDX: Set[int] = 0.to(2)  // every lock plan has at most 3 locks

  pure val WTS: Lock = 0
  pure val FILE_LOCK: Lock = 7
  pure def wtLock(t: int): Lock = 1 + t
  pure def histLock(r: int): Lock = 3 + r
  pure def refLock(r: int): Lock = 5 + r

  pure val NOP: Op = { kind: "none", tree: 0, ref: 0, cond: Any, value: 0, del: false }
  pure val IDLE: PState = {
    pc: "idle", op: NOP, plan: [], nHeld: 0, observed: ABSENT,
    pending: Set(), snapshot: Set(), outcome: "",
  }
  pure val NO_FAULTS: Faults = {
    misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false,
  }

  // ------------------------------------------------------------- helpers
  pure def rev(l: List[Lock]): List[Lock] = l.foldl([], (acc, x) => [x].concat(acc))

  pure def domainOf(kind: str): str =
    if (kind == "file") "file" else if (kind == "mem") "mem" else "local"

  // Which ref store the op touches: the file transport serves the SAME
  // on-disk refs the local chain mutates (§3.1); memory is separate.
  pure def storeOf(kind: str): str = if (kind == "mem") "mem" else "disk"

  // Canonical §4 lock plan per command path (SPEC-CONCURRENCY §4 table).
  pure def canonicalPlan(op: Op, f: Faults): List[Lock] =
    if (op.kind == "commit" or op.kind == "amend")
      (if (f.noRefLock) [wtLock(op.tree), histLock(op.ref)]
       else [wtLock(op.tree), histLock(op.ref), refLock(op.ref)])
    else if (op.kind == "updateRef")
      (if (f.noRefLock) [wtLock(op.tree)] else [wtLock(op.tree), refLock(op.ref)])
    else if (op.kind == "branch")
      (if (f.noRefLock) [WTS, histLock(op.ref)] else [WTS, histLock(op.ref), refLock(op.ref)])
    else if (op.kind == "gc") (if (f.gcSkipTrees) [WTS] else [WTS, wtLock(0), wtLock(1)])
    else if (op.kind == "file") (if (f.noFileLock) [] else [FILE_LOCK])
    else []

  pure def bodyStart(kind: str): str =
    if (kind == "gc") "expireRead" else if (kind == "amend") "record" else "read"

  // The condition evaluated against a given value (what linearizability demands).
  pure def condHolds(c: Cond, v: int): bool = match c {
    | Any => true
    | Missing => v == ABSENT
    | Match(e) => v == e
  }

  pure def validOp(op: Op): bool = and {
    KINDS.contains(op.kind),
    // deletes only through branch -d / rename's delete_ref_if_matches
    op.del implies (op.kind == "branch" and op.cond != Missing),
    // gc and transports ignore tree; gc ignores ref/cond/val (canonicalise for replay)
    (op.kind == "gc" or op.kind == "file" or op.kind == "mem" or op.kind == "branch") implies op.tree == 0,
    op.kind == "gc" implies (op.ref == 0 and op.cond == Any and op.value == 1),
  }

  pure def nextLock(st: PState): Lock = st.plan[st.nHeld]

  // ---------------------------------------------------------------- state
  var disk: int -> int          // on-disk refs (local chain AND file transport)
  var mem: int -> int           // memory-transport refs
  var owner: Lock -> Proc       // kernel lock holder, FREE if unheld
  var procs: Proc -> PState
  var recLog: Set[int]          // .mkit/recovery-log entry ids
  var nextEntry: int
  var faults: Faults
  // ghost / observation
  var violations: Set[Violation]  // successful conditional writes whose condition was false on the actual value
  var lostRecords: Set[int]       // recovery entries dropped by an interleaved expire rewrite
  var recordDuringExpire: bool    // a record landed between expireRead and expireWrite
  var lastAction: Action

  // --------------------------------------------------------------- init
  // Deterministic initial state (also the replay entry point for ITF traces).
  action initFixed(f: Faults, d0: int, d1: int, m0: int): bool = all {
    disk' = Map(0 -> d0, 1 -> d1),
    mem' = Map(0 -> m0, 1 -> ABSENT),
    owner' = LOCKS.mapBy(_ => FREE),
    procs' = PROCS.mapBy(_ => IDLE),
    recLog' = Set(),
    nextEntry' = 1,
    faults' = f,
    violations' = Set(),
    lostRecords' = Set(),
    recordDuringExpire' = false,
    lastAction' = { name: "init", proc: "", op: NOP, rev: false, lock: -1, outcome: "" },
  }

  action initWith(f: Faults): bool = {
    nondet d0 = VALUES.union(Set(ABSENT)).oneOf()
    nondet d1 = VALUES.union(Set(ABSENT)).oneOf()
    nondet m0 = VALUES.union(Set(ABSENT)).oneOf()
    initFixed(f, d0, d1, m0)
  }

  action init = initWith(FAULTS)

  // ------------------------------------------------------------- actions
  action unchangedData = all {
    disk' = disk, mem' = mem, recLog' = recLog, nextEntry' = nextEntry,
    faults' = faults, violations' = violations, lostRecords' = lostRecords,
    recordDuringExpire' = recordDuringExpire,
  }

  // begin(p, op, rev): p starts an operation. `rev` = take the plan in
  // reverse order (only possible under the `misorder` fault).
  action begin(p: Proc, op: Op, reversed: bool): bool = {
    val plan0 = canonicalPlan(op, faults)
    val plan = if (reversed) rev(plan0) else plan0
    all {
      procs.get(p).pc == "idle",
      validOp(op),
      reversed implies faults.misorder,
      procs' = procs.set(p, { ...IDLE, op: op, plan: plan,
                              pc: if (plan.length() == 0) bodyStart(op.kind) else "acquire" }),
      owner' = owner,
      unchangedData,
      lastAction' = { name: "begin", proc: p, op: op, rev: reversed, lock: -1, outcome: "" },
    }
  }

  // acquire(p): blocking exclusive kernel lock (repo_lock / RefLock); enabled
  // only when free (unless the racyAcquire mutant breaks exclusivity).
  action acquire(p: Proc): bool = {
    val st = procs.get(p)
    val l = nextLock(st)
    all {
      st.pc == "acquire",
      faults.racyAcquire or owner.get(l) == FREE,
      owner' = owner.set(l, p),
      procs' = procs.set(p, { ...st, nHeld: st.nHeld + 1,
                              pc: if (st.nHeld + 1 == st.plan.length()) bodyStart(st.op.kind) else "acquire" }),
      unchangedData,
      lastAction' = { name: "acquire", proc: p, op: st.op, rev: false, lock: l, outcome: "" },
    }
  }

  // record(p): recovery::record — single O_APPEND line (SPEC-CONCURRENCY §3.2).
  action record(p: Proc): bool = {
    val st = procs.get(p)
    all {
      st.pc == "record",
      recLog' = recLog.union(Set(nextEntry)),
      nextEntry' = nextEntry + 1,
      recordDuringExpire' = (recordDuringExpire or PROCS.exists(q => procs.get(q).pc == "expireWrite")),
      procs' = procs.set(p, { ...st, pc: "read" }),
      owner' = owner,
      disk' = disk, mem' = mem, faults' = faults, violations' = violations, lostRecords' = lostRecords,
      lastAction' = { name: "record", proc: p, op: st.op, rev: false, lock: -1, outcome: "" },
    }
  }

  // readRef(p): the "read" half of read-check-write.
  action readRef(p: Proc): bool = {
    val st = procs.get(p)
    val cur = if (storeOf(st.op.kind) == "mem") mem.get(st.op.ref) else disk.get(st.op.ref)
    all {
      st.pc == "read",
      procs' = procs.set(p, { ...st, pc: "commit", observed: cur, pending: Set() }),
      owner' = owner,
      unchangedData,
      lastAction' = { name: "readRef", proc: p, op: st.op, rev: false, lock: -1, outcome: "" },
    }
  }

  // commitRef(p): the "check-write" half.
  action commitRef(p: Proc): bool = {
    val st = procs.get(p)
    val op = st.op
    val store = storeOf(op.kind)
    val actual = if (store == "mem") mem.get(op.ref) else disk.get(op.ref)
    // Decision as implemented per SPEC-REFS §5.1 / refs.rs RefMutation:
    val ok = match op.cond {
      | Any => (not(op.del)) or actual != ABSENT   // delete_ref: NotFound on the actual file
      | Missing => actual == ABSENT                // O_EXCL / create_new
      | Match(e) => st.observed == e and ((not(op.del)) or actual != ABSENT)
    }
    val newVal = if (op.del) ABSENT else op.value
    val dom = domainOf(op.kind)
    val lost = ok and not(condHolds(op.cond, actual))
    val outcome = if (ok) "ok" else if (op.del and op.cond == Any) "notfound" else "conflict"
    all {
      st.pc == "commit",
      mem' = if (ok and store == "mem") mem.set(op.ref, newVal) else mem,
      disk' = if (ok and store == "disk") disk.set(op.ref, newVal) else disk,
      violations' = if (lost) violations.union(st.pending.map(d => { writer: dom, by: d })) else violations,
      procs' = PROCS.mapBy(q =>
        if (q == p) { ...st, pc: "release", outcome: outcome }
        else {
          val s = procs.get(q)
          if (ok and s.pc == "commit" and storeOf(s.op.kind) == store and s.op.ref == op.ref)
            { ...s, pending: s.pending.union(Set(dom)) }
          else s
        }),
      owner' = owner,
      recLog' = recLog, nextEntry' = nextEntry, faults' = faults,
      lostRecords' = lostRecords, recordDuringExpire' = recordDuringExpire,
      lastAction' = { name: "commitRef", proc: p, op: op, rev: false, lock: -1, outcome: outcome },
    }
  }

  // expireRead / expireWrite: recovery::expire reads, filters, then atomically
  // rewrites the log. Retention is abstracted as "keep the whole snapshot": the
  // property only concerns entries NOT in the snapshot.
  action expireRead(p: Proc): bool = {
    val st = procs.get(p)
    all {
      st.pc == "expireRead",
      procs' = procs.set(p, { ...st, pc: "expireWrite", snapshot: recLog }),
      owner' = owner,
      unchangedData,
      lastAction' = { name: "expireRead", proc: p, op: st.op, rev: false, lock: -1, outcome: "" },
    }
  }

  action expireWrite(p: Proc): bool = {
    val st = procs.get(p)
    all {
      st.pc == "expireWrite",
      recLog' = st.snapshot,
      lostRecords' = lostRecords.union(recLog.exclude(st.snapshot)),
      procs' = procs.set(p, { ...st, pc: "release", outcome: "ok" }),
      owner' = owner,
      disk' = disk, mem' = mem, nextEntry' = nextEntry, faults' = faults,
      violations' = violations, recordDuringExpire' = recordDuringExpire,
      lastAction' = { name: "expireWrite", proc: p, op: st.op, rev: false, lock: -1, outcome: "ok" },
    }
  }

  // release(p): RAII drop of every held guard.
  action release(p: Proc): bool = {
    val st = procs.get(p)
    all {
      st.pc == "release",
      procs' = procs.set(p, IDLE),
      owner' = LOCKS.mapBy(l => if (owner.get(l) == p) FREE else owner.get(l)),
      unchangedData,
      lastAction' = { name: "release", proc: p, op: st.op, rev: false, lock: -1, outcome: st.outcome },
    }
  }

  // Build an op that always satisfies validOp (keeps random simulation from
  // wasting steps on rejected begins).
  pure def mkOp(kind: str, t: int, r: int, c: Cond, v: int, d: bool): Op =
    if (kind == "gc") { kind: kind, tree: 0, ref: 0, cond: Any, value: 1, del: false }
    else {
      kind: kind,
      tree: if (kind == "commit" or kind == "amend" or kind == "updateRef") t else 0,
      ref: r, cond: c, value: v,
      del: d and kind == "branch" and c != Missing,
    }

  // p has an enabled step (only a blocked acquire is disabled).
  def canMove(p: Proc): bool = {
    val st = procs.get(p)
    st.pc != "acquire" or faults.racyAcquire or owner.get(nextLock(st)) == FREE
  }

  action step = {
    nondet p = PROCS.filter(q => canMove(q)).oneOf()
    nondet kind = KINDS.oneOf()
    nondet t = TREES.oneOf()
    nondet r = REFS.oneOf()
    nondet c = Set(Any, Missing, Match(1), Match(2)).oneOf()
    nondet v = VALUES.oneOf()
    nondet d = Set(false, true).oneOf()
    nondet rv = Set(false, true).oneOf()
    any {
      begin(p, mkOp(kind, t, r, c, v, d), rv and faults.misorder),
      acquire(p),
      record(p),
      readRef(p),
      commitRef(p),
      expireRead(p),
      expireWrite(p),
      release(p),
    }
  }

  // ---------------------------------------------------------- invariants
  // Lock bookkeeping: p owns exactly the held prefix of its plan (so kernel
  // locks are exclusive and nobody holds a lock it did not take).
  val LockOwnership: bool =
    LOCKS.forall(l => owner.get(l) != FREE implies {
      val st = procs.get(owner.get(l))
      PLAN_IDX.exists(i => i < st.nHeld and st.plan[i] == l)
    }) and
    PROCS.forall(p => {
      val st = procs.get(p)
      PLAN_IDX.forall(i => i < st.nHeld implies owner.get(st.plan[i]) == p)
    })

  // SPEC-CONCURRENCY §4: every process's held locks were taken in strictly
  // increasing global order.
  val LockOrderRespected: bool =
    PROCS.forall(p => {
      val st = procs.get(p)
      PLAN_IDX.forall(i => (i >= 1 and i < st.nHeld) implies st.plan[i - 1] < st.plan[i])
    })

  def waitsFor(p: Proc, q: Proc): bool = {
    val st = procs.get(p)
    p != q and st.pc == "acquire" and owner.get(nextLock(st)) == q
  }

  // No wait-for cycle (exhaustive for |PROCS| = 3: 2- and 3-cycles).
  val NoDeadlock: bool =
    not(PROCS.exists(p => PROCS.exists(q =>
      waitsFor(p, q) and (waitsFor(q, p) or PROCS.exists(r => waitsFor(q, r) and waitsFor(r, p))))))

  // SPEC-REFS §5.1 + direct local mixed-mutation contract: within the local
  // refs-<ref>.lock domain, no successful conditional write is based on a
  // value another local writer changed underneath it.
  val NoLostUpdateLocal: bool = not(violations.contains({ writer: "local", by: "local" }))
  // Same for the file transport's RefLock domain.
  val NoLostUpdateFile: bool = not(violations.contains({ writer: "file", by: "file" }))
  val NoLostUpdateWithinDomain: bool = NoLostUpdateLocal and NoLostUpdateFile

  // SPEC-CONCURRENCY §3.2: whenever expire is mid-rewrite, gc holds every
  // registered tree's worktree.lock (the superset that excludes producers)...
  val ExpireHoldsSuperset: bool =
    PROCS.forall(p => procs.get(p).pc == "expireWrite" implies TREES.forall(t => owner.get(wtLock(t)) == p))
  // ...hence record and expire never interleave and no entry is lost.
  val NoRecordExpireInterleave: bool = not(recordDuringExpire) and lostRecords == Set()

  val Safety: bool = and {
    LockOwnership, LockOrderRespected, NoDeadlock, NoLostUpdateWithinDomain,
    ExpireHoldsSuperset, NoRecordExpireInterleave,
  }

  // ---------------------------------------------- witnesses (expected FALSE)
  // Documented §5.1 exception: memory-transport .match is a read-then-write race.
  val WitnessMemMatchRace: bool = not(violations.contains({ writer: "mem", by: "mem" }))
  // DOCUMENTED GAP (SPEC-CONCURRENCY §3.1, SPEC-REFS §5.1 "There is no rule
  // that closes this gap"): a local ref write and a file-transport CAS on the
  // same root are not serialized. Expected reachable; not a bug.
  val WitnessCrossDomainGap: bool =
    not(violations.contains({ writer: "local", by: "file" }) or violations.contains({ writer: "file", by: "local" }))
  // Reachability canaries: the interesting states are actually visited.
  val WitnessMatchConflict: bool =
    not(lastAction.name == "commitRef" and lastAction.outcome == "conflict" and lastAction.op.kind == "commit")
  val WitnessConditionalDelete: bool =
    not(lastAction.name == "commitRef" and lastAction.outcome == "ok" and lastAction.op.del and lastAction.op.cond != Any)
  val WitnessGcExpires: bool = not(lastAction.name == "expireWrite" and recLog != Set())
  val WitnessTwoLocksContended: bool =
    not(PROCS.exists(p => PROCS.exists(q => waitsFor(p, q) and procs.get(q).nHeld >= 2)))
}

// ------------------------------------------------------------ instances
// FAULTS literal: { misorder, noRefLock, noFileLock, gcSkipTrees, racyAcquire }.
// 3 processes: every wait-for cycle shape (2- and 3-cycles). quint run.
module refs3 {
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).*
}
// 2 processes: Apalache instance (lost update, cross-domain gap, 2-cycle
// deadlock and record/expire interleaving all need only 2 processes).
module refs2 {
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).*
}
// Mutants (non-vacuity): each must violate the named invariant.
module refs3_misorder {    // NoDeadlock, LockOrderRespected
  import refs(PROCS = Set("p1", "p2", "p3"),
              FAULTS = { misorder: true, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).*
}
module refs2_misorder {    // NoDeadlock, LockOrderRespected
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: true, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).*
}
module refs2_noRefLock {   // NoLostUpdateLocal
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: false, noRefLock: true, noFileLock: false, gcSkipTrees: false, racyAcquire: false }).*
}
module refs2_noFileLock {  // NoLostUpdateFile
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: true, gcSkipTrees: false, racyAcquire: false }).*
}
module refs2_gcSkipTrees { // NoRecordExpireInterleave, ExpireHoldsSuperset
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: true, racyAcquire: false }).*
}
module refs2_racyAcquire { // LockOwnership
  import refs(PROCS = Set("p1", "p2"),
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: true }).*
}
