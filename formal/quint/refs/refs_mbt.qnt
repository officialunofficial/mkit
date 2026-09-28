// -*- mode: Bluespec; -*-
// Trace generation for model-based conformance (Linear MKIT-22, epic
// MKIT-17): `formal/scripts/gen-refs-traces.sh` runs
//   quint run refs_mbt.qnt --main refs_mbt2 --init initLin --step stepLin --mbt --out-itf ...
// and the Rust harness
//   rust/crates/mkit-formal-conformance/tests/formal_refs_conformance.rs
// replays every step of every trace against the real `mkit_core::refs`
// functions, `FileTransport` and `MemoryTransport`.
//
// Additive only: this file changes nothing in refs.qnt. It instantiates
// the real model (NO_FAULTS) and adds one scheduler restriction,
// `stepLin`, so that every generated trace is LINEARIZABLE at the ref
// level and can therefore be replayed with the real, atomic, API calls:
//
//   A disk readRef of one lock domain is not scheduled while a process of
//   ANOTHER disk domain (local chain vs file transport) has read the same
//   ref and not yet committed.
//
// Within one domain the model's own locks already serialize
// read-check-write (NoLostUpdateLocal / NoLostUpdateFile / NoLostUpdateMem);
// the restriction only removes the documented SPEC-CONCURRENCY §3.1 /
// SPEC-REFS §5.1 cross-domain gap (`WitnessCrossDomainGap`), which an
// atomic API call cannot reproduce. Consequently the generator checks
// `LinSafety` (Safety AND WitnessCrossDomainGap) on every trace, and the
// harness independently checks that every replayed commit saw the value it
// read (so a gap step that slipped through would fail the test loudly
// instead of being compared against the wrong expectation).
//
// The restriction never blocks progress: the process it holds back can
// move once the other process commits, and commitRef has no guard.
module refsLin {
  const LIN_PROCS: Set[str]
  import refs(PROCS = LIN_PROCS,
              FAULTS = { misorder: false, noRefLock: false, noFileLock: false, gcSkipTrees: false, racyAcquire: false, memNoMutex: false }).* from "./refs"

  // Another process of a different disk domain holds an uncommitted read
  // of the same on-disk ref.
  def crossDomainReadOpen(p: Proc): bool = {
    val st = procs.get(p)
    storeOf(st.op.kind) == "disk" and PROCS.exists(q => {
      val s = procs.get(q)
      q != p and s.pc == "commit" and storeOf(s.op.kind) == "disk"
        and s.op.ref == st.op.ref and domainOf(s.op.kind) != domainOf(st.op.kind)
    })
  }

  def canMoveLin(p: Proc): bool =
    canMove(p) and (procs.get(p).pc != "read" or not(crossDomainReadOpen(p)))

  action stepLin = {
    nondet p = PROCS.filter(q => canMoveLin(q)).oneOf()
    any {
      beginAny(p),
      acquire(p),
      record(p),
      readRef(p),
      commitRef(p),
      expireRead(p),
      expireWrite(p),
      release(p),
    }
  }

  // The model's own nondeterministic init (every disk/mem start value),
  // re-exported under a local name for `quint run --init initLin`.
  action initLin = init
  // The unrestricted step, for the generator's sanity check that the
  // restriction is load-bearing (it must reach WitnessCrossDomainGap).
  action stepAll = step

  // What every generated trace must satisfy: refs.qnt's Safety, and no
  // cross-domain lost update (refs.qnt's WitnessCrossDomainGap, which the
  // unrestricted `step` reaches).
  val NoCrossDomainGap: bool = WitnessCrossDomainGap
  val LinSafety: bool = Safety and NoCrossDomainGap
}

module refs_mbt2 {
  import refsLin(LIN_PROCS = Set("p1", "p2")).*
}

module refs_mbt3 {
  import refsLin(LIN_PROCS = Set("p1", "p2", "p3")).*
}
