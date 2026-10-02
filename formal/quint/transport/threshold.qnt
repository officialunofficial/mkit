// -*- mode: Bluespec; -*-
// t-of-n release-threshold aggregation and share rotation (transport model,
// epic verification toolchain, workstream quint-transport).
//
// SPEC-RELEASE-THRESHOLD (draft-normative) §2 trust model, §4 verifier, §5.2
// per-release ceremony, §5.3 rotation (resharing that keeps the cohort public
// key), §8 invariants; code: `mkit_attest::signer_bls_threshold::{aggregate,
// verify, threshold_for}` over commonware-cryptography 2026.9.0
// (`threshold::recover` = `prepare_evaluations` + Lagrange interpolation).
//
// Target properties (transport model (c)):
//   - an aggregate verifies IFF it was built from at least t distinct valid
//     partials of the current share set (soundness: `NoForgery`,
//     `AggregateFromOneShareSet`; completeness: `AggregateCompleteness`);
//   - rotation never lets old shares combine with new ones
//     (`AggregateFromOneShareSet`).
//
// Abstraction: signatures are symbolic, no crypto. A partial is a record
// (holder index, share-set epoch, message, valid). A share set ("epoch") is a
// degree-(T-1) polynomial with the cohort secret as constant term; resharing
// (§5.3) deals a FRESH polynomial with the same constant term, so the cohort
// public key, and hence the verifier's pin, never changes. Recovery
// interpolates the T chosen evaluations: the result is the cohort signature on
// m iff all T are valid signatures on m by shares of ONE polynomial (mixing
// evaluations of two polynomials interpolates to an unrelated point, fewer
// than T cannot determine the constant term). `verify` accepts exactly the
// cohort signature on the message it is asked about, under the namespace
// (§3.7, §4 step 5).
//
// What `aggregate` does (the code, not the spec's prose): decode every
// partial; `recover` deduplicates by participant index keeping the FIRST
// occurrence in input order, sorts by index, keeps the T LOWEST indices and
// interpolates them. It does not verify partials: its rustdoc says "the
// aggregator is expected to have already verified each partial individually
// (the future release-party CLI does this)", and §5.2 step 4 does not say it.
// `thr` models the coordinator that does (commonware
// `batch_verify_same_message` against the CURRENT sharing, then aggregate);
// `thr_asImpl` models a coordinator that calls `aggregate` directly.
//
// Adversary: may compromise up to F holders per share set (learning their
// current share), sign anything with a known share, and post garbage
// partials under any index; honest holders sign only the release message
// "rel". Whether a rotated-out share is erased is an ASSUMPTION the spec does
// not state (`retainOld` drops it). The coordination channel is the pool: the
// coordinator aggregates every partial posted for a message (the adversary
// controls which of two same-index partials comes first).
//
// Checks: ./check.sh (README.md lists each command and its expected outcome).
module thresholdCore {
  type Partial = { h: int, e: int, m: str, valid: bool }
  type TFaults = {
    noFilter: bool,           // coordinator calls `aggregate` without verifying partials
    filterAnyEpoch: bool,     // partials verified against ANY past sharing, not the current one
    noRefresh: bool,          // resharing reuses the old polynomial (old + new shares combine)
    retainOld: bool,          // ASSUMPTION OFF: rotated-out shares are not erased
    verifierIgnoresMsg: bool, // verify does not bind the message / namespace
  }

  const N: int      // holders per share set
  const T: int      // threshold (sharing.required())
  const F: int      // holders the adversary may compromise per share set
  const MAXE: int   // last epoch (number of rotations)
  const FAULTS: TFaults

  pure val HOLDERS: Set[int] = 0.to(N - 1)
  pure val MSGS: Set[str] = Set("rel", "evil")

  // --------------------------------------------------------------- state
  var cur: int                   // current share-set epoch
  var pool: Set[Partial]         // partials posted to the coordination channel
  var known: Set[(int, int)]     // (holder, epoch) shares the adversary holds
  var compromisedNow: Set[int]   // holders compromised in the current epoch
  var sigs: Set[str]             // messages with a recovered cohort signature
  // ghosts
  var recoveredMixed: bool       // a recovered cohort signature used shares of two polynomials
  var incomplete: bool           // an aggregation with T current valid partials failed
  var rotatedWithSig: bool       // a release signature was recovered after a rotation (canary)
  var staleRecovered: bool       // a signature was recovered from a rotated-out share set (witness)
  var faults: TFaults
  var lastAction: str

  // The polynomial behind an epoch's shares.
  def poly(e: int): int = if (faults.noRefresh) 0 else e

  action initWith(f: TFaults): bool = all {
    cur' = 0, pool' = Set(), known' = Set(), compromisedNow' = Set(), sigs' = Set(),
    recoveredMixed' = false, incomplete' = false, rotatedWithSig' = false, staleRecovered' = false,
    faults' = f, lastAction' = "init",
  }
  action init = initWith(FAULTS)

  action keepGhosts = all {
    recoveredMixed' = recoveredMixed, incomplete' = incomplete, rotatedWithSig' = rotatedWithSig,
    staleRecovered' = staleRecovered, faults' = faults,
  }

  // An honest holder signs the release PAE with its current share (§5.2 step 3).
  action honestSign(h: int): bool = all {
    pool' = pool.union(Set({ h: h, e: cur, m: "rel", valid: true })),
    cur' = cur, known' = known, compromisedNow' = compromisedNow, sigs' = sigs, keepGhosts,
    lastAction' = "honestSign",
  }

  // The adversary compromises holder h: it learns h's current share, and,
  // unless erased at rotation, h's earlier shares.
  action compromise(h: int): bool = all {
    compromisedNow.size() < F, not(compromisedNow.contains(h)),
    val old = if (faults.retainOld) 0.to(MAXE).filter(e => e <= cur).map(e => (h, e)) else Set((h, cur))
    all {
      known' = known.union(old), compromisedNow' = compromisedNow.union(Set(h)),
      cur' = cur, pool' = pool, sigs' = sigs, keepGhosts, lastAction' = "compromise",
    }
  }

  // The adversary signs m with a share it holds.
  action advSign(h: int, e: int, m: str): bool = all {
    known.contains((h, e)),
    pool' = pool.union(Set({ h: h, e: e, m: m, valid: true })),
    cur' = cur, known' = known, compromisedNow' = compromisedNow, sigs' = sigs, keepGhosts,
    lastAction' = "advSign",
  }

  // The adversary posts a garbage partial under index h for m.
  action advGarbage(h: int, m: str): bool = all {
    pool' = pool.union(Set({ h: h, e: cur, m: m, valid: false })),
    cur' = cur, known' = known, compromisedNow' = compromisedNow, sigs' = sigs, keepGhosts,
    lastAction' = "advGarbage",
  }

  // §5.3 resharing: a fresh share set for the same cohort key. The new
  // cohort may differ; indices are reused.
  action rotate: bool = all {
    cur < MAXE,
    cur' = cur + 1, compromisedNow' = Set(),
    pool' = pool, known' = known, sigs' = sigs, keepGhosts, lastAction' = "rotate",
  }

  // A partial passes the coordinator's check against the current sharing
  // (`partial_public(index)` of the CURRENT polynomial).
  def passesFilter(p: Partial, m: str): bool =
    p.valid and p.m == m and (if (faults.filterAnyEpoch) p.e <= cur else poly(p.e) == poly(cur))

  // Aggregate everything posted for m. `pick` resolves same-index duplicates
  // (the first occurrence in input order, adversary-controlled): for each
  // index it names the partial kept. `coord`: the honest coordinator (filters
  // unless noFilter; its failures count against completeness); otherwise the
  // adversary, which calls `aggregate` on whatever it likes: the verifier
  // cannot tell who aggregated.
  action aggregate(m: str, pick: int -> Partial, coord: bool): bool = all {
    val posted = pool.filter(p => p.m == m)
    val input = if (not(coord) or faults.noFilter) posted else posted.filter(p => passesFilter(p, m))
    val idx = input.map(p => p.h)
    all {
      idx.size() >= T,
      idx.forall(i => pick.keys().contains(i) and input.contains(pick.get(i)) and pick.get(i).h == i),
      // prepare_evaluations: sort by index, truncate to the T lowest.
      val lowest = idx.filter(i => idx.filter(j => j < i).size() < T)
      val chosen = lowest.map(i => pick.get(i))
      val polys = chosen.map(p => poly(p.e))
      val ok = chosen.forall(p => p.valid and p.m == m) and polys.size() == 1
      val quorumAvail = pool.filter(p => p.valid and p.m == m and poly(p.e) == poly(cur)).map(p => p.h).size() >= T
      all {
        sigs' = if (ok) sigs.union(Set(m)) else sigs,
        recoveredMixed' = (recoveredMixed or (ok and chosen.map(p => p.e).size() > 1)),
        incomplete' = (incomplete or (coord and quorumAvail and not(ok))),
        rotatedWithSig' = (rotatedWithSig or (ok and cur > 0)),
        staleRecovered' = (staleRecovered or (ok and chosen.exists(p => p.e != cur))),
        cur' = cur, pool' = pool, known' = known, compromisedNow' = compromisedNow,
        faults' = faults, lastAction' = "aggregate",
      }
    }
  }

  // An aggregation where the coordinator's dedup keeps, per index, any posted
  // partial for m (the nondeterministic choice covers every input order).
  action aggregateAny(m: str, coord: bool): bool = {
    val cands = pool.filter(p => p.m == m)
    val idx = cands.map(p => p.h)
    nondet pick = idx.setOfMaps(cands).oneOf()
    aggregate(m, pick, coord)
  }

  action step = any {
    { nondet h = HOLDERS.oneOf() honestSign(h) },
    { nondet h = HOLDERS.oneOf() compromise(h) },
    // Adversary moves that matter (the others are subsumed): signing "rel"
    // with a known share adds nothing honest holders cannot post, and
    // garbage under "evil" cannot help an "evil" aggregate verify.
    { nondet h = HOLDERS.oneOf() nondet e = 0.to(MAXE).oneOf() advSign(h, e, "evil") },
    { nondet h = HOLDERS.oneOf() advGarbage(h, "rel") },
    rotate,
    { nondet m = MSGS.oneOf() aggregateAny(m, true) },
    { nondet m = MSGS.oneOf() aggregateAny(m, false) },
  }

  // --------------------------------------------------------------- safety
  // §4: verify accepts the cohort signature on the message asked about.
  def accepts(m: str): bool = sigs.exists(s => s == m or faults.verifierIgnoresMsg)
  // No release signature on a message no T holders of one share set signed:
  // honest holders only sign "rel", and the adversary holds < T shares of any
  // one share set. (§8 "No single maintainer can produce a valid release
  // signature", generalized to any coalition below the threshold.)
  val NoForgery: bool = not(accepts("evil"))
  // Rotation never lets old shares combine with new ones: every recovered
  // cohort signature comes from partials of ONE share set.
  val AggregateFromOneShareSet: bool = not(recoveredMixed)
  // Completeness: T distinct valid partials of the current share set on m
  // always aggregate to a verifying signature, whatever else was posted.
  val AggregateCompleteness: bool = not(incomplete)
  // Soundness (the "only if" half), stated on the verifier's verdict rather
  // than on how the model recovers: a message is accepted only if T distinct
  // holders of ONE share set posted valid partials on it. It cannot say "the
  // CURRENT share set": no partial, aggregate or pin carries an epoch (§3.1,
  // §3.2, §5.3), so T partials of a rotated-out set verify forever
  // (CanaryNoStaleAggregate is reachable; see README finding on erasure).
  def shareSetQuorum(m: str): bool = 0.to(MAXE).exists(e =>
    pool.filter(p => p.valid and p.m == m and p.e == e).map(p => p.h).size() >= T)
  val AcceptedOnlyFromShareSetQuorum: bool = MSGS.forall(m => accepts(m) implies shareSetQuorum(m))
  val Safety: bool = and {
    NoForgery, AggregateFromOneShareSet, AggregateCompleteness, AcceptedOnlyFromShareSetQuorum,
  }

  // --------------------------------------------------------------- canaries
  val CanaryNoRelease: bool = not(accepts("rel"))
  val CanaryNoReleaseAfterRotation: bool = not(rotatedWithSig)
  // Reachable (witness, not a defect by itself): after a rotation, T partials
  // of the rotated-out share set still recover a verifying signature.
  val CanaryNoStaleAggregate: bool = not(staleRecovered)
  val CanaryNoCompromiseSign: bool = not(pool.exists(p => p.valid and p.m == "evil"))
  val CanaryNoGarbageSurvived: bool =
    not(accepts("rel") and pool.exists(p => not(p.valid) and p.m == "rel"))
}

// Threshold arithmetic of the code (commonware N3f1) vs the spec's prose.
module quorum {
  // commonware_utils::N3f1: f = (n-1)/3, quorum = n - f.
  pure def n3f1Quorum(n: int): int = n - (n - 1) / 3
  // SPEC-RELEASE-THRESHOLD §2.1 item 3, §8 and the rustdoc: ceil(2n/3).
  pure def specQuorum(n: int): int = (2 * n + 2) / 3
  // Holds for every n (documented as a finding: it is false for n = 3k).
  pure val SpecFormulaMatchesCode: bool = 1.to(13).forall(n => n3f1Quorum(n) == specQuorum(n))
  // What does hold: the code's quorum is never below the spec's, so the spec
  // never overstates the adversary's requirement.
  pure val CodeQuorumAtLeastSpec: bool = 1.to(13).forall(n => n3f1Quorum(n) >= specQuorum(n))
  // "No single maintainer can produce a valid release signature" needs n >= 2.
  pure val NoSingleSigner: bool = 2.to(13).forall(n => n3f1Quorum(n) >= 2)
}

// FAULTS literal order: noFilter, filterAnyEpoch, noRefresh, retainOld, verifierIgnoresMsg.
module thr {                    // 3 holders, t = 2, 1 compromise per share set, 1 rotation
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).*
}
module thr4 {                   // the N3f1 cohort of §2.1: 4 holders, t = 3, F = 2 (quint run / Apalache)
  import thresholdCore(N = 4, T = 3, F = 2, MAXE = 2, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).*
}
module thr_asImpl {             // FINDING: AggregateCompleteness (aggregate without partial verification)
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: true,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).*
}
module thr_filterAnyEpoch {     // AggregateCompleteness
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: true, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).*
}
module thr_noRefresh {          // AggregateFromOneShareSet, NoForgery
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: true, retainOld: false, verifierIgnoresMsg: false }).*
}
module thr_retainOld {          // ASSUMPTION WITNESS: NoForgery (rotated-out shares not erased)
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: true, verifierIgnoresMsg: false }).*
}
module thr_verifierIgnoresMsg { // NoForgery
  import thresholdCore(N = 3, T = 2, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: true }).*
}
module thr_t1 {                 // NoForgery: a 1-of-n deal (one maintainer signs alone)
  import thresholdCore(N = 3, T = 1, F = 1, MAXE = 1, FAULTS = { noFilter: false,
    filterAnyEpoch: false, noRefresh: false, retainOld: false, verifierIgnoresMsg: false }).*
}
