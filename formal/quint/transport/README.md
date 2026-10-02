# quint-transport: requested identities, shard quorum, release threshold

Quint transport models (formal verification effort, PR #1082), checked against the
specs on this branch. The spec text is normative. Each model says which Rust
code it follows. Where the code and the spec disagree, the model follows the
code and the difference is listed under "Findings".

| File | What it models |
|------|----------------|
| `identity.qnt` | INVARIANTS.md "Requested transport identities are checked before effects". A fetch of a packlist head and its pack from an adversarial server that returns internally valid substitutes. Covers SPEC-PACK-SHARDS §2 (the requested PackKey is the root of trust), §3, §4.2 (2c and 5) and SPEC-TRANSPORT's "Consumers MUST verify". Monolithic and sharded delivery (HTTP and S3) |
| `identity_test.qnt` | Pinned scenarios: honest paths, substituted node, foreign manifest, a manifest that lies about its shards, a substituted monolithic pack, and a witness for each mutant |
| `shards.qnt` | INVARIANTS.md "Shard worker bounds do not delay an available quorum". Models `mkit_core::pack_shard::download::download_shards`: non-blocking admission under the process-wide `MAX_SHARD_WORKERS`, quorum or failure threshold, cancellation of stragglers, and the decode that follows (SPEC-PACK-SHARDS §5, §4.2) |
| `shards_test.qnt` | Pinned scenarios: quorum past a stalled shard while a foreign straggler holds a slot, receiving while the pool is full, the failure threshold, a cancelled worker, the mutants, and the corrupt-shard finding |
| `threshold.qnt` | SPEC-RELEASE-THRESHOLD: t-of-n aggregation (`mkit_attest::signer_bls_threshold::aggregate` / commonware `threshold::recover`), `verify`, and §5.3 rotation. Signatures are symbolic. Module `quorum` compares the N3f1 arithmetic with the spec's text |
| `threshold_test.qnt` | Pinned scenarios: the quorum table, filtered and unfiltered aggregation, epochs that never combine, the no-refresh and retained-share witnesses, and a rotated-out share set that still verifies |
| `check.sh` | Runs every check below and compares each result with the expected outcome |

## Properties

### identity.qnt (transport model a)

The adversary answers each request with any valid object in the universe:
- another branch's packlist node;
- a real pack under another key;
- a consistent manifest plus shard set for another pack;
- a manifest that names the requested pack but commits to another pack's shards;
- shards taken from a different set.

BLAKE3 is modelled as the identity on contents (collision resistance is
assumed).

| Invariant | Meaning | Mutant that breaks it |
|---|---|---|
| `NodeMatchesRequest` | The packlist node that gets followed is the one requested (`download_packlist_node`: `verify_bytes` runs before decode) | `identity_nodeNoVerify` |
| `ShardsOnlyForRequestedManifest` | No shard is requested under a manifest naming another pack (T1: `manifest.pack_hash != key` is checked before `download_shards`) | `identity_noManifestPrecheck` |
| `ReconstructOnlyForRequested` | No reconstruction happens under a manifest naming another pack | `identity_noManifestChecks` (T1 and T2 off). With T1 off alone it still holds, because `decode_downloaded_pack` re-checks (T2) |
| `ShardPathReturnsRequested` | The sharded transport returns only the requested pack (§4.2 step 5 plus `key.verify_bytes`) | `identity_noPostDecodeCheck` |
| `PackMatchesRequest` | Every published pack is the one requested for it | `identity_consumerNoVerify` (monolithic path), `identity_noPackChecks` (shard path too) |
| `PublishedWithinRequestedClosure` | Nothing outside the requested head's closure is published | `identity_nodeNoVerify` |

The layers back each other up. Removing any single transport-side check
leaves `PackMatchesRequest` intact, because the consumer checks (C1 in
`fetch_packs`, C2 in `unpack_downloaded_packs`) still catch the substitute.
`check.sh` asserts that too. Canaries confirm that each of these is
reachable: a monolithic publish, a sharded publish, a rejection, and a
substitution that gets rejected. A substituted fetch never publishes
anything, because a fetch that sees `InvalidResponse` does not retry. That is
why no canary asks for a publish after a substitution.

### shards.qnt (transport model b)

Each shard index has a fixed behaviour:
- `ok`: valid and prompt;
- `fail`: a prompt error;
- `slow`: stalls until `SHARD_REQUEST_TIMEOUT`;
- `bad`: a prompt `200` with bytes that do not match the manifest.

Other downloads in the same process hold `foreign` slots, which they release
one at a time.

| Invariant | Meaning | Mutant / witness |
|---|---|---|
| `SlotBound` | The process-wide worker bound is never exceeded | `shards_noSlotCheck` |
| `OkHasQuorum` | Ok or invalid only after exactly `minimum_shards` Ok results | `shards_earlyQuorum` |
| `NotFoundPastThreshold` | `PackNotFound` only after `extra_shards + 1` failures | `shards_offByOne` |
| `NoFalseNotFound` | Never `PackNotFound` while `minimum_shards` shards would answer | `shards_offByOne` |
| `NoDisconnect` | The collector decides before its channel disconnects | `shards_noFailureThreshold` |
| `NoAttemptAfterDecision` | After the decision, no worker makes another request. The ghost is set whenever a worker makes a request while the collector has already returned, whatever let it through | `shards_noCancel` (workers ignore the token), `shards_noGroupCancel` (returning does not cancel the `DownloadGroup`) |
| `QuorumNotBlockedByAdmission` | Admission never keeps the collector from receiving a quorum that has already arrived | `shards_blocking` (blocking acquire before collecting) |
| `DecodeFailsOnlyWithoutHonestQuorum` | **Documented gap**: holds for honest environments (`shards`) and is violated by `shards_bad` (see Findings) | - |

Progress is checked by TLC only. The fairness assumptions are stated in
`check.sh` (`tlcl`):

- **P1** `QuorumArrived ~> Decided`, assuming weak fairness on the collector
  **only**. It holds even if no worker, straggler or timeout ever makes
  progress, so receiving results that have already arrived never needs a
  slot. This is the INVARIANTS.md statement. `shards_blocking` fails it
  (TLC exit 13; the trace shows two results queued, a full pool, and then
  stuttering).
- **P2** `HonestQuorumAvailable => <>DecidedOk`. The precondition is: at
  least `minimum_shards` shards are `ok`, none are `bad`, and fewer than
  `MAX_SHARD_WORKERS` are stalled. Fairness: the collector, every prompt
  worker's finish and thread exit, and foreign stragglers timing out. Own
  stalled shards get no fairness, so a stall may last forever and must not
  delay the result. P2 fails for these three:
  - `shards_recvBlocking` (a `recv()` with no timeout: after a foreign slot
    frees, the parked collector never retries admission; the trace ends
    `park`, then `foreignRelease`, then stuttering);
  - `P2NoForeignFairness` (canary);
  - `P2Corrupt` in `shards_bad` (finding).
- **P2AnyStall** drops the stall bound. It holds for `shards` (N=2, K=1,
  2 slots). It fails for `shards_tight` (N=1, K=2, 2 slots, two stalled
  shards). This documents a bound (see Findings).

### threshold.qnt (transport model c)

A partial is `(holder, share-set epoch, message, valid)`.

- Recovery follows the code. It deduplicates by index (the first occurrence
  wins, in an order the adversary controls), keeps the T **lowest**
  indices, and succeeds iff all T are valid signatures on m from one
  polynomial.
- Resharing deals a fresh polynomial with the same constant term, so the
  cohort key and the verifier pin never change (§5.3).
- The adversary compromises up to F holders per share set (F = T-1, the
  maximum that is still safe). It can sign anything with a share it knows,
  post garbage under any index, and run `aggregate` itself.
- Honest holders sign only `rel`.

| Invariant | Meaning | Mutant / witness |
|---|---|---|
| `NoForgery` | No verifying signature on a message that fewer than T holders of one share set signed (§8 "no single maintainer", generalized) | `thr_noRefresh`, `thr_verifierIgnoresMsg`, `thr_t1` (a 1-of-n deal); **assumption witness** `thr_retainOld` |
| `AggregateFromOneShareSet` | Rotation never lets old shares combine with new ones | `thr_noRefresh` |
| `AggregateCompleteness` | T distinct valid current-set partials always aggregate to a verifying signature, whatever else was posted (the "if" half of "iff") | `thr_filterAnyEpoch`; **finding** `thr_asImpl` |
| `AcceptedOnlyFromShareSetQuorum` | The "only if" half, stated on the verifier's verdict: a message is accepted only if T distinct holders of ONE share set posted valid partials on it. It says "one share set", not "the current share set", because nothing binds an epoch (see finding 6 and `CanaryNoStaleAggregate`) | `thr_noRefresh`, `thr_verifierIgnoresMsg`; holds in `thr_retainOld` (the forgery there uses a real old-set quorum) |

`thr` models a coordinator that verifies each partial against the current
sharing (commonware `batch_verify_same_message`) before calling `aggregate`.
`thr_asImpl` calls `aggregate` directly, as the code allows. Canaries:
- a release verifies;
- a release verifies after a rotation;
- the adversary signs `evil`;
- a release verifies despite a garbage partial;
- `CanaryNoStaleAggregate` (witness): after a rotation, T partials of the
  rotated-out share set still recover a verifying signature
  (`staleShareSetStillVerifiesTest`).

## Findings (discrepancies between the code and the specs or INVARIANTS)

1. **A corrupted shard defeats an available quorum** (spec gap; liveness
   only, still fails closed). `download_shards` counts every worker
   `Ok(shard)` toward `minimum_shards` before any hash check.
   `decode_shard_iter` then stops at the first `ShardHashMismatch`
   (§4.2 2c). One bad shard among the first `minimum_shards` responses
   therefore fails the download with `InvalidResponse`, even when
   `minimum_shards` valid shards are available and the `extra_shards`
   redundancy is unused. Witnesses: `shards_bad::DecodeFailsOnlyWithoutHonestQuorum`,
   `shards_bad::P2Corrupt`, and `shards_bad_test`. §5 promises tolerance
   of "up to `extra_shards` failures", but a corrupted `200` is not counted
   as a failure. Possible fix: have the worker check `BLAKE3(bytes)`
   against `manifest.shard_hashes[index]`, since the manifest is known
   before `download_shards`, and return `Err` on a mismatch.
2. **SPEC-PACK-SHARDS §5 describes the old client** (doc drift). It says
   "one std thread per shard URL, collect the first `minimum_shards`". The
   code admits workers in index order under the process-wide
   `MAX_SHARD_WORKERS = 32`, with non-blocking admission and a 10 ms
   re-poll. The spec does not mention the bound.
3. **The worker bound can delay an honest quorum** (documented bound,
   informational). INVARIANTS.md's claim covers responses that have
   *arrived* (P1 holds). Before responses arrive, admission is in index
   order, and a slot is held until its worker exits. Stalled shards of this
   download can hold every slot, and valid shards are then not admitted
   until those stalls hit `SHARD_REQUEST_TIMEOUT` (`shards_tight::P2AnyStall`).
   P2 gives other downloads' stragglers fairness (they time out), so the
   delay the checker exhibits needs this download's own stalled shards to
   fill the pool: at least `MAX_SHARD_WORKERS = 32` of them. With the
   client's advertised `16+4` at most 4 shards can stall while 16 stay
   valid, so this cannot happen; a server that answers with a manifest of
   `extra_shards >= 32` (the config is the server's, up to 256 shards) can
   cause it, and could stall its responses anyway. Slots held by foreign
   stragglers delay admission only until those stragglers time out.
   (Review correction: an earlier draft said "at least 13 foreign slots".)
4. **SPEC-RELEASE-THRESHOLD's quorum formula is wrong for n = 3k** (doc
   drift). §2.1 item 3, §8 and the rustdoc (`signer_bls_threshold.rs`
   `aggregate`, `trusted_dealer`) say quorum = ceil(2n/3). The code uses
   commonware `N3f1::quorum(n) = n - floor((n-1)/3)`. The two agree for
   n = 4 and n = 7, the spec's examples. They differ for n = 3 (3, not 2),
   n = 6 (5, not 4), n = 9 (7, not 6), and so on (`quorum` module,
   `threshold_test::quorumTableTest`). The code is the stricter of the
   two, so no safety claim is lost. Liveness claims made from the spec's
   formula are too optimistic.
5. **`aggregate` is complete only behind a verifying coordinator** (spec
   gap). `aggregate` does not verify partials. `recover` keeps the T
   lowest indices after deduplication, and the first occurrence of an index
   wins. So a garbage partial at a low index, or a garbage duplicate posted
   first, makes aggregation fail even when at least t valid partials are
   present (`thr_asImpl::AggregateCompleteness`,
   `unfilteredAggregateIncompleteTest`). The rustdoc hands per-partial
   verification to "the future release-party CLI". §5.2 step 4 does not
   require it. Also, the rustdoc's "recovery failed (e.g. duplicate
   indices)" is inaccurate: duplicate indices are silently deduplicated.
6. **Rotation safety rests on erasing old shares, which the spec never
   states** (spec gap, for the not-yet-implemented §5.3). The cohort key is
   unchanged, and neither the partial's wire form (§3.1: index and value)
   nor the `BlsShareRecord` AAD (§7: cohort key, index, threshold, total)
   carries a share-set epoch. So T shares of *any* past share set still
   produce a signature that verifies under today's pin. Suppose rotated-out
   shares are not erased, and the adversary compromises one holder per
   share set. With n = 3 and t = 2 it can then forge
   (`thr_retainOld::NoForgery`, `retainedOldSharesForgeTest`). §8's
   "Maintainer rotation never invalidates existing verifier pins" is the
   same property seen from the other side. A stale share record from a
   same-(t, n) reshare also cannot be told apart at load time. Even with
   erasure, "an aggregate verifies only if built from the *current* share
   set" does not hold: partials of a rotated-out set that were already
   posted still recover a verifying signature after rotation
   (`CanaryNoStaleAggregate`). That is harmless for messages the old
   holders chose to sign, so the model checks the achievable form,
   `AcceptedOnlyFromShareSetQuorum` (one share set, any epoch).
7. **Informational (identity):**
   - All checks hold for the code as it is.
   - The monolithic `download_pack` paths (HTTP, S3 fallback, SSH, Connect)
     return bodies without verifying them. The requested-key check is the
     consumer's, as SPEC-TRANSPORT requires ("Consumers MUST verify"), and
     `packmap` is the only production caller.
   - The `Transport::download_pack` / `download_blob` rustdoc does not say
     the caller must verify, so a new caller could miss it.
   - The adversary can force a downgrade to monolithic delivery (HTTP: a
     malformed `X-Pack-Shards`; S3: a manifest `404`). That is harmless
     because the consumer checks.

8. **Not modelled: the process-wide byte budget** (informational,
   unverified). `DownloadedShard::read` reserves bytes against
   `MAX_BUFFERED_SHARD_BYTES = PACK_BODY_LIMIT + 1 MiB`, and a refused
   reservation is a terminal `PayloadTooLarge` that the collector counts as
   a shard failure. All `N + K` shards of one download read concurrently
   (up to `(N+K)/N` of the pack size), so for a pack near
   `PACK_BODY_LIMIT` budget refusals may be spread across shards and could
   exceed `extra_shards`, returning `PackNotFound` although every shard is
   valid. `shards.qnt` does not model the budget, so `NoFalseNotFound` and
   P2 say nothing about this; it is a hypothesis for a Rust test, not a
   checked result.

### Non-vacuity notes

- identity.qnt: the per-shard hash check (§4.2 2c) has no mutant of its
  own. Dropping it (`hashesOk = true`) leaves every invariant intact because
  step 5 and T3 reject the reconstructed substitute. It is an integrity
  layer, not an identity one.
- shards.qnt: `NoAttemptAfterDecision` originally read a ghost that only
  the `noCancel` flag could set, so a collector that never cancelled
  passed. The ghost now records any request made after the decision, and
  `shards_noGroupCancel` checks that case.
- shards.qnt: `SlotBound`, `OkHasQuorum` and `NoDisconnect` had no mutant.
  `shards_noSlotCheck`, `shards_earlyQuorum` and `shards_noFailureThreshold`
  (added in review) break each of them under `quint run` and TLC.

## Running

```sh
./check.sh               # quint typecheck + test + run, then TLC (safety + progress)
TLC=0 ./check.sh         # skip TLC
APALACHE=1 ./check.sh    # add the bounded apalache-mc runs
```

Pins, following refs/ and gc/:
- quint 0.32.0.
- Apalache 0.62.2, run directly on the TLA+ that
  `quint compile --target tlaplus` produces, with `--no-deadlock`: the
  models have terminal states, and an expected `violation` must print
  `state invariant 0 violated`.
- TLC is `tlc2.TLC` from the Apalache jar.
- Java 21.

Environment variables:
- Tool locations: `FV_HOME`, `APALACHE_MC`, `TLA2TOOLS`, `JAVA_HOME`.
- Memory: `TLC_HEAP` (4g), `TLC_WORKERS` (2), `APALACHE_HEAP` (4g).
- `QUINT=0` skips `quint run`. `ONLY=<regex>` restricts TLC and Apalache to
  matching `<module>::<property>` checks.
- `STEPS` (40) and `SAMPLES` (20000) control `quint run`.
- `POOL_BOUND` (4) is the TLC constraint on threshold.qnt.
- `IDENTITY_DEPTH` (6), `SHARDS_DEPTH` (14), `THRESHOLD_DEPTH` (8) and
  `THR4_DEPTH` (6) set the Apalache lengths.

Each output line is either `<check>  <expected> (as expected)` or
`UNEXPECTED: ...`, and the script exits 1 on any unexpected outcome. The
expected outcomes mean:
- `ok`: the property holds within the stated bound.
- `violation`: the checker reached the mutant, canary or documented-gap
  witness, as it must.
- `liveness`: TLC reported a temporal violation (exit 13), not a safety
  violation or a deadlock.

## Bounds (bounded is not proved)

- **identity.qnt**: one fetch (one node, one pack), over a universe of
  2 nodes, 3 packs and a "mixed" shard set. TLC covers it exhaustively
  (27 distinct states for the base model). Apalache runs at length 6.
- **shards.qnt**:
  - Instances: `shards` (N=2, K=1, 2 slots), `shards_tight` (N=1, K=2,
    2 slots) and `shards_wide` (N=3, K=2, 3 slots).
  - Every initial behaviour mix and every foreign-slot count from 0 to
    `MAXW` is included.
  - TLC is exhaustive: 8,185 / 8,325 / 2,081,241 distinct states. The
    progress properties run on the same graphs.
  - Apalache runs at length 14 on `shards`.
  - The production sizes (T = 20, 32 slots) are not checked. The argument
    carries over only through the parametric structure.
- **threshold.qnt**:
  - Instances: `thr` (n=3, t=2, F=1, one rotation) and `thr4` (n=4, t=3,
    F=2, two rotations; quint run and Apalache length 6 only).
  - TLC on `thr` is exhaustive up to 4 posted partials by default, and
    every mutant or witness needs at most 3. It was also run with
    `POOL_BOUND=6` and `POOL_BOUND=8` (before review: 154,773 and 336,159
    states) and unconstrained, `POOL_BOUND=15` (the whole 15-partial
    universe). After the review added the `staleRecovered` ghost and
    `AcceptedOnlyFromShareSetQuorum`, the default bound gives 30,165
    distinct states and `POOL_BOUND=15` gives 477,344 (`thr::Safety` ok,
    13 minutes wall time while sharing the machine); 6 and 8 were not
    re-run.
  - The crypto is symbolic. Unforgeability of BLS, and the claim that
    interpolating shares from two polynomials yields no valid signature,
    are assumptions, not results.
