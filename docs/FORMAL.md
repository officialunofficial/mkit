# Formal verification

mkit checks parts of its specifications with formal tools: model
checkers for the concurrent and crash-recovery protocols, a proof
assistant for two pure algorithms, a bounded model checker for the
untrusted-input decoders, and a replay harness that ties one model back to
the code. This page says what each check covers, how strong its result
is, what it assumes, and what it found. The per-model READMEs under
[`formal/`](../formal/README.md) hold the full detail: every invariant,
mutant, bound, state count and run time.

The work is tracked in Linear epic MKIT-17 (integration: MKIT-18) and was
done against the specs on the `feat/mkit-server` line (PR #1082). The spec
text is normative. Where a model found the spec wrong, the spec was fixed;
where it found the code wrong, the code was fixed with a regression test,
or the gap is listed under [Open findings](#open-findings).

## How strong is a result

Every result on this page carries one of these labels. Read them
literally.

| Label | Meaning | Tool |
|---|---|---|
| **proved** | A machine-checked theorem for every input, under the hypotheses it states. No `sorry`, no `native_decide`, no axiom beyond `propext`, `Classical.choice`, `Quot.sound`. | Lean 4 |
| **exhaustive (finite instance)** | Every reachable state of a fixed, small instance (named constants: processes, objects, clock range). Says nothing about larger instances. | TLC |
| **bounded (length k)** | Every execution of at most k steps of a fixed instance, checked symbolically. | Apalache |
| **bounded (input size)** | Every input up to the stated size, checked symbolically by CBMC. | Kani |
| **simulated** | Random executions (for example 20,000 samples of 40 steps, seed `0x1`). Finds bugs; shows nothing about the executions it did not draw. | `quint run` |
| **tested** | Pinned scenarios (`quint test`, `#guard`, Rust tests) or a replay of sampled traces against the code. | quint, Lean, cargo |

"Bounded" never means "proved". Only the Lean theorems are proofs, and
only for the model: the link from the Lean model to the Rust code is a
differential test, not a proof.

**Non-vacuity.** A property that holds could hold because it is too weak
or because the model never reaches the interesting states. Every
invariant here is therefore paired with evidence that it can fail:

- a **mutant**, a copy of the model with one deliberate bug, which the
  checker must report as a violation of that specific invariant;
- a **canary**, a false reachability claim ("no gc ever deletes
  anything") the checker must refute, which shows the states that matter
  are reached;
- for Lean, a `*_needed` or `mutant_*` lemma showing that each
  hypothesis and each check is load-bearing;
- for Kani, a `*_canary_*` harness marked `#[kani::should_panic]`.

Each `check.sh` prints one line per check with its expected outcome
(`ok` or `violation`) and exits 1 on anything unexpected, so a mutant that
stops failing breaks the run just like an invariant that stops holding.

## Tool split

| Layer | Tool (pin) | Used for | Why this tool |
|---|---|---|---|
| Protocol models | [Quint](https://quint-lang.org) 0.32.0 | Ref CAS and lock order, gc and the recovery log, history publication and crash recovery, `advance_refs` retries, transport identity, shard quorum, threshold signing | Concurrency, crashes and retries are state-machine properties. Quint gives typed, executable models with `quint test` scenarios and fast random simulation, and compiles to TLA+ for the model checkers. |
| Model checking | Apalache 0.62.2, TLC (the `tlc2.TLC` class inside the Apalache jar), Java 21 | Bounded symbolic (Apalache) and exhaustive explicit-state (TLC) checks of the compiled Quint models, including TLC liveness under fairness | Apalache is run directly on the TLA+ `quint compile` emits, because `quint verify` bundles an older Apalache (0.56.1) that predates the FoldSet fixes the models rely on. |
| Algorithm proofs | Lean 4 v4.34.0 (`formal/lean/lean-toolchain`), core library only | Merkle inclusion proofs (SPEC-MERKLE-OBJECTS) and the delta codec (SPEC-DELTA) | Pure functions over unbounded inputs need proofs, not state exploration. The Cedar-style pattern: an executable Lean model, theorems about it, and a differential test that replays Rust-exported vectors through the model. |
| Decoders | Kani 0.68.0 (CBMC 6.11.0) | Panic freedom and spec agreement of `delta`, `merkle`, `pack`, `serialize`, the keystore record and RPC framing on small symbolic inputs | Checks the actual Rust, not a model, which is what matters for untrusted input. The fuzz targets ([FUZZ.md](FUZZ.md)) cover larger inputs by sampling. |
| Conformance | Rust test replaying ITF traces | `refs_mbt.qnt` traces replayed step by step against `mkit_core::refs`, `ops::recovery`, `FileTransport` and `MemoryTransport` | Closes the loop from a model to the code for the ref layer: the same step must produce the same refs, recovery log and CAS outcome. |

**Why no standalone TLA+.** The protocol models are written once, in
Quint, and TLA+ is generated from them. Hand-written TLA+ would be a
second copy of each model that could drift from the Quint one that the
tests and simulations use. The only hand-written TLA+ is
`formal/quint/history/tlc/`: thin wrappers that add a state `VIEW` and
fairness to the compiled output. TLC runs as a checker, not as a
modelling language.

## Traceability

One row per property that a spec clause depends on. "Status" is the
strongest label the property has; weaker checks (simulation, scenario
tests) also run on every row. Bounds are the defaults in each
`check.sh`. The linked READMEs list every property; this table lists the
ones a spec reader is most likely to look for.

### Refs, locks and servers ([`formal/quint/refs`](../formal/quint/refs/README.md), MKIT-19)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-REFS §5, §5.1 (CAS per lock domain) | `NoLostUpdateLocal`, `NoLostUpdateFile`, `NoLostUpdateMem` | exhaustive on two slices of `refs2` (2 processes, one ref, 3.4M and 3.5M states); bounded (length 8) on the full op space | mutants `refs2_noRefLock`, `refs2_noFileLock`, `refs2_memNoMutex` |
| SPEC-CONCURRENCY §4 (lock order) | `NoDeadlock`, `LockOrderRespected`, `LockOwnership` | as above | `refs3_misorder`, `refs2_racyAcquire` |
| SPEC-CONCURRENCY §3.2 (recovery log) | `ExpireHoldsSuperset`, `NoRecordExpireInterleave` | as above | `refs2_gcSkipTrees` |
| SPEC-CONCURRENCY §2, §3.1 (`serve.lock`, `server.lock`, startup sweep) | `SweepAlone`, `NoLiveUploadSwept`, `OneMkitServer`, `UpServersHoldServeShared`, `NoMissedDetection` | exhaustive (`serve2` 18,812 states, `serve3` 152,012) | `serve2_sweepUnlocked`, `serve2_sweepUnderShared`, `serve2_serverSkipsServe`, `serve2_serverLockShared` |
| SPEC-REFS v3 §2, §3 (served names, 512-byte bound) | `RefuseBeforeStorage`, `ExplicitRefusal`, `RefusedWritesNothing`, `ListingServedOnly` | exhaustive (`served`, 66,064 states) | `served_checkAfterRead`, `served_headCheckedLate`, `served_listNoSkip` |
| SPEC-CONCURRENCY §3.1 (documented cross-domain gap) | `WitnessCrossDomainGap`, `WitnessUndetectedLateServer` | reached, as documented | - |
| SPEC-REFS §5 (implementation conformance, MKIT-22) | 5 `refs_mbt.qnt` traces (300 steps, 41 commits) agree with the code after every step | tested | 5 injected adapter faults and 2 tampered traces are each caught; an independent adapter mutant was caught in review |

### Garbage collection ([`formal/quint/gc`](../formal/quint/gc/README.md), MKIT-21)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-GC Invariants (no live object pruned) | `NoLivePruned`, `NoDangling` | exhaustive (`gc` 19.6M states, `gcGrace0` 19.7M); bounded (length 8) | `mutLenient`, `mutNoLockGrace0`, `gcPushRaw*`, `gcPushFast` |
| SPEC-GC fail-closed requirement | `UnreadableAborts` | exhaustive | `mutLenient` |
| SPEC-GC recovery log, SPEC-CONCURRENCY §3.2 | `SupersededRetained`, `LockExclusion` | exhaustive | `mutNoRecord`, `mutNoKeepLast`, `mutNoLock` |
| SPEC-GC "Concurrent writers and the grace window" | writer outside gc's locks cannot lose an object when every newly reachable object has `T - mtime < GRACE` (`gcPushBounded`); dedup hits that refresh mtime (`gcPushFastFreshen`, the code since MKIT-55) are safe | exhaustive with at most 2 producer rewrites and no corrupt source (9.5M and 11.9M states); bounded (length 8) | `mutBoundedLax` (the bound is tight), `gcPushFast` (pre-MKIT-55 code) |
| SPEC-GC progress | `NoLeakedLock`, `NoStuckPush` | exhaustive | `mutLeakLock`, `mutStuckPush` |
| Server `ContentIndex` GC ordering (R-64; no spec text yet) | `NoReachableLoss`, `NoLiveDelete`, `DeletingClears`, `UploadCanStep` | exhaustive; bounded (length 16) | `ciBytesFirst`, `ciShortTtl`, `ciMutNoDeletingGuard`, `ciMutNoSeqGuard`, `ciMutNoResume`, `ciMutNoGiveUp` |

### History publication and scrub ([`formal/quint/history`](../formal/quint/history/README.md), MKIT-20)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-HISTORY-PROOF §4.4 (intent withholds proofs; crash recovery) | `NoProofWhileIntent`, `CurrentMatchesRef`, `ServedMatchesRef`, `FinishOnlyFromRecorded`, `RecoveryEnabled`, `NeverFailsClosed` | exhaustive (commits 1..4, at most 3 generations, any number of crashes; 200,388 states under a bisimulation VIEW); bounded (length 10) | `mutLoadIgnoresTx`, `mutHealTipOnly`, `mutFinishAnyRef`, `mutRawIgnoresTx`, `mutWriteBeforeInvalidate` |
| SPEC-HISTORY-PROOF §1 (generations) | `GenerationFastForwardOnly`, `ServedGenerationFresh`, `FastForwardRetainsGeneration` | as above | `mutRawSkipsInvalidate`, `mutReuseGenOnRewrite`, `mutFreshGenOnFF` |
| SPEC-HISTORY-PROOF §4.2, §4.3 (intent roots) | `IntentRootsRetained` | as above | `mutGcIgnoresIntent`, `mutSkipVerify` |
| SPEC-HISTORY-PROOF §4.4 (recovery completes) | `IntentEventuallyCleared` (liveness, weak fairness, finitely many crashes) | exhaustive (TLC temporal, 400,776 states) | `mutRecoverSkipsPending`, `mutRawIgnoresTx`, and the property fails without `WF(RecoverAttempt)` |
| SPEC-HISTORY-PROOF §4.5 (scrub lap at most 65 publishes, 7-day bound, invalid state forces a full walk) | `ActualPublishBound`, `TimeBound`, `InvalidForcesFull` | exhaustive on scaled constants (1,904 states); bounded (length 8); `realLapBoundTest` checks the real constants for every `verified_through` up to 1,000,000 | `mutWrapWithoutFull`, `mutIgnoreAge`, `mutTrustInvalid`, `scrubLossy`, `scrubClockBack` |
| SPEC-HISTORY-PROOF §4.5 ("fewer than 604800 s", MKIT-57) | `WindowOnlyWhenFresh` | bounded (Apalache length 8) and simulated only; the TLC VIEW omits the elapsed time | `mutAgeInclusive` (the pre-fix comparison) |

### Remote advance ([`formal/quint/advance`](../formal/quint/advance/README.md), MKIT-27)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-TRANSPORT-CONNECT §4; `Transport::advance_refs` contract | `DeltaTransfer` (a head that resolves to T has a packmap that reconstructs T) | exhaustive (2 and 3 pushers, commits 0..6, 3 loop attempts, 2 ladder re-issues; up to 7.6M states); bounded (length 8) | `ordered2_noGate`, `http1_gateNoAny`, `ordered2_headFirst` |
| SPEC-TRANSPORT §7 (`read_ref` before reporting a conflict, MKIT-58) | `SuccessSound`, `ConflictHonest` | as above | `ordered2_oldConflict`, `atomic2_oldConflict`, `ordered2_trustConflict` |
| SPEC-REFS §5 (no lost update, CAS and user level) | `NoLostUpdate`, `NoLostSuccess` | as above | `noop2_splitCas`, `ordered2_splitCas` |
| Progress of a push | `NoStuckPusher`, `BoundedRetries`; `Termination` (liveness, weak fairness) | exhaustive; `Termination` on the 2-pusher instances and `http1` only | `ordered2_noTimeout`, `ordered2_noLadderBound` |

### Transport identity, shards, threshold ([`formal/quint/transport`](../formal/quint/transport/README.md), MKIT-26)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| INVARIANTS.md "Requested transport identities are checked before effects"; SPEC-PACK-SHARDS §2, §4.2; SPEC-TRANSPORT "Consumers MUST verify" | `NodeMatchesRequest`, `ShardsOnlyForRequestedManifest`, `ReconstructOnlyForRequested`, `ShardPathReturnsRequested`, `PackMatchesRequest`, `PublishedWithinRequestedClosure` | exhaustive; bounded (length 6) | one mutant per check (`identity_nodeNoVerify`, `identity_noManifestPrecheck`, ...) |
| INVARIANTS.md "Shard worker bounds do not delay an available quorum"; SPEC-PACK-SHARDS §5 | `SlotBound`, `OkHasQuorum`, `NotFoundPastThreshold`, `NoFalseNotFound`, `NoDisconnect`, `NoAttemptAfterDecision`, `QuorumNotBlockedByAdmission`; liveness P1, P2 | exhaustive at N/K/slots 2/1/2, 1/2/2, 3/2/3; bounded (length 14) | `shards_noSlotCheck`, `shards_earlyQuorum`, `shards_offByOne`, `shards_noFailureThreshold`, `shards_noCancel`, `shards_noGroupCancel`, `shards_blocking`, `shards_recvBlocking` |
| SPEC-RELEASE-THRESHOLD §5.3, §8 (t-of-n, rotation) | `NoForgery`, `AggregateFromOneShareSet`, `AggregateCompleteness`, `AcceptedOnlyFromShareSetQuorum` | exhaustive at n=3, t=2, one rotation (477,344 states); bounded (length 8; n=4, t=3 at length 6) | `thr_noRefresh`, `thr_verifierIgnoresMsg`, `thr_t1`, `thr_filterAnyEpoch` |

### Merkle objects and delta ([`formal/lean`](../formal/lean/README.md), MKIT-24, MKIT-25)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-MERKLE-OBJECTS §1.1, §5.3, §5.4 (completeness) | `complete`, `complete_id`, `complete_chunk` | proved, for every `n` and `i < n` | `complete_witness` |
| SPEC-MERKLE-OBJECTS §2, §5.4 (soundness, binding, exact sibling consumption) | `sound`, `sound_id`, `unique_proof`, `cross_kind_rejected`, `accepted_length`, `extra_sibling_rejected`, `dropped_sibling_rejected` | proved, under the injectivity hypotheses `NodeInj`, `LeafInj`, `FinInj`, `WrapInj` | `*_needed` lemmas (drop a hypothesis and a wrong leaf verifies), `mutant_*` verifiers |
| SPEC-MERKLE-OBJECTS §4, §5.4, §5.5 (empty tree, zero positions, chunk position 0) | `empty_tree_no_proof`, `verifyRangeId_nil`, `verifyMultiId_nil`, `chunk_pos0_rejected` | proved | `vacuous_accepts_empty_tree` |
| SPEC-MERKLE-OBJECTS §5.4 (multi-leaf and range completeness) | selection and verification agree | tested: every subset for `n <= 9`, every range for `n <= 24` (`#guard`) | two `#guard` mutants |
| SPEC-MERKLE-OBJECTS (Rust agreement) | roots, ids, sibling positions and digests, every verdict | tested (differential, golden and seeded-random vectors up to 1,100 leaves) | two model mutants and two corrupted Rust verdicts must be detected |
| SPEC-DELTA §2, §3 (canonical codec) | `decode_encode`, `encode_decode` | proved | `decode_encode_needs_wf`, `decodeLax_not_canonical` |
| SPEC-DELTA §4, §8, §10 (no out-of-bounds read, soundness, completeness, error kind, truncation) | `apply_ne_oob`, `apply_sound`, `apply_complete`, `apply_overrun`, `apply_underrun`, `runT_bounded`, `apply_prefix` | proved | one reader mutant per §4 check (`applyMut`) falsifies the matching theorem |
| SPEC-DELTA §5 (writer) | `apply_encodeWith`, `apply_encodeRust` | proved (bases and targets under 2^32 bytes) | `trusting_roundtrip_fails` |
| SPEC-DELTA (Rust agreement) | acceptance, output bytes and error kind of every exported stream | tested (differential) | five `--mutant` readers and one corrupted Rust verdict must be detected |

### Decoders ([`formal/kani`](../formal/kani/README.md), MKIT-23)

| Spec clause | Property | Status | Non-vacuity |
|---|---|---|---|
| SPEC-DELTA §2, §4 | `delta::decode` never panics; equals the §4 reference algorithm; round-trips | bounded (streams up to 20 bytes, bases up to 4) | `delta_decode_canary_wrong_length` |
| SPEC-OBJECTS §2 to §8, §11 | deserializers never panic; tree-name rule matches §4.1; blob round-trip | bounded (bodies up to 12 bytes) | `serialize_canary_trailing_byte_accepted` |
| SPEC-MERKLE-OBJECTS §5.2 to §5.5 | proof decode, verify fold, builder round-trip; §5.4 builder refusal on the empty tree (MKIT-56) | bounded (0 to 2 siblings, leaf counts up to 8; any `u32` for `s0` and the empty-tree harness) | `merkle_canary_tampered_leaf_verifies` |
| SPEC-PACKFILE §1 to §3, §6, §8, §11 | pack parsing never panics and honors the header, trailer and entry count; window cursor decode | bounded (entry areas of 5 and 10 bytes; one fixed cursor layout of 125 bytes) | `pack_canary_mutation_still_parses`, `pack_window_cursor_canary_flip_accepted` |
| SPEC-KEYSTORE §6.1.1 | record decode never panics; round-trip; id `0x04` rejected in every build (MKIT-59) | bounded (inputs up to 15 bytes; default and `bls-threshold` builds) | `software_key_record_canary_trailing_byte_accepted` |
| SPEC-RPC §1 | `read_frame` never panics; accepts iff full prefix, in-cap length, full body | bounded (streams up to 6 bytes) | `rpc_canary_over_cap_length_accepted` |

## Assumptions

Each result holds only under these assumptions. They are stated in the
model or harness that relies on them.

- **Hashes.** Lean theorems take injectivity of the node, leaf, finalize
  and wrap hashes as explicit hypotheses (`NodeInj`, `LeafInj`, `FinInj`,
  `WrapInj`), not as axioms; `termHasher` (a free term algebra) satisfies
  all of them, so the theorems are not vacuous. The Quint transport
  models treat BLAKE3 as the identity on contents (collision resistance)
  and BLS signatures as symbolic (unforgeability, no interpolation across
  polynomials). Kani harnesses replace BLAKE3 with a deterministic mixer
  and stub zstd decompression.
- **Bounds.** Every Quint result is for the fixed instance in its README:
  a handful of processes (2 or 3), objects (up to 8), commits (up to 7)
  and clock values. Apalache lengths are 4 to 16 steps. Kani inputs are a
  few bytes to 125 bytes. Constants are scaled where the real ones are
  too large (for example the scrub model uses `MIN_WINDOW=2` for 512 and
  `MAX_AGE=3` for seven days, keeping the relation that matters, and a
  separate test checks the real constants).
- **Time and crashes.** Time is a small integer clock. Lock waits never
  time out. A crash is one atomic step that discards volatile state;
  history recovery liveness assumes finitely many crashes and fair
  callers.
- **Abstractions of the code.** Each model follows specific Rust
  functions, named in its README, and abstracts I/O: a durable write is
  one step, a lock is a set membership. A mismatch between a model step
  and the code it names is a modelling error these checks cannot catch;
  the reviews on MKIT-19 through MKIT-27 compared each model with the code
  by hand, and MKIT-22 replays one model against the code.
- **Lean to Rust.** The Lean models are executable specifications. Their
  agreement with `merkle.rs` and `delta.rs` rests on the differential
  tests (sampled vectors), not on a proof.

## Findings

What the models found, and where each stands. "Fixed" means the code
changed, with a regression test that fails before the fix and passes
after.

### Fixed in code

| Issue | Finding | Found by | Fix |
|---|---|---|---|
| MKIT-55 | A dedup hit left an object's old mtime, so gc could delete an object that a concurrent git import was about to publish (SPEC-GC "Concurrent writers") | `gcPushFast::NoDangling` (Apalache length 8, TLC) | `BulkWriter::write`, the git import writer and the only object writer outside gc's lock set, refreshes mtime on a dedup hit and rewrites the object if the refresh fails. `ObjectStore::write` and `WriteBatch` callers hold `worktree.lock`, so they skip the refresh (it cost ~280x on their dedup hits). Partially fixed: see the open gc findings below. |
| MKIT-56 | The range-proof builder returned the all-default proof for `0..=0` of the empty Tree; SPEC-MERKLE-OBJECTS §5.4 requires a refusal | Kani `merkle_builder_empty_tree_refuses` | `BmtTree::range_proof` refuses every range of the empty tree |
| MKIT-57 | The scrub took the window path at exactly 604800 s; SPEC-HISTORY-PROOF §4.5 says "fewer than" | `scrub::WindowOnlyWhenFresh` | `decide_chain` compares with `>=` |
| MKIT-58 | A push reported NonFastForward for a head write that landed but whose response was lost; SPEC-TRANSPORT §7 requires a `read_ref` first | `ordered2_oldConflict::ConflictHonest` | `head_conflict` reads the head back on `HeadConflict` and `RefConflict` |
| MKIT-59 | With `bls-threshold`, the `MKITKSV1` decoder accepted algorithm id `0x04`; SPEC-KEYSTORE §6.1.1 says it MUST reject it | Kani `software_key_record_rejects_algorithm_4` | `algorithm_from_id` rejects `4` in every build |

### Fixed in the spec

The models also found spec text that was wrong or incomplete, and the
spec was corrected on this branch: the scrub lap is at most 65 publishes,
not 64, and that bound needs the scrub write to land (SPEC-HISTORY-PROOF
§4.5); SPEC-GC now states the normative writer condition
`T - mtime < grace`; SPEC-TRANSPORT §7 and SPEC-TRANSPORT-CONNECT now
agree on the retry and `read_ref` obligations; SPEC-MERKLE-OBJECTS §5.4
states the builder refusal. The per-model READMEs list each change.

### Open findings

None of these has its own Linear issue yet; each is recorded under the
issue whose model found it.

| Found under | Severity | Finding | Evidence |
|---|---|---|---|
| MKIT-55 | spec gap | gc reads an object's mtime, then unlinks it later (`ops/gc.rs` `run_gc`), so a refresh landing between the two still loses the object. The model's `GcSweep` does both in one step and does not cover this window. The operator rule against running gc during a git import stays. | code reading; SPEC-GC and the gc README now say so |
| MKIT-55 | spec gap | git import skips objects its map cache already translated, so their mtime is not refreshed | `mkit-git-bridge` `Importer::object`; same operator rule |
| MKIT-55 | bug (pre-existing) | `BulkWriter::commit` opens every reused object file for writing to fsync it and fails with `EACCES` on a read-only object | probe during the MKIT-55 fix |
| MKIT-27 | bug (latent) | F1: an HTTP force push that falls back to the ordered `Any` path can be stranded by a concurrent atomic re-baseline | `gapHttpAny2::DeltaTransfer`; latent because the CLI builds only `ConnectTransport` |
| MKIT-27 | spec gap (latent) | F2: a force push, head-only or appending, can be stranded by a concurrent atomic re-baseline; checking the packmap before a head-only write is not enough | `gapNoopAny2`, `gapTwoAny3`, `gapAppendAny2`, `gapAppendTwoAny3`; latent until a Connect server opts in to atomic advance |
| MKIT-27 | spec ambiguity | The §7 `read_ref` rule cannot tell "never landed" from "landed, then built on"; such a push is reported NonFastForward although its commit is in the remote history | `WitnessLandedThenNff` |
| MKIT-26 | spec gap (liveness) | One corrupted shard among the first `minimum_shards` responses fails the download although a valid quorum is available | `shards_bad::DecodeFailsOnlyWithoutHonestQuorum`, `P2Corrupt` |
| MKIT-26 | spec gap | `aggregate` does not verify partials, so one low-index garbage partial blocks aggregation unless a coordinator verifies first | `thr_asImpl::AggregateCompleteness` |
| MKIT-26 | spec gap | Nothing binds a share-set epoch: rotation is safe only if old shares are erased, and a rotated-out set's posted partials still verify | `thr_retainOld::NoForgery`, `CanaryNoStaleAggregate` |
| MKIT-26 | doc drift | SPEC-PACK-SHARDS §5 still describes one thread per shard URL; SPEC-RELEASE-THRESHOLD's `ceil(2n/3)` differs from the code's N3f1 quorum for n = 3k | code reading; `quorumTableTest` |
| MKIT-26 | hypothesis | The shard byte budget (`MAX_BUFFERED_SHARD_BYTES`) could turn valid shards into failures for packs near the size limit; not modelled or tested | code reading |
| MKIT-22 | coverage | The conformance fixtures reach no successful `amend` commit and no memory-transport `Any` write | fixture tally |
| MKIT-58 | doc drift | `AdvanceOutcome::HeadConflict`'s rustdoc still says callers treat it as NonFastForward | `mkit-core/src/protocol.rs` |

## Limitations

- **Bounded is not proved.** Outside Lean, every result covers a finite
  instance, a bounded length or a bounded input size. Larger instances
  are argued, not checked; several READMEs record checks that did not
  finish within the 30-minute budget and were cut back.
- **Not everything is checked by every tool.** Some invariants are checked
  only by simulation and Apalache (for example `WindowOnlyWhenFresh`), some
  liveness properties only on the smaller instances (`Termination` on two
  pushers), and some mutants only by `quint run` and TLC. The per-model
  READMEs say which.
- **Models follow the code by hand.** Only the refs model is replayed
  against the implementation (MKIT-22), and only for 5 sampled traces.
  Lock steps, the `history-mmr` ancestry path and age-based recovery
  pruning are not compared.
- **Not modelled.** Among others: pack GC, ledger expiry, `MAX_REACHABLE`
  truncation, `mkit-server --meta sqlite`, the S3 spool sweep, the git
  bridge locks, the shard byte budget, multi-entry trees in Kani, and
  every decoder input beyond the Kani bounds (left to fuzzing and
  proptests).
- **Tool trust.** Results trust Quint's compiler to TLA+, Apalache, TLC,
  CBMC and the Lean kernel. Tool versions are pinned; the Apalache jar is
  checked by sha256.

## Run the checks

The `just` recipes run every layer and are what
[`.github/workflows/formal.yml`](../.github/workflows/formal.yml) runs
nightly (and on `workflow_dispatch`). Each prints one line per check and
fails on any unexpected outcome. Times below are from a shared 15-core
arm64 Mac. `just formal` is the smallest useful set, but at about an
hour it runs nightly rather than on every PR; most of it is the `quint
run` simulations of the refs model.

| Recipe | What it runs | Time (developer machine) |
|---|---|---|
| `just formal` | `formal-quint`, `formal-lean`, `formal-conformance` | about 1 h (56 and 65 min in two runs) |
| `just formal-quint` | every `formal/quint/*/check.sh` in its default mode: quint typecheck, test and run, plus TLC where the script runs it by default. `just formal-quint all` adds gc's TLC runs (~50 min). | 55 to 65 min (advance 8 to 12, gc 3, history 5 to 6, refs 26 to 40, transport 9 to 10) |
| `just formal-apalache` | every `check.sh` with `APALACHE=1` at its default lengths | hours (advance alone: 14 min; gc about 2 h) |
| `just formal-lean` | `lake build`, then `difftest-merkle.sh` and `difftest-delta.sh` | 20 s with a warm build |
| `just formal-kani` | every Kani harness, one at a time (`KANI_FILTER=regex` to pick some) | about 1.5 h |
| `just formal-conformance` | `cargo test -p mkit-formal-conformance` (offline, checked-in traces) | seconds after the build |
| `just formal-fixtures` | regenerate the conformance traces from the model and diff them | about 3 min |

### Install the tools

The pins live in the `formal_*` variables at the end of the
[`justfile`](../justfile), and `formal.yml` repeats them.

On macOS:

```sh
brew install openjdk@21 elan-init just jq node
npm install -g @informalsystems/quint@0.32.0
just formal-setup-apalache      # Apalache 0.62.2 into ~/.local/share/mkit-fv, sha256-checked
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
```

The `check.sh` scripts find Homebrew's keg-only `openjdk@21` on their
own. elan reads `formal/lean/lean-toolchain` and fetches Lean v4.34.0 on
the first `lake build`.

On Linux, install a Java 21 JDK (for example `apt install
openjdk-21-jdk-headless`) and set `JAVA_HOME` to it, install Node.js,
`jq` and [elan](https://github.com/leanprover/elan), then run the same
`npm`, `just formal-setup-apalache` and `cargo install` commands.

`FV_HOME` (default `~/.local/share/mkit-fv`) moves the Apalache install;
`APALACHE_MC` and `TLA2TOOLS` point at another copy. Each `check.sh`
documents its own knobs (`ONLY`, `SEL`, `TLC_HEAP`, `*_DEPTH`).

### Resource use

TLC runs with a 4 GB heap and 2 to 4 workers, Apalache with 4 GB. The
largest Kani harness peaks at about 5.4 GB. Run one Kani harness at a
time. The recorded times come from a 15-core arm64 Mac shared with other
jobs; a CI runner is slower.
