# Takedown publication and reader performance design

Status: implemented and validated; native and local Worker repros and all required gates passed.
Initial base inspected: `feat/mkit-server-next` at `22d7907433d29d8901b94492a953c74c655ad194`; rebased onto inspection storage commit `2326d2e8acb9adc8fcc27e3c7b80ee467dd96c4e`.
Scope: server core, Worker wiring, in-process native regressions and local Worker conformance. No changes to the native server crate.

## Approved directory

The user approved a new global descriptor-directory subkey and its register-before-activation ordering rule, with a sixteen-shard fan-out. No new partition kind, timer kind, client protocol, storage primitive, or normative spec amendment is proposed. The approved allocation is recorded in plan row R-207.

Directory: one entry per descriptor object, under a reserved global `b` subprefix in existing `ContentShard(0..15)`, routed by the high four object-id bits with DIRECTORY_SHARDS=16. Key bytes are `b\0\xffdenial-descriptor-directory\0<object-id>`; the value is version byte 1 plus the object id. Each small, strictly validated value binds its version and object id. Actual actions, immutable chunk pages, pack scopes and inventory facts stay in their existing content shards.

This directory is an authoritative superset of descriptor locations. It grants neither content availability nor membership. Registration alone is not a denial. Active denial remains the strongly read shard-local descriptor and block/action rows.

## Evidence and current constraints

The local evidence report confirms claims 1, 2, 3, 5 and 6, and partially confirms claim 4. Its measurements are inherited evidence, not new runs on this branch:

| Fixture | Current result or cost |
| --- | --- |
| Nine distinct canonical 1 MiB Blobs | `open closure` after the 8 MiB publication clamp; 100/256 publication calls |
| Thirty-two distinct 62,500-byte chunks | publication object-index cap refusal |
| Tiny takedown-on advance, scan clock +3 ms per call | 8,192 denial scans over two attempts; 24,600 simulated ms; deadline refusal |
| Reader canonical and size batches | 4,423 and 4,471 physical fixture calls respectively |
| Blob / ChunkedBlob size result | 100 payload bytes versus 118 canonical manifest bytes for a 95,000-byte file |

Relevant source evidence:

- `indexed/publication.rs::verify_inner` traverses packmap and history, retaining at most 4,096 visited objects/dependencies. Resolver failures other than `object blocked` currently collapse to `open closure`.
- `pipeline/mod.rs::verify_publication` clamps takedown decode to 8 MiB; `indexed/publication.rs::verify` independently sets 256 metadata/blob calls.
- `takedown/denial.rs::prove_shards` enumerates all 4,096 content partitions. `object_denials` does the same, serially, once per reader batch.
- `store/content_index.rs::block` and `install_stored_block_action_with_batch` atomically write descriptors alongside local denial state. There is currently no global directory or global denial snapshot version.
- `pipeline/mod.rs::apply_loop` fixes plan time before the proof and retains it through the guarded apply. Its next attempt re-proves after a deadline/precondition failure.
- `timers/publication_recheck.rs` currently resumes only dependency witness reads, using a 37-byte timer value, a retained Advance row and 128 routed calls per fire. It has no canonical closure verifier or blob client.
- `pipeline/object_reader.rs` creates fresh 8,500-call batches, checks duplicate output against the configured internal decode budget, and exposes public `object_sizes` with mixed semantics.
- `takedown/inventory.rs::Entry` records kind and references, but not verified ChunkedBlob logical total size.

`SPEC-SERVER` sections 9.3/9.4 require verification before acceptance, distinguish actual missing closure from capped lookup, and prescribe the public object-index error. Section 14.2 requires every gating write check at/after its plan time and bounds later application with NotAfter. Existing alarm limits remain 1,000 physical operations total; publication recheck keeps its 128-operation allocation. The 10 s commit window, 48 MiB component memory bound, 9,000 Worker request allowance and 8,500 reader core allowance stay fixed.

## Why existing-state-only shortcuts do not satisfy the request

Point block checks cannot discover a denied manifest that intersects a requested chunk or a denied pack scope that intersects a new source inventory. Existing descriptor scans supply that transitive coverage.

One full scan per request still pays 4,096 first-page reads, including for the minimal request. Reusing its result across later batches or optimistic attempts has no existing version/authority binding and cannot establish a check after a later attempt's plan time. Increased concurrency does not reduce physical calls. Extending the commit window contradicts the fixed safety cut. Namespace repository catalogs do not enumerate global content descriptors, including unrelated namespaces.

A monotonic occupied-shard bitmap would be smaller, but eventually retains all 4,096 shards after action removal and recreates empty-shard scanning. A directory of descriptor objects avoids that degradation; stale registrations instead cost bounded local descriptor reads. Its saturation can still exhaust the shared budget, which must fail closed with a typed resource refusal, never omit entries.

Moving existing descriptor keys into one global partition would also require a new placement/activation protocol and changes to same-shard atomic denial effects. Retaining current local authority and adding a directory is the smaller change.

## Directory activation and proof safety

1. Before either legacy block or action activation, idempotently reserve the descriptor object's directory entry with an Absent/CAS guard. Validate any existing value exactly. A failed registration prevents activation.
2. Only after the directory write is durably acknowledged may the existing local batch activate descriptor, block/action, safety and purge effects. Fix that batch's plan time afresh; directory registration does not extend its NotAfter window.
3. A crash after registration leaves an unused pointer. A retry validates/reuses it. A crash after local activation cannot leave an undiscoverable descriptor. An uncertain registration outcome must be resolved by a strong read before activation.
4. Keep directory entries monotonic through unblock/reinstatement. Directory removal would need another race protocol and is excluded. Local removal retains existing action-specific semantics.
5. Start each gating proof after its attempt's plan time. Page the sixteen strongly consistent directory shards under the caller's ledger. For each pointer, strongly read the current local descriptors, validate both supported local forms, and run the existing action, chunk-page, inventory, direct-id and hold checks. Empty local descriptors are safe only because all future activations also require prior registration.
6. Validate key/value identity, unique ordered progress, page shapes and routing. Storage failure, corruption, incomplete pagination or any exhausted ledger fails closed. Drain dispatched replies before returning/retrying; at most four joined descriptor reads for foreground paths and the existing scanner ceiling for private retrieval.
7. Every activation completed before proof plan time has a discoverable directory entry and local descriptor. New registrations/actions during a proof obey the existing post-plan NotAfter cut. Reader proofs use fresh directory scans for each batch; there is no request-lifetime cached all-clear snapshot.
8. All producers must use this order, including legacy `ContentIndex::block`, stored action activation, retried accepted takedown work and test fixtures. Preserve direct strong block checks in verification, extraction, holder and serving paths.

Only fresh/reset pre-launch stores are supported. No migration or backfill of existing descriptor stores is introduced. Tests must reserve the directory before writing descriptors; intentional corrupt/missing-directory tests establish refusal where the applicable invariant can be checked. Out-of-band raw writes that bypass producers cannot be made safe by a directory alone.

Expected empty-store cost is sixteen directory page reads rather than 4,096 partition scans. With N registered descriptor objects, cost is sixteen first pages, continuation pages and bounded strong reads of those N objects and existing nested checks. This is an analytical cost model, not a latency measurement or a universal constant-cost claim.

## Bounded publication verification using timer 12

Separate immutable closure work from final mutable acceptance. Extend existing verification/publication value state and timer-12 handling, without a new timer kind, to retain a frozen proposed pair before moving either ref or consuming its tickets. Merely applying an unchecked pair as Pending is disallowed by section 9.3 and the requested fail-closed behavior.

Oversized checkpoint frontiers compact into a terminal typed traversal refusal. The encoded verification state is capped at 520,192 bytes, reserving bytes for its prior-value guard, keys and timer settlement within the existing 1 MiB batch bound. The existing repository-scoped verification row carries a binding of the proposed pair, publication generation, exact added-pack selection, byte budget and delta depth limit. A changed binding starts fresh evidence. Ref names, expected refs, ticket ids/expiry and current dependency witnesses are mutable acceptance inputs; every foreground retry still validates them before guarded acceptance. Immutable closure evidence grants neither membership nor serving authority. Missing membership is retried with cumulative counters preserved and follows the consuming root-MKPL ticket/request's relay-lag classification. Final acceptance rechecks authorization, tickets, membership witnesses and global denial at the new attempt's plan time.

Checkpoint the packmap cursor, allowed packs, BFS frontier, visited ids, dependency/base sets, per-base traversal cursor and cumulative counters. Bound the encoded checkpoint by the existing value limit; check frontier size before allocation. Do not retain canonical blobs across fires. Each delta-base metadata step is independently checkpointed so a maximum-depth chain spans slices without restarting its object.

Explicit budgets:

| Resource | Bound |
| --- | --- |
| Whole closure canonical-length accounting | configured `IndexedConfig.decode_budget`, default 2 GiB; remove the 8 MiB takedown clamp |
| Distinct closure objects and each dependency/base set | existing 4,096-item bounds |
| Canonical-length accounting per continuation fire | 8 MiB; verified inventory facts retain no canonical allocations |
| Routed verification work per timer-12 fire | existing 128 calls, with the shared alarm ledger charged before each remote metadata operation |
| Whole closure transport work | explicit cumulative 1,048,576-call ceiling, in addition to slice limits |
| Resident component memory | existing 48 MiB; derive buffers/cache allowances together rather than retaining cumulative output |

Nine distinct canonical 1 MiB Blobs and 32 distinct chunks fit the whole-job bounds and must advance across slices. No total budget resets with retries or new alarms. Settlement/local operations and Worker blob-read multipliers count against the shared 1,000-operation alarm ledger; if 128 work calls leave insufficient reserve, lower usable work in that fire rather than borrowing another phase's allocation.

Use typed `Missing`, `DecodeBudgetExhausted`, `IndexCallsExhausted`, `TraversalLimit`, storage/corruption and temporary `Pending` outcomes. Slice exhaustion checkpoints and yields; permanent total exhaustion cannot become `open closure`. Preserve section 9's existing wire `invalid_argument: object index limit exceeded` where prescribed, with typed internal causes. A different public verification code would need separate spec review and is not proposed. Caller reader caps use the existing ResourceExhausted code.

The exact staging ownership/settlement of a proposed pair must be settled in implementation design before code: current timer 12 references an accepted Advance and current pack verification state is not pair-scoped. If staging needs another key or alters the fixed request/replay protocol, return for review instead of claiming that the existing timer alone authorizes those changes.

The second proof in the deadline repro is a retry, not evidence of a redundant proof within one attempt. Keep retry proofs. Remove another proof only after showing identical immutable target coverage and an at/after-plan-time proof in that same attempt. There is no unconditional second-proof deletion in this design.

## Reader limits and metadata

Add a limited canonical method or a reader session with `ReadLimits { max_output_bytes, max_decode_bytes, max_encoded_bytes, max_calls }`. Retain the current public method through a documented bounded default. Clamp caller settings to internal ceilings; use one ledger across authorization, reachability ancestors, delta reconstruction, denial and output materialization. Account duplicate output independently from unique cached objects. Use verified lengths to reject output/encoded/decode limits before the corresponding fetch or allocation. When a length is unavailable, stream-debit it under the remaining bound. Caller exhaustion is typed ResourceExhausted; inaccessible ids keep uniform absence and storage failures remain Unavailable. Do not change HTTP uniform-404 semantics.

Add `ObjectMetadata { kind, canonical_len, logical_len }`. Blob logical length is verified canonical length minus its 10-byte prologue. ChunkedBlob logical length is verified manifest total_size. Other kinds have no logical file length. Store these facts in the existing inventory value during verified decoding, cover delta-reconstructed objects, and bind them into inventory sealing/digests. No new metadata key is needed; directly replace the unshipped codec without compatibility machinery. Corrupt/inconsistent facts fail closed.

Expose an additive metadata method; deprecate the public `object_sizes` method and preserve its historical result while callers migrate. Metadata requests must not fetch the requested canonical manifest to derive its logical length; bounded ancestor authorization is still permitted and charged. Existing inventory lookup limits remain.

## Delivery and regression plan after review

One PR targets `feat/mkit-server-next`, within the 3,000-production-line cap, covering the approved directory, resumable publication, caller byte cap and typed metadata.

Required regressions reuse the report's native memory harness through the real Pipeline with D34/Multi, valid signed commits and separate MKIT/MKPL tickets. Convert diagnostic expected refusals into acceptance assertions for nine reachable canonical 1 MiB blobs and 32 distinct chunks. Verify multiple continuation fires, restart/resume, changed generation/binding, retryable missing closure, corrupt checkpoint, exact slice boundaries and cumulative exhaustion. Existing final-acceptance tests retain ticket expiry and expected-ref validation; no continuation-specific ticket-expiry claim is made.

Denial tests cover empty-directory calls, late directory entries, local activation after reservation, crashes on both sides of activation, concurrent registration, failed/uncertain storage writes, active/removed independent actions, pack/manifest/chunk intersections, corruption/continuations, and fresh proof after contention. Extend the +3-ms-per-call clock fixture; an empty-directory advance should consume a small fraction of 10 s, without changing the clock/window.

Reader tests retain the composed three-batch shared parent counter, include duplicate output and ancestor/delta bytes under small caller limits, and assert kind/canonical/logical lengths on Blob and ChunkedBlob. Measure read_canonical, metadata and URL preflights with denial on/off; no 4,096 empty-shard scans and no budget resets within a shared Worker request.

Run a local takedown-on Wrangler push of nine reachable blobs totaling at least 9 MiB and a valid 32-or-more-chunk file, confirm the resulting published pair. Native reader and denial regressions cover canonical/metadata results and active denial. Report foreground physical/core calls, advance proof and request wall timings, each continuation/alarm's calls, rounds to readiness and whole-alarm high-water mark. Compilation and scheduling wait must be separated from proof/request timing. These are local runs only; no deployment or cloud write.

The separate exact-1-MiB canonical geometry repair is a prerequisite for a Worker push using nine full 1 MiB payloads. This task does not silently change that separate scope: if it has not landed, use the report's nine canonical-1-MiB blobs for the regression and a >=9-MiB reachable Worker fixture with payloads below the old boundary, and disclose the geometry. Full 1 MiB payload success remains unclaimed until its repair lands.

Run the required formatting, Clippy, touched/reverse-dependency nextest/doc tests, wasm Clippy, strict rustdoc, script and security gates. Perform independent correctness/security and conformance review before opening PRs. Public artifacts contain repo-relative source references and summarized measurements only.

## Implementation refinements

Sealed inventory entries now retain canonical length, file logical length and all history children. MKPL inventory headers retain their verified predecessor and pack selection. The pair continuation walks these immutable facts instead of reconstructing canonical content again. Its 2 GiB default whole-closure byte budget charges canonical lengths, while the 8 MiB slice length accounting retains no object bytes. Existing `vs` values carry the bounded pair continuation and timer 12 references that existing row. Ref values, membership, tickets and outcomes are untouched while evidence remains incomplete; final acceptance rechecks mutable authority and denial.

The additive reader method applies one caller byte cap to two bounded counters: cumulative canonical decoding (including ancestors/bases) and ordered output bytes (counting duplicates). The four-dimensional limits struct in the original proposal is not necessary for the requested byte cap; the existing shared call ceiling remains. `object_metadata` returns kind, canonical_len and logical_len from verified inventory facts, with no requested manifest fetch. `object_sizes` is deprecated and preserves its historical values.

Custom publication policies and synchronous inspection retain the canonical verifier's 8 MiB decode allowance because it retains delta bases. The 2 GiB whole-job allowance applies to the resumable metadata path. A transient continuation read failure rolls back the incomplete item while retaining charged calls in a guarded checkpoint; foreground callers keep the storage error, and timer 12 retries the checkpoint through its existing settlement path. Permanent head-kind and delta-depth refusals are retained in the same private checkpoint so later foreground attempts return the required error instead of remaining pending.

## Measured regressions

Native memory measurements exclude compilation and scheduled verification rounds. All three publication fixtures committed. Nine canonical 1 MiB Blobs required 130 kind-7/relay rounds, one timer-12 continuation, then 48 metadata calls plus four BlobStore reads and 16 directory scans in 5.299 ms. The 32-chunk file required 209 verification rounds, one continuation, then 66 metadata calls plus four BlobStore reads and 16 scans in 10.828 ms. The tiny advance with +3 ms per content scan committed after 60 simulated ms (66 metadata/four blob reads/16 scans; 8.551 ms wall), preserving the 10 s window. Six composed canonical/typed-metadata reader batches used 508 fixture physical calls under one shared 8,500 allowance.

A local release Worker with takedown on, paid Uno profile, D34/Multi and fresh stores published both fixtures and read back their published pairs:

| Fixture | Raw pack bytes | Pending polls | Final Advance physical calls | Final Advance ingress wall | Whole push wall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Ten Blob payloads of 1 MiB minus ten bytes (>9 MiB total payload) | 10,486,593 | 7 | 52 (48 DO + 4 R2) | 228 ms | 9.092 s |
| Valid 32-chunk file, 62,500 bytes per chunk | 2,001,909 | 7 | 64 (60 DO + 4 R2) | 155 ms | 8.303 s |

The work-carrying pending advances used 57 and 130 physical calls and 133/260 ms respectively. Whole-push timings include upload, verification, polling sleeps and publication; they are not proof timings. Completed request observation peaked at 130 calls. Across 358 completed conservative alarm groups, the external-call high-water mark was 193, maximum outgoing lifetime concurrency four, and timer window high-water eight rows. Each alarm's work is bounded by its overlapping group total; exact Rust task overlap attribution is not claimed. The wrapper assessment passed with all invocation groups complete, no host-operation/handler errors, and settled response bodies. The separate isolate sampler was not run; retained linear capacity observation is not a memory certificate.

The successful Worker run required no proxy retries. Earlier runs hit known dev-proxy connection loss; wire fixtures now bound replay of identical signed launch requests on that transport failure. Ordinary server responses are not hidden by this retry.

No new timer or client protocol is introduced. The separate exact-1-MiB payload geometry repair remains independently owned.

## Final validation

The rebased tree passes all 3,019 server/core/Worker/conformance nextest tests (13 intentionally skipped), all 1,540 CLI reverse-dependency tests (nine intentionally skipped), all touched/reverse doctests, locked all-target/all-feature workspace Clippy, server/Worker wasm Clippy, strict rustdoc, formatting, script gates and security gates. Two independent static reviews completed; their checkpoint, missing-membership retry, base-cursor, binding and lag findings were fixed before the final run.

Existing denial-planning tests now use the directory fan-out; 4,200 stale registrations preserve the cumulative retry-ledger exhaustion regression. Reader tests cover caller caps including ancestor/framing work and duplicate output, requested-file metadata and separate root metadata. Late-owner mocks route directory reservations through the remote store while preserving local content calls; the acquisition fixture uses a clock consistent with its timestamps. Both new wire cases have exact documented requirements/exclusions. The host Worker parent-budget regression now asserts three proofs fit under 200 calls, then exhausts the same parent through actual metadata dispatches.
