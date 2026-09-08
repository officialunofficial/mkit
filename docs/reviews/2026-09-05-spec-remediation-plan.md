# Plan to resolve the specification audit

Status: implementation is in PR #965. The pre-production revision below
supersedes the original compatibility assumptions; verification is tracked in
[the execution record](2026-09-05-spec-remediation-execution.md).
Baseline: `abaf6f21`, 2026-09-05. This plan was written against the
[audit](2026-09-05-spec-architecture-audit.md) baseline. Finding numbers below refer to
that report. Scope is all ten findings, including their related caller and
specification corrections. Existing object IDs and signed object bytes remain
unchanged where their current behavior already satisfies the requirements.
Auxiliary formats have explicit versions and strict validation, without old-format
readers, migration APIs, or fallback state. The user confirmed on 2026-09-05
that the project is not live and backwards compatibility is not required.

## Work order and coverage

Each package includes its regression tests, implementation, normative text,
golden vectors where relevant, and documentation of actual verification.

| Order | Package | Audit finding | Depends on | Completion condition |
|---|---|---|---|---|
| 0 | Baseline and regression capture | All | — | Current-build failures or explicit contract tests identified for every finding |
| 1A | Requested pack identity | 2 | 0 | Substituted packs rejected before effects |
| 1B | Ref mutation serialization | 5 | 0 | Mixed writers/deletes have a legal serial outcome; complete lock order |
| 1C | Git correspondence audit | 3 | 0 | Swapped mappings and unrelated attestations fail without requiring a private key |
| 2A | Destination-bound request authorization | 4 | 0 | Audience/content/replay tests pass in clients and receiving services |
| 2B | Sparse metadata witnesses | 1 | 1A | Selected entries and completeness verified against the requested Tree ID |
| 2C | Bounded fetch staging | 6 | 1A | Memory independent of total pack-chain size; existing GC/ref guarantees retained |
| 2D | Two-phase external signer handshake | 8 | 0 | No signing request before compatible capabilities are validated |
| 3A | Durable staged state | 9 | 0 | Current index preserves staging; unsupported/corrupt index stops GC |
| 3B | Representation-independent file equality | 10 | 0 | Equivalent valid representations remain clean and compare equal |
| 3C | First-parent history proofs | 7 | 1B | Canonical ancestry roots, explicit generations, recoverable publication |
| 4 | Cross-feature verification and release preparation | All | All packages | Coverage ledger complete and applicable CI gates pass |

This is dependency order, not a requirement to serialize independent work.
Use separate worktrees/branches for packages that touch shared files. In
particular, serialize integration of 1A/2C in `remote_dispatch/packmap.rs`,
1B/3C in `refs.rs`, and 3A/3B around index/worktree behavior. Assign exclusive
file ownership when delegating implementation. No concurrent edits to the same
checkout files.

## 0. Establish the baseline and capture failures

1. Preserve unrelated work, including the existing untracked Windows installer.
   Record the base revision and enabled features with each test result.
2. Rebuild `mkit-cli` with `git-bridge` and turn the audit's temporary three-commit
   mapping-swap experiment into an integration regression. Do not rely on the
   pre-existing binary used for the initial experiment.
3. Add the smallest meaningful failing test at the start of each package, then
   implement that package. Use deterministic barriers/fault injection for races
   and recovery; do not rely on sleep-based races or intentionally exhaust the
   host's memory.
4. Confirm fake stores and fixtures use canonical `Object::id()` where they
   represent real stores. Pin expected IDs against independent golden fixtures,
   not a second invocation of the implementation under test.
5. For new policy contracts such as history generations and current index integrity, state
   expected behavior before writing tests. Track these separately from bugs
   reproduced in existing behavior.

Record new cross-cutting invariants in `docs/INVARIANTS.md` using
Always/Because/If-violated and the actual enforcing tests. Do not mark a finding
resolved merely because its misleading claim has been removed.

## 1A. Enforce the requested pack identity

**Design.** Introduce a shared check that bytes returned for a PackKey hash to
that exact key. Use the existing PackKey recipe: BLAKE3 over the entire returned
byte sequence, including the pack trailer; do not confuse it with the pack's
internal trailer checksum. Reject a shard manifest with another `pack_hash`
before requesting shards. Check reconstructed bytes again at the consumer
boundary, covering custom transports as well as bundled backends. Audit metadata
blob reads for the same expected-key invariant.

**Files.** `mkit-core/src/protocol.rs`, `pack_shard.rs`, HTTP/S3 `src/lib.rs`,
CLI `remote_dispatch/packmap.rs`; `SPEC-PACK-SHARDS`, `SPEC-TRANSPORT` and relevant
Connect contract text. Rust paths here are under `rust/crates/` unless stated otherwise.

**Regression.** Produce valid A and B containing the same objects in different
pack encodings. Request A and return B, both directly and through B's valid
manifest/shards. Require rejection before unpack, object writes or applied-pack
recording. Verify normal downloads and auxiliary blobs still work.

**Compatibility.** No wire change; enforce the existing addressing contract.
Repair nonconforming test fixtures rather than weakening the check.

## 1B. Serialize every mutation of a ref

**Design.** Centralize Any, Missing, Match, unconditional delete and conditional
delete behind a held ref-mutation guard. Expose guarded internal primitives so
history operations do not reacquire non-reentrant locks. Inventory tag, remote,
batch, rename and branch deletion paths as well as `cas_write`.

Define the complete order:

```text
worktrees registry → worktree locks → history locks → ref mutation locks
```

Acquire multiple locks within each class in a stable canonical order before
moving to the next class. Use full ref identity, including namespace, for ref
ordering. Do not imply multi-ref transactional semantics for operations that
only provide per-ref atomicity.

Fix the file transport's internal mixed-condition race too: its Any/Missing
writes must participate in the same serialization as its Match/delete paths.
Retain the documented deployment restriction against simultaneously serving a
root and mutating it as a local worktree; closing that separate GC/writer
coordination gap is not accomplished by sharing a ref lock alone.

**Files.** `mkit-core/src/refs.rs`, `repo_lock.rs`,
`mkit-transport-file/src/lib.rs`, CLI branch/update-ref/remote callers;
`SPEC-REFS`, `SPEC-CONCURRENCY`, `SPEC-WORKTREE`, `docs/INVARIANTS.md`.

**Regression.** Pause after Match observes its expected value and race Any or
deletion. Cover linked worktrees, separate file-transport instances, Missing vs
delete, reversed multi-ref argument order, and history enabled/disabled. Assert
legal serial outcomes and bounded completion, rather than one arbitrary winner.

**Compatibility.** No object/wire changes. Lock acquisition changes land together
with all participating mutations and the revised lock order.

## 1C. Verify the Git-to-mkit correspondence

**Design.** Extract a pure translation/validation layer from import logic so
verification can derive expected fields without signing, writing or importing
again. Walk the reachable correspondence graph from trusted targets: derive
trees, parents, author/tagger, timestamps, messages and annotation fields from
retained Git bytes under the recorded import-spec version. Check the stored
twin against that result and verify its signature under the pinned public key.
The mapping cache supplies lookup hints; it cannot establish correspondence.
Validate bridge-shaped native objects' parent/tree edges against the same graph.

For each required head attestation, use the shared signature verifier plus
strict claim checks: payload type, predicate type/version, subject hash/ref,
Git ID, canonical remote identity, schema/import version, and the pinned import
signer. An unrelated or merely present envelope is insufficient. Define whether
extra envelopes are ignored; require at least one complete valid matching claim.

**Files.** `mkit-git-bridge/src/import.rs`, `verify.rs`, `reconstruct.rs`,
`map.rs`; CLI `commands/git_tools.rs`, `git_import.rs`; shared attestation
verification helpers as needed; `SPEC-GIT-BRIDGE` and `SPEC-GIT-IMPORT`.

**Regression.** The three-commit swap must fail. Also cover another valid twin
signed by the same key, swapped parent/tree edges, malformed retained bytes,
unrelated/forged/wrong-remote head attestations, and valid import/fork/tag paths.
Remove private signing material after creating the fixture and prove audit
still succeeds for intact data. Use bounded graph traversal and cycle detection.

**Compatibility.** Preserve translated object bytes and existing valid claims.
Previously false-positive audits fail with actionable errors. Do not regenerate
signatures or rewrite imported identities to repair the cache.

## 2A. Version request authorization and bind its authority

**Design.** Define an unambiguous v2 signed-envelope encoding containing a fixed
domain/version, service audience, repository identity, full procedure, content
commitment, validity interval and nonce. Servers compare context against their
configured service/repository identity, not an arbitrary client header or
untrusted forwarded Host value. Pin canonicalization and aliases in test vectors.

Make auth mode user-scoped and require destination trust before accessing an
ambient signing key, even without a bearer token. For uploads sign the declared
PackKey and byte length already available at the client call boundary. Pass
that commitment through request metadata; do not collect a streaming body inside
the signing interceptor. Validate the header against it before attributed
effects, then validate actual stream length/digest before final publication.

Define replay storage as an atomic reservation keyed by service/repository,
signer and nonce. Store the operation commitment and result. Identical retries
return the result without charging quota twice; a different commitment under the
same nonce fails. Specify in-progress, aborted-upload and expiry behavior, with
records retained through the entire acceptance interval. Test concurrent replicas.
Clients retain the same operation nonce across retries. Commit quota, deduplication
state and transactional effects together; reservation plus a later result write
alone is insufficient. For external blob storage, define a recoverable publication
state machine using immutable content-addressed stages. A crash after an effect
but before completion recording must not charge or apply that effect again.

**Files.** Connect `envelope.rs`/`client.rs`, CLI `config.rs` and remote dispatch;
`apps/vcs-worker` auth/envelope/service adapters; inventory all shared-protocol
producers and consumers in `apps/repo-worker`, `apps/keys-worker`,
`apps/web/src/lib/repo/envelope.ts`, `apps/spammer-worker/src/envelope.ts`, and
`mkit-repo-client`. Update every participating implementation. Use shared pure
Rust encoding/verification where it fits existing crate boundaries, and common
golden vectors for Rust/TypeScript. Keep replay persistence deployment-specific.
Update `SPEC-CONFIG-SECURITY`, `SPEC-TRANSPORT-CONNECT`, and security guidance.

**Regression.** Cross-server and cross-repository replay; altered pack header,
length or payload; concurrent identical requests; changed commitment with reused
nonce; quota charged once; expired/noncanonical context; untrusted endpoint
refused before signing. Distinguish replay protection from merely fresh timestamps.
Inject crashes between reservation, quota/effect commit, blob publication and
result recording; retry the same nonce after recovery and verify one effect.

**Current contract.** Only auth v2 is accepted. Use one verifier and one replay
ledger, remove obsolete quota/idempotency schema, and store names only in SQLite.
Wrangler class declarations provision new Durable Objects; no data migration,
upgrade ordering, or downgrade path is required before production.

## 2B. Authenticate sparse results with complete tree metadata

**Design.** Ship sparse v2 using complete canonical Tree metadata as its witness,
without unselected file payloads. The verifier accepts the caller's expected
Tree ID, recomputes `Object::id()`, and derives the exact selected entries
locally. Return verified entries from that derivation, rather than trusting a
parallel server-selected list. This establishes both membership and completeness
without a new range/nonmembership proof construction.

Compose tree-local witnesses for recursive prefixes: every required child Tree
must verify against its authenticated parent's reference. An omitted required
witness is an error. Pin prefix semantics and use the existing authenticated
full-metadata path for filters whose CLI semantics cannot be represented exactly.

Keep the existing envelope cap and return a typed limit error for oversized
witnesses. Use authenticated full-tree/pack retrieval as fallback, subject to
normal resource limits. Never treat legacy bitmap verification as a safe fallback.
This first version saves file-payload bandwidth; metadata bandwidth optimization
through range proofs is not necessary to close the defect.

**Files.** `mkit-core/src/sparse.rs`, CLI `sparse_cache.rs`,
`commands/serve/sparse.rs`, HTTP/S3 sparse helpers, sparse integration tests;
`SPEC-SPARSE-CHECKOUT` and canonical identity references.

**Regression.** Wrong trusted root/filter; changed names/modes/object hashes;
omitted/duplicated matches or descendants; malformed ordering/names; empty tree;
oversized witness; stale cache/wire. Pin real v2 golden bytes and verify them
against committed Tree IDs.

**Compatibility.** Version wire and cache formats and the S3 response namespace.
Invalidate disposable v1 caches. Reject v1 at the authenticated API boundary and
advertise v2 only when the receiving implementation is available.

## 2C. Bound aggregate fetch memory

**Design.** Replace retained pack byte vectors with owned staged-file descriptors.
Download one missing pack at a time outside the repository lock, verify its
expected digest using 1A, and complete its stage. Retain paths/keys instead of
all bytes. Under the existing repository lock, read and apply one staged pack
at a time in chain order, preserving closure/signature checks before ref publication.

Use private temporary storage with lifetime-based cleanup and explicit cumulative
disk-budget accounting. Define cancellation, disk-full, digest failure and stale
applied-pack recovery behavior. Do not move the GC exclusion interval to reduce
memory. The initial bound is one pack plus unpack working memory, independent
of chain length for the staging layer's payload buffers. Account separately for
transport shard/download/reconstruction buffers: bound fanout, join or cancel
workers before releasing a stage, and include those buffers in the measured
end-to-end budget. Spool growing stage metadata and newly stored object-ID lists
to disk or enforce explicit count budgets; `stored.extend(report.stored)` must
not simply relocate the chain-length memory problem into metadata. Chunk-level
memory needs a later file-backed pack reader and is not claimed by this fix.

**Files.** CLI `remote_dispatch/packmap.rs` and a staging module if separation
helps; `SPEC-PACKFILE`, `SPEC-TRANSPORT`, `docs/INVARIANTS.md`.

**Regression.** Fetch many moderate packs whose sum exceeds the permitted live
memory. Use deterministic allocation/retained-byte accounting plus a bounded
process measurement, not host OOM. Cover cleanup on every exit, disk-budget
exhaustion, concurrent GC, applied-pack recovery and unchanged ref on failure.
Include shard-enabled transfers and packs containing many small objects, so
metadata or reconstruction buffers cannot evade the memory check.

**Compatibility.** No wire/repository-format change. Reuse streaming APIs where
available but retain a bounded one-pack path for transports that buffer.

## 2D. Negotiate signer capabilities before signing

**Design.** Send Hello with `want_capabilities = true`; validate protocol,
algorithm, key form and payload/frame limits; only then send SignRequest.
Missing required capabilities fail with an upgrade diagnostic. Preserve the
documented meaning of zero payload limit. Accept a terminal handshake Error as
a failure without sending a signing request.

Preserve the whole-conversation deadline, bounded I/O, concurrent stderr drain,
PIN handling, and child kill/reap behavior. Splitting writes into stages must
not reintroduce a blocking subprocess path.

**Files.** `mkit-attest/src/signer_external.rs`, mock signer tests and
`contrib/signers` implementations; `SPEC-EXTERNAL-SIGNER`, `SPEC-ATTESTATIONS`.

**Regression.** Incompatible/absent capabilities, wrong protocol, small/zero
limits, early Error, stalled hello, flooded stderr, valid delayed sign and PIN
exchange. Assert no SignRequest bytes on the incompatible cases.

**Compatibility.** Use existing v1 messages. Verify every shipped signer in its
own workspace/platform lane; do not silently retain capability bypass for old
third-party signers.

## 3A. Preserve authoritative staged state

**Design.** Classify path, mode/status, deletion intent and staged object hash as
authoritative; classify stat observations as disposable. Reject an existing
zero-length index as corruption. Keep absent-initial-index behavior; if stronger
missing-index detection is added, persist an initialization marker rather than
pretending absence alone identifies data loss.

Accept only checksummed index v3. Remove prior-layout readers, migration APIs,
and historical fixtures. Unsupported versions preserve their bytes and fail
safely. Checksums detect truncation/corruption before GC trusts staged roots.

**Files.** `mkit-core/src/index.rs`, `ops/gc.rs`, current index golden fixtures,
CLI index tests; `SPEC-CONVENTIONS`, `SPEC-INDEX`, `SPEC-GC`, invariants.

**Regression.** Preserve staged selections, tombstones and mode changes in
current-format round trips. Zero-length/corrupt indexes block GC. Unsupported
versions are rejected without changing their bytes. Do not auto-rebuild lost
staged selections from HEAD or working files.

**Current contract.** Index v3 only; no conversion or downgrade API.

## 3B. Compare logical contents without changing object identities

**Design.** Keep all valid Blob/ChunkedBlob encodings and their existing IDs.
Build a verified bounded content reader/comparator: same IDs are the fast path;
otherwise compare reconstructed sizes and streamed bytes. Malformed manifests
or missing chunks are errors, not ordinary inequality. Modes remain separate.

When unchanged worktree bytes equal the staged object, reuse its existing ID
in comparison/staging output. Integrate the equality contract into dirty checks,
diff, add, overwrite protections, merge shortcuts and exact rename detection.
For rename candidate indexing, memoize content digest/size by immutable object
ID and confirm equality; this derived digest never replaces a stored object ID.
Keep the current 1 MiB writer policy without retroactively invalidating other
conforming representations.

**Files.** `mkit-core/src/worktree/blob.rs`, `worktree.rs`, `ops/diff.rs`,
merge/rename and dirty-check callers; CLI status/diff tests;
`SPEC-FASTCDC`, `SPEC-OBJECTS`, `SPEC-INDEX`.

**Regression.** Large Blob vs equivalent ChunkedBlob, small ChunkedBlob vs Blob,
fixed-size vs CDC chunking, cleared/racy caches, modes, same-size unequal bytes,
missing chunks, rename and overwrite protection. Existing golden object IDs
must remain identical.

**Compatibility.** No object/schema/signature change. Comparison caches stay
disposable and do not require the new index format from 3A.

## 3C. Make history proofs mean first-parent ancestry

**Design.** Define membership precisely as the first-parent chain ending at an
identified tip. Do not claim all-parent DAG membership. Initial construction
and backfill use the same root-to-tip sequence. First-parent fast-forwards append
every missing commit; no-op ref writes append nothing. Reset, other rewrites,
delete/recreate and rename establish an explicit new branch generation.

Keep generation identity outside the MMR content digest so sequential updates,
one fast-forward and backfill of the same ancestry yield identical roots and
positions. Bind repository, full ref name, generation, tip, leaf count and root
in a versioned descriptor. Verification requires an independently trusted or
authenticated descriptor and explicit expected context. A server-provided root
or descriptor cannot authenticate itself or prove freshness. Provide a local
trusted-snapshot path first; remote callers without a trust anchor must receive
an unsupported/untrusted result rather than a verified-branch claim.

Replace the one-leaf-ahead recovery assumption. Persist transaction metadata
describing previous/target ref and generation; build and sync pending ancestry
state; publish under the mutation locks from 1B. Define crash recovery for each
step, finishing the recorded target or rebuilding from verified authoritative
objects. Withhold proofs until the descriptor matches the authoritative ref.
Never repair a multi-commit fast-forward by appending only its tip.

**Files.** `mkit-core/src/history.rs`, `refs.rs`, CLI history helpers and lifecycle
tests; `SPEC-HISTORY-PROOF`, `SPEC-CONCURRENCY`, `SPEC-REFS`, invariants.

**Regression.** Sequential/fast-forward/backfill equivalence; merge first-parent
selection; no-op; reset; rename; recreation; wrong repository/ref/generation/tip;
untrusted descriptor; crashes at every persistence/publication boundary.

**Current contract.** Canonical ancestry snapshots are the only history
representation. Remove journal compatibility APIs, executor/cache infrastructure
and unused dependencies. Keep generation recovery, context verification and
current snapshot bounds. Missing ancestors fail publication safely. Keep the
feature opt-in.

## Verification and completion gate

Run focused checks per package while iterating. The following commands are from
the current manifests; Rust workspace commands run in `rust/`. New integration
test names will be selected when adding the tests, not assumed to exist today.

```sh
cargo test --locked -p mkit-core --all-features
cargo test --locked -p mkit-transport-file
cargo test --locked -p mkit-transport-http --all-features
cargo test --locked -p mkit-transport-s3 --all-features
cargo test --locked -p mkit-transport-connect
cargo test --locked -p mkit-git-bridge
cargo test --locked -p mkit-attest --all-features
cargo test --locked -p mkit-cli --features git-bridge --test git_import_integration
cargo test --locked -p mkit-cli --features history-mmr --test history_mmr_records_commits
cargo test --locked -p mkit-cli --features history-mmr --test history_mmr_branch_lifecycle
cargo test --locked -p mkit-cli --test applied_packs_fetch
cargo test --locked -p mkit-cli --test fetch_pull_lock_scope
```

Add targeted new tests for CAS, current index integrity, logical equality, memory and
auth, plus existing HTTP/S3 sparse feature tests. Exercise default-off features
explicitly and retain default/no-default-feature build coverage. Validate golden
bytes with real store paths and independent expected identities.

Before completion, run host-appropriate `just ci-macos`/`just ci-linux` and the
applicable security/docs/unsafe-code gates from the root `justfile`. Linux CI
must cover the Linux-only signers; macOS CI must cover macOS behavior. For every
changed standalone Worker run its own locked host tests and wasm32 build. These
are separate Cargo workspaces; a green root workspace does not cover them.
Run `contrib/signers` checks separately as prescribed by CI.

If auth changes affect the web client, use `apps/web`'s actual Bun scripts:
`bun run lint`, `bun run fmt:check`, `bun run typecheck`, `bun run test` and the
applicable build check. Inspect the spammer package's own scripts for its auth
changes. Reuse generated WASM builds during targeted iteration, then run the
real package gates for final evidence. Do not run deploy scripts as verification.

For each finding, the completion ledger must link the spec decision, relevant
commit/diff, regression test, observed pre-fix failure or contract-test rationale,
passing checks, current-format scope and independent review. Final review must
test the composition: sparse data from requested packs, streamed auth commitments,
GC during staged fetch, CAS during history recovery, and staged identity through
index integrity/content comparison. Fix confirmed failures before closing items.

## Scope boundary

This plan resolves the ten numbered findings. The audit's separately acknowledged
absence of attestation/provenance transport remains an explicit product limitation:
document that a native clone is not a portable copy of Git audit context, and
correct any claim that consumers must share the importer private key. Building
a new portable-provenance transport, enabling shallow clone, or supporting
simultaneous served-root/local-worktree mutation is separate product work.

Publishing issues/PRs, committing/pushing, releases and live deployments require
the applicable user authorization. Implementation can proceed from this plan
without another design-planning gate; external rollout is not implied by it.
