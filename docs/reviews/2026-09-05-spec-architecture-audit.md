# mkit specification and architecture evaluation

Evaluated 2026-09-05 at checkout `abaf6f21`. Scope: the 26 `SPEC-*.md`
documents, their conventions, architecture/threat-model guidance, and selected
implementation and test paths. Workflow: `.agents/skills/plan-and-execute/`.
This is an evaluation, not a claim of exhaustive security review or a proposal
to change all formats at once.

The principal weakness is composition: individual components check well-defined
bytes, but several end-to-end claims omit the binding that makes those checks
meaningful. Sparse proofs need to bind to the requested tree; shard manifests
need to bind to the requested pack; import verification needs to bind both
representations; signed requests need to bind to their destination. Another
pattern is treating a local resource as disposable without proving that its
meaning can be reconstructed.

## Method and evidence

Three independent read-only investigations covered storage/concurrency,
transport/sparse/packs, and trust/signing/history. The main investigation covered
Git import/export and cross-cutting specification policy. Findings below include
concrete scenarios and proposed acceptance tests. P1 means fix before relying
on the affected guarantee; P2 means a material interoperability, operational,
or specification-design problem. Priority reflects impact within the affected
feature, not a claim that every feature is enabled by default.

Except for finding 3, scenarios are inferred from inspected source and have not
been executed. Finding 3 was reproduced with the existing local debug binary;
that binary was not rebuilt, so the runtime result is corroborating evidence,
not a certified build of the cited commit. Source inspection independently
shows the same missing checks. No production systems were contacted or changed.

## Findings

### 1. P1 — Sparse checkout proves self-consistency, not membership in the requested tree

**Contract and evidence.** `SPEC-SPARSE-CHECKOUT.md:44` promises verifiable
delivery. At lines 141–152 it defines the tree identity as flat
`BLAKE3(serialize(Tree))` and claims compatibility with commit/store references.
`SPEC-MERKLE-OBJECTS.md:100` instead defines the current domain-bound BMT identity.
`rust/crates/mkit-core/src/sparse.rs:434` follows the obsolete flat recipe;
`object.rs:492` implements the BMT identity. The sparse test at `sparse.rs:1067`
compares against the same obsolete recipe, so it cannot catch this divergence.

There is a deeper gap: `sparse.rs:344` checks entry count, names/filter membership,
and a bitmap against the response's own bitmap root. It does not authenticate
entry `object_hash` or `mode`, or link the bitmap to `manifest.tree_hash`.

**Failure scenario.** Keep a response's manifest, bitmap, proof and entry name;
replace that entry's object hash or mode. The checks do not inspect those
changes. Conversely, comparing an honest response's flat tree hash to the
actual commit's BMT tree reference rejects it. The acknowledged name/index gap
at `SPEC-SPARSE-CHECKOUT.md:181` understates the missing entry authentication.

**Decision needed.** Use the canonical Tree ID and inclusion proofs over
`(name, mode, object_hash, position)` rooted in the caller's trusted tree ID.
Specify completeness/omission evidence separately; a server-selected bitmap
does not establish completeness. Until implemented, describe the existing
verification as a self-consistency check and avoid claiming authenticated checkout.

**Acceptance tests.** Compare manifest identity with `Object::id()` and the
commit reference. Independently change hash, mode, position and matching name;
omit a requested entry. Require rejection against an unchanged trusted root.

### 2. P1 — Shard verification does not bind the response to the requested PackKey

**Contract and evidence.** `SPEC-PACK-SHARDS.md:46` calls the manifest a
content-addressed root of trust; lines 136–141 claim coordinated replacement is
prevented. HTTP (`rust/crates/mkit-transport-http/src/lib.rs:877`, `:933`) and
S3 (`rust/crates/mkit-transport-s3/src/lib.rs:1333`, `:1401`) decode a manifest
and its shards without comparing `manifest.pack_hash` to the requested key.
`rust/crates/mkit-core/src/pack_shard.rs:503` checks reconstructed bytes against
the manifest's own hash.

**Failure scenario.** Request A and receive a self-consistent manifest/shard set
for B. Every internal digest can pass. The shared consumer at
`rust/crates/mkit-cli/src/remote_dispatch/packmap.rs:729` retains the original
requested key, unpacks without an expected-key argument at line 769, and marks
that key applied at line 778. A and B can contain the same objects in different
valid pack orderings, so object/closure/signature validation need not detect the
substitution. This breaks content addressing and applied-pack bookkeeping;
it is not a demonstrated signature bypass.

**Decision needed.** Specify `manifest.pack_hash == requested PackKey` as an
early requirement. Independently check the returned pack digest at the shared
consumer boundary. A lookup URL is not authentication of the manifest contents.

**Acceptance test.** Request A, serve valid B and its shards, and require rejection
before object-store writes or applied-pack recording.

### 3. P1 — Git fork audit verifies two objects independently without proving their correspondence

**Contract and evidence.** `SPEC-GIT-BRIDGE.md:656` requires checking an imported
twin's signature and the retained Git bytes' SHA-1. Those predicates do not
establish that the twin is the translation of those Git bytes.
`rust/crates/mkit-cli/src/commands/git_tools.rs:232` implements exactly these
independent checks. At line 433 the imported-tip attestation check only tests
whether the directory lists any envelope; it does not establish the predicate,
subject, Git ID, remote or verified signer required for an import claim.
`SPEC-GIT-IMPORT.md:240` makes that provenance attestation authoritative.

**Reproduced scenario.** Create a Git repository with three commits; import it;
run `mkit git verify --fork-audit`. Swap the mkit-hash halves of the two non-head
commit rows in `.mkit/git/upstream/map`, preserving both Git IDs and all object
bytes. Run the audit again. Both runs return exit 0 and:

```text
ok: 0 bridge-translated (0 unsigned), 3 imported-vouched, 0 content-derived
```

The temporary fixture was deleted after the experiment. A two-commit variant
that also swapped the head failed on missing head attestation, which is why the
three-commit case matters: the head check does not protect intermediate mappings.
This demonstrates an audit false negative for corrupted/swapped local state,
not a claim of a remote path that modifies local cache files.

**Decision needed.** Define a correspondence verifier that re-derives the
translation's unsigned fields and parent/tree mappings from retained Git bytes,
then verifies the stored signature. Verify the required head attestation's actual
claim and signer, either directly or through a shared verifier. A signed mkit
closure binds its own objects; it does not validate an arbitrary external map.

**Acceptance tests.** Swap two intermediate mappings, substitute another valid
commit signed by the same importer, and supply an unrelated attestation at the
head. All must fail. Retain successful ordinary and fork-boundary audit cases.

### 4. P1 — Request signatures are transferable across destinations

**Contract and evidence.** `SPEC-CONFIG-SECURITY.md:82` classifies
`transport_auth` as safe for repository control. Yet
`rust/crates/mkit-transport-connect/src/envelope.rs:111` signs procedure, body
digest, timestamp and idempotency key without destination/service audience.
The streaming form at line 120 also omits the body commitment.
`rust/crates/mkit-cli/src/config.rs:1181` permits repo-selected Connect endpoints
when no bearer token is present, while `remote_dispatch/mod.rs:253` selects the
user's existing signing key.

**Failure scenario.** A destination receiving a legitimately signed request can
forward it to another deployment that accepts that key during the freshness
window. A streaming establishment signature is not tied to one pack's bytes.
The current demo Worker attributes activity/quota to the presented public key
(`apps/vcs-worker/src/worker_impl/auth.rs:190`, `:239`). This is a potential
misattribution/quota-abuse path, not a claim of bypassing a current write ACL:
that Worker explicitly uses open-write demo mode. No replay was executed.

**Decision needed.** Bind the service audience and repository identity into
every signed request. Treat use of ambient signing identity at a new endpoint
as an authorization decision. Bind streaming establishment to a declared pack
commitment, and define replay handling independently of timestamp freshness.
Chosen-message signature security does not prevent reuse of an already valid
authorization in another context.

**Acceptance tests.** Replay a request for A at B under the same accepted key;
replay an upload signature with a changed pack commitment. Require rejection.

### 5. P1 — Ref atomicity is only defined among cooperating writer modes

**Contract and evidence.** `SPEC-REFS.md:247` defines Match against the current
ref; lines 264–275 claim local cross-process atomicity. In
`rust/crates/mkit-core/src/refs.rs:1525`, Any writes without the per-ref lock;
only Match takes that lock at line 1564. CLI `commands/update_ref.rs:88` takes a
per-worktree lock and line 116 selects Any when no old value is supplied, so
linked-worktree callers need not share an outer lock.

**Failure scenario.** Match(A→B) reads A; Any(C) completes; Match publishes B
and reports success. No serial ordering explains both successful operations
and final B. Any means no precondition; it should not mean outside the ref's
serialization protocol. The code already calls an analogous Any/delete race
caller error (`refs.rs:925`), but that restriction does not close the public
CLI/API contract.

The lock-order specification compounds this: `SPEC-CONCURRENCY.md:125` says the
CAS lock is not nested and has no order relative to history/worktree locks.
`refs.rs:1073` explicitly documents history-lock → CAS-lock nesting. This is a
specification contradiction, not a claim of a reproduced current deadlock.

**Decision needed.** Put all mutations of one ref, including unconditional
writes and deletes, under one serialization rule. Extend the total order through
CAS locks and define ordering for multiple-ref operations. Keep the separately
acknowledged file-transport/local-worktree deployment restriction explicit.

**Acceptance tests.** Use a barrier between Match read/write to race Any and
deletion. Include callers from distinct linked worktrees and both history feature
settings. Assert outcomes admit a serial history.

### 6. P2 — Multi-pack transfers have no aggregate memory contract

**Contract and evidence.** `SPEC-PACKFILE.md:296` motivates the pack cap as a
memory bound and permits larger transfers split across packs. Lines 321–327
describe buffered parsing in terms of a pack plus decompression. But
`rust/crates/mkit-cli/src/remote_dispatch/packmap.rs:714` accumulates every missing
pack in `Vec<(PackKey, Vec<u8>)>`; only line 759 begins the unpack phase.

**Failure scenario.** An ordinary first clone needs memory approaching the sum
of all missing compressed packs, despite each pack satisfying the cap. A
large-repository feature therefore defeats its own resource-bounding rationale.
No OOM test was attempted.

**Decision needed.** Stage verified downloads into bounded temporary files
outside the repository lock, then apply them in order under the existing locking
contract. Specify memory, temporary-disk, cancellation and cleanup budgets.

**Acceptance test.** Fetch history exceeding the memory budget in aggregate but
fitting individual pack caps; require bounded-memory success and cancellation
cleanup without weakening ref-publication or GC safety.

### 7. P2 — History proofs conflate ancestry with a ref-update event log

**Contract and evidence.** `SPEC-HISTORY-PROOF.md:12` promises an Nth-commit
proof and lines 26–29 motivate ancestry membership. Its update protocol at
lines 280–285 appends a ref target, matching `refs.rs:755`; first-enable backfill
instead appends the first-parent ancestry sequence (`SPEC-HISTORY-PROOF.md:340`).

**Failure scenario.** For A→B→C, a repository recording A then a fast-forward to
C accumulates [A,C]. Backfill at C accumulates [A,B,C]. The same ancestry yields
different positions and roots. Reset to A leaves C in the accumulator even
though C is no longer an ancestor of the tip. This is a semantic defect in the
contract, with current exposure bounded by the default-off history feature.

**Decision needed.** Choose an authenticated ref-event log or an authenticated
ancestry sequence. For events, define event IDs, branch generations and reset
semantics, and do not call ancestry backfill equivalent. For ancestry, specify
fast-forward gaps, merge parents and non-fast-forward changes.

**Acceptance tests.** Compare sequential updates, one fast-forward and backfill;
then reset, rename and recreate the branch. Pin the intended root/index
relationships before testing implementation behavior.

### 8. P2 — Signer capability negotiation cannot satisfy its own sequencing rules

**Contract and evidence.** `SPEC-EXTERNAL-SIGNER.md:131` says to pipeline Hello
and SignRequest. Line 166 says the host MUST verify advertised algorithm/key
form before sending SignRequest. `rust/crates/mkit-attest/src/signer_external.rs:254`
disables capability requests and constructs both frames; lines 548–556 send
them. `require_hello_response` at line 1097 checks the response frame variant.

**Failure scenario.** A signer advertises an incompatible algorithm or key form,
but has already received the signing operation. Implementers cannot comply with
both sequencing instructions; capability rejection may occur after a prompt or
unsupported operation has been initiated.

**Decision needed.** Prefer Hello → validated capabilities → SignRequest. Define
missing/empty capabilities and payload-cap behavior. If pipelining is intended,
remove the pre-send guarantee and specify the weaker contract explicitly.

**Acceptance test.** A mock signer advertises incompatible capabilities or a
smaller payload limit; assert the host sends no SignRequest.

### 9. P2 — Locality is incorrectly used as a proxy for reconstructibility

**Contract and evidence.** `SPEC-CONVENTIONS.md:65` justifies rebuilding old
local index state. `SPEC-INDEX.md:159` accepts zero-length as empty and lines
164–170 reject every older format without migration because the index is local
and advisory. Yet its staged object pointers are durable state (line 153) and
explicit GC roots (`SPEC-GC.md:44`; `rust/crates/mkit-core/src/ops/gc.rs:180`).

**Failure scenario.** Stage content A, then edit the worktree to B. Neither HEAD
nor the worktree reconstructs the staged A selection. Rebuilding the index can
lose that selection; treating truncation as an empty index can remove its GC
roots. Current old-version parsing rejects rather than automatically deleting
the file: this is a policy/design gap, not a reproduced automatic-upgrade loss.

**Decision needed.** Separate authoritative staged entries from disposable stat
caches. Base migration policy on recoverability and user intent, independently
of whether peers exchange the format. Define preservation/export for staged
state and distinguish initialization from unexpected truncation.

**Acceptance tests.** Stage A, edit to B, migrate the index, and preserve staged
A. Truncate an existing index and require a safe recovery path before GC can
discard staged-only content.

### 10. P2 — File-content equality depends on an implementer-selected representation

**Contract and evidence.** `SPEC-FASTCDC.md:104` leaves the chunking threshold
to implementers. `rust/crates/mkit-core/src/worktree.rs:702` and line 775 select
Blob versus ChunkedBlob using a fixed 1 MiB threshold; `ops/diff.rs:267` treats
different object hashes as changed content.

**Failure scenario.** A conforming producer stores a 2 MiB file as a Blob.
mkit rehashes unchanged checkout bytes as a ChunkedBlob after a stat-cache miss,
yielding another ID and a false modification. Exact-identity assumptions also
restrict Git export (`SPEC-GIT-BRIDGE.md:100` and its chunking refusal rules).

**Decision needed.** Either make representation selection normative, or define
content equality independently of storage representation and use it in
worktree/rename comparisons. Specify handling of already valid noncanonical
objects rather than silently redefining their IDs.

**Acceptance tests.** Checkout a large plain Blob and a small ChunkedBlob;
invalidate stat caches without editing bytes; require clean status/diff under
the chosen compatibility policy.

## Architectural priorities

1. **Make trust bindings explicit before extending proof features.** Resolve
   findings 1–4 with end-to-end negative tests rooted in caller-supplied expected
   identities. Internal round trips are insufficient evidence of authenticity.
2. **Make mutation and resource contracts global.** Resolve mixed-writer CAS and
   aggregate transfer bounds before relying on linked-worktree concurrency or
   large-history performance. Per-function atomic writes and per-pack limits
   cannot establish these system-wide properties.
3. **Define semantic ownership and lifecycle.** Decide what history proves,
   which local state is authoritative, how file equality works, and how protocols
   negotiate before adding more compatibility obligations.

An additional acknowledged product limitation deserves an explicit roadmap
decision: native push/pull do not transport attestations
(`SPEC-ATTESTATIONS.md:613`). Import provenance calls those attestations
authoritative, but importer state and raw evidence are also local. The import
design ties identity to the import key and specifies a new fork for key rotation
(`SPEC-GIT-IMPORT.md:222`). Thus a normal native clone is not currently a portable
copy of the Git audit context. Choose a designated importer with a transferable,
verifiable provenance bundle, or deliberately limit downstream clones' claims.
Independent importing is not the same as consuming one designated importer's
published objects; sharing its private key should not be required merely to
consume those objects. This limitation is documented, not newly discovered here.

The report does not treat every declared non-goal as a defect. Deferred shallow
clone, unsupported simultaneous local/file-transport mutation, missing
attestation transport, and default-off proof features have explicit boundaries.
Their importance depends on the product promises mkit intends to make.

## Execution and validation

- Created the repository-local Plan and Execute skill and UI metadata, adapting
  the supplied Uno workflow to mkit's manifests, `justfile`, and evaluation scope.
- Applied its research, synthesis, report execution and independent review phases.
- Validated the skill with the bundled `quick_validate.py` successfully.
- Ran the isolated Git mapping-swap experiment described in finding 3.
- Inspected report evidence and changed-file whitespace/links. Application test
  suites were not run: the changes are a skill and an evaluation document;
  no application or normative protocol implementation was changed.
- Preserved the pre-existing untracked `apps/web/public/install.ps1`.

The acceptance tests above are a remediation plan, not passing tests. Changes
to formats and security contracts need their own versioning decisions and
regression-first implementation work. Nothing was committed, pushed or published.
