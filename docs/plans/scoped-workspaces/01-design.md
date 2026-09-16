# Technical design: portable mkit partial workspaces and optional hosting

Planning only. Baseline `9f7511d0`, inspected 2026-09-16. Names introduced below are proposed APIs/contracts, not existing features. This revision replaces the mandatory core-grant/server-first design. Implementation PRs freeze their new normative bytes together with code and goldens.

## 1. Existing features and actual gaps

| ID | Source at baseline (file:line) | Fact / consequence |
| --- | --- | --- |
| E01 | `rust/crates/mkit-core/src/verify.rs:5,548`; `sign.rs:386,560` | Proofs bind bytes to IDs; identity/trust is application policy. Reuse ID and ordinary signing helpers. |
| E02 | `rust/crates/mkit-core/src/sparse.rs:39,175,190,297`; `docs/specs/SPEC-SPARSE-CHECKOUT.md:43,70,86` | Full canonical Trees authenticate selected entries, but returned fields are public and selected entries omit siblings. New verified overlay must retain checked complete Trees. Sparse envelope max16 MiB; existing full-metadata fallback is unsuitable for confidential delivery. |
| E03 | `rust/crates/mkit-core/src/worktree.rs:459,482`; `index.rs:629,655` | Ordinary builder rejects Tree index state and reads every file; index flattening loses empty directories. Do not force partial state into this index. |
| E04 | `rust/crates/mkit-core/src/store/source.rs:19,88,124`; `store.rs:732`; `worktree.rs:887` | ObjectSource/ObjectSink and store_file_object are reusable. EphemeralSink requires a backing ObjectStore and globally deduplicates: not the portable output collector. |
| E05 | `rust/crates/mkit-core/src/worktree/blob.rs:159,469`; `docs/specs/SPEC-FASTCDC.md:33` | Bound total_size before allocation; use content_eq_bytes for equality. Writer CDC rules do not invalidate alternative valid existing representations. |
| E06 | `rust/crates/mkit-core/src/verify/closure.rs:221,247`; `serialize.rs:600`; `ops/graph.rs:78,95` | Closure checks decode/hash/reachability, not all signatures/types/chunk lengths. Snapshot skips parents; history includes them; Remix sources never followed. |
| E07 | `rust/crates/mkit-core/src/transfer.rs:64,664`; `pack.rs:317` | Reuse PackListNode and raw-only packs. Full closure-difference planner cannot run on partial client. Raw-entry supplied IDs still require object-aware verification. |
| E08 | `rust/crates/mkit-core/src/protocol.rs:40,548,581,606,623`; `rust/crates/mkit-transport-file/src/lib.rs:400` | AccessDenied is already transport-neutral; CAS exists. FileTransport inherits packmap-first/non-atomic advance and locks per ref call, not a durable submission transaction. |
| E09 | `rust/crates/mkit-wasm/src/objects.rs:155`; `chunking.rs:54` | Wasm can sign a root without closure. Chunk-display hashes are not canonical Blob IDs. Core remains default-features=false/no zstd/blst in wasm. |
| E10 | `rust/crates/mkit-core/src/layout.rs:540`; `rust/crates/mkit-cli/src/lib.rs:50` | Explicit discovery/dispatch integration needed; missing .mkit must not fall back into a parent full repo. |
| E11 | `apps/vcs-worker/README.md:45,63`; `src/worker_impl/auth.rs:55,89`; `src/worker_impl/service.rs:183,235,361,511` | Reference service has open writes and ungated reads. This blocks private rollout, not offline core editing. |
| E12 | `apps/vcs-worker/src/worker_impl/service.rs:91,495`; `worker_impl.rs:82`; `worker_impl/refstore.rs:215,368` | Pack-key storage lacks object catalog; R2 writes outside SQL; bridge buffers. Existing RefStore can atomically check/update refs and save request results. |
| E13 | `apps/mkit-worker-common/src/replay.rs:121,138,156`; `rust/crates/mkit-core/src/write_auth.rs:11,29` | Auth-v2 context/signatures reusable; 5min request ledger is not durable semantic outcome history; resumed reservations can bypass admission callback. |
| E14 | `rust/crates/mkit-transport-connect/src/envelope.rs:73,108,188,543`; `rust/crates/mkit-cli/src/config.rs:46,801`; `remote_dispatch/mod.rs:220` | Reads intentionally unsigned; trusted endpoint config is user-owned, not a remote-name parameter. Any signed-read option remains explicit/default-off. |
| E15 | `apps/workspace-worker/src/contracts.ts:16,104`; `workspace.ts:63,85,87,180`; `workspace-state.ts:155` | AgentGrant is an application contract, files are public and service holds agent key. Private mode must not reuse public exposure defaults. |
| E16 | `apps/workspace-worker/src/source.ts:145`; `objects.ts:217`; `workspace-runner.ts:227,234`; `sandbox-files.ts:31,42` | Full-source import today; first import Remix, later Commit; live execution/publication auth. Capture bounds256 files/256 KiB each/4 MiB total/depth32/path1024. |
| E17 | `docs/specs/SPEC-ATTESTATIONS.md:612`; `rust/crates/mkit-attest/src/statement.rs:25,112`; `docs/specs/SPEC-SIGNING.md:137` | Attestations not transported, predicates opaque; existing optional Commit annotations not signed authorization fields. |
| E18 | `rust/crates/mkit-core/tests/golden_disclosure.rs:1`; `docs/specs/SPEC-CONVENTIONS.md:32,84,103` | Committed-only vectors, normative durable formats, distinct signature domains and implementation-independent specs. |

Short paths in a cell resolve against that cell's preceding directory. No assertion that these existing APIs already implement partial editing.

## 2. Separation of mechanisms from policy

### Portable mkit

New `mkit_core::partial` provides verified partial snapshots, replacement overlays, explicit object inventories, partial-update validation and portable bundle codecs. It depends on existing object/verify/store/sign/pack primitives, **not** hosting-support, grants, clocks, account databases or makechain.

Core facts: which ID/path was authenticated; which bytes were supplied; actual before/after entry triples; typed dependency edges; signature verification; whether a selected/full snapshot/history profile completed. Selection means coverage, not authorization.

Core retains existing ObjectNotFound behavior outside the new abstraction. No global lazy/promised objects. No change to Commit/Tree/ChunkedBlob IDs or ordinary valid-history rules. Single-parent/base matching is the **partial-update v1 workflow** contract, not a redefinition of all valid mkit commits.

### Optional exchange and recipient

A partial update is ordinary object bytes plus a bounded manifest. Recipient verifies union with its retained base, then chooses its publication implementation/policy. Generic transport may authenticate callers and return AccessDenied without prescribing roles/grants. Ref CAS and integrity validation remain protocol mechanisms.

Local commit is a real mkit Commit even before another ref points at it. Export does not imply remote publication. A full-data peer can receive it; no centralized service is cryptographically necessary.

### Optional reference hosting

Ownership, grant codecs/registry, live clocks, branch rules, authorized-read sets, admission decisions, durable outcome ledger and receipt signing live in service code. Recommend a separate standalone `apps/mkit-hosting-policy/` package with pure codec/policy helpers and optional wasm binding; workers depend on it, mkit-core and generic mkit-wasm never do. Follow existing multi-workspace crypto-version gates if a new Cargo workspace is used. One direction only: host support -> core verification.

A third party may implement different permissions and still consume the same bundles/commits. Do not expose a hosting grant as a required field of portable workspace state, proof, commit or generic submission.

## 3. Verified partial snapshot and bundle

Proposed API contracts:

- `verify_partial_snapshot(expected_base, expected_paths, bundle, limits) -> VerifiedPartialSnapshot`.
- `replace_files(&verified, replacements, limits) -> PreparedPartialEdit`.
- `prepare_partial_commit(&prepared, author, signer, message, timestamp) -> Commit` (unsigned normal object; existing signer signs it).
- `export_partial_update(&verified, &prepared, expected_unsigned_commit, signed_commit) -> PartialUpdate`.
- `verify_partial_update(base_source, update, profile, limits) -> VerifiedPartialUpdate`, a factual report, never AuthorizedUpdate.

Verified types have private construction/fields; read-only accessors expose facts. Do not accept fabricated public VerifiedSparseTree fields as trust tokens.

Input includes canonical base Commit/Remix bytes, complete canonical ancestor Trees, and every canonical Blob/ChunkedBlob/chunk required for exactly the selected regular/executable files. Expected base and exact expected path list come independently from the caller. The producer's bundle cannot pick its own trust root/selection. Root signature is checked and signer reported; its identity/trust remains caller policy.

Full Trees already authenticate file membership; requiring redundant per-file DISCLOSURE bundles adds bytes without extra assurance. Reuse verifier-kit IDs, canonical serializers, sparse Tree checks and selected-file verification. Step/range-only proofs are **insufficient for this materializing Tier 1 API**: a correct proof without enough sibling triples cannot serialize rebuilt Trees. Return InsufficientWitness, not an invented complete result.

Proposed portable container `PartialSnapshotBundleV1` (new SPEC-PARTIAL-WORKSPACES, draft-normative, PR01):

```text
magic[4]="MKWB"; version:u8=1
base_id:[u8;32]
paths: Vec<Vec<Vec<u8>>>       exact component paths, sorted by joined '/' bytes
objects: Vec<{id:[u8;32], canonical_bytes:Vec<u8>}>
```

Use commonware codec fixed integers big-endian, minimal varint sequence lengths, raw fixed arrays; explicit exception to conventions' default LE. Path order is lexicographic comparison of joined raw UTF-8 bytes including '/' separators (not vector-of-components order). Objects sorted strictly by ID, deduplicated, no trailing bytes; recompute IDs by object kind, not flat hash for Trees/ChunkedBlobs. Require base object and exact required object set; no unrelated payloads/history. Repeated references share bytes but all typed edges are checked. No extra signature: base/object identities authenticate content; selection equality is checked against caller input.

The bundle is a portable exchange file, not an mkit object kind or a full closure export. Base producer accepts a full ObjectSource and a selection; consumer needs no full store or network.

For producer ObjectSource reads, the existing trait returns an allocated Vec: the caller's source must bound read allocation; the producer checks returned object size before decoding/copying. Do not claim core can prevent allocation inside an arbitrary source. Untrusted bundle decoding itself bounds lengths before allocation.

Validation order: encoded/input budgets -> canonical decode -> expected base equality/signature -> Tree root/type/canonicality -> exact selected traversal -> complete selected file dependency/type/length validation -> reject extra objects -> return immutable verified value. No partial state on error. Root/ancestor commit history and hidden subtree bytes remain unverified, explicitly.

## 4. Overlay, file semantics and ordinary signing

Replacements name an existing selected path and supply complete bytes (or explicitly reuse a fully verified selected representation). No caller-provided arbitrary child ID setter in the friendly replacement API. Capture preserves original mode. Reject duplicate/unselected paths, absence, symlink edit, new/delete/rename, directory replacement and executable-bit changes.

Copy every untouched entry triple exactly, including unseen sibling files, symlinks and empty Trees. Rebuild each changed ancestor path occurrence once, bottom-up, applying all sibling replacements together. Identical old Tree IDs can occur at different paths: deduplicate verified object bytes by ID, never rewrite contexts. Editing a/x must not mutate b/x merely because a and b reference the same original Tree. Do not reconstruct from only selected entries and do not populate ordinary EntryStatus::Tree.

Use ObjectSource/ObjectSink and existing store_file_object to produce current file representations. Add bounded canonical object collector without a required backing ObjectStore. Deduplicate within an output set only; neither selected-base nor unrelated store membership suppresses changed-file dependencies in the export. For unchanged content use validated content equality to retain prior ID, even if valid chunk representation differs. All-noop replacement batches return NoChanges; this does not prohibit ordinary empty commits elsewhere. Metadata/type changes are never hidden by content_eq.

Validate chunk occurrence count/type/length, checked total_size, fixed chunk layout when chunk_size!=0. For CDC chunk_size=0, accept existing valid alternative boundaries per SPEC-FASTCDC; new bytes use the existing writer. No sub-file blind/chunk-only editing. Never allocate from untrusted total_size before applying limits.

Produce Commit::new_unannotated, parent=[base_id], new tree, caller author/signer/message/time, existing signing hash/domain/interface. Do not force core author identity to equal signer or infer human identity from either; reference agent host may require its own identity binding. Metadata limits apply to this profile only. Root base may be Remix; new object is ordinary Commit, no imported synthetic Remix. Existing legacy consumer first-import Remix behavior remains unchanged.

A client can verify/preserve untouched **commitments** without verifying hidden payload semantics. Full resulting snapshot validation is recipient work. No claim that the author has complete closure.

## 5. Limits, errors and validation profiles

Core `PartialLimits` is explicit and caller-supplied; no grant lifetime, owner quota or service policy in it. Recommended bounded v1 bundle/CLI interoperability profile:

| Quantity | V1 profile maximum |
| --- | --- |
| Selected paths / components / joined UTF-8 bytes | 256 / 32 / 1,024 |
| One selected file / total selected bytes | 4 MiB / 16 MiB |
| One Tree witness envelope / entries per Tree | 16 MiB / 100,000 |
| Deduplicated witness bytes / Tree visits | 32 MiB / 8,193 |
| Complete bundle / explicit update request | 56 MiB each |
| Raw update pack / object count in either bundle or update / commit message | 48 MiB / 65,536 / 4 KiB |
| Materialized name component / total selected path bytes | 255 bytes / 64 KiB |

These are new profile bounds, not global object-format limits or permission checks. Underlying sparse limits differ (E02); explicitly reject otherwise-valid oversized input. First worker consumer retains stricter256 KiB/file and4 MiB total, and introduces12 MiB aggregate bundle/6 MiB deduplicated witness caps. PR03 measures near-limit JS/wasm/decode/persistence memory before enabling public mode; lower those consumer caps if needed, with explicit error and no fallback. An enormous valid directory can make this profile unavailable even for one tiny selected file. Never fall back to full pack/clone. Operators may lower, never silently truncate or widen advertised profile limits.

Pure verifier also accepts a full-validation profile from recipient: snapshot vs history, maximum objects/bytes/depth and work budget. Proposed host enrollment:100,000 objects/256 MiB canonical bytes/depth128/16 MiB per object. Validation slices <=1,024 fetches and16 MiB decoded bytes, at most30s; measured before enabling. No statement these fit deployed budgets until measured.

Reuse verify_closure_store for ObjectStore or verify_closure_streaming for generic ObjectSource and require report.is_complete(). Add typed semantic validation as a separate helper; old verifier meaning unchanged. Check canonical round trips, strict root/candidate signatures, Tree mode->child type, chunk metadata and each repeated-ID edge expectation. Snapshot skips parents; history uses existing graph::children, never Remix.sources.

Core errors: UnsupportedVersion, NonCanonical, BaseMismatch, SelectionMismatch, InsufficientWitness, WrongObjectType, InvalidSignature, InvalidChunkLayout, IncompleteSelection, IncompleteClosure, UnsupportedPartialOperation, WitnessTooLarge, WorkspaceTooLarge, SubmissionTooLarge, ValidationBudgetExceeded. Host errors are separate (PermissionDenied, GrantExpired, ContentOriginDenied, AuthorityUnavailable). No system clock in core cryptographic validity.

## 6. Explicit transfer and publication guarantees

PR02 offline export uses unchanged PackWriter::new_raw_only, entries sorted by object ID. Export includes candidate, rebuilt Trees and EVERY changed file's complete canonical representation/chunks, even when the same IDs already exist in the selected base or recipient. Deduplicate within the pack only. Unchanged entries remain implicit in the authenticated base. No compression/delta entries, no ordinary plan_pack_with, no global-store dedup. This is **not** a complete closure-profile export; 'new objects' means the explicit update payload, not globally novel IDs.

PartialUpdateV1 manifest in SPEC-PARTIAL-WORKSPACES (code/goldens PR02): magic MKWU/version1; base_id; candidate_id; sorted changes(path components, old mode, old ID, new ID); raw pack hash, length and bytes. Same bounded codec and joined-byte path ordering as bundle. It is unsigned contextual metadata checked against actual objects/diff; candidate Commit already signs parent/root. Reject manifest mismatch, duplicate/extraneous objects and missing changed-file dependencies. No retained-ID optimization in v1. Source representation reuse in the local overlay is allowed, but its complete bytes still travel when used at a changed destination. Signed candidate must verify and match prepared root/parent/fields before export.

PR06 adds policy-neutral exchange metadata: repository identity, exact full ref, random32-byte operation ID, expected base and update bytes. These are publication context, not new Commit signature fields. Authenticated transport binds exact context/request when used. Host credentials are adapter metadata, not part of PartialUpdate. A service-specific grant binding is checked by that service.

Recipient pipeline without policy:
1. Decode/recompute raw entries and candidate.
2. Resolve authenticated base from caller's source.
3. Check partial-update v1 one-parent/base contract, reconstruct actual entry diff, preserved modes/untouched entries, exact manifest and dependencies.
4. Verify resulting snapshot over uploaded objects union retained base with typed helper; report snapshot vs history separately.
5. Return VerifiedPartialUpdate with facts and bytes suitable for recipient publication. Never move a ref as a side effect of verification.

The reusable recipient verifier is a library/offline integration in PR06. Existing seven-verb/FileTransport backends do NOT automatically invoke it. Generic push uploads a client-produced explicit update through existing pack/ref operations; it makes no claim that the remote performed full-closure admission. Never fetch the hidden base into a partial client to supply that missing check. PR11/12 are the first reference network validation/admission receiver.

An optional generic publication adapter uses existing upload/append-only PackListNode/expected-head CAS. Ordinary full recipients can ingest the objects. Private hosts must NOT expose this generic bypass to restricted principals; PR08 enforces that.

**Do not claim existing FileTransport provides atomic head+packmap+result.** Its advance is packmap first, then head, safe for append-only packmaps; head conflict may leave a harmless superset packmap. Never reset packmap/history. After ambiguous completion with no durable ledger, return PublicationUnknown and preserve candidate; reading today's head alone cannot prove historical acceptance. Do not add a cross-writer local journal in this epic. Pure receiver tests use a complete base store; file publication tests cover actual existing semantics. No full-history guarantee for a snapshot-only recipient.

Managed service PR12 provides stronger advertised DurableResults semantics: stable operation ID/body fingerprint, saved outcomes across restarts and later heads, atomic mutable publication. Generic client inspects advertised capability; no fabricated receipt/guarantee for transports that lack it. RefConflict remains an explicit conflict, not automatic rebase. Core commit/export remains usable if no recipient supports exchange.

## 7. Local state and commands

Separate ScopedWorkspaceLayout. Root .mkit is a regular file containing exactly `mkit-scoped: 1\n`; state in .mkit-scoped/, no ordinary index/ref store. Normal discovery/init/store-open explicitly refuse recognized scoped roots, including upward searches and -C. Unknown/corrupt marker is not permission to fall back to parent repo. Creation uses a fresh directory and atomic marker-last publication; failed install never appears complete.

```text
.mkit
.mkit-scoped/
  workspace.bin        checksummed version, base, selection, limits; NO grant
  base.bundle          complete verified portable bundle
  stage.bin            authoritative staged IDs/modes/dependencies
  objects/<id>         produced canonical objects
  pending/             signed candidate, exact update/request, outcome
  accepted/            local accepted-version metadata
  service/             OPTIONAL adapter credentials/receipts, not core validity
  workspace.lock
<selected regular/executable files>
```

Path validation uses canonical repository components; filesystem materialization additionally rejects control characters, reserved .mkit-scoped aliases, symlink/hardlink traversal and collisions on actual case/normalization behavior. Do not normalize signed names. Preserve executable mode; Windows remains unsupported.

After definite publication success, derive a new verified selected bundle from old witnesses plus candidate/rebuilt Trees and selected file representations, then atomically update base/stage/accepted metadata and clear pending. No hidden fetch. PublicationUnknown retains old base and exact pending bytes until explicit resolution/abandonment; export alone never advances remote-associated base.

The tree above names logical state. Physically PR04 stores workspace.bin/stage.bin/pending metadata in immutable generation directories with a checksummed generation manifest and one atomically replaced CURRENT pointer. Readers resolve only CURRENT, never guess the newest directory. Base/update payloads are separately immutable and digest-bound. This provides coherent multi-file local transitions; it is not a remote publication journal. Orphan generations remain until explicit whole-workspace disposal.

Installation assembles the complete workspace in a private sibling temporary directory, writes/fsyncs its marker last there, then atomically renames without replacement to the destination and fsyncs the parent. Never expose a markerless destination. Discovery also treats recognized scoped CURRENT/generation state without its root marker as an incomplete-install error boundary, not parent fallback. An unrelated same-named user directory alone is not a scoped marker; valid ordinary .mkit directory handling remains unchanged.

State is authoritative and checksummed, never silently rebuilt from working files. Stage A then edit B must commit A. One pending candidate at a time in v1; export does not advance remote base. Allow offline creation/staging/commit without service/. Further candidate creation waits for accepted result or explicit local abandon (confirm disposal of unpublished work). Hosted expiry never invalidates local objects.

All JSON outputs: workspace_mode="scoped"; base_commit; selected_paths; coverage={content:"selected-files", history:"partial", verification:"selected-only"}; command-specific pending/publication status. No mandatory grant_id/read/write capability claim. Host adapter may add separately labeled authorization status.

Human prefix: "Scoped workspace: N selected files; repository content and history are partial."

| Command | Semantics |
| --- | --- |
| workspace create --bundle FILE --base ID <dir> | Independently pinned base; inspect bundle selection and require explicit --path values or --accept-bundle-selection; verification before installation. No grant/network. |
| workspace create --remote URL --base ID --path PATH... <dir> | Optional partial endpoint; exact selection expected; unsupported/oversized returns error, no full-clone fallback. Host credential supplied separately. |
| workspace status | Base↔stage and stage↔working for selected paths only; missing selected file is unsupported deletion; extras untracked/outside-selection. |
| workspace diff [--cached] [-- paths] | Working↔stage, or stage↔base; selected bytes only; no cross-selection rename detection. |
| workspace add -- paths / --all | Stage complete replacement bytes for selected existing files, preserve mode; whole batch rejects unsupported changes. Core selection is not host write permission. |
| workspace commit -m MESSAGE | Offline ordinary signed one-parent Commit; no permission/clock/network query. Existing signer interface. |
| workspace export --output FILE | Export pending PartialUpdate; does not claim remote acceptance or full closure. |
| workspace push | Explicit objects, pinned ref/base CAS, transport-specific result semantics. Fresh service authorization if that host requires it. No automatic force/rebase/fallback. |
| workspace log | Base and locally retained versions only; stop with unavailable-history boundary; no automatic ancestors or Remix sources. |
| workspace checkout / merge / rebase / gc | UnsupportedPartialOperation; ordinary equivalents refuse scoped marker too. |

Core can stage any selected file. A host can provide read-only supporting files and reject publication of their changes; its client UI may block earlier, but this is not a core proof/selection permission bit.

## 8. Optional host access model and grants

Reference standalone host stores its own operator-provisioned immutable owner and generation-bearing reader/writer membership; one deployment=one repository. No first-caller claim, chain lookup or “writer implies delegation.” Future adapters may supply identity/authority evidence, never mkit object validity. Ownership transfer/recovery not hidden in this MVP.

Managed-access artifact/default-off feature uses dedicated bindings/origin; default artifact unchanged (including R2-only reads). Managed artifact requires configuration and persisted identity/latch; missing config, DB error or downgrade never opens access. No public bucket/domain/shared deployment/CDN. Arbitrary operator replacement with an old public binary is outside software latch guarantees; deployment profile must prevent accidental cross-binding.

Complete matrix: anonymous/unknown deny; whole reader gets all legacy reads; writer additionally legacy mutations; owner manages policy/grants; grant-only subject gets **no** legacy refs/packs/existence/uploads/updates. All streaming/internal/auxiliary routes included. Managed incomplete routes stay closed. Read checks before response release; already authorized in-flight bytes may finish. No shared caching. Recheck live policy on resumed effects and inside final mutable transaction.

Reuse auth-v2 signing (unchanged domain), add explicit trusted-endpoint signed-read option only for managed clients. Bind sole actual uncompressed Connect message, including DownloadPack request; reject multiple/compressed request frames in this profile. No repository-config-triggered ambient signing or 401 downgrade.

Recommend optional **SPEC-HOSTED-WORKSPACE-GRANTS**, explicitly service-profile normative, not mkit core conformance. Commonware codec in hosting-support, not core; prefer it over DSSE to avoid building attestation transport. An alternative host may use another policy system and the same PartialUpdate.

HostGrantV1: magic MKHG/version1; audience<=512; repository<=255; exact refs/heads ref<=1024; workspace32; issuer32; subject32; receipt_signer32; authority_generation u64; grant_generation u64; initial_base32; not_before/expires u64 milliseconds; max_operations u32; sorted entries(component paths, operation mask); signature64. Default/max admitted operations64/256, paths<=256, mask READ=1 or READ|REPLACE=3, envelope<=256 KiB, lifetime<=24h. Generations>=1, expiry checked without overflow, no globs/delegation. Bounds/path grammar mirror portable materialization profile but remain host policy. Exact codec/endian and vectors freeze in PR09.

Distinct proposed domains `mkit.hosted-workspace-grant.v1\0` for BLAKE3(unsigned bytes) signed with strict Ed25519, and `mkit.hosted-workspace-grant-id.v1\0` for complete envelope ID. Signature validity is not current authority: owner-only registration, matching generations, live state, correct subject request signature and exact repo/ref/workspace/base required. Revocation permanent for incarnation; renewal explicit. Separate registry tracks workspace head; foreign branch movement needs owner-reviewed new base, no implicit reapplication.

Legacy AgentGrant stays application execution consent in legacy mode; never reinterpret its signature as a path grant. New private mode carries separate service credential plus execution consent. Browser uses hosting-specific wasm codec (not generic mkit-wasm); agent key remains service-custodied outside sandbox. Core bundle/commit remains usable without this credential.

## 9. Private disclosure, enrollment and origin

Optional binary HTTP service `POST /mkit/partial/v1/{GetWorkspace,SubmitWorkspace,GetSubmission}` exchanges generic bundle/update payloads; auth-v2 plus host-specific context metadata is separate and fully bound to the authenticated request. RegisterGrant/RevokeGrant/BeginSnapshot/UploadSnapshotPack/FinishSnapshot under a distinct host management namespace. No widening of seven existing transport verbs; no duplicate protobuf dialect. Spec+goldens land with each implemented method. UnsupportedCapability is explicit.

GetWorkspace accepts base+exact selection; private host intersects/checks against its registered read grant and rejects widening (never silently returns a different selection). Reply uses portable bundle exactly, no redundant path proofs, arbitrary hash fetch or extra history. Generic producer knows no grant; service authorizes **before** invoking it. Core/CLI cache never decides authorization.

R2 needs explicit catalog: owner uploads existing raw-only snapshot closure packs/manifest, bounded <=16 packs/48 MiB each/256 MiB total. Catalog locators (ID->immutable pack/offset/length) are never trust anchors; rehash reads. Finish verifies typed snapshot/is_complete and publishes readiness for matching current head. Ref/packmap already provisioned by owner; enrollment does not recreate history or change them. Legacy head movement invalidates readiness. Packmap metadata has its own grammar, not commit-root closure checks.

Content-origin policy for a private host:
- A(g,b) is complete canonical file representations currently read-authorized by grant g at workspace base b, including every validated Blob chunk and occurrence length. Merely witnessed sibling IDs/Trees are NOT in A.
- The general safe origin rule is supplied verified bytes or membership in A. **V1 deliberately requires the stronger, simpler case: every changed file representation and every chunk is present in the update**, deduplicated only within its pack. No hash-only reuse from either A or hidden catalog. A future retention optimization would require separately specified evidence and host authorization; it is not implemented here.
- An unchanged hidden entry can remain at its original path, not be moved/reused as readable output. Tree/subtree grafts rejected by exact structural diff.
- Global store presence never substitutes for origin. Supplied bytes equal to hidden data are allowed; a bare hidden hash is not.
- Compute actual typed base→candidate diff and compare manifest; preserve all ungranted entry triples/modes, not merely user-reported text diff or content_eq.

Core reports objects/diff/dependencies and verifies v1's complete changed-file payload. The **host** enforces private publication policy and never lets its broader store repair a missing changed-file payload. A is the authority model for any future authorized-retention profile, not a required core type or implemented wire optimization. A structurally valid candidate may still fail this policy. Friendly bytes-only APIs are not security enforcement against custom clients.

## 10. Managed admission and publication

Ordered host pipeline: bound request/concurrency -> authenticate exact context -> inspect durable result identity -> require fresh live authorization for new/resumed effects -> check base/readiness -> verify raw update/candidate/typed union -> actual diff and host path/origin/ancestry policy -> pin immutable dependencies and prepare packmap -> final transaction rechecks policy/time/base/refs -> persist acceptance/result.

Reference profile requires subject-signed normal Commit, author=subject key identity, exact one parent=workspace head=current ref; unannotated, message<=4 KiB. These are service/profile restrictions, not changes to normal Commit validity. Do not use commit timestamp as grant validity; current service clock controls publication.

Proposed durable record key=(repository,subject,workspace,operation32), immutable request fingerprint and grant incarnation. States reserved->validated->prepared->accepted or saved terminal rejection. New envelope nonce allowed; operation identity stable. Same identity/different bytes conflicts. Existing request TTL cannot evict semantic identity.

R2/SQL are separate: durable reservation/pins -> immutable raw pack and PackListNode writes/read-back -> single RefStore transaction for head+packmap+workspace head+validation certificate+saved result+receipt. No remote calls inside SQL. Crash after acceptance returns saved outcome even after later head changes. Head conflict terminal; packmap-only race may reprepare at most3 times without changing signed candidate.

Persisted leases/fencing revisions cover validation checkpoints and cleanup. Expiry/revocation blocks pending effects, not retrieval of the caller's already saved opaque result via freshly authenticated request. Accepted/rejected identities or non-reusable tombstones retained for repository lifetime; default subject1024/repository100000 total admission slots and grant budget enforced before new rows. Owner alone explicitly raises capacity. Bound pending uploads4/192 MiB per subject; expire unaccepted quarantine within24h of last bounded progress, fence before unpinning. No automatic audit eviction that enables replay.

Optional signed host receipt binds actual accepted base/result/ref/context/request/operation, policy/grant versions, packmap, validator profile and acceptance time. Receipt key pinned in host credential, different from Commit signer; separate domain and committed vectors in PR12. Host grant/receipt retention explicit, not Remix.sources or unattached attestations. Generic core does not require a receipt to recognize a valid Commit.

Sanitize errors before authorization: no object existence, hidden paths or closure inventory. Host-only errors include PermissionDenied, GrantExpired/Revoked, GenerationMismatch, BaseNotReady, ContentOriginDenied, HeadConflict, OperationIdConflict, OperationExpired, AuthorityUnavailable. No global new closure admission on ordinary pushes or commit checks on packmap refs.

## 11. Consumer, privacy and invariants

PR03 public selected-bundle mode is explicitly public/opt-in. A small owner-authenticated prepare request names expected base, exact paths and raw bundle digest; fetch only from configured PUBLIC_PARTIAL_BUNDLE_ORIGIN at /<digest>.mkwb, bounded to the consumer cap and without redirects/forwarded credentials. No arbitrary source URL. Missing setting disables this mode. Reuse existing prepare replay/quotas and execution consent. This is static public bundle delivery, not a grant-aware endpoint. It bypasses full source import, verifies/captures with portable wasm, and stores ordinary candidate plus owner-session export; it does not claim private access or remote acceptance. Existing AgentGrant still governs running the hosted agent, not mkit validity. Selected-mode activation persists verified base plus execution consent without calling legacy publishedVersion(..., remix=true) and creates no candidate. First explicit save/task completion produces an ordinary candidate directly parenting supplied base; legacy Remix import unchanged. One pending candidate blocks further edit/task/restore until later publication/resolution support; label execution completion separately from candidate/remote publication state.

PR13 new private mode persists privacy latch before any import; public listing/files/fork/preview/history/artifacts deny. Only authorized selection reaches sandbox. No full-repository CI, hidden-data execution or broad repository credentials. Subject seed stays outside shell. Publication completion requires saved host acceptance; conflict/revocation preserves draft. No automatic conversion of public workspaces to private.

Tier1 leaks ancestor sibling names/modes/hashes/counts, commit metadata and selected representations. Hidden subtree descendants remain undisclosed. Low-entropy contents can be guessed; IDs correlate across repositories. No hash salt/padding without identity changes. Host is trusted for withholding bytes, not for changing the agent-signed commit.

Add invariants with real tests only in enforcement PRs:
- Proof sufficiency permits local operations independently of host authority.
- Partial selection is coverage, never a grant.
- Untouched triples preserved, absence never deletion.
- Staged selection and pending bytes durable; full clone errors unchanged.
- Partial, snapshot and history verification claims distinct.
- Generic publication guarantees explicitly distinguish CAS, atomic advance and durable result.
- Managed reads/mutations all authorized; hidden IDs cannot be laundered.
- Managed live authority and publication/result linearize together; pending objects pinned.
- Private sandbox/routes cannot access hidden data.

Tier2 later: concrete hidden-name requirement first. Replacement-only edits can fold proofs, but materialization still needs Tree bytes elsewhere. Multiple edits need joint ancestor reconstruction. Pre-position digest skeleton supports reindexing, not name-order placement or absence. Prefer exact prepared result verified/client-signed plus separate materialization receipt if revisited. Intent reapplication is not a signature on arbitrary server output. No new Change object, two-signature Commit, salted IDs or consensus capability here.
