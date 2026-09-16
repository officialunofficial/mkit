# Executor brief PR01: feat(core): verify portable partial snapshot bundles

Status: **planning artifact, do not execute until explicitly authorized**. You are a fresh executor; this brief carries the required context. No prior conversation is assumed.

## Mission and branch contract

Implement only this PR after execution approval and feature-branch creation. At execution time create your own worktree/branch from the current, landed `feat/scoped-workspaces`. Open the PR with **base feat/scoped-workspaces**, never main. **Do not merge.** Integrator, not executor, syncs main at phase boundaries and handles final integration. Planning branch is plan/scoped-workspaces; do not implement there. Confirm clean task worktree and preserve unrelated changes.

mkit is its own BLAKE3 content-addressed protocol, not a Git extension. Core proof verification, selected-data editing and ordinary Commit signing require no owner/grant/service. VCS services separately enforce permissions. Full-clone defaults and existing object/signature/pack/ref bytes stay unchanged. Tier2 hidden names is shelved. “Add changes” means replace existing regular/executable file bytes; no new/delete/rename paths, mode changes, symlink edits, chunk-only editing, auto-rebase or lazy fetch.

Read applicable AGENTS/CLAUDE instructions, CONTRIBUTING.md, docs/INVARIANTS.md, SPEC-CONVENTIONS and relevant specs before editing. Evidence below refers to baseline9f7511d0; verify line drift, report contradictions rather than silently changing contracts. New paths named below are deliverables, not claims of existing APIs.

## Facts you must not rediscover

- verify.rs:5,548 separates ID verification from identity trust; sign.rs:560 verifies ordinary Commit signatures.
- sparse.rs:175 checks complete canonical Tree witnesses, but returned selected entries at190 lose siblings and VerifiedSparseTree fields at39 are public. Do not use that value as an unforgeable trust token.
- worktree.rs:459 rejects EntryStatus::Tree;482 reads every tracked file. This PR does not change ordinary index/tree building.
- store/source.rs:19 ObjectSource is reusable. verify/closure.rs:221,247 only establishes existing decode/hash/reachability properties; a selected snapshot cannot pass full closure and must not pretend to.
- worktree/blob.rs:159 can allocate from untrusted total_size. Bounds precede loading/reassembly. SPEC-FASTCDC:33 permits valid existing alternative representations.
- SPEC-SPARSE-CHECKOUT has16MiB per envelope and different aggregate/depth limits; its fallback is NOT part of this profile.
- mkit-wasm depends on core with default-features=false. All new portable verification compiles without zstd/blst.

## Exact deliverables

1. Add core `partial/{mod,limits,bundle,verify}.rs` (small subordinate modules allowed) and lib export. Proposed types PartialLimits, PartialSnapshotBundle, VerifiedPartialSnapshot, SelectedFile, PartialError. Verified result constructors/fields private; immutable accessors only.
2. Implement `build_partial_snapshot(source, base_id, selected_paths, limits)` over ObjectSource and `verify_partial_snapshot(expected_base, expected_paths, bundle_bytes, limits)`. Neither takes grant, owner, clock, URL or permission DB. No ambient I/O/network. Existing ObjectSource returns an allocated Vec: its caller must bound read allocation. Producer checks returned sizes before decoding/copying; bundle decoder bounds before allocating. Do not add a new streaming source abstraction merely to pretend arbitrary source allocation is controlled. Producer reads only base, necessary ancestor Trees and selected file representations; no history/hidden subtree traversal.
3. Verified value retains complete authenticated ancestor Trees, canonical base Commit/Remix, exact selected entries and complete Blob/ChunkedBlob/chunk bytes, plus explicit selected-only coverage. Verify base canonical object ID and strict signature; return signer facts without interpreting identity trust. Expected base and selection must be independently supplied, not copied silently from producer response.
4. Bundle bytes below; write SPEC-PARTIAL-WORKSPACES v1 draft-normative and registry entry in same PR. Fixed integers big-endian, commonware minimal varint vector lengths, arrays raw. Explain endian exception. No trailing bytes, duplicate IDs or unsorted vectors. IDs derived by object kind, NEVER flat hash of Tree/ChunkedBlob bytes.

```text
magic[4]="MKWB"; version:u8=1
base_id:[u8;32]
paths:Vec<Vec<Vec<u8>>>                    exact component paths
objects:Vec<{id:[u8;32], canonical_bytes:Vec<u8>}>
```

5. Paths strict order by joined raw UTF-8 bytes; duplicates reject. Existing Tree component validity plus profile:1..255 bytes/component, valid UTF-8, no Unicode control chars, slash/backslash/NUL/dot components, root .mkit-scoped alias (ASCII-insensitive). Do not normalize names. Unselected names need only existing canonical Tree rules; do not discard or rewrite them. Filesystem-specific collision validation comes PR04.
6. Default v1 profile:1..256 selected paths; depth32; joined path1024 bytes; aggregate path64KiB; selected file4MiB, sum16MiB; canonical base object<=4MiB; single Tree envelope<=16MiB and100000 entries; dedup witness bytes<=32MiB; Tree visits<=8193; bundle<=56MiB; object count<=65536; individual object<=16MiB. Count and encoded byte checks before allocation, checked arithmetic throughout. Core limits explicit; lower caller limits honored. These profile limits are not global object-format changes or grant restrictions.
7. Require all selected paths exist with regular/executable modes. Follow full ancestor Trees with exact ID/type/canonical roundtrip/name/order checks, derive entries locally, then validate complete selected file representations. Blob/Executable->Blob or ChunkedBlob, selected symlink unsupported; ChunkedBlob chunks->Blob. Check each occurrence length, checked total sum, fixed chunk_size constraints. Valid alternative CDC boundaries accepted; no global rechunking. Reused ID under another edge still checks expected type.
8. Objects set exactly equals required union of base+ancestor Trees+selected representations/chunks. Dedup shared objects; reject extras, including unrelated history. Full Trees authenticate membership, so do NOT require additional inclusion bundles. Proof-only input lacking materialization triples returns InsufficientWitness. No fallback.
9. Error variants at least UnsupportedVersion, NonCanonical, BaseMismatch, SelectionMismatch, InsufficientWitness, WrongObjectType, InvalidSignature, InvalidChunkLayout, IncompleteSelection, UnsupportedPartialOperation, WitnessTooLarge, WorkspaceTooLarge, ValidationBudgetExceeded. Return no partially usable verified value.
10. Add golden_partial_workspace.rs and golden area partial_workspace with positive plain/chunked/shared-ancestor fixtures and independent negatives. Add bounded partial_workspace fuzz target/wiring. No CLI/service/grant/storage-state implementation.

## Acceptance tests

- Wrong base ID; mutated/missing Tree; substituted child/mode; omitted requested file; missing/wrong chunk; incorrect size/layout; root signature failure; duplicate/trailing/nonminimal bytes; unsolicited payload/history all fail.
- Hidden sibling payload/subtree absent: verification succeeds and counting source proves no hidden read.
- Distinct selected files share chunk/object IDs but each edge checked; incompatible roles fail.
- Maximum/over-limit count/byte/size arithmetic rejects before allocations.
- Caller selection different from bundle fails; no producer-selected silent expansion.
- Valid alternate fixed/CDC representations accepted; declared huge size bounded without allocating.
- Full closure verification still reports missing hidden objects; selected verification explicitly does not claim full closure.
- No grant/server/account dependency in public API or Cargo graph; root signer trust remains separate.

Run focused core partial tests, golden_partial_workspace consumer with writer env unset, bounded fuzz smoke, existing sparse/disclosure regressions and no-default-features/wasm build checks.

## Reviewer focus

Authentication against independently expected IDs; preservation of full Trees, not selected-list fabrication; preallocation safety; edge-role validation; no hidden fetch; no permission semantics. Signature-checking is integrity, not identity authorization.

## Quality, process and review

Target one coherent PR, normally <=2,500 handwritten lines including tests/specs. If larger or a dependency is missing, stop and ask the planner to re-slice; never omit negative tests or weaken acceptance. Fresh executor can use more than one bounded session. No deployment, release, chain call or unrelated cleanup.

Wire/durable formats ship spec+code+committed goldens together. New spec front matter: spec/version/status:draft-normative/audience; register docs/specs/README.md. Existing object/disclosure/sparse/signing/pack fixtures must remain unchanged. Golden area includes MANIFEST.txt/.bin/.json; generator runs only with MKIT_WRITE_GOLDEN=1, then unset it for a consumer which reads committed files only (pattern golden_disclosure.rs). Independently construct malformed bytes, not just encode/decode agreement.

Add actual enforced invariant(s), Always/Because/If-violated/Enforced-by, and CHANGELOG Unreleased **SemVer:** additive note. Conventional Commit title below. Crypto-adjacent work requires second reviewer and a PR threat-model note.

macOS: ensure ~/tmp exists, then export TMPDIR="$HOME/tmp". Run focused tests plus cargo fmt/clippy for affected crates; core/wasm changes require cargo check --manifest-path rust/Cargo.toml -p mkit-wasm --target wasm32-unknown-unknown. Run bash scripts/check-spec-status.sh, just ci-scripts, just ci-docs; phase integrator runs just ci plus standalone app gates. Do not present tests you did not run as passing. For bug fixes, include parent-failing regression; feature tests cover contract.

If adding fuzz: rust/fuzz/fuzz_targets/<name>.rs -> mkit_fuzz::<name>_one_iteration -> Cargo registration -> .github/workflows/fuzz.yml -> docs/FUZZ.md; bounded smoke, no unbounded campaign. No zstd/blst dependency added to generic wasm.

## PR title and body

Title: `feat(core): verify portable partial snapshot bundles`

> Adds a portable authenticated selected-file bundle and private verified snapshot type using existing mkit object and witness contracts. It makes no permission or complete-repository claim.
>
> Base: feat/scoped-workspaces. Depends on approved execution + feature branch. Do not merge.
>
> Validation: [exact tests/goldens/wasm/docs checks and results].
> Threat model: [specific adversarial cases and remaining limits].
> Compatibility: [unchanged existing formats/defaults; new opt-in behavior].
> Review: [second reviewer required where crypto-adjacent].

## Required report

Report branch/worktree, base commit, commits, files changed, APIs/formats added, exact tests run/results/unrun gates, golden changes, line count, unresolved risks, evidence of unchanged defaults and PR URL/base. State “not merged.” Do not start the next PR.
