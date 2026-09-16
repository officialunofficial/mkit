# Executor brief PR04: feat(core): isolate durable partial workspace state

Status: **planning artifact, do not execute until explicitly authorized**. You are a fresh executor; this brief carries the required context. No prior conversation is assumed.

## Mission and branch contract

Implement only this PR after landed PR02 (PR03 consumer is not a core dependency). At execution time create your own worktree/branch from the current, landed `feat/scoped-workspaces`. Open the PR with **base feat/scoped-workspaces**, never main. **Do not merge.** Integrator, not executor, syncs main at phase boundaries and handles final integration. Planning branch is plan/scoped-workspaces; do not implement there. Confirm clean task worktree and preserve unrelated changes.

mkit is its own BLAKE3 content-addressed protocol, not a Git extension. Core proof verification, selected-data editing and ordinary Commit signing require no owner/grant/service. VCS services separately enforce permissions. Full-clone defaults and existing object/signature/pack/ref bytes stay unchanged. Tier2 hidden names is shelved. “Add changes” means replace existing regular/executable file bytes; no new/delete/rename paths, mode changes, symlink edits, chunk-only editing, auto-rebase or lazy fetch.

Read applicable AGENTS/CLAUDE instructions, CONTRIBUTING.md, docs/INVARIANTS.md, SPEC-CONVENTIONS and relevant specs before editing. Evidence below refers to baseline9f7511d0; verify line drift, report contradictions rather than silently changing contracts. New paths named below are deliverables, not claims of existing APIs.

## Facts you must not rediscover

- layout.rs owns all ordinary .mkit discovery; linked worktrees use a regular pointer file starting mkitdir:, normal single roots use a directory. At540 absent .mkit can produce ordinary-layout behavior.
- Ordinary index/tree/GC assume full storage; EntryStatus::Tree is rejected and indexed files loaded (worktree.rs:459,482). Do not change that.
- PR01 VerifiedPartialSnapshot is privately constructed and verifies complete selected bytes/ancestor Trees; PR02 creates ordinary Commit and complete changed-file raw export without grants.
- Current full index staging is authoritative/checksummed; do not treat stage as disposable cache.
- SPEC-CONCURRENCY existing full-repo lock order and layout rules remain unchanged. New partial state is isolated, not a linked full worktree.

## Exact deliverables

1. New `partial/layout.rs`, `partial/state.rs` (split persistence/lock modules if needed), types ScopedWorkspaceLayout, WorkspaceStateV1, StageStateV1, PendingStateV1, PartialStateError. No CLI command implementation beyond typed ordinary-command refusal seam where needed.
2. Root marker regular .mkit file exactly `mkit-scoped: 1\n`; .mkit-scoped/ holds workspace.bin, base.bundle, stage.bin, objects/, pending/, accepted/, optional service/, workspace.lock. No ordinary index, refs, config signing seed or grant requirement.
3. Workspace state: schema version, local random32-byte workspace ID (locally chosen, not host authority), base ID/bundle digest, sorted selected path+mode+base file IDs, explicit PartialLimits, optional remote publication target, current generation. Optional target is endpoint+repository+exact ref; no permission/owner/grant fields. Secrets/credentials only optional adapter-owned service/ files with restrictive permissions, never base validity.
4. Stage state contains base generation and sorted selected path/mode/staged ID plus required local object IDs; initialized to verified base. Pending state contains generation, candidate ID and exact MKWU digest/path, optional operation32/fingerprint when preparing push, and result state prepared/exported/accepted/conflict/unknown. Serialize exact bytes before external effect. No ref acceptance inferred from export.
5. Durable encoding per file: four-byte magic (MKWS workspace, MKST stage, MKPN pending), version1, canonical commonware payload with explicit bounded fields, then32-byte BLAKE3 checksum over magic/version/payload. Fixed integers big-endian and minimal vector lengths as portable profile. State envelope<=1MiB; existing bundle<=56MiB/update<=56MiB stored separately and digest-bound. Unknown versions/trailing bytes/checksum errors fail closed. Pin exact field order in SPEC-PARTIAL-WORKSPACES durable-state section with code and partial_local golden vectors.
6. Assemble verified snapshot/state/selected files in a private sibling temporary directory. Write and fsync its marker last THERE; then atomic no-replace rename of complete directory to fresh destination and fsync parent. Never expose a markerless destination. Refuse existing destination, nested ordinary repo, conflicting metadata, dual layouts. Temporary sibling directory uses safe mktemp-style creation and recoverable scoped cleanup; never broad recursive deletion. Verify data fully before exposing success.
7. Detect symlink traversal and hardlink aliases, case/Unicode-normalization collisions on actual filesystem, aliases of .mkit-scoped and metadata markers. No normalization of canonical path bytes. Preserve executable mode. Do not broaden Windows platform support.
8. All authoritative state transitions under scoped lock and atomic file replacement with appropriate fsync; use generation check across multi-file transition. Implement a small scoped state transaction/recovery record or immutable generation directory + atomic generation pointer so base/stage/pending cannot mix after crash. Choose immutable generation directories with checksummed generation manifest and one atomic CURRENT pointer; workspace.bin/stage.bin/pending/ names above are logical contents of the selected generation. Materialized working files remain outside it. Document this physical refinement in the design/spec in the implementation PR; readers resolve only CURRENT, never choose highest generation by guess. Orphan generations retained until explicit whole-workspace disposal; no GC feature.
9. API transitions: create; read verified state; atomic replace_stage(expected_generation,...); save_pending; record_outcome. Stage A then working B remains A. One pending candidate. Unknown/conflict retains pending/base; after definite acceptance derive updated selected bundle from old witnesses + candidate objects and atomically advance base/stage/accepted metadata and clear pending, without hidden fetch. Export does not advance. No live service authority/clock check.
10. Integrate full RepoLayout discover/init/ObjectStore open entrypoints: positively identified scoped marker -> typed ScopedWorkspaceRequiresCommand or equivalent. A malformed/corrupt scoped marker/state never means “try parent repo.” Recognized .mkit-scoped CURRENT/generation state without its root marker is an explicit incomplete-install boundary, not permission for init or parent fallback. Do not classify an unrelated same-named user directory alone as scoped or change valid ordinary .mkit directory handling. Ordinary command behavior everywhere else unchanged, including linked worktrees. Audit direct init/store-open bypasses with rg.
11. New partial_local golden area and unit/integration crash/marker tests; docs/INVARIANTS and CHANGELOG. No global GC, index-format migration, lazy fetch, host grants or network calls.

## Acceptance tests

- Fresh create succeeds without service/credential/owner; full verified bundle and complete selected files retained.
- Crash before data, state manifest, CURRENT switch and root marker: reopen sees one valid generation or explicit incomplete install, never mixed state or parent repository.
- Stage A, edit B, persist/restart returns A. Corrupt/empty/checksum/version mismatch aborts, no stage rebuild.
- Pending bytes immutable, candidate mismatch rejected, multiple pending candidate blocked, unknown result preserved.
- Simulated definite accepted result derives next base using only available witnesses/candidate; subsequent edit starts there.
- Ordinary init/status/checkout/gc/store-open in scoped root and nested/-C path refuses; full ordinary and linked-worktree tests unchanged.
- Symlink ancestor, hardlink alias, case/normalization collision, reserved metadata alias fail before outside-root access; platform-specific tests accurately reported.
- Golden consumer reads committed state only; successful decode canonical roundtrip and bounded malformed input.

## Commands and reviewer focus

Focused core layout/state tests, full existing layout/worktree/index regression subset, CLI refusal integration tests where dispatch touched; partial_local golden consumer; fmt/clippy, wasm check for shared modules. Native filesystem modules must not leak unsupported dependencies into wasm. No command family/help additions until PR05; if adding user-visible error guidance, update relevant existing snapshots.

Review authoritative state/crash consistency, CURRENT pointer strictness, lock scope, no parent fallback, no full repo/index/GC behavior change, and local ID not becoming a permission token.

## Quality, process and review

Target one coherent PR, normally <=2,500 handwritten lines including tests/specs. If larger or a dependency is missing, stop and ask the planner to re-slice; never omit negative tests or weaken acceptance. Fresh executor can use more than one bounded session. No deployment, release, chain call or unrelated cleanup.

Wire/durable formats ship spec+code+committed goldens together. New spec front matter: spec/version/status:draft-normative/audience; register docs/specs/README.md. Existing object/disclosure/sparse/signing/pack fixtures must remain unchanged. Golden area includes MANIFEST.txt/.bin/.json; generator runs only with MKIT_WRITE_GOLDEN=1, then unset it for a consumer which reads committed files only (pattern golden_disclosure.rs). Independently construct malformed bytes, not just encode/decode agreement.

Add actual enforced invariant(s), Always/Because/If-violated/Enforced-by, and CHANGELOG Unreleased **SemVer:** additive note. Conventional Commit title below. Crypto-adjacent work requires second reviewer and a PR threat-model note.

macOS: ensure ~/tmp exists, then export TMPDIR="$HOME/tmp". Run focused tests plus cargo fmt/clippy for affected crates; core/wasm changes require cargo check --manifest-path rust/Cargo.toml -p mkit-wasm --target wasm32-unknown-unknown. Run bash scripts/check-spec-status.sh, just ci-scripts, just ci-docs; phase integrator runs just ci plus standalone app gates. Do not present tests you did not run as passing. For bug fixes, include parent-failing regression; feature tests cover contract.

If adding fuzz: rust/fuzz/fuzz_targets/<name>.rs -> mkit_fuzz::<name>_one_iteration -> Cargo registration -> .github/workflows/fuzz.yml -> docs/FUZZ.md; bounded smoke, no unbounded campaign. No zstd/blst dependency added to generic wasm.

## PR title and body

Title: `feat(core): isolate durable partial workspace state`

> Adds isolated authoritative partial-workspace storage and explicit ordinary-command refusal at scoped markers. Local staging and pending commits remain recoverable without full repository storage or hosting credentials.
>
> Base: feat/scoped-workspaces. Depends on landed PR02. Do not merge.
>
> Validation: [exact tests/goldens/wasm/docs checks and results].
> Threat model: [specific adversarial cases and remaining limits].
> Compatibility: [unchanged existing formats/defaults; new opt-in behavior].
> Review: [second reviewer required where crypto-adjacent].

## Required report

Report branch/worktree, base commit, commits, files changed, APIs/formats added, exact tests run/results/unrun gates, golden changes, line count, unresolved risks, evidence of unchanged defaults and PR URL/base. State “not merged.” Do not start the next PR.
