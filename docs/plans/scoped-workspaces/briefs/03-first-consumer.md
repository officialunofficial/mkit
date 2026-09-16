# Executor brief PR03: feat(wasm): integrate partial bundles with hosted workspace editing

Status: **planning artifact, do not execute until explicitly authorized**. You are a fresh executor; this brief carries the required context. No prior conversation is assumed.

## Mission and branch contract

Implement only this PR after landed PR02. At execution time create your own worktree/branch from the current, landed `feat/scoped-workspaces`. Open the PR with **base feat/scoped-workspaces**, never main. **Do not merge.** Integrator, not executor, syncs main at phase boundaries and handles final integration. Planning branch is plan/scoped-workspaces; do not implement there. Confirm clean task worktree and preserve unrelated changes.

mkit is its own BLAKE3 content-addressed protocol, not a Git extension. Core proof verification, selected-data editing and ordinary Commit signing require no owner/grant/service. VCS services separately enforce permissions. Full-clone defaults and existing object/signature/pack/ref bytes stay unchanged. Tier2 hidden names is shelved. “Add changes” means replace existing regular/executable file bytes; no new/delete/rename paths, mode changes, symlink edits, chunk-only editing, auto-rebase or lazy fetch.

Read applicable AGENTS/CLAUDE instructions, CONTRIBUTING.md, docs/INVARIANTS.md, SPEC-CONVENTIONS and relevant specs before editing. Evidence below refers to baseline9f7511d0; verify line drift, report contradictions rather than silently changing contracts. New paths named below are deliverables, not claims of existing APIs.

## Facts you must not rediscover

- workspace-worker currently imports full source in source.ts:145. objects.ts:217 uses Remix only for first imported version; later ordinary Commit.
- workspace.ts:63,85,87,180 stores public workspace state; workspace-state.ts:155 holds service agent seed. This PR is PUBLIC selected-data mode, not confidential hosting.
- contracts.ts:16,104 AgentGrant is application execution consent. Keep it unchanged; it must not enter portable mkit APIs.
- workspace-runner.ts:227,234 checks live execution/publication consent. Keep those checks at application boundary.
- sandbox-files.ts:31,42 caps256 files,256KiB/file,4MiB total, depth32/path1024 and has no-follow capture. Do not widen these limits.
- PR01/02 provide shared native/wasm verification, full ancestor Tree overlay, ordinary Commit and MKWU export. No JS grammar or hashing reimplementation.

## Exact deliverables

1. Add explicit `public-partial-v1` consumer mode, separate from legacy source modes and future private mode. New partial-source.ts, partial-capture.ts and partial-candidate.ts modules (names may be nested directory). Keep source/state/runner dispatch thin. Full source import is never called in this mode.
2. Small owner-authenticated prepare request under existing prepare route gains explicit source kind `partial-bundle`: independently expected baseCommit, exact selectedPaths, bundleDigest. No caller-chosen arbitrary URL or repo credentials. New trusted deployment setting PUBLIC_PARTIAL_BUNDLE_ORIGIN is optional/default absent; absent returns unsupported mode. Fetch only HTTPS `<configured-origin>/<64-lowercase-hex-digest>.mkwb`, no redirects, cookies or forwarded owner auth, stream-bound to the consumer's12MiB bundle cap, hash raw bundle bytes against bundleDigest then verify expected base/selection with wasm. This is public static bundle delivery, not grant-aware GetWorkspace.
3. Source descriptor is signed by existing owner request authentication. Validate path/count/body limits before quota allocation. Reuse existing prepare replay and daily owner/global quotas (directory.ts:76 onward); do not create an unmetered preparation route. Failed verification may not leave an active workspace or unpinned agent key. Persist source identity/mode/verified base data together, not a cache filename trust anchor.
4. Import only selected regular/executable file bytes to fresh sandbox; metadata stays outside shell filesystem. Consumer caps above apply, plus NEW consumer aggregate caps: bundle12MiB and deduplicated witness bytes6MiB (stricter than portable56/32MiB). Pass lower limits to wasm and reject before copying oversized bytes into wasm. Measure near-limit JS+wasm+decode+persistence memory in local runtime before enabling; if it does not fit, lower advertised consumer caps and report the measured decision, never widen portable limits or fall back. No hidden source object requests; do not run legacy closure walk to calculate current version.
5. Preserve existing owner-signed AgentGrant for permission to run hosted agent and application actions. This is distinct from proof validity. Mode must label all selected files as local coverage, not service-authorized write scope. No HostGrant, policy registry or private-mode claim.
6. Capture complete selected-file replacements with stable no-follow reads. Reject additions/deletions/renames/mode changes, symlink/hardlink swaps or filesystem aliases; all-or-nothing capture. Use shared wasm overlay, never rebuild only selected files as a repository root.
7. Partial-mode activation must bypass workspace.ts:244–253's legacy publishedVersion(..., remix=true): persist verified base + execution consent only, with no candidate. First explicit save/task completion creates the candidate. Sign normal unannotated Commit with existing service-held agent key, author same agent identity for this consumer, sole parent supplied base. No synthetic Remix for selected-mode import. Preserve legacy import behavior. Save candidate ID, canonical update bytes, base selection and coverage as `candidate_ready`, not remotely accepted.
8. One candidate pending per partial workspace in this phase. Completed task can report execution completed and candidate ready, but not remote publication. Reject new edit/task/restore requiring progression while pending with explicit PendingSubmission; don't route through legacy version mutation. Existing public file viewing can show selected files only with coverage. Generic history/clone/fork paths requiring full closure return unsupported for this mode; do not fabricate full history.
9. Add owner-session-only `GET /api/workspaces/<id>/partial-update` returning saved MKWU bytes; enforce current session and exact workspace ownership using existing session machinery, no state mutation, no private key. Response coverage/content type appropriate, no-store. No automatic remote push. Public-mode files remain public; update export being owner-only is application behavior, not a confidentiality guarantee.
10. Tests and docs for explicit public mode, deployment setting, prepare payload and candidate/export states. Minimal existing UI coverage/status rendering only if this mode appears there; a full new editor/activation UI is not required. Ship a public test bundle recipe using PR01 producer; no live deployment/upload in this PR.
11. Rebuild existing mkit-wasm bindings through package wasm:build; portable API bytes/errors consumed, not duplicated in TS. Endpoint request/response fixtures committed alongside service documentation; no core object format changes.

## Acceptance tests

- Real public bundle->verify->sandbox edit->ordinary candidate->export round trip with fixed fixture; candidate root equals independent full-data rebuild.
- Spy proves neither full source loader nor unselected object URL is fetched.
- Origin absent, arbitrary digest/path, redirect, oversized body, corrupted bundle/wrong base/selection reject before active state. No forwarded owner credentials.
- Existing prepare replay/quotas upheld; retry cannot allocate two workspaces.
- Existing consumer count/content limits retained; new12MiB bundle/6MiB witnesses tested at/over bounds, with local runtime memory/CPU measurement recorded. >consumer limit can reject an otherwise valid core bundle.
- Link/mode/new/missing path mutations reject capture atomically; draft retained after task failure.
- No claim remote accepted; pending edit/task guard works; export owner session required.
- Legacy first-import Remix and ordinary versions tests unchanged; selected-mode uses ordinary Commit directly.
- Existing live AgentGrant execution checks still run, but independent core fixture succeeds without any grant.

## Commands and reviewer focus

Run npm --prefix apps/workspace-worker run wasm:build, typecheck, test, build (dry-run only), and relevant mkit-wasm tests. If web touched, run its real typecheck/tests/auth gates. Include actual source/capture/runner integration, not only mocked exported functions. Do not run deploy.

Review separation of portable verification and hosted execution consent, source authenticity and bounded fetch, public labeling, key outside sandbox, mode-specific guards on legacy full-repository actions, no premature private or publication claim.

## Quality, process and review

Target one coherent PR, normally <=2,500 handwritten lines including tests/specs. If larger or a dependency is missing, stop and ask the planner to re-slice; never omit negative tests or weaken acceptance. Fresh executor can use more than one bounded session. No deployment, release, chain call or unrelated cleanup.

Wire/durable formats ship spec+code+committed goldens together. New spec front matter: spec/version/status:draft-normative/audience; register docs/specs/README.md. Existing object/disclosure/sparse/signing/pack fixtures must remain unchanged. Golden area includes MANIFEST.txt/.bin/.json; generator runs only with MKIT_WRITE_GOLDEN=1, then unset it for a consumer which reads committed files only (pattern golden_disclosure.rs). Independently construct malformed bytes, not just encode/decode agreement.

Add actual enforced invariant(s), Always/Because/If-violated/Enforced-by, and CHANGELOG Unreleased **SemVer:** additive note. Conventional Commit title below. Crypto-adjacent work requires second reviewer and a PR threat-model note.

macOS: ensure ~/tmp exists, then export TMPDIR="$HOME/tmp". Run focused tests plus cargo fmt/clippy for affected crates; core/wasm changes require cargo check --manifest-path rust/Cargo.toml -p mkit-wasm --target wasm32-unknown-unknown. Run bash scripts/check-spec-status.sh, just ci-scripts, just ci-docs; phase integrator runs just ci plus standalone app gates. Do not present tests you did not run as passing. For bug fixes, include parent-failing regression; feature tests cover contract.

If adding fuzz: rust/fuzz/fuzz_targets/<name>.rs -> mkit_fuzz::<name>_one_iteration -> Cargo registration -> .github/workflows/fuzz.yml -> docs/FUZZ.md; bounded smoke, no unbounded campaign. No zstd/blst dependency added to generic wasm.

## PR title and body

Title: `feat(wasm): integrate partial bundles with hosted workspace editing`

> Exercises mkit's portable partial-edit engine in an explicit public selected-bundle consumer. It avoids full source fetching and produces ordinary signed candidate exports; confidential hosting and remote acceptance remain later phases.
>
> Base: feat/scoped-workspaces. Depends on landed PR02. Do not merge.
>
> Validation: [exact tests/goldens/wasm/docs checks and results].
> Threat model: [specific adversarial cases and remaining limits].
> Compatibility: [unchanged existing formats/defaults; new opt-in behavior].
> Review: [second reviewer required where crypto-adjacent].

## Required report

Report branch/worktree, base commit, commits, files changed, APIs/formats added, exact tests run/results/unrun gates, golden changes, line count, unresolved risks, evidence of unchanged defaults and PR URL/base. State “not merged.” Do not start the next PR.
