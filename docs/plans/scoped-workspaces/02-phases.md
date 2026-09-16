# Phases and PR plan

Revision: 15 PRs, **3 / 4 / 5 / 3**, replacing the 25-PR server-first plan. Planning only. All implementation PRs target **feat/scoped-workspaces**; no executor merges or targets main. Integrator creates feature branch from current main only after execution authorization, carries approved plans, merges main at each phase boundary and refreshes later briefs against actual feature HEAD.

Core phases do not depend on grants. Optional host track is required only for confidential hosted rollout. Each phase exit is a real usable/tested contract, not an assertion that unfinished service routes are secure.

## Common quality contract

- Estimates S<=800, M~800–1,500, L~1,500–2,500 handwritten lines including tests/specs; exceptional L+<=3,000 for publication. Generated fixtures reported separately, never concealed. These replace the former one-session/1.5k target; fresh executors may need more than one bounded session for L. If scope cannot fit, planner splits before execution, preserving all acceptance tests.
- Each PR independently builds on landed predecessors. No placeholder exposed endpoints or spec-only wire promises. Features incomplete at runtime remain unavailable.
- New specs use spec/version/status:draft-normative/audience, registered in docs/specs/README.md; format change=spec+code+goldens together. Existing object/proof/pack/signature vectors unchanged.
- Goldens in rust/tests/golden/<area>/ with MANIFEST.txt and .json sidecars; writer only MKIT_WRITE_GOLDEN=1; consumer reads committed files only. Follow golden_disclosure.rs; independent malformed bytes required, not encoder self-agreement.
- Invariants use Always/Because/If-violated/Enforced-by with actual tests. CHANGELOG Unreleased **SemVer:** notes. Conventional Commit scopes; second reviewer and threat-model note for crypto, admission and publication.
- Tests: focused crate/unit/property/integration, fmt/clippy; wasm32 check for shared core. macOS executor prepares ~/tmp and exports TMPDIR="$HOME/tmp". Planning runs no application tests/builds/executors.
- Phase gates: just ci, just ci-scripts, just ci-docs plus affected standalone Worker/consumer gates. cargo check --manifest-path rust/Cargo.toml -p mkit-wasm --target wasm32-unknown-unknown. Spec gate: bash scripts/check-spec-status.sh.
- Worker apps are separate workspaces: cargo test/fmt/clippy with their own manifests, native and wasm as CI requires, both default/managed artifacts. Actual local workerd route/DO tests are required for service claims.
- workspace-worker: package typecheck, test, build and wasm:build scripts; web/browser gates when touched. Read current package manifests/CI rather than assuming root just ci covers apps.
- Fuzz target wiring: rust/fuzz/fuzz_targets/<name>.rs -> mkit_fuzz::<name>_one_iteration -> Cargo target -> .github/workflows/fuzz.yml -> docs/FUZZ.md. Bounded implementation smoke only.
- CLI surfaces C: src/lib.rs dispatch; commands/mod.rs and clap; cli.rs HELP_TEXT+test; tests/help_snapshot.rs; docs/CLI.md; man/mkit.1; three completion files; commands/mcp.rs; docs/PARITY.md. Update each affected surface, not only generated help.
- Review exact evidence in design E01–E18. If baseline drifts, record new file:line and reconcile, never silently change the agreed boundary.

## Phase 1 — portable engine and early consumer (3 PRs)

User outcome: supplied verified subset -> local replacement -> ordinary signed Commit and portable export, no hosting authority. Exit A02/A05/A06/A07/A08/A24 demonstrated; first consumer uses shared wasm on explicit public bundles, not full source import.

### PR01 — feat(core): verify portable partial snapshot bundles

- **Size/deps:** L; approved execution, feature branch.
- **Scope/files:** new core partial/{mod,limits,bundle,verify}.rs; reusable typed file/edge helpers; core lib export; SPEC-PARTIAL-WORKSPACES initial bundle/profile sections, registry; golden_partial_workspace.rs and partial_workspace fixtures; fuzz partial_workspace.
- **Contract:** producer over ObjectSource, private VerifiedPartialSnapshot retaining full ancestor Trees, exact caller base/selection, complete selected representations, no hidden reads. No grants/clocks or claim of whole closure. Bounds before allocation.
- **Tests/goldens:** canonical bundle+negative bytes; substituted base/Tree/file, missing selected path/chunk, extra objects, wrong type/size, repeated-ID edge roles, oversized witness, no fallback. Existing sparse/disclosure golden consumption.
- **Docs/reviewer:** trust/coverage/limits/invariant/SemVer; reviewer checks Tree/ChunkedBlob IDs are not flat byte hashes, selected-only completeness and unforgeable verified type.
- **Brief:** [01-verified-partial-snapshot.md](briefs/01-verified-partial-snapshot.md).

### PR02 — feat(core): build and export ordinary partial-edit commits

- **Size/deps:** L; PR01.
- **Scope/files:** partial/{overlay,collector,update}.rs, existing writer/signer adapters, thin mkit-wasm exports, SPEC-PARTIAL-WORKSPACES update/export sections; golden_partial_update.rs/partial_update vectors; overlay fuzz.
- **Contract:** exact selected existing-file bytes, mode preservation, unchanged representation retention, shared ancestor path-occurrence rebuild once (repeated old Tree IDs stay independent), bounded collector, ordinary signed one-parent Commit, explicit raw-only PartialUpdate export. No full store, new object kind or service grant.
- **Tests/goldens:** hidden sibling/empty Tree preservation, two sibling and converging edits, >1MiB full file matches ordinary writer, alternate valid representations, no-op result, unsupported mutations, signature/export native-wasm parity, full-data root equivalence and independent full-store reconstruction plus existing closure verification. Reusable typed recipient API arrives PR06; no dependency on future code. Export alone correctly lacks hidden closure.
- **Docs/reviewer:** object-set definition, signing custody, incomplete-base semantics; second reviewer checks no hidden-store dedup, no distinct Commit signing contract.
- **Brief:** [02-partial-edit-and-export.md](briefs/02-partial-edit-and-export.md).

### PR03 — feat(wasm): integrate partial bundles with hosted workspace editing

- **Size/deps:** L; PR02.
- **Scope/files:** workspace-worker new partial-source/capture/candidate modules and explicit public mode in contracts/state/runner; wasm build bindings; focused tests; minimal web mode/coverage display if needed.
- **Contract:** explicit public selected-bundle import; owner/session execution consent still required, but portable engine receives no grant. No full source fetch. Only selected complete files captured; ordinary candidate directly parents supplied base; candidate/export distinct from remote acceptance. Legacy source/Remix flow unchanged.
- **Tests/goldens:** end-to-end bundle->sandbox capture->candidate verified by core, no hidden object requests, A/B staging-style capture consistency, link/mode/new-path rejection, stricter existing content caps plus new12MiB bundle/6MiB witnesses, measured local runtime memory near limits, unchanged public legacy tests. Consume PR01/02 vectors, no independent JS grammar.
- **Docs/reviewer:** call mode public, not confidential; service-held signer custody; no private-source URLs/credential forwarding; boundary and live execution consent review.
- **Brief:** [03-first-consumer.md](briefs/03-first-consumer.md).

## Phase 2 — native workspace and policy-neutral handoff (4 PRs)

User outcome: usable offline CLI plus explicit transfer without ownership machinery. Local file publication retains existing ordered packmap/CAS guarantees; no false durable acceptance claim. Native commands can speak optional managed exchange later without requiring it for local use.

### PR04 — feat(core): isolate durable partial workspace state

- **Size/deps:** L; PR02.
- **Scope/files:** partial/layout and state codecs/locks, layout discovery/init/store-open refusal seams, SPEC-PARTIAL-WORKSPACES durable state; partial_local goldens.
- **Contract:** marker .mkit file + .mkit-scoped state; authoritative base/stage/pending without grant; private-directory marker-last install then atomic no-replace rename, no parent fallback, scoped locks, corruption fail closed, actual filesystem alias checks.
- **Tests/goldens:** install interruption, staged A/working B, checksum/version corruption, dual/nested markers, -C, ordinary init/status/gc refusal, case/normalization/hardlink/symlink aliases. Old full layout/index untouched.
- **Docs/reviewer:** state vs cache, exact discovery boundary, no new global GC. [Brief](briefs/04-local-workspace-state.md).

### PR05 — feat(cli): inspect and stage authenticated partial workspaces

- **Size/deps:** L; PR04.
- **Scope/files:** commands/workspace/{mod,create,status,diff,add,log}.rs; CLI surfaces C; black-box tests.
- **Contract:** offline bundle creation with independently pinned base and explicit path selection/confirmation; coverage labels; atomic staging; no host permission semantics. Unsupported merge/rebase/checkout/gc. Core selection remains coverage, not writable authorization.
- **Tests/goldens:** JSON/human/help snapshots; exact selection; omitted never deleted; no cross-selection rename; offline/restart A/B; no ambient network/credentials; normal commands unchanged.
- **Docs/reviewer:** all C and invariants; reviewer checks conservative missing/extra-path reporting and complete CLI surface parity.

### PR06 — feat(transport): validate and transfer explicit partial updates

- **Size/deps:** L; PR02; PR04 for client pending persistence integration.
- **Scope/files:** core partial recipient typed-validator/report; transfer explicit-object helper; optional partial-exchange client abstraction/metadata; file/memory transport integration tests; spec and partial_exchange vectors.
- **Contract:** independent library/offline recipient verifier checks raw inventory and actual diff against complete base source; resulting snapshot is_complete plus types/signatures/chunk rules; preserve history packmap. Generic publish uses existing append-only advance/CAS, no owner/grant model; existing backends do not invoke the recipient verifier and no remote admission claim is made. Never full-fetch into partial client. No new local transactional receiver.
- **Tests/goldens:** manifest tamper, type/size failure, exact dependencies, wrong parent, full recipient union, missing history vs snapshot, ordinary packmap preservation, concurrent sibling edits, file packmap-first head conflict and PublicationUnknown after lost reply. Memory model tests do not count as FileTransport atomicity evidence.
- **Docs/reviewer:** separate verify/ingest/publish APIs and capabilities: conditional vs atomic vs DurableResults. Recipient consumes normal objects; generic acceptance says nothing about private-host authority. Freeze exchange context with code/goldens, not a grant envelope.

### PR07 — feat(cli): commit export and push partial workspace changes

- **Size/deps:** L; PR05,06.
- **Scope/files:** workspace/{commit,export,push}.rs, signer integration, pending/outcome persistence, optional remote adapter config, C surfaces.
- **Contract:** real offline ordinary Commit; export file independent of recipient; explicit-object push without full closure walk; one pending candidate; retain drafts on conflict, uncertainty or denial. Durable-result recovery only where advertised; no “current head proves historical acceptance.”
- **Tests/goldens:** no-grant offline round trip, external signer failure, complete local recipient interoperability, unsupported remote/no fallback, lost reply preserves pending, published vs exported distinction, mandatory coverage JSON.
- **Docs/reviewer:** no local expiry check, no embedded service credential in portable state; transport-guarantee UI; all C.

## Phase 3 — optional managed hosting (5 PRs)

User outcome: confidential subsets and restricted publication on a dedicated deployment. Host permissions never become mkit validity rules. No makechain adapter. Managed partial mutation routes remain closed until PR12.

### PR08 — feat(transport): enforce optional managed repository access

- **Size/deps:** L; independent of core PR01–07, lands after phase2 for review order.
- **Scope/files:** vcs-worker access_policy/access_store modules, thin auth/service/refstore hooks; managed Cargo/deployment profile; optional Connect signed reads and user-only client setting; SPEC-SERVER-ACCESS and service request fixtures; workerd tests.
- **Contract:** provisioned owner, <=256 collaborators, policy generation CAS; owner-only policy management; full legacy read/write route matrix; no first-caller claim; default artifact/dependencies unchanged. Auth before bytes, effects-time recheck including resumed uploads. Dedicated protected storage; no downgrade fallback.
- **Tests/goldens:** every route/principal including streaming DownloadPack/PackExists/internal aliases; exact read framing/body; policy races/outage/restart; revoked reservation resume; default unsigned-read regression; profile config/admin fixtures.
- **Docs/reviewer:** route inventory, deployment isolation, typed unavailable vs deny, owner bootstrap/recovery boundary. If complete enforcement exceeds2.5k lines, split plumbing/enforcement with every managed route closed until both land; do not expose partial protection.

### PR09 — feat(transport): add service-local workspace grants

- **Size/deps:** L; PR08.
- **Scope/files:** apps/mkit-hosting-policy codec/verification and optional wasm binding; vcs-worker grant_registry; service owner registration/revocation routes; SPEC-HOSTED-WORKSPACE-GRANTS; hosted_grants vectors. No mkit_core::grants.
- **Contract:** canonical owner-signed exact-path/read/replace credential; generation/time/repository/ref/subject/base/receipt pin/budget; registered live authority distinct from signature. No chaining. Legacy AgentGrant remains execution consent; private activation later.
- **Tests/goldens:** every signed field/context, path widening, expiry/overflow, malformed codecs, wrong issuer, write!=issue, revoked/renewed incarnation, no registry signature-only denial; native/hosting-wasm parity. Same core update under two policies test.
- **Docs/reviewer:** service-only conformance, policy dependency direction, native/browser codec shared without polluting generic wasm; second crypto review.

### PR10 — feat(transport): serve bounded private partial snapshots

- **Size/deps:** L; PR01,06,08,09.
- **Scope/files:** vcs-worker snapshot_catalog/enrollment/disclosure modules, generic partial HTTP client adapter, scoped management routes, readiness/pins; service spec sections and endpoint vectors.
- **Contract:** raw snapshot owner enrollment reusing closure profile, typed complete snapshot certificate, ID->pack locator verification, matching head/retained packmap, exact authorized GetWorkspace produces generic bundle. Budgeted/resumable validation with fenced checkpoints; no arbitrary hash fetch.
- **Tests/goldens:** catalog corruption/wrong offsets, missing chunks, legacy head invalidates readiness, authorization widening, oversized no fallback, resume/fence/resource bound measurement; existing bundle goldens consumed. Does not create branch or reset history.
- **Docs/reviewer:** hidden payload not in public response/cache, authorization before producer, measured Worker limits; rollout closed if measurement fails.

### PR11 — feat(transport): validate private partial-update admission

- **Size/deps:** L; PR06,09,10.
- **Scope/files:** host scoped_admission/origin helpers and tests; core helpers only if genuinely factual/reusable; host spec validation predicates.
- **Contract:** consume VerifiedPartialUpdate, actual diff, subject signature, one-parent/ref/workspace base, granted path/mode restrictions, private content-origin rule (v1 requires all changed-file bytes/chunks supplied), no hidden catalog satisfying changed dependencies. Produce validation facts; **no ref effects**.
- **Tests/goldens:** hidden Blob/chunk/Tree grafts, supplied matching hidden bytes, read-only path edit, mode/parent/ancestry injection, manifest lies, same ID conflicting types; no unreferenced uploads. Bounded admission fuzz wiring.
- **Docs/reviewer:** explicitly distinguish valid mkit commit from unauthorized host publication; second adversarial reviewer attempts laundering through chunks/subtrees/content_eq.

### PR12 — feat(transport): publish managed partial updates durably

- **Size/deps:** L+; PR08–11,06.
- **Scope/files:** submission_store/publication/receipt modules, minimal RefStore transaction integration, R2 quarantine pins, SubmitWorkspace/GetSubmission, client result adapter; service spec and receipt/exchange vectors.
- **Contract:** fenced reserved/validated/prepared/accepted lifecycle; live final authorization; head+packmap+workspace head+certificate+result/receipt one SQL transaction after immutable writes; stable operation identity outlives auth-v2 nonce. Bounded quotas/tombstones, strict head CAS,3 packmap-only retries. Server never signs candidate Commit.
- **Tests/goldens:** crash at every R2/SQL/reply seam, revocation during pause/finalization, same ID/different body, >5min/newer head/restart saved result, stale cleanup worker, capacity exhaustion before row, pinned receipt verification, complete ordinary fetch. Actual workerd DO tests required.
- **Docs/reviewer:** explicit linearization and recovery table, receipt key custody/retention, no network in SQL, no grant bypass through generic endpoints. Two reviewers; do not combine this with grants/catalog implementation merely to lower PR count.

## Phase 4 — confidential consumer and final assurance (3 PRs)

### PR13 — feat(wasm): integrate private hosted partial workspaces

- **Size/deps:** L; PR03,09–12.
- **Scope/files:** workspace-worker private mode/activation/source/publication/recovery, hosting codec bindings, minimal web activation/status, route authorization and sandbox tests.
- **Contract:** privacy latch before import; old public AgentGrant flow unchanged; owner execution consent separate from host grant; only selected files to sandbox; ordinary service-custodied agent signature; conflict/revocation retains drafts; restart queries same operation. No public files/fork/preview/history/artifact bypass.
- **Tests/goldens:** real worker/server round trip, revoked mid-edit, lost response, foreign head, public-route denial, hidden-input spy, captured readonly/mode/link mutation, saved completion only after acceptance. Shared vectors, no JS reimplementation.
- **Docs/reviewer:** custody, public vs private data, no broad credentials/hidden-code execution; consumer-specific caps unchanged.

### PR14 — test(core): cover partial workflow security and interoperability

- **Size/deps:** L; PR07,12,13.
- **Scope/files:** cross-component acceptance suites, property/fuzz harness completion, fault-injection fixtures, feature-target CI coverage, adversarial audit record.
- **Contract:** A01–A28 each maps to runnable evidence; no-grant offline path and alternative host policies demonstrated; native/wasm ordinary root equivalence; private attack/fault matrix.
- **Tests/goldens:** full-client fetch, malformed/canonical corpus, unrelated old goldens unchanged, fuzz wiring/smoke, actual standalone apps; independent reviewer. Significant discovered fixes become separate scoped feature-target PRs, not hidden audit changes.
- **Docs/reviewer:** no false whole-history/authorization/transaction claims; every skipped platform/deployment test explicitly recorded.

### PR15 — docs(core): finalize partial workspace contracts and release audit

- **Size/deps:** M; all earlier PRs and phase4 main sync.
- **Scope/files:** final threat model/audit, specs registry/invariants/CHANGELOG, CLI/MCP/man/completions/parity consistency, deployment and offline recipes.
- **Contract:** observed limits replace planned estimates; portable readiness separately reported from private-host readiness; all docs agree; no mandatory host/chain dependencies; default compatibility signoff. Any new wire change requires its implementation/goldens, not docs-only blessing.
- **Tests/gates:** just ci, ci-scripts, ci-docs plus app/worker/web gates, link/spec checks; second reviewer checks complete acceptance evidence and original scope. No false green for unrun jobs.
- **Handoff:** integrator prepares single feature-to-main PR only after final owner authorization. Executor reports audit, never merges feature or main.

## Dependency and brief policy

Default landing order PR01..15. PR04 needs PR02, not consumer policy. Hosting research can proceed independently, but no executor starts before execution authorization and landed dependencies. CI must build after every PR; unavailable features remain explicit.

First-phase briefs and PR04 are self-contained for fresh executors. The old “first second-phase PR is grant spec” is intentionally superseded: grants now PR09 in the optional hosting phase, and must not be started from the deleted old core-grant brief. Later briefs freeze current code, exact wires and tests at phase start; this map is not permission to improvise missing details.
