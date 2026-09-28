# mkit-server epic (MKIT-29): consolidated implementation plan

**Status:** consolidated plan, ready for review. **Source of truth:** Linear MKIT-29 (snapshot `docs/plans/mkit-server/prd-snapshot.md`),
decisions D1–D36 (D21 superseded by D34; D35 = staging environment; D36 = `X-Mkit-Ref` approved). **This file wins** over `m0-overview.md`, `m1-m2-breakdown.md`,
`m3-m5-breakdown.md` and the briefs wherever they differ. `registry.json` is the machine-readable registry for the Linear
sub-issues. Repo baseline: `main` @ `db0b826b` (workspace 0.4.2).

Settled inputs applied throughout (beyond D1–D31): **D32** (indexed-mode extraction: every plain blob ≥ 64 KiB, configurable,
and every `ChunkedBlob` reassembled once at ingest into one global-CAS object keyed by its manifest id; Range-native serving;
file-level dedup; chunks stay in packs), **D33** (attestation-gated refs and attestation transport are out of this epic; the
generic `pre_receive` hook stays), **D34** (metadata sharded into a namespace coordinator, strongly consistent `(repo, ref)`
ref shards and eventually consistent repo index shards; epoch leases; fixed 4096 prefix fan-out; hash-bucketed ref index;
bounded growth; outbox backpressure; ticket caps; ContentIndex holder sub-sharding), **D35** (staging on `staging-vcs.mkit.sh`,
§6), **D36** (`X-Mkit-Ref` is approved as an optional read-your-writes header on `PackExists`/`DownloadPack`, resolved
against that ref's strongly consistent shard and always subject to the caller's view), the **server-free CLI** criterion (the
CLI already reaches tokio through connectrpc/reqwest clients, so "tokio-free baseline" is replaced everywhere by "no axum,
SQLite or `mkit-server-native` in `mkit-cli`'s default graph", enforced by `scripts/check-cli-baseline.sh` from M0-13), the
backend-agnostic storage contract and the Durable Object constraints from the coordinator, and "cost is not a constraint;
optimize for scalability". The `feat/scoped-workspaces` coordination notes were deleted (another epic reconciles later).

---

### CI policy (authoritative; supersedes any CI-on-branch wording in this plan)

- **No CI runs for `feat/mkit-server`.** Nothing changes GitHub workflow triggers, Cloud Build triggers or rulesets to cover the branch. WP-P0 (CI enablement) is **dropped**: PR #1094 was closed unmerged.
- In place of CI, the evidence is the executor's local gate run (output in the PR body) and a clean adversarial review; all other merge rules are unchanged. The orchestrator re-runs the gate after rebasing and before squash-merging.
- Three pre-existing workflows (`actionlint`, `docs-lint`, `crypto-stack-version`) have no branch filter and may fire automatically on PRs into the branch. Their results are **ignored**: nothing waits on them, and their triggers are not changed.
- **CI runs once**, on the final PR that merges `feat/mkit-server` into `main` (WP-REL). All normal `main` gates apply there.
- `workflow_dispatch` runs are never dispatched against `feat/mkit-server`.
- A WP that adds CI wiring (new jobs, `server-staging.yml`, workflow changes) may add it, but it must trigger only on `main`, `schedule` or dispatch against `main`, never on the feature branch; it runs for the first time on the final PR to `main`. During the epic the same checks run **locally or against staging from the orchestrator's machine**, at the WP and at every milestone boundary, and the results go in the PR or the milestone report.

## 1. Pipeline

**Roles and models.** One orchestrator session. Executors and reviewers run on **Opus** (user model policy: never Fable
unless the user picks it; Sonnet only for broad read-only exploration sweeps). The orchestrator writes each executor prompt
to a scratchpad file and hands over the path; executors don't poll CI and don't comment on GitHub or Linear (the user
handles CI checks and comments).

**Worktrees and branches.** Every executor works in its own git worktree (Agent `isolation: "worktree"`), based on
`feat/mkit-server`. Branch: `mkit-server/wp-<id>-<slug>`, id lowercased with dots as dashes
(`mkit-server/wp-m0-02-storage-traits`, `mkit-server/wp-1-22-shard-model`, `mkit-server/wp-4-10a-content-index-shards`,
`mkit-server/wp-rel-0-5-release`). Stacked spec PRs (S2, S3 on S1) retarget to `feat/mkit-server` once the parent merges.

**Per-PR gate (P4 = A)**, run by the executor and pasted into the PR:

```bash
export TMPDIR="$HOME/.cache/mkit-test-tmp"; mkdir -p "$TMPDIR"   # never macOS /tmp (symlink breaks ~20 sign/attest tests)
cd rust && cargo fmt --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run -p <touched crates> -p <their reverse deps>    # reverse deps: cargo tree -i <crate> -e normal --workspace --depth 1
cargo test --doc -p <touched crates>
# + the WP's area gates (registry column), and full `just ci` when rust/Cargo.lock or mkit-core's public API changes
```

Area-gate codes in the registry: `rust` = the gate above; `wasm` = `cargo check/clippy --target wasm32-unknown-unknown` for
touched wasm crates + `scripts/check-wasm-dep-graph.sh`; `proto` = `buf lint`, `buf breaking` against the branch base,
`scripts/check-generated-fresh.sh`; `docs` = `just ci-docs`, `scripts/check-spec-status.sh` (+ the web spec-index test when
`spec-data.ts` changes); `workers` = the `apps/*` worker gate (fmt, clippy host + wasm32, `cargo test --lib`, wasm build);
`conf-native` = the wire suite in-process on FS+SQLite and S3+SQLite; `conf-wrangler` = `scripts/vcs-worker-conformance.sh`;
`staging` = the staging suite run against staging from the orchestrator's machine (from M1; the workflow is `main`-only); `cli` = `scripts/check-cli-baseline.sh` + CLI e2e; `sec` = `just ci-security`;
`web` = the `web.yml` gate (the `mkit-wasm` wasm-pack build plus `apps/web` lint, test and build);
`full` = `just ci`; `ci-yaml` = `actionlint`; `golden` = golden vectors (SPEC-CONVENTIONS §5) and fuzz build where listed.

**Merge rules.**
- One PR per WP, one concern, independently green, ≲ 1500 changed lines excluding generated code, goldens and fixtures; a WP
  that would exceed it stops and proposes a split.
- Review: an adversarial Opus reviewer checks the diff against the brief, PRD, specs and invariants; each finding is verified
  against the code before it is applied (the user's peer-review practice). The orchestrator squash-merges into
  `feat/mkit-server` after the reviewer's APPROVE and its own local gate re-run on the rebased branch. There is no CI on
  the branch; CI runs only on the final PR to `main`, which the user merges. The three rebuilt spec PRs (S1–S3) also need the user's approval of the normative text before the orchestrator merges them. Every other spec PR (3.6, 4.4, 4.11, 5.1a–c) merges like code, on local gates plus a clean adversarial review.
- M0 changes no proto (`git diff origin/feat/mkit-server -- proto/` empty). Proto changes land only in the proto/spec WPs
  that own them (1.2, 2.2, 3.1, 3.6, 4.4, 5.1a–c), additively (D24), with `buf breaking` green.
- **`apps/vcs-worker/Cargo.lock` refresh.** `workers.yml` builds the worker without `--locked`, so a stale lock doesn't
  fail CI; it silently resolves different versions. Every PR that changes the dependencies of `mkit-server`,
  `mkit-server-worker` or `mkit-worker-common` (from M0-17 on, when vcs-worker depends on them by path) runs
  `(cd apps/vcs-worker && cargo check --target wasm32-unknown-unknown)` (cargo rewrites the lock for changed
  path-dependency requirements; `cargo update -p <crate>` for a deliberate version move) and commits the refreshed
  `apps/vcs-worker/Cargo.lock`.
- File-overlap hazards (e.g. `rust/Cargo.toml` members, `scripts/check-wasm-dep-graph.sh`, `SPEC-TRANSPORT-CONNECT.md`,
  `workers.yml`, `wrangler.jsonc`): merge in registry order; the later PR rebases.
- Nothing is released from `feat/mkit-server`. Crates publish and the version bumps to 0.5 only at WP-REL.

**Milestone boundary routine** (at each exit-gate WP: M0-20, 1.20, 2.15, 3.13, 4.18, 5.13):
1. The exit-gate WP runs its checklist and records evidence in the PR (native, `wrangler dev`, and from M1 **deployed
   staging**: DO bindings are always local in `wrangler dev`).
2. The user signs off the milestone.
3. The orchestrator re-runs the interface reconciliation for the next milestone **against the merged code** (not this plan),
   writes the detailed executor briefs for that milestone (rolling wave) into `docs/plans/mkit-server/briefs/`, updates
   `registry.json`, the Linear sub-issues and the status table in `docs/plans/mkit-server/README.md`.
4. The next milestone's human actions (§6) are scheduled before its first WP starts; the Defaults table (§4) is re-reviewed.

---

## 2. Work-package registry

124 registry entries: P 2, S 3, M0 22, M1 28, M2 14, M3 14, M4 20, M5 20, plus WP-REL (the final merge-to-main release, filed
under M5). **Dropped:** M0-R (Q11 = no), WP-1.1 (folded into S1, Q18), WP-2.1 (folded into S2, Q19). **Added by
consolidation:** 1.21–1.29 (D34 and coordinator inputs), 4.8a (windowed reader), 4.10a (ContentIndex shards), REL.
**Split by review 01 (R-72):** M0-02 → M0-02a + M0-02b, M0-05 → M0-05a + M0-05b (the old ids no longer exist).
`registry.json` carries the same columns, including `area_gates`.
Sizes: S ≲ 400, M 400–900, L 900–1500 changed lines.

| id | title | milestone | track | depends-on | size | area gates | human action? |
|---|---|---|---|---|---|---|---|
| P0 | ~~Enable CI on feat/mkit-server (PR to main)~~ **dropped** (CI policy; #1094 closed) | P | prep | — | S | — | no |
| P1 | Create feat/mkit-server and land docs/plans/mkit-server (merged, #1093) | P | prep | — | S | docs | yes |
| S1 | SPEC-TRANSPORT-CONNECT v2: addressing, policies, GetServerInfo, upload tickets and parts, ref deletion, consistency (#1084, #1090) | S | spec | P1 | L | docs | yes |
| S2 | SPEC-WRITE-GRANTS v1 with signed reads, private repos, URL tokens and epoch leases (#1085, #1089) | S | spec | S1 | L | docs | yes |
| S3 | Admission challenges spec: 402, helper headers and allowlist, replay-after-auth, per-RPC lifecycle (#1086) | S | spec | S1 | M | docs | yes |
| M0-01 | mkit-server crate: core types, errors with response shaping, runtime model, telemetry | M0 | core | P1 | M | rust,wasm,sec,full | no |
| M0-02a | Storage contract core: key-level NamespaceStore with NotAfter deadlines, key layouts, codecs, BlobStore trait, replay model, memory backend | M0 | core | M0-01 | L | rust,wasm,sec,full | no |
| M0-02b | Storage contract layers: ContentIndex over shard partitions, portable export/import, optional StoreMaintenance and StateCommitment hooks | M0 | core | M0-02a | M | rust,wasm | no |
| M0-03 | mkit-server-conformance crate + storage-contract suite (incl. NotAfter, cancellation and crash/restart) | M0 | conformance | M0-02b | M | rust,full | no |
| M0-04 | Deduplicated protocol logic: CAS, refs, UploadValidator, download plan, quota math, auth-v2 glue, redaction | M0 | core | M0-01 | L | rust,wasm,full | no |
| M0-05a | Request pipeline core: stage traits, auth modes, ShardMap, pure planners with bounded re-plan and NotAfter deadlines, unary RPC flow | M0 | core | M0-02a, M0-04 | L | rust,wasm | no |
| M0-05b | Request pipeline streaming and faults: UploadSession, DownloadStream, resumable UploadPack, test-fault seam | M0 | core | M0-05a | M | rust,wasm | no |
| M0-06 | connect feature: vendored transport codegen, TransportService over the pipeline, auth interceptor, health | M0 | core | M0-05b | M | rust,wasm,proto,full | no |
| M0-07 | Black-box wire conformance suite + runner binary; baselines vs today's servers | M0 | conformance | M0-03, M0-06 | L | rust,full | no |
| M0-08 | FS stores with the .mkit layout (fs feature): streaming FsBlobStore, refs-only FsLayoutStore | M0 | storage | M0-03, M0-04 | M | rust,full | no |
| M0-09 | Shared SQL key-value backend SqlKvStore (owned 'static transaction closure, NotAfter, SQLITE_FULL) + mkit-server-native crate with rusqlite | M0 | storage | M0-03, M0-04 | L | rust,sec,full | no |
| M0-10 | mkit-server-native router, tower layers and the mkit-server binary (FS + SQLite; enables `fs`; sqlite refuses file-ref roots) | M0 | native | M0-06, M0-07, M0-08, M0-09 | L | rust,conf-native,sec,full | no |
| M0-11 | S3 BlobStore (native) + in-repo fake S3; S3+SQLite conformance | M0 | native | M0-10 | M | rust,conf-native,sec,full | no |
| M0-12 | ssh-frame session binding in mkit-server (ssh feature), transport-agnostic | M0 | core | M0-05b, M0-08 | L | rust,full | no |
| M0-13 | Port mkit serve (ssh stdio) onto the pipeline; stdio idle timeout; server-free CLI check | M0 | cli | M0-08, M0-12, M0-15 | M | rust,cli,full | no |
| M0-14 | Encrypted listener moves into the mkit-server binary | M0 | native | M0-10, M0-12 | M | rust,full | no |
| M0-15 | Remove --http/--listen-enc from mkit serve and mkit-transport-connect's server feature; docs | M0 | cli | M0-10, M0-14 | M | rust,cli,docs,full | no |
| M0-16 | mkit-server-worker: streaming R2 BlobStore (spawn_local put), Durable Object SqlConn, per-partition DO client | M0 | worker | M0-03, M0-05b, M0-06, M0-09 | L | rust,wasm,web,workers,sec,full | no |
| M0-17 | Port apps/vcs-worker onto mkit-server-worker (streaming dispatch); wrangler dev conformance job | M0 | worker | M0-06, M0-07, M0-16 | L | rust,wasm,workers,conf-wrangler,ci-yaml,full | no |
| M0-18 | release.yml: build (separate cargo invocations), sign, SBOM and provenance for mkit-server archives; release-artifact feature check | M0 | release | M0-10 | M | ci-yaml | no |
| M0-19 | mkit-server container image (multi-arch, signed, attested) | M0 | release | M0-18 | M | ci-yaml | no |
| M0-20 | M0 exit gate: CI wiring, invariants, exit checklist | M0 | conformance | M0-11, M0-13, M0-17, M0-19 | S | rust,conf-native,conf-wrangler,cli,full | no |
| 1.2 | Proto additions and codegen for M1 | M1 | proto | S1, M0-20 | S | rust,proto,wasm,full | no |
| 1.3 | mkit-core: part: commitment and BLAKE3 subtree module | M1 | core | S1 | M | rust,wasm,golden | no |
| 1.4 | Core: multi-repo addressing through the pipeline | M1 | core | S1, M0-20 | M | rust,conf-native,conf-wrangler,wasm | no |
| 1.22 | Core: D34 shard model: D34Shards map, namespace coordinator, ref shards | M1 | core | 1.4 | L | rust,conf-native,conf-wrangler,wasm | no |
| 1.24 | Core + adapters: timers (due_at, kind, ref) and alarm multiplexing | M1 | core | M0-20 | L | rust,workers,conf-wrangler | no |
| 1.5 | Core: namespace_policy, write_policy = owner, startup validation | M1 | core | 1.22 | M | rust,conf-native,conf-wrangler | no |
| 1.6 | GetServerInfo (server) | M1 | core | 1.2, 1.5 | S | rust,conf-native,conf-wrangler | no |
| 1.7 | Ref-shard rows: tickets, reservations, local membership, outbox (planners) | M1 | storage | 1.22, 1.24 | L | rust,conf-native | no |
| 1.23 | Core: repo index shards and the outbox relay | M1 | core | 1.7, 1.24 | L | rust,conf-native,conf-wrangler | no |
| 1.28 | Core: hash-bucketed ref-name index, ListRefs k-way merge pagination; flip Connect deployments to D34 | M1 | core | 1.23, 1.2, 1.8 | M | rust,conf-native,conf-wrangler | no |
| 1.25 | Core: epoch leases (D34 revocation) | M1 | core | 1.22, 1.24 | L | rust,conf-native,conf-wrangler | no |
| 1.26 | Core: default quota exact per ref shard, approximate per namespace | M1 | core | 1.22, 1.24, 1.25 | M | rust,conf-native | no |
| 1.8 | Worker: Durable Object classes per shard kind | M1 | worker | 1.22, 1.24 | M | rust,wasm,workers,conf-wrangler | no |
| 1.9a | Core: BeginUpload with target ref, stateless ticket token and ticket caps (done) | M1 | core | 1.2, 1.5, 1.7, 1.23 | L | rust,conf-native,conf-wrangler | no |
| 1.9b | Core: ticketed UploadPack, upload markers and ticket threshold | M1 | core | 1.9a | L | rust,conf-native,conf-wrangler | no |
| 1.10 | Core: AdvanceRefs consumes tickets, outcomes rows, ref deletion | M1 | core | 1.9b | L | rust,conf-native,conf-wrangler | no |
| 1.11a | Core: stateless UploadPart/CompleteUpload, receipts, MultipartBlobStore and memory backend | M1 | core | 1.9b | L | rust,wasm | no |
| 1.11b | FS multipart, native wiring, shared storage suite and conf-native wire cases | M1 | native | 1.11a | M | rust,conf-native | no |
| 1.12 | Worker: R2 multipart with client-streamed parts through the Worker | M1 | worker | 1.11b, 1.8 | M | rust,wasm,workers,conf-wrangler | no |
| 1.13 | Native: S3 multipart BlobStore | M1 | native | 1.11b | M | rust,conf-native | no |
| 1.14 | Ticket expiry and pre-M3 outbox retention | M1 | core | 1.10, 1.12, 1.24 | M | rust,conf-native,conf-wrangler | no |
| 1.29 | Ops: periodic DO backup export to R2 and per-shard storage alerts | M1 | ops | 1.24, 1.8, 1.25, 1.23a | M | rust,workers,conf-wrangler | no |
| 1.15 | ssh and enc: multi-repo addressing, --principal, implicit session tickets | M1 | cli | 1.5, 1.10 | M | rust,cli | no |
| 1.16 | Client: X-Repository everywhere, identity validation, GetServerInfo, ListRefs paging, ref hint | M1 | client | 1.2, 1.6 | M | rust,cli | no |
| 1.17 | Client: BeginUpload with target ref, ticket threading, nonce/re-sign rule | M1 | client | 1.16, 1.10 | L | rust,cli | no |
| 1.18 | Client: resumable part upload with client-held receipts | M1 | client | 1.17, 1.3, 1.11a | M | rust,cli | no |
| 1.21 | Worker: published-view ref snapshots per ref-index bucket (R2/Cache, debounced) for readers | M1 | worker | 1.28, 1.10, 1.8 | M | rust,workers,conf-wrangler,staging | no |
| 1.27 | M1 conformance: D34, tickets and growth cases (wire, storage, load) | M1 | conformance | 1.9b, 1.10, 1.14, 1.25, 1.26, 1.28 | L | rust,conf-native,conf-wrangler | no |
| 1.19 | Staging vcs-worker deployment config and runbook | M1 | ops | 1.6, 1.8, 1.12, 1.14, 1.18, 1.21, 1.29 | S | workers,ci-yaml | yes |
| 1.20 | CI: conformance and e2e against deployed staging (M1 exit) | M1 | conformance | 1.19, 1.27, 1.13, 1.15 | S | ci-yaml,staging | yes |
| 2.2 | Proto additions for M2 | M2 | proto | S2, 1.2 | S | rust,proto,full | no |
| 2.3 | mkit-attest: Keccak-256, EIP-191, secp256k1 recovery, address derivation | M2 | crypto | S2 | M | rust,wasm,sec,golden | no |
| 2.4a | mkit-attest: grant and epoch statement codec plus the ed25519 scheme | M2 | crypto | S2 | L | rust,wasm,golden | no | (split, see briefs/WP-2.4.md)
| 2.4b | mkit-attest: grant and epoch statement codec plus the ed25519 scheme | M2 | crypto | 2.4a | L | rust,wasm,golden | no | (split)
| 2.5 | mkit-attest: secp256k1-eip191 and webauthn-p256 owner schemes | M2 | crypto | 2.3, 2.4 | M | rust,wasm,golden | no |
| 2.6 | Server: grant-based write authorization, 0x namespaces, error-code alignment | M2 | core | 2.5, 2.2 | L | rust,conf-native,conf-wrangler,wasm | no |
| 2.7 | Server: ref scopes, packmap coverage and the delete flag | M2 | core | 2.6 | M | rust,conf-native | no |
| 2.8 | Epoch: GetGrantEpoch/SetGrantEpoch over epoch leases; revoke races | M2 | core | 2.6, 2.2 | M | rust,conf-native,conf-wrangler,staging | no |
| 2.9 | Server: signed reads, visibility via SetRepoVisibility, read grants, not_found | M2 | core | 2.6, 2.2 | L | rust,conf-native,conf-wrangler | no |
| 2.10 | Client: signed reads and grant header | M2 | client | 2.4, 1.16 | M | rust,cli | no |
| 2.11 | IssueObjectUrl and signed URL tokens (mint and verify) | M2 | core | 2.9 | M | rust,conf-native,golden | no |
| 2.12 | ssh and enc: server-side grant registry (mkit-server grant register) | M2 | native | 2.6, 2.8 | M | rust,cli | no |
| 2.13 | CLI: mkit grant create/add/list and the client grant store | M2 | cli | 2.5, 2.10 | L | rust,cli,docs | no |
| 2.14 | CLI: mkit grant revoke and mkit epoch | M2 | cli | 2.13, 2.8 | M | rust,cli,docs | no |
| 2.15 | Staging: enable M2 features and run M2 conformance (M2 exit) | M2 | ops | 2.7, 2.8, 2.9, 2.11, 2.12, 2.14 | S | ci-yaml,staging | yes |
| 3.1 | Proto: AdmissionChallenge error detail and goldens | M3 | proto | S3, 1.2 | S | rust,proto,wasm,golden | no |
| 3.2 | Core: two-phase Admission (Allow/Challenge/Deny), 402 mapping, GetServerInfo fields | M3 | core | 3.1 | M | rust,wasm | no |
| 3.3 | Core: outcome outbox, OutcomeSink, exactly-one-outcome, backpressure, read outcomes | M3 | core | 3.2 | L | rust,conf-native | no |
| 3.4 | Native adapter: outbox delivery task, CORS/redaction, ssh/enc 'use mkit+https' | M3 | native | 3.3 | M | rust,conf-native | no |
| 3.5 | Worker adapter: outbox delivery timer kind, CORS/redaction | M3 | worker | 3.3 | S | rust,wasm,workers,conf-wrangler | no |
| 3.6 | Spec: SPEC-SERVER v1 (M3 sections) and the mkit.server.hooks.v1 proto | M3 | spec | S3, M0-20 | M | docs,proto,golden | yes |
| 3.7 | Core: remote-hook adapter (remote-hooks feature) | M3 | core | 3.6, 3.3 | M | rust,wasm | no |
| 3.8 | Native hook channels: HTTP and signed webhook outcome sink | M3 | native | 3.7, 3.4 | M | rust,conf-native | no |
| 3.9 | Worker hook channels: service binding and Queue outcomes | M3 | worker | 3.7, 3.5 | M | rust,wasm,workers,conf-wrangler | no |
| 3.10 | Client: 402 detection -> AdmissionRequired, receipt passthrough | M3 | client | 3.1 | M | rust,cli | no |
| 3.11 | Client: admission_helper, header allowlist and hard-reserved set (D30) | M3 | client | 3.10 | L | rust,cli,docs | no |
| 3.12 | Stub MPP hook server and helper; end-to-end tests (M3 exit) | M3 | conformance | 3.8, 3.9, 3.11 | L | rust,conf-native,conf-wrangler | no |
| 3.13 | Wire conformance: admission, outcomes and backpressure on both adapters and staging | M3 | conformance | 3.4, 3.5, 3.12 | M | rust,conf-native,conf-wrangler,staging,ci-yaml | yes |
| 3.14 | Docs: TypeScript mppx reference Worker (documentation only) | M3 | docs | 3.6 | S | docs | no |
| 4.1 | mkit-core: pack-ruzstd decode feature and dep-graph check | M4 | core | P1 | S | rust,wasm,sec | no |
| 4.2 | mkit-core: repo-isolated delta-base seam and incremental push verification | M4 | core | P1 | L | rust,wasm,full | no |
| 4.3 | mkit-core: build_disclosure over a generic object source | M4 | core | P1 | S | rust,wasm,golden | no |
| 4.4 | Spec: indexed mode, D32 extraction, PendingVerification detail | M4 | spec | 3.6 | M | docs,proto,golden | yes |
| 4.5 | Server: per-repo object index in repo index shards | M4 | core | 4.4, 1.23, 1.8 | M | rust,conf-native | no |
| 4.6 | Worker: object index in RepoIndexShard DOs (limits, batching, alerts) | M4 | worker | 4.5 | S | rust,wasm,workers,conf-wrangler | no |
| 4.7 | Server: indexed ingestion and pre-receive verification (native/inline) | M4 | core | 4.1, 4.2, 4.5 | L | rust,conf-native | no |
| 4.8a | mkit-core: windowed, streaming pack reader | M4 | core | 4.1, 4.2 | M | rust,wasm | no |
| 4.8 | Worker: async verification as checkpointed alarm slices | M4 | worker | 4.7, 4.6, 4.8a | L | rust,wasm,workers,conf-wrangler,staging | yes |
| 4.9 | Client: PendingVerification polling | M4 | client | 4.4, 1.16 | M | rust,cli | no |
| 4.10a | ~~ContentIndex shards on Workers and holder sub-sharding~~ Deferred (R-131) | M4 | storage | 4.4, 1.8 | M | rust,wasm,workers,conf-wrangler | no |
| 4.10 | Server: D32 extraction into the global object CAS, holds and holders | M4 | core | 4.7 | L | rust,conf-native | no |
| 4.11 | Spec: HTTP serving and proofs (#1088) | M4 | spec | 4.4 | M | docs,golden | yes |
| 4.12 | Server core: HTTP object serving (http-objects feature) | M4 | core | 4.11, 4.7, 4.10 | L | rust,wasm | no |
| 4.13 | Admission on HTTP reads (paid downloads) with ReadServed outcomes | M4 | core | 4.12, 3.3 | S | rust | no |
| 4.14 | Proofs: query ranges, MKDS core/wasm verifier, boundary-aware builder and Workers prefetch (R-109) | M4 | core | 4.12, 4.3, 4.11 | M | rust,wasm,golden | no |
| 4.15 | Private serving via M2 signed URLs and read auth | M4 | core | 4.12, 2.9, 2.11 | M | rust,conf-native | no |
| 4.16 | Adapters: HTTP serving, Range, GET/HEAD CORS and query-string redaction (R-109) | M4 | native | 4.12 | M | rust,wasm,workers | no |
| 4.17 | Pre-receive policy hooks: allowed signers per ref, fast-forward-only grants | M4 | core | 4.7, 4.4, 2.7 | M | rust,conf-native | no |
| 4.18 | Conformance: indexed mode and serving wire suite (M4 exit) | M4 | conformance | 4.8, 4.9, 4.10, 4.14, 4.15, 4.16, 4.17 | L | rust,conf-native,conf-wrangler,staging | yes |
| 5.1a | Spec: leases, lifecycle events, server GC, published view and quarantine (#1091 part 1) | M5 | spec | 3.6, 4.4 | M | docs,proto,golden | yes |
| 5.1b-1 | Spec: takedown, tombstones, preservation and signed notices (#1091 part 2a) | M5 | spec | 5.1a-2, 5.1c | M | docs,proto,golden | no |
| 5.1b-2 | Spec: admin API, audit log and remote CachePurge (#1091 part 2b) | M5 | spec | 5.1b-1 | M | docs,proto,golden | no |
| 5.1c | Spec: storage receipts predicate (#1092) | M5 | spec | 5.1a | M | docs,proto,golden | yes |
| 5.2 | Leases and lifecycle states: model, enforcement, events | M5 | core | 5.1a, 3.5, 4.18, 2.15 | L | rust,conf-native,conf-wrangler | no |
| 5.3a | GC mark: roots, pins, grace, gc_pending; mark → wait → re-check protocol | M5 | core | 5.2, 4.10 | L | rust,conf-native | no |
| 5.3b | GC sweep: membership drop, holder removal, zero-holder deletion, adapters | M5 | core | 5.3a | L | rust,conf-native,conf-wrangler | no |
| 5.4 | Published view: (head, packmap) pointer storage and caller view on every read path | M5 | core | 5.2 | L | rust,conf-native,conf-wrangler | no |
| 5.5 | ContentInspector: sync checks, async quarantine, clearance, hit -> takedown | M5 | core | 5.4, 3.7, 5.6 | L | rust,conf-native | no |
| 5.6 | Takedown core: tombstones, blocklist (checked by the relay), preservation store, per-repo views, suspension | M5 | core | 5.1b-1, 4.10, 5.2, 5.10 | L | rust,conf-native,conf-wrangler | yes |
| 5.7a | mkit-core: delta-safe pack rewrite primitive | M5 | core | 4.2 | M | rust,wasm | no |
| 5.7b | Server: rewrite orchestration, packlist chain rebuild, packmap CAS | M5 | core | 5.7a, 5.6 | L | rust,conf-native | no |
| 5.8 | Storage receipts: ReceiptSigner, receipt key, key list, AdvanceRefs field | M5 | core | 5.1c, 5.2 | L | rust,conf-native,golden | yes |
| 5.9a | Server: RedactionNotice detail, HTTP 451, notice signing | M5 | core | 5.7b, 5.8, 5.1b-1 | M | rust,conf-native | no |
| 5.9b | Client: redaction-aware fetch and push re-plan | M5 | client | 5.9a | M | rust,cli | no |
| 5.10 | CachePurger hook and purge triggers, remote delivery after admin spec | M5 | core | 5.2, 5.1b-2 | S | rust | no |
| 5.11a | Admin API framework: signed envelope, replay protection, audit log | M5 | core | 5.1b-2, 4.18, 2.15 | L | rust,proto,conf-native | yes |
| 5.11b | Admin operations and the mkit-server admin CLI | M5 | native | 5.11a, 5.6, 5.2, 5.14 | L | rust,conf-native | no |
| 5.12 | Client: receipt storage under .mkit/receipts (not GC roots, not pushed) | M5 | client | 5.8 | S | rust,cli,docs | no |
| 5.13 | Conformance: lifecycle wire suite (M5 exit) | M5 | conformance | 5.3b, 5.5, 5.7b, 5.9b, 5.10, 5.11b, 5.12 | L | rust,conf-native,conf-wrangler,staging | yes |
| 5.14 | Reinstatement via server-side pack rewrite | M5 | core | 5.6, 5.7b, 5.1b-1 | M | rust,conf-native | no |
| REL | Final merge to main: 0.5.0 bump, publish mkit-server crates, first server release | M5 | release | 1.20, 2.15, 3.13, 3.14, 4.13, 4.18, 5.13 | S | full,ci-yaml | yes |

---

## 3. Global DAG, parallel waves and critical paths

**DAG.** The `depends-on` column is the DAG (hard dependencies only). Cross-milestone structure:

```text
P1 ─┬→ S1 ─┬→ S2 (→ crypto 2.3/2.4/2.5 may start early)
    │      └→ S3
    ├→ pure mkit-core WPs that may start early: 4.1, 4.2, 4.3, then 1.3 (after S1), 4.8a, 5.7a
    └→ M0 (M0-01 … M0-20, incl. 02a/02b, 05a/05b) ─→ M1 (1.2 … 1.20; 1.24 and 1.4 start at M0 exit)
                              ├→ M2 identity (entry 1.20; 2.2 …)       ─┐
                              ├→ M3 money (entry 1.20; 3.6 needs only M0 exit) ─┐
                              └→ M4 content (entry 1.20; spec 4.4 after 3.6)    ├→ M5 (entry 4.18 + 2.15) → REL
   Cross-track edges: 4.13 ← 3.3 (paid reads); 4.15 ← 2.9, 2.11; 4.17 ← 2.7; 5.2/5.11a ← 2.15, 4.18; 5.5 ← 3.7; 5.1a ← 3.6
   Review-01 edges (R-70, R-71): M0-16 ← M0-05b, M0-06 (features `test-faults`, `connect`); 1.28 ← 1.8 (DO classes before
   the D34 flip); 5.6 ← 5.10 (CachePurger before takedown); M0-09's `fs` feature moved to M0-10 (no M0-09 ← M0-08 edge)
```

Soft ordering (not in the DAG): M0-15 rebases onto S1 if both are open (both edit SPEC-TRANSPORT-CONNECT); M0-18 prefers
M0-14 merged first so the shipped binary has the enc listener.

**Waves.** Earliest wave per WP (longest dependency chain from the roots). Everything in a wave can run concurrently once
its predecessors have merged; in practice cap concurrent executors at ~4 to keep review load and rebases manageable.

| wave | runnable together once predecessors merge | milestone(s) |
|---|---|---|
| 0 | P1 | P |
| 1 | S1, M0-01, 4.1, 4.2, 4.3 | S, M0, M4 |
| 2 | S2, S3, M0-02a, M0-04, 1.3, 4.8a, 5.7a | S, M0, M1, M4, M5 |
| 3 | M0-02b, M0-05a, 2.3, 2.4 | M0, M2 |
| 4 | M0-03, M0-05b, 2.5 | M0, M2 |
| 5 | M0-06, M0-08, M0-09 | M0 |
| 6 | M0-07, M0-12, M0-16 | M0 |
| 7 | M0-10, M0-17 | M0 |
| 8 | M0-11, M0-14, M0-18 | M0 |
| 9 | M0-15, M0-19 | M0 |
| 10 | M0-13 | M0 |
| 11 | M0-20 | M0 |
| 12 | 1.2, 1.4, 1.24, 3.6 | M1, M3 |
| 13 | 1.22, 3.14, 4.4 | M1, M3, M4 |
| 14 | 1.5, 1.7, 1.25, 1.8, 4.11, 5.1a | M1, M4, M5 |
| 15 | 1.6, 1.23, 1.26, 1.29, 5.1b-1, 5.1b-2, 5.1c | M1, M5 |
| 16 | 1.28, 1.9, 1.16 | M1 |
| 17 | 1.10, 1.11 | M1 |
| 18 | 1.12, 1.13, 1.15, 1.17, 1.21 | M1 |
| 19 | 1.14, 1.18 | M1 |
| 20 | 1.27, 1.19 | M1 |
| 21 | 1.20 | M1 |
| 22 | 2.2, 2.10, 3.1, 4.5, 4.9, 4.10a | M2, M3, M4 |
| 23 | 2.6, 2.13, 3.2, 3.10, 4.6, 4.7 | M2, M3, M4 |
| 24 | 2.7, 2.8, 2.9, 3.3, 3.11, 4.8, 4.10 | M2, M3, M4 |
| 25 | 2.11, 2.12, 2.14, 3.4, 3.5, 3.7, 4.12, 4.17 | M2, M3, M4 |
| 26 | 2.15, 3.8, 3.9, 4.13, 4.14, 4.15, 4.16 | M2, M3, M4 |
| 27 | 3.12, 4.18 | M3, M4 |
| 28 | 3.13, 5.2, 5.11a | M3, M5 |
| 29 | 5.3a, 5.4, 5.8, 5.10 | M5 |
| 30 | 5.3b, 5.6, 5.12 | M5 |
| 31 | 5.5, 5.7b | M5 |
| 32 | 5.9a, 5.14 | M5 |
| 33 | 5.9b, 5.11b | M5 |
| 34 | 5.13 | M5 |
| 35 | REL | M5 |

**Critical paths per milestone.**

| milestone | critical path inside the milestone (size-weighted: S=1, M=2, L=3) | PRs |
|---|---|---|
| P | P1 | 1 (weight 1) |
| S | S1 → S2 | 2 (weight 6) |
| M0 | M0-01 → M0-02a → M0-05a → M0-05b → M0-06 → M0-07 → M0-10 → M0-14 → M0-15 → M0-13 → M0-20 | 11 (weight 25) |
| M1 | 1.4 → 1.22 → 1.7 → 1.23 → 1.9 → 1.11 → 1.12 → 1.14 → 1.27 → 1.20 | 10 (weight 25) |
| M2 | 2.4 → 2.5 → 2.6 → 2.9 → 2.11 → 2.15 | 6 (weight 14) |
| M3 | 3.1 → 3.2 → 3.3 → 3.7 → 3.8 → 3.12 → 3.13 | 7 (weight 15) |
| M4 | 4.4 → 4.5 → 4.7 → 4.10 → 4.12 → 4.14 → 4.18 | 7 (weight 18) |
| M5 | 5.1a → 5.2 → 5.10 → 5.6 → 5.7b → 5.14 → 5.11b → 5.13 → REL | 9 (weight 21) |

**Overall critical path by PR count** (36 PRs, 36 waves 0–35):
`P1 → M0-01 → M0-02a → M0-05a → M0-05b → M0-06 → M0-07 → M0-10 → M0-14 → M0-15 → M0-13 → M0-20 → 1.4 → 1.22 → 1.7 → 1.23 → 1.9 → 1.11 → 1.12 → 1.14 → 1.19 → 1.20 → 4.5 → 4.7 → 4.10 → 4.12 → 4.14 → 4.18 → 5.2 → 5.10 → 5.6 → 5.7b → 5.9a → 5.9b → 5.13 → REL`

**Overall critical path by size weight** (weight 86, 36 PRs); it differs only in M1 (1.27 instead of 1.19) and at the M5
tail (5.14 → 5.11b instead of 5.9a → 5.9b):
`P1 → M0-01 → M0-02a → M0-05a → M0-05b → M0-06 → M0-07 → M0-10 → M0-14 → M0-15 → M0-13 → M0-20 → 1.4 → 1.22 → 1.7 → 1.23 → 1.9 → 1.11 → 1.12 → 1.14 → 1.27 → 1.20 → 4.5 → 4.7 → 4.10 → 4.12 → 4.14 → 4.18 → 5.2 → 5.10 → 5.6 → 5.7b → 5.14 → 5.11b → 5.13 → REL`

Review 01 lengthened the chain by two PRs (was 35 counting the since-dropped P0): the M0-05 split adds one serial step (M0-02b and M0-03 stay off
the chain because the pipeline needs only M0-02a), and 5.10 now precedes 5.6.

The chain runs through the M0 serial foundation, the M1 D34/ticket core, then the M4 indexed-serving core (M4 is longer than
M2 or M3, so M2/M3 run in its shadow), then M5 takedown. Levers: start 3.6 (SPEC-SERVER), 4.4, 4.11 and 5.1a–c spec drafting
as soon as their deps allow (they are off the implementation chain); land the pure mkit-core WPs (1.3, 4.1, 4.2, 4.3, 4.8a,
5.7a) during M0; keep M1's four parallel tracks (tickets 1.9–1.14, leases 1.25–1.26, index/snapshot 1.23/1.28/1.21, client
1.16–1.18) staffed.

---

## 4. Defaults adopted (all reviewable)

"User" = default given by the user for this consolidation; "Coordinator" = settled input received during consolidation;
"Planner" = a planner default carried or introduced here, listed so it can be reviewed.

| # | Topic | Default adopted | Source | Affects |
|---|---|---|---|---|
| Q1 | M0 exit "tokio-free baseline" | **Server-free CLI**: no axum, SQLite or `mkit-server-native` in `mkit-cli`'s default graph (plus no hyper `server`/connectrpc `server`/`axum` features; `mkit serve` builds no runtime), enforced by `scripts/check-cli-baseline.sh` | User | M0-13, M0-20, every CLI WP |
| Q2 | Publishing | `mkit-server` crates published and workspace bumped to 0.5 at the final merge-to-main release (WP-REL), not before; `mkit-server` has no `publish = false` (mkit-cli depends on it); `-native`, `-conformance` publishable at REL; `-worker` never | User | M0-01/10/13/15/18, REL |
| Q3/Q4 | FS stores and ssh metadata | `fs` feature on `mkit-server`; `mkit serve` uses file refs (`FsLayoutStore`) for good; SQLite required when auth-v2 is on | User | M0-08, M0-10, M0-13, 1.15, 2.12 |
| Q5 | In-flight replay | Keep `UploadPack` retry-resume in M0; other in-flight → retryable `aborted` | User | M0-02a, M0-05b, M0-17 |
| Q6 | `mkit-server-worker` location | `rust/crates/mkit-server-worker`, workspace member, unpublished | User | M0-16 |
| Q7 | CI S3 endpoint | In-repo fake S3 (optional ignored MinIO test) | User | M0-11 |
| Q8 | `wrangler dev` conformance | New job in `workers.yml`, path-gated, pinned wrangler | User | M0-17 |
| Q9/Q10 | Container and targets | ghcr `officialunofficial/mkit-server`, private, **no `latest`**; distroless cc nonroot; same targets as `mkit` (Linux subset for the image) | User | M0-18, M0-19, REL |
| Q11 | repo-worker dedup | **No**: demo stack unchanged; M0-R dropped | User | M0-R |
| Q12 | ssh idle timeout | 60 s; `--idle-timeout-secs 0` disables | User | M0-13 |
| Q15 | buf-breaking base | ~~Fix Cloud Build `codegen.yaml` and `proto.yml` to the PR base in P0~~ N/A (P0 dropped; no CI on the branch) | User | P0 |
| Q18 | #1090 wire | BeginUpload/tickets/parts in S1 §7.6 | User | S1, 1.1 dropped |
| Q19 | #1089 wire | Signed reads, private repos, URL tokens in S2 | User | S2, 2.1 dropped |
| M1-a | Part-upload shape | **Client-streaming** `UploadPart` (a header message, then data chunks; decided in review 01 so no part is ever buffered whole: connectrpc collects unary bodies in full), explicit `CompleteUpload`, stateless signed ticket token, client-held signed part receipts for resume, no DO on the part path, no presigned R2 uploads | User + Coordinator | S1, 1.2, 1.9, 1.11, 1.12, 1.18 |
| M1-b | Ticket threading | Defaulted `Transport::advance_refs_committing(…, &[PackKey])` | User | 1.17 |
| M1-c | ssh tickets | Implicit per-session tickets; no threshold | User | 1.15 |
| M2-a | Visibility | Owner-signed `SetRepoVisibility` RPC (M2); default `public`; carried to shards by the epoch lease | User | S2, 2.2, 2.9 |
| M2-b | Unauthorized private read | `not_found` (no existence oracle) | User | S2, 2.9 |
| M2-c | URL tokens | Dedicated deployment URL-token key; TTL default 15 min, clamped | User | S2, 2.11 |
| M2-d | Epoch statements | Max lifetime 30 days | User | S2, 2.4, 2.8 |
| M2-e | ssh grant registration | `mkit-server grant register`/`list`/`remove` operator command (M2); full admin API stays M5 | User | 2.12, 5.11b |
| M2-f | Client grant store | Under the user config dir (never repo-scoped) | User | 2.13 |
| M2-g | Grant `delete` flag | Kept; governs ref deletion in `UpdateRef`/`AdvanceRefs` (S1 §7.8) | User | S1, S2, 1.2, 1.10, 2.7 |
| M3-a | Workers memory for verification | Windowed streaming pack reader (4.8a) + advertised indexed-mode max pack size in `GetServerInfo` | User | 4.4, 4.8a, 4.8 |
| M4-a | Proof HTTP format | Decided in the #1088 spec WP (4.11) | User | 4.11, 4.14 |
| M4-b | Cross-chunk disclosure ranges | Multi-chunk proof bundle; encoding decided in 4.11 | User | 4.11, 4.14 |
| M5-a | Opaque-mode receipts | Cover refs + pack ids only | User | 5.1c, 5.8 |
| M5-b | Preservation store | Separate restricted bucket/prefix (R2) or dir (FS), admin-API-only | User | 5.1b-1, 5.6 |
| M5-c | Keys | Distinct keys per role — receipt+notice signing, admin, hook channel, URL tokens (+ the M1 ticket/receipt MAC key) — each with a key id and rotation via a published key list | User | S1, S2, 3.6, 5.1b, 5.8, 5.11a |
| M5-d | Reinstatement | Re-add the object via server-side pack rewrite | User | 5.14 |
| M5-e | Client receipts | Stored under `.mkit/receipts/`, separate from attestations and not object-GC roots | User | 5.12 |
| M3-b | Paid HTTP reads | Produce an outcome: `ReadServed` variant defined in 3.3, emitted by 4.13 | User | 3.3, 4.13 |
| C-1 | Storage contract | Key-level `NamespaceStore`: one declarative `Batch` (preconditions `Absent`/`Present`/`Equals` and the time-bounded `NotAfter(deadline_ms)` evaluated on the backend's own clock, + puts/deletes), get/has/get_many/ordered scan with opaque cursor, key layouts not queries, single writer is enough, cancellation-safe, backend-defined backup/migration, crash/restart conformance, optional `StateCommitment` hook | Coordinator | M0-02a/02b/03/05a/08/09/16 |
| C-2 | DO constraints | ≤ ~2 DO calls per RPC; no whole-pack buffering (64 MiB kept only as an M1 stopgap); SQLite limits respected; timers with alarm = min(due_at) and idempotent handlers; placement option default none; app-level backup export to R2; bump `compatibility_date` (stay on `migrations`, not `exports`); conformance on deployed staging | Coordinator | M0-16/17, 1.8, 1.24, 1.29, 1.19/1.20 |
| C-3 | D34 details | Epoch leases (30 s) instead of a registry fan-out; fixed 4096 object-id fan-out (advertised); hash-bucketed ref-name index with k-way-merged ListRefs; bounded growth with per-shard stats and 70%/90% alerts; outbox backpressure (M3); open-ticket caps per (ref, signer) and per ref (M1); ContentIndex holder sub-sharding (M4) | Coordinator | M0-02, 1.22–1.29, 3.3, 4.10a |
| P-1 | DO names (Q13) | M0 keeps `RefStore`/`REFSTORE`/"root"; M1 adds one DO class per shard kind (migration `v2`) | Planner | M0-16/17, 1.8 |
| P-2 | Quota (Q14) | Today's limits (300 ops/h, 128 MiB/h) per (namespace, signer); exact per ref shard, approximate per namespace (1.26) | Planner | M0-04/05, 1.26 |
| P-3 | Membership in M0 (Q16) | Store presence (single repo); explicit membership from M1 | Planner | M0-02, 1.7 |
| P-4 | Download chunks (Q17) | 800 KiB for every server, incl. vcs-worker | Planner | M0-04, M0-17 |
| P-5 | New crates (Q20) | rusqlite (bundled), tower-http, metrics, tracing-subscriber, send_wrapper allowed; no Prometheus exporter | Planner | M0-01/09/10 |
| P-6 | Upload threshold | `BeginUpload` threshold 0 on multi-repo deployments (every upload ticketed, so membership is always recorded in a ref shard); single-repo unchanged | Planner | 1.6, 1.9 |
| P-7 | Part size | 8 MiB advertised, 32 MiB max | Planner | 1.11, 1.12 |
| P-8 | Single-part packs | `UploadPack` with the ticket token and `pack:` commitment | Planner | S1, 1.9 |
| P-9 | Outbox before M3 | Built-in no-op sink acks and deletes rows | Planner | 1.14 |
| P-10 | Atomic advance | Client auto-enables it from `GetServerInfo` | Planner | 1.16 |
| P-11 | Epoch step | `MAX_EPOCH_STEP` = 1024 | Planner | S2, 2.8 |
| P-12 | Lease safety margin | Shards stop using an epoch lease 5 s before expiry; the margin must exceed the worst clock skew between the coordinator and any ref shard's storage backend | Planner | 1.25, S2 |
| P-21 | Commit deadline | Every planned write batch carries `NotAfter(deadline)`, deadline = `plan_time + MAX_APPLY_WINDOW` (M0), and from WP-1.25 `min(lease_expires − margin, plan_time + MAX_APPLY_WINDOW)`; `MAX_APPLY_WINDOW` = 10 s (named parameter). Deadlines use the real clock, never the test clock-skew directive | Planner | M0-02a, M0-05a, 1.25, S2, 5.3a |
| P-22 | Coordinator config cache | Ref shards carry coordinator config (repo exists, visibility, lease defaults) with a `config_version` in the epoch lease; Workers keep an isolate cache keyed by `(ns, repo)` and `config_version`, TTL 10 s, invalidated when any shard reply carries a newer version; `SetRepoVisibility(private)` reports completion only after the lease rule **and** one cache TTL. Steady-state writes stay at ~2 DO calls | Planner | 1.22, 1.25, 2.9, 1.21 |
| P-23 | Relay watermark | Each ref shard reports its outbox relay high-water mark to the coordinator (on lease renewal and when its outbox drains) and stays in the coordinator's table until its outbox is empty; the namespace relay watermark is the minimum. GC and takedown wait on it; index shards dedup relay rows by per-source high-water marks, not per-row keys | Planner | 1.23, 5.3a, 5.3b, 5.6 |
| P-13 | Fan-outs and paging | `INDEX_FANOUT` 4096; `REF_INDEX_FANOUT` 16; ListRefs pages ≤ 2 MiB (below connectrpc's default 4 MiB client message limit, so the envelope always fits); `MAX_VALUE_BYTES` 1 MiB | Planner | M0-02a, 1.28, S1 |
| P-14 | Read-your-writes for packs | **Decided (D36, user):** optional `X-Mkit-Ref` header on `PackExists`/`DownloadPack`, resolved against that ref's strongly consistent shard and always subject to the caller's view (non-writers get the published view; quarantined packs stay hidden) | User | S1 §7.9, 1.16, 1.23, 1.27, 5.4, 5.13 |
| P-15 | Lagging delta bases | Retryable `unavailable` while the ticket is younger than the relay-lag bound (60 s), then the uniform permanent error | Planner | 4.4, 4.7 |
| P-16 | Snapshot `ReadRef` | M1 serves only unsigned `ListRefs` from the snapshot by default; unsigned `ReadRef` opt-in until M2 signed reads | Planner | 1.21, 2.9 |
| P-17 | Backups | Daily DO export to R2, 35-day default retention (configurable) | Planner | 1.29 |
| P-24 | Full partition | A backend at its storage cap (DO: `SQLITE_FULL`; reads and `DELETE` keep working) returns `StoreError::Full`; the pipeline fails the write closed with retryable `unavailable` ("storage partition full"), never `resource_exhausted`, and raises a critical alert; pruning still runs | Planner | M0-02a, M0-09, M0-16, 1.29 |
| P-18 | Grants UX | Selection "most specific scope, latest expiry"; native signing for ed25519 and keystore secp256k1, wallet/WebAuthn by import; single trusted signing remote; WebAuthn fails closed without RP pinning; `GetServerInfo` unsigned | Planner | 2.10, 2.13 |
| P-19 | Delta chains | Server-side chain cap 50, advertised | Planner | 4.7 |
| P-20 | M5 values | GC grace 7 days; no default lease periods (a `LeasePolicy` must set them); preservation retention must be configured when takedown is on; single admin key with key-list rotation (threshold deferred, PRD Q4); ssh/enc principals treated as writers for the published view | Planner | 5.1a/b, 5.2, 5.3a, 5.6, 5.11a |

---

## 5. Reconciliation log

Every change made to the inputs during consolidation. "Briefs" = `docs/plans/mkit-server/briefs/`; "M1/M2" and "M3–M5" = the breakdown files.

### 5.1 Interface reconciliation (M1/M2 A1–A19, M3–M5 A1–A19)

| R | Gap or conflict | Change | Files |
|---|---|---|---|
| R-01 | A12: `Principal` had no ssh key; not extensible | `#[non_exhaustive] Principal`; `SshForcedCommand { key: Option<[u8;32]> }` (set by WP-1.15 `--principal`); `ed25519()` accessor | M0-01, M0-13 |
| R-02 | A1: `Operation` closed; no grant/epoch slot | `#[non_exhaustive]` `Procedure`/`OpKind`/`Commitment`; `Operation.authz: AuthzFacts { grant: Option<GrantRef{id, epoch}>, owner }` | M0-01 |
| R-03 | A14 / H-A4: errors couldn't carry HTTP status, headers or typed details (needed for 402, `PendingVerification`, `RedactionNotice`) | `ServerError::with_http_status/with_header/with_detail` (sensitive headers dropped), `Code::Unimplemented/DeadlineExceeded`; M0-06 maps them to connectrpc `with_http_status/with_headers/with_detail`; a test proves the 402 path in M0 | M0-01, M0-06 |
| R-04 | A2: apply precondition slots | Provided as key-level `Absent/Present/Equals` preconditions (R-16); epoch = key `e` (M0) and the ref shard's epoch lease `el` (D34, WP-1.25); `tickets_open` in WP-1.7; GC-pending in WP-5.3a (superseded by R-61/R-64: `NotAfter` deadline + GC mark → wait → re-check) | M0-02, M1/M2 |
| R-05 | A3 / H-A3: `Mutation` extensibility | Superseded by the key-layout registry: new row kinds are new layouts; backends never change | M0-02 |
| R-06 | H-A5: GC/takedown need blob deletion | `BlobStore::delete` in M0 (memory, FS, S3, R2) with a suite case; unused until M5 | M0-02/03/08/11/16 |
| R-07 | H-A5: a global object keyspace | Stores take a keyspace (default `packs`); M4 instantiates a second store with `objects` | M0-02/08/11/16, 4.10 |
| R-08 | A5: multipart session API | Moved to WP-1.11 as a `MultipartBlobStore` sub-trait; session id carried in the ticket token | M0-02, 1.11 |
| R-09 | A10: storage suite must inspect rows | No separate inspect trait: the suite scans the documented key layouts via typed readers | M0-02, M0-03 |
| R-10 | A6: admission input fields | `AdmissionInput` has every PRD field from M0 (some unset); `creates_*` from the coordinator (1.22); per-namespace aggregate quota → 1.26 | M0-05, 1.5, 1.22, 1.26 |
| R-11 | A9: test hooks (barrier, clock override, fault after upload) | `test-faults` seam: `FaultHooks` at 5 points + `TestDirectives` (`x-mkit-test-fault`, `x-mkit-test-clock-skew-ms`), header plumbing in M0-06, store faults in M0-16/17; barrier implementation in 1.25/2.8; release builds never enable it | M0-05/06/16/17/18 |
| R-12 | A10: wire cases gated by feature and milestone | `Case::MILESTONE`/`REQUIRES`, `Profile.features` (from `GetServerInfo` from M1), `--milestone` | M0-07 |
| R-13 | A11 conflict: ssh with a SQLite store would break the server-free CLI | ssh keeps `FsLayoutStore` forever; multi-repo dirs (1.15) and grant/epoch files under the ref lock (2.12) | M0-08, 1.15, 2.12 |
| R-14 | A3: migrations | SQL physical schema is one `kv` table; logical layouts need no physical migration | M0-09 |
| R-15 | H-A8, A15: CORS extension, subcommands, spawner | `RouterOptions` extra allow/expose headers; clap subcommand enum; `TokioSpawner` | M0-10 |
| R-24 | A13 / H-A13: per-branch published pointer storage | Moved to WP-5.4 (ref shard); M1's snapshot serves live refs | M0-02, 5.4 |
| R-36 | A7 / H-A10: DO alarm multiplexing had no owner (3.5 was conditional) | New WP-1.24 owns timers `(due_at, kind, ref)`, alarm = min(due_at), idempotent handlers, per-kind budgets; 1.14, 1.23, 1.29, 3.3, 3.5, 4.8, 5.2, 5.3b register kinds | 1.24, 1.14, 3.5 |
| R-49 | A16: outbox table claimed by 1.7, 3.3, 3.4 and 3.5 | 1.7 owns the layouts (rows, pending index, backlog counter); 3.3 delivery/backpressure; 3.4/3.5 no schema | 1.7, 3.3–3.5 |
| R-52 | H-A1: `ContentInspector`, `LeasePolicy` missing from `HookSet` | Added by 3.7 (call shape) / 5.5 and 5.2 as associated types | M0-05, 3.7, 5.2, 5.5 |
| R-60 | H-A6: Workers `ContentIndex` impl | `ContentIndex` is a layer over any `NamespaceStore` (M0-02); Workers wiring + holder sub-sharding → new WP-4.10a | M0-02, 4.10a |

### 5.2 Backend-agnostic storage contract (coordinator input A)

| R | Change | Files |
|---|---|---|
| R-16 | `NamespaceStore` is a partitioned ordered KV store: `get`/`has`/`get_many`/`scan(start, end, after-cursor, limit)`/`apply(Batch)`/`stats`/`probe`; the only write is one declarative `Batch` of preconditions plus puts/deletes; no SQL, no closures | M0-02 |
| R-17 | Key-layout registry (`store/keys.rs`) with golden bytes: refs, replay + expiry index, quota + window index, epoch, timers, reserved M1–M5 prefixes, ContentIndex, outbox backlog counter | M0-02 |
| R-18 | Business logic moves into pure planners with a bounded optimistic re-plan loop (max 8 → retryable `aborted`); every read value is guarded by a precondition | M0-05 |
| R-19 | Optional `StoreMaintenance` (backend-defined migrate/backup); SQLite implements it with versioned physical migrations and `VACUUM INTO` | M0-02, M0-09 |
| R-20 | Portable logical export/import for every backend; DO `Export` call; periodic R2 dump in 1.29 | M0-02, M0-16, 1.29 |
| R-21 | Optional `StateCommitment` hook (`root()` + `prove()`), unimplemented, never required | M0-02 |
| R-22 | Storage suite adds cancellation (drop `apply` at random polls), crash/restart atomic at the last commit (`reopen`), export/import round trip | M0-03, M0-08, M0-09 |
| R-23 | Normative rules: single writer is enough; no locks across awaits; cancellation-safe check-and-write; poisoning recovery; `Blocking` runs to completion | M0-02, M0-09 |
| R-29 | D34-ready `Partition` enum (Namespace, Coordinator, Ref, RepoIndex, RefIndex, ContentShard); `ShardMap` with `SinglePartition` in M0; SQLite keys rows by partition ("tables keyed by shard"); DO naming per shard kind | M0-02, M0-05, M0-09, M0-16 |

### 5.3 Durable Object constraints (coordinator input B)

| R | Change | Files |
|---|---|---|
| R-25 | No whole-pack buffering: streaming R2 put that withholds the final chunk until BLAKE3 verifies, streaming R2 get, streaming Worker adapter both ways; `PackSink` memory bounded by one chunk; the 64 MiB cap stays only as a documented stopgap until M1 parts; escalate if connectrpc on wasm can't stream | M0-02, M0-16, M0-17 |
| R-26 | DO limits recorded and designed for (req/s, 128 MB shared memory, CPU, alarm semantics, subrequests/connections, SQLite limits, placement, PITR, local bindings in `wrangler dev`) | M0-16, M0-20, 1.8, 1.24 |
| R-27 | Bump `compatibility_date`; note that `exports` and `migrations` are mutually exclusive (stay on `migrations`) | M0-17, 1.8 |
| R-28 | Parts authorized by a stateless signed ticket token so they never hit a DO; streamed through the Worker, subtree-hashed, then `uploadPart`; no presigned uploads; resume from client-held signed part receipts (overrides the M1 planner's "BeginUpload returns received parts") | S1, 1.9, 1.11, 1.12, 1.18 |
| R-40 | Published-view ref snapshot in R2/Cache for hot namespaces, invalidated on ref changes (new WP-1.21; per ref-index bucket and debounced after R-73) | 1.21, 2.9, 5.4 |
| R-50 | Placement (`locationHint`/jurisdiction) as a namespace-creation option, default none | M0-16, 1.8 |
| R-51 | Conformance also runs against deployed staging, not only `wrangler dev` | M0-20, 1.20, 1.27, 2.15, 3.13, 4.18, 5.13 |

### 5.4 D32, D33, D34 and the storage-cap guardrails

| R | Change | Files |
|---|---|---|
| R-30 | Epoch leases replace any registry fan-out: 30 s coordinator leases, safety margin, revocation completes when leased shards ack or expire; covers revoke-in-flight, idle-shard wake-up, lease-expiry-vs-ack; new WP-1.25; 2.8 builds on it | S2, M0-02, 1.25, 2.6, 2.8, 2.9 |
| R-31 | Bounded growth: `stats` required; pruning of replay, tickets, outbox, quota; 70%/90% alerts; shrink-after-load tests | M0-02/03/05/07, 1.14, 1.27, 1.29 |
| R-32 | Consistency rules in S1 §7.9: strong `ReadRef`, eventual `ListRefs`/membership with safe failures, `X-Mkit-Ref` hint (D36, R-77), additive ListRefs paging (≤ 2 MiB after R-78), `index_fanout` in `GetServerInfo` | S1, 1.2, 1.16, 1.23, 1.28 |
| R-33 | Ref-name index hash-bucketed with a fixed fan-out and a k-way-merged, cursor-paged ListRefs (replaces "split by name range"); no resharding anywhere | M0-02, M0-16, 1.28 |
| R-34 | ContentIndex holder rows sub-sharded by (object, hash(holder)) with a safe-direction holder count; load case | M0-02, 4.10a, 5.3b |
| R-35 | Outbox backpressure: backlog counter (1.7), enforcement with retryable `unavailable` + alert (3.3), "hook down" conformance (3.13) | M0-02, 1.7, 3.3, 3.13 |
| R-37 | Open-ticket caps per (ref, signer) and per ref at admission; conformance | 1.9, 1.27 |
| R-38 | `BeginUpload(repository, ref, …)` names its target ref; tickets are local to the ref shard | S1, S3, 1.2, 1.9, 1.17 |
| R-39 | D34 M1 split into new WPs 1.22 (shard model), 1.23 (index shards + relay), 1.25 (epoch leases), 1.26 (quota), 1.27 (conformance), 1.28 (ref index + ListRefs; flips the default), 1.29 (backups + alerts); 1.7, 1.8, 1.9, 1.10, 1.14 reshaped | M1/M2 |
| R-42 | D32: 4.4 and 4.10 rewritten (≥ 64 KiB blobs + streamed ChunkedBlob reassembly, caller-verified `objects` sink, whole-file dedup, R2 same-key 429 → HEAD then verify); 4.12 serves extracted objects by native Range | M3–M5 |
| R-43 | D33: attestation predicates and carriage removed from 4.4, 4.17 (now signers + ff-only), 4.18 | M3–M5 |
| R-44 | Workers verification: new mkit-core windowed reader WP-4.8a; 4.8 as checkpointed alarm slices in the ref-shard DO with large Range windows | M3–M5 |
| R-53 | Delta-base resolution under eventual membership: retryable "base not yet visible" bounded by ticket age, then the uniform error (no oracle) | 4.4, 4.7 |

### 5.5 Corrections, defaults and scope

| R | Change | Files |
|---|---|---|
| R-45 | "Tokio-free baseline" replaced by the server-free CLI criterion everywhere | M0-08, M0-13, M0-20, overview, 1.15–1.17, 2.12, 2.13, 3.11, M3–M5 gates |
| R-46 | Keys per role with key ids and a published key list (incl. the M1 ticket/receipt MAC key) | S1, S2, 3.6, 5.1b-1, 5.1b-2, 5.8, 5.11a |
| R-47 | Q2: publish and bump at the new WP-REL; wording fixed in M0-01/10/13/15/18/19 | briefs, REL |
| R-48 | Deleted the `feat/scoped-workspaces` notes (G23, Q-X-1, the P1 untracked-dir note) | M1/M2, P1 |
| R-54 | Ref deletion added (S1 §7.8, proto 1.2, server 1.10, grant `d` flag 2.7) so the kept `delete` flag governs something | S1, S2, 1.2, 1.10, 2.7 |
| R-55 | Spec WPs with proto (3.6, 4.4) depend on M0 exit, not M1 exit, so they leave the implementation critical path; 4.5/4.9/4.10a take the M1 dependency instead | registry |
| R-56 | 4.13 depends on 3.3 (read outcome), not 3.2 | M3–M5, registry |
| R-57 | ~~P0 makes the Cloud Build `codegen.yaml` base-branch fix mandatory (Q15)~~ N/A (P0 dropped; no CI on the branch) | P0 |
| R-58 | Dropped: M0-R (Q11), WP-1.1 (→ S1), WP-2.1 (→ S2); M0-R brief marked dropped | briefs, M1/M2 |
| R-59 | S2 grows to L (docs) with #1089 folded in; S1 grows to L with #1090, ref deletion and D34 consistency | S1, S2 |

### 5.6 Review 01 fixes (adversarial review 01, not committed; findings verified by the orchestrator)

Rows R-01…R-60 above name `M0-02`/`M0-05`; after R-72 read them as the split WPs (contract core → M0-02a,
ContentIndex/export/hooks → M0-02b, unary pipeline → M0-05a, streaming/faults → M0-05b).

| R | Finding | Change | Files |
|---|---|---|---|
| R-61 | B1: the store only saw `Equals(el, observed)`; a batch planned under a valid lease could commit after the lease expired (e.g. its revocation push to that shard failed) | New `Precondition::NotAfter(deadline_ms)` in the storage contract, evaluated on the **backend's own clock** at apply, inside the non-yielding check-and-write step; implemented by `MemoryKv` (injected clock), `SqlKvStore` (native `SystemClock`, DO `WorkerClock`), `FsLayoutStore` (under the ref lock) and carried by the DO wire; storage-conformance cases `kv.not_after_*` | M0-02a, M0-03, M0-08, M0-09, M0-16 |
| R-62 | B1: deadline source | Planners attach `NotAfter(plan_time + MAX_APPLY_WINDOW)` to every write batch from M0 (P-21); WP-1.25 tightens it to `min(lease_expires − margin, plan_time + MAX_APPLY_WINDOW)`; a `NotAfter` failure re-plans (renewing the lease), so a revoked grant then fails its epoch check. Normative in S2 §5 and PRD §5.3 (epoch-lease bullet) | M0-05a, 1.25, S2, PRD §5.3 |
| R-63 | B1: missing test | Revocation case "paused write + failed push + expired lease": barrier a write after planning, make the revocation push to that shard fail, wait past lease expiry (clock skew), let `SetGrantEpoch` report success, resume → rejected, nothing committed | 1.25, 1.27, 2.8 |
| R-64 | B1: "pack not GC-pending" can't be an apply precondition (GC state lives in other partitions); WP-5.3a wrongly said it was "already declared in M0" | GC protocol: **mark** (`gc_pending`) → **wait** until `now > mark + MAX_APPLY_WINDOW + margin` and the namespace relay watermark (P-23) has passed that point → **re-check** roots by reading heads, published pointers, open tickets and pending advances from the strongly consistent ref shards (shard list from the ref index *after* the watermark plus the coordinator's active-shard table, never the lagging index alone) and holds/holder counts in ContentIndex → **delete** through a batch guarded by `Equals` on the mark and last-change keys. Planners that see `gc_pending` unmark first; `deleting` → retryable `unavailable`. Supersedes the GC-pending part of R-04 | 5.1a, 5.3a, 5.3b, PRD §5.3, §6.7 |
| R-65 | B3: one `cargo build --bin mkit --bin mkit-server` unifies features, so the shipped `mkit` would carry hyper `server`, connectrpc `axum`/`zstd`, mkit-server `connect`/`sql` | Two separate cargo invocations (`-p mkit-cli --bin mkit`, then `-p mkit-server-native --bin mkit-server`); `scripts/check-release-artifact-features.sh` parses the `compiler-artifact` JSON of the `mkit` release build and fails on any server crate/feature, plus a binary symbol check (no `sqlite3_` symbols); `check-cli-baseline.sh` alone is not enough | M0-18 |
| R-66 | S-1: M0-17 contradicted itself (`respond_buffered` via `dispatch_oneshot`, typed to `Full<Bytes>`) | Normative streaming dispatch: request body = `worker::Body` (`Send + Sync`) with `BodyExt::map_err` to a `Send + Sync` error and a byte-counting limiter; a generic-body `dispatch_oneshot`; responses via `respond_streamed`; deadline headers still stripped. No `respond_buffered` and no `Full<Bytes>` collection for streaming RPCs. Fallback (same wire, no whole-pack buffering): the adapter parses Connect stream envelopes for `UploadPack` itself and calls `UploadSession::push` | M0-17 |
| R-67 | S-2: `PutOptionsBuilder::execute` is an `async fn`, so a bounded channel feeding `FixedLengthStream` deadlocks unless the put is polled | `R2BlobStore::begin` spawns the put with `wasm_bindgen_futures::spawn_local` and keeps a oneshot for its result; `commit` sends the withheld final chunk, closes the stream and awaits the oneshot; `abort` errors the stream and awaits it | M0-16 |
| R-68 | S-3: a borrowed `&mut dyn FnMut` can't cross the DO `transactionSync` bridge (`Closure` is `'static`; no `unsafe` allowed) | `SqlConn::transaction` takes an owned `Box<dyn FnOnce(Self) -> Result<T, SqlError> + 'static>` over a cheaply cloneable connection; `apply` moves the owned `Batch` into it | M0-09, M0-16 |
| R-69 | S-4: connectrpc 0.9 collects unary bodies whole (default 4 MiB limit), so unary 8–32 MiB parts would be buffered | **Decided:** `UploadPart` is client-streaming (header message `{ticket_token, index}`, then data chunks; response `PartReceipt`); no part is buffered whole | S1 §7.6, 1.2, 1.11, 1.12, 1.18, PRD §6.2, M1-a |
| R-70 | B2: M0-16 enables `connect` (M0-06) and `test-faults` (M0-05) without an edge; 1.28 flips Workers to D34 before 1.8 creates the DO classes | Edges M0-16 ← M0-05b, M0-06 and 1.28 ← 1.8; waves and critical paths recomputed | registry, §3 |
| R-71 | B2: M0-09's native crate enabled `mkit-server/fs` (created by M0-08, same wave) | Smaller change chosen: M0-09 enables only `sql`; M0-10 (which already depends on M0-08) adds `fs` to `mkit-server-native` | M0-09, M0-10 |
| R-72 | S-12: M0-02 and M0-05 would exceed 1500 lines | Split: **M0-02a** (contract incl. `NotAfter`, keys, codecs, readers, `BlobStore` trait, replay, memory backends) and **M0-02b** (ContentIndex layer, export/import, optional hooks); **M0-05a** (stage traits, auth modes, `ShardMap`, planners, unary flow) and **M0-05b** (`UploadSession`, `DownloadStream`, resumable `UploadPack`, test-fault seam). `BlobStore` stays in 02a so the pipeline needs only 02a and 02b is off the critical path (deviates from the review's suggested 02b contents) | briefs, registry, §2, §3 |
| R-73 | S-5: one per-repo R2 snapshot rewritten on every advance hits R2's 1 write/s per key | Snapshots per ref-index bucket (hash-sharded, 16 per repo), written by the bucket's shard with debouncing (≥ 1 s between writes of one key, coalescing); unsigned ListRefs k-way merges the bucket snapshots from R2/Cache | 1.21, PRD §9 |
| R-74 | S-6: residual D21 text | "one strongly consistent partition per namespace, D21" and other D21 references rewritten to D34 (coordinator + ref shards) | S1, S2, M0-01, M0-02a, M0-09, M0-16, M0-17 |
| R-75 | S-7: lag holes in content safety | The relay checks the global blocklist on delivery and enqueues a takedown for a newly recorded holder of a blocked object; a takedown reports completion only after the namespace relay watermark passes the takedown point; 4.10 releases a hold only in the relay step that records the holder row; 5.4 applies the caller's view to the `X-Mkit-Ref` path | 1.23, 4.10, 5.4, 5.6, PRD §6.7 |
| R-76 | S-8: coordinator hot paths | Coordinator config cache with version-based invalidation (P-22) and repo/namespace creation folded into lease renewal, keeping steady-state writes at ~2 DO calls; the lease-renewal ceiling (~200–500 coordinator writes/s × 30 s ≈ 6k–15k active shards per namespace) documented as a risk; a packlist-membership miss in 1.10 is retryable `unavailable` within the relay-lag bound | 1.10, 1.22, 1.25, 2.9, §8, PRD §9 |
| R-77 | S-9 + **D36** (user decision) | `X-Mkit-Ref` approved: optional read-your-writes header on `PackExists`/`DownloadPack`, resolved against that ref's strongly consistent shard, always subject to the caller's view; normative in S1 §7.9; PRD §6.1 bullet and D36 row; conformance: a pusher reads its own write immediately (1.27), a non-writer under quarantine can't see pending packs through it (5.13); removed from the open questions | S1, 1.16, 1.23, 1.27, 5.4, 5.13, PRD, §4 P-14, §7 |
| R-78 | S-9: a 4 MiB ListRefs page equals connectrpc's default 4 MiB client message limit | Pages ≤ 2 MiB | S1 §7.9, 1.28, 1.27, P-13 |
| R-79 | S-9: `buf breaking` FILE doesn't forbid every harmful edit | WP-1.2 (and every proto WP) must not change the label (`optional`/`repeated`) or oneof membership of any existing field | 1.2 |
| R-80 | S-10: ops and pipeline gaps | Human actions: confirm Workers Paid; allow GitHub Actions to create ghcr packages; add team owners to new crates after the first publish. P1 snapshot heading D1–D36. Per-PR `apps/vcs-worker/Cargo.lock` refresh rule (§1). M0-16 notes the workers-rs 0.8.6 → wasm-bindgen ≥ 0.2.128 bump in `rust/Cargo.lock` and runs the new `web` area gate for `mkit-wasm` | §1, §6, P1, M0-16 |
| R-81 | S-11: `--meta sqlite` on a root that `mkit serve`/local commands use via file refs = split brain | Refuse: `mkit-server --meta sqlite:` exits with a config error when the repo root has file refs in use, and writes a `.mkit/server-meta` marker that makes `FsLayoutStore::open` refuse the root too | M0-10 |
| R-82 | Nits | Every key starts with its class tag followed by `0x00` (`o`/`oq`/`os`/`oc`, `p`/`px`/`pp`, `t`/`tb`, `e`/`el` share prefixes); the layout-version key `v 00` is not written to `RefsOnly` stores (their layout version is implicit, reported by `capabilities()`); 5.10 now precedes 5.6 (5.6 invokes it); `connectrpc-build` is an optional build-dependency enabled by `connect`; relay dedup by per-source high-water marks; the 16-DO-call cost of a signed k-way ListRefs page documented in 1.28; `area_gates` added to `registry.json`; the weighted critical path corrected (§3) | M0-02a, M0-06, M0-08, 1.23, 1.28, 5.6, 5.10, registry |
| R-83 | Cloudflare corrections | PRD: a Durable Object at its 10 GB cap fails writes with `SQLITE_FULL` while reads and `DELETE` keep working (documented; source: https://developers.cloudflare.com/durable-objects/platform/limits/); the fill-to-cap staging test is dropped (it existed only in the PRD); `SQLITE_FULL` → `StoreError::Full` → fail-closed retryable `unavailable` + critical alert (P-24). M0-16: the 6-connection limit applies only to connections waiting for response headers | PRD §5.3, §9, M0-02a, M0-09, M0-16, 1.29 |
| R-84 | Stale open question | §7's "staging environment ownership" was already resolved by D35 (§6); closed | §7 |
| R-85 | M0-05b review: un-ticketed `UploadPack` resumes an in-flight replay record, where SPEC-TRANSPORT-CONNECT §7.1 step 2 answers `aborted` | **Decided in WP-1.9b:** keep the legacy resume for un-ticketed uploads below the threshold on single-repository deployments; STC §7.1 permits it as a scoped MAY. Ticketed uploads are replay-exempt. | M0-05b, 1.9b |
| R-113 | WP-1.9b | A ticketed UploadPack touches no metadata; it writes a content-addressed upload marker (`BLAKE3(domain ‖ ticket ‖ pack)`) in a non-pack blob namespace, which WP-1.10 MUST require with the pack blob before consuming a ticket (PRD D15). The threshold is enforced (`failed_precondition`); empty packs need a ticket where T = 0 (accepted; clients never upload empty packs). Non-default admission and finite configured thresholds require auth v2 and ticket keys, except transport identity is exempt from admission's ticket requirement. Multi with transport identity is refused until WP-1.15 carries implicit tickets. The legacy resume is kept as a single-repository MAY (R-85). UploadPack does not enforce `bytes ≤ part_size`. Markers are reclaimed by M5 GC. Carry-forwards (review): `with_auth(TransportIdentity)` copies a finite threshold and would be refused by the threshold check; exempt transport identity or reset the threshold when a WP makes the threshold configurable. Multi with auth v2 but no ticket keys starts but can never upload (threshold 0, ticketed uploads `unimplemented`); WP-1.15 or the Multi binding WP refuses it at startup. | 1.9b, 1.10, 1.15, M5 |
| R-86 | M0-08 review: `FsLayoutStore` keeps only `refs/` names as `FileTransport` ref files; any other ref-class name goes to the server-side `.mkit/server/rows/` store, invisible to the CLI (today `mkit serve` writes `<root>/<name>` for any valid name, so `packs/<hex>` could overwrite a pack) | **Decided in M0-13:** the pipeline serves only `refs/` names (SPEC-REFS §2: refs live under `refs/`; every mkit client writes only `refs/heads/`, `refs/tags/`, `refs/mkit/packmap/`). `ReadRef`, `UpdateRef` and `AdvanceRefs` refuse any other grammar-valid name up front, on every binding, with `invalid_argument` "ref name must start with refs/ (…see the migration notes)" (the same text as `INVALID_REQUEST` on ssh); nothing reaches the side store, which stays for the storage contract only. `ListRefs` prefixes stay unrestricted (golden `session-2` lists `nope/`). Normative in SPEC-REFS v3 §2 (MUST), SPEC-TRANSPORT §4.2.1 and SPEC-TRANSPORT-CONNECT §5; wire case `refs.non_refs_prefix_rejected`. Legacy root-level refs an older `mkit serve` wrote (`<root>/main`; only third-party clients ever sent such names) are never migrated, deleted or scanned for: a read or write of the name gets the explicit error (which points at the migration notes) rather than a silent "absent", and docs/CLI.md "Refs outside `refs/`" gives operators a `find`/`mv` recipe. (A per-connection startup scan with a stderr warning was tried and dropped in review: it flagged worktree files and sent the server's paths to every client.) | M0-08, M0-13 |
| R-87 | WP-5.7a scope: the breakdown says a delta is rewritten raw when its "base chain passes through" an excluded id | **Orchestrator decision:** rawify a delta iff its DIRECT base id is excluded. A delta over a rawified entry stays a delta, because its base is still present, now raw. Direct-base is sufficient for decodability; transitive rawification only bloats packs | 5.7a, 5.7b |
| R-88 | M0 exit decisions (user, 2026-09-26) | (1) The 16 M0 wire changes in `m0-exit-report.md` §4 are accepted, so M0 is complete. (2) The sign-off rule is confirmed: only S1–S3 needed the user's approval; later normative edits (SPEC-REFS v2/v3, SPEC-WRITE-GRANTS §3.3/§4.3/§10) merge like code. (3) The `PackReader::read` memory issue and the 32-bit pack framing overflow are fixed on `main` by a separate hotfix PR (the user merges it); `main` is then synced into `feat/mkit-server`. (4) The published CLI's glibc 2.39 floor is documented on `main` now; REL builds the Linux archives against an older glibc (e.g. cargo-zigbuild with a glibc 2.28 target) or musl. (5) REL moves `id-token: write` out of the build job: build unsigned, sign in a separate job that downloads the artifacts; `persist-credentials: false` everywhere. (6) Q9: the container image carries versioned tags only, no `latest`. (7) `WORKERS_PLAN` stays `free` until the user confirms Workers Paid. (8) REL is the breaking 0.5.0 release and must publish `mkit-server` (a dependency of `mkit-cli` since M0-13) together with the other crates | M0, REL |
| R-89 | WP-1.24 native timer directory | An in-memory directory rebuilt from `SqlKvStore::timer_heads()` supersedes the breakdown's native-only helper partition: a helper partition is a second, non-atomic write per timer batch and doesn't survive a restore, while the `kv` table already knows. | 1.24 |
| R-90 | WP-1.22 coordinator cache | WP-1.22 defers the coordinator `config_version` isolate cache to WP-1.25, where `config_version` is delivered with the lease. Until then multi-repo reads that never touch a ref shard do one coordinator `get`. | WP-1.22, WP-1.25 |
| R-91 | Crash between a failed admitted apply and its `Aborted` can lose an outcome | SPEC-SERVER §5 requires a durable pending-reservation record before an admitted apply, so a crash between a failed apply and its `Aborted` cannot lose an outcome (STC §7.7 "exactly one outcome"). WP-3.3 implements it: one extra atomic unit per admitted write that carries a reservation id, and a reconcile pass that records `Aborted(ABANDONED)` after the operation's authentication validity has passed. Every replacement of a pending record (apply, `Aborted`, reconcile) is conditional on it still being pending, in the same atomic unit; a guarded apply that loses that condition commits nothing and answers retryable `unavailable`. | 3.3, 3.6 |
| R-92 | hooks.v1 `AdmitRequest.credential_headers` (WP-3.6b): the admission step needs the client's credential headers | WP-3.2 must add them to the Rust `AdmissionInput`, with the same default name set and bounds. WP-3.7 forwards them. | 3.2, 3.6b, 3.7 |
| R-93 | Switching `--sharding` on an existing SQLite database would hide its refs | WP-1.22 (review): the native server records the database's `--sharding` in its own `mkit_server_sharding` table on first use (a database with data but no record was written `single`) and refuses a mismatch with `CONFIG_ERROR`. There is no single→d34 migration yet; one lands with WP-1.28's flip. | 1.22, 1.28 |
| R-94 | Worker sharding guard | `sm 00` marker in the root `RefStore` object; cache only settled definitive outcomes keyed by (sharding mode, jurisdiction), dropping the cache and re-checking on a config change. At most 3 DO calls per request, and only for requests that arrive before the first definitive result is cached; 0 afterwards; never more than one check per request. An Absent race compares the atomically observed value. Store errors are not cached. No single→d34 migration until WP-1.28. | 1.8, 1.28 |
| R-95 | R-50 narrowed | Placement is per deployment, not per namespace. Per-namespace jurisdiction would be needed before routing to the namespace's own coordinator, which is circular. | 1.8 |
| R-96 | WP-1.5 core policy scope | WP-1.5 is core-only. Enabling multi-repository mode in the adapters, with its policy configuration (native `--addressing multi`, `--namespace-policy`, `--namespace-allowlist <file>` and `--unsafe-open-namespaces`; Worker vars `ADDRESSING`, `NAMESPACE_POLICY`, `NAMESPACE_ALLOWLIST` and `UNSAFE_OPEN_NAMESPACES`), is a dedicated WP-1.30, scheduled after WP-1.10 (pack membership) and before WP-1.19 (staging). | 1.5, 1.30 |
| R-97 | WP-1.25 admission ordering | WP-1.25 renews with exact coordinator reads, after admission, so no lease state is written for a challenged or denied request (STC §5.1). A new or expired shard costs 4 calls, not 3. Steady state stays 2. An optimistic single-call renewal can come later if measured load needs it. | WP-1.25 |
| R-98 | WP-1.25 coordinator cache | R-90's `config_version` cache is deferred to WP-2.9. M1 reads keep one coordinator `get`. | WP-1.25, WP-2.9 |
| R-99 | Tickets without admission reservations still need outcomes | WP-1.7: a ticket whose admission returned no reservation id uses `s:<hex replay scope>`, and its ticket id is derived from the reservation id, so tickets always have exactly one outcome row. Admission-supplied ids are unique per audience (SPEC-SERVER §6.6), and the `Absent(o rid)` guard detects duplicates within the ref shard that holds the row. | 1.7, 1.9 |
| R-100 | WP-1.25 lease-table recovery | WP-1.25: lease-table loss is declared through `mark_lease_table_recovered` (coordinator `lr 00` marker). WP-1.29's restore, and any coordinator rebuild, MUST call it before serving writes; revocation completion waits `epoch_lease + margin` after it (SPEC-WRITE-GRANTS §5.4). | WP-1.25, WP-1.29 |
| R-101 | WP-1.23 split | 1.23a is the relay core. 1.23b, after #1150 and #1151 merge, adds Worker `RelayHandler` registration on `RefShard`; `is_member`, `X-Mkit-Ref` reads and Multi `PackExists`/`DownloadPack` membership (replacing `require_pack_membership` for reads; UploadPack stays WP-1.9); coordinator watermark (P-23: renewal payload, `ls` retention while a shard's outbox is undelivered, `namespace_relay_watermark`). WP-1.9 depends on 1.23a only | 1.23a, 1.23b, 1.9 |
| R-102 | Relay lifecycle | `RelayV1` is upserts-only. Index deletes (ref deletion, WP-1.10/1.28) are designed by WP-1.28, either as tombstones or `RelayV2` with deletes. `rh` ordering keeps them safe because each key has exactly one source. Restore MUST set each restored source's `os` above every target's `rh` for that source, or re-key it: an older snapshot regresses `os` and new rows could be dropped as duplicates. There is no relay-backlog bound yet (the PRD bound is for outcomes); exceeding `RELAY_LAG_BOUND_MS` is logged | 1.23a, 1.28, 1.29 |
| R-103 | Relay liveness under failing targets (WP-1.23a review) | A persistently failing target whose backlog fills a fire's row budget (or 16 failing targets) stalls the source's other targets: 1.23a scans a contiguous window from the lowest seq. Harmless natively (one store); **WP-1.23b MUST fix it before Worker delivery**: keep a per-fire blocked-target set, scan past the window leaving only blocked targets' rows (order-safe), cap rows/bytes inspected, and set a RELAY `max_per_tick` within Worker subrequest limits. One undecodable row halts its source's outbox by design (never skipped); 1.23b delivers the decodable prefix before it and adds a [repair runbook](relay-repair.md). Relay values are effectively ≤ ~256 KiB (hex in JSON). | 1.23a, 1.23b |
| R-104 | One deployment secret for the M1 upload MACs | WP-1.9a derives the ticket-token key from it, and WP-1.11 derives the part-receipt key (context "mkit-server part receipt v1"). It's rotated by key id: the first key signs and all listed keys verify. This supersedes the breakdown's assignment of key config to WP-1.11. | 1.9a, 1.11 |
| R-105 | ListRefs default page cap | WP-1.28 defines an absent or 0 `page_size` as the server's `max_list_refs_page_size`, and adds that sentence to STC §7.9. The WP-1.16 client never sets `page_size`. | 1.16, 1.28 |
| R-106 | WP-1.23 coordinator watermark split | WP-1.23b ships the Worker relay, R-103 liveness and membership reads. The coordinator watermark (P-23) becomes WP-1.23c, which must land before WP-5.3a (GC) and WP-5.6 (takedown), its only consumers. It covers: the renewal payload carrying each shard's relay watermark; `ls` retention while a shard's outbox is undelivered (this changes `LeaseSweep`); and `namespace_relay_watermark()` as the minimum, with the coordinator keeping the running maximum per shard (the WP-1.23a lower bound can move backwards). | 1.23b, 1.23c, 5.3a, 5.6 |
| R-107 | WP-1.29 split | **1.29a:** observability (Worker console sinks, `Metrics::gauge`, storage-pressure alerts at 70%/90% of the physical soft limit on the write path (Worker) and every 60 s (native), P-24 labelled by kind) and native `backup`. **1.29b** (depends on 1.25 and 1.23a, both merged): a per-DO snapshot export to a `BACKUPS` R2 bucket via timer kind 4, seeded on the first committed put, as a synchronous single-`fire` snapshot capped by size, keyed by the BLAKE3 of `Partition::encode`; plus a core restore driver in dependency order (root `sm` first, coordinators with `mark_lease_table_recovered` (R-100) and epoch non-decrease, ref shards with `os` re-keyed above targets' `rh` (R-102)), native `export`/`restore`, and a runbook. PITR is the primary in-place restore within 30 days; the export covers disaster recovery and backend migration. | 1.29a, 1.29b |
| R-108 | WP-5.1a split | 5.1a-1 owns §12 storage leases and events, §13 GC, the `Event` RPC, `GetServerInfo.leases`, and section renumbering; 5.1a-2 owns §10 published view and §11 quarantine. Remote `CachePurge` is deferred to 5.1b-2; WP-5.10 first lands the Rust trait. Pack holders and holds are normative; the implementation gap belongs to 5.3a with 4.10. The `gc_pending` and `AlreadyPresent` pin fields are implementation state for 5.3a. | 5.1a-1, 5.1a-2, 5.1b-2, 5.3a, 4.10, 5.10 |
| R-109 | WP-4.11 decisions | **M4-a:** query-selected proof ranges; **M4-b:** MKDS over unchanged MKDP v2 (user, 2026-09-27). URL-token paths may be empty (root tree). HTTP selects repository by path; STC §7.4 is scoped to Connect RPCs. Indexed mode only; bearer gate applies. Deferred: signed-read HTTP GETs; an object-id field on `AdmitRequest` and a token `Principal` (both need a proto WP); an O(1)-offset proof builder (4.10 records chunk offsets, 4.14 adds a boundary-aware builder and in-memory `ObjectSource` prefetch on Workers). 4.14 adds mkit-core/mkit-wasm MKDS verification; 4.16 adds HEAD to native CORS and redacts query strings. | 4.10, 4.11, 4.14, 4.15, 4.16 |
| R-110 | WP-1.23b relay liveness | The source keeps a durable scan state (`rs 00`: cycle end, cursor, and at most 32 blocked targets), so a failing target's backlog cannot hide a healthy target beyond the per-fire inspection budget. Only failed targets are blocked; reaching `max_targets` pauses the scan. Blocked targets are retried at the start of each cycle. While fewer than `MAX_BLOCKED_TARGETS` distinct failing targets precede it, every healthy target is eventually delivered: every fire that sees a deliverable row delivers at least one, and delivered rows are deleted in the same guarded checkpoint. No closed-form fire bound is claimed (two orchestrator formulas failed verification); the relay throughput regressions pin fire counts for representative schedules. A mid-cycle append first waits for the next cycle. Fires that deliver nothing back off. A target's later row is not retried ahead of its earlier undelivered row. This can exceed `RELAY_LAG_BOUND_MS`; WP-1.23c's `namespace_relay_watermark` must tolerate it. Beyond the cap, the cycle resets. This supersedes R-103's liveness wording. | 1.23b |
| R-111 | WP-1.9a review carry-forwards | (1) Kind-2 ticket-expiry timer rows have no handler until WP-1.14, so an expired ticket re-arms its shard's alarm every 5 s and counts against the tick scan budget: no deployment of this branch before WP-1.14 lands. (2) Live-ticket and `AlreadyPresent` answers write replay rows with no quota charge (STC §7.7); WP-1.14/1.27 bound replay-row growth per signer (R-31). (3) WP-1.10: the live-ticket answer must guard the ticket row, so a concurrent consume cannot return a just-consumed ticket. | 1.10, 1.14, 1.27 |
| R-112 | WP-1.29b restore invariants | Restore is Fresh-only. Import the root `sm` first; mark coordinators recovered (R-100); set each namespace epoch to `max(snapshot + 2^32, --epoch-at-least)` and drop old ref-shard `el` leases so old grants cannot write. For each relay source, compute `floor = max(snapshot os, max supplied rh)`, re-key restored relay rows by `floor`, and set `os = snapshot os + floor`; refuse overflow. Reject missing relay sources and namespace coordinators by default. `--allow-incomplete` reconstructs missing sources at `os = floor`; missing coordinators additionally require `--epoch-at-least`, and receive that epoch and `lr`. Drop restored `rs`, `bk` and kind-4 timer rows. In-place/Merge restore and a production Worker restore/PITR admin route are deferred to WP-5.11b; segmented export above the size cap, post-restore index reconcile (R-116, after 1.28), a replay fence, and a GC hold at least as long as backup retention (M5) are also deferred. | 1.29b, 5.11b |
| R-114 | WP-1.11 split along the storage seam | **1.11a:** protocol, receipts, trait plus memory, BeginUpload session. **1.11b:** FS, native wiring, shared storage multipart suite and conf-native wire cases under `Feature::Multipart`. 1.12 and 1.13 depend on 1.11b; 1.18 depends on 1.11a. Completion writes the upload marker (R-113). Stateless completion writes no row, so indexed-mode verification scheduling (SPEC-SERVER §9.5) moves to the first AdvanceRefs that consumes the ticket. A BeginUpload cancelled after `begin_multipart` can leak a session; WP-1.14 and backend lifecycle rules reclaim sessions no ticket references. R2 multipart tags are MD5 ETags: WP-1.12 must verify the completed object's BLAKE3 or escalate. G18 corrected: `mkit-transport-s3` multipart helpers are private and blocking; only `sigv4` is reusable in 1.13. | 1.11a, 1.11b, 1.12, 1.13, 1.18 |
| R-115 | WP-5.1a-1 fix-2: reliance on existing members | Writes that newly rely on an existing member MUST durably clear its GC mark before commit; in opaque mode this covers every non-uploaded pack listed in new packmap nodes. WP-5.3a designs the detection mechanism and its cost, and escalates to the user if it adds more than one metadata read per newly referenced pack to the push path. | 5.1a-1, 5.3a |
| R-116 | Post-restore index reconcile | Rebuilding index and membership rows from restored ref shards is required before GA; it runs after WP-1.28. Per-partition snapshots do not form one consistent cut, and relay rows already delivered before a target's snapshot are gone from the source, so an older target can retain missing rows after restore. | 1.28, 1.29b |
| R-117 | Restore replays takedown actions | A restore must replay takedowns and reinstatements recorded after the snapshot in action order; active admin-store action records are the source, independent of audit pruning. Owner: the admin implementation (5.11a/b), with a 1.29b follow-up. | 5.11a, 5.11b, 1.29b |
| R-118 | WP-5.1b split | 5.1b-1 defines §14 and notices; 5.1b-2 defines §16 and remote CachePurge. A global inspector hit takes down content (user, 2026-09-28); resolution is per repository; a holder sweep finds small blobs; superseded packs are deleted at completion; notices use a custom DSSE payloadType; writers are told of repository- and namespace-level takedowns. | 5.1b-1, 5.1b-2, 5.6, 5.9a, 5.10, 5.14 |
| R-119 | WP-5.1c storage receipts | Receipts are evidence at issue time, not a promise, and attest the live committed advance only (user, 2026-09-28). Subjects are blake3-only (SPEC-ATTESTATIONS §4.2 amendment); WP-5.8 adds an additive blake3-only encode path to published `mkit-attest`, without a field-type change. Keys use `blake3:<64hex>` DSSE ids, a well-known key list kept forever, and compromise by removal. `AdmitAllow.external_ref` carries the implementer's reference. The advance batch has one op of headroom (`outbox.rs`), so WP-5.8 must budget the receipt row against the published pointer (WP-5.4). WP-5.12 stores receipts under `.mkit/receipts/`, not `.mkit/attestations/`. SSH and enc clients receive no storage receipts in M5; transport integration is a follow-up. WP-5.8: the pending-signature row is the stored statement row (one op of advance-batch headroom); the key fixed at apply is kept until its pending signatures complete; write-only grantees are limited to in-scope advance and per-ref lease receipts. | 5.1c, 5.8, 5.12 |
| R-120 | WP-5.1b-2 admin API | The admin key list carries roles (user, 2026-09-28): `lease`, `moderation`, `grants`, `audit`, `all`. The admin envelope uses `mkit-admin:v1`; the audit hash chain uses `mkit-admin-audit:v1`. Native uses a loopback listener by default; Workers use a separate path. The audit log is admin-only in v1. Remote CachePurge uses the outbox (5.10 depends on 5.1b-2). Namespace-scoped events use `Event.namespace`. | 5.1b-2, 5.10 |
| R-121 | M1 staging exit no longer gates M2–M4 code (user, 2026-09-28) | Proto, core and client WPs in M2–M4 depend on the specific M1 code WPs they build on, not on the M1 staging exit 1.20: 2.2 and 3.1 depend on 1.2 (M1 proto/codegen); 4.5 on 1.23 and 1.8; 4.10a on 1.8; 4.9 and 2.10 on 1.16. Staging and conformance WPs (1.20, 2.15, 3.13, 4.18 and each milestone exit) keep their staging edges, so staging-only problems surface at those exits. | 2.2, 2.10, 3.1, 4.5, 4.9, 4.10a |
| R-128 | WP-4.9 pending verification polling | Polling lives in `ConnectTransport` with no new error variant; the mechanism ships now. WP-1.17 passes the earliest consumed ticket's `expires_unix_ms` and reuses this helper. WP-1.17 also owns the orphaned 4.4 client obligations: re-plan once on "delta base not available", rebuild the packlist, retry membership-lag `unavailable` past the ladder up to 60 s, and fail cleanly on "too many open upload tickets". WP-4.7 and WP-4.8 own two open cases: inline verification exceeding the 20 s client timeout, and indexed mode with one repository and a threshold above 0. Consider bundling all `TransportError` changes, with `#[non_exhaustive]`, into the 0.5.0 break. | 4.9, 1.17, 4.7, 4.8 |
| R-131 | WP-4.10a holder sub-sharding deferred (user, 2026-09-28) | ContentIndex shards on Workers are already wired (WP-1.8). Holder sub-sharding is deferred: holders stay in the object's primary content shard. The trigger to revisit is an object whose holder count or content-shard size approaches a configured threshold (alert). WP-4.10 absorbs what is still needed: the holder value becomes `HolderV1 { seq, op_id }` so SPEC-SERVER §13.3's per-holder change sequence exists, and the hold is released in the same primary batch that records the holder (R-75 unchanged). Timer kind 6 stays reserved. | 4.10, 4.10a |
| R-133 | WP-5.6 takedown sweep enumeration | WP-5.6 builds the `nl` namespace registry that the takedown sweep enumerates, and WP-5.6's sweep uses at most one read per distinct index partition per repository. A namespace MUST be registered in `nl` before any write into it commits, and the sweep reads `nl` only after that registry's own watermark passes the cut. | 5.6 |

---

## 6. Human-action checklist

| When | WP | Action | Who / needs |
|---|---|---|---|
| Before P1 | P0 | ~~Cloud Build PR triggers~~: dropped (no CI on the feature branch) | — |
| Before P1 | P0 | ~~GitHub ruleset for `feat/mkit-server`~~: dropped (no CI on the feature branch) | — |
| P1 | P1 | ~~Confirm the checks appear on a throwaway PR~~: dropped (no CI on the branch) | — |
| Specs | S1, S2, S3, 3.6, 4.4, 4.11, 5.1a-1/2, 5.1c | Review the normative text at each marked point. `human_action: true` marks a user review point; spec PRs merge under local gates and adversarial review. Close #1087 with the credit comment when S1–S3 have merged. | User |
| Before M0-16 | M0-16 | Confirm the Cloudflare account is on **Workers Paid** (10 GB SQLite per Durable Object, CPU configurable to 5 min, 10,000 subrequests per invocation); the plan's limits assume it (Free caps DOs at 1 GB) | Cloudflare account admin |
| M1 | 1.19 | **Resolved (D35):** `staging-vcs.mkit.sh` on the `mkit.sh` zone, in the same account as the other mkit workers, as `env.staging` of `vcs-worker`. Dedicated staging R2 buckets and DO classes. Data can be reset at any time (no retention promise; CI may wipe it). One dedicated staging CI Ed25519 signer (GitHub secret) whose namespace is the only allowlist entry. Resources are created through the Cloudflare MCP with the user's OK. | Coordinator (with user OK) |
| M1 | 1.19 | Create a Cloudflare API token scoped to Workers Scripts:Edit, Workers Routes:Edit, R2:Edit, Durable Objects; verify scopes (a previous deploy failed with APIError 7403 on a token lacking D1 scope) | Cloudflare account admin |
| M1 | 1.19 | `wrangler r2 bucket create mkit-vcs-objects-staging` and a `BACKUPS` bucket; install a 35-day default lifecycle rule scoped to `backups/` only, never `packs/` or other CAS objects | Cloudflare |
| M1 | 1.19 | First `wrangler deploy --env staging` (DO migration `v2`), `limits.cpu_ms`, placement vars (default none) | Cloudflare |
| M1 | 1.19 | Generate the staging CI Ed25519 signer, put its `ed25519-<hex>` namespace on the allowlist; generate the ticket/receipt MAC key and install it as a Wrangler secret | Key custody |
| M1 | 1.20 | GitHub secrets `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `MKIT_STAGING_SIGNER_SEED`; variable `MKIT_STAGING_URL` | Repo admin |
| M1 | 1.19 | Manual `mkit push`/`clone` smoke against staging (the M1 exit record) | User workstation |
| M2 | 2.15 | Staging URL-token key (Wrangler secret, key id published); test owner secp256k1 wallet key secret for the eip191 case; WebAuthn RP config; redeploy | Repo admin, Cloudflare |
| M3 | 3.9, 3.13 | Deploy the stub MPP hook Worker to staging, bind it (service binding / optional Queue), install the hook-channel key | Cloudflare |
| M4 | 4.8, 4.18 | Enable indexed mode on staging, raise `limits.cpu_ms`, confirm R2 lifecycle rules never delete `objects/` | Cloudflare |
| M5 | 5.6, 5.13 | Create the restricted preservation R2 bucket on staging (admin-only access) | Cloudflare |
| M5 | 5.8 | Generate the receipt+notice key, install as a secret, publish the key list | Key custody |
| M5 | 5.11a | Generate the admin key, install its public key, decide custody | Key custody |
| Before REL | REL, M0-19 | Allow GitHub Actions to create packages in the `officialunofficial` org (org Settings → Packages → package creation), so the release workflow can push the first `ghcr.io/officialunofficial/mkit-server` image | Org admin |
| REL | REL | Merge `feat/mkit-server` → `main`; run the mkit-release flow (signed tag; `cargo publish --workspace` rather than release-plz when the signed tag precedes publishing; org `CRATES_PACKAGE_KEY`); after the release, check the ghcr `mkit-server` package is private and linked to the repo | User |
| After REL publish | REL | Add the team owners to every newly published crate (`mkit-server`, `mkit-server-native`, `mkit-server-conformance`): `cargo owner --add github:<org>:<team> <crate>` with the same team that co-owns the existing mkit crates | crates.io owner |

---

## 7. Remaining truly open questions

None that block a WP. The former item "staging environment ownership" is resolved by D35 (§6), and `X-Mkit-Ref` is
decided by D36 (§4 P-14).

Everything else has an adopted or planner default in §4 (all reviewable). Planner defaults that most deserve a look:
P-6 (upload threshold 0 on multi-repo), P-16 (snapshot `ReadRef` opt-in), P-20 (single admin key; no default lease
periods), P-21 (`MAX_APPLY_WINDOW` = 10 s), P-22 (config-cache TTL 10 s), and the many-ref throughput bar in WP-1.27
(≥ 8× a single hot ref on staging).

---

## 8. Risks

- **Hot-spot ceilings.** A Durable Object sustains about 200–500 storage-writing req/s. With D34 this binds per ref shard
  (one hot ref is serial anyway: every push CASes the previous head) and per coordinator (rarely written: namespace/repo
  creation and lease renewals every 30 s per active shard). A namespace-wide single-DO design would have capped the whole
  namespace at that rate. Reads scale through R2 snapshots (1.21) and the Cache API.
- **Index size.** One DO holds ≲ 10 GB of SQLite, about 50–100M index rows. The fixed 4096 prefix fan-out gives ~200–400
  billion objects per repo; per-shard stats alert at 70%/90% (1.29).
- **Eventual consistency (D34).** Membership and `ListRefs` lag by seconds; mitigated by the safe-failure rules, the
  `X-Mkit-Ref` hint and lag-window conformance. Relay backlog and outbox backpressure are monitored.
- **Revocation latency.** Up to one lease interval (30 s) before a revocation completes; exact once reported, because
  every write batch carries a `NotAfter` commit deadline checked on the storage backend's clock (R-61/R-62).
- **Coordinator lease-renewal ceiling.** Every active ref shard renews its lease with a coordinator write about every
  30 s, so one namespace supports roughly 200–500 writes/s × 30 s ≈ **6k–15k concurrently active ref shards**. Beyond
  that, renewals queue and writes see retryable `unavailable`. Monitored through the coordinator's leased-shard count;
  raising the lease interval trades revocation latency for headroom.
- **Full partitions.** A Durable Object at 10 GB fails writes with `SQLITE_FULL` (reads and deletes keep working). The
  pipeline fails those writes closed with retryable `unavailable` and a critical alert (P-24); the 70%/90% alerts
  (1.29) should fire long before.
- **Workers memory and CPU.** 128 MB shared per isolate and wasm memory never shrinks: streaming everywhere (R-25),
  windowed verification (4.8a/4.8), CPU raised to 5 min on staging.
- **Streaming Connect through the Workers bridge.** Checked against the code in review 01: connectrpc 0.9 reads
  client-streaming bodies incrementally (`spawn_body_reader` on `spawn_local`, a bounded mpsc of one message) and
  workers-rs 0.8.6's `worker::Body` is `Send + Sync`, so M0-17 streams; its fallback parses the Connect envelopes for
  `UploadPack` directly. M1 parts are client streams of ≤ 32 MiB.
- **Native single writer.** Native SQLite serializes all shards; multi-writer native scaling needs the future Postgres
  backend (D2).
- **Scope.** 124 WPs; mitigated by the serial foundation, three tracks after M1, per-milestone exits and the rolling-wave
  brief refresh.
