# mkit-server implementation plan (MKIT-29)

The implementation plan for the production mkit server epic. The canonical PRD is
[Linear MKIT-29](https://linear.app/officialunofficial/issue/MKIT-29); [`prd-snapshot.md`](prd-snapshot.md) is a dated copy of it.

## Files

| File | What it is |
|---|---|
| [`00-plan.md`](00-plan.md) | The consolidated plan: pipeline, WP registry, DAG and parallel waves, defaults, reconciliation log, human actions, risks. **It wins** over the other files wherever they differ. |
| [`conventions.md`](conventions.md) | Shared executor rules: base branch, branch naming, TMPDIR, commit trailer, no CI polling or comments, size target, per-PR gate, pre-production policy, credit rule for spec PRs. |
| [`prd-snapshot.md`](prd-snapshot.md) | Snapshot of the approved PRD (decisions D1–D36). |
| [`registry.json`](registry.json) | Machine-readable WP registry: id, title, milestone, track, dependencies, size, area gates. |
| [`linear-groups.json`](linear-groups.json) | The 25 Linear work groups (G01–G25) and the WPs each one contains. |
| [`m0-overview.md`](m0-overview.md) | M0 (foundation) overview. |
| [`m1-m2-breakdown.md`](m1-m2-breakdown.md), [`m3-m5-breakdown.md`](m3-m5-breakdown.md) | Coarse breakdowns for the later milestones (rolling wave: detailed briefs are written at each milestone boundary). |
| [`briefs/`](briefs/) | Executor briefs, one per WP (`WP-<id>.md`). Currently Prep, Specs and M0. |

## Branch and PR conventions

- Integration branch: **`feat/mkit-server`**, cut from `main` at `db0b826b`. Every WP targets it.
- One PR per WP. Branch `mkit-server/wp-<id>-<slug>` (id lowercased, dots as dashes).
- The per-PR gate, commit trailer and the other executor rules are in [`conventions.md`](conventions.md).
- **No CI on the branch** (see the CI policy in [`conventions.md`](conventions.md)): local gates plus an adversarial review per PR. CI runs only on the final PR to `main`. WP-P0 is dropped.

## Linear tracking

Linear tracks the epic as **25 work groups (G01–G25)**, the sub-issues of MKIT-29. Each group lists its WPs;
[`linear-groups.json`](linear-groups.json) is the mapping. The **WP id stays the unit of execution**: one brief, one branch
and one PR per WP. A group is done when all of its WPs have merged.

| Group | Milestone | Title | WPs |
|---|---|---|---|
| G01 | Prep & Specs | Prep: land the plan on feat/mkit-server (P0 dropped: no CI on the branch) | P0, P1 |
| G02 | Prep & Specs | Specs: rebuild #1087 as S1 addressing/uploads, S2 grants/private, S3 admission | S1, S2, S3 |
| G03 | M0 Foundation | M0: core crate, backend-agnostic storage contract and storage conformance | M0-01, M0-02a, M0-02b, M0-03, M0-04 |
| G04 | M0 Foundation | M0: request pipeline, Connect binding and wire conformance suite | M0-05a, M0-05b, M0-06, M0-07 |
| G05 | M0 Foundation | M0: native server, FS/S3/SQL backends, ssh-frame session and the mkit-server binary | M0-08, M0-09, M0-10, M0-11, M0-12, M0-14 |
| G06 | M0 Foundation | M0: port mkit serve (ssh) and vcs-worker onto the core | M0-13, M0-15, M0-16, M0-17 |
| G07 | M0 Foundation | M0: release pipeline, container image and M0 exit | M0-18, M0-19, M0-20 |
| G08 | M1 Addressing & uploads | M1: proto, part commitments and multi-repo addressing | 1.2, 1.3, 1.4 |
| G09 | M1 Addressing & uploads | M1: D34 sharding (DO classes, relay, timers, ref index), epoch leases, policies, GetServerInfo, quota | 1.5, 1.6, 1.7, 1.8, 1.22, 1.23, 1.24, 1.25, 1.26, 1.28 |
| G10 | M1 Addressing & uploads | M1: BeginUpload tickets, client-streaming parts (R2/S3 multipart), AdvanceRefs consumption | 1.9, 1.10, 1.11, 1.12, 1.13, 1.14 |
| G11 | M1 Addressing & uploads | M1: client changes, ssh/enc multi-repo and published-view snapshots | 1.15, 1.16, 1.17, 1.18, 1.21 |
| G12 | M1 Addressing & uploads | M1: staging, ops (backups, alerts) and M1 exit conformance | 1.19, 1.20, 1.27, 1.29 |
| G13 | M2 Identity | M2: grant and epoch formats and verifiers (mkit-attest) | 2.2, 2.3, 2.4, 2.5 |
| G14 | M2 Identity | M2: server authorization, ref scopes, epochs, signed reads, private repos, URL tokens | 2.6, 2.7, 2.8, 2.9, 2.11, 2.12 |
| G15 | M2 Identity | M2: client signed reads, grant/epoch CLI and M2 exit | 2.10, 2.13, 2.14, 2.15 |
| G16 | M3 Admission | M3: admission (402), outcome outbox and adapter delivery | 3.1, 3.2, 3.3, 3.4, 3.5 |
| G17 | M3 Admission | M3: SPEC-SERVER, remote hooks and hook channels | 3.6, 3.7, 3.8, 3.9, 3.14 |
| G18 | M3 Admission | M3: client 402 handling, admission_helper and M3 exit | 3.10, 3.11, 3.12, 3.13 |
| G19 | M4 Indexed mode | M4: indexed ingestion, verification and D32 extraction | 4.1, 4.2, 4.4, 4.5, 4.6, 4.7, 4.8, 4.8a, 4.9, 4.10, 4.10a, 4.17 |
| G20 | M4 Indexed mode | M4: HTTP serving, proofs, paid/private reads and M4 exit | 4.3, 4.11, 4.12, 4.13, 4.14, 4.15, 4.16, 4.18 |
| G21 | M5 Lifecycle | M5: lifecycle specs, leases and GC | 5.1a, 5.1b, 5.1c, 5.2, 5.3a, 5.3b |
| G22 | M5 Lifecycle | M5: published view and quarantine (ContentInspector) | 5.4, 5.5 |
| G23 | M5 Lifecycle | M5: storage receipts (server signing and client storage) | 5.8, 5.12 |
| G24 | M5 Lifecycle | M5: takedown, redaction notices, cache purge, admin API, reinstatement | 5.6, 5.7a, 5.7b, 5.9a, 5.9b, 5.10, 5.11a, 5.11b, 5.14 |
| G25 | Release | M5 exit conformance and final release to main (0.5.0) | 5.13, REL |

## Work-package status

The orchestrator updates this table as WPs merge. "Plan" links the brief when one exists, otherwise the milestone breakdown.
Split and dropped WPs keep their briefs for the record: [WP-M0-02](briefs/WP-M0-02.md) (split into 02a/02b),
[WP-M0-05](briefs/WP-M0-05.md) (split into 05a/05b) and [WP-M0-R](briefs/WP-M0-R.md) (dropped).

| WP | Group | Title | Plan | PR | State |
|---|---|---|---|---|---|
| P0 | G01 | Enable CI on feat/mkit-server (PR to main) | [brief](briefs/WP-P0.md) | [#1094](https://github.com/officialunofficial/mkit/pull/1094) | **dropped** (no CI on the branch) |
| P1 | G01 | Create feat/mkit-server and land docs/plans/mkit-server | [brief](briefs/WP-P1.md) | [#1093](https://github.com/officialunofficial/mkit/pull/1093) | merged |
| S1 | G02 | SPEC-TRANSPORT-CONNECT v2: addressing, policies, GetServerInfo, upload tickets and parts, ref deletion, consistency (#1084, #1090) | [brief](briefs/WP-S1.md) | | planned |
| S2 | G02 | SPEC-WRITE-GRANTS v1 with signed reads, private repos, URL tokens and epoch leases (#1085, #1089) | [brief](briefs/WP-S2.md) | | planned |
| S3 | G02 | Admission challenges spec: 402, helper headers and allowlist, replay-after-auth, per-RPC lifecycle (#1086) | [brief](briefs/WP-S3.md) | | planned |
| M0-01 | G03 | mkit-server crate: core types, errors with response shaping, runtime model, telemetry | [brief](briefs/WP-M0-01.md) | | planned |
| M0-02a | G03 | Storage contract core: key-level NamespaceStore with NotAfter deadlines, key layouts, codecs, BlobStore trait, replay model, memory backend | [brief](briefs/WP-M0-02a.md) | | planned |
| M0-02b | G03 | Storage contract layers: ContentIndex over shard partitions, portable export/import, optional StoreMaintenance and StateCommitment hooks | [brief](briefs/WP-M0-02b.md) | | planned |
| M0-03 | G03 | mkit-server-conformance crate + storage-contract suite (incl. NotAfter, cancellation and crash/restart) | [brief](briefs/WP-M0-03.md) | | planned |
| M0-04 | G03 | Deduplicated protocol logic: CAS, refs, UploadValidator, download plan, quota math, auth-v2 glue, redaction | [brief](briefs/WP-M0-04.md) | | planned |
| M0-05a | G04 | Request pipeline core: stage traits, auth modes, ShardMap, pure planners with bounded re-plan and NotAfter deadlines, unary RPC flow | [brief](briefs/WP-M0-05a.md) | | planned |
| M0-05b | G04 | Request pipeline streaming and faults: UploadSession, DownloadStream, resumable UploadPack, test-fault seam | [brief](briefs/WP-M0-05b.md) | | planned |
| M0-06 | G04 | connect feature: vendored transport codegen, TransportService over the pipeline, auth interceptor, health | [brief](briefs/WP-M0-06.md) | | planned |
| M0-07 | G04 | Black-box wire conformance suite + runner binary; baselines vs today's servers | [brief](briefs/WP-M0-07.md) | | planned |
| M0-08 | G05 | FS stores with the .mkit layout (fs feature): streaming FsBlobStore, refs-only FsLayoutStore | [brief](briefs/WP-M0-08.md) | | planned |
| M0-09 | G05 | Shared SQL key-value backend SqlKvStore (owned 'static transaction closure, NotAfter, SQLITE_FULL) + mkit-server-native crate with rusqlite | [brief](briefs/WP-M0-09.md) | | planned |
| M0-10 | G05 | mkit-server-native router, tower layers and the mkit-server binary (FS + SQLite; enables `fs`; sqlite refuses file-ref roots) | [brief](briefs/WP-M0-10.md) | | planned |
| M0-11 | G05 | S3 BlobStore (native) + in-repo fake S3; S3+SQLite conformance | [brief](briefs/WP-M0-11.md) | | planned |
| M0-12 | G05 | ssh-frame session binding in mkit-server (ssh feature), transport-agnostic | [brief](briefs/WP-M0-12.md) | | planned |
| M0-13 | G06 | Port mkit serve (ssh stdio) onto the pipeline; stdio idle timeout; server-free CLI check | [brief](briefs/WP-M0-13.md) | | planned |
| M0-14 | G05 | Encrypted listener moves into the mkit-server binary | [brief](briefs/WP-M0-14.md) | | planned |
| M0-15 | G06 | Remove --http/--listen-enc from mkit serve and mkit-transport-connect's server feature; docs | [brief](briefs/WP-M0-15.md) | | planned |
| M0-16 | G06 | mkit-server-worker: streaming R2 BlobStore (spawn_local put), Durable Object SqlConn, per-partition DO client | [brief](briefs/WP-M0-16.md) | | planned |
| M0-17 | G06 | Port apps/vcs-worker onto mkit-server-worker (streaming dispatch); wrangler dev conformance job | [brief](briefs/WP-M0-17.md) | | planned |
| M0-18 | G07 | release.yml: build (separate cargo invocations), sign, SBOM and provenance for mkit-server archives; release-artifact feature check | [brief](briefs/WP-M0-18.md) | | planned |
| M0-19 | G07 | mkit-server container image (multi-arch, signed, attested) | [brief](briefs/WP-M0-19.md) | | planned |
| M0-20 | G07 | M0 exit gate: CI wiring, invariants, exit checklist | [brief](briefs/WP-M0-20.md) | | planned |
| 1.2 | G08 | Proto additions and codegen for M1 | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.3 | G08 | mkit-core: part: commitment and BLAKE3 subtree module | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.4 | G08 | Core: multi-repo addressing through the pipeline | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.22 | G09 | Core: D34 shard model: D34Shards map, namespace coordinator, ref shards | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.24 | G09 | Core + adapters: timers (due_at, kind, ref) and alarm multiplexing | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.5 | G09 | Core: namespace_policy, write_policy = owner, startup validation | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.6 | G09 | GetServerInfo (server) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.7 | G09 | Ref-shard rows: tickets, reservations, local membership, outbox (planners) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.23 | G09 | Core: repo index shards and the outbox relay | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.28 | G09 | Core: hash-bucketed ref-name index, ListRefs k-way merge pagination; flip Connect deployments to D34 | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.25 | G09 | Core: epoch leases (D34 revocation) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.26 | G09 | Core: default quota exact per ref shard, approximate per namespace | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.8 | G09 | Worker: Durable Object classes per shard kind | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.9 | G10 | Core: BeginUpload with target ref, stateless ticket token, ticketed UploadPack, ticket caps | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.10 | G10 | Core: AdvanceRefs consumes tickets, outcomes rows, ref deletion | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.11 | G10 | Core: stateless client-streaming UploadPart/CompleteUpload, part receipts, MultipartBlobStore, FS backend | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.12 | G10 | Worker: R2 multipart with client-streamed parts through the Worker | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.13 | G10 | Native: S3 multipart BlobStore | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.14 | G10 | Ticket expiry and pre-M3 outbox retention | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.29 | G12 | Ops: periodic DO backup export to R2 and per-shard storage alerts | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.15 | G11 | ssh and enc: multi-repo addressing, --principal, implicit session tickets | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.16 | G11 | Client: X-Repository everywhere, identity validation, GetServerInfo, ListRefs paging, ref hint | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.17 | G11 | Client: BeginUpload with target ref, ticket threading, nonce/re-sign rule | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.18 | G11 | Client: resumable part upload with client-held receipts | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.21 | G11 | Worker: published-view ref snapshots per ref-index bucket (R2/Cache, debounced) for readers | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.27 | G12 | M1 conformance: D34, tickets and growth cases (wire, storage, load) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.19 | G12 | Staging vcs-worker deployment config and runbook | [M1/M2](m1-m2-breakdown.md) | | planned |
| 1.20 | G12 | CI: conformance and e2e against deployed staging (M1 exit) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.2 | G13 | Proto additions for M2 | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.3 | G13 | mkit-attest: Keccak-256, EIP-191, secp256k1 recovery, address derivation | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.4 | G13 | mkit-attest: grant and epoch statement codec plus the ed25519 scheme | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.5 | G13 | mkit-attest: secp256k1-eip191 and webauthn-p256 owner schemes | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.6 | G14 | Server: grant-based write authorization, 0x namespaces, error-code alignment | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.7 | G14 | Server: ref scopes, packmap coverage and the delete flag | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.8 | G14 | Epoch: GetGrantEpoch/SetGrantEpoch over epoch leases; revoke races | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.9 | G14 | Server: signed reads, visibility via SetRepoVisibility, read grants, not_found | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.10 | G15 | Client: signed reads and grant header | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.11 | G14 | IssueObjectUrl and signed URL tokens (mint and verify) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.12 | G14 | ssh and enc: server-side grant registry (mkit-server grant register) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.13 | G15 | CLI: mkit grant create/add/list and the client grant store | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.14 | G15 | CLI: mkit grant revoke and mkit epoch | [M1/M2](m1-m2-breakdown.md) | | planned |
| 2.15 | G15 | Staging: enable M2 features and run M2 conformance (M2 exit) | [M1/M2](m1-m2-breakdown.md) | | planned |
| 3.1 | G16 | Proto: AdmissionChallenge error detail and goldens | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.2 | G16 | Core: two-phase Admission (Allow/Challenge/Deny), 402 mapping, GetServerInfo fields | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.3 | G16 | Core: outcome outbox, OutcomeSink, exactly-one-outcome, backpressure, read outcomes | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.4 | G16 | Native adapter: outbox delivery task, CORS/redaction, ssh/enc 'use mkit+https' | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.5 | G16 | Worker adapter: outbox delivery timer kind, CORS/redaction | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.6 | G17 | Spec: SPEC-SERVER v1 (M3 sections) and the mkit.server.hooks.v1 proto | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.7 | G17 | Core: remote-hook adapter (remote-hooks feature) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.8 | G17 | Native hook channels: HTTP and signed webhook outcome sink | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.9 | G17 | Worker hook channels: service binding and Queue outcomes | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.10 | G18 | Client: 402 detection -> AdmissionRequired, receipt passthrough | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.11 | G18 | Client: admission_helper, header allowlist and hard-reserved set (D30) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.12 | G18 | Stub MPP hook server and helper; end-to-end tests (M3 exit) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.13 | G18 | Wire conformance: admission, outcomes and backpressure on both adapters and staging | [M3–M5](m3-m5-breakdown.md) | | planned |
| 3.14 | G17 | Docs: TypeScript mppx reference Worker (documentation only) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.1 | G19 | mkit-core: pack-ruzstd decode feature and dep-graph check | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.2 | G19 | mkit-core: repo-isolated delta-base seam and incremental push verification | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.3 | G20 | mkit-core: build_disclosure over a generic object source | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.4 | G19 | Spec: indexed mode, D32 extraction, PendingVerification detail | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.5 | G19 | Server: per-repo object index in repo index shards | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.6 | G19 | Worker: object index in RepoIndexShard DOs (limits, batching, alerts) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.7 | G19 | Server: indexed ingestion and pre-receive verification (native/inline) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.8a | G19 | mkit-core: windowed, streaming pack reader | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.8 | G19 | Worker: async verification as checkpointed alarm slices | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.9 | G19 | Client: PendingVerification polling | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.10a | G19 | ContentIndex shards on Workers and holder sub-sharding | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.10 | G19 | Server: D32 extraction into the global object CAS, holds and holders | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.11 | G20 | Spec: HTTP serving and proofs (#1088) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.12 | G20 | Server core: HTTP object serving (http-objects feature) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.13 | G20 | Admission on HTTP reads (paid downloads) with ReadServed outcomes | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.14 | G20 | Proofs: ?proof=1 inclusion and range disclosure; mkit-wasm round trip | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.15 | G20 | Private serving via M2 signed URLs and read auth | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.16 | G20 | Adapters: mount HTTP serving (axum and Workers fetch), Range reads, CORS | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.17 | G19 | Pre-receive policy hooks: allowed signers per ref, fast-forward-only grants | [M3–M5](m3-m5-breakdown.md) | | planned |
| 4.18 | G20 | Conformance: indexed mode and serving wire suite (M4 exit) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.1a | G21 | Spec: leases, lifecycle events, server GC, published view and quarantine (#1091 part 1) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.1b | G21 | Spec: takedown, RedactionNotice, preservation store, admin API and audit log (#1091 part 2) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.1c | G21 | Spec: storage receipts predicate (#1092) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.2 | G21 | Leases and lifecycle states: model, enforcement, events | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.3a | G21 | GC mark: roots, pins, grace, gc_pending; mark → wait → re-check protocol | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.3b | G21 | GC sweep: membership drop, holder removal, zero-holder deletion, adapters | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.4 | G22 | Published view: (head, packmap) pointer storage and caller view on every read path | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.5 | G22 | ContentInspector: sync checks, async quarantine, clearance, hit -> takedown | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.6 | G24 | Takedown core: tombstones, blocklist (checked by the relay), preservation store, per-repo views, suspension | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.7a | G24 | mkit-core: delta-safe pack rewrite primitive | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.7b | G24 | Server: rewrite orchestration, packlist chain rebuild, packmap CAS | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.8 | G23 | Storage receipts: ReceiptSigner, receipt key, key list, AdvanceRefs field | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.9a | G24 | Server: RedactionNotice detail, HTTP 451, notice signing | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.9b | G24 | Client: redaction-aware fetch and push re-plan | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.10 | G24 | CachePurger hook and purge triggers (before takedown) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.11a | G24 | Admin API framework: signed envelope, replay protection, audit log | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.11b | G24 | Admin operations and the mkit-server admin CLI | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.12 | G23 | Client: receipt storage under .mkit/attestations (not GC roots, not pushed) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.13 | G25 | Conformance: lifecycle wire suite (M5 exit) | [M3–M5](m3-m5-breakdown.md) | | planned |
| 5.14 | G24 | Reinstatement via server-side pack rewrite | [M3–M5](m3-m5-breakdown.md) | | planned |
| REL | G25 | Final merge to main: 0.5.0 bump, publish mkit-server crates, first server release | [plan §2](00-plan.md#2-work-package-registry) | | planned |
