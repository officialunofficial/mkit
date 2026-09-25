# mkit-server: prep, spec PRs, and Milestone M0 work-package plan

Source of truth: Linear MKIT-29 (PRD, decisions D1–D36 settled; D21 superseded by D34; D32–D36 recorded in `00-plan.md`).
Review 01 (`00-plan.md` §5.6, R-61…R-84) split M0-02 and M0-05, added edges and the `NotAfter` commit deadline; the
tables below are updated.
Snapshot: `docs/plans/mkit-server/prd-snapshot.md`. **`00-plan.md` is the consolidated plan**: its registry, Defaults adopted
table and Reconciliation log supersede this overview wherever they differ (open questions below are now decided).
Integration branch: `feat/mkit-server`. One PR per work package (WP), branch `mkit-server/wp-<id>-<slug>`,
squash-merged after an adversarial review. Every brief under `briefs/` is self-contained.

Repo baseline this plan was written against: `main` @ `db0b826b` (workspace version 0.4.2).

---

## 1. Work packages

Sizes: S ≲ 400, M 400–900, L 900–1500 changed lines (excluding generated code, golden vectors, fixtures).

### Prep

| Id | Title | Base | Size |
|---|---|---|---|
| ~~WP-P0~~ | **Dropped** (no CI on the branch; #1094 closed unmerged) | — | — |
| WP-P1 | Create `feat/mkit-server` from main, land `docs/plans/mkit-server/` (orchestrator-run) | main→new branch | S (docs) |

### Spec PRs (docs only, rebuilt from #1087, credit @christopherwxyz)

| Id | Title | Stacks on | Size |
|---|---|---|---|
| WP-S1 | SPEC-TRANSPORT-CONNECT v2: addressing, namespace policy, owner-key writes, `GetServerInfo` (#1084) | P1 | M (docs) |
| WP-S2 | SPEC-WRITE-GRANTS v1: grants, epochs, read/write capabilities (#1085/#1089) | S1 | M (docs) |
| WP-S3 | Admission challenges: 402, helper headers + allowlist, replay-after-auth, per-RPC lifecycle (#1086) | S1 | M (docs) |

### M0 — foundation refactor (no wire change)

| Id | Title | Depends on | Size |
|---|---|---|---|
| M0-01 | `mkit-server` crate: core types, errors, runtime model (`MaybeSend`, `Clock`, `send_wrap`), telemetry trait | P1 | M |
| M0-02a | Storage contract core (key-level `NamespaceStore` with declarative `Batch` incl. `NotAfter` deadlines, key layouts, codecs, `BlobStore`/`PackSink` trait), replay-ledger state model, in-memory backends | 01 | L |
| M0-02b | `ContentIndex` layer, portable export/import, optional maintenance/commitment hooks | 02a | M |
| M0-03 | `mkit-server-conformance` crate + storage-trait suite (runs on memory impls) | 02b | M |
| M0-04 | Deduplicated pure logic: CAS decision, ref validation/wire conversion, `UploadValidator`, download chunk plan, quota math, auth-v2 adapter, storage-error redaction | 01 | L |
| M0-05a | Request pipeline core (§5.4 stages as traits + defaults, `ShardMap`, planners with `NotAfter`), unary replay/admission/apply flow, tracing + metrics | 02a, 04 | L |
| M0-05b | `UploadSession`, `DownloadStream`, resumable `UploadPack`, `test-faults` seam | 05a | M |
| M0-06 | `connect` feature: vendored `mkit.transport.v1` + health codegen, `TransportService` over the pipeline, auth interceptor | 05b | M (+generated) |
| M0-07 | Black-box wire suite skeleton + runner binary; baselines vs today's servers | 03, 06 | L |
| M0-08 | FS stores in `mkit-server` (`fs` feature): `.mkit`-layout `FsBlobStore`, refs-as-files `FsLayoutStore` | 03, 04 | M |
| M0-09 | Shared SQL key-value backend `SqlKvStore` (`sql` feature, versioned physical migrations) + `mkit-server-native` crate with rusqlite `SqlConn` (no `fs` feature: moved to 10) | 03, 04 | M–L |
| M0-10 | `mkit-server-native` router + tower layers + `mkit-server` binary + graceful shutdown (FS+SQLite; enables `fs`; sqlite refuses file-ref roots) | 06, 07, 08, 09 | L |
| M0-11 | S3 `BlobStore` (native) + fake-S3 test server; S3+SQLite conformance | 10 | M |
| M0-12 | ssh-frame session binding in `mkit-server` (`ssh` feature), transport-agnostic | 05b, 08 | L |
| M0-14 | Encrypted listener moves to the `mkit-server` binary (async enc listener API with shutdown) | 10, 12 | M |
| M0-15 | Remove `--http`/`--listen-enc` from `mkit serve`; remove `mkit-transport-connect` `server` feature; docs | 10, 14 (soft: S1) | M |
| M0-13 | Port `mkit serve` ssh stdio onto the pipeline (blocking executor), stdio idle timeout, server-free CLI check | 08, 12, 15 | M |
| M0-16 | `mkit-server-worker`: streaming R2 `BlobStore`, Durable Object `SqlConn`, per-partition DO `NamespaceStore` client | 03, 05b, 06, 09 | L |
| M0-17 | Port `apps/vcs-worker` onto `mkit-server-worker`; `wrangler dev` conformance job | 06, 07, 16 | L |
| M0-18 | `release.yml`: build (separate cargo invocations), sign, SBOM, provenance for `mkit-server` archives; release-artifact feature check | 10 (soft: 14) | M |
| M0-19 | `mkit-server` container image (multi-arch, signed, attested) | 18 | M |
| M0-20 | M0 exit gate: CI wiring, invariants docs, exit checklist run | 11, 13, 17, 19 | S |
| ~~M0-R~~ | **Dropped** (adopted Q11 default: the demo stack stays unchanged) | — | — |

M0-13 is numbered before M0-14/15 for continuity with earlier drafts but **runs after** them (removing the
enc/http code first means the stdio port no longer has to keep enc.rs compiling against deleted helpers).

## 2. DAG

```text
P1 ─┬─▶ S1 ─┬─▶ S2
    │       └─▶ S3
    └─▶ 01 ─┬─▶ 02a ─┬─▶ 02b ─▶ 03 ─┬──────────────▶ 07 ◀─ 06
            │        │              ├─▶ 08 ─┐         │
            │        │              ├─▶ 09 ─┼─▶ 16 ─▶ 17 ◀┘(+06,07)
            └─▶ 04 ──┼──────────────┘(08,09) │   ▲(05b, 06)
                     └─▶ 05a ─▶ 05b ─┬─▶ 06 ─┘
                                     └─▶ 12 ◀─ 08
   10 ◀─ 06,07,08,09          11 ◀─ 10          14 ◀─ 10,12
   15 ◀─ 10,14 (soft S1)      13 ◀─ 08,12,15    18 ◀─ 10   19 ◀─ 18
   20 ◀─ 11,13,17,19
```

Critical path: 01 → 02a → 05a → 05b → 06 → 07 → 10 → 14 → 15 → 13 → 20 (11 PRs; 02b and 03 run in parallel with
05a/05b and stay off it).

## 3. Parallel waves

| Wave | Runnable together | Notes |
|---|---|---|
| 0 | P1 | orchestrator-run; lands the plan on `feat/mkit-server` (no P0: no CI on the branch) |
| 1 | S1, M0-01 | spec and code tracks are independent (M0 has no wire change) |
| 2 | S2, S3, M0-02a, M0-04 | S2 and S3 both stack on S1 only |
| 3 | M0-02b, M0-05a | |
| 4 | M0-03, M0-05b | |
| 5 | M0-06, M0-08, M0-09 | M0-09 no longer needs M0-08 (`fs` moved to M0-10) |
| 6 | M0-07, M0-12, M0-16 | M0-16 needs M0-06 (`connect`) and M0-05b (`test-faults`) |
| 7 | M0-10, M0-17 | M0-17 needs M0-07 for the wire suite |
| 8 | M0-11, M0-14, M0-18 | |
| 9 | M0-15, M0-19 | |
| 10 | M0-13 | |
| 11 | M0-20 | |

(Wave numbers here match the global waves in `00-plan.md` §3, which also lists the non-M0 WPs of each wave.)

File-overlap hazards between parallel WPs (merge in the listed order or rebase):
- `rust/Cargo.toml` `members`: 01, 03, 09, 16 each add a member. Trivial rebases.
- `scripts/check-wasm-dep-graph.sh`: 01 and 16.
- `scripts/regen-transport-proto.sh`: 06 (adds `mkit-server`) and 17 (drops `apps/vcs-worker`).
- `docs/specs/SPEC-TRANSPORT-CONNECT.md`: S1, S3 (and S2 touches §7.1), and M0-15 (§7.2 rewrite). Land S1 before M0-15.
- `rust/.config/nextest.toml` ignored-lane filter: 14, 15.
- `.github/workflows/workers.yml`: 17 only (P0 is dropped), so no M0 overlap.

## 4. How the PRD's M0 bullets map to WPs

| PRD §8 M0 item | WP(s) |
|---|---|
| Create `mkit-server`, `-native`, `-worker`, `-conformance` | 01, 09, 16, 03 |
| Merge duplicated upload validation, download chunking, ref CAS, ref-name validation, quota, envelope | 04 (canonical modules), consumers switched in 13, 15, 17; repo-worker copies stay (Q11 = no; M0-R dropped) |
| Port `mkit serve` (ssh, enc, http) and `vcs-worker`, streaming end to end; Workers buffering capped | 12, 13 (ssh), 14 (enc), 10 + 15 (http), 16 + 17 (worker) |
| Replay-ledger state model; `ContentIndex` trait surface | 02a (types + pure rules), 02b (`ContentIndex` layer), 05a/05b (flow), 09 (SQL impl) |
| FS (`.mkit` layout), S3, SQLite backends with migrations | 08, 11, 09 |
| ssh stdio read timeout | 13 |
| timeouts and concurrency caps, CORS | 10 (native), 17 (worker CORS parity) |
| `tracing` spans and a metrics facade, error redaction | 01 (traits, redaction types), 05a/05b (spans, metrics calls), 10 (subscriber, `metrics` bridge, header redaction) |
| Extend the wasm dependency-graph check | 01 (`mkit-server`), 16 (`mkit-server-worker`), 17 (`apps/vcs-worker`) |
| `mkit-server` binary via `release.yml`; container image | 18, 19 |
| Remove `--http`/`--listen-enc` from `mkit serve` | 15 |
| Exit criteria | 20 (plus per-WP acceptance) |

## 5. Findings from the code that shape the plan

1. **The CLI baseline is not tokio-free today** (hence the adopted "server-free CLI" criterion). `mkit-cli` depends unconditionally on
   `mkit-transport-connect` (tokio + connectrpc client; `rust/crates/mkit-cli/Cargo.toml` "mkit-transport-connect"
   entry) and on reqwest (blocking client spawns tokio). `cargo tree -p mkit-cli -e normal -i tokio` shows tokio.
   What the baseline *does* avoid: axum, hyper's `server` feature, connectrpc's `server`/`axum` features, and any
   tokio runtime on the `mkit serve` stdio path (`serve/mod.rs:201-207` is plain blocking I/O). M0-13 turns that into
   a checked invariant (`scripts/check-cli-baseline.sh`). See Q1.
2. `connectrpc` 0.9 depends on tokio unconditionally, but `Router`, `ConnectRpcService` and `Interceptor` are
   available without its `server` feature. So `mkit-server` with `connect` compiles for wasm32
   (as `apps/vcs-worker` already proves), but "runtime-agnostic" means "no runtime required", not "tokio absent".
3. `mkit-cli` is published to crates.io. As soon as it depends on `mkit-server` (M0-13), `mkit-server` must be
   published at the final merge-to-main release, with the 0.5 bump (adopted Q2 default; WP-REL). `mkit-transport-connect` is published and semver-checked, so removing
   its `server` feature (M0-15) is a breaking change that forces a 0.MINOR bump at the next release.
4. The replay ledger in `apps/mkit-worker-common/src/replay.rs:115-168` stores `reply = NULL` for an in-flight
   reservation and returns `Some(None)`, which `vcs-worker`'s `UploadPack` treats as "resume the interrupted
   publication" (exercised by `apps/vcs-worker/tests/auth_v2.mjs --fault`). The PRD's model says in-flight → retryable
   `aborted`. M0 keeps today's resume behavior for `UploadPack` only (Q5).
5. `FileTransport` (used by `mkit serve`) keeps refs as files under the served root (`<root>/refs/...`) and packs at
   `<root>/packs/<hex>`, with a cross-process lock at `<root>/.mkit/refs/.lock`
   (`rust/crates/mkit-transport-file/src/lib.rs:202-248, 328-334`). It has no transactional multi-ref write and no
   replay/quota. Keeping `mkit serve` on the `.mkit` layout therefore needs a refs-as-files metadata store (Q4).
6. Durable Object SQLite and rusqlite speak the same SQL. M0-09 writes the `NamespaceStore`/`ContentIndex` logic
   once over a small sync `SqlConn` trait. The DO (`transactionSync`) and rusqlite implement it, so the
   storage-trait suite exercises the Workers logic on the host.
7. `apps/*` are standalone Cargo workspaces (own `Cargo.lock`, `[workspace]`), not `rust/` members. `vcs-worker`
   vendors its own copy of the transport + health codegen (`apps/vcs-worker/generated/`). After M0-17, `mkit-server`
   owns the wasm-clean server codegen and `vcs-worker`'s copy is deleted.
8. `std::time::Instant::now()` panics on wasm32 (`apps/mkit-worker-common/src/adapter.rs:55` exists for this reason).
   `mkit-server` must never read a clock directly; `Clock` is injected.
9. `rust/.config/nextest.toml` `ignored-lane` filter names `listen_enc_*` tests in `mkit-cli`. Moving them (M0-14)
   must keep the names or update the filter.
10. Cloud Build owns the Linux Rust gate (`cloudbuild/ci.yaml`). Its PR triggers are created with
    `--pull-request-pattern='^main$'` (`scripts/setup-cloud-build.sh:99-100`), and they stay that way: by policy the
    branch has no CI (see the CI policy in `conventions.md`). PRs into `feat/mkit-server` are gated by the executor's
    local gate run and an adversarial review; the Linux Rust gate first runs on the final PR to `main`.

## 6. Questions raised by the M0 planner (all now decided; see `00-plan.md` → Defaults adopted)

Q1–Q12, Q15, Q18 and Q19 were decided by the user as listed in `00-plan.md` (Q11 = no, so M0-R is dropped; Q18/Q19
fold #1090 into S1 and #1089 into S2). Q13, Q14, Q16, Q17 and Q20 keep the planner default below and are listed in
`00-plan.md` as reviewable planner defaults. The table is kept for the rationale.

| # | Question | Planner default | Blocks |
|---|---|---|---|
| Q1 | The exit criterion says "the tokio-free baseline build still compiles", but the baseline already contains tokio (finding 1). What should the criterion be? | The **server-free baseline**: the default-feature `mkit-cli` normal graph has no `axum`, no `mkit-server-native`, no `rusqlite`/`libsqlite3-sys`, no hyper `server` feature and no connectrpc `server`/`axum` feature, and `mkit serve` builds no async runtime. Checked by `scripts/check-cli-baseline.sh`. | 13, 20 |
| Q2 | Publish `mkit-server` to crates.io at the next release (forced once `mkit-cli` depends on it)? Also publish `-native`/`-conformance`? | `mkit-server`: publishable (version.workspace, no `publish=false`). `-native`, `-worker`, `-conformance`: `publish = false` in M0. | 01, 13, 18 |
| Q3 | The PRD puts FS blobs in `-native`, but the server-free ssh path in `mkit-cli` needs them. Is an `fs` feature on `mkit-server` (std-only, no tokio) OK? | Yes, `mkit-server/fs`. `-native` re-exports it and offloads calls to `spawn_blocking`. | 08, 13 |
| Q4 | Which metadata store backs `mkit serve` (ssh) and a `mkit-server --repo-root` Connect deployment with bearer auth? | ssh: `FsLayoutStore` (refs as files, same bytes as today, no replay/quota). Binary: `--meta fs-layout` allowed only with bearer/none auth (parity with the removed `mkit serve --http`). `--meta sqlite:` is required for auth v2. | 08, 10, 13 |
| Q5 | In-flight replay semantics in M0 | Keep today's resume for `UploadPack` (`ReplayState::InFlight { resumable: true }`). Non-resumable in-flight → `aborted` (retryable), per the PRD. The final `UploadPack` semantics are settled by S3/M1 tickets. | 02, 05, 17 |
| Q6 | Where does `mkit-server-worker` live? It depends on `apps/mkit-worker-common` (standalone, `publish=false`). | `rust/crates/mkit-server-worker`, a workspace member with `publish = false` and a path dependency on `../../../apps/mkit-worker-common`. Wasm-only modules are `cfg(target_arch = "wasm32")`. | 16 |
| Q7 | Which S3 endpoint does CI use for the S3+SQLite exit criterion? | An in-repo fake S3 (axum, in `mkit-server-conformance`, test-only) in normal CI. An optional `#[ignore]` MinIO/testcontainers test is not added to the ignored-lane filter. | 11 |
| Q8 | Where does the `wrangler dev` conformance run live? It needs Node, wrangler and worker-build. | A new job in `.github/workflows/workers.yml`, path-gated like the existing `ci` job. `wrangler` pinned through `npx wrangler@<version>`. | 17 |
| Q9 | Container registry, visibility and base image | `ghcr.io/officialunofficial/mkit-server` (private while the repo is private), `gcr.io/distroless/cc-debian12:nonroot`, linux/amd64 + linux/arm64, cosign keyless signature and GitHub provenance attestation on the digest. | 19 |
| Q10 | Which platforms does `mkit-server` ship for? | The same 4 targets as `mkit`. | 18 |
| Q11 | Deduplicate `apps/repo-worker`'s copies (refs, write_quota, envelope, storage_error)? The PRD's rollout says the demo stack stays unchanged. | **No** in M0. M0-R is written but only runs if you say yes. | M0-R |
| Q12 | Default stdio idle timeout for `mkit serve` (new behavior for idle ssh sessions) | 60 s for the Hello and between frames, `--idle-timeout-secs 0` disables. Mirrors the enc listener defaults (`serve/mod.rs:82-98`). | 13 |
| Q13 | Durable Object class, binding and instance names | Keep `RefStore` / `REFSTORE` / instance `"root"` for the deployment-default namespace, so there's no wrangler migration in M0. | 16, 17 |
| Q14 | The default quota in D27 is per (namespace, signer) **and per namespace**. Adding the per-namespace cap in M0 would change behavior. | M0 keeps today's per-signer limits (300 ops/h, 128 MiB/h, `apps/vcs-worker/src/write_quota.rs:31-39`), keyed by (namespace, signer). The per-namespace aggregate lands in M1. | 04, 05 |
| Q15 | `cloudbuild/codegen.yaml:76-77` hardcodes `buf breaking --against '.git#branch=main'`, and `proto.yml` compares against `origin/main`. | ~~In P0, switch both to the PR base branch (`$_BASE_BRANCH` in Cloud Build, `github.base_ref` in Actions), with `main` as the fallback. M0 has no proto change, so this only matters from M1.~~ N/A (P0 dropped; no CI on the branch). | P0 |
| Q16 | In M0, is `PackExists` membership (single-repo) answered by blob presence? | Yes (`MembershipMode::StorePresence`), the same as today everywhere. Explicit membership rows start in M1. | 02, 05 |
| Q17 | Is it OK to unify `vcs-worker`'s single-chunk `DownloadPack` on 800 KiB chunks (valid per SPEC-TRANSPORT-CONNECT §6.2)? | Yes. The wire contract is unchanged, and the conformance suite asserts contiguity rather than chunk count. | 17 |
| Q18 | Should the spec text for `BeginUpload`, tickets and resumable parts (#1090, M1) go in S1? The PRD says "the M1 spec PR", but the S1–S3 split doesn't assign #1090. | Include it in S1 as §6.x "Upload tickets", without admission rules. S3 references it. If you say no, it becomes a WP-S4 on S1, and S3 then stacks on S4. | S1, S3 |
| Q19 | Should the signed-read, private-repo and `IssueObjectUrl` text (#1089) go in S2? | S2 defines the `read` capability in the grant format, because the format can't grow later without a v2. Signed reads, private repos and `IssueObjectUrl` go in S2 §9 only if S2 stays at M size or smaller. Otherwise they split into WP-S2b. | S2 |
| Q20 | New third-party crates: `rusqlite` (bundled C SQLite), `tower-http`, `metrics`, `tracing-subscriber`, `send_wrapper` (wasm only). Is that acceptable for `cargo deny`/licensing, and is a Prometheus exporter wanted in M0? | Allowed. No Prometheus exporter in M0: the binary installs the `metrics` facade only, and an exporter is a deployment choice. | 01, 09, 10 |

## 7. Spec-vs-implementation sequencing notes

- M0 changes no proto. Each M0 PR must show `git diff origin/feat/mkit-server -- proto/` is empty.
- The spec PRs change docs only. Their proto messages land with the M1/M2/M3 implementation PRs (D24: additive only;
  `buf breaking` stays green).
- M0-15 rewrites SPEC-TRANSPORT-CONNECT §7.2 (the "mkit serve" HTTP mode is gone). If S1 has not merged, M0-15
  rebases onto it rather than the reverse.
