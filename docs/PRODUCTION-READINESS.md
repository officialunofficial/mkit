<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# mkit production readiness — review & execution plan

Status: **Plan**. Audience: maintainers and the agent team executing it.

This document is the output of an exhaustive multi-agent review of the
repository (2026-07-11): ten specialist reviewers over the core engine,
CLI surface, transports, RPC/schema layer, Cloudflare Workers, TS apps,
CI/release, security posture, and marker/doc drift, plus an ecosystem
research pass on buffa/ConnectRPC/Buf tooling and a completeness critic
over the combined findings. Every finding below was verified against
the tree at the time of review with file citations.

It has two halves:

1. **What we found** — the gap inventory, ranked (§2–§4).
2. **How we close it** — a target Buf/ConnectRPC architecture (§5) and
   a milestone plan with an explicit Fable 5 + Sonnet 5 execution model
   (§6–§7).

Guiding directive: **leverage buffa / ConnectRPC / Buf tooling as much
as possible.** Where a gap can be closed schema-first with generated
code on both sides of the wire, that is the preferred fix.

---

## 1. Where mkit stands

The review's consistent headline: the core is unusually strong for an
alpha, and the gaps are concentrated at the edges.

**Strong** (verified, not vibes):

- Crash-safe object store (tmp+rename, fsync-before-visibility,
  batched flush ordering), bounded DoS-resistant binary parsers,
  fail-closed GC with truncation-cap aborts, per-ref kernel-lock CAS,
  symlink/path-traversal containment with negative tests, golden
  vectors pinning v1 formats. Zero `unimplemented!`/`todo!()` in
  shipped code; clippy denies `unwrap`/`dbg!` outside tests.
- ~50-subcommand CLI with sysexits, snapshot-pinned help text, and
  thoughtful data-loss guards; docs (CLI.md / PARITY.md / man page /
  completions) largely in sync via tests.
- Rigorous signing core: DSSE/in-toto PAE construction, key-file
  `O_NOFOLLOW`/0600/atomic-write hardening, domain-separated signing.
- Mature supply chain: cosign keyless signing with pinned identity
  regexes, native DSSE release attestation with a rotation runbook,
  CycloneDX SBOM, cargo-deny/audit/geiger gates, semver-checks,
  downgrade-resistant install.sh, npm provenance for the wasm package.
- `apps/repo-worker` is a real, well-tested ConnectRPC service (envelope
  verification, serially-consistent DO CAS, server-side BLAKE3
  re-verification, body caps) — the pattern to replicate, not a toy.

**Weak** — the four structural themes every workstream below maps to:

- **T1 — The wire story is fragmented.** Three protocols coexist:
  buffa-over-stdio (signer/ssh), a bespoke JSON REST dialect
  (`mkit-transport-http`) **with no server implementation anywhere in
  the repo**, and one real Connect service (`repo-worker`) that serves
  an unrelated demo. Buf tooling is configured but dormant: no
  `buf lint`/`buf breaking` runs in any CI, `mkit-rpc/proto` has no
  buf.yaml at all, TS types are hand-mirrored with verified drift, and
  the one attempted Connect stream (WatchRefs) fell back to a
  schema-less WebSocket.
- **T2 — Security defaults don't match the pitch.** A
  "cryptographically-signed VCS" that never verifies signatures on
  clone/pull/fetch, has no trusted-signer binding even in manual
  `mkit verify`, and leaks hardware-signer PINs onto argv because the
  spec'd PinPrompt round-trip is unimplemented.
- **T3 — The hosted service is a cost/abuse liability.** Anonymous
  writes to R2 with no rate limit or quota on the paths that cost
  money, a documented-but-unfixed replay hole, no retention/deletion/
  backup story, minimal observability — and neither worker is built,
  tested, or linted by any CI.
- **T4 — Adoption/GA hygiene.** No format-migration path despite a
  latest-minor-only security policy, a legal notice promising a
  THIRD-PARTY-NOTICES file that is never generated, public parity page
  drifted from PARITY.md, no Windows binaries, quadratic `add -A`,
  macOS/Windows tests manual-only.

---

## 2. Blockers

| # | Finding | Evidence | Fix (short) |
|---|---------|----------|-------------|
| B1 | **No signature verification on clone/pull/fetch by default.** Only BLAKE3 closure completeness is checked; a hostile remote's unsigned/self-signed history is silently accepted and materialized. | `mkit-cli/src/commands/{pull,clone}.rs` (no verify calls); `remote_dispatch/mod.rs:1072-1081` (`verify_closure_present` is graph-completeness only); `commands/verify.rs` is manual, single-revision | Verify newly fetched commits/remixes/tags after fetch; fail closed by default with explicit opt-out (`pull.require_signed`) |
| B2 | **No trust-root binding for commit history.** `mkit verify` proves self-consistency only — the attacker's own key verifies "ok". `TrustRoot` is wired only into `mkit-attest` (attestations), never commit/tag verification. | `commands/verify.rs:52-61` → `mkit_core::sign::verify_*` with no trust lookup; `grep TrustRoot` hits only attest/wasm/self-update paths; SPEC-SIGNING §6 defers pairing to "application policy" that doesn't exist | `allowed_signers`-equivalent + `mkit trust add/list/remove` command family; `verify --trusted` / `log --show-signature` |
| B3 | **repo-worker: unlimited free writes.** `PutObject`/`UpdateRef` are gated on signature validity only; Ed25519 keys are free, so anyone can fill the shared R2 bucket and run up the bill. Chat/react already have DO rate-limit ledgers; the costly paths have none. | `worker_impl/auth.rs:40-45`; `service.rs:199-235,306-359` (no throttle); `chat.rs:24-26` (limiter exists for chat only); wrangler.jsonc has no rate-limit binding | Per-pubkey/per-room write budget in the RefStore DO mirroring the chat ledger + edge rate limiting; enforce via the existing ConnectRPC AuthInterceptor |
| B4 | **`mkit+https://` has no server.** The CLI's HTTP dialect exists only as a mockito mock in tests; SPEC-TRANSPORT §5 calls a "VCS Worker" the reference deployment, but none exists. There is no self-host story at all. | `mkit-transport-http/src/lib.rs:1-31`; `mkit-cli/tests/remote_dispatch_http.rs:17,25`; `ls apps/` | The centerpiece of §5: a canonical `mkit.transport.v1` Connect service, reference Worker, native Rust Connect client, and `mkit serve` |

---

## 3. High-severity gaps

**Wire/schema (T1)**

- `buf lint`/`buf breaking` never run in CI anywhere; the buf CLI isn't
  even installed in the CI image. `rust/crates/mkit-rpc/proto/`
  (signer/ssh/common — the security-critical external-signer contract)
  has no buf.yaml at all. (`.github/workflows/*`, `cloudbuild/*`;
  only hit is a comment in `release-plz.yml:69`.)
- No generated TypeScript client. Proto shapes are hand-copied in ≥3
  places (`apps/web/src/lib/repo/backend.ts`, `.../envelope.ts`,
  `reference-ts/lib/envelope.ts`); the live WebSocket parser already
  tolerates both snake_case and camelCase — drift has happened.
  No `@connectrpc`/`@bufbuild` package exists in any package.json.
- `Transport` trait forces whole-pack buffering (`&[u8]` in,
  `Vec<u8>` out, 4 GiB cap, re-cloned per retry attempt); no streaming
  or resume, while the SSH wire already chunks (800 KiB `PackChunk`).
  S3 multipart is unimplemented → packs >~5 GiB cannot be pushed at
  all. (`mkit-core/src/protocol.rs:205,300,306`;
  `mkit-transport-http/src/lib.rs:503-512`;
  `mkit-transport-s3/src/lib.rs:48-50,538-556`.)
- SSH/enc transports have zero retry/backoff and no caller retries
  `ConnectionFailed`, contradicting SPEC-TRANSPORT §7's "MUST retry".
  (`mkit-transport-ssh/src/lib.rs:213-450`;
  `remote_dispatch/mod.rs:679`.)
- The generated-code freshness gate (`check-generated-fresh.sh`) runs
  only on Cloud Build, which auto-runs for collaborators but requires a
  maintainer `/gcbrun` for fork PRs — a fork PR editing a .proto
  without regenerating can merge green. `rust.yml:82-87` explicitly
  skips codegen freshness. No unconditional GitHub Actions proto check
  exists.

**Security (T2)**

- SPEC-EXTERNAL-SIGNER's PinPrompt/PinResponse is documented but the
  host never sends `PinResponse` — any `PinPrompt` frame is a protocol
  error — so PIN-requiring signers (CTAP) take `--pin` on argv,
  world-readable via `/proc`. (`mkit-attest/src/signer_external.rs:
  449-468,613-671`; `mkit-sign-ctap/src/main.rs:107-110`.)
- repo-worker `UpdateRef` with `REF_EXPECTATION_ANY` is replayable for
  the whole 5-minute freshness window: the signed Idempotency-Key is
  never threaded into `UpdateReq`, unlike chat/react which dedupe.
  (`worker_impl/wire.rs:50-61`; `service.rs:306-359`; self-documented
  in the README.)

**Operations & CI (T3/T4)**

- `apps/repo-worker` (32 unit tests) and `apps/keys-worker` (zero
  tests) are never built/tested/linted by any CI. keys-worker also has
  no request body size cap (`lib.rs:117,150` buffer unbounded bodies).
- macOS and Windows Rust tests (incl. the keystore-backend matrix) run
  only on manual `workflow_dispatch` — platform regressions can ship
  in a tagged release untested.
- Quadratic staging: `mkit add -A` does multiple O(index) scans per
  file (`commands/add.rs:304-479`; `index.rs:126-128` "O(n)"), with no
  staging benchmark to catch it.
- No migration path for pre-1.0 format breaks (hard
  `IncompatibleRepoFormat` rejection, no export tool) while SECURITY.md
  only patches the latest minor — early adopters can be stranded.
- `NOTICE` promises a generated THIRD-PARTY-NOTICES file shipped with
  release binaries; nothing generates it (no cargo-about, no workflow
  reference) — a factual legal-compliance gap.
- Zero React component tests across apps/web (no testing-library
  dependency; all 15 test files are pure logic).

---

## 4. Medium/low inventory (grouped)

**Connect/Buf leverage** — WatchRefs falls back to a hand-rolled
WebSocket+JSON channel carrying chat/reaction/presence frames that have
no proto schema at all (`refstore.rs:71-93,132-140`;
`backend.ts:888-948`); worker↔DO hop is hand-rolled JSON-over-HTTP
(`wire.rs`, `service.rs:150-182`); stale `PACKAGE_DIRECTORY_MATCH`
lint exception in buf.yaml (comment describes a layout that no longer
exists); `reference-ts` "conformance reference" is orphaned and broken
(imports `../src/lib/...` which doesn't exist; no package.json; never
run).

**CLI/UX** — no `fetch/pull --all`; no `clone -b/-o`; machine-readable
output split three ways (`--porcelain` vs `--format=json` vs nothing on
push/pull/commit/merge); `config` can't `--unset` or scope; no transfer
progress; `log`/`diff` missing `--author/--grep/--since/-w/-U<n>`
(tracked in PARITY.md as deferred).

**Hosted service** — no retention/deletion/backup RPC or R2 lifecycle
rule; minimal observability (4 `console_error!` calls total, no
auth-failure telemetry, no Analytics Engine dataset); no
staging/preview wrangler environment; `UpdateRef` doesn't length-check
`expected_id`; no self-hosting guide or Cloudflare plan/cost
disclosure.

**Release/CI** — 3 of 11 fuzz targets missing from the nightly matrix
(`merkle_packlist`, `merkle_proof`, `sparse_verify`); no SLSA
provenance for release binaries (cosign + bespoke DSSE only); no
Windows release target despite a tested Windows keystore backend;
dependabot npm paths point at nonexistent `/web`, `/mcp` (should be
`/apps/web`, `/apps/mcp`; `apps/og` uncovered); deny.toml RUSTSEC
ignore expires 2026-08-21 — verify the reminder actually gates CI.

**Docs/product honesty** — public mkit.sh parity page
(`apps/web/src/lib/parity-data.ts`) overstates parity vs PARITY.md
with no sync test; performance claims live off-repo with no freshness
check; sigstore-keyless signer is a stub drawn at-parity in the
architecture diagram; SPEC-REFS/WORKTREE/INDEX/KEYSTORE still `draft`
while backing shipped code; repo flock has no documented
network-filesystem (NFS) caveat though it solely serializes GC vs
writers; no local pack/compaction story (ADR-0004 accepted, needs a
revisit trigger); waku is pre-1.0 under the production site; apps/og
has no tests, no `title` length cap, no Cache-Control.

---

## 5. Target Buf/ConnectRPC architecture

Ecosystem facts (verified 2026-07): buffa 0.8.1 and connectrpc 0.8.1
are current; connectrpc implements all four RPC shapes over
Connect/gRPC/gRPC-Web with interceptors and passes the full conformance
suite; `connectrpc-workers` provides Workers client transports;
protobuf-es/connect-es 2.x fully support editions and server-streaming
in browsers; `bufbuild/buf-action@v1` is the production CI gate; BSR
hosts a `buffa` remote plugin (`buf.build/anthropics/buffa`), while
Rust *service* stubs should stay vendored via build.rs (no confirmed
BSR service plugin). Prior art to copy: Gitaly's resource-RPC naming +
chunked streaming for large payloads; Buf's own registry-proto for a
stable public Connect API.

### 5.1 One buf workspace, three modules

```
buf.yaml (repo root, v2 workspace)
├── rust/crates/mkit-rpc/proto        → mkit.rpc.v1      (signer, ssh, common)   [FROZEN]
├── apps/repo-worker/proto            → mkit.repo.v1     (multiplayer demo)
└── proto/mkit/transport/v1           → mkit.transport.v1 (NEW: canonical remote)
```

- v1 stdio protocols stay **wire-frozen** (SPEC-RPC promise); buf
  `breaking` enforces that mechanically instead of by review.
- **Deduplicate `RefExpectation`/`RefEntry` now, while it's free.**
  ssh.proto and repo.proto carry verbatim copies with deliberately
  matching wire numbers (`repo.proto:39` "do NOT renumber"); extract
  them into a shared `mkit/common/v1/refs.proto` imported by both and
  by the new `mkit.transport.v1`. Because the numbers already agree
  the move is wire-identical — gate it with a WIRE-level
  `buf breaking` check (the FILE-level default flags cross-file moves;
  wire is the actual v1 freeze contract). Do this before the copies
  diverge and the merge becomes a real break.
- mkit-rpc's protos are currently flat (`proto/{common,signer,ssh}.proto`);
  restructure to `mkit/rpc/v1/` package-matching paths as part of the
  workspace move so no lint exceptions are needed.
- Drop the stale `PACKAGE_DIRECTORY_MATCH` exception; add buf.yaml
  coverage for mkit-rpc's protos.

### 5.2 CI gates (bufbuild/buf-action)

- `buf lint` + `buf format --diff` on every PR touching protos.
- `buf breaking --against '.git#branch=main'` on PRs; against the last
  release tag on release branches.
- Keep vendored generated code + `check-generated-fresh.sh` as the
  codegen gate (per research: safest for Rust service stubs); add
  connect-es/protobuf-es generation to the same freshness check.
- Optional (M3): publish modules to the BSR so external signer authors
  generate clients against a pinned ref instead of vendoring
  signer.proto by hand (as mkit-sign-se does today).

### 5.3 `mkit.transport.v1` — the canonical remote protocol (fixes B4)

A Connect service mapping the existing 8-verb `Transport` trait,
Gitaly-style:

```proto
service TransportService {
  rpc ListRefs(ListRefsRequest) returns (ListRefsResponse);
  rpc ReadRef(ReadRefRequest) returns (ReadRefResponse);
  rpc UpdateRef(UpdateRefRequest) returns (UpdateRefResponse);      // CAS via RefExpectation
  rpc AdvanceRefs(AdvanceRefsRequest) returns (AdvanceRefsResponse); // atomic two-ref advance
  rpc PackExists(PackExistsRequest) returns (PackExistsResponse);
  rpc UploadPack(stream UploadPackRequest) returns (UploadPackResponse);     // client-stream of PackChunk
  rpc DownloadPack(DownloadPackRequest) returns (stream DownloadPackResponse); // server-stream of PackChunk
  // blob verbs delegate to pack verbs as today (trait default impls)
}
```

- `PackChunk` reuses the shape already proven byte-for-byte on the
  SSH/enc wire — no new chunked-encoding invention. This also kills
  the whole-pack-buffering problem end-to-end (client streams from
  disk; server streams from R2/filesystem).
- **Three deployment targets from one proto:**
  1. **Reference Worker** (`apps/vcs-worker` or a second service in
     repo-worker): connectrpc + workers-rs + R2 + DO CAS, reusing
     repo-worker's build.rs/vendored-codegen pattern and its
     AuthInterceptor — but auth-gated (bearer/allow-list), not
     open-write.
  2. **`mkit serve`**: the same generated service trait behind
     axum/hyper (connectrpc supports both) over a local repo — the
     self-host story the CLI currently lacks.
  3. **CLI client**: a native (non-wasm) connectrpc client crate
     (mirroring `mkit-repo-client`'s zero-duplication codegen)
     becomes the `mkit+https://` transport; retry/backoff moves into
     a shared Connect interceptor instead of per-crate ladders —
     which also closes the SSH-retry gap when the enc/ssh dispatch
     migrates behind the same retry wrapper.
- The bespoke JSON REST dialect in `mkit-transport-http` is retired
  once the Connect transport reaches verb parity (CAS, atomic
  advance, sparse fetch). SPEC-TRANSPORT gains a §5 rewrite
  ("SPEC-TRANSPORT-CONNECT").
- **Known risk, planned for:** Workers' borrowed
  `WebSocket::events()` stream defeated Connect server-streaming once
  (WatchRefs). Server-streaming *responses* over plain fetch are
  viable on Workers (no wall-clock limit while the client stays
  connected; CPU billed separately) — the fix is bridging DO events
  into an owned `mpsc` channel pumped via `spawn_local` so the
  generated trait's `'static + Send` stream bound is met. Prototype
  this **first** (M2 task 0) before committing the streaming verbs.

### 5.4 Schema-first everywhere else

- **repo-worker live feed**: model Commit/Chat/Reaction/Presence as a
  proto `oneof` and implement WatchRefs as real Connect
  server-streaming using the bridge above; delete `parseActivityFrame`
  and the snake/camel tolerance hack.
- **TS clients**: `buf generate` with protoc-gen-es + connect-es for
  `mkit.repo.v1` and `mkit.transport.v1`; apps/web consumes generated
  clients for all unauthenticated reads directly (keeping the wasm
  client only where signing is involved). Deletes all three
  hand-mirrored type copies; fix or retire `reference-ts`.
- **worker↔DO hop**: small internal proto generated with buffa on both
  sides (low priority; brings the service to 100% schema coverage).
- **Signer protocol v2 (future)**: when PROTOCOL_VERSION_2 happens,
  evaluate Connect bidi-streaming as the conversation carrier — the
  PinPrompt state machine is exactly the loop hand-rolled (and
  under-implemented) in `signer_external.rs` today. v1 stays frozen
  stdio.

---

## 6. Milestones

Ordering rule: cheap mechanical gates first (they protect everything
after), then security defaults, then the Connect convergence, then GA
polish. Effort: S ≤ 1 agent-day, M ≤ 3, L ≤ 7, XL = epic.

### M0 — Gates & hygiene (parallel, ~1 week)

| Task | Effort | Theme |
|------|--------|-------|
| buf.yaml for `mkit-rpc/proto`; root buf v2 workspace; drop stale lint exception | S | T1 |
| `bufbuild/buf-action` CI: lint + breaking on PRs (both proto trees), **required and unconditional** — closes the fork-PR hole in the Cloud-Build-only freshness gate | S | T1 |
| Shared `mkit/common/v1/refs.proto` (RefExpectation/RefEntry) with WIRE-level breaking gate | S | T1 |
| CI jobs for repo-worker + keys-worker (fmt/clippy/test/wasm build) | M | T3 |
| keys-worker: body-size cap (port repo-worker pattern) + unit tests | S | T3 |
| `UpdateRef` `expected_id` length validation | S | T3 |
| Fix dependabot dirs (`/apps/web`, `/apps/mcp`, add `/apps/og`) | S | T4 |
| Add 3 missing fuzz targets to fuzz.yml matrix | S | T4 |
| macOS tests on push-to-main; Windows smoke build on PRs | M | T4 |
| cargo-about → generate THIRD-PARTY-NOTICES in release.yml (or fix NOTICE) | M | T4 |
| Verify deny.toml RUSTSEC reminder actually fails CI after 2026-08-21 | S | T4 |
| Parity-page ↔ PARITY.md sync test (generate or assert) | M | T4 |
| Fix or retire `reference-ts` (imports, package.json, CI wiring) | S | T1 |

### M1 — Security & abuse (partly parallel, ~2 weeks)

| Task | Effort | Theme |
|------|--------|-------|
| repo-worker write quota/rate limit (DO ledger + AuthInterceptor + edge rule) **(B3)** | M | T3 |
| UpdateRef replay fix: thread Idempotency-Key, DO dedup ledger | S | T3 |
| Verify-on-fetch: walk new commits/remixes/tags post-fetch, fail closed, config opt-out **(B1)** | L | T2 |
| `mkit trust` command family + allowed-signers file + `verify --trusted`, `log --show-signature` **(B2)** | L | T2 |
| PinPrompt/PinResponse host implementation (TTY prompt loop); deprecate `--pin` argv | M | T2 |
| Worker observability: accepted/rejected write logs + Analytics Engine dataset | M | T3 |
| Staging wrangler environment for both workers | S | T3 |
| repo-worker README: document storage-abuse surface until quota ships | S | T3 |

### M2 — Connect convergence (the big one, ~4–6 weeks)

| Task | Effort | Theme |
|------|--------|-------|
| **Task 0 (spike):** Connect server-streaming on Workers via owned-channel bridge; go/no-go informs everything below | M | T1 |
| `mkit.transport.v1` proto + SPEC-TRANSPORT-CONNECT draft (design review gate) | M | T1 |
| Reference server: Worker (R2 + DO CAS, auth-gated) reusing repo-worker patterns **(B4)** | L | T1 |
| `mkit serve`: same service trait over axum for self-hosting **(B4)** | L | T1 |
| Native Rust Connect client transport in the CLI; retire bespoke JSON dialect at parity | L | T1 |
| Streaming pack path: additive `Transport` streaming API; client-stream upload / server-stream download | XL | T1 |
| Shared retry interceptor (closes SSH/enc retry gap) | M | T1 |
| S3 multipart upload (still needed for the direct-S3 transport) | L | T1 |
| WatchRefs as real Connect streaming; proto oneof for live feed; delete hand-rolled WS protocol | L | T1 |
| Generated TS clients (connect-es) for repo + transport; delete hand-mirrored types | M | T1 |
| Retention/deletion RPC + R2 lifecycle + backup runbook | M | T3 |

### M3 — Product & GA polish (parallel, ongoing)

| Task | Effort | Theme |
|------|--------|-------|
| Fix quadratic `add -A` (path→position map) + staging benchmark at 10k/100k files | M | T4 |
| CLI UX: `fetch/pull --all`, `clone -b/-o`, `config --unset/--global/--local` | M | T4 |
| Unify machine output on `--format=json` (push/pull/commit/merge/verify-attest), sourced from generated proto types | L | T4 |
| Transfer progress reporting (honest bytes/objects) | M | T4 |
| `log --author/--grep/--since/--until`; `diff -w/-U<n>`; color | L | T4 |
| Export tool for incompatible-format repos + upgrade-path docs | L | T4 |
| Windows release target + install.sh support | L | T4 |
| SLSA provenance (actions/attest-build-provenance) for release archives | S | T4 |
| Self-hosting guide + Cloudflare plan/cost disclosure | S | T3 |
| Promote SPEC-REFS/WORKTREE/INDEX to stable; NFS caveat for repo flock; sigstore stub → roadmap tier in diagrams | S | T4 |
| React component smoke tests + TS coverage thresholds; apps/og tests + `title` cap + Cache-Control | M | T4 |
| BSR publishing for signer.proto integrators | S | T1 |
| Benchmark freshness job; move perf methodology in-repo | M | T4 |

---

## 7. Execution model — Fable 5 orchestrator + Sonnet 5 team

**Fable 5 (one session, the orchestrator/architect).** Owns everything
where a wrong call is expensive to unwind:

- The `mkit.transport.v1` proto design + SPEC-TRANSPORT-CONNECT (M2),
  reviewed against Gitaly/BSR conventions before any implementation.
- The M2 Task 0 streaming spike go/no-go decision.
- Security-semantics changes (B1/B2 verify-on-fetch and trust model) —
  design and final review; a Sonnet agent implements to the approved
  design.
- The `Transport` streaming API change (cross-crate, touches every
  transport).
- Adversarial review of every Sonnet PR (`/code-review` + targeted
  verification), milestone sequencing, and integration of parallel
  streams.

**Sonnet 5 team (parallel agents, one task = one branch/PR).** All
M0/M1/M3 tasks and the well-scoped M2 tasks are sized for a single
Sonnet agent with the task's evidence citations as the brief. Fan-out
per milestone:

- **M0:** all 12 tasks in parallel (independent), each PR gated on the
  new CI it adds where applicable.
- **M1:** worker tasks (quota, replay, observability, staging env) in
  parallel with CLI security tasks; B1/B2 wait for Fable's design note.
- **M2:** Task 0 spike first; then proto (Fable) → server/serve/client
  in parallel → streaming pack path → WatchRefs/TS clients.
- **M3:** fully parallel, throttled by review bandwidth.

**Working agreement for every agent PR:** cite the finding it closes
(section/row of this doc), include tests that fail without the change,
keep generated code fresh (`check-generated-fresh.sh` + buf gates),
and never touch frozen v1 protos except additively per SPEC-RPC §2.

**Definition of done for "production ready":** all §2 blockers closed;
M0+M1 complete; M2 through the reference server + CLI client (bespoke
HTTP dialect retired); M3 items triaged into GA-required vs post-GA by
the maintainers.
