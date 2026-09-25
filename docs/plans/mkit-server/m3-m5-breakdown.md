# mkit-server M3–M5: coarse work-package breakdown (rolling wave)

Source of truth: Linear MKIT-29 PRD (`docs/plans/mkit-server/prd-snapshot.md`). Decisions D1–D36 are settled and not reopened here
(D21 superseded by D34; D36 approves `X-Mkit-Ref`). Review 01 fixes: `00-plan.md` §5.6 (R-61…R-84). References to M0-02 / M0-05 mean the split WPs
(M0-02a/02b, M0-05a/05b).

**Consolidated** (see `00-plan.md`: registry, Defaults adopted, Reconciliation log R-xx; `00-plan.md` wins on any
difference). Applied here: D32 (extraction = every blob ≥ 64 KiB plus every `ChunkedBlob` reassembled once into one
object keyed by its manifest id; Range-native serving; chunks stay in packs), D33 (attestation-gated refs and
attestation transport are out of this epic; the generic `pre_receive` hook stays), D34 (metadata sharded into a
namespace coordinator, `(repo, ref)` ref shards and eventually consistent repo index shards; epoch leases; fixed
4096 prefix fan-out; bounded growth; outbox backpressure; ticket caps; ContentIndex holder sub-sharding), the
server-free CLI criterion, and the M3–M5 defaults. New WPs: 4.8a, 4.10a. "A `Mutation` with row X" means a planner
emitting a key-level `Batch` in the right shard (M0-02).
This file gives a coarse but complete WP list for **M3 (money)**, **M4 (indexed mode + serving)** and **M5 (lifecycle)**. Detailed executor briefs get written at the start of each milestone.

**Conventions**
- Branch: `feat/mkit-server`. One PR per WP, one concern each. Every PR must merge on its own and be green.
- Budget: ≲1500 changed lines per PR, not counting generated code (`*/generated/`), goldens (`rust/tests/golden/**`) or fixtures.
- Size legend: **S** ≤ 400 lines, **M** 400–900, **L** 900–1500.
- Dependencies outside this scope are written `M0:<capability>`, `M1:<capability>`, `M2:<capability>`, `S3` (admission spec PR, #1086). §H lists the assumed interfaces.
- "Gates" means the standard set plus the WP-specific items:
  - `cargo fmt`, `clippy -D warnings`, `cargo test --workspace`
  - `buf lint` and `buf breaking` when protos change
  - `scripts/check-wasm-dep-graph.sh` when a wasm-reachable manifest changes
  - the server-free CLI check (`scripts/check-cli-baseline.sh`, M0-13) when the CLI changes
  - the conformance suite on native (FS+SQLite and S3+SQLite) and on `wrangler dev` when server behaviour changes
- "Human action" lists only steps an agent can't or mustn't do (secrets, Cloudflare resources, staging deploys, product decisions).
- Spec PRs come first wherever there are wire changes (PRD §8). Golden vectors follow SPEC-CONVENTIONS §5 under `rust/tests/golden/<area>/`.

---

## A. Code grounding: facts the breakdown relies on

| Fact | Where | Consequence |
|---|---|---|
| wasm has no zstd. The non-`pack-zstd` build fails closed on `0x03`/`0x04` entries. | `mkit-core/src/pack.rs:658` `decompress_zstd_entry`. `:681` zstd impl. `:686` `#[cfg(not(feature="pack-zstd"))]` stub returns `ZstdDecompress`. `Cargo.toml:115-122` has `default=["pack-zstd"]`. | WP-4.1 fills the `:686` slot with a `ruzstd` decode path behind a new feature. It is decode-only, and `PackWriter` never compresses without `pack-zstd`. |
| The store-less pack iterator already exists and is public. | `pack.rs:1133` `PackEntry`, `:1156` `PackEntries`, `:1187` `PackEntries::new(&[u8])` | The server can decode packs without `ObjectStore`, but it needs the **whole pack in memory** (`&[u8]`). That matters for the Workers 128 MB limit (Q-M4-1). |
| Delta bases resolve from in-pack entries first, then from the **local `ObjectStore`**. | `pack.rs:1399` `resolve_delta_target` (`store.contains`/`store.read`). SPEC-PACKFILE §3.2 ("destination object store"). | Repo-isolated resolution needs a new base-source seam, not `ObjectStore` (WP-4.2). |
| Delta bases can be pre-scanned without decompressing. | `pack.rs:715` `delta_base_hashes` | The server prefetches bases asynchronously, then verifies synchronously. It also gives an early "base ∉ repo membership" rejection. |
| The closure walker is pull-based and generic over a source, but it has **no known-good frontier and no signature check**. | `verify/closure.rs:48` `trait ObjectSource { fn fetch(&mut self,&Hash) }`, `:214` `walk_closure`, `:479` `verify_closure_streaming`. `ops/graph.rs:107` `children` is the single source of child ids. | Incremental push verification needs a frontier-aware variant with signature verification (WP-4.2). The shared-`children` invariant (INVARIANTS "Closure walks share one `children` function") must hold. |
| Signature checks exist, and batch verification sits behind a feature. | `sign.rs:560` `verify_commit`, `:568` `verify_remix`, `:536` `verify_tag`, `:318` `verify_batch` (`batch-verify` feature). The CLI's post-fetch fan-out is `mkit-cli/src/remote_dispatch/packmap.rs:778` `verify_new_object_signatures` / `:801` `verify_one_object`. | Lift the per-object verify logic into mkit-core (WP-4.2) so the CLI and the server share it. |
| The disclosure builder is hard-wired to `&ObjectStore`. | `verify.rs:1279` `build_disclosure(store:&ObjectStore, …)`. `verify.rs:1219` `verify_disclosure` (store-less). `store/source.rs:19` `trait ObjectSource { fn read(&self,&Hash) }` is a second, different trait. | Generalize `build_disclosure` over `store::ObjectSource` (WP-4.3). The wasm verifiers already exist: `mkit-wasm/src/verify.rs:332` `verify_disclosure`, `:541` `blob_bao_verify_slice`, `:367` `verify_closure_packs`. |
| A disclosure range can't cross a ChunkedBlob chunk boundary. | `verify.rs:1270-1278` doc | HTTP Range proofs are limited (Q-M4-5). |
| Chunking thresholds: files **>1 MiB** are chunked into FastCDC chunks with **max 256 KiB**. | `worktree.rs:32` `CHUNK_THRESHOLD = 1 MiB`. `chunker.rs:30/32` `AVG 64 KiB` / `MAX 256 KiB`. | Read literally per object, "blobs and chunks ≥ 1 MiB" extracts almost nothing (Q-M4-2). |
| Packlist codec | `transfer.rs:41` `PACKLIST_MAGIC=b"MKPL"`, `:74` `PackListNode{prev,packs}`, `:105` `encode_packlist`, `:130` `decode_packlist` | Needed for magic classification (M4), opaque GC chain walks (M5) and chain rebuild after a rewrite (M5). |
| Client packmap: the chain is written as a blob (`upload_blob`), then the atomic `advance_refs(head, packmap)`. The packmap-contains-keys idempotency shortcut applies. | `remote_dispatch/packmap.rs:367` `advance_packmap` (`:465-467` node upload, `:475` advance). Fetch treats a missing packmap as a hard error: `mod.rs:1477` `PackmapMissing`. | Server pack rewrite (M5) must keep the chain decodable. Fetch-after-rewrite is an M5 exit test. |
| The push planner deltas only against `closure(remote_tip)`, with a self-contained re-plan fallback. | `remote_dispatch/mod.rs:744` `plan_pack_with(store, tip, remote_tip, …)`, `:798` re-plan with `None`. The build-and-upload doc is at `:846-852`. | The RedactionNotice re-plan (WP-5.9b) reuses the `:798` "no external bases" path, or adds an excluded-bases set to `plan_pack_with` (`transfer.rs:657`). |
| The client error mapping sends `PermissionDenied` to `AccessDenied`, which is not retryable. `ResourceExhausted` goes to `ServerError{429}`, which is retryable. Everything else goes to `RemoteError`. | `mkit-transport-connect/src/error.rs:101-119`. `mkit-core/src/protocol.rs:198` `is_retryable`. | A 402 carrying a `permission_denied` body already fails fast on old clients: the exit test is a test, not new code. The new `AdmissionRequired` must be non-retryable. |
| The connectrpc 0.9 client drops the HTTP status. A non-Connect 402 becomes `ErrorCode::Unknown` with the message `"HTTP error 402: …"`. Response headers and details are kept. | `connectrpc-0.9.x/src/client/mod.rs` `http_status_to_error_code` (402 falls to `_ => Unknown`). Error bodies keep `details` and `set_response_headers`. | Detect admission by (a) the `AdmissionChallenge` detail, or (b) a `WWW-Authenticate: Payment…` / `PAYMENT-REQUIRED` response header. Don't rely on the numeric status. |
| The server can emit a 402 with a Connect body. | connectrpc 0.9.0 `ConnectError::with_http_status` (`error.rs:385`), `with_headers` (`:321`), `with_detail` (`:488`) | No fork of connectrpc is needed. |
| The client sends a bearer token only when one is configured. | `mkit-transport-connect/src/client.rs:276-280` | This is the "`Authorization` only when the remote doesn't already use it" rule in D30. |
| The `TransportError` enum is not `#[non_exhaustive]`. Retry happens inside `retrying` for every RPC, including `upload_pack`. | `protocol.rs:36`, `client.rs:494/705` | Adding the `AdmissionRequired`, `PendingVerification` and `Redacted` variants is a semver-visible change to published mkit-core. That's acceptable under the pre-production policy, but flag it in PRs. |
| Config: `REPO_FORBIDDEN_KEYS` lists user-scoped-only keys. Trust is keyed by **exact endpoint** (`trusted_remote_endpoint`). Named remotes are repo-safe, meaning repo-controlled. | `mkit-cli/src/config.rs:71-93`, `:127`, `:593` `user_config_path`, `:1117` `enforce_trusted_remote_endpoint` | `admission_helper` config must be user-scoped and keyed by endpoint, never by remote name. |
| Subprocess helper prior art with a timeout | `mkit-attest/src/signer_external.rs:209` (Command, stdin framing, timeout thread) | This is the pattern for the `admission_helper` exec (JSON over stdin/stdout). |
| Attestation builders (in-toto statement, DSSE envelope, local store) compile for wasm, since mkit-wasm depends on mkit-attest. | `mkit-attest/src/statement.rs:67` `Statement`, `:89` `encode`, `:170` `for_commit` (needs the **commit bytes** for a sha256 subject). `envelope.rs:44/80` `Envelope`, `pae_of`. `verify.rs:62/125` `Registry`, `verify_envelope`. `store.rs:76` `save(layout, commit, bytes)`. | Receipts reuse these. An opaque-mode server has no commit bytes (Q-M5-4). |
| Attestations are **not transported**: "Push/pull of attestations … not yet implemented" (planned). | `docs/specs/SPEC-ATTESTATIONS.md` §7.3 | Decided (D33): attestation-gated refs and attestation transport are a follow-up epic; M4 keeps only the generic `pre_receive` policy hook. |
| Local GC treats `.mkit/attestations/<commit>/` as a **GC root**. | `docs/specs/SPEC-GC.md` roots table | Decided: client receipts are stored under attestations but are **not** object-GC roots (WP-5.12 amends SPEC-GC). |
| SPEC-GC is client-local only | `docs/specs/SPEC-GC.md` | Server GC needs its own normative section (WP-5.1a). |
| vcs-worker: one DO does replay + quota + CAS in one SQLite transaction. There are **no alarms and no queues** anywhere in `apps/`. | `apps/vcs-worker/src/worker_impl/refstore.rs` (`mutate` ≈`:360`). `apps/mkit-worker-common/src/replay.rs:115` `reserve`, `:139` fingerprint check, `:169` `finish`. | Decided: WP-1.24 builds the timer facility (`(due_at, kind, ref)` per shard, DO alarm = min due_at, idempotent handlers, per-kind budgets); M3–M5 only register timer kinds. workers-rs 0.8 has `set_alarm` (`worker-0.8.6/src/durable.rs:508`). |
| Workers limits: 128 MB memory per isolate. CPU is 30 s by default, configurable up to 5 min. Alarm and queue consumers have 15 min wall time. | Cloudflare docs (workers/platform/limits) | Pack verification on Workers must be range-streamed and checkpointed (Q-M4-1). |
| MPP two-phase: `mppx` `validateCredential()` checks without settling, and `broadcastCredential()` settles. This is documented for EVM charge. | `mpp.txt:11917` (a snapshot of https://mpp.dev/llms-full.txt). Cache and CORS rules are at `:6675`, `:6237`, `:9755-9757`. | These map onto `admit` and `outcome(Committed)`. The reference example documents the limits (Q-M3-4). x402 v2 has facilitator `/verify` and `/settle`, which map the same way. |
| Proto codegen is vendored. | `mkit-transport-connect/build.rs` (committed `generated/`, `scripts/regen-transport-proto.sh`). `buf.yaml` `breaking: FILE`. | New detail messages and `hooks.v1` add generated code, which is excluded from the line budget. |

---

## B. M3: Track Money (admission, outcomes, remote hooks, client 402)

Entry condition: M1 is merged and S3 (#1086) is merged. M3 runs in parallel with M2.

### WP-3.1: Proto: `AdmissionChallenge` error detail, plus goldens
- **Depends on:** S3.
- **Goal:** Add an additive `mkit.transport.v1.AdmissionChallenge { repeated Challenge challenges = 1; string description = 2; }` with `Challenge { string scheme; string value; }`. Document its type URL for Connect error details.
- **PRD:** §6.3, D8, D24.
- **Files:**
  - `proto/mkit/transport/v1/transport.proto`, or a sibling `errors.proto` in the same package
  - `rust/crates/mkit-transport-connect/generated/**` (regen)
  - `rust/tests/golden/transport/admission-challenge/*` (the binary detail plus the JSON Connect error body with HTTP 402)
- **Design:**
  - The detail is opaque: mkit registers no schemes (§6.3).
  - `value` carries the raw header value verbatim (for example the full `WWW-Authenticate: Payment …` parameter string, or the `PAYMENT-REQUIRED` base64 blob).
  - The JSON golden pins `code: "permission_denied"` in the body.
- **Tests:** Golden round trip (encode, then decode) in `mkit-core/tests/golden*.rs` or the transport-connect tests. `buf breaking` passes.
- **Gates:** buf lint/breaking; wasm dep-graph (the generated code is reachable from workers).
- **Size:** S (~150 lines plus generated and goldens).
- **Risks:** A naming collision with anything the S3 spec text names. Mirror S3 exactly.

### WP-3.2: Core: two-phase `Admission` stage (Allow/Challenge/Deny), 402 mapping, GetServerInfo fields
- **Depends on:**
  - WP-3.1
  - M0:pipeline-stage-traits
  - M0:error→Connect mapping
  - M0:replay-ledger state model
  - M1:BeginUpload/reservations
  - M1:GetServerInfo
- **Goal:** Extend the M0 `Admission` trait to return `Allow{reservation} | Challenge{[{scheme,value}], description} | Deny`. Pass it the full `AdmitOp`:
  - audience, repo and procedure
  - the signer or anonymous
  - namespace owner and the grant used (`None` until M2)
  - `creates_namespace` and `creates_repo`
  - `pack_id` and declared bytes
  - new-to-repo bytes
  - the idempotency key
  - **no** new-to-store bytes
- **Pipeline wiring:**
  - Order: authenticate → replay lookup (committed → stored result; in_flight → retryable `aborted`) → identity → authorizer → **admission** → replay reservation.
  - A challenge returns before *any* state write: no repo creation, no quota, no nonce consumption.
  - Admission applies to unary RPCs only. When admission is enabled, `UploadPack` without a ticket is rejected, because the `BeginUpload` threshold is 0.
- **402 mapping:**
  - `ConnectError::permission_denied(desc).with_http_status(402).with_detail(AdmissionChallenge).with_headers(passthrough)`.
  - Passthrough: `WWW-Authenticate` (one header value per MPP challenge) and/or `PAYMENT-REQUIRED`, plus `Cache-Control: no-store`.
- **Receipt passthrough on success:** implementer-supplied response headers (`Payment-Receipt`, `PAYMENT-RESPONSE`) are attached with `Cache-Control: private`. The `Allow` variant carries optional `response_headers`.
- **Shared constants:**
  - Export `PAYMENT_HEADERS_REDACT` (`Authorization: Payment`, `Payment-Authorization`, `PAYMENT-SIGNATURE`, `Payment-Receipt`, `PAYMENT-RESPONSE`) for tracing redaction.
  - Export `CORS_EXPOSE_PAYMENT` for the adapters.
- **GetServerInfo:** populate `admission_supported=true` and `begin_upload_threshold=0` when a non-default Admission is configured.
- **Startup guard (D27):** already implemented by WP-1.5; this WP only adds the non-default-Admission detection for
  remote hooks. `creates_namespace`/`creates_repo` come from the coordinator (WP-1.22); the default quota is WP-1.26's
  exact-per-shard/approximate-per-namespace model.
- **PRD:** §5.4 (0, 3, 4), §6.2 rules, §6.3 server side, D10, D27.
- **Files:** `rust/crates/mkit-server/src/{admission.rs, pipeline.rs, error.rs, server_info.rs}` (names per M0). Tests go in `mkit-server/tests/admission.rs`.
- **Tests:**
  - A challenge leaves the replay ledger, quota and repo set unchanged (storage-suite assertion on an in-memory store).
  - Committed replay returns the stored result without calling admission (a spy Admission counts calls: 0).
  - An in-flight replay gives retryable `aborted` without calling admission.
  - A fingerprint mismatch gives `invalid_argument`.
  - Pinned: the fingerprint **excludes** payment headers (the same nonce plus a credential header is the same fingerprint). This is what makes the "retry with credential" flow work.
- **Gates:** standard, plus mkit-server compiles for wasm32 (`--no-default-features --features connect`).
- **Size:** M (~800).
- **Risks:**
  - The M0 trait shape may already bake in `Allow/Deny`. The WP then becomes a trait migration, and the default quota must keep passing.
  - A fingerprint that covers headers would break the flow. Pin it in S3 and in the tests.

### WP-3.3: Core: outcome outbox model, `OutcomeSink`, exactly-one-outcome rules, backpressure, read outcomes
- **Depends on:** WP-3.2, M1 (WP-1.7 outbox layouts, WP-1.14 expiry, WP-1.24 timers).
- **Goal:** Outbox rows live in the **ref shard** of the operation (D34):
  - `AdvanceRefs` writes one `Committed{bytes_stored,new_to_repo,new_to_store,refs}` row per consumed ticket in the
    same ref-shard batch as the head/packmap CAS, local membership and replay record.
  - Any apply failure after `Allow{reservation}` writes `Aborted{reason}` in a separate batch; reservation id is the
    idempotency key (a second outcome is a no-op). Ticket expiry writes `Expired`.
  - A **read outcome variant** (adopted default): `ReadServed{reservation_id, object, bytes_served}` for paid HTTP
    reads (emitted by WP-4.13), same delivery guarantees.
  - `OutcomeSink::deliver(&Outcome) -> Result<Ack, Retry>` and a runtime-agnostic delivery driver registered as a
    timer kind (WP-1.24): claim a batch from the `oq` pending index, deliver, **delete the row on ack** (bounded
    growth), exponential backoff with jitter, never drop.
  - **Outbox backpressure** (D34 guardrail, R-35): the `oc` backlog counter {rows, bytes} is maintained in every
    batch; above a configured backlog a ref shard rejects **new admitted writes** with retryable `unavailable`
    (retry-after) and raises an alert metric (`mkit_server_outbox_backlog{shard_kind}`), so a hook consumer outage
    can't grow storage without bound. Outcomes are never dropped; delivery resumes when the sink recovers.
- **Byte accounting:** `new_to_store` in opaque mode is pack-level (`BlobStore` put-if-absent); indexed mode refines
  it per object from ContentIndex (M4). Never exposed before commit.
- **Files:** `mkit-server/src/{outbox.rs, outcome.rs, plan/outbox.rs}`, `mkit-server-conformance/src/storage/outbox.rs`.
- **Tests:** exactly one outcome per reservation across commit, lost CAS → Aborted, double Aborted, Committed after
  Aborted rejected, expiry; flaky sink delivers at least once and rows are deleted on ack; backpressure: backlog over
  the threshold → new admitted writes get `unavailable`, reads and non-admitted writes unaffected, recovery drains.
- **Size:** L (~1100).
- **Risks:** a crash between a failed apply and the `Aborted` write: the delivery driver's reconcile pass emits
  `Expired` for reservations with no outcome past ticket expiry (SPEC-SERVER states it).

### WP-3.4: Native adapter: outbox delivery task, CORS/redaction, ssh/enc "use mkit+https"
- **Depends on:** WP-3.3.
- **Goal:** native delivery runs through the WP-1.24 timer driver (no new schema: outbox rows are key layouts, M0-09);
  graceful-shutdown drain; CORS via M0-10's `RouterOptions` extension lists (expose `WWW-Authenticate`,
  `Payment-Receipt`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`; allow `Authorization`, `Payment-Authorization`,
  `PAYMENT-SIGNATURE`); preflight never hits admission; payment headers redacted in spans and access logs; the
  ssh/enc paths turn `Challenge` into "payment required: use mkit+https" (§6.9, D23).
- **Files:** `mkit-server-native/src/{delivery.rs, layers/cors.rs, redact.rs}`, ssh/enc glue.
- **Tests:** CORS preflight (no admission call); tracing-capture redaction; ssh-path challenge message; delivery
  drains on shutdown.
- **Size:** M (~600).

### WP-3.5: Worker adapter: outbox delivery timer kind, CORS/redaction
- **Depends on:** WP-3.3.
- **Goal:** register outbox delivery as a timer kind in the `RefShard` DO class (WP-1.24's alarm multiplexer and
  per-kind budgets already exist; the DO's single alarm stays `min(due_at)`); Worker-side CORS
  (`apps/mkit-worker-common/src/cors.rs` pattern) and redaction in console/observability. No new tables: the outbox
  lives in the ref shard's `SqlKvStore`.
- **Files:** `rust/crates/mkit-server-worker/src/{outbox.rs, cors.rs}`.
- **Tests:** `wrangler dev` conformance: an outcome is delivered after a DO restart; the alarm reschedules after a
  failed delivery; backpressure trips and recovers.
- **Size:** S (~400).

### WP-3.6: Spec: SPEC-SERVER v1 (M3 sections) plus the `mkit.server.hooks.v1` proto
- **Depends on:** S3, M0-20 (it adds proto, which M0 forbids). It doesn't wait for the M1 exit, which keeps it (and WP-4.4 after it) off the implementation critical path.
- **Goal:** Create `docs/specs/SPEC-SERVER.md` with these sections:
  - pipeline order and the authenticate-then-replay-lookup rule
  - the per-RPC lifecycle (the table from PRD §5.4)
  - fail-closed rules
  - outcome and outbox guarantees: exactly one outcome per reservation, at-least-once delivery, the reservation id as idempotency key, Aborted in a separate transaction, Expired on ticket expiry, and the reconcile rule from WP-3.3
  - the remote contract `mkit.server.hooks.v1` (Connect/JSON; `Authorize`, `Admit`, `Inspect`, `Outcome`) with request and response messages mirroring the Rust types
  - channel authentication (adopted default: distinct keys per role, each with a key id and rotation via a published
    key list):
    - a dedicated **hook-channel Ed25519 key** signs each request; the envelope is **domain-separated** from
      `mkit-write:v2` (`write_auth.rs:11`), e.g. `mkit-hook:v1`
    - or service-binding isolation
    - outcome webhooks signed with the same hook key (Ed25519, verifiable from the published key list)
    - replay window
  - per-hook failure behaviour: authorize and admit fail closed; outcome retries forever until acked; inspect follows D18
  - placeholders (headings only) for the M5 sections: published view, quarantine, admin API, backends and backup
- **Proto:** `proto/mkit/server/hooks/v1/hooks.proto` in a new buf module path under `proto/`, with golden JSON request/response vectors.
- **PRD:** §5.4 remote hooks, §6.10, D11.
- **Files:**
  - `docs/specs/SPEC-SERVER.md`
  - `docs/specs/README.md` index
  - `proto/mkit/server/hooks/v1/hooks.proto`
  - `buf.yaml` only if a new module is needed. Prefer the existing `proto` module.
  - `rust/tests/golden/server-hooks/*`
- **Gates:** buf lint/breaking; spec lint per SPEC-CONVENTIONS (no vendor references, §6).
- **Size:** M (~700 lines of prose plus proto).
- **Human action:** Spec review and approval before WP-3.7 merges.
- **Decided:** Q-M3-1 by the per-role key default (Ed25519 hook key + key list; no HMAC).

### WP-3.7: Core: remote-hook adapter (`remote-hooks` feature), transport-agnostic
- **Depends on:** WP-3.6, WP-3.3.
- **Goal:**
  - `RemoteHooks<C: HookChannel>` implements `Authorizer`, `Admission`, `ContentInspector` (the trait is a stub until M5; only the call shape here) and `OutcomeSink` by calling `hooks.v1`.
  - `HookChannel` is an async `call(procedure, bytes) -> bytes` with a `MaybeSend` bound.
  - Signing uses the deployment hook key, with configurable per-hook timeouts.
  - Failure mapping: a transport error or timeout on authorize or admit gives Deny (fail closed). On outcome it gives Retry.
  - Hook responses are validated: challenge values are bounded in size and count, and header names are validated.
  - Uses the generated buffa/serde types from WP-3.6, placed in `mkit-server/generated/`.
- **Files:** `mkit-server/src/hooks/{mod.rs, channel.rs, sign.rs, map.rs}`, `mkit-server/generated/**`.
- **Tests:**
  - A mock channel exercises each failure mode.
  - Signature golden vectors from WP-3.6 verify.
  - An oversize challenge list is rejected (so a hook can't make the server emit unbounded headers).
- **Size:** M (~900 plus generated).
- **Risks:** The wasm build of the generated code. The `connectrpc` zstd feature stays off (PRD §5.1).

### WP-3.8: Native hook channels: HTTP (Connect/JSON) and signed webhook outcome sink
- **Depends on:** WP-3.7, WP-3.4.
- **Goal:**
  - An HTTP `HookChannel`: a hyper/reqwest client with TLS and connection reuse, redirects disabled, a loopback-only plain-HTTP rule mirroring `TransportError::InsecureScheme`.
  - A webhook `OutcomeSink` (POST of the signed `Outcome`; a 2xx counts as the ack).
  - `mkit-server` binary config keys: hook URL, key path, timeouts.
- **Files:** `mkit-server-native/src/hooks/{http.rs, webhook.rs}`, `mkit-server-native/src/config.rs`.
- **Tests:** An in-process axum stub hook server. Fail-closed on connection refused. The webhook is retried until 2xx.
- **Size:** M (~600).
- **Human action:** None.

### WP-3.9: Worker hook channels: service binding and Cloudflare Queue outcomes
- **Depends on:** WP-3.7, WP-3.5.
- **Goal:**
  - A `HookChannel` over a service binding (`Fetcher`).
  - An `OutcomeSink` that enqueues to a Cloudflare Queue producer: the ack is the successful `send`, and the implementer's consumer owns downstream retry.
  - The webhook option (as in WP-3.8) via `fetch`.
  - The workers-rs `queue` feature is enabled on `mkit-server-worker` only.
- **Files:** `mkit-server-worker/src/hooks/{binding.rs, queue.rs}`, `apps/vcs-worker/wrangler.jsonc` (optional `services`/`queues` bindings, commented out by default).
- **Tests:** `wrangler dev` with a second local Worker as the hook (Miniflare supports service bindings and queues locally).
- **Size:** M (~600).
- **Human action:** Create the staging Queue and service binding when the staging deploy uses them (optional for exit).

### WP-3.10: Client: 402 detection → `TransportError::AdmissionRequired`, receipt passthrough surface
- **Depends on:**
  - WP-3.1
  - M1:client BeginUpload path in `mkit-transport-connect`
- **Goal:**
  - Add `TransportError::AdmissionRequired { challenges: Vec<(String,String)>, description: String, raw_headers: Vec<(String,String)> }` in `mkit-core/src/protocol.rs:36`. It is non-retryable, and `is_retryable` (`:198`) is unchanged.
  - Map it in `mkit-transport-connect/src/error.rs:101`:
    1. An `AdmissionChallenge` detail (any code).
    2. Otherwise, a payment challenge header present (`WWW-Authenticate` starting with `Payment`, or `PAYMENT-REQUIRED`) on any error, including `Unknown` from a raw 402.
  - Never parse a problem+json body, and never retry automatically (§6.3 client side).
  - **Receipt passthrough:** a per-call response-metadata sink on the Connect client (e.g. `ConnectTransport::last_response_meta()`, or an `Arc<Mutex<Vec<ResponseMeta>>>` injected at construction) captures `Payment-Receipt` and `PAYMENT-RESPONSE` from successful responses. The CLI surfaces them. This avoids widening the sync `Transport` trait (Q-M3-2, planner default; M5 storage receipts reuse the same seam).
- **Files:**
  - `mkit-core/src/protocol.rs`
  - `mkit-transport-connect/src/{error.rs, client.rs}`
  - `mkit-cli/src/remote_dispatch/mod.rs` (`DispatchError` variant plus the user message)
- **Tests:**
  - Unit: detail-based mapping and raw-402-header-based mapping (build `ConnectError`s by hand).
  - Unit: the retry ladder attempts exactly once on AdmissionRequired.
  - Unit: the "old client" simulation, i.e. the pre-WP mapping on `permission_denied` plus a 402 body gives `AccessDenied` with 1 attempt. Keep it as a regression test.
- **Size:** M (~500).
- **Risks:** Adding a `TransportError` variant touches every exhaustive `match` across transports (http/s3/ssh/enc/file/memory). The line count is mostly mechanical.

### WP-3.11: Client: `admission_helper` (user-scoped, trusted remotes), header allowlist, hard-reserved set (D30)
- **Depends on:** WP-3.10.
- **Goal:**
  - **User-scoped** config keyed by exact endpoint, never by remote name, because named remotes are repo-controlled (`config.rs` `REPO_FORBIDDEN_KEYS` model):
    - `admission.<endpoint>.helper` (path plus args)
    - `admission.<endpoint>.allow_headers` (an extension list)
    - `admission.<endpoint>.timeout_secs`
  - The helper runs only when the endpoint is trusted: it equals `trusted_remote_endpoint` or is otherwise user-configured (reuse `enforce_trusted_remote_endpoint`, `config.rs:1117`).
  - **Exec protocol:** JSON on stdin `{endpoint, repository, procedure, challenges:[{scheme,value}], description, fingerprint:{repo,signer,pack_id,bytes}}` → JSON on stdout `{headers:{name:value}}`. It has a timeout and no shell, following the `signer_external.rs:209` pattern.
  - **Allowlist filter:**
    - Default: `Payment-Authorization`, `PAYMENT-SIGNATURE`, and `Authorization` only when no bearer token is configured for this remote (`client.rs:276`).
    - The per-endpoint extension is applied next.
    - **The hard-reserved set is applied last and can't be overridden:**
      - every `x-*` envelope header (the prefix rule covers future ones)
      - `Host`, `Content-*`, `Transfer-Encoding`, `Connect-*`, `Cookie`, `X-Forwarded-*`, `Idempotency-Key`
      - hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Upgrade`)
    - A rejected header gives an error **naming the header** and whether it was reserved or merely not allowlisted.
  - **Retry:** one retry of the same `BeginUpload` with the same nonce and timestamps while the envelope is still valid (≤300 s), otherwise re-sign. On a lost response, re-send the same headers (the stored result comes back without a new challenge).
  - Credentials never reach logs or `Debug` output (use a `Redacted` wrapper type).
- **Files:**
  - `mkit-cli/src/{config.rs, admission_helper.rs}`
  - `mkit-cli/src/remote_dispatch/{mod.rs, envelope_signer.rs}`
  - `mkit-transport-connect/src/client.rs` (per-call extra headers)
  - `docs/CLI.md` config section
- **Tests:**
  - Unit: the allowlist/reserved matrix, including case-insensitivity and `x-` prefix coverage.
  - A repo-scoped `admission.*` key is rejected (extend `mkit-cli/tests/repo_config_forbidden_keys.rs` plus its snapshot).
  - Helper timeout and malformed output.
  - An exit-criterion test: a hard-reserved header can't be set even through config.
- **Gates:** standard, plus `scripts/check-cli-baseline.sh` (server-free CLI).
- **Size:** L (~1100).
- **Risks:** Plumbing per-call headers through the sync `Transport` → Connect client without widening the trait; the same seam as WP-3.10.

### WP-3.12: Stub MPP hook server and helper, plus end-to-end tests (M3 exit)
- **Depends on:** WP-3.8, WP-3.11 (and WP-3.9 for the Workers leg).
- **Goal:**
  - A test-only stub implementing `hooks.v1` `Admit` and `Outcome`:
    - It issues `WWW-Authenticate: Payment id=…, method="stub", intent="charge", request=…`.
    - It verifies a stub credential: an HMAC over the challenge id and the mkit fingerprint (repo, signer, pack_id, bytes).
    - It records outcomes.
  - A matching stub `admission_helper` binary or script.
  - E2E against `mkit-server` (native) and `wrangler dev`:
    1. challenge → helper → credential → commit → **exactly one** `Committed`
    2. an aborted upload (lost CAS) → `Aborted`, nothing settled
    3. ticket expiry → `Expired`
    4. retry after a dropped response (fault-injecting proxy) → stored result, no new challenge, admit called once
    5. an old client (the current `map_connect_error`) fails fast in 1 attempt
    6. a hard-reserved header from the helper is refused, naming the header
- **Files:** `rust/crates/mkit-server-conformance/src/stubs/mpp.rs` (feature `stubs`), `rust/crates/mkit-cli/tests/admission_e2e.rs`, `rust/crates/mkit-test-util` (fault proxy, if not already present).
- **Size:** L (~1200).
- **Risks:** Flakiness from delivery timing. Use outbox-drain hooks rather than sleeps.

### WP-3.13: Wire conformance: admission and outcome cases (black-box, both adapters, staging)
- **Depends on:**
  - WP-3.4, WP-3.5, WP-3.12
  - M1:staging CI conformance job
- **Goal:** Add the cases to the `mkit-server-conformance` wire suite:
  - a 402 has a Connect body, the detail, `no-store`, and passthrough headers
  - a preflight doesn't require payment
  - a challenge doesn't change state (nonce reusable, no repo created)
  - `UploadPack` without a ticket is refused when admission is on
  - receipt headers come with `Cache-Control: private`
  - CORS expose list
  - replay ordering (in-flight gives `aborted` without an admit call)
  - **outbox backpressure when the hook is down** (stop the stub hook; drive admitted writes until the backlog
    threshold; new admitted writes get retryable `unavailable`; restart the hook; the backlog drains to zero and
    writes succeed again; every outcome delivered exactly once per reservation id)
- **Files:** `mkit-server-conformance/src/wire/admission.rs`, `.github/workflows/*` (enable against staging with the stub hook deployed).
- **Size:** M (~700).
- **Human action:** Deploy the stub hook Worker to staging and bind it to the staging vcs-worker (secrets: hook key).

### WP-3.14: Docs: TypeScript `mppx` reference Worker (documentation only)
- **Depends on:** WP-3.6 (the contract). It can be drafted in parallel after that.
- **Goal:**
  - A `docs/examples/mppx-admission-worker/` README plus a `src/index.ts` sketch. It is not a supported crate or package, and CI doesn't build it (optionally a `tsc --noEmit` if a lockfile is acceptable).
  - `admit` → `mppx.validateCredential()`, or a 402 challenge list when there is no credential.
  - `outcome(Committed)` → `broadcastCredential()` (settle).
  - `Aborted`/`Expired` → release.
  - Shows the service-binding wiring and `requiresAuth: true` (`header="Payment-Authorization"`) when the deployment uses bearer auth (§6.3).
- **Size:** S (~350).
- **Open:** Q-M3-4.

---

## C. M4: Track Content, indexed mode and HTTP serving

Entry condition: M1 is merged. The M4 private-serving WPs (4.15) need M2 read auth. Everything else in M4 depends only on M0/M1 (plus WP-3.3's `ReadServed` outcome for paid reads, isolated in WP-4.13), and WP-4.17 on M2's grant ref scopes. The spec WPs 4.4 and 4.11 can merge before the M1 exit. Pure mkit-core WPs 4.1, 4.2, 4.3 and 4.8a can land during M0.

### WP-4.1: mkit-core: `pack-ruzstd` decode feature, plus the dep-graph check
- **Depends on:** none (it can start at any time; recommended as the first M4 PR).
- **Goal:**
  - Add a new feature `pack-ruzstd = ["dep:ruzstd"]`. When `pack-zstd` is **off** and `pack-ruzstd` is on, `zstd_decompress_capped` (`pack.rs:686`) decodes with `ruzstd` under the same `capacity` cap and `ZstdLengthMismatch` checks.
  - It is decode-only, so `maybe_compress` (`:643`) keeps returning `None` without `pack-zstd`.
  - Extend `scripts/check-wasm-dep-graph.sh`:
    - assert `ruzstd` is present and `zstd-sys` is absent for `mkit-server-worker` (indexed feature) and `vcs-worker`
    - add those crates to the checked set if M0 hasn't already
  - `mkit-wasm` does **not** turn it on by default. That's a separate decision, because the closure profile is raw-only by design (SPEC-DISCLOSURE §7.2).
- **PRD:** §6.5, §4 "wasm build has no zstd decoder", §5.1.
- **Files:** `rust/crates/mkit-core/{Cargo.toml, src/pack.rs}`, `scripts/check-wasm-dep-graph.sh`, `docs/INVARIANTS.md` (the wasm dep-graph invariant text).
- **Tests:**
  - Differential: every v2 golden pack (`rust/tests/golden/…pack…`) plus a proptest corpus decode identically under `pack-zstd` and `pack-ruzstd` (run the test binary twice via a cfg matrix in CI).
  - Decompression-bomb caps: `ZstdDecompressedTooLarge` fires on ruzstd.
  - A `wasm32` build of mkit-core with `--no-default-features --features pack-ruzstd`.
- **Size:** S (~300).
- **Risks:**
  - ruzstd performance: 2–4× slower than C zstd. Feeds into Q-M4-1.
  - Supply chain: pin the version and run `cargo deny`.

### WP-4.2: mkit-core: repo-isolated delta-base seam and incremental push verification
- **Depends on:** none (pure core).
- **Goal:**
  - (a) A `DeltaBaseSource` trait (`fn base(&mut self, &Hash) -> Result<Option<Cow<[u8]>>, PackError>`). Add `pack::decode_entries_with(pack:&[u8], bases:&mut impl DeltaBaseSource, sink: impl FnMut(Hash, Cow<[u8]>, Object))`, which refactors `resolve_delta_target` (`pack.rs:1399`) so `ObjectStore` becomes one impl. `PackReader::read` behaviour stays byte-identical.
  - (b) `verify::verify_push(new_tips:&[Hash], mode, source:&mut impl closure::ObjectSource, known: impl FnMut(&Hash)->bool) -> PushReport{verified, missing, corrupt, bad_signatures}`:
    - a frontier-aware BFS sharing `ops::graph::children` (`graph.rs:107`)
    - re-hashes via `id_from_object`
    - verifies commit, remix and tag signatures by lifting `verify_one_object` from `packmap.rs:801` into `mkit-core::sign` as `verify_object_signature`, with the CLI switched to it
    - stops at ids for which `known(id)` holds (already verified in this repo)
    - `missing` means the closure is not closed, so the push is rejected
  - Batch verification is optional (`batch-verify` is off on wasm).
- **PRD:** §6.5 (verification before refs move, isolated lookups), §5.4 step 5.
- **Files:**
  - `mkit-core/src/{pack.rs, verify.rs, verify/closure.rs (shared walker internals), sign.rs}`
  - `mkit-cli/src/remote_dispatch/packmap.rs` (call-site swap)
  - `docs/INVARIANTS.md` (a "push verification shares `children`" entry)
- **Tests:**
  - Unit:
    - a base outside the source gives `DeltaBaseMissing`
    - a frontier stop
    - an unsigned commit is rejected
    - a forged tag is rejected
    - a tree referencing an absent blob gives `missing`
  - Existing closure goldens unchanged (`mkit-core/tests/golden_closure.rs`).
  - `PackReader` goldens unchanged.
- **Size:** L (~1200).
- **Risks:**
  - Refactoring the hot unpack path (perf-sensitive: #643/#647 caching). Run the `rust/benches` unpack bench before and after.
  - Keep the streaming-closure invariants (INVARIANTS "Streaming closure verification reads only reachable objects, each once").

### WP-4.3: mkit-core: `build_disclosure` over a generic object source
- **Depends on:** none.
- **Goal:**
  - `build_disclosure_from(source:&impl store::ObjectSource, commit_id, path, selector)`.
  - `build_disclosure(&ObjectStore, …)` (`verify.rs:1279`) becomes a thin wrapper.
  - The server can then build proofs from its per-repo index or global CAS without an FS store.
  - Byte-identical bundles.
- **Files:** `mkit-core/src/verify.rs`, `mkit-core/tests/golden_disclosure.rs` (unchanged fixtures).
- **Size:** S (~200).

### WP-4.4: Spec: indexed mode, D32 extraction, `PendingVerification` detail
- **Depends on:** WP-3.6 (SPEC-SERVER exists), M1:SPEC-TRANSPORT-CONNECT v2.
- **Goal:**
  - A SPEC-SERVER §indexed-mode section:
    - opt-in
    - magic classification: `MKPK`-style pack vs `MKPL` node
    - the MKPL rule: every listed pack is a member or ticketed in the same advance
    - verification obligations (re-hash, signatures, closure)
    - **repo-isolated resolution**, with the normative statement that accept/reject and error text must not depend on global existence
    - hybrid extraction per **D32**: every plain blob ≥ 64 KiB (configurable) and every `ChunkedBlob` reassembled once
      at ingest into one global-CAS object keyed by its manifest id; chunks stay in packs for clone; file-level dedup;
      Range-native serving (resolves Q-M4-2)
    - async verification and `pending_verification` states; the advertised indexed-mode max pack size in
      `GetServerInfo` (Workers memory bound, resolves Q-M4-1 with WP-4.8a's windowed reader)
    - D34 consistency: delta-base resolution reads repo membership, which is eventually consistent. An unresolved base
      yields retryable `unavailable` ("base not yet visible") only while the ticket is younger than the
      deployment's relay-lag bound, then the uniform permanent error; the response never depends on whether the
      object exists in another repo
  - Additive proto `PendingVerification { google.protobuf.Duration retry_after }` (or `uint32 retry_after_ms`) as an `unavailable` detail.
  - SPEC-TRANSPORT-CONNECT client obligations: poll until ticket expiry instead of the ~15 s ladder (`protocol.rs:209-215`), and re-sign after 300 s.
  - The `RefPolicy` hook shape (allowed signers per ref, fast-forward-only enforcement). Attestation predicates and
    carriage are out of scope (D33).
- **Files:** `docs/specs/{SPEC-SERVER.md, SPEC-TRANSPORT-CONNECT.md}`, `proto/mkit/transport/v1/*.proto`, generated code, `rust/tests/golden/transport/pending-verification/*`.
- **Size:** M (~600).
- **Human action:** spec approval (Q-M4-2 decided by D32, Q-M4-3 by D33).

### WP-4.5: Server: per-repo object index in repo index shards (model, planners, relay targets)
- **Depends on:** WP-4.4, M1 (WP-1.23 repo index shards and relay).
- **Goal:**
  - Object-index rows in `RepoIndex{prefix}` partitions (fixed fan-out 4096 by object-id prefix, D34):
    `(repo, object_id) → {pack_key, entry_offset, entry_len, entry_type, base_id?, state: pending|verified, extracted}`,
    written through the ref-shard outbox relay (at least once, idempotent).
  - Pack verification state `pending_verification|verified|rejected` lives with the ticket in the ref shard.
  - Batch lookups (`contains_many`, `locate_many`) scoped to one repo: one `get_many` per touched prefix; no
    cross-repo query API by construction.
  - No physical migration (new key layouts in M0-02's registry).
- **Files:** `mkit-server/src/index/{mod.rs, layout.rs, lookup.rs}`, storage conformance cases.
- **Tests:** isolation (repo B never sees repo A rows for the same id), batch sizes, pending → verified, relay
  re-delivery idempotent.
- **Size:** M (~900).

### WP-4.6: Worker: object index in `RepoIndexShard` DOs (limits, batching, alerts)
- **Depends on:** WP-4.5.
- **Goal:** relay writes batched per index DO within the DO limits (≤ 100 bound parameters per statement, 2 MB
  rows, ≤ 4 concurrent subrequests per invocation); per-shard size reported through WP-1.29's stats alerts. The
  10 GB concern is handled by the fixed 4096 fan-out (PRD Q5 largely resolved by D34; ~50–100M rows per shard).
- **Files:** `mkit-server-worker/src/index.rs`.
- **Tests:** `wrangler dev` storage-suite run; a 1M-object synthetic push spread across prefixes (staging).
- **Size:** S (~400).

### WP-4.7: Server: indexed ingestion and pre-receive verification (native / inline path)
- **Depends on:**
  - WP-4.1, WP-4.2, WP-4.5
  - M1:tickets + AdvanceRefs-with-tickets
- **Goal:**
  - On upload completion of a ticketed blob, classify it by magic.
    - **Pack:**
      1. Prefetch `delta_base_hashes` (`pack.rs:715`).
      2. Check each base is in (this pack's raw entries) ∪ (repo membership, verified). If not: retryable
         `unavailable` ("base not yet visible") while the ticket is younger than the relay-lag bound (membership is
         eventually consistent, D34), then a **uniform** `failed_precondition` "delta base not available in this
         repository". Neither response depends on whether the object exists anywhere else.
      3. Decode through `DeltaBaseSource` backed by the repo index plus BlobStore range reads. Bases in other packs are resolved by reading the entry and recursively resolving its chain, with a **chain-depth cap**.
      4. Stage index rows.
    - **MKPL node** (`transfer::decode_packlist`, `transfer.rs:130`): every listed pack is a member or ticketed in the same advance.
  - In `pre_receive` for `AdvanceRefs`, run `verify_push(new tips, History, source=repo index ∪ staged, known=verified-in-repo)`.
  - On success, one ref-shard batch: head/packmap, local membership additions, the pack's `verified` state, and relay
    outbox rows that flip the index rows to `verified` in the repo index shards.
  - `AlreadyPresent` answers use membership only (M1 already enforces this, re-assert it here).
  - Native runs verification inline, bounded by limits advertised in GetServerInfo.
- **PRD:** §6.5, §6.2 (MKPL tickets), §5.4 step 5, D3, D15.
- **Files:** `mkit-server/src/indexed/{mod.rs, classify.rs, ingest.rs, resolve.rs, verify.rs}`, `mkit-server/src/pipeline.rs` (pre_receive slot).
- **Tests:**
  - An in-process native test covers:
    - a good push
    - a forged signature is rejected, refs unmoved
    - an open closure is rejected
    - an MKPL listing a foreign pack is rejected
  - **Thin-delta cross-repo test:** repo B pushes a delta against a blob that exists only in repo A. The rejection is byte-identical to the one for a base that exists nowhere.
- **Size:** L (~1400).
- **Risks:**
  - Memory: `PackEntries` needs the whole pack. Native is fine for the existing 4 GiB cap only with mmap or a temp file. Use the FS BlobStore path with `memmap2` or a bounded pack size.
  - Deep delta chains are a CPU cost.

### WP-4.8a: mkit-core: windowed, streaming pack reader
- **Depends on:** WP-4.1 (ruzstd path), WP-4.2.
- **Goal:** a `PackEntries`-over-windows reader for packs that don't fit in memory: incremental BLAKE3 trailer check,
  an entry cursor that can be serialized (checkpoint/resume), bounded zstd decode window (ruzstd on wasm), and a
  `WindowSource` trait that fetches large byte ranges (so a Workers caller spends one subrequest per window, not per
  entry). Peak memory = window + max entry + zstd window. Byte-identical results to `PackEntries::new`.
- **Files:** `mkit-core/src/pack/window.rs` (new), tests and a bench.
- **Tests:** differential vs `PackEntries` over goldens and a proptest corpus; resume from every checkpoint;
  decompression-bomb caps; peak-memory assertion.
- **Size:** M (~800).

### WP-4.8: Worker: async verification as checkpointed alarm slices (`pending_verification`)
- **Depends on:** WP-4.7, WP-4.6, WP-4.8a.
- **Goal:**
  - Upload completion enqueues a `verify(pack)` timer in the ticket's **ref-shard DO** (WP-1.24).
  - Each alarm slice reads the pack from R2 in large Range windows (e.g. 16 MiB) through WP-4.8a, decodes with ruzstd,
    and emits index rows via the relay in batches; the entry cursor and running hashes are checkpointed in the ref
    shard (`vc/` layout) so a CPU-limit restart or alarm retry resumes idempotently.
  - Completion marks the pack `verified`, or `rejected` with a reason on the ticket.
  - `AdvanceRefs` on a pending pack → `unavailable` + `PendingVerification{retry_after}`, **never stored** in the
    replay ledger.
  - Closure and signature verification run at advance time over the verified index, or as a further slice if large.
  - The indexed-mode max pack size is advertised in `GetServerInfo`; `limits.cpu_ms` raised on staging.
- **Files:** `mkit-server-worker/src/indexed/{job.rs, window_source.rs}`, `mkit-server/src/indexed/checkpoint.rs`.
- **Tests:** a `wrangler dev` push larger than one window: AdvanceRefs polls → committed; an injected crash mid-pack
  resumes from the checkpoint; a rejected pack gives a permanent error; staging run with a large pack.
- **Size:** L (~1200).
- **Human action:** raise `limits.cpu_ms` in the staging wrangler config.

### WP-4.9: Client: `PendingVerification` polling
- **Depends on:** WP-4.4, M1:client AdvanceRefs-with-tickets.
- **Goal:**
  - Add a `TransportError::PendingVerification{retry_after}` mapping.
  - The CLI push loop polls `AdvanceRefs` until the ticket expires, honouring `retry_after`. It reuses the nonce within 300 s and re-signs afterwards.
  - Progress output ("waiting for server verification").
  - Not part of the generic retry ladder.
- **Files:** `mkit-core/src/protocol.rs`, `mkit-transport-connect/src/error.rs`, `mkit-cli/src/remote_dispatch/{mod.rs, packmap.rs}` (the `advance_packmap` loop, `packmap.rs:367`).
- **Tests:** A memory-transport fake returning N pending results then committed. The expiry path. The re-sign boundary at 300 s with an injected clock.
- **Size:** M (~500).

### WP-4.10: Server: D32 extraction into the global object CAS, ContentIndex holds and holders
- **Depends on:** WP-4.7, WP-4.10a.
- **Goal:**
  - At verification, extract per **D32**: every plain blob ≥ 64 KiB (configurable) and every `ChunkedBlob`,
    **reassembled once by streaming** its chunks (from this pack or repo membership) into one object keyed by its
    manifest id. Objects go to a second `BlobStore` instance with keyspace `objects` (M0-02 R-07) through a
    **caller-verified object sink** (the object id isn't BLAKE3 of the served bytes; the sink trusts ids proven by
    verified pack entries and the manifest's chunk list).
  - Dedup is by whole file: put-if-absent; on R2 a same-key 429 (1 write/s/key) is treated as "HEAD, then verify"
    rather than an error.
  - A ContentIndex **hold** is recorded before the ref-shard apply (§5.3); holders gain `(namespace, repo)` via the
    relay after apply; the index row gets `extracted = true`. **The hold is released only by the relay step that
    records the holder row, in the same ContentIndex batch (R-75)**, never on apply and never on a timer while the
    holder row is still in flight; a hold outlives a lagging relay (its expiry only covers a crash between hold and
    apply, and must exceed `MAX_APPLY_WINDOW` plus the relay-lag bound).
  - `new_to_store` in `Committed` is refined per object (reported only in outcomes).
- **Files:** `mkit-server/src/indexed/extract.rs`, `mkit-server/src/store/blob.rs` (caller-verified sink).
- **Tests:** two repos push the same large file → one CAS object, two holders, `new_to_store` 0 for the second; a
  ChunkedBlob round-trips byte-identically from the reassembled object; a crash between hold and apply leaves only
  the hold (expires with GC grace in M5); with the relay delayed, the hold stays until the holder row lands (no
  instant with neither); peak memory during reassembly ≤ one chunk + window.
- **Size:** L (~1200).

### WP-4.10a: ContentIndex shards: Workers DOs and holder sub-sharding
- **Depends on:** WP-4.4, M1 (WP-1.8 `ContentIndexShard` class, WP-1.23 relay).
- **Goal:** wire `Partition::ContentShard` (fixed fan-out 4096 by object-id prefix) to `ContentIndexShard` DOs; move
  holder rows into sub-shards keyed by (object, hash(holder)) with a holder **count** kept on the object's primary
  shard (D34 guardrail, R-34), updated in the safe direction (increment before adding a row, decrement after removing
  one) plus a periodic reconcile; `collectable` reads the count. Same layout on native SQLite and memory.
- **Files:** `mkit-server/src/store/content_index.rs`, `mkit-server-worker/src/content_index.rs`.
- **Tests:** a load case with 100k holders of one object stays within per-shard size bounds and spreads over
  sub-shards; crash at every step never under-counts; storage suite on all backends.
- **Size:** M (~900).

### WP-4.11: Spec: HTTP serving and proofs (#1088)
- **Depends on:** WP-4.4, M2:signed-URL token format (reference only).
- **Goal:** A normative spec, either a new SPEC-HTTP-OBJECTS or a SPEC-SERVER section, covering:
  - URL grammar: `/<ns>/<repo>/-/objects/<id>` and `/<ns>/<repo>/-/refs/<ref>/-/<path>`
  - reachability in the caller's view
  - **404 before 451** ordering
  - Range and ETag semantics (ETag = id)
  - `Cache-Control` rules: `immutable, public` / `private` / `no-cache` on ref paths
  - redirect vs direct serve
  - **proof delivery format** for `?proof=1` and Range disclosure (adopted default: decided in this spec WP), including
    the **multi-chunk proof bundle** encoding for ranges that cross chunk boundaries
  - signed-URL token placement
  - admission on reads (a 402 is an ordinary HTTP response)
  - CORS
  - Golden vectors for proof responses.
- **Files:** `docs/specs/SPEC-HTTP-OBJECTS.md` (or a SPEC-SERVER section), `rust/tests/golden/http-objects/*`.
- **Size:** M (~600).
- **Human action:** spec approval.

### WP-4.12: Server core: HTTP object serving (`http-objects` feature, runtime-agnostic)
- **Depends on:** WP-4.11, WP-4.7, WP-4.10.
- **Goal:**
  - A runtime-agnostic `http` handler: parse the `/-/` URLs (ref names may contain `/`), resolve ref → commit → tree path (the ref from its ref shard, or the published-view snapshot for unsigned readers, WP-1.21) with the repo index, then:
    - reachability check (Q-M4-4)
    - Authorizer
    - optional Admission (WP-4.13)
    - serve extracted objects (≥ 64 KiB blobs and reassembled chunked files, D32) by a direct blob-store read with native
      Range; reconstruct small objects from their pack entry
  - Range (single range; multi-range returns 200 or 416 per spec), ETag and `If-None-Match`.
  - Unreachable ids return 404. The 451 branch is a hook that M5 fills; M4 always serves 404 or 200.
  - Public repos only here; private in WP-4.15.
- **Files:** `mkit-server/src/http_objects/{mod.rs, route.rs, resolve.rs, range.rs, reach.rs}`.
- **Tests:**
  - Unit tests on URL parsing, including refs with `/`.
  - Range edge cases.
  - An unreachable (orphaned by force-push) object returns 404.
- **Size:** L (~1300).
- **Risks:** Reachability cost per request (Q-M4-4).

### WP-4.13: Admission on HTTP reads (paid downloads)
- **Depends on:** WP-4.12, WP-3.3.
- **Goal:**
  - Call `Admission` for GETs when configured (anonymous allowed, per §6.3 ordering).
  - Emit a plain HTTP 402 with the passthrough headers and `no-store`.
  - Receipt headers come with `private`.
  - Emit the `ReadServed` outcome defined by WP-3.3 (adopted default: paid reads produce an outcome).
- **Files:** `mkit-server/src/http_objects/admission.rs`.
- **Size:** S (~300).
- **Note:** This is the only M4 WP that depends on M3. Keeping it separate means M4 isn't blocked by M3.

### WP-4.14: Proofs: `?proof=1` inclusion and byte-range disclosure; mkit-wasm round trip
- **Depends on:** WP-4.12, WP-4.3, WP-4.11.
- **Goal:**
  - For ref/path URLs, build the disclosure bundle via `build_disclosure_from` (`Selector` per SPEC-DISCLOSURE) over the repo index.
  - For Range requests within one chunk, use a Bao slice bundle; a range crossing chunk boundaries gets a
    **multi-chunk proof bundle** in the encoding WP-4.11 fixes (adopted default).
  - Deliver it in the format WP-4.11 fixes.
  - Object-by-id URLs take proofs only with commit context (per spec).
- **Files:** `mkit-server/src/http_objects/proof.rs`, `rust/crates/mkit-wasm/tests/` (node or wasm-bindgen-test verifying server-produced bundles with `verify_disclosure` / `blob_bao_verify_slice`), goldens.
- **Tests:**
  - The M4/M5 exit criterion "serving and proof round trips verify with `mkit-wasm`".
  - A tampered bundle is rejected.
  - A cross-chunk range gets a multi-chunk bundle that `mkit-wasm` verifies.
- **Size:** M (~800).

### WP-4.15: Private serving via M2 signed URLs and read auth
- **Depends on:**
  - WP-4.12
  - M2:signed reads/visibility/read grants
  - M2:IssueObjectUrl + token verifier
- **Goal:**
  - Private repos: a request needs a valid signed URL token (or signed-read headers for API clients).
  - `Cache-Control: private`, and never `public`/`immutable` on a private response.
  - A visibility check at request time.
  - Wire the Workers/native adapters (WP-4.16) to not populate shared caches for private responses.
- **Files:** `mkit-server/src/http_objects/auth.rs`.
- **Tests:** Token expiry, wrong repo, wrong object, and revoked grant (epoch) cases. Cache headers.
- **Size:** M (~500).

### WP-4.16: Adapters: mount HTTP serving (axum and Workers fetch), R2 Range reads, CORS
- **Depends on:** WP-4.12 (WP-4.15 and WP-4.13 are optional follow-ons).
- **Goal:**
  - Native: an axum route mount in the `mkit-server` binary; FS/S3 range reads.
  - Workers: a fetch route in `mkit-server-worker`, R2 `get` with range, streaming response bodies.
  - CORS for GET/HEAD with Range and ETag exposed.
- **Files:** `mkit-server-native/src/http_objects.rs`, `mkit-server-worker/src/http_objects.rs`, `apps/vcs-worker/src/lib.rs`.
- **Size:** M (~600).

### WP-4.17: Pre-receive policy hooks: allowed signers per ref, fast-forward-only grants
- **Depends on:** WP-4.7, WP-4.4, M2 (WP-2.7 grant ref scopes).
- **Goal:** a `RefPolicy` trait in `pre_receive`: (a) allowed signer keys per ref pattern, checked against verified
  commit signers; (b) M2 `update`-without-`force` grants enforced as **fast-forward-only** by an ancestry walk over the
  repo index (the opaque server rejects such grants, per M2). Attestation-gated refs are **out of this epic** (D33);
  implementers can still gate refs through the generic `pre_receive` hook.
- **Files:** `mkit-server/src/policy/{mod.rs, signers.rs, ff.rs}`.
- **Tests:** an unauthorized signer is rejected; a non-ff update under an ff-only grant is rejected; an ff update
  passes.
- **Size:** M (~700).

### WP-4.18: Conformance: the indexed-mode and serving wire suite (M4 exit)
- **Depends on:** WP-4.8, WP-4.9, WP-4.10, WP-4.14, WP-4.15, WP-4.16, WP-4.17.
- **Goal:** Black-box cases on native, `wrangler dev` and staging:
  - verification before refs move
  - forged signature rejected
  - **thin-delta cross-repo rejection that reveals nothing** (a byte-identical error for a base in another repo vs a base that exists nowhere)
  - MKPL membership rule
  - `PendingVerification` polling (Workers)
  - reachability-only serving (404 for unreachable ids)
  - Range/ETag/caching headers
  - private serving
  - proof round trip via `mkit-wasm` (node harness), including a cross-chunk range
  - D32 extraction and whole-file dedup across repos; a chunked file served with Range from the reassembled object
  - windowed verification of a pack larger than one window on **deployed staging**
- **Files:** `mkit-server-conformance/src/wire/{indexed.rs, http_objects.rs}`, CI workflow.
- **Size:** L (~1200).
- **Human action:** Enable indexed mode on staging, raise the CPU limits, and set up R2 lifecycle rules (none should delete CAS objects).

---

## D. M5: Track Content, lifecycle, quarantine, takedown, receipts, admin

Entry condition:
- M4 is merged: ContentIndex holders (WP-4.10) and the index and serving (WP-4.12).
- **M2 signed reads are merged.** PRD §8: without them, writers loop on `PackmapConflict` under quarantine.

### WP-5.1a: Spec: leases, lifecycle events, server GC, published view and quarantine (#1091 part 1)
- **Depends on:** WP-3.6, WP-4.4.
- **Goal:** SPEC-SERVER sections covering:
  - per-ref leases, the repo default, and opaque repo-level only
  - the state machine active → grace → suspended → deleted, with events on every transition
  - server GC:
    - roots (live refs, published pointers, open tickets, pending advances)
    - grace and pins (open tickets, recent `AlreadyPresent`, pending advances)
    - opaque pack-granularity liveness via packmap chains
    - ContentIndex zero holders and zero holds
    - the fail-closed rule mirroring SPEC-GC
    - the **mark → wait → re-check → delete** protocol of WP-5.3a/5.3b (R-64), with `MAX_APPLY_WINDOW` and the relay
      watermark as named parameters, and the rule that every write batch carries a `NotAfter` commit deadline
  - takedown completion waits for the relay watermark (R-75)
  - the published pointer (head, packmap) per branch: the "last advance *k* such that all ≤ *k* cleared" rule
  - caller-view semantics for ListRefs, ReadRef, PackExists, DownloadPack (including the D36 `X-Mkit-Ref` path) and
    HTTP
  - `ContentInspector` sync/async and the fail-closed/publish setting
  - Proto for the lease and lifecycle event messages (additive), if the events are delivered through the outbox or hooks.
- **Files:** `docs/specs/SPEC-SERVER.md`, protos, goldens.
- **Size:** M (~800).
- **Human action:** Spec approval. Planner defaults (reviewable): no mkit default lease — the implementer's
  `LeasePolicy` must set grace and suspension periods explicitly; GC grace 7 days.
- **D34:** leases and lifecycle state live in the ref shard; the published pointer is stored in the ref shard
  (WP-5.4); quarantine state and tombstone views live in repo index shards.

### WP-5.1b: Spec: takedown, `RedactionNotice`, preservation store, admin API and audit log (#1091 part 2)
- **Depends on:** WP-5.1a.
- **Goal:** The normative text for:
  - takedown levels
  - the whole-object unit
  - chunk removal only when unreferenced by any live object
  - tombstones and reinstatement
  - the preservation store access rule (admin API only) and retention
  - the delta-safe pack rewrite and packlist chain rebuild with server-authored packmap CAS paired with the unchanged head
  - a `RedactionNotice` Connect detail plus the signed notice format: a DSSE-over-JSON predicate with the deployment key (object id, reason code, date, origin, key id, old→new pack map)
  - HTTP 451
  - the ReadRef/ListRefs notice attachment for branches whose closure contains a tombstone
  - the admin API:
    - a signed envelope with its **own domain** (e.g. `mkit-admin:v1`), not `mkit-write:v2`
    - replay protection
    - operations
    - audit-log format
- **Files:** `docs/specs/SPEC-SERVER.md`, `proto/mkit/transport/v1/*` (the `RedactionNotice` detail), `proto/mkit/server/admin/v1/admin.proto`, goldens.
- **Size:** L (~1000).
- **Adopted defaults:** preservation store = a separate restricted R2 bucket/prefix or FS directory, reachable only
  through the admin API (Q-M5-1); distinct keys per role — receipt+notice signing, admin, hook channel, URL tokens
  (plus M1's ticket/receipt MAC key) — each with a key id and rotation via a published key list (Q-M5-2, PRD Q3);
  admin model = a single Ed25519 key per deployment with key-list rotation, threshold deferred (planner default for
  PRD Q4); preservation retention has no mkit default and must be configured when takedown is enabled (planner
  default); reinstatement re-adds the object via server-side pack rewrite (Q-M5-5).
- **Human action:** spec approval.

### WP-5.1c: Spec: storage receipts predicate (#1092)
- **Depends on:** WP-5.1a (lease fields).
- **Goal:**
  - The predicate type URI, e.g. `https://github.com/officialunofficial/mkit/spec/predicate/storage-receipt/v1`, following the SPEC-ATTESTATIONS §6.4 convention.
  - Fields: repo, ref, commit and pack ids; logical and stored bytes; lease end and state; `issued_at`; origin; key id; `external_ref` with a no-secrets rule.
  - The subject: commit subjects in indexed mode; in opaque mode receipts cover **refs + pack ids only** (adopted
    default, Q-M5-4).
  - The well-known key-list URL and format (adopted default: published key list with key ids; PRD Q3).
  - An additive proto field on the `AdvanceRefs` response, plus fetch-later.
  - Golden DSSE vectors.
- **Files:** `docs/specs/SPEC-SERVER.md` (or SPEC-RECEIPTS), `docs/specs/SPEC-ATTESTATIONS.md` §6.4 list, protos, `rust/tests/golden/receipts/*`.
- **Size:** M (~500).
- **Human action:** spec approval.

### WP-5.2: Leases and lifecycle states: model, enforcement, events
- **Depends on:**
  - WP-5.1a
  - WP-3.3 (outbox reused for events)
  - WP-3.5 (scheduler)
- **Goal:**
  - A per-ref lease table (repo default; opaque = repo-level only).
  - Enforcement in the pipeline: grace blocks writes, suspended blocks reads.
  - A `LeasePolicy` hook: the implementer sets and extends leases; mkit enforces them.
  - Transitions are driven by the scheduler (DO alarm / native task).
  - A lifecycle event for every transition goes through the outbox (same delivery guarantees).
  - Lease expiry into `deleted` deletes the **ref** only. Objects wait for GC.
  - `GetServerInfo` advertises lease support.
- **Files:** `mkit-server/src/lifecycle/{lease.rs, state.rs, events.rs}`, both adapters' schema migrations.
- **Tests:**
  - Storage and wire tests for each transition.
  - Renewal in grace restores active.
  - A read is blocked in suspended.
  - An event is emitted exactly once per transition (idempotent delivery).
- **Size:** L (~1200).

### WP-5.3a: GC mark: roots, pins, grace, GC-pending, apply precondition
- **Depends on:** WP-5.2, WP-4.10, M1:tickets.
- **Goal:**
  - Runtime-agnostic mark over D34 shards: roots and pins come from ref shards (heads, published pointers, open
    tickets, pending advances); membership from repo index shards; runs as timer slices (WP-1.24).
    - roots are live refs, published pointers, open tickets and pending advances
    - pins are open tickets, recent `AlreadyPresent` answers (recorded with a timestamp), pending advances, and holds
  - Reachability:
    - indexed mode: the closure over the repo index via `children`
    - opaque mode: walk every root's packmap chain (`transfer::decode_packlist`) → live packs and nodes
  - Mark candidates `gc_pending` with `pending_since` (on the object's ContentIndex row and the repo's membership rows).
  - **No cross-shard apply precondition (R-64).** The earlier "apply rejects Mutations that reference a `gc_pending`
    pack (already declared in M0)" was wrong: M0 declares no such precondition, and GC state lives in index shards
    and ContentIndex, which a single ref-shard batch can't read. Safety comes instead from:
    - every write batch carrying `NotAfter(deadline ≤ plan_time + MAX_APPLY_WINDOW)` (M0-02a/M0-05a, P-21), so a write
      planned before the mark either commits within `MAX_APPLY_WINDOW` or never;
    - planners that read a `gc_pending` membership row **unmark** it first (a guarded batch on that index or
      ContentIndex partition) before relying on the pack, and treat `deleting` as absent (retryable `unavailable`);
    - WP-5.3b's wait and re-check before deleting.
  - **Fail closed:** any unreadable root aborts the run (mirrors SPEC-GC).
- **Files:** `mkit-server/src/gc/{roots.rs, mark.rs, pins.rs}`.
- **Tests:**
  - A lease expiry never removes a reachable object.
  - GC never races an open ticket: a ticket opened during mark pins its pack.
  - A write planned just before the mark and delayed past `MAX_APPLY_WINDOW` fails its `NotAfter` and re-plans (sees
    `gc_pending`, unmarks); a write planned just before the mark and committed in time is found by the re-check.
  - A truncated walk aborts.
- **Size:** L (~1100).

### WP-5.3b: GC sweep: per-repo membership drop, ContentIndex holder removal, zero-holder deletion, adapters
- **Depends on:** WP-5.3a.
- **Goal:**
  - **Wait** until `now > mark + MAX_APPLY_WINDOW + margin` **and** the namespace relay watermark (WP-1.23, P-23)
    has passed that time, so every write that could have referenced a candidate has committed and been relayed, or
    has failed its `NotAfter` deadline.
  - **Re-check** roots from strongly consistent sources: heads, published pointers, open tickets and pending advances
    read from the ref shards themselves; the shard list comes from the ref index read *after* the watermark plus the
    coordinator's active-shard table (never the eventually consistent ref index alone); ContentIndex holds and holder
    counts are read from the object's partition. A candidate re-referenced or unmarked since the mark is kept.
  - Remove membership, index rows and the ContentIndex holder for `(ns, repo)`.
  - A global CAS object or pack is deleted only when the holder **count** (WP-4.10a) is zero and there are zero holds:
    one ContentIndex per-object batch guarded by `Equals` on the `gc_pending` mark and the last-change key (any hold,
    holder or unmark since the mark fails it) sets `deleting`, then `BlobStore::delete` (exists since M0-02a), then the
    row is removed.
  - Native: a background task. Workers: a namespace-DO alarm for the per-namespace phase, and a ContentIndex-shard DO alarm for global deletes.
  - Metrics.
- **Files:** `mkit-server/src/gc/sweep.rs`, `mkit-server-native/src/gc.rs`, `mkit-server-worker/src/gc.rs`.
- **Tests:** A cross-repo shared object survives until the last holder is gone. A hold blocks deletion. A crash mid-sweep is safe on re-run. With the relay delayed, the sweep waits (watermark) instead of deleting. A ref created during the wait (visible only in its ref shard and the coordinator table) keeps its packs.
- **Size:** L (~1000).
- **Risks:** R2 has no put-if-absent-then-delete atomicity. The order must be: ContentIndex marks the object `deleting`, then the R2 delete, then the row removed; a re-upload during `deleting` recreates it.

### WP-5.4: Published view: (head, packmap) pointer, caller view on every read path
- **Depends on:**
  - WP-5.2 (which carries WP-5.1a and the M2 exit: signed reads for writer detection)
  - the published pointer storage is added here (§H-A13, R-24), not in M1
- **Goal:**
  - Add the **published pointer storage** in the ref shard (moved here from M0/M1, R-24): a per-branch advance
    sequence, clearance state and the (head, packmap) pointer; until M5 it equals the live ref.
  - Maintain a per-branch advance sequence and clearance state.
  - The published pointer = the (head, packmap) of the last advance *k* such that every advance ≤ *k* has cleared.
  - ListRefs, ReadRef, PackExists, DownloadPack and HTTP serving answer from the **caller's view**: writers (owner or write grant, via signed read) see the real refs; the public and read-only grantees see the published view.
  - **The D36 `X-Mkit-Ref` path too (R-75, R-77):** for a non-writer, the header resolves only against membership
    added by advances ≤ the published pointer (cleared advances); membership added by a pending (quarantined) advance
    is invisible through it, exactly as through the index.
  - Pending packs and blobs are never served to non-writers.
  - Without any inspector configured, published == real (no behaviour change).
- **Files:** `mkit-server/src/view.rs`, touches to `pipeline.rs` read handlers and `http_objects/reach.rs`, the
  published-view snapshot writer (WP-1.21) switched to the published pointer.
- **Tests:** A non-writer never sees a pending advance over the transport or HTTP, including `PackExists`/`DownloadPack` with `X-Mkit-Ref` naming the quarantined ref. A writer with a signed read sees it. A writer without a signed read gets the published view (documented).
- **Size:** M (~800).

### WP-5.5: `ContentInspector`: sync fast checks, async quarantine, clearance, hit → takedown
- **Depends on:**
  - WP-5.4
  - WP-3.7 (remote `inspect`)
  - WP-5.6 (hit → takedown; stub the call until WP-5.6 lands)
- **Goal:**
  - A `ContentInspector` trait: `inspect_sync(blob_meta, bytes)` in `pre_receive` (blocklist and hash lists reject the push) and `enqueue_async`.
  - A quarantine queue per advance. Clearance advances the published pointer. A hit triggers a content takedown.
  - A per-inspector `on_unavailable: fail_closed | publish` (D18).
  - Indexed mode only.
  - A remote `inspect` via `hooks.v1`.
  - mkit ships no scanners; tests use a stub.
- **Files:** `mkit-server/src/inspect/{mod.rs, sync.rs, quarantine.rs}`, scheduler integration.
- **Tests:** An exit criterion: quarantined content never reaches a principal without write access, over any path. Fail-closed vs publish behaviour when the inspector is down.
- **Size:** L (~1100).

### WP-5.6: Takedown core: tombstones, blocklist, preservation store, per-repo views, suspension
- **Depends on:** WP-5.1b, WP-4.10, WP-5.2, WP-5.10 (R-82: the CachePurger lands first; this WP invokes it).
- **Goal:**
  - A `Takedown{level: content|repo|namespace}`.
  - Content level (indexed only):
    - resolve the **whole object** (blob id, or a ChunkedBlob manifest id)
    - find all holders in ContentIndex
    - write per-repo tombstone views in each holder's namespace
    - add the id to the **global blocklist**, so later uploads containing it are rejected at ingestion in any namespace
    - move the bytes to the **`PreservationStore`** (adopted default): a separate restricted R2 bucket binding on
      Workers, a separate S3 prefix or FS directory natively; readable only through the admin API; no public read path
    - write tombstone views into the holders' repo index shards (D34) via the relay
    - remove chunks only when no other live object references them (holders per chunk)
  - **Lag holes closed (R-75):**
    - holders still in flight in the relay when the takedown runs are caught by the relay itself: WP-1.23's
      pre-delivery hook checks the global blocklist when it records a holder row and, for a blocked object, writes
      the tombstone view for that repo and enqueues its per-repo takedown steps (idempotent);
    - a content takedown reports **completion** only after the namespace relay watermark (P-23) of every affected
      namespace has passed the takedown time, so no holder recorded before the blocklist entry is missed.
  - Repo and namespace takedown and **suspension** reuse the lease states (WP-5.2).
  - Invoke `CachePurger` (WP-5.10) with the takedown trigger.
- **Files:** `mkit-server/src/takedown/{mod.rs, tombstone.rs, blocklist.rs, preserve.rs}`, adapter preservation-store impls.
- **Tests:** An exit criterion: a takedown hits every repo holding the content, a re-upload is rejected, and the preserved bytes are reachable only via admin. With the relay delayed, a push that recorded a holder just before the takedown is tombstoned when its holder row lands, and the takedown isn't reported complete before that.
- **Size:** L (~1300).
- **Human action:** Create the preservation R2 bucket (restricted) on staging.
- **Decided:** Q-M5-1 (preservation store), Q-M5-5 (reinstatement via server-side rewrite, WP-5.14).

### WP-5.7a: mkit-core: delta-safe pack rewrite primitive
- **Depends on:** WP-4.2 (`DeltaBaseSource` / `decode_entries_with`).
- **Goal:**
  - A pure function `pack::rewrite_excluding(pack:&[u8], excluded:&HashSet<Hash>, bases:&mut impl DeltaBaseSource) -> Rewritten{bytes, removed:Vec<Hash>, rawified:Vec<Hash>}`.
  - It drops entries whose id ∈ excluded, and re-emits as **raw** every delta entry whose base chain passes through an excluded id, whether in-pack or external.
  - The output keeps SPEC-PACKFILE §4 ordering and is a valid v2 pack (the writer may zstd raw entries on native; on wasm raw stays raw).
- **Files:** `mkit-core/src/pack.rs` (or a new `pack/rewrite.rs`), plus tests.
- **Tests:**
  - Property tests: the rewritten pack decodes, and the rewritten object set equals original minus excluded.
  - An exit criterion: a pack whose delta chain runs through a taken-down object is rewritten and still decodes.
- **Size:** M (~700).

### WP-5.7b: Server: rewrite orchestration, packlist chain rebuild, packmap CAS
- **Depends on:** WP-5.7a, WP-5.6.
- **Goal:**
  - For each holder repo, find the affected packs (index: entries = X, or delta chains through X) and rewrite them.
  - Rebuild every affected packlist chain: new MKPL nodes via `transfer::encode_packlist`, preserving apply order.
  - A server-authored `AdvanceRefs`-equivalent Mutation that CASes `refs/mkit/packmap/<branch>` paired with the **unchanged** head.
  - Record old→new pack ids in the notice. The old packs become GC candidates.
  - Handle concurrent client pushes: the CAS loses → recompute.
- **Files:** `mkit-server/src/takedown/rewrite.rs`.
- **Tests:** An exit criterion: a client whose packmap chain predates the rewrite fetches cleanly afterwards (a CLI e2e using the real `remote_dispatch::fetch_all`, `mod.rs:1333`), unless the tip's closure contains the tombstone.
- **Size:** L (~1300).
- **Risks:**
  - Long rewrites on Workers (CPU and memory) need the same windowed machinery as WP-4.8.
  - Client caches of applied packs (`remote_dispatch/applied_packs.rs`) must stay correct with the new pack ids. They're content-addressed, so they should.

### WP-5.8: Storage receipts: `ReceiptSigner`, deployment key, well-known URL, AdvanceRefs field
- **Depends on:** WP-5.1c, WP-5.2 (lease fields), M1:GetServerInfo.
- **Goal:**
  - A `ReceiptSigner` trait. The default Ed25519 DSSE signer builds on `mkit_attest::statement::encode` (`statement.rs:89`) and the `envelope` module.
  - A receipt is signed on every committed advance and every lease change.
  - Receipt+notice key loading (a dedicated role key, not the hook, admin or URL-token key): native from a key file
    or mkit-keystore; Workers from a secret. The published key list carries key ids for rotation.
  - Opaque mode: receipts cover refs + pack ids only (adopted default); indexed mode may add commit subjects.
  - `GetServerInfo` `receipt_public_key` and key id.
  - The well-known URL route on both adapters.
  - Receipts are returned in the additive `AdvanceRefs` response field and are fetchable later (via a stored receipt keyed by the reservation or advance).
  - `external_ref` comes from the implementer's `OutcomeSink`/`Admission`, validated for size.
- **Files:** `mkit-server/src/receipts/{mod.rs, predicate.rs, signer.rs}` (feature `receipts`), adapters' key loading and route.
- **Tests:** The golden vectors from WP-5.1c. The receipt verifies with `mkit_attest::verify::verify_envelope` and with `mkit-wasm` `attest_verify` (`mkit-wasm/src/attest.rs:223`).
- **Size:** L (~1000).
- **Human action:** Generate the staging deployment key and install it as a Wrangler secret. Publish the key.

### WP-5.9a: Server: `RedactionNotice` detail on fetch and push, HTTP 451, notice signing
- **Depends on:** WP-5.7b, WP-5.8 (signing key).
- **Goal:**
  - A signed notice (deployment key, the WP-5.1b format).
  - ReadRef/ListRefs attach the notice for branches whose closure contains a tombstone. They're computed at takedown time and stored as a per-branch flag, **not** per read.
  - DownloadPack/PackExists answer consistently.
  - A push whose delta base is tombstoned fails with the `RedactionNotice` detail. This check sits **after** the repo-isolation check, so it's only visible for bases in this repo.
  - HTTP: **404 before 451**. The 451 is only for tombstoned ids visible in the caller's view (fills the WP-4.12 hook).
- **Files:** `mkit-server/src/takedown/notice.rs`, touches to the read handlers and `http_objects`.
- **Tests:**
  - A tombstoned id not reachable in the caller's view returns 404, not 451.
  - The notice verifies.
- **Size:** M (~800).

### WP-5.9b: Client: redaction-aware fetch and push re-plan
- **Depends on:** WP-5.9a.
- **Goal:**
  - A `TransportError::Redacted(notice)` / `DispatchError::Redacted` with a precise message: object id, reason, date, origin. Fetch and clone fail closed with it instead of `RemoteMissingObject`.
  - On push, a `RedactionNotice` triggers one re-plan that excludes the tombstoned ids as delta bases. Add an `excluded_bases` parameter to `transfer::plan_pack_with` (`transfer.rs:657`), or fall back to the self-contained plan (`mod.rs:798` path).
  - If the new tip's closure itself contains the tombstoned id, fail with the notice.
  - Optionally store the notice under `.mkit/` for audit (decide in the brief).
- **Files:** `mkit-core/src/{protocol.rs, transfer.rs}`, `mkit-transport-connect/src/error.rs`, `mkit-cli/src/remote_dispatch/{mod.rs, packmap.rs}`.
- **Size:** M (~700).

### WP-5.10: `CachePurger` hook and purge triggers
- **Depends on:** WP-5.2. (R-82: was also WP-5.6, but 5.6 invokes the purger; the order is now 5.10 → 5.6.)
- **Goal:**
  - A `CachePurger` trait. The implementer provides it (e.g. the Cloudflare purge API); mkit ships a no-op and a logging impl.
  - It's invoked on suspension, lease deletion and visibility change (this WP), and on takedown (wired by WP-5.6),
    with the affected URL set (object URLs plus ref paths, including the per-bucket snapshot keys of WP-1.21).
  - Delivery goes through the outbox (retry until acked).
- **Files:** `mkit-server/src/purge.rs`.
- **Size:** S (~350).

### WP-5.11a: Admin API framework: signed envelope, replay protection, audit log
- **Depends on:** WP-5.1b.
- **Goal:**
  - An `mkit.server.admin.v1` Connect service.
  - Requests are signed with the deployment admin Ed25519 key (a dedicated role key; single key with key-list rotation,
    threshold deferred) using a **distinct domain** (so a write envelope can't be replayed as an admin one).
  - A replay ledger with an admin scope.
  - An append-only **audit log**: who, what, when, request digest, result. It's stored in a deployment-global admin store: native SQLite; on Workers a dedicated admin DO.
  - Admin endpoints are off unless an admin key is configured.
- **Files:** `mkit-server/src/admin/{mod.rs, auth.rs, audit.rs}`, `mkit-server/generated/**`, adapter mounts.
- **Tests:** A replay is rejected. A write-domain envelope is rejected. Every call is audited, including failures.
- **Size:** L (~1000).
- **Decided:** PRD Q4 by planner default (single admin key per deployment, key-list rotation; reviewable).

### WP-5.11b: Admin operations and the `mkit-server admin` CLI
- **Depends on:**
  - WP-5.11a, WP-5.6, WP-5.2, WP-5.14
  - M2:ssh grant registration (if M2 used an RPC, the admin operation just wraps it)
- **Goal:** Operations:
  - takedown
  - reinstatement
  - suspension and unsuspension
  - blocklist add/remove
  - set or extend a lease
  - register ssh grants
  - read preserved bytes (the only path to the preservation store)
  - read the audit log

  Plus an `mkit-server admin …` subcommand in the D31 binary with admin-key signing.
- **Files:** `mkit-server/src/admin/ops.rs`, `mkit-server-native/src/bin/mkit-server/admin.rs`.
- **Size:** L (~1100).

### WP-5.12: Client: receipt storage (`.mkit/attestations/`), not pushed
- **Depends on:** WP-5.8.
- **Goal:**
  - On a committed push, store the returned DSSE receipt via `mkit_attest::store::save(layout, commit, bytes)` (`mkit-attest/src/store.rs:76`).
  - `mkit verify-attest` recognizes the receipt predicate given a trust-root entry for the server key.
  - Receipts are never pushed.
  - The user sees the key id and a pointer to the receipt.
- **Files:** `mkit-cli/src/remote_dispatch/mod.rs`, `mkit-cli/src/commands/verify_attest.rs`, `docs/CLI.md`.
- **Size:** S (~350).
- **Decided:** receipts are stored under `.mkit/attestations/` but are **not** object-GC roots (adopted default);
  amend SPEC-GC's roots table to exclude the storage-receipt predicate.

### WP-5.13: Conformance: the lifecycle wire suite (M5 exit)
- **Depends on:** WP-5.3b, WP-5.5, WP-5.7b, WP-5.9b, WP-5.10, WP-5.11b, WP-5.12.
- **Goal:** All M5 exit criteria as black-box cases on native, `wrangler dev` and staging:
  - a takedown hits every holder, a re-upload is rejected, preserved bytes are admin-only
  - fetch after a rewrite is clean, or fails with the notice when the tip closure contains the tombstone
  - a rewritten pack decodes
  - a lease expiry never removes a reachable object
  - GC never races an open ticket
  - quarantine never leaks to non-writers over any path, including `PackExists`/`DownloadPack` with the D36
    `X-Mkit-Ref` header naming a ref whose latest advance is quarantined
  - a takedown racing a delayed relay still tombstones the late holder, and GC waits on the relay watermark
  - receipts verify
  - admin replay protection and the audit trail
- **Files:** `mkit-server-conformance/src/wire/{lifecycle.rs, takedown.rs, receipts.rs, admin.rs}`.
- **Size:** L (~1400). It may split by area if it exceeds the budget.
- **Human action:** Staging preservation bucket, admin key and receipt key secrets.

### WP-5.14: Reinstatement
- **Depends on:** WP-5.6, WP-5.7b.
- **Goal:**
  - Reverse a tombstone: restore the bytes from the preservation store into global CAS (if extracted) and remove the blocklist entry. Keep the old pack ids retired; the rewrite is not undone.
  - Re-add the object for the pack protocol through a **server-side pack rewrite** (adopted default): append a
    single-object pack to each affected packlist chain and CAS the packmap paired with the unchanged head (the
    WP-5.7b machinery).
  - Audit it.
- **Files:** `mkit-server/src/takedown/reinstate.rs`.
- **Size:** M (~500).

---

## E–G. DAG, parallel sets, human actions

Superseded by `00-plan.md` §3 (global DAG, waves and critical paths computed from `registry.json`) and §6 (human-action
checklist). Not repeated here to avoid drift.

---

## H. Interface assumptions: reconciliation status

| # | Assumption (short) | Status after consolidation |
|---|---|---|
| A1 | `Operation`, `RepoId`, principals, §5.4 stage traits with defaults | Provided: M0-01/M0-05 (Authorizer, Admission, PreReceive, ReceiptSigner, OutcomeSink). Moved: `ContentInspector` (call shape WP-3.7, impl WP-5.5), `LeasePolicy` (WP-5.2), each added as a `HookSet` associated type |
| A2 | Replay state model, lookup after auth, before authorizer/admission | Provided: M0-02a, M0-05a/05b. D34: records live in the op's ref shard |
| A3 | Atomic `apply` with preconditions; extensible row kinds | Provided in key-level form: M0-02 declarative `Batch` + key-layout registry; planners in M0-05 — R-16..R-18 |
| A4 | Error mapping with HTTP status, extra headers and details | Provided: M0-01 `ServerError` shaping, M0-06 Connect mapping — R-03 |
| A5 | `BlobStore` with Range, put-if-absent; a global CAS keyspace | Provided: M0-02 keyspaces (second store instance, keyspace `objects`), `delete`, streaming bodies. Moved: caller-verified object sink → WP-4.10 — R-06, R-07, R-25 |
| A6 | `ContentIndex` holders/holds/blocklist; Workers impl | Provided: M0-02 layer over any `NamespaceStore` (shard partitions). Moved: Workers DO wiring + holder sub-sharding → WP-4.10a — R-34 |
| A7 | Clock/Spawner; native background tasks | Provided: M0-01, M0-10 `TokioSpawner`; timers → WP-1.24 |
| A8 | CORS extension lists; redaction facility | Provided: M0-10 `RouterOptions` extra allow/expose headers, M0-01 `SENSITIVE_HEADERS` — R-15 |
| A9 | Conformance harness native, `wrangler dev`, staging | Provided: M0-03/M0-07 (M0), WP-1.20 (staging from M1; DO bindings are always local in `wrangler dev`) |
| A10 | DO alarm scheduler multiplexed over due work | Moved: WP-1.24 (`(due_at, kind, ref)` timers, alarm = min due_at, idempotent handlers); M3–M5 register kinds |
| A11 | `BeginUpload`/tickets/`AdvanceRefs` ticket ids; client path; `part:` | Provided by M1 (WP-1.2, 1.3, 1.9–1.11, 1.17, 1.18); `BeginUpload` names its target ref (D34) |
| A12 | `GetServerInfo` carries every §6.1 field | Provided: WP-1.2/1.6 (plus `index_fanout`, ListRefs page bounds, indexed max pack size) |
| A13 | Published pointer per branch stored from M1 | **Moved:** WP-5.4 adds it in the ref shard (equal to live until M5); M1's snapshot (WP-1.21) serves the live refs — R-24 |
| A14 | Membership per repo, effective at `AdvanceRefs` | Provided: WP-1.10 (local in the ref shard) + WP-1.23 (repo index shards, eventually consistent) |
| A15 | Signed reads, writer/reader distinction, visibility, read grants | Provided: M2 (WP-2.9) |
| A16 | `IssueObjectUrl` + token verifier | Provided: WP-2.11 (dedicated URL-token key) |
| A17 | Grant ref scopes incl. ff-only | Provided: WP-2.7 |
| A18 | ssh grant registration | Provided: WP-2.12 (`mkit-server grant register`); WP-5.11b wraps it |
| A19 | Binary config/feature plumbing | Provided: M0-10 subcommand enum; M0-18 release build (never `test-faults`) |

---

## I. Open technical questions: resolution

| Question | Resolution |
|---|---|
| Q-M3-1 hook channel auth | Dedicated hook-channel Ed25519 key with key id; requests and outcome webhooks signed; published key list (adopted: distinct keys per role) |
| Q-M3-2 response metadata surface | Connect-transport-specific metadata sink, not a wider `Transport` (planner default; M5 receipts reuse it) |
| Q-M3-3 outcomes for paid reads | `ReadServed` outcome variant defined in WP-3.3, emitted by WP-4.13 (adopted) |
| Q-M3-4 mppx two-phase coverage | Documentation-only caveat in WP-3.14 (methods that settle at verification make `Aborted` a refund) |
| Q-M3-5 credential reuse on retry | Consistent with the PRD; no change |
| Q-M4-1 Workers CPU/memory | Windowed streaming reader (WP-4.8a) + advertised indexed-mode max pack size + checkpointed alarm slices (adopted) |
| Q-M4-2 extraction threshold | D32 |
| Q-M4-3 attestation carriage | D33: out of this epic |
| Q-M4-4 reachability cost | Technical choice inside WP-4.11/4.12 (maintained reachable set vs bounded walk), shared with WP-5.3a; not a product question |
| Q-M4-5 proof format | Decided in WP-4.11; cross-chunk ranges use a multi-chunk proof bundle (adopted) |
| Q-M4-6 delta-chain depth | Technical: a server-side chain cap in WP-4.7 (planner default 50), advertised in `GetServerInfo` limits |
| PRD Q5 index overflow | Largely resolved by D34's fixed 4096 fan-out |
| Q-M5-1 preservation store | Separate restricted R2 bucket/prefix or FS dir, admin-API-only (adopted) |
| Q-M5-2 key separation | Distinct keys per role with key ids and a published key list (adopted) |
| Q-M5-3 admin key model | Single admin key with key-list rotation; threshold deferred (planner default for PRD Q4) |
| Q-M5-4 opaque receipt subject | Refs + pack ids only (adopted) |
| Q-M5-5 reinstatement after rewrite | Re-add via server-side pack rewrite (adopted) |
| Q-M5-6 receipts as GC roots | Not GC roots; stored under attestations (adopted) |
| Q-M5-7 chunk-level holders | Resolved by D32: holders are per extracted whole object; chunk removal is by pack rewrite, per repo index |
| Q-M5-8 unsigned writer reads | ssh/enc principals are transport-authenticated and treated as writers (planner default) |
