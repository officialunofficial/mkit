# Launch runtime coverage plan (WP-4.18 / R-194)

Status: **research and proposed execution plan; integrated cases UNRUN**.
This inventory was read at source checkpoint
`5f3c7a36634f80cc3a8585db552af42ab8268027`. Concurrent phase 2 edits and
later merges require a fresh candidate pin before execution. No command in
this document has been run as part of this coverage audit.

The user authorized phase 2 work on available prerequisites. Preservation
core 5.6a-2 and the restricted admin catalog 5.6a-3 (#1251) are merged.
Configured operator endpoint activation is authorized; adapter integration
and actual runtime evidence remain UNRUN. Optional sync
inspection, native proofs, and release Worker proof refusal remain in scope.
Async inspection, holds/review, publication Events, and Worker proofs are
excluded. The resolved header ruling adopts merged #1246.

## Existing harness boundaries

The [28-case inventory](launch-cases.json) names contracts, not complete
executable runtime probes. Keep the native, actual release Worker, and
fault-build results separate in [launch-evidence.md](launch-evidence.md).

| Existing entrypoint | Meaningful evidence | Limit |
|---|---|---|
| `scripts/vcs-worker-launch.sh native --sha <SHA>` | Serialized locked all-feature tests for core, native, Worker adapters, and conformance | `--all-features` includes `test-faults`; it omits release-only tests guarded by `not(feature = "test-faults")` and does not run ignored local Worker tests |
| `scripts/vcs-worker-launch.sh release-launch --sha <SHA>` | Actual optimized launch artifact, Paid indexed Multi/D34, HTTP/token opt-in, discovery and absent test route | No write, extraction payload, byte serving, scanner, admin, or settlement assertion |
| `scripts/vcs-worker-conformance.sh --multi -- --filter info.` | Default-off release discovery and concurrent cold initialization | No opted-in launch configuration; its wire filters cannot certify the full matrix |
| `scripts/vcs-worker-conformance.sh --test-faults --indexed` | Scheduled verifier retry/checkpoint behavior through real workerd | Both existing indexed wire cases require `TestFaults`; the phase injects a failed verifier slice |
| `scripts/vcs-worker-conformance.sh --hooks` | Actual wasm Fetch/Delay cancellation, cap, redirect, and synchronous Inspect mechanics | Builds `test-faults,signed-http-hooks`; the synthetic wrapper exposes test-only routes |
| `scripts/vcs-worker-hooks.sh` | Admission/CORS/Outcome wire checks, isolated service binding, durable retries | Builds `test-faults`, uses short-ticket/backlog test variables, and does not opt into Paid indexed HTTP reads |
| `scripts/vcs-worker-authority.sh --authority` | Actual release D34 authority barrier and stale ticket/backend facts | Uses a default-off deployment, not the Paid indexed launch profile |
| `rust/crates/mkit-server-worker/tests/http-mount-probe/probe.py` | Actual workerd response bridge, real memory-indexed ref-file vectors, streamed response timing, local R2 multipart | Builds `--dev --no-opt`; synthetic/memory-store fixtures do not exercise the reference release launch's DO/publication/inspection/settlement wiring |
| `apps/vcs-worker/tests/published-view-probe/profile.mjs` | Optimized workerd snapshot/cache routing and local CPU profile with seeded local R2 | Programmatically seeded disposable fixture; does not prove launch publication transitions or deployed resource ceilings |

In particular, `rust/crates/mkit-server-worker/tests/scanner_retrieval.rs`
uses real SQL behind a host loopback and a simulated bucket. Its sparse
transport short-circuits empty shards. It is useful backend coverage, but
does not establish mounted scanner latency or the physical release DO count.
The operator runbook records failed/unproven historical mounted diagnostics.
Repeat cold and warm retrieval at the actual candidate without bypassing
global denial or changing the timeout gate.

## Proposed release fixtures

Each fixture starts an empty private local state directory, uses pinned
wrangler 4.134.0 and compatibility date 2026-09-09, and owns its ports and
process groups. Build optimized artifacts without `test-faults` or production
`TEST_*` variables. Preserve artifact hashes before another build overwrites
the output. HTTP/key/scanner/hook role fixtures use distinct public test seeds.

| Fixture | Configuration and purpose |
|---|---|
| R0 | Default-off release; retain existing wire regression plus absent HTTP/scanner/admin routes |
| R1 | Minimal Paid indexed Multi/D34, no inspector, `allowlist` and `any` with unsafe flag as separate fresh deployments; ticketed raw and multipart writes, scheduled verification/extraction, refs, and Connect reads |
| R2 | R1 plus HTTP objects/tokens; publish pack fixtures containing Blob, ChunkedBlob, manifest/chunks, small/surplus objects, delta sources, and #1246 filenames; exercise public/private/token object and ref paths |
| R3 | R2 plus isolated unsigned binding Authorize/Admit/Outcome; receiver records procedure/body, controls allow/challenge/deny/failure, and verifies durable read settlement after stream close |
| R4 | R2 plus signed HTTPS hooks and optional one through four sync fail-closed inspectors with R-193; receiver verifies signatures, audience, body, nonce, and independently decodes assigned raw ranges |
| R5 | Configured preservation/admin/takedown and signed purge, including the four restricted operator methods; also test the expressly authorized embedded custom `PurgeSink` alternative, with both admin placement modes |
| R6 | Embedded example release: custom hooks, combined DO construction, programmatic policy, host admin routing, constructed streamed `UploadPart`, publication and optional cache configuration |

For local signed-channel testing, the existing synthetic-origin fetch wrapper
is a reusable technique: map one fixture-only HTTPS origin to a local receiver
while keeping the release shim and production signed hook paths unchanged.
A new release wrapper must dispatch ordinary client requests, not
`/__mkit_test/` functions, and must not synthesize protocol outcomes. Preserve
manual redirects, abort signals, streamed body limits, and signed bytes during
mapping. Label this transport mapping in evidence; it proves production
Fetch/Delay behavior under workerd, not external TLS trust or Cloudflare
network behavior. Never enable a release loopback/trust bypass to make the
fixture pass. Use an isolated service-binding fixture for its separate channel.

## Per-case native and release paths

Native entries below are existing meaningful test modules or named tests.
They still require execution and full case counts at the final candidate.
The last column is proposed work, not a claim that a retained executable probe
already implements it. All integrated result pairs remain UNRUN. The inventory
has 28 cases, including four restricted operator methods and the pending
R-203 native push round trip.

| Case | Existing meaningful native/host coverage | Existing workerd coverage | Proposed actual release assertion |
|---|---|---|---|
| B4.config | Native `tests/launch_profile.rs`, `hook_config.rs`, `http_inert.rs`; Worker `launch`, hook and scanner configuration tests | R0 discovery and release-launch HTTP configuration | Launch R0–R5 invalid/partial grammar, bindings, absent compiled features, key collisions, off-profile opt-ins, leases/GC/retention refusal; configured admin activation requires preservation, denial, indexed work and signed purge |
| B4.discovery | Native config and Connect server-info tests, `wire_multi`; HTTP proof mount | Existing `info.shape_and_policy`, `info.ignores_repository_header`, release-launch | Query every R1–R5 opt-in combination; verify zero threshold, leases/async false, active inspector bound only when present, no proof/receipt/rewrite overclaim; native proof advertisement separately |
| B4.inspected-set | Core indexed inspection and inspection-budget tests | RemoteInspector runtime wrapper checks a synthetic one-object request | R4 uploads packs with surplus/small/file/manifest/chunk/deduplicated entries, extracted copies, Verified reuse and pending prior membership; receiver records each inspector's exact independent complete set |
| B4.inspection-bound | Core indexed inspection, whole-advance budget tests | Inspect pass/quarantine/defer wrapper outcomes | R4 tests object counts at the configured bound and one beyond; preflight prevents Inspect and mutation on excess, each of up to four inspectors gets one complete batch, reject dominates and unavailable leaves no committed refs |
| B4.scanner-bytes | Core scanner/pipeline tests; native `scanner_fetches_all_packs_with_ranges_and_decodes_manifest_membership`; host Worker DO/SQL/R2 adapter test | No retained reference-app release retrieval probe | R4 receiver uses signed Inspect metadata to fetch all assigned staged added-pack ranges and independently decode manifests; earlier packs and delta bases need its independent authorized cache/resolver |
| B4.scanner-denial | Core capability/service tests; native `adapter_and_lifetime_failures_are_uniform`, ticket expiry and global-block tests | No complete mounted release denial matrix | R4 compares status/body for foreign key/repo/pack, wrong audience, missing/bad capability, range, replay, expiry, terminal ticket and block; assert source read absence where locally observable and cancel in-flight retrieval |
| B4.publication | Core published-view/pipeline tests; native `d34_creation`, `relay`; host Worker published-view tests | Existing D34 wire tests and fault-only planted relay | R1 polls paired heads/packmaps and reader views after real pushes; source/live writer and published reader remain distinct during delayed projection. R6 exercises configured snapshots; restart same state and verify eventual coherent publication |
| B4.public-reads | Core HTTP/publication tests; native real `tests/http_mount.rs`, header vectors | HTTP bridge and memory-indexed file vectors; release-launch only keys | R2 checks PackExists/DownloadPack, object/index reads, MKDP/MKDS, token binding, ref path, and R6 snapshots/cache; apply the #1246 GET/HEAD/206/304 filename/media vectors to wire-ingested release bytes; R5 adds stale-cache global denial |
| B4.native-proofs | Native named `native_object_proofs_*`, `native_range_proofs_*`, syntax/context/offset/golden/payment/cache tests | Worker host unsupported-proof tests; no reachable release-object check | Execute native raw/manifest/chunk/range independent verification; R2 uploads and publishes reachable bytes, then requests `?proof=1` and verifies unsupported response plus absent discovery claim |
| B4.writer-reuse | Core indexed/ticket/takedown tests; native `ticketed_upload`, `begin_upload` | Existing raw/multipart/ticket wire cases; indexed mode is fault-only | R1/R2 raw and multipart upload, dedup/AlreadyPresent, consumed and reused Verified tickets, implicit membership/external delta chains; R5 repeats every bypass path after global denial |
| B4.authority-races | Core authority/write-gate tests; native `write_gate`, `epoch_leases` | `authority_worker` ignored test through actual release D34 binding fixture | Move its setup into R1/R4; interleave generation/revocation with upload/backend/marker/apply, delayed receiver reply, retry, signer rotation and restart; do not count the default-off script alone as the launch intersection |
| B4.extraction | Core extraction/group/job tests; host Worker `bounded_object_multipart.rs` covers restart, CVS, roots and completion | Fault-build indexed scheduled verifier; local R2 multipart fixture | R1 creates A+B/B+C overlap with immutable delta sources and repeated/deduplicated packs; advance polls real scheduled completion, verifies extracted object bytes, cancels open work and restarts same-format state without fault routes |
| B4.takedown | Core takedown and HTTP-denial tests | Configured preservation startup and Worker mount catalog component tests | R5 acceptance denies before success, private verified preservation, retention/legal hold, late/unresolved holders, every read/reuse path; `any` reports discovery incomplete and `allowlist` records its explicit scope |
| B4.admin | Core admin replay/audit/roles; takedown tests | Worker configured/unconfigured route unit tests | R5/R6 public versus host-only mounting; authenticated Takedown/Get/List/ReadPreserved/SetLegalHold/PurgeCache/ReadAuditLog, distinct role denial, durable replay/gapless audit; Reinstate and hold review remain absent |
| B4.admin-get-takedown | Core `takedown::admin_tests` signed-operation checks and `status_keeps_acquisition_verification_discovery_hold_and_completion_separate` | Configured catalog/Work delegation component coverage; actual release status UNRUN | R5 pending/verified/held/purged/unknown status, allowlist/any discovery honesty, no payload leakage, fresh role/key/replay/in-flight audit checks |
| B4.admin-list-takedowns | Core `list_pagination_rejects_foreign_scope_token_and_reports_missing_state_pending`, all-scope and protojson scope/page tests | Catalog delegation only; no retained release page probe | R5 absent/null/empty/all and normalized repository/namespace scopes; page sizes 1/100 and invalid sizes, empty continued pages, malformed/foreign/oversized tokens, 100-row/256 KiB scan bounds and confidentiality; measure physical calls |
| B4.admin-read-preserved | Core fresh-retry authority/ownership, exact offsets/final rules, corrupt-second-piece, expiry-between-pieces, key-expiry and audit-failure regressions | Streamed admin adapter component coverage; real release byte stream UNRUN | R5 production Connect stream verifies bounded pieces, post-I/O ownership/retention, exact offsets and final piece; retry with current key/role checks, missing/corrupt piece, audit failure and cancellation; no-store, no payload replay/logging, measured poll calls/resident work |
| B4.admin-set-legal-hold | Core signed-hold/audit/nonce/purge regression, stale ownership race and UTF-8 reason/label bounds | Work delegation/atomic-batch component coverage; actual release mutation UNRUN | R5 set/clear and replay/in-flight requests, 512/128-byte reason/label boundaries, retention deadline and purge ownership races, hold blocks purge; failed audit/CAS commits no hold mutation |
| B4.purge | Core/Worker purge retry/invalidation and admin tests | No retained actual release signed purge-outage probe | R5 signed receiver outage/lost acknowledgement/duplicate delivery, authoritative denial and local invalidation throughout, async manual acceptance then audited completion; R6 custom sink plus local invalidation |
| B4.recovery | Core timers/publication/outcomes; native `export_restore`, hook restart/drain tests | Fault-only snapshot/import/relay/retry checks | Restart R1–R5 against the same current-format persist directory during extraction/publication/Outcome/purge/takedown; client deliberately loses replies and retries identical signed requests. Fresh-store activation/reset is separate from unsupported old-store migration |
| B4.native-push-zstd | Native encoder/CLI round-trip coverage; bounded decoder prerequisite still pending | Launch Worker decoder remains off until R-203; no release round trip yet | After R-203, actual native zstd push to R1/R2, clone and compare canonical refs/content; measure decode CPU, window/scratch/resident work and adversarial compressed inputs |
| B5.admission | Core paid HTTP reads; native `native_proofs_share_payment_length_head_and_validator_cache_policy`, HTTP mount and admission E2E | M3 binding wire admission on fault build | R3/R4 `HTTP_ADMIT_READS=true`: raw/token GET, HEAD, range, early 304/416/challenge/deny; receiver sees exact admitted bytes and no payload generation on early decisions. Native proof encoded size has its separate assertion |
| B5.settlement | Core paid-read completion/reconcile tests; native HTTP/admission E2E | Synthetic streamed bridge timing; fault-build M3 Outcome tests | R3/R4 read full/partial body, HEAD zero, abort before first byte and after bytes, disconnect fetch, lose delivery reply and restart; receiver proves actual-byte ReadServed, one durable terminal decision, waitUntil retention and reconcile recovery |
| B5.runtime | Native `hook_channel.rs` signed Inspect, redirects, oversized/endless bodies and timeout/cancel; `hook_e2e.rs` retry nonces | Signed Fetch/Delay wrapper under fault build | R4 ordinary signed production Admit/Inspect/Outcome calls encounter stalled headers/body, cancel, redirect, oversized response and retry; receiver verifies exact signatures/body/audience and fresh nonce. Keep mapped local transport limitations explicit |
| B5.outcomes | Core outcomes; native signed hook retry/drain/restart and admission E2E | Fault-build M3 outcomes; release authority/binding script subset | R3/R4 collect remote reservations across write, CAS loss and replay; deliver duplicates/reordered/retried replies and restart; Committed stays Sent and never implies Delivered/publication; remote Admit replaces default internal charges |
| B3.request-budget | Core inspection/extraction budgets; host Worker `request_budget.rs` combines DO/R2/proof dispatch and heap; allocator multipart tests | Fault-build streamed buffer measurements; HTTP fixture first-byte timing | Instrument R1–R6 whole dispatch boundaries without replacing stores or bypassing checks; record routed DO/R2/Fetch plus retries, 100-op/seven-ticket applies, six ongoing response bodies and settlement lifetime. If counters are unavailable, record the measurement gap, not a PASS |
| B3.alarm-budget | Core shared TickBudget/frozen clocks and extraction bounds; reviewed #1247 SQL/alarm regression and native soft-cap tests | Fault-build verifier/retry and planted relay; no complete release mixed-kind audit | With #1247/#1248 merged, R1/R3/R5 schedules verification, extraction, publication, Outcome and purge together; restart cold with more than one scan window, verify fair progress/no loss, shared limits and 256-call/48 MiB slices. Frozen injected clocks stay a separately labeled host test; actual release alarms record observed physical work |
| B4.embedding | Source API/trait tests and external crate compile checks | Existing class glue; no retained embedded UploadPart lane | R6 compiles the example and generated/documented five-class pattern, custom hooks and combined sinks, host-only admin and programmatic policy; constructed streamed UploadPart must use config audience and share isolate budgets. Measure raw and deterministic gzip wasm for minimal/HTTP/signed/launch variants |

## Execution order and acceptance

1. Merge exact available prerequisites and freeze implementation/configuration.
   Execute native all-feature coverage plus a separate release feature set
   without `test-faults`, including release-only launch refusal assertions.
   Previous native timer flake exceptions no longer apply after #1248. Report
   any remaining failure; a new classification needs a pinned unchanged-base
   reproduction. This research does not classify any failure.
2. Retain R0 release regression. Build R1/R2 at the candidate and reuse the
   wire runner's signing, upload, token, and visibility helpers. Existing
   cases declare their feature prerequisites manually; declaring a feature
   does not mean the server advertised it. Confirm discovery independently.
3. Add explicit production indexed helpers rather than activating the
   TestFaults-only indexed case. The large-pack verifier helper is reusable;
   its fault marker and injected-slice log assertions are not release checks.
   Require named case execution with no unexpected skip, not only exit zero.
4. Exercise R3 and R4 separately. Adapt signed-channel receiver/mapping and
   real request helpers; keep binding requests unsigned and enforce isolated
   receiver routing. R-193's cold/warm cost can expose a real deterministic
   gap; record failure and fix within scope rather than skipping the case.
5. Compile and run R6 after the addenda land, and run configured R5 against
   the merged restricted catalog. R1–R4 results cannot fill its rows. Any branch/config change invalidates
   affected evidence before the final candidate pin.
6. Every result records SHA/tree/base, build features/artifact hash, config
   digest, command, named checks/pass/fail/skip counts, timestamps, receiver
   transcript and log hashes. Complete matrix PASS requires each contract,
   including budget measurement, at the actual candidate. Whole-launch
   reviews and external deployed/staging/resource gates remain separate.

No cloud call, deployment, staging operation, new RPC, or new production
durable state is authorized by this plan. Local wrapper/receiver diagnostics must
remain outside production artifact routes.

## R-203 addition

After bounded ruzstd (WP-zstd-bound) merges, enable `mkit-core/pack-ruzstd` in
the launch build. Execute `B4.native-push-zstd`: run native `mkit push` against the
actual release Worker, clone from it and compare canonical refs/content. The
native encoder must actually emit zstd; a hand-built raw-pack fixture does
not cover this case. Include zstd decode CPU and resident memory in the budget
audit. Until the prerequisite merges, leave the decoder off and this row UNRUN.
