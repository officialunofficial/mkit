# Uno launch readiness checklist

Status: **FINAL PREPARATION — NOT READY FOR LAUNCH; EXTERNAL GATES UNRUN**
(WP-1.20 / R-195). As-built feature checkpoint:
`c3921b06effc0f38e2cdbe6f25b4e5a309018136` (merged 4.18, #1259).
This is not the launch candidate. FIX-preservation-memory, PR-size cleanup,
this docs PR and the delta review remain candidate prerequisites.
Every real staging, resource/cost/multicolo and sign-off slot is **UNRUN and
user-owned**. No local result completes one of those gates.

Use the [standalone operator guide](../../operations/workers.md),
[staging measurement definition](staging-uno.md),
[scoped local evidence](launch-read-failure-evidence.md),
[historical matrix](launch-evidence.md), and
[DRAFT user-only main merge prompt](briefs/REL-1-draft.md).

## Actual launch dependency set

REL-1's direct dependencies in [registry.json](registry.json) are:

`1.27, 1.30b, 2.14, 3.13, 3.14, 3.9c, 2.16, 5.4, 5.5a, R-193, 4.10b-multipart, 4.10b-1, 4.10b-2, 4.14b-1, 4.16b, 4.16c, uno-urls, uno-visibility, zstd-bound, 5.10, 5.11a, 5.6a-1, 5.6a-2, 5.6a-3, 4.18, 1.20, FIX-preservation-memory`.

The baseline wire/grant/admission terminal set is 1.27, 1.30b, 2.14, 3.13,
3.14; the table below records the subsequent launch inputs. Transitive
prerequisites stay in the registry. Extraction's historical `4.10b` entry is
reconciled to merged `4.10b-2`, resolving two dangling edges. There is no
activation-to-foundation reverse edge, nor a dependency on withdrawn R-196/197.
Merged provenance does not mean a local or staging case passed.

| Input | Governing obligation | Merged PR / SHA prefix |
|---|---|---|
| 3.9c / 2.16 | Signed HTTP hooks / namespace authority fence, R-180/181 | #1233 / `4d1c8fd4` |
| 5.4 | Published view, indexed permanent retention, leases/GC off, R-182/198 | #1235 / `8515ad8e` |
| 5.10 / 5.11a | Durable purge, signed admin and gapless audit, R-188/189 | #1236 / `e99e2b24` |
| 4.10b-multipart / 4.10b-1 / 4.10b-2 | Bounded grouping, protection and extraction, R-192/186 | #1232 / `39998d86`; #1238 / `8bc30385`; #1244 / `d691d32e` |
| 4.14b-1 | Native/core proof serving; Worker proofs excluded, R-187 | #1239 / `e5174c75` |
| 5.5a sync | Complete added-pack file set, at most four fail-closed batches, R-183/200 | #1240 / `233f51af` |
| 5.6a-1 / 5.6a-2 / 5.6a-3 | Denial, preservation/retention/legal holds, restricted catalog, R-190 | #1242 / `bc114103`; #1249 / `a3966d84`; #1251 / `e8164870` |
| R-193 | Private assigned raw-pack scanner retrieval / no oracle | #1243 / `ade6179e` |
| Timer repairs | Publication recheck, physical scan/fairness and deterministic conformance | #1245 / `d89c37fb`; #1247 / `e45def2f`; #1248 / `12e4ce49` |
| 4.16b / 4.16c | File media/disposition/security headers and bounded in-process reader, R-201/202 | #1246 / `cd680351`; #1250 / `1edfc306` |
| R-203 / zstd-bound | Bounded corrupt zstd and delta decoding | #1252 / `841ff110` |
| R-204/205 | Batch URL issuance and default repository visibility | #1253 / `d2bc9a72` |
| CLI CA option | Additive PEM roots, preserved TLS checks; Connect HTTPS only | #1254 / `b90f74a3` |
| Launch review repair | Inherited timers/jobs/goldens, memory/pack cap/scanner writes, decoder scratch, purge/admin/outcomes/sha2 | #1255 / `acd17923`; #1256 / `e1533a9c`; #1257 / `86c04dfd`; #1258 / `dd0c875c` |
| Stale-connection retry | Replay-safe unary retry once, same envelope/deadline; streams never replayed | #1260 / `849d83cb` |
| 4.18 | Paid indexed Multi/D34 activation, embedding, requested Uno local matrix, R-194 | #1259 / `c3921b06` |
| FIX-preservation-memory | Required <=48 MiB Worker preservation allowance before candidate/main | IN FLIGHT; no merged SHA |
| 1.20 final | This preparation and standalone operator guide, R-195 | THIS PR; no staging claim |

Full merged SHAs resolve from these PRs and the pinned feature Git history;
prior implementation pins are also retained in [launch-evidence.md](launch-evidence.md).
#1260 review B includes 47 targeted PASS / 0 FAIL / 1 existing helper skip.
#1259 correctness/security B and conformance/budgets C led to two fixed
Mediums (bounded seven-op admin mount and programmatic indexed-profile guard).
The user accepted B for merging #1259, with the open preservation memory Medium
required as a separate fix before candidate/main. Its reviewed head is
`78b32ab633206cc1455ce8fe584510f7ed75ba0b`. This is not resource sign-off.

**Post-launch:** 5.5a-0 → 5.5c → 5.15 → 4.14b-2. These cover the inspection
marker, async inspection/holds/review, publication Events and Worker proofs;
none is in REL-1's dependency closure. The three deferred hold tests remain
declared skips, not launch PASS. Leases/serving GC/receipts, rewrite, notices,
reinstatement, full admin and Queue outcomes/owner bridge remain excluded.
Committed Outcome means **Sent**, not Delivered: D34 dependency projections
can still delay published-prefix advancement. Next free R-row is **R-206**;
this docs work updates R-195 and allocates no new row.

## Pinned local evidence, not staging

#1259's [matrix record](launch-read-failure-evidence.md) pins source
`7527556d09c7753462f0449622d86ade0fb3b70e`, tree
`d83f2cb00a13f21189dfb07e5fff4fbcd09fb032`. Later review/source fixes are not
silently treated as reruns of that runtime matrix. The feature checkpoint above
contains those fixes; revalidate affected evidence at the future candidate.

| Pin | Value |
|---|---|
| Uno host features | `mkit-server-worker`: `http-objects,pack-ruzstd`; custom in-process Authorize/Admit/Outcome and paired local purge; no test-faults, signed-HTTPS or snapshot runtime acceptance inferred |
| Uno Wasm SHA-256 | `8db43d251998a36c4206bdf921bc1a60a01cf5c5978cfc9949fa226997d3faaf` |
| Native CLI SHA-256 | `e2c69903f0d5431fb7bb2c73bff08fa0be1990e5c536150a8a6a91d1868d32e8` |
| Matrix runner SHA-256 | `d80dc9005565676e2b198f3a296ef8f95d870fcbd04a37258579e1227cc85b65` |
| Matrix manifest SHA-256 | `809c176afc05fdf4f262ae097c7ae3361721accf54dba5f42956067c06552ca4` |
| Runtime / command | Wrangler 4.134.0 / Miniflare 5.20260917.0-alpha; `vcs-worker-launch-admin-runtime.py --uno --namespace any --observe-resources`; exact args/times/config/log hashes in the retained record |
| Uno config digest | `82c634fff2d30b4cd3d976913193d19b8702d78054f417bd72bc31e44f320c2f` |
| Geometry | Embedded 8,631,723-byte canonical pack, two streamed parts; native HTTPS four 128 KiB files, signed zstd push/exact clone; public Multi/D34 `any`, internal admin, leases/GC off |

| #1259 local lane | PASS | FAIL | Declared skip / scope |
|---|---:|---:|---|
| Requested Uno functional matrix | 5 grouped rows | 0 in final run | 0 in those rows: embedded push/AlreadyPresent/402; native HTTPS push/clone; HTTP/headers; takedown/preservation/audit; cold-restart Outcome. Sixth PR row records scoped resource observations, not a sixth functional test |
| Embedded fixture checks | 10 named assertions | 0 | 0; count from retained matrix manifest, distinct from grouped PR rows |
| Physical observation | All groups complete | 0 completeness failures | 72,685 records, 244 alarm groups; no resource certificate |
| Conformance + transport nextest | 680 | 0 | 2 |
| Separate transport nextest | 140 | 0 | 1; one passing test reported leaky in standalone run |
| CLI + conformance reverse dependencies | 2,073 | 0 | 10 |
| Final review-targeted Worker config/admin + transport socket tests | 38 | 0 | 27 Worker + 11 socket regressions; release tests explicitly excluded test-faults |
| Broader historical variants/full matrix | UNRUN | Retained historical failures | No aggregate PASS or skip waiver |

Do not sum overlapping lanes. Skips keep the owning runner's declarations;
feature-filtered and unexecuted cases are not passing tests. Historical failures
remain retained: stale pooled-client reads, tooling/parser/PATH/port failures,
native key-mode/deadline failures, concurrent-compilation timeouts, and the first
semantic PASS with incomplete alarm observations. The corrected observer rerun
completed all groups. Fresh reads and direct Miniflare support a local workerd
connection-reuse artifact classification, not proof of its internal cause or
production behavior. #1260 narrows retry to reused HTTP/1 with zero new decrypted
response bytes; partial replies/HTTP errors and streams are not replayed.

| Local resource | Observation / unchanged boundary |
|---|---|
| CPU | 17.17 s OS-accounted process CPU / 18.03 s elapsed for heavy AdvanceRefs; all threads/storage isolates/concurrent alarms. Earlier 28.224 s active sampling spans the whole upload sequence. Neither is deployed per-invocation CPU |
| Configured CPU | `limits.cpu_ms=60000`, provisional in staging template/environment; deployed validation UNRUN |
| Request calls | Peak 8,290; 9,000 backend / 10,000 combined allowances |
| Alarm calls | Peak 123 across 244 groups; unchanged 960 + 40 reserved headroom |
| Connections | Peak four complete outgoing lifetimes; ceiling six |
| Timer window / SQL | Peak nine rows; 114,223 read / 31,315 written |
| Memory | Wasm linear capacity 20,316,160 bytes; sampled co-observed used sum 60,458,558 and allocated-capacity sum 104,604,962 bytes (~105 MB) |
| Memory coverage | 154 identified samples / 1,667 total; 1,513 unknown, 27 gaps. Raw-Blob Uno fixture does not exercise maximum preservation delta geometry |

Historical five-variant sizes are pinned to
`43256803446f7f29a7fbf45d794afcfb78cea181`, before final review fixes, in
[launch-feature-sizes.json](launch-feature-sizes.json) (SHA-256
`ef1d92a85fce5c665131d2a5616d6d358ffec26e7c9ba5061d340a7f8fd71375`).
All commands start `worker-build --release --features` from `apps/vcs-worker`.

| Features | Raw Wasm bytes | Deterministic gzip bytes | Full emitted bytes |
|---|---:|---:|---:|
| `pack-ruzstd` | 6,661,292 | 2,279,944 | 6,701,318 |
| `pack-ruzstd,http-objects` | 6,990,192 | 2,380,916 | 7,030,420 |
| `pack-ruzstd,signed-http-hooks` | 6,665,414 | 2,282,338 | 6,705,440 |
| `pack-ruzstd,http-objects,signed-http-hooks` | 6,993,827 | 2,383,298 | 7,034,055 |
| `launch` (also published-view) | 7,029,471 | 2,397,658 | 7,070,032 |
| Distinct Uno host at matrix source | 6,934,119 | 2,370,989 | 6,974,355 |

The five variants passed their local 64 MiB emitted-size guard; final-head
variant measurements and remote packaging acceptance remain UNRUN. Gzip is
informational. Size does not establish runtime/resource acceptance.

## Known open items and review disposition

- **FIX-preservation-memory, in flight and required before candidate/main:**
  reduce 96 MiB Worker Rust acquisition allowance to at most 48 MiB with bounded
  chain memo retention. Keep the original whole-isolate Medium open until fixed,
  independently reviewed and measured; the ~105 MB sample supplies no headroom
  certificate. Exercise the [whole-isolate memory gate](staging-uno.md#whole-isolate-memory-gate).
- **many_refs connection reuse:** inherited Worker conformance failure remains
  Medium/unclassified. #1260 and the requested Uno matrix do not constitute a
  rerun/closure of many_refs. Diagnose at its original geometry and preserve
  its failed evidence.
- **Review Mediums deferred post-launch:** full review at `e8164870` retains
  2-1 (Any + Address authority generation), 3-2 (native implicit
  TransportIdentity denial), 3-3 (larger configurable outcome batches),
  6-1 (sliding Public reader cache without takedown denial), 7b-2 (admin
  validation/audit-field drift), 9-1 (native logical restore ownership) and
  11-1 (untrusted admin body lifetime). These are configuration/native limitations,
  not waivers for enabling their affected surfaces. The final delta review must
  classify any fixes and remaining restrictions; do not assume all old findings
  survive unchanged. #1255–#1258 repair the launch findings and ordinary gate
  defects; original 12-1/12-2 are not deferred gate waivers.
- **Review closure:** historical whole-launch review is source evidence, not
  user acceptance at the future candidate. Delta `e8164870..c3921b06`, cleanup
  and preservation fix need final source validation and affected checks.
- **Transport limitation:** `MKIT_SSL_CA_FILE` / `http.sslCAInfo` apply to Connect
  HTTPS RPC/upload/download; private-CA S3 support is post-launch, and release
  downloads keep their own trust policy.

The release rebuild statically retains `docs/operations/**`. Its archive policy
is still pinned before 12 existing 4.18 planning paths were added; the user must
review/archive those and extend the guard policy before rebuilding #1261. This
PR adds no new planning paths and does not execute or bypass the rebuild.

## User-owned staging and sign-off slots

All results below are literally **UNRUN**. Pin final candidate, artifact/features,
compatibility date, config/limits, resource identities/jurisdiction/placement,
input geometry, concurrency, command/tool versions/times, samples/error counts,
logs and reproduction steps. Invalidate affected results when any pin changes.
Later main-only CI against an already deployed server does not substitute for
pre-main user staging; no workflow is created or dispatched by this docs PR.

| User-owned gate | Required evidence | Result / owner |
|---|---|---|
| Real staging conformance | Full wire/e2e push/clone, discovery, private scanner/admin isolation, role collisions, incompatible profile refusal, key rotation | UNRUN / user |
| CPU | Deployed p50/p95/max upload/ingest, decode/delta/extraction, scanner reads and alarms; native proofs separately; 60000 ms configuration and headroom | UNRUN / user |
| Physical calls/alarms/connections | DO/R2/hooks/scanner/purge by kind including retries, mixed due heads, whole request/alarm work and response lifetimes | UNRUN / user |
| Whole-isolate memory | Synchronized Wasm/V8/backing/transport peaks, retained capacity, cancellation, cold/warm largest valid delta/frame/preservation geometry at concurrency 1/2/3/4/6; retain gaps/limit errors | UNRUN / user |
| Cost | Storage, DO CPU/duration, R2 operations/storage, egress per upload/read/inspection/backlog and per 102400 payload bytes; dated rate inputs | UNRUN / user |
| Scanner timing | Assignment through all bounded raw-pack ranges, external-base resolver and verdict within actual 5000 ms default / 30000 ms max Worker timeout | UNRUN / user |
| Multicolo | Global block/visibility denial, stale tokens/snapshots, actual CDN purge convergence and outage recovery | UNRUN / user |
| Settlement and failure drills | Outcome duplicates/reordering, disconnect reconciliation, hook header/body limits/redirect/cancellation, hooks/scanner/purge down then recovery | UNRUN / user |
| Recovery | Empty initial store; same-format restart; offline restore preserves root ownership and all later denial/legal holds | UNRUN / user |
| Whole-launch review acceptance | User-selected full/delta review, source-validated findings/fix SHAs and independent outcomes at final candidate | UNRUN / user |
| Staging acceptance | Explicit accepted candidate/config and headroom, with evidence links | UNRUN / user |
| Main merge authorization | Explicit user authorization for rebuilt #1261 merge commit after all prerequisites | UNRUN / user |
| Deployment authorization | Separately scoped artifact/config/resources and rollback acceptance | UNRUN / user |
| Later tag/publish/release decision | Separate future authorization; no version bump or tag at Workers launch | UNRUN / user |
