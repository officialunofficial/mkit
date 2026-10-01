# Uno launch readiness checklist

Status: **SKELETON — NOT READY / NOT EXECUTED** (early WP-1.20, R-195, R-198).
Local evidence is executor-owned in [launch-evidence.md](launch-evidence.md).
All external review, staging measurement and release sign-off slots below are
**user-owned, pending and unfilled**. No measurement or launch gate is certified
by a skeleton or by a successful phase 1 refusal.
Final WP-1.20 waits for 4.18. See the [archived full brief](briefs/WP-1.20-readiness.md),
[D35 definition](staging-uno.md) and [operator runbook](launch-operations.md).

Current merged-input checkpoint: `7a2d1bf039e0853fb53d5e8e78d4d449782196ca`,
including extraction #1244, retrieval #1243 and timer-12 repair #1245;
base `e45def2fe1855a531d0149727bf6678fc8145c3c` includes HTTP headers #1246,
physical timer bounds #1247 and deterministic native timer conformance #1248. This is a
documentation reference, **not the final launch candidate**. Empty cells are
intentional; no checkbox is satisfied by this document or by local wrangler.

## Concrete launch prerequisite record

Reconcile this list with the final [registry](registry.json) at phase 2. Each
row requires a full merged SHA, PR and independent review outcome in
[launch-evidence.md](launch-evidence.md). A registry status is no passing gate.
Extraction 4.10b-2 and retrieval R-193 have merged (#1244 / #1243).
The user authorized phase 2 for the available prerequisites. Preservation core
5.6a-2 (#1249) and the restricted admin catalog 5.6a-3 (#1251) are merged.
Configured operator endpoint activation is authorized; adapter integration
and runtime evidence remain UNRUN. The Worker zstd decoder stays off
until bounded ruzstd (R-203) merges.
#1245 publication recheck timer 12 progress repair is merged. Physical alarm
bounds/backoff #1247 and native conformance #1248 are also merged. Timer/alarm
reruns require fresh results; previous native timer flake exceptions no longer
apply, and any remaining failure must be reported.

The resolved header ruling adopts merged #1246: successful ordinary ref-path
files use its extension media/disposition allowlist and safe filename headers.
Object-id file responses stay binary. All byte-serving responses retain nosniff
and the sandbox CSP; non-file, native proof, 304, and error policies remain
specified separately. Actual release header evidence is UNRUN.

| Prerequisite | Launch obligation / governing contract | Evidence link / result |
|---|---|---|
| 1.27 / 1.30b / 2.14 | Wire/storage, adapter grants and CLI grant controls; STC / SPEC-WRITE-GRANTS | UNRUN |
| 3.13 / 3.14 | Admission/Outcome conformance and reference hook integration | UNRUN |
| 3.9c / 2.16 | Signed HTTP / isolated binding hooks and namespace authority fence; R-180 / R-181 | UNRUN |
| 5.4 | Coherent published view with permanent retention, leases/GC off; R-182 / R-198 | UNRUN |
| 5.5a-sync | Optional zero to four sync fail_closed inspectors, complete one-batch added-pack file set and whole-advance bound; R-183 / R-200 | UNRUN |
| 4.10b-1 / 4.10b-2 / multipart | Extraction grouping/driver, canonical source and whole-phase bounds; R-186 / R-192 | UNRUN |
| 4.14b-1 | Native/core proofs, advertised and served only natively; R-187 | UNRUN |
| R-193 | Optional private assigned added-pack raw retrieval, dedicated allowlist/key and no-oracle contract | UNRUN |
| 5.10 / 5.11a | Automatic purge delivery, signed admin framework and audit, without reverse activation dependency; R-188 / R-189 | UNRUN |
| 5.6a-1 / 5.6a-2 | Lean takedown, verified preservation/retention/legal holds, incomplete discovery under any, manual asynchronous PurgeCache; R-190 | UNRUN |
| 5.6a-3 | Configured restricted GetTakedown/ListTakedowns/ReadPreserved/SetLegalHold with fresh signed authority, replay/audit, bounded scans/pieces and atomic hold ownership; [contract](WP-5.6a-3-contract.md), merged `e8164870170ac0dcedd1512fde25d3c0063ee6d0` | UNRUN |
| 4.18 | Paid profile, startup opt-ins, capability honesty and complete local launch matrix; R-194 | UNRUN |
| 1.20 final | Staging definition/templates, evidence consolidation and user gates; R-195 | UNRUN |

R-196 and R-197 are withdrawn and retired. 5.5a-0, 5.5c, 5.15 and 4.14b-2
are post-launch. Async inspection, inspection holds/review, publication Events
and Worker proofs are excluded from launch conformance and budgets. There is
no launch inspection mode marker or old-store migration.

## Candidate and reproduction record

Candidate/build/local reproduction fields are executor-owned; staging and
acceptance fields remain user-owned. Fill after phase 2, and invalidate affected
evidence whenever code, config or build features change.

| Pin | Value |
|---|---|
| Final feature candidate SHA and reviewed diff range | |
| Activated release Worker artifact digest / build feature set | |
| Native reference artifact digest / feature set | |
| Spec revisions / golden vector revisions | |
| Final profile config digest, compatibility date and limits | |
| Staging resource identities, placement, jurisdiction, Paid plan | |
| Input geometry: pack/raw bytes, object count, delta depth, refs, concurrency | |
| Commands, tool versions, timestamps, redacted log/artifact locations | |
| Approved ceilings and reviewer accepting headroom | |

## Resource and cost evidence

Use actual deployed measurements at the pinned artifact/config. Record samples,
input geometry, repeat procedure, error counts and limitations; distinguish CPU
from wall latency. Preserve project budgets and headroom; platform maxima alone
do not certify safety. No historical local timing is a value for these slots.

| User-owned pending gate | Required record | Evidence / result |
|---|---|---|
| CPU | p50 / p95 / max deployed CPU for upload/ingest, decode, delta, extraction, native proofs, assigned private scanner reads and alarms; configured CPU allowance | |
| Request subrequests | DO internal, R2, HTTP hooks/scanner/purge by kind, retries and whole-request worst case; input/chunk geometry | |
| Whole-alarm calls | Combined fires: relay, backup, outcomes/rollup, verification, snapshots, publication recheck, takedown and purge; sync inspection is request-path work; calls/ops, retries, simultaneous connections and headroom | |
| Memory | JS + Wasm resident peaks during verification/extraction/scanner reads; native proofs measured separately and concurrent response lifetimes; concurrency and retained buffers | |
| Cost per operation | Storage operations, DO duration/CPU, R2 storage/operations and network/egress components for upload, read, inspection, backlog and purge; dated rate inputs | |
| Cost per 100 KiB | Same itemized costs normalized to 102,400 payload bytes; state bytes, request counts and whether rounding/minimum charges apply | |
| Scanner latency and backlog | PRE_RECEIVE assignment-to-verdict p50/p95/max; fail-closed failures and bounded request concurrency; no held queue or clear deadline | |
| Multicolo serving/cache/purge | Global-block denial, visibility changes, convergence, stale snapshots/tokens and sink outage recovery | |

## Conformance and review gates

Record exact commands, logs, pass/fail/declared-skip counts and reasons at the
final immutable SHA. Local checks belong beside deployed checks; they cannot
complete user staging or external review. Future main-only workflow results
also cannot substitute for pre-main user-operated staging.

| Gate / owner | Evidence required | Evidence / result |
|---|---|---|
| Native reference (executor) | Final full/local gates and indexed serving/inspection/preservation matrix | |
| Worker local runtime (executor) | Final native parity, default-off release regression and opted-in **release** wasm runtime; test-faults separately identified | |
| Real staging conformance | Full wire suite and real push/clone; private/scanner isolation and Worker proof refusal, role collisions, authority/profile refusal and key rotation | |
| Network settlement | Outcome delivery, duplicate/reordered delivery, disconnect settlement/reconciliation, hook header/body limits, redirects, timeout/cancellation | |
| Failure drills | [Hooks/scanner/purge outage drills](launch-operations.md#failure-drills-and-evidence), restart/recovery and durable backlog evidence | |
| External whole-launch code/spec review | User-selected external reviewer, candidate SHA, report and explicit outcome | |
| Validated review findings/fixes | Source validation per finding, fix SHA/PR, affected gate reruns and independent adversarial review | |
| Final known limitations / unresolved requests | Actual unresolved hit/late-holder work, no false completion; accepted exclusions and retention implications | |
| Staging acceptance | User sign-off with evidence links and exact accepted candidate/config | |
| Release authorization | Separate explicit user authorization, date and authorized main/version/tag/publish/deploy scope | |

Launch excludes async inspection, inspection holds and review, publication
Events, Worker proofs, storage leases, serving GC, storage receipts, rewrite/451
notices, reinstatement, full admin/CLI, optional Queue outcomes and owner-approval
bridge. Preservation retention/legal-hold purge is separate and required.
Native remains the maintained reference/test server. Unresolved requests stay
unresolved; this skeleton grants no waiver of serving denial or preservation.

The [conformance plan](launch-conformance.md) distinguishes phase 1 configuration
refusal evidence from phase 2 native and opted-in release runtime PASS. HTTP,
inspection and admin/takedown are opt-ins, each with complete startup validation.
The Uno Kit demo uses `any` plus its unsafe flag; takedown must report incomplete
discovery. Worker discovery never advertises proofs; native discovery does.

## Post-launch transport follow-up

Private-CA S3 endpoints: extend additional CA-file support to `mkit+s3://`
remotes after launch. `MKIT_SSL_CA_FILE` and `http.sslCAInfo` currently cover
Connect HTTPS remotes only (RPCs, uploads and downloads); S3 retains its current
HTTPS trust policy. Keep release downloads outside these custom-CA settings.
