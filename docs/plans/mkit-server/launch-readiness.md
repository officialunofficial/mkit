# Uno launch readiness checklist

Status: **SKELETON — NOT READY / NOT EXECUTED** (early WP-1.20, R-195, R-198).
All launch evidence and sign-off slots below are **user-owned, pending and
unfilled**. This PR supplies forms; it certifies no measurement or launch gate.
Final WP-1.20 waits for 4.18. See the [archived full brief](briefs/WP-1.20-readiness.md),
[D35 definition](staging-uno.md) and [operator runbook](launch-operations.md).

Source baseline for this skeleton: `origin/feat/mkit-server` at
`4d1c8fd435b4552c8716a60b606280cf63434ace`, fetched 2026-09-30. This is a
documentation reference, **not the final launch candidate**. Empty cells are
intentional; no checkbox is satisfied by this document or by local wrangler.

## REL-1 dependency mapping

These are **all 14 direct `REL-1.depends_on` entries** in the current
[registry.json](registry.json), in its order. Registry presence and historical
status tables are not evidence that the launch version has merged or passed.
The user fills each row with merged SHA, implementation PR, independent review
outcome and owning-spec/R evidence for the final candidate.

| Registry dep | Launch obligation / governing contract | Evidence link (user-owned; pending) |
|---|---|---|
| 1.27 | M0/M1 wire and storage conformance; STC / R-185 | |
| 1.30b | Adapter grant flags and WebAuthn relying-party config; SPEC-WRITE-GRANTS / R-185 | |
| 2.14 | CLI grant revoke, epoch and visibility statements; SPEC-WRITE-GRANTS / R-185 | |
| 3.13 | Admission/outcome conformance; SPEC-SERVER §§5–8 / R-185 | |
| 3.14 | TypeScript mppx reference Worker docs; SPEC-SERVER admission/outcome contract | |
| 3.9c | Signed Worker hooks; SPEC-SERVER §7 / R-180 | |
| 2.16 | Namespace authority fence; SPEC-SERVER §6.2.1 / R-181 | |
| 5.4 | Published view and launch-profile amendment; SPEC-SERVER §§10–12, 18 / R-182, R-198 | |
| 5.5a | Synchronous inspection and the launch-profile §11/§18 amendment; SPEC-SERVER §11 / R-183, R-200 | |
| 4.18 | Complete release Worker activation and indexed/serving conformance; SPEC-SERVER §§9–11, 18 / R-194 | |
| 5.6 | Historical full aggregate: launch uses lean **5.6a**, not all full-profile operations; SPEC-SERVER §§14, 16 / R-190, R-198 | |
| 5.11a | Signed admin framework, roles, replay and audit; SPEC-SERVER §16 / R-189, R-198 | |
| 1.20 | Final staging definition/automation, local evidence consolidation and user staging gates; D35 / R-195 | |

**Registry reconciliation remains pending its owning lanes.** The current
registry lacks concrete 5.6a and remote Inspect entries and retains historical
activation edges (including 5.11a → 4.18). This early docs PR does not rewrite
their DAG or treat historical aggregates as completed. Final 4.18 / 1.20 must
verify an acyclic concrete graph and replace the full 5.6 aggregate with lean
5.6a; include R-193 and final proof/extraction prerequisites. R-196 and R-197
are withdrawn, retired and not launch dependencies. Under R-200, 5.15, 4.14b-2,
5.5a-0 and 5.5c are post-launch follow-ups, not launch dependencies.

| Concrete prerequisite to reconcile | Owner / evidence required | Evidence link (user-owned; pending) |
|---|---|---|
| Durable inspection storage + authority | 5.5a, including R-199 storage prerequisite and R-198 B3 acceptance | |
| Remote Inspect / private canonical retrieval | R-193; merged contract, vectors and independent crypto/security reviews | |
| Extraction driver and multipart primitive | 4.10b / R-186, R-192; canonical source and bounded whole-phase accounting | |
| Native/core proofs | 4.14b-1 / R-187; final integrated conformance (Worker proofs 4.14b-2 / R-191 are post-launch) | |
| Automatic purge and admin foundations | 5.10 / R-188 and 5.11a / R-189; no reverse activation dependency | |
| Lean takedown + manual asynchronous PurgeCache | 5.6a / R-190; preservation, retention/legal holds, audit and unresolved status | |

## Candidate and reproduction record

Every field is user-owned and pending. Fill once final 4.18 and readiness
preparation are merged; invalidate affected evidence if code/config changes.

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
| CPU | p50 / p95 / max deployed CPU for upload/ingest, decode, delta, extraction, proofs, assigned private scanner reads and alarms; configured CPU allowance | |
| Request subrequests | DO internal, R2, HTTP hooks/scanner/purge by kind, retries and whole-request worst case; input/chunk geometry | |
| Whole-alarm calls | Combined fires: relay, backup, outcomes/rollup, verification, snapshots, publication, inspection, takedown and purge; calls/ops, retries, simultaneous connections and headroom | |
| Memory | JS + Wasm resident peaks during verification/extraction/proofs/scanner reads and concurrent response lifetimes; concurrency and retained buffers | |
| Cost per operation | Storage operations, DO duration/CPU, R2 storage/operations and network/egress components for upload, read, inspection, backlog and purge; dated rate inputs | |
| Cost per 100 KiB | Same itemized costs normalized to 102,400 payload bytes; state bytes, request counts and whether rounding/minimum charges apply | |
| Scanner latency and backlog | Assignment-to-verdict p50/p95/max; failure retry/deadline, pending/held queue growth and drain | |
| Multicolo serving/cache/purge | Held and global-block denial, visibility changes, convergence, stale snapshots/tokens and sink outage recovery | |

## Conformance and review gates

Record exact commands, logs, pass/fail/declared-skip counts and reasons at the
final immutable SHA. Local checks belong beside deployed checks; they cannot
complete user staging or external review. Future main-only workflow results
also cannot substitute for pre-main user-operated staging.

| User-owned pending gate | Evidence required | Evidence / result |
|---|---|---|
| Native reference | Final full/local gates and indexed serving/inspection/preservation matrix | |
| Worker local runtime | Final native parity, default-off release regression and opted-in **release** wasm runtime; test-faults separately identified | |
| Real staging conformance | Full wire suite and real push/clone; private/proof/scanner isolation, role collisions, authority/profile refusal and key rotation | |
| Network settlement | Outcome delivery, duplicate/reordered delivery, disconnect settlement/reconciliation, hook header/body limits, redirects, timeout/cancellation | |
| Failure drills | [Hooks/scanner/purge outage drills](launch-operations.md#failure-drills-and-evidence), restart/recovery and durable backlog evidence | |
| External whole-launch code/spec review | User-selected external reviewer, candidate SHA, report and explicit outcome | |
| Validated review findings/fixes | Source validation per finding, fix SHA/PR, affected gate reruns and independent adversarial review | |
| Final known limitations / unresolved requests | Actual unresolved hit/late-holder work, no false completion; accepted exclusions and retention implications | |
| Staging acceptance | User sign-off with evidence links and exact accepted candidate/config | |
| Release authorization | Separate explicit user authorization, date and authorized main/version/tag/publish/deploy scope | |

Launch excludes storage leases, serving GC, storage receipts, rewrite/451
notices, reinstatement, full admin/CLI, optional Queue outcomes and owner-approval
bridge. Preservation retention/legal-hold purge is separate and required.
Native remains the maintained reference/test server. Unresolved requests stay
unresolved; this skeleton grants no waiver of serving denial or preservation.
