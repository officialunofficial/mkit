# WP-1.20 readiness — full brief, early subset authorized

Status: **early documentation skeleton only (R-195, R-198)**. The full
readiness implementation waits for WP-4.18. This archived brief does not
activate its deferred scope or authorize staging, cloud or release actions.

The early subset creates the embedding host D35 environment definition, operator runbook,
user-owned empty evidence checklist and DRAFT REL-1 prompt. It changes docs
only; no workflow, script, configuration, version or runtime changes.
Run `just ci-scripts` and repository docs lint, self-review, then open a PR into
`feat/mkit-server`; do not merge it.

R-198 takes precedence over older language below: reset unsupported pre-launch
stores; no migration, backfill or old-row transformation. R-196 and R-197 are
withdrawn and retired. No new R-row, key tag, timer kind or protocol is allocated
here. The requested R-195 entry records preparation, not launch readiness.

Source: `<local notes>`,
Purpose onward, retained below for the later readiness pass.

## Purpose

Prepare a reviewable main-only staging conformance definition, configuration/runbook, complete local launch evidence checklist and DRAFT-only REL-1 execution prompt. The user can perform whole-launch external review and real Cloudflare staging measurements before separately authorizing release operations. The orchestrator does not execute those user gates.

## A. Fixed

HANDOFF4.10/R185 user boundary: all implementation into feat/mkit-server through independently reviewed feature PRs; user owns external full code/spec review, real staging/deployment and CPU/subrequest/cost measurements, feature→main merge commit,0.5.0 publishing/release. No squash feature→main. Existing full release machinery/signed attestation rules apply only to the future authorized release, not this task. Do not mark user gates completed from local wrangler or drafts.

## B. Root decisions

B1.1.20 defines staging CI and a local user-operated runbook against an ALREADY deployed isolated staging server. Workflow remains main-only and is not dispatched on feat/mkit-server. Do not insert automatic deployment or provisioning steps. Clarify local user staging before main merge versus later main-only workflow use; no hidden feature-branch checkout/dispatch workaround. Use names/placeholders for secrets, bindings, audiences, artifact pins and test repositories; never actual credentials or account APIs.

B2. Match the actual final profile/config grammar and key-role matrix. Include isolated bucket/DO namespaces and scanner/admin/preservation roles, rollback/old-state migration compatibility, safe cleanup commands for explicitly named staging resources, failure behavior and evidence capture. Commands requiring cloud/release authorization are plainly USER-RUN and stay unexecuted. Readiness records unrun external gates as pending, not false blockers for locally implemented prep.

B3. Create/update docs/plans/mkit-server/launch-readiness.md pinned to exact feature SHA: each critical implementation PR and independent review outcome, owning spec/R/dependency, final local commands/logs/pass/declaredskip counts, native/wrangler/release-default-off/opt-in evidence, actual budgets and known limitations. Include separate user whole-launch external review findings/validated fixes, staging and release approval slots. Preserve unresolved lean takedown requests and excluded rewrite/451/reinstatement/leases/GC/receipts/full admin features; do not advertise unsupported capabilities.

B4. Staging measurement matrix: deployed CPU p50/p95/max for ingest/decode/delta/extraction/proofs/private scanner reads/alarms; routed subrequests by kind and whole-request/alarm worstcase; JS+Wasm resident memory under concurrency; storage/billing/egress cost per upload/read/inspection/backlog; scanner latency; multicolo cache/purge convergence and held/global-block denial. Include network Outcome→Event correlation/duplicate ordering, disconnection settlement/reconciliation, signed hook header/body timeout/cancellation/redirect/oversize, authority/key rotation and profile incompatibility. Record exact artifact/config/limits/input geometry and reproduction procedure, no fabricated performance claims.

B5. Draft the REL-1 release PR prompt as an artifact marked DRAFT—NOT EXECUTED. It must require the user-owned whole-launch review, validated/adversarially reviewed fixes, staging evidence and explicit authorization before any feature→main/version/tag/publish/release/deploy action. Pin the completed local candidate and current release machinery references but require revalidation at future execution. Describe0.5.0/publication package scope and merge-commit rule accurately; do not execute or pre-authorize release actions in this turn.

B6. Registry1.20/readiness dependencies and REL-1 launch implementation terminal set must be explicit and acyclic, using lean5.6a/concrete5.5a-remote/proof prerequisites rather than historical unimplemented aggregates. Keep user-only release/staging semantics. Update R195/plan/CHANGELOG where needed and final local evidence files. No unsolicited extra postlaunch implementation in this prep bundle.

## C. Executor choices

Evidence layout, workflow/input/template names, reusable local runbook commands and practical measurement forms. Prefer concrete reviewable files over a checklist detached from actual final code/config. Avoid implementation trivia in user-facing product flows.

## D. Escalate

A required launch implementation/local gate remains incomplete; actual release/config contracts disagree; user-only execution would be necessary to claim a prepared result; static definition cannot remain main-only or needs cloud calls; sizecap exceeded. Report precise evidence and leave external gates pending. Do not ask for release approval until the concrete preparation is complete/reviewable; root continues authorized independent work.

## Verification

Read every claimed local result against final exact SHA/reports, verify dependency graph and file links, lint YAML/config/shell and required docs checks with no cloud execution. Check workflow cannot dispatch on feature branches or provision/deploy, secret values are absent, default-off/Paid/profile inputs match final code, user slots are unambiguously pending. No new tests that mirror documentation; meaningful static checks suffice. Independent two-pass adversarial review then PR merge into feat/mkit-server. Report all unrun user gates explicitly, and hand off DRAFT release prompt without invoking it.
