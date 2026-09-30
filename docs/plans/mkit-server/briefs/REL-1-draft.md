# REL-1 execution prompt — DRAFT

**DRAFT — NOT EXECUTED — USER-ONLY EXECUTION.** This document neither authorizes
nor initiates release. The early WP-1.20 executor and orchestrator do not execute
the main merge, version bump, tags, publish, release or deployment. Finalize
this prompt only after WP-4.18 and full readiness preparation are complete.

## Purpose and authority

User conducts the single Uno Workers launch under R-185 / R-198 at version
0.5.0. Implementation PRs land in `feat/mkit-server` through independent review.
The user owns whole-launch external code/spec review, actual Cloudflare staging
and measurements, release approval and every release/deployment action.

Starting reference only: feature SHA
`4d1c8fd435b4552c8716a60b606280cf63434ace`. It is **not a release candidate**.
Fill the following user-owned pending pins before execution:

| Required pin / approval | Value |
|---|---|
| Completed feature candidate SHA and full review range | |
| Final [readiness checklist](../launch-readiness.md) with accepted evidence | |
| External whole-code/spec review report and user sign-off | |
| Validated findings, fix SHAs and independent adversarial review outcomes | |
| Real staging artifact/config digests, conformance and CPU/calls/memory/cost evidence | |
| Explicit user authorization for main merge/version/tag/publish/release/deploy | |
| Reviewed version-bump/release commit and resulting main merge SHA | |

## Preconditions

1. Re-read current [registry](../registry.json),
   [plan](../00-plan.md), [conventions](../conventions.md),
   [release runbook](../../../RELEASE.md),
   [release workflow](../../../../.github/workflows/release.yml),
   [crates workflow](../../../../.github/workflows/crates-publish.yml),
   [server artifact feature list](../../../../scripts/release/mkit-server-features)
   and current release signing/attestation policy. Revalidate these references
   at the final candidate; this draft does not amend release machinery.
2. Confirm every REL-1 dependency and concrete 5.5a (sync)/R-193/5.6a/4.18,
   purge/admin, extraction and proof prerequisite is merged and independently
   reviewed. Reconcile the historical registry aggregates/activation edges
   without cycles. Do not depend on withdrawn R-196/R-197.
3. Require user-owned external review of the **entire** launch code and specs.
   Validate findings against source; fixes get their own adversarial review and
   affected gates. Accept no unresolved release-blocking finding.
4. Require real isolated staging evidence and explicit user acceptance at the
   candidate/config pins, including whole-alarm accounting and cost per operation
   and per 100 KiB. Local wrangler and old milestone reports do not fill these
   gates. Complete final local conformance/default-off/opt-in evidence as well.
5. Require explicit user authorization after those concrete records are
   reviewable. No feature-branch workflow dispatch, cloud provisioning or
   deployment is implied by this draft. Later staging CI remains main-only
   against already deployed staging.

## User execution sequence

1. User prepares and reviews the 0.5.0 version/release change under the current
   release process. Preserve the server-free CLI and exact approved artifact
   feature sets; exclude test seams. Record the final reviewed feature SHA.
2. User opens the launch PR from `feat/mkit-server` into `main`, runs all required
   main gates and merges **with a merge commit, never squash**. Record the
   resulting main SHA and its relationship to the approved candidate. Revalidate
   affected evidence if integration changes code/config.
3. User creates the authorized signed annotated `v0.5.0` tag only at the reviewed
   main-reachable commit, following current release signing and threshold /
   attestation requirements. Never tag the feature branch as a release shortcut.
4. User publishes through the current signed release flow: CLI/server archives,
   approved container image, npm Wasm, workspace crates and configured docs/proto
   channels. Publish `mkit-server`, `mkit-server-native` and
   `mkit-server-conformance`; `mkit-server-worker` stays unpublished. Follow
   current `docs/RELEASE.md` and the plan's signed-tag-first cargo-publish guidance;
   avoid duplicate publishing and confirm organization credentials/owners.
5. User verifies signatures, checksums, provenance, SBOMs, actual channel outcomes,
   team crate ownership and the plan's private linked GHCR package requirement.
   Reconcile any disagreement between current machinery and the launch plan
   before publication; do not silently weaken the signed-artifact rules.
6. User deploys the approved Workers artifact/config under separately authorized
   production resources and exact origins, using the final
   [operator runbook](../launch-operations.md). Verify conformance, advertised
   active capabilities, sync inspection, global-block denial, preservation/audit, durable
   purge delivery and rollback readiness. Record actual outcomes.

The Uno profile is Paid-only indexed serving/inspection, storage leases off,
permanent serving retention, serving GC off and lean takedown. Unresolved
requests remain unresolved. Rewrite, 451 notices, reinstatement, storage
receipts, full admin and post-launch leases/GC are not launch capabilities.
Reset unsupported pre-launch stores under R-198 B1; do not add migration or
old-row compatibility. Any missing prerequisite or pin keeps this prompt DRAFT.
