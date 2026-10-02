# REL-1 main merge prompt — DRAFT

**DRAFT — NOT EXECUTED — USER-ONLY.** This prompt neither authorizes nor
initiates main merge or deployment. At the Workers launch there is **no version
bump, tag, crate publication or release**. Tagging and publishing require a
later, separate user decision and the then-current signed release machinery.

## Purpose and pins

Merge the completed Workers launch into `main` with its feature history through
the rebuilt `release/mkit-server-launch` branch and existing draft
[#1261](https://github.com/officialunofficial/mkit/pull/1261), using a **merge
commit, never squash**. Planning stays on `feat/mkit-server`; main ships product
docs, including [the operator guide](../../../operations/workers.md).
Follow-ups move to a new feature branch after launch.

Current as-built reference is `c3921b06effc0f38e2cdbe6f25b4e5a309018136`,
including #1259 and #1260. It is not the launch candidate. The requested embedding host
matrix is local evidence at an earlier source, with gaps and historical failures
retained in [readiness](../launch-readiness.md). FIX-preservation-memory,
PR-size cleanup, readiness/operator docs and delta review remain prerequisites.

| Required user-owned pin / decision | Status |
|---|---|
| Final feature candidate SHA and full/delta review ranges | UNRUN / user |
| Validated review findings, fix SHAs and independent review outcomes | UNRUN / user |
| Preservation memory fix (96 MiB to <=48 MiB), accepted whole-isolate headroom | UNRUN / user |
| Actual staging artifact/config/resource pins and conformance/drills | UNRUN / user |
| Deployed CPU/calls/memory/concurrency/cost and multicolo evidence | UNRUN / user |
| Accepted readiness record and supported configuration restrictions | UNRUN / user |
| Rebuilt release head, archived planning hashes and main gate results | UNRUN / user |
| Explicit user main merge authorization and resulting merge SHA | UNRUN / user |
| Separate production deployment authorization / outcome | UNRUN / user |
| Later tag/publishing/version decision | UNRUN / user |

## Preconditions

1. Re-read [registry](../registry.json), [plan](../00-plan.md),
   [readiness](../launch-readiness.md) and
   [SPEC-SERVER §18](../../../specs/SPEC-SERVER.md#18-conformance-scope).
   Confirm all REL-1 direct and transitive dependencies are merged/reviewed,
   with concrete multipart/extraction, sync inspection/scanner retrieval,
   all three lean takedown parts, purge/admin, reader/URL/default visibility,
   bounded ruzstd and activation. No dependence on withdrawn R-196/197 or
   post-launch 5.5a-0/5.5c/5.15/4.14b-2. Graph must be acyclic.
2. Require the preservation fix before selecting the candidate or merging main.
   Validate delta review and cleanup changes against the complete launch source;
   fixes require independent adversarial review and affected gates. Preserve
   many_refs and other open findings until source/evidence establishes their
   disposition. Accept no unresolved launch blocker.
3. Require user-owned real isolated staging at final artifact/config pins,
   including whole-isolate preservation worst-case memory and deployed CPU,
   physical calls/connections, cost, scanner timing and multicolo denial/purge.
   Local workerd, component PASS and sampled ~105 MB do not complete these gates.
4. Require explicit user acceptance of that concrete evidence and separate main
   merge authorization. No cloud call, automatic provisioning, feature-branch
   dispatch or production deployment is implied. Future staging automation is
   main-only against an already deployed staging server.

## User execution sequence

1. Fetch and record the final reviewed feature SHA and current main. Re-read
   the archive's `rebuild-release-branch.sh` and its guarded policy before use:
   `<repo>-planning-archive/2026-10-01-dd0c875c/`.
   The script rebuilds the release branch from an explicit feature SHA, archives
   planning, reapplies reference cleanup and merges `origin/main`. It never
   pushes, tags, publishes or deploys. There are already 12 planning paths added since the archive pin, including
   the 4.18 brief and launch evidence/harness records; its current policy will
   refuse them. New planning paths, changed reference anchors and unfamiliar
   conflicts cause refusal; review and extend archive
   policy explicitly when needed rather than bypassing guards. `--test` tree
   equality is only for its original pinned source/main, not a new candidate.
2. User runs the reviewed rebuild with the final feature SHA. Inspect cleanup
   and main-integration diffs, retain archive manifests/hashes, preserve all
   feature history and verify `docs/operations/**`, its README links, staging
   templates, product docs/specs and tests survive. No dangling planning links
   may ship to main. Resolve conflicts by preserving both sides' valid changes;
   re-review and revalidate affected code/config.
3. User pushes the rebuilt branch to update #1261, runs all required main gates,
   and leaves it draft until final review/acceptance is complete. Review the
   resulting source/artifact/config relationship to the accepted candidate.
4. Only with explicit user authorization, user merges #1261 into `main` with a
   merge commit. Record main SHA and candidate ancestry. Do not bump versions,
   create a release tag, publish crates/artifacts, dispatch release workflows
   or execute the release flow for this Workers launch.
5. User separately deploys the approved Workers artifact/config/resources using
   [workers.md](../../../operations/workers.md), records actual acceptance and
   retains rollback pins. Reset unsupported pre-launch stores; no migration.
6. If the user later decides to tag/publish, prepare a separate reviewable action
   under current [RELEASE.md](../../../RELEASE.md), release/crates workflows,
   signing and attestation policy. Revalidate package/version scope then; this
   draft makes no 0.5.0 commitment or preauthorization.

Launch is Paid indexed Multi/D34, permanent repository retention, leases/GC off,
optional sync inspection and lean preservation-backed takedown. Under `any`,
discovery is incomplete. Retain global denial, root/recovery ownership, legal
holds and unresolved requests; preservation is not full completion. Worker
proofs, Events, async holds/review, rewrite, notices and reinstatement remain
post-launch. Missing pins or decisions keep this prompt DRAFT.
