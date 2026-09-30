# Executor prompt: WP-4.18 (launch), Paid Workers activation and integrated conformance (R-194). Starts now, in two phases.

Run locally in `/Users/vitormarthendalnunes/Documents/21.Uno/04.Mkit/mkit`.

**Definition of done:** an open PR into `feat/mkit-server`, after phase 2. Don't merge it.

**Read first:**
- `~/.cache/mkit-orch/scratchpad/prompts/executor-common-external.md`, including the R-198 section;
- `~/.cache/mkit-orch/scratchpad/plan/R-198-restart-ruling.md`, including R-200;
- the base brief, `~/.cache/mkit-orch/scratchpad/prompts/WP-4.18-codex.md`, sections A, B1–B7, C, D and Verification;
- `~/.cache/mkit-orch/scratchpad/research/WP-4.18-codex-research.md`;
- `docs/plans/mkit-server/staging-uno.md`, `launch-operations.md` and `launch-readiness.md`;
- SPEC-SERVER §18 (the launch profile) and SPEC-HTTP-OBJECTS.

**This prompt wins over the base brief where they differ.** Ignore the base brief's QUEUED line and its
HANDOFF/gpt/root wording.

**Setup:**
- **Worktree:** `.claude/worktrees/wp-4-18`, from a fresh `origin/feat/mkit-server`.
- **Branch:** `mkit-server/wp-4-18-launch-activation`.
- **PR title:** `feat(server): Paid Workers launch activation and integrated conformance (WP-4.18)`.
- **Cap:** 3,000 non-test Rust production lines. Docs, config templates and generated code don't count.

Your first commit copies this prompt plus the base brief, from "Purpose" on, to
`docs/plans/mkit-server/briefs/WP-4.18.md`.

## The launch scope changed since the base brief (decided)

- **Inspection is sync-only (R-200) and optional.**
  - Allowed: no inspector, or up to 4 sync `fail_closed` inspectors with R-193 scanner retrieval.
  - Refused: async inspectors, publish-on-unavailable and clear deadlines.
  - The launch has no holds, no hold review ops and no publication Events. 5.15 and 5.5c are post-launch. Remove them
    from the matrix and the budgets.
- **Proofs are native-only at launch.** Worker proofs (4.14b-2) are post-launch. The release Worker keeps HTTP
  `?proof=1` unsupported and must **not** advertise proof capability. Native advertises and serves proofs.
- **Namespace policy:** `allowlist`, or `any` with `UNSAFE_OPEN_NAMESPACES=true`. The Uno Kit demo (UNO-420) runs
  `any`. Under `any`, takedown works but reports discovery as incomplete (the 5.6a-2 ruling). Update `staging-uno.md`
  accordingly: it currently says "allowlist" only.
- **Features are opt-ins inside the Paid indexed launch profile.** Each opt-in validates its complete configuration at
  startup:
  - **HTTP serving and URL tokens:** `URL_TOKEN_KEYS` distinct from the other key roles.
  - **Signed hooks and the service binding:** see 3.9c.
  - **Inspection plus R-193 retrieval:** the scanner allowlist and a dedicated retrieval key.
  - **Admin and takedown:** `ADMIN_KEYS`. Enabling takedown requires the complete §14.7 preservation configuration:
    the bucket, explicit retention and the preservation signing key. It also requires signed HTTPS `cache-purge`.
    Refuse partial configurations.

  Leases stay off and GC stays off/refused, with permanent retention.
- **Expose `Takedown` on the Worker admin mount** (together with `GetTakedown`, `ListTakedowns`, `ReadPreserved`,
  `SetLegalHold`, `PurgeCache` and `ReadAuditLog`) when admin plus takedown is configured. Replace the unit test that
  asserts Takedown is unexposed (`mkit-server-worker/src/admin.rs`) with the configured and unconfigured assertions.
  Hold ops and `Reinstate` stay unexposed.
- **Fix the stale `apps/vcs-worker/README.md`:**
  - the 64 MiB pack cap (now `MAX_PACK_BYTES`, 1 GiB default, up to 4.995 GiB, plus the 65 MiB request cap and 8 MiB
    minimum part);
  - "any valid key can write, no allow-list";
  - "indexed mode unavailable";
  - the per-signer write quota: it applies only with default admission, and a remote Admit replaces it (no internal
    charges).

  Also document that HTTP responses are always `application/octet-stream` with nosniff and the sandbox CSP.

## Phase 1: now, against the merged base

Merged so far: 5.4, 5.10/5.11a, 4.10b-1, 4.14b-1, 5.5a-sync and 5.6a-1.

Implement:
- config grammar and startup validation;
- the Paid launch-profile selection;
- the GetServerInfo capability honesty rules;
- the Worker admin mount changes;
- the whole-alarm and request budget audit (B3, minus Events and async inspection);
- the conformance harness and the evidence-matrix skeleton;
- the README and docs fixes.

**Lifting the release `INDEXED_MODE` refusal** (`mkit-server-worker/src/adapter.rs`, "requires WP-4.10b") needs
4.10b-2's extraction driver. Implement the lift behind a startup check that fails closed with a precise diagnostic
while the extraction driver is unavailable. Likewise, takedown activation fails closed until 5.6a-2's preservation
lands, and retrieval until R-193.

When phase 1 is done, commit, report "phase 1 checkpoint", and wait.

## Phase 2: after 4.10b-2, 5.6a-2 and R-193 merge

The user will tell you when. Then:
- merge the base;
- remove the fail-closed placeholders as each prerequisite lands;
- run the complete native and real wrangler launch matrix (base brief B4/B5, reduced as above), including the opted-in
  release Worker runtime, not just test-faults;
- build the evidence matrix (B6) pinned to exact SHAs;
- run all gates;
- do the two self-reviews;
- open the PR.

## Rules

- **Known flakes:** the recurring native timer-conformance failures must be reproduced on an unchanged base before you
  classify them. Record them; don't fix them here unless they're caused by this branch.
- **No new R-row, tag, timer or protocol.** R-194 is yours.
- No cloud calls, deploys or staging.

## Escalate

The base brief's section D, plus: if a launch-profile opt-in can't be validated at startup without new durable state.

---

# Base brief (overridden above where different)

## Purpose

Enable one explicit Paid Workers profile only when complete publication, inspection, private scanner access, proofs, purge/audit and lean takedown safeguards are available. Prove the entire integrated path with native and actual local Worker conformance; prepare honest external staging evidence slots without running cloud operations.

## A. Fixed

R-185 replaces all historical Stage1/Stage2 activation timing. Uno profile: indexed serving and inspection, leases=false, permanent retention, GC disabled. Non-open write policy, ticketed uploads with threshold0, fail-closed scanner and explicit async deadlines. Held/blocked bytes deny writers and readers through every public/reuse/cache/relay path; remote scanner has only its assigned private scope. Lean unresolved takedown permission does not waive verified preservation, retention/legal hold/global denial/audit or14.7 key requirements. Rewrite/451/reinstatement remain excluded and cannot be advertised.

Keep native as reference/test server; no Uno source edits. Specs win over old prompts, adapter shortcuts and size estimates. No test-faults route/config in release production. Local wrangler success cannot establish deployed CPU/cost/multicolo safety.

## B. Root decisions

B1. Production opt-in explicitly selects the Uno launch profile and Paid plan. Default-off core/native/Worker wire and config remain compatible. Remove the release INDEXED_MODE refusal only here, after all concrete prerequisites merge. Startup rejects Free, open/opaque inspection, missing indexed verification/extraction/HTTP/proofs/private retrieval, no retention, enabledGC/storageleases, missing signed hook/scanner/admin/preservation configuration, absent deadline, contradictory/unknown role/binding/audience config and key reuse across roles. Check old persisted authority/publication migration states according to owning contracts; a mismatched executor cannot suppress durable mode to accept writes.

B2. GetServerInfo advertises implemented ACTIVE capabilities honestly, including explicit false storage leases where the protocol requires it; no async inspection before a complete active scanner. No default-full-profile claim, receipt/notice/rewrite capability inflation or false exposure of inert operations. Document exact configuration grammar and minimal bindings/secret NAMES, never secret values. Configure canonical HTTPS hook audiences and all required14.7 preservation/receipt key/public-key list protections; resolve any concrete lean-profile conflict through root rather than silently skipping requirements.

B3. Audit and enforce WHOLE alarm/request budgets across verification, extraction, relay, Outcome, reconcile, snapshots, publication recheck, inspection, purge, content requests, migration and Events. Count routed DO/R2/Fetch operations, hook-before-apply reads, CAS retries, source passes/dedup and private retrieval; local physical-DO operations and remote calls are distinguished. Keep existing256 calls/slice and48MiB extraction allowance,100-op/seven-ticket writes, <=6 simultaneous outgoing connections and bounded cold scans. Reserve real headroom and coordinate handlers instead of granting each kind an independent full budget. Model frozen clock, multiple due kinds and adversarial retry/cursor paths. Do not raise project budgets to platform maxima.

B4. Conformance runs native and ACTUAL wasm/wrangler request/timer/stream lifetimes. Cover complete inspected sets (surplus/small/manifests/chunks/Verified reuse/chain intermediates), coherent paired publication, all public read/token/snapshot/proof surfaces, every writer/reuse/delta/dedup/AlreadyPresent/global denial path, private assigned staged/held canonical bytes and blocked preservation separation. Include races/restart/lost reply between authority revocation, upload backend/marker/apply, mode initialization, publication and source/projection migration, scanner supersession/deadline, A+B/B+C extraction group overlap, gp/late-holder delivery, purge and audited review.

B5. Payment/admission is common for raw/proof/private-token public HTTP. Exact proof size before admission, no build/payload reads on304/416/challenge/deny, HEAD settlement0, partial actual-byte ReadServed and abort-before-first-byte, cancellation/header/body timeout plus durable completion/reconcile arbiter. Signed Worker Fetch/Delay behavior must be verified on real wasm runtime, including redirect refusal, oversize responses and fresh nonce retry. Event-before-Outcome/duplicates/reordering never falsely report Delivered or change committed outcomes. Add permanent focused regressions for any integrated defect; fixes receive independent review.

B6. Build an itemized complete launch evidence matrix pinned to exact feature/head SHA and every prerequisite PR/review outcome. Separate local native/wrangler PASS from unrun user external whole-code/spec review, actual Cloudflare staging, CPU/subrequest/resident-memory/cost measurements and multicolo behavior. Known flakes require isolated reproduction on unchanged base before classification, not automatic waivers. Missing deterministic local behavior blocks activation/PR. No remote deploy/workflow invocation.

B7. Registry4.18 aggregates all concrete serving/inspection/lean foundations without reverse activation edges from5.11a/5.5a. Add R194 and accurate dependencies; REL-1 uses lean5.6a and concrete remote/proof prerequisites rather than incomplete historical full aggregates. Prepare/update launch-readiness.md with user gate slots and excluded features, but do not mark1.20/staging or release executed. The separate final readiness/docs WP prepares1.20 templates and draft REL-1 prompt; no version bump/publishing in this WP.

## C. Executor choices

Config names/module boundaries, compatible startup diagnostic wording, counter instrumentation, conformance scheduling and retained evidence layout. Decisions and measured maxima must be reviewable; product flows contain only configuration needed for meaningful operation.

## D. Escalate

Any prerequisite remains default-inert/partial; fail-closed isolation/no-oracle cannot hold under a race; shared budgets or canonical proof/source retrieval cannot fit; preservation14.7 conflicts with lean launch; cap3000 exceeded; actual wasm runtime lacks required timer/body/cancellation behavior. Preserve checkpoint and propose a concrete additive fix or split; do not enable partial production behavior or fabricate staging evidence.

## Verification

Run all current common/full/area local gates at final immutable head, plus complete native and wrangler launch matrix. Gates include release/default-off regression and opted-in release Worker runtime, not test-faults alone. Count whole-alarm calls/ops/resident work and concurrent response lifetimes with adversarial inputs. Keep per-worktree ports/processes isolated; serialize known high-memory models appropriately. Two independent self-reviews including security/spec/crypto audit, followed by independent adversarial PR review. Open PR with exact commands/logs, measured limits and remaining user-owned staging/external review slots. No cloud/CI polling.


## Addendum (2026-09-30): embedding support for Uno Kit (UNO-420), in scope for 4.18

- Budget: up to about 350 extra production lines; the cap becomes 3,350.
- Phase: 1 or 2.
- **Scope:**
  1. **The documented embedding surface.** Module docs plus a README section listing the supported public API for
     embedding: `adapter::serve_with` / `fetch_with`, `adapter::ns_object_with`, `WorkerConfig` (including a
     programmatic `WorkerHttpMountConfig`), `ns_object::NsObject`, `classes::ShardClass` and the `HookSet` /
     `Authorizer` / `Admission` / `OutcomeSink` traits.
     - The crate stays `publish = false`, consumed as a git dependency pinned to the release tag.
     - Mark the surface "supported, 0.x; breaking changes called out in the CHANGELOG".
  2. **Close the builder gap.** Today `ns_object_configured` (published-view config) can't take a custom outcome sink,
     and `ns_object_with` can't take the published-view config. Add one constructor or builder that takes both.
     Update the stale "Stage 2" wording.
  3. **A `mkit_server_worker::durable_objects!` macro** (or an equivalent documented pattern if a `macro_rules!`
     wrapping workers-rs `#[durable_object]` doesn't expand cleanly across crates). It generates the five DO classes
     (RefStore, NsCoordinator, RefShard, RepoIndexShard and ContentIndexShard) with fetch and alarm glue, given a sink
     factory and a config. `apps/vcs-worker` must use it, which proves it. If it can't work, document the 140-line
     pattern from `apps/vcs-worker/src/worker_impl.rs` as the example instead, and say why.
  4. **An example crate, `examples/embedded-worker`** (or `apps/`, whichever the repo convention is). Custom hooks that
     call another Worker over a service binding; an in-process `serve_with` call with a constructed request,
     including a streamed `UploadPart` body. Add it to the wasm32 check.
     - Document that the envelope audience must equal `WorkerConfig`'s audience (`AUTH_AUDIENCE`, the exact public
       origin) regardless of the constructed request's URL.
     - Document that in-process dispatch shares the isolate's CPU, memory and subrequest budget with the caller.
     - Add a wrangler test that an in-process streamed `UploadPart` works end to end.
  5. **A feature and size table** in the README: the minimal feature set for the launch profile (with and without
     `http-objects` / `signed-http-hooks`), and the measured release wasm size, raw and gzip, for each, against the
     Workers script size limits. Record the exact build commands.
- **Not in scope:** a `ListRepos` RPC. It's post-launch.

### Addendum 2 (2026-09-30): embedding gaps found by Uno Kit's questions (cap now 3,500)

6. **A custom purge sink.** The DO builder (addendum item 2) also accepts an optional
   `Arc<dyn mkit_server::purge::PurgeSink>` (plus `LocalInvalidation`), so an embedder can purge in-process. Today
   `ns_object_inner` hard-wires `purge_from_env` (a signed HTTPS `cache-purge` hook). Env-based configuration stays
   the default. Startup validation must accept "takedown on plus a custom sink" without `HOOK_ROLES=cache-purge`.
7. **Admin mount placement.** Add a `WorkerConfig` option to keep AdminService **off the public fetch path**, while
   exposing an embedding entry point (for example `adapter::serve_admin_with(req, env, &cfg)`) that the host calls for
   admin requests it routes itself.
   - The default stays as today: mounted at `/mkit.server.admin.v1.AdminService/` when `ADMIN_KEYS` is set.
   - `ADMIN_KEYS` stays the authentication in both modes.
8. **Programmatic pipeline knobs for embedders.** Expose on `WorkerConfig`, programmatic only with no env vars:
   - `RefPolicy`/`RefRule`, for fast-forward-only and signer rules, e.g. immutable tags via a fast-forward-only
     `refs/tags/*` rule plus a no-delete policy if one exists;
   - the takedown enablement you already wire (`takedown_denial`).

   Document them in the embedding section.

- **Also document in the embedding README section:**
  - reserved path prefixes: Connect `/mkit.transport.v1.TransportService/`, `/mkit.server.admin.v1.AdminService/`,
    any path containing `/-/` when HTTP serving is mounted, `/.well-known/mkit-*`, `/_mkit/`, and `/__mkit_test/` in
    test builds;
  - that a host may use any other prefix, such as `/_uno/`. Namespaces and repo names can't start with `_`.

Executor phase assignment: both embedding addenda will be implemented and verified in phase 2. The final binding production-line cap is 3,500 (addendum 2). Phase 1 removes the extraction and retrieval placeholders after merged PRs #1244 and #1243; only WP-5.6a-2 preservation remains a startup refusal. The separate timer-12 repair is PR #1245 (`3038c158`), to merge before phase 2.

A configured custom purge sink is the expressly authorized embedding alternative to the environment-based signed HTTPS purge hook. Public/admin-separated mounting and programmatic RefPolicy/takedown options remain phase-2 work.
