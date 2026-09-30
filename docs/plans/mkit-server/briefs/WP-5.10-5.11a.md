> Restart scope (R-198, 2026-09-30): this original brief is narrowed to purge delivery, automatic purge intents, the admin framework and ReadAuditLog. Manual PurgeCache moves to 5.6a (R-190); it is not exposed here. Automatic intents commit in the triggering state apply. No new cross-partition protocol, key or timer may be invented without an orchestrator ruling. Merge the latest feature base before final gates; integrate 5.4 if available, otherwise retain its snapshot seam and record the carry-forward.

## Purpose

- **Cache purge.** Every event that hides content (quarantine and hits, via 5.5a/5.6a seams, visibility change,
  administrative suspension, manual purge) invalidates local and shared caches durably, and retries until
  acknowledged.
- **Admin framework.** Operators call a signed, replay-safe, audited admin API, which the review and takedown
  operations build on.

## A. Fixed (do not change)

1. **SPEC-SERVER §16:** `mkit-admin:v1` bound to the exact body, path and origin; strict Ed25519; eight single-value
   headers; validity of at most 5 minutes; a durable nonce reservation with result replay (same-nonce retries return
   the stored result); persistent operation-id deduplication.
2. **The audit hash chain:** gapless, covering authenticated successes, failures, reads and automatic actions.
3. **SPEC-SERVER §14 and §16 purge semantics,** and `admin.proto` and its goldens.
4. **Serving fences stay authoritative** even while purge fails.
5. **Credential separation:** the admin, scanner, notice, token and write keys are all distinct.

## B. Decided (do not change)

### Part 1: WP-5.10, launch purge

- **B1. Triggers:**
  - quarantine, hits and takedown, through seams that 5.5a/5.6a call;
  - administrative suspension, through a seam;
  - visibility change (2.9);
  - manual `PurgeCache`.

  Lease-deletion triggers stay with 5.2, post-launch.
- **B2. Workers.**
  - Immediate local invalidation, via the Cache API delete, which is colo-local.
  - A real **global** purge through either the Cloudflare purge API, as an internal purger with an API token secret,
    or a signed durable remote sink. Pick one and document it.
  - Cover the object, repository, namespace, ref-path, proof and snapshot variants, with custom-key purge selectors.
  - Extend snapshot invalidation, and fence against a stale R2 refill.
  - **Keep the Workers Caching feature disabled** on gated entry points.
  - Retries keep the body and purge id, use fresh signing nonces, and stay pending until acknowledged.
- **B3. Native:** local cache invalidation plus the same durable purge-work model, with a remote sink option.
- **B4. Budget:**
  - Paid-only activation;
  - checkpointed alarm slices;
  - one combined budget charging enumeration and purge delivery;
  - recalculate the whole-alarm budget and record it in R-188.

### Part 2: WP-5.11a, admin framework

- **B5. Everything in A1.** Admin keys are configured on the native side (flags and key file) and the Worker side
  (secret). Both are default-off.
- **B6. Audit:**
  - the gapless hash chain;
  - a durable action intent before any effect;
  - **acceptance and audit before success**;
  - resumable cross-DO effects on Workers;
  - a `ReadAuditLog` operation.
- **B7. Operations in this PR:** only `PurgeCache` and `ReadAuditLog`, as the framework's first consumers. The review
  and takedown operations come in 5.6a.
- **B8. The launch profile** declares the supported admin subset instead of claiming full §16. Add an SPEC-SERVER §18
  row, with a version-history entry.

### Both parts

- **B9. Docs:** R-188 and R-189, a CHANGELOG line per WP, and the READMEs. Registry: 5.10 and 5.11a deps are
  explicit; 5.2 is only needed for lease-deletion triggers.

## C. Your decisions

Global purge mechanism (B2), audit storage layout, and module layout.

## D. Escalate (stop and report) if

- A global purge isn't feasible on Workers without a secret API token, and no signed remote sink is acceptable.
- Audit-before-success can't be guaranteed across Durable Objects.
- Production code passes 3,000 lines.

## Tests (required)

From the fact sheet's required tests:
- signature, role and mixed-credential failures;
- nonce and operation replay, including same-nonce stored results;
- crash-safe audit continuity;
- purge retries and backlog;
- a stale snapshot refill;
- every cache variant;
- the combined budget;
- default-off inertness;
- native and wrangler coverage.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy and the worker build.
- `scripts/vcs-worker-conformance.sh`, with a free `VCS_CONFORMANCE_PORT`.

### Production cap exception (user, 2026-09-30)

The user authorized a modest excess over the original 3,000-line cap to finish
local invalidation and snapshot fencing ("fine to pass the cap for a bit").
The final Rust production diff has 3,301 additions and 115 removals; the mandatory
review and gates still apply.
