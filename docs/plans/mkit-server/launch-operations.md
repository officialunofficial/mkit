# Uno launch operator runbook skeleton

Status: **SKELETON — USER-RUN ONLY, unexecuted** (WP-1.20 / R-195 / R-198).
Final commands and exact resource identifiers wait for 4.18 and final WP-1.20.
This document authorizes no staging, secret, cloud or release operation.
Use the [D35 definition](staging-uno.md) and [readiness record](launch-readiness.md).

## Deploy order

1. User confirms the completed candidate SHA, independent implementation reviews,
   whole-launch external review and the separate authorization for isolated
   staging. Confirm final 4.18 profile grammar and artifact digest; do not use
   `test-faults` to bypass the release adapter's current indexed-mode refusal.
2. User records exact staging Worker/DO namespace and bucket identifiers,
   canonical server/hook/scanner/purge audiences, placement and Paid account.
   Provision private staging resources with all five DO classes, serving,
   backups, snapshots and separate preservation storage. Keep ingress closed.
3. User installs dedicated secrets and public trust lists, retention and key
   list configuration. Prepare hook receiver, scanner and purge sink first;
   verify their audiences, permitted roles and replay/deduplication behavior.
   Concrete scanner provisioning is R-193; preservation 5.6a. No publication Events at launch (R-200).
4. User deploys the exact opted-in release artifact with consistent fetch and
   every DO's configured entrypoint/alarm wiring from 4.18. Use a fresh store
   for first activation; do not convert persisted addressing/sharding modes.
5. User mounts only the D35 staging hostname behind approved network controls.
   Check honest GetServerInfo, signed push/clone, HTTP reads, native proofs and Worker proof refusal, optional sync scanner
   verdicts, global-block denial, audit and delivery reconciliation.
   Run final local and deployed conformance and failure drills; fill the evidence
   slots. Choose CPU/pack/concurrency limits from deployed evidence.
6. User approves release separately. The [DRAFT REL-1 prompt](briefs/REL-1-draft.md)
   governs the future main merge, tags, publish and production deployment.
   Before-main staging runs locally under user control; later staging CI runs
   against already deployed staging on main only.

## Rollback and containment

User first closes ingress and stops writers/byte-serving traffic if an invariant
fails. Retain protected data, audit, unresolved takedown work, purge
intents and evidence. Record the failed artifact/config and outstanding work.

Rollback to a prior artifact only when it implements the **same current store
contracts**, persisted addressing/sharding/authority modes, role matrix and timer kinds.
Sync-only inspection keeps no obligations or holds (R-200); removing the scanner
only stops scanning future pushes and must never be used to publish rejected content. Do not restore an older snapshot
that could remove a global block or legal hold. Pending purge delivery does not
relax authoritative serving denial. If compatibility is uncertain, leave the
deployment offline and use the pre-launch reset procedure for disposable test
data. There is no cross-format downgrade/migration promise.

Preservation evidence, active legal holds and a meaningful retained audit need
their owning 5.6a recovery policy; do not delete them to make rollback succeed.
Production incident recovery is not supplied by this pre-launch skeleton.

## Pre-launch store reset (R-198 B1)

Stores written by unreleased `feat/mkit-server` builds are unsupported. **Reset
them; do not migrate, backfill, add era discriminators or transform old rows.**
This does not change released mkit-core wire/object contracts or current row
producer contracts. Wrangler class declarations are separate from row migration.

1. User enumerates the exact disposable staging resources: Worker identity,
   all five DO namespaces, `mkit-vcs-objects-staging`,
   `mkit-vcs-backups-staging`, `mkit-vcs-published-staging`, and the final 5.6a
   preservation resource. Verify none is shared with production or another lane.
2. User takes staging offline, stops CI/writers/scanner/delivery work and retains
   diagnostics. Verify that no preservation/legal-hold or audit obligation
   requires retention before deleting any test resource. If it does, keep that
   resource offline and obtain its owning operation's reviewed disposition.
3. User replaces the disposable deployment with fresh DO storage identities and
   fresh private buckets. Never clear only a marker or a subset of partitions;
   never attach old packs, backups or snapshots to an empty metadata store.
   Exact scoped resource replacement/cleanup commands wait for final 4.18 / 1.20;
   no wildcard deletion command is provided here.
4. User installs final keys/config, uses a fresh snapshot identity, recreates the
   CI test repository and runs conformance from an empty store. Confirm the old
   endpoints cannot serve and old artifacts cannot access the fresh resources.
   Only then may explicitly named, disposable old staging resources be removed.

Do not import an unreleased store or old backup as a migration shortcut.

## Key rotation

All steps are user-operated and require the final role-specific contract.
Record ids/fingerprints and rollout times; never log private seeds or tokens.

| Role | Rotation procedure / acceptance check |
|---|---|
| Ticket MAC | New unique id first, old entries retained on every instance for at least seven days after rotation; verify new tickets/part receipts and existing-session completion. Follow [upload-key-rotation.md](upload-key-rotation.md) |
| Hook / purge delivery | Publish overlapping public trust list at each receiver, switch outgoing signer, retire old key after longest request validity and trust-cache propagation. Retry durable deliveries with fresh nonces; preserve reservation/purge deduplication |
| Scanner / capability | Install a unique new `active <id> <64-hex secret>` in `SCANNER_RETRIEVAL_KEYS` on every instance; move the old key to `retained <id> <64-hex secret> <retired_at_ms>`. Retained verification ends 301,000 ms after retirement, covering the maximum capability lifetime. Overlap scanner public keys in `SCANNER_KEYS`, switch the scanner's separate signer, then remove the old public key to revoke it. Each Inspect retry uses a fresh capability with the same inspection id; capability expiry and fresh open-ticket checks remain mandatory. Prove bounded assigned reads, foreign/expired/consumed/closed-ticket/global-block denial and configured role-collision refusal; scanner access grants no write/admin/ReadPreserved permission. Activation remains default-off, Paid-only and gated by 4.18 |
| Admin | Add bounded-validity role-bearing public key, switch offline signer, retire old key after outstanding envelope validity and replay records expire (§16.3). Retiring keys never erases audit history |
| Authority fence | Keep separate namespace permissions. Stop authorization and persist/complete the signed target barrier before acknowledging revocation; a key-list change alone does not complete that barrier. Follow final 2.16 / 4.18 contract |
| URL token | Follow active/retained key grammar and public-list refresh; retain verification for outstanding tokens per final limits. Prove unknown/retired token denial and role collision refusal |
| Preservation signer | 5.6a / 4.18 finalize §14.7 / §15.5 publication, pinning and retained-signature verification. Rotation never deletes preservation or drops legal holds |

Compromise handling uses the owning revocation contract; it is not ordinary
overlap rotation. Never make a failing role work by substituting another key.

## Failure drills and evidence

These are unrun scenarios for a user-authorized isolated deployment. Inject
failures only into explicitly named staging services. Capture exact artifact,
config/limits, timestamps, durable ids, queue depths, redacted logs and final
reconciliation; store links in the readiness record. No drill below has passed.

| Drill | Injection | Expected contract and recovery | Finalizing lane |
|---|---|---|---|
| Hooks down | Authorize/Admit timeout, connection failure, non-2xx, invalid or oversize response; redirect and cancellation | Decisions fail closed with retryable unavailable and no state write; preserve §8's otherwise-authorized public-read classification exception. Outcome delivery stays durable until acknowledgement; restore receiver and reconcile by reservation id | Existing 3.9c; integrated 4.18; publication Events excluded at launch |
| Scanner down | Unreachable Inspect endpoint; invalid verdict; private retrieval expiry/revocation mid-read | Sync fail-closed inspection returns unavailable and nothing commits. Restore the scanner; prove no public/private oracle and global-block denial | 5.5a / R-193 / 4.18 |
| Scanner timing | Cold and warm global-denial proof plus every bounded range needed for pack decoding | Measure against actual Inspect timeout before activation. Worker HOOK_TIMEOUT_MS stays default 5,000 ms / maximum 30,000 ms; native/core retrieval supports up to 300,000 ms. Fail-closed retries keep tickets open and mint fresh capabilities, but timing must be proved for the deployed profile | 4.18 |
| Purge sink down | Timeout/non-2xx or lost acknowledgement during overlapping block/visibility intents | Retain intents, retry with backoff, reconcile duplicates; local invalidation and authoritative global-block checks remain effective while sink is down. Manual acceptance returns purge id, not completion; later audit proves completion | 5.10 / 5.6a / 4.18 |

R-193 scanner retrieval prefetches up to six first descriptor pages
concurrently, with at most 3 MiB of raw descriptor values (within the
4 MiB contract ceiling) plus bounded
key, cursor and collection overhead. Continuations and nested
inventory, chunk and action proofs remain sequential under existing bounds,
preserving fresh checks and the shared call budget. Host tests cover
production Worker DO/R2 adapters, two-pack independent decoding and ranges.

Local mounted diagnostics returned one cold HTTP 206 after 18.459 s and
another read's uniform expiry HTTP 404 after 35.454 s. A subsequent request
returned runtime HTTP 500 before the fixture ran. Local workerd restarted
while exercising the 4,096 SQLite DOs; sampled RSS was 1.36 GiB. The cause
was not established. Mounted scanner conformance and production timing
remain unproven; the optional mounted scanner harness is not retained.
At 4.18, measure latency and resource use for the actual profile and retain
cold and warm end-to-end evidence for all pack ranges and the scanner's independent
external-base resolver/cache before activation; capability scope stays limited
to raw added packs. No timeout or activation gate is relaxed by these probes.

Also capture Outcome duplicates, disconnect settlement,
multicolo block denial and cache convergence, key rotation and incompatible
profile startup refusal. Do not claim takedown completion solely to drain a failed drill's backlog.
Hits and late-holder
requests remain unresolved until their actual applicable completion.

## Activation and local evidence handoff

Before any user-owned operation, reconcile the concrete candidate and its
[launch matrix](launch-conformance.md) with the [evidence record](launch-evidence.md).
The profile accepts zero inspectors; if inspection is enabled, provision up to
four sync `fail_closed` inspectors plus R-193 retrieval. Refuse async,
publish-on-unavailable and clear deadlines. There are no inspection holds,
hold review operations or publication Events. Native proofs are required
reference evidence; Worker `?proof=1` remains unsupported and discovery must
omit proof capability.

The Uno Kit demo uses `any` plus `UNSAFE_OPEN_NAMESPACES=true`. Its takedown
responses must report incomplete holder discovery while enforcing configured
global denial and preservation. An allowlisted staging variant records its
explicit namespace list. Do not change the policy to conceal unresolved work.

Admin/takedown activation requires `ADMIN_KEYS`, preservation storage,
explicit retention, dedicated signing key and published public-key list, and
signed HTTPS `cache-purge`. A service binding does not replace that purge
channel requirement. The supported Worker subset is `Takedown`,
`GetTakedown`, `ListTakedowns`, `ReadPreserved`, `SetLegalHold`, `PurgeCache`
and `ReadAuditLog`; `Reinstate` and hold review remain unavailable.
Phase 1 prerequisite refusals are checkpoint evidence only. User staging
operations require the completed phase 2 matrix and separate authorization.
