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
   for first activation; do not convert persisted inspection/sharding modes.
5. User mounts only the D35 staging hostname behind approved network controls.
   Check honest GetServerInfo, signed push/clone, private reads/proofs, sync scanner
   verdicts, global-block denial, audit and delivery reconciliation.
   Run final local and deployed conformance and failure drills; fill the evidence
   slots. Choose CPU/pack/concurrency limits from deployed evidence.
6. User approves release separately. The [DRAFT REL-1 prompt](briefs/REL-1-draft.md)
   governs the future main merge, tags, publish and production deployment.
   Before-main staging runs locally under user control; later staging CI runs
   against already deployed staging on main only.

## Rollback and containment

User first closes ingress and stops writers/byte-serving traffic if an invariant
fails. Retain protected data, audit, unresolved inspection obligations, purge
intents and evidence. Record the failed artifact/config and outstanding work.

Rollback to a prior artifact only when it implements the **same current store
contracts**, persisted inspection/authority modes, role matrix and timer kinds.
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
| Hook / purge delivery | Publish overlapping public trust list at each receiver, switch outgoing signer, retire old key after longest request validity and trust-cache propagation. Retry durable deliveries with fresh nonces; preserve reservation/event/purge deduplication |
| Scanner / capability | R-193 finalizes overlap, assignment lifetime, expiry and bounded-segment revocation. Prove new assigned reads, stale/foreign/expired denial and no write/admin/ReadPreserved access before retiring old keys |
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
| Hooks down | Authorize/Admit timeout, connection failure, non-2xx, invalid or oversize response; redirect and cancellation | Decisions fail closed with retryable unavailable and no state write; preserve §8's otherwise-authorized public-read classification exception. Outcome delivery stays durable until acknowledgement; restore receiver and reconcile by reservation id | Existing 3.9c; Event durable/reordered replay 5.15; integrated 4.18 |
| Scanner down | Unreachable Inspect endpoint; invalid verdict; private retrieval expiry/revocation mid-read | Sync fail-closed inspection returns unavailable and nothing commits. Restore the scanner; prove no public/private oracle and global-block denial | 5.5a / R-193 / 4.18 |
| Purge sink down | Timeout/non-2xx or lost acknowledgement during overlapping block/visibility intents | Retain intents, retry with backoff, reconcile duplicates; local invalidation and authoritative hold/block checks remain effective while sink is down. Manual acceptance returns purge id, not completion; later audit proves completion | 5.10 / 5.6a / 4.18 |

Also capture Outcome duplicates, disconnect settlement,
multicolo block denial and cache convergence, key rotation and incompatible
profile startup refusal. Do not release a hold, waive an obligation or claim
takedown completion solely to drain a failed drill's backlog. Hits and late-holder
requests remain unresolved until their actual applicable completion.
