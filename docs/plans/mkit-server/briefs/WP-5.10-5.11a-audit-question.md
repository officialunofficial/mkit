# Ruling requested: automatic purge audit across partitions

Work stopped at the user's request on 2026-09-30. No PR or push.

## Question for the orchestrator

What approved mechanism should connect an automatic purge intent, committed in the same apply as its triggering state change, to the deployment-wide gapless audit chain when the trigger and admin ledger live in different partitions?

Please specify the allowed acceptance/completion audit semantics and recovery owner when the source apply loses its CAS or the executor crashes. May the root record an accepted but not yet applied purge, and what existing mechanism resumes or resolves that acceptance? The executor will not invent a cross-partition protocol, key, timer or storage primitive.

## Concrete source evidence

- `rust/crates/mkit-server/src/admin/ledger.rs:212`: `SystemAudit::plan` ignores the supplied trigger partition. Lines 238–251 append an `ok` audit entry and `ai` intent using a separate apply to the root, then return an empty batch.
- `rust/crates/mkit-server/src/pipeline/purge.rs:46`: the caller subsequently reads the trigger partition and plans the `cp` work, `cg` refill fence and kind-11 timer. Those effects join the caller's state-change apply; the earlier root audit does not.
- Thus a failed caller apply can leave the root audit/intent without accepted purge work. There is no recovery consumer for `ai` in the draft. This also occurs when both applies happen to use the same partition.
- SPEC-SERVER §16.6 requires automatic purge system entries and a gapless chain; original B6 requires durable action intent before effects and resumable cross-DO effects. R-198 requires the automatic purge intent in the triggering apply and requires a ruling before new cross-partition machinery.
- The added `automatic_audit_does_not_commit_when_trigger_apply_loses` test captures the desired same-partition atomicity. It remains unrun and is expected to fail on the checkpoint; no containment/protocol fix was applied after the stop.

## Checkpoint and remaining work

Independent edits unexpose manual PurgeCache, move Worker admin dispatch after persisted mode guards, require a signed empty purge acknowledgement, honor native hook timeout, and correct the 5.11a/4.18 dependency order without cycles. Regression tests accompany these edits; final verification is pending.

Still outstanding: the ruling and automatic audit fix; Worker timer/local invalidation wiring; snapshot refill fencing; ReadAuditLog request-budget batching; launch subset/spec/readme/changelog completion; final gates, independent self-review and PR.

Clean `origin/feat/mkit-server` at `4d1c8fd4` reproduces the two mkit-attest wasm clippy errors (signer_external.rs:329 and store.rs:235) and the mkit-server wasm collapsible-if error (pipeline/mod.rs:591). They remain untouched. `just ci-security` passed. Workspace clippy found a branch-owned zero-sized-map-values lint in the new purge acknowledgement type; it remains unresolved in this stopped checkpoint. Other final gates were not completed.
