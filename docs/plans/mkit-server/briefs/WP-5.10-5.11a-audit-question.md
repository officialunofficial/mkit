# Ruling requested: automatic purge audit across partitions

Resolved by the user on 2026-09-30. Implementation resumed using the existing outbox relay; this document preserves the source evidence behind the ruling.

## Question for the orchestrator

What approved mechanism should connect an automatic purge intent, committed in the same apply as its triggering state change, to the deployment-wide gapless audit chain when the trigger and admin ledger live in different partitions?

Please specify the allowed acceptance/completion audit semantics and recovery owner when the source apply loses its CAS or the executor crashes. May the root record an accepted but not yet applied purge, and what existing mechanism resumes or resolves that acceptance? The executor will not invent a cross-partition protocol, key, timer or storage primitive.

## Concrete source evidence

- `rust/crates/mkit-server/src/admin/ledger.rs:212`: `SystemAudit::plan` ignores the supplied trigger partition. Lines 238–251 append an `ok` audit entry and `ai` intent using a separate apply to the root, then return an empty batch.
- `rust/crates/mkit-server/src/pipeline/purge.rs:46`: the caller subsequently reads the trigger partition and plans the `cp` work, `cg` refill fence and kind-11 timer. Those effects join the caller's state-change apply; the earlier root audit does not.
- Thus a failed caller apply can leave the root audit/intent without accepted purge work. There is no recovery consumer for `ai` in the draft. This also occurs when both applies happen to use the same partition.
- SPEC-SERVER §16.6 requires automatic purge system entries and a gapless chain; original B6 requires durable action intent before effects and resumable cross-DO effects. R-198 requires the automatic purge intent in the triggering apply and requires a ruling before new cross-partition machinery.
- The added `automatic_audit_does_not_commit_when_trigger_apply_loses` test captures the desired same-partition atomicity. It remains unrun and is expected to fail on the checkpoint; no containment/protocol fix was applied after the stop.

## User ruling

The outbox relay is the existing cross-partition mechanism. Automatic actions join the audit chain through it:

1. Remove the pre-apply `ai` intent and premature success entry. An automatic action is audited only after its state change commits.
2. The caller's state-change apply atomically commits the purge intent, its timer kind 11 in the same partition, and an outbox row carrying the action, source partition and operation identity, occurred time and purge id. Purge delivery does not depend on audit append.
3. A root target hook appends the gapless chain idempotently on source identity. Redelivery appends nothing; lost replies are safe. The watermark advances in the same apply as the append. Chain order is arrival order; entries retain the source occurred time.
4. Count the added source outbox row and keep the target apply at 100 operations or fewer. Cover source-apply failure, duplicate/reordered delivery, commit-before-relay recovery and chain continuity.

Stop only if targeting root requires a new relay codec or partition kind. The existing `RelayV1` target already encodes `Partition::Namespace` and `Partition::Coordinator`, so that stop condition does not apply.
