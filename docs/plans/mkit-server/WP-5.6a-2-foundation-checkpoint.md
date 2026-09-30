# WP-5.6a-2 foundation checkpoint (superseded)

The namespace stop and finite-only refusal are superseded by the latest user
ruling in the [PR2 brief](briefs/WP-5.6a-2.md) and [R-190](00-plan.md).
Any supports normal denial and preservation from the named repository, with
sweeps of provable named/known-holder namespaces and explicitly incomplete
discovery/takedown state. Finite allowlist/Single Root sweeps remain required.
The exhaustive `nl` catalog is post-launch; no catalog protocol is built here.

The investigation found partition-bound scans but no authoritative Any catalog:
[partition enumeration](../../../rust/crates/mkit-server/src/store/partition.rs)
and the [`nl` reservation](../../../rust/crates/mkit-server/src/store/keys.rs).
Known holders cannot establish an exhaustive namespace set before relay delivery.
This limitation prevents completion claims, not denial or named-repo preservation.

The [core contract](WP-5.6a-2-contract.md) records the final layout, source
checkpoints, verified acquisition/manifest closure, ct ownership, retention/hold
arbitration, action-owned audited purge and inert runtime wiring. The reported
production Rust count is 3,298/3,300 against merged base `cd680351`; docs are
excluded. Five focused source tests pass, with at most 12 counted calls per
selection step and 357 final-decode calls for the dense 50-hop fixtures. The
[verification report](WP-5.6a-2-verification.md) records the completed local checks,
full-run baseline failures, isolated passes and unchanged-parent results.

Activation stays fixed false. PR3 owns Get/List/ReadPreserved/SetLegalHold,
byte-free replay and fresh verified streams. ReadPreserved remains unexposed.
All three parts and final launch gates remain required. Historical closure
verification does not replace fresh verification of every streamed piece.
The [PR2](briefs/WP-5.6a-2.md)/[PR3](briefs/WP-5.6a-3.md) briefs retain the remaining
scope. This document is not launch-readiness evidence.
