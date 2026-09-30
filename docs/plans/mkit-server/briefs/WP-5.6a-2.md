# WP-5.6a-2: verified preservation core (R-190)

The [launch/base brief](WP-5.6a.md) remains binding except for the latest
approved split and namespace ruling below. All three PRs are required for
launch. PR2 branches from merged PR1 and targets `feat/mkit-server`; open the
PR without merging. Latest PR2 cap: 3,300 non-test Rust production lines;
docs do not count. Stop and report before exceeding it.

PR2 owns bounded canonical acquisition, manifest/chunk closure verification,
holder/context discovery, retention and legal-hold arbitration, audited
per-action purge, adapters/templates, actual ct ownership transfer and local
timer-15 runtime wiring. Acquisition cannot report success for an unverified
manifest or missing chunk. Legal-hold/purge concurrency stays in this core.
Runtime wiring remains gated off: activation is fixed false and `ReadPreserved`
is unexposed. User provisions storage; no cloud calls or new schema/protocol.

The approved [PR3](WP-5.6a-3.md) owns admin Get/List/ReadPreserved/SetLegalHold,
byte-free replay and fresh verified streaming; these remain required for launch.
This is an authorized split, not removal of launch scope. No other deferrals.

**Latest namespace ruling (supersedes finite-only):** Any supports normal global
denial and preservation from the named repository. Discovery sweeps provable
named-namespace and known-holder namespaces but MUST NOT claim discovery or
repository/global takedown completion under Any. The exhaustive `nl` catalog is
post-launch; implement no catalog or new cross-partition protocol now. Finite
Multi deployments sweep the configured allowlist; Single sweeps its sole Root.
Persist the safety cut/cursor, wait for each relay watermark, sweep the union of
repository registry and active-shard records, and retry incomplete reads.

Merged 4.10b-1 makes the actual `ct`/timer-13 handoff required here. Ready means
availability, never completion. Preserve provenance/action binding and acknowledge
only after the owning workflow has durable responsibility; corrupt requests fail
closed. Timer 15 `TAKEDOWN_WORK` remains allocated under R-190 for acquisition,
discovery retries and audited retention purge. Use disjoint existing `b` subkeys;
preserve exact current-producer V1 `b 00 object:32` denial. No older-build migration.

Keep request acceptance, verified preservation and real completion distinct.
No rewrite, notices, reinstatement, inspection hits or hold-review operations at
launch. §14.7 signing key, public key list and retention startup requirements
remain. Run the base/common gates, including wasm32 clippy and default vcs-worker
conformance on a free port, then self-review and open the PR. Activation remains
fixed false in PR2; all three parts and launch gates are required. Docs are not
runtime evidence.
