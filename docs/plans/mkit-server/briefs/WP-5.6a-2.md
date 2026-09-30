# WP-5.6a-2: verified preservation and restricted administration (R-190)

The [approved split](WP-5.6a-1.md) and [launch/base brief](WP-5.6a.md)
remain binding, with the latest namespace ruling below taking precedence.
Both parts are required for launch. Branch from 5.6a-1; target `feat/mkit-server`
after PR1 merges. Open the PR; do not merge it. Cap: 2,600 non-test lines,
including docs. Stop and report the measured count before exceeding it.

Implement bounded canonical acquisition and holder/context discovery; verified
streaming `ReadPreserved`; retention, legal holds and audited per-action purge;
native/Worker adapters and user provisioning templates; remaining lean normative
amendments; and timer-store locality without self-DO calls. User provisions
preservation storage; no cloud calls. Nothing else is deferred to fit the cap.

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
off until both parts and launch gates are complete; docs are not runtime evidence.
