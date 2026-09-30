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

Continue bounded acquisition/discovery, actual ct/timer-13 ownership transfer,
verified streaming, retention/legal holds, adapters and templates under the cap.
The end-to-end owning workflow and admin reads remain unfinished/unregistered;
this ruling/amendment is not runtime verification or launch-readiness evidence.
PR1 [#1242](https://github.com/officialunofficial/mkit/pull/1242) and its
[contract](WP-5.6a-1-contract.md) remain the denial/pending-intent baseline.

## Implementation checkpoint after PR1 merge

PR1 review fixes were merged from `origin/feat/mkit-server` at `596782c7`.
The new core uses existing blob/storage primitives, timer 15 on its local store,
bounded namespace candidates and action-owned copy intents. It keeps intents
through audited retention passes so delayed PUTs remain purge-discoverable.
Any remains explicitly incomplete; no catalog was introduced. The actual ct
owner commits provenance, audit and timer responsibility before acknowledgment.

This checkpoint is inert and incomplete. Manifest reassembly validation,
GetTakedown/ListTakedowns/SetLegalHold, byte-free replay and verified ReadPreserved
streaming, native/Worker store and timer registration remain required. Manifest
sources stay `ManifestClosurePending`; they do not claim verified preservation.
The cap stops further implementation; nothing is removed from launch scope.
Focused tests, host clippy and wasm32 clippy pass. Full gates, default vcs-worker
conformance and opening the PR remain pending. Activation stays off.

The measured acquisition bound covers valid Worker-admitted content, including
compressed 50-hop chains. Arbitrary later-corrupted zstd blocks retain the
existing decoder's post-block output-check limitation; no decoder fork is added.
