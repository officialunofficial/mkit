# Approved WP-5.6a split (R-190)

The split is approved. Both PRs stay under R-190, keep timer 15, and are required for launch.

PR 1, WP-5.6a-1: global denial and durable admin intent, as you proposed.
- Scope:
  - independent action sets and chunk paging;
  - the pack inventory;
  - every serving, reuse and final-apply proof;
  - signed, replay-safe Takedown acceptance;
  - asynchronous manual PurgeCache;
  - the pending-state contract and layout docs.
- Cap: 2,500 non-test lines.
- Activation stays off until 5.6a-2 lands.
- Branch mkit-server/wp-5-6a-1-global-denial. Run the full gates, including wasm32 clippy and the vcs-worker default
  conformance on a free port, then open the PR.

PR 2, WP-5.6a-2: verified preservation and admin reads.
- Scope:
  - bounded acquisition and holder/context discovery;
  - retention and legal hold, with the audited per-action purge;
  - verified streaming in ReadPreserved;
  - storage adapters and provisioning templates;
  - the remaining lean-profile normative amendment;
  - timer-store locality, with no self-DO calls;
  - the conditional ct handoff.
- Cap: 2,600 non-test lines.
- Branch from 5.6a-1, and keep working while PR 1 is in review. Its PR targets feat/mkit-server after PR 1 merges.

Don't defer anything else to fit the caps. If either PR would pass its cap, stop and report the measured count.

The [launch brief and historical base brief](WP-5.6a.md) remain binding except where this approval overrides them.
