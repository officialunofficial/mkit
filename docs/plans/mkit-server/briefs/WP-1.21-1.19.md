## Purpose

Anonymous ListRefs on the Worker can be served from debounced, per-bucket published-view snapshots in R2 and the
Cache API, falling back to the live buckets. This cuts ref-index Durable Object calls, and private repositories and
signed reads are never served from a snapshot. 1.19 ships an **inert** staging configuration template and runbook,
activated after REL-1.

## A. Fixed (do not change)

1. **STC §7.9 (eventual ListRefs) and the page-token contract:** strict forward progress, and at most 2 MiB encoded.
2. **SPEC-SERVER §10:** snapshots hold published values only.
3. **R-152's 1.21 carry-forward:**
   - never serve private repositories;
   - signed reads bypass snapshots;
   - cache ref data, **not** authorization or visibility.
4. **The fixed Free-plan split:** relay 32 + backup 1 + outcome 8 + rollup 8.
5. **R-154.** The existing single-sharding backup round-trip test stays unchanged.

## B. Decided (do not change)

- **B1. Format:**
  - one bounded, deterministic envelope per bucket, containing: format version; namespace, repository and bucket
    identity; bucket generation; capture time; validity deadline; sorted `(full ref name, raw 32-byte id)` records;
  - R2 key `snapshots/v1/<ns>/<repo>/<bucket>`;
  - a Cache API key that includes the deployment identity and the format version;
  - conditional R2 replacement via ETag, rejecting older generations;
  - a dedicated snapshot bucket interface;
  - byte and row caps, with live fallback for oversized buckets.
- **B2. Timer kind 10:**
  - relay delivery atomically records dirty state, bumps a **bucket-local generation** and seeds the timer, through
    the target-local apply seam in the guarded transaction;
  - a 1 s debounce, with at most one replacement per key per second;
  - completion guards the captured generation;
  - alarm wakes are preserved.
- **B3. Read path:**
  - snapshots serve **authorized anonymous ListRefs only**; signed requests go live;
  - fall back to the live bucket on a missing, expired, malformed, unsupported or oversized snapshot;
  - reuse the merge engine and token contract;
  - Cache TTL 1 s, a finite snapshot validity, and quiet buckets refreshed before expiry;
  - snapshot use for unsigned ReadRef is programmatic opt-in and off by default.
- **B4. Security:**
  - the coordinator authorization read happens **before** any snapshot;
  - repositories observed as private are skipped and obsolete public snapshots cleaned up;
  - R2 stays private, with no raw snapshot route;
  - add a published-source seam, and snapshots are disabled when inspection is configured (5.4/5.5). **Never fall
    back to live values under inspection.**
- **B5. Budget:**
  - kind 10 is registered only on RefIndex partitions (RepoIndexShard);
  - one snapshot fire per alarm;
  - a total external-call cap of 8 per alarm.
  - On the read path: 16 buckets × at most 3 operations, plus the coordinator call. Reserve one call and do no extra
    retries.
  - Measure feature-on Worker CPU and record it in R-175.
- **B6. Inertness:**
  - a default-off `published-view` feature;
  - `Option<PublishedViewConfig>`, default `None`;
  - explicit configured fetch and DO entry points;
  - existing app entry points unchanged;
  - no Stage 1 opt-in, env var, binding, timer, cache activity, writes or routes.
- **B7. 1.19:**
  - an **inert** staging configuration template and runbook, with activation instructions;
  - `ADDRESSING=multi`, not the obsolete `SERVER_MODE`;
  - no activation or route mounting in Stage 1;
  - provisioning, deployment and CPU re-measurement are post-REL ops steps.
- **B8. Docs and plan:** R-175 and R-176, registry notes, the breakdown corrections (1.28 → 1.28b, the staleness bound
  including Cache TTL, "no ref-index DO calls"), and a CHANGELOG line per WP.

## C. Your decisions

Module layout, envelope encoding details, and cache-key hashing.

## D. Escalate (stop and report) if

- The Free budget can't hold the read path.
- The target-local relay seam can't carry the dirty/generation writes within batch limits.
- Production code passes 2,500 lines.

## Tests (required)

The fact sheet's §9, in full.

## Gates

- The common gate set, plus `just ci-server`, `ci-scripts` and `ci-security`.
- `cargo nextest run --locked -p mkit-server -p mkit-server-worker -p mkit-server-conformance --all-features`.
- wasm32 clippy and the worker build, with and without `published-view`.
- `scripts/vcs-worker-conformance.sh` default phase, with a free `VCS_CONFORMANCE_PORT`.
