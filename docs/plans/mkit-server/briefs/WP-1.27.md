## Purpose

Produce the M1 exit evidence for Stage 1 without staging. Every M1 behaviour (D34 sharding, tickets, growth
bounds, isolation, lag windows, epoch leases) is covered by wire conformance cases that run locally on native lanes
and under `wrangler dev`. `docs/plans/mkit-server/m1-exit-report.md` records the results.

## A. Fixed (do not change)

1. **R-154 and SPEC-SERVER §18:** the core profile.
   - Staging runs, the "≥ 8× on staging" bar and the staging push/clone smoke are **Stage 2**, owned by 1.19 and 1.20.
   - List them as "deferred per R-154" in the report.
2. **R-159's 1.27 scope decisions:**
   - **Epoch-lease scope (R-159, amended by the orchestrator after review):** wire cases cover bump, idle-shard
     wake, and lease expiry before revocation completes, with no acknowledgement in flight. No new pause faults.
     Expiry racing an ack stays in-crate (`mkit-server-native/tests/epoch_leases.rs::expiry_races_ack_memory` and
     `expiry_races_ack_sqlite`), alongside revoke-during-write and R-63; all are cited in the report.
   - **The over-32 MiB listing** is a **native-only** wire case. The Worker keeps 1,000 refs (R-134).
   - A **partition-scoped Worker stats hook**, so `growth.*` runs under D34, which is now the default.
   - The exit evidence is `m1-exit-report.md`, from local runs, with no staging.
3. **SPEC-SERVER** and STC for each case's expected behaviour. The spec wins over the breakdown.
4. **The existing wire harness conventions:** the case table, the profile feature tags, the doc table (`wire/mod.rs`),
   and the per-lane `judge` allow-lists.

## B. Decided (do not change)

- **B1. The cases to add** (the fact sheet §4 table, rows a–k). The row letter follows each case name.
  - **(a)** `repo.isolation_replay`: a replay record in repository A never satisfies a request to B.
  - **(b)** Namespace-policy cases run on native Multi and the Worker `--multi`, which exist since #1210. Drop the
    stale reserved `namespace.policy_*` names.
  - **(c)** `tickets.advance_ticket_bindings` runs under Multi and D34. Fix its doc row.
  - **(d)** A per-ref open-ticket cap case, plus the profile field for the cap.
  - **(e)** Membership and ListRefs lag-window cases, using `x-mkit-test-relay-delay-ms`. They run on the native binary
    and the Worker, D34, with test-faults.
  - **(f)** D36 over the wire: a real ticketed push, then `PackExists`/`DownloadPack` with `X-Mkit-Ref` while the relay
    is delayed, plus a cross-repository check with the same ref name (Multi).
  - **(g)** Epoch leases, per A2. Enable `epoch-leases` in the Worker D34 phase.
  - **(h)** Many-ref throughput: 64 refs in one repository, correctness only.
  - **(i)** `growth.tickets_and_outbox_pruned`, plus the partition-scoped Worker stats hook (test-faults only; never in
    a release build). Optionally add a native test-faults stats route.
  - **(j)** The over-32 MiB merge-paging listing: native-only.
  - **(k)** An expiry-timer case: a freed cap slot and an aborted session, via `run-timers`.
- **B2.** Every new case is registered with its doc row. Add a doc-table test that compares the requires and excludes
  lists too, which would have caught the `advance_ticket_bindings` mismatch.
- **B3.** Update the `judge` allow-lists for every lane. Skips carry precise reasons.
- **B4. `docs/plans/mkit-server/m1-exit-report.md`,** in the format of `m0-exit-report.md`:
  - native nextest lane summaries;
  - wire tables per native lane (single, D34 with test-faults, Multi);
  - the in-process memory baselines;
  - Worker phases: single, single + faults, D34 + faults, multi, multi + D34 quota, and grants if present;
  - the in-crate epoch-lease evidence;
  - a skip table with reasons;
  - a "deferred per R-154" list.
- **B4b. Default-feature test build.** `mkit-server-native/tests/begin_upload.rs` doesn't compile without `--features test-faults`, because its `FsBlobStore` import is gated. Gate the test file, or the affected tests, on `test-faults` so that `cargo test -p mkit-server-native` builds with default features. Check that every native test binary builds with default features.
- **B5. R-160:** B1–B4. Mark the M1 exit criteria in `m1-m2-breakdown.md` and the PRD snapshot as satisfied, pointing
  to the report, with staging deferred. Add a CHANGELOG line.

## C. Your decisions

- The case module layout, the fault-header choices within the existing test-faults set, and the report tooling. A
  script that produces the tables is welcome.

## D. Escalate (stop and report) if

- A case exposes a real server bug that isn't a small fix (over about 50 lines). Skip it with a reason, and report it.
- A case needs a new pause or fail fault beyond A2.
- Production code (including conformance `src/`) passes 1,800 lines.

## Gates

- The common gate set.
- `cargo nextest run --locked -p mkit-server-conformance -p mkit-server-native -p mkit-server-worker -p mkit-server --all-features`.
- **Every Worker phase:** `scripts/vcs-worker-conformance.sh` default (D34), `--sharding single`, `--multi`, and the
  Multi+D34 quota phase, with `VCS_CONFORMANCE_PORT` set to a free port. macOS has no `timeout` command.
- The native wire lanes.
- `just ci-server`, `ci-scripts` and `ci-security`.
- The report's numbers come from the final runs.
