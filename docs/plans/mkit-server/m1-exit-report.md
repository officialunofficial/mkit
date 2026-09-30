# M1 exit report (WP-1.27)

Local Stage 1 evidence for [MKIT-29](https://linear.app/officialunofficial/issue/MKIT-29),
SPEC-SERVER §18 and PRD §8, on 2026-09-29. Initial evidence used `feat/mkit-server` at `85c4adf3`
plus WP-1.27; the final integration rerun includes `b0bbbba2` (#1225).
This work finishes an interrupted executor's snapshot (`525a4dba`).
Runs used macOS, Rust 1.95.0, cargo-nextest 0.9.133 and wrangler 4.134.0 on a shared
machine; these are correctness results, not throughput measurements.
All builds used `CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`, the worktree's
own `rust/target`, and non-symlinked `TMPDIR=$HOME/.cache/mkit-test-tmp/1.27`.
Worker phases used `VCS_CONFORMANCE_PORT=8911` and stopped only their own processes.

**Verdict:** native and every complete local Worker gate pass on the final
integration tree. Default Worker D34 needed its one permitted network-flake
retry; failed earlier attempts and their separate continuations remain below.
Isolation, policy, tickets, D34 lag/hinted reads, lease renewal, 64-ref
correctness, paging and bounded-growth evidence follows.
Exact expiry during an acknowledgement remains an in-crate race, an explicit
deviation from A2/B1(g): request clock skew changes business time, while lease
observation, revocation and acknowledgement use real time. No new pause or clock
transition was added. Staging remains deferred per R-154.

## 1. Native nextest and build gates

| Gate | Final result |
|---|---|
| `just ci-server` / four-crate all-features nextest | 2,204 passed, 0 failed, 8 skipped; 281.733 s |
| `mkit-server` | 1,023 passed |
| `mkit-server-conformance` | 523 passed |
| `mkit-server-native` | 389 passed |
| `mkit-server-worker` | 269 passed |
| CLI reverse dependency (before #1225) | 1,534 passed, 0 failed, 9 skipped; 959.926 s |
| Default-feature native test build | passed, every binary builds |
| fmt; workspace/all-targets/all-features clippy | passed, warnings denied |
| Docs; doctests; wasm32 core/Worker clippy | passed |
| `ci-scripts`; `ci-security` | passed |

`ci-server` also passed wasm32 core checks with default, remote-hooks and
http-objects features, the Worker wasm build, and the server-free CLI check.

The server gate runs the brief's four-crate all-features nextest command. The CLI
suite covers the reverse dependency. Default-feature `cargo test --locked
-p mkit-server-native --no-run` builds every native test binary. Base #1224 already
made the `FsBlobStore` import unconditional, so no test was hidden behind a new
feature gate for B4b.

The first post-merge server run timed out in the unchanged memory namespace-quota
test; it passed alone in 0.088 s, in the full rerun in 0.079 s, and on unchanged
parent `b0bbbba2` in 0.120 s.
The initial native timeout diagnostics passed alone: CLI stateful export in
21.290 s and relay schedule property in 21.443 s. Both passed in the final full
suites and on unchanged parent `85c4adf3` (12.251 s and 10.055 s respectively).

## 2. Native wire lanes

```bash
cd rust
cargo nextest run --locked -p mkit-server-native -p mkit-server-conformance \
  --all-features -E 'binary(/wire_/) or binary(=baseline_pipeline_memory)' --no-capture
```

The dedicated selection before #1225 passed **36/36** nextest tests in 639.629 s; one ignored
large-listing test is excluded here and runs separately below. The post-merge
server gate reran these non-ignored wire tests successfully. Counts are TAP
case results, with filtered runs aggregated per lane; every row has zero failures.

| Native lane | Sharding / addressing | Pass | Skip |
|---|---|---:|---:|
| Spawned FS layout, bearer | Single | 51 | 148 |
| Spawned FS + SQLite, auth v2, faults | Single | 88 | 111 |
| Spawned FS + SQLite, auth v2, faults | D34 | 90 | 109 |
| Spawned FS + SQLite, multipart filter | Single / D34 (each) | 3 | 1 |
| Spawned S3 + SQLite, auth v2, faults | Single | 88 | 111 |
| In-process FS layout, bearer | Single | 51 | 148 |
| In-process FS + SQLite, auth v2 | Single | 85 | 114 |
| In-process S3 + SQLite, auth v2, faults | Single | 88 | 111 |
| Multi repository/policy/tickets/info | Single, Multi | 17 | 7 |
| Multi repository/policy/tickets/info | D34, Multi, faults | 19 | 5 |
| Grants and epochs | Single, Multi | 53 | 3 |
| Grants and epochs | D34, Multi, faults | 55 | 1 |
| Per-branch quota | D34 | 4 | 1 |
| Namespace cap after forced rollup | D34, Multi | 1 | 0 |

The native Multi lanes explicitly pass `policy.*`, `repo.isolation_replay` and the
same `tickets.advance_ticket_bindings` case used by Single. D34 with test-faults
passes `lag.list_refs_window`, `lag.membership_window` and
`repo.d36_hint_reads_during_lag`; the latter performs a real ticketed push, reads
the pack through `X-Mkit-Ref` before relay delivery, and checks another repository
with the same ref name. Grant lanes run both idle-shard and expired-lease renewal.

The native-only ignored listing lane runs separately:

```bash
cargo nextest run --locked -p mkit-server-native --all-features \
  --profile ignored-lane --run-ignored ignored-only \
  -E 'test(=listing_over_32_mib_pages_under_d34)' --no-capture
```

It passed in 259.070 s: **75,000 refs, 36,204,242 bytes, 75 pages**. Every page is
at most 2 MiB, and the returned rows have strict ordering and no duplicate names.
The first run exhausted an 8-minute relay-convergence wait under shared load;
the final case allows 20 minutes within its existing 30-minute outer deadline.
This fixture measures correctness only; it does not establish a performance bar.

## 3. In-process memory baselines

All 16 memory integration tests passed, including the three mutant controls.
The following rows aggregate each test's filtered TAP runs (grant and signed-read
rows combine Single and D34); every positive run has zero failures.

| Memory baseline | Pass | Skip |
|---|---:|---:|
| Open | 48 | 151 |
| Bearer | 51 | 148 |
| Auth v2, atomic, quota | 85 | 114 |
| Auth v2, test-faults (five selected cases) | 5 | 0 |
| D34 epoch leases and tickets | 16 | 1 |
| D34 Multi membership/hinted lag reads | 4 | 0 |
| D34 per-branch quota | 4 | 1 |
| D34 Multi namespace cap after rollup | 1 | 0 |
| Multipart | 3 | 1 |
| Multi repository/policy/tickets/info | 18 | 8 |
| Grants, Single and D34 | 106 | 0 |
| Signed reads, Single and D34 | 41 | 1 |
| Expiry timer, physical session abort, Single and D34 | 2 | 0 |

The negative controls deliberately use broken stores: non-atomic read/write must
fail concurrent CAS, a non-pruning store must fail growth, and leaking replay
indices must fail the exact key bound. Their nextest tests pass only when the wire
cases detect those defects; their intentionally failed TAP assertions are not
positive conformance failures.

`wire_expiry_timer_aborts_multipart_sessions` runs the same public expiry-cap case
under Single and D34, opening one actual multipart session and filling the rest
of the cap with small tickets. The observer must first see an actual open
session. After `run-timers`, a new ticket succeeds and the instrumented memory
blob store reports zero sessions. The strengthened observation reran successfully
in the focused lane (one nextest test, two wire cases, 0 failures; 0.080 s) and
the final four-crate server run. Public RPC ticket validation alone cannot
observe deletion of an underlying session; this direct
test-faults-only observation supplies the B1(k) physical-abort evidence.

## 4. Worker phases (`wrangler dev`)

All five complete script invocations passed after merging #1225. A permission
profile change temporarily blocked Git/scratch writes and GitHub access; the
original Worker process continued and its exit files were collected after access
was restored. No duplicate server was started.

| Final post-#1225 Worker phase | Pass | Fail | Skip |
|---|---:|---:|---:|
| Default D34, full-suite retry | 84 | 0 | 115 |
| Single, full suite | 84 | 0 | 115 |
| Single plus faults, main suite | 91 | 0 | 108 |
| Single plus faults, growth | 2 | 0 | 0 |
| Single plus faults, quota | 4 | 0 | 1 |
| Ordinary `--multi`, initial D34 suite | 84 | 0 | 115 |
| Ordinary Multi | 17 | 0 | 5 |
| D34 plus faults, main suite | 93 | 0 | 106 |
| D34 plus faults, growth | 2 | 0 | 0 |
| D34 plus faults, quota | 4 | 0 | 1 |
| Multi phase in fault build | 17 | 0 | 5 |
| D34 Multi grants/epochs/leases/lag/repo/ticket | 66 | 0 | 6 |
| Multi+D34 namespace quota after rollup | 1 | 0 | 0 |

Final Single growth: replay/quota keys **26 → 284 → 76** (bound 76, 24 triggers),
ticket/outbox keys **159 → 355 → 212** (bound 215, 27 triggers).
Final D34 growth: replay/quota keys **29 → 279 → 67** (bound 76, 21 triggers),
ticket/outbox keys **27 → 223 → 107** (bound 119, 48 triggers).
Streaming-buffer peaks passed: **864,189 bytes** (Single) and **864,141 bytes**
(D34), each below 1 MiB. Snapshot round trip and planted relay delivery passed.
The initial default D34 attempt had two proxy failures (multipart resume and
64-ref correctness); its one retry passed. The other four final invocations
passed on their first attempts. Their logs are `worker-merged-*.log`.

```bash
export VCS_CONFORMANCE_PORT=8911
bash scripts/vcs-worker-conformance.sh
bash scripts/vcs-worker-conformance.sh --sharding single
bash scripts/vcs-worker-conformance.sh --sharding single --test-faults
bash scripts/vcs-worker-conformance.sh --multi
bash scripts/vcs-worker-conformance.sh --test-faults --multi
```

| Earlier pre-#1225 phase / final attempt | Pass | Fail | Skip |
|---|---:|---:|---:|
| Default D34, full suite | 84 | 0 | 115 |
| Single, full suite | 84 | 0 | 115 |
| Single plus faults, full-suite retry | 91 | 0 | 108 |
| Single plus faults, growth | 2 | 0 | 0 |
| Single plus faults, quota | 4 | 0 | 1 |
| Ordinary `--multi`, full-suite retry before Multi | 81 | 3 | 115 |
| Ordinary Multi phase, resumed release build | 17 | 0 | 5 |
| D34 plus faults, full-suite retry before Multi | 84 | 9 | 106 |
| D34 expiry timer, isolated | 0 | 1 | 0 |
| D34 ListRefs lag and epoch bump, resumed (each) | 1 | 0 | 0 |
| D34 plus faults, growth, resumed | 2 | 0 | 0 |
| D34 plus faults, quota, resumed | 4 | 0 | 1 |
| Multi phase in fault build, resumed | 17 | 0 | 5 |
| D34 Multi grants/epochs/leases/lag/repo/ticket, resumed | 65 | 1 | 6 |
| Multi+D34 namespace quota after rollup, resumed | 1 | 0 | 0 |

Single growth: replay/quota keys **26 → 284 → 82** (bound 100, 36 triggers),
ticket/outbox keys **159 → 355 → 212** (bound 215, 27 triggers).
D34 growth: replay/quota keys **32 → 307 → 113** (bound 139, 42 triggers),
ticket/outbox keys **31 → 223 → 81** (bound 95, 26 triggers).
Single's streaming-buffer check passed at **863,996 bytes**, below 1 MiB.
The final failed D34 main log and resumed logs also passed the streaming bound
check at **864,166 bytes**.

Before #1225, the ordinary Multi retry failed in concurrent ref/advance cases. The D34 retry
failed in multipart, per-ref cap, concurrent refs/advance and replay cases; each
failure is `Network connection lost`. Isolated D34 expiry failed after its timer
call with the same proxy error. The resumed grant phase's `repo.isolation_refs`
read also failed this way; D36 hinted reads, membership lag and both grant-lease
renewal cases passed. No panic, restart or alarm exception accompanied the proxy
failures; their underlying socket failure mechanism remains unproven.

To finish unreached coverage without a third full-suite retry, scratch harnesses
retained the committed script's build, fresh-server, phase and own-process cleanup
blocks, while selecting the remaining phases. Their success messages explicitly
label continuation results; they do not turn a failed full gate into a pass.
The report retains these failed attempts, superseded by the complete post-#1225
passes above. Isolated checks of the unchanged
`refs.concurrent_missing_one_winner` and `repo.isolation_refs` cases failed with
the proxy error on this branch, then passed on unchanged parent `85c4adf3`. This
comparison does not establish that the failures pre-existed this work. Source and logs are under the
WP's scratch directory. No repository script was weakened to ignore failures.

Worker D34 keeps 1,000 refs (R-134); Single keeps its 10,000-ref fixture. Growth
uses disposable stores, a real short ticket lifetime and partition-scoped
`/__mkit_test/stats?ref=<name>` under D34. These hooks compile only with
test-faults. Grant phases run `leases.`, `lag.` and `repo.` alongside grant/epoch
cases; D34 enables epoch-leases.

The first pre-#1225 Single+faults attempt hit Miniflare `Network connection lost`; it was
rerun once, as required. The initial attempt also exposed a fixture quota error:
opening 64 large multipart tickets exceeded the default quota. The final case
opens one multipart session, sufficient to prove abort, and small remaining
tickets. The tables distinguish successful phases from the earlier failed full-suite retries.

## 5. Epoch-lease evidence and wire deviation

All **48** native `epoch_leases` integration tests passed in the final server run.
`expiry_races_ack_memory` passed in 0.064 s and `expiry_races_ack_sqlite` in
0.125 s. `failed_push_then_expired_lease_{memory,sqlite}` (R-63) passed in
0.063/0.103 s; `revoke_during_authorize_{memory,sqlite}` passed in 0.055/0.085 s.

Both backends also cover revoke-during-authorize, the failed revocation push with
an expired lease (R-63), paused and cancelled renewals, and renewal between push
and acknowledgement. The wire idle case renews an unwarmed shard at the new
epoch. The expired wire case waits 31 real seconds before revocation, then proves
that the old grant cannot change the warm ref and that the new grant can.
It does **not** reproduce expiry during an in-flight acknowledgement: the existing
skew header cannot advance that real clock, and A2 forbids adding a pause fault.
The exact in-crate race is the remaining evidence boundary for adversarial review.

## 6. Skips and deferred work

| Cases / profiles | Skip reason and alternate evidence |
|---|---|
| Auth-v2 cases on open/bearer lanes; bearer cases on auth-v2 lanes | Required authentication feature is absent. Matching lanes run them. |
| `repo.*`, `repository.*`, `policy.*`, cross-repository tickets on Single | Require multi-repo and, for policy, namespace-policy. Separate Multi lanes run them. |
| Ordinary Single-only auth/header/cap/many-ref cases on Multi | Registry excludes multi-repo; the Single-addressing suite runs them under D34. |
| Grant, scope, epoch, signed-read cases in M1 profiles | Milestone M2 exceeds the main profile; dedicated grant and memory signed-read lanes provide applicable coverage. |
| `indexed.pending_verification_unavailable` in core-profile suites | Milestone M4 exceeds M1; a separate native binary test passes with programmatic indexed configuration. Stage 1 exposes no indexed adapter option. |
| Fault, manual-timer, expired-replay and lease-bump cases in ordinary builds | Require test-faults, timers or epoch-leases. Fault builds run applicable cases. |
| Idle/expired grant lease cases outside D34 grant profiles | Require D34 epoch-leases, grants and test-faults; the D34 grant phases run them. |
| Lag/D36 cases on Single or without faults | Require separate shards, a lagging ref index and/or test-faults. D34 fault lanes hold the real relay. |
| `repo.membership_read_your_writes` on a served Multi target | Needs membership held undelivered; a live relay may deliver at any time. Instrumented memory runs it; the real ticketed D36 case covers held-relay reads. |
| `quota.*`, `growth.*` without a declared quota profile | Required quota features are absent; Worker quota phases and memory quota baselines run them. Native adapters add no optional stats route. |
| `quota.namespace_cap_after_rollup` in Single-addressing quota phases | Requires quota plus multi-repo; the dedicated Multi+D34 rollup phase runs it. |
| Multipart cases without multipart support; multipart cross-repository case on Single | Require multipart and, for cross-repository reads, multi-repo. Matching profiles run them. |
| Atomic/non-atomic advance cases on the opposite profile | Registry requires or excludes atomic-advance as appropriate; each profile runs its applicable behavior. |
| `list.merge_paging_over_32_mib` outside the native ignored lane | `merge_paging_refs = 0` explicitly skips it; the separate 75,000-ref native lane passes. |

The tables above report exact skip counts per lane. The published wire case table
records each case's exact requires/excludes lists; TAP supplies the corresponding
reason, including combinations of missing features.

Native lane skip allowlists and mandatory-case pass assertions guard expected
coverage; Worker phases require their selected mandatory cases to pass.
The doc-table test compares all 199 registry rows, including their exact
requires/excludes sets. `scripts/wire-report.sh LOG...` regenerates TAP result
tables and the precise case-level skip reasons from the saved final logs.

**Deferred per R-154:** deployed-staging conformance (WP-1.19/1.20), the staging
push/clone smoke, and the ≥8× many-ref throughput bar on staging. Cloudflare
placement and production platform limits were not exercised by these local runs.
No staging deployment, workflow dispatch, tag, registry publication or PR merge was
performed. The deterministic wire expiry/ack race needs an approved clock seam;
native growth continues to skip without the optional stats route.
