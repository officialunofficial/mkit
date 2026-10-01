# WP-5.6a-3 restricted administration contract (R-190)

Status: implemented and independently source-reviewed. PR #1249 merged as
`a3966d84`; the assigned branch `mkit-server/wp-5-6a-3-admin-reads` integrates
that base in `19ffce76`, then integrates the subsequently merged WP-4.16c
target `1edfc306` in `b4a80a34`. Activation remains false. Worker mounting and launch
activation belong to WP-4.18, which also depends on the R-203 bounded decoder
repair carried forward by the orchestrator from PR #1249.

## Implementation and brief checklist

- Signed moderation-role GetTakedown/ListTakedowns/SetLegalHold/ReadPreserved:
  `takedown/admin.rs` implements AdminOperations for the existing Work runtime;
  `admin/ledger.rs` uses the existing authentication, replay and audit lifecycle.
- Status: additive fields on the existing v1 TakedownRecord separately report
  acquisition pending, historical canonical verification, discovery status,
  legal hold and purged copies. Real completion remains false. Any never reports
  discovery complete. Get/List include no canonical payload. Missing state uses
  the existing preservation defaults and checked explicit retention.
- List: absent, null or empty scope lists all requests. Repository and namespace
  selectors filter a bounded root scan. Tokens bind the normalized scope and
  last processed request key; foreign/malformed tokens fail closed. Page size
  is 1–100; filtered pages can be empty with a continuation.
- Hold: uses PR2 plan_legal_hold, including its purge ownership guard, state CAS
  and deadline. Reason and operator label follow the existing 512/128 UTF-8
  byte limits. The core effects, signed operator audit and terminal nonce
  result commit in one batch. No second retention/ownership arbiter is added.
- Read replay: only a bounded action/object/offset descriptor or terminal error
  is persisted. Each byte-reading retry freshly verifies the current key and
  role, rechecks retention and availability metadata and appends acceptance
  audit before returning a fresh stream. Ordinary-operation replay preserves
  SPEC-SERVER §16.4 behavior; the §18 fresh-read exception applies to ReadPreserved.
- Streaming: each poll checks live request/state/object ownership and retention,
  verifies the bounded piece intent and immutable action/object/offset header
  and content hash, then checks live retention/ownership again after blob I/O.
  Offsets are exact and ordered. Successful streams emit one last response,
  including an empty last at size. Above-size offsets fail. Piece/backend or
  retention failures append a backend-clock operator audit and terminate with
  a Connect error, without a last message. Audit failure aborts the transport.
- Confidentiality: no preserved response enters replay, public caches, audit,
  logs or errors. Public stream/piece Debug representations omit payload.
- Foundations: no new tag, timer, storage primitive, catalog, protocol or wire
  version. The five additive status fields remain in AdminService v1 and are
  documented by a separate SPEC-SERVER version-history entry and golden vector.
  §14.7 configuration/signing/public-key-list and full-profile rules remain.

## Adapter handoff to 4.18

Delegate Takedown and the restricted catalog to the configured Work runtime
within the existing Engine::with_operations dispatcher, preserving its other
operations (including PurgeCache). Forward preserved_piece/preserved_now_ms to
Work as well; Work delegates Takedown acceptance/resume to Service. On the protected Worker
admin mount, invoke Arc<Engine>::handle_streamed, supplying separately decoded
bytes when appropriate while signing the exact wire body. Reply::Unary uses the
existing response adapter. Reply::Stream is an application/connect+json HTTP 200
body stream, containing its own success/error end envelope. Apply
Cache-Control: no-store to every response and do not collect the stream.
Engine::handle/handle_decoded reject preserved reads because those methods
return replayable buffered responses. All catalog exposure/activation remains
4.18 work, as specified by the executor prompt.

## Bounds

List scans at most 100 existing root request rows, retains at most 256 KiB of
record JSON plus framing, and bounds page tokens at 2 KiB. Under the generic
512 KiB value limit its scanned raw rows are at most 50 MiB; actual current
producer rows are smaller. A status lookup uses two metadata reads; a full
100-row matching list uses at most 201 calls within one plan, plus the existing
ledger transaction/retry calls. The shared operation budget remains 9,000.

A successful nonempty stream piece uses eight logical calls: request/state/
object before I/O, piece intent, blob GET, then request/state/object again.
An empty final response uses six. Each poll has a 16-call allowance and retains
one at-most-1 MiB owner-framed piece (payload at most 1 MiB minus 72 bytes),
plus bounded base64/JSON/framing buffers. No whole-copy preflight, whole-object
accumulation or piece-count-sized collection is used. These are source-derived
bounds, not allocator/RSS measurements. Adapters retain their actual Worker
request/R2/DO call budgets; exhausting them terminates the stream with error.

Production Rust delta against integrated target 1edfc306 after review: 719 added
and twelve deleted physical lines (731 counting test-module declarations);
below 1,500. The separate test file adds 1,055 lines.
Sixteen focused regression tests are implemented and pass: roles/replay/audit
continuity, separate status, current-role/key/retention/ownership retry checks,
byte-free nonce storage, offsets and last-message rules, midstream failures,
actual hold-blocked purge, all/scoped pagination, stale hold CAS and audit failure.

## Verification evidence (2026-09-30)

Builds use DEV/TEST_DEBUG=0, the assigned worktree's own target and prescribed
`~/.cache/mkit-test-tmp/wp-5-6a-3` TMPDIR. No dependency manifests or lockfiles
change. Final integrated-tree gate results are recorded below, in the PR body and
scratch logs. Prior sandbox-denied attempts are not counted as completed gates.

The first broad CLI run timed out in the unchanged pack-count property test
`remote_dispatch::split::tests::estimate_bounds_the_real_pack_count_and_three_caps_always_fit`.
The isolated branch nextest run passed in 12.186 seconds; unchanged-parent
`a3966d84` passed in 11.68 seconds. The initial Worker run passed 30/30 cold
health probes but failed `refs.many_refs_one_repository` with Miniflare's
`Network connection lost` HTTP 500. The integrated-base Worker rerun and parent control are recorded below.

The exact `just ci-server` run stopped at two unchanged indexed interruption
tests. Both reproduce on unchanged parent `a3966d84`: the closure/recheck test
expects `{1,2,4}` but observes `{2,4}`, and the killed-slice test reports `job did
not finish`. Three isolated branch retries and a complete non-fail-fast rerun record
the remaining results; these inherited assertions are not changed by this WP.

## Independent self-review

Two independent read-only reviewers checked correctness/security and spec/brief
conformance against the preservation-base diff `a3966d84..19ffce76`, finding no
remaining actionable source defects. They did not independently execute gates.

Self-review fixed all-scope List support and pagination, hardened payload Debug,
defended Any incomplete status, rejected buffered read replay descriptor exposure,
and audited invalid descriptor/offset errors. A final spec pass tightened
SetLegalHold to the existing UTF-8 byte limits and aligned List with ProtoJSON
null scope and quoted page sizes. Both new regressions failed before the fix;
all fifteen admin tests and native server clippy then passed.

## Full gate results on preservation base a3966d84 (head 19ffce76)

- PASS: formatting/diff checks, workspace all-target/all-feature clippy,
  mkit-server wasm32 all-feature clippy, warning-denied server rustdoc,
  touched/reverse-dependency doctests, ci-security, ci-scripts and ci-proto
  (including admin schema/golden hashes and protobuf round trips).
- PASS: all 1,534 CLI reverse-dependency tests (32 slow, one leaky, nine skipped).
  The earlier timed-out pack-count property also passed in this run (45.332 s).
- PASS: all fifteen restricted admin tests in the final integrated suite.
- PASS: all three ci-server wasm feature checks, default Worker wasm build and
  CLI baseline. Exact just ci-server itself fails at the first two assertions;
  it is not recorded as green.
- Server non-fail-fast all-feature suite: 2,810 run, 2,794 pass, thirteen
  assertion failures, three timeouts, twelve skips. All thirteen assertions
  fail in three sequential isolated branch runs and on unchanged parent a3966d84.
- Timeout controls: reuse times out at 120 s in all three isolated branch
  attempts and on the parent. Inspection times out initially, then passes
  isolated in 37.224 s; the parent times out at 60 s. Relay property times out
  at 60 s in all three isolated branch attempts; the parent passes in 33.274 s.
  No passing relay branch run or load-cause diagnosis is claimed.
- Default Worker on free port 52983: cold health 30/30, 81 wire pass, three
  HTTP 500 Miniflare Network connection lost failures, 131 profile skips.
  Both multipart cases pass individually; many_refs_one_repository fails in
  three isolated attempts. Unchanged parent on free port 52984: cold health
  30/30, 83 wire pass, one many-refs Network connection lost failure and 131
  profile skips. Scripts stop only their own servers and retain evidence.

The common executor rule permits these unchanged-code gate exceptions after
isolation and parent checks; they remain visible rather than weakening tests.
Logs are retained under ~/.cache/mkit-test-tmp/wp-5-6a-3, including
server-suite-full.log, ci-server-final.log, ci-server-wasm-final.log,
cli-reverse-final.log, doctests-final.log, ci-scripts-final.log,
ci-security-final.log, ci-proto-final.log, timeout-*-isolated-*.log,
timeouts-parent.log, *-parent.log and worker-conformance-{final,parent}.log.

### Parent-confirmed assertion failures

| Package / binary | Test (all unchanged by this WP) |
|---|---|
| `mkit-server` | `indexed::job_tests::interrupted_closure_and_recheck_slices_shrink_then_end_terminal` |
| `mkit-server` | `indexed::job_tests::killed_slices_shrink_the_entry_cap_and_end_in_a_terminal_outcome_not_a_rejection` |
| `mkit-server` | `pipeline::tests::golden_two_ticket_advance_batch_keys` |
| `mkit-server` | `relay::tests::same_millisecond_writer_during_fire_cannot_lose_wakeup` |
| `mkit-server-native::relay` | `sqlite_crash_after_target_commit_retries_without_another_target_apply` |
| `mkit-server-native::relay` | `sqlite_scan_state_guard_conflict_retries_without_deleting_rows` |
| `mkit-server-native::relay` | `sqlite_full_source_relay_timer_reschedules_immediately_after_progress` |
| `mkit-server-native::relay_capacity` | `sql_soft_limit_reserves_space_for_guarded_relay_timer_reschedule` |
| `mkit-server-worker` | `published_view::tests::etag_conflict_crash_and_relay_during_upload_preserve_dirty_work` |
| `mkit-server-worker::quota_rollup` | `rollup_config_failure_retries_the_stored_timer` |
| `mkit-server-worker::quota_rollup` | `rollup_is_registered_on_the_classes_that_hold_quota_rows_only` |
| `mkit-server-worker::relay` | `relay_config_failure_retries_the_stored_timer` |
| `mkit-server-worker::relay` | `relay_is_registered_only_on_ref_shards` |

## Canonical-reader base integration (target 1edfc306, head b4a80a34)

Both independent reviewers rechecked this merge. Restricted admin implementation
and wire fields are unchanged. The resolver refactor retains selected-source
semantics; its new read-denial cache defaults empty for preservation. ObjectReader
uses serving storage rather than Work.preserved and exposes no preserved reads.

All 38 affected admin/object-reader/denial tests pass (8.460 s), including all
fifteen admin tests. Exact just ci-server is rerun on this base and again stops
at the same two parent-confirmed indexed assertions (292 pass, two fail, twelve
skipped; 2,536 not run). Earlier full-suite, CLI and Worker controls above refer
to a3966d84; no complete green latest-base server or Worker suite is claimed.
Latest-base formatting/diff checks, workspace all-target/all-feature clippy,
wasm32 all-feature server clippy, warning-denied server rustdoc, touched/reverse
doctests, ci-scripts and ci-security all pass. ci-scripts also reruns protocol
checks, admin golden vectors, CLI baseline, wasm feature checks and default
Worker build. Results are retained in the corresponding *-latest-base.log files.

## Reviewer fix and targeted verification (2026-09-30)

Independent security and A/B conformance passes reviewed head 2f4677be.
A signed in-flight nonce retry returned aborted without auditing that result.
The shared ledger now appends that failure through record_result without
replacing the in-flight nonce or repeating workflow effects. A regression for
all four restricted operations failed before the fix (zero audit entries,
expected two), then passed with two audited retries per operation and verified
chain continuity. Both reviewers concurred with this small correction.

All 37 admin/restricted-takedown tests pass, including the sixteen restricted
regressions. Native all-target/all-feature and wasm32 all-feature mkit-server
clippy pass with -D warnings; formatting and diff checks pass. Both existing
transport bindings were regenerated from canonical protos and remain unchanged;
AdminService uses handwritten Connect JSON and dynamic proto golden validation.
Review logs are retained under ~/.cache/mkit-test-tmp/wp-5-6a-3-review.
Full gates were not rerun; the measured parent controls and timeout/Worker
limitations above remain exceptions, not green suites. Activation remains off
until WP-4.18 and R-203; no additional launch capability is enabled here.
