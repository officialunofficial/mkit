# Performance measurements

Enable the `perf-metrics` Cargo feature on `mkit-server` to collect bounded
verification and fork measurements. Embedders provide a metrics sink and an
INFO tracing subscriber through their runtime setup.

Default builds omit the optional collectors, timers, metadata, and events.
The feature changes no storage query, page boundary, budget, retry hint,
authorization check, checkpoint, or public response body. It requires no store
reset. Enable it for a measurement window, then rebuild without it.

## Clocks and CPU

Durations measure elapsed wall time, including waits. They do not measure CPU.
The host supplies the clock and timer context; timer metadata is available only
when that host records it. Unknown scheduling or failure evidence remains
unknown. Use a profiler to isolate synchronous CPU work.

## Verification events and metrics

New structured events contain only constant stage/reason names, counts, and
numeric durations. Tracing adds `level`, `target`, and `message` when supplied.
Existing verification events and their existing identifiers stay unchanged.

| Event | Fields |
|---|---|
| `verification_stage_duration` | `stage`, `component = total`, `duration_ms`, `stop_reason` on phase steps: one phase step or inline verifier invocation, including errors |
| `verification_denial_histogram` | `stage`, `calls`, and disjoint `ms_0`, `ms_1`, `ms_10`, `ms_50`, `ms_100`, `ms_250`, `ms_500`, `ms_1000`, `ms_inf` counts; one row per nonempty aggregate |
| `verification_emit_components` | `scan_ms`, `plan_ms`, `denial_ms`, `direct_apply_ms`, `relay_commit_ms`, `outbox_read_ms`: sums for one EmitIndex invocation, including early exits |
| `verification_phase_chain` | `steps`, `stop_reason`: why the bounded phase chain stopped |
| `verification_extract_chain` | `steps`, `stage`, `stop_reason`: why the bounded extraction selection chain stopped |
| `verification_extract_chunk_chain` | `steps`, `stop_reason`: one internal chunk walk, including budget stops and failed next steps |
| `verification_await_hint_histogram` | `hint_ms` and disjoint `ms_100`, `ms_250`, `ms_500`, `ms_1000`, `ms_2000`, `ms_3000`, `ms_inf` bucket counts for a returned AwaitDelivery retry hint |

Chunk-walk stop reasons are `steps`, `calls`, `ops`, `elapsed`, `next_unfused`,
`next_error`, `part_complete`, `chunk_partial`, and `object_complete`.

Stage stop reasons are `complete`, `pending`, `store_error`, `outcome`,
`rejected`, and `restart`. Phase stages are `decode`, `closure_resolve`, `emit_index`, `await_delivery`,
`extract`, `verify`, `recheck`, `watch`, and `inline_verifier`. Extract components
are `scan`, `closure`, `dependencies`, `members`, `head`, `select`, `choose`,
`preflight`, `start`, `upload`, `complete`, `offsets`, `enqueue`, `delivery`, and
`invalid`. Emit components match the six fields above. Total stage time also
includes work outside those components; overlapping denial calls are not added
together to compute stage time.

Extract stop reasons are `steps`, `effect_stage`, `calls`, `ops`, `elapsed`,
`error`, `next_error`, `no_progress`, `phase_complete`, and `complete`. Phase
chain reasons are `pending_or_error`, `decode_boundary`, `phase_incomplete`,
`terminal`, `durable_boundary`, `steps`, `calls`, and `complete`. These reflect
the existing stop conditions; no extra work runs to obtain a reason.

| Metric | Labels and value |
|---|---|
| `mkit_server_verification_stage_duration_ms` | `stage`, `component`; wall milliseconds |
| `mkit_server_verification_denial_calls_total` | `stage`; aggregate attempted denial checks |
| `mkit_server_verification_extract_chain_stops_total` | `reason`; one chain stop |
| `mkit_server_verification_await_hint_ms` | No labels; returned hint in milliseconds |

Metrics use the existing envelope: `metric`, `labels`, and `value`. Embedders provide a metrics sink and choose their sampling policy. Use
aggregate events for complete histograms and stage totals. Duration metric values saturate at `u32::MAX`
milliseconds; structured stage durations retain the full integer value.
Bucket fields are disjoint, not cumulative: sum each
bucket across events before computing a distribution. Hint values describe
client advice, not delivery completion estimates.
The Await histogram records one selected response hint when a pending
AwaitDelivery job participates. It includes the maximum selected across all
consumed tickets; candidates suppressed by a terminal error produce no row.

## Extract slice gaps

With the feature enabled, the existing `verification_slice_result` event also
carries the following fields. This adds fields to one existing row per slice;
it adds no per-call or per-slice rows. The original event identifiers and field
values remain unchanged. The row is emitted after the handler finishes its
flush, before the timer driver's guarded commit. An interrupted flush can leave
an existing start row without a result row; use retry metadata and adjacent
platform errors for that case.

| Field | Meaning |
|---|---|
| `alarm_last_armed_ms` | Last successfully set timestamp remembered by this live instance; a hint that does not establish the current callback's schedule |
| `alarm_scheduled_ms` | Remembered physical timestamp confirmed by runtime metadata for an initial callback; absent after reconstruction, on retries, or without forwarding |
| `alarm_fired_ms` | Wall-clock timestamp at alarm callback entry |
| `alarm_delay_ms` | Nonnegative difference between known physical schedule and callback entry |
| `timer_scheduled_ms` | Scheduled timestamp in the current logical timer key, including a retry backoff |
| `logical_due_ms` | Original logical due time retained across timer retries |
| `timer_retry_attempt` | Logical timer retry count; includes failed or raced guarded attempts and saturates at eight |
| `runtime_retry_count` | Runtime-provided alarm retry count; absent if the caller supplies no metadata |
| `runtime_is_retry` | Runtime-provided alarm retry flag; this indicates a previous alarm callback failed, which does not establish that this slice failed |
| `slice_started_ms` | Timestamp at this slice's handler entry |
| `timer_delay_ms` | Nonnegative difference between the current logical timer schedule and slice entry; includes alarm scheduling and earlier work within the callback |
| `cold_first_slice` | First verification slice served by this object instance after construction; HTTP requests and unrelated timers do not consume it |
| `previous_alarm_failed` | `true` when the runtime identifies a retry of a failed alarm callback; absent when that failure is not established |
| `prior_unfinished_job_attempts` | Existing durable job attempt count on entry, before this slice prepares an attempt; applies to guarded lookup phases, rather than an Extract retry counter |
| `previous_slice_failed` | `unknown`: neither a raced logical timer nor a failed alarm callback establishes that the preceding slice itself failed |
| `previous_disconnect` | `unknown`: the runtime supplies no preceding failure cause, and generic storage errors or retry counts do not establish a disconnect |
| `slowest_rpc_prefix` | Partition kind of the slowest storage transport call in this slice, using the same allowlist as RPC summaries |
| `slowest_rpc_ms` | Caller transport wall time for that call, including dropped futures; includes the final flush, excludes the driver's guarded commit |
| `slice_stop_reason` | Slice limit or boundary that ended Extract work |
| `extract_chain_stop_reason` | Exact extraction selection-chain stop reason |
| `extract_chunk_stop_reason` | Exact last chunk-walk stop reason, when a chunk walk ran |

The normalized slice reasons include `step_cap`, `elapsed_cutoff`,
`call_allowance`, `operation_allowance`, and `chunk_boundary`; exact chain
reasons retain the labels listed above.

Absent values mean unavailable evidence, rather than zero or false. Physical
alarm scheduling is remembered only in memory; telemetry does not read storage
to reconstruct it. Logical timer lag remains available after a cold start. Consecutive tiny slices
retain the same durable timer key, so their timer lag includes earlier inline
slices; it does not mean that another physical alarm was scheduled.
Runtime retry and physical schedule metadata depend on the host forwarding
those observations. Without them, the corresponding fields remain unknown.
The last-armed hint alone is never treated as a retry's physical schedule.

For a gap, first compare physical alarm delay with logical timer delay. A large
physical delay points to alarm scheduling. A small physical delay and large
timer delay points to earlier work in the same callback. Group by cold flag
and retry evidence, then inspect the slowest partition call and stop reason.
For runtime retries, inspect adjacent platform error entries for a failure
cause; the retry metadata alone cannot establish a disconnect. Unknown
scheduling or failure fields cannot establish a cause. The host clock
semantics still apply to synchronous work within the slice.

## Fork step events

With the feature enabled, every `fork::step` execution — one per request
attempt and one per kind-16 timer fire that reaches a step — emits one
`fork_step` row, and the step whose apply committed `Done` or `Failed` emits
one `fork_step_summary`
row. A timer fire that lands on an already-terminal job emits its own
`fork_step` row but no second summary; a fire on a deleted job ends its timer
before stepping and emits none.
Events carry constant labels, counts,
and durations only: `job` is the truncated request-binding hash, never a
repository name or object id.

| Event | Fields |
|---|---|
| `fork_step` | `driver` (`request` or `alarm`, from the runtime's timer context), `job`, `phase_in`, `phase_out`, `wall_ms`, `calls` and per-partition-kind splits (`calls_coordinator`, `calls_content`, `calls_ref`, `calls_repo_index`, `calls_ref_index`, `calls_namespace`), `serial_rounds` (calls that started while no other call was in flight), `applies`, `cas_losses` (applies lost to `PreconditionFailed`), `budget_calls` (slice-budget spend), `progressed`, `finished`, `error`, and when `driver = alarm` the same timer metadata fields as `verification_slice_result` (`timer_scheduled_ms`, `logical_due_ms`, `timer_retry_attempt`, `timer_delay_ms`) |
| `fork_step_summary` | `job`, `request_steps`, `alarm_steps`, `cas_losses`: totals over every step that ran the job to its terminal phase |

Phase names are `plan`, `trees`, `walk`, `register`, `copy`, `count`,
`publish`, `done`, `failed`, and `absent` (no job row on entry); `phase_out`
is `-` when the step errored before reporting. The `driver`
split and `cas_losses` answer the dual-driver question directly: an alarm
that fires while the request's slices run the job appears as interleaved
`request`/`alarm` rows for one `job`, and each `PreconditionFailed` apply is
a lost slice's commit.

## Compare verification overhead

The verification harness runs 50 fresh jobs over an 18-entry pack. Profile
the same test binary configuration with and without `perf-metrics`, using
`indexed::job_tests::performance::verification_instrumentation_cost_probe`.
It checks final storage snapshots, counts slices and logical store calls,
and prints total tracing rows and bytes, plus counts for new events.
Compare total bytes: added fields on existing events do not count as new rows.
Its metrics sink discards observations, so console metric rows are additional.

Build first, then run each already-built binary under `/usr/bin/time` at least
three times in alternating order. Report the median process CPU (user plus
system), range, row and byte totals, matching call counts, and final snapshot
digest in the change's validation report. Startup, fixture construction, and
JSON formatting are included. These native debug-build observations are not
production estimates or regression thresholds.
