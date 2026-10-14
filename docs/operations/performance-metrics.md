# Performance measurements

Enable the `perf-metrics` Cargo feature on `mkit-server-worker` to collect
bounded storage and verification measurements. It forwards the same feature
to the generic `mkit-server` core. From the reference Worker's directory,
build and enable runtime alarm metadata forwarding:

```sh
rm -f build/worker/alarm-base.mjs
worker-build --features launch,perf-metrics
python3 ../../scripts/enable-worker-alarm-info.py build/worker/shim.mjs
```

The explicit post-build step preserves the SDK's default and named exports.
It replaces only the five classes' `alarm(info)` methods, forwarding to the
feature's additive `alarmWithInfo` export. Class identity, constructor, fetch,
WebSocket, connect, and other methods and static exports remain with the SDK. Repeat the step after every
fresh build and include both generated modules when packaging the Worker. The wire harness does this only for its feature-enabled matrix.
Default builds retain the original shim. Other embedders can use the same
helper on their generated shim or explicitly forward metadata to
`NsObject::alarm_with_info`.

Default builds omit the collectors, timers, header metadata, and new events.
The feature changes no storage query, page boundary, budget, retry hint,
authorization check, checkpoint, or public response body. It requires no store
reset. Enable it for a measurement window, then rebuild without it. Worker
factories install the existing console subscriber, including the embedding
pipeline when this feature is enabled. Native core embedders provide a metrics
sink and an INFO tracing subscriber through their existing setup.

## Clocks and CPU

Every custom duration is elapsed wall time, including waits. The Worker clock
has an additional limitation: Cloudflare freezes `Date.now()` and
`performance.now()` during synchronous execution. Decode CPU, SQL stepping,
base64, and JSON work can report zero despite consuming CPU. The `clock` field
on RPC summaries is `workers_io` on Workers and `monotonic` in native tests.
Never interpret these values as CPU time or subtract them to estimate CPU.
Caller-minus-inside time also includes any CPU tail hidden by the object clock;
it is not a pure network or activation estimate. Use platform trace durations
for the complete in-object span.
See [Cloudflare performance and timers](https://developers.cloudflare.com/workers/runtime-apis/performance/).

Use the platform invocation fields `$workers.cpuTimeMs` and
`$workers.wallTimeMs` for whole-invocation measurements. An alarm can run
several stages, so its CPU is not necessarily Decode CPU. Use a local workerd
CPU profile to isolate Decode and SQL; Cloudflare also supports capturing
production profiles. See [profiling CPU usage](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/).

The native scan harness separates SQL execution, cursor stepping, row
materialization, request decoding, reply encoding, and caller reply decoding.
It measures the same SQL and page driver over SQLite, but its timing is not a
prediction of the Workers JavaScript bridge. A later scan optimization needs a
local workerd profile showing SQL consumes more than roughly 40% of in-object
CPU. Production `sql_query_ms = 0` cannot establish that gate.

## Storage RPC summaries

Each `StubTransport` factory owns one collector shared by its clones. Request
clients flush the tail when their last clone is dropped. Long-lived alarm
clients flush every 100 completed or dropped call futures, then retain only
the next bounded window. This is a transport lifetime window, not necessarily
one HTTP request for an embedder that retains its pipeline.

One JSON row has `event = storage_rpc_summary`, `sample_window = 100`, `clock`,
and the `summary` object below. Every call contributes to counts and buckets;
only its four slowest calls retain detail. Ties retain the earlier calls.
This top-four selection is biased toward slow calls and is not a random sample.

| Field | Meaning |
|---|---|
| `summary.calls` | Call futures completed or dropped in this window |
| `summary.incomplete` | Futures canceled or failing before a successful transport response/body EOF; typed storage errors in an HTTP 200 reply count as complete |
| `summary.caller_ms` | Sum of caller transport wall times, from stub lookup through response-body EOF; concurrent durations overlap |
| `summary.caller_ms_buckets` | Eight disjoint count buckets: at most 1, 10, 50, 100, 250, 500, 1000 ms, then greater than 1000 ms |
| `summary.slowest` | At most four call objects, ordered by descending `caller_ms` |
| `slowest[].prefix` | Logical partition kind: `ri:`, `x:`, `ci:`, `r:`, `c:`, or `n:`; unsupported direct transport calls use `other` |
| `slowest[].op` | Storage operation, including `get_many`, `scan_many`, and `apply` |
| `slowest[].count` | Requested keys for `get_many`, ranges for `scan_many`, writes for `apply`; one for `get`, `scan`, or `export`, zero for scalar operations |
| `slowest[].caller_ms` | This call's transport wall time; excludes outer request serialization and caller reply JSON decoding |
| `slowest[].complete` | Whether a successful transport response reached body EOF |
| `slowest[].inside_ms` | In-object wall time from handler entry through reply construction, including request body read, activation repair, store initialization, and alarm maintenance |
| `slowest[].cold` | First HTTP request served by this object instance since construction; an earlier alarm does not consume this flag |
| `slowest[].decode_ms` | In-object request JSON/base64 and partition decode wall time |
| `slowest[].encode_ms` | In-object reply JSON/base64 encode wall time |
| `slowest[].sql_query_ms` | SQL query execution, cursor stepping and materialization wall time, excluding wire encode/decode |
| `slowest[].sql_statements` | Queries attempted, including failed queries; excludes non-query statements |
| `slowest[].rows` | Returned scan rows or present get values; excludes SQL lookahead rows; zero for scalar replies and errors |
| `slowest[].sql_rows` | SQL rows materialized by successful queries, including lookahead rows |

`ri:` names the repository-index kind; its existing routing name starts with
`i:`. Only the kind is logged, never that routing name. Missing reply metadata
is `null`, including transport failures and a build without the feature.
Repository-index activation hints use `op = ping`, their partition prefix, and
`count = 0`. Filter these calls separately from ordinary storage operations.
They share the same summary windows and top-four retention; no extra row is
emitted for a warm-up. A warm-up can consume the first-HTTP-request cold flag.


The internal request header `x-mkit-perf: 1` asks the object for numeric reply
metadata. The response header carries, in order, inside milliseconds, cold
(0 or 1), decode milliseconds, encode milliseconds, query milliseconds, query
count, materialized row count, returned row count, and schema marker 1. Bodies remain identical;
invalid or absent metadata never changes an RPC result. The object emits no
new per-query or per-RPC log rows.

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

Metrics use the existing envelope: `metric`, `labels`, and `value`. The console
sink samples duration observations on its existing isolate-wide cadence; use
the unsampled aggregate events for complete histograms and stage totals.
Counters are unsampled. Duration metric values saturate at `u32::MAX`
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
Runtime retry metadata requires the explicit post-build forwarding step above.
The unmodified SDK bridge and direct Rust calls to `NsObject::alarm` continue
to work, with unknown runtime retry fields and physical scheduling delay.
The last-armed hint alone is never treated as a retry's physical schedule.
See [Durable Object alarms](https://developers.cloudflare.com/durable-objects/api/alarms/).

For a gap, first compare physical alarm delay with logical timer delay. A large
physical delay points to alarm scheduling. A small physical delay and large
timer delay points to earlier work in the same callback. Group by cold flag
and retry evidence, then inspect the slowest partition call and stop reason.
For runtime retries, inspect adjacent platform error entries for a failure
cause; the retry metadata alone cannot establish a disconnect. Unknown
scheduling or failure fields cannot establish a cause. The Workers
clock limitation still applies to synchronous work within the slice.

## Fork step events

With the feature enabled, every `fork::step` execution — one per request
attempt and one per kind-16 timer fire that reaches a step — emits one
`fork_step` row, and the step whose apply committed `Done` or `Failed` emits
one `fork_step_summary`
row. A timer fire that lands on an already-terminal job emits its own
`fork_step` row but no second summary; a fire on a deleted job emits none.
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

## Query Workers observability

Enable JSON log collection in the deployment's Wrangler configuration:

```jsonc
{
  "observability": {
    "enabled": true,
    "head_sampling_rate": 1
  }
}
```

Open **Workers and Pages**, select the Worker, then **Observability** and
**Query Builder**. Filter the custom `event` field by one of the event names
above, choose the measurement time range, and inspect an event to confirm the
parsed field paths. Add Sum, Average, or a percentile calculation for a numeric
field, and group by a constant stage or component. Save each query for the next
before/after run. Platform sampling applies to the entire invocation; compare
runs using the same settings. See [Query Builder](https://developers.cloudflare.com/workers/observability/query-builder/)
and [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/).
The console uses JSON strings, matching the [structured logging example](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/#observability).

Useful saved queries:

- Filter `event = storage_rpc_summary`; sum `summary.calls` and each caller
  bucket. Inspect the slowest call objects by prefix, operation, and cold flag.
  Compare caller and inside wall time to investigate activation or transport
  delay; nested top-call arrays are details, not population percentiles.
- Filter `event = verification_denial_histogram`; group by `stage`, sum `calls`
  and all nine bucket fields. Compare denial distributions across Decode,
  EmitIndex, and inline verification without changing denial checks.
- Filter `event = verification_emit_components`; sum its six fields to separate
  scan, denial, direct writes, relay commit, and outbox lookup waits.
- Filter `event = verification_extract_chain`; group by `stop_reason` and
  `stage`, then count events and average `steps`. A high `calls` or `ops` share
  indicates a different limit from `steps` or `elapsed`.
- Filter `event = verification_slice_result` and `old_phase = Extract`; compare
  `alarm_delay_ms` and `timer_delay_ms`, group by `cold_first_slice`,
  `runtime_is_retry`, and `slice_stop_reason`, and inspect `slowest_rpc_prefix`
  and `slowest_rpc_ms` for slices around a gap.
- Filter `event = verification_await_hint_histogram`; sum the hint bucket counts and
  inspect `hint_ms` to compare client advice with observed delivery waits.
- Select invocation logs; calculate CPU and wall-time percentiles with
  `$workers.cpuTimeMs` and `$workers.wallTimeMs`. Profile synchronous work
  locally before deciding to change SQL stepping or Decode checkpointing.

## Bounds, privacy, and regression checks

RPC accounting uses eight bucket counters and at most four fixed-shape call
records, flushing one row per 100 calls plus one lifetime tail. SQL accounting
uses five numeric totals with no statement logs. Denial aggregates use nine
counters per active stage. Emit aggregates use six duration totals. Slice
context retains fixed metadata and one slowest call; it restores context at
every future poll so interleaved tasks cannot share measurements.
No new performance field accepts a repository name, namespace, key bytes,
object ID, credential, SQL text, value, cursor, or error message. The deferred
slice row carries only the identifiers already present in that existing event.

Run the heavy scan harness and the log-bound/privacy tests:

```sh
just cargo-cached test -p mkit-server-worker --features perf-metrics \
  --lib telemetry::perf_ -- --nocapture --test-threads=3
```

The harness returns the same scan reply bytes across baseline, unmeasured,
and measured SQL paths. Its fixture is eight ranges of 100 rows with 240-byte
values. Each scan attempts 56 queries and materializes 848 rows, including
lookahead, while returning 800 rows. Set `MKIT_PERF_COST_MODE` to `baseline`,
`disabled`, or `enabled` and profile the already-built test binary with
`/usr/bin/time` to compare process CPU without including compilation. Repeat
runs under comparable load; no noisy latency threshold is an assertion.

### Compare verification overhead

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

Apply the same alternating-run method to the three scan modes above. The
collector-disabled mode exercises an unmeasured wrapper in a feature-enabled
binary; default production builds omit both wrapper and collectors. Report
wire identity, query and materialized-row counts, summary bytes, and CPU.
Use a Workers profile to establish SQL CPU share or platform overhead.
