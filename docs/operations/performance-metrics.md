# Performance measurements

Enable the `perf-metrics` Cargo feature on `mkit-server-worker` to collect
bounded storage and verification measurements. It forwards the same feature
to the generic `mkit-server` core. The reference Worker forwards this feature:

```sh
worker-build --features launch,perf-metrics
```

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
- Filter `event = verification_await_hint_histogram`; sum the hint bucket counts and
  inspect `hint_ms` to compare client advice with observed delivery waits.
- Select invocation logs; calculate CPU and wall-time percentiles with
  `$workers.cpuTimeMs` and `$workers.wallTimeMs`. Profile synchronous work
  locally before deciding to change SQL stepping or Decode checkpointing.

## Bounds, privacy, and regression checks

RPC accounting uses eight bucket counters and at most four fixed-shape call
records, flushing one row per 100 calls plus one lifetime tail. SQL accounting
uses five numeric totals with no statement logs. Denial aggregates use nine
counters per active stage. Emit aggregates use six duration totals.
No collector accepts a repository name, namespace, key bytes, object ID,
credential, SQL text, value, cursor, or error message.

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

### Native verification cost sample

The verification harness runs 50 fresh jobs over an 18-entry pack. Profile
the same test binary configuration with and without `perf-metrics`, using
`indexed::job_tests::performance::verification_instrumentation_cost_probe`.
Three alternating runs of each configuration produced:

| Measurement | Feature off | Feature on |
|---|---:|---:|
| Median process CPU (user + system) | 0.38 s | 0.41 s |
| CPU range | 0.37–0.54 s | 0.39–0.54 s |
| Slices / logical store calls | 150 / 2650 | 150 / 2650 |
| Tracing rows | 1250 | 1850 |
| Tracing bytes | 428200 | 532550 |
| New tracing rows / bytes per job | 0 / 0 | 12 / 2087 |

Final storage snapshots match. This debug-build sample includes process
startup, fixture construction, and JSON formatting. It measures tracing rows;
its metrics sink discards metric observations, so console metric rows are
additional. Shared-load ranges overlap: the roughly 8% median CPU increase
is a harness observation, not a production estimate or regression threshold.

### Native scan cost sample

Three alternating runs of each mode, each issuing 64 scans, produced:

| Measurement | Raw SQL baseline | Collector disabled | Collector enabled |
|---|---:|---:|---:|
| Median process CPU (user + system) | 0.72 s | 0.73 s | 0.73 s |
| CPU range | 0.72–0.72 s | 0.72–0.73 s | 0.73–0.73 s |
| New RPC summary rows | 0 | 0 | 1 |
| New RPC summary bytes | 0 | 0 | 1135–1152 |
| New per-statement log rows | 0 | 0 | 0 |

Each reply is byte-identical. The enabled run counts 3584 queries and 54272
materialized rows. Its roughly 1% median CPU increase has the same native
debug-build and process-level limits as the verification sample. The disabled
mode exercises an unmeasured wrapper within the feature-enabled test binary;
default production builds compile the wrapper and collectors out. These
numbers establish a repeatable harness and bounded log volume, not Workers
SQL CPU share.
