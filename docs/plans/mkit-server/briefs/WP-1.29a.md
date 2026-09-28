## Purpose

Operators must learn that a shard is filling up **before** writes fail.

Today, on Workers, every `tracing` event and every metric is discarded: the adapter uses `NoopMetrics`, and no
subscriber is installed. So even the existing P-24 "partition full" alert is invisible there. Natively, the metrics
facade has no exporter, and there's no backup command.

## A. Fixed (do not change)

1. **Plan:** `m1-m2-breakdown.md` "WP-1.29"; `00-plan.md` C-2, P-24 (partition full: a critical alert), R-26, R-88(7)
   (`WORKERS_PLAN=free` stays).
2. **Capacity:**
   - DO caps come from `WORKERS_PLAN` (1 GB Free, 10 GB Paid; `do_sql.rs`, `adapter::plan_capacity`);
   - the store refuses put batches at `Capacity::soft_limit()` (`sql/capacity.rs`), reading the **physical**
     `databaseSize` on every put batch (`sql/kv.rs`);
   - `stats().bytes` is **logical** bytes. That is not the number the cap applies to.
   - Natively the cap is database-wide (`--sqlite-max-bytes`).
3. **`telemetry.rs` `Metrics`** has `incr` and `observe_ms`, and no gauge. The existing P-24 counter is
   `mkit_server_partition_full` (`pipeline/mod.rs`).
4. **Native backup** already exists as `RusqliteConn::backup_to` (`VACUUM INTO`, `sqlite.rs:~296`). The destination
   must not exist.

## B. Decided by the orchestrator (do not change)

### B.1 Worker log and metric sinks

- **A `ConsoleMetrics` implementation of `Metrics`** in `mkit-server-worker`:
  - it emits one structured `console_log!` JSON line per `incr`, `observe_ms` and `gauge` call: `{"metric": name,
    "labels": {...}, "value": n}`;
  - it replaces `NoopMetrics` in the adapter;
  - `observe_ms` is **sampled at 1-in-100** to keep log volume bounded, and documented; counters and gauges are
    never sampled.
- **A minimal `tracing` subscriber** for wasm32, installed once per isolate (e.g. through a `OnceCell` in the
  adapter):
  - it formats `warn`/`error` events as JSON through `console_error!` and `info` through `console_log!`;
  - `debug`/`trace` are off;
  - no new dependency beyond `tracing-subscriber`'s minimal features, **if** the wasm dependency-graph check allows
    it; otherwise implement a tiny `tracing::Subscriber` by hand (C).

### B.2 `Metrics::gauge`

- Add `fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {}`, a **provided no-op**
  default, so existing implementors are unchanged.
- Implement it in `MetricsBridge` (native) and `ConsoleMetrics` (Worker).

### B.3 Storage-pressure alerts

- **Worker, write path:** in `NsObject`, after a **committed** batch that contained a put, read
  `conn().size_bytes()`.
  - Compare it to the object's `Capacity::soft_limit()`: **70% → warn**, **90% → critical**.
  - Emit a structured log (`event: "storage_pressure"`, `level`, `kind` = the `ShardClass` label, `bytes`,
    `limit_bytes`, `pct`) and `gauge("mkit_server_partition_bytes", [("kind", …)], bytes)`.
  - **Rate-limit per instance:** at most once per level per 10 minutes, with hysteresis. A level clears only when it
    drops 5 points below its threshold.
  - No new DO calls: the size read is local.
- **Native, periodic:** a background task every 60 s (reuse the server's runtime and `Shutdown`) reads the
  database-wide size against `--sqlite-max-bytes`, with the same thresholds, events and gauge (`kind = "database"`).
  It runs only for the SQLite metadata choice.
- **P-24:**
  - rename the counter to `mkit_server_partition_full_total`, with label `kind` (the partition kind: `namespace`,
    `coordinator`, `ref`, `repo_index`, `ref_index`, `content`);
  - keep the existing `tracing::error!`;
  - update any test that names the old metric.

### B.4 Native `backup` subcommand

- `mkit-server backup --meta sqlite:<PATH> --out <FILE>` runs `VACUUM INTO`. It's safe while a server runs (WAL, a
  separate reader).
- It refuses an existing `<FILE>`: `USAGE` 64.
- It prints the output path and size.
- A matching README section explains `backup` versus the forthcoming portable export and restore (1.29b), and that a
  restored database must be restarted with the same `--sharding` (R-93).

### B.5 Plan rows

Add row **R-107** to `00-plan.md`:

> WP-1.29 is split.
> - **1.29a:** observability (Worker console sinks, `Metrics::gauge`, storage-pressure alerts at 70%/90% of the
>   physical soft limit on the write path (Worker) and every 60 s (native), P-24 labelled by kind) and native
>   `backup`.
> - **1.29b** (depends on 1.25 and 1.23a, both merged): a per-DO snapshot export to a `BACKUPS` R2 bucket via timer
>   kind 4, seeded on the first committed put, as a synchronous single-`fire` snapshot capped by size, keyed by the
>   BLAKE3 of `Partition::encode`; plus a core restore driver in dependency order (root `sm` first, coordinators with
>   `mark_lease_table_recovered` (R-100) and epoch non-decrease, ref shards with `os` re-keyed above targets' `rh`
>   (R-102)), native `export`/`restore`, and a runbook.
> - PITR is the primary in-place restore within 30 days; the export covers disaster recovery and backend migration.

## C. Your decisions

- The `tracing` subscriber implementation (B.1), within the wasm dependency rules.
- The exact JSON field names beyond those given, and the rate-limit bookkeeping.
- Test organisation.

## Tests (required)

1. `ConsoleMetrics`, host-testable through an injectable sink: each call emits the expected JSON, and sampling works.
2. **The pressure logic, as a pure function:** thresholds, hysteresis and rate limiting with an injected clock. Plus
   one `NsObject` host test through the existing DO shim, if feasible.
3. **Native:** the size task emits warn/critical against a small `--sqlite-max-bytes`, and stops on shutdown.
4. **Native `backup`:** it produces a database that opens and holds the same rows, and an existing `--out` is refused.
5. **P-24:** the renamed metric with its `kind` label.
6. **Unchanged:** every existing test.

## D. Escalate if

- The wasm dependency-graph check (`scripts/check-wasm-dep-graph.sh`) rejects every viable subscriber option.
- Reading `size_bytes()` after a commit isn't possible without a JS await that opens the input gate.

## Gates

- `just ci-server`
- `cargo nextest run --locked -p mkit-server -p mkit-server-native -p mkit-server-worker --all-features`
- the wasm32 check and the worker build
- `scripts/check-wasm-dep-graph.sh`
- `scripts/vcs-worker-conformance.sh` (default phase)
