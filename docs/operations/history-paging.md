# History continuation paging measurements

The `continuation_pages_complete_long_changing_histories_without_cursor_walk`
test completes every page of 201- and 302-commit changing histories, with new
readers and sessions for each request, in owner/public views and denial OFF/ON.
Canonical bytes and IDs match the fixture's commits in first-parent order.
Every page performs exactly two raw range GETs per returned commit, with zero
history/tree cursor walk. The independent
`continuation_selected_ref_overhead_is_bounded_independently_of_cursor_depth`
test measures **six additional physical calls/rounds with denial OFF and seven
with denial ON**, in both views, relative to the selected-ref history primitive.

Reproduce from `rust/`:

```sh
CARGO_PROFILE_DEV_DEBUG=0 cargo test --locked -p mkit-server --all-features --lib continuation_pages_complete_long_changing_histories_without_cursor_walk -- --ignored --nocapture --test-threads=1
```

The default lane covers a 40-commit changing history over four/six pages, using
the same canonical-byte, budget, fixed-expiry and no-cursor-walk assertions in
all view/denial/latency configurations. The full fixture runs explicitly in the
serial `ignored-lane` profile in GitHub Actions and Cloud Build. Its standalone
debug measurement used 13.10 s CPU and 14.17 s wall time; parallel Cloud Build
exceeded the default 60 s ceiling. The slow lane retains every assertion and a
bounded 300 s timeout. No production allowance or general timeout changes.

These are bounded memory-store dispatch measurements with a fixed business
clock. Reader units retain the 8,500-unit request allowance, including parsing,
security reads and page work. Reader construction is included in physical calls;
its separate authorization allowance is outside the session ledger. The
201-commit fixture has one real indexed pack per commit and distinct nested
snapshots. The 302-commit fixture packs two commits per upload, with distinct
files and trees, to remain within the existing fixture write quota. No reader
or production write allowance is increased. The first paging request in a
repository may perform one coordinator apply to activate its retained visibility
revision; following visibility writes maintain that fence even without token
issuance configured.

Physical calls are KV dispatches plus twice the ranged GET count, modeling the
adapter's HEAD then GET. Paused Tokio time injects 30 ms and 130 ms RPC waits
through the reader-batching latency probe. All continuation reads share the
existing six-call I/O admission envelope. Blob delays include both sequential
range RPCs. The fixture performs reader construction and guarded applies without
delay; the reported wait adds their physical calls serially at the selected RPC
latency. The table records virtual wait and its equivalent RPC rounds, including
Tokio timer granularity. It does not assume a fixed number of denial waves.

The business clock stays fixed while virtual time measures storage waits. These
figures are recorded without a latency gate and are not observed deployment
latency or p95. Real expiry, deadlines, queues, CPU and nonempty denial directories
can terminate slower requests. The measurements establish paging budget
completion. Canonical windows and permission/denial caches are absent.

| History | Page size | Page | View | Denial | RPC latency (ms) | Units | KV | Range GETs | Physical calls | Equivalent rounds | Virtual wait (s) |
|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 201 | 30 | 1 | public | OFF | 30 | 612 | 369 | 60 | 489 | 379.00 | 11.370 |
| 201 | 30 | 2 | public | OFF | 30 | 611 | 368 | 60 | 488 | 378.00 | 11.340 |
| 201 | 30 | 3 | public | OFF | 30 | 610 | 367 | 60 | 487 | 378.00 | 11.340 |
| 201 | 30 | 4 | public | OFF | 30 | 610 | 367 | 60 | 487 | 378.00 | 11.340 |
| 201 | 30 | 5 | public | OFF | 30 | 611 | 368 | 60 | 488 | 378.00 | 11.340 |
| 201 | 30 | 6 | public | OFF | 30 | 611 | 368 | 60 | 488 | 378.00 | 11.340 |
| 201 | 30 | 7 | public | OFF | 30 | 431 | 260 | 42 | 344 | 267.00 | 8.010 |
| 201 | 30 | 1 | public | OFF | 130 | 611 | 368 | 60 | 488 | 378.00 | 49.140 |
| 201 | 30 | 2 | public | OFF | 130 | 611 | 368 | 60 | 488 | 378.00 | 49.140 |
| 201 | 30 | 3 | public | OFF | 130 | 610 | 367 | 60 | 487 | 378.00 | 49.140 |
| 201 | 30 | 4 | public | OFF | 130 | 610 | 367 | 60 | 487 | 378.00 | 49.140 |
| 201 | 30 | 5 | public | OFF | 130 | 611 | 368 | 60 | 488 | 378.00 | 49.140 |
| 201 | 30 | 6 | public | OFF | 130 | 611 | 368 | 60 | 488 | 378.00 | 49.140 |
| 201 | 30 | 7 | public | OFF | 130 | 431 | 260 | 42 | 344 | 267.00 | 34.710 |
| 201 | 100 | 1 | public | OFF | 30 | 2007 | 1204 | 200 | 1604 | 1241.00 | 37.230 |
| 201 | 100 | 2 | public | OFF | 30 | 2006 | 1203 | 200 | 1603 | 1241.00 | 37.230 |
| 201 | 100 | 3 | public | OFF | 30 | 31 | 20 | 2 | 24 | 21.00 | 0.630 |
| 201 | 100 | 1 | public | OFF | 130 | 2007 | 1204 | 200 | 1604 | 1241.00 | 161.330 |
| 201 | 100 | 2 | public | OFF | 130 | 2006 | 1203 | 200 | 1603 | 1241.00 | 161.330 |
| 201 | 100 | 3 | public | OFF | 130 | 31 | 20 | 2 | 24 | 21.00 | 2.730 |
| 201 | 30 | 1 | owner | OFF | 30 | 611 | 369 | 60 | 489 | 379.00 | 11.370 |
| 201 | 30 | 2 | owner | OFF | 30 | 611 | 369 | 60 | 489 | 379.00 | 11.370 |
| 201 | 30 | 3 | owner | OFF | 30 | 610 | 368 | 60 | 488 | 379.00 | 11.370 |
| 201 | 30 | 4 | owner | OFF | 30 | 610 | 368 | 60 | 488 | 379.00 | 11.370 |
| 201 | 30 | 5 | owner | OFF | 30 | 611 | 369 | 60 | 489 | 379.00 | 11.370 |
| 201 | 30 | 6 | owner | OFF | 30 | 611 | 369 | 60 | 489 | 379.00 | 11.370 |
| 201 | 30 | 7 | owner | OFF | 30 | 431 | 261 | 42 | 345 | 268.00 | 8.040 |
| 201 | 30 | 1 | owner | OFF | 130 | 611 | 369 | 60 | 489 | 379.00 | 49.270 |
| 201 | 30 | 2 | owner | OFF | 130 | 611 | 369 | 60 | 489 | 379.00 | 49.270 |
| 201 | 30 | 3 | owner | OFF | 130 | 610 | 368 | 60 | 488 | 379.00 | 49.270 |
| 201 | 30 | 4 | owner | OFF | 130 | 610 | 368 | 60 | 488 | 379.00 | 49.270 |
| 201 | 30 | 5 | owner | OFF | 130 | 611 | 369 | 60 | 489 | 379.00 | 49.270 |
| 201 | 30 | 6 | owner | OFF | 130 | 611 | 369 | 60 | 489 | 379.00 | 49.270 |
| 201 | 30 | 7 | owner | OFF | 130 | 431 | 261 | 42 | 345 | 268.00 | 34.840 |
| 201 | 100 | 1 | owner | OFF | 30 | 2007 | 1205 | 200 | 1605 | 1242.00 | 37.260 |
| 201 | 100 | 2 | owner | OFF | 30 | 2006 | 1204 | 200 | 1604 | 1242.00 | 37.260 |
| 201 | 100 | 3 | owner | OFF | 30 | 31 | 21 | 2 | 25 | 22.00 | 0.660 |
| 201 | 100 | 1 | owner | OFF | 130 | 2007 | 1205 | 200 | 1605 | 1242.00 | 161.460 |
| 201 | 100 | 2 | owner | OFF | 130 | 2006 | 1204 | 200 | 1604 | 1242.00 | 161.460 |
| 201 | 100 | 3 | owner | OFF | 130 | 31 | 21 | 2 | 25 | 22.00 | 2.860 |
| 201 | 30 | 1 | public | ON | 30 | 1287 | 1044 | 60 | 1164 | 651.00 | 19.530 |
| 201 | 30 | 2 | public | ON | 30 | 1287 | 1044 | 60 | 1164 | 651.00 | 19.530 |
| 201 | 30 | 3 | public | ON | 30 | 1286 | 1043 | 60 | 1163 | 651.00 | 19.530 |
| 201 | 30 | 4 | public | ON | 30 | 1285 | 1042 | 60 | 1162 | 650.00 | 19.500 |
| 201 | 30 | 5 | public | ON | 30 | 1287 | 1044 | 60 | 1164 | 651.00 | 19.530 |
| 201 | 30 | 6 | public | ON | 30 | 1287 | 1044 | 60 | 1164 | 651.00 | 19.530 |
| 201 | 30 | 7 | public | ON | 30 | 909 | 738 | 42 | 822 | 459.00 | 13.770 |
| 201 | 30 | 1 | public | ON | 130 | 1287 | 1044 | 60 | 1164 | 651.00 | 84.630 |
| 201 | 30 | 2 | public | ON | 130 | 1287 | 1044 | 60 | 1164 | 651.00 | 84.630 |
| 201 | 30 | 3 | public | ON | 130 | 1286 | 1043 | 60 | 1163 | 651.00 | 84.630 |
| 201 | 30 | 4 | public | ON | 130 | 1285 | 1042 | 60 | 1162 | 650.00 | 84.500 |
| 201 | 30 | 5 | public | ON | 130 | 1287 | 1044 | 60 | 1164 | 651.00 | 84.630 |
| 201 | 30 | 6 | public | ON | 130 | 1287 | 1044 | 60 | 1164 | 651.00 | 84.630 |
| 201 | 30 | 7 | public | ON | 130 | 909 | 738 | 42 | 822 | 459.00 | 59.670 |
| 201 | 100 | 1 | public | ON | 30 | 4223 | 3420 | 200 | 3820 | 2144.00 | 64.320 |
| 201 | 100 | 2 | public | ON | 30 | 4221 | 3418 | 200 | 3818 | 2143.00 | 64.290 |
| 201 | 100 | 3 | public | ON | 30 | 69 | 58 | 2 | 62 | 33.00 | 0.990 |
| 201 | 100 | 1 | public | ON | 130 | 4223 | 3420 | 200 | 3820 | 2144.00 | 278.720 |
| 201 | 100 | 2 | public | ON | 130 | 4221 | 3418 | 200 | 3818 | 2143.00 | 278.590 |
| 201 | 100 | 3 | public | ON | 130 | 69 | 58 | 2 | 62 | 33.00 | 4.290 |
| 201 | 30 | 1 | owner | ON | 30 | 1287 | 1045 | 60 | 1165 | 652.00 | 19.560 |
| 201 | 30 | 2 | owner | ON | 30 | 1287 | 1045 | 60 | 1165 | 652.00 | 19.560 |
| 201 | 30 | 3 | owner | ON | 30 | 1286 | 1044 | 60 | 1164 | 652.00 | 19.560 |
| 201 | 30 | 4 | owner | ON | 30 | 1285 | 1043 | 60 | 1163 | 651.00 | 19.530 |
| 201 | 30 | 5 | owner | ON | 30 | 1287 | 1045 | 60 | 1165 | 652.00 | 19.560 |
| 201 | 30 | 6 | owner | ON | 30 | 1287 | 1045 | 60 | 1165 | 652.00 | 19.560 |
| 201 | 30 | 7 | owner | ON | 30 | 909 | 739 | 42 | 823 | 460.00 | 13.800 |
| 201 | 30 | 1 | owner | ON | 130 | 1287 | 1045 | 60 | 1165 | 652.00 | 84.760 |
| 201 | 30 | 2 | owner | ON | 130 | 1287 | 1045 | 60 | 1165 | 652.00 | 84.760 |
| 201 | 30 | 3 | owner | ON | 130 | 1286 | 1044 | 60 | 1164 | 652.00 | 84.760 |
| 201 | 30 | 4 | owner | ON | 130 | 1285 | 1043 | 60 | 1163 | 651.00 | 84.630 |
| 201 | 30 | 5 | owner | ON | 130 | 1287 | 1045 | 60 | 1165 | 652.00 | 84.760 |
| 201 | 30 | 6 | owner | ON | 130 | 1287 | 1045 | 60 | 1165 | 652.00 | 84.760 |
| 201 | 30 | 7 | owner | ON | 130 | 909 | 739 | 42 | 823 | 460.00 | 59.800 |
| 201 | 100 | 1 | owner | ON | 30 | 4223 | 3421 | 200 | 3821 | 2145.00 | 64.350 |
| 201 | 100 | 2 | owner | ON | 30 | 4221 | 3419 | 200 | 3819 | 2144.00 | 64.320 |
| 201 | 100 | 3 | owner | ON | 30 | 69 | 59 | 2 | 63 | 34.00 | 1.020 |
| 201 | 100 | 1 | owner | ON | 130 | 4223 | 3421 | 200 | 3821 | 2145.00 | 278.850 |
| 201 | 100 | 2 | owner | ON | 130 | 4221 | 3419 | 200 | 3819 | 2144.00 | 278.720 |
| 201 | 100 | 3 | owner | ON | 130 | 69 | 59 | 2 | 63 | 34.00 | 4.420 |
| 302 | 30 | 1 | public | OFF | 30 | 597 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 2 | public | OFF | 30 | 595 | 352 | 60 | 472 | 376.00 | 11.280 |
| 302 | 30 | 3 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 4 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 5 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 6 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 7 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 8 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 9 | public | OFF | 30 | 595 | 352 | 60 | 472 | 376.00 | 11.280 |
| 302 | 30 | 10 | public | OFF | 30 | 596 | 353 | 60 | 473 | 376.00 | 11.280 |
| 302 | 30 | 11 | public | OFF | 30 | 50 | 31 | 4 | 39 | 33.00 | 0.990 |
| 302 | 30 | 1 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 2 | public | OFF | 130 | 595 | 352 | 60 | 472 | 376.00 | 48.880 |
| 302 | 30 | 3 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 4 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 5 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 6 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 7 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 8 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 9 | public | OFF | 130 | 595 | 352 | 60 | 472 | 376.00 | 48.880 |
| 302 | 30 | 10 | public | OFF | 130 | 596 | 353 | 60 | 473 | 376.00 | 48.880 |
| 302 | 30 | 11 | public | OFF | 130 | 50 | 31 | 4 | 39 | 33.00 | 4.290 |
| 302 | 100 | 1 | public | OFF | 30 | 1957 | 1154 | 200 | 1554 | 1233.00 | 36.990 |
| 302 | 100 | 2 | public | OFF | 30 | 1959 | 1156 | 200 | 1556 | 1233.00 | 36.990 |
| 302 | 100 | 3 | public | OFF | 30 | 1955 | 1152 | 200 | 1552 | 1232.00 | 36.960 |
| 302 | 100 | 4 | public | OFF | 30 | 50 | 31 | 4 | 39 | 33.00 | 0.990 |
| 302 | 100 | 1 | public | OFF | 130 | 1957 | 1154 | 200 | 1554 | 1233.00 | 160.290 |
| 302 | 100 | 2 | public | OFF | 130 | 1959 | 1156 | 200 | 1556 | 1233.00 | 160.290 |
| 302 | 100 | 3 | public | OFF | 130 | 1955 | 1152 | 200 | 1552 | 1232.00 | 160.160 |
| 302 | 100 | 4 | public | OFF | 130 | 50 | 31 | 4 | 39 | 33.00 | 4.290 |
| 302 | 30 | 1 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 2 | owner | OFF | 30 | 595 | 353 | 60 | 473 | 377.00 | 11.310 |
| 302 | 30 | 3 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 4 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 5 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 6 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 7 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 8 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 9 | owner | OFF | 30 | 595 | 353 | 60 | 473 | 377.00 | 11.310 |
| 302 | 30 | 10 | owner | OFF | 30 | 596 | 354 | 60 | 474 | 377.00 | 11.310 |
| 302 | 30 | 11 | owner | OFF | 30 | 50 | 32 | 4 | 40 | 34.00 | 1.020 |
| 302 | 30 | 1 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 2 | owner | OFF | 130 | 595 | 353 | 60 | 473 | 377.00 | 49.010 |
| 302 | 30 | 3 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 4 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 5 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 6 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 7 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 8 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 9 | owner | OFF | 130 | 595 | 353 | 60 | 473 | 377.00 | 49.010 |
| 302 | 30 | 10 | owner | OFF | 130 | 596 | 354 | 60 | 474 | 377.00 | 49.010 |
| 302 | 30 | 11 | owner | OFF | 130 | 50 | 32 | 4 | 40 | 34.00 | 4.420 |
| 302 | 100 | 1 | owner | OFF | 30 | 1957 | 1155 | 200 | 1555 | 1234.00 | 37.020 |
| 302 | 100 | 2 | owner | OFF | 30 | 1959 | 1157 | 200 | 1557 | 1234.00 | 37.020 |
| 302 | 100 | 3 | owner | OFF | 30 | 1955 | 1153 | 200 | 1553 | 1233.00 | 36.990 |
| 302 | 100 | 4 | owner | OFF | 30 | 50 | 32 | 4 | 40 | 34.00 | 1.020 |
| 302 | 100 | 1 | owner | OFF | 130 | 1957 | 1155 | 200 | 1555 | 1234.00 | 160.420 |
| 302 | 100 | 2 | owner | OFF | 130 | 1959 | 1157 | 200 | 1557 | 1234.00 | 160.420 |
| 302 | 100 | 3 | owner | OFF | 130 | 1955 | 1153 | 200 | 1553 | 1233.00 | 160.290 |
| 302 | 100 | 4 | owner | OFF | 130 | 50 | 32 | 4 | 40 | 34.00 | 4.420 |
| 302 | 30 | 1 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 2 | public | ON | 30 | 1256 | 1013 | 60 | 1133 | 634.00 | 19.020 |
| 302 | 30 | 3 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 4 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 5 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 6 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 7 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 8 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 9 | public | ON | 30 | 1256 | 1013 | 60 | 1133 | 634.00 | 19.020 |
| 302 | 30 | 10 | public | ON | 30 | 1257 | 1014 | 60 | 1134 | 634.00 | 19.020 |
| 302 | 30 | 11 | public | ON | 30 | 109 | 90 | 4 | 98 | 53.00 | 1.590 |
| 302 | 30 | 1 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 2 | public | ON | 130 | 1256 | 1013 | 60 | 1133 | 634.00 | 82.420 |
| 302 | 30 | 3 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 4 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 5 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 6 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 7 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 8 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 9 | public | ON | 130 | 1256 | 1013 | 60 | 1133 | 634.00 | 82.420 |
| 302 | 30 | 10 | public | ON | 130 | 1257 | 1014 | 60 | 1134 | 634.00 | 82.420 |
| 302 | 30 | 11 | public | ON | 130 | 109 | 90 | 4 | 98 | 53.00 | 6.890 |
| 302 | 100 | 1 | public | ON | 30 | 4123 | 3320 | 200 | 3720 | 2086.00 | 62.580 |
| 302 | 100 | 2 | public | ON | 30 | 4125 | 3322 | 200 | 3722 | 2086.00 | 62.580 |
| 302 | 100 | 3 | public | ON | 30 | 4121 | 3318 | 200 | 3718 | 2085.00 | 62.550 |
| 302 | 100 | 4 | public | ON | 30 | 109 | 90 | 4 | 98 | 53.00 | 1.590 |
| 302 | 100 | 1 | public | ON | 130 | 4123 | 3320 | 200 | 3720 | 2086.00 | 271.180 |
| 302 | 100 | 2 | public | ON | 130 | 4125 | 3322 | 200 | 3722 | 2086.00 | 271.180 |
| 302 | 100 | 3 | public | ON | 130 | 4121 | 3318 | 200 | 3718 | 2085.00 | 271.050 |
| 302 | 100 | 4 | public | ON | 130 | 109 | 90 | 4 | 98 | 53.00 | 6.890 |
| 302 | 30 | 1 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 2 | owner | ON | 30 | 1256 | 1014 | 60 | 1134 | 635.00 | 19.050 |
| 302 | 30 | 3 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 4 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 5 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 6 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 7 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 8 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 9 | owner | ON | 30 | 1256 | 1014 | 60 | 1134 | 635.00 | 19.050 |
| 302 | 30 | 10 | owner | ON | 30 | 1257 | 1015 | 60 | 1135 | 635.00 | 19.050 |
| 302 | 30 | 11 | owner | ON | 30 | 109 | 91 | 4 | 99 | 54.00 | 1.620 |
| 302 | 30 | 1 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 2 | owner | ON | 130 | 1256 | 1014 | 60 | 1134 | 635.00 | 82.550 |
| 302 | 30 | 3 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 4 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 5 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 6 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 7 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 8 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 9 | owner | ON | 130 | 1256 | 1014 | 60 | 1134 | 635.00 | 82.550 |
| 302 | 30 | 10 | owner | ON | 130 | 1257 | 1015 | 60 | 1135 | 635.00 | 82.550 |
| 302 | 30 | 11 | owner | ON | 130 | 109 | 91 | 4 | 99 | 54.00 | 7.020 |
| 302 | 100 | 1 | owner | ON | 30 | 4123 | 3321 | 200 | 3721 | 2087.00 | 62.610 |
| 302 | 100 | 2 | owner | ON | 30 | 4125 | 3323 | 200 | 3723 | 2087.00 | 62.610 |
| 302 | 100 | 3 | owner | ON | 30 | 4121 | 3319 | 200 | 3719 | 2086.00 | 62.580 |
| 302 | 100 | 4 | owner | ON | 30 | 109 | 91 | 4 | 99 | 54.00 | 1.620 |
| 302 | 100 | 1 | owner | ON | 130 | 4123 | 3321 | 200 | 3721 | 2087.00 | 271.310 |
| 302 | 100 | 2 | owner | ON | 130 | 4125 | 3323 | 200 | 3723 | 2087.00 | 271.310 |
| 302 | 100 | 3 | owner | ON | 130 | 4121 | 3319 | 200 | 3719 | 2086.00 | 271.180 |
| 302 | 100 | 4 | owner | ON | 130 | 109 | 91 | 4 | 99 | 54.00 | 7.020 |
