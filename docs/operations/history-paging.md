# History continuation paging measurements

The `continuation_pages_complete_long_changing_histories_without_cursor_walk`
test completes every page of 201- and 302-commit changing histories, with new
readers and sessions for each request, in owner/public views and denial OFF/ON.
Canonical bytes and IDs match the fixture's commits in first-parent order.
Every page performs exactly two raw range GETs per returned commit, with zero
history/tree cursor walk. The independent
`continuation_selected_ref_overhead_is_bounded_independently_of_cursor_depth`
test measures **seven additional physical calls/rounds**, for all four view/denial
combinations, relative to the selected-ref history primitive.

Reproduce from `rust/`:

```sh
CARGO_PROFILE_DEV_DEBUG=0 cargo test --locked -p mkit-server --all-features --lib continuation -- --nocapture --test-threads=1
```

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
adapter's HEAD then GET. Rounds subtract 12 for each completed strong denial
directory check: its 16 independent initial reads run in four waves. The empty
directory is checked once per returned node and once at the final page boundary.
The 30 ms and 130 ms columns are modeled ideal RPC waits, not observed latency
or p95. They are recorded without a latency gate. Real clocks, expiry, deadlines,
queues, CPU and nonempty denial directories can terminate slower requests;
these results establish paging budget completion, not a deployment latency
promise. Canonical windows and permission/denial caches are absent.

| History | Page size | Page | View | Denial | Units | KV | Range GETs | Physical calls | Rounds | Wait at 30 ms (s) | Wait at 130 ms (s) |
|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 201 | 30 | 1 | public | OFF | 675 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 2 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 201 | 30 | 3 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 201 | 30 | 4 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 201 | 30 | 5 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 201 | 30 | 6 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 201 | 30 | 7 | public | OFF | 476 | 305 | 42 | 389 | 389 | 11.67 | 50.57 |
| 201 | 100 | 1 | public | OFF | 2214 | 1411 | 200 | 1811 | 1811 | 54.33 | 235.43 |
| 201 | 100 | 2 | public | OFF | 2214 | 1411 | 200 | 1811 | 1811 | 54.33 | 235.43 |
| 201 | 100 | 3 | public | OFF | 36 | 25 | 2 | 29 | 29 | 0.87 | 3.77 |
| 201 | 30 | 1 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 2 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 3 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 4 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 5 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 6 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 201 | 30 | 7 | owner | OFF | 476 | 306 | 42 | 390 | 390 | 11.70 | 50.70 |
| 201 | 100 | 1 | owner | OFF | 2214 | 1412 | 200 | 1812 | 1812 | 54.36 | 235.56 |
| 201 | 100 | 2 | owner | OFF | 2214 | 1412 | 200 | 1812 | 1812 | 54.36 | 235.56 |
| 201 | 100 | 3 | owner | OFF | 36 | 26 | 2 | 30 | 30 | 0.90 | 3.90 |
| 201 | 30 | 1 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 2 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 3 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 4 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 5 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 6 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 201 | 30 | 7 | public | ON | 1080 | 909 | 42 | 993 | 729 | 21.87 | 94.77 |
| 201 | 100 | 1 | public | ON | 5030 | 4227 | 200 | 4627 | 3415 | 102.45 | 443.95 |
| 201 | 100 | 2 | public | ON | 5030 | 4227 | 200 | 4627 | 3415 | 102.45 | 443.95 |
| 201 | 100 | 3 | public | ON | 80 | 69 | 2 | 73 | 49 | 1.47 | 6.37 |
| 201 | 30 | 1 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 2 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 3 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 4 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 5 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 6 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 201 | 30 | 7 | owner | ON | 1080 | 910 | 42 | 994 | 730 | 21.90 | 94.90 |
| 201 | 100 | 1 | owner | ON | 5030 | 4228 | 200 | 4628 | 3416 | 102.48 | 444.08 |
| 201 | 100 | 2 | owner | ON | 5030 | 4228 | 200 | 4628 | 3416 | 102.48 | 444.08 |
| 201 | 100 | 3 | owner | ON | 80 | 70 | 2 | 74 | 50 | 1.50 | 6.50 |
| 302 | 30 | 1 | public | OFF | 675 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 2 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 3 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 4 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 5 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 6 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 7 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 8 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 9 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 10 | public | OFF | 674 | 431 | 60 | 551 | 551 | 16.53 | 71.63 |
| 302 | 30 | 11 | public | OFF | 58 | 39 | 4 | 47 | 47 | 1.41 | 6.11 |
| 302 | 100 | 1 | public | OFF | 2214 | 1411 | 200 | 1811 | 1811 | 54.33 | 235.43 |
| 302 | 100 | 2 | public | OFF | 2214 | 1411 | 200 | 1811 | 1811 | 54.33 | 235.43 |
| 302 | 100 | 3 | public | OFF | 2214 | 1411 | 200 | 1811 | 1811 | 54.33 | 235.43 |
| 302 | 100 | 4 | public | OFF | 58 | 39 | 4 | 47 | 47 | 1.41 | 6.11 |
| 302 | 30 | 1 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 2 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 3 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 4 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 5 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 6 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 7 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 8 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 9 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 10 | owner | OFF | 674 | 432 | 60 | 552 | 552 | 16.56 | 71.76 |
| 302 | 30 | 11 | owner | OFF | 58 | 40 | 4 | 48 | 48 | 1.44 | 6.24 |
| 302 | 100 | 1 | owner | OFF | 2214 | 1412 | 200 | 1812 | 1812 | 54.36 | 235.56 |
| 302 | 100 | 2 | owner | OFF | 2214 | 1412 | 200 | 1812 | 1812 | 54.36 | 235.56 |
| 302 | 100 | 3 | owner | OFF | 2214 | 1412 | 200 | 1812 | 1812 | 54.36 | 235.56 |
| 302 | 100 | 4 | owner | OFF | 58 | 40 | 4 | 48 | 48 | 1.44 | 6.24 |
| 302 | 30 | 1 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 2 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 3 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 4 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 5 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 6 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 7 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 8 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 9 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 10 | public | ON | 1530 | 1287 | 60 | 1407 | 1035 | 31.05 | 134.55 |
| 302 | 30 | 11 | public | ON | 130 | 111 | 4 | 119 | 83 | 2.49 | 10.79 |
| 302 | 100 | 1 | public | ON | 5030 | 4227 | 200 | 4627 | 3415 | 102.45 | 443.95 |
| 302 | 100 | 2 | public | ON | 5030 | 4227 | 200 | 4627 | 3415 | 102.45 | 443.95 |
| 302 | 100 | 3 | public | ON | 5030 | 4227 | 200 | 4627 | 3415 | 102.45 | 443.95 |
| 302 | 100 | 4 | public | ON | 130 | 111 | 4 | 119 | 83 | 2.49 | 10.79 |
| 302 | 30 | 1 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 2 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 3 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 4 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 5 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 6 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 7 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 8 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 9 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 10 | owner | ON | 1530 | 1288 | 60 | 1408 | 1036 | 31.08 | 134.68 |
| 302 | 30 | 11 | owner | ON | 130 | 112 | 4 | 120 | 84 | 2.52 | 10.92 |
| 302 | 100 | 1 | owner | ON | 5030 | 4228 | 200 | 4628 | 3416 | 102.48 | 444.08 |
| 302 | 100 | 2 | owner | ON | 5030 | 4228 | 200 | 4628 | 3416 | 102.48 | 444.08 |
| 302 | 100 | 3 | owner | ON | 5030 | 4228 | 200 | 4628 | 3416 | 102.48 | 444.08 |
| 302 | 100 | 4 | owner | ON | 130 | 112 | 4 | 120 | 84 | 2.52 | 10.92 |
