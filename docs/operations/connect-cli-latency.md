# CLI HTTPS connection reuse

The CLI routes Connect repository operations through `ClientSource` and
`mkit-client`. The native channel keeps one idle connection per origin for ten
seconds on its owned current-thread runtime. Reads and signed writes, including
streamed transfers, reuse that connection. TCP_NODELAY matches the previous
adapter. No runtime scheduler thread, dependency, or feature is added.

## Measurement

The `cli_https_latency_comparison` fixture drives separately built real CLI
binaries against the same Connect service and a TLS proxy with certificate-chain
and hostname verification enabled. It delays encrypted bytes by 25 ms in each
direction, including TLS handshake flights: 50 ms injected RTT, with local TCP
connection establishment. The server advertises HTTP/2 and HTTP/1.1. The old
adapter negotiates HTTP/2; the native channel negotiates HTTP/1.1.

Each comparison uses five samples per row, alternating binary order. Clone
follows six independently published packmap nodes. The small push publishes a
seventh commit; the following pull receives that commit. Every measured command
starts a fresh CLI process. The fixture verifies exact normalized stdout,
stderr, exit codes, refs, canonical object bytes, and pack/packmap ids and bytes.
The server and repositories are recreated for each sample. This is a small
repository latency comparison, not a throughput benchmark or a remote service
measurement. Shared-host timing noise is shown in the ranges.

The old-path source is merged #1438 (`e1dff395`); its CLI, adapter, native channel
and lockfile match the separately built approved parent tree. The switch before
reuse is `7df65e1b`. The second comparison changes only native connection reuse
and TCP_NODELAY in production. No other builds ran during either measurement.

Before the fix, median milliseconds (min–max), and new TLS connections:

| Operation | Old adapter | Switch before reuse | Old / switch connections |
| --- | ---: | ---: | ---: |
| Clone, six-node chain | 2493 (2388–2614) | 2250 (2161–2318) | 13 / 14 |
| Pull, no-op | 294 (280–312) | 313 (312–318) | 1 / 2 |
| Pull, one commit | 687 (651–802) | 729 (716–837) | 3 / 4 |
| Push, small commit | 1863 (1834–1908) | 1835 (1816–1937) | 9 / 13 |

After the fix, rerunning both binaries with the same fixture:

| Operation | Old adapter | Switch with reuse | Improvement | Old / switch connections |
| --- | ---: | ---: | ---: | ---: |
| Clone, six-node chain | 2452 (2435–2635) | 1186 (1028–1361) | 51.6% | 13 / 1 |
| Pull, no-op | 301 (282–311) | 240 (226–351) | 20.3% | 1 / 1 |
| Pull, one commit | 759 (677–800) | 442 (392–648) | 41.8% | 3 / 1 |
| Push, small commit | 1873 (1761–1940) | 897 (822–1236) | 52.1% | 9 / 1 |

Every median is lower than the old path. The old adapter pooled unary calls but
opened fresh connections for streamed transfers, accounting for its clone,
one-commit pull, and push counts. The restored pool includes transfers; it does
not introduce a separate read or write protocol implementation.

## Replay boundary

Hyper's automatic cancellation retry recovers only an untouched request from a
reused connection before writing starts. It does not clone or reconstruct the
request. Buffered bodies and streaming receivers, signed headers, nonces and
idempotency keys remain unchanged. Once the request starts writing, hyper
returns failures to the existing host recovery policy. Signed writes therefore
reuse connections under the same pre-start guarantee as reads; fresh write
connections are unnecessary.

The implementation was audited against hyper-util 0.1.20's
[`send_request`](https://docs.rs/hyper-util/0.1.20/src/hyper_util/client/legacy/client.rs.html)
and hyper 1.11.1's
[HTTP/1 dispatcher](https://docs.rs/hyper/1.11.1/src/hyper/proto/h1/dispatch.rs.html).
The [pool builder](https://docs.rs/hyper-util/0.1.20/hyper_util/client/legacy/struct.Builder.html#method.retry_canceled_requests)
documents that retry boundary. Pool checkout rejects elapsed idle connections
even when runtime tasks paused between calls; a Tokio pool timer also removes
idle entries when the runtime is driven. Response bodies are consumed before
reuse; partial or canceled exchanges do not contribute a reusable connection.

Native tests pin same-connection sequential reads and signed writes, expiration
while the runtime is paused, server closure between calls, exact streamed bytes
after an idle close, refusal to replay a fully received signed mutation that
loses its reply, and clean exchange after a truncated response. Existing
streaming, deadline, typed failure, Send/Sync, and host recovery tests remain.

## Reproduction

Build the old and new CLI binaries in separate worktrees using
`CARGO_BUILD_JOBS=3 just cargo-cached build -p mkit-cli --bin mkit`; retain each
binary separately. Set `MKIT_HTTPS_BENCH_OLD_BIN` and
`MKIT_HTTPS_BENCH_NEW_BIN` to those binaries, optionally set
`MKIT_HTTPS_BENCH_SAMPLES` (default five), then run from the new checkout:

```sh
CARGO_BUILD_JOBS=3 just cargo-cached test -p mkit-cli \
  --test remote_dispatch_connect cli_https_latency_comparison \
  -- --exact --nocapture
```

The latency fixture is opt-in because noisy wall-clock comparisons are unsuitable
as shared-runner assertions. Normal CI retains the verified-TLS byte-parity
matrix and deterministic native connection/replay regressions.
