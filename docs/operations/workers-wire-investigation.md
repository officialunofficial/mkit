# Local Workers connection-loss investigation

The connection-loss cause remains unresolved. The comparison favors the
Wrangler proxy path, but does not prove a Miniflare-only defect or exclude a
runtime/server behavior that depends on scheduling. The investigation ended at isolation; it did not justify a production fix.
The wire harness now bypasses the dev proxy while retaining the pinned runtime,
all assertions and the existing replay-safe retry policy; see the
[operator guide](workers.md#wire-connection-diagnostics).

## Comparison

The release Worker and conformance runner were built from main `472b297b`
with diagnostic-only client changes. Wrangler was pinned to `4.134.0`, resolving
Miniflare `5.20260917.0-alpha` and workerd `1.20260917.1`, with compatibility date
`2026-09-09`. The cached Wrangler CLI matched the published package's SHA-256
`cd189a0814aa00501584cbd124155cf8f57daa1c754862e5c644c13cca1b1dbd`.

Each route used a fresh state directory and the same compiled release Worker,
Free plan, D34 sharding, Single addressing, fake local ticket key and auth-v2
profile. The two cases alternated for twenty iterations on each long-lived
server. Each case invocation used a random signer and fresh run namespace.
Thirty concurrent Health requests passed before the repeated cases. The direct
route used Miniflare's `unsafeDirectSockets` / `unsafeGetDirectURL` to expose the
user Worker directly over workerd HTTP, bypassing Wrangler's ProxyWorker.
It retained the same five SQLite Durable Object classes and two R2 bindings.

| Route | Case | Passed / attempts | Attempts with losses | Recovered retry records |
| --- | --- | ---: | ---: | ---: |
| Wrangler proxy | `refs.many_refs_one_repository` | 20 / 20 | 5 / 20 | 61 |
| Wrangler proxy | `advance.concurrent_one_committed` | 20 / 20 | 0 / 20 | 0 |
| Direct workerd socket | `refs.many_refs_one_repository` | 20 / 20 | 0 / 20 | 0 |
| Direct workerd socket | `advance.concurrent_one_committed` | 20 / 20 | 0 / 20 | 0 |

A separate fresh startup through the ordinary shell harness also passed
`refs.many_refs_one_repository` with no losses. Repeated warm runs are useful:
a single passing startup does not close the issue.

Every traced lost write had HTTP 500 followed by HTTP 200 with matching case,
procedure, body, signer and replay-key hashes. For example, four writes in the
second proxy iteration failed after approximately 1,964–1,966 ms and their
same-envelope replays returned 200 after 896–954 ms. The unchanged case checked
every final ref and the full listing. The advance case retained exactly-one-
committed and paired head/packmap final-state assertions; it remains unretried.

Proxy console/debug logs report `Error inside ProxyWorker` / `Network connection
lost` while RefShard alarms and relay telemetry continue. No adjacent panic,
trap, reset or resource-limit diagnostic was observed. Absence of such a log
is not evidence that these events cannot occur.

## Reproduction and retained evidence

The current harness uses a direct workerd socket, with the same cold-start
assertions and replay policy:

```sh
CI=true VCS_LIST_PARALLEL=8 VCS_CONFORMANCE_KEEP=1 \
  scripts/vcs-worker-conformance.sh -- --filter refs.many_refs_one_repository
CI=true VCS_LIST_PARALLEL=8 VCS_CONFORMANCE_KEEP=1 \
  scripts/vcs-worker-conformance.sh -- --filter advance.concurrent_one_committed
```

For warm repeats, keep `wrangler dev` alive with the development config and its
normal `AUTH_AUDIENCE`, `AUTH_REPOSITORY=default` and `SHARDING=d34` variables.
Invoke `mkit-server-conformance wire` with auth-v2, the same audience and
repository, `--random-signer --atomic-advance --fresh-target --milestone M1`,
`--features health,strict-gzip-auth,tickets,multipart,epoch-leases`,
`--sharding d34 --list-parallel 8 --max-pack-bytes 1073741824`, alternating the
two exact filters above. Set `MKIT_CONFORMANCE_HTTP_TRACE` to a separate
canonical absolute JSON-lines path under `TMPDIR` for each invocation.

The local comparison retained all eighty runner logs, HTTP traces, runtime
console/debug logs, the direct-socket configuration and a per-invocation result
matrix. Hosted runs retain these diagnostic categories in `workers-wire-logs`
whenever losses/retries occur, as described in the
[operator guide](workers.md#wire-connection-diagnostics).

## Bounds on the conclusion

These samples used a local runtime, not the hosted Node 22/Linux environment.
The direct configuration removes the entire dev proxy and changes scheduling;
it does not replay the same failures through the same live runtime instance.
Twenty clean direct trials do not establish a zero failure rate. Neither
historical terminal assertion failure reproduced, and the fault-enabled profile
was not part of this focused comparison. Timer races remain a separate issue.

Classification is therefore **unresolved, with evidence favoring the harness
proxy path**. The new retained evidence is the next step toward distinguishing
proxy connection handling, a workerd limit and an mkit exception. Keep the
current pin and existing bounded retries until that distinction is demonstrated.
