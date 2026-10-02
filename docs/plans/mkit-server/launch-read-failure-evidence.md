# Embedding host read-failure repair and completed local matrix

The requested matrix for the first embedding consumer passes locally at
`7527556d09c7753462f0449622d86ade0fb3b70e`, tree
`d83f2cb00a13f21189dfb07e5fff4fbcd09fb032`. This is the embedded
Paid indexed Multi/D34 `any` profile, permanent retention, leases/GC off,
bounded ruzstd, default-public repositories, local Authorize/Admit/Outcome and
the existing restricted admin catalog remounted at `/_uno/operator`.
No deployment, merge, new server key, timer or protocol was performed.

## Diagnosis and repair

The stock pooled client reproduced `IncompleteMessage` immediately after a
successful heavy AdvanceRefs. No corresponding Worker ingress marker was captured;
fresh ReadRef and ListRefs returned the published pair. Direct Miniflare
reproduced the failure without Wrangler's HTTP proxy. A smaller pack also
reproduced it when AdvanceRefs remained slow. Its duration does not establish
a fast-request control. Debug logs with the fixture panic hook showed no
identified panic, limit or isolate-restart marker. These observations support
a local workerd keep-alive transport artifact; they do not identify an exact
workerd internal cause or prove deployed behavior.

[#1260](https://github.com/officialunofficial/mkit/pull/1260), commit
`4e7e5fca`, is the separate prerequisite against `feat/mkit-server`. It retries
an allowlisted unary read or nonce-protected auth-v2 write once, below signing,
on a fresh pool, only when the captured HTTP/1 socket was previously used and
received zero new decrypted bytes. It preserves the complete signed envelope,
TLS configuration and caller deadline. First-use failures, HTTP/2, partial
responses, HTTP errors and unsigned writes are excluded. Hyper's implicit
canceled-request retry is disabled. Streaming RPCs get a fresh connection on
their single initial attempt and are never buffered or replayed.

The conformance client uses that transport. HTTP object GETs also start fresh,
preserving their observer handle and all content/status assertions. The
observer no longer waits for the SDK's `"timers processed"` alarm return body:
[workerd alarms have no HTTP response consumer](https://developers.cloudflare.com/durable-objects/api/base/#alarm).
Outgoing response bodies, SQL cursors, waitUntil and errors remain tracked;
completeness and budget checks remain unchanged.

## Requested acceptance matrix

| Case | Result | Executed evidence |
|---|---|---|
| Embedded push, AlreadyPresent, Admit 402 | PASS | `uno.public_fixture`, 8,631,723-byte canonical pack, two actual streamed parts, pending verification/publication, coherent head and packmap; dedicated 13-byte challenge |
| Native HTTPS push and clone | PASS | Existing fixture CA via `MKIT_SSL_CA_FILE`; default trust rejects it. Four 128 KiB files, signed zstd push, exact cloned HEAD and four independent SHA-256 hashes. Push 29.336 s; clone 37.874 s |
| Public HTTP reads/content headers | PASS | Object/file GET, HEAD, range, invalid range, safe filename/type and security headers; raw Blob canonical BLAKE3 independently verified |
| Takedown → denial → preservation → audit | PASS | Immediate 404, verified private preserved canonical bytes and terminal offsets, role denial, hold set/clear, bounded list scopes, gapless accepted audit, deferred catalog absent; custom paired LocalCache acknowledgement |
| Outcome after cold-alarm restart | PASS | Both committed reservation IDs first fail in the test sink, then deliver from the same persisted stores in a new process before another request; no new timer kind or signing identity |
| embedding host size/CPU/calls/memory measurements | MEASURED | Sizes and complete physical-call traces below; CPU is OS process accounting, memory is identified inspector sampling with explicit gaps |

The native run is pinned to source `d205ac61db76f9e7dc94877dc68f355561742e98`.
The subsequent matrix-source commit changes only the JS alarm observer; the
native CLI and embedding host Wasm bytes are identical. Final evidence-only commits do
not change those executable bytes. This embedding acceptance does not fill every
historical full-profile case in [launch-evidence.md](launch-evidence.md).

## Resource measurements and limits

| Measurement | Local result | Scope |
|---|---:|---|
| embedding host Wasm / deterministic gzip | 6,934,119 / 2,370,989 bytes | Actual host with panic/failure fixture; all emitted artifact files total 6,974,355 bytes |
| Request physical calls peak | 8,290 | Complete invocation groups; below 9,000 backend and 10,000 combined request allowances |
| Alarm physical calls peak | 123 | 244 completed alarm groups; below unchanged 960 allowance |
| Combined outgoing lifetime peak | 4 | Below unchanged six; bodies/cancellation included |
| Wasm retained linear capacity peak | 20,316,160 bytes | One observed Wasm instance per identified module |
| Sampled used heap + embedder/backing + Wasm peak | 60,458,558 bytes | Maximum co-observed sum; not a full resident peak certificate |
| Sampled allocated heap capacity + embedder/backing + Wasm peak | 104,604,962 bytes | Maximum co-observed capacity sum, below 128 MiB; separate from used-heap figure |
| Heavy AdvanceRefs bracketed process CPU / elapsed | 17.17 / 18.03 seconds | OS-accounted workerd CPU, 50 ms sampling, 10 ms CPU resolution; all threads/storage isolates/concurrent alarms included |
| Earlier whole-sequence inspector active samples / wall | 28.224 / 30.502 seconds | One user isolate across the upload sequence; not per-invocation CPU accounting |

The observer retained 72,685 records with all physical groups complete,
114,223 SQL rows read, 31,315 written, timer-window maximum nine. Inspector
sampling retained 1,667 samples, including 154 identified user-module samples
across both cold-process epochs, 1,513 unknown samples (including internal
runtime targets) and 27 gaps. The memory observations are measurements, not
continuous coverage or a deployed 128 MiB certificate.

`limits.cpu_ms=60000` is explicit in the launch staging template and both local
configs. It supplies provisional headroom over the measured CPU and sampled
sequence. Verification stays alarm sliced; pack, decoder, physical-call,
connection and memory limits are unchanged. Local development does not enforce
deployed CPU limits; user-owned staging must measure per-invocation CPU and
full memory/cost before launch, per the
[Cloudflare profiling documentation](https://developers.cloudflare.com/workers/observability/dev-tools/cpu-usage/).

The earlier D64 five-variant table remains pinned to `43256803`: minimal
6,661,292 raw bytes, HTTP 6,990,192, signed 6,665,414, HTTP+signed 6,993,827,
snapshots 7,029,471. Those are historical variant measurements, not this
latest embedding host digest or a new runtime acceptance for those variants.

## Pins, commands and retained failures

Scratch root: `~/.cache/mkit-test-tmp/wp-4-18/executor-readfix/`.

| Evidence | SHA-256 |
|---|---|
| `launch-admin-70qml3yz/evidence.json` | `809c176afc05fdf4f262ae097c7ae3361721accf54dba5f42956067c06552ca4` |
| `launch-admin-70qml3yz/any/observation.json` | `a90dae07e695f482fee2b578e415f30145e8e40f54c5834b9d6c66b9a3cef645` |
| `final-memory-summary.json` | `d325486667c2798306ff6ba89e1ec32e3ebd1bd9a8417b5a3c79a98d5eb6f885` |
| `heavy-direct-cpu-final/cpu.json` | `e8a3c95f60d8c62b44389ca249c0eb68f715dd3870eefecab0353ea7d44ad840` |
| `native-https-r3/evidence.json` | `4de8c6b801c7d8d36050791b976897a6ea7de8405919da453e6b527509a8c6f2` |
| embedding host `artifact/index_bg.wasm` | `8db43d251998a36c4206bdf921bc1a60a01cf5c5978cfc9949fa226997d3faaf` |
| Matrix conformance runner | `d80dc9005565676e2b198f3a296ef8f95d870fcbd04a37258579e1227cc85b65` |
| Native CLI | `e2c69903f0d5431fb7bb2c73bff08fa0be1990e5c536150a8a6a91d1868d32e8` |

The matrix manifest contains full source/tree/config/artifact and log hashes,
UTC timestamps and exact commands. It ran the documented
`vcs-worker-launch-admin-runtime.py --uno --namespace any --observe-resources`
at the clean matrix SHA, with Wrangler 4.134.0's installed Miniflare
5.20260917.0-alpha, workerd direct HTTP, ports 18928/18930 and pinned `ws`.
Native HTTPS used 18938/18940 and the existing fixture CA. All owned processes
were stopped. See the [fixture instructions](../../../apps/embedded-worker/tests/uno-launch/README.md).

Every earlier failure remains retained: stale stock-client runs, the light
pack's still-slow failure, tooling/PATH/port/parser failures, native key-mode
and timeout failures, and the run where both pooled and fresh requests timed
out during concurrent compilation. None is relabeled as passing or dismissed
as load without a separate successful isolated run. The first final semantic
PASS (`launch-admin-hjpxw3eo`) retains incomplete alarm observations; the
corrected observer rerun above passes the unchanged physical checks.

## Gates and review

Locked full workspace/all-targets/all-features clippy, root/app formatting,
embedding host fixture wasm clippy, warnings-as-errors rustdoc, doctests, scripts and
security checks pass. Current conformance + transport nextest: 680 passed,
two skipped. Separate transport: 140 passed, one skipped; reverse-dependency
CLI + conformance: 2,073 passed, ten skipped. Existing observer tests were
updated to require accurate traces across fresh sockets; partial-body errors
and HTTP 500 remain unchanged. All app lockfiles accept locked metadata.

Two independent reviews fixed implicit Hyper replay, dead weak-reference
retention, missing no-third-retry coverage, canceled-error classification,
optional inspector configuration, byte/text log offsets, actual internal
admin probes, purge acknowledgement assertions and CPU evidence wording.
Both confirmed the alarm observer correction against the runtime contract.

Using the inherited physical non-test Rust counter and external test-module
deductions, activation is **3,495 / 3,500** lines, conservatively including all
163 standalone fixture lines. The separate transport prerequisite is 366
changed non-test Rust lines and is excluded from activation accounting; its
tests are separate. `cap-final.json` records this split. Other variants,
deployed CDN purge, staging and user-owned external acceptance remain outside
this requested embedding host matrix; larger native publication workloads retain the
existing cumulative limit.
