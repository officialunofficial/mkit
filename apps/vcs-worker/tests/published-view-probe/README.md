# Local published-view probe

This disposable test Worker opts in explicitly; the application does not.
Use `wrangler dev --local` only. It has no public routes or cloud resources.
The `/seed` fixture writes 58 long refs per bucket to private local R2 and
creates the coordinator record. ListRefs then uses the real configured
fetch adapter, Cache API, R2, authorization and bounded merge/Connect codec.

From this directory, with a private non-symlinked TMPDIR:

```sh
worker-build --release
npx wrangler@4.134.0 dev --local --port 18921 --inspector-port 18922 --persist-to "$TMPDIR/probe-state"
# In another terminal; ports and output directory must match:
# Install ws in your private scratch directory or set MKIT_PROBE_WS_MODULE
# to the absolute ws/index.js already installed by your local Wrangler.
node profile.mjs 18921 18922 "$TMPDIR"
```

The Node script uses the local V8 CPU profiler at 100 µs sampling intervals,
retains the cpuprofile, and reports sampled active and Wasm CPU separately
from wall time. Fixture generation and cold guard calls precede profiling.
The JSON page must have a continuation token and remain below 2 MiB.
R2 cache misses may occur as the one-second TTL expires during the run.
Local samples do not certify Cloudflare production hardware or account limits;
repeat the measurement before enabling snapshot staging.

Measurement on the executor's shared Mac (2026-09-29, optimized Wasm,
Wrangler 4.134.0, 30 sequential requests): 928 refs in 496,422 encoded
snapshot bytes; 128 refs/page, 73,573 encoded response bytes. Sampled
active time averaged 42.45 ms/request (13.62 ms in Wasm), wall time 48.59 ms.
The larger initial probe (256 rows/128 KiB per bucket, 1,000 refs/page)
measured 59.90 ms active / 31.88 ms Wasm. These profiler samples include
local JS/runtime overhead and host scheduling; Free CPU is not certified.
The smaller limits bound retained bodies to 512 KiB; the allocator test
bounds body/decode/merge retention below 2 MiB. Snapshot activation requires
production CPU measurement and an appropriate account CPU allowance.
