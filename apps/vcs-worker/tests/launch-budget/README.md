# Ordinary release budget fixture

This local-only wrapper imports the pinned release module and exports its five
unchanged Durable Object classes through observing subclasses. It adds no Rust
seam, production route, timer, storage row, fault feature or deployment change.
The private Wrangler configuration enables `nodejs_als` for the observer only.

From a clean committed worktree, with private ports and scratch space:

```sh
export TMPDIR="$HOME/.cache/mkit-test-tmp/wp-4-18"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export VCS_CONFORMANCE_PORT=18838
unset CARGO_TARGET_DIR
bash scripts/vcs-worker-launch-budget-runtime.sh --sha "$(git rev-parse HEAD)"
```

The runner builds the ordinary release with `http-objects,pack-ruzstd`, copies and hashes
its full artifact, runs the two discovery cases and the real scheduled
verification/extraction producer, then reads its extracted Blob with GET,
HEAD and Range. Both namespace policies use isolated local state. Only the
runner's own process groups are stopped. No deployment or cloud call occurs.

Counters increment at actual DO, R2, Fetch and Cache API dispatch. A response retains its
outgoing token until EOF, cancellation or error; headers alone do not close it.
R2 stream getters and buffered `arrayBuffer`/text/JSON readers are observed.
Upload handles count `uploadPart`/complete/abort rather than the synchronous
`resumeMultipartUpload` handle construction. Zero-prefetch stream wrappers do
not tee or retain payload copies. SQL counts observe the existing cursor's raw
iterator and its final `rowsRead`/`rowsWritten`; they never issue observer SQL.
Unconsumed SQL cursors refuse PASS. One bounded JSON record is emitted per
completed invocation.

Fresh top-level Env proxies capture their request scope directly. Persistent
DO proxies share conservative totals across overlapping events, including
returned bodies and `waitUntil` work. The fixture deliberately makes no exact
Rust async-local attribution claim: the dependency's shared task queue batches
future polling. A completed overlapping group bounds each constituent alarm;
the checker refuses unfinished observed groups and missing completion records
for the replay's HTTP object/file reads and their paid-read settlement. It
requires at least one actual alarm
with R2 work, at most 960 observed external calls per alarm-containing group,
at most 10,000 per incoming request group, at most six outstanding outgoing lifetimes per group and across the observed
module isolate (including distinct request/DO owners),
and raw indexed timer windows of at most 64 returned rows.

This component cannot fill the complete launch matrix. It does not exercise
signed hooks, service-binding hooks, snapshots/Cache API, scanner retrieval,
preservation/admin, cold seeded heads, restart, maximal dependency fanout or
resident-memory bounds. The prelude captures exported Wasm linear-memory
capacity at observation boundaries. That includes retained pages and is not a
live Rust heap counter. The observer keeps only the current exported memories
and counts every initialization; multiple instances invalidate assessment,
and retired buffers are not rooted by the observer. It excludes JavaScript
and embedder heap. Groups are keyed by module identity and local group number,
so restart cannot overwrite another module's results.
A separate CDP sampler records isolate identity, sampled JavaScript heap,
embedder heap and backing storage alongside the linear-memory observation.
Record sample count, covered isolate identities, gaps and missing heap/Wasm
fields. An empty JSON file is NO_SAMPLES; incomplete observations are PARTIAL.
The module UUID is separate from CDP's isolate ID. Missing fields/time intervals
remain gaps; these samples are not a complete
128 MB peak theorem. The CDP fields follow the primary
[Runtime protocol definition](https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/json/js_protocol.json). Those require separate evidence. `streamBytes` counts
observed stream flow (including overlapping stream layers), not buffered readers
or retained memory. Workerd observations do not certify Cloudflare CPU,
memory, cost, multicolo behavior or internal connection accounting.

Cloudflare documents [AsyncLocalStorage-only activation](https://developers.cloudflare.com/workers/runtime-apis/nodejs/)
and [its async context API](https://developers.cloudflare.com/workers/runtime-apis/nodejs/asynclocalstorage/).
