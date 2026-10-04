# Reference Workers embedding

This small, generic host demonstrates the supported composition APIs. The
[Workers embedder guide](../../docs/embedding/workers.md) explains request
budgets, durable continuation and upgrade notes; the specs and conformance suite
remain the contracts. Nothing here is a deployed performance measurement.

| Host route | Composition |
|---|---|
| `/_embedding/mkit/<canonical procedure>` | Transfer method, headers and ReadableStream to safe `adapter::serve_with`; UploadPart stays streamed |
| `/_embedding/read/public` | Anonymous published-view reader |
| `/_embedding/read/owner` | Same preview, requiring a genuine signed ListRefs envelope |
| Repository `/-/` URLs and token key document | Existing HTTP mount, preserving escaped query and request lifetime |

The reader requires indexed mode, an HTTP mount and dedicated URL-token keys.
The acceptance flow supplies that configuration; `wrangler.jsonc` keeps the
smaller single-repository streaming setup for the original streaming check.

The read preview accepts POST with `X-Repository`, repeated `?id=<hex>` (at most
`OBJECT_READER_BATCH`, 16) and optional `&metadata=true`. It returns canonical
lengths, optional logical file lengths and scoped URL tokens. Owner headers must
sign the exact bounded body for the canonical ListRefs procedure and public
`AUTH_AUDIENCE`, even though the host constructs an internal dispatch URL.
Selecting Owner alone confers no authority. Responses use `Cache-Control: no-store`.
The reference accepts at most 4 KiB of body and 2 KiB of query.

Each request constructs one pipeline, one reader and one ReaderSession. Canonical
and optional metadata reads share that session; the outer SliceBudget also covers
URL issuance, which has independent per-call limits. `REFERENCE reader` records
calls, decoded bytes, encoded reservations, output bytes and physical units even
on failure. The preview discards canonical bytes after measuring them; a host can
feed them into `MemorySource` for bounded core algorithms.

`hooks.rs` implements Authorizer, Admission, OutcomeSink and PurgeSink in process.
The Authorizer retains already verified facts; Admission delegates default limits
and reserves signed write nonces. `durable_objects!(config, sink)` supplies the
same sink to requests and cold alarms. Purge pairs budgeted LocalCache with a
custom sink that acknowledges only this host's local serving cache; a host with
additional caches must invalidate those before acknowledging. Complete
preservation/admin configuration activates real purge delivery.

The private `HostEvents` Durable Object atomically deduplicates reservation IDs
and projects `RepoStorageChanged`, retaining the highest version. Its SQLite
trigger and fixed-width decimal text preserve unordered delivery and full u64
precision. It retains the newest 1,024 accepted reservation IDs per receiver,
pruning older IDs atomically without removing the storage projection. Duplicates
do not refresh retention. Size host retention to outlive outcome redelivery (see
the guide); non-idempotent effects need protection beyond this example's cap.
The receiver has no public route. Storage uses the five
adapter DO classes plus this one host class; no extra server API is needed.

From the repository root, with the pinned Rust/Node tools, `worker-build`, `b3sum`
and the locked local Miniflare dependency installed:

```sh
export CARGO_PROFILE_DEV_DEBUG=0
export TMPDIR="$HOME/.cache/mkit-test-tmp/reference-embedding"
mkdir -p "$TMPDIR"
(cd apps/embedded-worker && cargo clippy --locked --target wasm32-unknown-unknown -- -D warnings)
export MKIT_MINIFLARE_MODULE="$PWD/apps/workspace-worker/node_modules/miniflare"
python3 scripts/reference-worker-acceptance.py
```

Acceptance builds the release wasm, publishes an indexed pack, runs bounded
public/owner previews and token readback, rejects invalid owner audiences and
oversized batches/bodies, consumes real storage events, injects unordered and
duplicate events in a private test wrapper, makes the repository private to
exercise purge, then restarts workerd to verify cold outcome retry and retained
projection state. `worker.log`, `producer.tap` and `evidence.json` are kept in
TMPDIR. Hosted Workers CI builds and runs this same flow.

Faults and receiver probes live only in `tests/reference-acceptance/wrapper.mjs`;
the reference binary has no fault switch or test route. The separate
`tests/embedding-conformance` fixture retains the broader hook/failure rehearsals.
The single-repository streaming check remains
`scripts/embedded-worker-conformance.sh --port 8795`.
The fixed development keys in local configs are for fresh local state only.

Use the separate `apps/` workspace convention. The adapter is unpublished; pin
external git dependencies and repeat the root `pack-ruzstd` patch from the guide.
