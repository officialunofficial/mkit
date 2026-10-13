# Embedding an immutable read cache

mkit supplies optional store wrappers and a byte-cache contract. You supply the
backend and choose its retention bound. Existing deployments keep caching off.
The [server cacheability contract](../specs/SPEC-SERVER.md#171-immutable-read-caching)
defines which reads qualify.

Only complete pack bytes are Immutable today. Every namespace key and scan
remains Live, including object-index rows: supported merge imports and public
index planners can replace those values. Upload markers, extracted object
content, chunk-offset sidecars, and staged multipart state remain Live.
A content hash in a metadata key does not authorize caching its value.

## Configure the wrappers

The core exposes these APIs through `mkit_server::store`:

- `cacheability`, `scan_cacheability`, and `blob_cacheability` classify reads.
  Unknown families default to `Cacheability::Live`.
- `ImmutableCache` provides async `get` and `put` of bytes under opaque keys.
  A miss returns `Ok(None)`; backend errors fall back to authoritative storage.
- `CacheConfig::new` accepts a deployment/storage identity, a runtime `Sleep`,
  and a nonzero per-backend-call timeout of at most 100 ms.
- `CachingNamespaceStore::new` and `CachingBlobStore::new` wrap your stores with
  that backend and configuration.
- `MemoryImmutableCache::new` accepts a byte budget, insertion-time TTL, and
  `Clock`. Clones share the bounded LRU. Hits do not extend TTL. Zero capacity
  or TTL disables retention. `evict_expired` physically removes expired entries;
  every lookup and insertion also sweeps them.

Give each deployment and independent authoritative store a distinct identity.
Rotate it after a restore or reset. The wrapper derives stable opaque keys from
that identity, storage kind, partition, and authoritative key. Global pack
entries have no namespace partition and stay scoped to the deployment.
Do not reinterpret those keys as public download URLs or authorization tokens.

The memory budget accounts for retained keys, values, and 128 bytes of entry
overhead. Insertion copies the key and value into owned allocations, so a small
slice cannot retain a larger backing allocation. The wrapper accepts cache entries of at most 1 MiB. Your backend must
also bound response allocation before returning bytes, retained storage, and
background work. It must permit cancellation when a cache call times out. A put
that already completed can remain after cancellation; its retention bound still
applies.

Writes, deletes, guarded batches, and their preconditions delegate directly to
the store. The wrappers never fill or invalidate entries on writes. No absent
result is cached. Cache failures and timeouts preserve ordinary store results;
authoritative store failures still fail the read.

## Opt in on Workers

Use `mkit_server_worker::adapter::embedding_pipeline_with_cache` in place of
`embedding_pipeline`. Its existing environment, configuration, hooks, and shared
request budget arguments stay in the same order. Append your cache backend and
`CacheConfig`. The return type is `CachedWorkerPipeline<H, C>`.
For fetch dispatch, use `serve_with_cache` in place of `serve_with`. Append a
backend factory and `CacheConfig`. The factory receives the dispatch invocation's
shared `SliceBudget` after the adapter creates it, and returns the cache handle
for that request. A memory-only backend can use `|_| cache.clone()`. An external
backend must bind the supplied budget to its handle. Both paths validate the
existing Worker configuration.
`embedding_pipeline`, `serve_with`, and the default fetch path keep caching off.
No environment variable implicitly enables it.

For example, construct a memory backend once in the host that owns its lifetime
and clone it into each request:

```rust
use std::{sync::Arc, time::Duration};
use mkit_server::store::{CacheConfig, MemoryImmutableCache};
use mkit_server_worker::{clock::WorkerClock, sleep::WorkerSleep};

let cache = MemoryImmutableCache::new(
    8 * 1024 * 1024,
    Duration::from_mins(1),
    Arc::new(WorkerClock),
);
let cache_config = CacheConfig::new(
    "deployment-storage-generation-1",
    Arc::new(WorkerSleep),
    Duration::from_millis(25),
)?;
```

The 60-second TTL is an example. For a physical-retention SLA, choose the TTL
and maximum sweep interval so their sum fits that SLA.
Creating a new backend for every request produces a cold cache. Keep the
pipeline, reader, and session request-scoped as described in
[Workers embedding](workers.md#one-reader-and-one-session-per-request).
Sharing retained cache data does not share proof memos or credentials. A backend
that performs platform I/O needs a request-scoped handle carrying that request's
shared physical budget.

## Durable Object memory backend

Keep `MemoryImmutableCache` on the Durable Object instance, or implement
`ImmutableCache` over another bounded instance-owned LRU. Reuse it across
requests to that object. A cached value is disposable and is never durable work
ownership or recovery state.

TTL stops an expired entry from being returned; it does not erase an idle
backend by itself. Schedule `evict_expired` even when there are no reads or
drop all backend clones within your retention bound. TTL plus the maximum
sweep interval must be no greater than your purge SLA.

Durable Object memory survives while the instance remains resident. Eviction,
hibernation, or a restart loses it, so the next request fetches authoritative
bytes again. Isolate memory can include several objects; size each cache with
that shared footprint in mind. See Cloudflare's
[in-memory state documentation](https://developers.cloudflare.com/durable-objects/reference/in-memory-state/).

The Worker embedding constructor wraps the request's physical stores. It does
not install a cache inside the exported storage Durable Objects. If you host
request handling in another Durable Object, that host can own and pass the
backend explicitly.

## Workers Cache API backend

Implement `get` with `cache.match` and `put` with `cache.put`. Encode the opaque
key into a synthetic HTTPS request URL under your deployment's control. Store
only the raw immutable bytes in the response body and use an explicit finite
freshness bound, such as `Cache-Control: max-age=<seconds>`. Return a miss for a
missing or expired response. Bound the response before buffering it into bytes;
reject an oversized response as a backend error.

The Cache API is per-colo: entries do not replicate to other data centers.
`cache.delete` removes an entry only in the data center executing that Worker.
Do not acknowledge a global purge based on one local delete. Cloudflare
provides separate global purge facilities, whose applicability depends on the
cache-key arrangement. See the [Cache API contract](https://developers.cloudflare.com/workers/runtime-apis/cache/)
and [Cache API purge options](https://developers.cloudflare.com/workers/reference/how-the-cache-works/#purge-assets-stored-with-the-cache-api).

Cache API I/O consumes platform resources. Your backend must charge every
external cache call to the same invocation `SliceBudget` supplied as
`request_budget` to the embedding pipeline. Reserve the call before dispatch;
on refusal, return a backend error so the wrapper falls back to the store
within its remaining allowance. For `embedding_pipeline_with_cache`, construct a request-scoped backend handle
with your shared `request_budget`. For `serve_with_cache`, construct that handle
in its backend factory using the budget the adapter passes in. Share only
retained data across requests. Do not reuse an
earlier request's budget with the cache. Choose a short cache timeout and
measure cache calls separately from store calls. The core wrappers do not
raise any request, byte, decode, or platform limit.

## Integrity, deletion, and retention

The wrapper populates entries only from a complete pack of at most 1 MiB whose
BLAKE3 matches its id. Larger packs keep the streaming store path. A ranged read
can reuse a previously cached complete pack; a range miss stays a store read
and does not populate an entry. A streamed fill buffers at most 64 pieces,
including empty pieces, then polls once more for completion. If another piece
arrives, it returns a pass-through stream with the consumed prefix restored
and does not fill the cache. This bounds work even for streams that repeatedly
yield empty chunks.

Every pack hit rehashes the complete entry and reads authoritative `head`.
Garbage or mismatched cache bytes fall back to `get`. Missing physical content
returns absence even when bytes remain cached; failed `head` fails the read.
A correct hit saves a blob GET while retaining that live HEAD. It does not
eliminate namespace reads.

Authorization, visibility, membership, publication, ref observations, denial,
and final guards still execute live. A denial added after warm-up stops serving
through those guards. An immutable byte entry grants no permission and does
not preserve a reader session between requests.

Cached copies of content later purged by takedown can persist until the backend
physically evicts or deletes them. Bound physical retention to your purge SLA,
and account for racing or canceled puts. For the memory backend, insertion-time
TTL plus the maximum sweep interval must fit that SLA; schedule `evict_expired`
or drop all clones even when the backend is idle. Cache hits must not refresh that deadline. Live denial
and physical-presence checks stop serving, but do not erase retained copies.
Your `PurgeSink` must still follow the
[cache-purge acknowledgement contract](../specs/SPEC-SERVER.md#167-remote-cache-purge);
local cache deletion alone cannot attest deletion of copies in other colos.

When measuring warm repeats, report cache hits, store GETs and HEADs, namespace
calls, and cache-backend I/O separately. For Show, Log(10), and GetReadGate,
identify each remaining store call's Live key family and read step. That shows
which authoritative checks remain and which byte retrievals the cache saves.
