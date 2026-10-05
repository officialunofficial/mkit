# mkit-server

A generic, runtime-agnostic mkit server core. Embedders build a deployment on
it (for example, the Cloudflare Workers adapter in this repository), and
`mkit serve` in the `mkit` CLI uses its `fs` and `ssh` pieces. It compiles for
native targets and `wasm32-unknown-unknown`.

## What it provides

- Identifiers (`RepoId`, `NamespaceKey`, `Addressing`), principals and the
  typed `Operation` model.
- A transport-neutral `ServerError` with redaction by construction, mapped to
  Connect and ssh error codes by the bindings.
- The runtime model: `MaybeSend`, `BoxFuture`, injected `Clock` and `Spawner`,
  and `send_wrap`; plus a `Metrics` facade with no metrics backend.
- The storage contract (`store`): a key-level `NamespaceStore` whose only
  write is one declarative `Batch`, a content-addressed `BlobStore`, key
  layouts, value codecs and the replay-ledger model.
- The request pipeline (`pipeline`): stage traits, auth modes (open, bearer,
  auth v2, transport identity), shard routing, the unary RPCs, and resumable
  streaming upload and download.
- Protocol helpers shared by every binding: ref CAS and name checks, upload
  and download framing, quota evaluation and storage-error redaction.

## Supported public API

Embedders construct `pipeline::Pipeline` with `PipelineConfig::new` and hook
implementations (`Authorizer`, `Admission`, `PreReceive`, `OutcomeSink` and
`HookSet`). Public repository identities, authentication, ref policy, quotas,
upload limits and transport bindings remain part of that contract. Indexed
and HTTP serving start with `IndexedConfig::default()` and
`HttpObjectsConfig::default()`; adjust their public fields before building the
pipeline. Public configuration structs are non-exhaustive: use constructors,
parsers or `Default`, then setters or field assignment instead of literals.

`Pipeline::{object_reader, issue_urls, repo_storage, set_repo_visibility}`,
`ObjectReader::{read_canonical, object_metadata}`, `ReaderView`, `ReadLimits`
and `ReaderSession` support embedding object access. Metadata distinguishes
canonical length from a `Blob` or `ChunkedBlob`'s logical length; the removed
`object_sizes` convenience can be reproduced by selecting the required length.
`ReservationV1` constructors, `OutcomeRef`, `AbortReason`, `PendingOp` and
`StoredProcedure` are documented exports of `store` for outcome integrations.

Storage adapters implement `NamespaceStore`, `BlobStore` and
`MultipartBlobStore`; `Partition`, batch/precondition types, capabilities,
portable export/import and maintenance hooks remain public. The optional
native `fs` stores keep their constructors and durable filesystem behavior.
`budget::SliceBudget` is shared by request and purge accounting; its existing
`indexed::budget::SliceBudget` and `purge::SliceBudget` paths remain reachable.
Preservation work uses `takedown::work::{Work, WorkConfig}` constructors with
explicit routing, retention and an injected clock. Default call allowances
are defined once in `limits`; compatibility constants
such as `pipeline::OBJECT_READER_CALLS` keep their current paths.

The doc-hidden `store::adapter_spi` exposes only the storage modules used by
adapter and conformance implementations: `keys`, `codec`, `index`, `tickets`,
`outbox`, `publication` and `watermark`. These layouts and codecs are an adapter
SPI, outside the supported embedder API. Core-only typed readers and serving
views are crate-private. Unintegrated inspection/restore planning stays in
private test support; the live recovery marker and portable import API remain
in core. The internal `__test-faults` feature is for repository tests, and is
not a supported deployment feature. The wire test capability remains named
`test-faults`.

```rust
use mkit_server::upload::UploadLimits;
use mkit_server::indexed::IndexedConfig;

let upload = UploadLimits::new(64 << 20, 1024);
let mut indexed = IndexedConfig::default();
indexed.max_pack_bytes = upload.max_total_bytes;
indexed.decode_budget = 4 * upload.max_total_bytes;
```

## Features

| Feature | Effect |
| --- | --- |
| `connect` (default) | The `mkit.transport.v1` Connect binding (`connect::service`), with its health service and auth interceptor. wasm-clean. |
| `memory` | In-memory reference backends, a template for third-party backends. |
| `fs` | std-only stores over the `.mkit` on-disk layout (`FsBlobStore`, `FsLayoutStore`). Native only. |
| `ssh` | The `mkit.rpc.v1.ssh` session (`ssh::serve_session`), with no async runtime of its own. |
| `remote-hooks` | Signed `mkit.server.hooks.v1` authorization, admission and outcome adapters over a `HookChannel`. |
| `http-objects` | Runtime-agnostic HTTP object serving; requires explicit configuration and indexed mode. |
| `pack-ruzstd` | Pure-Rust zstd decoding for wasm targets. Needs a ruzstd patch when consumed from crates.io (see below). |

### `pack-ruzstd` and the ruzstd patch

`pack-ruzstd` relies on a bounded-decode patch to ruzstd 0.9 (the RFC 8878
block-size preflight) that lives only in this repository's workspace
`[patch.crates-io]`. Cargo does not inherit a dependency's patches, and the
crates.io `ruzstd` 0.9 has no such bound, so a consumer that enables
`pack-ruzstd` must apply the patch in its own workspace until upstream
releases it:

```toml
[patch.crates-io]
ruzstd = { git = "https://github.com/officialunofficial/mkit", tag = "v0.5.0" }
```

Upstreaming of the patch is in progress; the patch will be dropped once a
ruzstd release includes it. Without it the feature still builds but decodes
through the unbounded upstream path.

Upstream tracking: [KillingSpark/zstd-rs #124, "Refuse blocks that decode past
Block_Maximum_Size"](https://github.com/KillingSpark/zstd-rs/pull/124) is open. Keep the patch until a released
version includes the bound; the tracked PR does not establish released coverage.

## Object-reader sessions and entry sizes

With `http-objects`, opt into 45-id canonical/metadata calls with
`pipeline.object_reader(repo, view).await?.with_batch_limit(45)?`; the default
remains 16 and URL issuance still accepts at most 16 targets. This changes no
call, row, byte, decode or output allowance. Pass one `pipeline::ReaderSession` to
`ObjectReader::read_canonical_in` and `object_metadata_in` to share an allowance
across calls (and readers). `ReadLimits::new(calls, decoded, encoded, output)`
sets the four dimensions; `ReaderSession::used()` reports consumption.
Defaults are 8,500 call units and 256 MiB each for decoded bytes and canonical
output. Encoded I/O is unlimited by default, matching the existing API; set a
finite encoded limit to bound storage traffic. The configured per-call HTTP
decode allowance remains an additional ceiling.

Calls use the existing `SliceBudget` granularity: a metadata store method call costs
one unit, a blob `head` one, a ranged blob read two (blob `probe` is not charged), and authorization and read seams retain their
existing call reservations. Encoded accounting reserves requested pack ranges
before I/O, including prefixes, duplicate fetches and failed attempts; metadata
row bytes are excluded. Decode work counts canonical objects, proof ancestors
and delta bases each time they are decoded. Canonical outputs count duplicates
individually; metadata outputs have no canonical byte charge. Failed calls keep
charges already incurred. Cancellation settles completed decode work and keeps
I/O reservations, including decoded reservations for parallel raw-member waves. Existing per-invocation `SliceBudget` decorators still work.

Keep one reader and one session per logical operation. Read canonical parents
before their children: a commit proves its tree and parents, and a returned tree
proves its entries. Use metadata only when lengths are needed; metadata does not
create decoded child proofs. Do not fetch unchanged file bodies merely to keep
their hashes when loading a base tree.

Each batch shares verified locations and sealed inventory, and coalesces denial
reads only within the operation. With `takedown_denial` enabled, the descriptor
directory is read strongly for every batch. Disabling that option skips the
descriptor proofs, but direct object/pack blocklist guards remain mandatory
(SPEC-SERVER §14.2), including fail-closed reads and blocked reconstruction bases.
A fresh denial phase and a final gate precede output; external delta
bases still follow repository/view membership, denial and reconstruction limits.
Index scans, membership reads and independent raw member loads share one
six-call I/O admission envelope. Scan waves retain the existing 1,000 transient
row allowance across all concurrent replies, and results are processed in
partition/input order. Encoded ranges, calls and decoded raw members are reserved
before dispatch. Failed or cancelled waves keep their reservations. Delta chains
use the bounded sequential resolver. Raw-load waves also bound combined encoded
buffers and canonical results to the previous single-member transient allowance;
large frames therefore run in smaller waves. Decoder scratch overlaps only one
synchronous decode. Store decorators that impose an inherited
call or byte budget must forward the hidden reader-admission and reservation hooks, so the entire
wave is admitted before the first backend dispatch. Activate the returned
reservations only around their owning read future with `ReadReservation::scope`;
unrelated tasks and mutations cannot consume that wave’s prepaid credit.

The old reader methods retain their signatures and per-call allowances. Cap
hits return `ResourceExhausted` with `OBJECT_READER_LIMIT_MESSAGE` (`object reader
limit exceeded`). As required by SPEC-HTTP-OBJECTS §4 and SPEC-SERVER §10.1,
public IDs whose reachability cannot be proved within the caps remain absent.
An ID with more index rows than the lookup cap is absent for that ID only; page and membership-read caps on a proven or owner read are `ResourceExhausted`. Backend failures remain `Unavailable`.

Indexed canonical entries are limited to **1,048,586 bytes**, including object
framing. Very large trees and chunk manifests can exceed this even when the
pack is small or highly compressed. Split very large flat directories into
smaller subdirectories. An oversized entry is refused at indexed verification
with the existing `InvalidArgument` decode-limit error (SPEC-SERVER section 9.8).
Neither stored data nor pack framing changes.

## Related crates

- `mkit-server-worker`: Cloudflare Workers adapter (R2 blobs, Durable Objects).
  Not published.
- `mkit-server-conformance`: backend and wire conformance suites. Not
  published.

See the crate documentation and `docs/specs/SPEC-SERVER.md` in the repository for
details.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your
option.

The `SQLite` store lives in `mkit_server_worker::sql`; core has no SQL feature.

### Connect deadlines on wasm

On wasm32, mkit entry points (`connect::service`, `serve`, `serve_with`,
`serve_admin_with` and the `fetch*` helpers) are safe with `connect-timeout-ms`
and `grpc-timeout` present. **Deadlines are ignored on wasm**: the core Connect
service removes both headers before connectrpc computes an absolute deadline,
and ignores configured `DeadlinePolicy` settings, including default and
inter-message timeouts. Native deadlines are unchanged. Body streaming,
authentication and body limits still apply. Bound host work using the platform
clock and timer as needed; the admin engine already uses the Worker timer.

To mount `connect::router` yourself, use `connect::ConnectService::new(router)`
instead of a raw connectrpc service. `ConnectService` aliases
`ConnectRpcService` natively and wraps it on wasm. Hosts dispatching to **other
connectrpc services** must apply the same rule before dispatch: remove both
headers (the public `mkit_worker_common::adapter::is_deadline_header` remains
available), and leave deadline policies unset. Header stripping alone does not
neutralize a configured default or inter-message timeout.

### Bounded history and commit paths

Retain one `ObjectReader` and `ReaderSession` per request. Use
`walk_history_in(session, reference, start, limit, HistoryOptions::default())`
for a parent-only log, or `locate_commit_in` for an old commit's canonical bytes.
The inclusive start is proved from the selected ref on every call. All-parent
BFS and first-parent traversal are explicit options; node, merge-frontier and
tag bounds fail safely. Only local canonical parent edges are followed.

`read_commit_path_in` locates the commit and walks exact decoded byte components
through its trees. An empty path reads the root; directory intermediates must
decode as trees. It preserves leaf modes, returns symlink blob bytes without
following them, and leaves chunked files as canonical manifests. Supply an
expected leaf ID to bind a requested target before its body is loaded. Set
`PathOptions.include_witness` to acquire the canonical commit and path trees
for local inclusion proof construction without repeating those reads. The
witness is output-budgeted data, with fresh source checks, and grants no
permission on a later request.

Each helper strongly captures the selected ref in the current view, replacing
structural evidence while retaining budgets/deadline. Authority, membership,
source dependencies, denial and ancestry stops remain live. Public unprovable
starts/paths are absent; owner caps use the existing typed exhaustion message.
The complete helper shares the existing per-call decode allowance across all
nodes/bases, in addition to its session ledger. Ref capture, node loads and
retained page/witness checks use one shared I/O admission envelope. Denial proofs
reuse the actual source locations and sealed inventory in bounded groups;
final target/pack guards start fresh after body I/O, final authorization and proof
revalidation, live callbacks and descriptor checks. The inventory supplies
clearance facts, never new history edges.
These helpers reduce history/path acquisition work within the unchanged reader
allowance. They add no persisted state, continuation tokens, URL forms, canonical
windows or latency guarantee. Existing arbitrary-ID and metadata APIs remain
available, and can reuse the selected canonical edges in the same session.
