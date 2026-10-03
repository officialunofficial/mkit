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

## Features

| Feature | Effect |
| --- | --- |
| `connect` (default) | The `mkit.transport.v1` Connect binding (`connect::service`), with its health service and auth interceptor. wasm-clean. |
| `memory` | In-memory reference backends, a template for third-party backends. |
| `fs` | std-only stores over the `.mkit` on-disk layout (`FsBlobStore`, `FsLayoutStore`). Native only. |
| `sql` | A shared SQL backend (`SqlKvStore`) over a synchronous `SqlConn` trait; the embedder supplies the engine. |
| `ssh` | The `mkit.rpc.v1.ssh` session (`ssh::serve_session`), with no async runtime of its own. |
| `remote-hooks` | Signed `mkit.server.hooks.v1` authorization, admission and outcome adapters over a `HookChannel`. |
| `http-objects` | Runtime-agnostic HTTP object serving; requires explicit configuration and indexed mode. |
| `pack-ruzstd` | Pure-Rust zstd decoding for wasm targets. |
| `test-faults` | Test-only fault injection. Never enable it in a release build. |

## Object-reader sessions and entry sizes

With `http-objects`, pass one `pipeline::ReaderSession` to
`ObjectReader::read_canonical_in` and `object_metadata_in` to share an allowance
across calls (and readers). `ReadLimits::new(calls, decoded, encoded, output)`
sets the four dimensions; `ReaderSession::used()` reports consumption.
Defaults are 8,500 call units and 256 MiB each for decoded bytes and canonical
output. Encoded I/O is unlimited by default, matching the existing API; set a
finite encoded limit to bound storage traffic. The configured per-call HTTP
decode allowance remains an additional ceiling.

Calls use the existing `SliceBudget` granularity: a metadata store method call costs
one unit, a ranged blob read two, and authorization and read seams retain their
existing call reservations. Encoded accounting reserves requested pack ranges
before I/O, including prefixes, duplicate fetches and failed attempts; metadata
row bytes are excluded. Decode work counts canonical objects, proof ancestors
and delta bases each time they are decoded. Canonical outputs count duplicates
individually; metadata outputs have no canonical byte charge. Failed calls keep
charges already incurred. Cancellation settles completed decode work and keeps
I/O reservations. Existing per-invocation `SliceBudget` decorators still work.

The old reader methods retain their signatures and per-call allowances. Cap
hits return `ResourceExhausted` with `OBJECT_READER_LIMIT_MESSAGE` (`object reader
limit exceeded`). As required by SPEC-HTTP-OBJECTS §4 and SPEC-SERVER §10.1,
public IDs whose reachability cannot be proved within the caps remain absent.
Backend failures remain `Unavailable`.

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

See the crate documentation and `docs/SPEC-SERVER.md` in the repository for
details.

## License

Licensed under either of Apache License, Version 2.0 or MIT license, at your
option.
