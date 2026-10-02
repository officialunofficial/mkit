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
| `published-view` | Published reader source; explicit adapter configuration. |
| `pack-ruzstd` | Pure-Rust zstd decoding for wasm targets. |
| `test-faults` | Test-only fault injection. Never enable it in a release build. |

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
