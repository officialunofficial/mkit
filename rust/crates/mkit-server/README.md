# mkit-server

The runtime-agnostic core of the production mkit server. It holds the
vocabulary every server adapter shares, and compiles for both native targets
and `wasm32-unknown-unknown`:

- repo and namespace identifiers (`RepoId`, `NamespaceKey`, `Addressing`)
- principals (`Principal`) and the typed `Operation` model
- a transport-neutral `ServerError` with redaction by construction, mapped to
  Connect (and ssh) error codes by the bindings
- the async/runtime model: `MaybeSend`, `BoxFuture`, injected `Clock` and
  `Spawner`, and `send_wrap`
- a `Metrics` facade with no dependency on a metrics backend
- the protocol logic every binding shares: ref CAS and ref-name checks
  (`refs`), `UploadPack` framing (`upload`), download chunking (`download`),
  quota evaluation (`quota`), auth v2 glue (`auth_v2`) and storage-error
  redaction (`storage_error`)
- the storage contract (`store`): a key-level `NamespaceStore` whose only
  write is one declarative `Batch`, a content-addressed `BlobStore`, the key
  layouts, value codecs and typed readers, and the replay-ledger model;
  in-memory reference backends behind the `memory` feature; behind the
  native `fs` feature, std-only stores over the `.mkit` on-disk layout
  (`FsBlobStore` for `packs/`, `FsLayoutStore` for refs as files) that
  delegate to `mkit-transport-file`; and the shared SQL backend
  (`SqlKvStore` over a synchronous `SqlConn`, with versioned schema
  migrations) behind the `sql` feature
- the request pipeline (`pipeline`): the PRD §5.4 stages as hook traits with
  the M0 defaults, the auth modes (open, bearer, auth v2, transport
  identity), shard routing (`ShardMap`), pure write planners whose batches
  carry a `NotAfter` commit deadline, the unary RPCs over the storage
  contract, and the streaming ones: a resumable `UploadPack`
  (`UploadSession`, memory bounded by one chunk) and a chunked
  `DownloadPack` (`DownloadStream`)
- the `test-faults` feature, for test builds only: `FaultHooks` called at
  five pipeline points and per-request `TestDirectives`
  (`x-mkit-test-fault`, `x-mkit-test-clock-skew-ms`). No release build
  enables it; without it the seam is compiled out.

- the `connect` feature (on by default): the `mkit.transport.v1` Connect
  binding. `connect::service(pipeline)` serves `TransportService` and
  `grpc.health.v1.Health` over the pipeline behind an `AuthInterceptor`
  that runs stage 0 on the exact unary request bytes. It uses connectrpc
  without its `server` and `zstd` features, so it stays wasm-clean; the
  native and Workers adapters mount it unchanged. The generated code is
  vendored under `generated/` (refresh it with
  `scripts/regen-transport-proto.sh`), so building needs no `protoc`.
  Build with `default-features = false` to leave the binding and its
  dependencies out.
- the `ssh` feature: the `mkit.rpc.v1.ssh` session over the pipeline
  (`ssh::serve_session`), with no async runtime of its own. `mkit serve`
  (the `mkit` CLI, which depends on this crate with only `ssh` and `fs`)
  runs it over stdio under a blocking executor, and the native enc
  listener under tokio.

## Crate map

| Crate | Role |
| --- | --- |
| `mkit-server` | This crate. The core, with no runtime dependency: operation model, identifiers, storage and policy traits, the request pipeline, upload validation, CAS and quota logic, error mapping. |
| `mkit-server-native` | axum/tokio router, tower layers and graceful shutdown; FS and S3 blobs with `SQLite` metadata; builds the `mkit-server` binary. |
| `mkit-server-worker` | Cloudflare Workers adapter: R2 blobs and sharded Durable Objects. |
| `mkit-server-conformance` | Storage-trait suite for every backend, plus a black-box wire suite for any deployment. |

Not yet published to crates.io: the first release ships with mkit 0.5.
