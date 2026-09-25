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

The storage and policy traits, the request pipeline and the Connect binding
land here in later work of the same effort.

## Crate map

| Crate | Role |
| --- | --- |
| `mkit-server` | This crate. The core, with no runtime dependency: operation model, identifiers, storage and policy traits, the request pipeline, upload validation, CAS and quota logic, error mapping. |
| `mkit-server-native` | axum/tokio router, tower layers and graceful shutdown; FS and S3 blobs with `SQLite` metadata; builds the `mkit-server` binary. |
| `mkit-server-worker` | Cloudflare Workers adapter: R2 blobs and sharded Durable Objects. |
| `mkit-server-conformance` | Storage-trait suite for every backend, plus a black-box wire suite for any deployment. |

Not yet published to crates.io: the first release ships with mkit 0.5.
