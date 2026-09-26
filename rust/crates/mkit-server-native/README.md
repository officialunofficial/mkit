# mkit-server-native

The native (tokio) adapter of the mkit server, and the `mkit-server` binary.

- `build_router` (`http` feature, on by default): the `mkit.transport.v1`
  Connect binding and `grpc.health.v1.Health` over a `Pipeline`, as an
  `axum::Router` behind production tower layers (CORS, header redaction,
  tracing, a concurrency cap, a body limit, per-procedure deadlines).
  Mountable in your own axum app.
- `serve`, `Shutdown`, `shutdown_signal`: graceful shutdown on SIGINT or
  SIGTERM, with a grace deadline. `TokioSpawner` runs background work on the
  server runtime until shutdown.
- `RusqliteConn`: `mkit-server`'s synchronous `SqlConn` over a local `SQLite`
  file (rusqlite, `SQLite` bundled; `sqlite` feature, on by default)
- `Blocking<S>`: runs a store whose bodies are synchronous (the `SQLite`
  store, `mkit-server`'s `FsBlobStore` and `FsLayoutStore`) on tokio's
  blocking pool, keeping `apply` cancellation-safe; it adapts both
  `NamespaceStore` and `BlobStore`
- `SqliteKvStore`: `Blocking<SqlKvStore<RusqliteConn>>`, the `NamespaceStore`
  a native server uses

The store logic is `mkit-server`'s `SqlKvStore`, shared with the Durable
Object backend: both run the same statements and the same schema migrations.

## Operator guide: `mkit-server serve`

```text
mkit-server serve --listen <ADDR> --repo-root <DIR>
    [--meta fs-layout | --meta sqlite:<PATH>]
    [--auth bearer | --auth auth-v2 | --unsafe-allow-any-peer]
    [--bearer-token-file <PATH>]          # or MKIT_API_TOKEN
    [--audience <ORIGIN>] [--repository <ID>]
    [--max-pack-bytes N] [--unary-timeout-secs 30] [--stream-timeout-secs 3600]
    [--max-concurrency 256] [--cors-allow-origin <ORIGIN>]... [--shutdown-grace-secs 30]
    [--sqlite-max-bytes N] [--log-format text|json]
mkit-server version
```

`mkit-server` replaces `mkit serve --http`; it is a separate binary, so the
`mkit` CLI carries no HTTP server or `SQLite`.

### The served root

`--repo-root` must be a directory holding `.mkit`, and must lie under
`MKIT_SERVE_ROOT` when that is set (the same checks as `mkit serve`). Packs
live in `<DIR>/packs/<64-hex>`, the layout `mkit serve` and `mkit+file://`
remotes use. While it runs, the server holds `<DIR>/.mkit/serve.lock`
shared, so local worktree commands and `gc` see the root is served.

### Authentication

The listener fails closed, like `mkit serve --http`:

- `--auth bearer`, or just a token: every RPC needs `Authorization: Bearer
  <token>`. The token comes from `--bearer-token-file <PATH>` (one trailing
  newline ignored) or `MKIT_API_TOKEN`, never from the command line. An empty
  token is refused.
- `--auth auth-v2 --audience <ORIGIN> [--repository <ID>]`: writes carry auth
  v2 signatures (SPEC-TRANSPORT-CONNECT §7.1) for exactly that audience and
  repository, with the replay ledger and the default per-signer write quota
  (300 writes and 128 MiB an hour). Reads are unsigned in M0. Needs
  `--meta sqlite:`.
- `--unsafe-allow-any-peer`: no authentication at all, with a loud warning.
  Development only.
- With none of these the server refuses to start (`CONFIG_ERROR`). A token
  together with `--unsafe-allow-any-peer` is a usage error.

`grpc.health.v1.Health` answers without authentication. Each store's probe
result is cached for one second, so health checks cannot load the stores.

### Metadata storage

- `--meta fs-layout` (the default for bearer and unsafe auth): refs are files
  under `<DIR>/refs`, shared with `mkit serve` over ssh and local `mkit`
  commands. It holds refs only, so it cannot serve auth v2, and
  `AdvanceRefs` moves the packmap, then the head, as `mkit serve --http` did.
- `--meta sqlite:<PATH>`: refs, replay records and quota windows in one
  `SQLite` file; `AdvanceRefs` is atomic. `--sqlite-max-bytes` (default 8
  GiB) caps the file: see "Capacity" below.

One root never keeps refs in both places (R-81). `--meta sqlite:` refuses a
root that already holds ref files, and otherwise writes the marker
`<DIR>/.mkit/server-meta` (content `sqlite`) before it listens. From then on
`--meta fs-layout` and every `FsLayoutStore::open` (the future `mkit serve`
path) refuse the root. The marker is never removed automatically: to move the
refs back to files, stop the server, export the refs, write them as files,
and delete `.mkit/server-meta` by hand.

### TLS, limits and timeouts

The listener speaks plaintext HTTP/1.1 and h2c. Terminate TLS at a reverse
proxy (nginx, Caddy, a cloud load balancer) and pass the original origin
through: auth v2 signatures name the public origin (`--audience`).

- `--max-pack-bytes` (default 4 GiB) caps an upload's declared size; the
  request body limit is that cap plus framing slack
  (`layers::body_limit_for`). A larger `Content-Length` is refused `413`
  before any handler runs.
- `--unary-timeout-secs` bounds every unary RPC and `--stream-timeout-secs`
  every `UploadPack` or `DownloadPack` stream; a timeout answers Connect
  `deadline_exceeded`. A client's `Connect-Timeout-Ms` may shorten a
  deadline, never extend it.
- `--max-concurrency` requests run at once; the rest wait. Keep it below
  tokio's blocking-pool size (512 by default): every store call runs there.
- `--cors-allow-origin` (repeatable; `*` for any) enables browser access.
  Preflights are answered without authentication; the allowed request
  headers are the auth v2 set plus `authorization`.

### Shutdown and exit codes

SIGINT or SIGTERM stops accepting connections and lets in-flight requests
finish, for at most `--shutdown-grace-secs`; requests still running then are
dropped (an interrupted upload leaves nothing visible). The exit codes are
`mkit`'s sysexits values: 0 clean shutdown, 64 usage, 65 root without
`.mkit`, 66 missing root, 69 bind or runtime failure, 75 serve lock busy, 77
root outside `MKIT_SERVE_ROOT`, 78 refused configuration.

### Logs and metrics

Logs go to stderr, as text or JSON (`--log-format`), filtered by `RUST_LOG`
(default `info`). Every request is traced with its headers; credential
headers (`mkit_server::NEVER_LOG`: `Authorization`, cookies, payment headers,
`X-Signature`) print as `Sensitive`. Metrics go to the `metrics` crate
facade; the binary installs no exporter, so an embedder that wants them
installs a recorder.

### Embedding

`build_router(pipeline, &RouterOptions)` returns an `axum::Router` whose
fallback is the Connect service: add your own routes to it, or mount it as
your app's fallback service. `server::open` builds the same router from a
resolved `config::ServeConfig`.

## `SQLite` operations

### File layout

One database file holds every partition: the `kv` table is keyed by
`(part, key)`, where `part` is the partition's portable encoding. The
`mkit_schema` table records the physical schema version. With WAL, `SQLite`
keeps two companion files next to the database, `<file>-wal` and
`<file>-shm`; they are part of the database while it is open.

The connection runs with `journal_mode = WAL`, `synchronous = FULL` (a
committed batch is on disk before `apply` returns) and a 5 s busy timeout.
Several processes may open one file, but `SQLite` has a single writer:
batches from every partition commit one at a time.

### Migrations

Opening a store (`SqlKvStore::open`) applies any missing physical migrations,
each in its own transaction. They are forward-only and idempotent. A database
whose recorded schema is newer than the binary's is refused with
`StoreError::Unsupported` and left untouched: there is no downgrade, so take
a backup before upgrading. New key layouts need no physical migration; the
per-partition layout version (the `v` row) covers them.

### Physical backup

Take a consistent copy of the whole database, online, with
`StoreMaintenance::backup_to(dest)`, which runs `VACUUM INTO '<dest>'`
(`RusqliteConn`'s backup hook; the shared SQL store has no engine-specific
backup of its own, and a Durable Object uses the portable export). `dest`
must not exist. The copy is compacted and self-contained (no WAL files). The
`sqlite3` shell's `.backup` command, or `VACUUM INTO` from any `SQLite`
client, works too. Do not copy the database file alone while the server runs:
recent commits may still sit in `<file>-wal`.

To restore, stop the server, move the database and its `-wal` and `-shm`
files aside, put the backup in the database's place, and start the server.
Migrations run on open, so a backup from an older binary is brought forward.

### Portable logical backup

`mkit_server::store::export_partition` streams one partition's rows in the
backend-neutral export format, and `import_stream` restores them into any
backend: another `SQLite` file, a Durable Object, the in-memory store. Use it
to move between backends or to back up single partitions. It is not a
snapshot: export a quiesced partition. `ImportMode::Fresh` restores into
empty partitions; an interrupted import can be rerun with
`ImportMode::Merge`.

### Capacity

Open the store with `SqlKvStore::open_with_capacity(conn, Capacity::new(cap))`.
`cap` is the hard limit, which the connection enforces as `max_page_count`.
Once the database uses `cap - reserve` bytes (pages holding data; free pages
don't count), batches that add data fail with `StoreError::Full`. Reads and
delete-only batches keep working, so pruning can still run.

The reserve exists because deleting from the b-tree can itself need new
pages. The default is the larger of about 20 MiB (two maximal batches'
worst-case growth at 4 KiB pages) and `cap / 64`; `Capacity::with_reserve`
overrides it. See `mkit_server::sql::Capacity` for the derivation.

`SQLITE_FULL` means `Full` only at the page limit. A full host disk reports the
same code, but surfaces as `StoreError::Unavailable`, because deleting rows
does not free disk space (the file never shrinks without `VACUUM`). Watch the
host's free space separately.
