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
- `S3BlobStore` (`s3` feature, on by default): the `BlobStore` over an
  S3-compatible bucket (see "S3 blob storage" below)

The store logic is `mkit-server`'s `SqlKvStore`, shared with the Durable
Object backend: both run the same statements and the same schema migrations.

## Operator guide: `mkit-server serve`

```text
mkit-server serve --listen <ADDR> --repo-root <DIR>
    [--meta fs-layout | --meta sqlite:<PATH>]
    [--blob fs | --blob s3://<BUCKET>[/<PREFIX>] --s3-endpoint <URL>
        [--s3-region auto] [--s3-credentials-file <PATH>]   # or MKIT_R2_* / AWS_*
        [--s3-spool-max-bytes N] [--s3-allow-insecure-http]]
    [--auth bearer | --auth auth-v2 | --unsafe-allow-any-peer]
    [--bearer-token-file <PATH>]          # or MKIT_API_TOKEN
    [--audience <ORIGIN>] [--repository <ID>]
    [--max-pack-bytes N] [--unary-timeout-secs 30] [--stream-timeout-secs 3600]
    [--max-concurrency 256] [--queue-timeout-secs 5]
    [--max-connections 1024] [--header-read-timeout-secs 10] [--idle-timeout-secs 60]
    [--cors-allow-origin <ORIGIN>]... [--shutdown-grace-secs 30]
    [--sqlite-max-bytes N] [--log-format text|json]
mkit-server version
```

`mkit-server` replaces `mkit serve --http`; it is a separate binary, so the
`mkit` CLI carries no HTTP server or `SQLite`.

### Deployment

Production deployments SHOULD run `mkit-server` behind a buffering reverse
proxy (nginx, Caddy, Envoy, a cloud load balancer) that terminates TLS and
enforces connection limits, request-header and slow-body timeouts, and a
request size limit. The server's own limits (below) bound its resources,
but a proxy absorbs slow clients before they hold a server slot. This
matters most for `--auth auth-v2`: a signed write is verified over its exact
body, so the server must read the (up to 4 MiB) unary body before it can
reject an unsigned or forged request. Pass the original origin through
unchanged: auth v2 signatures name the public origin (`--audience`).

### The served root

`--repo-root` must be a directory holding `.mkit`, and must lie under
`MKIT_SERVE_ROOT` when that is set (the same checks as `mkit serve`). Packs
live in `<DIR>/packs/<64-hex>`, the layout `mkit serve` and `mkit+file://`
remotes use.

**One server process per root.** `mkit-server` holds `<DIR>/.mkit/server.lock`
exclusively for its whole lifetime, and a second `mkit-server` on the same
root refuses to start (`CONFIG_ERROR`): its write serialization and caches
are per process. To scale out, serve different roots. It also holds
`<DIR>/.mkit/serve.lock` shared, so local worktree commands and `gc` see the
root is served; `mkit serve` over ssh shares that lock. Both locks are
released only after the server's runtime has shut down, so no store call is
still running when another process takes the root.

### Authentication

The listener fails closed, like `mkit serve --http`:

- `--auth bearer`, or just a token: every RPC needs `Authorization: Bearer
  <token>`. The token comes from `--bearer-token-file <PATH>` (one trailing
  newline ignored) or `MKIT_API_TOKEN`, never from the command line. The file
  must be a regular file (not a symlink) readable by its owner only (`chmod
  600`); it is opened once without following symlinks and checked on the
  open handle. Secret mounts that are symlinks (Kubernetes projects secrets
  that way) must pass the token through `MKIT_API_TOKEN` instead. An empty
  token is refused. The token is checked from the request
  headers before the request takes a concurrency slot, so unauthenticated
  callers cost no slot.
- `--auth auth-v2 --audience <ORIGIN> [--repository <ID>]`: writes carry auth
  v2 signatures (SPEC-TRANSPORT-CONNECT §7.1) for exactly that audience and
  repository, with the replay ledger and the default per-signer write quota
  (300 writes and 128 MiB an hour). Reads are unsigned in M0. Needs
  `--meta sqlite:`.
- `--unsafe-allow-any-peer`: no authentication at all, with a loud warning.
  Development only.
- With none of these the server refuses to start (`CONFIG_ERROR`). A token
  together with `--unsafe-allow-any-peer` is a usage error.

> **Warning (M0): auth v2 authenticates, it does not authorize.** With the
> default hooks, `--auth auth-v2` lets ANY key holder write ANY ref: a
> signature proves who signed, not that the signer may write. The
> per-signer quota can be bypassed by minting new keys. Real authorization
> arrives in M2 (write grants). Until then, run auth v2 only behind an
> authorizer hook (`mkit_server::pipeline::Authorizer`, embedding the
> router) or on a trusted network.

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

One root never keeps refs in two places (R-81). `--meta sqlite:` refuses a
root that already holds ref files. Otherwise, under the root's ref lock, it
writes the marker `<DIR>/.mkit/server-meta`, which binds the root to one
database: a random root id and the database's path (its directory
resolved). The same root id is stored in the database (the native table
`mkit_server_root`). On every start the marker must name the `--meta` file
and the database must carry the root's id, so the server refuses a different
database for the root, and a database another root already uses. From then
on `--meta fs-layout`, every `FsLayoutStore::open` (the future `mkit serve`
path) and every ref write through `FileTransport` (a local `mkit push` to a
`file://` remote, `mkit serve` today) refuse the root. The marker is never
removed automatically: to move the refs back to files, stop the server,
export the refs, write them as files, and delete `.mkit/server-meta` by
hand.

**Moving a root.** Stop the server, move the root (and its database, if it
lives elsewhere), and start it with the new `--repo-root` and `--meta
sqlite:<new path>`. When the old database path no longer exists and the
database at the new path carries the root's id, the server records the new
path in the marker (under the ref lock, logged as a warning) and starts. If
the old path still exists (or cannot be checked), the new one is refused as
a stale copy or a wrong path: serving an old backup would roll the refs and
the replay ledger back. To restore a backup, stop the server and move the
backup over the recorded file. A database carrying another root's id, or
none, is refused too; each error names both paths.

### S3 blob storage

`--blob s3://<BUCKET>[/<PREFIX>]` keeps packs in an S3-compatible bucket
(AWS S3, Cloudflare R2's S3 API, `MinIO`) as `<PREFIX>/packs/<64-hex>`,
addressed path-style at `--s3-endpoint` (an origin such as
`https://<account>.r2.cloudflarestorage.com`, no path). It needs `--meta
sqlite:<PATH>`: `fs-layout` refs are shared with local `mkit` commands, which
read packs from `<DIR>/packs`. `--repo-root` still holds `.mkit`, the locks,
the root marker and the upload spool.

- **Credentials** come from `MKIT_R2_ACCESS_KEY_ID` and
  `MKIT_R2_SECRET_ACCESS_KEY` (the `mkit+s3://` client's names), else
  `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, or from
  `--s3-credentials-file <PATH>`: `KEY=VALUE` lines with those names
  (systemd `EnvironmentFile` syntax), owner-only as the bearer token file;
  given a file, the environment is not read for them. Never from the command
  line or repo config. Requests are signed for `--s3-region` (default
  `auto`, R2's).
- **Long-lived keys only.** Temporary credentials (`AWS_SESSION_TOKEN`) are
  refused: they need an `x-amz-security-token` header, which the signer
  (`mkit-transport-s3::sigv4`, a published crate whose `Credentials` has no
  token field; adding one would break semver) does not send. So IAM roles,
  instance profiles, IRSA (EKS service accounts) and ECS task roles are
  unsupported until an additive signer sends the token.
- **Permissions.** The key needs, on the bucket (or its prefix):
  `s3:PutObject` (uploads), `s3:GetObject` (downloads, `HEAD`),
  `s3:ListBucket` (the health probe's `HEAD` on the bucket; it is also what
  lets S3 answer `404` for a missing pack: without it, S3 answers `403` and
  every absent-pack check, and the health check, fails as a storage error),
  and `s3:DeleteObject` (garbage collection, from M5; unused in M0). An R2
  API token needs "Object Read & Write" on the bucket.
- **The provider must honor `If-None-Match: *` on `PUT`** (AWS S3 since
  2024, R2, `MinIO`) for put-if-absent reporting. One that ignores it stays
  correct, since every key only ever holds its verified bytes, but reports
  re-uploads as new.
- **TLS.** A plain-`http` endpoint to a non-loopback host is refused unless
  `--s3-allow-insecure-http` is passed (development only): pack bytes would
  cross the network in cleartext, and on-path tampering would go unnoticed
  (downloads are not re-verified against their BLAKE3, and
  `If-None-Match` is not signed). Loopback `http` is allowed.
- **Verify before visible.** An upload is spooled under
  `<DIR>/.mkit/server-spool` while it is hashed, and sent to the bucket in
  one `PUT` only after its BLAKE3 matches its key. Nothing unverified ever
  reaches the bucket, and an aborted, failed or dropped upload sends
  nothing. Spool files are unnamed: on Linux `O_TMPFILE`, so they never
  have a name; elsewhere (macOS) a `.tmp*` file is unlinked right after it
  is created, and the leftovers of a crash in between are swept at startup.
  The cost: each pack is written and read locally once, and the bucket
  transfer starts only when the client's upload ends.
- **Spool budget.** `--s3-spool-max-bytes` (default 16 GiB, at least
  `--max-pack-bytes`) caps the disk the uploads in flight may use: each
  reserves its declared length before any byte arrives, and one that does
  not fit is refused at once with a retryable `unavailable` ("storage
  partition full"), as is a full disk while spooling.
- **Retries.** A `PUT` answered `409`, `429`, `5xx` or `400 RequestTimeout`
  is retried from the spool (three attempts), after a jittered exponential
  backoff (100 ms, then 400 ms) that honors `Retry-After` (up to 10 s).
  An attempt is abandoned when its body stops moving, or its answer does
  not come, for 60 s, and in any case after 60 s plus 1 s per MiB. A failed
  `PUT` whose object is then present with the right length counts as
  already present. One `PUT` carries at most 5 GiB, above the 4 GiB
  default pack cap; resumable multipart uploads come in M1.
- **Health** probes the bucket with a `HEAD` (5 s timeout), at most once a
  second.
- Failures are logged with the HTTP status, the S3 error code and request
  ids; clients see only "object storage request failed".

### Limits and timeouts

The listener speaks plaintext HTTP/1.1 and h2c; terminate TLS at the proxy.

- `--max-connections` (default 1024) connections are open at once; further
  clients wait in the kernel's accept backlog.
- `--header-read-timeout-secs` (default 10): a client that does not send its
  request headers in time (or, on a new connection, anything at all) is
  disconnected. HTTP/2 connections are pinged every 30 s and closed if a
  ping goes unanswered for 20 s; each carries at most 128 streams.
- `--idle-timeout-secs` (default 60): a connection (HTTP/2, or HTTP/1.1
  keep-alive) with no request in flight for that long is closed gracefully,
  so idle clients cannot hold every connection slot.
- `--max-concurrency` (default 256) requests run at once. A request holds its
  slot until its response body ends, so a streaming `DownloadPack` counts
  for as long as it streams. A request that finds no slot within
  `--queue-timeout-secs` (default 5; 0 sheds at once) is answered HTTP 503
  with `Retry-After: 1` and Connect code `unavailable`. Keep the cap
  below tokio's blocking-pool size (512 by default): every store call runs
  there.
- `--max-pack-bytes` (default 4 GiB) caps an upload's declared size; the
  request body limit is that cap plus framing slack
  (`layers::body_limit_for`). A larger `Content-Length` is refused `413`
  before any handler runs; a chunked body that grows past it fails.
- `--unary-timeout-secs` bounds every unary RPC and `--stream-timeout-secs`
  every `UploadPack` or `DownloadPack` stream; a timeout answers Connect
  `deadline_exceeded`. A client's `Connect-Timeout-Ms` may shorten a
  deadline, never extend it.
- `--cors-allow-origin` (repeatable; `*` for any) enables browser access.
  Preflights are answered without authentication; the allowed request
  headers are the auth v2 set plus `authorization`.

### Shutdown and exit codes

SIGINT or SIGTERM stops accepting connections and lets in-flight requests
finish, for at most `--shutdown-grace-secs`; requests still running then are
dropped (an interrupted upload leaves nothing visible). The exit codes are
`mkit`'s sysexits values: 0 clean shutdown, 64 usage, 65 root without
`.mkit`, 66 missing root, 69 bind or runtime failure, 75 serve lock busy, 77
root outside `MKIT_SERVE_ROOT`, 78 refused configuration (including a root
another `mkit-server` holds).

### Logs and metrics

Logs go to stderr, as text or JSON (`--log-format`), filtered by `RUST_LOG`
(default `info`). Every request is traced with its headers; credential
headers (`mkit_server::NEVER_LOG`: `Authorization`, cookies, payment headers,
`X-Signature`) print as `Sensitive`, in requests and responses. Metrics go
to the `metrics` crate facade; the binary installs no exporter, so an
embedder that wants them installs a recorder.

### Embedding

`build_router(pipeline, &RouterOptions)` returns an `axum::Router` whose
fallback is the Connect service: add your own routes to it, or mount it as
your app's fallback service. Serve it with `serve(listener, router,
shutdown, &ServeOptions)` to get the connection cap, header-read timeout
and graceful shutdown. `server::open` builds the same router from a
resolved `config::ServeConfig`, taking the root's locks.

## `SQLite` operations

### File layout

One database file holds every partition: the `kv` table is keyed by
`(part, key)`, where `part` is the partition's portable encoding. The
`mkit_schema` table records the physical schema version. With WAL, `SQLite`
keeps two companion files next to the database, `<file>-wal` and
`<file>-shm`; they are part of the database while it is open.

The connection runs with `journal_mode = WAL`, `synchronous = FULL` (a
committed batch is on disk before `apply` returns) and a 5 s busy timeout.
`SQLite` has a single writer: batches from every partition commit one at a
time. `mkit-server` serves each database from exactly one process (the
root's exclusive `server.lock` and the root binding above); tools may open
the file read-only, for example to back it up.

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
