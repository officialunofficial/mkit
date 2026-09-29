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
mkit-server serve [--listen <ADDR>] [--listen-enc <ADDR>] --repo-root <DIR>
    [--enc-authorized-peers <PATH> --enc-server-key <PATH> | --unsafe-allow-any-enc-peer]
    [--enc-idle-timeout-secs 60] [--enc-handshake-timeout-secs 10] [--enc-max-handshakes N]
    [--meta fs-layout | --meta sqlite:<PATH>] [--sharding single|d34]
    [--blob fs | --blob s3://<BUCKET>[/<PREFIX>] --s3-endpoint <URL>
        [--s3-region auto] [--s3-credentials-file <PATH>]   # or MKIT_R2_* / AWS_*
        [--s3-spool-max-bytes N] [--s3-allow-insecure-http]]
    [--auth bearer | --auth auth-v2 | --unsafe-allow-any-peer]
    [--bearer-token-file <PATH>]          # or MKIT_API_TOKEN
    [--ticket-key-file <PATH>]            # or MKIT_TICKET_KEYS
    [--audience <ORIGIN>] [--repository <ID>]
    [--addressing single|multi]
    [--namespace-policy allowlist|any] [--namespace-allowlist <PATH>]
    [--unsafe-open-namespaces] [--enc-repository <NS>/<NAME>]
    [--grant-schemes <TOKENS>] [--webauthn-rp <ID=ORIGINS>]... [--unsafe-allow-loopback-grants]
    [--max-pack-bytes N] [--unary-timeout-secs 30] [--stream-timeout-secs 3600]
    [--max-concurrency 256] [--queue-timeout-secs 5]
    [--max-connections 1024] [--header-read-timeout-secs 10] [--idle-timeout-secs 60]
    [--cors-allow-origin <ORIGIN>]... [--shutdown-grace-secs 30]
    [--sqlite-max-bytes N] [--log-format text|json]
mkit-server version
```

`mkit-server` replaces `mkit serve --http` and `mkit serve --listen-enc`;
it is a separate binary, so the `mkit` CLI carries no HTTP server or
`SQLite`. Pass `--listen` (HTTP), `--listen-enc` (`mkit+enc://`), or
both: at least one listener is required, and both serve the same root
through one pipeline (the same stores and write gate), on one runtime,
stopped by one signal. `docs/CLI.md` ("Migrating from `mkit serve --http`
and `--listen-enc`") maps the removed `mkit serve` flags to these.

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

### Running in a container

Releases publish `ghcr.io/officialunofficial/mkit-server` (`linux/amd64`,
`linux/arm64`): distroless, running as uid 65532, with this binary at
`/usr/local/bin/mkit-server` and `mkit-server serve` as the entrypoint, so
arguments after the image are the flags below. Listen on `0.0.0.0` inside
the container; make the root, the `SQLite` file and the enc key directory
writable by uid 65532; pass Kubernetes secrets through `MKIT_API_TOKEN` and
the S3 environment variables (secret volumes are symlinks, which the file
flags refuse); and probe `grpc.health.v1.Health` from outside, since the
image has no shell (for readiness only: it reports store outages). Details,
including the enc port's per-IP limit:
[`docs/CONTAINER.md`](https://github.com/officialunofficial/mkit/blob/main/docs/CONTAINER.md).

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

The listener fails closed, as `mkit serve --http` did:

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
  `--meta sqlite:`. To serve `BeginUpload`, set `--ticket-key-file <PATH>`
  or `MKIT_TICKET_KEYS` to one `<key-id> <64 hex>` entry per line. The
  first key signs; all listed keys verify, so prepend a new key to rotate.
  Keep every retired key id in the verify set for at least seven days after
  rotation. Outstanding multipart part receipts use the same key ids and
  remain valid for the maximum ticket lifetime.
  Blank lines and `#` comments are allowed. The file follows the same
  owner-only, no-symlink rule as the bearer secret; invalid keys fail with
  `USAGE`. Without keys, `BeginUpload` answers `unimplemented`.
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

These flags configure the HTTP listener; without `--listen` they are
refused (and `MKIT_API_TOKEN` is ignored).

### Multi-repository addressing

`--addressing single` (the default) serves one repository, named by
`--repository`. `--addressing multi` serves every repository its namespace
policy admits: each request's `X-Repository <ns>/<name>` header selects the
repository, and `--repository` is refused. A Multi deployment requires
`--listen` with `--auth auth-v2`, upload ticket keys (`--ticket-key-file`
or `MKIT_TICKET_KEYS`: a signed write names its repository, and uploads
still need tickets) and `--meta sqlite:<PATH>` (per-namespace partitions
need a transactional store). Encrypted-only Multi is deliberately
unsupported — Multi requires the auth-v2 HTTP listener; an enc listener
can only join a Multi deployment as the bound `--enc-repository` session
below. Writes are owner-only (STC §7.5): a signature
may write only inside its own key's `ed25519-` namespace.

The namespace policy selects which owner namespaces may write:

- `--namespace-policy allowlist` (the Multi default) admits only the
  namespaces in `--namespace-allowlist <PATH>`: canonical namespaces
  (`ed25519-<64 hex>` or `0x<40 hex>`) separated by newlines or commas,
  with `#` comments and blank entries ignored. Malformed or duplicate
  entries and an empty file are refused at startup. The file is security
  configuration, read with the same checks as `--enc-authorized-peers`:
  a regular file, no symlink, owned by the server's user, writable by no
  one else.
- `--namespace-policy any` admits every self-certifying namespace and
  requires `--unsafe-open-namespaces`: without non-default admission (M3),
  any fresh key resets its namespace's quota, so the open policy is an
  explicit development opt-in (D27). `any` and `--namespace-allowlist`
  are mutually exclusive.

Under `--addressing multi`, `--listen-enc` requires `--enc-repository
<NS>/<NAME>` naming the one repository the listener's sessions bind
(SPEC-TRANSPORT-CONNECT §7.4), and `--unsafe-allow-any-enc-peer` is
refused: an enc session needs the repository its peer is authorized for.

### Write grants

Write grants (SPEC-WRITE-GRANTS) let a namespace owner delegate writes. They
are off unless `--grant-schemes` is set, and need `--addressing multi` with
`--auth auth-v2`: the grant audience is the deployment's own `--audience`, so
there is no separate audience flag.

- `--grant-schemes <TOKENS>`: the accepted owner schemes, comma-separated
  (`ed25519`, `secp256k1-eip191`, `webauthn-p256`), advertised as
  `GetServerInfo.grant_schemes`. A blank list or an unknown token is refused.
- `--webauthn-rp <ID=ORIGINS>` (repeatable): a `WebAuthn` relying party,
  `id=origin[,origin...]`, split on the first `=`. `webauthn-p256` requires one;
  a duplicate id, or a relying party without `--grant-schemes`, is refused.
- `--unsafe-allow-loopback-grants`: development only. Without it a loopback
  `--audience` or relying party (`localhost`, `127.0.0.1`, `[::1]`) is refused:
  every local deployment shares one, so a grant for it would verify at all of
  them (SPEC-WRITE-GRANTS §3.2). The flag prints a warning banner.

Every bad or partial value stops the server at startup (`USAGE` or
`CONFIG_ERROR`); none degrades to "grants off". `mkit-attest` owns all
validation beyond syntax. The `--listen-enc` sibling pipeline serves
transport-identity sessions, which carry no grant header, so it runs without
grants; registered grants over ssh and enc arrive with WP-2.12.

### The enc listener (`mkit+enc://`)

`--listen-enc <ADDR>` serves `mkit+enc://` clients (SPEC-TRANSPORT-ENC):
an encrypted, mutually authenticated handshake, then the ssh-frame
protocol of `mkit serve`. Each session runs `mkit_server::ssh::serve_session`
over the pipeline as the `TransportPeer` principal, holding the client key
the handshake authenticated; nothing a client sends can change it. The
flags, messages and the `mkit serve-enc/<version>` server id are those of
`mkit serve --listen-enc`, which it replaces. It fails closed:

- `--enc-authorized-peers <PATH> --enc-server-key <PATH>`: only the client
  keys listed (one per line, 64-hex or the 43-char url-safe base64 of
  `?pubkey=`; `#` comments and blank lines ignored) complete the handshake.
  The allowlist is opened without following a symlink and must be a
  regular file owned by the server's user (or root) that neither group nor
  others can write (`chmod go-w`); an allowlist without a valid key is
  refused. Peer authorization never comes from the served root's
  `.mkit/config`. The file is read once, at startup: to revoke a key,
  edit it and restart the server, which also ends every open session.
- `--unsafe-allow-any-enc-peer`: any client key, with a loud warning.
  Development only. Refused (exit 78) when the HTTP listener requires a
  bearer token or auth v2, since it would let any client around them.
- With neither, or both, the server refuses to start.

Under `--addressing multi` the listener also needs `--enc-repository
<NS>/<NAME>` (see "Multi-repository addressing" above); its sessions then
serve only that repository.

> **Authorization (M0).** An enc peer is a `TransportPeer` principal: the
> handshake authenticates its key, and the allowlist is the whole of its
> authorization. Under `--addressing single` it may write any ref, like
> an ssh forced command. Under `multi` the write policy is the owner
> rule: only a peer whose key is the bound repository's `ed25519-`
> namespace may write (every other peer reads). Packs a session uploads
> and verifies may be published by that session's packmap write — the
> implicit form of upload tickets — and a packmap whose node, `prev`
> node or listed pack is neither pending nor a member is refused. Enc
> peers are NOT subject to the M2 write grants until M2
> wires the grant check into the transport-identity path.

The server's static key is the raw 32-byte ed25519 seed in
`--enc-server-key`, created on first run (`0600`, missing directories
`0700`, never overwritten); on every start it must be a regular file (no
symlink on its path), owned by the server's user, with no group or other
bits, in a directory with none either. Clients pin its public half: the
server prints `mkit-server serve --listen-enc on <ADDR> (server pubkey =
<hex>); clients dial mkit+enc://<host>:<port>?pubkey=<hex>` at startup.
With an allowlist the flag is required, so the key survives restarts
(`mkit serve` fell back to `~/.config/mkit/enc/server.key`; the server
resolves no home directory). With `--unsafe-allow-any-enc-peer` and no key
file the key is per process.

Bounds, as for HTTP:

- at most `--enc-max-handshakes` connections in the handshake at once
  (default 128, or `--max-connections` if lower; the rest wait in the
  accept backlog), each for at most `--enc-handshake-timeout-secs`
  (default 10, SPEC-TRANSPORT-ENC §2.1). Clients that connect and say
  nothing can fill only these slots: established sessions go on, and an
  authorized client gets in as soon as one frees;
- at most `--max-connections` sessions at once (per listener). A client
  that completes the handshake while every session slot is taken waits,
  keeping its handshake slot, until one frees: for at most the handshake
  timeout, and not past the start of a shutdown;
- `--enc-idle-timeout-secs` (default 60; at least 1, so every session
  ends) for every frame read and write after the handshake;
- the ssh session's budgets (10,000 frames and 1 GiB per connection; an
  upload of at most 1 GiB and 10,000 chunks, or `--max-pack-bytes` if
  lower).

### Metadata storage

- `--meta fs-layout` (the default for bearer and unsafe auth): refs are files
  under `<DIR>/refs`, shared with `mkit serve` over ssh and local `mkit`
  commands. It holds refs only, so it cannot serve auth v2, and
  `AdvanceRefs` moves the packmap, then the head, as `mkit serve --http` did.
- `--meta sqlite:<PATH>`: refs, replay records and quota windows in one
  `SQLite` file; `AdvanceRefs` is atomic. `--sqlite-max-bytes` (default 8
  GiB) caps the file: see "Capacity" below.

`--sharding` defaults to `d34` with `--meta sqlite:<PATH>` and to `single`
otherwise (fs-layout cannot run D34). `single` keeps each namespace in one
partition. `d34` requires `SQLite` metadata and routes each branch head and its
`refs/mkit/packmap/<branch>` together into a ref partition, with configuration
in the namespace coordinator. Any other `AdvanceRefs` pair is
`invalid_argument`. D34's default write quota counts per ref partition;
namespace totals arrive with WP-1.26. `ListRefs` under D34 reads the eventual
ref-name index. The conformance runner accepts the same
`--sharding single|d34` option and runs its listing cases under both modes.

**Breaking change (WP-1.28c).** A database written `single`, or written before
`--sharding` existed and holding data, is refused under the D34 default with
`CONFIG_ERROR`; there is no migration (R-123). Pass `--sharding single` to keep
serving it. Under Single addressing the default write quota is now counted per
(signer, branch) rather than per signer.

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
and enc sessions finish, for at most `--shutdown-grace-secs` (an enc
session ends at its next frame boundary: an idle one at once, never inside
an upload); those still
running then are dropped (an interrupted upload leaves nothing visible). The exit codes are
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
and graceful shutdown. `server::open` builds the same router (and the enc
service) from a resolved `config::ServeConfig`, taking the root's locks.
With the `enc` feature (on by default), `enc::session_fn` serves enc
sessions over a `TransportIdentity` pipeline (`Pipeline::with_auth` makes
one beside yours) and `enc::serve` runs the listener.

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

Take a consistent copy of the whole database while the server runs:

```sh
mkit-server backup --meta sqlite:/srv/mkit/meta.sqlite3 --out /srv/backups/meta.sqlite3
```

The command opens a separate WAL reader and runs `VACUUM INTO`. It prints
the output path and size in bytes. The output must not already exist;
an existing path is refused with exit code 64 (`USAGE`).

Embedders can call `StoreMaintenance::backup_to(dest)`, which runs `VACUUM INTO '<dest>'`
(`RusqliteConn`'s backup hook; the shared SQL store has no engine-specific
backup of its own, and a Durable Object uses the portable export). `dest`
must not exist. The copy is compacted and self-contained (no WAL files). The
`sqlite3` shell's `.backup` command, or `VACUUM INTO` from any `SQLite`
client, works too. Do not copy the database file alone while the server runs:
recent commits may still sit in `<file>-wal`.

To restore, stop the server, move the database and its `-wal` and `-shm`
files aside, put the backup in the database's place, and start the server.
Migrations run on open, so a backup from an older binary is brought forward.
Restart with the same `--sharding` mode used by the backed-up database
(R-93); its stored routing mode is checked on startup. A `single` database
needs `--sharding single`, since `d34` is the default with `--meta sqlite`.

This physical backup covers one native `SQLite` database.

### Disaster recovery and backend moves

For a Workers Durable Object incident within 30 days, use Cloudflare's
point-in-time restore (PITR) first. For an older disaster, or to move metadata
between backends, use the portable `.kvlog` snapshots. Export a live native
`SQLite` database without stopping its writers:

```sh
mkit-server export --meta sqlite:/srv/mkit/meta.sqlite3 --out /srv/backups/export-2026-09-27
```

The output directory must be empty. Export checks the existing schema version
without migrating the live database. A single `SQLite` read transaction covers
partition enumeration and every page of every partition. Files are owner-only
(0600) in owner-only directories (0700), under
`<kind>/<blake3-partition>/<export-ms>-<digest>.kvlog`. Each file
also carries its partition identity in its records. The native exporter adds a
root sharding marker from the database's recorded `single` or `d34` mode.

With the destination server stopped, restore into a **new** database path:

```sh
mkit-server restore --meta sqlite:/srv/mkit/new-meta.sqlite3 \
  --from /srv/backups/export-2026-09-27 --sharding d34
```

`--sharding` defaults to the archive marker's mode and must match it when
given. `--epoch-at-least N` can set a
higher minimum grant epoch. Restore advances fresh coordinator epochs by at
least 2^32, marks their lease tables recovered, re-keys relay sequences and removes backup
timers/state. Keep traffic off the destination until the command succeeds;
the restore spans multiple partition transactions. An existing database is
refused. For an in-place native recovery using a physical backup, follow the
preceding physical backup instructions.
Owners must re-issue grants after logical restore.

Missing relay sources or namespace coordinators stop restore by default.
`--allow-incomplete` reconstructs missing sources at their target watermark;
missing coordinators additionally require `--epoch-at-least N` with N ≥ 2^32 (4294967296), above any epoch the lost coordinator could have issued. The command
prints the missing partitions it reconstructed.

On Workers, bind a dedicated `BACKUPS` R2 bucket and leave
`BACKUP_INTERVAL_MS` at its daily default unless operations require another
cadence. Configure a 35-day lifecycle rule for the `backups/` prefix only.
Never apply that rule to `packs/`, which holds live content. The bucket and
lifecycle rule are deployment steps; inspect them before relying on periodic
exports. A snapshot older than the maximum accepted envelope validity does
not carry replay risk from still-valid old envelopes.

The bucket must be private, with no r2.dev or custom domain and only scoped
tokens, and match `NAMESPACE_JURISDICTION`. Snapshots contain private ref
names, signer keys, tickets and replay rows. Staging must use its own
`BACKUP_PREFIX`. The first export runs one interval after the first committed
put. Choose one object per `<kind>/<hash>/`, normally the newest; Worker
snapshots are per partition rather than one consistent cut. An older target
can lack membership or index rows until index reconciliation ships (R-116).

Production Worker import and PITR control await the admin API (WP-5.11b).
Exports above the per-object size cap await segmentation. Index reconciliation
after restore, a post-restore replay fence, and a GC hold covering backup
retention remain deferred.

### Portable logical backup

`mkit_server::store::export_partition` streams one partition's rows in the
backend-neutral export format, and `import_stream` restores them into any
backend: another `SQLite` file, a Durable Object, the in-memory store. The
stream alone does not guarantee a snapshot; use a quiesced partition or a
single backend read transaction as the native command does.

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


### Storage pressure alerts

With `SQLite` metadata, the server reads physical database bytes at startup and
then every 60 seconds against the `--sqlite-max-bytes` soft limit (the hard cap
minus the pruning reserve). A `storage_pressure` event contains `level`,
`kind = database`, `bytes`, `limit_bytes` and `pct`: warning at 70%, critical at
90%. A level clears at 65% or 85%, respectively. Only the highest
active level emits, at most once per level per ten minutes. JSON log mode keeps
these fields structured. The `mkit_server_partition_bytes{kind="database"}`
gauge uses the metrics facade; an embedder must install a recorder to export it.

Workers emit the same pressure fields after committed put batches, using the
local physical `databaseSize` and the `WORKERS_PLAN` soft limit. Metrics go to
console JSON as `{"metric": name, "labels": {...}, "value": n}`. Counters and
gauges always emit; latency observations emit every hundredth call across an
isolate. Info events use the log console; warning/error events use the error
console. Debug and trace events are disabled. Pressure state is per DO instance;
a new instance starts a new alert interval.
