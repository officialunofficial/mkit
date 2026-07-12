# mkit-transport-connect

An axum-hosted [ConnectRPC] server for `mkit.transport.v1.TransportService`
(SPEC-TRANSPORT-CONNECT), generic over any
[`mkit_core::protocol::Transport`] backend. This is `mkit serve --http`'s
implementation: an operator without SSH access or a cloud object store can
run it against a local repository so teammates can push/pull over
`mkit+https://` without standing up a Cloudflare Worker.

[ConnectRPC]: https://connectrpc.com/

## What this crate is (and isn't)

- **Is**: the server half — [`TransportServer`] wraps any `Transport` impl
  (today, `mkit-transport-file::FileTransport`) and answers the seven wire
  RPCs (`ListRefs`, `ReadRef`, `UpdateRef`, `AdvanceRefs`, `PackExists`,
  `UploadPack`, `DownloadPack`) defined in
  `proto/mkit/transport/v1/transport.proto`.
- **Isn't**: the native CLI Connect *client* that will back `mkit+https://`
  remotes — that's a separate crate, tracked as mkit#701. This crate's
  `[dev-dependencies]` pull in `connectrpc`'s `client` feature only to drive
  this crate's own integration test end-to-end; it is not a public client API.

## Codegen

`build.rs` compiles directly against the CANONICAL proto
(`<repo-root>/proto/mkit/transport/v1/transport.proto`, referenced by a
workspace-relative path) — there is no second copy, so this crate and any
future consumer of the same proto cannot drift. Default builds stage the
pre-generated sources committed under `generated/` (no protoc required, same
as `mkit-repo-client` / `apps/repo-worker`). Set `MKIT_TRANSPORT_CODEGEN=1`
to regenerate via `connectrpc-build` after editing `transport.proto`
(requires protoc >= 27 on `PATH` or via `PROTOC`); run
`scripts/regen-transport-proto.sh` from the repo root and commit the result.

## Usage

```rust,ignore
use std::sync::Arc;
use mkit_transport_connect::serve;
use mkit_transport_file::FileTransport;

let transport = Arc::new(FileTransport::new("/path/to/repo"));
let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
serve(listener, transport, std::future::pending()).await?;
```

`mkit serve --http <addr>` (`rust/crates/mkit-cli/src/commands/serve/http.rs`,
behind the `http-transport` cargo feature) is the CLI entry point.

## Error mapping

Every `TransportError` variant maps onto exactly one Connect code, per
SPEC-TRANSPORT-CONNECT §5 — see `src/error.rs`.

## Streaming

`UploadPack` (client-streaming) and `DownloadPack` (server-streaming) follow
SPEC-TRANSPORT-CONNECT §6's header-then-chunks contract: a rejected upload
never creates or overwrites the destination pack, and a download either
completes with `chunk.last = true` or fails before any message is sent — see
`src/pack.rs`.
