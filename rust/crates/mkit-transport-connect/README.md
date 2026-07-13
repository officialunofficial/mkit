# mkit-transport-connect

Both halves of `mkit.transport.v1.TransportService` (SPEC-TRANSPORT-CONNECT)
— the implementation behind the `mkit+https://` (and loopback-only
`mkit+http://`) remote scheme — live in this crate:

- **Client** ([`ConnectTransport`]): a non-wasm ConnectRPC client
  implementing the `Transport` trait (`docs/specs/SPEC-TRANSPORT.md`) itself
  over the same `mkit.transport.v1` service. `mkit-cli`'s `remote_dispatch`
  constructs this for `mkit+https://` / loopback `mkit+http://`, replacing
  `mkit-transport-http`'s bespoke JSON dialect there. This is the crate's
  mandatory baseline — always compiled, no cargo feature needed.
- **Server** ([`serve`]/[`router`]/[`TransportServer`]): an
  axum-hosted [ConnectRPC] server generic over any
  [`mkit_core::protocol::Transport`] backend (today,
  `mkit-transport-file::FileTransport`). This is `mkit serve --http`'s
  implementation: an operator without SSH access or a cloud object store can
  run it against a local repository so teammates can push/pull over
  `mkit+https://` without standing up a Cloudflare Worker. Behind this
  crate's own `server` cargo feature (off by default; `mkit-cli` enables it
  via its `http-transport` feature, mirroring `enc-transport`) so a
  client-only consumer doesn't pay axum/hyper-server's compile cost.

[ConnectRPC]: https://connectrpc.com/

See `docs/specs/SPEC-TRANSPORT-CONNECT.md` for the full normative wire
contract: verb-to-RPC mapping, CAS semantics, the `TransportError` <->
Connect-code mapping (both directions — `src/error.rs`), and the
`UploadPack`/`DownloadPack` streaming design.

## Codegen

`build.rs` compiles directly against the CANONICAL proto
(`<repo-root>/proto/mkit/transport/v1/transport.proto`, referenced by a
workspace-relative path) — there is no second copy, so this crate and any
future consumer of the same proto cannot drift. Mirrors `mkit-repo-client`'s
"zero-duplication" approach.

- **Default path**: `build.rs` stages the pre-generated sources committed
  under `generated/` into `$OUT_DIR` — no `protoc` required. This keeps
  Cloudflare Workers Builds, CI, and docs.rs (whose images lack a `protoc`
  new enough for the `edition = "2023"` proto) building with zero system
  dependencies.
- **Regeneration path**: set `MKIT_REPO_CODEGEN=1` to run `connectrpc-build`
  against the canonical proto instead (requires `protoc >= 27` on `PATH`, or
  via `PROTOC`). After editing `transport.proto`, run
  `scripts/regen-transport-proto.sh` from the repo root and commit the
  refreshed `generated/`.

## Server usage (`server` feature)

```rust,ignore
use std::sync::Arc;
use mkit_transport_connect::serve;
use mkit_transport_file::FileTransport;

let transport = Arc::new(FileTransport::new("/path/to/repo"));
let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
serve(listener, transport, std::future::pending()).await?;
```

`mkit serve --http <addr>` (`rust/crates/mkit-cli/src/commands/serve/http.rs`,
behind `mkit-cli`'s `http-transport` cargo feature, which in turn enables
this crate's `server` feature) is the CLI entry point.

## Client: native vs. wasm

The client half differs from `mkit-repo-client` (its wasm sibling) only in
target: native (Tokio, `connectrpc`'s hyper-rustls client transport) rather
than wasm (Fetch API, `wasm-bindgen`). It drops the wasm-only dependencies
(`wasm-bindgen`, `web-sys`, `send_wrapper`) and enables `connectrpc`'s native
client-TLS feature instead. TLS trust uses `webpki-roots` (the Mozilla root
program, a pure-Rust dependency) rather than the OS trust store, so this
crate has no system dependency beyond a working TLS/TCP stack.

## Sync `Transport`, async client

`Transport` is a synchronous, object-safe trait (`&self` methods, no
`async`). Both the server (wrapping the backend `Transport`) and
`ConnectTransport` (the client) bridge this to `connectrpc`'s async API via
`mkit_core::protocol::async_shim::Executor` — a dedicated tokio runtime,
mirroring `mkit-transport-enc`'s `tcp::TokioExecutor`.

## No built-in retry ladder

Unlike `mkit-transport-http`, the client does **not** implement its own
retry/backoff loop. SPEC-TRANSPORT-CONNECT §7.3 defers that to a shared
Connect interceptor wrapping the generated client (tracked separately) —
every call here is a single attempt. Callers that need SPEC-TRANSPORT §7
retry semantics apply `mkit_core::protocol::is_retryable` /
`BackoffIterator` to this transport's returned `TransportError` themselves.
`mkit-transport-http` is NOT removed: its `sparse-checkout`/`pack-shards`
extensions have no `mkit.transport.v1` equivalent yet.

## Testing

`tests/roundtrip.rs` proves the client against a real (in-process)
`TransportService` server — a `connectrpc` hyper server on an ephemeral
loopback port, implementing the generated `TransportService` trait over an
in-memory `mkit-transport-memory::MemoryTransport` backend — driving a full
upload/download/ref/advance round trip through the generated codebase. This
is the regression gate SPEC-TRANSPORT-CONNECT's testing decisions call for:
a real server, not a mock standing in for one. It builds its own connectrpc
server harness directly and does NOT need this crate's `server` feature, so
`cargo test -p mkit-transport-connect` (no flags) still runs it.

`tests/e2e.rs` additionally proves this crate's own [`serve`] against a real
(non-wasm) `connectrpc` client over loopback TCP, backed by
`mkit-transport-file::FileTransport`. It needs this crate's `server` feature
(`required-features` in `Cargo.toml`), so run with `--features server` (or
`--all-features`) to include it.
