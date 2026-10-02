# mkit-transport-connect

The native [ConnectRPC] client of `mkit.transport.v1.TransportService`
(SPEC-TRANSPORT-CONNECT) &mdash; the implementation behind the `mkit+https://`
(and loopback-only `mkit+http://`) remote scheme.

[`ConnectTransport`] implements the `Transport` trait
(`docs/specs/SPEC-TRANSPORT.md`) itself over the `mkit.transport.v1` service.
`mkit-cli`'s `remote_dispatch` constructs it for `mkit+https://` / loopback
`mkit+http://`, replacing `mkit-transport-http`'s bespoke JSON dialect there.

The server side is not in this crate. Self-hosted remotes run `mkit-server`
(the `mkit-server-native` crate, over `mkit-server`'s pipeline):
`mkit-server serve --listen <ADDR> --repo-root <DIR>`. The `server` cargo
feature and its `serve`/`router`/`TransportServer`/`map_transport_error` API,
which backed the removed `mkit serve --http`, were removed in 0.5.

[ConnectRPC]: https://connectrpc.com/

See `docs/specs/SPEC-TRANSPORT-CONNECT.md` for the full normative wire
contract: verb-to-RPC mapping, CAS semantics, the `TransportError` <->
Connect-code mapping (the client direction is `src/error.rs`), and the
`UploadPack`/`DownloadPack` streaming design.

## Codegen

`mkit-rpc` owns the generated messages and Connect bindings behind its opt-in
`transport` feature. This client re-exports the shared types at `proto` and
`generated`; its native runtime features stay here. Both the client and server
use the canonical `<repo-root>/proto/mkit/transport/v1/transport.proto`.

- **Default path**: `mkit-rpc` stages committed sources from
  `generated/transport/` into `$OUT_DIR`; consumers and docs.rs need no `protoc`.
- **Regeneration path**: run `scripts/regen-transport-proto.sh` from the repo
  root (requires `protoc >= 27` on `PATH`, or via `PROTOC`). It enables
  `MKIT_TRANSPORT_CODEGEN=1` for the owning crate and refreshes the single
  shared tree. Commit that output after editing the canonical proto.

## Native vs. wasm

The client differs from `mkit-repo-client` (its wasm sibling) only in
target: native (Tokio, `connectrpc`'s hyper-rustls client transport) rather
than wasm (Fetch API, `wasm-bindgen`). It drops the wasm-only dependencies
(`wasm-bindgen`, `web-sys`, `send_wrapper`) and enables `connectrpc`'s native
client-TLS feature instead. TLS trust uses `webpki-roots` (the Mozilla root
program, a pure-Rust dependency) rather than the OS trust store, so this
crate has no system dependency beyond a working TLS/TCP stack.

The native CLI can add trusted certificates with `http.sslCAInfo`, or with
`MKIT_SSL_CA_FILE`, which takes precedence. The selected PEM file augments
the Mozilla roots for every Connect HTTPS RPC, including upload and download
streams. Certificate-chain and hostname verification remain enabled.
Missing, unreadable, empty, or malformed files are hard errors. Supply
certificates only; keep private keys out of the CA file. These settings cover
Connect remotes only: the self-updater is excluded by design, S3 remotes are
not yet covered, and wasm/browser Fetch trust is unaffected. See the
[CLI certificate trust reference](../../../docs/CLI.md#https-certificate-trust).

## Sync `Transport`, async client

`Transport` is a synchronous, object-safe trait (`&self` methods, no
`async`). `ConnectTransport` bridges it to `connectrpc`'s async API via
`mkit_core::protocol::async_shim::Executor` &mdash; a dedicated tokio runtime,
mirroring `mkit-transport-enc`'s `tcp::TokioExecutor`.

## No built-in retry ladder

Unlike `mkit-transport-http`, the client does **not** implement its own
retry/backoff loop. SPEC-TRANSPORT-CONNECT §7.3 defers that to a shared
Connect interceptor wrapping the generated client (tracked separately) &mdash;
every call here is a single attempt. Callers that need SPEC-TRANSPORT §7
retry semantics apply `mkit_core::protocol::is_retryable` /
`BackoffIterator` to this transport's returned `TransportError` themselves.
`mkit-transport-http` is NOT removed: its `sparse-checkout`/`pack-shards`
extensions have no `mkit.transport.v1` equivalent yet.

## Testing

`tests/roundtrip.rs` proves the client against a real (in-process)
`TransportService` server &mdash; a `connectrpc` hyper server on an ephemeral
loopback port, implementing the generated `TransportService` trait over an
in-memory `mkit-transport-memory::MemoryTransport` backend &mdash; driving a full
upload/download/ref/advance round trip through the generated codebase. This
is the regression gate SPEC-TRANSPORT-CONNECT's testing decisions call for:
a real server, not a mock standing in for one. `tests/retry.rs` and
`tests/rpc_timeout.rs` build their own servers the same way.

End to end against the real server, `mkit-server-native`'s
`tests/client_e2e.rs` drives `ConnectTransport` against `mkit-server serve`
over FS blobs and `.mkit`-layout refs.

Unary reads and auth-v2 writes retry once on a fresh HTTP/1 connection when a
previously used pooled socket closes or resets before receiving any response
bytes. Socket accounting includes partial headers. Writes replay the same
signed envelope and nonce, allowing the server's stored result to answer a
lost response. Streaming RPCs start their sole attempt on a fresh connection, so a stale
pooled socket cannot interrupt an unreplayable body. Unsigned writes, HTTP
error responses and body read failures are not replayed. Both attempts share the caller's RPC deadline;
TLS trust and client credentials remain the same on the fresh connection.
