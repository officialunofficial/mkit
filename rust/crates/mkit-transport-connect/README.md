# mkit-transport-connect

The native host adapter for `mkit.transport.v1.TransportService`
([SPEC-TRANSPORT-CONNECT](../../../docs/specs/SPEC-TRANSPORT-CONNECT.md)).
`mkit-client` owns request construction, signatures, framing, and decoding.
`ClientSource` in `mkit-sync` owns bounded native uploads and ref advances.

`ConnectTransport` retains the synchronous `Transport` API and native host
configuration: TLS trust, bearer credentials, grants, admission helpers,
scheduling, and progress callbacks. The CLI lends its configured `ClientSource`
through `ConnectTransport::with_source` for `mkit+https` and `mkit+http`
push, fetch, pull, and clone. Other schemes use `TransportSource`.

The server side is not in this crate. `mkit-server`'s pipeline serves
`mkit.transport.v1`. The `server` Cargo
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

## Native and wasm

The protocol client is runtime-independent and builds for native and wasm.
This adapter uses `mkit-sync::NativeHttp`, a current-thread Tokio runtime and
Hyper over rustls. TLS verifies chain and hostname against the compiled Mozilla
roots. Browser clients retain browser-managed trust.

The native CLI can add trusted certificates with `http.sslCAInfo`, or with
`MKIT_SSL_CA_FILE`, which takes precedence. The selected PEM file augments
the Mozilla roots for every Connect HTTPS RPC, including upload and download
streams. Certificate-chain and hostname verification remain enabled.
Missing, unreadable, empty, or malformed files are hard errors. Supply
certificates only; keep private keys out of the CA file. These settings cover
Connect remotes only: the self-updater is excluded by design, S3 remotes are
not yet covered, and wasm/browser Fetch trust is unaffected. See the
[CLI certificate trust reference](../../../docs/CLI.md#https-certificate-trust).

## Synchronous operations and recovery

`Transport` remains synchronous and object-safe. The adapter lends a borrowed
client and caller-owned `ClientSession` for each operation. Short internal locks
protect shared session state and release before host callbacks, which may reenter
the adapter. A CLI repository operation keeps the same source
from upload through the consuming advance. Stored part receipts keep their
existing format and durability boundary.

The host uses the core backoff ladder for classified transient failures.
Ambiguous writes retain their authenticated operation, body, and identity until
expiry. Grants are selected per signed request. Only `BeginUpload`, `UpdateRef`,
and ticketless `AdvanceRefs` run a one-shot admission helper, followed by a new
retry ladder. Ticket-consuming calls return payment challenges without a helper.
Pending verification and membership waits retain their deadlines and cancellation
checkpoints. HTTP request budgets are clipped to the remaining advance deadline.

## Native behavior differences

| Behavior | Previous driver | Protocol client adapter |
| --- | --- | --- |
| Uploads | Generated streaming calls and a part producer thread | Pull frames through a bounded channel; no producer thread |
| Downloads | Generated streaming decoder | Incremental bounded Connect and protobuf decoding into the final pack buffer |
| Runtime | Dedicated runtime with multiple worker threads | Current-thread runtime, driven by the synchronous caller |
| Connections | Pooled unary connections with one stale-socket retry; fresh streamed transfers | One idle connection per origin, including streams, with a ten-second idle timeout; hyper retries only untouched requests canceled before writing starts |
| HTTP and content coding | HTTP/1.1 or HTTP/2, gzip or zstd | HTTP/1.1, gzip or identity |
| Request budgets | 30 seconds for metadata, 300 seconds for transfers; signing consumes the local budget | Same budgets, including signing, bounded by remaining advance time; the timeout header advertises the locally clamped remaining budget |
| Channel failures | Connect status mapping and ordinary retry ladder | Host-owned mappings retain HTTP diagnostics, status classes, and retry counts; body-read failures and deadlines remain terminal; metadata-bound failures retain 429 retries |
| Gzip validation | Buffered decoder could stop after the first member | Streaming decoder rejects trailing bytes and concatenated members |
| Shared adapter operations | Independent operation state with shared ticket maps | Caller-owned session with short internal state locks; callbacks may reenter the adapter |

Neither upload framing nor download decoding retains a complete framed transfer
next to the final pack. Generic `HttpTransport` implementations can use the
buffered streaming fallback; the native adapter implements bounded streaming.
Pack bytes and ids, ref conditions and moves, receipt records, CLI output, and
exit codes remain unchanged. No server, wire, stored-format change, or wipe occurs.

Reads and signed writes both reuse connections on the same owned current-thread
runtime. Hyper's cancellation retry can recover only a request that has not
started writing; it preserves the original request, including signed headers,
nonce, body, and streaming receiver. A failure after writing starts returns to
the host's existing recovery policy. Idle checkout checks elapsed monotonic time
even when the runtime is paused, and TCP_NODELAY matches the previous adapter.
See the [CLI HTTPS latency comparison](../../../docs/operations/connect-cli-latency.md)
for measured clone, pull, and push behavior and reproduction instructions.

The host response profile retains the previous metadata limit of 4 MiB and its
acceptance of successful 2xx responses, missing content types, protobuf content
type prefixes, and omitted false presence fields. It omits a zero listing page
size, ignores malformed optional read hints, and leaves final download digest
verification to sync's staging boundary, as the previous driver did. Chunk
identity, offsets, lengths, and resource bounds remain enforced. The protocol
client's default validation and response limits remain unchanged.

This adapter keeps pack-location negotiation disabled so reads retain their
existing discovery and retry behavior. Native hosts using `mkit-client` directly
can negotiate verified locations through `mkit-sync::NativeHttp`.

## Remaining adapter users

The CLI retains this adapter for TLS and bearer configuration, envelope signers,
per-request grants, admission helpers, durable receipt storage, and progress.
Its epoch and visibility commands also retain the concrete adapter's legacy
`Completion` result. Config validates admission header names through its public
helper. In-process sync tests retain `Transport`; server conformance retains that
facade and generated aliases. `EnvelopeTransport`, pooled HTTP utilities, and
generated aliases remain published compatibility APIs. None retains a second
per-RPC protocol driver.

## Testing

Existing roundtrip, retry, timeout, TLS, grant, admission, multipart, and
conformance tests exercise the retained adapter APIs. Native streaming tests
check incremental delivery, bounded frames and gzip, end markers, checksums,
and request deadlines. Both-backend sync push tests pin pack bytes and ids,
CAS behavior, grants, admission recovery, and receipt reuse after interruption.
