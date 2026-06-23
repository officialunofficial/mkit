# mkit-repo-client

Browser ConnectRPC client for `mkit.repo.v1.RepoService`, compiled to
`wasm32-unknown-unknown` and consumed by the web demo (`apps/web/src/lib/repo-api.ts`).

- Transport: a Fetch-API `ClientTransport` ported from connect-rust's
  `examples/wasm-client` (`src/transport.rs`).
- Codegen: `build.rs` runs `connectrpc-build` directly over the **canonical**
  proto — `apps/repo-worker/proto/mkit/repo/v1/repo.proto` (referenced by a
  workspace-relative path). There is **no second copy**: this crate and the
  worker compile the same file, so they cannot drift. (As part of the mkit
  monorepo, this crate expects that path to exist.)
- Build to web: `wasm-pack build --target web` (driven by
  `web` script `wasm:build:repo-client`). `wasm-opt` is disabled in
  `Cargo.toml` metadata (mirrors `mkit-wasm`): wasm-pack's bundled `wasm-opt`
  predates bulk-memory ops and rejects rustc 1.95 codegen.

## Exposed JS API (wasm-bindgen)

```ts
// reads (no auth)
get_ref(baseUrl, room, name): Promise<string | undefined>            // objectId hex | undefined
get_object(baseUrl, room, objectIdHex): Promise<Uint8Array | undefined>
list_refs(baseUrl, room, prefix): Promise<Array<{ name, objectIdHex }>>

// writes (signed — see envelope contract below)
put_object(baseUrl, room, objectIdHex, bytes, sign): Promise<{ stored, duplicate }>
update_ref(baseUrl, room, name, newIdHex, expectation, expectedIdHex, sign)
  : Promise<{ committed, conflict, currentIdHex }>   // expectation: "ANY"|"MISSING"|"MATCH"

// streaming feature-detect (always false today — see §Streaming)
watch_refs_supported(): boolean
```

All object/ref ids cross the boundary as **lowercase hex**; on the wire they are
raw 32-byte BLAKE3 digests (`bytes` proto fields). The proto is `edition 2023`,
so every scalar field has explicit presence — the Rust side wraps/unwraps the
`Option`s; JS never sees that.

## Envelope-signing contract (integration-critical)

Writes (`PutObject` / `UpdateRef`) carry a signed-write envelope as request
**headers** (not proto fields). The signature is computed **in JS** (the web app
holds the Ed25519 seed in the Zustand store and signs via `mkit-wasm`'s
`ed25519_sign` + `blake3_hex`); this client only forwards the resulting headers.

### Header names

| Header           | Value                                                              |
| ---------------- | ----------------------------------------------------------------- |
| `X-Public-Key`   | 64-hex Ed25519 public key (the anonymous author id)               |
| `X-Signature`    | 128-hex Ed25519 signature                                          |
| `X-Digest`       | 64-hex BLAKE3 of the **raw request body** (client-claimed)        |
| `X-Created-At`   | `String(epochMillis)` — **epoch ms**, NOT ISO-8601                |
| `Idempotency-Key`| opaque dedupe token (omitted ⇒ canonical field is `""`)           |

These exactly match `apps/repo-worker/src/lib/envelope.ts`
(`EnvelopeHeaders`). The server recomputes `BLAKE3(rawBody)` and rejects on
`X-Digest` mismatch (`400 body digest mismatch`), then strict-Ed25519-verifies.

### Canonical string (signed)

```
[ "mkit-write:v1",
  procedure,        // e.g. "/mkit.repo.v1.RepoService/UpdateRef"
  bodyDigest,       // lowercase hex BLAKE3 of the RAW request body bytes
  createdAt,        // String(epoch ms)
  idempotencyKey ]  // or "" if absent
.join("\n")
```

Then `signing_digest = BLAKE3(utf8(canonical))` (hex) and
`signature = ed25519_sign(signing_digest, seed)` (strict verify server-side).
This is a plain envelope digest — the SPEC-SIGNING commit/remix/tag domain
prefixes do **NOT** apply.

### Which bytes are hashed — and why the client owns the digest

`bodyDigest` (and the server's `actualBodyDigest`) is `BLAKE3` of the
**serialized protobuf request message** — the exact bytes on the Connect/proto
wire. The client config uses the default `CodecFormat::Proto` and **no request
compression**, so the body is the bare serialized message (no Connect-stream
framing, no gzip). The server hashes the same raw body it receives.

JS cannot reproduce these protobuf bytes reliably, so **the digest is computed
inside this wasm client**, where serialization happens. The flow:

1. JS calls `update_ref(..., sign)` / `put_object(..., sign)`, passing a
   **sign-callback**.
2. The transport serializes the request and computes `BLAKE3(rawBody)`.
3. It invokes `sign(bodyDigestHex)` — JS builds the canonical string with that
   digest, signs it with the in-memory seed (via `mkit-wasm`), and returns
   `{ publicKeyHex, signatureHex, createdAt, idempotencyKey }` (sync or a
   `Promise`). An optional `digestHex` field, if present, must equal
   `bodyDigestHex`.
4. The transport attaches the `X-*` headers and sends.

This is why writes take a callback rather than pre-built headers: the digest the
JS must sign is only known after the wasm side serializes the message, and the
server validates against exactly those bytes. Signing the digest of a *different*
serialization (e.g. JS `JSON.stringify`) would fail `X-Digest` verification.

> Note: `createdAt` is **epoch milliseconds**. The pre-existing
> `repo-api.ts` mock used `new Date().toISOString()`; the real client (and
> server) require `String(Date.now())`.

## Streaming (`WatchRefs`)

`WatchRefs` is server-streaming. The buffered Fetch transport here reads the
whole response body via `array_buffer()` and cannot surface an incremental
stream in `wasm32-unknown-unknown`. `watch_refs_supported()` returns `false`;
the demo drives liveness another way (mock fan-out today; a WebSocket/SSE bridge
is the intended follow-up). The unary surface does not depend on it.
