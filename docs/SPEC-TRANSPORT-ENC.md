---
spec: SPEC-TRANSPORT-ENC
version: 1 (Phase 2)
status: draft
audience: implementers of mkit encrypted-stream clients and servers
---

# SPEC-TRANSPORT-ENC — mkit encrypted-stream transport

`mkit-transport-enc` is the encrypted-stream sibling of
`mkit-transport-ssh`. It implements the same seven-verb
[`Transport`](../rust/crates/mkit-core/src/protocol.rs) trait, exchanging
the same [`SshFrame`](../rust/crates/mkit-rpc/proto/ssh.proto) protobuf
messages, but over an authenticated, encrypted byte stream provided by
[`commonware-stream::encrypted`](https://docs.rs/commonware-stream)
instead of a system `ssh(1)` child process.

The motivation is to give mkit a self-contained "always-encrypted"
transport for environments where shelling out to OpenSSH is awkward
(WASM, embedded targets, browser-hosted Workers) while keeping a single
source of truth for verb-level framing across SSH and encrypted paths.

Phase 1 landed the in-process scaffold (`EncSession` /
`from_session`) and the deterministic-runtime round-trip test. Phase 2
(this revision) adds real TCP: URL parsing, `connect_tcp` /
`serve_tcp`, the `mkit-cli/enc-transport` feature gate, and the
`mkit serve --listen-enc <addr>` listener. §6 records what now ships
and what remains for Phase 3.

---

## 1. URL scheme

| Scheme prefix | Transport | Notes |
|---|---|---|
| `mkit+enc://[user@]host[:port][/path]?pubkey=<hex-or-b64url>` | `mkit-transport-enc` | Implemented in Phase 2 (`mkit_transport_enc::url::parse_enc_url`). The `user@` and `/path` components are accepted for round-tripping but not consulted by the handshake; trust is via the `?pubkey=` payload only. |

The URL carries the **server's static `ed25519` public key** as a
query-parameter `pubkey=<…>` in one of two equivalent encodings:

- **Hex**: 64 lowercase or uppercase hex digits (32 bytes raw).
- **URL-safe base64, no padding**: 43 chars, alphabet
  `[A-Za-z0-9-_]`. The trailing 2 bits of the final base64 character
  MUST be zero; otherwise the parser rejects the URL to prevent
  two distinct strings from decoding to the same payload.

Trust is established by out-of-band knowledge of this key — there is
no fall-back to a TOFU-style first-use cache, and no CA chain. If the
server's actual key during handshake differs from the URL-advertised
key, the dialer aborts with `EncInitError::PeerRejected` (mapped from
`commonware_stream::encrypted::Error::PeerRejected`).

The default TCP port when the URL omits one is **9418** (same as git's
daemon, reused for operator familiarity).

### 1.1 Examples

```text
mkit+enc://h.example?pubkey=0000…0000             # bare host + hex
mkit+enc://h.example:7777?pubkey=0000…0000        # explicit port
mkit+enc://alice@h.example/projects/x?pubkey=…    # user + path (round-trip only)
mkit+enc://h.example?pubkey=AAAAAA…AAA            # b64-url, 43 chars
```

---

## 2. Cryptographic layer

The encrypted layer is provided verbatim by
[`commonware_stream::encrypted`] (version `2026.5.0` pinned in
`Cargo.toml`). mkit does **not** implement its own handshake or AEAD;
this section documents the parameters mkit configures.

### 2.1 Handshake parameters

| Field | Value | Rationale |
|---|---|---|
| `namespace` | `b"mkit/transport-enc/v1"` | Pre-shared transcript binding. Prevents cross-application replay if peers share `ed25519` keys with another commonware-stream user. Bumping the `/v1` suffix is the lever for a hard cryptographic break in future. |
| `max_message_size` | `mkit_rpc::MAX_FRAME_BYTES` (1 MiB) | Matches the inner `SshFrame` framing cap so a maximally-sized verb fits in one encrypted record. Removes an off-by-overhead class of bugs where one limit sneaks past the other. |
| `synchrony_bound` | 30 s | Tolerable clock skew between client and server. Generous in Phase 1 to keep flaky-CI failures out of the in-tree round-trip test; Phase 2 will tighten to ≤ 5 s. |
| `max_handshake_age` | 30 s | Same envelope as `synchrony_bound`; Phase 2 will tighten. |
| `handshake_timeout` | 60 s | Hard ceiling for handshake completion. Generous for Phase 1; Phase 2 will tighten to ≤ 10 s. |

### 2.2 Identity

Both peers carry an [`ed25519`](https://docs.rs/commonware-cryptography)
static keypair. mkit chose ed25519 (over BLS) for Phase 1 because:

1. The keys are small (32-byte public, 32-byte private), matching the
   shape of SSH host keys mkit operators already manage.
2. Verification is constant-time and fast, suitable for browser-hosted
   clients in the planned Workers integration.
3. `commonware-cryptography::ed25519` is already a stable `Signer` and
   needs no application glue.

Phase 2 may add BLS as an optional alternative (the
`commonware_stream::encrypted` API is generic over `Signer`), but the
default — and the only form covered by Phase 1's CLI — is ed25519.

### 2.3 Properties

Inherited from `commonware-stream::encrypted` (verbatim from its
documented guarantees):

- **Mutual authentication** via static-key signatures over the
  handshake transcript.
- **Forward secrecy** via ephemeral X25519.
- **Per-record nonce derivation** — ChaCha20-Poly1305 nonces are a
  monotonic counter, never transmitted on the wire.
- **Session uniqueness** — `SynAck` is transcript-bound to `Syn`,
  preventing replay across sessions.
- **Handshake timeout** — see §2.1.

Not provided (also inherited):

- **Anonymity** — peer identities are exchanged in cleartext during
  the handshake. mkit clients embed `mkit/<version>` in the
  application-level Hello frame anyway, so we lose nothing.
- **Padding** — message lengths leak. Pack-upload chunks are 800 KiB
  each, so the leak ceiling is "this verb is or isn't a pack body
  chunk", which the SSH transport also reveals.

---

## 3. Application layer

The application protocol on top of the encrypted stream is the same
`SshFrame` protobuf message set used by `mkit-transport-ssh`, defined
in [`ssh.proto`](../rust/crates/mkit-rpc/proto/ssh.proto). Verb
semantics, error mapping, ref-CAS encoding, and pack-streaming chunk
boundaries are byte-for-byte identical to SPEC-TRANSPORT §4.

### 3.1 Framing — encrypted records, not length-prefixed bytes

The one deliberate departure from the SSH transport's wire is the
inner framing. `mkit-transport-ssh` wraps each `SshFrame` in a 4-byte
LE u32 length prefix (defined in
[`mkit-rpc/src/framing.rs`](../rust/crates/mkit-rpc/src/framing.rs))
because SSH's stdin/stdout pipe is an unframed byte stream.

`commonware-stream::encrypted` already frames each ciphertext record
(one varint length prefix per `Sender::send` call), so the inner
SshFrame rides as a **single protobuf payload per encrypted record**
— no second length prefix. One `SshFrame` send produces exactly one
`Sender::send`, and one `Receiver::recv` returns exactly one
`SshFrame`'s worth of bytes.

Concretely:

```text
┌──────────────────────────────────────────────┐
│ SshFrame protobuf body (verb message)        │
├──────────────────────────────────────────────┤
│ ChaCha20-Poly1305 ciphertext + 16-byte tag   │  per direction, counter nonce
├──────────────────────────────────────────────┤
│ commonware-stream varint length prefix       │  framing
├──────────────────────────────────────────────┤
│ Sink / Stream byte transport                 │  TCP (Phase 2) or mocks::Channel (Phase 1 tests)
└──────────────────────────────────────────────┘
```

The 1 MiB ceiling on `MAX_FRAME_BYTES` is enforced twice — once by
`commonware-stream` via `max_message_size` (see §2.1), once by every
`SshFrame` consumer that already exists. Either layer will reject a
non-conforming peer.

### 3.2 Hello handshake

After the encrypted handshake completes, the client MUST send a
`Hello` frame with `proto = PROTOCOL_VERSION_1` and `client_id =
"mkit <semver>"`. The server MUST reply with a `HelloResponse` whose
`proto` matches. If either side disagrees, both close the connection
without further verb exchange.

This Hello is layered **on top of** the encrypted channel, not inside
the encrypted handshake. It mirrors what `mkit-transport-ssh` does and
keeps the protocol-version dance in one place.

---

## 4. Resource caps

| Cap | Value | Source |
|---|---|---|
| Max single encrypted record | 1 MiB | `mkit_rpc::MAX_FRAME_BYTES` |
| Max ref name / prefix | 4096 bytes | `MAX_REF_NAME` in `mkit-rpc/src/helpers.rs` (re-exported by `mkit-transport-enc`) |
| Per-chunk pack data | 800 KiB | `CHUNK_DATA_MAX`; same as `mkit-transport-ssh` |
| Pack body total | `mkit_core::protocol::PACK_BODY_LIMIT` | Shared client cap |

---

## 5. Test plan

The in-tree test suite lives in
[`mkit-transport-enc/src/lib.rs`](../rust/crates/mkit-transport-enc/src/lib.rs)
under `#[cfg(test)] mod tests`. Tests run inside a single
`commonware_runtime::deterministic::Runner` so they exercise the same
async code paths Phase 2's tokio wiring will hit, without depending on
wall-clock time or a multi-threaded executor.

| Test | What it pins |
|---|---|
| `hello_and_list_refs_roundtrip_over_ciphertext` | End-to-end: encrypted handshake → app Hello → ListRefs round-trip → assert two refs decoded. Also captures bytes leaving the dialer's `Sink` and asserts the literal `"refs/heads/"` plaintext does NOT appear in the capture — the bytes on wire are ChaCha20-Poly1305 ciphertext. |
| `handshake_rejection_surfaces_peer_rejected` | Server's bouncer unconditionally returns `false`; client's `dial` MUST resolve to an error and the server-side outcome MUST be `EncryptedError::PeerRejected`. |
| `peer_rejected_error_maps_to_init_error` | Pure unit test: `EncryptedError::PeerRejected(_) → EncInitError::PeerRejected`. Catches regressions in the `From` impl even if a future commonware release moves which side surfaces the rejection. |
| `url::parse_enc_url::*` (~25 cases) | URL parser: pins accepted forms (`mkit+enc://[user@]host[:port][/path]?pubkey=<hex\|b64url>`), both pubkey encodings, and rejection of bad inputs (missing prefix / pubkey, port overflow, CRLF / NUL injection, `..` path segments, b64 trailing-bit ambiguity, duplicate / unknown query params). |
| `tcp::executor_handles_repeated_block_on` | `TokioExecutor::block_on` is safe to call repeatedly. Pins the `Arc<Runtime>` shape so a future refactor doesn't silently drop the runtime between calls. |
| `tcp::buffer_pool_is_cached` | The `OnceLock`-cached buffer pool returns the same underlying allocation across calls. |
| `tcp_e2e::list_refs_round_trip_over_real_tcp` (Phase 2, gated on `--features tcp`) | End-to-end TCP: real `TcpListener` on a free port, real `connect_tcp` dialer via an in-test byte-sniffing proxy. Asserts (a) `Transport::list_refs` round-trip succeeds and (b) the proxy never observes the literal `"refs/heads/"` prefix the client sent — bytes on wire are ChaCha20-Poly1305 ciphertext. |

---

## 6. Phase status

### 6.1 Phase 2 — landed

1. ~~**URL parsing**~~ — done. `mkit_transport_enc::url::parse_enc_url`
   accepts `mkit+enc://[user@]host[:port][/path]?pubkey=<hex|b64url>`.
   Pubkey encoding is hex (64 chars) or unpadded url-safe base64
   (43 chars) — both decode to the same 32-byte payload. See §1.
2. ~~**TCP transport**~~ — done. `EncTransport::connect_tcp` opens a
   tokio `TcpStream`, drives `commonware_stream::encrypted::dial`
   against the URL-advertised peer pubkey, and returns a fully-wired
   synchronous `Transport`. The dial is single-roundtrip; verb calls
   block_on a per-call future through the `TokioExecutor`. Custom
   `Sink`/`Stream` wrappers (`tokio_io::{TokioSink, TokioStream}`)
   adapt tokio's `OwnedReadHalf` / `OwnedWriteHalf` to
   `commonware_runtime::{Sink, Stream}` because the upstream
   `pub(crate)` types aren't reachable from outside the runtime crate.
3. ~~**CLI dispatch**~~ — done. `remote_dispatch::open` recognises the
   `mkit+enc://` scheme behind the `mkit-cli/enc-transport` cargo
   feature; default builds remain SSH-only.
4. ~~**Server binary**~~ — done. `mkit serve --listen-enc <addr>`
   spawns an async accept loop via
   `mkit_transport_enc::serve_tcp_with_policy`. The listener is
   **fail-closed** (issue #178): it refuses to bind unless the operator
   supplies `--enc-authorized-peers <PATH>` (an allowlist of client
   public keys) or passes `--unsafe-allow-any-enc-peer` (a dev escape
   that prints a loud warning). The allowlist bouncer rejects any
   unlisted dialer at the handshake — a rejected peer never receives a
   `HelloResponse`, list-refs, packs, or update-ref. The server
   identity is a **stable** raw-32 key loaded/auto-created from
   `--enc-server-key <PATH>` (or a user-scoped default
   `~/.config/mkit/enc/server.key`) so the advertised `?pubkey=` is
   stable across restarts; only the unsafe allow-any mode keeps the
   historic ephemeral per-process key. Peer-authorization and identity
   key paths are CLI-supplied or user-scoped and are **never** read
   from repo-local `.mkit/config`.

### 6.2 Phase 3 — deferred

5. **Keystore integration** — the server identity and (optionally) the
   client identity are now stable raw-32 key files on disk: the server
   uses `--enc-server-key` / the user-scoped default, and a client can
   pin its identity via the `MKIT_ENC_CLIENT_KEY` environment variable
   (a user-scoped / CLI-supplied raw-32 key file) so an allowlisting
   server can pin the client across restarts. When `MKIT_ENC_CLIENT_KEY`
   is unset the client still derives an ephemeral per-process key (works
   only against `--unsafe-allow-any-enc-peer` servers). Full
   `mkit-keystore` integration — surfacing these identities through the
   same backends as the SSH host keys and signing keys — remains the
   deferred follow-up.
6. **Tighten handshake bounds** — `default_handshake_config` still
   uses the generous 30 s / 30 s / 60 s envelope inherited from
   Phase 1 (deterministic-runtime tests). Real-network deployments
   should tighten `synchrony_bound` / `max_handshake_age` to ≤ 5 s
   and `handshake_timeout` to ≤ 10 s. Pending CI infra for a
   real-network e2e job.
7. ~~**Server-side keyring / bouncer policy**~~ — done (issue #178).
   `serve_tcp_with_policy` consults a `PeerPolicy` — `AllowAny` (dev /
   the explicit unsafe escape) or `Allowlist(HashSet<[u8;32]>)` built
   from the `--enc-authorized-peers` file (one client pubkey per line,
   64-hex or 43-char url-safe base64; `#` comments and blank lines
   ignored). The bare `serve_tcp` retains `AllowAny` for the direct
   e2e harness only. Surfacing the allowlist from a keystore partition
   instead of a flat file remains a follow-up.
8. **`publish = true`** — flip the `mkit-transport-enc` `Cargo.toml`
   flag so the crate ships to crates.io alongside the other
   transports. Requires keystore integration (#5) so the public
   `connect_tcp` signature does not have to churn when raw
   `PrivateKey` is replaced.
9. **Buffer-pool footprint** — `connect_tcp` lazily bootstraps a
   `commonware_runtime::BufferPool` by spinning up a one-shot
   commonware tokio Runner on a fresh OS thread, then dropping the
   bootstrap runtime while holding an `Arc` clone of the pool. The
   pool is cached process-wide. Phase 3 should land an upstream
   contribution to `commonware-runtime` that exposes a public
   `BufferPool::new_for_network()` so this trick can retire.

---

## 7. Versioning

Application protocol version is the same as the rest of mkit
(`PROTOCOL_VERSION_1`). The cryptographic-namespace prefix
(`mkit/transport-enc/v1`) is bumped independently if the handshake or
record layer needs a hard break that the application-level
`HelloResponse` mismatch can't catch.
