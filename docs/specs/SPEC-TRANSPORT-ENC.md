---
spec: SPEC-TRANSPORT-ENC
version: 1
status: draft
audience: implementers of mkit encrypted-stream clients and servers
---

# SPEC-TRANSPORT-ENC — mkit encrypted-stream transport

`mkit-transport-enc` is the encrypted-stream sibling of
`mkit-transport-ssh`. It implements the same seven-verb
[`Transport`](../../rust/crates/mkit-core/src/protocol.rs) trait, exchanging
the same [`SshFrame`](../../rust/crates/mkit-rpc/proto/ssh.proto) protobuf
messages, but over an authenticated, encrypted byte stream provided by
[`commonware-stream::encrypted`](https://docs.rs/commonware-stream)
instead of a system `ssh(1)` child process.

The motivation is to give mkit a self-contained "always-encrypted"
transport for environments where shelling out to OpenSSH is awkward
(WASM, embedded targets, browser-hosted Workers) while keeping a single
source of truth for verb-level framing across SSH and encrypted paths.

The transport has two forms: a deterministic in-process scaffold
(`EncSession` / `from_session`) exercised by the in-tree round-trip
test suite, and the real TCP transport used in production — URL
parsing, `connect_tcp` / `serve_tcp`, the `mkit-cli/enc-transport`
feature gate, and the `mkit serve --listen-enc <addr>` listener. §6
describes the TCP transport's mechanics and its current limitations.

---

## 1. URL scheme

| Scheme prefix | Transport | Notes |
|---|---|---|
| `mkit+enc://[user@]host[:port][/path]?pubkey=<hex-or-b64url>` | `mkit-transport-enc` | Implemented by `mkit_transport_enc::url::parse_enc_url`. The `user@` and `/path` components are accepted for round-tripping but not consulted by the handshake; trust is via the `?pubkey=` payload only. |

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
| `synchrony_bound` | 30 s | Tolerable clock skew between client and server. Generous, sized to keep flaky-CI failures out of the in-tree round-trip test; a production deployment operating over real, higher-latency networks SHOULD configure a tighter bound (≤ 5 s). |
| `max_handshake_age` | 30 s | Same envelope as `synchrony_bound`; the same tightening applies for production use. |
| `handshake_timeout` | 60 s | Hard ceiling for handshake completion. Generous for the in-process test scaffold; a production deployment SHOULD tighten to ≤ 10 s. |

### 2.2 Identity

Both peers carry an [`ed25519`](https://docs.rs/commonware-cryptography)
static keypair. mkit chose ed25519 (over BLS) for the in-process scaffold because:

1. The keys are small (32-byte public, 32-byte private), matching the
   shape of SSH host keys mkit operators already manage.
2. Verification is constant-time and fast, suitable for browser-hosted
   clients, including a Workers-hosted deployment.
3. `commonware-cryptography::ed25519` is already a stable `Signer` and
   needs no application glue.

A later revision may add BLS as an optional alternative (the
`commonware_stream::encrypted` API is generic over `Signer`), but the
default — and the only form covered by the in-process scaffold's CLI — is ed25519.

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
in [`ssh.proto`](../../rust/crates/mkit-rpc/proto/ssh.proto). Verb
semantics, error mapping, ref-CAS encoding, and pack-streaming chunk
boundaries are byte-for-byte identical to SPEC-TRANSPORT §4.

### 3.1 Framing — encrypted records, not length-prefixed bytes

The one deliberate departure from the SSH transport's wire is the
inner framing. `mkit-transport-ssh` wraps each `SshFrame` in a 4-byte
LE u32 length prefix (defined in
[`mkit-rpc/src/framing.rs`](../../rust/crates/mkit-rpc/src/framing.rs))
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
│ Sink / Stream byte transport                 │  TCP (production) or mocks::Channel (in-process test scaffold)
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
[`mkit-transport-enc/src/lib.rs`](../../rust/crates/mkit-transport-enc/src/lib.rs)
under `#[cfg(test)] mod tests`. Tests run inside a single
`commonware_runtime::deterministic::Runner` so they exercise the same
async code paths the TCP transport's tokio wiring hits, without
depending on wall-clock time or a multi-threaded executor.

| Test | What it pins |
|---|---|
| `hello_and_list_refs_roundtrip_over_ciphertext` | End-to-end: encrypted handshake → app Hello → ListRefs round-trip → assert two refs decoded. Also captures bytes leaving the dialer's `Sink` and asserts the literal `"refs/heads/"` plaintext does NOT appear in the capture — the bytes on wire are ChaCha20-Poly1305 ciphertext. |
| `handshake_rejection_surfaces_peer_rejected` | Server's bouncer unconditionally returns `false`; client's `dial` MUST resolve to an error and the server-side outcome MUST be `EncryptedError::PeerRejected`. |
| `peer_rejected_error_maps_to_init_error` | Pure unit test: `EncryptedError::PeerRejected(_) → EncInitError::PeerRejected`. Catches regressions in the `From` impl even if a future commonware release moves which side surfaces the rejection. |
| `url::parse_enc_url::*` (~25 cases) | URL parser: pins accepted forms (`mkit+enc://[user@]host[:port][/path]?pubkey=<hex\|b64url>`), both pubkey encodings, and rejection of bad inputs (missing prefix / pubkey, port overflow, CRLF / NUL injection, `..` path segments, b64 trailing-bit ambiguity, duplicate / unknown query params). |
| `tcp::executor_handles_repeated_block_on` | `TokioExecutor::block_on` is safe to call repeatedly: a task spawned during the first `block_on` is still alive when a later `block_on` awaits it, so a refactor that drops and rebuilds the runtime between calls fails the test. |
| `tcp_e2e::list_refs_round_trip_over_real_tcp` (gated on `--features tcp`) | End-to-end TCP: real `TcpListener` on a free port, real `connect_tcp` dialer via an in-test byte-sniffing proxy. Asserts (a) `Transport::list_refs` round-trip succeeds and (b) the proxy never observes the literal `"refs/heads/"` prefix the client sent — bytes on wire are ChaCha20-Poly1305 ciphertext. |

---

## 6. TCP transport mechanics and known limitations

### 6.1 Mechanics

`mkit_transport_enc::url::parse_enc_url` accepts
`mkit+enc://[user@]host[:port][/path]?pubkey=<hex|b64url>` per §1.
`EncTransport::connect_tcp` opens a tokio `TcpStream`, drives
`commonware_stream::encrypted::dial` against the URL-advertised peer
pubkey, and returns a fully-wired synchronous `Transport`. The dial is
single-roundtrip; verb calls block_on a per-call future through the
`TokioExecutor`. Custom `Sink`/`Stream` wrappers
(`tokio_io::{TokioSink, TokioStream}`) adapt tokio's `OwnedReadHalf` /
`OwnedWriteHalf` to `commonware_runtime::{Sink, Stream}` because the
upstream `pub(crate)` types aren't reachable from outside the runtime
crate.

`remote_dispatch::open` recognises the `mkit+enc://` scheme behind the
`mkit-cli/enc-transport` cargo feature; default builds remain SSH-only.

`mkit serve --listen-enc <addr>` spawns an async accept loop via
`mkit_transport_enc::serve_tcp_with_policy`. The listener is
**fail-closed** (issue #178): it refuses to bind unless the operator
supplies `--enc-authorized-peers <PATH>` (an allowlist of client public
keys) or passes `--unsafe-allow-any-enc-peer` (a dev escape that prints
a loud warning). `serve_tcp_with_policy` consults a `PeerPolicy` —
`AllowAny` (dev / the explicit unsafe escape) or
`Allowlist(HashSet<[u8;32]>)` built from the `--enc-authorized-peers`
file (one client pubkey per line, 64-hex or 43-char url-safe base64;
`#` comments and blank lines ignored). The bare `serve_tcp` retains
`AllowAny` for the direct e2e harness only. The allowlist bouncer
rejects any unlisted dialer at the handshake — a rejected peer never
receives a `HelloResponse`, list-refs, packs, or update-ref.

The server identity is a **stable** raw-32 key loaded/auto-created from
`--enc-server-key <PATH>` (or a user-scoped default
`~/.config/mkit/enc/server.key`) so the advertised `?pubkey=` is stable
across restarts; only the unsafe allow-any mode keeps an ephemeral
per-process key. A client can similarly pin its identity via the
`MKIT_ENC_CLIENT_KEY` environment variable (a user-scoped or
CLI-supplied raw-32 key file) so an allowlisting server can pin the
client across restarts; when unset, the client derives an ephemeral
per-process key, which only an `--unsafe-allow-any-enc-peer` server
will accept. Peer-authorization and identity key paths are CLI-supplied
or user-scoped and are **never** read from repo-local `.mkit/config`.

`connect_tcp` lazily bootstraps a `commonware_runtime::BufferPool` by
spinning up a one-shot commonware tokio Runner on a fresh OS thread,
then dropping the bootstrap runtime while holding an `Arc` clone of the
pool; the pool is cached process-wide. This exists because
`commonware-runtime` does not currently expose a public
`BufferPool::new_for_network()` constructor.

### 6.2 Known limitations

Server and client identities are stable raw-32 key files on disk
(`--enc-server-key` / `MKIT_ENC_CLIENT_KEY`), not yet routed through
`mkit-keystore` the way SSH host keys and signing keys are; keystore
integration would also let the public `connect_tcp` signature take a
keystore-backed key type instead of a raw one. The allowlist is a flat
`--enc-authorized-peers` file, not a keystore partition.

---

## 7. Versioning

Application protocol version is the same as the rest of mkit
(`PROTOCOL_VERSION_1`). The cryptographic-namespace prefix
(`mkit/transport-enc/v1`) is bumped independently if the handshake or
record layer needs a hard break that the application-level
`HelloResponse` mismatch can't catch.

---

## 8. Invariants

| Invariant | Enforced by |
|---|---|
| The peer is the key the URL advertises, or no session exists | `?pubkey=` carried out-of-band in the URL; mismatch → `EncInitError::PeerRejected`; no TOFU cache, no CA fallback (§1) |
| Two distinct URL strings cannot decode to the same pubkey | hex (exactly 64 chars) or unpadded b64url (43 chars, trailing 2 bits zero) — ambiguous encodings rejected at parse (§1) |
| Mutual authentication and forward secrecy | static-key signatures over the handshake transcript; ephemeral X25519 (§2.3) |
| No nonce reuse, no cross-session replay | per-record counter nonces never on the wire; `SynAck` transcript-bound to `Syn` (§2.3) |
| No cross-application replay of handshakes | `namespace = b"mkit/transport-enc/v1"` transcript binding (§2.1) |
| No frame exceeds 1 MiB — enforced twice | `max_message_size = mkit_rpc::MAX_FRAME_BYTES` at the record layer (§2.1) and by every existing `SshFrame` consumer (§3.1) |
| One `SshFrame` per encrypted record, no framing ambiguity | single protobuf payload per `Sender::send`; no second length prefix (§3.1) |
| No verb exchanged before version agreement | post-handshake `Hello`/`HelloResponse` with `PROTOCOL_VERSION_1`; disagreement closes the connection (§3.2) |
| The listener is fail-closed: an unlisted peer gets nothing | binding requires `--enc-authorized-peers` (or the loud `--unsafe-allow-any-enc-peer` escape); rejected peers never receive a `HelloResponse`, refs, or packs (§6.1) |
| Verb semantics never diverge from the SSH transport | same `SshFrame` message set; semantics byte-for-byte per SPEC-TRANSPORT §4 (§3) |
| Application plaintext never appears on the wire | pinned by the byte-sniffing round-trip tests (§5) |

Explicitly **not** guaranteed, inherited from the stream layer:
anonymity (peer identities exchanged in cleartext) and length padding
(message sizes leak) (§2.3).
