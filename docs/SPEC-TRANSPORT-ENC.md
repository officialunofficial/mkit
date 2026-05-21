---
spec: SPEC-TRANSPORT-ENC
version: 0 (draft, Phase 1)
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

This is the Phase 1 scaffold spec. The CLI plumbing (`mkit+enc://` URL
parsing, `remote_dispatch::open` switch, cargo feature gating) lands in
Phase 2 — see §6 for the punch list.

---

## 1. URL scheme

| Scheme prefix | Transport | Notes |
|---|---|---|
| `mkit+enc://[user@]host[:port]/path?pubkey=<base64>` | `mkit-transport-enc` | Phase 2. Phase 1 constructs the transport in-process from a `(host, port, server_pubkey)` triple — see §6. |

The Phase 2 URL form carries the **server's static `ed25519` public
key** as a query-parameter `pubkey=<base64>` (or `pubkey=<hex>`; final
encoding lands in §6 alongside the parser). Trust is established by
out-of-band knowledge of this key — there is no fall-back to a
TOFU-style first-use cache, and no CA chain. If the server's actual
key during handshake differs from the URL-advertised key, the dialer
aborts with `EncInitError::PeerRejected`.

---

## 2. Cryptographic layer

The encrypted layer is provided verbatim by
[`commonware_stream::encrypted`] (version `2026.4.0` pinned in
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
| Max ref name / prefix | 4096 bytes | `MAX_REF_NAME` in `mkit-transport-enc/src/lib.rs` |
| Per-chunk pack data | 800 KiB | `CHUNK_DATA_MAX`; same as `mkit-transport-ssh` |
| Pack body total | `mkit_core::protocol::PACK_BODY_LIMIT` | Shared client cap |

---

## 5. Test plan (Phase 1)

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
| `connect_tcp_is_unimplemented_in_phase_1` | The Phase 2 TCP entry point returns `EncInitError::Unimplemented`. Locks the symbol shape so Phase 2 CLI code can bind against it. |

---

## 6. Phase 2 punch list

Items intentionally out of scope for Phase 1, listed here so the next
PR can grab them as a single batch:

1. **URL parsing** — accept `mkit+enc://[user@]host[:port]/path?pubkey=<…>`
   in a `mkit-transport-enc::url` module mirroring
   `mkit-transport-ssh::url`. Decide pubkey encoding (base64 vs hex)
   and document under §1.
2. **TCP transport** — wire `commonware-runtime::tokio` Sink/Stream to
   a real TCP socket; flesh out `connect_tcp`.
3. **CLI dispatch** — extend
   [`remote_dispatch::open`](../rust/crates/mkit-cli/src/remote_dispatch.rs)
   to recognise the `mkit+enc://` scheme. Gate the dependency behind
   a `mkit-cli/enc-transport` cargo feature so users who only need
   `mkit+ssh://` don't pay the commonware compile-time cost.
4. **Server binary** — analog of `mkit serve` for the encrypted path.
   Likely a flag on `mkit serve` (`--listen-enc <addr>`) rather than
   a separate binary.
5. **Keystore integration** — clients today carry their static signing
   key as a raw `PrivateKey`. Phase 2 wires it through `mkit-keystore`
   so the key is stored at rest the same way SSH keys and signing
   keys are.
6. **Tighten handshake bounds** — drop `synchrony_bound` / `max_handshake_age`
   to ≤ 5 s, `handshake_timeout` to ≤ 10 s. Defer until Phase 2 because
   the tighter bounds depend on real-network testing rather than the
   deterministic-runtime tests Phase 1 runs.
7. **`publish = true`** — flip the `mkit-transport-enc` `Cargo.toml`
   flag so the crate ships to crates.io alongside the other
   transports. Requires keystore integration (#5) to land first so the
   public API isn't a moving target.

---

## 7. Versioning

Application protocol version is the same as the rest of mkit
(`PROTOCOL_VERSION_1`). The cryptographic-namespace prefix
(`mkit/transport-enc/v1`) is bumped independently if the handshake or
record layer needs a hard break that the application-level
`HelloResponse` mismatch can't catch.
