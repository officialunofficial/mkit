---
spec: SPEC-RPC
version: 1
status: draft
audience: integrators implementing an mkit external signer or mkit-server
---

# SPEC-RPC — mkit cross-system wire protocol v1

mkit speaks to processes outside its address space — external signers
running as subprocesses, and remote `mkit-server` instances reached
over `ssh(1)` — using a single shared wire protocol.

The schemas live in [`rust/crates/mkit-rpc/proto/`](../rust/crates/mkit-rpc/proto/):

| File | Purpose |
|---|---|
| `common.proto` | Shared types: `Algorithm`, `KeyForm`, `ErrorCode`, `Error`, `ProtocolVersion` |
| `signer.proto` | External-signer protocol (`SignerFrame` oneof). See [SPEC-EXTERNAL-SIGNER](SPEC-EXTERNAL-SIGNER.md) for prose. |
| `ssh.proto` | SSH transport protocol (`SshFrame` oneof). See [SPEC-TRANSPORT](SPEC-TRANSPORT.md) for prose. |

Protocol-version integer is `1` (`PROTOCOL_VERSION_1`). All v0.1.x mkit
releases speak this and only this. A future breaking revision will
introduce sibling `signer2.proto` / `ssh2.proto` with
`PROTOCOL_VERSION_2`; v1 is frozen.

---

## 1. Wire framing

Both protocols use the same length-prefixed framing:

```
+------------------+------------------------------------+
| u32 LE length    | N bytes protobuf-encoded Frame     |
+------------------+------------------------------------+
```

- **Length prefix**: 4 bytes, little-endian unsigned integer, encoded
  length of the protobuf body in bytes — does NOT include the prefix
  itself.
- **Body**: a single protobuf-encoded `SignerFrame` (signer protocol)
  or `SshFrame` (SSH protocol), per the `oneof body { ... }`
  definitions in the .proto files. The Rust reference implementations
  use the `buffa` runtime, but any protobuf 3 / edition 2023 toolchain
  emitting the same wire bytes is conformant.
- **Cap**: `MAX_FRAME_BYTES = 1 MiB` (`1024 * 1024`, exported from
  `mkit-rpc` as a constant of the same name). Receivers MUST close
  the connection on a frame whose advertised length exceeds the cap,
  before reading the body. Senders MUST refuse to emit a frame whose
  body would exceed the cap. Bulk data flows that need more than
  1 MiB use a streaming pattern (see `PackChunk` in `ssh.proto`).

Receivers MUST validate the length prefix against the cap before
allocating buffers — there is no streaming decode of a single frame.

A truncated length prefix or body is a connection-fatal protocol
error. There is no recovery; the receiving side MUST close the
underlying stream.

---

## 2. Versioning

The single `ProtocolVersion` enum in `common.proto` carries the wire
contract version. Every initiating frame (`SignerFrame::Hello`,
`SshFrame::Hello`) MUST set `protocol = PROTOCOL_VERSION_1`.

Wire-compatible additions to the v1 schemas are allowed in v0.1.x
patch releases:

- New enum values for `Algorithm`, `KeyForm`, `ErrorCode` (existing
  consumers see them as unknown variants and fall back to
  `ERROR_CODE_UNSPECIFIED` / a no-op).
- New optional fields on existing messages (Edition 2023 default
  semantics).
- New oneof variants on `SignerFrame::body` and `SshFrame::body`
  (existing consumers reject them with `ERROR_CODE_INVALID_REQUEST`).

Renumbering or removing a field is a wire break. Do that by
introducing a sibling `*2.proto` with a new package and bumping
`ProtocolVersion`.

---

## 3. Common types

### 3.1 `Algorithm`

Wire-load-bearing integers; do NOT renumber. New algorithms append at
the next available number.

| Name | Wire | Notes |
|---|---|---|
| `ALGORITHM_UNSPECIFIED` | 0 | Treated as "request invalid". |
| `ALGORITHM_ED25519` | 1 | RFC 8032 raw signing. Default for commit/ref. |
| `ALGORITHM_SECP256K1` | 2 | ECDSA over SHA-256. DSSE-compatible. |
| `ALGORITHM_P256` | 3 | ECDSA P-256 / secp256r1 / prime256v1 over SHA-256. |
| `ALGORITHM_ED25519_WEBAUTHN` | 4 | Ed25519 wrapped in a WebAuthn assertion (CTAP signers). |
| `ALGORITHM_BLS12381_THRESHOLD` | 5 | BLS12-381 threshold signature (variant `MinSig`); see `docs/SPEC-RELEASE-THRESHOLD.md`. |

### 3.2 `KeyForm`

| Name | Wire | Used by |
|---|---|---|
| `KEY_FORM_UNSPECIFIED` | 0 | — |
| `KEY_FORM_RAW_BYTES` | 1 | `mkit-sign-file` (32-byte seed/scalar on disk). |
| `KEY_FORM_PKCS8_DER` | 2 | Reserved; no signer ships with v0.1.0. |
| `KEY_FORM_OPAQUE_HANDLE` | 3 | `mkit-sign-tpm`, `mkit-sign-ctap`. The bytes in `key_ref` are interpreted by the signer (TPM persistent handle, CTAP credentialId, …). |

### 3.3 `ErrorCode`

| Name | Wire | Meaning |
|---|---|---|
| `ERROR_CODE_UNSPECIFIED` | 0 | Default/unset. Receivers MUST treat this as a protocol error (every `Error` frame MUST carry a known non-zero code). |
| `ERROR_CODE_INVALID_REQUEST` | 1 | Structurally bad request. Connection MAY continue. |
| `ERROR_CODE_UNSUPPORTED_ALGORITHM` | 2 | Signer doesn't speak the algorithm. |
| `ERROR_CODE_UNSUPPORTED_KEY_FORM` | 3 | Signer doesn't accept the key form. |
| `ERROR_CODE_KEY_NOT_FOUND` | 4 | Named key (handle / path) was absent. |
| `ERROR_CODE_USER_DECLINED` | 5 | User cancelled (touched cancel on hardware key, refused TPM auth). |
| `ERROR_CODE_AUTHENTICATION_REQUIRED` | 6 | Signer needs PIN / biometric — see `PinPrompt`. |
| `ERROR_CODE_HARDWARE_ERROR` | 7 | Vendor-specific hardware fault; `details` carries the raw code. |
| `ERROR_CODE_TIMEOUT` | 8 | User presence check timed out. |
| `ERROR_CODE_INTERNAL` | 99 | Unmapped — `message` MUST be set. |

`Error.message` is human-readable English, suitable for direct UI
display. Producers SHOULD keep it under 1 KiB so receivers can render
it inline; the framing layer does NOT enforce a per-field cap, only
the `MAX_FRAME_BYTES = 1 MiB` whole-frame ceiling from §1.
`Error.details` is opaque vendor-specific bytes (CTAP CBOR status,
TPM `TPM_RC`, PKCS#11 `CKR_*`, etc.); programs MUST NOT pattern-match
on its contents.

---

## 4. Conformance

A signer or server is mkit-rpc-compliant if and only if:

1. It speaks length-prefixed protobuf frames as in §1.
2. The first frame it sends or expects is `Hello` with
   `protocol = PROTOCOL_VERSION_1`.
3. It returns a `HelloResponse` with the same `protocol` value before
   processing any other request.
4. Every error response is an `Error` frame with a known non-zero
   `ErrorCode` and a non-empty `message`.
5. It enforces `MAX_FRAME_BYTES` on receive AND on send.

Reference implementations (all in this repository):

- [`contrib/signers/mkit-sign-file/`](../contrib/signers/mkit-sign-file/) —
  `KEY_FORM_RAW_BYTES`, Ed25519 / secp256k1 / P-256.
- [`contrib/signers/mkit-sign-ctap/`](../contrib/signers/mkit-sign-ctap/) —
  FIDO2/WebAuthn signer, P-256 / Ed25519-WebAuthn.
- [`contrib/signers/mkit-sign-tpm/`](../contrib/signers/mkit-sign-tpm/) —
  TPM 2.0 P-256 signer.
- [`rust/crates/mkit-cli/src/commands/serve.rs`](../rust/crates/mkit-cli/src/commands/serve.rs) —
  `mkit serve` SSH server (consumes `ssh.proto`).

The Swift `contrib/signers/mkit-sign-se/` (Apple Secure Enclave)
binary is a conforming v1 reference signer: it speaks the
length-prefixed protobuf wire (its `Package.swift` depends on
swift-protobuf, with generated `common.pb.swift` / `signer.pb.swift`),
and is listed alongside the other reference signers in
[`SPEC-EXTERNAL-SIGNER`](SPEC-EXTERNAL-SIGNER.md) §8. It wires through
the `external` signer selector like any other mkit-rpc signer.

---

## 5. Why protobuf, not JSON

mkit-rpc replaces an earlier line-JSON external-signer protocol and a
hand-rolled OP_HELLO byte format on the SSH transport. The protobuf
choice is deliberate:

- **Forward-compatible by default.** Edition 2023 fields are
  explicit-presence; adding optional fields or oneof variants is a
  wire-compatible patch-level change.
- **Cross-language.** mkit ships in Rust, but external signers may
  ship in any language with a protobuf 3 / edition 2023
  implementation. JSON parsing edge cases (number precision, escape
  handling, key ordering) are not in the contract.
- **Bounded sizes by construction.** Length-prefixed framing with a
  hard cap is simpler to reason about than JSON-line streams that
  may need arbitrary lookahead for `}` matching.
- **Schema-as-source-of-truth.** The .proto files are the contract;
  prose specs (this file, SPEC-EXTERNAL-SIGNER, SPEC-TRANSPORT) are
  derivative.

The buffa runtime (`buffa = "0.7"`) is used by the Rust reference
implementations. Other languages can use any compliant protobuf 3 /
edition 2023 toolchain.
