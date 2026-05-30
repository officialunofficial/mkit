---
spec: SPEC-EXTERNAL-SIGNER
version: 1
status: draft
audience: integrators shipping a signer for a platform mkit does not ship natively (HSM, Secure Enclave, TPM, WebAuthn, KMS)
---

# SPEC-EXTERNAL-SIGNER — mkit external signer protocol v1

The wire contract between the mkit host process and a user-supplied
external signer binary. Implementations that follow this spec are
drop-in compatible with the `external` signer selector referenced in
[`SPEC-ATTESTATIONS.md`](SPEC-ATTESTATIONS.md) §6.2.

Audience: integrators shipping a signer for a platform mkit does not
ship natively — Apple Secure Enclave, Ledger / Trezor, WebAuthn/CTAP,
MetaMask / EVM wallet bridges, Makechain, HSMs, etc.

The wire format itself is defined in [`SPEC-RPC`](SPEC-RPC.md). This
document covers the signer-specific aspects: process invocation,
conversation flow, capability advertisement, and reference signer
behaviours.

---

## 1. Scope

mkit asks an external binary to produce a DSSE signature over a
specific blob (the PAE) under a specific algorithm, and the binary
returns the signature plus a key identifier.

In scope:

- Process invocation, I/O framing, lifetimes, exit-code semantics.
- The `signer.proto` request / response shapes.
- Capability discovery via `Capabilities`.
- PIN / authentication round-trips.
- Error surface, size limits, determinism expectations.

Out of scope:

- Key generation or import. The signer is assumed to already possess
  or have access to the secret. Reference signers that *do* offer
  enrolment (`mkit-sign-ctap enroll`, `mkit-sign-tpm keygen`) expose
  it as a separate CLI subcommand outside the protocol.
- The DSSE / in-toto envelope structure ([SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md)).
- Trust-roots configuration ([SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md) §7).

---

## 2. Process invocation

mkit invokes the configured signer binary as a subprocess. The
binary's path is resolved at config time and MUST be absolute; mkit
refuses relative paths to close the `$PATH` resolution race.

```
$ /absolute/path/to/signer [argv...]
```

Optional argv tokens come from `attest.external_signer_args` in the
user-scoped config, passed verbatim with no shell interpolation. mkit
does NOT pass:

- Any shell metacharacters.
- The PAE on argv (it goes through stdin).
- The algorithm on argv (it goes inside `SignRequest`).
- Any environment variables it didn't already inherit.

The signer's stdin and stdout are pipes; stderr is inherited and is
free-form for human-readable diagnostics.

---

## 3. Wire framing

Length-prefixed protobuf-encoded `SignerFrame` messages on stdin
(mkit → signer) and stdout (signer → mkit). The Rust reference
signers use the `buffa` runtime; any protobuf 3 / edition 2023
toolchain emitting the same wire bytes is conformant. See
[SPEC-RPC §1](SPEC-RPC.md#1-wire-framing) for the 4-byte LE length
prefix, endianness, and the `MAX_FRAME_BYTES = 1 MiB` cap (frames
exceeding the cap are a connection-fatal error).

Schema: [`rust/crates/mkit-rpc/proto/signer.proto`](../rust/crates/mkit-rpc/proto/signer.proto).

---

## 4. Conversation flow

```
mkit -> signer:    Hello { protocol = PROTOCOL_VERSION_1,
                            caller_id, want_capabilities }
signer -> mkit:    HelloResponse { protocol, signer_id, capabilities }
mkit -> signer:    SignRequest { algorithm, key_form, key_ref, payload, context }
signer -> mkit:    SignResponse { signature, public_key, algorithm, key_id, ... }
                     OR
                   Error { code, message, details }
```

Optional PIN round-trip mid-sign:

```
signer -> mkit:    PinPrompt { reason, retries_remaining, wants_pin }
mkit   -> signer:  PinResponse { pin }
signer -> mkit:    SignResponse OR Error
```

mkit MAY send multiple `SignRequest`s on a single connection; the
file signer's reference implementation explicitly supports it. The
signer MUST process them in order.

---

## 5. Capability advertisement

`Capabilities` in `HelloResponse` advertises what the signer can do:

| Field | Meaning |
|---|---|
| `algorithms[]` | Algorithms the signer can produce signatures with. |
| `key_forms[]` | Key forms the signer accepts. |
| `supports_pin` | True if the signer supports a PIN round-trip. |
| `supports_certificate_chain` | True if `SignResponse.certificate_chain` is populated. |
| `max_payload_bytes` | Per-request payload cap. `0` = "use the framing default" (1 MiB). |
| `requires_user_presence` | True if a touch/PIN/biometric is required. Advisory; mkit-cli MAY surface a "touch your YubiKey" hint. |

mkit MUST verify the requested algorithm + key form against
advertised capabilities before sending a `SignRequest`.

---

## 6. SignRequest / SignResponse semantics

| `SignRequest` field | Meaning |
|---|---|
| `algorithm` | The algorithm to sign under. MUST be one the signer advertised. |
| `key_form` | The form the key is provided in. |
| `key_ref` | Identifies which key. Empty for raw-bytes signers (key path is configured at signer startup). For opaque-handle signers (CTAP credentialId, TPM 4-byte BE persistent handle): the wire value is preferred, but signers MAY fall back to a per-process default supplied on argv (`mkit-sign-tpm --handle 0x81010001`, `mkit-sign-ctap --credential-id <b64url>`) when `key_ref` is empty. An ill-formed `key_ref` (wrong length, undecodable) MUST be rejected with `ERROR_CODE_INVALID_REQUEST` rather than silently falling through to the argv default. |
| `payload` | Raw bytes to sign. For DSSE, this is the PAE per [SPEC-ATTESTATIONS](SPEC-ATTESTATIONS.md) §4. |
| `context` | Optional context. CTAP signers ignore the wire field today and build the WebAuthn `clientDataJSON` themselves from the payload and configured origin; this field is reserved for a future signer that needs caller-supplied context. |

| `SignResponse` field | Meaning |
|---|---|
| `signature` | Compact signature. 64 bytes for Ed25519 / k256 / p256. |
| `public_key` | Public key bytes. 32 for Ed25519, 33 SEC1-compressed (or 65 uncompressed) for k256/p256. REQUIRED, except that the CTAP signer MAY return an empty `public_key` if it has no record of the credential in its local store (the verifier then has to recover the key from a separate trust root). |
| `algorithm` | Echoes the algorithm used. |
| `key_id` | DSSE `signatures[].keyid`. Conventions used by the reference signers: `blake3:<hex>` for Ed25519 (BLAKE3-256 over the raw 32-byte public key), `secp256k1:<hex(compressed-pubkey)>`, `p256:<hex(compressed-pubkey)>`, `webauthn:<base64url-cred-id>`. Other schemes are tolerated; mkit treats `key_id` as opaque. |
| `certificate_chain[]` | DER-encoded X.509 chain when applicable. Empty for raw-key signers and for both reference hardware signers today (no signer ships an attestation chain in v1). |
| `webauthn` | `{ authenticator_data, client_data_json }` for CTAP signers — required when `algorithm = ALGORITHM_ED25519_WEBAUTHN` or when the signer is FIDO2-flavoured P-256, so the verifier can reconstruct `authenticator_data ‖ SHA-256(client_data_json)` and check `signature` against that. Unset for non-WebAuthn signers. |

Callers MUST treat `SignResponse` as untrusted. For non-WebAuthn
responses, mkit rejects the response unless `algorithm` echoes the
requested algorithm, `public_key` is present, and `signature` verifies
against `public_key` and the requested `payload`. If `key_id` uses one
of the reference canonical prefixes (`blake3:`, `ed25519:`,
`secp256k1:`, `p256:`), mkit recomputes the expected identifier from
`public_key` and rejects mismatches. Unknown `key_id` prefixes remain
opaque and are accepted so third-party signer namespaces keep working.
WebAuthn responses are validated by the WebAuthn verifier using the
`webauthn` extension rather than this raw-payload check.

---

## 7. Errors

Per-request errors are returned as `Error` frames; the signer keeps
running. Setup-phase failures (no key configured, bad permissions on
the key file, missing argv flag) exit non-zero with a stderr message,
and the signer MUST NOT emit any frame on stdout in that case — a
half-formed response would desync the caller's reader.

Error code semantics: see [SPEC-RPC §3.3](SPEC-RPC.md#33-errorcode).

---

## 8. Reference signers

Four reference signers ship in `contrib/signers/` and exercise the
full v1 wire surface: three in Rust (`mkit-sign-file`, `mkit-sign-tpm`,
`mkit-sign-ctap`) and one in Swift (`mkit-sign-se`, using
`swift-protobuf`). All loop on stdin, processing successive
`Hello` / `SignRequest` pairs until the caller closes the stream; a
clean EOF on the length prefix is treated as a graceful shutdown.

### 8.1 mkit-sign-file

Raw-bytes signer. Reads a 32-byte seed/scalar from disk. Unix
permission bits MUST be `0600`; otherwise the binary refuses to start.

```
$ mkit-sign-file --key /home/alice/.mkit/keys/default.key
```

```
algorithms = [ED25519, SECP256K1, P256]
key_forms  = [RAW_BYTES]
supports_pin = false
supports_certificate_chain = false
requires_user_presence = false
```

Reference / development implementation. Not production-grade — the
secret is unencrypted on disk.

### 8.2 mkit-sign-ctap

FIDO2 / WebAuthn signer. Drives a plugged-in roaming authenticator
(YubiKey, Nitrokey, SoloKey, …) over CTAP-HID.

```
$ mkit-sign-ctap enroll --rp-id mkit.local --user-name alice
$ mkit-sign-ctap sign  --credential-id <base64url> [--pin <pin>]
```

```
algorithms = [P256, ED25519_WEBAUTHN]
key_forms  = [OPAQUE_HANDLE]            # the credential_id
supports_pin = true
supports_certificate_chain = false
requires_user_presence = true
```

`SignResponse.webauthn` is populated with `authenticator_data` +
`client_data_json` so the verifier reconstructs the signed input.

### 8.3 mkit-sign-tpm

TPM 2.0 P-256 signer. Linux-native via `tss-esapi` (gated behind the
`tpm2` Cargo feature).

```
$ mkit-sign-tpm keygen --handle 0x81010001
$ mkit-sign-tpm sign   --handle 0x81010001
```

```
algorithms = [P256]
key_forms  = [OPAQUE_HANDLE]            # 4-byte BE persistent handle
supports_pin = false
supports_certificate_chain = false
requires_user_presence = false
```

`SignRequest.key_ref` is the persistent handle as a 4-byte big-endian
u32; bare-argv `--handle` populates a per-process default that the
signer uses when `key_ref` is empty.

---

## 9. Determinism

The signer MUST be deterministic for a fixed `(payload, key)` under
ECDSA-SHA-256 (RFC 6979) and Ed25519 (RFC 8032). Test fixtures pin
specific signature bytes against fixed scalars; non-deterministic
signatures break golden-vector tests.

WebAuthn signatures are NOT deterministic (`authenticatorData`
includes a sign counter). Verifiers reconstruct via
`authenticator_data || SHA-256(client_data_json)`; the counter does
not leak through to the protocol layer.

---

## 10. Security model

The signer process is in mkit's TCB. mkit does NOT verify what the
signer signed beyond requiring that the returned `signature`
verifies against the returned `public_key` over the requested
`payload`. A compromised signer can:

- Sign arbitrary blobs of mkit's choosing.
- Lie about which `key_id` produced the signature, leading the
  verifier to attribute the signature to a different key.
- Fail closed (error frames) but not fail open.

Mitigations the host SHOULD take:

- Require absolute paths for the signer binary (mkit enforces).
- Verify the signer binary's checksum out-of-band.
- Run the signer under a restricted user / sandbox (systemd
  `DynamicUser=`, macOS `sandbox-exec`, …).

---

## 11. Versioning

This document and `signer.proto` are jointly v1. Wire-compatible
additions land in v0.1.x patch releases. Breaking changes bump to v2
with a sibling `signer2.proto`. See [SPEC-RPC §2](SPEC-RPC.md#2-versioning).
