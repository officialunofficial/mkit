# mkit-sign-se — Apple Secure Enclave signer for mkit

`mkit-sign-se` is a Swift binary that implements the mkit external
signer v1 wire protocol ([`docs/SPEC-EXTERNAL-SIGNER.md`](../../../docs/SPEC-EXTERNAL-SIGNER.md))
backed by Apple's Secure Enclave.

Headline properties:

- **P-256 only.** The Secure Enclave supports no other algorithm. Any
  `SignRequest` with a non-P-256 `algorithm` is answered with an
  `Error` frame carrying `ERROR_CODE_UNSUPPORTED_ALGORITHM` — this
  signer **will not** fall back to a software key.
- **Non-extractable private key.** `SecureEnclave.P256.Signing.PrivateKey`
  generates and holds the scalar inside the Secure Enclave processor;
  the blob we persist to the keychain is an encrypted handle that only
  the SEP on the same physical device can reconstitute.
- **Optional biometric gating.** `--require-biometric` on `keygen`
  binds the key to `.biometryCurrentSet`, so every sign prompts for
  Touch ID / Face ID (and the key becomes unusable if the user enrolls
  a new fingerprint / face). When the user cancels the prompt the
  signer returns `ERROR_CODE_USER_DECLINED`.

---

## Wire protocol

`mkit-sign-se sign` speaks the v1 wire — length-prefixed protobuf
`SignerFrame` messages on stdin/stdout. This is the same protocol
all other mkit reference signers (`mkit-sign-file`, `mkit-sign-tpm`,
`mkit-sign-ctap`) speak; the schema is shared
([`signer.proto`](../../../rust/crates/mkit-rpc/proto/signer.proto)
plus [`common.proto`](../../../rust/crates/mkit-rpc/proto/common.proto)).

The Swift implementation links the canonical Apple-platform protobuf
runtime — [SwiftProtobuf](https://github.com/apple/swift-protobuf),
pinned to `1.30.0+` in `Package.swift`. Pre-generated `.pb.swift`
sources are checked into `Sources/mkit-sign-se/Generated/` to avoid
build-time codegen (SwiftPM has no clean equivalent of `build.rs`).
To regenerate after a `.proto` change:

```console
$ brew install swift-protobuf   # provides `protoc-gen-swift`
$ protoc --swift_out=contrib/signers/mkit-sign-se/Sources/mkit-sign-se/Generated \
         --proto_path=rust/crates/mkit-rpc/proto \
         rust/crates/mkit-rpc/proto/common.proto \
         rust/crates/mkit-rpc/proto/signer.proto
```

### Capabilities

```
algorithms = [P256]
key_forms  = [OPAQUE_HANDLE]   # UTF-8 bytes of the keychain tag
supports_pin = false
supports_certificate_chain = false
requires_user_presence = true   # advisory — biometric or keychain prompt
```

### Resolving the key

The Secure Enclave key to sign with is selected by **tag** — the same
label `keygen` stored under `kSecAttrAccount`. The tag can be supplied
two ways:

- `--tag <label>` on argv (per-process default).
- `SignRequest.key_ref` over the wire, interpreted as the UTF-8 bytes
  of the tag (`KEY_FORM_OPAQUE_HANDLE` per `signer.proto`).

When both are set, the wire value wins. If neither is set the signer
answers with `ERROR_CODE_INVALID_REQUEST`.

---

## Requirements

- macOS 12 (Monterey) or later.
- Apple Silicon, or an Intel Mac with a T2 security chip. (Check with
  `swift -e 'import CryptoKit; print(SecureEnclave.isAvailable)'`.)
- Swift 5.9+ toolchain — shipping Xcode 14+ or the standalone
  Command Line Tools is enough.
- For the e2e test: `openssl` and `python3` (both ship with macOS).
- SwiftProtobuf 1.30+ is fetched automatically by SwiftPM on first
  build; no manual setup needed.

## Build

```console
$ swift build -c release
$ ls .build/release/mkit-sign-se
.build/release/mkit-sign-se
```

Or via the Makefile:

```console
$ make build
```

## Install

```console
$ make install                      # copies to /usr/local/bin
$ make install PREFIX=$HOME/.local  # installs under ~/.local/bin
```

The expected production install path is `/usr/local/bin/mkit-sign-se`;
that is the path mkit's `attest.external_signer_path` config key
should point at.

---

## Usage

Subcommands:

```
mkit-sign-se keygen --tag <label> [--require-biometric]
mkit-sign-se sign   [--tag <label>]
mkit-sign-se list
mkit-sign-se delete --tag <label>
```

### `keygen`

Mints a new SEP-backed P-256 key and stores it in the login keychain
under `<label>`. Prints the `p256:<66-hex>` keyid to stdout so you can
register it with an mkit trust-root registry.

```console
$ mkit-sign-se keygen --tag my-attest-key
p256:033783333f45f68642c2df4d023a5e027ed0bf68f6ddd01506cdfe5b007456ca87
```

Add `--require-biometric` to gate signing on Touch ID / Face ID.

### `sign`

Implements the v1 external-signer wire protocol. Reads framed
`SignerFrame` messages from stdin and writes framed responses to
stdout:

```
mkit -> signer:    SignerFrame{ Hello { protocol_version = V1, ... } }
signer -> mkit:    SignerFrame{ HelloResponse { capabilities... } }
mkit -> signer:    SignerFrame{ SignRequest { algorithm = P256, ... } }
signer -> mkit:    SignerFrame{ SignResponse { signature, public_key, key_id, ... } }
```

Each frame is a 4-byte little-endian u32 length prefix followed by the
protobuf body, capped at 1 MiB matching `MAX_FRAME_BYTES` in
`rust/crates/mkit-rpc/src/framing.rs`. The signer loops on stdin and
processes successive `Hello` + `SignRequest` pairs until the caller
closes the stream — a clean EOF on the length prefix is treated as a
graceful shutdown.

Per-request errors (no key with that tag, biometric declined,
unsupported algorithm) come back as `Error` frames; the binary keeps
running. Setup-phase failures (no Secure Enclave on the host, bad
argv) exit non-zero with a message on stderr and no frame on stdout.

### `list`

Prints `<tag>\t<compressed-pubkey-hex>` for each key this binary owns.
Useful after a `keygen` to sanity-check persistence, or on a clean
machine to confirm nothing is stored yet.

### `delete`

Removes a key by tag. Idempotent is NOT the contract: deleting an
unknown tag exits non-zero with a `tagNotFound` message.

---

## Wiring mkit to use it

`.mkit/config`:

```toml
[attest]
signer = "external"
external_signer_path = "/usr/local/bin/mkit-sign-se"
external_signer_args = "sign|--tag|my-attest-key"
```

The pipe (`|`) is used in the args string because commas are reserved
for `--additional-signer` multi-sig specs. mkit splits on `|` and
passes each piece as a separate argv element, so the signer is
launched as `mkit-sign-se sign --tag my-attest-key`.

### `mkit keygen` does NOT produce an SEP-backed key

`mkit keygen --algorithm p256` writes a raw-key file to
`.mkit/signing.key` — a *different* flow. For the SEP workflow:

1. Run `mkit-sign-se keygen --tag my-attest-key` to mint the SEP key.
2. Note the printed `p256:<hex>` keyid.
3. Add that keyid to your verifier's trust-root registry.
4. Configure mkit with the `external_signer_*` block above.

---

## Security notes

- **Non-extractable secret.** The private scalar is generated inside
  the SEP and never leaves it. A full disk snapshot — or even a
  compromised kernel — cannot exfiltrate the key material; they can
  only ask the SEP to sign, subject to whatever access control was
  set at creation.
- **Biometric-gated signing.** With `--require-biometric`, signing
  prompts for Touch ID / Face ID. Cancelling the prompt surfaces as
  an `ERROR_CODE_USER_DECLINED` frame.
- **Device loss = key loss.** SEP keys are bound to the physical SEP
  silicon. They are **not** synced via iCloud Keychain. A lost /
  wiped / reset device loses the key irrecoverably — you cannot back
  it up. **Export and record the public key (the `p256:<hex>`
  keyid) before you rely on the signer in production**, and plan a
  key-rotation policy against device loss.
- **One binary, one keychain.** All keys this binary creates live
  under `kSecAttrService = dev.mkit.mkit-sign-se`; `list` shows only
  those. Deleting a key is reversible only if you kept the old
  `dataRepresentation` blob (we don't; we delete the keychain item
  wholesale).
- **Installation path.** Treat `attest.external_signer_path` as a
  code-execution sink (same class as `git config core.editor`). For
  any deployment where the local user account is less trusted than
  the user who configured mkit, install the binary on a root-owned,
  non-user-writable path (e.g. `/usr/local/bin/`).

---

## Troubleshooting

### "Secure Enclave not available on this device"

You are on an Intel Mac without a T2, or inside a sandboxed /
container environment where `SecureEnclave.isAvailable` returns
false. This signer refuses to fall back to a software key by design
— use `mkit-sign-file` (the reference signer) for dev / CI, and the
Apple signer only on hardware that has a real SEP.

### "keychain error: -25308 (User interaction is not allowed.)"

The keychain is locked and the binary is running under a non-GUI
session (e.g. SSH, LaunchDaemon, cron). Unlock your keychain, or
mark the item as "always allow" the first time you use it
interactively, or re-run under the same user session that created
the key.

### "keychain error: -25300 (The specified item could not be found.)"

The tag you passed to `sign` / `delete` doesn't exist. Run
`mkit-sign-se list` to see what's there, or `mkit-sign-se keygen
--tag <label>` to create it.

### Got an `ERROR_CODE_USER_DECLINED` from `sign`

You pressed Cancel on the Touch ID / Face ID dialog, let it time
out, or enrolled a new biometric after creating a
`--require-biometric` key (that invalidates the key per
`.biometryCurrentSet`). Re-create the key with a fresh `keygen`.

### Code-signing for distribution

For Gatekeeper-approved distribution of this binary you'll need a
Developer ID signature + notarisation. Neither is needed for local
development; `swift build -c release` produces a binary the running
user can execute directly. For a signed build:

```console
$ codesign --force --options runtime --sign "Developer ID Application: …" \
    .build/release/mkit-sign-se
$ xcrun notarytool submit .build/release/mkit-sign-se --wait …
```

---

## Testing

```console
$ swift test           # unit tests; SEP-roundtrip tests are XCTSkip'd
                       # if the SEP is unavailable
$ ./Tests/e2e.sh       # end-to-end: keygen -> sign (over the protobuf
                       # wire) -> openssl verify -> reject path -> delete
```

The `e2e.sh` script is self-contained: it assembles the request frames
with a small python3 helper (no protobuf dependency — we encode the
varints by hand), pipes them through the signer, parses the response
frames, and verifies the compact signature out-of-band with `openssl`.
On a host without a SEP, the script prints a skip message and exits 0.

The script lives under `Tests/e2e.sh` rather than a separate `tests/`
directory so the same folder hosts both the XCTest sources and the
shell e2e — and so the path works on case-insensitive macOS
filesystems where `Tests/` and `tests/` are the same directory anyway.

---

## Status

Reference Swift implementation of the v1 external-signer wire
protocol. Companion to the Rust signers (`mkit-sign-file`,
`mkit-sign-tpm`, `mkit-sign-ctap`) — same protocol, different
language, different secret store.
