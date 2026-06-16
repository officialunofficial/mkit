# mkit external signers

Third-party signer implementations for mkit's `external` signer slot
live here. They all speak the same wire protocol:

> [**SPEC-EXTERNAL-SIGNER.md**](../../docs/SPEC-EXTERNAL-SIGNER.md) — v1
> length-prefixed protobuf [`SignerFrame`](../../rust/crates/mkit-rpc/proto/signer.proto)
> messages over stdin/stdout. Schema is `mkit-rpc/proto/signer.proto`
> (with `common.proto` for shared types); the Rust runtime is `buffa`.

Write your signer to that spec and mkit will drive it via
`attest.external_signer_path = /abs/path/to/your-binary` in
`.mkit/config`.

---

## What lives here

| Path                                          | Status                  | Summary                                                                             |
|-----------------------------------------------|-------------------------|-------------------------------------------------------------------------------------|
| [`mkit-sign-file/`](mkit-sign-file/)          | **reference** (Rust)    | Raw 32-byte key on disk. Ed25519 / secp256k1 / P-256. Not production.               |
| [`mkit-sign-se/`](mkit-sign-se/README.md)     | **reference** (Swift)   | Apple Secure Enclave, P-256 only. SwiftProtobuf on the v1 wire. Non-extractable key; optional Touch ID / Face ID gating. |
| [`mkit-sign-ctap/`](mkit-sign-ctap/)          | **reference** (Rust)    | FIDO2/WebAuthn roaming authenticator over CTAP-HID (YubiKey, Nitrokey, SoloKey). P-256. WebAuthn-wrapping mode — see SPEC-EXTERNAL-SIGNER §14. |
| [`mkit-sign-tpm/`](mkit-sign-tpm/README.md)   | **reference** (Rust)    | TPM 2.0 persistent-handle P-256 key. Linux/Windows-native. `tss-esapi` under the hood. |
| `ledger/` *(planned)*                         | not yet                 | Ledger Nano X/S via HID. secp256k1 + Ed25519. User button confirmation.             |
| `wallet-bridge/` *(planned)*                  | not yet                 | JSON-RPC bridge to a running browser wallet. secp256k1, `personal_sign`.            |

`mkit-sign-file` is the one integrators should read first — it's the
shortest demonstration of the v1 wire protocol, and its end-to-end
test is the contract test any conforming implementation should pass.
`mkit-sign-tpm` (TPM 2.0) and `mkit-sign-ctap` (FIDO2/WebAuthn) are
the first hardware-backed signers and the joint blueprint for the
rest of the `ledger` / wallet-bridge lineup: argv subcommand shape,
hardware-handle storage, "reject non-native algorithms explicitly"
stance, and a self-contained `tests/e2e.sh` that proves wire-format
conformance without a built `mkit`. `mkit-sign-ctap` additionally
demonstrates the **WebAuthn-wrapping mode** — for signers that cannot
sign arbitrary bytes (WebAuthn authenticators, some browser wallets)
and need to wrap the PAE inside a per-ceremony transport (here:
`clientDataJSON`).

## WebAuthn wrapping (CTAP signers)

`mkit-sign-ctap` populates `SignResponse.webauthn` (a `WebAuthnData`
message defined in [`signer.proto`](../../rust/crates/mkit-rpc/proto/signer.proto))
with the `authenticator_data` and `client_data_json` the authenticator
signed over, and it returns the enrolled credential public key in
`SignResponse.public_key`. Verifiers reconstruct
`authenticator_data || SHA256(client_data_json)` and check the
signature against it, after asserting that
`clientDataJSON.challenge == base64url_nopad(PAE)`. The full spec is
in [`docs/SPEC-EXTERNAL-SIGNER.md`](../../docs/SPEC-EXTERNAL-SIGNER.md)
§14, and the reference verifier helper lives at
`rust/crates/mkit-attest/src/webauthn.rs` (`verify_webauthn_wrapping`).

---

## Reference signer: `mkit-sign-file`

A tiny Rust binary that signs a DSSE PAE using a 32-byte raw private
key read from disk. All three algorithms (`ed25519`, `secp256k1`,
`p256`) are supported.

**Not a production signer.** The secret lives on disk as raw bytes;
there is no unwrap, no passphrase, no audit log. Use it to:

- Validate your mkit config and env plumbing end-to-end.
- Sanity-check a signer protocol implementation you're porting to
  another language.
- As a copy-and-modify starting point for a "real" signer.

### Build

```console
$ cd contrib/signers
$ cargo build --release -p mkit-sign-file
$ ls target/release/mkit-sign-file
target/release/mkit-sign-file
```

The signers are their own Cargo workspace (`contrib/signers/Cargo.toml`),
so run `cargo test` from `contrib/signers/` to exercise the end-to-end test —
it is NOT covered by `cargo test --workspace` in `rust/`.

### Usage

```console
$ # Generate a 32-byte key. `openssl rand` or any CSPRNG works.
$ openssl rand 32 > /tmp/mkit-ref.key
$ chmod 0600 /tmp/mkit-ref.key

$ # Point mkit at it.
$ mkit config attest.signer external
$ mkit config attest.external_signer_path "$(pwd)/target/release/mkit-sign-file"

$ # Plumb --key into the subprocess. Three options, in order of
$ # preference:
$ #   (a) config: attest.external_signer_args = --key|/tmp/mkit-ref.key
$ #   (b) flag:   mkit attest --external-signer-arg --key \
$ #                           --external-signer-arg /tmp/mkit-ref.key
$ #   (c) env:    export MKIT_SIGN_FILE_KEY=/tmp/mkit-ref.key
$ mkit config attest.external_signer_args "--key|/tmp/mkit-ref.key"
```

The argv pass-through (a/b) is the recommended path — it works for
any signer binary without env-var plumbing and supports per-invocation
overrides via `--external-signer-arg`. The pipe (`|`) is used on disk
because commas are reserved for `--additional-signer` multi-sig specs.
Env vars (c) still work when a wrapper layer (CI, systemd unit) owns
the environment and you don't want argv in `.mkit/config`.

### Direct invocation (for testing)

The wire is binary protobuf (`SignerFrame`), so you can't craft a
request by hand at the shell. To exercise a signer outside `mkit`:

- Use the contract test at
  [`mkit-sign-file/tests/end_to_end.rs`](mkit-sign-file/tests/end_to_end.rs).
  It spawns the binary, writes a `Hello` + `SignRequest` frame,
  reads the response, and verifies the signature with
  `mkit_attest::verify_signature`.
- Port that test to your language; if it passes, your signer is
  protocol-conforming.

---

## Reference signer: `mkit-sign-ctap` (WebAuthn-wrapping mode)

Pure-Rust binary that drives a FIDO2/WebAuthn roaming authenticator
over CTAP-HID. Supports the three canonical brands (YubiKey,
Nitrokey, SoloKey) via the `ctap-hid-fido2` crate. Populates the
`webauthn` field of the v1 `SignResponse` with the wrapping material
(authenticator data + clientDataJSON) the authenticator signed over.

### Build

```console
$ cd contrib/signers
$ cargo build --release -p mkit-sign-ctap
$ ls target/release/mkit-sign-ctap
target/release/mkit-sign-ctap
```

### Usage

```console
$ # Enroll a credential (user touches the authenticator when it flashes).
$ mkit-sign-ctap enroll --rp-id mkit.local --user-name alice
p256:020c901d423c831ca85e27c73c263ba132721bb9d7a84c4f0380b2a6756fd60133
mkit-sign-ctap: enrolled credential_id=... at ~/.mkit-sign-ctap/credentials.json

$ # List what's enrolled.
$ mkit-sign-ctap list-credentials
credential_id=...	keyid=p256:...	rp_id=mkit.local	user_name=alice

$ # Sign. mkit drives this over stdin/stdout with protobuf
$ # SignerFrame messages — see the contract test in
$ # mkit-sign-file/tests/end_to_end.rs for the framing shape.
$ mkit-sign-ctap sign --credential-id <base64url>
# (input/output are binary SignerFrame protobuf; not shell-paste-able)
```

The signer advertises `KEY_FORM_OPAQUE_HANDLE` for CTAP credential IDs.
For compatibility with mkit's current external-signer host path, it also
accepts `KEY_FORM_RAW_BYTES` when `key_ref` is empty and `--credential-id`
supplies the credential handle on argv.

Exit codes: 0 success, 1 generic error, 2 algorithm mismatch (same as
`mkit-sign-se`). Requires a physical authenticator for `enroll` /
`sign`; `list-credentials` runs fine without one. The
`tests/e2e.sh` probe detects an attached authenticator by USB-vendor
match and exits 0 with a skip message when none is present.

## Writing your own signer

1. Read [`docs/SPEC-EXTERNAL-SIGNER.md`](../../docs/SPEC-EXTERNAL-SIGNER.md).
   It's ~400 lines and covers invocation, wire format, errors,
   timeouts, and the security model.
2. Copy `mkit-sign-file/tests/end_to_end.rs` as a contract test. It
   spawns the binary as a subprocess, pipes a request in, and
   verifies the signature via `mkit_attest::verify_signature`. Port
   the same checks to your language of choice — if the test passes,
   your signer is protocol-conforming.
3. Handle the permission + locking / user-confirmation bits that are
   relevant to your platform:
   - Secure Enclave: biometric gate (LAContext / Face ID / Touch ID).
   - Ledger: user presses both buttons.
   - WebAuthn: user gesture + optional user verification (PIN).
   - Wallet bridge: the wallet's own `personal_sign` prompt.
4. Decide your keyid convention. `<algorithm-prefix>:<hex>` is the
   default and easy to verify; platform-specific schemes like
   `webauthn:<credential-id>`, `yubikey:<serial>`, or
   `tpm2:<handle>` are allowed when the verifier side knows how to
   dispatch.

---

## Security reminder

The external signer runs as a child process under mkit's user. It
holds the key. mkit trusts it completely for the duration of a
signing call — there's no sandbox beyond OS user isolation. Treat
the `attest.external_signer_path` config key as a code-execution sink
(same class as `git config core.editor` or shell-profile hooks) and
make sure the binary is on a non-user-writable path in any environment
where the threat model warrants it.
