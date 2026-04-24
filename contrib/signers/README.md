# mkit external signers

Third-party signer implementations for mkit's `external` signer slot
live here. They all speak the same wire protocol:

> [**SPEC-EXTERNAL-SIGNER.md**](../../docs/SPEC-EXTERNAL-SIGNER.md) — v1 JSON-over-stdin/stdout

Write your signer to that spec and mkit will drive it via
`attest.external_signer_path = /abs/path/to/your-binary` in
`.mkit/config`.

---

## What lives here

| Path                                          | Status                  | Summary                                                                             |
|-----------------------------------------------|-------------------------|-------------------------------------------------------------------------------------|
| [`mkit-sign-file/`](mkit-sign-file/)          | **reference** (Rust)    | Raw 32-byte key on disk. Ed25519 / secp256k1 / P-256. Not production.               |
| [`mkit-sign-se/`](mkit-sign-se/README.md)     | **reference** (Swift)   | Apple Secure Enclave, P-256 only, optional biometric gate. Production-viable on Apple Silicon / T2. |
| `ledger/` *(planned)*                         | not yet                 | Ledger Nano X/S via HID. secp256k1 + Ed25519. User button confirmation.             |
| `webauthn/` *(planned)*                       | not yet                 | WebAuthn/CTAP authenticator, pure Rust. P-256. Browser or roaming auth.             |
| `wallet-bridge/` *(planned)*                  | not yet                 | JSON-RPC bridge to a running browser wallet. secp256k1, `personal_sign`.            |

`mkit-sign-file` is the one integrators should read first — it's short
enough (~250 lines) to be the shortest possible demonstration of the
protocol, and its end-to-end test is the contract test any conforming
implementation should pass. `mkit-sign-se` is the first
platform-specific signer and the blueprint for the rest of the
`ledger` / `webauthn` / wallet-bridge lineup: argv subcommand shape,
keychain-backed tag storage, "reject non-native algorithms explicitly"
stance, and a self-contained `tests/e2e.sh` that proves wire-format
conformance without a built `mkit`.

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
$ cd rust
$ cargo build --release -p mkit-sign-file
$ ls target/release/mkit-sign-file
target/release/mkit-sign-file
```

The binary is a workspace member, so `cargo test --workspace` from
`rust/` runs its end-to-end test alongside the rest of the tree.

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

```console
$ echo '{"pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ==","algorithm":"ed25519"}' \
    | ./target/release/mkit-sign-file --key /tmp/mkit-ref.key
{"keyid":"blake3:…","sig_base64":"…"}
```

Exit 0 and a one-line JSON response on success; non-zero with a
stderr message on any error.

---

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
