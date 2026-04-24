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
| [`mkit-sign-ctap/`](mkit-sign-ctap/)          | **reference** (Rust)    | FIDO2/WebAuthn roaming authenticator over CTAP-HID (YubiKey, Nitrokey, SoloKey). P-256 only. Speaks Protocol **v1.1** with WebAuthn wrapping — see SPEC-EXTERNAL-SIGNER §14. |
| [`mkit-sign-tpm/`](mkit-sign-tpm/README.md)   | **reference** (Rust)    | TPM 2.0 persistent-handle P-256 key. Linux/Windows-native. `tss-esapi` under the hood. |
| `ledger/` *(planned)*                         | not yet                 | Ledger Nano X/S via HID. secp256k1 + Ed25519. User button confirmation.             |
| `wallet-bridge/` *(planned)*                  | not yet                 | JSON-RPC bridge to a running browser wallet. secp256k1, `personal_sign`.            |

`mkit-sign-file` is the one integrators should read first — it's short
enough (~250 lines) to be the shortest possible demonstration of the
protocol, and its end-to-end test is the contract test any conforming
implementation should pass. `mkit-sign-se` (Apple Secure Enclave),
`mkit-sign-tpm` (TPM 2.0), and `mkit-sign-ctap` (FIDO2/WebAuthn) are
the first platform-specific signers and the joint blueprint for the
rest of the `ledger` / wallet-bridge lineup: argv subcommand shape,
hardware-handle storage, "reject non-native algorithms explicitly"
stance, and a self-contained `tests/e2e.sh` that proves wire-format
conformance without a built `mkit`. `mkit-sign-ctap` additionally
demonstrates **Protocol v1.1** — the wrapping mode for signers that
cannot sign arbitrary bytes (WebAuthn authenticators, some browser
wallets) and need to wrap the PAE inside a per-ceremony transport
(here: `clientDataJSON`).

## Protocol v1.1: WebAuthn wrapping

`mkit-sign-ctap` produces v1.1 responses: the usual `{keyid,
sig_base64}` plus an optional `webauthn` object with the
`authenticatorData` and `clientDataJSON` the authenticator signed
over. Verifiers reconstruct `authenticator_data || SHA256(client_data_json)`
and check the signature against it, after asserting that
`clientDataJSON.challenge == base64url_nopad(PAE)`. The full spec is
in [`docs/SPEC-EXTERNAL-SIGNER.md`](../../docs/SPEC-EXTERNAL-SIGNER.md)
§14, and the reference verifier helper lives at
`rust/crates/mkit-attest/src/webauthn.rs` (`verify_webauthn_wrapping`).

A v1.1 response MUST also be verifiable by a plain v1 verifier only
as a *negative* check — v1 treats `sig_base64` as a signature over
`SHA256(PAE)`, which it isn't, so the v1 verifier reports
`SignatureMismatch`. This is the deliberate upgrade path: absence of
`webauthn` is ignored by v1.1 verifiers (they fall back to v1
behaviour), presence of `webauthn` is invisible to v1 verifiers.

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

## Reference signer: `mkit-sign-ctap` (Protocol v1.1, WebAuthn)

Pure-Rust binary that drives a FIDO2/WebAuthn roaming authenticator
over CTAP-HID. Supports the three canonical brands (YubiKey,
Nitrokey, SoloKey) via the `ctap-hid-fido2` crate. Produces Protocol
v1.1 responses with the WebAuthn wrapping material inlined.

### Build

```console
$ cd rust
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

$ # Sign. Read v1 request from stdin, emit v1.1 response on stdout.
$ echo '{"pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ==","algorithm":"p256"}' \
    | mkit-sign-ctap sign --credential-id <base64url>
{"keyid":"p256:...","sig_base64":"...","webauthn":{"authenticator_data":"...","client_data_json":"..."}}
```

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
