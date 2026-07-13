# mkit-sign-tpm — TPM 2.0 P-256 external signer for mkit

`mkit-sign-tpm` is a pure-Rust binary that implements the mkit external
signer v1 wire protocol ([`docs/specs/SPEC-EXTERNAL-SIGNER.md`](../../../docs/specs/SPEC-EXTERNAL-SIGNER.md))
backed by a TPM 2.0 device. It is the Linux/Windows-native analog of
`mkit-sign-se` (Apple Secure Enclave).

Headline properties:

- **P-256 only.** Every modern TPM 2.0 implements NIST P-256 (ECC-256);
  some add secp256k1 or BrainpoolP256, but this signer deliberately
  rejects any `algorithm` other than `ALGORITHM_P256` with an `Error`
  frame (`ERROR_CODE_UNSUPPORTED_ALGORITHM`) — protocol simplicity beats
  curve-zoo support.
- **Non-extractable private key.** The signing scalar is generated
  inside the TPM during `keygen` and persisted to an owner-hierarchy
  handle (`0x81010001`-style). It never leaves the TPM.
- **Pure Rust.** Wraps [`tss-esapi`](https://crates.io/crates/tss-esapi)
  (bindings to the upstream `tpm2-tss` library). No hand-rolled C
  wrappers, no shelling out to `tpm2-tools`.

---

## Requirements

### Linux

- A TPM 2.0 device (`/dev/tpmrm0` or `/dev/tpm0`) OR the `swtpm`
  simulator.
- The `tpm2-tss` native library:
  - **Debian / Ubuntu**: `sudo apt install libtss2-dev`
  - **Fedora / RHEL**: `sudo dnf install tpm2-tss-devel`
  - **Arch**: `sudo pacman -S tpm2-tss`
- Rust 1.95+ (inherits the workspace `rust-toolchain`).

### Windows

The `tss-esapi` crate supports the Windows TBS (TPM Base Services)
TCTI. Build with `--features tpm2` plus `tss-esapi`'s `tbs` feature
once it's wired into this crate — currently untested; contributions
welcome.

### macOS

macOS has no TPM hardware. On a Mac you can:

1. Use `mkit-sign-se` (Secure Enclave) for a similar hardware-backed
   P-256 signer.
2. Or run a Linux VM with `swtpm` for development of this signer.

The crate still **builds** on macOS with the default feature set OFF;
only the TPM-dependent paths require `--features tpm2`, which in turn
requires the `tpm2-tss` native library.

### Optional: `swtpm` for TPM-less testing

On Linux without real TPM hardware:

```console
sudo apt install swtpm swtpm-tools
swtpm socket --tpmstate dir=/tmp/swtpm-state --tpm2 \
    --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
    --flags not-need-init &
export TCTI="swtpm:host=localhost,port=2321"
```

Then run this signer; it picks up `TCTI` from the environment.

---

## Build

```console
$ cd contrib/signers
# All cargo commands below run inside the contrib/signers/ workspace.
# Default build — pure-Rust helpers only, no tss-esapi link.
# Useful on macOS / CI where libtss2-dev isn't installed.
$ cargo build -p mkit-sign-tpm --release

# Full build — links tss-esapi, can actually talk to a TPM.
$ cargo build -p mkit-sign-tpm --release --features tpm2
```

The crate belongs to the `contrib/signers/` Cargo workspace, so run
`cargo test -p mkit-sign-tpm` from `contrib/signers/`; it is NOT part of
`cargo test --workspace` in `rust/`.

## Install

```console
$ sudo cp contrib/signers/target/release/mkit-sign-tpm /usr/local/bin/
```

---

## Usage

Subcommands:

```
mkit-sign-tpm keygen --handle <persistent-handle> [--auth-policy owner]
mkit-sign-tpm sign   --handle <persistent-handle>
mkit-sign-tpm list
mkit-sign-tpm delete --handle <persistent-handle>
```

### `keygen`

Creates a P-256 signing primary key in the TPM's owner hierarchy and
promotes it to a persistent handle (the value you pass via
`--handle`). Prints the `p256:<66-hex>` keyid on stdout.

```console
$ mkit-sign-tpm keygen --handle 0x81010001
p256:027d8c...
```

Pick a handle that no other application on the host is already using.
The TCG recommends the `0x81010000`–`0x8101FFFF` range for user
applications.

`--auth-policy owner` (the default) uses the TPM's empty-password
owner auth. Non-default policies (password, PCR-binding) are a
documented TODO for this crate — the TPM itself can enforce them, but
the CLI surface is still minimal.

### `sign`

Enters the external-signer v1 protocol loop. The wire is
**length-prefixed protobuf `SignerFrame` messages** (4-byte
little-endian length prefix, `MAX_FRAME_BYTES = 1 MiB`) on stdin and
stdout — NOT a JSON line protocol. See
[`docs/specs/SPEC-EXTERNAL-SIGNER.md`](../../../docs/specs/SPEC-EXTERNAL-SIGNER.md)
and [`docs/specs/SPEC-RPC.md`](../../../docs/specs/SPEC-RPC.md); the schema is
[`rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto`](../../../rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto).

The conversation:

```
mkit   -> signer:  SignerFrame{ Hello{ protocol = PROTOCOL_VERSION_1,
                                        want_capabilities } }
signer -> mkit:    SignerFrame{ HelloResponse{ protocol, signer_id,
                                                capabilities } }
mkit   -> signer:  SignerFrame{ SignRequest{ algorithm = ALGORITHM_P256,
                                              key_form  = KEY_FORM_OPAQUE_HANDLE,
                                              key_ref   = <4-byte BE handle>,
                                              payload   = <PAE> } }
signer -> mkit:    SignerFrame{ SignResponse{ signature, public_key,
                                              algorithm, key_id } }
                     OR
                   SignerFrame{ Error{ code, message } }
```

`mkit-sign-tpm` advertises:

```
algorithms = [P256]
key_forms  = [OPAQUE_HANDLE]            # 4-byte BE persistent handle
supports_pin = false
supports_certificate_chain = false
requires_user_presence = false
```

The signer loops on stdin, processing successive `Hello` / `SignRequest`
pairs until the caller closes the stream; a clean EOF on the length
prefix is a graceful shutdown.

**Exit / error model** (per SPEC-EXTERNAL-SIGNER §7):

- **Per-request failures are `Error` frames, not process exits.** A
  `SignRequest` whose `algorithm` is not `ALGORITHM_P256` is answered
  with an `Error` frame carrying `ERROR_CODE_UNSUPPORTED_ALGORITHM`; an
  unsupported key form yields `ERROR_CODE_UNSUPPORTED_KEY_FORM`; an
  ill-formed `key_ref` or missing handle yields
  `ERROR_CODE_INVALID_REQUEST`; a TPM failure yields
  `ERROR_CODE_HARDWARE_ERROR`. The signer **keeps running** after an
  error frame so mkit can issue further requests on the same connection.
- **The process exits non-zero only for setup-phase failures** — bad
  argv, TPM unreachable at startup, or a fatal framing error (oversize
  or truncated frame). In that case the signer MUST NOT have emitted a
  partial stdout frame.

The signature is the 64-byte compact `r ‖ s` big-endian form the spec
requires, low-S normalised. TPM 2.0 does not implement RFC 6979, so
signatures are non-deterministic — the verifier still accepts them,
but byte-identical round-trips across invocations are not expected
(same shape as the Secure Enclave signer).

### `list`

Enumerates persistent handles in the `0x81000000`+ range that the TPM
reports as ECC; prints `<handle>\t<compressed-pubkey-hex>` for each.
This is a best-effort scan — the TPM exposes handle ranges, not
per-handle ownership, so keys created by other applications may also
appear.

### `delete`

Evicts the persistent handle from the TPM. Irreversible.

---

## Wiring mkit to use it

mkit drives external signers through three **user-scoped** config keys
(`$XDG_CONFIG_HOME/mkit/config`, never per-repo `.mkit/config` — a
hostile repo must not be able to point your attestations at an arbitrary
binary):

- `attest.signer = external` — select the external signer.
- `attest.external_signer_path = /absolute/path/to/binary` — the binary
  to spawn. MUST be absolute (mkit rejects relative paths to close the
  `$PATH` resolution race).
- `attest.external_signer_args = sign|--handle|0x81010001` — argv tokens
  passed verbatim, **pipe-separated** (no shell interpolation).

```console
$ mkit config attest.signer external
$ mkit config attest.external_signer_path /usr/local/bin/mkit-sign-tpm
$ mkit config attest.external_signer_args 'sign|--handle|0x81010001'
```

These keys may also be overridden per-invocation with
`mkit attest --signer external` and repeated `--external-signer-arg`
flags.

### Selecting the persistent handle

mkit prefers `SignRequest.key_ref` (the 4-byte big-endian persistent
handle) on the wire. When `key_ref` is empty the signer falls back to
the `--handle` value supplied on argv via `attest.external_signer_args`
(per SPEC-EXTERNAL-SIGNER §8.3). So either source works; the argv
default is the simplest for a single-key deployment, as shown above. An
ill-formed `key_ref` (wrong length) is rejected with
`ERROR_CODE_INVALID_REQUEST` rather than silently falling through to the
argv default.

---

## Security notes

- **Non-extractable secret.** The private scalar is generated inside
  the TPM and never leaves it. A full disk snapshot cannot exfiltrate
  the key; an attacker can only ask the TPM to sign.
- **Default auth is owner-hierarchy empty-password.** This matches
  the TPM's default configuration on most Linux distros. For
  higher-assurance deployments, bind the key to PCR values or a
  password auth policy at `keygen` time — neither is implemented in
  v1 of this CLI, but the TPM itself supports both via the
  `tss-esapi` API we depend on. Contributions welcome.
- **Device loss = key loss.** TPM-bound keys are tied to the specific
  TPM chip. A motherboard replacement, BIOS clear, or `tpm2_clear`
  invalidates every persistent handle irrecoverably. **Export and
  record the public key (the `p256:<hex>` keyid) before you rely on
  the signer in production**, and plan a key-rotation policy against
  device loss.
- **Installation path.** Treat `attest.external_signer_path` as a
  code-execution sink (same class as `git config core.editor`). For
  any deployment where the local user account is less trusted than
  the user who configured mkit, install the binary on a root-owned,
  non-user-writable path (e.g. `/usr/local/bin/`).

---

## Testing

```console
# Run from contrib/signers/.
# Unit tests — pure-Rust helpers, no TPM required.
$ cargo test -p mkit-sign-tpm

# Integration tests — spawn the binary, round-trip the protocol.
# TPM-dependent tests are auto-ignored on hosts without /dev/tpmrm0
# or libtss2-dev.
$ cargo test -p mkit-sign-tpm --features tpm2 -- --ignored

# End-to-end shell test — keygen → drive the protobuf SignerFrame wire
# → openssl verify → reject wrong algorithm (Error frame) → delete.
# Skips cleanly on TPM-less hosts.
$ ./tests/e2e.sh
```

The `build.rs` script detects only the TPM device files `/dev/tpmrm0`
and `/dev/tpm0`, setting the `tpm_available` cfg flag. (Earlier revisions
also accepted a `pkg-config --exists tss2-esys` hit, but that produced
false positives on hosts with the library installed yet no TPM, so the
device-file check is now the sole signal.) TPM-dependent Rust
tests are tagged `#[cfg_attr(not(tpm_available), ignore)]` so a macOS
or bare-CI test run leaves them in the "ignored" bucket rather than
failing.

---

## Status

Reference implementation for TPM 2.0 signers. Alongside `mkit-sign-se`
(Apple Secure Enclave) it is a blueprint for platform-specific signers
— same protobuf `SignerFrame` wire and subcommand surface, different
secret store. Follow-ups: PCR-bound auth policies, Windows TBS TCTI
wiring, optional attestation-key quote export for stronger endorsement
chains.
