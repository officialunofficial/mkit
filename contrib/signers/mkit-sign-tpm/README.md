# mkit-sign-tpm — TPM 2.0 P-256 external signer for mkit

`mkit-sign-tpm` is a pure-Rust binary that implements the mkit external
signer v1 wire protocol ([`docs/SPEC-EXTERNAL-SIGNER.md`](../../../docs/SPEC-EXTERNAL-SIGNER.md))
backed by a TPM 2.0 device. It is the Linux/Windows-native analog of
`mkit-sign-se` (Apple Secure Enclave).

Headline properties:

- **P-256 only.** Every modern TPM 2.0 implements NIST P-256 (ECC-256);
  some add secp256k1 or BrainpoolP256, but this signer deliberately
  rejects any `algorithm` other than `"p256"` with exit code 2 —
  protocol simplicity beats curve-zoo support.
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
# Default build — pure-Rust helpers only, no tss-esapi link.
# Useful on macOS / CI where libtss2-dev isn't installed.
$ cargo build -p mkit-sign-tpm --release

# Full build — links tss-esapi, can actually talk to a TPM.
$ cargo build -p mkit-sign-tpm --release --features tpm2
```

The crate is a workspace member of `rust/`, so `cargo test --workspace`
runs the unit tests alongside the rest of the tree.

## Install

```console
$ sudo cp rust/target/release/mkit-sign-tpm /usr/local/bin/
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

Implements the external-signer v1 protocol. Reads one line of JSON
from stdin and writes one line of JSON to stdout:

```console
$ PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
$ PAE_B64=$(printf '%s' "$PAE" | base64 | tr -d '\n')
$ printf '{"pae_base64":"%s","algorithm":"p256"}\n' "$PAE_B64" \
    | mkit-sign-tpm sign --handle 0x81010001
{"keyid":"p256:…","sig_base64":"…"}
```

Exit codes:

- **0** on success, one line of JSON on stdout.
- **2** specifically for `algorithm != "p256"`, empty stdout, reject
  message on stderr.
- **1** for everything else (bad handle, TPM unreachable, malformed
  request, TPM refused the sign, …).

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

`.mkit/config`:

```toml
[attest]
signer = "external"
external_signer = "/usr/local/bin/mkit-sign-tpm-myproject"
```

### Known limitation: `--handle` is not passed through today

mkit's external-signer invocation today sends the signer an **empty
argv**. That means `mkit-sign-tpm sign --handle <H>` — which is how
you tell this binary *which* TPM key to use — can't be selected by
mkit directly; the binary would be invoked with no `--handle`
argument and exit on the "missing --handle" path.

Team Phi is landing a `--tag` / `--handle` pass-through in parallel.
Until that ships, wrap the binary in a trivial shell script that
hard-codes your chosen handle and point mkit at the wrapper:

`~/.local/bin/mkit-sign-tpm-myproject`:

```sh
#!/bin/sh
exec /usr/local/bin/mkit-sign-tpm sign --handle 0x81010001
```

Then:

```console
$ chmod 755 ~/.local/bin/mkit-sign-tpm-myproject
$ mkit config set attest.external_signer "$HOME/.local/bin/mkit-sign-tpm-myproject"
```

(The same wrapper pattern is how `mkit-sign-file` handles its `--key`
plumbing and `mkit-sign-se` handles `--tag` — see
`contrib/signers/README.md`.)

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
- **Installation path.** Treat `attest.external_signer` as a
  code-execution sink (same class as `git config core.editor`). For
  any deployment where the local user account is less trusted than
  the user who configured mkit, install the binary on a root-owned,
  non-user-writable path (e.g. `/usr/local/bin/`).

---

## Testing

```console
# Unit tests — pure-Rust helpers, no TPM required.
$ cargo test -p mkit-sign-tpm

# Integration tests — spawn the binary, round-trip the protocol.
# TPM-dependent tests are auto-ignored on hosts without /dev/tpmrm0
# or libtss2-dev.
$ cargo test -p mkit-sign-tpm --features tpm2 -- --ignored

# End-to-end shell test — keygen → sign → openssl verify → reject
# wrong algorithm → delete. Skips cleanly on TPM-less hosts.
$ ./tests/e2e.sh
```

The `build.rs` script auto-detects `pkg-config --exists tss2-esys` and
`/dev/tpm*`, setting the `tpm_available` cfg flag. TPM-dependent Rust
tests are tagged `#[cfg_attr(not(tpm_available), ignore)]` so a macOS
or bare-CI test run leaves them in the "ignored" bucket rather than
failing.

---

## Status

Reference implementation for TPM 2.0 signers. Alongside `mkit-sign-se`
(Apple Secure Enclave) it is a blueprint for platform-specific signers
— same argv / subcommand / JSON shape, different secret store.
Follow-ups: PCR-bound auth policies, Windows TBS TCTI wiring, optional
attestation-key quote export for stronger endorsement chains.
