# mkit-sign-se — Apple Secure Enclave signer for mkit

`mkit-sign-se` is a Swift binary that implements the mkit external
signer v1 wire protocol ([`docs/SPEC-EXTERNAL-SIGNER.md`](../../../docs/SPEC-EXTERNAL-SIGNER.md))
backed by Apple's Secure Enclave.

Headline properties:

- **P-256 only.** The Secure Enclave supports no other algorithm. Any
  request with `"algorithm"` other than `"p256"` is rejected with
  exit code 2 and a message on stderr — this signer **will not** fall
  back to a software key.
- **Non-extractable private key.** `SecureEnclave.P256.Signing.PrivateKey`
  generates and holds the scalar inside the Secure Enclave processor;
  the blob we persist to the keychain is an encrypted handle that only
  the SEP on the same physical device can reconstitute.
- **Optional biometric gating.** `--require-biometric` on `keygen`
  binds the key to `.biometryCurrentSet`, so every sign prompts for
  Touch ID / Face ID (and the key becomes unusable if the user enrolls
  a new fingerprint / face).

---

## Requirements

- macOS 12 (Monterey) or later.
- Apple Silicon, or an Intel Mac with a T2 security chip. (Check with
  `swift -e 'import CryptoKit; print(SecureEnclave.isAvailable)'`.)
- Swift 5.9+ toolchain — shipping Xcode 14+ or the standalone
  Command Line Tools is enough.
- For the e2e test: `openssl` and `python3` (both ship with macOS).

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

Either copy the binary or use the Makefile target:

```console
$ make install                      # copies to /usr/local/bin
$ make install PREFIX=$HOME/.local  # installs under ~/.local/bin
```

---

## Usage

Subcommands:

```
mkit-sign-se keygen --tag <label> [--require-biometric]
mkit-sign-se sign   --tag <label>
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

Implements the external-signer v1 protocol. Reads one line of JSON
from stdin and writes one line of JSON to stdout:

```console
$ PAE='DSSEv1 28 application/vnd.in-toto+json 2 {}'
$ PAE_B64=$(printf '%s' "$PAE" | base64 | tr -d '\n')
$ printf '{"pae_base64":"%s","algorithm":"p256"}\n' "$PAE_B64" \
    | mkit-sign-se sign --tag my-attest-key
{"keyid":"p256:…","sig_base64":"…"}
```

- Exit 0 on success with one line of JSON on stdout (nothing on stderr).
- Exit 2 specifically for `algorithm != "p256"` — nothing on stdout, a
  human-readable reject message on stderr.
- Exit 1 for everything else (unknown tag, SEP unavailable, biometric
  declined, malformed stdin JSON, keychain failure).

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
external_signer = "/usr/local/bin/mkit-sign-se"
```

### ⚠️ Known limitation: `--tag` is not passed through today

mkit's external-signer invocation today sends the signer an **empty
argv**. That means `mkit-sign-se sign --tag <label>` — which is how you
tell this binary *which* SEP key to use — can't be selected by mkit
directly; the binary would be invoked with no `--tag` argument and
exit on the "missing --tag" path.

**Workaround until mkit grows a `--tag` pass-through (tracked as a
follow-up):** wrap the binary in a trivial shell script that hard-codes
your chosen tag and point mkit at the wrapper instead.

`~/.local/bin/mkit-sign-se-myproject`:

```sh
#!/bin/sh
exec /usr/local/bin/mkit-sign-se sign --tag my-attest-key
```

Then:

```console
$ chmod 755 ~/.local/bin/mkit-sign-se-myproject
$ mkit config set attest.external_signer "$HOME/.local/bin/mkit-sign-se-myproject"
```

(That same wrapper trick is how `mkit-sign-file` handles its own
per-invocation `--key` plumbing — see `contrib/signers/README.md`.)

### `mkit keygen` does NOT produce an SEP-backed key

`mkit keygen --algorithm p256` writes a raw-key file to
`.mkit/signing.key` — that is a *different* flow. For the SEP
workflow:

1. Run `mkit-sign-se keygen --tag my-attest-key` to mint the SEP key.
2. Note the printed `p256:<hex>` keyid.
3. Add that keyid to your verifier's trust-root registry.
4. Configure mkit with the `external_signer` block above (plus the
   wrapper-script workaround for `--tag`).

---

## Security notes

- **Non-extractable secret.** The private scalar is generated inside
  the SEP and never leaves it. A full disk snapshot — or even a
  compromised kernel — cannot exfiltrate the key material; they can
  only ask the SEP to sign, subject to whatever access control was
  set at creation.
- **Biometric-gated signing.** With `--require-biometric`, signing
  prompts for Touch ID / Face ID. Declining or cancelling the prompt
  surfaces as a non-zero exit with a `biometric prompt was declined`
  message. mkit treats that as a normal signer failure.
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
- **Installation path.** Treat `attest.external_signer` as a
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

### "biometric prompt was declined or cancelled"

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
$ swift test           # unit tests; SEP-roundtrip test is XCTSkip'd
                       # if the SEP is unavailable
$ ./Tests/e2e.sh       # end-to-end: keygen -> sign -> openssl verify
                       # -> reject-wrong-algorithm -> delete
```

The `e2e.sh` script is self-contained: it uses `openssl` (ships with
macOS) to verify the compact signature out-of-band, so it exercises
the on-the-wire format directly without needing a built `mkit` binary.
On a host without a SEP, the script prints a skip message and exits 0.

The script lives under `Tests/e2e.sh` rather than a separate `tests/`
directory so the same folder hosts both the XCTest sources and the
shell e2e — and so the path works on case-insensitive macOS
filesystems where `Tests/` and `tests/` are the same directory anyway.

---

## Status

Reference implementation for SEP signers. The plan is to use this as
the blueprint for other platform-specific signers (Ledger, WebAuthn,
HSM, ...): each follows the same argv / subcommand / JSON shape, but
targets a different secret store.
