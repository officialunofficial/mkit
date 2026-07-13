# mkit-keystore

Platform-aware signing-key vault abstraction for mkit: software keys, OS
keychains, systemd-creds, `YubiKey`, and external signer subprocesses. See
`docs/specs/SPEC-KEYSTORE.md` for the normative backend contract.

This crate owns keystore backends and signer handles; `mkit-core` remains
independent and continues to own canonical object signing bytes.

## Backends (each behind its own Cargo feature)

- `software` &mdash; the default, always-available backend: a raw key file on
  disk.
- `backend-macos-keychain` &mdash; `macOS` Keychain Services.
- `backend-linux-secret-service` &mdash; the Secret Service D-Bus API (GNOME
  Keyring, `KWallet`).
- `backend-systemd-creds` &mdash; `systemd-creds`-sealed credentials on Linux.
- `backend-windows-credential` &mdash; Windows Credential Manager.
- `backend-yubikey` &mdash; `YubiKey` via `OpenPGP` card/PIV (`card-backend-pcsc`,
  `yubikey`).

`bls-threshold` (requires `attest`) additionally exposes a `SoftwareKeystore`
API for encrypted-at-rest BLS12-381 threshold signing shares
(`store_bls_share` / `load_bls_share` / `list_bls_shares`).

External hardware signers that don't fit a native OS keystore API (Secure
Enclave, TPM 2.0, `FIDO2`/`WebAuthn`) are driven as subprocesses instead &mdash; see
`contrib/signers/README.md` and `docs/specs/SPEC-EXTERNAL-SIGNER.md`.
