# Changelog

All notable changes to mkit are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-07

Initial public release. mkit is a content-addressed VCS for creative
work with native cryptographic attestations. Earlier development tags
(`v0.1.0`, `v0.2.0`, `v0.2.1` from the pre-release iteration) are
superseded by this release; the repository history was flattened
prior to publication.

### Added

- **mkit-core** — content-addressed object model (BLAKE3 hashing,
  canonical objects, refs, packs), FastCDC chunker, delta encoding,
  Bao verified streaming, Ed25519 commit signing.
- **mkit-attest** — DSSE + in-toto v1 attestations with multi-algorithm
  signers (Ed25519, secp256k1, P-256) and an RFC 8785 JCS encoder.
- **mkit-cli** — the `mkit` binary, with subcommands for init, add,
  commit, log, status, branch, checkout, merge, cherry-pick, rebase,
  push, pull, fetch, clone, attest, verify-attest, keygen, config.
- **Transports** — memory (test), file (local), http (REST + rustls),
  s3 (SigV4 over rustls, R2-compatible), ssh (forced-command server
  pattern over `ssh(1)`).
- **mkit-wasm** — wasm-bindgen surface for browsers and Cloudflare
  Workers, published to npm as `@makechain/mkit-wasm`.
- **External signers** — reference implementations under `contrib/`
  for FIDO2/WebAuthn (CTAP-HID), TPM 2.0 P-256, and a raw-key file
  signer for development.
- **Release pipeline** — cosign keyless OIDC signing, CycloneDX SBOMs,
  reproducible-build smoke tests, MSRV checks on Linux + macOS.

### Security

- Per-repo `.mkit/config` is partitioned: security-sensitive keys
  (signing key paths, external-signer paths, SSH trust knobs) are
  user-scoped only. A hostile clone cannot redirect signing or
  weaken transport trust via repo-local config.
- `mkit verify-attest` defaults to `$XDG_CONFIG_HOME/mkit/trust-roots.toml`
  rather than a repo-local path; in-repo trust-roots require an
  explicit `--trust-roots` flag.
- Key files are opened with `O_NOFOLLOW`, written via tmp + fsync +
  rename + parent fsync, owner-checked against the running euid, and
  parent directory mode is enforced `0700`.
- HTTP and S3 transports require an explicit user-scoped
  `trusted_remote_endpoint` before they will use ambient environment
  credentials for repo-configured remotes.
- Reference external signer keeps secret material in a zeroizing
  buffer until the per-algorithm signer consumes it.

[Unreleased]: https://github.com/officialunofficial/mkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/officialunofficial/mkit/releases/tag/v0.1.0
