# Supply-chain policy

mkit's supply chain is intentionally narrow. The binary users run traces
back to a small, auditable set of inputs. This document is the contract.

## Current state

- **Rust dependencies:** fully pinned via `Cargo.lock`. Every transitive
  dep is hash-pinned on each release build. The workspace's direct
  deps are kept deliberately small — see `rust/Cargo.toml` and each
  crate's `[dependencies]` section for the full list.
- **System libs:** default release builds link musl (Linux) or the
  platform C runtime (macOS). Optional keystore backend features may use
  platform services such as Security.framework, Windows Credential
  Manager, D-Bus Secret Service, PC/SC, or the `systemd-creds` binary.
  These features are off by default, platform-gated, and fail closed when
  the required service or device is unavailable. The Linux Secret Service
  feature selects the pure-Rust crypto runtime, not OpenSSL.
- **Build inputs:** the Rust toolchain (version pinned in
  `rust-toolchain.toml`), the source tree at a tagged Git commit, and
  the set of `--target=` / profile flags documented in
  `docs/release/REPRODUCIBILITY.md`.

## Adding a Rust dependency

Every new direct dependency added to a workspace `Cargo.toml` must:

1. Be **version-pinned** in `Cargo.toml` and reflected in `Cargo.lock`.
2. Have its source reviewed by **two maintainers**. Sign-off lives in
   the PR description.
3. Have a stated purpose. A PR that adds a dep must answer: what does
   mkit gain, and what would implementing it in-tree cost? Default
   answer should be "implement in-tree"; deps are the exception.
4. Be compatible with **MIT OR Apache-2.0**. The CI dependency-review
   action denies GPL and LGPL families outright when the repo has
   Dependency Graph enabled and `ENABLE_DEPENDENCY_REVIEW=1`.
5. Have a cross-platform build. If the dep breaks on one of our four
   release targets, it doesn't land.

## Keystore V1 backend dependency review

Issue #104 adds optional backend and envelope-encryption dependencies to
`mkit-keystore`. T19 reviewed the direct additions below. All are pinned in
`Cargo.toml`, reflected in `Cargo.lock`, sourced from crates.io, accepted by
`cargo deny`, and isolated from default builds unless listed as always-on.

| Dependency | Use | Gate | License | Notes |
|------------|-----|------|---------|-------|
| `chacha20poly1305 = 0.10.1` | XChaCha20-Poly1305 software-key envelope encryption | always-on keystore crypto | Apache-2.0 OR MIT | Pure Rust, default features disabled except `alloc`; no OpenSSL/libcurl/native C dependency. |
| `zeroize = 1.8.2` | Secret-memory clearing for software keys and records | always-on keystore crypto | Apache-2.0 OR MIT | Already common in the RustCrypto ecosystem; used directly for local secret material. |
| `security-framework = 3.7.0` | macOS Keychain bindings | `macos-keychain`, macOS target only | MIT OR Apache-2.0 | Wraps platform Security.framework APIs; no default-build impact. |
| `keyring-core = 1.0.0` | Shared keyring abstraction for OS key stores | `windows-credential`, `linux-secret-service` | MIT OR Apache-2.0 | Small shared abstraction used only by optional OS backends. |
| `windows-native-keyring-store = 1.0.0` | Windows Credential Manager store | `windows-credential`, Windows target only | MIT OR Apache-2.0 | Requires Rust 1.88, below workspace MSRV 1.95; platform-gated. |
| `zbus-secret-service-keyring-store = 1.0.0` | Linux Secret Service store | `linux-secret-service`, Linux target only | MIT OR Apache-2.0 | Requires Rust 1.88, below workspace MSRV 1.95; feature uses `rt-async-io-crypto-rust` to avoid OpenSSL. |
| `card-backend-pcsc = 0.5.1` | PC/SC card discovery for OpenPGP cards | `backend-yubikey` | MIT OR Apache-2.0 | Requires PC/SC libraries at build/runtime only when the YubiKey backend is enabled. |
| `openpgp-card = 0.6.1` | OpenPGP card protocol for YubiKey signing-slot keys | `backend-yubikey` | MIT OR Apache-2.0 | Supports existing card keys; V1 does not generate/import/delete card keys. |
| `secrecy = 0.10.3` | PIN handling wrappers for card operations | `backend-yubikey` | Apache-2.0 OR MIT | Complements `zeroize` for secret inputs crossing card APIs. |
| `der = 0.8.0` | DER parsing for YubiKey PIV certificates | `backend-yubikey` | Apache-2.0 OR MIT | RustCrypto format crate; used to extract P-256 public keys from existing certificates. |
| `yubikey = 0.9.0-pre.0` | YubiKey PIV certificate discovery and signing | `backend-yubikey` | BSD-2-Clause | Accepted because V1 PIV support needs mature PIV APDUs and no stable alternative matched the API. Risk is contained by optional feature gating, existing-key-only support, fail-closed behavior, CI feature builds, and manual hardware validation. |

`cargo deny check` currently finishes with `advisories ok, bans ok, licenses ok,
sources ok`. Remaining warnings are duplicate crate versions from existing
ecosystem splits and optional YubiKey/RustCrypto prerelease transitive stacks,
plus stale license allowances. They are tracked as warnings rather than release
blockers because they do not introduce unapproved sources, yanked crates, or
denied licenses.

## GitHub Actions dependencies

All third-party actions in `.github/workflows/` must be pinned to a major
version tag (`@v4`) or to a full SHA. No `@main`, no `@latest`. Trusted publishers today:

- `actions/*` (GitHub-owned)
- `dtolnay/rust-toolchain` (Rust toolchain installer)
- `sigstore/cosign-installer` (cosign)
- `anchore/sbom-action` (SBOM)
- `softprops/action-gh-release` (release creation)
- `ossf/scorecard-action` (Scorecard)

Any new action from an untrusted publisher needs the same two-maintainer
review as a Rust dep.

## Release artifact integrity

Every release archive is:

- **Hashed** in a per-archive `SHA256SUMS` inside the tarball.
- **Signed** with cosign keyless OIDC, with signatures tied to this
  repo's release workflow identity.
- **Logged** in the public Rekor transparency log — every signature is
  discoverable via <https://search.sigstore.dev/>.
- **Inventoried** in a CycloneDX SBOM (`sbom.cdx.json`), attached to the
  release.

Details and verification commands: `docs/release/SIGNING.md`.

## Package-manager publications

When we publish to Homebrew (and later Scoop, Nix, etc.), the published
manifest must reference the GitHub Releases archive URL directly — never
a re-hosted copy. The `sha256` in the manifest is the authoritative pin;
users who distrust the package manager can fetch the archive and repeat
the cosign verification in `docs/release/SIGNING.md`.

## SBOM lifecycle

- A fresh SBOM is generated on every tagged release and attached to the
  GitHub Release.
- A weekly cron (`supply-chain.yml`) regenerates the SBOM for `main` so
  we notice drift from indirect sources (e.g. a GitHub Actions bump
  pulling in a new transitive).

## Vulnerability response

A CVE against any dep we ship is treated as a P1. Workflow:

1. Patch, test, tag a new release.
2. Open a GitHub Security Advisory citing the CVE.
3. Update `CHANGELOG.md` under `### Security`.
4. Email the contact in `SECURITY.md` if the issue requires coordinated
   disclosure with a reporter.
