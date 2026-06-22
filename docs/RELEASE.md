# Cutting an mkit release

This is the single release runbook. It consolidates what used to live under
`docs/release/` (checklist, signing/verification, supply-chain policy,
reproducibility, crates.io publishing) into one page.

Contents:

- [What gets published](#what-gets-published)
- [Pre-release checklist](#pre-release-checklist)
- [Cutting a release](#cutting-a-release)
- [Publishing to crates.io](#publishing-to-cratesio)
- [Signing and verification](#signing-and-verification)
- [Supply-chain policy](#supply-chain-policy)
- [Reproducibility](#reproducibility)
- [Required GitHub Actions secrets and variables](#required-github-actions-secrets-and-variables)
- [One-time setup](#one-time-setup)

## What gets published

A single `vX.Y.Z` tag drives two decoupled channels:

- **Binaries + npm wasm** via
  [`.github/workflows/release.yml`](../.github/workflows/release.yml).
- **crates.io** via
  [`.github/workflows/crates-publish.yml`](../.github/workflows/crates-publish.yml).

Both are gated on the same signed tag. Before `release.yml` publishes anything,
it verifies that the tag is strict semver, annotated, GPG-signed by an
allowlisted release fingerprint, and points at a commit reachable from
`origin/main`. It then produces:

1. **GitHub Release** with native binaries for four targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`

   Each archive contains the `mkit` binary, licenses, README, optional
   changelog, `share/man/man1/mkit.1`, and shell completions under
   `share/completions/`. Each archive is cosign-signed (keyless OIDC, Rekor
   logged) and ships alongside per-archive `.sig`/`.crt`/`.cosign.bundle`, an
   aggregate `SHA256SUMS` (also cosign-signed), and a CycloneDX
   `sbom.cdx.json`.

2. **npm package** `@makechain/mkit-wasm@X.Y.Z`. Built with
   `wasm-pack --target bundler` and published with `npm publish --access
   public`. The pkg tarball is also attached to the GitHub Release as
   `mkit-wasm-X.Y.Z-npm.tar.gz` for offline mirroring. npm provenance is
   enabled with `npm publish --provenance`; it binds the package to this
   GitHub Actions workflow run through GitHub OIDC.

3. **crates.io** — every workspace crate without `publish = false`, in
   dependency order. See [Publishing to crates.io](#publishing-to-cratesio).

## Pre-release checklist

> **Homebrew tap status: not yet provisioned.** The
> `officialunofficial/homebrew-tap` repository will be created at or before the
> first public release. Until then, the Distribution step that targets that tap
> is skipped and `brew tap officialunofficial/tap` will fail.

Run top to bottom. Do not skip steps.

### Pre-tag

- [ ] `main` is green in CI (build + test).
- [ ] `cd rust && cargo test --workspace` passes on a fresh clone.
- [ ] `cargo build --release` passes for each release target:
  - [ ] `--target=aarch64-apple-darwin`
  - [ ] `--target=x86_64-apple-darwin`
  - [ ] `--target=x86_64-unknown-linux-gnu`
  - [ ] `--target=aarch64-unknown-linux-gnu`
- [ ] `[workspace.package].version` in `rust/Cargo.toml` is bumped to a version
      **not already published** (crates.io versions are immutable — a re-publish
      of an existing version fails the whole `cargo publish` run).
- [ ] `CHANGELOG.md` has an entry for this version; move items from
      `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] Version bumped wherever it is hard-coded (README install snippets,
      `contrib/homebrew/mkit.rb`).
- [ ] [Signing and verification](#signing-and-verification) and
      [Reproducibility](#reproducibility) still accurate for this release.
- [ ] `MKIT_RELEASE_GPG_FINGERPRINTS` repo/org Actions variable contains the
      release tag signing key fingerprint.
- [ ] The release tag signing public key is published to `keys.openpgp.org` or
      `keyserver.ubuntu.com` so the workflow can import it before
      `git verify-tag`.
- [ ] `SECURITY.md` disclosure contact confirmed reachable.

### Wait for the release workflows

- [ ] `release.yml` succeeded through `validate-release-tag` and all four
      platform builds.
- [ ] `crates-publish.yml` succeeded (every publishable crate indexed).
- [ ] GitHub Release created as a non-draft.
- [ ] Archives present:
      `mkit-X.Y.Z-aarch64-apple-darwin.tar.gz`,
      `mkit-X.Y.Z-x86_64-apple-darwin.tar.gz`,
      `mkit-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz`, and
      `mkit-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz`.
- [ ] `sbom.cdx.json` present.
- [ ] `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.crt`,
      `SHA256SUMS.cosign.bundle` present.
- [ ] Per-archive `.cosign.bundle` present for every archive.

### Smoke test

On at least one macOS and one Linux box:

- [ ] Download the archive for your platform.
- [ ] Verify the cosign signature (see [below](#verify-a-downloaded-archive)).
- [ ] Verify `SHA256SUMS` matches the archive.
- [ ] Extract and run `./mkit-X.Y.Z-<target>/mkit version` — version string
      matches the tag.
- [ ] Extracted archive contains `share/man/man1/mkit.1`,
      `share/completions/mkit.bash`, `share/completions/_mkit`, and
      `share/completions/mkit.fish`.
- [ ] Basic flow: `mkit init` → add a file → `mkit commit`.
- [ ] `npm view @makechain/mkit-wasm@X.Y.Z` and `npm audit signatures`.

### Distribution and announce

- [ ] If `officialunofficial/homebrew-tap` exists, copy
      `contrib/homebrew/mkit.rb` into `Formula/mkit.rb`, update the version, and
      replace every `PLACEHOLDER_SHA_*` with the matching archive hash from
      release `SHA256SUMS`.
- [ ] (If applicable) update Scoop manifest — deferred until Windows builds
      land.
- [ ] Release notes reviewed (auto-generated by `softprops/action-gh-release`
      plus the signing snippet).
- [ ] Pin the release in the repo sidebar; post in relevant channels.

### Post-release

- [ ] Open a PR bumping `CHANGELOG.md` with a fresh `## [Unreleased]` heading at
      the top.
- [ ] File follow-up issues for anything discovered during smoke test.

## Cutting a release

1. Land everything on `main`. Confirm CI is green.
2. Bump `[workspace.package].version` in `rust/Cargo.toml` (to a version not yet
   on crates.io). Update `CHANGELOG.md` (move `Unreleased` items into
   `[X.Y.Z] - YYYY-MM-DD`).
3. Open a release-prep PR, merge it.
4. Tag the merge commit on `main`:
   ```sh
   git tag -s vX.Y.Z -m "mkit X.Y.Z"
   git push origin vX.Y.Z
   ```
   Signed, annotated tags only. The signing key fingerprint must be listed in
   the `MKIT_RELEASE_GPG_FINGERPRINTS` repository or organization variable and
   its public key must be available from `keys.openpgp.org` or
   `keyserver.ubuntu.com`. Verify the exact fingerprint before pushing:
   ```sh
   git tag -v vX.Y.Z
   ```
   The release workflow rejects lightweight tags, invalid signatures,
   fingerprints not listed in `MKIT_RELEASE_GPG_FINGERPRINTS`, tags outside the
   strict `vX.Y.Z[-prerelease]` form, and tag targets not reachable from
   `origin/main`.
5. Watch the workflows. `release.yml` job order is:
   `validate-release-tag` → `build` (× 4 archs) → `sbom` → `release` →
   `publish-wasm`. `crates-publish.yml` runs `cargo publish --workspace
   --locked` in dependency order.
6. Run the [smoke test](#smoke-test).

## Publishing to crates.io

crates.io publishing is **tag-driven**, owned by
[`.github/workflows/crates-publish.yml`](../.github/workflows/crates-publish.yml).
On a pushed `v*.*.*` tag it runs `cargo publish --workspace --locked`, which
publishes every workspace member without `publish = false` to crates.io in
dependency order, waiting for each to index before the next. A guard refuses to
publish if the tag does not match the workspace version (`mkit-core`'s version
in `rust/Cargo.toml` at the tagged tree).

### What publishes vs. what doesn't

| Publishes to crates.io | Stays off crates.io (`publish = false`) |
|---|---|
| the library crates (`mkit-core`, `mkit-rpc`, `mkit-attest`, `mkit-keystore`, `mkit-git-bridge`, `mkit-transport-{file,http,memory,s3,ssh,enc}`) plus `mkit-cli` (so `cargo install mkit-cli` works) | `mkit-wasm` (npm-only), the contrib signers, `fuzz`, `benches` |

The published crates depend only on each other, forming a closed,
dependency-ordered set; `cargo publish --workspace` computes that order and
skips any `publish = false` member.

Notes on the published set:

- **`mkit-cli`** — published so `cargo install mkit-cli` installs the `mkit`
  binary; it also ships via the signed GitHub Release archives and `cargo
  install --git`. Its library surface is unstable CLI internals, deliberately
  **not** a public API — kept out of the pre-publish semver gate (the
  `cargo semver-checks` step in `crates-publish.yml`). Depend on the `mkit-*`
  library crates, not on `mkit_cli::…`.
- **The crates.io `mkit` name** belongs to an unrelated project; the CLI is
  published as **`mkit-cli`**. Do not run `cargo install mkit`.

### Token

`cargo publish` authenticates with the `CRATES_PACKAGE_KEY` **org-level** secret
(scopes: publish-new + publish-update), exposed to cargo as
`CARGO_REGISTRY_TOKEN`. A token (not trusted publishing) is required because
brand-new crates can't use trusted publishing on their first publish. The org
secret must grant this repo access, and its crates.io account must own the
crates (via the `makechain` team). Migrating to crates.io Trusted Publishing
(OIDC) to drop the long-lived token is a recommended follow-up.

> `release-plz` is left **inert** (`release_always = false` in
> `rust/release-plz.toml`); the config is kept only as a dormant
> `workflow_dispatch` escape hatch if versioning is ever handed back to it.

### Gotchas

- **Immutable versions**: crates.io never lets you overwrite a published
  version. Always bump before tagging; never re-publish an existing version.
- **Partial publish**: if a publish fails mid-train, the already-landed crates
  can't be re-published. Re-runs must `--exclude` what landed (edit the publish
  step or publish the remainder by hand).
- **Native deps**: `cargo publish` builds each crate with **default** features,
  so no `libpcsclite` is needed (`mkit-keystore`'s `backend-yubikey` is off by
  default); only `protoc` is required (installed in the workflow for
  `mkit-rpc`).

## Signing and verification

Every mkit release is signed with
[cosign](https://docs.sigstore.dev/cosign/overview/) using **keyless OIDC**: the
signing identity is the GitHub Actions workflow itself
(`.github/workflows/release.yml`), authenticated by GitHub's OIDC provider, and
every signature is recorded in the
[Rekor transparency log](https://docs.sigstore.dev/logging/overview/).

No artifact-signing private keys are held by any human or stored in GitHub
Secrets. Artifact signatures are keyless and bound to the artifact hash, so a
stolen release signature cannot be reused on any other artifact. The installer
(`install.sh`) enforces this same trust boundary by default.

### Artifacts attached to every release

For each of the four target archives, release archives build the production
`mkit-cli` target for that platform. The CLI enables the matching keystore
software-protector feature so `software` keys are encrypted at rest on supported
targets without changing the lean default feature set of the `mkit-keystore`
library crate.

| File | Purpose |
| --- | --- |
| `mkit-X.Y.Z-<triple>.tar.gz` | Binary, licenses, README, manpage, completions. |
| `...tar.gz.sha256` | SHA256 of the archive (convenience). |
| `...tar.gz.sig` | Raw cosign signature (base64). |
| `...tar.gz.crt` | Fulcio-issued code-signing certificate. |
| `...tar.gz.cosign.bundle` | Bundle: sig + cert + Rekor entry. |

Plus one top-level set for the aggregate:

| File | Purpose |
| --- | --- |
| `SHA256SUMS` | Hashes of every archive + SBOM. |
| `SHA256SUMS.{sig,crt,cosign.bundle}` | Cosign signature of `SHA256SUMS`. |
| `sbom.cdx.json` | CycloneDX SBOM of the release. |

### Verify a downloaded archive

Install cosign: <https://docs.sigstore.dev/cosign/installation/>. Then:

```sh
VERSION=0.3.0
TARGET=aarch64-apple-darwin
ARCHIVE="mkit-${VERSION}-${TARGET}.tar.gz"

cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "${ARCHIVE}.cosign.bundle" \
  "${ARCHIVE}"
```

Expected output: `Verified OK`. The `--certificate-identity-regexp` pins the
signature to a tag build of mkit's release workflow; a signature produced by any
other workflow (a fork, a branch build, a locally-run cosign) fails
verification.

The archive's sibling `.sha256` file is not an authenticity signal on its own
because it is served from the same origin as the archive. Treat it as
defense-in-depth after cosign, not instead of it.

### Inspect the Rekor transparency log entry

The `.cosign.bundle` contains a Rekor log index. To view the public entry, add
`--rekor-url "https://rekor.sigstore.dev"` to the `cosign verify-blob` command
above, or search by the archive's sha256 at
<https://search.sigstore.dev/?hash=sha256:DIGEST>.

### Verify the SBOM

The SBOM (`sbom.cdx.json`) is included in the top-level `SHA256SUMS`, which is
itself cosign-signed. The chain is:

1. Verify `SHA256SUMS.cosign.bundle` signs `SHA256SUMS` (cosign).
2. Verify `sbom.cdx.json`'s sha256 matches its entry in `SHA256SUMS`.

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle SHA256SUMS.cosign.bundle \
  SHA256SUMS

grep ' sbom.cdx.json$' SHA256SUMS > sbom.cdx.json.sha256
sha256sum -c sbom.cdx.json.sha256 || shasum -a 256 -c sbom.cdx.json.sha256
```

### macOS Gatekeeper

macOS binaries are **not Developer ID-signed and not notarized**. The trust
boundary is the cosign verification above, not Apple notarization. Users on
Ventura+ may see a Gatekeeper warning when launching a freshly-downloaded binary
from Finder. After you verify the archive, either run `mkit` from a terminal or
clear quarantine explicitly:

```sh
xattr -d com.apple.quarantine /path/to/mkit
```

If notarized macOS releases ever ship, the release notes and this document will
say so explicitly.

## Supply-chain policy

mkit's supply chain is intentionally narrow. The binary users run traces back to
a small, auditable set of inputs. This section is the contract.

### Current state

- **Rust dependencies:** fully pinned via `Cargo.lock`. Every transitive dep is
  hash-pinned on each release build. The workspace's direct deps are kept
  deliberately small — see `rust/Cargo.toml` and each crate's `[dependencies]`.
- **System libs:** default release builds link musl (Linux) or the platform C
  runtime (macOS). Optional keystore backend features may use platform services
  (Security.framework, Windows Credential Manager, D-Bus Secret Service, PC/SC,
  `systemd-creds`). These are off by default, platform-gated, and fail closed
  when the required service or device is unavailable. The Linux Secret Service
  feature selects the pure-Rust crypto runtime, not OpenSSL. Production
  `mkit-cli` builds enable the target-appropriate software protector feature so
  `software:<label>` stores encrypted records by default, while the
  `mkit-keystore` library keeps an empty default feature set.
- **Build inputs:** the Rust toolchain (pinned in `rust-toolchain.toml`), the
  source tree at a tagged Git commit, and the `--target=` / profile flags
  documented under [Reproducibility](#reproducibility).

### Adding a Rust dependency

Every new direct dependency added to a workspace `Cargo.toml` must:

1. Be **version-pinned** in `Cargo.toml` and reflected in `Cargo.lock`.
2. Have its source reviewed by **two maintainers** (sign-off in the PR).
3. Have a stated purpose — what does mkit gain, and what would implementing it
   in-tree cost? The default answer should be "implement in-tree"; deps are the
   exception.
4. Be compatible with **MIT OR Apache-2.0**. The CI dependency-review action
   denies GPL/LGPL families when the repo has Dependency Graph enabled and
   `ENABLE_DEPENDENCY_REVIEW=1`.
5. Have a cross-platform build. If the dep breaks on one of our four release
   targets, it doesn't land.

### Keystore backend dependency review

The optional keystore backend and envelope-encryption dependencies (issue #104)
were reviewed for the V1 keystore. All are pinned in `Cargo.toml`, reflected in
`Cargo.lock`, sourced from crates.io, accepted by `cargo deny`, and isolated
from default builds unless listed as always-on.

| Dependency | Use | Gate | License |
|---|---|---|---|
| `chacha20poly1305 = 0.10.1` | XChaCha20-Poly1305 software-key envelope encryption | always-on keystore crypto | Apache-2.0 OR MIT |
| `zeroize = 1.8.2` | Secret-memory clearing | always-on keystore crypto | Apache-2.0 OR MIT |
| `security-framework = 3.7.0` | macOS Keychain bindings | `backend-macos-keychain` (macOS only) | MIT OR Apache-2.0 |
| `keyring-core = 1.0.0` | Shared keyring abstraction | `backend-windows-credential`, `backend-linux-secret-service` | MIT OR Apache-2.0 |
| `windows-native-keyring-store = 1.0.0` | Windows Credential Manager store | `backend-windows-credential` (Windows only) | MIT OR Apache-2.0 |
| `zbus-secret-service-keyring-store = 1.0.0` | Linux Secret Service store | `backend-linux-secret-service` (Linux only; OpenSSL-free) | MIT OR Apache-2.0 |
| `card-backend-pcsc = 0.5.1` | PC/SC card discovery | `backend-yubikey` | MIT OR Apache-2.0 |
| `openpgp-card = 0.6.1` | OpenPGP card protocol | `backend-yubikey` | MIT OR Apache-2.0 |
| `secrecy = 0.10.3` | PIN handling wrappers | `backend-yubikey` | Apache-2.0 OR MIT |
| `der = 0.8.0` | DER parsing for PIV certs | `backend-yubikey` | Apache-2.0 OR MIT |
| `yubikey = 0.9.0-pre.0` | YubiKey PIV discovery + signing | `backend-yubikey` | BSD-2-Clause |

The `yubikey` prerelease is accepted because V1 PIV support needs mature PIV
APDUs and no stable alternative matched the API; risk is contained by optional
feature gating, existing-key-only support, fail-closed behavior, CI feature
builds, and manual hardware validation. Remaining direct support deps are
exact-pinned (`ed25519-dalek`, `getrandom`, `k256`, `p256`, `sha2`, `thiserror`,
dev-only `tempfile`).

`cargo deny check` finishes with `advisories ok, bans ok, licenses ok, sources
ok`. Remaining warnings are duplicate crate versions from ecosystem splits and
optional YubiKey/RustCrypto prerelease transitive stacks; they are tracked as
warnings, not release blockers, because they introduce no unapproved sources,
yanked crates, or denied licenses. Live OS-native keystore tests are opt-in via
`MKIT_RUN_NATIVE_KEYSTORE_TESTS=1`.

### GitHub Actions dependencies

All third-party actions in `.github/workflows/` must be pinned to a major
version tag (`@v4`) or a full SHA. No `@main`, no `@latest`. Trusted publishers:
`actions/*`, `dtolnay/rust-toolchain`, `sigstore/cosign-installer`,
`anchore/sbom-action`, `softprops/action-gh-release`, `ossf/scorecard-action`.
Any new action from an untrusted publisher needs the same two-maintainer review
as a Rust dep.

### Release artifact integrity, SBOM lifecycle, vulnerability response

Every release archive is **hashed** (per-archive `SHA256SUMS`), **signed**
(cosign keyless OIDC, tied to this repo's release workflow identity), **logged**
in the public Rekor transparency log, and **inventoried** in a CycloneDX SBOM.
Package-manager manifests must reference the GitHub Releases archive URL directly
(never a re-hosted copy); the `sha256` in the manifest is the authoritative pin.

A fresh SBOM is generated on every tagged release; a weekly cron
(`supply-chain.yml`) regenerates the SBOM for `main` to catch drift from indirect
sources. A CVE against any dep we ship is a P1: patch, test, tag a new release,
open a GitHub Security Advisory citing the CVE, update `CHANGELOG.md` under
`### Security`, and coordinate disclosure via the `SECURITY.md` contact.

## Reproducibility

A mkit release binary is a function of a small, pinned set of inputs. If all of
them match, any machine that can run the same Rust toolchain will produce a
byte-identical binary to the one published on GitHub Releases.

### The inputs

1. **Rust toolchain version** — pinned in `rust-toolchain.toml`; the workflow
   installs it verbatim.
2. **Target triple** — one of the four release triples, passed as
   `--target=<triple>`.
3. **Build profile** — `release`.
4. **Source tree hash** — the Git commit the tag points at; every source file is
   tracked in Git.
5. **Dependency fingerprint** — `Cargo.lock`, fully pinning every transitive
   dependency. Any `cargo update` is a visible change to that file.

### Reproducing a published binary

```sh
# 1. Clone at the release tag.
git clone --depth 1 --branch vX.Y.Z https://github.com/officialunofficial/mkit.git
cd mkit
# 2. rustup picks up rust-toolchain.toml on first `cargo` invocation.
# 3. Build for your target.
cargo build --release --manifest-path rust/Cargo.toml --bin mkit
# 4. Hash the binary.
shasum -a 256 rust/target/release/mkit
# 5. Compare against SHA256SUMS from the GitHub Release.
```

If the hashes don't match, treat it as a supply-chain incident: open an issue
with your host OS, `rustc --version`, the sha256 you got, and the expected one.
`diffoscope` on the two binaries usually isolates the culprit.

### CI safety net and what is not guaranteed

`.github/workflows/reproducible-build.yml` builds mkit twice on the same commit
and fails if the outputs diverge (it runs on every source-touching PR and weekly
on `main`). A failure means a non-deterministic input has crept in (embedded
timestamps, random seeds, absolute paths in debug info, unsorted directory
reads) and must be fixed before the next tag.

Binaries built on your local macOS are not expected to match GitHub's `macos-14`
runner byte-for-byte unless your OS, SDK, and linker versions match. The Linux
x86_64 build is the most reliable reproducibility target for third parties.

## Required GitHub Actions secrets and variables

| Secret | Purpose | Required for |
| --- | --- | --- |
| `CRATES_PACKAGE_KEY` (org-level) | crates.io publish token (publish-new + publish-update) | `crates-publish.yml` |
| `MKIT_NPM_TOKEN` | npm publish auth (Automation token, 2FA-bypass) | `publish-wasm` |
| `CODECOV_TOKEN` | Codecov upload auth (required while repo is private; tokenless OIDC once public) | `coverage.yml` |
| `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | macOS notarization | macOS archives (gated; no-op until set) |

cosign keyless and npm provenance both run on the GitHub OIDC token; no extra
secrets are needed for those.

| Variable | Purpose | Required for |
| --- | --- | --- |
| `MKIT_RELEASE_GPG_FINGERPRINTS` | Space-separated trusted 40-hex GPG fingerprints allowed to sign release tags (public keys must be on `keys.openpgp.org` or `keyserver.ubuntu.com`) | `release.yml` preflight |

## One-time setup

### `CRATES_PACKAGE_KEY`

Generate a crates.io API token (scopes: publish-new + publish-update) on an
account that owns the `mkit-*` crates (via the `makechain` team), and add it as
an **org-level** secret named `CRATES_PACKAGE_KEY` with this repo granted access.
For the very first publish, ensure each crate name is available or already owned
by the org; crates.io rejects deps on unpublished crates, so the dependency-order
publish in `crates-publish.yml` handles a clean first release once the token and
version are in place.

### `CODECOV_TOKEN`

Codecov receives the lcov report from `coverage.yml` so the README badge, trend
chart, and PR-diff overlay work.

1. Sign in at <https://app.codecov.io/> with the GitHub account that admins the
   `officialunofficial` org.
2. Add the `officialunofficial/mkit` repo; copy the "Upload token".
3. In GitHub: `Settings → Secrets and variables → Actions → New repository
   secret`. Name `CODECOV_TOKEN`, value the token from step 2.
4. Trigger `coverage.yml` (push to main, or `gh workflow run coverage.yml`). The
   first run seeds the baseline; subsequent runs populate the badge.
5. Once the repo flips public, remove the secret — Codecov accepts tokenless
   uploads from public repos via GitHub OIDC.

### `MKIT_NPM_TOKEN`

`@makechain/mkit-wasm` is the npm package published by the release workflow.

1. **Create an npm org / user.** The package publishes under the account that
   owns `MKIT_NPM_TOKEN`. Recommended: a machine account or a maintainer account
   with the package in a 2FA-protected org.
2. **Generate an Automation token** (`npmjs.com → Access Tokens`). Required
   scope: `read+write` on `@makechain/mkit-wasm`. Automation tokens bypass the
   2FA OTP prompt that would otherwise block CI.
3. **Add to GitHub repo secrets:** name `MKIT_NPM_TOKEN`, value the token.
4. **Claim the package name (one-time).** Until the first successful
   `npm publish`, `@makechain/mkit-wasm` is unclaimed. Either cut a real tag (the
   workflow publishes), or publish a placeholder once from a maintainer
   workstation:
   ```sh
   cd rust
   wasm-pack build crates/mkit-wasm --release --target bundler --out-dir pkg
   cd crates/mkit-wasm/pkg
   npm version --no-git-tag-version --allow-same-version 0.0.0-init
   npm publish --access public
   ```
5. Verify with `npm view @makechain/mkit-wasm` after the first publish.

**Future work: migrate to npm
[Trusted Publishers (OIDC)](https://docs.npmjs.com/trusted-publishers)** so the
`publish-wasm` job authenticates via the GitHub Actions OIDC token directly — no
`MKIT_NPM_TOKEN` to rotate, leak, or revoke. Configure the repo + `release.yml`
workflow under the package's Publishing access settings, drop the
`NODE_AUTH_TOKEN` env on the publish step, delete the secret, and cut a patch
release to validate. Defer until after at least one successful token-based
release.

### Package name decision

The Rust crate remains `mkit-wasm`, but the release workflow publishes the npm
package as `@makechain/mkit-wasm` so ownership and token scope live under the
Makechain npm organization. If the scope ever changes, update
`rust/crates/mkit-wasm/README.md`'s install snippet, the `publish-wasm` workflow
`npm pkg set name=...` line, and the `npm view` smoke-test references in this
doc.
