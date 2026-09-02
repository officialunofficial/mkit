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

A single `vX.Y.Z` tag drives four decoupled channels:

- **Binaries plus npm wasm** via
  [`.github/workflows/release.yml`](../.github/workflows/release.yml).
- **crates.io** via
  [`.github/workflows/crates-publish.yml`](../.github/workflows/crates-publish.yml).
- **Docs MCP corpus** via
  [`.github/workflows/mcp-release.yml`](../.github/workflows/mcp-release.yml),
  which indexes the tagged tree for the mkit docs MCP server so the served
  corpus always matches the published crates.
- **BSR proto modules** (`buf.build/officialunofficial/mkit-rpc` and
  `buf.build/officialunofficial/mkit-repo`) via the `buf-push` job in
  [`.github/workflows/crates-publish.yml`](../.github/workflows/crates-publish.yml),
  so third-party signer integrators and `RepoService` clients can `buf
  generate` typed bindings from a pinned tag without vendoring this repo.
  Dormant until [`BUF_TOKEN`](#buf_token) is provisioned.

All are gated on the same signed tag. Before `release.yml` publishes anything,
it verifies that the tag is strict semver, annotated, GPG-signed by an
allowlisted release fingerprint, and points at a commit reachable from
`origin/main`. It then produces:

1. **GitHub Release** with native binaries for five targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`
   - `x86_64-pc-windows-msvc` (`.zip`, `mkit.exe`, `backend-windows-credential`
     keystore feature enabled &mdash; see [Artifacts attached to every
     release](#artifacts-attached-to-every-release))

   Each archive contains the `mkit`/`mkit.exe` binary, licenses, README,
   optional changelog, `share/man/man1/mkit.1`, and shell completions under
   `share/completions/`. Each archive is cosign-signed (keyless OIDC, Rekor
   logged) and ships alongside per-archive `.sig`/`.crt`/`.cosign.bundle`, an
   aggregate `SHA256SUMS` (also cosign-signed), a CycloneDX `sbom.cdx.json`,
   a `THIRD-PARTY-NOTICES` file, and a standards-based SLSA build provenance
   attestation (`actions/attest-build-provenance`), verifiable with `gh
   attestation verify` or `slsa-verifier` in addition to cosign.

2. **npm package** `@officialunofficial/mkit-wasm@X.Y.Z`. Built with
   `wasm-pack --target bundler` and published with `npm publish --access
   public`. The pkg tarball is also attached to the GitHub Release as
   `mkit-wasm-X.Y.Z-npm.tar.gz` for offline mirroring. npm provenance is
   enabled with `npm publish --provenance`; it binds the package to this
   GitHub Actions workflow run through GitHub OIDC.

3. **crates.io** &mdash; every workspace crate without `publish = false`, in
   dependency order. See [Publishing to crates.io](#publishing-to-cratesio).

## Pre-release checklist

> **Homebrew tap status: provisioned, no formula yet.** The
> `officialunofficial/homebrew-tap` repository exists and is public, but holds
> only LICENSE plus README &mdash; there is no `Formula/` directory, so `brew install`
> fails until a formula is pushed. The Distribution step that targets the tap
> is live and expected to be performed at the next release.
>
> **Scoop bucket status: not yet provisioned.** Unlike the Homebrew tap,
> `officialunofficial/scoop-bucket` does not exist yet &mdash; creating it (empty
> bucket repo, then `bucket/mkit.json` from `contrib/scoop/mkit.json`) is
> part of the Distribution step below, same pattern as the Homebrew tap's
> initial setup.

Run top to bottom. Do not skip steps.

### Pre-tag

- [ ] `main` is green in CI (build plus test).
- [ ] `cd rust && cargo test --workspace` passes on a fresh clone.
- [ ] `cargo build --release` passes for each release target:
  - [ ] `--target=aarch64-apple-darwin`
  - [ ] `--target=x86_64-apple-darwin`
  - [ ] `--target=x86_64-unknown-linux-gnu`
  - [ ] `--target=aarch64-unknown-linux-gnu`
  - [ ] `--target=x86_64-pc-windows-msvc` (requires a Windows host or the
        `windows-latest` CI runner &mdash; cross-compiling this target isn't
        possible here, same reasoning as the `keystore-backends` matrix in
        `rust.yml`: `windows-native-keyring-store` is `cfg(windows)`-gated)
- [ ] `[workspace.package].version` in `rust/Cargo.toml` is bumped to a version
      **not already published** (crates.io versions are immutable &mdash; a re-publish
      of an existing version fails the whole `cargo publish` run).
- [ ] `CHANGELOG.md` has an entry for this version; move items from
      `## [Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`.
- [ ] Version bumped wherever it is hard-coded: README install snippets,
      `contrib/homebrew/mkit.rb`, `docs/INSTALL.md` (three sites: two
      `VERSION=` snippets and the expected `mkit version` output), and the
      `vX.Y.Z` examples in `install.sh` usage text.
- [ ] [Signing and verification](#signing-and-verification) and
      [Reproducibility](#reproducibility) still accurate for this release.
- [ ] `MKIT_RELEASE_GPG_FINGERPRINTS` repo/org Actions variable contains the
      release tag signing key fingerprint.
- [ ] The release tag signing public key is published to `keys.openpgp.org` or
      `keyserver.ubuntu.com` so the workflow can import it before
      `git verify-tag`.
- [ ] `SECURITY.md` disclosure contact confirmed reachable.
- [ ] Manually dispatch `rust.yml`'s `keystore-backends` job
      (`gh workflow run rust.yml --ref main`) and confirm all three legs
      (Linux Secret Service+systemd-creds+YubiKey, macOS Keychain+YubiKey,
      Windows Credential Manager) succeed. It stays `workflow_dispatch`-only
      (3-OS matrix cost) and is not exercised by any automatic trigger, so this
      is the only per-release check that native keystore backends still work.

### Wait for the release workflows

- [ ] `release.yml` succeeded through `validate-release-tag` and all five
      platform builds.
- [ ] `crates-publish.yml` succeeded (every publishable crate indexed).
- [ ] `mcp-release.yml` succeeded (docs MCP corpus indexed for the tag).
- [ ] GitHub Release created as a non-draft.
- [ ] Archives present:
      `mkit-X.Y.Z-aarch64-apple-darwin.tar.gz`,
      `mkit-X.Y.Z-x86_64-apple-darwin.tar.gz`,
      `mkit-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz`,
      `mkit-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz`, and
      `mkit-X.Y.Z-x86_64-pc-windows-msvc.zip`.
- [ ] `sbom.cdx.json` present.
- [ ] `THIRD-PARTY-NOTICES` present.
- [ ] `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.crt`,
      `SHA256SUMS.cosign.bundle` present.
- [ ] Per-archive `.cosign.bundle` present for every archive (including the
      `.zip`).
- [ ] `mkit-X.Y.Z.provenance.jsonl` (SLSA build provenance) present, and
      `gh attestation verify <archive> --repo officialunofficial/mkit`
      succeeds for at least one archive (including the `.zip`).

### Smoke test

On at least one Linux box, one macOS box, and one Windows box (or
`windows-latest` via `gh workflow run`), download the archive for your
platform, then run the mechanized checklist below instead of the steps by
hand:

```sh
# Linux / macOS
scripts/release-smoke.sh --archive mkit-X.Y.Z-<target>.tar.gz --version X.Y.Z
```

```powershell
# Windows
.\scripts\release-smoke.ps1 -Archive mkit-X.Y.Z-x86_64-pc-windows-msvc.zip -Version X.Y.Z
```

The script covers every item below in one pass **except** the "Windows
only" `install.ps1` one-liner check, which still needs to be run by hand
against a fresh PowerShell session: cosign signature, the `SHA256SUMS`
entry, `mkit version`/`mkit.exe version` against the tag, the bundled man
page and completions, a basic `mkit init` → `mkit keygen` → add a file →
`mkit commit` flow, and (unless `--skip-npm`/`-SkipNpm`) `npm view
@officialunofficial/mkit-wasm@X.Y.Z` plus `npm audit signatures`. It's the same
script used for a pre-flight dry run against a locally packaged archive
before tagging (missing sidecars like the cosign bundle are skipped with a
warning, not a failure, in that case) &mdash; this checklist is the spec of
record the script implements, so if the two ever disagree, fix the script:

- [ ] Download the archive for your platform.
- [ ] Verify the cosign signature (see [below](#verify-a-downloaded-archive)).
- [ ] Verify `SHA256SUMS` matches the archive.
- [ ] Extract and run `./mkit-X.Y.Z-<target>/mkit version` (Linux/macOS) or
      `.\mkit-X.Y.Z-x86_64-pc-windows-msvc\mkit.exe version` (Windows) &mdash;
      version string matches the tag.
- [ ] Extracted archive contains `share/man/man1/mkit.1`,
      `share/completions/mkit.bash`, `share/completions/_mkit`, and
      `share/completions/mkit.fish`.
- [ ] Basic flow: `mkit init` → add a file → `mkit commit`.
- [ ] Windows only: `irm https://mkit.sh/install.ps1 | iex` installs
      `mkit.exe` and `mkit version` runs from a fresh PowerShell session.
- [ ] `npm view @officialunofficial/mkit-wasm@X.Y.Z` and `npm audit signatures`.

### Distribution and announce

- [ ] In `officialunofficial/homebrew-tap`, copy `contrib/homebrew/mkit.rb`
      into `Formula/mkit.rb`, update the version, and replace every
      `PLACEHOLDER_SHA_*` with the matching archive hash from release
      `SHA256SUMS`.
- [ ] In `officialunofficial/scoop-bucket` (create the bucket repo if it
      doesn't exist yet &mdash; same pattern as `homebrew-tap`), copy
      `contrib/scoop/mkit.json` into `bucket/mkit.json`, update `version`
      and `url`, and replace `PLACEHOLDER_SHA_X86_64_PC_WINDOWS_MSVC` with
      the `x86_64-pc-windows-msvc.zip` hash from release `SHA256SUMS`.
- [ ] Release notes reviewed (auto-generated by `softprops/action-gh-release`
      plus the signing snippet).
- [ ] Pin the release in the repo sidebar; post in relevant channels.
- [ ] Once the Homebrew/Scoop steps above are done, dispatch
      [`release-verify.yml`](../.github/workflows/release-verify.yml)
      (`gh workflow run release-verify.yml -f version=X.Y.Z`) to check
      every distribution channel end to end in an isolated environment —
      `cargo install`, `cargo binstall`, npm, the curl-pipe install
      script (Debian/Ubuntu/Fedora), Homebrew, and Scoop (including the
      Windows `install.ps1` one-liner). Not a substitute for the smoke
      test above (which verifies the archive itself); this verifies every
      OTHER way a user actually gets `mkit` onto their machine.

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
   `validate-release-tag` → `build` (× 4 archs) → `sbom` / `third-party-notices`
   (parallel) → `release` → `publish-wasm`. `crates-publish.yml` runs `cargo
   publish --workspace --locked` in dependency order.
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
| the library crates (`mkit-core`, `mkit-rpc`, `mkit-attest`, `mkit-keystore`, `mkit-git-bridge`, `mkit-transport-{file,http,memory,s3,ssh,enc}`) plus `mkit-cli` (so `cargo install mkit-cli` works) | `mkit-wasm` (npm-only), `mkit-repo-client`, `mkit-test-util`, `fuzz`, `benches`. The contrib signers are a separate workspace under `contrib/signers/` (not workspace members at all). |

The published crates depend only on each other, forming a closed,
dependency-ordered set; `cargo publish --workspace` computes that order and
skips any `publish = false` member.

Notes on the published set:

- **`mkit-cli`** &mdash; published so `cargo install mkit-cli` installs the `mkit`
  binary; it also ships via the signed GitHub Release archives and `cargo
  install --git`. Its library surface is unstable CLI internals, deliberately
  **not** a public API &mdash; kept out of the pre-publish semver gate (the
  `cargo semver-checks` step in `crates-publish.yml`). Depend on the `mkit-*`
  library crates, not on `mkit_cli::…`.
- **The crates.io `mkit` name** belongs to an unrelated project; the CLI is
  published as **`mkit-cli`**. Do not run `cargo install mkit`.

### Token

`cargo publish` authenticates with the `CRATES_PACKAGE_KEY` **org-level** secret
(scopes: publish-new plus publish-update), exposed to cargo as
`CARGO_REGISTRY_TOKEN`. A token (not trusted publishing) is required because
brand-new crates can't use trusted publishing on their first publish. The org
secret must grant this repo access, and its crates.io account must own the
crates (via the `makechain` team). Migrating to crates.io Trusted Publishing
(OIDC) to drop the long-lived token is a recommended follow-up.

> Both jobs in `.github/workflows/release-plz.yml` (`release-plz-release`,
> `release-plz-pr`) are `workflow_dispatch`-only, gated on the repo variable
> `RELEASE_PLZ_ENABLED == 'true'` (currently true). Neither runs on push.
>
> This used to be different: `release-plz-release` ran on every push to
> `main`, on the assumption that `release_always = false` in
> `rust/release-plz.toml` would always no-op it ("commit is not from a
> release PR"). That assumption broke on the v0.4.2 release (2026-09-02):
> the mkit-release skill's own procedure merges release-plz's own PR as the
> release-prep PR, and release-plz recognized that merge commit as a real
> release and actually ran `cargo publish` for every crate — racing (and
> mostly winning against) the tag-driven `crates-publish.yml` publish, which
> then failed with a harmless-but-confusing "already exists" error. The push
> trigger was removed for this reason: `crates-publish.yml` is the sole real
> publish path, and this job must never fire on its own.

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

Cosign signatures are keyless and bound to the artifact hash, so a stolen
release signature cannot be reused on any other artifact. The installer
(`install.sh`) enforces this same trust boundary by default.

### Artifacts attached to every release

For each of the five target archives, release archives build the production
`mkit-cli` target for that platform. The CLI enables the matching keystore
software-protector feature so `software` keys are encrypted at rest on supported
targets without changing the lean default feature set of the `mkit-keystore`
library crate. On Windows the CLI additionally enables the native
`backend-windows-credential` keystore backend unconditionally (via
`mkit-cli`'s `[target.'cfg(windows)'.dependencies]`), matching the
`windows-credential` leg of `rust.yml`'s `keystore-backends` matrix.

| File | Purpose |
| --- | --- |
| `mkit-X.Y.Z-<triple>.tar.gz` (Linux/macOS) or `.zip` (Windows) | Binary, licenses, README, manpage, completions. |
| `...sha256` | SHA256 of the archive (convenience). |
| `...sig` | Raw cosign signature (base64). |
| `...crt` | Fulcio-issued code-signing certificate. |
| `...cosign.bundle` | Bundle: sig plus cert plus Rekor entry. |

The Windows archive is not Authenticode-signed (no code-signing
certificate); trust is the cosign signature above, same as every other
target.

Plus one top-level set for the aggregate:

| File | Purpose |
| --- | --- |
| `SHA256SUMS` | Hashes of every archive plus SBOM plus notices. |
| `SHA256SUMS.{sig,crt,cosign.bundle}` | Cosign signature of `SHA256SUMS`. |
| `sbom.cdx.json` | CycloneDX SBOM of the release. |
| `THIRD-PARTY-NOTICES` | Consolidated third-party license attribution for the Rust dependency graph, generated by `cargo about generate` (see [`NOTICE`](../NOTICE)). |
| `mkit-X.Y.Z.provenance.jsonl` | GitHub-native SLSA build provenance attestation (`actions/attest-build-provenance`) over the archives. Verified with `gh attestation verify` or `slsa-verifier`. |

### Verify a downloaded archive

Install cosign: <https://docs.sigstore.dev/cosign/installation/>. Then:

```sh
VERSION=X.Y.Z
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

### Verify THIRD-PARTY-NOTICES

`THIRD-PARTY-NOTICES` is generated by `cargo about generate` (config:
`rust/about.toml` plus `rust/about.hbs`) from the `rust` workspace's resolved
dependency graph, and is covered by the same `SHA256SUMS` chain as the SBOM:

```sh
grep ' THIRD-PARTY-NOTICES$' SHA256SUMS > THIRD-PARTY-NOTICES.sha256
sha256sum -c THIRD-PARTY-NOTICES.sha256 || shasum -a 256 -c THIRD-PARTY-NOTICES.sha256
```

`cargo about generate` fails the `third-party-notices` job outright if any
dependency's license isn't in `rust/about.toml`'s `accepted` list &mdash; that list
is kept in lockstep with `rust/deny.toml`'s `[licenses] allow` list (the
license check cargo-deny already runs on every PR via `cloudbuild/security.yaml`).
`.github/workflows/third-party-notices.yml` runs the same `cargo about
generate` check on every PR that touches the dependency graph, so an
unapproved license is caught before a release attempt, not during one.

### Verify the SLSA build provenance attestation

Every archive also carries a standard
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation,
generated by [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
and recorded in the Sigstore public-good transparency log. Unlike the cosign
signature above (an mkit-specific verification path), this attestation is
checkable with off-the-shelf, standards-aware tooling and requires no
mkit-specific parsing:

```sh
gh attestation verify mkit-X.Y.Z-<target>.tar.gz --repo officialunofficial/mkit
```

or with [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier):

```sh
slsa-verifier verify-artifact mkit-X.Y.Z-<target>.tar.gz \
  --provenance-path mkit-X.Y.Z.provenance.jsonl \
  --source-uri github.com/officialunofficial/mkit \
  --source-tag vX.Y.Z
```

This is additive: it does not replace the cosign signature, which remains in
place and is independently verified above.

### macOS Gatekeeper

macOS binaries are **not Developer ID-signed and not notarized**. The trust
boundary is the cosign verification above, not Apple notarization. Users on
Ventura+ may see a Gatekeeper warning when launching a freshly-downloaded binary
from Finder. After you verify the archive, either run `mkit` from a terminal or
clear quarantine explicitly:

```sh
xattr -d com.apple.quarantine /path/to/mkit
```

Notarization is future work: `release.yml` has no notarization step today
(only a placeholder comment). When it is wired, it will authenticate with
`APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, and `APPLE_TEAM_ID` secrets. If
notarized macOS releases ever ship, the release notes and this document will
say so explicitly.

## Supply-chain policy

mkit's supply chain is intentionally narrow. The binary users run traces back to
a small, auditable set of inputs. This section is the contract.

### Current state

- **Rust dependencies:** fully pinned via `Cargo.lock`. Every transitive dep is
  hash-pinned on each release build. The workspace's direct deps are kept
  deliberately small &mdash; see `rust/Cargo.toml` and each crate's `[dependencies]`.
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
3. Have a stated purpose &mdash; what does mkit gain, and what would implementing it
   in-tree cost? The default answer should be "implement in-tree"; deps are the
   exception.
4. Be compatible with **MIT OR Apache-2.0**. The CI dependency-review action
   denies GPL/LGPL families when the repo has Dependency Graph enabled and
   `ENABLE_DEPENDENCY_REVIEW=1`.
5. Have a cross-platform build. If the dep breaks on one of the four release
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
| `yubikey = 0.9.0-pre.0` | YubiKey PIV discovery plus signing | `backend-yubikey` | BSD-2-Clause |

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

A fresh SBOM is generated at release time only (the `sbom` job in
`release.yml`); there is **no** scheduled SBOM regeneration for `main`. The
weekly cadence is `cargo audit` via `rust-security.yml` (Mondays 06:00 UTC),
which sweeps for newly published advisories against the unchanged dependency
tree. Restoring a scheduled SBOM-drift job is an open follow-up. A CVE against
any shipped dep is a P1: patch, test, tag a new release,
open a GitHub Security Advisory citing the CVE, update `CHANGELOG.md` under
`### Security`, and coordinate disclosure via the `SECURITY.md` contact.

## Reproducibility

A mkit release binary is a function of a small, pinned set of inputs. If all of
them match, any machine that can run the same Rust toolchain will produce a
byte-identical binary to the one published on GitHub Releases.

### The inputs

1. **Rust toolchain version** &mdash; pinned in `rust-toolchain.toml`; the workflow
   installs it verbatim.
2. **Target triple** &mdash; one of the five release triples, passed as
   `--target=<triple>`.
3. **Build profile** &mdash; `release`.
4. **Source tree hash** &mdash; the Git commit the tag points at; every source file is
   tracked in Git.
5. **Dependency fingerprint** &mdash; `Cargo.lock`, fully pinning every transitive
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

There is currently **no** automated reproducibility check: no CI job builds
mkit twice and compares the outputs. The manual procedure above is the
verification path. Restoring an automated double-build job is an open
follow-up. A divergence between two builds of the same commit means a
non-deterministic input has crept in (embedded timestamps, random seeds,
absolute paths in debug info, unsorted directory reads) and must be fixed
before the next tag.

Binaries built on your local macOS are not expected to match GitHub's `macos-14`
runner byte-for-byte unless your OS, SDK, and linker versions match. The Linux
x86_64 build is the most reliable reproducibility target for third parties.
Windows (`x86_64-pc-windows-msvc`) additionally embeds a PDB path and MSVC
linker/toolset version into the binary, so byte-identical reproduction there
also requires matching Visual Studio Build Tools versions &mdash; treat it as even
less reliable than the macOS case until that's verified.

## Required GitHub Actions secrets and variables

| Secret | Purpose | Required for |
| --- | --- | --- |
| `CRATES_PACKAGE_KEY` (org-level) | crates.io publish token (publish-new plus publish-update) | `crates-publish.yml` |
| `CODECOV_TOKEN` | Codecov upload auth &mdash; **vestigial**: no GitHub workflow reads it. Coverage runs on Cloud Build (`cloudbuild/coverage.yaml`); the live token is the GCP Secret Manager copy | &mdash; (see [`CODECOV_TOKEN`](#codecov_token)) |
| `BUF_TOKEN` | Buf Schema Registry API token (write access) &mdash; pushes the `mkit-rpc`/`mkit-repo` proto modules | `crates-publish.yml`'s `buf-push` job (see [`BUF_TOKEN`](#buf_token)) |

cosign keyless and npm Trusted Publishing (auth plus provenance) both run on
the GitHub OIDC token; no extra secrets are needed for those.

| Variable | Purpose | Required for |
| --- | --- | --- |
| `MKIT_RELEASE_GPG_FINGERPRINTS` | Space-separated trusted 40-hex GPG fingerprints allowed to sign release tags (public keys must be on `keys.openpgp.org` or `keyserver.ubuntu.com`) | `release.yml` preflight |
| `BUF_PUBLISH_ENABLED` | Set to `true` to arm the `buf-push` job (job-level `if:` cannot read `secrets`, so this variable &mdash; not `BUF_TOKEN`'s presence &mdash; is the gate) | `crates-publish.yml`'s `buf-push` job |

## One-time setup

### `CRATES_PACKAGE_KEY`

Generate a crates.io API token (scopes: publish-new plus publish-update) on an
account that owns the `mkit-*` crates (via the `makechain` team), and add it as
an **org-level** secret named `CRATES_PACKAGE_KEY` with this repo granted access.
For the very first publish, ensure each crate name is available or already owned
by the org; crates.io rejects deps on unpublished crates, so the dependency-order
publish in `crates-publish.yml` handles a clean first release once the token and
version are in place.

### `CODECOV_TOKEN`

Codecov receives the lcov report from the Cloud Build coverage build
(`cloudbuild/coverage.yaml`, trigger `mkit-coverage-main`) so the README badge,
trend chart, and PR-diff overlay work. The live token lives in **GCP Secret
Manager**, not GitHub: no GitHub workflow reads `CODECOV_TOKEN` anymore, so the
GitHub Actions secret of the same name is vestigial and safe to delete.

1. Sign in at <https://app.codecov.io/> with the GitHub account that admins the
   `officialunofficial` org.
2. Add the `officialunofficial/mkit` repo; copy the "Upload token".
3. Store it as the `CODECOV_TOKEN` secret in GCP Secret Manager and grant the
   Cloud Build service account access (`cloudbuild/coverage.yaml` mounts
   `projects/${PROJECT_ID}/secrets/CODECOV_TOKEN/versions/latest`). The upload
   is optional: if the secret is absent, the upload step is skipped and the
   report is still produced and logged.
4. Trigger a run: push to `main` (`mkit-coverage-main` fires on push to `main`
   only). The first run seeds the baseline; subsequent runs populate the badge.
5. Once the repo flips public, Codecov accepts tokenless uploads from public
   repos via GitHub OIDC &mdash; but that applies to GitHub Actions uploads, not
   Cloud Build, so the Secret Manager token stays.

### npm Trusted Publishing (OIDC) — `@officialunofficial/mkit-wasm`

`@officialunofficial/mkit-wasm` is the npm package published by the release
workflow, under the `officialunofficial` npm org (matching the GitHub org —
renamed from the earlier `@makechain/mkit-wasm` once the repo went public).
`publish-wasm` authenticates via the GitHub Actions OIDC token directly (npm
[Trusted Publishers](https://docs.npmjs.com/trusted-publishers)) &mdash; there is
**no `MKIT_NPM_TOKEN`-equivalent secret to provision, rotate, leak, or
revoke** for the automated path. This replaced the original
Automation-token setup once the package had at least one successful
token-based release behind it (0.1.0&ndash;0.3.0, published as
`@makechain/mkit-wasm`).

**One-time setup (npmjs.com, by an owner of the `officialunofficial` org):**

1. If `@officialunofficial/mkit-wasm` has never been published, either cut a
   real tag (the workflow's first successful OIDC-authenticated publish
   claims the name) or publish a placeholder once from a maintainer
   workstation with a personal token:
   ```sh
   cd rust
   wasm-pack build crates/mkit-wasm --release --target bundler --out-dir pkg
   cd crates/mkit-wasm/pkg
   npm pkg set name=@officialunofficial/mkit-wasm
   npm version --no-git-tag-version --allow-same-version 0.0.0-init
   npm publish --access public --tag init
   ```
   `wasm-pack`'s raw output is named unscoped `mkit-wasm`, hence the `npm pkg
   set` step. `--tag init` keeps the placeholder off the `latest` dist-tag
   once a real version publishes (it briefly holds `latest` too, being the
   only version, until the first real tag push supersedes it).

   The npm registry's CDN edge cache can serve a stale 404 for a
   brand-new scope/package for a few minutes after a successful publish,
   even though `npm dist-tag ls`, `npm access list packages`, and
   `npm install` (corgi-format endpoint) already see it — don't diagnose a
   fresh publish as failed from a bare `npm view`/`curl` 404, and don't
   re-query the same URL repeatedly (it just refreshes the negative-cache
   TTL). Wait a few minutes and recheck.
2. On the package's `npmjs.com` page &rarr; **Settings** &rarr; **Trusted
   Publisher**, add a GitHub Actions publisher:
   - Organization or user: `officialunofficial`
   - Repository: `mkit`
   - Workflow filename: `release.yml` (filename only, not the full
     `.github/workflows/` path)
   - Environment: leave blank (the job doesn't use a GitHub environment)
   - Allowed actions: `npm publish`
3. Verify with `npm view @officialunofficial/mkit-wasm` after the first
   OIDC-authenticated publish; confirm provenance with `npm audit
   signatures`.

Requires npm CLI &ge;11.5.1 (the workflow pins this explicitly) and
GitHub-hosted runners (self-hosted runners aren't supported for Trusted
Publishing as of this writing).

### `BUF_TOKEN`

`buf.build/officialunofficial/mkit-rpc` (common.proto/signer.proto/ssh.proto/
verify.proto, from the `rust/crates/mkit-rpc/proto` module) and
`buf.build/officialunofficial/mkit-repo` (repo.proto, from the
`apps/repo-worker/proto` module) are the two named modules in the repo-root
`buf.yaml` v2 workspace that the `buf-push` job in `crates-publish.yml`
publishes on every tagged release (issue #719). Both are pushed **private** &mdash;
`signer.proto` is the security-critical external-signer wire contract
([SPEC-EXTERNAL-SIGNER.md](specs/SPEC-EXTERNAL-SIGNER.md)) and `repo.proto` is
this repo's internal `RepoService` contract; flip a module to public only as a
deliberate decision, not a default.

1. Sign in (or create an account) at <https://buf.build/> under the
   `officialunofficial` organization. **The BSR org name is assumed to match
   the GitHub org (`officialunofficial`) &mdash; confirm this before the first push,
   or update the `name:` field on the `rust/crates/mkit-rpc/proto` and
   `apps/repo-worker/proto` modules in the repo-root `buf.yaml` (and the `buf
   generate`/`buf push` references in this doc and the `buf-push` job) to the
   actual BSR org if it differs.**
2. Generate a BSR API token (`buf.build` → Settings → API Tokens) scoped to
   that organization, with write access.
3. Add it as an **org-level** (or repo) secret named `BUF_TOKEN`, and set the
   `BUF_PUBLISH_ENABLED` repo/org **variable** to `true`. Until the variable is
   `true`, `buf-push` is a clean skip (`if: vars.BUF_PUBLISH_ENABLED ==
   'true'`) &mdash; same dormant-until-provisioned pattern as `RELEASE_PLZ_ENABLED`.
   Two knobs, not one, because a job-level `if:` cannot read the `secrets`
   context to gate on `BUF_TOKEN`'s presence directly.
4. First push auto-creates both BSR repositories (`--create
   --create-visibility private`); no manual "create the module" step needed.
5. Verify: after a release tag, `buf generate
   buf.build/officialunofficial/mkit-repo:vX.Y.Z --template
   apps/repo-worker/proto/buf.gen.yaml` (with `buf registry login` first, since
   the module is private) should produce TypeScript bindings without this repo
   checked out &mdash; this is exactly what the `buf-push` job's own smoke-test step
   does on every tagged release.

### Package name decision

The Rust crate remains `mkit-wasm`, but the release workflow publishes the npm
package as `@officialunofficial/mkit-wasm`, matching the GitHub org this repo
lives under (renamed from `@makechain/mkit-wasm` once the repo went public —
see [npm Trusted Publishing](#npm-trusted-publishing-oidc-officialunofficialmkit-wasm)
above). If the scope ever changes again, update
`rust/crates/mkit-wasm/README.md`'s install snippet, the `publish-wasm` workflow
`npm pkg set name=...` line, the npm Trusted Publisher config on npmjs.com, and
the `npm view` smoke-test references in this doc.
