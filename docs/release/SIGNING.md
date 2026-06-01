# Signing and verification

Every mkit release is signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
using **keyless OIDC**: the signing identity is the GitHub Actions workflow
itself (`.github/workflows/release.yml`), authenticated by GitHub's OIDC
provider, and every signature is recorded in the [Rekor transparency
log](https://docs.sigstore.dev/logging/overview/).

No artifact-signing private keys are held by any human or stored in GitHub
Secrets. Artifact signatures are keyless and bound to the artifact hash, so a
stolen release signature cannot be reused on any other artifact. The installer
(`install.sh`) enforces this same trust boundary by default.

The release workflow also validates the Git tag before any artifacts are
published: the tag must be strict semver, annotated, GPG-signed by a
fingerprint listed in the `MKIT_RELEASE_GPG_FINGERPRINTS` repository or
organization variable, and point at a commit reachable from `origin/main`. The
workflow imports those public keys from `keys.openpgp.org` or
`keyserver.ubuntu.com` before running `git verify-tag`. Protected tag rulesets
should be enabled as defense in depth, but the workflow performs these checks
itself.

## Artifacts attached to every release

For each of the four target archives
(`aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`):

Release archives build the production `mkit-cli` target for that platform. The
CLI enables the matching keystore software-protector feature so `software` keys
are encrypted at rest on supported targets without changing the lean default
feature set of the `mkit-keystore` library crate.

| File                         | Purpose                                      |
| ---------------------------- | -------------------------------------------- |
| `mkit-X.Y.Z-<triple>.tar.gz` | Binary, licenses, README, manpage, completions. |
| `...tar.gz.sha256`           | SHA256 of the archive (convenience).         |
| `...tar.gz.sig`              | Raw cosign signature (base64).               |
| `...tar.gz.crt`              | Fulcio-issued code-signing certificate.      |
| `...tar.gz.cosign.bundle`    | Bundle: sig + cert + Rekor entry.            |

Plus one top-level set for the aggregate:

| File                                 | Purpose                               |
| ------------------------------------ | ------------------------------------- |
| `SHA256SUMS`                         | Hashes of every archive + SBOM.       |
| `SHA256SUMS.{sig,crt,cosign.bundle}` | Cosign signature of `SHA256SUMS`.     |
| `sbom.cdx.json`                      | CycloneDX SBOM of the release.        |

## Verify a downloaded archive

Install cosign: <https://docs.sigstore.dev/cosign/installation/>

Then:

```sh
VERSION=0.1.0
TARGET=aarch64-apple-darwin
ARCHIVE="mkit-${VERSION}-${TARGET}.tar.gz"

cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "${ARCHIVE}.cosign.bundle" \
  "${ARCHIVE}"
```

Expected output: `Verified OK`.

The `--certificate-identity-regexp` pins the signature to a tag build of
mkit's release workflow. If a signature was produced by any other workflow
(including a fork, a branch build, or a locally-run cosign), verification
will fail.

The archive's sibling `.sha256` file is not an authenticity signal on
its own because it is served from the same origin as the archive. Treat
it as defense-in-depth after cosign, not instead of cosign.

## Inspect the Rekor transparency log entry

The `.cosign.bundle` contains a Rekor log index. To view the public entry:

```sh
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/officialunofficial/mkit/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "${ARCHIVE}.cosign.bundle" \
  --rekor-url "https://rekor.sigstore.dev" \
  "${ARCHIVE}"
```

Or search by the archive's sha256 at
<https://search.sigstore.dev/?hash=sha256:DIGEST>.

## Verify the SBOM

The SBOM (`sbom.cdx.json`) is included in the top-level `SHA256SUMS`. The
top-level `SHA256SUMS` is itself cosign-signed. So the chain is:

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

## macOS Gatekeeper

macOS binaries are **not Developer ID-signed and not notarized**. That
is the current shipping state; the trust boundary is the cosign
verification above, not Apple notarization. Users on Ventura+ may see a
Gatekeeper warning when launching a freshly-downloaded binary from
Finder. After you verify the archive, either run `mkit` from a terminal
or clear quarantine explicitly:

```sh
xattr -d com.apple.quarantine /path/to/mkit
```

If notarized macOS releases ever ship, the release notes and this
document will say so explicitly.
