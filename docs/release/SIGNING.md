# Signing and verification

Every mkit release is signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
using **keyless OIDC**: the signing identity is the GitHub Actions workflow
itself (`.github/workflows/release.yml`), authenticated by GitHub's OIDC
provider, and every signature is recorded in the [Rekor transparency
log](https://docs.sigstore.dev/logging/overview/).

No private keys are held by any human. No private keys are stored in
GitHub Secrets. If someone steals a release signature, they cannot reuse
it on any other artifact — the signature is bound to the artifact hash.

## Artifacts attached to every release

For each of the four target archives
(`aarch64-macos`, `x86_64-macos`, `x86_64-linux`, `aarch64-linux`):

| File                            | Purpose                                 |
| ------------------------------- | --------------------------------------- |
| `mkit-X.Y.Z-<triple>.tar.gz`    | The release archive.                    |
| `...tar.gz.sha256`              | SHA256 of the archive (convenience).    |
| `...tar.gz.sig`                 | Raw cosign signature (base64).          |
| `...tar.gz.crt`                 | Fulcio-issued code-signing certificate. |
| `...tar.gz.cosign.bundle`       | Bundle: sig + cert + Rekor entry.       |

Plus one top-level set for the aggregate:

| File                                 | Purpose                               |
| ------------------------------------ | ------------------------------------- |
| `SHA256SUMS`                         | Hashes of every archive + SBOM.       |
| `SHA256SUMS.{sig,crt,cosign.bundle}` | Cosign signature of `SHA256SUMS`.     |
| `sbom.cdx.json`                      | CycloneDX SBOM of the release.        |

## Verify a downloaded archive

Install cosign: <https://docs.sigstore.dev/cosign/system_config/installation/>

Then:

```sh
ARCHIVE=mkit-0.2.0-aarch64-macos.tar.gz
TAG=v0.2.0

cosign verify-blob \
  --certificate-identity-regexp "https://github.com/officialunofficial/mkit/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "${ARCHIVE}.cosign.bundle" \
  "${ARCHIVE}"
```

Expected output: `Verified OK`.

The `--certificate-identity-regexp` pins the signature to a tag build of
mkit's release workflow. If a signature was produced by any other workflow
(including a fork, a branch build, or a locally-run cosign), verification
will fail.

## Inspect the Rekor transparency log entry

The `.cosign.bundle` contains a Rekor log index. To view the public entry:

```sh
cosign verify-blob \
  --certificate-identity-regexp "https://github.com/officialunofficial/mkit/.github/workflows/release.yml@refs/tags/v.*" \
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
  --certificate-identity-regexp "https://github.com/officialunofficial/mkit/.github/workflows/release.yml@refs/tags/v.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle SHA256SUMS.cosign.bundle \
  SHA256SUMS

grep sbom.cdx.json SHA256SUMS | sha256sum -c -
```

## macOS notarization (future)

The release workflow has a scaffolded notarization step gated on three
secrets: `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`.
Until an Apple Developer ID is configured on this repo, macOS binaries
are **cosign-signed but not notarized**. Users on Ventura+ will see a
Gatekeeper warning; override with
`xattr -d com.apple.quarantine /path/to/mkit` after cosign verification.

Once notarization is enabled, the archive will carry a stapled ticket and
Gatekeeper will accept it without intervention.
