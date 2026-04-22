# Supply-chain policy

mkit's supply chain is intentionally narrow. The binary users run traces
back to a small, auditable set of inputs. This document is the contract.

## Current state

- **Zig packages:** zero. `build.zig.zon` has no `dependencies` table.
  Every symbol in the binary is either ours or from the Zig standard
  library.
- **System libs:** the default static Zig build links only musl (Linux) or
  the platform C runtime (macOS). We do not pull in openssl, libcurl, or
  any other C library.
- **Build inputs:** the Zig toolchain (version pinned in `.zigversion` and
  in `release.yml`), the source tree at a tagged Git commit, and the set
  of `-Dtarget=` / `-Doptimize=` flags documented in
  `docs/release/REPRODUCIBILITY.md`.

## Adding a Zig package dependency

Every new entry in `build.zig.zon`'s `dependencies` table must:

1. Be **hash-pinned**. `.hash = "..."` is mandatory; `.url` alone is not
   enough.
2. Have its source reviewed by **two maintainers**. Sign-off lives in the
   PR description.
3. Have a stated purpose. A PR that adds a dep must answer: what does mkit
   gain, and what would implementing it in-tree cost? Default answer
   should be "implement in-tree"; deps are the exception.
4. Be compatible with **MIT OR Apache-2.0**. The CI dependency-review
   action denies GPL and LGPL families outright.
5. Have a cross-platform build. If the dep breaks on one of our four
   release targets, it doesn't land.

## GitHub Actions dependencies

All third-party actions in `.github/workflows/` must be pinned to a major
version tag (`@v4`) or to a full SHA. No `@main`, no `@latest`. Trusted
publishers today:

- `actions/*` (GitHub-owned)
- `mlugg/setup-zig` (Zig toolchain installer)
- `sigstore/cosign-installer` (cosign)
- `anchore/sbom-action` (SBOM)
- `softprops/action-gh-release` (release creation)
- `ossf/scorecard-action` (Scorecard)

Any new action from an untrusted publisher needs the same two-maintainer
review as a Zig dep.

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
