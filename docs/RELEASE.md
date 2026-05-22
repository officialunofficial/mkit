# Cutting an mkit release

This is the release runbook. For per-step verification (cosign, hashes,
reproducibility), see [`docs/release/CHECKLIST.md`](release/CHECKLIST.md)
and [`docs/release/SIGNING.md`](release/SIGNING.md).

## What gets published

A single `vX.Y.Z` tag triggers
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
produces:

1. **GitHub Release** with native binaries for four targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`
   Each archive is cosign-signed (keyless OIDC, Rekor logged) and ships
   alongside per-archive `.sig`/`.crt`/`.cosign.bundle`, an aggregate
   `SHA256SUMS` (also cosign-signed), and a CycloneDX `sbom.cdx.json`.

2. **npm package** `@makechain/mkit-wasm@X.Y.Z`. Built with
   `wasm-pack --target bundler` and published with `npm publish
   --access public`. The pkg tarball is also attached to the GitHub
   Release as `mkit-wasm-X.Y.Z-npm.tar.gz` for offline mirroring.

   *Provenance is currently disabled* — `--provenance` requires the
   source GitHub repo to be `public`, but this one is `internal`.
   The workflow code path is intact (the `id-token: write` permission
   is still set); just re-add `--provenance` to the `npm publish`
   line once the repo is flipped to public. Sigstore attestation
   will then bind each release to the GitHub Actions run that
   produced it.

## Cutting a release

1. Land everything on `main`. Confirm CI is green.
2. Bump `[workspace.package].version` in `rust/Cargo.toml`. Update
   `CHANGELOG.md` (move `Unreleased` items into `[X.Y.Z] - YYYY-MM-DD`).
3. Open a release-prep PR, merge it.
4. Tag the merge commit on `main`:
   ```sh
   git tag -s vX.Y.Z -m "mkit X.Y.Z"
   git push origin vX.Y.Z
   ```
   Signed tags only — see `docs/release/CHECKLIST.md`.
5. Watch `release.yml`. The job order is:
   `build` (× 4 archs) → `sbom` → `release` → `publish-wasm`.
6. Run the post-release smoke checks in
   [`docs/release/CHECKLIST.md`](release/CHECKLIST.md) (cosign verify,
   `npm view mkit-wasm@X.Y.Z`, `npm audit signatures`).

## Required GitHub Actions secrets

| Secret | Purpose | Required for |
| --- | --- | --- |
| `MKIT_NPM_TOKEN` | npm publish auth (Automation token, 2FA-bypass) | `publish-wasm` |
| `CODECOV_TOKEN` | Codecov upload auth (required while repo is internal/private; once flipped to public, Codecov supports tokenless OIDC upload and this secret can be removed) | `coverage.yml` |
| `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | macOS notarization | macOS archives (gated; no-op until set) |

cosign keyless and npm provenance both run on the GitHub OIDC token;
no extra secrets needed for those.

## One-time setup: `CODECOV_TOKEN`

Codecov receives the lcov report from `coverage.yml` so the README
badge, trend chart, and PR-diff overlay work. Steps:

1. Sign in at <https://app.codecov.io/> with the GitHub account that
   admins the `officialunofficial` org.
2. Add the `officialunofficial/mkit` repo. Codecov shows an "Upload
   token" — copy it.
3. In GitHub: `Settings → Secrets and variables → Actions → New
   repository secret`.
   - Name: `CODECOV_TOKEN`
   - Value: the token from step 2.
4. Trigger `coverage.yml` (push to main, or `gh workflow run coverage.yml`).
   The first run seeds the baseline; subsequent runs populate the badge.
5. Once the repo flips public, remove the secret — Codecov accepts
   tokenless uploads from public repos via GitHub OIDC.

## One-time setup: `MKIT_NPM_TOKEN`

`mkit-wasm` is currently unclaimed on the npm registry. Steps for the
human cutting the first release:

1. **Create an npm org / user.** The package will publish under the
   account that owns `MKIT_NPM_TOKEN`. Recommended: a machine account or
   a maintainer account with the package added to a 2FA-protected org.
2. **Generate an Automation token** (`npmjs.com → Access Tokens → New
   Granular Token` or a classic Automation token). Required scopes:
   `read+write` on `mkit-wasm`. Automation tokens bypass the 2FA OTP
   prompt that would otherwise block CI.
3. **Add to GitHub repo secrets:**
   `Settings → Secrets and variables → Actions → New repository secret`
   - Name: `MKIT_NPM_TOKEN`
   - Value: the token from step 2.
4. **Claim the package name (one-time).** Until the first successful
   `npm publish`, the name `mkit-wasm` remains unclaimed. Two options:
   - Recommended: cut a real `v0.1.0` tag — the workflow will publish.
   - Or, manually publish a placeholder once from a maintainer
     workstation:
     ```sh
     cd rust
     wasm-pack build crates/mkit-wasm --release --target bundler --out-dir pkg
     cd crates/mkit-wasm/pkg
     npm version --no-git-tag-version --allow-same-version 0.0.0-init
     npm publish --access public
     ```
     Subsequent publishes go through Actions.
5. Verify with `npm view @makechain/mkit-wasm` after the first publish.

### Future work: migrate to Trusted Publishers (drop `MKIT_NPM_TOKEN`)

npm now supports
[Trusted Publishers (OIDC)](https://docs.npmjs.com/trusted-publishers).
With Trusted Publishers configured, the `publish-wasm` job authenticates
via the GitHub Actions OIDC token directly — no `MKIT_NPM_TOKEN` secret to
rotate, leak, or revoke.

Migration plan:

1. On `npmjs.com`, open the `mkit-wasm` package settings → Publishing
   access → Trusted Publishers → add this repo + the `release.yml`
   workflow.
2. Drop the `NODE_AUTH_TOKEN` env on the publish step in
   `.github/workflows/release.yml`.
3. Delete the `MKIT_NPM_TOKEN` secret from the repo.
4. Cut a patch release to validate the OIDC flow end-to-end.

This is a strict-improvement follow-up; defer until after at least one
successful token-based release so the runbook is exercised.

## Package name decision

`mkit-wasm` (unscoped). Verified available via
`npm view @makechain/mkit-wasm` (404). Unscoped is what consumers will type
without a registry-scope prefix and reads cleanly as `bun add @makechain/mkit-wasm`.

If the unscoped name is ever lost or squatted, fall back to
`@officialunofficial/mkit-wasm` and update:

- `rust/crates/mkit-wasm/Cargo.toml` `[package].name`
- `rust/crates/mkit-wasm/README.md` install snippet
- The `publish-wasm` workflow (no `--access` change needed; already
  `public`)
- `npm view` smoke-test references in this doc
