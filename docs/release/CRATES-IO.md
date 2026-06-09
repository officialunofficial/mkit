# Publishing to crates.io (release-plz) — runbook

Resolves #225. mkit publishes its **9 library crates** to crates.io via
[release-plz]; the existing `release.yml` keeps owning binaries, the GitHub
Release, and the npm wasm package. This is the same model used in the
`polychrome` repo, adapted because mkit *does* publish to crates.io.

## What publishes vs. what doesn't

| Publishes to crates.io (9) | Stays off crates.io (`publish = false`) |
|---|---|
| mkit-core, mkit-rpc, mkit-attest, mkit-keystore, mkit-transport-{file,http,memory,s3,ssh} | mkit-cli (binary), mkit-wasm (npm), mkit-transport-enc (Phase 2), contrib signers, fuzz, benches |

The 9 libraries depend **only on each other**, so they form a closed,
dependency-ordered set (core → rpc → attest → keystore → transports);
release-plz computes that order automatically. release-plz reads each crate's
`publish = false` and skips the rest.

## How it works — two DECOUPLED channels

release.yml's binary release is gated on an **annotated, GPG-signed tag from an
allowlisted fingerprint** (it runs `git verify-tag`). release-plz can't create
such a tag, so the two channels are kept separate:

- **crates.io (release-plz)** — `release-plz-pr` opens a Release PR (version
  bump + **rewritten internal dep requirements** + `CHANGELOG.md` +
  cargo-semver-checks); merging it runs `release-plz-release`, which
  **`cargo publish`es the 9 libs** in dependency order. release-plz creates **no
  git tag and no GitHub Release** (`git_tag_enable`/`git_release_enable = false`).
- **Binaries (release.yml, unchanged)** — a human cuts the annotated, GPG-signed
  `v{version}` tag via the existing release ceremony; that tag drives binaries +
  SBOM + GitHub Release + npm wasm.

So a release is: merge the Release PR (→ crates.io), then cut the signed tag
(→ binaries). `release_always = false` means the publish job is a no-op except
on a merged Release PR, so ordinary pushes never publish. The GitHub App token
is used only so the Release PR can trigger CI (a `GITHUB_TOKEN`-authored PR
can't).

## One-time setup

### 1. Claim/verify the crate names
Make sure all 9 `mkit-*` names are available (or already owned by the
`officialunofficial` crates.io org). If any is taken by someone else, resolve
before proceeding.

### 2. Secrets (repo → Settings → Secrets and variables → Actions)
| Secret | What | Notes |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | crates.io API token | Scopes: **publish-new** + **publish-update**. A token (not trusted publishing) is required because brand-new crates can't be published via trusted publishing the first time. |
| `RELEASE_PLZ_APP_ID` | GitHub App id | Reuse the same App as polychrome if it's installed on this repo; else create one (perms: contents:write, pull-requests:write, workflows). |
| `RELEASE_PLZ_APP_PRIVATE_KEY` | GitHub App private key | Minted into a short-lived token per run; never stored as a static token. |

### 3. First publish (one-time, manual — read carefully)
The first crates.io release is special and can't be fully automated, for two
reasons:
- The version is still **`0.1.0`** with a **`v0.1.0` git tag** but nothing on
  crates.io. release-plz refuses to compute a release in that state ("package
  `mkit-core` not found in the registry, but the git tag v0.1.0 exists"), so it
  can't open the first Release PR. The version must move OFF `0.1.0` once.
- The internal dependency requirements are all `version = "0.1"`
  (`mkit-attest → mkit-core = "0.1"`, etc.). A bump that only changes the
  workspace version would publish `mkit-core@0.2.0` and then **fail** publishing
  `mkit-attest` (it still requires `mkit-core = "0.1"`). Those requirements must
  be rewritten too. `release-plz update` does exactly that.

Sequence:

1. Merge this PR (release-plz config/workflow, contrib split, path-only enc dep).
   It bumps no version, and `release_always = false`, so nothing publishes.
2. Provision all three secrets (above) and verify the 9 names on crates.io.
3. **Open a one-time bump PR that rewrites everything** — locally:
   ```sh
   cd rust
   # pick the first crates.io version (0.2.0 here; use 1.0.0 if you prefer):
   sed -i '' 's/^version = "0.1.0"/version = "0.2.0"/' Cargo.toml
   cargo install release-plz   # if not installed
   release-plz update --config release-plz.toml   # rewrites all internal dep
                                                   # requirements + CHANGELOG.md
   ```
   Commit the result (workspace version + every `version = "0.2"` dep rewrite +
   `CHANGELOG.md`), open + merge the PR. (This is the only manual version bump
   ever.)
4. **Publish the first version by hand**, in dependency order — because
   `release_always = false` and this bump PR isn't a release-plz Release-PR
   commit, the release job won't auto-publish it:
   ```sh
   cd rust
   export CARGO_REGISTRY_TOKEN=...   # or `cargo login`
   for c in mkit-core mkit-rpc mkit-attest mkit-keystore \
            mkit-transport-memory mkit-transport-file mkit-transport-http \
            mkit-transport-s3 mkit-transport-ssh; do
     cargo publish -p "$c" --locked   # let each index before the next dependent
   done
   ```
5. **Cut the signed binary release**: create the annotated, GPG-signed `v0.2.0`
   tag via the existing release ceremony (allowlisted signer) — that drives
   `release.yml` → binaries + SBOM + GitHub Release + npm.

## Steady-state (every release after the first)
Now that the crates exist on crates.io, release-plz is fully in charge of the
crates.io channel:
1. Actions → **release-plz** → Run (`release-plz-pr`). It opens the Release PR
   (next version, dep-requirement rewrites, CHANGELOG, semver gate).
2. Review + merge the Release PR → `release-plz-release` publishes the 9 libs to
   crates.io automatically.
3. Cut the annotated, GPG-signed `v{version}` tag (the existing ceremony) →
   `release.yml` builds the binaries + GitHub Release + npm.

## Notes / gotchas
- **Stale version**: bump-from-`0.1.0` only matters for the first release; after
  that release-plz tracks the published version on crates.io.
- **semver gate**: release-plz runs cargo-semver-checks against the previous release
  in the Release PR (`semver_check = true`); the standalone `semver-checks.yml`
  still runs per-PR against the base branch. Both are fine.
- **Native deps**: `cargo publish` builds each crate with **default** features,
  so no `libpcsclite` is needed (mkit-keystore's `backend-yubikey` is off by
  default); only `protoc` is required (installed in the workflow for mkit-rpc).
- **Yanking**: if a publish goes wrong mid-train, `cargo yank` the affected
  versions; release-plz re-publishes the remainder on the next run.
- **deny.toml**: after the first publish you may tighten
  `allow-wildcard-paths` now that the crates exist on the registry.

[release-plz]: https://release-plz.dev/
