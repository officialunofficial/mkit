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

## How it works

- **`release-plz` (this repo's `release-plz.yml`)** — opens a Release PR
  (version bump from Conventional Commits + `CHANGELOG.md` + cargo-semver-checks)
  on manual trigger; on merge to `main` it **`cargo publish`es the 9 libs** and
  creates **one `v{version}` git tag**.
- **`release.yml` (unchanged)** — triggers on that `v*.*.*` tag and builds the
  signed binaries, SBOM, GitHub Release, and npm wasm.

release-plz does **not** create the GitHub Release (`git_release_enable = false`)
— `release.yml` owns it, so there's exactly one Release per tag. The tag is
pushed with a **GitHub App token** (not `GITHUB_TOKEN`), which is required for
the tag to trigger `release.yml`.

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

### 3. First publish (the important part)
The workspace version is still **`0.1.0`** and a **`v0.1.0` tag already exists**,
but `main` has advanced far past that tag. So the first crates.io release must
be a **fresh version** — publishing current `main` *as* `0.1.0` would mismatch
the tagged `v0.1.0` release. Let release-plz pick the new version:

> **Why a manual first bump?** release-plz refuses to compute a release while the
> only baseline is the `v0.1.0` *git tag* with nothing on crates.io ("package
> `mkit-core` not found in the registry, but the git tag v0.1.0 exists"). The
> fix is to move the version OFF `0.1.0` once, by hand; from then on release-plz
> tracks the published crates.io version and fully automates the rest. (Validated
> locally: at `0.2.0` with a clean tree, `release-plz update` succeeds and plans
> to publish exactly the 9 libs.)

1. Merge this PR (adds `release-plz.yml` + `rust/release-plz.toml`, splits the
   contrib signers, makes the enc dep path-only). It bumps no version, so its
   `release` job is a clean no-op.
2. Provision all three secrets (above).
3. **Cut the first release with a one-time manual bump PR:** edit
   `rust/Cargo.toml` `[workspace.package] version = "0.2.0"` (or `1.0.0` if you
   prefer), add a `## [0.2.0]` heading to `CHANGELOG.md`, open + merge the PR.
   (This is the only manual version bump ever; release-plz can't do this first
   one for the reason above.)
4. On that merge, the `release-plz-release` job publishes the 9 libs to crates.io
   in dependency order and tags `v0.2.0` (new — no clash with `v0.1.0`). That tag
   triggers `release.yml` → binaries + GitHub Release + npm.

> Validate any time with `cd rust && release-plz update --config release-plz.toml`
> (install: `cargo install release-plz`). It writes the proposed version +
> changelog locally (no publish); `git checkout .` to discard. Confirm exactly
> one version moves and the 9 libs are the publish set.

## Steady-state (every release after the first)
1. Actions → **release-plz** → Run (the `release-plz-pr` job). It gathers
   everything merged since the last tag into one Release PR.
2. Review + merge the Release PR.
3. Done — crates.io publish, the `v{version}` tag, binaries, and npm all happen
   automatically off the merge.

## Notes / gotchas
- **Stale version**: bump-from-`0.1.0` only matters for the first release; after
  that release-plz tracks the published version on crates.io.
- **semver gate**: release-plz runs cargo-semver-checks against the previous tag
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
