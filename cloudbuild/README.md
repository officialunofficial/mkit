# Cloud Build CI for mkit

mkit's Rust CI runs on **Google Cloud Build**. This directory holds the build
configs; `scripts/setup-cloud-build.sh` provisions the GCP side and creates
the triggers.

## Why Cloud Build

- **Durable caching.** Builds run *as* a service account, so `sccache` reaches a
  GCS bucket via the metadata server — no key file, no WIF, a persistent cache
  GitHub-hosted runners can't have.
- **Bigger machines.** `E2_HIGHCPU_8` + 100 GB disk removes the disk pressure
  that forced `rust.yml` to free the Android/.NET/Haskell trees on GitHub's
  ~14 GB runners.
- **One toolchain image.** Tools are pinned once in `Dockerfile.ci` and baked,
  so every PR uses the identical environment (no per-PR install drift).

## Scope: CI only

mkit ships a CLI binary + Cloudflare Workers, so there is **no image-publish /
GKE-deploy half**. These stay on GitHub Actions:

- **Release / publish:** `release.yml`, `crates-publish.yml`, `mcp-release.yml`,
  `release-plz.yml` (CLI binaries, cosign, crates.io, npm).
- **Cross-platform legs Cloud Build (Linux-only) can't run:** the macOS leg of
  `build-and-test`, the `windows-smoke` build, and the `keystore-backends`
  matrix (macOS/Windows/Linux native keystores) in `rust.yml`.
- **TS/wasm app validation:** `web.yml`, `mcp.yml`, `actionlint.yml`.

## Layout

mkit's Rust workspace is in **`rust/`** (not the repo root) and the reference
signers are a **separate workspace** in **`contrib/signers/`**. Every config
`cd`s into the right tree — that's the main difference from a root-workspace
layout.

| Config | Replaces (GitHub Actions) | Notes |
|---|---|---|
| `Dockerfile.ci` | — | Baked toolchain: rust 1.95.0, protoc 31.0, native deps, nextest/sccache/deny/audit/llvm-cov/geiger@0.13.0. Tag `:rust-1.95.0`. |
| `builder.yaml` | — | Builds + pushes `Dockerfile.ci` to GAR. |
| `ci.yaml` | `rust.yml` build-and-test (Linux) + `msrv` | fmt → clippy → build → signers → nextest → doctests → version contract → enc-transport → msrv check. |
| `codegen.yaml` | `rust.yml` codegen-fresh | `scripts/check-generated-fresh.sh` (needs git + wasm32), then `buf lint` + `buf breaking` against every module in the repo-root `buf.yaml` (`buf` downloaded at run time, not baked into the image). |
| `security.yaml` | `rust-security.yml` | `cargo audit` (both workspaces) + `cargo deny`. |
| `docs.yaml` | `docs.yml` | rustdoc `-D warnings`, both workspaces. |
| `geiger.yaml` | `geiger.yml` | `scripts/check-geiger-baseline.sh`. |
| `coverage.yaml` | `coverage.yml` | llvm-cov → lcov → Codecov (main only, non-fatal). |

## Triggers

All on branch `^main$`. Every PR trigger auto-runs for org collaborators and
needs a maintainer **`/gcbrun`** only for external/fork PRs. See
`scripts/setup-cloud-build.sh` for the exact `--included-files` /
`--ignored-files` filters.

| Trigger | Config | PR gate |
|---|---|---|
| `mkit-ci-{pr,main}` | `ci.yaml` | collaborators auto, `/gcbrun` for forks |
| `mkit-codegen-{pr,main}` | `codegen.yaml` | collaborators auto |
| `mkit-security-{pr,main}` | `security.yaml` | collaborators auto |
| `mkit-docs-{pr,main}` | `docs.yaml` | collaborators auto |
| `mkit-geiger-{pr,main}` | `geiger.yaml` | collaborators auto |
| `mkit-coverage-main` | `coverage.yaml` | main push only |

## One-time setup

```bash
gcloud config set project <gcp-project-id>   # shared GCP project
./scripts/setup-cloud-build.sh
```

This creates the sccache bucket, builds + pushes the CI image, (optionally)
stores a Codecov token, and creates the triggers. It is idempotent.

## Rebuilding the CI image

Re-run `builder.yaml` whenever `Dockerfile.ci` or `rust/rust-toolchain.toml`
changes, and bump the `:rust-1.95.0` tag in lockstep across `Dockerfile.ci`,
`builder.yaml`, every consuming config's `_CI_IMAGE` default, and the setup
script:

```bash
gcloud builds submit . --region=us-east4 --config=cloudbuild/builder.yaml
```

## Local repro

```bash
gcloud builds submit . --region=us-east4 --config=cloudbuild/ci.yaml \
  --substitutions=_CI_IMAGE=us-east4-docker.pkg.dev/<project>/docker/mkit-ci:rust-1.95.0
```

`codegen.yaml` needs a git checkout (it diffs the worktree), so reproduce it via
a trigger or run `./scripts/check-generated-fresh.sh` directly — a manual submit
ships a `.git`-less tarball.

## Branch protection

After the triggers are live and green, update `main`'s required status checks:
add the Cloud Build checks and remove the retired GitHub Actions checks
(`rust-security`, `docs`, `geiger`, `coverage`, and the Linux Rust gate). Don't
flip these until a real `/gcbrun` run has proven the Cloud Build side green —
otherwise `main` loses its Rust gate in the gap.
