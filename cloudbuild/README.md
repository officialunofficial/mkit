# Cloud Build CI for mkit

mkit's Rust CI runs on **Google Cloud Build**. This directory holds the build
configs; `scripts/setup-cloud-build.sh` provisions the GCP side and creates
the triggers.

## Why Cloud Build

- **Durable caching.** Builds run *as* a service account, so `sccache` reaches a
  GCS bucket via the metadata server &mdash; no key file, no WIF, a persistent cache
  GitHub-hosted runners can't have.
- **Bigger machines.** `E2_HIGHCPU_8` plus 100 GB disk removes the disk pressure
  that forced `rust.yml` to free the Android/.NET/Haskell trees on GitHub's
  ~14 GB runners.
- **One toolchain image.** Tools are pinned once in `Dockerfile.ci` and baked,
  so every PR uses the identical environment (no per-PR install drift).

## Scope: CI only

mkit ships a CLI binary and Cloudflare Workers, so there is **no image-publish/
GKE-deploy half**. These stay on GitHub Actions:

- **Release/publish:** `release.yml`, `crates-publish.yml`, `mcp-release.yml`,
  `release-plz.yml` (CLI binaries, cosign, crates.io, npm).
- **Cross-platform legs Cloud Build (Linux-only) can't run:** the macOS leg of
  `build-and-test` and the `keystore-backends` matrix (Linux/macOS native
  keystores) in `rust.yml`. Windows is not a supported target (MKIT-6; see
  `docs/INVARIANTS.md`).
- **TS/wasm app validation:** `web.yml`, `mcp.yml`, `actionlint.yml`.

## Layout

mkit's Rust workspace is in **`rust/`** (not the repo root) and the reference
signers are a **separate workspace** in **`contrib/signers/`**. Every config
`cd`s into the right tree &mdash; that's the main difference from a root-workspace
layout.

| Config | Replaces (GitHub Actions) | Notes |
|---|---|---|
| `Dockerfile.ci` | &mdash; | Baked toolchain: rust 1.95.0, protoc 31.0, native deps, nextest/sccache/deny/audit/llvm-cov/geiger@0.13.0. Tag `:rust-1.95.0`. |
| `builder.yaml` | &mdash; | Builds and pushes `Dockerfile.ci` to GAR. |
| `ci.yaml` | `rust.yml` build-and-test (Linux) and `msrv` | Main gates (60-minute step): fmt → clippy → build → signers → nextest → doctests → version contract → enc-transport → msrv/wasm checks. Required serial ignored-test step follows (50 minutes); overall build limit is 120 minutes. |
| `codegen.yaml` | `rust.yml` codegen-fresh | `scripts/check-generated-fresh.sh` (needs git and wasm32), then `buf lint` and `buf breaking` against every module in the repo-root `buf.yaml` (`buf` downloaded at run time, not baked into the image). |
| `security.yaml` | `rust-security.yml` | `cargo audit` (both workspaces) and `cargo deny`. |
| `docs.yaml` | retired from GitHub Actions, Cloud Build only | rustdoc `-D warnings`, both workspaces. |
| `geiger.yaml` | retired from GitHub Actions, Cloud Build only | `scripts/check-geiger-baseline.sh`. |
| `commonware-latest.yaml` | GitHub latest-release probe reproduction | Same bounded update/build/test script; automatic runs use the scheduled and path-filtered GitHub workflow to avoid duplicate PR builds. |
| `coverage.yaml` | retired from GitHub Actions, Cloud Build only | llvm-cov → lcov → Codecov (main only, non-fatal). |

## Triggers

All on branch `^main$`. Every PR trigger auto-runs for org collaborators and
needs a maintainer **`/gcbrun`** only for external/fork PRs. See
`scripts/setup-cloud-build.sh` for the exact `--included-files`/
`--ignored-files` filters.

| Trigger | Config | PR gate |
|---|---|---|
| `mkit-ci-{pr,main}` | `ci.yaml` | collaborators auto, `/gcbrun` for forks |
| `mkit-codegen-{pr,main}` | `codegen.yaml` | collaborators auto |
| `mkit-security-{pr,main}` | `security.yaml` | collaborators auto |
| `mkit-docs-{pr,main}` | `docs.yaml` | collaborators auto |
| `mkit-geiger-{pr,main}` | `geiger.yaml` | collaborators auto |
| `mkit-coverage-main` | `coverage.yaml` | main push only |

## Test compilation memory

The workspace's unified `mkit-server` lib-test compiler is killed with signal 9
near the worker's memory limit, even with one Cargo job and debuginfo disabled.
`CARGO_PROFILE_TEST_CODEGEN_UNITS=256` splits LLVM code generation into smaller
modules. Workspace nextest commands also use `--build-jobs 1` to reserve the
remaining memory for that compiler. Both steps use identical profile settings
to reuse compiled tests. Test selection and execution concurrency stay unchanged,
including the required ignored-test lane. The machine type stays unchanged.

sccache replaces Cargo's jobserver with CPU-count parallelism even for
uncached test binaries. The `check` step's compiler wrapper invokes rustc
directly only for the linked `mkit-server` lib-test, preserving Cargo's
single-job bound. Other compilations, including metadata checks, keep sccache.
The lib-test binary was already uncacheable, so this bypass loses no cache hits.

The wrapper also copies sccache's raw stdout to stderr on failure and preserves
its exit code. This exposes signal messages that Cargo's JSON renderer otherwise
discards. For diagnosis, use `cargo test --no-run --message-format=human` on the
same workspace feature graph and measure the Linux compiler's memory use.

## Test failure reporting

Every nextest invocation in `ci.yaml` runs with `--no-fail-fast`, overriding the
default profile's `fail-fast = true` (`rust/.config/nextest.toml`), so one
failing test reports the run's complete failure set instead of cancelling it.
Inside the `check` step, each command after the workspace build and TPM setup
still runs after an earlier failure (a `cd` into a missing tree aborts only
its own subshell, via `|| exit 1`): failures are recorded and the step exits
non-zero at the end. Timeouts, retries and
test selection stay at the default profile's values &mdash; the `ci` profile's
longer envelopes and retries are not used here.

## Diagnosing main test failures

At `e3440bd0`, [the macOS test run](https://github.com/officialunofficial/mkit/actions/runs/37141273001)
and [Cloud Build's check step](https://console.cloud.google.com/cloud-build/builds;region=us-east4/bcfe7e6f-c2ef-404b-8c10-4dc164fd83f6?project=545902902213)
failed in `mkit-rpc::hooks_public::decode_every_golden_request`: all 18
requests decoded, but the test still asserted 16. The schema, generated
types, manifest, spec anchors and schema-check script already contained
`outcome-visibility` and `outcome-repo-storage`. Updating the count and
asserting preservation of every fixture field fixes the test at its source.

The wasm clippy command from `just ci-server` passed on a fresh checkout of
`26375a0b` from both `rust/` and `rust/crates/`; the reported working-directory
feature-unification failure did not reproduce. Keep the same command in the
local gate and `cloudbuild/ci.yaml`.

[The Workers conformance run](https://github.com/officialunofficial/mkit/actions/runs/37141273030)
on `e3440bd0` logged HTTP 500 `Network connection lost` errors from
Miniflare's `core/entry.worker.js` in `refs.many_refs_one_repository`, then
passed the suite. This is evidence of transient dev-proxy failures, not a
failed server assertion. Its existing bounded retry uses the same signed,
idempotent request, records each retry, and still verifies every written ref
and the exact ordered listing. Preserve these diagnostics and assertions;
investigate runtime logs if a retry is exhausted.

## One-time setup

```bash
gcloud config set project <gcp-project-id>   # shared GCP project
./scripts/setup-cloud-build.sh
```

This creates the sccache bucket, builds and pushes the CI image, (optionally)
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
a trigger or run `./scripts/check-generated-fresh.sh` directly &mdash; a manual submit
ships a `.git`-less tarball.

## Branch protection

After the triggers are live and green, update `main`'s required status checks:
add the Cloud Build checks and remove the retired GitHub Actions checks
(`rust-security`, `docs`, `geiger`, `coverage`, and the Linux Rust gate). Don't
flip these until a real `/gcbrun` run has proven the Cloud Build side green &mdash;
otherwise `main` loses its Rust gate in the gap.

## Commonware release compatibility

**CI: Commonware latest release** runs weekly, on manifest/lockfile PRs, and
on manual dispatch. One Linux job has a 30-minute limit, three build workers,
and three nextest workers. It updates every resolved `commonware-*` package
to the newest compatible release, prints the versions, and builds and tests
`mkit-core`, `mkit-attest`, and `mkit-transport-enc` with all features.
It also includes `mkit-primitives` when that crate exists. Golden encoder
assertions run in these tests and in ordinary crate test runs.

A newer release that cannot build or changes pinned bytes fails the job.
Report the incompatibility; do not silently restore an older dependency.
The compatibility job's modified lockfile is disposable and is never committed.
The baseline version audit remains a separate check of committed lockfiles.

For a local sample run in a clean checkout:

```sh
MKIT_CARGO_CACHED=1 bash scripts/check-commonware-latest.sh
```

This command changes **rust/Cargo.lock**. Save and restore that file when
returning to baseline tests. The optional Cloud Build reproduction uses the
baked CI image, sccache, and the same script:

```sh
gcloud builds submit . --region=us-east4 --config=cloudbuild/commonware-latest.yaml
```
