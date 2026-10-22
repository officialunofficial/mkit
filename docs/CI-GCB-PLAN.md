# CI cost analysis and Cloud Build migration plan

This document explains why GitHub Actions usage for mkit reached about
$1,000 of list price in October 2026. It then gives the plan to move
nearly all CI to Google Cloud Build (GCB).

## 1. What the bill is

The GitHub billing report for October 2026 (through the 22nd) shows
mkit at $1,082 gross and $0 net. The organization's included Enterprise
minutes absorbed the cost.

| Runner | Minutes | Rate per minute | List price |
|---|---|---|---|
| macOS | 10,647 | $0.062 | about $660 |
| Linux | 70,357 | $0.006 | about $422 |

The included minutes are one pool for the whole organization. mkit used
most of the pool. The `monorepo` and `polychrome` repositories paid the
overflow: about $200 net for October. Two fixed items add $85 to $120 per
month of real cash: GitHub Code Security and Code Quality licenses.

mkit usage grew about 5x in two months: $52 in August, $206 in
September, and $1,082 in October.

## 2. Root causes

Measured from the job logs of 1,000 runs (October 18 to 22). The sample
matches the billed minutes for those days.

1. **The macOS job on every merge.** `Build & Test (macos-latest)` ran
   about 83 minutes per push to `main`. It is 72% of the weighted usage.
   Many small merges in October repeated it.
2. **macOS stub jobs on every pull request push.** Two matrix jobs ran
   only skipped steps, but GitHub bills at least one minute at the macOS
   rate for each.
3. **No path filters on most workflows.** About 13 workflows started on
   each pull request push. Most of them run one short job, and each job
   rounds up to a whole minute.
4. **Nightly jobs on hosted runners.** Formal verification used about
   2,170 Linux minutes in the sample. Fuzzing and mutation testing add
   more.
5. **Duplicate gates.** `buf.yml` and `proto.yml` overlap
   `cloudbuild/codegen.yaml`. `rust-security.yml` overlaps
   `cloudbuild/security.yaml`.
6. **Dependabot.** About 44 Dependabot update runs and 64 auto-merge runs
   in the sample month.

## 3. Changes made in this branch

| Change | Effect |
|---|---|
| `native.yml` replaces the macOS jobs in `rust.yml`. | No macOS job runs on a pull request. |
| `native.yml` runs on push to `main` only when the macOS surface changes. | Fewer macOS runs per merge. |
| `native.yml` runs nightly. | Other changes get macOS coverage within 24 hours. |
| `cloudbuild/darwin.yaml` type-checks both Darwin targets on Linux. | Pull requests keep a macOS compile gate at Linux price. |

Expected macOS cost: about $660 per month of list price falls to about
$170 in the worst case (30 nightly runs of about 90 minutes). The
per-merge runs now happen only for macOS-relevant changes.

## 4. How Darwin targets work on Cloud Build

Cloud Build has no macOS workers. Three levels of coverage exist:

| Level | Where | What it proves |
|---|---|---|
| `cargo check --target aarch64-apple-darwin` and `x86_64-apple-darwin` | Cloud Build, every pull request | The code compiles for both targets, including `cfg(target_os = "macos")` code. |
| `cargo nextest` on macOS | GitHub, nightly and path-filtered push | The code runs and the Keychain backend works. |
| Release binaries for both targets | GitHub `release.yml` on `macos-14`, tags only | The shipped artifact builds, links, and passes the smoke checks. |

Two problems appeared when building `darwin.yaml`:

- Build scripts for `blake3` and `zstd-sys` compile C code for the target.
  The Debian `cc` rejects the Apple flags `-arch` and `-mmacosx-version-min`.
- `cargo zigbuild check` is not a valid command.

The fix is `scripts/zig-cc-darwin.sh`. It runs `zig cc -target` and drops
the Apple flags and the `--target=` flag that `cc-rs` adds. The CI image
bakes in zig (through the `ziglang` Python package) and both rustup
targets. A cold run took 5 minutes 45 seconds. A cached run took
2 minutes 24 seconds.

Limits of this approach:

- It does not link. Linking needs the Apple SDK frameworks, and the SDK
  license does not allow redistribution in a Linux image.
- It does not run tests.
- If a future crate needs an Apple header that zig does not ship, the
  check fails. Fix it in the shim, or add that crate to a skip list.

Do not move the release binaries to Cloud Build. They need the real
linker and the signing steps, and they run only on tags.

## 5. Migration plan

The rule: a workflow stays on GitHub only if it needs GitHub-only
features, a macOS runner, or repository secrets for publishing.

### 5.1 Stays on GitHub Actions

| Workflow | Reason |
|---|---|
| `native.yml` | macOS runner. |
| `release.yml`, `release-verify.yml` | macOS builds, cosign, SLSA provenance. Tags and manual runs only. |
| `crates-publish.yml`, `primitives-publish.yml`, `mcp-release.yml`, `release-plz.yml` | Trusted Publishing and tokens. Tags only. |
| `dependabot-auto-merge.yml` | Needs `pull_request_target`. Costs under one minute. |

### 5.2 Moves to Cloud Build

| GitHub workflow | New Cloud Build config | Trigger |
|---|---|---|
| `rust.yml` jobs: `primitives`, `server-feature-clippy`, `native-wire-conformance`, `server-semver`, `client-wasm`, `sync-native-deps` | `server.yaml` (shards run in parallel) | `mkit-server-{pr,main}`, path-filtered to `rust/**` |
| `conformance.yml` | `server.yaml` (same shard as native-wire) | Same trigger |
| `buf.yml`, `proto.yml` | Already in `codegen.yaml`. Delete after one verified run. | `mkit-codegen-{pr,main}` |
| `third-party-notices.yml`, `release-artifact-check.yml` | `supply.yaml` | Path-filtered to manifests and `scripts/release/**` |
| `docs-lint.yml`, `crypto-stack-version.yml`, `actionlint.yml` | `meta.yaml` (script checks in the CI image) | Path-filtered |
| `web.yml`, `mcp.yml`, `og.yml`, `spammer-worker.yml`, `workers.yml` | `ts.yaml` with a Node and wasm-pack image. Use one shard per app. | Path-filtered per app. |
| `commonware-latest.yml`, `connect-latest.yml` | `commonware-latest.yaml`, `connect-latest.yaml` (exist) | Cloud Scheduler, weekly. |
| `fuzz.yml`, `formal.yml`, `mutants.yml`, `bench-freshness.yml`, `rust-security.yml` | `nightly-*.yaml` | Cloud Scheduler. Delete `rust-security.yml` because `security.yaml` covers it. |

Reuse these patterns from `../polychrome` and `../monorepo`:

- **Sharded triggers.** One config per concern, one trigger per config.
  Shards run in parallel and report separate checks.
- **Partitioned tests.** Polychrome builds one nextest archive and runs
  four partitions against it. Use this for the 6,780-test workspace
  instead of one 60-minute step.
- **Path filters on every trigger.** Always keep one unfiltered gate so
  a required check exists on every pull request.
- **Comment control.** `COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY`
  runs collaborator pull requests at once. Forks and bots need `/gcbrun`.
- **Guard scripts.** Polychrome's `check_cloudbuild_arg_len.py` and
  `check_ci_guard_coverage.py` catch the 10,000-character argument limit
  and unreached guards. Port both.
- **Manual run helper.** Monorepo's `tools/scripts/cloudbuild-run.sh`
  starts a pull-request shard by hand.
- **Scheduled builds.** Polychrome runs nightly and drift checks with
  Cloud Scheduler plus a manual trigger.
- **Cross-file invariants.** Keep `_CI_IMAGE`, `_CACHE_BUCKET`, and tool
  versions identical in every config. Add a script that checks them.

### 5.3 Required checks

Replace GitHub required checks with the Cloud Build check names. Do this
only after each new config passes a real pull request. Otherwise `main`
loses a gate in the gap. Use `/mkit-ci-preflight` before every merge. It
lists the GCB `mkit-*-pr` checks by name.

## 6. Order of work

Each step is one pull request. Verify each with a real run before the next.

1. **This branch.** `native.yml`, `darwin.yaml`, baked image, triggers.
   Run `scripts/setup-cloud-build.sh` to create `mkit-darwin-{pr,main}`.
   Then remove the old macOS required checks.
2. **Server shard.** Move the `rust.yml` jobs and `conformance.yml`.
   Delete both workflows and the `Rust CI gate` job.
3. **Duplicates.** Delete `buf.yml`, `proto.yml`, `rust-security.yml`.
4. **TypeScript shards.** Move the five app workflows.
5. **Meta and supply checks.** Move the small script checks.
6. **Nightlies.** Move fuzz, formal, mutants, and bench to Cloud Scheduler.
7. **Cleanup.** Reduce Dependabot frequency and use grouped updates.
   Review whether the Code Security and Code Quality licenses are needed.

## 7. Expected result

| Item | October | After step 1 | After step 6 |
|---|---|---|---|
| macOS list price | $660 | about $170 | about $170 |
| Linux list price | $422 | about $420 | under $60 |
| Real cash from mkit | $0 (pool) | $0 | $0 |
| Pool pressure on other repos | high | medium | low |

Cloud Build cost is extra. Estimate it at 4 to 6 build-minutes per pull
request shard on `E2_HIGHCPU_8` (about $0.016 per minute at list price).
sccache in GCS keeps it low. Measure the first two weeks, then tune.

## 8. Risks

- The Darwin type-check catches compile errors only. A runtime macOS bug
  appears at the next push or nightly run. The release build is the last
  gate.
- The nightly run hides a macOS break for up to 24 hours when no
  macOS-specific file changed. Set a notification on failure.
- Cloud Build checks do not appear until the trigger exists. Create the
  trigger before you change branch protection.
- The shared image tag `:rust-1.95.0` was rebuilt in place. Rebuilding
  an old commit uses the new image.
