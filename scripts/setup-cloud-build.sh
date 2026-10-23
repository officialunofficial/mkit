#!/usr/bin/env bash
# One-time setup for mkit's Rust CI on Google Cloud Build.
#
# The hard part is already done: the `officialunofficial/mkit` repo is linked to
# the existing 2nd-gen Cloud Build GitHub connection (`github`, in us-east4) —
# the same connection other org repos already use. So there is NO GitHub
# App to install. This script provisions the rest:
#   1. sccache GCS bucket    (+ grant the build SA access)
#   2. CI toolchain image    (cloudbuild/Dockerfile.ci → GAR; consumed by every
#                             cloudbuild/*.yaml config)
#   3. Codecov token         (optional — Secret Manager, for coverage upload)
#   4. Build triggers        (the /gcbrun-gated Rust suite + path-gated gates)
#
# SCOPE: CI, scheduled jobs and tag-driven crate publishing. mkit has no GKE
# deploy half. The GitHub binaries, cosign, SLSA, npm Trusted Publishing and
# release-plz stay on GitHub Actions, as do the macOS legs (native.yml) that
# Cloud Build's Linux containers can't run.
#
# Idempotent: existing buckets/secrets/triggers are detected and skipped, so it
# is safe to re-run. Requires gcloud (authed). Run from the repo root.
set -euo pipefail

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"
: "${PROJECT:?set PROJECT (or run: gcloud config set project <id>) — every step below needs it}"
REGION="${REGION:-us-east4}"            # connection + triggers + GAR
CONNECTION="${CONNECTION:-github}"
REPO="${REPO:-officialunofficial-mkit}"
CACHE_BUCKET="${CACHE_BUCKET:-${PROJECT}-mkit-sccache}"
CI_IMAGE="${CI_IMAGE:-us-east4-docker.pkg.dev/${PROJECT}/docker/mkit-ci:rust-1.99.1}"
GAR_REPO="${GAR_REPO:-docker}" # GAR repo (us-east4) the CI image is pushed to

REPO_RES="projects/${PROJECT}/locations/${REGION}/connections/${CONNECTION}/repositories/${REPO}"
PROJ_NUM="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
BUILD_SA="${PROJ_NUM}@cloudbuild.gserviceaccount.com"

echo "Project ${PROJECT} (#${PROJ_NUM}); build SA ${BUILD_SA}"
echo "Repo resource: ${REPO_RES}"

# ── 1. sccache bucket + build-SA access ─────────────────────────────────────
echo "== sccache bucket =="
gcloud storage buckets create "gs://${CACHE_BUCKET}" \
  --project="$PROJECT" --location="$REGION" --uniform-bucket-level-access \
  || echo "  (bucket exists — skipping)"
# Auto-expire stale cache objects after 30 days to bound cost.
printf '{"rule":[{"action":{"type":"Delete"},"condition":{"age":30}}]}' \
  | gcloud storage buckets update "gs://${CACHE_BUCKET}" --lifecycle-file=/dev/stdin
gcloud storage buckets add-iam-policy-binding "gs://${CACHE_BUCKET}" \
  --member="serviceAccount:${BUILD_SA}" --role="roles/storage.objectAdmin"

# ── 2. CI toolchain image ───────────────────────────────────────────────────
# Baked once here (and rebuilt when Dockerfile.ci / rust-toolchain.toml change).
# The build SA needs artifactregistry.writer on the target GAR repo.
echo "== CI toolchain image (${CI_IMAGE}) =="
gcloud artifacts repositories add-iam-policy-binding "$GAR_REPO" \
  --project="$PROJECT" --location="$REGION" \
  --member="serviceAccount:${BUILD_SA}" --role="roles/artifactregistry.writer" >/dev/null
gcloud builds submit . --project="$PROJECT" --region="$REGION" \
  --config=cloudbuild/builder.yaml --substitutions="_CI_IMAGE=${CI_IMAGE}"

# ── 3. Codecov token (optional) ─────────────────────────────────────────────
# coverage.yaml uploads to Codecov when this secret exists; it's a no-op upload
# otherwise. Set SKIP_CODECOV=1 to skip this step entirely.
if [ "${SKIP_CODECOV:-0}" != "1" ]; then
  echo "== CODECOV_TOKEN secret =="
  if ! gcloud secrets describe CODECOV_TOKEN --project="$PROJECT" >/dev/null 2>&1; then
    echo "Paste the Codecov repo upload token (or Ctrl-D to skip; coverage upload stays off):"
    if gcloud secrets create CODECOV_TOKEN --project="$PROJECT" \
         --replication-policy=automatic --data-file=-; then
      gcloud secrets add-iam-policy-binding CODECOV_TOKEN --project="$PROJECT" \
        --member="serviceAccount:${BUILD_SA}" --role="roles/secretmanager.secretAccessor"
    else
      echo "  (no token provided — skipping; coverage.yaml will no-op the upload)"
    fi
  else
    echo "  (secret exists — to rotate: gcloud secrets versions add CODECOV_TOKEN --data-file=-)"
    gcloud secrets add-iam-policy-binding CODECOV_TOKEN --project="$PROJECT" \
      --member="serviceAccount:${BUILD_SA}" --role="roles/secretmanager.secretAccessor"
  fi
fi

# ── 4. Triggers ─────────────────────────────────────────────────────────────
# All PR triggers auto-run for org collaborators and require a maintainer
# `/gcbrun` only for external/fork contributors — matching the same control
# other org repos' *-ci-pr triggers use. This keeps internal PRs flowing on
# push while still gating untrusted fork code.
COL="COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY"

# Idempotent create: skip if a trigger of this name already exists.
mk() {
  local name="$1"; shift
  if gcloud builds triggers describe "$name" --project="$PROJECT" --region="$REGION" \
       >/dev/null 2>&1; then
    echo "  (trigger ${name} exists — skipping)"
    return 0
  fi
  gcloud builds triggers create github --project="$PROJECT" --region="$REGION" \
    --repository="$REPO_RES" --name="$name" "$@"
}
mk_pr()   { local n="$1"; shift; mk "$n" --pull-request-pattern='^main$' "$@"; }
mk_push() { local n="$1"; shift; mk "$n" --branch-pattern='^main$' "$@"; }

echo "== triggers =="

# Rust suite (fmt/clippy/build/test/doctests/msrv): auto on internal PRs,
# /gcbrun for forks; auto on main (skip apps/web/docs-only pushes).
mk_pr   mkit-ci-pr   --build-config=cloudbuild/ci.yaml --comment-control="$COL"
mk_push mkit-ci-main --build-config=cloudbuild/ci.yaml \
        --ignored-files='apps/**','web/**','docs/**','**/*.md'

# Vendored codegen freshness: path-gated to anything that can change generated
# output — protos, build.rs, the regen scripts, the committed generated/ trees,
# AND the inputs that silently drive codegen: Cargo.lock (the buffa-build /
# connectrpc-build crate versions) and Dockerfile.ci (the baked protoc version).
CODEGEN_FILES='**/*.proto','**/build.rs','**/Cargo.lock','buf.yaml','cloudbuild/Dockerfile.ci','scripts/regen-rpc-proto.sh','scripts/regen-repo-proto.sh','scripts/regen-transport-proto.sh','scripts/regen-hooks-proto.sh','scripts/check-generated-fresh.sh','**/generated/**','**/buf.yaml','scripts/check-server-hooks-goldens.sh','rust/tests/golden/server-hooks/**'
mk_pr   mkit-codegen-pr   --build-config=cloudbuild/codegen.yaml \
        --comment-control="$COL" --included-files="$CODEGEN_FILES"
mk_push mkit-codegen-main --build-config=cloudbuild/codegen.yaml \
        --included-files="$CODEGEN_FILES"

# Supply chain (cargo audit + deny): path-gated to manifests / lockfiles / deny.
SEC_FILES='**/Cargo.toml','**/Cargo.lock','rust/deny.toml','cloudbuild/security.yaml'
mk_pr   mkit-security-pr   --build-config=cloudbuild/security.yaml \
        --comment-control="$COL" --included-files="$SEC_FILES"
mk_push mkit-security-main --build-config=cloudbuild/security.yaml \
        --included-files="$SEC_FILES"

# Docs build: skip apps/web/docs-only changes.
DOC_IGNORE='apps/**','web/**','**/*.md'
mk_pr   mkit-docs-pr   --build-config=cloudbuild/docs.yaml \
        --comment-control="$COL" --ignored-files="$DOC_IGNORE"
mk_push mkit-docs-main --build-config=cloudbuild/docs.yaml \
        --ignored-files="$DOC_IGNORE"

# Unsafe-code ceiling: every PR (and main pushes).
mk_pr   mkit-geiger-pr   --build-config=cloudbuild/geiger.yaml --comment-control="$COL"
mk_push mkit-geiger-main --build-config=cloudbuild/geiger.yaml

# Darwin type-check (aarch64 + x86_64): path-gated to the macOS-specific code
# and the dependency graph. The macOS runtime tests run nightly on GitHub.
DARWIN_FILES='rust/Cargo.lock','rust/Cargo.toml','rust/rust-toolchain.toml','rust/crates/**','contrib/signers/**','cloudbuild/darwin.yaml','cloudbuild/Dockerfile.ci','scripts/zig-cc-darwin.sh'
mk_pr   mkit-darwin-pr   --build-config=cloudbuild/darwin.yaml \
        --comment-control="$COL" --included-files="$DARWIN_FILES"
mk_push mkit-darwin-main --build-config=cloudbuild/darwin.yaml \
        --included-files="$DARWIN_FILES"

# Server shard (primitives, server clippy powerset, wire conformance, semver,
# wasm client): path-gated to Rust and the server specs.
SERVER_FILES='rust/**','scripts/**','docs/specs/SPEC-SERVER.md','docs/specs/SPEC-TRANSPORT-CONNECT.md','cloudbuild/server.yaml'
mk_pr   mkit-server-pr   --build-config=cloudbuild/server.yaml \
        --comment-control="$COL" --included-files="$SERVER_FILES"
mk_push mkit-server-main --build-config=cloudbuild/server.yaml \
        --included-files="$SERVER_FILES"

# Supply files (third-party notices, release artifact feature check).
SUPPLY_FILES='rust/Cargo.lock','rust/Cargo.toml','rust/crates/**/Cargo.toml','rust/about.toml','rust/about.hbs','rust/crates/mkit-cli/**','rust/rust-toolchain.toml','scripts/check-release-artifact-features.sh','scripts/release/**','.github/workflows/release.yml','cloudbuild/supply.yaml'
mk_pr   mkit-supply-pr   --build-config=cloudbuild/supply.yaml \
        --comment-control="$COL" --included-files="$SUPPLY_FILES"
mk_push mkit-supply-main --build-config=cloudbuild/supply.yaml \
        --included-files="$SUPPLY_FILES"

# Meta checks (spec status, crypto stack version, actionlint, dependabot
# coverage, no-windows-target).
META_FILES='docs/specs/**','.github/workflows/**','.github/actions/**','.github/actionlint.yaml','.github/dependabot.yml','scripts/check-spec-status.sh','scripts/check-crypto-stack-version.sh','scripts/check-dependabot-coverage.sh','scripts/check-no-windows-target.sh','justfile','install.sh','rust/**/Cargo.toml','rust/**/Cargo.lock','contrib/**/Cargo.toml','contrib/signers/**/Cargo.lock','apps/*/Cargo.toml','apps/**/Cargo.lock','apps/web/package.json','apps/web/scripts/*.mjs','apps/web/.gitignore','cloudbuild/meta.yaml'
mk_pr   mkit-meta-pr   --build-config=cloudbuild/meta.yaml \
        --comment-control="$COL" --included-files="$META_FILES"
mk_push mkit-meta-main --build-config=cloudbuild/meta.yaml \
        --included-files="$META_FILES"

# TypeScript apps (web, mcp, og, spammer-worker, workers): one build runs all
# five in parallel, so the trigger uses the union of the old path filters.
TS_FILES='apps/**','docs/**','SKILL.md','README.md','man/**','rust/Cargo.lock','rust/Cargo.toml','rust/rust-toolchain.toml','rust/vendor/ruzstd/**','rust/crates/mkit-attest/**','rust/crates/mkit-core/**','rust/crates/mkit-rpc/**','rust/crates/mkit-wasm/**','rust/crates/mkit-repo-client/**','scripts/patch-wasm-bundler-glue.mjs','scripts/check-generated-fresh-ts.sh','cloudbuild/ts.yaml'
mk_pr   mkit-ts-pr   --build-config=cloudbuild/ts.yaml \
        --comment-control="$COL" --included-files="$TS_FILES"
mk_push mkit-ts-main --build-config=cloudbuild/ts.yaml \
        --included-files="$TS_FILES"

# Coverage: informational, main pushes only (does not gate PRs).
mk_push mkit-coverage-main --build-config=cloudbuild/coverage.yaml

# ── 5. Release triggers (opt in: ENABLE_RELEASE_TRIGGERS=1) ──────────────────
# Tag-driven crate, primitives and MCP publishes. These run the SAME release
# steps as the GitHub publish workflows, so enable them only when the matching
# GitHub workflow (crates-publish.yml, primitives-publish.yml, mcp-release.yml)
# is retired in the same change. Otherwise one tag publishes twice.
# Needs secrets CARGO_REGISTRY_TOKEN's source (CRATES_PACKAGE_KEY),
# cloudflare-api-token and BUF_TOKEN in Secret Manager (see docs/RELEASE.md).
mk_tag() { local n="$1"; shift; mk "$n" "$@"; }
if [ "${ENABLE_RELEASE_TRIGGERS:-0}" = "1" ]; then
  echo "== release triggers =="
  mk_tag mkit-publish-crates --tag-pattern='^v[0-9]+\.[0-9]+\.[0-9]+$' \
         --build-config=cloudbuild/publish-crates.yaml
  mk_tag mkit-mcp-release --tag-pattern='^v[0-9]+\.[0-9]+\.[0-9]+$' \
         --build-config=cloudbuild/mcp-release.yaml \
         --substitutions="_CF_ACCOUNT_ID=${CF_ACCOUNT_ID:?set CF_ACCOUNT_ID}"
  mk_tag mkit-publish-primitives \
         --tag-pattern='^mkit-primitives-v[0-9]+\.[0-9]+\.[0-9]+$' \
         --build-config=cloudbuild/publish-primitives.yaml \
         --substitutions="_GPG_FINGERPRINTS=${GPG_FINGERPRINTS:?set GPG_FINGERPRINTS}"
fi

# ── 6. Scheduled triggers (opt in: ENABLE_SCHEDULED_TRIGGERS=1) ──────────────
# A manual trigger per config plus a Cloud Scheduler job that runs it
# (polychrome's pattern). Cron times match the retired GitHub schedules (UTC).
mk_manual() {
  local n="$1" cfg="$2" cron="$3"; shift 3
  mk "$n" --branch-pattern='^main$' --build-config="$cfg" "$@"
  if gcloud scheduler jobs describe "$n" --project="$PROJECT" --location="$REGION" \
       >/dev/null 2>&1; then
    echo "  (scheduler job ${n} exists — skipping)"
    return 0
  fi
  gcloud scheduler jobs create http "$n" --project="$PROJECT" --location="$REGION" \
    --schedule="$cron" --time-zone=UTC --http-method=POST \
    --uri="https://cloudbuild.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/triggers/${n}:run" \
    --message-body='{"source":{"branchName":"main"}}' \
    --oauth-service-account-email="$BUILD_SA"
}
if [ "${ENABLE_SCHEDULED_TRIGGERS:-0}" = "1" ]; then
  echo "== scheduled triggers =="
  mk_manual mkit-nightly-fuzz   cloudbuild/nightly-fuzz.yaml   '0 4 * * *'
  mk_manual mkit-nightly-formal cloudbuild/nightly-formal.yaml '0 5 * * *'
  mk_manual mkit-nightly-bench  cloudbuild/nightly-bench.yaml  '0 7 * * 0'
  mk_manual mkit-mutants-full   cloudbuild/mutants.yaml        '0 7 * * 2' \
            --substitutions=_MODE=full
  mk_manual mkit-security-weekly cloudbuild/security.yaml      '0 6 * * 1'
  mk_manual mkit-commonware-latest cloudbuild/commonware-latest.yaml '23 5 * * 1'
  mk_manual mkit-connect-latest cloudbuild/connect-latest.yaml '23 5 * * 1'
fi
# Pull-request mutation diff.
mk_pr mkit-mutants-pr --build-config=cloudbuild/mutants.yaml \
      --comment-control="$COL" --included-files='rust/**' \
      --substitutions=_MODE=diff

echo "Done. Triggers:"
gcloud builds triggers list --project="$PROJECT" --region="$REGION" \
  --format='table(name,filename)'
