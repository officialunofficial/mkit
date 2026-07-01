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
# SCOPE: CI only. mkit ships a CLI binary + Cloudflare Workers, so there is no
# image-publish / GKE-deploy half. Release/crates.io/npm/
# cosign stay on GitHub Actions; the macOS + keystore-backends legs (which Cloud
# Build's Linux containers can't run) also stay on GitHub Actions.
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
CI_IMAGE="${CI_IMAGE:-us-east4-docker.pkg.dev/${PROJECT}/docker/mkit-ci:rust-1.95.0}"
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
CODEGEN_FILES='**/*.proto','**/build.rs','**/Cargo.lock','cloudbuild/Dockerfile.ci','scripts/regen-rpc-proto.sh','scripts/regen-repo-proto.sh','scripts/check-generated-fresh.sh','**/generated/**'
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

# Coverage: informational, main pushes only (does not gate PRs).
mk_push mkit-coverage-main --build-config=cloudbuild/coverage.yaml

echo "Done. Triggers:"
gcloud builds triggers list --project="$PROJECT" --region="$REGION" \
  --format='table(name,filename)'
