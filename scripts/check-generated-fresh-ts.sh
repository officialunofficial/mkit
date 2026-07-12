#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Fail if the vendored connect-es TypeScript codegen committed under
# apps/web/vendor/mkit-repo-proto/generated/ has drifted from what the
# current repo.proto + protoc-gen-es would produce. TS sibling of
# scripts/check-generated-fresh.sh (which covers the Rust buffa/connectrpc
# trees) — kept as a SEPARATE script/CI step rather than folded into that one
# because it runs on a DIFFERENT CI surface: `check-generated-fresh.sh` runs
# on Google Cloud Build's Rust-only `mkit-ci` image (cloudbuild/Dockerfile.ci
# has no Node/bun/buf), while this needs `buf` + apps/web's `bun install`'d
# `protoc-gen-es`. Wired into `.github/workflows/web.yml`'s `web` job, which
# already installs Node/Bun/protoc and runs on every PR touching apps/web.
#
# Requires: `buf` on PATH, apps/web/node_modules populated (`bun install`).

set -euo pipefail

cd "$(dirname "$0")/.."

bash scripts/regen-repo-proto-ts.sh

drift="$(git status --porcelain -- apps/web/vendor/mkit-repo-proto/generated)"
if [ -n "${drift}" ]; then
    echo "::error::Vendored TS codegen is STALE. Run scripts/regen-repo-proto-ts.sh, then commit the result." >&2
    echo >&2
    echo "Drift detected in vendored codegen:" >&2
    echo "${drift}" >&2
    exit 1
fi

echo "Vendored TS codegen is up to date with repo.proto."
