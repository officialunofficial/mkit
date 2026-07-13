#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored connect-es TypeScript codegen for
# mkit.repo.v1.RepoService — the TS sibling of scripts/regen-repo-proto.sh
# (which refreshes the two RUST codegen trees from the same canonical proto).
#
# apps/web builds from pre-generated sources committed under
# apps/web/vendor/mkit-repo-proto/generated/ so consumers never need buf or
# protoc — only apps/web's own devDependencies (`@bufbuild/protoc-gen-es`).
# After editing apps/repo-worker/proto/mkit/repo/v1/repo.proto, run this
# script from the repo root and commit the refreshed generated/ output.
#
# Requires: `buf` on PATH, and apps/web's devDependencies installed
# (`cd apps/web && bun install`) so protoc-gen-es is under
# apps/web/node_modules/.bin.
#
# `--include-imports`: repo.proto imports mkit/common/v1/refs.proto (#679's
# RefExpectation/RefEntry extraction), which lives in the repo-root `proto`
# workspace module, not this one. Plain `buf generate` only emits output for
# files in the target module, so without this flag the imported refs types
# compile fine but never get a repo_pb.ts sibling — repo_pb.ts's `import
# "../../common/v1/refs_pb"` then points at a file that doesn't exist. The
# Rust codegen path (rust/crates/mkit-repo-client/build.rs) avoids this by
# passing both proto files explicitly to connectrpc-build; buf's equivalent
# is generating with imports included. refs.proto itself imports nothing
# further, so this pulls in exactly the one extra file, not a wider tree.
#
# NOTE: only `protoc-gen-es` runs here — `@connectrpc/protoc-gen-connect-es`
# (latest: 1.7.0) does not support Protobuf Editions yet, and repo.proto is
# `edition = "2023"`. Connect-ES v2 doesn't need it anyway: protoc-gen-es
# alone emits the `RepoService` GenService descriptor that
# `@connectrpc/connect`'s `createClient()` consumes directly. See
# apps/repo-worker/buf.gen.yaml for the full explanation.

set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=apps/web/vendor/mkit-repo-proto/generated

if ! command -v buf >/dev/null 2>&1; then
    echo "error: buf not found on PATH (https://buf.build/docs/installation)" >&2
    exit 1
fi

if [ ! -x apps/web/node_modules/.bin/protoc-gen-es ]; then
    echo "error: apps/web/node_modules/.bin/protoc-gen-es not found — run 'cd apps/web && bun install' first" >&2
    exit 1
fi

rm -rf "$GEN_DIR"
mkdir -p "$GEN_DIR"

(
    cd apps/repo-worker
    PATH="$(pwd)/../web/node_modules/.bin:$PATH" buf generate --include-imports
)

echo "refreshed $GEN_DIR:"
find "$GEN_DIR" -type f

if ! git diff --quiet -- "$GEN_DIR" || [ -n "$(git status --porcelain -- "$GEN_DIR")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$GEN_DIR"
else
    echo "generated output is unchanged."
fi
