#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored buffa codegen for the canonical
# proto/mkit/server/hooks/v1/hooks.proto, consumed by mkit-server's
# `remote-hooks` feature (rust/crates/mkit-server/generated/hooks/).
#
# Messages and the JSON codec only: no ConnectRPC stubs, so the feature stays
# wasm-clean and pulls no client. mkit-server builds from the committed
# sources, so consumers (Cloudflare Workers Builds, CI, docs.rs) never need
# protoc (their images lack one new enough for `edition = "2023"`). After
# editing hooks.proto, run this from the repo root and commit generated/hooks/.
#
# Requires protoc >= 27 on PATH (edition 2023 support), like the sibling
# regen-*-proto.sh scripts.

set -euo pipefail

cd "$(dirname "$0")/.."

gen_dir="rust/crates/mkit-server/generated/hooks"
marker=".mkit-server-hooks-codegen"

echo ">> mkit-server remote-hooks (wasm32 target, matching regen-transport-proto.sh)"
MKIT_HOOKS_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-server \
    --no-default-features --features remote-hooks --target wasm32-unknown-unknown

# Pick the OUT_DIR whose marker is freshest: staging-mode runs fill OUT_DIR
# with the same file set, so the marker is what marks a true codegen run.
build_glob="rust/target/wasm32-unknown-unknown/debug/build/mkit-server-*/out/hooks"
# shellcheck disable=SC2086
out=$(ls -t $build_glob/$marker 2>/dev/null | head -n 1)
if [ -z "${out}" ]; then
    echo "error: no codegen output found for mkit-server hooks under: $build_glob" >&2
    exit 1
fi
out="${out%/$marker}"
rm -f "$gen_dir"/*.rs
mkdir -p "$gen_dir"
cp "$out"/*.rs "$gen_dir/"
echo "refreshed $gen_dir from $out:"
ls "$gen_dir"

# `git status --porcelain`, not only `git diff`: a new module lands untracked.
if ! git diff --quiet -- "$gen_dir" || [ -n "$(git status --porcelain -- "$gen_dir")" ]; then
    echo
    echo "generated output changed: review and commit:"
    git status --short -- "$gen_dir"
else
    echo "generated output is unchanged."
fi
