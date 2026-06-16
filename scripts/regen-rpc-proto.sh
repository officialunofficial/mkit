#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored buffa codegen output for mkit-rpc.
#
# mkit-rpc builds from pre-generated sources committed under
# rust/crates/mkit-rpc/generated/ so that consumers (and docs.rs) never
# need protoc. After editing any file in rust/crates/mkit-rpc/proto/,
# run this script from the repo root and commit the refreshed output.
#
# Requires protoc >= 27 on PATH (protobuf `edition = "2023"` support).

set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=rust/crates/mkit-rpc/generated

MKIT_RPC_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-rpc

out_dir=$(ls -dt rust/target/debug/build/mkit-rpc-*/out 2>/dev/null | while read -r d; do
    # Pick the freshest OUT_DIR holding REAL codegen output. The
    # default (staging) build mode also fills its OUT_DIR with the
    # same .rs file set copied from generated/, so the presence of
    # _includes.rs is not enough — build.rs drops .mkit-rpc-codegen
    # only in codegen mode, and removes it again on staging runs.
    if [ -f "$d/.mkit-rpc-codegen" ]; then echo "$d"; break; fi
done)

if [ -z "${out_dir}" ]; then
    echo "error: no buffa codegen output found under rust/target/debug/build/mkit-rpc-*/out" >&2
    exit 1
fi

rm -f "$GEN_DIR"/*.rs
mkdir -p "$GEN_DIR"
cp "$out_dir"/*.rs "$GEN_DIR/"

echo "refreshed $GEN_DIR from $out_dir:"
ls "$GEN_DIR"

if ! git diff --quiet -- "$GEN_DIR"; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$GEN_DIR"
else
    echo "generated output is unchanged."
fi
