#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored ConnectRPC codegen for
# rust/crates/mkit-transport-connect — both the axum-hosted
# `mkit.transport.v1` server behind `mkit serve --http` and the native
# ConnectRPC client behind `mkit+https://` (see SPEC-TRANSPORT-CONNECT.md).
#
# Builds from pre-generated sources committed under generated/ so consumers
# (Cloudflare Workers Builds, CI, docs.rs) never need protoc (their images
# lack a protoc new enough for protobuf `edition = "2023"`). The canonical
# proto is proto/mkit/transport/v1/transport.proto (repo root); after editing
# it, run this script from the repo root and commit the refreshed generated/
# dir.
#
# Requires protoc >= 27 on PATH (edition 2023 support); mirrors
# regen-repo-proto.sh / regen-rpc-proto.sh.

set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=rust/crates/mkit-transport-connect/generated

MKIT_REPO_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-transport-connect

# Picks the freshest OUT_DIR carrying the real codegen marker
# (.mkit-repo-codegen) — staging-mode runs fill OUT_DIR with the same file
# set, so the marker is what distinguishes a true codegen run.
out_dir=$(ls -dt rust/target/debug/build/mkit-transport-connect-*/out 2>/dev/null | while read -r d; do
    if [ -f "$d/.mkit-repo-codegen" ]; then echo "$d"; break; fi
done)

if [ -z "${out_dir}" ]; then
    echo "error: no codegen output found under rust/target/debug/build/mkit-transport-connect-*/out" >&2
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
