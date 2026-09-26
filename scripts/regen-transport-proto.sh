#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored ConnectRPC codegen for every consumer of the
# canonical proto/mkit/transport/v1/transport.proto:
#   - rust/crates/mkit-transport-connect  (native client for mkit+https://,
#     plus the axum-hosted `mkit serve --http` server behind its `server`
#     feature)
#   - rust/crates/mkit-server             (the production server's wasm-clean
#     `connect` binding, mounted by its native and Workers adapters; it also
#     vendors grpc.health.v1)
#
# apps/vcs-worker no longer vendors its own copy (WP-M0-17): it is a thin
# deployment of mkit-server-worker, which mounts mkit-server's binding.
# mkit-server cannot share mkit-transport-connect's copy: that crate's
# client/server halves are native (Tokio, hyper) and don't compile for the
# wasm32-unknown-unknown Workers target, so each consumer vendors its own
# generated/ from the SAME canonical proto rather than sharing a crate
# dependency (mirrors apps/repo-worker + mkit-repo-client's split — see
# scripts/regen-repo-proto.sh).
#
# Both build from pre-generated sources committed under their
# generated/ dirs so consumers (Cloudflare Workers Builds, CI, docs.rs) never
# need protoc (their images lack a protoc new enough for protobuf
# `edition = "2023"`). After editing transport.proto, run this script from
# the repo root and commit EVERY refreshed generated/ dir.
#
# Requires protoc >= 27 on PATH (edition 2023 support); mirrors
# regen-repo-proto.sh / regen-rpc-proto.sh.

set -euo pipefail

cd "$(dirname "$0")/.."

# $1 = human label, $2 = generated/ dir to refresh, $3 = build-dir glob for
# the crate's build-script OUT_DIRs, $4 = codegen marker file name (each
# consumer's build.rs writes its own; see their `cargo:rerun-if-env-changed`
# env var). Picks the freshest OUT_DIR carrying that marker — staging-mode
# runs fill OUT_DIR with the same file set, so the marker is what
# distinguishes a true codegen run.
refresh() {
    local label="$1" gen_dir="$2" build_glob="$3" marker="$4"
    local out
    out=$(ls -dt $build_glob 2>/dev/null | while read -r d; do
        if [ -f "$d/$marker" ]; then echo "$d"; break; fi
    done)
    if [ -z "${out}" ]; then
        echo "error: no codegen output found for $label under: $build_glob" >&2
        exit 1
    fi
    rm -f "$gen_dir"/*.rs
    mkdir -p "$gen_dir"
    cp "$out"/*.rs "$gen_dir/"
    echo "refreshed $gen_dir from $out:"
    ls "$gen_dir"
}

echo ">> mkit-transport-connect (host target)"
MKIT_REPO_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-transport-connect
refresh "mkit-transport-connect" \
    "rust/crates/mkit-transport-connect/generated" \
    "rust/target/debug/build/mkit-transport-connect-*/out" \
    ".mkit-repo-codegen"

echo ">> mkit-server (wasm32 target; its default features include connect)"
MKIT_TRANSPORT_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-server --target wasm32-unknown-unknown
refresh "mkit-server" \
    "rust/crates/mkit-server/generated" \
    "rust/target/wasm32-unknown-unknown/debug/build/mkit-server-*/out" \
    ".mkit-server-transport-codegen"

generated_dirs=(
    rust/crates/mkit-transport-connect/generated
    rust/crates/mkit-server/generated
)
# `git status --porcelain`, not only `git diff`: a new module lands untracked.
if ! git diff --quiet -- "${generated_dirs[@]}" \
    || [ -n "$(git status --porcelain -- "${generated_dirs[@]}")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "${generated_dirs[@]}"
else
    echo "generated output is unchanged."
fi
