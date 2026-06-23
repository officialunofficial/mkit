#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored ConnectRPC codegen for the repo-service crates:
#   - rust/crates/mkit-repo-client  (the wasm ConnectRPC client)
#   - apps/repo-worker              (the workers-rs ConnectRPC server)
#
# Both build from pre-generated sources committed under their generated/ dirs
# so that consumers — Cloudflare Workers Builds, CI, docs.rs — never need protoc
# (their images lack a protoc new enough for protobuf `edition = "2023"`). They
# share one canonical proto (apps/repo-worker/proto/mkit/repo/v1/repo.proto), so
# after editing it, run this script from the repo root and commit BOTH refreshed
# generated/ dirs.
#
# Requires protoc >= 27 on PATH (edition 2023 support); mirrors regen-rpc-proto.sh.

set -euo pipefail

cd "$(dirname "$0")/.."

# $1 = human label, $2 = generated/ dir to refresh, $3 = build-dir glob for the
# crate's build-script OUT_DIRs. Picks the freshest OUT_DIR carrying the real
# codegen marker (.mkit-repo-codegen) — staging-mode runs fill OUT_DIR with the
# same file set, so the marker is what distinguishes a true codegen run.
refresh() {
    local label="$1" gen_dir="$2" build_glob="$3"
    local out
    out=$(ls -dt $build_glob 2>/dev/null | while read -r d; do
        if [ -f "$d/.mkit-repo-codegen" ]; then echo "$d"; break; fi
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

echo ">> mkit-repo-client (host target)"
MKIT_REPO_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-repo-client
refresh "mkit-repo-client" \
    "rust/crates/mkit-repo-client/generated" \
    "rust/target/debug/build/mkit-repo-client-*/out"

echo ">> apps/repo-worker (wasm32 target)"
MKIT_REPO_CODEGEN=1 cargo build --manifest-path apps/repo-worker/Cargo.toml --target wasm32-unknown-unknown
refresh "apps/repo-worker" \
    "apps/repo-worker/generated" \
    "apps/repo-worker/target/wasm32-unknown-unknown/debug/build/mkit-repo-worker-*/out"
