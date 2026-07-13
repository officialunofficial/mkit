#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored ConnectRPC codegen for every consumer of the
# canonical proto/mkit/transport/v1/transport.proto:
#   - rust/crates/mkit-transport-connect  (native client for mkit+https://,
#     plus the axum-hosted `mkit serve --http` server behind its `server`
#     feature)
#   - apps/vcs-worker                     (the workers-rs ConnectRPC
#     reference Worker, R2 + Durable Object backed — mkit#699)
#
# apps/vcs-worker cannot depend on mkit-transport-connect directly: its
# client/server halves are native (Tokio, hyper) and don't compile for the
# wasm32-unknown-unknown Workers target, so each consumer vendors its own
# generated/ from the SAME canonical proto rather than sharing a crate
# dependency (mirrors apps/repo-worker + mkit-repo-client's split — see
# scripts/regen-repo-proto.sh).
#
# Both build from pre-generated sources committed under their generated/
# dirs so consumers (Cloudflare Workers Builds, CI, docs.rs) never need
# protoc (their images lack a protoc new enough for protobuf
# `edition = "2023"`). After editing transport.proto, run this script from
# the repo root and commit BOTH refreshed generated/ dirs.
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

echo ">> apps/vcs-worker (wasm32 target)"
MKIT_TRANSPORT_CODEGEN=1 cargo build --manifest-path apps/vcs-worker/Cargo.toml --target wasm32-unknown-unknown
refresh "apps/vcs-worker" \
    "apps/vcs-worker/generated" \
    "apps/vcs-worker/target/wasm32-unknown-unknown/debug/build/mkit-vcs-worker-*/out" \
    ".mkit-transport-codegen"

if ! git diff --quiet -- rust/crates/mkit-transport-connect/generated apps/vcs-worker/generated; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- rust/crates/mkit-transport-connect/generated apps/vcs-worker/generated
else
    echo "generated output is unchanged."
fi
