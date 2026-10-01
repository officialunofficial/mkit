#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the shared transport and health ConnectRPC bindings owned by
# mkit-rpc (feature transport), consumed by both mkit-server and the native
# mkit-transport-connect client. The canonical protos stay at the repo root;
# ordinary builds use the committed generated/transport/ tree without protoc.
# Requires protoc >= 27 on PATH (or PROTOC).

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
    # Reusing an OUT_DIR updates the marker, not necessarily its directory
    # mtime. Select by marker mtime so an older directory with fresh codegen
    # wins over a newer directory containing stale output.
    out=$(ls -t $build_glob/$marker 2>/dev/null | head -n 1)
    if [ -z "${out}" ]; then
        echo "error: no codegen output found for $label under: $build_glob" >&2
        exit 1
    fi
    out="${out%/$marker}"
    rm -f "$gen_dir"/*.rs
    mkdir -p "$gen_dir"
    cp "$out"/*.rs "$gen_dir/"
    echo "refreshed $gen_dir from $out:"
    ls "$gen_dir"
}

echo ">> mkit-rpc transport (wasm32 target)"
MKIT_TRANSPORT_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-rpc \
    --features transport --target wasm32-unknown-unknown
refresh "mkit-rpc transport" \
    "rust/crates/mkit-rpc/generated/transport" \
    "rust/target/wasm32-unknown-unknown/debug/build/mkit-rpc-*/out/transport" \
    ".mkit-rpc-transport-codegen"

generated_dirs=(rust/crates/mkit-rpc/generated/transport)
# `git status --porcelain`, not only `git diff`: a new module lands untracked.
if ! git diff --quiet -- "${generated_dirs[@]}" \
    || [ -n "$(git status --porcelain -- "${generated_dirs[@]}")" ]; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "${generated_dirs[@]}"
else
    echo "generated output is unchanged."
fi
