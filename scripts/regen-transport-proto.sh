#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the vendored ConnectRPC codegen for
# rust/crates/mkit-transport-connect (the axum-hosted `mkit.transport.v1`
# server behind `mkit serve --http` — see SPEC-TRANSPORT-CONNECT.md).
#
# Builds from pre-generated sources committed under generated/ so consumers
# (CI, docs.rs) never need protoc (their images lack a protoc new enough for
# protobuf `edition = "2023"`). The canonical proto is
# proto/mkit/transport/v1/transport.proto (repo root); after editing it, run
# this script from the repo root and commit the refreshed generated/ dir.
#
# Requires protoc >= 27 on PATH (edition 2023 support); mirrors
# regen-repo-proto.sh / regen-rpc-proto.sh.

set -euo pipefail

cd "$(dirname "$0")/.."

MKIT_TRANSPORT_CODEGEN=1 cargo build --manifest-path rust/Cargo.toml -p mkit-transport-connect

out=$(ls -dt rust/target/debug/build/mkit-transport-connect-*/out 2>/dev/null | while read -r d; do
    if [ -f "$d/.mkit-transport-codegen" ]; then echo "$d"; break; fi
done)
if [ -z "${out}" ]; then
    echo "error: no codegen output found under rust/target/debug/build/mkit-transport-connect-*/out" >&2
    exit 1
fi

gen_dir="rust/crates/mkit-transport-connect/generated"
rm -f "$gen_dir"/*.rs
mkdir -p "$gen_dir"
cp "$out"/*.rs "$gen_dir/"
echo "refreshed $gen_dir from $out:"
ls "$gen_dir"
