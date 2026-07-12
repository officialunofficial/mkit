#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Regenerate the checked-in Swift bindings for mkit-sign-se from
# rust/crates/mkit-rpc/proto/buf.gen.yaml — the same recipe published for
# third-party signer integrators alongside the mkit-rpc BSR module
# (buf.build/officialunofficial/mkit-rpc, see issue #719). SwiftPM has no
# build.rs equivalent, so mkit-sign-se vendors generated sources the way
# mkit-rpc's own Rust build vendors buffa output; unlike that path this one
# runs through `buf generate` (a buf remote plugin execution — no local
# protoc-gen-swift/Swift toolchain required) instead of a raw `protoc` call.
#
# After editing common.proto/signer.proto, run this script from the repo
# root and commit the refreshed output alongside the .proto change.
#
# Requires `buf` on PATH (https://buf.build/docs/installation) and network
# access to buf.build's remote plugin execution service.

set -euo pipefail

cd "$(dirname "$0")/.."

PROTO_DIR=rust/crates/mkit-rpc/proto
DEST=contrib/signers/mkit-sign-se/Sources/mkit-sign-se/Generated

command -v buf >/dev/null 2>&1 || {
    echo "error: buf not found on PATH — https://buf.build/docs/installation" >&2
    exit 1
}

TMP_OUT=$(mktemp -d)
trap 'rm -rf "$TMP_OUT"' EXIT

buf generate "$PROTO_DIR" --template "$PROTO_DIR/buf.gen.yaml" -o "$TMP_OUT"

# buf.gen.yaml's swift plugin mirrors each .proto's path under gen/swift/,
# matching the module's mkit/rpc/v1/{...} directory layout (#677's
# flat-to-package-matching restructure). mkit-sign-se only needs the
# common/signer pair (ssh.proto and verify.proto also generate here — a
# single shared recipe covers the whole module, and dropping them from
# generation would silently diverge from what integrators get from the
# published BSR module — but mkit-sign-se doesn't vendor a copy of either).
GEN="$TMP_OUT/gen/swift/mkit/rpc/v1"
[ -f "$GEN/common.pb.swift" ] && [ -f "$GEN/signer/signer.pb.swift" ] || {
    echo "error: buf generate did not produce common.pb.swift/signer/signer.pb.swift under $GEN" >&2
    exit 1
}

cp "$GEN/common.pb.swift" "$DEST/common.pb.swift"
cp "$GEN/signer/signer.pb.swift" "$DEST/signer.pb.swift"

echo "refreshed $DEST from buf generate:"
ls "$DEST"

if ! git diff --quiet -- "$DEST"; then
    echo
    echo "generated output changed — review and commit:"
    git status --short -- "$DEST"
else
    echo "generated output is unchanged."
fi
