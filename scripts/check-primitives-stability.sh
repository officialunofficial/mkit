#!/usr/bin/env bash
# Scope stability compilation to this crate. The inventory sweep lands with codecs.
set -euo pipefail
cd "$(dirname "$0")/.."
just cargo-cached check --locked -p mkit-primitives --lib --all-features
wrappers=$(mktemp -d)
trap 'rm -rf "$wrappers"' EXIT
for level in BETA GAMMA DELTA EPSILON RESERVED; do
  cp scripts/primitives-stability-rustc.py "$wrappers/$level"
  MKIT_PRIMITIVES_MIN_STABILITY="$level" \
    RUSTC_WORKSPACE_WRAPPER="$wrappers/$level" \
    just cargo-cached check --locked -p mkit-primitives --lib --all-features
 done
