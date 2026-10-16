#!/usr/bin/env bash
# Scope stability compilation to this crate. The inventory sweep lands with codecs.
set -euo pipefail
cd "$(dirname "$0")/.."
just cargo-cached check --locked -p mkit-primitives --lib --all-features
wrappers=$(mktemp -d)
trap 'rm -rf "$wrappers"' EXIT
# sccache cannot nest the scoped workspace compiler wrapper. The ordinary
# build above uses it; scoped passes use Cargo directly in the same worktree.
unset RUSTC_WRAPPER
export CARGO_BUILD_BUILD_DIR="${MKIT_BUILD_ROOT:-$HOME/.cache/mkit/build}/{workspace-path-hash}"
cd rust
for level in BETA GAMMA DELTA EPSILON RESERVED; do
  cp ../scripts/primitives-stability-rustc.py "$wrappers/$level"
  MKIT_PRIMITIVES_MIN_STABILITY="$level" \
    RUSTC_WORKSPACE_WRAPPER="$wrappers/$level" \
    cargo check --locked -p mkit-primitives --lib --all-features
 done
